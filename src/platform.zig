const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");

const env_c = @cImport({
    @cInclude("stdlib.h");
});

/// Cross-platform wrapper over std_compat.process.getEnvVarOwned that returns
/// null instead of error.EnvironmentVariableNotFound.
/// Caller owns the returned slice and must free it with `allocator.free()`.
/// Note: OOM is treated as "variable not found" because callers universally
/// use the pattern `if (getEnvOrNull(...)) |v| { defer free(v); ... }` and
/// propagating OOM would require changing every call-site to handle errors.
/// In practice, env var allocation (< 4 KB) does not OOM.
pub fn getEnvOrNull(allocator: std.mem.Allocator, name: []const u8) ?[]const u8 {
    return std_compat.process.getEnvVarOwned(allocator, name) catch return null;
}

/// Sets or unsets a process environment variable.
/// Passing null removes the variable on POSIX and clears it on Windows.
pub fn setProcessEnv(allocator: std.mem.Allocator, name: []const u8, value: ?[]const u8) !void {
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);

    const rc: c_int = if (value) |env_value| blk: {
        const value_z = try allocator.dupeZ(u8, env_value);
        defer allocator.free(value_z);
        break :blk if (comptime builtin.os.tag == .windows)
            env_c._putenv_s(name_z.ptr, value_z.ptr)
        else
            env_c.setenv(name_z.ptr, value_z.ptr, 1);
    } else if (comptime builtin.os.tag == .windows)
        env_c._putenv_s(name_z.ptr, "")
    else
        env_c.unsetenv(name_z.ptr);

    if (rc != 0) return error.EnvMutationFailed;
}

/// Returns the user's home directory. Tries:
///   Windows: USERPROFILE → HOMEDRIVE+HOMEPATH
///   Unix:    HOME
/// Caller owns the returned slice.
pub fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (comptime builtin.os.tag == .windows) {
        if (getEnvOrNull(allocator, "USERPROFILE")) |v| return v;
        const drive = getEnvOrNull(allocator, "HOMEDRIVE") orelse return error.HomeDirNotFound;
        defer allocator.free(drive);
        const path = getEnvOrNull(allocator, "HOMEPATH") orelse return error.HomeDirNotFound;
        defer allocator.free(path);
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ drive, path });
    } else {
        return std_compat.process.getEnvVarOwned(allocator, "HOME") catch return error.HomeDirNotFound;
    }
}

/// Returns the system temp directory. Tries:
///   Windows: TEMP → TMP → "C:\\Temp"
///   Unix:    TMPDIR → "/tmp"
/// Caller owns the returned slice.
pub fn getTempDir(allocator: std.mem.Allocator) ![]const u8 {
    if (comptime builtin.os.tag == .windows) {
        if (getEnvOrNull(allocator, "TEMP")) |v| return v;
        if (getEnvOrNull(allocator, "TMP")) |v| return v;
        return allocator.dupe(u8, "C:\\Temp");
    } else {
        if (getEnvOrNull(allocator, "TMPDIR")) |v| return v;
        return allocator.dupe(u8, "/tmp");
    }
}

/// Returns the platform shell for executing commands.
pub fn getShell() []const u8 {
    return if (comptime builtin.os.tag == .windows) "cmd.exe" else "/bin/sh";
}

/// Returns the shell flag for passing a command string.
pub fn getShellFlag() []const u8 {
    return if (comptime builtin.os.tag == .windows) "/c" else "-c";
}

// ── Tests ────────────────────────────────────────────────────────

test "getEnvOrNull returns null for missing var" {
    try std.testing.expect(getEnvOrNull(std.testing.allocator, "NULLCLAW_NONEXISTENT_VAR_12345") == null);
}

test "setProcessEnv updates and clears process env var" {
    const allocator = std.testing.allocator;
    const name = "NULLCLAW_PLATFORM_TEST_ENV";
    const previous = getEnvOrNull(allocator, name);
    defer if (previous) |value| allocator.free(value);
    defer setProcessEnv(allocator, name, previous) catch @panic("failed to restore platform test env");

    try setProcessEnv(allocator, name, "value");
    const current = getEnvOrNull(allocator, name) orelse return error.TestUnexpectedResult;
    defer allocator.free(current);
    try std.testing.expectEqualStrings("value", current);

    try setProcessEnv(allocator, name, null);
    const cleared = getEnvOrNull(allocator, name);
    defer if (cleared) |value| allocator.free(value);
    try std.testing.expect(cleared == null);
}

test "getHomeDir returns a non-empty string" {
    const home = try getHomeDir(std.testing.allocator);
    defer std.testing.allocator.free(home);
    try std.testing.expect(home.len > 0);
}

test "getTempDir returns a non-empty string" {
    const tmp = try getTempDir(std.testing.allocator);
    defer std.testing.allocator.free(tmp);
    try std.testing.expect(tmp.len > 0);
}

test "getShell returns a known value" {
    const shell = getShell();
    try std.testing.expect(shell.len > 0);
}
