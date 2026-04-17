const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");

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
