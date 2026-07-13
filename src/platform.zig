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

/// Test-only guard for process-wide environment mutations. Captures all named
/// variables and restores them on deinit, including values inherited from the
/// developer shell or CI runner.
pub const TestEnvGuard = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    const Entry = struct {
        name: []const u8,
        value: ?[]u8,
    };

    pub fn capture(allocator: std.mem.Allocator, names: []const []const u8) !TestEnvGuard {
        const entries = try allocator.alloc(Entry, names.len);
        var initialized: usize = 0;
        errdefer {
            for (entries[0..initialized]) |entry| {
                if (entry.value) |value| allocator.free(value);
            }
            allocator.free(entries);
        }

        for (names, 0..) |name, i| {
            const value = std_compat.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
                error.EnvironmentVariableNotFound => null,
                else => return err,
            };
            entries[i] = .{ .name = name, .value = value };
            initialized += 1;
        }
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn clear(self: *const TestEnvGuard) !void {
        for (self.entries) |entry| {
            try setProcessEnv(self.allocator, entry.name, null);
        }
    }

    pub fn captureAndClear(allocator: std.mem.Allocator, names: []const []const u8) !TestEnvGuard {
        var guard = try capture(allocator, names);
        errdefer guard.deinit();
        try guard.clear();
        return guard;
    }

    pub fn deinit(self: *TestEnvGuard) void {
        var restore_failed = false;
        for (self.entries) |entry| {
            setProcessEnv(self.allocator, entry.name, entry.value) catch {
                restore_failed = true;
            };
            if (entry.value) |value| self.allocator.free(value);
        }
        self.allocator.free(self.entries);
        if (restore_failed) @panic("failed to restore test process environment");
    }
};

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

test "TestEnvGuard restores inherited values" {
    const allocator = std.testing.allocator;
    const name = "NULLCLAW_PLATFORM_GUARD_TEST_ENV";
    var outer = try TestEnvGuard.capture(allocator, &.{name});
    defer outer.deinit();

    try setProcessEnv(allocator, name, "original");
    {
        var guard = try TestEnvGuard.captureAndClear(allocator, &.{name});
        defer guard.deinit();
        const cleared = getEnvOrNull(allocator, name);
        defer if (cleared) |value| allocator.free(value);
        try std.testing.expect(cleared == null);
        try setProcessEnv(allocator, name, "mutated");
    }

    const restored = getEnvOrNull(allocator, name) orelse return error.TestUnexpectedResult;
    defer allocator.free(restored);
    try std.testing.expectEqualStrings("original", restored);
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
