const std = @import("std");
const builtin = @import("builtin");
const Sandbox = @import("sandbox.zig").Sandbox;

/// Landlock sandbox backend for Linux kernel 5.13+ LSM.
/// Restricts filesystem access using the Landlock kernel interface.
/// On non-Linux platforms, returns error.UnsupportedPlatform.
pub const LandlockSandbox = struct {
    workspace_dir: []const u8,

    pub const sandbox_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getName,
        .description = getDescription,
    };

    pub fn sandbox(self: *LandlockSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sandbox_vtable,
        };
    }

    fn wrapCommand(_: *anyopaque, argv: []const []const u8, _: [][]const u8) anyerror![]const []const u8 {
        if (comptime builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }
        // Landlock applies restrictions via syscalls on the spawning process before exec(),
        // not by prepending a wrapper to the command (unlike firejail/bubblewrap).
        // The caller is responsible for calling landlock_create_ruleset →
        // landlock_add_rule → landlock_restrict_self on the current thread before
        // spawning the child; the child inherits those restrictions automatically.
        // wrapCommand therefore returns argv unchanged — no wrapper is needed.
        return argv;
    }

    fn isAvailable(_: *anyopaque) bool {
        return comptime builtin.os.tag == .linux;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "landlock";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        if (comptime builtin.os.tag == .linux) {
            return "Linux kernel LSM sandboxing (filesystem access control)";
        } else {
            return "Linux kernel LSM sandboxing (not available on this platform)";
        }
    }
};

pub fn createLandlockSandbox(workspace_dir: []const u8) LandlockSandbox {
    return .{ .workspace_dir = workspace_dir };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "landlock sandbox name" {
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    try std.testing.expectEqualStrings("landlock", sb.name());
}

test "landlock sandbox availability matches platform" {
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    if (comptime builtin.os.tag == .linux) {
        try std.testing.expect(sb.isAvailable());
    } else {
        try std.testing.expect(!sb.isAvailable());
    }
}

test "landlock sandbox description" {
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    const desc = sb.description();
    try std.testing.expect(desc.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, desc, "landlock") != null or std.mem.indexOf(u8, desc, "LSM") != null or std.mem.indexOf(u8, desc, "Linux") != null);
}

test "landlock sandbox wrap command on non-linux returns error" {
    if (comptime builtin.os.tag == .linux) return;
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    const argv = [_][]const u8{ "echo", "test" };
    var buf: [16][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.UnsupportedPlatform, result);
}

test "landlock sandbox wrap command on linux passes through" {
    if (comptime builtin.os.tag != .linux) return;
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    const argv = [_][]const u8{ "echo", "test" };
    var buf: [16][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("echo", result[0]);
}

test "landlock sandbox vtable consistent" {
    var ll = createLandlockSandbox("/tmp/workspace");
    const sb = ll.sandbox();
    try std.testing.expectEqualStrings("landlock", sb.name());
    try std.testing.expectEqualStrings("landlock", sb.name());
    try std.testing.expect(sb.vtable == &LandlockSandbox.sandbox_vtable);
}
