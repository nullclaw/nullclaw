const std = @import("std");
const builtin = @import("builtin");
const probe = @import("probe.zig");
const Sandbox = @import("sandbox.zig").Sandbox;

/// Bubblewrap (bwrap) sandbox backend.
/// Wraps commands with `bwrap` for user-namespace isolation.
pub const BubblewrapSandbox = struct {
    workspace_dir: []const u8,

    pub const sandbox_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getName,
        .description = getDescription,
    };

    pub fn sandbox(self: *BubblewrapSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sandbox_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *BubblewrapSandbox {
        return @ptrCast(@alignCast(ptr));
    }

    fn wrapCommand(ptr: *anyopaque, argv: []const []const u8, buf: [][]const u8) anyerror![]const []const u8 {
        const self = resolve(ptr);
        // Keep the host shell/runtime paths visible so `/bin/sh -c ...` still
        // works after ShellTool wraps commands with bubblewrap.
        const prefix = [_][]const u8{
            "bwrap",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--bind",
            "/tmp",
            "/tmp",
            "--bind",
            self.workspace_dir,
            self.workspace_dir,
            "--unshare-all",
            "--die-with-parent",
        };
        const prefix_len = prefix.len;

        if (buf.len < prefix_len + argv.len) return error.BufferTooSmall;

        for (prefix, 0..) |p, i| {
            buf[i] = p;
        }
        for (argv, 0..) |arg, i| {
            buf[prefix_len + i] = arg;
        }
        return buf[0 .. prefix_len + argv.len];
    }

    fn isAvailable(ptr: *anyopaque) bool {
        if (comptime builtin.os.tag != .linux) return false;
        const smoke_argv = [_][]const u8{ "/bin/sh", "-c", "exit 0" };
        var wrapped_argv: [32][]const u8 = undefined;
        // Probe the same wrapper argv we execute later so auto-detect does not
        // advertise bubblewrap when the host cannot actually sandbox a command.
        const argv = wrapCommand(ptr, &smoke_argv, &wrapped_argv) catch return false;
        return probe.runQuietCommand(argv);
    }

    fn getName(_: *anyopaque) []const u8 {
        return "bubblewrap";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        return "User namespace sandbox (requires bwrap)";
    }
};

pub fn createBubblewrapSandbox(workspace_dir: []const u8) BubblewrapSandbox {
    return .{ .workspace_dir = workspace_dir };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "bubblewrap sandbox name" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();
    try std.testing.expectEqualStrings("bubblewrap", sb.name());
}

test "bubblewrap sandbox description mentions bwrap" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();
    const desc = sb.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "bwrap") != null);
}

test "bubblewrap sandbox wrap command prepends bwrap args" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("bwrap", result[0]);
    try std.testing.expectEqualStrings("--ro-bind", result[1]);
    try std.testing.expectEqualStrings("/usr", result[2]);
    try std.testing.expectEqualStrings("/usr", result[3]);
    try std.testing.expectEqualStrings("--ro-bind-try", result[4]);
    try std.testing.expectEqualStrings("/bin", result[5]);
    try std.testing.expectEqualStrings("/bin", result[6]);
    // Original command is at the end
    try std.testing.expectEqualStrings("echo", result[result.len - 2]);
    try std.testing.expectEqualStrings("test", result[result.len - 1]);
}

test "bubblewrap sandbox wrap includes unshare and die-with-parent" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{"ls"};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    var has_unshare = false;
    var has_die = false;
    for (result) |arg| {
        if (std.mem.eql(u8, arg, "--unshare-all")) has_unshare = true;
        if (std.mem.eql(u8, arg, "--die-with-parent")) has_die = true;
    }
    try std.testing.expect(has_unshare);
    try std.testing.expect(has_die);
}

test "bubblewrap sandbox wrap empty argv" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    // Just the prefix args, no original command
    try std.testing.expectEqualStrings("bwrap", result[0]);
    try std.testing.expect(result.len == 25);
}

test "bubblewrap buffer too small returns error" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [3][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "bubblewrap sandbox preserves workspace path for process cwd" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{ "/bin/sh", "-c", "printf test" };
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    // Regression: ShellTool sets cwd before spawning bwrap, so the workspace
    // must remain mounted at its original absolute path inside the sandbox.
    try std.testing.expectEqualStrings("--bind", result[20]);
    try std.testing.expectEqualStrings("/tmp/workspace", result[21]);
    try std.testing.expectEqualStrings("/tmp/workspace", result[22]);
    try std.testing.expectEqualStrings("/bin/sh", result[result.len - 3]);
}

test "bubblewrap sandbox availability requires executable in PATH" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expect(!sb.isAvailable());
        return;
    }

    const platform = @import("../platform.zig");
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    const key_z = try std.testing.allocator.dupeZ(u8, "PATH");
    defer std.testing.allocator.free(key_z);

    const old_path = platform.getEnvOrNull(std.testing.allocator, "PATH");
    defer if (old_path) |path| std.testing.allocator.free(path);

    const old_path_z = if (old_path) |path| try std.testing.allocator.dupeZ(u8, path) else null;
    defer if (old_path_z) |path| std.testing.allocator.free(path);

    defer {
        if (old_path_z) |path| {
            _ = c.setenv(key_z.ptr, path.ptr, 1);
        } else {
            _ = c.unsetenv(key_z.ptr);
        }
    }

    const empty_z = try std.testing.allocator.dupeZ(u8, "");
    defer std.testing.allocator.free(empty_z);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key_z.ptr, empty_z.ptr, 1));
    try std.testing.expect(!sb.isAvailable());
}
