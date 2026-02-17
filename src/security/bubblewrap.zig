const std = @import("std");
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
        // bwrap --ro-bind /usr /usr --dev /dev --proc /proc --bind /tmp /tmp --bind WORKSPACE /workspace --unshare-all --die-with-parent <argv...>
        const prefix = [_][]const u8{
            "bwrap",
            "--ro-bind",
            "/usr",
            "/usr",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--bind",
            "/tmp",
            "/tmp",
            "--bind",
            self.workspace_dir,
            "/workspace",
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

    fn isAvailable(_: *anyopaque) bool {
        const builtin = @import("builtin");
        return comptime (builtin.os.tag == .linux);
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
    try std.testing.expect(result.len == 16);
}

test "bubblewrap buffer too small returns error" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [3][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "bubblewrap sandbox vtable consistent" {
    var bw = createBubblewrapSandbox("/tmp/workspace");
    const sb = bw.sandbox();
    try std.testing.expect(sb.vtable == &BubblewrapSandbox.sandbox_vtable);
}
