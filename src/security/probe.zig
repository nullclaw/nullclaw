const std = @import("std");
const std_compat = @import("compat");

/// Run a probe command with stdio suppressed and treat exit code 0 as success.
pub fn runQuietCommand(argv: []const []const u8) bool {
    var child = std_compat.process.Child.init(argv, std.heap.page_allocator);
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stdin_behavior = .Ignore;
    child.spawn() catch return false;
    const term = child.wait() catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "runQuietCommand reports child exit status" {
    const platform = @import("../platform.zig");
    try std.testing.expect(runQuietCommand(&.{ platform.getShell(), platform.getShellFlag(), "exit 0" }));
    try std.testing.expect(!runQuietCommand(&.{ platform.getShell(), platform.getShellFlag(), "exit 9" }));
}
