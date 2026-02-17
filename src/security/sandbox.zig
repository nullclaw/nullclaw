const std = @import("std");

/// Sandbox backend vtable interface for OS-level isolation.
/// In Zig, we use a vtable pattern instead of Rust's trait objects.
pub const Sandbox = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Wrap a command with sandbox protection.
        /// Returns a modified argv or error.
        wrapCommand: *const fn (ctx: *anyopaque, argv: []const []const u8, buf: [][]const u8) anyerror![]const []const u8,
        /// Check if this sandbox backend is available on the current platform
        isAvailable: *const fn (ctx: *anyopaque) bool,
        /// Human-readable name of this sandbox backend
        name: *const fn (ctx: *anyopaque) []const u8,
        /// Description of what this sandbox provides
        description: *const fn (ctx: *anyopaque) []const u8,
    };

    pub fn wrapCommand(self: Sandbox, argv: []const []const u8, buf: [][]const u8) ![]const []const u8 {
        return self.vtable.wrapCommand(self.ptr, argv, buf);
    }

    pub fn isAvailable(self: Sandbox) bool {
        return self.vtable.isAvailable(self.ptr);
    }

    pub fn name(self: Sandbox) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn description(self: Sandbox) []const u8 {
        return self.vtable.description(self.ptr);
    }
};

/// No-op sandbox (always available, provides no additional isolation)
pub const NoopSandbox = struct {
    pub const sandbox_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getName,
        .description = getDescription,
    };

    pub fn sandbox(self: *NoopSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sandbox_vtable,
        };
    }

    fn wrapCommand(_: *anyopaque, argv: []const []const u8, _: [][]const u8) ![]const []const u8 {
        // Pass through unchanged
        return argv;
    }

    fn isAvailable(_: *anyopaque) bool {
        return true;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "none";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        return "No sandboxing (application-layer security only)";
    }
};

/// Create a noop sandbox (default fallback)
pub fn createNoopSandbox() NoopSandbox {
    return .{};
}

/// Re-export detect module's createSandbox for convenience.
pub const createSandbox = @import("detect.zig").createSandbox;
pub const SandboxBackend = @import("detect.zig").SandboxBackend;
pub const SandboxStorage = @import("detect.zig").SandboxStorage;
pub const detectAvailable = @import("detect.zig").detectAvailable;
pub const AvailableBackends = @import("detect.zig").AvailableBackends;

// ── Tests ──────────────────────────────────────────────────────────────

test "noop sandbox name" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();
    try std.testing.expectEqualStrings("none", sb.name());
}

test "noop sandbox is always available" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();
    try std.testing.expect(sb.isAvailable());
}

test "noop sandbox description" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();
    try std.testing.expectEqualStrings(
        "No sandboxing (application-layer security only)",
        sb.description(),
    );
}

test "noop sandbox wrap command is passthrough" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [16][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("echo", result[0]);
    try std.testing.expectEqualStrings("test", result[1]);
}

test "noop sandbox wrap empty argv" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();

    const argv = [_][]const u8{};
    var buf: [16][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "noop sandbox wrap single arg" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();

    const argv = [_][]const u8{"ls"};
    var buf: [16][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("ls", result[0]);
}

test "noop sandbox wrap many args" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();

    const argv = [_][]const u8{ "git", "commit", "-m", "test message", "--no-edit" };
    var buf: [16][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualStrings("git", result[0]);
    try std.testing.expectEqualStrings("--no-edit", result[4]);
}

test "noop sandbox vtable consistent" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();
    // Multiple calls should give same results
    try std.testing.expectEqualStrings("none", sb.name());
    try std.testing.expectEqualStrings("none", sb.name());
    try std.testing.expect(sb.isAvailable());
    try std.testing.expect(sb.isAvailable());
}

test "create noop sandbox returns valid struct" {
    var noop = createNoopSandbox();
    const sb = noop.sandbox();
    // vtable should point to the static sandbox_vtable
    try std.testing.expect(sb.vtable == &NoopSandbox.sandbox_vtable);
    // Should be usable
    try std.testing.expectEqualStrings("none", sb.name());
}
