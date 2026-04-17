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

const testing = std.testing;

test "NoopSandbox is always available" {
    var ns = NoopSandbox{};
    try testing.expect(ns.sandbox().isAvailable());
}

test "NoopSandbox name is 'none'" {
    var ns = NoopSandbox{};
    try testing.expectEqualStrings("none", ns.sandbox().name());
}

test "NoopSandbox description is non-empty" {
    var ns = NoopSandbox{};
    const desc = ns.sandbox().description();
    try testing.expect(desc.len > 0);
}

test "NoopSandbox wrapCommand passes argv through unchanged" {
    var ns = NoopSandbox{};
    const sandbox = ns.sandbox();
    const argv = &[_][]const u8{ "echo", "hello" };
    var buf: [2][]const u8 = undefined;
    const result = try sandbox.wrapCommand(argv, &buf);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("echo", result[0]);
    try testing.expectEqualStrings("hello", result[1]);
}

test "NoopSandbox wrapCommand with empty argv" {
    var ns = NoopSandbox{};
    const sandbox = ns.sandbox();
    const argv: []const []const u8 = &.{};
    var buf: [0][]const u8 = undefined;
    const result = try sandbox.wrapCommand(argv, &buf);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "Sandbox interface dispatches to NoopSandbox correctly" {
    var ns = NoopSandbox{};
    const sb = ns.sandbox();
    try testing.expect(sb.isAvailable());
    try testing.expectEqualStrings("none", sb.name());
    try testing.expect(sb.description().len > 0);
}

test "createNoopSandbox returns functional sandbox" {
    var ns = createNoopSandbox();
    const sb = ns.sandbox();
    try testing.expect(sb.isAvailable());
    try testing.expectEqualStrings("none", sb.name());
}

test "SandboxBackend enum exhaustiveness" {
    const expected_names = [_][]const u8{
        "auto",
        "none",
        "landlock",
        "firejail",
        "bubblewrap",
        "docker",
    };
    const enum_fields = @typeInfo(SandboxBackend).@"enum".fields;
    try testing.expectEqual(expected_names.len, enum_fields.len);
    inline for (expected_names, 0..) |expected_name, i| {
        try testing.expectEqualStrings(expected_name, enum_fields[i].name);
    }
}
