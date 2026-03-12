//! No-op bootstrap provider for `none` and `memory` (LRU) backends
//! where bootstrap documents are not persisted.

const std = @import("std");
const BootstrapProvider = @import("provider.zig").BootstrapProvider;

pub const NullBootstrapProvider = struct {
    allocator: std.mem.Allocator = undefined,
    owns_self: bool = false,

    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn deinit(_: *Self) void {}

    pub fn provider(self: *Self) BootstrapProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn implLoad(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!?[]const u8 {
        return null;
    }

    fn implLoadExcerpt(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: usize) anyerror!?[]const u8 {
        return null;
    }

    fn implStore(_: *anyopaque, _: []const u8, _: []const u8) anyerror!void {}

    fn implRemove(_: *anyopaque, _: []const u8) anyerror!bool {
        return false;
    }

    fn implExists(_: *anyopaque, _: []const u8) bool {
        return false;
    }

    fn implList(_: *anyopaque, allocator: std.mem.Allocator) anyerror![]const []const u8 {
        return allocator.alloc([]const u8, 0);
    }

    fn implFingerprint(_: *anyopaque, _: std.mem.Allocator) anyerror!u64 {
        return 0;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    const vtable = BootstrapProvider.VTable{
        .load = &implLoad,
        .load_excerpt = &implLoadExcerpt,
        .store = &implStore,
        .remove = &implRemove,
        .exists = &implExists,
        .list = &implList,
        .fingerprint = &implFingerprint,
        .deinit = &implDeinit,
    };
};

test "load returns null" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    const result = try bp.load(std.testing.allocator, "AGENTS.md");
    try std.testing.expect(result == null);
}

test "load_excerpt returns null" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    const result = try bp.load_excerpt(std.testing.allocator, "AGENTS.md", 4);
    try std.testing.expect(result == null);
}

test "store is no-op (no error)" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    try bp.store("AGENTS.md", "content");
}

test "exists returns false even after store" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    try bp.store("AGENTS.md", "content");
    try std.testing.expect(!bp.exists("AGENTS.md"));
}

test "remove returns false" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    const removed = try bp.remove("AGENTS.md");
    try std.testing.expect(!removed);
}

test "list returns empty" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    const items = try bp.list(std.testing.allocator);
    defer std.testing.allocator.free(items);
    try std.testing.expectEqual(@as(usize, 0), items.len);
}

test "fingerprint returns 0" {
    var np = NullBootstrapProvider.init();
    const bp = np.provider();
    const fp = try bp.fingerprint(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), fp);
}
