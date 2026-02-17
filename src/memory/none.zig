//! Explicit no-op memory backend.
//!
//! Used when `memory.backend = "none"` to disable persistence
//! while keeping the runtime wiring stable.

const std = @import("std");
const root = @import("root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

pub const NoneMemory = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn deinit(_: *Self) void {}

    fn implName(_: *anyopaque) []const u8 {
        return "none";
    }

    fn implStore(_: *anyopaque, _: []const u8, _: []const u8, _: MemoryCategory) anyerror!void {}

    fn implRecall(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize) anyerror![]MemoryEntry {
        return allocator.alloc(MemoryEntry, 0);
    }

    fn implGet(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!?MemoryEntry {
        return null;
    }

    fn implList(_: *anyopaque, allocator: std.mem.Allocator, _: ?MemoryCategory) anyerror![]MemoryEntry {
        return allocator.alloc(MemoryEntry, 0);
    }

    fn implForget(_: *anyopaque, _: []const u8) anyerror!bool {
        return false;
    }

    fn implCount(_: *anyopaque) anyerror!usize {
        return 0;
    }

    fn implHealthCheck(_: *anyopaque) bool {
        return true;
    }

    fn implDeinit(_: *anyopaque) void {}

    const vtable = Memory.VTable{
        .name = &implName,
        .store = &implStore,
        .recall = &implRecall,
        .get = &implGet,
        .list = &implList,
        .forget = &implForget,
        .count = &implCount,
        .healthCheck = &implHealthCheck,
        .deinit = &implDeinit,
    };

    pub fn memory(self: *Self) Memory {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "none memory is noop" {
    var mem = NoneMemory.init();
    defer mem.deinit();
    const m = mem.memory();

    try std.testing.expectEqualStrings("none", m.name());

    try m.store("k", "v", .core);

    const got = try m.get(std.testing.allocator, "k");
    try std.testing.expect(got == null);

    const recalled = try m.recall(std.testing.allocator, "k", 10);
    defer std.testing.allocator.free(recalled);
    try std.testing.expectEqual(@as(usize, 0), recalled.len);

    const listed = try m.list(std.testing.allocator, null);
    defer std.testing.allocator.free(listed);
    try std.testing.expectEqual(@as(usize, 0), listed.len);

    const forgotten = try m.forget("k");
    try std.testing.expect(!forgotten);

    try std.testing.expectEqual(@as(usize, 0), try m.count());

    try std.testing.expect(m.healthCheck());
}

test "none memory count always zero" {
    var mem = NoneMemory.init();
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "b", .core);
    try m.store("c", "d", .daily);

    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

test "none memory list always empty" {
    var mem = NoneMemory.init();
    defer mem.deinit();
    const m = mem.memory();

    try m.store("key", "value", .core);

    const core_list = try m.list(std.testing.allocator, .core);
    defer std.testing.allocator.free(core_list);
    try std.testing.expectEqual(@as(usize, 0), core_list.len);

    const all_list = try m.list(std.testing.allocator, null);
    defer std.testing.allocator.free(all_list);
    try std.testing.expectEqual(@as(usize, 0), all_list.len);
}

test "none memory recall always empty" {
    var mem = NoneMemory.init();
    defer mem.deinit();
    const m = mem.memory();

    try m.store("searchable", "find me", .core);

    const results = try m.recall(std.testing.allocator, "find", 10);
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "none memory get always null" {
    var mem = NoneMemory.init();
    defer mem.deinit();
    const m = mem.memory();

    try m.store("existing", "value", .core);

    const result = try m.get(std.testing.allocator, "existing");
    try std.testing.expect(result == null);
}
