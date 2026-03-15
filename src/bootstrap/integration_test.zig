// src/bootstrap/integration_test.zig
//! Integration tests for the bootstrap provider factory and full lifecycle.

const std = @import("std");
const bootstrap_root = @import("root.zig");
const memory_root = @import("../memory/root.zig");
const InMemoryLruMemory = memory_root.InMemoryLruMemory;

const testing = std.testing;

test "factory creates working FileBootstrapProvider for hybrid backend" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir_path);

    const bp = try bootstrap_root.createProvider(testing.allocator, "hybrid", null, dir_path);
    defer bp.deinit();

    try bp.store("SOUL.md", "# Test Soul");
    const loaded = try bp.load(testing.allocator, "SOUL.md");
    defer if (loaded) |c| testing.allocator.free(c);
    try testing.expectEqualStrings("# Test Soul", loaded.?);

    // Verify file actually exists on disk.
    const file_path = try std.fs.path.join(testing.allocator, &.{ dir_path, "SOUL.md" });
    defer testing.allocator.free(file_path);
    const f = try std.fs.openFileAbsolute(file_path, .{});
    f.close();
}

test "factory creates working MemoryBootstrapProvider for sqlite backend" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    const bp = try bootstrap_root.createProvider(testing.allocator, "sqlite", lru.memory(), null);
    defer bp.deinit();

    try bp.store("AGENTS.md", "# Agent Config");
    const loaded = try bp.load(testing.allocator, "AGENTS.md");
    defer if (loaded) |c| testing.allocator.free(c);
    try testing.expectEqualStrings("# Agent Config", loaded.?);

    // Verify it lives in memory, not on disk.
    try testing.expect(bp.exists("AGENTS.md"));
}

test "MemoryBootstrapProvider disk fallback works via factory" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a bootstrap file to disk first.
    tmp.dir.writeFile(.{ .sub_path = "IDENTITY.md", .data = "# Disk Identity" }) catch unreachable;

    const workspace = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(workspace);

    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    // Create a DB-backed provider with workspace fallback.
    const bp = try bootstrap_root.createProvider(testing.allocator, "sqlite", lru.memory(), workspace);
    defer bp.deinit();

    // Load should find the file via disk fallback.
    const loaded = try bp.load(testing.allocator, "IDENTITY.md");
    defer if (loaded) |c| testing.allocator.free(c);
    try testing.expectEqualStrings("# Disk Identity", loaded.?);
}

test "factory creates NullBootstrapProvider for none backend" {
    const bp = try bootstrap_root.createProvider(testing.allocator, "none", null, null);
    defer bp.deinit();

    try bp.store("SOUL.md", "content");
    const loaded = try bp.load(testing.allocator, "SOUL.md");
    try testing.expect(loaded == null);
}

test "factory creates NullBootstrapProvider for memory backend" {
    const bp = try bootstrap_root.createProvider(testing.allocator, "memory", null, null);
    defer bp.deinit();

    try bp.store("AGENTS.md", "content");
    const loaded = try bp.load(testing.allocator, "AGENTS.md");
    try testing.expect(loaded == null);
}
