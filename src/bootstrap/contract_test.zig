// src/bootstrap/contract_test.zig
//! Contract tests verifying that every BootstrapProvider implementation
//! satisfies the interface invariants.

const std = @import("std");
const BootstrapProvider = @import("provider.zig").BootstrapProvider;
const FileBootstrapProvider = @import("file_provider.zig").FileBootstrapProvider;
const MemoryBootstrapProvider = @import("memory_provider.zig").MemoryBootstrapProvider;
const NullBootstrapProvider = @import("null_provider.zig").NullBootstrapProvider;
const memory_root = @import("../memory/root.zig");
const InMemoryLruMemory = memory_root.InMemoryLruMemory;

const testing = std.testing;

/// Shared contract: exercises the full BootstrapProvider surface.
/// Every persisting implementation must pass all checks.
fn runContractTests(bp: BootstrapProvider) !void {
    const allocator = testing.allocator;

    // 1. store + load
    try bp.store("SOUL.md", "# Soul v1");
    const loaded = try bp.load(allocator, "SOUL.md");
    defer if (loaded) |c| allocator.free(c);
    try testing.expectEqualStrings("# Soul v1", loaded.?);

    // 2. exists
    try testing.expect(bp.exists("SOUL.md"));
    try testing.expect(!bp.exists("AGENTS.md"));

    // 3. overwrite
    try bp.store("SOUL.md", "# Soul v2");
    const loaded2 = try bp.load(allocator, "SOUL.md");
    defer if (loaded2) |c| allocator.free(c);
    try testing.expectEqualStrings("# Soul v2", loaded2.?);

    // 3b. excerpt
    const excerpt = try bp.load_excerpt(allocator, "SOUL.md", 3);
    defer if (excerpt) |c| allocator.free(c);
    try testing.expectEqualStrings("# S", excerpt.?);

    // 4. list contains stored files
    try bp.store("AGENTS.md", "# Agents");
    const items = try bp.list(allocator);
    defer {
        for (items) |item| allocator.free(item);
        allocator.free(items);
    }
    try testing.expect(items.len >= 2);

    // 5. remove
    const removed = try bp.remove("SOUL.md");
    try testing.expect(removed);
    try testing.expect(!bp.exists("SOUL.md"));

    // 6. fingerprint changes
    const fp1 = try bp.fingerprint(allocator);
    try bp.store("IDENTITY.md", "# Id");
    const fp2 = try bp.fingerprint(allocator);
    try testing.expect(fp1 != fp2);

    // 7. load missing
    const missing = try bp.load(allocator, "TOOLS.md");
    try testing.expect(missing == null);

    // Cleanup: remove remaining entries for clean teardown.
    _ = try bp.remove("AGENTS.md");
    _ = try bp.remove("IDENTITY.md");
}

test "contract: FileBootstrapProvider" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir_path);

    var impl = FileBootstrapProvider.init(testing.allocator, dir_path);
    const bp = impl.provider();
    try runContractTests(bp);
}

test "contract: MemoryBootstrapProvider" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var impl = MemoryBootstrapProvider.init(testing.allocator, lru.memory(), null);
    const bp = impl.provider();
    try runContractTests(bp);
}

test "contract: NullBootstrapProvider has no-op semantics" {
    var impl = NullBootstrapProvider.init();
    const bp = impl.provider();

    // Null provider: store is no-op, load always null.
    try bp.store("SOUL.md", "content");
    const loaded = try bp.load(testing.allocator, "SOUL.md");
    try testing.expect(loaded == null);
    const excerpt = try bp.load_excerpt(testing.allocator, "SOUL.md", 3);
    try testing.expect(excerpt == null);
    try testing.expect(!bp.exists("SOUL.md"));

    // list returns empty.
    const items = try bp.list(testing.allocator);
    defer testing.allocator.free(items);
    try testing.expectEqual(@as(usize, 0), items.len);

    // remove returns false.
    const removed = try bp.remove("SOUL.md");
    try testing.expect(!removed);

    // fingerprint is always 0.
    const fp = try bp.fingerprint(testing.allocator);
    try testing.expectEqual(@as(u64, 0), fp);
}
