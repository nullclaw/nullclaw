//! In-memory LRU memory backend.
//!
//! Pure in-memory store with LRU eviction — no disk I/O, no external
//! dependencies.  Ideal for testing, CI, and ephemeral sessions.

const std = @import("std");
const std_compat = @import("compat");
const root = @import("../root.zig");
const key_codec = @import("../vector/key_codec.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

pub const InMemoryLruMemory = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(StoredEntry),
    max_entries: usize,
    access_counter: u64,
    owns_self: bool = false,

    const Self = @This();

    const StoredEntry = struct {
        key: []const u8,
        content: []const u8,
        category: MemoryCategory,
        session_id: ?[]const u8,
        created_at: []const u8,
        updated_at: []const u8,
        last_access: u64,
    };

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) Self {
        return .{
            .allocator = allocator,
            .entries = .{},
            .max_entries = max_entries,
            .access_counter = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.freeStoredEntry(kv.value_ptr.*);
            self.allocator.free(kv.key_ptr.*);
        }
        self.entries.deinit(self.allocator);
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn freeStoredEntry(self: *Self, entry: StoredEntry) void {
        self.allocator.free(entry.key);
        self.allocator.free(entry.content);
        self.allocator.free(entry.created_at);
        self.allocator.free(entry.updated_at);
        if (entry.session_id) |sid| self.allocator.free(sid);
        switch (entry.category) {
            .custom => |name| self.allocator.free(name),
            else => {},
        }
    }

    fn nextAccess(self: *Self) u64 {
        self.access_counter += 1;
        return self.access_counter;
    }

    fn evictLru(self: *Self) void {
        var min_access: u64 = std.math.maxInt(u64);
        var evict_key: ?[]const u8 = null;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.last_access < min_access) {
                min_access = kv.value_ptr.last_access;
                evict_key = kv.key_ptr.*;
            }
        }
        if (evict_key) |key| {
            if (self.entries.fetchRemove(key)) |removed| {
                self.freeStoredEntry(removed.value);
                self.allocator.free(removed.key);
            }
        }
    }

    fn nowTimestamp(self: *Self) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{d}", .{std_compat.time.timestamp()});
    }

    fn dupCategory(self: *Self, cat: MemoryCategory) !MemoryCategory {
        return switch (cat) {
            .custom => |name| .{ .custom = try self.allocator.dupe(u8, name) },
            else => cat,
        };
    }

    fn cloneEntry(allocator: std.mem.Allocator, e: StoredEntry) !MemoryEntry {
        const id = try allocator.dupe(u8, e.key);
        errdefer allocator.free(id);
        const dup_key = try allocator.dupe(u8, e.key);
        errdefer allocator.free(dup_key);
        const dup_content = try allocator.dupe(u8, e.content);
        errdefer allocator.free(dup_content);
        const dup_cat: MemoryCategory = switch (e.category) {
            .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
            else => e.category,
        };
        errdefer switch (dup_cat) {
            .custom => |name| allocator.free(name),
            else => {},
        };
        const dup_ts = try allocator.dupe(u8, e.updated_at);
        errdefer allocator.free(dup_ts);
        const dup_sid = if (e.session_id) |sid| try allocator.dupe(u8, sid) else null;
        errdefer if (dup_sid) |sid| allocator.free(sid);

        return .{
            .id = id,
            .key = dup_key,
            .content = dup_content,
            .category = dup_cat,
            .timestamp = dup_ts,
            .session_id = dup_sid,
            .score = null,
        };
    }

    fn findDefaultEntryPtr(self: *Self, key: []const u8) ?*StoredEntry {
        var best: ?*StoredEntry = null;
        var best_is_global = false;
        var best_access: u64 = 0;

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (!std.mem.eql(u8, kv.value_ptr.key, key)) continue;
            const is_global = kv.value_ptr.session_id == null;
            if (best == null or
                (is_global and !best_is_global) or
                (is_global == best_is_global and kv.value_ptr.last_access > best_access))
            {
                best = kv.value_ptr;
                best_is_global = is_global;
                best_access = kv.value_ptr.last_access;
            }
        }

        return best;
    }

    // ── vtable impl fns ────────────────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "memory_lru";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const storage_key = try key_codec.encode(self_.allocator, key, session_id);
        errdefer self_.allocator.free(storage_key);

        if (self_.entries.getPtr(storage_key)) |existing| {
            defer self_.allocator.free(storage_key);
            // Upsert: update existing entry in-place.
            self_.allocator.free(existing.content);
            existing.content = try self_.allocator.dupe(u8, content);

            self_.allocator.free(existing.updated_at);
            existing.updated_at = try self_.nowTimestamp();

            // Update category
            switch (existing.category) {
                .custom => |name| self_.allocator.free(name),
                else => {},
            }
            existing.category = try self_.dupCategory(category);

            // Update session_id
            if (existing.session_id) |sid| self_.allocator.free(sid);
            existing.session_id = if (session_id) |sid| try self_.allocator.dupe(u8, sid) else null;

            existing.last_access = self_.nextAccess();
            return;
        }

        // New entry — reject if capacity is zero, evict if at capacity.
        if (self_.max_entries == 0) return;
        if (self_.entries.count() >= self_.max_entries) {
            self_.evictLru();
        }

        const ts = try self_.nowTimestamp();
        errdefer self_.allocator.free(ts);

        const ts2 = try self_.allocator.dupe(u8, ts);
        errdefer self_.allocator.free(ts2);

        const stored_key = try self_.allocator.dupe(u8, key);
        errdefer self_.allocator.free(stored_key);

        const stored_content = try self_.allocator.dupe(u8, content);
        errdefer self_.allocator.free(stored_content);

        const stored_cat = try self_.dupCategory(category);
        errdefer switch (stored_cat) {
            .custom => |name| self_.allocator.free(name),
            else => {},
        };

        const stored_sid = if (session_id) |sid| try self_.allocator.dupe(u8, sid) else null;
        errdefer if (stored_sid) |sid| self_.allocator.free(sid);

        const stored = StoredEntry{
            .key = stored_key,
            .content = stored_content,
            .category = stored_cat,
            .session_id = stored_sid,
            .created_at = ts,
            .updated_at = ts2,
            .last_access = self_.nextAccess(),
        };

        try self_.entries.put(self_.allocator, storage_key, stored);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        // Collect matches via substring search on key and content.
        const Pair = struct { entry: StoredEntry, map_key: []const u8 };
        var matches: std.ArrayList(Pair) = .empty;
        defer matches.deinit(allocator);

        var it = self_.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            // Session filter
            if (session_id) |filter_sid| {
                if (e.session_id) |esid| {
                    if (!std.mem.eql(u8, esid, filter_sid)) continue;
                } else continue;
            }
            // Substring match on key or content
            if (std.mem.indexOf(u8, e.key, query) != null or
                std.mem.indexOf(u8, e.content, query) != null)
            {
                try matches.append(allocator, .{ .entry = e, .map_key = kv.key_ptr.* });
            }
        }

        // Sort by last_access descending (most recent first).
        std.mem.sort(Pair, matches.items, {}, struct {
            fn lessThan(_: void, a: Pair, b: Pair) bool {
                return a.entry.last_access > b.entry.last_access;
            }
        }.lessThan);

        const result_len = @min(matches.items.len, limit);
        const results = try allocator.alloc(MemoryEntry, result_len);
        var filled: usize = 0;
        errdefer {
            for (results[0..filled]) |*e| e.deinit(allocator);
            allocator.free(results);
        }

        for (results, 0..) |*slot, i| {
            const src = matches.items[i].entry;
            slot.* = try cloneEntry(allocator, src);
            filled += 1;
        }

        return results;
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const entry_ptr = self_.findDefaultEntryPtr(key) orelse return null;

        // Update access timestamp.
        entry_ptr.last_access = self_.nextAccess();

        return try cloneEntry(allocator, entry_ptr.*);
    }

    fn implGetScoped(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, session_id: ?[]const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const storage_key = try key_codec.encode(allocator, key, session_id);
        defer allocator.free(storage_key);

        const entry_ptr = self_.entries.getPtr(storage_key) orelse return null;
        entry_ptr.last_access = self_.nextAccess();
        return try cloneEntry(allocator, entry_ptr.*);
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var results: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*e| e.deinit(allocator);
            results.deinit(allocator);
        }

        var it = self_.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;

            // Category filter
            if (category) |cat| {
                if (!e.category.eql(cat)) continue;
            }

            // Session filter
            if (session_id) |filter_sid| {
                if (e.session_id) |esid| {
                    if (!std.mem.eql(u8, esid, filter_sid)) continue;
                } else continue;
            }

            try results.append(allocator, try cloneEntry(allocator, e));
        }

        return results.toOwnedSlice(allocator);
    }

    fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8, limit: usize, offset: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var results: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*e| e.deinit(allocator);
            results.deinit(allocator);
        }

        var skipped: usize = 0;
        var it = self_.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;

            if (category) |cat| {
                if (!e.category.eql(cat)) continue;
            }

            if (session_id) |filter_sid| {
                if (e.session_id) |esid| {
                    if (!std.mem.eql(u8, esid, filter_sid)) continue;
                } else continue;
            }

            if (skipped < offset) {
                skipped += 1;
                continue;
            }
            if (results.items.len >= limit) break;
            try results.append(allocator, try cloneEntry(allocator, e));
        }

        return results.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        var keys_to_remove: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (keys_to_remove.items) |storage_key| self_.allocator.free(storage_key);
            keys_to_remove.deinit(self_.allocator);
        }

        var it = self_.entries.iterator();
        while (it.next()) |kv| {
            if (!std.mem.eql(u8, kv.value_ptr.key, key)) continue;
            try keys_to_remove.append(self_.allocator, try self_.allocator.dupe(u8, kv.key_ptr.*));
        }

        var removed_any = false;
        for (keys_to_remove.items) |storage_key| {
            if (self_.entries.fetchRemove(storage_key)) |removed| {
                self_.freeStoredEntry(removed.value);
                self_.allocator.free(removed.key);
                removed_any = true;
            }
        }

        return removed_any;
    }

    fn implForgetScoped(ptr: *anyopaque, key: []const u8, session_id: ?[]const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const storage_key = try key_codec.encode(self_.allocator, key, session_id);
        defer self_.allocator.free(storage_key);

        const removed = self_.entries.fetchRemove(storage_key) orelse return false;
        self_.freeStoredEntry(removed.value);
        self_.allocator.free(removed.key);
        return true;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.entries.count();
    }

    fn implHealthCheck(_: *anyopaque) bool {
        return true;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        self_.deinit();
    }

    const vtable = Memory.VTable{
        .name = &implName,
        .store = &implStore,
        .recall = &implRecall,
        .get = &implGet,
        .getScoped = &implGetScoped,
        .list = &implList,
        .listPaged = &implListPaged,
        .forget = &implForget,
        .forgetScoped = &implForgetScoped,
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

test "empty state: get returns null, recall returns empty, count=0" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 10);
    defer mem.deinit();
    const m = mem.memory();

    try std.testing.expectEqualStrings("memory_lru", m.name());
    try std.testing.expect(m.healthCheck());
    try std.testing.expectEqual(@as(usize, 0), try m.count());

    const got = try m.get(std.testing.allocator, "nonexistent");
    try std.testing.expect(got == null);

    const recalled = try m.recall(std.testing.allocator, "anything", 10, null);
    defer std.testing.allocator.free(recalled);
    try std.testing.expectEqual(@as(usize, 0), recalled.len);

    const listed = try m.list(std.testing.allocator, null, null);
    defer std.testing.allocator.free(listed);
    try std.testing.expectEqual(@as(usize, 0), listed.len);
}

test "basic store/get/recall/forget cycle" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    // Store
    try m.store("greeting", "hello world", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    // Get
    {
        const entry = (try m.get(std.testing.allocator, "greeting")).?;
        defer entry.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("greeting", entry.key);
        try std.testing.expectEqualStrings("hello world", entry.content);
        try std.testing.expect(entry.category.eql(.core));
    }

    // Recall via substring
    {
        const results = try m.recall(std.testing.allocator, "hello", 10, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqualStrings("hello world", results[0].content);
    }

    // Forget
    const forgotten = try m.forget("greeting");
    try std.testing.expect(forgotten);
    try std.testing.expectEqual(@as(usize, 0), try m.count());

    // Forget nonexistent returns false
    const forgotten2 = try m.forget("greeting");
    try std.testing.expect(!forgotten2);
}

test "update existing key within same namespace" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("key1", "original", .core, "sess-1");
    try m.store("key1", "updated", .daily, "sess-1");
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    const entry = (try m.getScoped(std.testing.allocator, "key1", "sess-1")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("updated", entry.content);
    try std.testing.expect(entry.category.eql(.daily));
    try std.testing.expectEqualStrings("sess-1", entry.session_id.?);
}

test "LRU eviction: oldest entry evicted at capacity" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 3);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "first", .core, null);
    try m.store("b", "second", .core, null);
    try m.store("c", "third", .core, null);
    try std.testing.expectEqual(@as(usize, 3), try m.count());

    // Adding a 4th should evict "a" (oldest)
    try m.store("d", "fourth", .core, null);
    try std.testing.expectEqual(@as(usize, 3), try m.count());

    const got_a = try m.get(std.testing.allocator, "a");
    try std.testing.expect(got_a == null);

    const got_d = (try m.get(std.testing.allocator, "d")).?;
    defer got_d.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("fourth", got_d.content);
}

test "eviction order: accessing middle entry protects it" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 3);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "first", .core, null);
    try m.store("b", "second", .core, null);
    try m.store("c", "third", .core, null);

    // Access "a" — moves it to front, so "b" becomes the LRU candidate.
    {
        const entry = (try m.get(std.testing.allocator, "a")).?;
        defer entry.deinit(std.testing.allocator);
    }

    // Insert "d", should evict "b" (least recently accessed)
    try m.store("d", "fourth", .core, null);
    try std.testing.expectEqual(@as(usize, 3), try m.count());

    const got_b = try m.get(std.testing.allocator, "b");
    try std.testing.expect(got_b == null);

    // "a" is still alive
    const got_a = (try m.get(std.testing.allocator, "a")).?;
    defer got_a.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("first", got_a.content);
}

test "recall with substring matching" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("user_pref", "dark mode enabled", .core, null);
    try m.store("api_key", "sk-12345", .core, null);
    try m.store("note", "remember to buy milk", .daily, null);

    // Search for "mode" — matches "dark mode enabled"
    {
        const results = try m.recall(std.testing.allocator, "mode", 10, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqualStrings("user_pref", results[0].key);
    }

    // Search for "key" — matches key "api_key"
    {
        const results = try m.recall(std.testing.allocator, "key", 10, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqualStrings("api_key", results[0].key);
    }

    // Search for "e" — matches all three
    {
        const results = try m.recall(std.testing.allocator, "e", 10, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 3), results.len);
    }
}

test "recall with session_id filter" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "data for session A", .core, "sess-A");
    try m.store("k2", "data for session B", .core, "sess-B");
    try m.store("k3", "data no session", .core, null);

    // Filter to sess-A
    {
        const results = try m.recall(std.testing.allocator, "data", 10, "sess-A");
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqualStrings("k1", results[0].key);
    }

    // No filter — all match
    {
        const results = try m.recall(std.testing.allocator, "data", 10, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 3), results.len);
    }
}

test "list by category filter" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("core1", "c1", .core, null);
    try m.store("core2", "c2", .core, null);
    try m.store("daily1", "d1", .daily, null);
    try m.store("conv1", "v1", .conversation, null);

    // List core only
    {
        const results = try m.list(std.testing.allocator, .core, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 2), results.len);
    }

    // List daily only
    {
        const results = try m.list(std.testing.allocator, .daily, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
    }

    // List all (no filter)
    {
        const results = try m.list(std.testing.allocator, null, null);
        defer root.freeEntries(std.testing.allocator, results);
        try std.testing.expectEqual(@as(usize, 4), results.len);
    }
}

test "count accuracy after store/forget" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try std.testing.expectEqual(@as(usize, 0), try m.count());
    try m.store("a", "1", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());
    try m.store("b", "2", .core, null);
    try std.testing.expectEqual(@as(usize, 2), try m.count());
    _ = try m.forget("a");
    try std.testing.expectEqual(@as(usize, 1), try m.count());
    _ = try m.forget("b");
    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

test "session_id accepted on store" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, "session-42");

    const recalled = try m.recall(std.testing.allocator, "v", 10, "session-42");
    defer root.freeEntries(std.testing.allocator, recalled);
    try std.testing.expectEqual(@as(usize, 1), recalled.len);

    const listed = try m.list(std.testing.allocator, null, "session-42");
    defer root.freeEntries(std.testing.allocator, listed);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
}

test "same logical key can exist in global and scoped namespaces" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("shared", "global", .core, null);
    try m.store("shared", "scoped", .core, "sess-a");

    const global_entry = (try m.getScoped(std.testing.allocator, "shared", null)).?;
    defer global_entry.deinit(std.testing.allocator);
    try std.testing.expect(global_entry.session_id == null);
    try std.testing.expectEqualStrings("global", global_entry.content);

    const scoped_entry = (try m.getScoped(std.testing.allocator, "shared", "sess-a")).?;
    defer scoped_entry.deinit(std.testing.allocator);
    try std.testing.expect(scoped_entry.session_id != null);
    try std.testing.expectEqualStrings("sess-a", scoped_entry.session_id.?);
    try std.testing.expectEqualStrings("scoped", scoped_entry.content);
}

test "forgetScoped removes only matching namespace in LRU" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("shared", "global", .core, null);
    try m.store("shared", "scoped", .core, "sess-a");

    try std.testing.expect(try m.forgetScoped(std.testing.allocator, "shared", "sess-a"));
    try std.testing.expect(try m.getScoped(std.testing.allocator, "shared", "sess-a") == null);

    const global_entry = (try m.getScoped(std.testing.allocator, "shared", null)).?;
    defer global_entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("global", global_entry.content);
}

test "recall respects limit" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "data", .core, null);
    try m.store("b", "data", .core, null);
    try m.store("c", "data", .core, null);

    const results = try m.recall(std.testing.allocator, "data", 2, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "custom category preserved" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .{ .custom = "my_cat" }, null);
    const entry = (try m.get(std.testing.allocator, "k")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("my_cat", entry.category.custom);
}

// ── R3 deep review tests ──────────────────────────────────────────

test "LRU store and get with empty key" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("", "content for empty key", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    const entry = (try m.get(std.testing.allocator, "")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", entry.key);
    try std.testing.expectEqualStrings("content for empty key", entry.content);
}

test "LRU store and get with empty content" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "", .core, null);
    const entry = (try m.get(std.testing.allocator, "k")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", entry.content);
}

test "LRU store with special chars in key and content" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    const key = "key with \"quotes\" and 'apostrophes' and %wildcards%";
    const content = "line1\nline2\ttab\r\nwindows";
    try m.store(key, content, .core, null);

    const entry = (try m.get(std.testing.allocator, key)).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(key, entry.key);
    try std.testing.expectEqualStrings(content, entry.content);
}

test "LRU recall with empty query matches everything" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "alpha", .core, null);
    try m.store("b", "beta", .core, null);

    // Empty string is substring of everything
    const results = try m.recall(std.testing.allocator, "", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "LRU same key supports null and value session_id" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, null);
    {
        const entry = (try m.get(std.testing.allocator, "k")).?;
        defer entry.deinit(std.testing.allocator);
        try std.testing.expect(entry.session_id == null);
    }

    try m.store("k", "v2", .core, "sess-new");
    {
        try std.testing.expectEqual(@as(usize, 2), try m.count());

        const global_entry = (try m.getScoped(std.testing.allocator, "k", null)).?;
        defer global_entry.deinit(std.testing.allocator);
        try std.testing.expect(global_entry.session_id == null);

        const scoped_entry = (try m.getScoped(std.testing.allocator, "k", "sess-new")).?;
        defer scoped_entry.deinit(std.testing.allocator);
        try std.testing.expect(scoped_entry.session_id != null);
        try std.testing.expectEqualStrings("sess-new", scoped_entry.session_id.?);
    }
}

test "LRU same key supports value and null session_id" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, "sess-old");
    try m.store("k", "v2", .core, null);

    try std.testing.expectEqual(@as(usize, 2), try m.count());

    const scoped_entry = (try m.getScoped(std.testing.allocator, "k", "sess-old")).?;
    defer scoped_entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("sess-old", scoped_entry.session_id.?);

    const global_entry = (try m.getScoped(std.testing.allocator, "k", null)).?;
    defer global_entry.deinit(std.testing.allocator);
    try std.testing.expect(global_entry.session_id == null);
}

test "LRU list with session_id filter" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "v1", .core, "sess-a");
    try m.store("k2", "v2", .core, "sess-b");
    try m.store("k3", "v3", .core, null);

    const list_a = try m.list(std.testing.allocator, null, "sess-a");
    defer root.freeEntries(std.testing.allocator, list_a);
    try std.testing.expectEqual(@as(usize, 1), list_a.len);
    try std.testing.expectEqualStrings("k1", list_a[0].key);
}

test "LRU list with category and session_id combined" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "v1", .core, "sess-a");
    try m.store("k2", "v2", .daily, "sess-a");
    try m.store("k3", "v3", .core, "sess-b");

    const results = try m.list(std.testing.allocator, .core, "sess-a");
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("k1", results[0].key);
}

test "LRU recall returns most recently accessed first" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "common", .core, null);
    try m.store("b", "common", .core, null);
    try m.store("c", "common", .core, null);

    // Access "a" last, so it should come first in recall results
    {
        const entry = (try m.get(std.testing.allocator, "a")).?;
        defer entry.deinit(std.testing.allocator);
    }

    const results = try m.recall(std.testing.allocator, "common", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 3), results.len);
    // First result should be "a" (most recently accessed)
    try std.testing.expectEqualStrings("a", results[0].key);
}

test "LRU recall with session_id returns only matching" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "shared data", .core, "sess-a");
    try m.store("k2", "shared data", .core, "sess-b");
    try m.store("k3", "shared data", .core, null);

    const results = try m.recall(std.testing.allocator, "shared", 10, "sess-a");
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("k1", results[0].key);
}

test "LRU forget nonexistent key returns false" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 100);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "exists", .core, null);
    const result = try m.forget("nonexistent");
    try std.testing.expect(!result);
    try std.testing.expectEqual(@as(usize, 1), try m.count());
}

test "LRU get on nonexistent key does not increment access counter" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 3);
    defer mem.deinit();
    const m = mem.memory();

    // Access counter starts at 0
    try std.testing.expectEqual(@as(u64, 0), mem.access_counter);

    const result = try m.get(std.testing.allocator, "nonexistent");
    try std.testing.expect(result == null);

    // Access counter should still be 0 (no entry touched)
    try std.testing.expectEqual(@as(u64, 0), mem.access_counter);
}

test "LRU eviction with capacity 1" {
    var mem = InMemoryLruMemory.init(std.testing.allocator, 1);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "first", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    try m.store("b", "second", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    // "a" should be evicted
    const got_a = try m.get(std.testing.allocator, "a");
    try std.testing.expect(got_a == null);

    const got_b = (try m.get(std.testing.allocator, "b")).?;
    defer got_b.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("second", got_b.content);
}
