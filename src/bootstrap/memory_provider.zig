//! Memory-backed BootstrapProvider.
//!
//! Delegates to the Memory vtable using `__bootstrap.prompt.<filename>` keys.
//! Supports an optional workspace_dir for graceful disk fallback during
//! migration from file-based to memory-based bootstrap storage.

const std = @import("std");
const provider = @import("provider.zig");
const BootstrapProvider = provider.BootstrapProvider;
const isBootstrapFilename = provider.isBootstrapFilename;
const memory_root = @import("../memory/root.zig");
const Memory = memory_root.Memory;

pub const Error = error{NotBootstrapFile};

pub const MemoryBootstrapProvider = struct {
    allocator: std.mem.Allocator,
    mem: Memory,
    workspace_dir: ?[]const u8,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, mem: Memory, workspace_dir: ?[]const u8) Self {
        return .{
            .allocator = allocator,
            .mem = mem,
            .workspace_dir = workspace_dir,
        };
    }

    pub fn provider(self: *Self) BootstrapProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = BootstrapProvider.VTable{
        .load = implLoad,
        .load_excerpt = implLoadExcerpt,
        .store = implStore,
        .remove = implRemove,
        .exists = implExists,
        .list = implList,
        .fingerprint = implFingerprint,
        .deinit = implDeinit,
    };

    fn memoryKey(allocator: std.mem.Allocator, filename: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ memory_root.PromptBootstrapKeyPrefix, filename });
    }

    /// Try to read a file from the disk fallback directory.
    fn diskFallback(workspace_dir: []const u8, allocator: std.mem.Allocator, filename: []const u8) ?[]const u8 {
        const path = std.fs.path.join(allocator, &.{ workspace_dir, filename }) catch return null;
        defer allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch return null;
        defer file.close();

        return file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch null;
    }

    fn implLoad(ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8) anyerror!?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const key = try memoryKey(allocator, filename);
        defer allocator.free(key);

        if (try self.mem.get(allocator, key)) |entry| {
            defer allocator.free(entry.id);
            defer allocator.free(entry.key);
            defer allocator.free(entry.timestamp);
            defer if (entry.session_id) |sid| allocator.free(sid);
            defer switch (entry.category) {
                .custom => |name| allocator.free(name),
                else => {},
            };
            // Keep entry.content — caller owns it.
            return entry.content;
        }

        // Disk fallback for graceful migration.
        if (self.workspace_dir) |dir| {
            return diskFallback(dir, allocator, filename);
        }

        return null;
    }

    fn implLoadExcerpt(ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8, max_bytes: usize) anyerror!?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const key = try memoryKey(allocator, filename);
        defer allocator.free(key);

        if (try self.mem.get(allocator, key)) |entry| {
            defer allocator.free(entry.id);
            defer allocator.free(entry.key);
            defer allocator.free(entry.timestamp);
            defer if (entry.session_id) |sid| allocator.free(sid);
            defer switch (entry.category) {
                .custom => |name| allocator.free(name),
                else => {},
            };

            if (entry.content.len <= max_bytes) {
                return entry.content;
            }

            defer allocator.free(entry.content);
            return try allocator.dupe(u8, entry.content[0..max_bytes]);
        }

        if (self.workspace_dir) |dir| {
            return diskFallbackExcerpt(dir, allocator, filename, max_bytes);
        }

        return null;
    }

    fn implStore(ptr: *anyopaque, filename: []const u8, content: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const key = try memoryKey(self.allocator, filename);
        defer self.allocator.free(key);

        try self.mem.store(key, content, .core, null);
    }

    fn implRemove(ptr: *anyopaque, filename: []const u8) anyerror!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const key = try memoryKey(self.allocator, filename);
        defer self.allocator.free(key);

        return self.mem.forget(key);
    }

    fn implExists(ptr: *anyopaque, filename: []const u8) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (!isBootstrapFilename(filename)) return false;

        const key = memoryKey(self.allocator, filename) catch return false;
        defer self.allocator.free(key);

        if (self.mem.get(self.allocator, key)) |maybe_entry| {
            if (maybe_entry) |entry| {
                entry.deinit(self.allocator);
                return true;
            }
        } else |_| {
            return false;
        }

        // Not in memory — check disk fallback.
        if (self.workspace_dir) |dir| {
            const path = std.fs.path.join(self.allocator, &.{ dir, filename }) catch return false;
            defer self.allocator.free(path);
            std.fs.accessAbsolute(path, .{}) catch return false;
            return true;
        }

        return false;
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]const []const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var result = std.ArrayListUnmanaged([]const u8).empty;
        errdefer {
            for (result.items) |item| allocator.free(item);
            result.deinit(allocator);
        }

        for (memory_root.prompt_bootstrap_docs) |doc| {
            const key = try memoryKey(allocator, doc.filename);
            defer allocator.free(key);

            var found_in_mem = false;
            if (try self.mem.get(allocator, key)) |entry| {
                entry.deinit(allocator);
                found_in_mem = true;
            }

            if (!found_in_mem) {
                // Check disk fallback.
                if (self.workspace_dir) |dir| {
                    const path = try std.fs.path.join(allocator, &.{ dir, doc.filename });
                    defer allocator.free(path);
                    std.fs.accessAbsolute(path, .{}) catch continue;
                } else {
                    continue;
                }
            }

            try result.append(allocator, try allocator.dupe(u8, doc.filename));
        }

        return try result.toOwnedSlice(allocator);
    }

    fn implFingerprint(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var hasher = std.hash.Fnv1a_64.init();

        for (memory_root.prompt_bootstrap_docs) |doc| {
            hasher.update(doc.filename);
            hasher.update("\n");

            const key = try memoryKey(allocator, doc.filename);
            defer allocator.free(key);

            if (try self.mem.get(allocator, key)) |entry| {
                defer entry.deinit(allocator);
                hasher.update("present");
                hasher.update(entry.content);
            } else {
                // Check disk fallback.
                if (self.workspace_dir) |dir| {
                    if (diskFallback(dir, allocator, doc.filename)) |content| {
                        defer allocator.free(content);
                        hasher.update("present");
                        hasher.update(content);
                        continue;
                    }
                }
                hasher.update("missing");
            }
        }

        return hasher.final();
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }
};

fn diskFallbackExcerpt(workspace_dir: []const u8, allocator: std.mem.Allocator, filename: []const u8, max_bytes: usize) ?[]const u8 {
    const path = std.fs.path.join(allocator, &.{ workspace_dir, filename }) catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const buf = allocator.alloc(u8, max_bytes) catch return null;
    const read_len = file.readAll(buf) catch {
        allocator.free(buf);
        return null;
    };
    return shrink_alloc(allocator, buf, read_len) catch {
        allocator.free(buf);
        return null;
    };
}

fn shrink_alloc(allocator: std.mem.Allocator, slice: []u8, new_len: usize) ![]u8 {
    if (new_len >= slice.len) return slice;
    return allocator.realloc(slice, new_len) catch blk: {
        const fresh = try allocator.alloc(u8, new_len);
        @memcpy(fresh, slice[0..new_len]);
        allocator.free(slice);
        break :blk fresh;
    };
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const InMemoryLruMemory = memory_root.InMemoryLruMemory;

fn initTestProvider(lru: *InMemoryLruMemory, workspace_dir: ?[]const u8) struct { provider: MemoryBootstrapProvider } {
    return .{
        .provider = .{
            .allocator = testing.allocator,
            .mem = lru.memory(),
            .workspace_dir = workspace_dir,
        },
    };
}

test "store then load via memory backend" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    try bp.store("AGENTS.md", "agent content");
    const content = try bp.load(testing.allocator, "AGENTS.md");
    defer if (content) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("agent content", content.?);
}

test "load missing returns null" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    const content = try bp.load(testing.allocator, "SOUL.md");
    try testing.expect(content == null);
}

test "load_excerpt returns prefix for stored memory bootstrap" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    try bp.store("AGENTS.md", "abcdef");
    const excerpt = try bp.load_excerpt(testing.allocator, "AGENTS.md", 4);
    defer if (excerpt) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("abcd", excerpt.?);
}

test "fallback reads from workspace dir when not in DB" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a file to the tmp dir.
    tmp.dir.writeFile(.{ .sub_path = "IDENTITY.md", .data = "disk identity" }) catch unreachable;

    const workspace = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(workspace);

    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, workspace);
    var bp = ctx.provider.provider();

    const content = try bp.load(testing.allocator, "IDENTITY.md");
    defer if (content) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("disk identity", content.?);
}

test "load_excerpt uses disk fallback prefix when not in DB" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(.{ .sub_path = "IDENTITY.md", .data = "disk identity" }) catch unreachable;

    const workspace = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(workspace);

    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, workspace);
    var bp = ctx.provider.provider();

    const excerpt = try bp.load_excerpt(testing.allocator, "IDENTITY.md", 4);
    defer if (excerpt) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("disk", excerpt.?);
}

test "DB takes priority over disk fallback" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.writeFile(.{ .sub_path = "SOUL.md", .data = "disk soul" }) catch unreachable;

    const workspace = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(workspace);

    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, workspace);
    var bp = ctx.provider.provider();

    // Store in memory — should take priority.
    try bp.store("SOUL.md", "memory soul");

    const content = try bp.load(testing.allocator, "SOUL.md");
    defer if (content) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("memory soul", content.?);
}

test "fingerprint changes after store" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    const fp_before = try bp.fingerprint(testing.allocator);

    try bp.store("TOOLS.md", "tool content");

    const fp_after = try bp.fingerprint(testing.allocator);
    try testing.expect(fp_before != fp_after);
}

test "remove works" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    try bp.store("USER.md", "user content");
    try testing.expect(bp.exists("USER.md"));

    const removed = try bp.remove("USER.md");
    try testing.expect(removed);
    try testing.expect(!bp.exists("USER.md"));

    // Removing again returns false.
    const removed_again = try bp.remove("USER.md");
    try testing.expect(!removed_again);
}

test "list returns stored filenames" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    // Initially empty.
    const empty = try bp.list(testing.allocator);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);

    // Store some files.
    try bp.store("AGENTS.md", "a");
    try bp.store("SOUL.md", "s");

    const files = try bp.list(testing.allocator);
    defer {
        for (files) |f| testing.allocator.free(f);
        testing.allocator.free(files);
    }

    try testing.expectEqual(@as(usize, 2), files.len);
    // prompt_bootstrap_docs order: AGENTS.md first, SOUL.md second.
    try testing.expectEqualStrings("AGENTS.md", files[0]);
    try testing.expectEqualStrings("SOUL.md", files[1]);
}

test "rejects non-bootstrap filenames" {
    var lru = InMemoryLruMemory.init(testing.allocator, 100);
    defer lru.deinit();

    var ctx = initTestProvider(&lru, null);
    var bp = ctx.provider.provider();

    // store
    const store_result = bp.store("evil.md", "bad");
    try testing.expectError(Error.NotBootstrapFile, store_result);

    // load
    const load_result = bp.load(testing.allocator, "evil.md");
    try testing.expectError(Error.NotBootstrapFile, load_result);

    // remove
    const remove_result = bp.remove("evil.md");
    try testing.expectError(Error.NotBootstrapFile, remove_result);

    // exists returns false (no error).
    try testing.expect(!bp.exists("evil.md"));
}
