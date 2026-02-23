//! Markdown-based memory — plain files as source of truth.
//!
//! Layout:
//!   workspace/MEMORY.md          — curated long-term memory (core)
//!   workspace/memory/YYYY-MM-DD.md — daily logs (append-only)
//!
//! This backend is append-only: forget() is a no-op to preserve audit trail.

const std = @import("std");
const root = @import("root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

pub const MarkdownMemory = struct {
    workspace_dir: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, workspace_dir: []const u8) !Self {
        return Self{
            .workspace_dir = try allocator.dupe(u8, workspace_dir),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.workspace_dir);
    }

    fn corePath(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/MEMORY.md", .{self.workspace_dir});
    }

    fn memoryDir(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/memory", .{self.workspace_dir});
    }

    fn dailyPath(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const ts = std.time.timestamp();
        const epoch: u64 = @intCast(ts);
        const es = std.time.epoch.EpochSeconds{ .secs = epoch };
        const day = es.getEpochDay().calculateYearDay();
        const md = day.calculateMonthDay();

        return std.fmt.allocPrint(allocator, "{s}/memory/{d:0>4}-{d:0>2}-{d:0>2}.md", .{
            self.workspace_dir,
            day.year,
            @intFromEnum(md.month),
            md.day_index + 1,
        });
    }

    fn ensureDir(path: []const u8) !void {
        if (std.fs.path.dirname(path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
    }

    fn appendToFile(path: []const u8, content: []const u8, allocator: std.mem.Allocator) !void {
        try ensureDir(path);

        const existing = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch "";
        defer if (existing.len > 0) allocator.free(existing);

        const new_content = if (existing.len == 0)
            try std.fmt.allocPrint(allocator, "{s}\n", .{content})
        else
            try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ existing, content });
        defer allocator.free(new_content);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(new_content);
    }

    fn parseEntries(text: []const u8, filename: []const u8, category: MemoryCategory, allocator: std.mem.Allocator) ![]MemoryEntry {
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*e| e.deinit(allocator);
            entries.deinit(allocator);
        }

        var line_idx: usize = 0;
        var iter = std.mem.splitScalar(u8, text, '\n');
        while (iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            const clean = if (std.mem.startsWith(u8, trimmed, "- "))
                trimmed[2..]
            else
                trimmed;

            const id = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ filename, line_idx });
            errdefer allocator.free(id);
            const key = try allocator.dupe(u8, id);
            errdefer allocator.free(key);
            const content_dup = try allocator.dupe(u8, clean);
            errdefer allocator.free(content_dup);
            const timestamp = try allocator.dupe(u8, filename);
            errdefer allocator.free(timestamp);

            const cat = switch (category) {
                .custom => |name| MemoryCategory{ .custom = try allocator.dupe(u8, name) },
                else => category,
            };

            try entries.append(allocator, MemoryEntry{
                .id = id,
                .key = key,
                .content = content_dup,
                .category = cat,
                .timestamp = timestamp,
            });

            line_idx += 1;
        }

        return entries.toOwnedSlice(allocator);
    }

    fn readAllEntries(self: *Self, allocator: std.mem.Allocator) ![]MemoryEntry {
        var all: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (all.items) |*e| e.deinit(allocator);
            all.deinit(allocator);
        }

        const cp = try self.corePath(allocator);
        defer allocator.free(cp);
        if (std.fs.cwd().readFileAlloc(allocator, cp, 1024 * 1024)) |content| {
            defer allocator.free(content);
            const entries = try parseEntries(content, "MEMORY", .core, allocator);
            defer allocator.free(entries);
            for (entries) |e| try all.append(allocator, e);
        } else |_| {}

        const md = try self.memoryDir(allocator);
        defer allocator.free(md);
        if (std.fs.cwd().openDir(md, .{ .iterate = true })) |*dir_handle| {
            var dir = dir_handle.*;
            defer dir.close();
            var it = dir.iterate();
            while (try it.next()) |entry| {
                if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
                const fpath = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ md, entry.name });
                defer allocator.free(fpath);
                if (std.fs.cwd().readFileAlloc(allocator, fpath, 1024 * 1024)) |content| {
                    defer allocator.free(content);
                    const fname = entry.name[0 .. entry.name.len - 3];
                    const entries = try parseEntries(content, fname, .daily, allocator);
                    defer allocator.free(entries);
                    for (entries) |e| try all.append(allocator, e);
                } else |_| {}
            }
        } else |_| {}

        return all.toOwnedSlice(allocator);
    }

    // ── Memory vtable impl ────────────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "markdown";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, _: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const entry_text = try std.fmt.allocPrint(self_.allocator, "- **{s}**: {s}", .{ key, content });
        defer self_.allocator.free(entry_text);

        const path = switch (category) {
            .core => try self_.corePath(self_.allocator),
            else => try self_.dailyPath(self_.allocator),
        };
        defer self_.allocator.free(path);

        try appendToFile(path, entry_text, self_.allocator);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, _: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const all = try self_.readAllEntries(allocator);
        defer allocator.free(all);

        const query_lower = try std.ascii.allocLowerString(allocator, query);
        defer allocator.free(query_lower);

        var keywords: std.ArrayList([]const u8) = .empty;
        defer keywords.deinit(allocator);
        var kw_iter = std.mem.tokenizeAny(u8, query_lower, " \t\n\r");
        while (kw_iter.next()) |word| try keywords.append(allocator, word);

        if (keywords.items.len == 0) {
            for (all) |*e| @constCast(e).deinit(allocator);
            return allocator.alloc(MemoryEntry, 0);
        }

        var scored: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (scored.items) |*e| e.deinit(allocator);
            scored.deinit(allocator);
        }

        for (all) |*entry_ptr| {
            var entry = entry_ptr.*;
            const content_lower = try std.ascii.allocLowerString(allocator, entry.content);
            defer allocator.free(content_lower);

            var matched: usize = 0;
            for (keywords.items) |kw| {
                if (std.mem.indexOf(u8, content_lower, kw) != null) matched += 1;
            }

            if (matched > 0) {
                const score: f64 = @as(f64, @floatFromInt(matched)) / @as(f64, @floatFromInt(keywords.items.len));
                entry.score = score;
                try scored.append(allocator, entry);
            } else {
                @constCast(entry_ptr).deinit(allocator);
            }
        }

        std.mem.sort(MemoryEntry, scored.items, {}, struct {
            fn lessThan(_: void, a: MemoryEntry, b: MemoryEntry) bool {
                return (b.score orelse 0) < (a.score orelse 0);
            }
        }.lessThan);

        if (scored.items.len > limit) {
            for (scored.items[limit..]) |*e| e.deinit(allocator);
            scored.shrinkRetainingCapacity(limit);
        }

        return scored.toOwnedSlice(allocator);
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const all = try self_.readAllEntries(allocator);
        defer allocator.free(all);

        var found: ?MemoryEntry = null;
        for (all) |*entry_ptr| {
            const entry = entry_ptr.*;
            if (found == null and (std.mem.eql(u8, entry.key, key) or std.mem.indexOf(u8, entry.content, key) != null)) {
                found = entry;
            } else {
                @constCast(entry_ptr).deinit(allocator);
            }
        }

        return found;
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, _: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const all = try self_.readAllEntries(allocator);
        defer allocator.free(all);

        if (category == null) {
            const result = try allocator.alloc(MemoryEntry, all.len);
            @memcpy(result, all);
            return result;
        }

        var filtered: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (filtered.items) |*e| e.deinit(allocator);
            filtered.deinit(allocator);
        }

        for (all) |*entry_ptr| {
            var entry = entry_ptr.*;
            if (entry.category.eql(category.?)) {
                try filtered.append(allocator, entry);
            } else {
                @constCast(entry_ptr).deinit(allocator);
            }
        }

        return filtered.toOwnedSlice(allocator);
    }

    fn implForget(_: *anyopaque, _: []const u8) anyerror!bool {
        return false;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const all = try self_.readAllEntries(self_.allocator);
        defer {
            for (all) |*entry| {
                @constCast(entry).deinit(self_.allocator);
            }
            self_.allocator.free(all);
        }
        return all.len;
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

test "markdown forget always returns false" {
    var mem = try MarkdownMemory.init(std.testing.allocator, "/tmp/nullclaw-test-md-forget");
    defer mem.deinit();
    const m = mem.memory();

    // Multiple forget calls all return false
    try std.testing.expect(!(try m.forget("key1")));
    try std.testing.expect(!(try m.forget("key2")));
    try std.testing.expect(!(try m.forget("")));
}

test "markdown parseEntries skips empty lines" {
    const text = "line one\n\n\nline two\n";
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator);
    defer {
        for (entries) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("line one", entries[0].content);
    try std.testing.expectEqualStrings("line two", entries[1].content);
}

test "markdown parseEntries skips headings" {
    const text = "# Heading\nContent under heading\n## Sub\nMore content";
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator);
    defer {
        for (entries) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("Content under heading", entries[0].content);
    try std.testing.expectEqualStrings("More content", entries[1].content);
}

test "markdown parseEntries strips bullet prefix" {
    const text = "- Item one\n- Item two\nPlain line";
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator);
    defer {
        for (entries) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("Item one", entries[0].content);
    try std.testing.expectEqualStrings("Item two", entries[1].content);
    try std.testing.expectEqualStrings("Plain line", entries[2].content);
}

test "markdown parseEntries generates sequential ids" {
    const text = "a\nb\nc";
    const entries = try MarkdownMemory.parseEntries(text, "myfile", .core, std.testing.allocator);
    defer {
        for (entries) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("myfile:0", entries[0].id);
    try std.testing.expectEqualStrings("myfile:1", entries[1].id);
    try std.testing.expectEqualStrings("myfile:2", entries[2].id);
}

test "markdown parseEntries empty text returns empty" {
    const entries = try MarkdownMemory.parseEntries("", "test", .core, std.testing.allocator);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "markdown parseEntries only headings returns empty" {
    const text = "# Heading\n## Another\n### Third";
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "markdown parseEntries preserves category" {
    const text = "content";
    const entries = try MarkdownMemory.parseEntries(text, "test", .daily, std.testing.allocator);
    defer {
        for (entries) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expect(entries[0].category.eql(.daily));
}

test "markdown accepts session_id param" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem = try MarkdownMemory.init(std.testing.allocator, base);
    defer mem.deinit();
    const m = mem.memory();

    // session_id is accepted but ignored by markdown backend
    try m.store("sess_key", "session data", .core, "session-123");

    const recalled = try m.recall(std.testing.allocator, "session", 10, "session-123");
    defer {
        for (recalled) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(recalled);
    }

    const listed = try m.list(std.testing.allocator, null, "session-123");
    defer {
        for (listed) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(listed);
    }
}
