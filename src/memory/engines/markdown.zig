//! Markdown-based memory — plain files as source of truth.
//!
//! Layout:
//!   workspace/MEMORY.md          — curated long-term memory (core)
//!   workspace/memory/YYYY-MM-DD.md — daily logs (append-only)
//!
//! This backend is append-only: forget() is a no-op to preserve audit trail.

const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../../fs_compat.zig");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

pub const MarkdownMemory = struct {
    workspace_dir: []const u8,
    allocator: std.mem.Allocator,
    owns_self: bool = false,

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

    // Parse timestamp from filename (e.g., "2024-03-04-1243.md") or return 0.
    // Supports YYYY-MM-DD, YYYY-MM-DD-HHMM, YYYY-MM-DD-HHMMSS.
    fn parseTimestamp(filename: []const u8) i64 {
        // Skip evergreen names
        if (std.mem.eql(u8, filename, "MEMORY.md") or std.mem.eql(u8, filename, "memory.md")) {
            return 0;
        }

        // Remove .md extension if present
        const name = if (std.mem.endsWith(u8, filename, ".md"))
            filename[0 .. filename.len - 3]
        else
            filename;

        // Parse YYYY-MM-DD[-HHMM[SS]]
        var parts = std.mem.splitScalar(u8, name, '-');
        const year_str = parts.next() orelse return 0;
        const month_str = parts.next() orelse return 0;
        const day_str = parts.next() orelse return 0;
        const time_str = parts.next(); // optional: HHMM or HHMMSS

        const year = std.fmt.parseInt(i16, year_str, 10) catch return 0;
        const month = std.fmt.parseInt(u8, month_str, 10) catch return 0;
        const day = std.fmt.parseInt(u8, day_str, 10) catch return 0;

        // Basic validation
        if (month < 1 or month > 12) return 0;
        if (day < 1 or day > 31) return 0;

        const epoch_day = ymdToEpochDays(year, month, day);
        var total_seconds: i64 = epoch_day * 86400;

        // If time part exists, add hours, minutes, and optional seconds
        if (time_str) |t| {
            if (t.len >= 4) {
                const hour = std.fmt.parseInt(u8, t[0..2], 10) catch 0;
                const minute = std.fmt.parseInt(u8, t[2..4], 10) catch 0;
                total_seconds += @as(i64, @intCast(hour)) * 3600 + @as(i64, @intCast(minute)) * 60;
                if (t.len >= 6) {
                    const second = std.fmt.parseInt(u8, t[4..6], 10) catch 0;
                    total_seconds += @as(i64, @intCast(second));
                }
            }
        }

        return total_seconds;
    }

    // Convert Gregorian Y-M-D to days since 1970-01-01 (epoch day 0) using Julian Day Number.
    fn ymdToEpochDays(year: i16, month: u8, day: u8) i64 {
        var y = @as(i32, @intCast(year));
        var m = @as(i32, @intCast(month));
        if (m <= 2) {
            y -= 1;
            m += 12;
        }
        const era = if (y >= 0) @divTrunc(y, 400) else @divTrunc(y - 399, 400);
        const yoe = @as(u32, @intCast(y - era * 400)); // [0, 399]
        const doy = @as(u32, @intCast(@divTrunc(153 * @as(i32, m - 3) + 2, 5))) + @as(u32, @intCast(day)) - 1; // [0, 365]
        const doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        const days = era * 146097 + @as(i64, @intCast(doe)) - 719468;
        return days;
    }

    fn corePath(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/MEMORY.md", .{self.workspace_dir});
    }

    fn rootPath(self: *const Self, allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.workspace_dir, filename });
    }

    fn memoryDir(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/memory", .{self.workspace_dir});
    }

    fn dailyPath(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const ts = std_compat.time.timestamp();
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
        if (std_compat.fs.path.dirname(path)) |dir| {
            std_compat.fs.makeDirAbsolute(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
    }

    fn appendToFile(path: []const u8, content: []const u8, allocator: std.mem.Allocator) !void {
        try ensureDir(path);

        // Open (or create) without truncation and seek to end to append.
        // This avoids the read-concat-rewrite pattern which loses data if
        // the process crashes between truncation and write completion.
        const file = try fs_compat.createPath(path, .{ .truncate = false, .read = true });
        defer file.close();

        const stat = try fs_compat.stat(file);
        const size = stat.size;

        try file.seekTo(size);

        // If the file already has content and doesn't end with a newline,
        // prepend one to keep entries on separate lines.
        if (size > 0) {
            try file.seekTo(size - 1);
            var last_byte: [1]u8 = undefined;
            const n = try file.read(&last_byte);
            if (n == 1 and last_byte[0] != '\n') {
                try file.seekTo(size);
                try file.writeAll("\n");
            } else {
                try file.seekTo(size);
            }
        }

        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{content});
        defer allocator.free(line);
        try file.writeAll(line);
    }

    // Modified: now receives file_timestamp as argument (computed from filename or mtime)
    fn parseEntries(text: []const u8, filename: []const u8, category: MemoryCategory, allocator: std.mem.Allocator, file_timestamp: i64) ![]MemoryEntry {
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*e| e.deinit(allocator);
            entries.deinit(allocator);
        }

        // Convert file_timestamp to string; if file_timestamp is 0, that's fine (unknown)
        const timestamp_str = try std.fmt.allocPrint(allocator, "{d}", .{file_timestamp});
        errdefer allocator.free(timestamp_str);

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
            const timestamp = try allocator.dupe(u8, timestamp_str);
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
                .session_id = null,
            });

            line_idx += 1;
        }

        // Free the template timestamp string; each entry has its own copy.
        allocator.free(timestamp_str);

        return entries.toOwnedSlice(allocator);
    }

    fn readAllEntries(self: *Self, allocator: std.mem.Allocator) ![]MemoryEntry {
        var all: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (all.items) |*e| e.deinit(allocator);
            all.deinit(allocator);
        }

        var seen_root_paths: std.StringHashMapUnmanaged(void) = .empty;
        defer {
            var key_it = seen_root_paths.keyIterator();
            while (key_it.next()) |key| allocator.free(key.*);
            seen_root_paths.deinit(allocator);
        }

        const root_candidates = [_]struct {
            filename: []const u8,
            label: []const u8,
        }{
            .{ .filename = "MEMORY.md", .label = "MEMORY" },
            .{ .filename = "memory.md", .label = "memory" },
        };

        for (root_candidates) |candidate| {
            const root_path = try self.rootPath(allocator, candidate.filename);
            defer allocator.free(root_path);

            // Open file, get its stat, then read content in one go.
            const file = fs_compat.openPath(root_path, .{}) catch continue;
            defer file.close();
            const stat = fs_compat.stat(file) catch continue;
            const content = file.readToEndAlloc(allocator, 1024 * 1024) catch continue;
            defer allocator.free(content);

            const canonical = std_compat.fs.realpathAlloc(allocator, root_path) catch
                try allocator.dupe(u8, root_path);
            errdefer allocator.free(canonical);
            if (seen_root_paths.contains(canonical)) {
                allocator.free(canonical);
                continue;
            }
            try seen_root_paths.put(allocator, canonical, {});

            // Resolve timestamp: parse from filename, else use file mtime (converted to seconds).
            const file_timestamp = blk: {
                const parsed = parseTimestamp(candidate.filename);
                if (parsed != 0) {
                    break :blk parsed;
                } else {
                    break :blk @as(i64, @intCast(@divTrunc(stat.mtime, std.time.ns_per_s)));
                }
            };

            const entries = try parseEntries(content, candidate.label, .core, allocator, file_timestamp);
            defer allocator.free(entries);
            for (entries) |e| try all.append(allocator, e);
        }

        const md = try self.memoryDir(allocator);
        defer allocator.free(md);
        if (fs_compat.openDirPath(md, .{ .iterate = true })) |*dir_handle| {
            var dir = dir_handle.*;
            defer dir.close();
            var it = dir.iterate();
            while (try it.next()) |entry| {
                if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
                const fpath = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ md, entry.name });
                defer allocator.free(fpath);

                const file = fs_compat.openPath(fpath, .{}) catch continue;
                defer file.close();
                const stat = fs_compat.stat(file) catch continue;
                const content = file.readToEndAlloc(allocator, 1024 * 1024) catch continue;
                defer allocator.free(content);

                const fname = entry.name[0 .. entry.name.len - 3];
                const file_timestamp = blk: {
                    const parsed = parseTimestamp(entry.name);
                    if (parsed != 0) {
                        break :blk parsed;
                    } else {
                        break :blk @as(i64, @intCast(@divTrunc(stat.mtime, std.time.ns_per_s)));
                    }
                };

                const entries = try parseEntries(content, fname, .daily, allocator, file_timestamp);
                defer allocator.free(entries);
                for (entries) |e| try all.append(allocator, e);
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
            const matches = blk: {
                if (std.mem.eql(u8, entry.key, key)) break :blk true;

                const trimmed = std.mem.trim(u8, entry.content, " \t\r");
                if (std.mem.startsWith(u8, trimmed, "**")) {
                    const rest = trimmed[2..];
                    if (std.mem.indexOf(u8, rest, "**:")) |suffix| {
                        if (suffix > 0 and std.mem.eql(u8, rest[0..suffix], key)) {
                            break :blk true;
                        }
                    }
                }

                break :blk std.mem.indexOf(u8, entry.content, key) != null;
            };

            if (matches) {
                if (found) |*prev| prev.deinit(allocator);
                found = entry;
            } else {
                @constCast(entry_ptr).deinit(allocator);
            }
        }

        return found;
    }

    fn implGetScoped(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, _: ?[]const u8) anyerror!?MemoryEntry {
        return implGet(ptr, allocator, key);
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

    fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, _: ?[]const u8, limit: usize, offset: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const all = try self_.readAllEntries(allocator);
        defer allocator.free(all);

        var paged: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (paged.items) |*e| e.deinit(allocator);
            paged.deinit(allocator);
        }

        var skipped: usize = 0;
        for (all) |*entry_ptr| {
            const entry = entry_ptr.*;
            if (category) |cat| {
                if (!entry.category.eql(cat)) {
                    entry_ptr.deinit(allocator);
                    continue;
                }
            }
            if (skipped < offset) {
                skipped += 1;
                entry_ptr.deinit(allocator);
                continue;
            }
            if (paged.items.len < limit) {
                try paged.append(allocator, entry);
            } else {
                entry_ptr.deinit(allocator);
            }
        }

        return paged.toOwnedSlice(allocator);
    }

    fn implForget(_: *anyopaque, _: []const u8) anyerror!bool {
        return false;
    }

    fn implForgetScoped(_: *anyopaque, _: []const u8, _: ?[]const u8) anyerror!bool {
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
        if (self_.owns_self) {
            self_.allocator.destroy(self_);
        }
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
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator, 0);
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
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator, 0);
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
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator, 0);
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
    const entries = try MarkdownMemory.parseEntries(text, "myfile", .core, std.testing.allocator, 0);
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
    const entries = try MarkdownMemory.parseEntries("", "test", .core, std.testing.allocator, 0);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "markdown parseEntries only headings returns empty" {
    const text = "# Heading\n## Another\n### Third";
    const entries = try MarkdownMemory.parseEntries(text, "test", .core, std.testing.allocator, 0);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "markdown parseEntries preserves category" {
    const text = "content";
    const entries = try MarkdownMemory.parseEntries(text, "test", .daily, std.testing.allocator, 0);
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
    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
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

test "markdown getScoped returns entry inside isolated workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem = try MarkdownMemory.init(std.testing.allocator, base);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("scoped_key", "session data", .core, "session-123");

    const entry = (try m.getScoped(std.testing.allocator, "scoped_key", "session-123")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, entry.content, "session data") != null);
}

test "markdown reads memory.md when MEMORY.md is absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try @import("compat").fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "memory.md",
        .data = "- legacy-memory-entry",
    });
    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem = try MarkdownMemory.init(std.testing.allocator, base);
    defer mem.deinit();
    const m = mem.memory();

    const recalled = try m.recall(std.testing.allocator, "legacy", 10, null);
    defer {
        for (recalled) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(recalled);
    }

    try std.testing.expectEqual(@as(usize, 1), recalled.len);
    try std.testing.expect(std.mem.indexOf(u8, recalled[0].content, "legacy-memory-entry") != null);
}

test "markdown reads both MEMORY.md and memory.md when distinct" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "MEMORY.md",
        .data = "- primary-entry",
    });

    var has_distinct_case_files = true;
    const alt = @import("compat").fs.Dir.wrap(tmp.dir).createFile("memory.md", .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => blk: {
            has_distinct_case_files = false;
            break :blk null;
        },
        else => return err,
    };
    if (alt) |f| {
        defer f.close();
        try f.writeAll("- alt-entry");
    }

    if (!has_distinct_case_files) return;

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem = try MarkdownMemory.init(std.testing.allocator, base);
    defer mem.deinit();
    const m = mem.memory();

    const listed = try m.list(std.testing.allocator, .core, null);
    defer {
        for (listed) |*e| e.deinit(std.testing.allocator);
        std.testing.allocator.free(listed);
    }

    var found_primary = false;
    var found_alt = false;
    for (listed) |entry| {
        if (std.mem.indexOf(u8, entry.content, "primary-entry") != null) found_primary = true;
        if (std.mem.indexOf(u8, entry.content, "alt-entry") != null) found_alt = true;
    }

    try std.testing.expect(found_primary);
    try std.testing.expect(found_alt);
}

test "markdown get returns latest matching entry for duplicate key" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem = try MarkdownMemory.init(std.testing.allocator, base);
    defer mem.deinit();
    const m = mem.memory();

    try m.store("dup_key", "old", .core, null);
    try m.store("dup_key", "new", .core, null);

    const entry = (try m.get(std.testing.allocator, "dup_key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, entry.content, "new") != null);
}

// ── Additional timestamp tests ──────────────────────────────────────

test "markdown parseTimestamp parses YYYY-MM-DD" {
    const ts = MarkdownMemory.parseTimestamp("2024-03-04.md");
    // Should be some valid epoch (we don't assert exact value, just >0)
    try std.testing.expect(ts > 0);
}

test "markdown parseTimestamp parses YYYY-MM-DD-HHMM" {
    const ts = MarkdownMemory.parseTimestamp("2024-03-04-1243.md");
    try std.testing.expect(ts > 0);
}

test "markdown parseTimestamp parses YYYY-MM-DD-HHMMSS" {
    const ts = MarkdownMemory.parseTimestamp("2024-03-04-124530.md");
    try std.testing.expect(ts > 0);
}

test "markdown parseTimestamp returns 0 for MEMORY.md" {
    try std.testing.expectEqual(@as(i64, 0), MarkdownMemory.parseTimestamp("MEMORY.md"));
    try std.testing.expectEqual(@as(i64, 0), MarkdownMemory.parseTimestamp("memory.md"));
}

test "markdown parseTimestamp returns 0 for malformed" {
    try std.testing.expectEqual(@as(i64, 0), MarkdownMemory.parseTimestamp("not-a-date.md"));
    try std.testing.expectEqual(@as(i64, 0), MarkdownMemory.parseTimestamp("2024-13-01.md")); // invalid month
}
