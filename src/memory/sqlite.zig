//! SQLite-backed persistent memory — the brain.
//!
//! Features:
//! - Core memories table with CRUD
//! - FTS5 full-text search with BM25 scoring
//! - FTS5 sync triggers (insert/update/delete)
//! - Upsert semantics (ON CONFLICT DO UPDATE)
//! - Session message storage (legacy compat)
//! - KV store for settings

const std = @import("std");
const root = @import("root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

const c = @cImport({
    @cInclude("sqlite3.h");
});

const SQLITE_STATIC: c.sqlite3_destructor_type = null;

pub const SqliteMemory = struct {
    db: ?*c.sqlite3,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, db_path: [*:0]const u8) !Self {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }

        var self_ = Self{ .db = db, .allocator = allocator };
        try self_.configurePragmas();
        try self_.migrate();
        return self_;
    }

    pub fn deinit(self: *Self) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
    }

    fn configurePragmas(self: *Self) !void {
        const pragmas =
            \\PRAGMA journal_mode = WAL;
            \\PRAGMA synchronous  = NORMAL;
            \\PRAGMA temp_store   = MEMORY;
            \\PRAGMA cache_size   = -2000;
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, pragmas, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    fn migrate(self: *Self) !void {
        const sql =
            \\-- Core memories table
            \\CREATE TABLE IF NOT EXISTS memories (
            \\  id         TEXT PRIMARY KEY,
            \\  key        TEXT NOT NULL UNIQUE,
            \\  content    TEXT NOT NULL,
            \\  category   TEXT NOT NULL DEFAULT 'core',
            \\  created_at TEXT NOT NULL,
            \\  updated_at TEXT NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
            \\CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key);
            \\
            \\-- FTS5 full-text search (BM25 scoring)
            \\CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
            \\  key, content, content=memories, content_rowid=rowid
            \\);
            \\
            \\-- FTS5 triggers: keep in sync with memories table
            \\CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
            \\  INSERT INTO memories_fts(rowid, key, content)
            \\  VALUES (new.rowid, new.key, new.content);
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
            \\  INSERT INTO memories_fts(memories_fts, rowid, key, content)
            \\  VALUES ('delete', old.rowid, old.key, old.content);
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
            \\  INSERT INTO memories_fts(memories_fts, rowid, key, content)
            \\  VALUES ('delete', old.rowid, old.key, old.content);
            \\  INSERT INTO memories_fts(rowid, key, content)
            \\  VALUES (new.rowid, new.key, new.content);
            \\END;
            \\
            \\-- Legacy tables for backward compat
            \\CREATE TABLE IF NOT EXISTS messages (
            \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\  session_id TEXT NOT NULL,
            \\  role TEXT NOT NULL,
            \\  content TEXT NOT NULL,
            \\  created_at TEXT DEFAULT (datetime('now'))
            \\);
            \\CREATE TABLE IF NOT EXISTS sessions (
            \\  id TEXT PRIMARY KEY,
            \\  provider TEXT,
            \\  model TEXT,
            \\  created_at TEXT DEFAULT (datetime('now')),
            \\  updated_at TEXT DEFAULT (datetime('now'))
            \\);
            \\CREATE TABLE IF NOT EXISTS kv (
            \\  key TEXT PRIMARY KEY,
            \\  value TEXT NOT NULL
            \\);
            \\
            \\-- Embedding cache for vector search
            \\CREATE TABLE IF NOT EXISTS embedding_cache (
            \\  content_hash TEXT PRIMARY KEY,
            \\  embedding    BLOB NOT NULL,
            \\  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
            \\);
            \\
            \\-- Embeddings linked to memory entries
            \\CREATE TABLE IF NOT EXISTS memory_embeddings (
            \\  memory_key  TEXT PRIMARY KEY,
            \\  embedding   BLOB NOT NULL,
            \\  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            \\  FOREIGN KEY (memory_key) REFERENCES memories(key) ON DELETE CASCADE
            \\);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    // ── Memory trait implementation ────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "sqlite";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const now = getNowTimestamp(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(now);

        const id = generateId(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(id);

        const cat_str = category.toString();

        const sql = "INSERT INTO memories (id, key, content, category, created_at, updated_at) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6) " ++
            "ON CONFLICT(key) DO UPDATE SET " ++
            "content = excluded.content, " ++
            "category = excluded.category, " ++
            "updated_at = excluded.updated_at";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, id.ptr, @intCast(id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, key.ptr, @intCast(key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, content.ptr, @intCast(content.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 4, cat_str.ptr, @intCast(cat_str.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 5, now.ptr, @intCast(now.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 6, now.ptr, @intCast(now.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const trimmed = std.mem.trim(u8, query, " \t\n\r");
        if (trimmed.len == 0) return allocator.alloc(MemoryEntry, 0);

        const results = try fts5Search(self_, allocator, trimmed, limit);
        if (results.len > 0) return results;

        allocator.free(results);
        return try likeSearch(self_, allocator, trimmed, limit);
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sql = "SELECT id, key, content, category, created_at FROM memories WHERE key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            return try readEntryFromRow(stmt.?, allocator);
        }
        return null;
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        if (category) |cat| {
            const cat_str = cat.toString();
            const sql = "SELECT id, key, content, category, created_at FROM memories " ++
                "WHERE category = ?1 ORDER BY updated_at DESC";
            var stmt: ?*c.sqlite3_stmt = null;
            var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);

            _ = c.sqlite3_bind_text(stmt, 1, cat_str.ptr, @intCast(cat_str.len), SQLITE_STATIC);

            while (true) {
                rc = c.sqlite3_step(stmt);
                if (rc == c.SQLITE_ROW) {
                    try entries.append(allocator, try readEntryFromRow(stmt.?, allocator));
                } else break;
            }
        } else {
            const sql = "SELECT id, key, content, category, created_at FROM memories ORDER BY updated_at DESC";
            var stmt: ?*c.sqlite3_stmt = null;
            var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);

            while (true) {
                rc = c.sqlite3_step(stmt);
                if (rc == c.SQLITE_ROW) {
                    try entries.append(allocator, try readEntryFromRow(stmt.?, allocator));
                } else break;
            }
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sql = "DELETE FROM memories WHERE key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        return c.sqlite3_changes(self_.db) > 0;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sql = "SELECT COUNT(*) FROM memories";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const count = c.sqlite3_column_int64(stmt, 0);
            return @intCast(count);
        }
        return 0;
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self_.db, "SELECT 1", null, null, &err_msg);
        if (err_msg) |msg| c.sqlite3_free(msg);
        return rc == c.SQLITE_OK;
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

    // ── Legacy helpers ─────────────────────────────────────────────

    pub fn saveMessage(self: *Self, session_id: []const u8, role_str: []const u8, content: []const u8) !void {
        const sql = "INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, role_str.ptr, @intCast(role_str.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, content.ptr, @intCast(content.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    }

    pub fn reindex(self: *Self) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(
            self.db,
            "INSERT INTO memories_fts(memories_fts) VALUES('rebuild');",
            null,
            null,
            &err_msg,
        );
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.StepFailed;
        }
    }

    // ── Internal search helpers ────────────────────────────────────

    fn fts5Search(self_: *Self, allocator: std.mem.Allocator, query: []const u8, limit: usize) ![]MemoryEntry {
        // Build FTS5 query: wrap each word in quotes joined by OR
        var fts_query: std.ArrayList(u8) = .empty;
        defer fts_query.deinit(allocator);

        var iter = std.mem.tokenizeAny(u8, query, " \t\n\r");
        var first = true;
        while (iter.next()) |word| {
            if (!first) {
                try fts_query.appendSlice(allocator, " OR ");
            }
            try fts_query.append(allocator, '"');
            for (word) |ch_byte| {
                if (ch_byte == '"') {
                    try fts_query.appendSlice(allocator, "\"\"");
                } else {
                    try fts_query.append(allocator, ch_byte);
                }
            }
            try fts_query.append(allocator, '"');
            first = false;
        }

        if (fts_query.items.len == 0) return allocator.alloc(MemoryEntry, 0);

        const sql =
            "SELECT m.id, m.key, m.content, m.category, m.created_at, bm25(memories_fts) as score " ++
            "FROM memories_fts f " ++
            "JOIN memories m ON m.rowid = f.rowid " ++
            "WHERE memories_fts MATCH ?1 " ++
            "ORDER BY score " ++
            "LIMIT ?2";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return allocator.alloc(MemoryEntry, 0);
        defer _ = c.sqlite3_finalize(stmt);

        // Null-terminate the FTS query for sqlite
        try fts_query.append(allocator, 0);
        const fts_z = fts_query.items[0 .. fts_query.items.len - 1];
        _ = c.sqlite3_bind_text(stmt, 1, fts_z.ptr, @intCast(fts_z.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int64(stmt, 2, @intCast(limit));

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        while (true) {
            rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_ROW) {
                const score_raw = c.sqlite3_column_double(stmt.?, 5);
                var entry = try readEntryFromRow(stmt.?, allocator);
                entry.score = -score_raw; // BM25 returns negative (lower = better)
                try entries.append(allocator, entry);
            } else break;
        }

        return entries.toOwnedSlice(allocator);
    }

    fn likeSearch(self_: *Self, allocator: std.mem.Allocator, query: []const u8, limit: usize) ![]MemoryEntry {
        var keywords: std.ArrayList([]const u8) = .empty;
        defer keywords.deinit(allocator);

        var iter = std.mem.tokenizeAny(u8, query, " \t\n\r");
        while (iter.next()) |word| {
            try keywords.append(allocator, word);
        }

        if (keywords.items.len == 0) return allocator.alloc(MemoryEntry, 0);

        var sql_buf: std.ArrayList(u8) = .empty;
        defer sql_buf.deinit(allocator);

        try sql_buf.appendSlice(allocator, "SELECT id, key, content, category, created_at FROM memories WHERE ");

        for (keywords.items, 0..) |_, i| {
            if (i > 0) try sql_buf.appendSlice(allocator, " OR ");
            try sql_buf.appendSlice(allocator, "(content LIKE ?");
            try appendInt(&sql_buf, allocator, i * 2 + 1);
            try sql_buf.appendSlice(allocator, " OR key LIKE ?");
            try appendInt(&sql_buf, allocator, i * 2 + 2);
            try sql_buf.appendSlice(allocator, ")");
        }

        try sql_buf.appendSlice(allocator, " ORDER BY updated_at DESC LIMIT ?");
        try appendInt(&sql_buf, allocator, keywords.items.len * 2 + 1);
        try sql_buf.append(allocator, 0);

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql_buf.items.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return allocator.alloc(MemoryEntry, 0);
        defer _ = c.sqlite3_finalize(stmt);

        var like_bufs: std.ArrayList([]u8) = .empty;
        defer {
            for (like_bufs.items) |buf| allocator.free(buf);
            like_bufs.deinit(allocator);
        }

        for (keywords.items, 0..) |word, i| {
            const like = try std.fmt.allocPrint(allocator, "%{s}%", .{word});
            try like_bufs.append(allocator, like);
            _ = c.sqlite3_bind_text(stmt, @intCast(i * 2 + 1), like.ptr, @intCast(like.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_text(stmt, @intCast(i * 2 + 2), like.ptr, @intCast(like.len), SQLITE_STATIC);
        }
        _ = c.sqlite3_bind_int64(stmt, @intCast(keywords.items.len * 2 + 1), @intCast(limit));

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        while (true) {
            rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_ROW) {
                var entry = try readEntryFromRow(stmt.?, allocator);
                entry.score = 1.0;
                try entries.append(allocator, entry);
            } else break;
        }

        return entries.toOwnedSlice(allocator);
    }

    // ── Utility functions ──────────────────────────────────────────

    fn readEntryFromRow(stmt: *c.sqlite3_stmt, allocator: std.mem.Allocator) !MemoryEntry {
        const id = try dupeColumnText(stmt, 0, allocator);
        errdefer allocator.free(id);
        const key = try dupeColumnText(stmt, 1, allocator);
        errdefer allocator.free(key);
        const content = try dupeColumnText(stmt, 2, allocator);
        errdefer allocator.free(content);
        const cat_str = try dupeColumnText(stmt, 3, allocator);
        const timestamp = try dupeColumnText(stmt, 4, allocator);
        errdefer allocator.free(timestamp);

        const category = blk: {
            if (std.mem.eql(u8, cat_str, "core")) {
                allocator.free(cat_str);
                break :blk MemoryCategory.core;
            } else if (std.mem.eql(u8, cat_str, "daily")) {
                allocator.free(cat_str);
                break :blk MemoryCategory.daily;
            } else if (std.mem.eql(u8, cat_str, "conversation")) {
                allocator.free(cat_str);
                break :blk MemoryCategory.conversation;
            } else {
                break :blk MemoryCategory{ .custom = cat_str };
            }
        };

        return MemoryEntry{
            .id = id,
            .key = key,
            .content = content,
            .category = category,
            .timestamp = timestamp,
            .session_id = null,
            .score = null,
        };
    }

    fn dupeColumnText(stmt: *c.sqlite3_stmt, col: c_int, allocator: std.mem.Allocator) ![]u8 {
        const raw = c.sqlite3_column_text(stmt, col);
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
        if (raw == null or len == 0) {
            return allocator.dupe(u8, "");
        }
        const slice: []const u8 = @as([*]const u8, @ptrCast(raw))[0..len];
        return allocator.dupe(u8, slice);
    }

    fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: usize) !void {
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return error.PrepareFailed;
        try buf.appendSlice(allocator, s);
    }

    fn getNowTimestamp(allocator: std.mem.Allocator) ![]u8 {
        const ts = std.time.timestamp();
        return std.fmt.allocPrint(allocator, "{d}", .{ts});
    }

    fn generateId(allocator: std.mem.Allocator) ![]u8 {
        const ts = std.time.nanoTimestamp();
        var buf: [16]u8 = undefined;
        std.crypto.random.bytes(&buf);
        const rand_hi = std.mem.readInt(u64, buf[0..8], .little);
        const rand_lo = std.mem.readInt(u64, buf[8..16], .little);
        return std.fmt.allocPrint(allocator, "{d}-{x}-{x}", .{ ts, rand_hi, rand_lo });
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "sqlite memory init with in-memory db" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    try mem.saveMessage("test-session", "user", "hello");
}

test "sqlite name" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expectEqualStrings("sqlite", m.name());
}

test "sqlite health check" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expect(m.healthCheck());
}

test "sqlite store and get" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("user_lang", "Prefers Zig", .core);

    const entry = try m.get(std.testing.allocator, "user_lang");
    try std.testing.expect(entry != null);
    defer entry.?.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("user_lang", entry.?.key);
    try std.testing.expectEqualStrings("Prefers Zig", entry.?.content);
    try std.testing.expect(entry.?.category.eql(.core));
}

test "sqlite store upsert" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("pref", "likes Zig", .core);
    try m.store("pref", "loves Zig", .core);

    const entry = try m.get(std.testing.allocator, "pref");
    try std.testing.expect(entry != null);
    defer entry.?.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("loves Zig", entry.?.content);

    const cnt = try m.count();
    try std.testing.expectEqual(@as(usize, 1), cnt);
}

test "sqlite recall keyword" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "Zig is fast and safe", .core);
    try m.store("b", "Python is interpreted", .core);
    try m.store("c", "Zig has comptime", .core);

    const results = try m.recall(std.testing.allocator, "Zig", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    for (results) |entry| {
        try std.testing.expect(std.mem.indexOf(u8, entry.content, "Zig") != null);
    }
}

test "sqlite recall no match" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "Zig rocks", .core);

    const results = try m.recall(std.testing.allocator, "javascript", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite recall empty query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "data", .core);

    const results = try m.recall(std.testing.allocator, "", 10);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite recall whitespace query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "data", .core);

    const results = try m.recall(std.testing.allocator, "   ", 10);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite forget" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("temp", "temporary data", .conversation);
    try std.testing.expectEqual(@as(usize, 1), try m.count());

    const removed = try m.forget("temp");
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

test "sqlite forget nonexistent" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const removed = try m.forget("nope");
    try std.testing.expect(!removed);
}

test "sqlite list all" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "one", .core);
    try m.store("b", "two", .daily);
    try m.store("c", "three", .conversation);

    const all = try m.list(std.testing.allocator, null);
    defer root.freeEntries(std.testing.allocator, all);
    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "sqlite list by category" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "core1", .core);
    try m.store("b", "core2", .core);
    try m.store("c", "daily1", .daily);

    const core_list = try m.list(std.testing.allocator, .core);
    defer root.freeEntries(std.testing.allocator, core_list);
    try std.testing.expectEqual(@as(usize, 2), core_list.len);

    const daily_list = try m.list(std.testing.allocator, .daily);
    defer root.freeEntries(std.testing.allocator, daily_list);
    try std.testing.expectEqual(@as(usize, 1), daily_list.len);
}

test "sqlite count empty" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

test "sqlite get nonexistent" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const entry = try m.get(std.testing.allocator, "nope");
    try std.testing.expect(entry == null);
}

test "sqlite category roundtrip" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k0", "v0", .core);
    try m.store("k1", "v1", .daily);
    try m.store("k2", "v2", .conversation);
    try m.store("k3", "v3", .{ .custom = "project" });

    const e0 = (try m.get(std.testing.allocator, "k0")).?;
    defer e0.deinit(std.testing.allocator);
    try std.testing.expect(e0.category.eql(.core));

    const e1 = (try m.get(std.testing.allocator, "k1")).?;
    defer e1.deinit(std.testing.allocator);
    try std.testing.expect(e1.category.eql(.daily));

    const e2 = (try m.get(std.testing.allocator, "k2")).?;
    defer e2.deinit(std.testing.allocator);
    try std.testing.expect(e2.category.eql(.conversation));

    const e3 = (try m.get(std.testing.allocator, "k3")).?;
    defer e3.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("project", e3.category.custom);
}

test "sqlite forget then recall no ghost results" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("ghost", "phantom memory content", .core);
    _ = try m.forget("ghost");

    const results = try m.recall(std.testing.allocator, "phantom memory", 10);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite forget and re-store same key" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("cycle", "version 1", .core);
    _ = try m.forget("cycle");
    try m.store("cycle", "version 2", .core);

    const entry = (try m.get(std.testing.allocator, "cycle")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("version 2", entry.content);
    try std.testing.expectEqual(@as(usize, 1), try m.count());
}

test "sqlite store empty content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("empty", "", .core);
    const entry = (try m.get(std.testing.allocator, "empty")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", entry.content);
}

test "sqlite store empty key" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("", "content for empty key", .core);
    const entry = (try m.get(std.testing.allocator, "")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("content for empty key", entry.content);
}

test "sqlite recall results have scores" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("s1", "scored result test", .core);

    const results = try m.recall(std.testing.allocator, "scored", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len > 0);
    for (results) |entry| {
        try std.testing.expect(entry.score != null);
    }
}

test "sqlite reindex" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("r1", "reindex test alpha", .core);
    try m.store("r2", "reindex test beta", .core);

    try mem.reindex();

    const results = try m.recall(std.testing.allocator, "reindex", 10);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "sqlite recall with sql injection attempt" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("safe", "normal content", .core);

    const results = try m.recall(std.testing.allocator, "'; DROP TABLE memories; --", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), try m.count());
}

test "sqlite schema has fts5 table" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    const sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memories_fts'";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    const count = c.sqlite3_column_int64(stmt, 0);
    try std.testing.expectEqual(@as(i64, 1), count);
}

test "sqlite fts5 syncs on insert" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("test_key", "unique_searchterm_xyz", .core);

    const sql = "SELECT COUNT(*) FROM memories_fts WHERE memories_fts MATCH '\"unique_searchterm_xyz\"'";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    try std.testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(stmt, 0));
}

test "sqlite fts5 syncs on delete" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("del_key", "deletable_content_abc", .core);
    _ = try m.forget("del_key");

    const sql = "SELECT COUNT(*) FROM memories_fts WHERE memories_fts MATCH '\"deletable_content_abc\"'";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    try std.testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(stmt, 0));
}

test "sqlite fts5 syncs on update" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("upd_key", "original_content_111", .core);
    try m.store("upd_key", "updated_content_222", .core);

    {
        const sql = "SELECT COUNT(*) FROM memories_fts WHERE memories_fts MATCH '\"original_content_111\"'";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
        try std.testing.expectEqual(c.SQLITE_OK, rc);
        defer _ = c.sqlite3_finalize(stmt);
        rc = c.sqlite3_step(stmt);
        try std.testing.expectEqual(c.SQLITE_ROW, rc);
        try std.testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(stmt, 0));
    }

    {
        const sql = "SELECT COUNT(*) FROM memories_fts WHERE memories_fts MATCH '\"updated_content_222\"'";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
        try std.testing.expectEqual(c.SQLITE_OK, rc);
        defer _ = c.sqlite3_finalize(stmt);
        rc = c.sqlite3_step(stmt);
        try std.testing.expectEqual(c.SQLITE_ROW, rc);
        try std.testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(stmt, 0));
    }
}

test "sqlite list custom category" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("c1", "custom1", .{ .custom = "project" });
    try m.store("c2", "custom2", .{ .custom = "project" });
    try m.store("c3", "other", .core);

    const project = try m.list(std.testing.allocator, .{ .custom = "project" });
    defer root.freeEntries(std.testing.allocator, project);
    try std.testing.expectEqual(@as(usize, 2), project.len);
}

test "sqlite list empty db" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const all = try m.list(std.testing.allocator, null);
    defer root.freeEntries(std.testing.allocator, all);
    try std.testing.expectEqual(@as(usize, 0), all.len);
}

test "sqlite recall matches by key not just content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("zig_preferences", "User likes systems programming", .core);

    const results = try m.recall(std.testing.allocator, "zig", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len > 0);
}

test "sqlite recall respects limit" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    for (0..10) |i| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch continue;
        var content_buf: [64]u8 = undefined;
        const content = std.fmt.bufPrint(&content_buf, "searchable content number {d}", .{i}) catch continue;
        try m.store(key, content, .core);
    }

    const results = try m.recall(std.testing.allocator, "searchable", 3);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len <= 3);
}

test "sqlite store unicode content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("unicode_key", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", .core);

    const entry = (try m.get(std.testing.allocator, "unicode_key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", entry.content);
}

test "sqlite recall unicode query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("jp", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", .core);

    const results = try m.recall(std.testing.allocator, "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len > 0);
}

test "sqlite store long content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    // Build a long string
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    for (0..1000) |_| {
        try buf.appendSlice(std.testing.allocator, "abcdefghij");
    }

    try m.store("long", buf.items, .core);
    const entry = (try m.get(std.testing.allocator, "long")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 10000), entry.content.len);
}

test "sqlite multiple categories count" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "one", .core);
    try m.store("b", "two", .daily);
    try m.store("c", "three", .conversation);
    try m.store("d", "four", .{ .custom = "project" });

    try std.testing.expectEqual(@as(usize, 4), try m.count());
}

test "sqlite saveMessage stores messages" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    try mem.saveMessage("session-1", "user", "hello");
    try mem.saveMessage("session-1", "assistant", "hi there");
    try mem.saveMessage("session-2", "user", "another session");

    // Verify messages table has data
    const sql = "SELECT COUNT(*) FROM messages";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    try std.testing.expectEqual(@as(i64, 3), c.sqlite3_column_int64(stmt, 0));
}

test "sqlite store and forget multiple keys" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "v1", .core);
    try m.store("k2", "v2", .core);
    try m.store("k3", "v3", .core);

    try std.testing.expectEqual(@as(usize, 3), try m.count());

    _ = try m.forget("k2");
    try std.testing.expectEqual(@as(usize, 2), try m.count());

    _ = try m.forget("k1");
    _ = try m.forget("k3");
    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

test "sqlite upsert changes category" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("key", "value", .core);
    try m.store("key", "new value", .daily);

    const entry = (try m.get(std.testing.allocator, "key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("new value", entry.content);
    try std.testing.expect(entry.category.eql(.daily));
}

test "sqlite recall multi-word query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("zig-lang", "Zig is a systems programming language", .core);
    try m.store("rust-lang", "Rust is also a systems language", .core);
    try m.store("python-lang", "Python is interpreted", .core);

    const results = try m.recall(std.testing.allocator, "systems programming", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len >= 1);
}

test "sqlite list returns all entries" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("first", "first entry", .core);
    try m.store("second", "second entry", .core);
    try m.store("third", "third entry", .core);

    const all = try m.list(std.testing.allocator, null);
    defer root.freeEntries(std.testing.allocator, all);

    try std.testing.expectEqual(@as(usize, 3), all.len);

    // All keys should be present
    var found_first = false;
    var found_second = false;
    var found_third = false;
    for (all) |entry| {
        if (std.mem.eql(u8, entry.key, "first")) found_first = true;
        if (std.mem.eql(u8, entry.key, "second")) found_second = true;
        if (std.mem.eql(u8, entry.key, "third")) found_third = true;
    }
    try std.testing.expect(found_first);
    try std.testing.expect(found_second);
    try std.testing.expect(found_third);
}

test "sqlite get returns entry with all fields" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("test_key", "test_content", .daily);

    const entry = (try m.get(std.testing.allocator, "test_key")).?;
    defer entry.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test_key", entry.key);
    try std.testing.expectEqualStrings("test_content", entry.content);
    try std.testing.expect(entry.category.eql(.daily));
    try std.testing.expect(entry.id.len > 0);
    try std.testing.expect(entry.timestamp.len > 0);
}

test "sqlite recall with quotes in query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("quotes", "He said \"hello\" to the world", .core);

    const results = try m.recall(std.testing.allocator, "hello", 10);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len > 0);
}

test "sqlite health check after operations" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core);
    _ = try m.forget("k");

    try std.testing.expect(m.healthCheck());
}

test "sqlite kv table exists" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    const sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='kv'";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    try std.testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(stmt, 0));
}
