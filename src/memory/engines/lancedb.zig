//! LanceDB-style vector memory backend — SQLite + embedding-based store/recall.
//!
//! Combines SQLite for storage
//! with cosine similarity search for vector-augmented recall. Features:
//!
//! - Duplicate detection: skip entries with >95% cosine similarity
//! - Importance scoring (0.0-1.0) per entry
//! - Full-scan cosine similarity on recall (no ANN index)
//! - Min search score filtering
//! - Category and session isolation
//!
//! Uses the existing vector/math.zig for cosine similarity and serialization.

const std = @import("std");
const std_compat = @import("compat");
const build_options = @import("build_options");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const vector = @import("../vector/math.zig");
const embeddings_mod = @import("../vector/embeddings.zig");
const EmbeddingProvider = embeddings_mod.EmbeddingProvider;
const log = std.log.scoped(.lancedb_memory);

const sqlite_mod = if (build_options.enable_sqlite) @import("sqlite.zig") else @import("sqlite_disabled.zig");
const c = sqlite_mod.c;
const SQLITE_STATIC = sqlite_mod.SQLITE_STATIC;

// ── Config ────────────────────────────────────────────────────────

pub const LanceDbConfig = struct {
    duplicate_threshold: f32 = 0.95,
    min_search_score: f32 = 0.3,
    default_importance: f32 = 0.5,
};

// ── LanceDbMemory ────────────────────────────────────────────────

pub const LanceDbMemory = struct {
    db: ?*c.sqlite3,
    allocator: std.mem.Allocator,
    embedder: ?EmbeddingProvider,
    config: LanceDbConfig,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        db_path: [*:0]const u8,
        embedder: ?EmbeddingProvider,
        config: LanceDbConfig,
    ) !Self {
        const use_wal = sqlite_mod.shouldUseWal(db_path);

        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }

        var self_ = Self{
            .db = db,
            .allocator = allocator,
            .embedder = embedder,
            .config = config,
        };
        self_.configurePragmas(use_wal);
        try self_.migrate();
        return self_;
    }

    fn configurePragmas(self: *Self, use_wal: bool) void {
        const journal_pragma: [:0]const u8 = if (use_wal)
            "PRAGMA journal_mode = WAL;"
        else
            "PRAGMA journal_mode = DELETE;";
        const pragmas = [_][:0]const u8{
            journal_pragma,
            "PRAGMA synchronous  = NORMAL;",
            "PRAGMA temp_store   = MEMORY;",
        };
        for (pragmas) |pragma| {
            var err_msg: [*c]u8 = null;
            const rc = c.sqlite3_exec(self.db, pragma, null, null, &err_msg);
            if (rc != c.SQLITE_OK) {
                if (err_msg) |msg| {
                    log.err("pragma failed: {s}", .{std.mem.span(msg)});
                    c.sqlite3_free(msg);
                }
            }
        }
    }

    fn migrate(self: *Self) !void {
        const sql =
            \\CREATE TABLE IF NOT EXISTS lancedb_memories (
            \\  id         TEXT PRIMARY KEY,
            \\  key        TEXT UNIQUE NOT NULL,
            \\  text       TEXT NOT NULL,
            \\  embedding  BLOB,
            \\  importance REAL DEFAULT 0.5,
            \\  category   TEXT DEFAULT 'other',
            \\  created_at TEXT NOT NULL,
            \\  updated_at TEXT NOT NULL,
            \\  session_id TEXT
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_lance_category ON lancedb_memories(category);
            \\CREATE INDEX IF NOT EXISTS idx_lance_session ON lancedb_memories(session_id);
            \\CREATE INDEX IF NOT EXISTS idx_lance_key ON lancedb_memories(key);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| {
                log.err("lancedb migration failed: {s}", .{std.mem.span(msg)});
                c.sqlite3_free(msg);
            }
            return error.MigrationFailed;
        }
    }

    pub fn deinit(self: *Self) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
    }

    // ── UUID generation ──────────────────────────────────────────

    fn generateUuid(allocator: std.mem.Allocator) ![]u8 {
        var buf: [16]u8 = undefined;
        std_compat.crypto.random.bytes(&buf);
        // Set version 4
        buf[6] = (buf[6] & 0x0f) | 0x40;
        // Set variant bits
        buf[8] = (buf[8] & 0x3f) | 0x80;
        return std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            buf[0],  buf[1],  buf[2],  buf[3],
            buf[4],  buf[5],  buf[6],  buf[7],
            buf[8],  buf[9],  buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15],
        });
    }

    // ── Duplicate detection ──────────────────────────────────────

    fn isDuplicate(self: *Self, new_embedding: []const f32, exclude_key: []const u8) bool {
        const db = self.db orelse return false;

        const sql = "SELECT embedding, key FROM lancedb_memories WHERE embedding IS NOT NULL";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return false;
        defer _ = c.sqlite3_finalize(stmt);

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            // Skip the entry being updated so upserts are not blocked by self-similarity
            const row_key_ptr = c.sqlite3_column_text(stmt, 1);
            if (row_key_ptr != null) {
                const row_key = std.mem.span(row_key_ptr);
                if (std.mem.eql(u8, row_key, exclude_key)) continue;
            }

            const blob_ptr = c.sqlite3_column_blob(stmt, 0);
            const blob_len = c.sqlite3_column_bytes(stmt, 0);
            if (blob_ptr == null or blob_len <= 0) continue;

            const bytes: [*]const u8 = @ptrCast(blob_ptr);
            const slice = bytes[0..@intCast(blob_len)];
            const existing = vector.bytesToVec(self.allocator, slice) catch continue;
            defer self.allocator.free(existing);

            const sim = vector.cosineSimilarity(new_embedding, existing);
            if (sim >= self.config.duplicate_threshold) return true;
        }

        return false;
    }

    // ── Category conversion ──────────────────────────────────────

    fn categoryToString(cat: MemoryCategory) []const u8 {
        return switch (cat) {
            .core => "fact",
            .daily => "preference",
            .conversation => "other",
            .custom => |name| name,
        };
    }

    fn stringToCategory(s: []const u8) MemoryCategory {
        if (std.mem.eql(u8, s, "fact") or std.mem.eql(u8, s, "core")) return .core;
        if (std.mem.eql(u8, s, "preference") or std.mem.eql(u8, s, "daily")) return .daily;
        if (std.mem.eql(u8, s, "other") or std.mem.eql(u8, s, "conversation")) return .conversation;
        return .conversation; // default
    }

    // ── Memory vtable implementation ────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "lancedb";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        // Compute embedding if provider is available
        var emb: ?[]f32 = null;
        var emb_bytes: ?[]u8 = null;
        defer if (emb) |e| self_.allocator.free(e);
        defer if (emb_bytes) |b| self_.allocator.free(b);

        if (self_.embedder) |ep| {
            emb = ep.embed(self_.allocator, content) catch |err| blk: {
                log.warn("embedding failed for key '{s}': {}", .{ key, err });
                break :blk null;
            };
            if (emb) |e| {
                if (e.len > 0) {
                    // Check for duplicates (exclude same key so upserts work)
                    if (self_.isDuplicate(e, key)) {
                        log.debug("duplicate detected for key '{s}', skipping store", .{key});
                        return;
                    }
                    emb_bytes = vector.vecToBytes(self_.allocator, e) catch null;
                }
            }
        }

        const uuid = try generateUuid(self_.allocator);
        defer self_.allocator.free(uuid);
        const uuid_z = try self_.allocator.dupeZ(u8, uuid);
        defer self_.allocator.free(uuid_z);

        const cat_str = categoryToString(category);
        const cat_z = try self_.allocator.dupeZ(u8, cat_str);
        defer self_.allocator.free(cat_z);

        const key_z = try self_.allocator.dupeZ(u8, key);
        defer self_.allocator.free(key_z);

        const content_z = try self_.allocator.dupeZ(u8, content);
        defer self_.allocator.free(content_z);

        const now = try std.fmt.allocPrint(self_.allocator, "{d}", .{std_compat.time.timestamp()});
        defer self_.allocator.free(now);

        const sql = "INSERT INTO lancedb_memories (id, key, text, embedding, importance, category, created_at, updated_at, session_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(key) DO UPDATE SET text=?3, embedding=?4, updated_at=?8";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, uuid_z.ptr, @intCast(uuid_z.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, key_z.ptr, @intCast(key_z.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, content_z.ptr, @intCast(content_z.len), SQLITE_STATIC);

        if (emb_bytes) |eb| {
            _ = c.sqlite3_bind_blob(stmt, 4, eb.ptr, @intCast(eb.len), SQLITE_STATIC);
        } else {
            _ = c.sqlite3_bind_null(stmt, 4);
        }

        _ = c.sqlite3_bind_double(stmt, 5, self_.config.default_importance);
        _ = c.sqlite3_bind_text(stmt, 6, cat_z.ptr, @intCast(cat_z.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 7, now.ptr, @intCast(now.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 8, now.ptr, @intCast(now.len), SQLITE_STATIC);

        // session_id binding — must outlive sqlite3_step, so allocate outside the if block
        var sid_z: ?[:0]u8 = null;
        defer if (sid_z) |sz| self_.allocator.free(sz);

        if (session_id) |sid| {
            sid_z = try self_.allocator.dupeZ(u8, sid);
            _ = c.sqlite3_bind_text(stmt, 9, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
        } else {
            _ = c.sqlite3_bind_null(stmt, 9);
        }

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        // Try vector-based recall if embedder is available
        if (self_.embedder) |ep| {
            const query_emb = ep.embed(allocator, query) catch null;
            if (query_emb) |qe| {
                defer allocator.free(qe);
                if (qe.len > 0) {
                    return self_.vectorRecall(db, allocator, qe, limit, session_id);
                }
            }
        }

        // Fallback: text-based LIKE search
        return self_.textRecall(db, allocator, query, limit, session_id);
    }

    fn vectorRecall(self_: *Self, db: *c.sqlite3, allocator: std.mem.Allocator, query_emb: []const f32, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
        const sql = if (session_id != null)
            "SELECT key, text, category, created_at, embedding FROM lancedb_memories WHERE embedding IS NOT NULL AND session_id = ?1 ORDER BY created_at DESC LIMIT 1000"
        else
            "SELECT key, text, category, created_at, embedding FROM lancedb_memories WHERE embedding IS NOT NULL ORDER BY created_at DESC LIMIT 1000";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        // Bind session_id filter — must outlive sqlite3_step loop
        var sid_z: ?[:0]u8 = null;
        defer if (sid_z) |sz| allocator.free(sz);
        if (session_id) |sid| {
            sid_z = try allocator.dupeZ(u8, sid);
            _ = c.sqlite3_bind_text(stmt, 1, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
        }

        const Scored = struct { entry: MemoryEntry, score: f32 };
        var scored: std.ArrayListUnmanaged(Scored) = .empty;
        errdefer {
            for (scored.items) |*s| s.entry.deinit(allocator);
            scored.deinit(allocator);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            // Get embedding
            const blob_ptr = c.sqlite3_column_blob(stmt, 4);
            const blob_len = c.sqlite3_column_bytes(stmt, 4);
            if (blob_ptr == null or blob_len <= 0) continue;

            const bytes: [*]const u8 = @ptrCast(blob_ptr);
            const slice = bytes[0..@intCast(blob_len)];
            const entry_emb = vector.bytesToVec(self_.allocator, slice) catch continue;
            defer self_.allocator.free(entry_emb);

            const sim = vector.cosineSimilarity(query_emb, entry_emb);
            if (sim < self_.config.min_search_score) continue;

            // Build entry
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const text_ptr = c.sqlite3_column_text(stmt, 1);
            const cat_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_ptr = c.sqlite3_column_text(stmt, 3);

            if (key_ptr == null or text_ptr == null) continue;

            const key = try allocator.dupe(u8, std.mem.span(key_ptr));
            errdefer allocator.free(key);
            const content = try allocator.dupe(u8, std.mem.span(text_ptr));
            errdefer allocator.free(content);
            const id = try allocator.dupe(u8, key);
            errdefer allocator.free(id);
            const timestamp = if (ts_ptr != null) try allocator.dupe(u8, std.mem.span(ts_ptr)) else try allocator.dupe(u8, "0");
            errdefer allocator.free(timestamp);
            const cat_str = if (cat_ptr != null) std.mem.span(cat_ptr) else "other";

            try scored.append(allocator, .{
                .entry = .{
                    .id = id,
                    .key = key,
                    .content = content,
                    .category = stringToCategory(cat_str),
                    .timestamp = timestamp,
                    .session_id = null,
                },
                .score = sim,
            });
        }

        // Sort by score descending
        std.mem.sort(Scored, scored.items, {}, struct {
            fn lessThan(_: void, a: Scored, b: Scored) bool {
                return a.score > b.score;
            }
        }.lessThan);

        // Take top-k
        const take = @min(scored.items.len, limit);
        const result = try allocator.alloc(MemoryEntry, take);
        for (0..take) |i| {
            result[i] = scored.items[i].entry;
        }
        // Free entries beyond the limit
        for (take..scored.items.len) |i| {
            scored.items[i].entry.deinit(allocator);
        }
        // Clear scored without freeing moved entries (defer only frees the backing array)
        scored.clearAndFree(allocator);

        return result;
    }

    fn textRecall(self_: *Self, db: *c.sqlite3, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
        _ = self_;

        const like_pattern = try std.fmt.allocPrint(allocator, "%{s}%", .{query});
        defer allocator.free(like_pattern);

        const sql = if (session_id != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE (text LIKE ?1 OR key LIKE ?1) AND session_id = ?3 ORDER BY created_at DESC LIMIT ?2"
        else
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE text LIKE ?1 OR key LIKE ?1 ORDER BY created_at DESC LIMIT ?2";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, like_pattern.ptr, @intCast(like_pattern.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(limit));

        // Bind session_id filter — must outlive sqlite3_step loop
        var sid_z: ?[:0]u8 = null;
        defer if (sid_z) |sz| allocator.free(sz);
        if (session_id) |sid| {
            sid_z = try allocator.dupeZ(u8, sid);
            _ = c.sqlite3_bind_text(stmt, 3, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
        }

        var results: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*e| e.deinit(allocator);
            results.deinit(allocator);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const text_ptr = c.sqlite3_column_text(stmt, 1);
            const cat_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_ptr = c.sqlite3_column_text(stmt, 3);

            if (key_ptr == null or text_ptr == null) continue;

            const key = try allocator.dupe(u8, std.mem.span(key_ptr));
            errdefer allocator.free(key);
            const content = try allocator.dupe(u8, std.mem.span(text_ptr));
            errdefer allocator.free(content);
            const id = try allocator.dupe(u8, key);
            errdefer allocator.free(id);
            const timestamp = if (ts_ptr != null) try allocator.dupe(u8, std.mem.span(ts_ptr)) else try allocator.dupe(u8, "0");
            errdefer allocator.free(timestamp);
            const cat_str = if (cat_ptr != null) std.mem.span(cat_ptr) else "other";

            try results.append(allocator, .{
                .id = id,
                .key = key,
                .content = content,
                .category = stringToCategory(cat_str),
                .timestamp = timestamp,
                .session_id = null,
            });
        }

        const owned = try results.toOwnedSlice(allocator);
        return owned;
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        const key_z = try allocator.dupeZ(u8, key);
        defer allocator.free(key_z);

        const sql = "SELECT key, text, category, created_at FROM lancedb_memories WHERE key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_z.ptr, @intCast(key_z.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const text_ptr = c.sqlite3_column_text(stmt, 1);
            const cat_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_ptr = c.sqlite3_column_text(stmt, 3);

            if (key_ptr == null or text_ptr == null) return null;

            const k = try allocator.dupe(u8, std.mem.span(key_ptr));
            errdefer allocator.free(k);
            const content = try allocator.dupe(u8, std.mem.span(text_ptr));
            errdefer allocator.free(content);
            const id = try allocator.dupe(u8, k);
            errdefer allocator.free(id);
            const timestamp = if (ts_ptr != null) try allocator.dupe(u8, std.mem.span(ts_ptr)) else try allocator.dupe(u8, "0");
            errdefer allocator.free(timestamp);
            const cat_str = if (cat_ptr != null) std.mem.span(cat_ptr) else "other";

            return .{
                .id = id,
                .key = k,
                .content = content,
                .category = stringToCategory(cat_str),
                .timestamp = timestamp,
                .session_id = null,
            };
        }

        return null;
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        var results: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*e| e.deinit(allocator);
            results.deinit(allocator);
        }

        // Build SQL with optional category and session_id filters
        const sql = if (category != null and session_id != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE category = ?1 AND session_id = ?2 ORDER BY created_at DESC"
        else if (category != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE category = ?1 ORDER BY created_at DESC"
        else if (session_id != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE session_id = ?1 ORDER BY created_at DESC"
        else
            "SELECT key, text, category, created_at FROM lancedb_memories ORDER BY created_at DESC";

        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        // Bind category filter — must outlive sqlite3_step
        var cat_z_buf: ?[:0]u8 = null;
        defer if (cat_z_buf) |cz| allocator.free(cz);
        var sid_z: ?[:0]u8 = null;
        defer if (sid_z) |sz| allocator.free(sz);

        if (category != null and session_id != null) {
            const cat_str = categoryToString(category.?);
            cat_z_buf = try allocator.dupeZ(u8, cat_str);
            _ = c.sqlite3_bind_text(stmt, 1, cat_z_buf.?.ptr, @intCast(cat_z_buf.?.len), SQLITE_STATIC);
            sid_z = try allocator.dupeZ(u8, session_id.?);
            _ = c.sqlite3_bind_text(stmt, 2, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
        } else if (category) |cat| {
            const cat_str = categoryToString(cat);
            cat_z_buf = try allocator.dupeZ(u8, cat_str);
            _ = c.sqlite3_bind_text(stmt, 1, cat_z_buf.?.ptr, @intCast(cat_z_buf.?.len), SQLITE_STATIC);
        } else if (session_id) |sid| {
            sid_z = try allocator.dupeZ(u8, sid);
            _ = c.sqlite3_bind_text(stmt, 1, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const text_ptr = c.sqlite3_column_text(stmt, 1);
            const cat_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_ptr = c.sqlite3_column_text(stmt, 3);

            if (key_ptr == null or text_ptr == null) continue;

            const k = try allocator.dupe(u8, std.mem.span(key_ptr));
            errdefer allocator.free(k);
            const content = try allocator.dupe(u8, std.mem.span(text_ptr));
            errdefer allocator.free(content);
            const id = try allocator.dupe(u8, k);
            errdefer allocator.free(id);
            const timestamp = if (ts_ptr != null) try allocator.dupe(u8, std.mem.span(ts_ptr)) else try allocator.dupe(u8, "0");
            errdefer allocator.free(timestamp);
            const cat_str = if (cat_ptr != null) std.mem.span(cat_ptr) else "other";

            try results.append(allocator, .{
                .id = id,
                .key = k,
                .content = content,
                .category = stringToCategory(cat_str),
                .timestamp = timestamp,
                .session_id = null,
            });
        }

        return try results.toOwnedSlice(allocator);
    }

    fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8, limit: usize, offset: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        var results: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*e| e.deinit(allocator);
            results.deinit(allocator);
        }

        const sql = if (category != null and session_id != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE category = ?1 AND session_id = ?2 ORDER BY created_at DESC, key DESC LIMIT ?3 OFFSET ?4"
        else if (category != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE category = ?1 ORDER BY created_at DESC, key DESC LIMIT ?2 OFFSET ?3"
        else if (session_id != null)
            "SELECT key, text, category, created_at FROM lancedb_memories WHERE session_id = ?1 ORDER BY created_at DESC, key DESC LIMIT ?2 OFFSET ?3"
        else
            "SELECT key, text, category, created_at FROM lancedb_memories ORDER BY created_at DESC, key DESC LIMIT ?1 OFFSET ?2";

        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        var cat_z_buf: ?[:0]u8 = null;
        defer if (cat_z_buf) |cz| allocator.free(cz);
        var sid_z: ?[:0]u8 = null;
        defer if (sid_z) |sz| allocator.free(sz);

        if (category != null and session_id != null) {
            const cat_str = categoryToString(category.?);
            cat_z_buf = try allocator.dupeZ(u8, cat_str);
            _ = c.sqlite3_bind_text(stmt, 1, cat_z_buf.?.ptr, @intCast(cat_z_buf.?.len), SQLITE_STATIC);
            sid_z = try allocator.dupeZ(u8, session_id.?);
            _ = c.sqlite3_bind_text(stmt, 2, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_int64(stmt, 3, @intCast(limit));
            _ = c.sqlite3_bind_int64(stmt, 4, @intCast(offset));
        } else if (category) |cat| {
            const cat_str = categoryToString(cat);
            cat_z_buf = try allocator.dupeZ(u8, cat_str);
            _ = c.sqlite3_bind_text(stmt, 1, cat_z_buf.?.ptr, @intCast(cat_z_buf.?.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(limit));
            _ = c.sqlite3_bind_int64(stmt, 3, @intCast(offset));
        } else if (session_id) |sid| {
            sid_z = try allocator.dupeZ(u8, sid);
            _ = c.sqlite3_bind_text(stmt, 1, sid_z.?.ptr, @intCast(sid_z.?.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(limit));
            _ = c.sqlite3_bind_int64(stmt, 3, @intCast(offset));
        } else {
            _ = c.sqlite3_bind_int64(stmt, 1, @intCast(limit));
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(offset));
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const text_ptr = c.sqlite3_column_text(stmt, 1);
            const cat_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_ptr = c.sqlite3_column_text(stmt, 3);

            if (key_ptr == null or text_ptr == null) continue;

            const k = try allocator.dupe(u8, std.mem.span(key_ptr));
            errdefer allocator.free(k);
            const content = try allocator.dupe(u8, std.mem.span(text_ptr));
            errdefer allocator.free(content);
            const id = try allocator.dupe(u8, k);
            errdefer allocator.free(id);
            const timestamp = if (ts_ptr != null) try allocator.dupe(u8, std.mem.span(ts_ptr)) else try allocator.dupe(u8, "0");
            errdefer allocator.free(timestamp);
            const cat_str = if (cat_ptr != null) std.mem.span(cat_ptr) else "other";

            try results.append(allocator, .{
                .id = id,
                .key = k,
                .content = content,
                .category = stringToCategory(cat_str),
                .timestamp = timestamp,
                .session_id = if (session_id) |sid| try allocator.dupe(u8, sid) else null,
            });
        }

        return try results.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        const key_z = try self_.allocator.dupeZ(u8, key);
        defer self_.allocator.free(key_z);

        const sql = "DELETE FROM lancedb_memories WHERE key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_z.ptr, @intCast(key_z.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.DeleteFailed;
        return c.sqlite3_changes(db) > 0;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const db = self_.db orelse return error.NotConnected;

        const sql = "SELECT COUNT(*) FROM lancedb_memories";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            return @intCast(c.sqlite3_column_int(stmt, 0));
        }
        return 0;
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        _ = implCount(ptr) catch return false;
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
        .list = &implList,
        .listPaged = &implListPaged,
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

const testing = std.testing;

test "lancedb store and recall" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try mem.store("greeting", "Hello, world!", .core, null);

    const count = try mem.count();
    try testing.expectEqual(@as(usize, 1), count);

    // Text-based recall (no embedder)
    const results = try mem.recall(allocator, "Hello", 10, null);
    defer root.freeEntries(allocator, results);
    try testing.expect(results.len >= 1);
    try testing.expectEqualStrings("greeting", results[0].key);
}

test "lancedb get by key" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try mem.store("test_key", "test content", .daily, null);

    const entry = try mem.get(allocator, "test_key");
    try testing.expect(entry != null);
    if (entry) |e| {
        var e_mut = e;
        defer e_mut.deinit(allocator);
        try testing.expectEqualStrings("test content", e.content);
    }
}

test "lancedb forget" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try mem.store("to_forget", "bye", .conversation, null);
    try testing.expectEqual(@as(usize, 1), try mem.count());

    const deleted = try mem.forget("to_forget");
    try testing.expect(deleted);
    try testing.expectEqual(@as(usize, 0), try mem.count());
}

test "lancedb list by category" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try mem.store("fact1", "Earth orbits Sun", .core, null);
    try mem.store("pref1", "User likes Zig", .daily, null);
    try mem.store("talk1", "Discussed memory", .conversation, null);

    const facts = try mem.list(allocator, .core, null);
    defer root.freeEntries(allocator, facts);
    try testing.expectEqual(@as(usize, 1), facts.len);
}

test "lancedb empty recall" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    const results = try mem.recall(allocator, "anything", 10, null);
    defer root.freeEntries(allocator, results);
    try testing.expectEqual(@as(usize, 0), results.len);
}

test "lancedb health check" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try testing.expect(mem.healthCheck());
}

test "lancedb upsert updates existing" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    try mem.store("key1", "version 1", .core, null);
    try mem.store("key1", "version 2", .core, null);

    try testing.expectEqual(@as(usize, 1), try mem.count());

    const entry = try mem.get(allocator, "key1");
    try testing.expect(entry != null);
    if (entry) |e| {
        var e_mut = e;
        defer e_mut.deinit(allocator);
        try testing.expectEqualStrings("version 2", e.content);
    }
}

test "lancedb forget nonexistent returns false" {
    const allocator = testing.allocator;
    var impl_ = try LanceDbMemory.init(allocator, ":memory:", null, .{});
    defer impl_.deinit();

    var mem = impl_.memory();
    const deleted = try mem.forget("no_such_key");
    try testing.expect(!deleted);
}
