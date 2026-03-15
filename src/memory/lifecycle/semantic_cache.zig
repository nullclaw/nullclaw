//! Semantic response cache — extends the exact-match ResponseCache with
//! cosine similarity matching on query embeddings.
//!
//! Algorithm (from reference/memory/bigtech.md B3):
//!   1. Compute embedding of user_prompt
//!   2. Search cached embeddings for cosine_sim > threshold (default: 0.95)
//!   3. If found: return cached response (semantic hit)
//!   4. If not found: exact hash check (existing behavior)
//!   5. On miss: call LLM, cache response + embedding
//!
//! The semantic cache stores query embeddings alongside responses in a
//! separate SQLite table (semantic_cache). It bridges the response cache
//! with the vector/embeddings module.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const vector_math = @import("../vector/math.zig");
const embeddings_mod = @import("../vector/embeddings.zig");
const EmbeddingProvider = embeddings_mod.EmbeddingProvider;

const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const c = sqlite_mod.c;
const SQLITE_STATIC = sqlite_mod.SQLITE_STATIC;

pub const SemanticCache = struct {
    db: ?*c.sqlite3,
    ttl_minutes: i64,
    max_entries: usize,
    similarity_threshold: f32,
    embedding_provider: ?EmbeddingProvider,

    const Self = @This();

    pub fn init(
        db_path: [*:0]const u8,
        ttl_minutes: u32,
        max_entries: usize,
        similarity_threshold: f32,
        embedding_provider: ?EmbeddingProvider,
    ) !Self {
        if (!build_options.enable_sqlite) {
            if (builtin.is_test) return error.SkipZigTest;
            return error.SqliteOpenFailed;
        }

        const use_wal = sqlite_mod.shouldUseWal(db_path);

        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }

        var self_ = Self{
            .db = db,
            .ttl_minutes = @intCast(ttl_minutes),
            .max_entries = max_entries,
            .similarity_threshold = similarity_threshold,
            .embedding_provider = embedding_provider,
        };
        self_.configurePragmas(use_wal);
        try self_.migrate();
        return self_;
    }

    pub fn deinit(self: *Self) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
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
                if (err_msg) |msg| c.sqlite3_free(msg);
            }
        }
    }

    fn migrate(self: *Self) !void {
        const sql =
            \\CREATE TABLE IF NOT EXISTS semantic_cache (
            \\  id          INTEGER PRIMARY KEY AUTOINCREMENT,
            \\  prompt_hash TEXT NOT NULL,
            \\  model       TEXT NOT NULL,
            \\  response    TEXT NOT NULL,
            \\  token_count INTEGER NOT NULL DEFAULT 0,
            \\  embedding   TEXT,
            \\  created_at  TEXT NOT NULL,
            \\  accessed_at TEXT NOT NULL,
            \\  hit_count   INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_sc_hash ON semantic_cache(prompt_hash);
            \\CREATE INDEX IF NOT EXISTS idx_sc_accessed ON semantic_cache(accessed_at);
            \\CREATE INDEX IF NOT EXISTS idx_sc_created ON semantic_cache(created_at);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    /// Semantic lookup: embed the query, compare against all cached embeddings.
    /// Returns the best matching response if cosine similarity > threshold.
    /// Falls back to exact hash match if no semantic match or no embedding provider.
    pub fn get(self: *Self, allocator: std.mem.Allocator, key_hex: []const u8, query_text: ?[]const u8) !?CacheHit {
        const now_ts = std.time.timestamp();
        const cutoff_ts = now_ts - self.ttl_minutes * 60;
        const cutoff_str = try timestampStr(allocator, cutoff_ts);
        defer allocator.free(cutoff_str);
        const now_str = try timestampStr(allocator, now_ts);
        defer allocator.free(now_str);

        // Step 1: Try semantic match if we have an embedding provider and query text
        if (self.embedding_provider) |ep| {
            if (query_text) |qt| {
                if (qt.len > 0) {
                    const query_emb = ep.embed(allocator, qt) catch null;
                    if (query_emb) |qe| {
                        defer allocator.free(qe);
                        if (qe.len > 0) {
                            if (try self.findSemanticMatch(allocator, qe, cutoff_str, now_str)) |hit| {
                                return hit;
                            }
                        }
                    }
                }
            }
        }

        // Step 2: Fall back to exact hash match
        return self.findExactMatch(allocator, key_hex, cutoff_str, now_str);
    }

    /// Store a response with its query embedding.
    pub fn put(
        self: *Self,
        allocator: std.mem.Allocator,
        key_hex: []const u8,
        model: []const u8,
        response: []const u8,
        token_count: u32,
        query_text: ?[]const u8,
    ) !void {
        const now_ts = std.time.timestamp();
        const now_str = try timestampStr(allocator, now_ts);
        defer allocator.free(now_str);

        // Compute embedding if provider is available
        var embedding_json: ?[]u8 = null;
        if (self.embedding_provider) |ep| {
            if (query_text) |qt| {
                if (qt.len > 0) {
                    const emb = ep.embed(allocator, qt) catch null;
                    if (emb) |e| {
                        defer allocator.free(e);
                        embedding_json = serializeEmbedding(allocator, e) catch null;
                    }
                }
            }
        }
        defer if (embedding_json) |ej| allocator.free(ej);

        // Remove prior entries for this exact hash to prevent unbounded accumulation.
        // Unlike ResponseCache (which uses INSERT OR REPLACE on a UNIQUE key), semantic_cache
        // uses an auto-increment id, so we must delete explicitly.
        {
            const del_sql = "DELETE FROM semantic_cache WHERE prompt_hash = ?1";
            var del_stmt: ?*c.sqlite3_stmt = null;
            const del_rc = c.sqlite3_prepare_v2(self.db, del_sql, -1, &del_stmt, null);
            if (del_rc == c.SQLITE_OK) {
                defer _ = c.sqlite3_finalize(del_stmt);
                _ = c.sqlite3_bind_text(del_stmt, 1, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
                _ = c.sqlite3_step(del_stmt);
            }
        }

        const sql =
            "INSERT INTO semantic_cache " ++
            "(prompt_hash, model, response, token_count, embedding, created_at, accessed_at, hit_count) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, model.ptr, @intCast(model.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, response.ptr, @intCast(response.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int(stmt, 4, @intCast(token_count));

        if (embedding_json) |ej| {
            _ = c.sqlite3_bind_text(stmt, 5, ej.ptr, @intCast(ej.len), SQLITE_STATIC);
        } else {
            _ = c.sqlite3_bind_null(stmt, 5);
        }

        _ = c.sqlite3_bind_text(stmt, 6, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 7, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        // Evict expired + LRU
        self.evictExpired(allocator) catch {};
        self.evictLru() catch {};
    }

    /// Cache hit result.
    pub const CacheHit = struct {
        response: []u8,
        similarity: f32,
        semantic: bool,
    };

    fn findSemanticMatch(self: *Self, allocator: std.mem.Allocator, query_emb: []const f32, cutoff_str: []const u8, now_str: []const u8) !?CacheHit {
        const sql = "SELECT id, response, embedding FROM semantic_cache WHERE created_at > ?1 AND embedding IS NOT NULL";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return null;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, cutoff_str.ptr, @intCast(cutoff_str.len), SQLITE_STATIC);

        var best_sim: f32 = 0.0;
        var best_response: ?[]u8 = null;
        var best_id: i64 = 0;

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const id = c.sqlite3_column_int64(stmt.?, 0);

            const emb_raw = c.sqlite3_column_text(stmt.?, 2);
            const emb_len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 2));
            if (emb_raw == null or emb_len == 0) continue;

            const emb_json: []const u8 = @as([*]const u8, @ptrCast(emb_raw))[0..emb_len];
            const cached_emb = deserializeEmbedding(allocator, emb_json) catch continue;
            defer allocator.free(cached_emb);

            const sim = vector_math.cosineSimilarity(query_emb, cached_emb);
            if (sim > best_sim and sim >= self.similarity_threshold) {
                const resp_raw = c.sqlite3_column_text(stmt.?, 1);
                const resp_len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 1));
                if (resp_raw == null or resp_len == 0) continue;

                const new_response = allocator.dupe(u8, @as([*]const u8, @ptrCast(resp_raw))[0..resp_len]) catch continue;
                // Only update best after successful allocation to avoid losing previous match
                if (best_response) |br| allocator.free(br);
                best_response = new_response;
                best_sim = sim;
                best_id = id;
            }
        }

        if (best_response) |response| {
            // Bump hit count for the matched entry
            self.bumpHitCount(best_id, now_str);
            return .{
                .response = response,
                .similarity = best_sim,
                .semantic = true,
            };
        }

        return null;
    }

    fn findExactMatch(self: *Self, allocator: std.mem.Allocator, key_hex: []const u8, cutoff_str: []const u8, now_str: []const u8) !?CacheHit {
        const sql = "SELECT id, response FROM semantic_cache WHERE prompt_hash = ?1 AND created_at > ?2 ORDER BY created_at DESC LIMIT 1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return null;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, cutoff_str.ptr, @intCast(cutoff_str.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_ROW) return null;

        const id = c.sqlite3_column_int64(stmt.?, 0);
        const raw = c.sqlite3_column_text(stmt.?, 1);
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 1));
        if (raw == null or len == 0) return null;

        const response = try allocator.dupe(u8, @as([*]const u8, @ptrCast(raw))[0..len]);

        self.bumpHitCount(id, now_str);
        return .{
            .response = response,
            .similarity = 1.0,
            .semantic = false,
        };
    }

    fn bumpHitCount(self: *Self, id: i64, now_str: []const u8) void {
        const sql = "UPDATE semantic_cache SET accessed_at = ?1, hit_count = hit_count + 1 WHERE id = ?2";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int64(stmt, 2, id);
        _ = c.sqlite3_step(stmt);
    }

    /// Return cache statistics.
    pub fn stats(self: *Self) !struct { count: usize, hits: u64, tokens_saved: u64, entries_with_embedding: usize } {
        var count_val: i64 = 0;
        var hits_val: i64 = 0;
        var tokens_val: i64 = 0;
        var emb_count: i64 = 0;

        {
            const sql = "SELECT COUNT(*) FROM semantic_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                count_val = c.sqlite3_column_int64(stmt, 0);
            }
        }
        {
            const sql = "SELECT COALESCE(SUM(hit_count), 0) FROM semantic_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                hits_val = c.sqlite3_column_int64(stmt, 0);
            }
        }
        {
            const sql = "SELECT COALESCE(SUM(token_count * hit_count), 0) FROM semantic_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                tokens_val = c.sqlite3_column_int64(stmt, 0);
            }
        }
        {
            const sql = "SELECT COUNT(*) FROM semantic_cache WHERE embedding IS NOT NULL";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                emb_count = c.sqlite3_column_int64(stmt, 0);
            }
        }

        return .{
            .count = @intCast(count_val),
            .hits = @intCast(hits_val),
            .tokens_saved = @intCast(tokens_val),
            .entries_with_embedding = @intCast(emb_count),
        };
    }

    /// Wipe the entire cache.
    pub fn clear(self: *Self) !usize {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, "DELETE FROM semantic_cache", null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.StepFailed;
        }
        return @intCast(c.sqlite3_changes(self.db));
    }

    fn evictExpired(self: *Self, allocator: std.mem.Allocator) !void {
        const now_ts = std.time.timestamp();
        const cutoff_ts = now_ts - self.ttl_minutes * 60;
        const cutoff_str = try timestampStr(allocator, cutoff_ts);
        defer allocator.free(cutoff_str);

        const sql = "DELETE FROM semantic_cache WHERE created_at <= ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, cutoff_str.ptr, @intCast(cutoff_str.len), SQLITE_STATIC);
        _ = c.sqlite3_step(stmt);
    }

    fn evictLru(self: *Self) !void {
        const sql =
            "DELETE FROM semantic_cache WHERE id IN (" ++
            "SELECT id FROM semantic_cache " ++
            "ORDER BY accessed_at ASC " ++
            "LIMIT MAX(0, (SELECT COUNT(*) FROM semantic_cache) - ?1)" ++
            ")";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, @intCast(self.max_entries));
        _ = c.sqlite3_step(stmt);
    }

    fn timestampStr(allocator: std.mem.Allocator, ts: i64) ![]u8 {
        return std.fmt.allocPrint(allocator, "{d}", .{ts});
    }
};

// ── Embedding serialization helpers ────────────────────────────────

/// Serialize f32 slice to JSON array string: "[0.1,0.2,0.3]"
pub fn serializeEmbedding(allocator: std.mem.Allocator, embedding: []const f32) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, '[');
    for (embedding, 0..) |val, i| {
        if (i > 0) try buf.append(allocator, ',');
        var tmp: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{val}) catch return error.FormatError;
        try buf.appendSlice(allocator, s);
    }
    try buf.append(allocator, ']');

    return buf.toOwnedSlice(allocator);
}

/// Deserialize JSON array string to f32 slice.
pub fn deserializeEmbedding(allocator: std.mem.Allocator, json_text: []const u8) ![]f32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return error.InvalidEmbeddingCache;
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.InvalidEmbeddingCache,
    };

    const result = try allocator.alloc(f32, arr.items.len);
    for (arr.items, 0..) |val, i| {
        result[i] = switch (val) {
            .float => |f| @floatCast(f),
            .integer => |n| @floatFromInt(n),
            else => 0.0,
        };
    }
    return result;
}

// ── Tests ──────────────────────────────────────────────────────────

test "serializeEmbedding roundtrip" {
    const embedding = [_]f32{ 0.1, 0.2, -0.5, 3.0 };
    const json = try serializeEmbedding(std.testing.allocator, &embedding);
    defer std.testing.allocator.free(json);

    const back = try deserializeEmbedding(std.testing.allocator, json);
    defer std.testing.allocator.free(back);

    try std.testing.expectEqual(@as(usize, 4), back.len);
    try std.testing.expect(@abs(back[0] - 0.1) < 0.001);
    try std.testing.expect(@abs(back[1] - 0.2) < 0.001);
    try std.testing.expect(@abs(back[2] - (-0.5)) < 0.001);
    try std.testing.expect(@abs(back[3] - 3.0) < 0.001);
}

test "serializeEmbedding empty" {
    const empty = [_]f32{};
    const json = try serializeEmbedding(std.testing.allocator, &empty);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("[]", json);
}

test "deserializeEmbedding invalid json" {
    const result = deserializeEmbedding(std.testing.allocator, "not json");
    try std.testing.expectError(error.InvalidEmbeddingCache, result);
}

test "deserializeEmbedding not array" {
    const result = deserializeEmbedding(std.testing.allocator, "\"hello\"");
    try std.testing.expectError(error.InvalidEmbeddingCache, result);
}

test "SemanticCache init and deinit" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.count);
}

test "SemanticCache put and exact get without embedding" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "abc123", "gpt-4", "Hello!", 10, null);

    const result = try cache_inst.get(std.testing.allocator, "abc123", null);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?.response);
    try std.testing.expectEqualStrings("Hello!", result.?.response);
    try std.testing.expect(!result.?.semantic);
    try std.testing.expect(result.?.similarity == 1.0);
}

test "SemanticCache miss returns null" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    const result = try cache_inst.get(std.testing.allocator, "nonexistent", null);
    try std.testing.expect(result == null);
}

test "SemanticCache stats tracks entries" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "key1", "gpt-4", "resp1", 10, null);
    try cache_inst.put(std.testing.allocator, "key2", "gpt-4", "resp2", 20, null);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 2), s.count);
    try std.testing.expectEqual(@as(usize, 0), s.entries_with_embedding);
}

test "SemanticCache hit count incremented" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "key1", "gpt-4", "response", 10, null);

    for (0..3) |_| {
        const r = try cache_inst.get(std.testing.allocator, "key1", null);
        if (r) |hit| std.testing.allocator.free(hit.response);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(u64, 3), s.hits);
}

test "SemanticCache clear" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "k1", "gpt-4", "r1", 5, null);
    try cache_inst.put(std.testing.allocator, "k2", "gpt-4", "r2", 5, null);

    const cleared = try cache_inst.clear();
    try std.testing.expectEqual(@as(usize, 2), cleared);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.count);
}

test "SemanticCache lru eviction" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 3, 0.95, null);
    defer cache_inst.deinit();

    for (0..5) |i| {
        var key_buf: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "key_{d}", .{i}) catch continue;
        try cache_inst.put(std.testing.allocator, key, "gpt-4", "response", 10, null);
    }

    const s = try cache_inst.stats();
    try std.testing.expect(s.count <= 3);
}

test "SemanticCache expired entry returns null" {
    var cache_inst = try SemanticCache.init(":memory:", 0, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "key1", "gpt-4", "resp", 10, null);

    const result = try cache_inst.get(std.testing.allocator, "key1", null);
    try std.testing.expect(result == null);
}

test "SemanticCache tokens saved" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "key1", "gpt-4", "resp", 100, null);

    for (0..4) |_| {
        const r = try cache_inst.get(std.testing.allocator, "key1", null);
        if (r) |hit| std.testing.allocator.free(hit.response);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(u64, 400), s.tokens_saved);
}

test "SemanticCache put same key replaces (no duplicates)" {
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "dup_key", "gpt-4", "answer v1", 10, null);
    try cache_inst.put(std.testing.allocator, "dup_key", "gpt-4", "answer v2", 20, null);
    try cache_inst.put(std.testing.allocator, "dup_key", "gpt-4", "answer v3", 30, null);

    // Should have exactly 1 entry, not 3
    const s2 = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 1), s2.count);

    // Should return the latest
    const result = try cache_inst.get(std.testing.allocator, "dup_key", null);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?.response);
    try std.testing.expectEqualStrings("answer v3", result.?.response);
}

// ── R3 Tests ──────────────────────────────────────────────────────

test "R3: SemanticCache put same prompt_hash twice produces only 1 row" {
    // Regression: with AUTOINCREMENT id and no dedup, rows accumulated unboundedly.
    // The fix is DELETE before INSERT. Verify it works.
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.95, null);
    defer cache_inst.deinit();

    // Put same hash 10 times
    for (0..10) |_| {
        try cache_inst.put(std.testing.allocator, "same_hash", "gpt-4", "response", 5, null);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 1), s.count);
}

test "R3: SemanticCache findSemanticMatch returns null below threshold" {
    // Without an embedding provider, semantic match is skipped.
    // Test exact-match path: a miss key should return null.
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.99, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "hash_a", "gpt-4", "resp_a", 10, null);

    // Query with a different hash and no embedding provider -> no semantic match, no exact match
    const result = try cache_inst.get(std.testing.allocator, "hash_b", "some query");
    try std.testing.expect(result == null);
}

test "R3: SemanticCache exact match returns best match above threshold" {
    // Exact match always returns similarity 1.0 which is above any threshold
    var cache_inst = try SemanticCache.init(":memory:", 60, 1000, 0.99, null);
    defer cache_inst.deinit();

    try cache_inst.put(std.testing.allocator, "exact_key", "gpt-4", "exact response", 10, null);

    const result = try cache_inst.get(std.testing.allocator, "exact_key", null);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?.response);
    try std.testing.expectEqualStrings("exact response", result.?.response);
    try std.testing.expect(result.?.similarity == 1.0);
    try std.testing.expect(!result.?.semantic);
}
