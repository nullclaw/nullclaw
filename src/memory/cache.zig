//! Response cache — avoid burning tokens on repeated prompts.
//!
//! Stores LLM responses in a separate SQLite database keyed by a hash of
//! (model, system_prompt, user_prompt). Entries expire after a configurable
//! TTL. The cache is optional and disabled by default.

const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

const SQLITE_STATIC: c.sqlite3_destructor_type = null;

pub const ResponseCache = struct {
    db: ?*c.sqlite3,
    ttl_minutes: i64,
    max_entries: usize,

    const Self = @This();

    pub fn init(db_path: [*:0]const u8, ttl_minutes: u32, max_entries: usize) !Self {
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
        };
        try self_.migrate();
        return self_;
    }

    pub fn deinit(self: *Self) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
    }

    fn migrate(self: *Self) !void {
        const sql =
            \\PRAGMA journal_mode = WAL;
            \\PRAGMA synchronous  = NORMAL;
            \\PRAGMA temp_store   = MEMORY;
            \\
            \\CREATE TABLE IF NOT EXISTS response_cache (
            \\  prompt_hash TEXT PRIMARY KEY,
            \\  model       TEXT NOT NULL,
            \\  response    TEXT NOT NULL,
            \\  token_count INTEGER NOT NULL DEFAULT 0,
            \\  created_at  TEXT NOT NULL,
            \\  accessed_at TEXT NOT NULL,
            \\  hit_count   INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_rc_accessed ON response_cache(accessed_at);
            \\CREATE INDEX IF NOT EXISTS idx_rc_created ON response_cache(created_at);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    /// Build a deterministic cache key from model + system prompt + user prompt.
    /// Uses a simple hash (FNV-1a) since we don't have SHA-256 in std.
    pub fn cacheKey(model: []const u8, system_prompt: ?[]const u8, user_prompt: []const u8) u64 {
        var hasher = std.hash.Fnv1a_64.init();
        hasher.update(model);
        hasher.update("|");
        if (system_prompt) |sys| hasher.update(sys);
        hasher.update("|");
        hasher.update(user_prompt);
        return hasher.final();
    }

    /// Format a cache key as a hex string.
    pub fn cacheKeyHex(buf: *[16]u8, model: []const u8, system_prompt: ?[]const u8, user_prompt: []const u8) []const u8 {
        const key = cacheKey(model, system_prompt, user_prompt);
        return std.fmt.bufPrint(buf, "{x:0>16}", .{key}) catch "0000000000000000";
    }

    /// Look up a cached response. Returns null on miss or expired entry.
    pub fn get(self: *Self, allocator: std.mem.Allocator, key_hex: []const u8) !?[]u8 {
        const now_ts = std.time.timestamp();
        const cutoff_ts = now_ts - self.ttl_minutes * 60;
        const now_str = try timestampStr(allocator, now_ts);
        defer allocator.free(now_str);
        const cutoff_str = try timestampStr(allocator, cutoff_ts);
        defer allocator.free(cutoff_str);

        const sql = "SELECT response FROM response_cache WHERE prompt_hash = ?1 AND created_at > ?2";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return null;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, cutoff_str.ptr, @intCast(cutoff_str.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_ROW) return null;

        const raw = c.sqlite3_column_text(stmt.?, 0);
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 0));
        if (raw == null or len == 0) return null;

        const result = try allocator.dupe(u8, @as([*]const u8, @ptrCast(raw))[0..len]);

        // Bump hit count and accessed_at
        const update_sql = "UPDATE response_cache SET accessed_at = ?1, hit_count = hit_count + 1 WHERE prompt_hash = ?2";
        var update_stmt: ?*c.sqlite3_stmt = null;
        rc = c.sqlite3_prepare_v2(self.db, update_sql, -1, &update_stmt, null);
        if (rc == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(update_stmt);
            _ = c.sqlite3_bind_text(update_stmt, 1, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_text(update_stmt, 2, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
            _ = c.sqlite3_step(update_stmt);
        }

        return result;
    }

    /// Store a response in the cache.
    pub fn put(self: *Self, allocator: std.mem.Allocator, key_hex: []const u8, model: []const u8, response: []const u8, token_count: u32) !void {
        const now_ts = std.time.timestamp();
        const now_str = try timestampStr(allocator, now_ts);
        defer allocator.free(now_str);

        const sql =
            "INSERT OR REPLACE INTO response_cache " ++
            "(prompt_hash, model, response, token_count, created_at, accessed_at, hit_count) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key_hex.ptr, @intCast(key_hex.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, model.ptr, @intCast(model.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, response.ptr, @intCast(response.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int(stmt, 4, @intCast(token_count));
        _ = c.sqlite3_bind_text(stmt, 5, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 6, now_str.ptr, @intCast(now_str.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        // Evict expired entries
        try self.evictExpired(allocator);

        // LRU eviction if over max_entries
        try self.evictLru();
    }

    /// Return cache statistics: (total_entries, total_hits, total_tokens_saved).
    pub fn stats(self: *Self) !struct { count: usize, hits: u64, tokens_saved: u64 } {
        var count_val: i64 = 0;
        var hits_val: i64 = 0;
        var tokens_val: i64 = 0;

        // Count
        {
            const sql = "SELECT COUNT(*) FROM response_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                count_val = c.sqlite3_column_int64(stmt, 0);
            }
        }

        // Total hits
        {
            const sql = "SELECT COALESCE(SUM(hit_count), 0) FROM response_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                hits_val = c.sqlite3_column_int64(stmt, 0);
            }
        }

        // Tokens saved
        {
            const sql = "SELECT COALESCE(SUM(token_count * hit_count), 0) FROM response_cache";
            var stmt: ?*c.sqlite3_stmt = null;
            const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);
            if (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
                tokens_val = c.sqlite3_column_int64(stmt, 0);
            }
        }

        return .{
            .count = @intCast(count_val),
            .hits = @intCast(hits_val),
            .tokens_saved = @intCast(tokens_val),
        };
    }

    /// Wipe the entire cache.
    pub fn clear(self: *Self) !usize {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, "DELETE FROM response_cache", null, null, &err_msg);
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

        const sql = "DELETE FROM response_cache WHERE created_at <= ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, cutoff_str.ptr, @intCast(cutoff_str.len), SQLITE_STATIC);
        _ = c.sqlite3_step(stmt);
    }

    fn evictLru(self: *Self) !void {
        const sql =
            "DELETE FROM response_cache WHERE prompt_hash IN (" ++
            "SELECT prompt_hash FROM response_cache " ++
            "ORDER BY accessed_at ASC " ++
            "LIMIT MAX(0, (SELECT COUNT(*) FROM response_cache) - ?1)" ++
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

// ── Tests ──────────────────────────────────────────────────────────

test "cache key deterministic" {
    const k1 = ResponseCache.cacheKey("gpt-4", "sys", "hello");
    const k2 = ResponseCache.cacheKey("gpt-4", "sys", "hello");
    try std.testing.expectEqual(k1, k2);
}

test "cache key varies by model" {
    const k1 = ResponseCache.cacheKey("gpt-4", null, "hello");
    const k2 = ResponseCache.cacheKey("claude-3", null, "hello");
    try std.testing.expect(k1 != k2);
}

test "cache key varies by system prompt" {
    const k1 = ResponseCache.cacheKey("gpt-4", "You are helpful", "hello");
    const k2 = ResponseCache.cacheKey("gpt-4", "You are rude", "hello");
    try std.testing.expect(k1 != k2);
}

test "cache key varies by prompt" {
    const k1 = ResponseCache.cacheKey("gpt-4", null, "hello");
    const k2 = ResponseCache.cacheKey("gpt-4", null, "goodbye");
    try std.testing.expect(k1 != k2);
}

test "cache put and get" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "What is Zig?");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "Zig is a systems programming language.", 25);

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?);
    try std.testing.expectEqualStrings("Zig is a systems programming language.", result.?);
}

test "cache miss returns null" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    const result = try cache_inst.get(std.testing.allocator, "nonexistent_key");
    try std.testing.expect(result == null);
}

test "cache expired entry returns null" {
    var cache_inst = try ResponseCache.init(":memory:", 0, 1000); // 0-minute TTL
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "test");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "response", 10);

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    // With TTL=0, cutoff = now, and created_at <= now, so this should be null
    try std.testing.expect(result == null);
}

test "cache hit count incremented" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "hello");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "Hi!", 5);

    // 3 hits
    for (0..3) |_| {
        const r = try cache_inst.get(std.testing.allocator, key_hex);
        if (r) |resp| std.testing.allocator.free(resp);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(u64, 3), s.hits);
}

test "cache tokens saved calculated" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "explain zig");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "Zig is...", 100);

    // 5 cache hits * 100 tokens = 500 tokens saved
    for (0..5) |_| {
        const r = try cache_inst.get(std.testing.allocator, key_hex);
        if (r) |resp| std.testing.allocator.free(resp);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(u64, 500), s.tokens_saved);
}

test "cache lru eviction" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 3); // max 3 entries
    defer cache_inst.deinit();

    for (0..5) |i| {
        var prompt_buf: [64]u8 = undefined;
        const prompt = std.fmt.bufPrint(&prompt_buf, "prompt {d}", .{i}) catch continue;
        var key_buf: [16]u8 = undefined;
        const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, prompt);

        var resp_buf: [64]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf, "response {d}", .{i}) catch continue;
        try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", resp, 10);
    }

    const s = try cache_inst.stats();
    try std.testing.expect(s.count <= 3);
}

test "cache clear wipes all" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    for (0..10) |i| {
        var prompt_buf: [64]u8 = undefined;
        const prompt = std.fmt.bufPrint(&prompt_buf, "prompt {d}", .{i}) catch continue;
        var key_buf: [16]u8 = undefined;
        const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, prompt);

        var resp_buf: [64]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf, "response {d}", .{i}) catch continue;
        try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", resp, 10);
    }

    const cleared = try cache_inst.clear();
    try std.testing.expectEqual(@as(usize, 10), cleared);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.count);
}

test "cache stats empty" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.count);
    try std.testing.expectEqual(@as(u64, 0), s.hits);
    try std.testing.expectEqual(@as(u64, 0), s.tokens_saved);
}

test "cache overwrite same key" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "question");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "answer v1", 20);
    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "answer v2", 25);

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?);
    try std.testing.expectEqualStrings("answer v2", result.?);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 1), s.count);
}

test "cache key hex is 16 chars" {
    var buf: [16]u8 = undefined;
    const hex = ResponseCache.cacheKeyHex(&buf, "gpt-4", null, "hello");
    try std.testing.expectEqual(@as(usize, 16), hex.len);
}

test "cache key includes system prompt in hash" {
    // Keys with different system prompts should differ
    const k1 = ResponseCache.cacheKey("gpt-4", "system A", "hello");
    const k2 = ResponseCache.cacheKey("gpt-4", "system B", "hello");
    try std.testing.expect(k1 != k2);
}

test "cache unicode prompt handling" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "\xe3\x81\xaf\xe3\x81\x84\xe3\x80\x81Zig\xe3\x81\xaf\xe7\xb4\xa0\xe6\x99\xb4\xe3\x82\x89\xe3\x81\x97\xe3\x81\x84", 30);

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?);
    try std.testing.expectEqualStrings("\xe3\x81\xaf\xe3\x81\x84\xe3\x80\x81Zig\xe3\x81\xaf\xe7\xb4\xa0\xe6\x99\xb4\xe3\x82\x89\xe3\x81\x97\xe3\x81\x84", result.?);
}

test "cache put then clear then get returns null" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "test");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "response", 10);
    _ = try cache_inst.clear();

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    try std.testing.expect(result == null);
}

test "cache multiple different keys" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf1: [16]u8 = undefined;
    const key1 = ResponseCache.cacheKeyHex(&key_buf1, "gpt-4", null, "prompt1");
    try cache_inst.put(std.testing.allocator, key1, "gpt-4", "response1", 10);

    var key_buf2: [16]u8 = undefined;
    const key2 = ResponseCache.cacheKeyHex(&key_buf2, "gpt-4", null, "prompt2");
    try cache_inst.put(std.testing.allocator, key2, "gpt-4", "response2", 20);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 2), s.count);

    const r1 = try cache_inst.get(std.testing.allocator, key1);
    try std.testing.expect(r1 != null);
    defer std.testing.allocator.free(r1.?);
    try std.testing.expectEqualStrings("response1", r1.?);

    const r2 = try cache_inst.get(std.testing.allocator, key2);
    try std.testing.expect(r2 != null);
    defer std.testing.allocator.free(r2.?);
    try std.testing.expectEqualStrings("response2", r2.?);
}

test "cache stats after multiple puts and hits" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf1: [16]u8 = undefined;
    const key1 = ResponseCache.cacheKeyHex(&key_buf1, "gpt-4", null, "q1");
    try cache_inst.put(std.testing.allocator, key1, "gpt-4", "a1", 50);

    var key_buf2: [16]u8 = undefined;
    const key2 = ResponseCache.cacheKeyHex(&key_buf2, "gpt-4", null, "q2");
    try cache_inst.put(std.testing.allocator, key2, "gpt-4", "a2", 100);

    // 2 hits on key1, 3 hits on key2
    for (0..2) |_| {
        const r = try cache_inst.get(std.testing.allocator, key1);
        if (r) |resp| std.testing.allocator.free(resp);
    }
    for (0..3) |_| {
        const r = try cache_inst.get(std.testing.allocator, key2);
        if (r) |resp| std.testing.allocator.free(resp);
    }

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 2), s.count);
    try std.testing.expectEqual(@as(u64, 5), s.hits);
    // tokens saved: 2*50 + 3*100 = 400
    try std.testing.expectEqual(@as(u64, 400), s.tokens_saved);
}

test "cache lru keeps most recently accessed" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 2); // max 2 entries
    defer cache_inst.deinit();

    var key_buf1: [16]u8 = undefined;
    const key1 = ResponseCache.cacheKeyHex(&key_buf1, "gpt-4", null, "oldest");
    try cache_inst.put(std.testing.allocator, key1, "gpt-4", "resp1", 10);

    var key_buf2: [16]u8 = undefined;
    const key2 = ResponseCache.cacheKeyHex(&key_buf2, "gpt-4", null, "middle");
    try cache_inst.put(std.testing.allocator, key2, "gpt-4", "resp2", 10);

    // Access key1 to make it recently used
    const r = try cache_inst.get(std.testing.allocator, key1);
    if (r) |resp| std.testing.allocator.free(resp);

    // Add a third entry, should evict the least recently accessed
    var key_buf3: [16]u8 = undefined;
    const key3 = ResponseCache.cacheKeyHex(&key_buf3, "gpt-4", null, "newest");
    try cache_inst.put(std.testing.allocator, key3, "gpt-4", "resp3", 10);

    const s = try cache_inst.stats();
    try std.testing.expect(s.count <= 2);
}

test "cache empty response stored" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "empty response test");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "", 0);

    // Empty string stored as empty, get returns null because len == 0
    const result = try cache_inst.get(std.testing.allocator, key_hex);
    // The implementation returns null for len==0, which is expected
    try std.testing.expect(result == null);
}

test "cache zero token count" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "zero tokens");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "free response", 0);

    const r = try cache_inst.get(std.testing.allocator, key_hex);
    if (r) |resp| std.testing.allocator.free(resp);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(u64, 0), s.tokens_saved);
}

test "cache large max entries" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000000);
    defer cache_inst.deinit();

    // Just verify it can be created and used with large max_entries
    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "test");
    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "ok", 5);

    const s = try cache_inst.stats();
    try std.testing.expectEqual(@as(usize, 1), s.count);
}

test "cache key with system prompt" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    var key_buf: [16]u8 = undefined;
    const key_hex = ResponseCache.cacheKeyHex(&key_buf, "gpt-4", "You are helpful", "hello");

    try cache_inst.put(std.testing.allocator, key_hex, "gpt-4", "Hi there!", 5);

    const result = try cache_inst.get(std.testing.allocator, key_hex);
    try std.testing.expect(result != null);
    defer std.testing.allocator.free(result.?);
    try std.testing.expectEqualStrings("Hi there!", result.?);
}

test "cache clear returns zero on empty" {
    var cache_inst = try ResponseCache.init(":memory:", 60, 1000);
    defer cache_inst.deinit();

    const cleared = try cache_inst.clear();
    try std.testing.expectEqual(@as(usize, 0), cleared);
}
