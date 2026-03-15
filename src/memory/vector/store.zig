//! VectorStore — vtable interface + SQLite shared implementation.
//!
//! Provides a generic vector store abstraction for embedding-based
//! similarity search, plus a concrete SQLite implementation that
//! shares the database handle with SqliteMemory (memory_embeddings table).

const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const vector = @import("math.zig");
const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const c = sqlite_mod.c;
const SQLITE_STATIC = sqlite_mod.SQLITE_STATIC;

// ── Health status ─────────────────────────────────────────────────

pub const HealthStatus = struct {
    ok: bool,
    latency_ns: u64,
    entry_count: ?usize,
    error_msg: ?[]const u8,

    pub fn deinit(self: *const HealthStatus, allocator: Allocator) void {
        if (self.error_msg) |msg| allocator.free(msg);
    }
};

// ── Result types ──────────────────────────────────────────────────

pub const VectorResult = struct {
    key: []const u8,
    score: f32, // cosine similarity [0,1]

    pub fn deinit(self: *const VectorResult, allocator: Allocator) void {
        allocator.free(self.key);
    }
};

pub fn freeVectorResults(allocator: Allocator, results: []VectorResult) void {
    for (results) |*r| r.deinit(allocator);
    allocator.free(results);
}

const ANN_SIGNATURE_BITS: u32 = 64;
const ANN_BAND_BITS: u32 = 16;
const ANN_BAND_COUNT: u32 = ANN_SIGNATURE_BITS / ANN_BAND_BITS;
const ANN_DEFAULT_CANDIDATE_MULTIPLIER: u32 = 12;
const ANN_DEFAULT_MIN_CANDIDATES: u32 = 64;

fn queryNorm(query_embedding: []const f32) f64 {
    if (query_embedding.len == 0) return 0.0;

    var norm_sq: f64 = 0.0;
    for (query_embedding) |q_raw| {
        const q: f64 = @floatCast(q_raw);
        norm_sq += q * q;
    }
    return @sqrt(norm_sq);
}

fn cosineSimilarityBlob(query_embedding: []const f32, query_norm: f64, blob: []const u8) f32 {
    if (query_embedding.len == 0) return 0.0;
    if (blob.len != query_embedding.len * 4) return 0.0;
    if (!std.math.isFinite(query_norm) or query_norm < std.math.floatEps(f64)) return 0.0;

    var dot: f64 = 0.0;
    var norm_blob_sq: f64 = 0.0;

    for (query_embedding, 0..) |q_raw, i| {
        const chunk = blob[i * 4 ..][0..4];
        const blob_val: f32 = @bitCast(chunk.*);

        const q: f64 = @floatCast(q_raw);
        const b: f64 = @floatCast(blob_val);
        dot += q * b;
        norm_blob_sq += b * b;
    }

    const denom = query_norm * @sqrt(norm_blob_sq);
    if (!std.math.isFinite(denom) or denom < std.math.floatEps(f64)) return 0.0;

    const raw = dot / denom;
    if (!std.math.isFinite(raw)) return 0.0;

    const clamped = @max(0.0, @min(1.0, raw));
    return @floatCast(clamped);
}

fn indexOfLowestScore(results: []const VectorResult) usize {
    if (results.len == 0) return 0;
    var idx: usize = 0;
    var score = results[0].score;
    for (results[1..], 1..) |r, i| {
        if (r.score < score) {
            score = r.score;
            idx = i;
        }
    }
    return idx;
}

fn appendTopKCandidate(
    alloc: Allocator,
    candidates: *std.ArrayListUnmanaged(VectorResult),
    max_results: usize,
    key: []const u8,
    score: f32,
    lowest_idx: *usize,
    lowest_score: *f32,
) !void {
    if (max_results == 0) return;

    if (candidates.items.len < max_results) {
        const owned_key = try alloc.dupe(u8, key);
        errdefer alloc.free(owned_key);

        try candidates.append(alloc, .{
            .key = owned_key,
            .score = score,
        });
        if (candidates.items.len == 1 or score < lowest_score.*) {
            lowest_idx.* = candidates.items.len - 1;
            lowest_score.* = score;
        }
        return;
    }

    if (score <= lowest_score.*) return;

    const owned_key = try alloc.dupe(u8, key);
    errdefer alloc.free(owned_key);

    candidates.items[lowest_idx.*].deinit(alloc);
    candidates.items[lowest_idx.*] = .{
        .key = owned_key,
        .score = score,
    };

    lowest_idx.* = indexOfLowestScore(candidates.items);
    lowest_score.* = candidates.items[lowest_idx.*].score;
}

fn exactSearchSqlite(
    db: ?*c.sqlite3,
    alloc: Allocator,
    query_embedding: []const f32,
    max_results: usize,
) anyerror![]VectorResult {
    if (max_results == 0) return alloc.alloc(VectorResult, 0);

    const query_norm = queryNorm(query_embedding);
    const sql = "SELECT memory_key, embedding FROM memory_embeddings";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    var candidates: std.ArrayListUnmanaged(VectorResult) = .empty;
    errdefer {
        for (candidates.items) |*r| r.deinit(alloc);
        candidates.deinit(alloc);
    }

    var lowest_idx: usize = 0;
    var lowest_score: f32 = 0.0;

    while (true) {
        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const key_ptr = c.sqlite3_column_text(stmt, 0);
            const key_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            if (key_ptr == null) continue;

            const blob_ptr: ?[*]const u8 = @ptrCast(c.sqlite3_column_blob(stmt, 1));
            const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
            if (blob_ptr == null or blob_len == 0) continue;

            const score = cosineSimilarityBlob(query_embedding, query_norm, blob_ptr.?[0..blob_len]);
            const key_slice: []const u8 = key_ptr[0..key_len];
            try appendTopKCandidate(alloc, &candidates, max_results, key_slice, score, &lowest_idx, &lowest_score);
        } else break;
    }

    if (rc != c.SQLITE_DONE) return error.StepFailed;

    std.mem.sortUnstable(VectorResult, candidates.items, {}, struct {
        fn lessThan(_: void, a: VectorResult, b: VectorResult) bool {
            return a.score > b.score;
        }
    }.lessThan);

    const result = try alloc.dupe(VectorResult, candidates.items);
    candidates.deinit(alloc);
    return result;
}

fn annCandidateLimit(limit: u32, candidate_multiplier: u32, min_candidates: u32) u32 {
    if (limit == 0) return 0;

    const multiplier = @max(candidate_multiplier, @as(u32, 1));
    const scaled_u64 = @as(u64, limit) * @as(u64, multiplier);
    const scaled = @as(u32, @intCast(@min(scaled_u64, @as(u64, std.math.maxInt(u32)))));
    return @max(scaled, @max(limit, min_candidates));
}

fn clampU32ToSqliteInt(value: u32) c_int {
    const max_sqlite_int: u64 = @intCast(std.math.maxInt(c_int));
    const clamped: u64 = @min(@as(u64, value), max_sqlite_int);
    return @intCast(clamped);
}

fn mix64(x_raw: u64) u64 {
    var x = x_raw;
    x ^= x >> 30;
    x *%= 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x *%= 0x94d049bb133111eb;
    x ^= x >> 31;
    return x;
}

fn projectionCoeff(bit_idx: u32, dim_idx: usize) f64 {
    const seed_a = @as(u64, bit_idx) *% 0x9E3779B185EBCA87;
    const dim_u64: u64 = @intCast(dim_idx);
    const seed_b = dim_u64 *% 0xC2B2AE3D27D4EB4F;
    const hashed = mix64(seed_a ^ seed_b ^ 0xD6E8FEB86659FD93);
    const unit = @as(f64, @floatFromInt(hashed & 0xFFFF)) / 65535.0;
    return (unit * 2.0) - 1.0;
}

fn simhashSignatureFromEmbedding(embedding: []const f32) u64 {
    var sig: u64 = 0;
    var bit_idx: u32 = 0;
    while (bit_idx < ANN_SIGNATURE_BITS) : (bit_idx += 1) {
        var dot: f64 = 0.0;
        for (embedding, 0..) |val_raw, dim_idx| {
            const val: f64 = @floatCast(val_raw);
            dot += val * projectionCoeff(bit_idx, dim_idx);
        }
        if (dot >= 0.0) {
            sig |= (@as(u64, 1) << @intCast(bit_idx));
        }
    }
    return sig;
}

fn simhashSignatureFromBlob(blob: []const u8) u64 {
    const dims = blob.len / 4;
    if (dims == 0) return 0;

    var sig: u64 = 0;
    var bit_idx: u32 = 0;
    while (bit_idx < ANN_SIGNATURE_BITS) : (bit_idx += 1) {
        var dot: f64 = 0.0;
        var dim_idx: usize = 0;
        while (dim_idx < dims) : (dim_idx += 1) {
            const chunk = blob[dim_idx * 4 ..][0..4];
            const val: f32 = @bitCast(chunk.*);
            dot += @as(f64, @floatCast(val)) * projectionCoeff(bit_idx, dim_idx);
        }
        if (dot >= 0.0) {
            sig |= (@as(u64, 1) << @intCast(bit_idx));
        }
    }
    return sig;
}

fn signatureBands(sig: u64) [ANN_BAND_COUNT]u16 {
    return .{
        @intCast(sig & 0xFFFF),
        @intCast((sig >> 16) & 0xFFFF),
        @intCast((sig >> 32) & 0xFFFF),
        @intCast((sig >> 48) & 0xFFFF),
    };
}

// ── VectorStore vtable ────────────────────────────────────────────

pub const VectorStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        upsert: *const fn (ptr: *anyopaque, key: []const u8, embedding: []const f32) anyerror!void,
        search: *const fn (ptr: *anyopaque, alloc: Allocator, query_embedding: []const f32, limit: u32) anyerror![]VectorResult,
        delete: *const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
        count: *const fn (ptr: *anyopaque) anyerror!usize,
        health_check: *const fn (ptr: *anyopaque, alloc: Allocator) anyerror!HealthStatus,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn upsert(self: VectorStore, key: []const u8, embedding: []const f32) !void {
        return self.vtable.upsert(self.ptr, key, embedding);
    }

    pub fn search(self: VectorStore, alloc: Allocator, query_embedding: []const f32, limit: u32) ![]VectorResult {
        return self.vtable.search(self.ptr, alloc, query_embedding, limit);
    }

    pub fn delete(self: VectorStore, key: []const u8) !void {
        return self.vtable.delete(self.ptr, key);
    }

    pub fn count(self: VectorStore) !usize {
        return self.vtable.count(self.ptr);
    }

    pub fn healthCheck(self: VectorStore, alloc: Allocator) !HealthStatus {
        return self.vtable.health_check(self.ptr, alloc);
    }

    pub fn deinitStore(self: VectorStore) void {
        self.vtable.deinit(self.ptr);
    }
};

// ── SqliteSharedVectorStore ───────────────────────────────────────

pub const SqliteSharedVectorStore = struct {
    db: ?*c.sqlite3, // borrowed from SqliteMemory — NOT owned
    allocator: Allocator,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, db: ?*c.sqlite3) SqliteSharedVectorStore {
        return .{
            .db = db,
            .allocator = allocator,
        };
    }

    pub fn store(self: *SqliteSharedVectorStore) VectorStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_instance,
        };
    }

    pub fn deinit(self: *SqliteSharedVectorStore) void {
        // Do NOT close the db — it's borrowed from SqliteMemory.
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    // ── vtable implementations ────────────────────────────────────

    fn implUpsert(ptr: *anyopaque, key: []const u8, embedding: []const f32) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const blob = try vector.vecToBytes(self.allocator, embedding);
        defer self.allocator.free(blob);

        const sql = "INSERT OR REPLACE INTO memory_embeddings (memory_key, embedding, updated_at) VALUES (?1, ?2, datetime('now'))";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_blob(stmt, 2, blob.ptr, @intCast(blob.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn implSearch(ptr: *anyopaque, alloc: Allocator, query_embedding: []const f32, limit: u32) anyerror![]VectorResult {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return exactSearchSqlite(self.db, alloc, query_embedding, @intCast(limit));
    }

    fn implDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const sql = "DELETE FROM memory_embeddings WHERE memory_key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const sql = "SELECT COUNT(*) FROM memory_embeddings";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const n = c.sqlite3_column_int64(stmt, 0);
            return @intCast(n);
        }
        return 0;
    }

    fn implHealthCheck(ptr: *anyopaque, alloc: Allocator) anyerror!HealthStatus {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const start = std.time.nanoTimestamp();

        const sql = "SELECT COUNT(*) FROM memory_embeddings";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));
            return HealthStatus{
                .ok = false,
                .latency_ns = elapsed,
                .entry_count = null,
                .error_msg = try alloc.dupe(u8, "sqlite prepare failed"),
            };
        }
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_step(stmt);
        const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));

        if (rc == c.SQLITE_ROW) {
            const n: usize = @intCast(c.sqlite3_column_int64(stmt, 0));
            return HealthStatus{
                .ok = true,
                .latency_ns = elapsed,
                .entry_count = n,
                .error_msg = null,
            };
        }

        return HealthStatus{
            .ok = false,
            .latency_ns = elapsed,
            .entry_count = null,
            .error_msg = try alloc.dupe(u8, "sqlite step failed"),
        };
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    const vtable_instance = VectorStore.VTable{
        .upsert = &implUpsert,
        .search = &implSearch,
        .delete = &implDelete,
        .count = &implCount,
        .health_check = &implHealthCheck,
        .deinit = &implDeinit,
    };
};

// ── Sidecar vector store ──────────────────────────────────────────
//
// Opens its OWN SQLite database for vector storage.  Use this when the
// primary backend is *not* SQLite-based (markdown, postgres, redis, etc.).
// The sidecar owns the db handle and closes it on deinit.

pub const SqliteSidecarVectorStore = struct {
    db: ?*c.sqlite3,
    allocator: Allocator,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, db_path: [*:0]const u8) !SqliteSidecarVectorStore {
        var db: ?*c.sqlite3 = null;
        var rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }
        // Create table (same schema as shared)
        const create_sql = "CREATE TABLE IF NOT EXISTS memory_embeddings (memory_key TEXT PRIMARY KEY, embedding BLOB NOT NULL, updated_at TEXT NOT NULL DEFAULT (datetime('now')))";
        rc = c.sqlite3_exec(db, create_sql, null, null, null);
        if (rc != c.SQLITE_OK) {
            _ = c.sqlite3_close(db);
            return error.MigrationFailed;
        }
        return .{
            .db = db,
            .allocator = allocator,
        };
    }

    pub fn store(self: *SqliteSidecarVectorStore) VectorStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sidecar_vtable,
        };
    }

    pub fn deinit(self: *SqliteSidecarVectorStore) void {
        if (self.db) |d| _ = c.sqlite3_close(d);
        self.db = null;
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    // Reuse shared vtable methods (same db schema, same struct layout).
    // Only deinit differs: sidecar closes its own db handle.
    // Safety: both structs must have `db` and `allocator` at the same offsets.
    comptime {
        const shared_db = @offsetOf(SqliteSharedVectorStore, "db");
        const shared_alloc = @offsetOf(SqliteSharedVectorStore, "allocator");
        const sidecar_db = @offsetOf(SqliteSidecarVectorStore, "db");
        const sidecar_alloc = @offsetOf(SqliteSidecarVectorStore, "allocator");
        if (shared_db != sidecar_db) @compileError("db field offset mismatch between Shared and Sidecar");
        if (shared_alloc != sidecar_alloc) @compileError("allocator field offset mismatch between Shared and Sidecar");
    }
    const sidecar_vtable = VectorStore.VTable{
        .upsert = SqliteSharedVectorStore.vtable_instance.upsert,
        .search = SqliteSharedVectorStore.vtable_instance.search,
        .delete = SqliteSharedVectorStore.vtable_instance.delete,
        .count = SqliteSharedVectorStore.vtable_instance.count,
        .health_check = SqliteSharedVectorStore.vtable_instance.health_check,
        .deinit = &implDeinit,
    };
};

// ── Sqlite ANN vector store (experimental) ────────────────────────
//
// Uses a lightweight SimHash+band prefilter in SQLite to cut the search
// candidate set, then computes exact cosine on candidates. Falls back to
// exact search when ANN candidate recall is insufficient.

pub const SqliteAnnVectorStore = struct {
    db: ?*c.sqlite3, // borrowed from SqliteMemory — NOT owned
    allocator: Allocator,
    owns_self: bool = false,
    candidate_multiplier: u32 = ANN_DEFAULT_CANDIDATE_MULTIPLIER,
    min_candidates: u32 = ANN_DEFAULT_MIN_CANDIDATES,

    const Self = @This();
    const ANN_SYNC_SAVEPOINT_BEGIN: [:0]const u8 = "SAVEPOINT ann_sync";
    const ANN_SYNC_SAVEPOINT_ROLLBACK: [:0]const u8 = "ROLLBACK TO SAVEPOINT ann_sync";
    const ANN_SYNC_SAVEPOINT_RELEASE: [:0]const u8 = "RELEASE SAVEPOINT ann_sync";

    pub fn init(
        allocator: Allocator,
        db: ?*c.sqlite3,
        candidate_multiplier: u32,
        min_candidates: u32,
    ) !SqliteAnnVectorStore {
        var self = Self{
            .db = db,
            .allocator = allocator,
            .candidate_multiplier = @max(candidate_multiplier, @as(u32, 1)),
            .min_candidates = @max(min_candidates, @as(u32, 1)),
        };
        try self.migrateAnn();
        try self.backfillAnnIfNeeded();
        return self;
    }

    pub fn store(self: *SqliteAnnVectorStore) VectorStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_instance,
        };
    }

    pub fn deinit(self: *SqliteAnnVectorStore) void {
        // Do NOT close db — it's borrowed from SqliteMemory.
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn execSql(self: *Self, sql: [:0]const u8) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.ExecFailed;
        }
    }

    fn execSqlIgnoreError(self: *Self, sql: [:0]const u8) void {
        var err_msg: [*c]u8 = null;
        _ = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (err_msg) |msg| c.sqlite3_free(msg);
    }

    fn rollbackAnnSyncSavepoint(self: *Self) void {
        self.execSqlIgnoreError(ANN_SYNC_SAVEPOINT_ROLLBACK);
        self.execSqlIgnoreError(ANN_SYNC_SAVEPOINT_RELEASE);
    }

    fn beginAnnSyncSavepoint(self: *Self) !void {
        try self.execSql(ANN_SYNC_SAVEPOINT_BEGIN);
    }

    fn releaseAnnSyncSavepoint(self: *Self) !void {
        try self.execSql(ANN_SYNC_SAVEPOINT_RELEASE);
    }

    fn migrateAnn(self: *Self) !void {
        const ddl =
            \\CREATE TABLE IF NOT EXISTS memory_embedding_ann (
            \\  memory_key TEXT PRIMARY KEY,
            \\  band0 INTEGER NOT NULL,
            \\  band1 INTEGER NOT NULL,
            \\  band2 INTEGER NOT NULL,
            \\  band3 INTEGER NOT NULL,
            \\  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            \\  FOREIGN KEY (memory_key) REFERENCES memory_embeddings(memory_key) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_memory_embedding_ann_band0 ON memory_embedding_ann(band0);
            \\CREATE INDEX IF NOT EXISTS idx_memory_embedding_ann_band1 ON memory_embedding_ann(band1);
            \\CREATE INDEX IF NOT EXISTS idx_memory_embedding_ann_band2 ON memory_embedding_ann(band2);
            \\CREATE INDEX IF NOT EXISTS idx_memory_embedding_ann_band3 ON memory_embedding_ann(band3);
            \\DELETE FROM memory_embedding_ann WHERE memory_key NOT IN (SELECT memory_key FROM memory_embeddings);
            \\DELETE FROM memory_embedding_ann WHERE memory_key IN (
            \\  SELECT memory_key FROM memory_embeddings WHERE length(embedding) = 0 OR (length(embedding) % 4) != 0
            \\);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, ddl, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    fn countWithSql(self: *Self, sql: [:0]const u8) !usize {
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const n = c.sqlite3_column_int64(stmt, 0);
            return @intCast(n);
        }
        return 0;
    }

    fn countStaleAnnRows(self: *Self) !usize {
        const stale_sql =
            \\SELECT COUNT(*)
            \\FROM memory_embeddings e
            \\LEFT JOIN memory_embedding_ann a ON a.memory_key = e.memory_key
            \\WHERE length(e.embedding) > 0
            \\  AND (length(e.embedding) % 4) = 0
            \\  AND (a.memory_key IS NULL OR a.updated_at < e.updated_at)
        ;
        return self.countWithSql(stale_sql);
    }

    fn backfillAnnIfNeeded(self: *Self) !void {
        const stale_count = try self.countStaleAnnRows();
        if (stale_count == 0) return;

        try self.rebuildAnnIndex();
    }

    fn rebuildAnnIndex(self: *Self) !void {
        const select_sql =
            "SELECT e.memory_key, e.embedding " ++
            "FROM memory_embeddings e " ++
            "LEFT JOIN memory_embedding_ann a ON a.memory_key = e.memory_key " ++
            "WHERE length(e.embedding) > 0 " ++
            "AND (length(e.embedding) % 4) = 0 " ++
            "AND (a.memory_key IS NULL OR a.updated_at < e.updated_at)";
        var select_stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, select_sql, -1, &select_stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(select_stmt);

        const upsert_sql =
            "INSERT OR REPLACE INTO memory_embedding_ann (memory_key, band0, band1, band2, band3, updated_at) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))";
        var upsert_stmt: ?*c.sqlite3_stmt = null;
        rc = c.sqlite3_prepare_v2(self.db, upsert_sql, -1, &upsert_stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(upsert_stmt);

        while (true) {
            rc = c.sqlite3_step(select_stmt);
            if (rc == c.SQLITE_ROW) {
                const key_ptr = c.sqlite3_column_text(select_stmt, 0);
                const key_len: usize = @intCast(c.sqlite3_column_bytes(select_stmt, 0));
                if (key_ptr == null) continue;

                const blob_ptr: ?[*]const u8 = @ptrCast(c.sqlite3_column_blob(select_stmt, 1));
                const blob_len: usize = @intCast(c.sqlite3_column_bytes(select_stmt, 1));
                if (blob_ptr == null or blob_len == 0) continue;

                const sig = simhashSignatureFromBlob(blob_ptr.?[0..blob_len]);
                const bands = signatureBands(sig);

                _ = c.sqlite3_reset(upsert_stmt);
                _ = c.sqlite3_clear_bindings(upsert_stmt);
                _ = c.sqlite3_bind_text(upsert_stmt, 1, key_ptr, @intCast(key_len), SQLITE_STATIC);
                _ = c.sqlite3_bind_int(upsert_stmt, 2, @intCast(bands[0]));
                _ = c.sqlite3_bind_int(upsert_stmt, 3, @intCast(bands[1]));
                _ = c.sqlite3_bind_int(upsert_stmt, 4, @intCast(bands[2]));
                _ = c.sqlite3_bind_int(upsert_stmt, 5, @intCast(bands[3]));

                const step_rc = c.sqlite3_step(upsert_stmt);
                if (step_rc != c.SQLITE_DONE) return error.StepFailed;
            } else break;
        }

        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn upsertAnn(self: *Self, key: []const u8, sig: u64) !void {
        const bands = signatureBands(sig);
        const sql =
            "INSERT OR REPLACE INTO memory_embedding_ann (memory_key, band0, band1, band2, band3, updated_at) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(bands[0]));
        _ = c.sqlite3_bind_int(stmt, 3, @intCast(bands[1]));
        _ = c.sqlite3_bind_int(stmt, 4, @intCast(bands[2]));
        _ = c.sqlite3_bind_int(stmt, 5, @intCast(bands[3]));

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn deleteAnn(self: *Self, key: []const u8) !void {
        const sql = "DELETE FROM memory_embedding_ann WHERE memory_key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn implUpsert(ptr: *anyopaque, key: []const u8, embedding: []const f32) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var savepoint_open = false;
        try self.beginAnnSyncSavepoint();
        savepoint_open = true;
        errdefer if (savepoint_open) self.rollbackAnnSyncSavepoint();

        const blob = try vector.vecToBytes(self.allocator, embedding);
        defer self.allocator.free(blob);

        const sql = "INSERT OR REPLACE INTO memory_embeddings (memory_key, embedding, updated_at) VALUES (?1, ?2, datetime('now'))";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_blob(stmt, 2, blob.ptr, @intCast(blob.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        if (embedding.len == 0) {
            try self.deleteAnn(key);
        } else {
            try self.upsertAnn(key, simhashSignatureFromEmbedding(embedding));
        }

        try self.releaseAnnSyncSavepoint();
        savepoint_open = false;
    }

    fn implSearch(ptr: *anyopaque, alloc: Allocator, query_embedding: []const f32, limit: u32) anyerror![]VectorResult {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const max_results: usize = @intCast(limit);
        if (max_results == 0) return alloc.alloc(VectorResult, 0);

        const query_norm = queryNorm(query_embedding);
        const sig = simhashSignatureFromEmbedding(query_embedding);
        const bands = signatureBands(sig);
        const candidate_limit = annCandidateLimit(limit, self.candidate_multiplier, self.min_candidates);

        const sql =
            "SELECT e.memory_key, e.embedding " ++
            "FROM memory_embeddings e " ++
            "JOIN memory_embedding_ann a ON a.memory_key = e.memory_key " ++
            "WHERE a.band0 = ?1 OR a.band1 = ?2 OR a.band2 = ?3 OR a.band3 = ?4 " ++
            "LIMIT ?5";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int(stmt, 1, @intCast(bands[0]));
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(bands[1]));
        _ = c.sqlite3_bind_int(stmt, 3, @intCast(bands[2]));
        _ = c.sqlite3_bind_int(stmt, 4, @intCast(bands[3]));
        _ = c.sqlite3_bind_int(stmt, 5, clampU32ToSqliteInt(candidate_limit));

        var candidates: std.ArrayListUnmanaged(VectorResult) = .empty;
        var should_cleanup_candidates = true;
        errdefer {
            if (should_cleanup_candidates) {
                for (candidates.items) |*r| r.deinit(alloc);
                candidates.deinit(alloc);
            }
        }

        var lowest_idx: usize = 0;
        var lowest_score: f32 = 0.0;
        var candidate_rows: usize = 0;

        while (true) {
            rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_ROW) {
                candidate_rows += 1;

                const key_ptr = c.sqlite3_column_text(stmt, 0);
                const key_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
                if (key_ptr == null) continue;

                const blob_ptr: ?[*]const u8 = @ptrCast(c.sqlite3_column_blob(stmt, 1));
                const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
                if (blob_ptr == null or blob_len == 0) continue;

                const score = cosineSimilarityBlob(query_embedding, query_norm, blob_ptr.?[0..blob_len]);
                const key_slice: []const u8 = key_ptr[0..key_len];
                try appendTopKCandidate(alloc, &candidates, max_results, key_slice, score, &lowest_idx, &lowest_score);
            } else break;
        }

        if (rc != c.SQLITE_DONE) return error.StepFailed;

        // Conservative fallback: if ANN prefilter yields too few candidates, run exact.
        if (candidate_rows < max_results or candidates.items.len < max_results) {
            for (candidates.items) |*r| r.deinit(alloc);
            candidates.deinit(alloc);
            should_cleanup_candidates = false;
            return exactSearchSqlite(self.db, alloc, query_embedding, max_results);
        }

        std.mem.sortUnstable(VectorResult, candidates.items, {}, struct {
            fn lessThan(_: void, a: VectorResult, b: VectorResult) bool {
                return a.score > b.score;
            }
        }.lessThan);

        const result = try alloc.dupe(VectorResult, candidates.items);
        candidates.deinit(alloc);
        should_cleanup_candidates = false;
        return result;
    }

    fn implDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var savepoint_open = false;
        try self.beginAnnSyncSavepoint();
        savepoint_open = true;
        errdefer if (savepoint_open) self.rollbackAnnSyncSavepoint();

        // Keep ANN side table in sync regardless of FK settings.
        try self.deleteAnn(key);

        const sql = "DELETE FROM memory_embeddings WHERE memory_key = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        try self.releaseAnnSyncSavepoint();
        savepoint_open = false;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.countWithSql("SELECT COUNT(*) FROM memory_embeddings");
    }

    fn implHealthCheck(ptr: *anyopaque, alloc: Allocator) anyerror!HealthStatus {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const start = std.time.nanoTimestamp();

        const sql = "SELECT COUNT(*) FROM memory_embeddings";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));
            return HealthStatus{
                .ok = false,
                .latency_ns = elapsed,
                .entry_count = null,
                .error_msg = try alloc.dupe(u8, "sqlite prepare failed"),
            };
        }
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_step(stmt);
        const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));

        if (rc == c.SQLITE_ROW) {
            const n: usize = @intCast(c.sqlite3_column_int64(stmt, 0));
            return HealthStatus{
                .ok = true,
                .latency_ns = elapsed,
                .entry_count = n,
                .error_msg = null,
            };
        }

        return HealthStatus{
            .ok = false,
            .latency_ns = elapsed,
            .entry_count = null,
            .error_msg = try alloc.dupe(u8, "sqlite step failed"),
        };
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    const vtable_instance = VectorStore.VTable{
        .upsert = &implUpsert,
        .search = &implSearch,
        .delete = &implDelete,
        .count = &implCount,
        .health_check = &implHealthCheck,
        .deinit = &implDeinit,
    };
};

// ── Tests ─────────────────────────────────────────────────────────

fn testExecSql(db: ?*c.sqlite3, sql: [:0]const u8) !void {
    var err_msg: [*c]u8 = null;
    const rc = c.sqlite3_exec(db, sql, null, null, &err_msg);
    if (rc != c.SQLITE_OK) {
        if (err_msg) |msg| c.sqlite3_free(msg);
        return error.SqlExecFailed;
    }
}

fn testQuerySingleText(allocator: Allocator, db: ?*c.sqlite3, sql: [:0]const u8) ![]u8 {
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_ROW) return error.RowNotFound;
    const value_ptr = c.sqlite3_column_text(stmt, 0);
    const value_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (value_ptr == null) return error.NullTextValue;
    return allocator.dupe(u8, value_ptr[0..value_len]);
}

test "init with in-memory sqlite" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const cnt = try s.count();
    try std.testing.expectEqual(@as(usize, 0), cnt);
}

test "upsert stores embedding then verify with count" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb = [_]f32{ 1.0, 2.0, 3.0 };
    try s.upsert("key1", &emb);

    const cnt = try s.count();
    try std.testing.expectEqual(@as(usize, 1), cnt);
}

test "upsert overwrites existing key" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb1 = [_]f32{ 1.0, 2.0, 3.0 };
    const emb2 = [_]f32{ 4.0, 5.0, 6.0 };
    try s.upsert("key1", &emb1);
    try s.upsert("key1", &emb2);

    const cnt = try s.count();
    try std.testing.expectEqual(@as(usize, 1), cnt);
}

test "search returns sorted results" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    // Insert 3 items: a is very similar to query, b is less similar, c is orthogonal
    const query = [_]f32{ 1.0, 0.0, 0.0 };
    const emb_a = [_]f32{ 0.9, 0.1, 0.0 }; // very similar to query
    const emb_b = [_]f32{ 0.5, 0.5, 0.5 }; // partially similar
    const emb_c = [_]f32{ 0.0, 0.0, 1.0 }; // orthogonal

    try s.upsert("a", &emb_a);
    try s.upsert("b", &emb_b);
    try s.upsert("c", &emb_c);

    const results = try s.search(std.testing.allocator, &query, 3);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    // Best match should be "a"
    try std.testing.expectEqualStrings("a", results[0].key);
    // Scores should be descending
    try std.testing.expect(results[0].score >= results[1].score);
    try std.testing.expect(results[1].score >= results[2].score);
}

test "search with no data returns empty" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const query = [_]f32{ 1.0, 2.0, 3.0 };
    const results = try s.search(std.testing.allocator, &query, 10);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "search respects limit" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    // Insert 5 items
    var bufs: [5][8]u8 = undefined;
    for (0..5) |i| {
        const key = std.fmt.bufPrint(&bufs[i], "key_{d}", .{i}) catch "?";
        var emb = [_]f32{ 1.0, 0.0, 0.0 };
        emb[0] = 1.0 - @as(f32, @floatFromInt(i)) * 0.1;
        try s.upsert(key, &emb);
    }

    const results = try s.search(std.testing.allocator, &[_]f32{ 1.0, 0.0, 0.0 }, 2);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "delete removes embedding" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb = [_]f32{ 1.0, 2.0, 3.0 };
    try s.upsert("key1", &emb);
    try std.testing.expectEqual(@as(usize, 1), try s.count());

    try s.delete("key1");
    try std.testing.expectEqual(@as(usize, 0), try s.count());
}

test "delete non-existent key is no-op" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    // Should not error
    try s.delete("nonexistent");
    try std.testing.expectEqual(@as(usize, 0), try s.count());
}

test "count returns correct count" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    try std.testing.expectEqual(@as(usize, 0), try s.count());

    try s.upsert("a", &[_]f32{ 1.0, 0.0 });
    try std.testing.expectEqual(@as(usize, 1), try s.count());

    try s.upsert("b", &[_]f32{ 0.0, 1.0 });
    try std.testing.expectEqual(@as(usize, 2), try s.count());

    try s.upsert("c", &[_]f32{ 1.0, 1.0 });
    try std.testing.expectEqual(@as(usize, 3), try s.count());
}

test "VectorResult deinit frees key" {
    const allocator = std.testing.allocator;
    const key = try allocator.dupe(u8, "test_key");
    const r = VectorResult{ .key = key, .score = 0.5 };
    r.deinit(allocator);
    // No leak = pass (testing allocator detects leaks)
}

test "freeVectorResults frees slice" {
    const allocator = std.testing.allocator;
    var results = try allocator.alloc(VectorResult, 2);
    results[0] = .{ .key = try allocator.dupe(u8, "key_a"), .score = 0.9 };
    results[1] = .{ .key = try allocator.dupe(u8, "key_b"), .score = 0.5 };
    freeVectorResults(allocator, results);
    // No leak = pass
}

test "cosine similarity cross-check: exact match returns score near 1.0" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb = [_]f32{ 1.0, 2.0, 3.0 };
    try s.upsert("exact", &emb);

    const results = try s.search(std.testing.allocator, &emb, 1);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("exact", results[0].key);
    try std.testing.expect(@abs(results[0].score - 1.0) < 0.001);
}

test "blob cosine similarity matches math cosine similarity" {
    const emb = [_]f32{ 0.25, 0.5, 0.75, 1.0 };
    const query = [_]f32{ 0.1, 0.2, 0.3, 0.4 };

    const blob = try vector.vecToBytes(std.testing.allocator, &emb);
    defer std.testing.allocator.free(blob);

    const expected = vector.cosineSimilarity(&query, &emb);
    const query_norm = queryNorm(&query);
    const actual = cosineSimilarityBlob(&query, query_norm, blob);
    try std.testing.expect(@abs(expected - actual) < 0.0001);
}

test "search with zero limit returns empty" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();
    const s = vs.store();

    try s.upsert("k1", &[_]f32{ 1.0, 0.0, 0.0 });
    const results = try s.search(std.testing.allocator, &[_]f32{ 1.0, 0.0, 0.0 }, 0);
    defer freeVectorResults(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "ann candidate limit respects multiplier and minimum" {
    try std.testing.expectEqual(@as(u32, 0), annCandidateLimit(0, 12, 64));
    try std.testing.expectEqual(@as(u32, 64), annCandidateLimit(1, 4, 64));
    try std.testing.expectEqual(@as(u32, 120), annCandidateLimit(10, 12, 64));
    try std.testing.expectEqual(@as(u32, 20), annCandidateLimit(10, 2, 5));
}

test "sqlite bind int clamp handles u32 overflow safely" {
    const max_sqlite_int: c_int = std.math.maxInt(c_int);
    try std.testing.expectEqual(max_sqlite_int, clampU32ToSqliteInt(std.math.maxInt(u32)));
}

test "projection coeff handles large dimension indices without overflow" {
    const indices = [_]usize{
        0,
        1,
        65_535,
        std.math.maxInt(u32),
        @as(usize, std.math.maxInt(u32)) + 1,
        std.math.maxInt(usize),
    };
    for (indices) |dim_idx| {
        const coeff = projectionCoeff(63, dim_idx);
        try std.testing.expect(std.math.isFinite(coeff));
        try std.testing.expect(coeff >= -1.0 and coeff <= 1.0);
    }
}

test "sqlite ann search falls back to exact when ann index has no candidates" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var shared = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer shared.deinit();
    const shared_store = shared.store();
    try shared_store.upsert("k_exact", &[_]f32{ 1.0, 0.0, 0.0 });

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    // Simulate missing ANN coverage for existing rows.
    var clear_stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, "DELETE FROM memory_embedding_ann", -1, &clear_stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(clear_stmt);
    rc = c.sqlite3_step(clear_stmt);
    try std.testing.expectEqual(c.SQLITE_DONE, rc);

    const ann_store = ann.store();
    const results = try ann_store.search(std.testing.allocator, &[_]f32{ 1.0, 0.0, 0.0 }, 1);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("k_exact", results[0].key);
    try std.testing.expect(results[0].score > 0.99);
}

test "sqlite ann upsert and search basic path" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 32);
    defer ann.deinit();

    const s = ann.store();
    try s.upsert("exact", &[_]f32{ 1.0, 0.0, 0.0 });
    try s.upsert("close", &[_]f32{ 0.9, 0.1, 0.0 });
    try s.upsert("far", &[_]f32{ 0.0, 0.0, 1.0 });

    const results = try s.search(std.testing.allocator, &[_]f32{ 1.0, 0.0, 0.0 }, 2);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expect(results[0].score >= results[1].score);
    try std.testing.expect(results[0].score > 0.9);
}

test "sqlite ann backfill refreshes stale rows even when counts match" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var shared = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer shared.deinit();
    try shared.store().upsert("stale_key", &[_]f32{ 1.0, 0.0, 0.0 });

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    try testExecSql(mem.db,
        \\UPDATE memory_embedding_ann
        \\SET updated_at = '1970-01-01 00:00:00'
        \\WHERE memory_key = 'stale_key'
    );
    try std.testing.expectEqual(@as(usize, 1), try ann.countStaleAnnRows());

    try ann.backfillAnnIfNeeded();
    try std.testing.expectEqual(@as(usize, 0), try ann.countStaleAnnRows());
}

test "sqlite ann upsert is atomic across embeddings and ann rows" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    try testExecSql(mem.db,
        \\CREATE TRIGGER fail_ann_insert BEFORE INSERT ON memory_embedding_ann
        \\BEGIN
        \\  SELECT RAISE(ABORT, 'forced ann insert failure');
        \\END;
    );
    defer testExecSql(mem.db, "DROP TRIGGER IF EXISTS fail_ann_insert") catch {};

    const s = ann.store();
    var saw_error = false;
    s.upsert("atomic_upsert_key", &[_]f32{ 1.0, 0.0, 0.0 }) catch |err| {
        saw_error = true;
        try std.testing.expect(err == error.StepFailed or err == error.ExecFailed);
    };
    try std.testing.expect(saw_error);

    try std.testing.expectEqual(@as(usize, 0), try ann.countWithSql("SELECT COUNT(*) FROM memory_embeddings WHERE memory_key = 'atomic_upsert_key'"));
    try std.testing.expectEqual(@as(usize, 0), try ann.countWithSql("SELECT COUNT(*) FROM memory_embedding_ann WHERE memory_key = 'atomic_upsert_key'"));
}

test "sqlite ann delete is atomic across embeddings and ann rows" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    const s = ann.store();
    try s.upsert("atomic_delete_key", &[_]f32{ 1.0, 0.0, 0.0 });
    try std.testing.expectEqual(@as(usize, 1), try ann.countWithSql("SELECT COUNT(*) FROM memory_embeddings WHERE memory_key = 'atomic_delete_key'"));
    try std.testing.expectEqual(@as(usize, 1), try ann.countWithSql("SELECT COUNT(*) FROM memory_embedding_ann WHERE memory_key = 'atomic_delete_key'"));

    try testExecSql(mem.db,
        \\CREATE TRIGGER fail_embeddings_delete BEFORE DELETE ON memory_embeddings
        \\BEGIN
        \\  SELECT RAISE(ABORT, 'forced embedding delete failure');
        \\END;
    );
    defer testExecSql(mem.db, "DROP TRIGGER IF EXISTS fail_embeddings_delete") catch {};

    var saw_error = false;
    s.delete("atomic_delete_key") catch |err| {
        saw_error = true;
        try std.testing.expect(err == error.StepFailed or err == error.ExecFailed);
    };
    try std.testing.expect(saw_error);

    try std.testing.expectEqual(@as(usize, 1), try ann.countWithSql("SELECT COUNT(*) FROM memory_embeddings WHERE memory_key = 'atomic_delete_key'"));
    try std.testing.expectEqual(@as(usize, 1), try ann.countWithSql("SELECT COUNT(*) FROM memory_embedding_ann WHERE memory_key = 'atomic_delete_key'"));
}

test "sqlite ann backfill ignores non-indexable embeddings in stale detection" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var shared = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer shared.deinit();
    try shared.store().upsert("good", &[_]f32{ 1.0, 0.0, 0.0 });
    try testExecSql(mem.db, "INSERT OR REPLACE INTO memory_embeddings (memory_key, embedding, updated_at) VALUES ('bad', x'', datetime('now'))");

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    try testExecSql(mem.db,
        \\UPDATE memory_embeddings SET updated_at = '2000-01-01 00:00:00' WHERE memory_key = 'good';
        \\UPDATE memory_embedding_ann SET updated_at = '2000-01-01 00:00:00' WHERE memory_key = 'good';
    );
    try std.testing.expectEqual(@as(usize, 0), try ann.countStaleAnnRows());

    try ann.backfillAnnIfNeeded();

    const updated_at = try testQuerySingleText(std.testing.allocator, mem.db, "SELECT updated_at FROM memory_embedding_ann WHERE memory_key = 'good'");
    defer std.testing.allocator.free(updated_at);
    try std.testing.expectEqualStrings("2000-01-01 00:00:00", updated_at);
}

test "sqlite ann upsert with empty embedding keeps ann table clean" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var ann = try SqliteAnnVectorStore.init(std.testing.allocator, mem.db, 8, 64);
    defer ann.deinit();

    const s = ann.store();
    try s.upsert("empty_ann_key", &.{});
    try std.testing.expectEqual(@as(usize, 1), try ann.countWithSql("SELECT COUNT(*) FROM memory_embeddings WHERE memory_key = 'empty_ann_key'"));
    try std.testing.expectEqual(@as(usize, 0), try ann.countWithSql("SELECT COUNT(*) FROM memory_embedding_ann WHERE memory_key = 'empty_ann_key'"));
}

test "round-trip: upsert then search finds the key" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb = [_]f32{ 0.5, 0.5, 0.5, 0.5 };
    try s.upsert("roundtrip_key", &emb);

    const results = try s.search(std.testing.allocator, &emb, 10);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("roundtrip_key", results[0].key);
    try std.testing.expect(results[0].score > 0.99);
}

test "multiple upserts + search returns best match" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    // Insert several items
    try s.upsert("north", &[_]f32{ 1.0, 0.0, 0.0 });
    try s.upsert("east", &[_]f32{ 0.0, 1.0, 0.0 });
    try s.upsert("up", &[_]f32{ 0.0, 0.0, 1.0 });
    try s.upsert("northeast", &[_]f32{ 0.7, 0.7, 0.0 });

    // Search for something close to "north"
    const query = [_]f32{ 0.95, 0.05, 0.0 };
    const results = try s.search(std.testing.allocator, &query, 4);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 4), results.len);
    // Best match should be "north"
    try std.testing.expectEqualStrings("north", results[0].key);
}

test "empty embedding handled gracefully" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const empty: []const f32 = &.{};

    // Upsert with empty vec should not crash
    try s.upsert("empty_key", empty);
    try std.testing.expectEqual(@as(usize, 1), try s.count());

    // Search with empty query should not crash (cosine returns 0 for empty)
    const results = try s.search(std.testing.allocator, empty, 10);
    defer freeVectorResults(std.testing.allocator, results);
    // The empty embedding row has 0-length blob, bytesToVec returns empty, cosine returns 0
    // Result is still returned (score = 0)
}

test "healthCheck returns ok with entry count" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    // Insert some data
    try s.upsert("hc_key1", &[_]f32{ 1.0, 0.0 });
    try s.upsert("hc_key2", &[_]f32{ 0.0, 1.0 });

    const status = try s.healthCheck(std.testing.allocator);
    defer status.deinit(std.testing.allocator);

    try std.testing.expect(status.ok);
    try std.testing.expect(status.latency_ns > 0);
    try std.testing.expectEqual(@as(?usize, 2), status.entry_count);
    try std.testing.expectEqual(@as(?[]const u8, null), status.error_msg);
}

test "healthCheck on empty store returns ok with zero count" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const status = try s.healthCheck(std.testing.allocator);
    defer status.deinit(std.testing.allocator);

    try std.testing.expect(status.ok);
    try std.testing.expectEqual(@as(?usize, 0), status.entry_count);
    try std.testing.expectEqual(@as(?[]const u8, null), status.error_msg);
}

test "HealthStatus deinit frees error_msg" {
    const allocator = std.testing.allocator;
    const msg = try allocator.dupe(u8, "test error");
    const status = HealthStatus{
        .ok = false,
        .latency_ns = 100,
        .entry_count = null,
        .error_msg = msg,
    };
    status.deinit(allocator);
    // No leak = pass (testing allocator detects leaks)
}

test "HealthStatus deinit with null error_msg is safe" {
    const status = HealthStatus{
        .ok = true,
        .latency_ns = 50,
        .entry_count = 42,
        .error_msg = null,
    };
    status.deinit(std.testing.allocator);
}

// ── R3 tests ──────────────────────────────────────────────────────

test "upsert same key updates embedding not duplicate" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();
    const emb1 = [_]f32{ 1.0, 0.0, 0.0 };
    const emb2 = [_]f32{ 0.0, 1.0, 0.0 };

    try s.upsert("same_key", &emb1);
    try std.testing.expectEqual(@as(usize, 1), try s.count());

    // Upsert again with different embedding
    try s.upsert("same_key", &emb2);
    try std.testing.expectEqual(@as(usize, 1), try s.count()); // still 1, not 2

    // Search with emb2 as query — should find "same_key" with high score
    const results = try s.search(std.testing.allocator, &emb2, 1);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("same_key", results[0].key);
    // Score should be ~1.0 since emb2 matches the stored embedding
    try std.testing.expect(results[0].score > 0.99);
}

test "search returns results sorted by similarity descending" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    // Insert vectors with known similarity to query [1,0,0]
    try s.upsert("exact", &[_]f32{ 1.0, 0.0, 0.0 }); // cosine = 1.0
    try s.upsert("close", &[_]f32{ 0.9, 0.1, 0.0 }); // cosine ~ 0.994
    try s.upsert("medium", &[_]f32{ 0.5, 0.5, 0.5 }); // cosine ~ 0.577
    try s.upsert("far", &[_]f32{ 0.0, 0.0, 1.0 }); // cosine = 0.0

    const query = [_]f32{ 1.0, 0.0, 0.0 };
    const results = try s.search(std.testing.allocator, &query, 4);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 4), results.len);

    // Verify descending order
    try std.testing.expectEqualStrings("exact", results[0].key);
    try std.testing.expect(results[0].score >= results[1].score);
    try std.testing.expect(results[1].score >= results[2].score);
    try std.testing.expect(results[2].score >= results[3].score);

    // Verify boundary scores
    try std.testing.expect(results[0].score > 0.99); // exact match
    try std.testing.expect(results[3].score < 0.01); // orthogonal
}

test "delete then search returns empty for deleted key" {
    var mem = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var vs = SqliteSharedVectorStore.init(std.testing.allocator, mem.db);
    defer vs.deinit();

    const s = vs.store();

    const emb = [_]f32{ 1.0, 0.0, 0.0 };
    try s.upsert("del_target", &emb);
    try s.upsert("keep_this", &[_]f32{ 0.0, 1.0, 0.0 });

    try std.testing.expectEqual(@as(usize, 2), try s.count());

    // Delete del_target
    try s.delete("del_target");
    try std.testing.expectEqual(@as(usize, 1), try s.count());

    // Search with del_target's embedding — should not find it
    const results = try s.search(std.testing.allocator, &emb, 10);
    defer freeVectorResults(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("keep_this", results[0].key);
}
