//! VectorOutbox — durable outbox for vector sync operations.
//!
//! Enqueues upsert/delete operations against the vector store and
//! drains them reliably with retry semantics. Dead letters (items
//! that exceed max_retries) are purged separately.
//!
//! The outbox borrows its SQLite handle from SqliteMemory — it does
//! NOT own the database connection.

const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const c = sqlite_mod.c;
const SQLITE_STATIC = sqlite_mod.SQLITE_STATIC;
const embeddings = @import("embeddings.zig");
const key_codec = @import("key_codec.zig");
const vector_store_mod = @import("store.zig");
const circuit_breaker_mod = @import("circuit_breaker.zig");
const log = std.log.scoped(.outbox);

pub const VectorOutbox = struct {
    db: ?*c.sqlite3, // borrowed from SqliteMemory
    allocator: Allocator,
    max_retries: u32, // from sync.embed_max_retries (default 2)
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, db: ?*c.sqlite3, max_retries: u32) VectorOutbox {
        return .{
            .db = db,
            .allocator = allocator,
            .max_retries = max_retries,
        };
    }

    pub fn deinit(self: *VectorOutbox) void {
        // Do NOT close db — it is borrowed from SqliteMemory.
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    /// Create the vector_outbox table if not exists.
    pub fn migrate(self: *VectorOutbox) !void {
        const ddl =
            \\CREATE TABLE IF NOT EXISTS vector_outbox (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    memory_key TEXT NOT NULL,
            \\    operation TEXT NOT NULL,
            \\    created_at TEXT NOT NULL DEFAULT (datetime('now')),
            \\    attempts INTEGER DEFAULT 0,
            \\    last_error TEXT
            \\);
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, ddl, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    /// Enqueue an operation (upsert or delete).
    pub fn enqueue(self: *VectorOutbox, memory_key: []const u8, operation: []const u8) !void {
        const sql = "INSERT INTO vector_outbox (memory_key, operation) VALUES (?1, ?2)";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, memory_key.ptr, @intCast(memory_key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, operation.ptr, @intCast(operation.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    /// Internal item representation collected from the SELECT.
    const OutboxItem = struct {
        id: i64,
        key: []u8, // owned (duped)
        op: []u8, // owned (duped)
    };

    const ResolvedMemoryContent = struct {
        content: []u8,
        vector_key: []u8,
    };

    /// Drain: process pending items. For each: embed -> upsert to vector store -> delete from outbox.
    /// Returns count of successfully processed items.
    pub fn drain(
        self: *VectorOutbox,
        allocator: Allocator,
        embed_provider: embeddings.EmbeddingProvider,
        vs: vector_store_mod.VectorStore,
        breaker: ?*circuit_breaker_mod.CircuitBreaker,
    ) !u32 {
        // ── 1. Collect pending items into an ArrayList ──────────────
        var items: std.ArrayListUnmanaged(OutboxItem) = .empty;
        defer {
            for (items.items) |item| {
                allocator.free(item.key);
                allocator.free(item.op);
            }
            items.deinit(allocator);
        }

        {
            const select_sql = "SELECT id, memory_key, operation FROM vector_outbox WHERE attempts < ?1 ORDER BY id LIMIT 50";
            var sel_stmt: ?*c.sqlite3_stmt = null;
            var rc = c.sqlite3_prepare_v2(self.db, select_sql, -1, &sel_stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(sel_stmt);

            _ = c.sqlite3_bind_int(sel_stmt, 1, @intCast(self.max_retries));

            while (true) {
                rc = c.sqlite3_step(sel_stmt);
                if (rc == c.SQLITE_ROW) {
                    const id = c.sqlite3_column_int64(sel_stmt, 0);

                    const key_ptr = c.sqlite3_column_text(sel_stmt, 1);
                    const key_len: usize = @intCast(c.sqlite3_column_bytes(sel_stmt, 1));
                    if (key_ptr == null) continue;

                    const op_ptr = c.sqlite3_column_text(sel_stmt, 2);
                    const op_len: usize = @intCast(c.sqlite3_column_bytes(sel_stmt, 2));
                    if (op_ptr == null) continue;

                    const key_slice: []const u8 = @as([*]const u8, @ptrCast(key_ptr))[0..key_len];
                    const op_slice: []const u8 = @as([*]const u8, @ptrCast(op_ptr))[0..op_len];

                    const owned_key = try allocator.dupe(u8, key_slice);
                    errdefer allocator.free(owned_key);
                    const owned_op = try allocator.dupe(u8, op_slice);
                    errdefer allocator.free(owned_op);
                    try items.append(allocator, .{
                        .id = id,
                        .key = owned_key,
                        .op = owned_op,
                    });
                } else break;
            }
        }

        // ── 2. Process each collected item ──────────────────────────
        var success_count: u32 = 0;

        for (items.items) |item| {
            const decoded_item_key = key_codec.decode(item.key);
            if (std.mem.eql(u8, item.op, "delete")) {
                // Delete from vector store
                vs.delete(item.key) catch |err| {
                    self.recordItemFailure(item.id, @errorName(err)) catch {};
                    if (breaker) |b| b.recordFailure();
                    continue;
                };
                if (!decoded_item_key.is_legacy) {
                    vs.delete(decoded_item_key.logical_key) catch {};
                }
                self.deleteItem(item.id) catch {};
                if (breaker) |b| b.recordSuccess();
                success_count += 1;
            } else if (std.mem.eql(u8, item.op, "upsert")) {
                // Fetch content from the memories table
                const resolved = self.fetchMemoryContent(allocator, item.key) catch {
                    // Could not look up content — record failure
                    self.recordItemFailure(item.id, "content_lookup_failed") catch {};
                    if (breaker) |b| b.recordFailure();
                    continue;
                };

                if (resolved) |value| {
                    defer allocator.free(value.content);
                    defer allocator.free(value.vector_key);

                    // Embed the content
                    const embedding = embed_provider.embed(allocator, value.content) catch |err| {
                        self.recordItemFailure(item.id, @errorName(err)) catch {};
                        if (breaker) |b| b.recordFailure();
                        continue;
                    };
                    defer allocator.free(embedding);

                    // Upsert to vector store
                    vs.upsert(value.vector_key, embedding) catch |err| {
                        self.recordItemFailure(item.id, @errorName(err)) catch {};
                        if (breaker) |b| b.recordFailure();
                        continue;
                    };
                    const decoded_vector_key = key_codec.decode(value.vector_key);
                    if (!decoded_vector_key.is_legacy) {
                        vs.delete(decoded_vector_key.logical_key) catch {};
                    }

                    self.deleteItem(item.id) catch {};
                    if (breaker) |b| b.recordSuccess();
                    success_count += 1;
                } else {
                    // Content not found in memories table — nothing to embed, remove from outbox.
                    self.deleteItem(item.id) catch {};
                    success_count += 1;
                }
            } else {
                // Unknown operation — delete from outbox as dead letter
                log.warn("unknown outbox operation: {s}", .{item.op});
                self.deleteItem(item.id) catch {};
            }
        }

        return success_count;
    }

    /// Purge dead letters (items that exceeded max_retries).
    pub fn purgeDeadLetters(self: *VectorOutbox) !u32 {
        const sql = "DELETE FROM vector_outbox WHERE attempts >= ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int(stmt, 1, @intCast(self.max_retries));

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;

        return @intCast(c.sqlite3_changes(self.db));
    }

    /// Count pending items.
    pub fn pendingCount(self: *VectorOutbox) !usize {
        const sql = "SELECT COUNT(*) FROM vector_outbox WHERE attempts < ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int(stmt, 1, @intCast(self.max_retries));

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const n = c.sqlite3_column_int64(stmt, 0);
            return @intCast(n);
        }
        return 0;
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Delete a processed item from the outbox by id.
    fn deleteItem(self: *VectorOutbox, id: i64) !void {
        const sql = "DELETE FROM vector_outbox WHERE id = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, id);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    /// Increment attempts and record the last error for a failed item.
    fn recordItemFailure(self: *VectorOutbox, id: i64, err_msg: []const u8) !void {
        const sql = "UPDATE vector_outbox SET attempts = attempts + 1, last_error = ?2 WHERE id = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, id);
        _ = c.sqlite3_bind_text(stmt, 2, err_msg.ptr, @intCast(err_msg.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    /// Fetch content from the memories table by key. Returns null if not found.
    /// Caller owns the returned slices.
    fn fetchMemoryContent(self: *VectorOutbox, allocator: Allocator, key: []const u8) !?ResolvedMemoryContent {
        const decoded = key_codec.decode(key);
        const sql = if (decoded.is_legacy)
            "SELECT content, session_id FROM memories WHERE key = ?1 ORDER BY updated_at DESC LIMIT 1"
        else if (decoded.session_id != null)
            "SELECT content, session_id FROM memories WHERE key = ?1 AND session_id = ?2 LIMIT 1"
        else
            "SELECT content, session_id FROM memories WHERE key = ?1 AND session_id IS NULL LIMIT 1";
        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, decoded.logical_key.ptr, @intCast(decoded.logical_key.len), SQLITE_STATIC);
        if (decoded.session_id) |sid| {
            _ = c.sqlite3_bind_text(stmt, 2, sid.ptr, @intCast(sid.len), SQLITE_STATIC);
        }

        rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            const content_ptr = c.sqlite3_column_text(stmt, 0);
            const content_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            if (content_ptr == null or content_len == 0) return null;

            const slice: []const u8 = @as([*]const u8, @ptrCast(content_ptr))[0..content_len];
            const content = try allocator.dupe(u8, slice);
            errdefer allocator.free(content);

            const session_ptr = c.sqlite3_column_text(stmt, 1);
            const session_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
            const session_id = if (session_ptr != null and session_len > 0)
                @as([*]const u8, @ptrCast(@constCast(session_ptr)))[0..session_len]
            else
                null;
            const vector_key = if (decoded.is_legacy)
                try key_codec.encode(allocator, decoded.logical_key, session_id)
            else
                try allocator.dupe(u8, key);
            errdefer allocator.free(vector_key);

            return .{
                .content = content,
                .vector_key = vector_key,
            };
        }
        return null;
    }
};

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const TestSetup = struct {
    mem: sqlite_mod.SqliteMemory,
    ob: VectorOutbox,
    vs_impl: vector_store_mod.SqliteSharedVectorStore,

    fn deinit(self: *TestSetup) void {
        self.vs_impl.deinit();
        self.ob.deinit();
        self.mem.deinit();
    }
};

fn testSetup(allocator: Allocator) !TestSetup {
    const mem = try sqlite_mod.SqliteMemory.init(allocator, ":memory:");
    var ob = VectorOutbox.init(allocator, mem.db, 2);
    try ob.migrate();
    const vs_impl = vector_store_mod.SqliteSharedVectorStore.init(allocator, mem.db);
    return .{ .mem = mem, .ob = ob, .vs_impl = vs_impl };
}

/// Helper: insert a row into the memories table so drain can find content.
fn insertMemory(db: ?*c.sqlite3, key: []const u8, content: []const u8) !void {
    const sql =
        "INSERT OR REPLACE INTO memories (id, key, content, category, created_at, updated_at) " ++
        "VALUES (?1, ?1, ?2, 'core', datetime('now'), datetime('now'))";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_text(stmt, 2, content.ptr, @intCast(content.len), SQLITE_STATIC);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_DONE) return error.StepFailed;
}

fn insertScopedMemory(db: ?*c.sqlite3, key: []const u8, content: []const u8, session_id: []const u8) !void {
    const sql =
        "INSERT OR REPLACE INTO memories (id, key, content, category, session_id, created_at, updated_at) " ++
        "VALUES (?1, ?2, ?3, 'core', ?4, datetime('now'), datetime('now'))";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_text(stmt, 2, key.ptr, @intCast(key.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_text(stmt, 3, content.ptr, @intCast(content.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_text(stmt, 4, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_DONE) return error.StepFailed;
}

/// Helper: manually set attempts on an outbox row.
fn setAttempts(db: ?*c.sqlite3, memory_key: []const u8, attempts: i32) !void {
    const sql = "UPDATE vector_outbox SET attempts = ?2 WHERE memory_key = ?1";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, memory_key.ptr, @intCast(memory_key.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_int(stmt, 2, attempts);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_DONE) return error.StepFailed;
}

/// Helper: get total row count from vector_outbox (regardless of attempts).
fn totalOutboxCount(db: ?*c.sqlite3) !usize {
    const sql = "SELECT COUNT(*) FROM vector_outbox";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    rc = c.sqlite3_step(stmt);
    if (rc == c.SQLITE_ROW) {
        return @intCast(c.sqlite3_column_int64(stmt, 0));
    }
    return 0;
}

// 1. migrate creates table (no error)
test "migrate creates vector_outbox table" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();
    // If we get here, migrate succeeded — table exists.
    // Verify by inserting directly.
    try setup.ob.enqueue("test_key", "upsert");
    const cnt = try setup.ob.pendingCount();
    try testing.expectEqual(@as(usize, 1), cnt);
}

// 2. enqueue inserts row (then pendingCount == 1)
test "enqueue inserts row" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try setup.ob.enqueue("key1", "upsert");
    const cnt = try setup.ob.pendingCount();
    try testing.expectEqual(@as(usize, 1), cnt);
}

// 3. enqueue upsert + delete (pendingCount == 2)
test "enqueue upsert and delete" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try setup.ob.enqueue("key1", "upsert");
    try setup.ob.enqueue("key2", "delete");
    const cnt = try setup.ob.pendingCount();
    try testing.expectEqual(@as(usize, 2), cnt);
}

// 4. pendingCount returns correct count
test "pendingCount returns correct count" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
    try setup.ob.enqueue("a", "upsert");
    try testing.expectEqual(@as(usize, 1), try setup.ob.pendingCount());
    try setup.ob.enqueue("b", "upsert");
    try testing.expectEqual(@as(usize, 2), try setup.ob.pendingCount());
    try setup.ob.enqueue("c", "delete");
    try testing.expectEqual(@as(usize, 3), try setup.ob.pendingCount());
}

// 5. drain with noop provider processes items (upsert with content)
test "drain upsert succeeds when content exists in memories" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // Store content in memories table
    try insertMemory(setup.mem.db, "key1", "hello world");

    // Enqueue an upsert
    try setup.ob.enqueue("key1", "upsert");
    try testing.expectEqual(@as(usize, 1), try setup.ob.pendingCount());

    // Drain with noop embedding provider
    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 1), processed);

    // Outbox should be empty now
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
}

// 6. drain deletes item from outbox when content not found (no content to embed)
test "drain removes upsert when content not found" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // Enqueue upsert but do NOT store content in memories
    try setup.ob.enqueue("missing_key", "upsert");
    try testing.expectEqual(@as(usize, 1), try setup.ob.pendingCount());

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    // Item is removed (no content to embed) — counts as success
    try testing.expectEqual(@as(u32, 1), processed);
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
}

// 7. drain deletes item from outbox on success
test "drain deletes item from outbox on success" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try insertMemory(setup.mem.db, "k", "content");
    try setup.ob.enqueue("k", "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    _ = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
}

test "drain resolves scoped content from encoded vector key" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    const encoded_key = try key_codec.encode(allocator, "scoped", "sess-a");
    defer allocator.free(encoded_key);

    try insertScopedMemory(setup.mem.db, "scoped", "scoped content", "sess-a");
    try setup.ob.enqueue(encoded_key, "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    _ = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
    try testing.expectEqual(@as(usize, 1), try vs.count());
}

test "drain migrates legacy outbox key to encoded vector key" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    const encoded_key = try key_codec.encode(allocator, "legacy", "sess-a");
    defer allocator.free(encoded_key);

    try insertScopedMemory(setup.mem.db, "legacy", "legacy content", "sess-a");
    try setup.ob.enqueue("legacy", "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    _ = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
    try testing.expect(try hasEmbeddingKey(setup.mem.db, encoded_key));
    try testing.expect(!(try hasEmbeddingKey(setup.mem.db, "legacy")));
}

// 8. purgeDeadLetters removes over-limit items
test "purgeDeadLetters removes over-limit items" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // max_retries = 2
    try setup.ob.enqueue("dead1", "upsert");
    try setup.ob.enqueue("dead2", "upsert");
    try setup.ob.enqueue("alive", "upsert");

    // Set attempts >= max_retries for the dead ones
    try setAttempts(setup.mem.db, "dead1", 2);
    try setAttempts(setup.mem.db, "dead2", 3);

    const purged = try setup.ob.purgeDeadLetters();
    try testing.expectEqual(@as(u32, 2), purged);

    // Only alive remains
    try testing.expectEqual(@as(usize, 1), try totalOutboxCount(setup.mem.db));
    try testing.expectEqual(@as(usize, 1), try setup.ob.pendingCount());
}

// 9. drain respects max_retries (items at limit are skipped)
test "drain respects max_retries" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // max_retries = 2 → items with attempts >= 2 should NOT be processed
    try setup.ob.enqueue("exhausted", "upsert");
    try setAttempts(setup.mem.db, "exhausted", 2);

    try insertMemory(setup.mem.db, "exhausted", "some content");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 0), processed);

    // Item should still be in outbox (not touched by drain)
    try testing.expectEqual(@as(usize, 1), try totalOutboxCount(setup.mem.db));
}

// 10. drain with circuit breaker records success
test "drain with circuit breaker records success" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try insertMemory(setup.mem.db, "cb_key", "breaker content");
    try setup.ob.enqueue("cb_key", "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();
    var breaker = circuit_breaker_mod.CircuitBreaker.init(5, 1000);

    const processed = try setup.ob.drain(allocator, ep, vs, &breaker);
    try testing.expectEqual(@as(u32, 1), processed);
    try testing.expectEqual(circuit_breaker_mod.State.closed, breaker.state);
    try testing.expectEqual(@as(u32, 0), breaker.failure_count);
}

// 11. drain with empty outbox returns 0
test "drain with empty outbox returns 0" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 0), processed);
}

// 12. multiple enqueue + drain cycle
test "multiple enqueue and drain cycle" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // First cycle
    try insertMemory(setup.mem.db, "m1", "content one");
    try insertMemory(setup.mem.db, "m2", "content two");
    try setup.ob.enqueue("m1", "upsert");
    try setup.ob.enqueue("m2", "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    var processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 2), processed);
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());

    // Second cycle
    try insertMemory(setup.mem.db, "m3", "content three");
    try setup.ob.enqueue("m3", "upsert");
    try setup.ob.enqueue("m1", "delete");

    processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 2), processed);
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
}

// 13. drain upsert with content verifies vector store receives it
test "drain upsert stores embedding in vector store" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try insertMemory(setup.mem.db, "vec_key", "vector content");
    try setup.ob.enqueue("vec_key", "upsert");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 1), processed);

    // NoopEmbedding returns empty vec, but upsert still stores a row
    const count = try vs.count();
    try testing.expectEqual(@as(usize, 1), count);
}

// 14. drain delete calls vector_store.delete
test "drain delete removes from vector store" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    const vs = setup.vs_impl.store();

    // Pre-populate vector store with a key
    try vs.upsert("del_key", &[_]f32{ 1.0, 2.0 });
    try testing.expectEqual(@as(usize, 1), try vs.count());

    // Enqueue a delete
    try setup.ob.enqueue("del_key", "delete");

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 1), processed);

    // Vector store should now be empty
    try testing.expectEqual(@as(usize, 0), try vs.count());
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
}

// 15. pendingCount after drain is reduced
test "pendingCount after drain is reduced" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    try insertMemory(setup.mem.db, "p1", "data");
    try insertMemory(setup.mem.db, "p2", "data");
    try insertMemory(setup.mem.db, "p3", "data");

    try setup.ob.enqueue("p1", "upsert");
    try setup.ob.enqueue("p2", "upsert");
    try setup.ob.enqueue("p3", "upsert");
    try testing.expectEqual(@as(usize, 3), try setup.ob.pendingCount());

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 3), processed);
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
}

// ── R3 tests ──────────────────────────────────────────────────────

/// Helper: read the attempts count for a given memory_key from vector_outbox.
fn getAttempts(db: ?*c.sqlite3, memory_key: []const u8) !?i32 {
    const sql = "SELECT attempts FROM vector_outbox WHERE memory_key = ?1";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, memory_key.ptr, @intCast(memory_key.len), SQLITE_STATIC);

    rc = c.sqlite3_step(stmt);
    if (rc == c.SQLITE_ROW) {
        return c.sqlite3_column_int(stmt, 0);
    }
    return null;
}

fn hasEmbeddingKey(db: ?*c.sqlite3, memory_key: []const u8) !bool {
    const sql = "SELECT COUNT(*) FROM memory_embeddings WHERE memory_key = ?1";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, memory_key.ptr, @intCast(memory_key.len), SQLITE_STATIC);
    rc = c.sqlite3_step(stmt);
    if (rc == c.SQLITE_ROW) {
        return c.sqlite3_column_int64(stmt, 0) > 0;
    }
    return false;
}

/// Failing embedding provider for testing drain failure paths.
const FailingEmbedding = struct {
    const Self = @This();

    fn implName(_: *anyopaque) []const u8 {
        return "failing";
    }

    fn implDimensions(_: *anyopaque) u32 {
        return 3;
    }

    fn implEmbed(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror![]f32 {
        return error.EmbeddingApiError;
    }

    fn implDeinit(_: *anyopaque) void {}

    const vtable = embeddings.EmbeddingProvider.VTable{
        .name = &implName,
        .dimensions = &implDimensions,
        .embed = &implEmbed,
        .deinit = &implDeinit,
    };

    fn provider(self: *Self) embeddings.EmbeddingProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }
};

// R3-1: enqueue → drain → verify items processed and removed
test "enqueue drain verify items processed" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // Insert 3 items with content
    try insertMemory(setup.mem.db, "r3_a", "content a");
    try insertMemory(setup.mem.db, "r3_b", "content b");
    try insertMemory(setup.mem.db, "r3_c", "content c");

    try setup.ob.enqueue("r3_a", "upsert");
    try setup.ob.enqueue("r3_b", "upsert");
    try setup.ob.enqueue("r3_c", "upsert");
    try testing.expectEqual(@as(usize, 3), try setup.ob.pendingCount());

    var noop = embeddings.NoopEmbedding{};
    const ep = noop.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 3), processed);
    // All items should be removed from outbox
    try testing.expectEqual(@as(usize, 0), try totalOutboxCount(setup.mem.db));
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
    // Vector store should have 3 entries
    try testing.expectEqual(@as(usize, 3), try vs.count());
}

// R3-2: enqueue → fail drain → verify retry count incremented
test "drain failure increments retry count" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // Insert content so drain attempts embedding (which will fail)
    try insertMemory(setup.mem.db, "fail_key", "some content");
    try setup.ob.enqueue("fail_key", "upsert");

    // Use FailingEmbedding that always returns error
    var failing = FailingEmbedding{};
    const ep = failing.provider();
    const vs = setup.vs_impl.store();

    const processed = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 0), processed);

    // Item should still be in outbox with attempts incremented
    try testing.expectEqual(@as(usize, 1), try totalOutboxCount(setup.mem.db));
    const attempts = try getAttempts(setup.mem.db, "fail_key");
    try testing.expect(attempts != null);
    try testing.expectEqual(@as(i32, 1), attempts.?);

    // Drain again — attempts should increment again
    const processed2 = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 0), processed2);
    const attempts2 = try getAttempts(setup.mem.db, "fail_key");
    try testing.expectEqual(@as(i32, 2), attempts2.?);

    // Now it has reached max_retries (2) — drain should skip it
    const processed3 = try setup.ob.drain(allocator, ep, vs, null);
    try testing.expectEqual(@as(u32, 0), processed3);
    // Still in outbox but not pending (attempts >= max_retries)
    try testing.expectEqual(@as(usize, 1), try totalOutboxCount(setup.mem.db));
    try testing.expectEqual(@as(usize, 0), try setup.ob.pendingCount());
}

// R3-3: dead letter — max retries exceeded → purge removes item
test "dead letter purge removes exhausted items" {
    const allocator = testing.allocator;
    var setup = try testSetup(allocator);
    defer setup.deinit();

    // Enqueue items and manually exhaust retries
    try setup.ob.enqueue("dead_a", "upsert");
    try setup.ob.enqueue("dead_b", "upsert");
    try setup.ob.enqueue("alive_c", "upsert");

    // Set dead_a and dead_b past max_retries (max_retries=2)
    try setAttempts(setup.mem.db, "dead_a", 5); // well past limit
    try setAttempts(setup.mem.db, "dead_b", 2); // exactly at limit

    // alive_c is still at attempts=0 — should survive purge
    try testing.expectEqual(@as(usize, 3), try totalOutboxCount(setup.mem.db));

    const purged = try setup.ob.purgeDeadLetters();
    try testing.expectEqual(@as(u32, 2), purged);

    // Only alive_c remains
    try testing.expectEqual(@as(usize, 1), try totalOutboxCount(setup.mem.db));
    try testing.expectEqual(@as(usize, 1), try setup.ob.pendingCount());
}
