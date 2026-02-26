//! Brain.db source reader — reads SQLite-based memory from OpenClaw/ZeroClaw.
//!
//! Detects schema dynamically via PRAGMA table_info to support both legacy
//! and current brain.db variants. Used by migration.zig for SQLite import.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const sqlite = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const c = sqlite.c;

pub const SqliteSourceEntry = struct {
    key: []const u8,
    content: []const u8,
    category: []const u8,
};

pub const BrainDbError = error{
    OpenFailed,
    NoMemoriesTable,
    NoContentColumn,
    QueryFailed,
    OutOfMemory,
    SkipZigTest,
};

/// Read all entries from a brain.db file. Caller owns returned slice.
pub fn readBrainDb(
    allocator: std.mem.Allocator,
    db_path: [*:0]const u8,
) BrainDbError![]SqliteSourceEntry {
    if (!build_options.enable_sqlite) {
        if (builtin.is_test) return error.SkipZigTest;
        return error.OpenFailed;
    }

    var db: ?*c.sqlite3 = null;
    var rc = c.sqlite3_open_v2(db_path, &db, c.SQLITE_OPEN_READONLY, null);
    if (rc != c.SQLITE_OK) {
        if (db) |d| _ = c.sqlite3_close(d);
        return error.OpenFailed;
    }
    defer _ = c.sqlite3_close(db.?);

    // Check memories table exists
    if (!tableExists(db.?, "memories")) return error.NoMemoriesTable;

    // Detect columns
    const cols = detectColumns(db.?) orelse return error.QueryFailed;

    // Build and execute query
    var query_buf: [256]u8 = undefined;
    const query = std.fmt.bufPrintZ(&query_buf, "SELECT {s}, {s}, {s} FROM memories", .{
        cols.key_expr,
        cols.content_col,
        cols.category_expr,
    }) catch return error.QueryFailed;

    var stmt: ?*c.sqlite3_stmt = null;
    rc = c.sqlite3_prepare_v2(db.?, query.ptr, @intCast(query.len), &stmt, null);
    if (rc != c.SQLITE_OK) return error.QueryFailed;
    defer _ = c.sqlite3_finalize(stmt);

    var entries: std.ArrayList(SqliteSourceEntry) = .empty;
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.key);
            allocator.free(e.content);
            allocator.free(e.category);
        }
        entries.deinit(allocator);
    }

    while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
        const raw_key = columnText(stmt, 0);
        const raw_content = columnText(stmt, 1);
        const raw_category = columnText(stmt, 2);

        if (raw_content.len == 0) continue; // skip empty content

        const key = allocator.dupe(u8, raw_key) catch return error.OutOfMemory;
        errdefer allocator.free(key);
        const content = allocator.dupe(u8, raw_content) catch return error.OutOfMemory;
        errdefer allocator.free(content);
        const category = allocator.dupe(u8, raw_category) catch return error.OutOfMemory;
        errdefer allocator.free(category);

        entries.append(allocator, .{
            .key = key,
            .content = content,
            .category = category,
        }) catch return error.OutOfMemory;
    }

    return entries.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Free all entries returned by readBrainDb.
pub fn freeSqliteEntries(allocator: std.mem.Allocator, entries: []SqliteSourceEntry) void {
    for (entries) |e| {
        allocator.free(e.key);
        allocator.free(e.content);
        allocator.free(e.category);
    }
    allocator.free(entries);
}

// ── Internal helpers ───────────────────────────────────────────────

const ColumnMapping = struct {
    key_expr: []const u8,
    content_col: []const u8,
    category_expr: []const u8,
};

fn detectColumns(db: *c.sqlite3) ?ColumnMapping {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "PRAGMA table_info(memories)";
    const rc = c.sqlite3_prepare_v2(db, sql, @intCast(sql.len), &stmt, null);
    if (rc != c.SQLITE_OK) return null;
    defer _ = c.sqlite3_finalize(stmt);

    var has_key = false;
    var has_id = false;
    var has_name = false;
    var has_content = false;
    var has_value = false;
    var has_text = false;
    var has_memory = false;
    var has_category = false;
    var has_kind = false;
    var has_type = false;

    while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
        const col_name = columnText(stmt, 1); // column 1 = name in table_info
        if (std.mem.eql(u8, col_name, "key")) has_key = true;
        if (std.mem.eql(u8, col_name, "id")) has_id = true;
        if (std.mem.eql(u8, col_name, "name")) has_name = true;
        if (std.mem.eql(u8, col_name, "content")) has_content = true;
        if (std.mem.eql(u8, col_name, "value")) has_value = true;
        if (std.mem.eql(u8, col_name, "text")) has_text = true;
        if (std.mem.eql(u8, col_name, "memory")) has_memory = true;
        if (std.mem.eql(u8, col_name, "category")) has_category = true;
        if (std.mem.eql(u8, col_name, "kind")) has_kind = true;
        if (std.mem.eql(u8, col_name, "type")) has_type = true;
    }

    // Content column (required)
    const content_col: []const u8 = if (has_content)
        "content"
    else if (has_value)
        "value"
    else if (has_text)
        "text"
    else if (has_memory)
        "memory"
    else
        return null; // no content column found → error

    // Key column (fallback to rowid)
    const key_expr: []const u8 = if (has_key)
        "key"
    else if (has_id)
        "id"
    else if (has_name)
        "name"
    else
        "CAST(rowid AS TEXT)";

    // Category column (fallback to literal 'core')
    const category_expr: []const u8 = if (has_category)
        "category"
    else if (has_kind)
        "kind"
    else if (has_type)
        "type"
    else
        "'core'";

    return .{
        .key_expr = key_expr,
        .content_col = content_col,
        .category_expr = category_expr,
    };
}

fn tableExists(db: *c.sqlite3, table_name: []const u8) bool {
    const sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, @intCast(sql.len), &stmt, null);
    if (rc != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, table_name.ptr, @intCast(table_name.len), sqlite.SQLITE_STATIC);
    return c.sqlite3_step(stmt) == c.SQLITE_ROW;
}

fn columnText(stmt: ?*c.sqlite3_stmt, col: c_int) []const u8 {
    const ptr = c.sqlite3_column_text(stmt, col);
    if (ptr == null) return "";
    const len = c.sqlite3_column_bytes(stmt, col);
    if (len <= 0) return "";
    return ptr[0..@intCast(len)];
}

// ── Helper: create in-memory db with schema ────────────────────────

fn createTestDb(allocator: std.mem.Allocator, schema: []const u8) !*c.sqlite3 {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    _ = allocator;
    var db: ?*c.sqlite3 = null;
    const rc = c.sqlite3_open(":memory:", &db);
    if (rc != c.SQLITE_OK) {
        if (db) |d| _ = c.sqlite3_close(d);
        return error.OpenFailed;
    }

    if (c.sqlite3_exec(db, schema.ptr, null, null, null) != c.SQLITE_OK) {
        _ = c.sqlite3_close(db.?);
        return error.QueryFailed;
    }

    return db.?;
}

fn closeTestDb(db: *c.sqlite3) void {
    _ = c.sqlite3_close(db);
}

fn execSql(db: *c.sqlite3, sql: [*:0]const u8) void {
    _ = c.sqlite3_exec(db, sql, null, null, null);
}

// ── Tests ──────────────────────────────────────────────────────────

test "readBrainDb with standard schema (key/content/category)" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
        \\INSERT INTO memories VALUES ('pref1', 'likes Zig', 'core');
        \\INSERT INTO memories VALUES ('pref2', 'uses NeoVim', 'daily');
    );
    defer closeTestDb(db);

    // readBrainDb expects a file path; we need to use the in-memory db directly.
    // Since readBrainDb opens its own db, we test via the internal helpers instead.
    // For the full path test, we verify the column detection works.
    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("key", cols.key_expr);
    try std.testing.expectEqualStrings("content", cols.content_col);
    try std.testing.expectEqualStrings("category", cols.category_expr);
}

test "readBrainDb with legacy schema (id/value/kind)" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (id TEXT, value TEXT, kind TEXT);
        \\INSERT INTO memories VALUES ('m1', 'some value', 'conversation');
    );
    defer closeTestDb(db);

    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("id", cols.key_expr);
    try std.testing.expectEqualStrings("value", cols.content_col);
    try std.testing.expectEqualStrings("kind", cols.category_expr);
}

test "readBrainDb with minimal schema (content only, others fallback)" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (content TEXT);
        \\INSERT INTO memories VALUES ('standalone content');
    );
    defer closeTestDb(db);

    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("CAST(rowid AS TEXT)", cols.key_expr);
    try std.testing.expectEqualStrings("content", cols.content_col);
    try std.testing.expectEqualStrings("'core'", cols.category_expr);
}

test "readBrainDb with missing memories table" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    const result = readBrainDb(std.testing.allocator, ":memory:");
    try std.testing.expectError(error.NoMemoriesTable, result);
}

test "readBrainDb with empty table" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
    );
    defer closeTestDb(db);

    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("key", cols.key_expr);
    try std.testing.expectEqualStrings("content", cols.content_col);
}

test "readBrainDb with no content column" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, description TEXT);
    );
    defer closeTestDb(db);

    const cols = detectColumns(db);
    try std.testing.expect(cols == null); // no content/value/text/memory column
}

test "column detection: finds key before id before name" {
    // DB with both key and id — key should win
    const db1 = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (id TEXT, key TEXT, content TEXT);
    );
    defer closeTestDb(db1);
    const cols1 = detectColumns(db1).?;
    try std.testing.expectEqualStrings("key", cols1.key_expr);

    // DB with id and name — id should win
    const db2 = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (name TEXT, id TEXT, content TEXT);
    );
    defer closeTestDb(db2);
    const cols2 = detectColumns(db2).?;
    try std.testing.expectEqualStrings("id", cols2.key_expr);
}

test "column detection: finds content before value" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT, value TEXT);
    );
    defer closeTestDb(db);
    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("content", cols.content_col);
}

test "freeSqliteEntries frees all allocations" {
    const allocator = std.testing.allocator;
    var entries = try allocator.alloc(SqliteSourceEntry, 2);
    entries[0] = .{
        .key = try allocator.dupe(u8, "k1"),
        .content = try allocator.dupe(u8, "c1"),
        .category = try allocator.dupe(u8, "core"),
    };
    entries[1] = .{
        .key = try allocator.dupe(u8, "k2"),
        .content = try allocator.dupe(u8, "c2"),
        .category = try allocator.dupe(u8, "daily"),
    };
    freeSqliteEntries(allocator, entries);
    // testing allocator detects leaks
}

test "multiple entries roundtrip via column detection" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
        \\INSERT INTO memories VALUES ('a', 'alpha', 'core');
        \\INSERT INTO memories VALUES ('b', 'beta', 'daily');
        \\INSERT INTO memories VALUES ('c', 'gamma', 'conversation');
    );
    defer closeTestDb(db);

    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("key", cols.key_expr);
    try std.testing.expectEqualStrings("content", cols.content_col);
    try std.testing.expectEqualStrings("category", cols.category_expr);

    // Query manually to verify entries are readable
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT key, content, category FROM memories";
    _ = c.sqlite3_prepare_v2(db, sql, @intCast(sql.len), &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);

    var count: usize = 0;
    while (c.sqlite3_step(stmt) == c.SQLITE_ROW) count += 1;
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "unicode content preservation" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
    );
    defer closeTestDb(db);

    // Insert unicode content via parameterized query
    const insert_sql = "INSERT INTO memories VALUES (?, ?, ?)";
    var insert_stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, insert_sql, @intCast(insert_sql.len), &insert_stmt, null);
    defer _ = c.sqlite3_finalize(insert_stmt);

    const unicode_content = "Привет, мир! 🌍 日本語";
    _ = c.sqlite3_bind_text(insert_stmt, 1, "unicode_key", 11, sqlite.SQLITE_STATIC);
    _ = c.sqlite3_bind_text(insert_stmt, 2, unicode_content.ptr, @intCast(unicode_content.len), sqlite.SQLITE_STATIC);
    _ = c.sqlite3_bind_text(insert_stmt, 3, "core", 4, sqlite.SQLITE_STATIC);
    _ = c.sqlite3_step(insert_stmt);

    // Read back
    const select_sql = "SELECT content FROM memories WHERE key='unicode_key'";
    var sel_stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, select_sql, @intCast(select_sql.len), &sel_stmt, null);
    defer _ = c.sqlite3_finalize(sel_stmt);

    try std.testing.expect(c.sqlite3_step(sel_stmt) == c.SQLITE_ROW);
    const read_back = columnText(sel_stmt, 0);
    try std.testing.expectEqualStrings(unicode_content, read_back);
}

test "category fallback to core" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (key TEXT, content TEXT);
    );
    defer closeTestDb(db);
    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("'core'", cols.category_expr);
}

test "tableExists returns false for non-existent table" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE other_table (id TEXT);
    );
    defer closeTestDb(db);
    try std.testing.expect(!tableExists(db, "memories"));
    try std.testing.expect(tableExists(db, "other_table"));
}

test "text column detection" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (name TEXT, text TEXT, type TEXT);
    );
    defer closeTestDb(db);
    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("name", cols.key_expr);
    try std.testing.expectEqualStrings("text", cols.content_col);
    try std.testing.expectEqualStrings("type", cols.category_expr);
}

test "memory column detection" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE memories (memory TEXT);
    );
    defer closeTestDb(db);
    const cols = detectColumns(db).?;
    try std.testing.expectEqualStrings("memory", cols.content_col);
    try std.testing.expectEqualStrings("CAST(rowid AS TEXT)", cols.key_expr);
    try std.testing.expectEqualStrings("'core'", cols.category_expr);
}

// ── P5.1: Edge case tests ─────────────────────────────────────────

test "readBrainDb with corrupt file returns no memories table" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "corrupt.db", .data = "not a sqlite database" });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "corrupt.db");
    defer std.testing.allocator.free(path);
    const pathZ = try std.testing.allocator.dupeZ(u8, path);
    defer std.testing.allocator.free(pathZ);

    const result = readBrainDb(std.testing.allocator, pathZ.ptr);
    try std.testing.expectError(error.NoMemoriesTable, result);
}

test "readBrainDb with empty table returns empty slice" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    // Create a temp file with an empty memories table
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create an actual SQLite file on disk with empty table
    const file = try tmp.dir.createFile("empty.db", .{});
    file.close();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "empty.db");
    defer std.testing.allocator.free(path);

    // Open it properly and create the table
    const pathZ = try std.testing.allocator.dupeZ(u8, path);
    defer std.testing.allocator.free(pathZ);

    var db: ?*c.sqlite3 = null;
    const rc = c.sqlite3_open(pathZ.ptr, &db);
    if (rc != c.SQLITE_OK) {
        if (db) |d| _ = c.sqlite3_close(d);
        return error.OpenFailed;
    }
    _ = c.sqlite3_exec(db, "CREATE TABLE memories (key TEXT, content TEXT, category TEXT)", null, null, null);
    _ = c.sqlite3_close(db.?);

    // Now read via the public API
    const entries = try readBrainDb(std.testing.allocator, pathZ.ptr);
    defer freeSqliteEntries(std.testing.allocator, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "readBrainDb skips rows with empty content" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("skip_empty.db", .{});
    file.close();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "skip_empty.db");
    defer std.testing.allocator.free(path);
    const pathZ = try std.testing.allocator.dupeZ(u8, path);
    defer std.testing.allocator.free(pathZ);

    var db: ?*c.sqlite3 = null;
    _ = c.sqlite3_open(pathZ.ptr, &db);
    _ = c.sqlite3_exec(db,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
        \\INSERT INTO memories VALUES ('k1', '', 'core');
        \\INSERT INTO memories VALUES ('k2', 'valid', 'core');
        \\INSERT INTO memories VALUES ('k3', NULL, 'core');
    , null, null, null);
    _ = c.sqlite3_close(db.?);

    const entries = try readBrainDb(std.testing.allocator, pathZ.ptr);
    defer freeSqliteEntries(std.testing.allocator, entries);
    // Only 'k2' has non-empty content
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("valid", entries[0].content);
}

test "readBrainDb full roundtrip with file-based db" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("roundtrip.db", .{});
    file.close();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "roundtrip.db");
    defer std.testing.allocator.free(path);
    const pathZ = try std.testing.allocator.dupeZ(u8, path);
    defer std.testing.allocator.free(pathZ);

    var db: ?*c.sqlite3 = null;
    _ = c.sqlite3_open(pathZ.ptr, &db);
    _ = c.sqlite3_exec(db,
        \\CREATE TABLE memories (key TEXT, content TEXT, category TEXT);
        \\INSERT INTO memories VALUES ('pref1', 'likes Zig', 'core');
        \\INSERT INTO memories VALUES ('pref2', 'uses NeoVim', 'daily');
    , null, null, null);
    _ = c.sqlite3_close(db.?);

    const entries = try readBrainDb(std.testing.allocator, pathZ.ptr);
    defer freeSqliteEntries(std.testing.allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("pref1", entries[0].key);
    try std.testing.expectEqualStrings("likes Zig", entries[0].content);
    try std.testing.expectEqualStrings("core", entries[0].category);
    try std.testing.expectEqualStrings("pref2", entries[1].key);
    try std.testing.expectEqualStrings("uses NeoVim", entries[1].content);
    try std.testing.expectEqualStrings("daily", entries[1].category);
}

test "columnText returns empty for null column" {
    const db = try createTestDb(std.testing.allocator,
        \\CREATE TABLE t (a TEXT);
        \\INSERT INTO t VALUES (NULL);
    );
    defer closeTestDb(db);

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT a FROM t";
    _ = c.sqlite3_prepare_v2(db, sql, @intCast(sql.len), &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);

    try std.testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    const val = columnText(stmt, 0);
    try std.testing.expectEqual(@as(usize, 0), val.len);
}
