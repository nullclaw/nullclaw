const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

// SQLITE_STATIC = NULL — tells SQLite the bound value won't change during statement lifetime.
// SQLITE_STATIC can't be expressed in Zig 0.15 (unaligned fn pointer).
// Callers must ensure bound slices outlive the statement execution.
const SQLITE_STATIC: c.sqlite3_destructor_type = null;

pub const Memory = struct {
    db: ?*c.sqlite3,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, db_path: [*:0]const u8) !Memory {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }

        var self = Memory{ .db = db, .allocator = allocator };
        try self.migrate();
        return self;
    }

    pub fn deinit(self: *Memory) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
    }

    fn migrate(self: *Memory) !void {
        const sql =
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
        ;
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    pub fn saveMessage(self: *Memory, session_id: []const u8, role: []const u8, content: []const u8) !void {
        const sql = "INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, role.ptr, @intCast(role.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, content.ptr, @intCast(content.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    }
};

test "memory init with in-memory db" {
    var mem = try Memory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    try mem.saveMessage("test-session", "user", "hello");
}
