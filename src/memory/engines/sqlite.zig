//! SQLite-backed persistent memory — the brain.
//!
//! Features:
//! - Core memories table with CRUD
//! - FTS5 full-text search with BM25 scoring
//! - FTS5 sync triggers (insert/update/delete)
//! - Upsert semantics (ON CONFLICT DO UPDATE)
//! - Session-scoped memory isolation via session_id
//! - Session message storage (legacy compat)
//! - KV store for settings

const std = @import("std");
const builtin = @import("builtin");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const log = std.log.scoped(.memory_sqlite);

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const SQLITE_STATIC: c.sqlite3_destructor_type = null;
const BUSY_TIMEOUT_MS: c_int = 5000;

/// Detect whether the filesystem backing `path` supports WAL mode (which
/// requires mmap).  On Linux, 9p / NFS / CIFS do not support mmap, so we
/// fall back to DELETE journal mode for those.  On non-Linux or on statfs
/// failure we default to WAL (the common case).
///
/// Primary detection: parse `/proc/self/mountinfo` to find the fs_type for
/// the longest matching mount_point prefix.  This correctly identifies 9p
/// even when statfs reports the host's backing filesystem magic (e.g. ZFS).
///
/// Fallback: statfs syscall (catches cases where mountinfo is unavailable).
pub fn shouldUseWal(path: [*:0]const u8) bool {
    if (comptime builtin.os.tag != .linux) return true;

    const path_span = std.mem.span(path);
    if (path_span.len == 0 or std.mem.eql(u8, path_span, ":memory:")) return true;

    // Primary: /proc/self/mountinfo
    if (checkMountinfo(path_span)) |use_wal| return use_wal;

    // Fallback: statfs syscall
    return checkStatfs(path);
}

/// Parse /proc/self/mountinfo to find the filesystem type for `path`.
/// Returns `false` if the fs is 9p/nfs/cifs/smb3, `true` for others,
/// `null` if mountinfo is unavailable or unparseable.
fn checkMountinfo(path: []const u8) ?bool {
    const file = std.fs.openFileAbsolute("/proc/self/mountinfo", .{}) catch return null;
    defer file.close();

    var best_len: usize = 0;
    var best_is_network = false;
    var buf: [4096]u8 = undefined;
    var carry: [512]u8 = undefined;
    var carry_len: usize = 0;

    while (true) {
        const n = file.read(buf[carry_len..]) catch break;
        if (carry_len > 0) {
            // Prepend leftover bytes from the previous read
            @memcpy(buf[0..carry_len], carry[0..carry_len]);
        }
        const total = carry_len + n;
        carry_len = 0;
        if (total == 0) break;

        var data = buf[0..total];
        while (data.len > 0) {
            if (std.mem.indexOfScalar(u8, data, '\n')) |nl| {
                const line = data[0..nl];
                data = data[nl + 1 ..];
                parseMountinfoLine(line, path, &best_len, &best_is_network);
            } else {
                // Incomplete line -- carry over to next read
                const leftover = data.len;
                if (leftover <= carry.len) {
                    @memcpy(carry[0..leftover], data[0..leftover]);
                    carry_len = leftover;
                }
                break;
            }
        }

        if (n == 0) break; // EOF
    }

    if (best_len == 0) return null;
    return !best_is_network;
}

/// Parse one mountinfo line and update best match if mount_point is a
/// longer prefix of `path`.
///
/// Format: mount_id parent_id major:minor root mount_point flags [opts]* - fs_type source super_opts
fn parseMountinfoLine(line: []const u8, path: []const u8, best_len: *usize, best_is_network: *bool) void {
    // Fields are space-separated.  We need field index 4 (mount_point)
    // and the field after the " - " separator (fs_type).
    var it = std.mem.splitScalar(u8, line, ' ');

    // Skip mount_id (0), parent_id (1), major:minor (2), root (3)
    inline for (0..4) |_| {
        _ = it.next() orelse return;
    }
    const mount_point = it.next() orelse return;

    // mount_point in mountinfo uses octal escapes (for example "\040" for space).
    // Decode while matching against `path` to avoid allocating.
    const mount_point_len = mountPointDecodedPrefixLen(path, mount_point) orelse return;
    // Ensure it's a proper prefix (exact match, or next char is '/')
    if (mount_point_len != path.len and mount_point_len > 1 and
        (mount_point_len >= path.len or path[mount_point_len] != '/'))
        return;
    if (mount_point_len <= best_len.*) return;

    // Find " - " separator to locate fs_type
    const sep = " - ";
    const sep_pos = std.mem.indexOf(u8, line, sep) orelse return;
    const after_sep = line[sep_pos + sep.len ..];
    var sep_it = std.mem.splitScalar(u8, after_sep, ' ');
    const fs_type = sep_it.next() orelse return;

    best_len.* = mount_point_len;
    best_is_network.* = isNetworkFs(fs_type);
}

fn mountPointDecodedPrefixLen(path: []const u8, mount_point: []const u8) ?usize {
    var path_idx: usize = 0;
    var mp_idx: usize = 0;
    while (mp_idx < mount_point.len) {
        if (mount_point[mp_idx] == '\\' and mp_idx + 3 < mount_point.len) {
            const d1 = octalDigit(mount_point[mp_idx + 1]);
            const d2 = octalDigit(mount_point[mp_idx + 2]);
            const d3 = octalDigit(mount_point[mp_idx + 3]);
            if (d1 != null and d2 != null and d3 != null) {
                const decoded: u8 = (@as(u8, d1.?) << 6) | (@as(u8, d2.?) << 3) | d3.?;
                if (path_idx >= path.len or path[path_idx] != decoded) return null;
                path_idx += 1;
                mp_idx += 4;
                continue;
            }
        }

        if (path_idx >= path.len or path[path_idx] != mount_point[mp_idx]) return null;
        path_idx += 1;
        mp_idx += 1;
    }
    return path_idx;
}

fn octalDigit(ch: u8) ?u8 {
    if (ch < '0' or ch > '7') return null;
    return ch - '0';
}

fn isNetworkFs(fs_type: []const u8) bool {
    const network_types = [_][]const u8{ "9p", "nfs", "nfs4", "cifs", "smb3" };
    for (network_types) |nt| {
        if (std.mem.eql(u8, fs_type, nt)) return true;
    }
    return false;
}

/// Fallback: use statfs to check f_type. If the DB file does not exist yet,
/// retry on its parent directory.
fn checkStatfs(path: [*:0]const u8) bool {
    if (statfsSupportsWal(path)) |use_wal| return use_wal;

    const path_span = std.mem.span(path);
    if (path_span.len == 0 or std.mem.eql(u8, path_span, ":memory:")) return true;

    const dir_path = std.fs.path.dirname(path_span) orelse ".";
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir_path.len + 1 > dir_buf.len) return true;
    @memcpy(dir_buf[0..dir_path.len], dir_path);
    dir_buf[dir_path.len] = 0;
    const dir_z: [*:0]const u8 = @ptrCast(&dir_buf[0]);

    if (statfsSupportsWal(dir_z)) |use_wal| return use_wal;
    return true;
}

fn statfsSupportsWal(path: [*:0]const u8) ?bool {
    var buf: [15]usize = undefined;
    const rc = std.os.linux.syscall2(
        .statfs,
        @intFromPtr(path),
        @intFromPtr(&buf),
    );
    const signed_rc: isize = @bitCast(rc);
    if (signed_rc < 0) return null;

    const f_magic: u32 = @truncate(buf[0]);
    return switch (f_magic) {
        0x01021997, // V9FS_MAGIC
        0x6969, // NFS_SUPER_MAGIC
        0xFF534D42, // CIFS_MAGIC_NUMBER
        => false,
        else => true,
    };
}

pub const SqliteMemory = struct {
    db: ?*c.sqlite3,
    allocator: std.mem.Allocator,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, db_path: [*:0]const u8) !Self {
        const use_wal = shouldUseWal(db_path);

        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(db_path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }
        if (db) |d| {
            // Reduce startup flakiness when multiple runtimes touch the same DB.
            _ = c.sqlite3_busy_timeout(d, BUSY_TIMEOUT_MS);
        }

        var self_ = Self{ .db = db, .allocator = allocator };
        try self_.configurePragmas(use_wal);
        try self_.migrate();
        try self_.migrateSessionId();
        return self_;
    }

    pub fn deinit(self: *Self) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
            self.db = null;
        }
    }

    fn logExecFailure(self: *Self, context: []const u8, sql: []const u8, rc: c_int, err_msg: [*c]u8) void {
        if (err_msg) |msg| {
            const msg_text = std.mem.span(msg);
            log.warn("sqlite {s} failed (rc={d}, sql={s}): {s}", .{ context, rc, sql, msg_text });
            return;
        }
        if (self.db) |db| {
            const msg_text = std.mem.span(c.sqlite3_errmsg(db));
            log.warn("sqlite {s} failed (rc={d}, sql={s}): {s}", .{ context, rc, sql, msg_text });
            return;
        }
        log.warn("sqlite {s} failed (rc={d}, sql={s})", .{ context, rc, sql });
    }

    fn configurePragmas(self: *Self, use_wal: bool) !void {
        // Pragmas are tuning knobs; failure should not prevent startup.
        const journal_pragma: [:0]const u8 = if (use_wal)
            "PRAGMA journal_mode = WAL;"
        else
            "PRAGMA journal_mode = DELETE;";
        if (!use_wal) {
            log.info("filesystem does not support mmap; using DELETE journal mode instead of WAL", .{});
        }
        const pragmas = [_][:0]const u8{
            journal_pragma,
            "PRAGMA synchronous  = NORMAL;",
            "PRAGMA temp_store   = MEMORY;",
            "PRAGMA cache_size   = -2000;",
        };
        for (pragmas) |pragma| {
            var err_msg: [*c]u8 = null;
            const rc = c.sqlite3_exec(self.db, pragma, null, null, &err_msg);
            if (rc != c.SQLITE_OK) {
                self.logExecFailure("pragma", pragma, rc, err_msg);
            }
            if (err_msg) |msg| c.sqlite3_free(msg);
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
            \\  session_id TEXT,
            \\  created_at TEXT NOT NULL,
            \\  updated_at TEXT NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
            \\CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key);
            \\CREATE INDEX IF NOT EXISTS idx_memories_session ON memories(session_id);
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
            \\CREATE TABLE IF NOT EXISTS session_usage (
            \\  session_id TEXT PRIMARY KEY,
            \\  total_tokens INTEGER NOT NULL DEFAULT 0,
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
            self.logExecFailure("schema migration", "CREATE TABLE/FTS/triggers", rc, err_msg);
            if (err_msg) |msg| c.sqlite3_free(msg);
            return error.MigrationFailed;
        }
    }

    /// Migration: add session_id column to existing databases that lack it.
    /// Safe to run repeatedly — ALTER TABLE fails gracefully if column already exists.
    pub fn migrateSessionId(self: *Self) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(
            self.db,
            "ALTER TABLE memories ADD COLUMN session_id TEXT;",
            null,
            null,
            &err_msg,
        );
        if (rc != c.SQLITE_OK) {
            // "duplicate column name" is expected on databases that already have the column.
            var ignore_error = false;
            if (err_msg) |msg| {
                const msg_text = std.mem.span(msg);
                ignore_error = std.mem.indexOf(u8, msg_text, "duplicate column name") != null;
            }
            if (!ignore_error) {
                self.logExecFailure("session_id migration", "ALTER TABLE memories ADD COLUMN session_id TEXT", rc, err_msg);
            }
            if (err_msg) |msg| c.sqlite3_free(msg);
        }
        // Ensure index exists regardless
        var err_msg2: [*c]u8 = null;
        const rc2 = c.sqlite3_exec(
            self.db,
            "CREATE INDEX IF NOT EXISTS idx_memories_session ON memories(session_id);",
            null,
            null,
            &err_msg2,
        );
        if (rc2 != c.SQLITE_OK) {
            self.logExecFailure("session_id migration", "CREATE INDEX IF NOT EXISTS idx_memories_session", rc2, err_msg2);
            if (err_msg2) |msg| c.sqlite3_free(msg);
        }
    }

    // ── Memory trait implementation ────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "sqlite";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const now = getNowTimestamp(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(now);

        const id = generateId(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(id);

        const cat_str = category.toString();

        const sql = "INSERT INTO memories (id, key, content, category, session_id, created_at, updated_at) " ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) " ++
            "ON CONFLICT(key) DO UPDATE SET " ++
            "content = excluded.content, " ++
            "category = excluded.category, " ++
            "session_id = excluded.session_id, " ++
            "updated_at = excluded.updated_at";

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, id.ptr, @intCast(id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, key.ptr, @intCast(key.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, content.ptr, @intCast(content.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 4, cat_str.ptr, @intCast(cat_str.len), SQLITE_STATIC);
        if (session_id) |sid| {
            _ = c.sqlite3_bind_text(stmt, 5, sid.ptr, @intCast(sid.len), SQLITE_STATIC);
        } else {
            _ = c.sqlite3_bind_null(stmt, 5);
        }
        _ = c.sqlite3_bind_text(stmt, 6, now.ptr, @intCast(now.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 7, now.ptr, @intCast(now.len), SQLITE_STATIC);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const trimmed = std.mem.trim(u8, query, " \t\n\r");
        if (trimmed.len == 0) return allocator.alloc(MemoryEntry, 0);

        const results = try fts5Search(self_, allocator, trimmed, limit, session_id);
        if (results.len > 0) return results;

        allocator.free(results);
        return try likeSearch(self_, allocator, trimmed, limit, session_id);
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sql = "SELECT id, key, content, category, created_at, session_id FROM memories WHERE key = ?1";
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

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        if (category) |cat| {
            const cat_str = cat.toString();
            const sql = "SELECT id, key, content, category, created_at, session_id FROM memories " ++
                "WHERE category = ?1 ORDER BY updated_at DESC";
            var stmt: ?*c.sqlite3_stmt = null;
            var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);

            _ = c.sqlite3_bind_text(stmt, 1, cat_str.ptr, @intCast(cat_str.len), SQLITE_STATIC);

            while (true) {
                rc = c.sqlite3_step(stmt);
                if (rc == c.SQLITE_ROW) {
                    const entry = try readEntryFromRow(stmt.?, allocator);
                    if (session_id) |sid| {
                        if (entry.session_id == null or !std.mem.eql(u8, entry.session_id.?, sid)) {
                            entry.deinit(allocator);
                            continue;
                        }
                    }
                    try entries.append(allocator, entry);
                } else break;
            }
        } else {
            const sql = "SELECT id, key, content, category, created_at, session_id FROM memories ORDER BY updated_at DESC";
            var stmt: ?*c.sqlite3_stmt = null;
            var rc = c.sqlite3_prepare_v2(self_.db, sql, -1, &stmt, null);
            if (rc != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(stmt);

            while (true) {
                rc = c.sqlite3_step(stmt);
                if (rc == c.SQLITE_ROW) {
                    const entry = try readEntryFromRow(stmt.?, allocator);
                    if (session_id) |sid| {
                        if (entry.session_id == null or !std.mem.eql(u8, entry.session_id.?, sid)) {
                            entry.deinit(allocator);
                            continue;
                        }
                    }
                    try entries.append(allocator, entry);
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
        if (self_.owns_self) {
            self_.allocator.destroy(self_);
        }
    }

    pub const vtable = Memory.VTable{
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

    /// A single persisted message entry (role + content).
    pub const MessageEntry = root.MessageEntry;

    /// Load all messages for a session, ordered by creation time.
    /// Caller owns the returned slice and all strings within it.
    pub fn loadMessages(self: *Self, allocator: std.mem.Allocator, session_id: []const u8) ![]MessageEntry {
        const sql = "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);

        var list: std.ArrayListUnmanaged(MessageEntry) = .empty;
        errdefer {
            for (list.items) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
            }
            list.deinit(allocator);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const role_ptr = c.sqlite3_column_text(stmt, 0);
            const role_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            const content_ptr = c.sqlite3_column_text(stmt, 1);
            const content_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));

            if (role_ptr == null or content_ptr == null) continue;

            try list.append(allocator, .{
                .role = try allocator.dupe(u8, role_ptr[0..role_len]),
                .content = try allocator.dupe(u8, content_ptr[0..content_len]),
            });
        }

        return list.toOwnedSlice(allocator);
    }

    /// Delete all messages for a session.
    pub fn clearMessages(self: *Self, session_id: []const u8) !void {
        const sql = "DELETE FROM messages WHERE session_id = ?";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;

        try self.clearUsage(session_id);
    }

    pub fn saveUsage(self: *Self, session_id: []const u8, total_tokens: u64) !void {
        const sql =
            "INSERT INTO session_usage (session_id, total_tokens, updated_at) VALUES (?1, ?2, datetime('now')) " ++
            "ON CONFLICT(session_id) DO UPDATE SET total_tokens = excluded.total_tokens, updated_at = datetime('now')";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int64(stmt, 2, @intCast(total_tokens));
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    }

    pub fn loadUsage(self: *Self, session_id: []const u8) !?u64 {
        const sql = "SELECT total_tokens FROM session_usage WHERE session_id = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
        const total = c.sqlite3_column_int64(stmt, 0);
        if (total < 0) return 0;
        return @intCast(total);
    }

    fn clearUsage(self: *Self, session_id: []const u8) !void {
        const sql = "DELETE FROM session_usage WHERE session_id = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    }

    /// Delete auto-saved memory entries (autosave_user_*, autosave_assistant_*).
    /// If `session_id` is provided, only entries for that session are removed.
    /// If `session_id` is null, entries are removed globally.
    pub fn clearAutoSaved(self: *Self, session_id: ?[]const u8) !void {
        const sql_scoped = "DELETE FROM memories WHERE key LIKE 'autosave_%' AND session_id = ?1";
        const sql_global = "DELETE FROM memories WHERE key LIKE 'autosave_%'";
        const sql = if (session_id != null) sql_scoped else sql_global;

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        if (session_id) |sid| {
            _ = c.sqlite3_bind_text(stmt, 1, sid.ptr, @intCast(sid.len), SQLITE_STATIC);
        }

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    }

    // ── History queries ──────────────────────────────────────────────

    pub fn countSessions(self: *Self) !u64 {
        const sql = "SELECT COUNT(*) FROM (SELECT 1 FROM messages GROUP BY session_id)";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
        const total = c.sqlite3_column_int64(stmt, 0);
        if (total < 0) return 0;
        return @intCast(total);
    }

    /// List sessions with message counts and time bounds.
    pub fn listSessions(self: *Self, allocator: std.mem.Allocator, limit: usize, offset: usize) ![]root.SessionInfo {
        const sql =
            "SELECT session_id, COUNT(*) as msg_count, MIN(created_at) as first_at, MAX(created_at) as last_at " ++
            "FROM messages GROUP BY session_id ORDER BY MAX(created_at) DESC LIMIT ?1 OFFSET ?2";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, @intCast(limit));
        _ = c.sqlite3_bind_int64(stmt, 2, @intCast(offset));

        var list: std.ArrayListUnmanaged(root.SessionInfo) = .empty;
        errdefer {
            for (list.items) |info| info.deinit(allocator);
            list.deinit(allocator);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const sid_ptr = c.sqlite3_column_text(stmt, 0);
            const sid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            const count = c.sqlite3_column_int64(stmt, 1);
            const first_ptr = c.sqlite3_column_text(stmt, 2);
            const first_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
            const last_ptr = c.sqlite3_column_text(stmt, 3);
            const last_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));

            if (sid_ptr == null) continue;

            try list.append(allocator, .{
                .session_id = try allocator.dupe(u8, sid_ptr[0..sid_len]),
                .message_count = if (count < 0) 0 else @intCast(count),
                .first_message_at = if (first_ptr) |p| try allocator.dupe(u8, p[0..first_len]) else try allocator.dupe(u8, ""),
                .last_message_at = if (last_ptr) |p| try allocator.dupe(u8, p[0..last_len]) else try allocator.dupe(u8, ""),
            });
        }

        return list.toOwnedSlice(allocator);
    }

    pub fn countDetailedMessages(self: *Self, session_id: []const u8) !u64 {
        const sql = "SELECT COUNT(*) FROM messages WHERE session_id = ?1";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
        const total = c.sqlite3_column_int64(stmt, 0);
        if (total < 0) return 0;
        return @intCast(total);
    }

    /// Load messages with timestamps for a session.
    pub fn loadMessagesDetailed(self: *Self, allocator: std.mem.Allocator, session_id: []const u8, limit: usize, offset: usize) ![]root.DetailedMessageEntry {
        const sql = "SELECT role, content, created_at FROM messages WHERE session_id = ?1 ORDER BY id ASC LIMIT ?2 OFFSET ?3";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, session_id.ptr, @intCast(session_id.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_int64(stmt, 2, @intCast(limit));
        _ = c.sqlite3_bind_int64(stmt, 3, @intCast(offset));

        var list: std.ArrayListUnmanaged(root.DetailedMessageEntry) = .empty;
        errdefer {
            for (list.items) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
                allocator.free(entry.created_at);
            }
            list.deinit(allocator);
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const role_ptr = c.sqlite3_column_text(stmt, 0);
            const role_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            const content_ptr = c.sqlite3_column_text(stmt, 1);
            const content_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
            const ts_ptr = c.sqlite3_column_text(stmt, 2);
            const ts_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));

            if (role_ptr == null or content_ptr == null) continue;

            try list.append(allocator, .{
                .role = try allocator.dupe(u8, role_ptr[0..role_len]),
                .content = try allocator.dupe(u8, content_ptr[0..content_len]),
                .created_at = if (ts_ptr) |p| try allocator.dupe(u8, p[0..ts_len]) else try allocator.dupe(u8, ""),
            });
        }

        return list.toOwnedSlice(allocator);
    }

    // ── SessionStore vtable ────────────────────────────────────────

    fn implSessionSaveMessage(ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.saveMessage(session_id, role, content);
    }

    fn implSessionLoadMessages(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8) anyerror![]root.MessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.loadMessages(allocator, session_id);
    }

    fn implSessionClearMessages(ptr: *anyopaque, session_id: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.clearMessages(session_id);
    }

    fn implSessionClearAutoSaved(ptr: *anyopaque, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.clearAutoSaved(session_id);
    }

    fn implSessionSaveUsage(ptr: *anyopaque, session_id: []const u8, total_tokens: u64) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.saveUsage(session_id, total_tokens);
    }

    fn implSessionLoadUsage(ptr: *anyopaque, session_id: []const u8) anyerror!?u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.loadUsage(session_id);
    }

    fn implSessionCountSessions(ptr: *anyopaque) anyerror!u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.countSessions();
    }

    fn implSessionListSessions(ptr: *anyopaque, allocator: std.mem.Allocator, limit: usize, offset: usize) anyerror![]root.SessionInfo {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.listSessions(allocator, limit, offset);
    }

    fn implSessionCountDetailedMessages(ptr: *anyopaque, session_id: []const u8) anyerror!u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.countDetailedMessages(session_id);
    }

    fn implSessionLoadMessagesDetailed(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8, limit: usize, offset: usize) anyerror![]root.DetailedMessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.loadMessagesDetailed(allocator, session_id, limit, offset);
    }

    const session_vtable = root.SessionStore.VTable{
        .saveMessage = &implSessionSaveMessage,
        .loadMessages = &implSessionLoadMessages,
        .clearMessages = &implSessionClearMessages,
        .clearAutoSaved = &implSessionClearAutoSaved,
        .saveUsage = &implSessionSaveUsage,
        .loadUsage = &implSessionLoadUsage,
        .countSessions = &implSessionCountSessions,
        .listSessions = &implSessionListSessions,
        .countDetailedMessages = &implSessionCountDetailedMessages,
        .loadMessagesDetailed = &implSessionLoadMessagesDetailed,
    };

    pub fn sessionStore(self: *Self) root.SessionStore {
        return .{ .ptr = @ptrCast(self), .vtable = &session_vtable };
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

    fn fts5Search(self_: *Self, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
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
            "SELECT m.id, m.key, m.content, m.category, m.created_at, bm25(memories_fts) as score, m.session_id " ++
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
                var entry = try readEntryFromRowWithSessionCol(stmt.?, allocator, 6);
                entry.score = -score_raw; // BM25 returns negative (lower = better)
                // Filter by session_id if requested
                if (session_id) |sid| {
                    if (entry.session_id == null or !std.mem.eql(u8, entry.session_id.?, sid)) {
                        entry.deinit(allocator);
                        continue;
                    }
                }
                try entries.append(allocator, entry);
            } else break;
        }

        return entries.toOwnedSlice(allocator);
    }

    fn likeSearch(self_: *Self, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
        var keywords: std.ArrayList([]const u8) = .empty;
        defer keywords.deinit(allocator);

        var iter = std.mem.tokenizeAny(u8, query, " \t\n\r");
        while (iter.next()) |word| {
            try keywords.append(allocator, word);
        }

        if (keywords.items.len == 0) return allocator.alloc(MemoryEntry, 0);

        var sql_buf: std.ArrayList(u8) = .empty;
        defer sql_buf.deinit(allocator);

        try sql_buf.appendSlice(allocator, "SELECT id, key, content, category, created_at, session_id FROM memories WHERE ");

        for (keywords.items, 0..) |_, i| {
            if (i > 0) try sql_buf.appendSlice(allocator, " OR ");
            try sql_buf.appendSlice(allocator, "(content LIKE ?");
            try appendInt(&sql_buf, allocator, i * 2 + 1);
            try sql_buf.appendSlice(allocator, " ESCAPE '\\' OR key LIKE ?");
            try appendInt(&sql_buf, allocator, i * 2 + 2);
            try sql_buf.appendSlice(allocator, " ESCAPE '\\')");
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
            const like = try escapeLikePattern(allocator, word);
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
                // Filter by session_id if requested
                if (session_id) |sid| {
                    if (entry.session_id == null or !std.mem.eql(u8, entry.session_id.?, sid)) {
                        entry.deinit(allocator);
                        continue;
                    }
                }
                try entries.append(allocator, entry);
            } else break;
        }

        return entries.toOwnedSlice(allocator);
    }

    // ── Utility functions ──────────────────────────────────────────

    fn readEntryFromRow(stmt: *c.sqlite3_stmt, allocator: std.mem.Allocator) !MemoryEntry {
        return readEntryFromRowWithSessionCol(stmt, allocator, 5);
    }

    fn readEntryFromRowWithSessionCol(stmt: *c.sqlite3_stmt, allocator: std.mem.Allocator, session_col: c_int) !MemoryEntry {
        const id = try dupeColumnText(stmt, 0, allocator);
        errdefer allocator.free(id);
        const key = try dupeColumnText(stmt, 1, allocator);
        errdefer allocator.free(key);
        const content = try dupeColumnText(stmt, 2, allocator);
        errdefer allocator.free(content);
        const cat_str = try dupeColumnText(stmt, 3, allocator);
        errdefer allocator.free(cat_str);
        const timestamp = try dupeColumnText(stmt, 4, allocator);
        errdefer allocator.free(timestamp);
        const sid = try dupeColumnTextNullable(stmt, session_col, allocator);
        errdefer if (sid) |s| allocator.free(s);

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
            .session_id = sid,
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

    /// Like dupeColumnText but returns null when the column value is SQL NULL.
    fn dupeColumnTextNullable(stmt: *c.sqlite3_stmt, col: c_int, allocator: std.mem.Allocator) !?[]u8 {
        if (c.sqlite3_column_type(stmt, col) == c.SQLITE_NULL) {
            return null;
        }
        const raw = c.sqlite3_column_text(stmt, col);
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
        if (raw == null) {
            return null;
        }
        const slice: []const u8 = @as([*]const u8, @ptrCast(raw))[0..len];
        return try allocator.dupe(u8, slice);
    }

    /// Escape SQL LIKE wildcards (% and _) in user input, then wrap with %...%.
    /// Uses backslash as escape char (paired with ESCAPE '\' in the query).
    fn escapeLikePattern(allocator: std.mem.Allocator, word: []const u8) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        try buf.append(allocator, '%');
        for (word) |ch| {
            if (ch == '%' or ch == '_' or ch == '\\') {
                try buf.append(allocator, '\\');
            }
            try buf.append(allocator, ch);
        }
        try buf.append(allocator, '%');
        return buf.toOwnedSlice(allocator);
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

test "mountinfo parser decodes escaped mount point and picks network fs" {
    const path = "/mnt/My Drive/work/memory.db";
    const root_line = "24 1 0:21 / / rw,relatime - ext4 /dev/root rw";
    const share_line = "36 24 0:31 / /mnt/My\\040Drive rw,relatime - 9p drvfs rw";

    var best_len: usize = 0;
    var best_is_network = false;
    parseMountinfoLine(root_line, path, &best_len, &best_is_network);
    parseMountinfoLine(share_line, path, &best_len, &best_is_network);

    try std.testing.expect(best_len > 1);
    try std.testing.expect(best_is_network);
}

test "mountinfo parser enforces directory boundary on prefix matches" {
    const line = "36 24 0:31 / /mnt/share rw,relatime - 9p drvfs rw";
    const path = "/mnt/share2/memory.db";

    var best_len: usize = 0;
    var best_is_network = false;
    parseMountinfoLine(line, path, &best_len, &best_is_network);

    try std.testing.expectEqual(@as(usize, 0), best_len);
    try std.testing.expect(!best_is_network);
}

test "sqlite memory init with in-memory db" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    try mem.saveMessage("test-session", "user", "hello");
}

test "sqlite init configures busy timeout" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    var stmt: ?*c.sqlite3_stmt = null;
    const prep_rc = c.sqlite3_prepare_v2(mem.db, "PRAGMA busy_timeout;", -1, &stmt, null);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_OK), prep_rc);
    defer _ = c.sqlite3_finalize(stmt);

    const step_rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_ROW), step_rc);
    const timeout_ms = c.sqlite3_column_int(stmt, 0);
    try std.testing.expect(timeout_ms >= BUSY_TIMEOUT_MS);
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

    try m.store("user_lang", "Prefers Zig", .core, null);

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

    try m.store("pref", "likes Zig", .core, null);
    try m.store("pref", "loves Zig", .core, null);

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

    try m.store("a", "Zig is fast and safe", .core, null);
    try m.store("b", "Python is interpreted", .core, null);
    try m.store("c", "Zig has comptime", .core, null);

    const results = try m.recall(std.testing.allocator, "Zig", 10, null);
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

    try m.store("a", "Zig rocks", .core, null);

    const results = try m.recall(std.testing.allocator, "javascript", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite recall empty query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "data", .core, null);

    const results = try m.recall(std.testing.allocator, "", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite recall whitespace query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "data", .core, null);

    const results = try m.recall(std.testing.allocator, "   ", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite forget" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("temp", "temporary data", .conversation, null);
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

    try m.store("a", "one", .core, null);
    try m.store("b", "two", .daily, null);
    try m.store("c", "three", .conversation, null);

    const all = try m.list(std.testing.allocator, null, null);
    defer root.freeEntries(std.testing.allocator, all);
    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "sqlite list by category" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "core1", .core, null);
    try m.store("b", "core2", .core, null);
    try m.store("c", "daily1", .daily, null);

    const core_list = try m.list(std.testing.allocator, .core, null);
    defer root.freeEntries(std.testing.allocator, core_list);
    try std.testing.expectEqual(@as(usize, 2), core_list.len);

    const daily_list = try m.list(std.testing.allocator, .daily, null);
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

    try m.store("k0", "v0", .core, null);
    try m.store("k1", "v1", .daily, null);
    try m.store("k2", "v2", .conversation, null);
    try m.store("k3", "v3", .{ .custom = "project" }, null);

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

    try m.store("ghost", "phantom memory content", .core, null);
    _ = try m.forget("ghost");

    const results = try m.recall(std.testing.allocator, "phantom memory", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "sqlite forget and re-store same key" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("cycle", "version 1", .core, null);
    _ = try m.forget("cycle");
    try m.store("cycle", "version 2", .core, null);

    const entry = (try m.get(std.testing.allocator, "cycle")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("version 2", entry.content);
    try std.testing.expectEqual(@as(usize, 1), try m.count());
}

test "sqlite store empty content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("empty", "", .core, null);
    const entry = (try m.get(std.testing.allocator, "empty")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", entry.content);
}

test "sqlite store empty key" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("", "content for empty key", .core, null);
    const entry = (try m.get(std.testing.allocator, "")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("content for empty key", entry.content);
}

test "sqlite recall results have scores" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("s1", "scored result test", .core, null);

    const results = try m.recall(std.testing.allocator, "scored", 10, null);
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

    try m.store("r1", "reindex test alpha", .core, null);
    try m.store("r2", "reindex test beta", .core, null);

    try mem.reindex();

    const results = try m.recall(std.testing.allocator, "reindex", 10, null);
    defer root.freeEntries(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "sqlite recall with sql injection attempt" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("safe", "normal content", .core, null);

    const results = try m.recall(std.testing.allocator, "'; DROP TABLE memories; --", 10, null);
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

    try m.store("test_key", "unique_searchterm_xyz", .core, null);

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

    try m.store("del_key", "deletable_content_abc", .core, null);
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

    try m.store("upd_key", "original_content_111", .core, null);
    try m.store("upd_key", "updated_content_222", .core, null);

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

    try m.store("c1", "custom1", .{ .custom = "project" }, null);
    try m.store("c2", "custom2", .{ .custom = "project" }, null);
    try m.store("c3", "other", .core, null);

    const project = try m.list(std.testing.allocator, .{ .custom = "project" }, null);
    defer root.freeEntries(std.testing.allocator, project);
    try std.testing.expectEqual(@as(usize, 2), project.len);
}

test "sqlite list empty db" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const all = try m.list(std.testing.allocator, null, null);
    defer root.freeEntries(std.testing.allocator, all);
    try std.testing.expectEqual(@as(usize, 0), all.len);
}

test "sqlite recall matches by key not just content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("zig_preferences", "User likes systems programming", .core, null);

    const results = try m.recall(std.testing.allocator, "zig", 10, null);
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
        try m.store(key, content, .core, null);
    }

    const results = try m.recall(std.testing.allocator, "searchable", 3, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len <= 3);
}

test "sqlite store unicode content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("unicode_key", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", .core, null);

    const entry = (try m.get(std.testing.allocator, "unicode_key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", entry.content);
}

test "sqlite recall unicode query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("jp", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", .core, null);

    const results = try m.recall(std.testing.allocator, "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 10, null);
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

    try m.store("long", buf.items, .core, null);
    const entry = (try m.get(std.testing.allocator, "long")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 10000), entry.content.len);
}

test "sqlite multiple categories count" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "one", .core, null);
    try m.store("b", "two", .daily, null);
    try m.store("c", "three", .conversation, null);
    try m.store("d", "four", .{ .custom = "project" }, null);

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

    try m.store("k1", "v1", .core, null);
    try m.store("k2", "v2", .core, null);
    try m.store("k3", "v3", .core, null);

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

    try m.store("key", "value", .core, null);
    try m.store("key", "new value", .daily, null);

    const entry = (try m.get(std.testing.allocator, "key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("new value", entry.content);
    try std.testing.expect(entry.category.eql(.daily));
}

test "sqlite recall multi-word query" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("zig-lang", "Zig is a systems programming language", .core, null);
    try m.store("rust-lang", "Rust is also a systems language", .core, null);
    try m.store("python-lang", "Python is interpreted", .core, null);

    const results = try m.recall(std.testing.allocator, "systems programming", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len >= 1);
}

test "sqlite list returns all entries" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("first", "first entry", .core, null);
    try m.store("second", "second entry", .core, null);
    try m.store("third", "third entry", .core, null);

    const all = try m.list(std.testing.allocator, null, null);
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

    try m.store("test_key", "test_content", .daily, null);

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

    try m.store("quotes", "He said \"hello\" to the world", .core, null);

    const results = try m.recall(std.testing.allocator, "hello", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len > 0);
}

test "sqlite health check after operations" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, null);
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

// ── Session ID tests ──────────────────────────────────────────────

test "sqlite store with session_id persists" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "session data", .core, "sess-abc");

    const entry = (try m.get(std.testing.allocator, "k1")).?;
    defer entry.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("session data", entry.content);
    try std.testing.expect(entry.session_id != null);
    try std.testing.expectEqualStrings("sess-abc", entry.session_id.?);
}

test "sqlite store without session_id gives null" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "no session", .core, null);

    const entry = (try m.get(std.testing.allocator, "k1")).?;
    defer entry.deinit(std.testing.allocator);

    try std.testing.expect(entry.session_id == null);
}

test "sqlite recall with session_id filters correctly" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "session A fact", .core, "sess-a");
    try m.store("k2", "session B fact", .core, "sess-b");
    try m.store("k3", "no session fact", .core, null);

    // Recall with session-a filter returns only session-a entry
    const results = try m.recall(std.testing.allocator, "fact", 10, "sess-a");
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("k1", results[0].key);
    try std.testing.expect(results[0].session_id != null);
    try std.testing.expectEqualStrings("sess-a", results[0].session_id.?);
}

test "sqlite recall with null session_id returns all" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "alpha fact", .core, "sess-a");
    try m.store("k2", "beta fact", .core, "sess-b");
    try m.store("k3", "gamma fact", .core, null);

    const results = try m.recall(std.testing.allocator, "fact", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
}

test "sqlite list with session_id filter" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "a1", .core, "sess-a");
    try m.store("k2", "a2", .conversation, "sess-a");
    try m.store("k3", "b1", .core, "sess-b");
    try m.store("k4", "none1", .core, null);

    // List with session-a filter
    const results = try m.list(std.testing.allocator, null, "sess-a");
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    for (results) |entry| {
        try std.testing.expect(entry.session_id != null);
        try std.testing.expectEqualStrings("sess-a", entry.session_id.?);
    }
}

test "sqlite list with session_id and category filter" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "a1", .core, "sess-a");
    try m.store("k2", "a2", .conversation, "sess-a");
    try m.store("k3", "b1", .core, "sess-b");

    const results = try m.list(std.testing.allocator, .core, "sess-a");
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("k1", results[0].key);
}

test "sqlite cross-session recall isolation" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("secret", "session A secret data", .core, "sess-a");

    // Session B cannot see session A data
    const results_b = try m.recall(std.testing.allocator, "secret", 10, "sess-b");
    defer root.freeEntries(std.testing.allocator, results_b);
    try std.testing.expectEqual(@as(usize, 0), results_b.len);

    // Session A can see its own data
    const results_a = try m.recall(std.testing.allocator, "secret", 10, "sess-a");
    defer root.freeEntries(std.testing.allocator, results_a);
    try std.testing.expectEqual(@as(usize, 1), results_a.len);
}

test "sqlite schema has session_id column" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    // Verify session_id column exists by querying it
    const sql = "SELECT session_id FROM memories LIMIT 0";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(mem.db, sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    _ = c.sqlite3_finalize(stmt);
}

test "sqlite schema migration is idempotent" {
    // Calling migrateSessionId twice should not fail
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    // migrateSessionId already ran during init; call it again
    try mem.migrateSessionId();

    // Store with session_id should still work
    const m = mem.memory();
    try m.store("k1", "data", .core, "sess-x");
    const entry = (try m.get(std.testing.allocator, "k1")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("sess-x", entry.session_id.?);
}

// ── clearAutoSaved tests ──────────────────────────────────────────

test "sqlite clearAutoSaved removes autosave entries" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("autosave_user_1000", "user msg", .conversation, null);
    try m.store("autosave_assistant_1001", "assistant reply", .daily, null);
    try m.store("normal_key", "keep this", .core, null);

    try std.testing.expectEqual(@as(usize, 3), try m.count());

    try mem.clearAutoSaved(null);

    try std.testing.expectEqual(@as(usize, 1), try m.count());
    const entry = (try m.get(std.testing.allocator, "normal_key")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("keep this", entry.content);
}

test "sqlite clearAutoSaved scoped by session_id" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("autosave_user_a", "a", .conversation, "sess-a");
    try m.store("autosave_user_b", "b", .conversation, "sess-b");
    try m.store("normal_key", "keep this", .core, "sess-b");

    try mem.clearAutoSaved("sess-a");

    const a_entry = try m.get(std.testing.allocator, "autosave_user_a");
    defer if (a_entry) |entry| entry.deinit(std.testing.allocator);
    try std.testing.expect(a_entry == null);

    const b_entry = try m.get(std.testing.allocator, "autosave_user_b");
    defer if (b_entry) |entry| entry.deinit(std.testing.allocator);
    try std.testing.expect(b_entry != null);
    try std.testing.expectEqualStrings("b", b_entry.?.content);

    const normal = try m.get(std.testing.allocator, "normal_key");
    defer if (normal) |entry| entry.deinit(std.testing.allocator);
    try std.testing.expect(normal != null);
    try std.testing.expectEqualStrings("keep this", normal.?.content);
}

test "sqlite clearAutoSaved preserves non-autosave entries" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("user_pref", "likes Zig", .core, null);
    try m.store("daily_note", "some note", .daily, null);
    try m.store("autosave_like_prefix", "not autosave", .core, null);

    try mem.clearAutoSaved(null);

    // "autosave_like_prefix" starts with "autosave_" so it IS removed
    try std.testing.expectEqual(@as(usize, 2), try m.count());
}

test "sqlite clearAutoSaved no-op on empty" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    try mem.clearAutoSaved(null);
    const m = mem.memory();
    try std.testing.expectEqual(@as(usize, 0), try m.count());
}

// ── SessionStore vtable tests ─────────────────────────────────────

test "sqlite sessionStore returns valid vtable" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try std.testing.expect(store.vtable == &SqliteMemory.session_vtable);
}

test "sqlite sessionStore saveMessage + loadMessages roundtrip" {
    const allocator = std.testing.allocator;
    var mem = try SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("s1", "user", "hello");
    try store.saveMessage("s1", "assistant", "hi there");

    const msgs = try store.loadMessages(allocator, "s1");
    defer root.freeMessages(allocator, msgs);

    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("user", msgs[0].role);
    try std.testing.expectEqualStrings("hello", msgs[0].content);
    try std.testing.expectEqualStrings("assistant", msgs[1].role);
    try std.testing.expectEqualStrings("hi there", msgs[1].content);
}

test "sqlite sessionStore clearMessages" {
    const allocator = std.testing.allocator;
    var mem = try SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("s1", "user", "hello");
    try store.saveUsage("s1", 99);
    try store.clearMessages("s1");

    const msgs = try store.loadMessages(allocator, "s1");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
    try std.testing.expectEqual(@as(?u64, null), try store.loadUsage("s1"));
}

test "sqlite sessionStore saveUsage + loadUsage roundtrip" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveUsage("s1", 123);
    try std.testing.expectEqual(@as(?u64, 123), try store.loadUsage("s1"));
}

test "sqlite sessionStore clearAutoSaved" {
    const allocator = std.testing.allocator;
    var mem = try SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const m = mem.memory();
    try m.store("autosave_user_1", "auto data", .core, "s1");
    try m.store("normal_key", "normal data", .core, null);

    const store = mem.sessionStore();
    try store.clearAutoSaved("s1");

    // autosave entry should be gone
    const entry = try m.get(allocator, "autosave_user_1");
    try std.testing.expect(entry == null);

    // normal entry should remain
    const normal = try m.get(allocator, "normal_key");
    try std.testing.expect(normal != null);
    var e = normal.?;
    defer e.deinit(allocator);
}

// ── R3 additional tests ───────────────────────────────────────────

test "sqlite recall with SQL LIKE wildcard percent in content" {
    // Verify that % in search query does not match everything
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "100% safe data", .core, null);
    try m.store("k2", "completely unrelated", .core, null);

    // Searching for "%" should NOT match "completely unrelated"
    // because % is escaped in LIKE patterns
    const results = try m.recall(std.testing.allocator, "%", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    // FTS5 may or may not match "%" — but LIKE fallback must not wildcard-match everything.
    // If FTS5 returns 0 results (likely for single %), the LIKE search must be precise.
    for (results) |entry| {
        // Every returned result must actually contain "%" in key or content
        const has_pct = std.mem.indexOf(u8, entry.content, "%") != null or
            std.mem.indexOf(u8, entry.key, "%") != null;
        try std.testing.expect(has_pct);
    }
}

test "sqlite recall with SQL LIKE wildcard underscore in content" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k1", "test_value", .core, null);
    try m.store("k2", "testXvalue", .core, null);

    // Searching for "_" should not match "testXvalue" via LIKE _
    // (underscore matches single char in unescaped LIKE)
    const results = try m.recall(std.testing.allocator, "_", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    for (results) |entry| {
        const has_underscore = std.mem.indexOf(u8, entry.content, "_") != null or
            std.mem.indexOf(u8, entry.key, "_") != null;
        try std.testing.expect(has_underscore);
    }
}

test "sqlite escapeLikePattern escapes wildcards" {
    const alloc = std.testing.allocator;

    // Normal word — just wrapped with %
    {
        const result = try SqliteMemory.escapeLikePattern(alloc, "hello");
        defer alloc.free(result);
        try std.testing.expectEqualStrings("%hello%", result);
    }

    // Percent sign — escaped
    {
        const result = try SqliteMemory.escapeLikePattern(alloc, "100%");
        defer alloc.free(result);
        try std.testing.expectEqualStrings("%100\\%%", result);
    }

    // Underscore — escaped
    {
        const result = try SqliteMemory.escapeLikePattern(alloc, "test_value");
        defer alloc.free(result);
        try std.testing.expectEqualStrings("%test\\_value%", result);
    }

    // Backslash — escaped
    {
        const result = try SqliteMemory.escapeLikePattern(alloc, "path\\to");
        defer alloc.free(result);
        try std.testing.expectEqualStrings("%path\\\\to%", result);
    }

    // Empty string
    {
        const result = try SqliteMemory.escapeLikePattern(alloc, "");
        defer alloc.free(result);
        try std.testing.expectEqualStrings("%%", result);
    }
}

test "sqlite store and get with special chars in key" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const key = "key with \"quotes\" and 'apostrophes' and %wildcards%";
    try m.store(key, "content", .core, null);

    const entry = (try m.get(std.testing.allocator, key)).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(key, entry.key);
}

test "sqlite store newlines in content roundtrip" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    const content = "line1\nline2\ttab\r\nwindows\n\ndouble newline";
    try m.store("nl", content, .core, null);

    const entry = (try m.get(std.testing.allocator, "nl")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(content, entry.content);
}

test "sqlite upsert updates session_id from null to value" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, null);
    {
        const entry = (try m.get(std.testing.allocator, "k")).?;
        defer entry.deinit(std.testing.allocator);
        try std.testing.expect(entry.session_id == null);
    }

    try m.store("k", "v2", .core, "sess-new");
    {
        const entry = (try m.get(std.testing.allocator, "k")).?;
        defer entry.deinit(std.testing.allocator);
        try std.testing.expect(entry.session_id != null);
        try std.testing.expectEqualStrings("sess-new", entry.session_id.?);
    }
}

test "sqlite upsert updates session_id from value to null" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();
    const m = mem.memory();

    try m.store("k", "v", .core, "sess-old");
    try m.store("k", "v2", .core, null);

    const entry = (try m.get(std.testing.allocator, "k")).?;
    defer entry.deinit(std.testing.allocator);
    try std.testing.expect(entry.session_id == null);
}

test "sqlite loadMessages empty session" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    const msgs = try mem.loadMessages(std.testing.allocator, "nonexistent");
    defer std.testing.allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "sqlite loadMessages preserves order" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    try mem.saveMessage("s1", "user", "first");
    try mem.saveMessage("s1", "assistant", "second");
    try mem.saveMessage("s1", "user", "third");

    const msgs = try mem.loadMessages(std.testing.allocator, "s1");
    defer root.freeMessages(std.testing.allocator, msgs);

    try std.testing.expectEqual(@as(usize, 3), msgs.len);
    try std.testing.expectEqualStrings("first", msgs[0].content);
    try std.testing.expectEqualStrings("second", msgs[1].content);
    try std.testing.expectEqualStrings("third", msgs[2].content);
}

test "sqlite clearMessages does not affect other sessions" {
    var mem = try SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem.deinit();

    try mem.saveMessage("s1", "user", "s1 msg");
    try mem.saveMessage("s2", "user", "s2 msg");

    try mem.clearMessages("s1");

    const s1_msgs = try mem.loadMessages(std.testing.allocator, "s1");
    defer std.testing.allocator.free(s1_msgs);
    try std.testing.expectEqual(@as(usize, 0), s1_msgs.len);

    const s2_msgs = try mem.loadMessages(std.testing.allocator, "s2");
    defer root.freeMessages(std.testing.allocator, s2_msgs);
    try std.testing.expectEqual(@as(usize, 1), s2_msgs.len);
}
