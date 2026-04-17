//! PostgreSQL-backed persistent memory via libpq.
//!
//! Compile-time gated behind `build_options.enable_postgres`.
//! When disabled, this file provides only pure-logic helpers and their tests.

const std = @import("std");
const std_compat = @import("compat");
const build_options = @import("build_options");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const SessionStore = root.SessionStore;

const c = if (build_options.enable_postgres) @cImport({
    @cInclude("libpq-fe.h");
}) else struct {};

// ── SQL injection protection ──────────────────────────────────────

pub const IdentifierError = error{
    EmptyIdentifier,
    IdentifierTooLong,
    InvalidCharacter,
};

/// Validate a SQL identifier (schema/table name).
/// Must be 1-63 chars, alphanumeric or underscore only.
pub fn validateIdentifier(name: []const u8) IdentifierError!void {
    if (name.len == 0) return error.EmptyIdentifier;
    if (name.len > 63) return error.IdentifierTooLong;
    for (name) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '_') {
            return error.InvalidCharacter;
        }
    }
}

/// Quote a SQL identifier by wrapping in double-quotes.
/// The identifier must have been validated first.
pub fn quoteIdentifier(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\"{s}\"", .{name});
}

/// Build a query by substituting {schema} and {table} placeholders.
/// Uses pre-validated, pre-quoted identifiers.
/// Returns a null-terminated slice suitable for passing to libpq C functions.
pub fn buildQuery(allocator: std.mem.Allocator, template: []const u8, schema_q: []const u8, table_q: []const u8) ![:0]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var i: usize = 0;
    while (i < template.len) {
        if (i + 8 <= template.len and std.mem.eql(u8, template[i .. i + 8], "{schema}")) {
            try buf.appendSlice(allocator, schema_q);
            i += 8;
        } else if (i + 7 <= template.len and std.mem.eql(u8, template[i .. i + 7], "{table}")) {
            try buf.appendSlice(allocator, table_q);
            i += 7;
        } else {
            try buf.append(allocator, template[i]);
            i += 1;
        }
    }

    return buf.toOwnedSliceSentinel(allocator, 0);
}

fn getNowTimestamp(allocator: std.mem.Allocator) ![]u8 {
    const ts = std_compat.time.timestamp();
    return std.fmt.allocPrint(allocator, "{d}", .{ts});
}

fn generateId(allocator: std.mem.Allocator) ![]u8 {
    const ts = std_compat.time.nanoTimestamp();
    var buf: [16]u8 = undefined;
    std_compat.crypto.random.bytes(&buf);
    const rand_hi = std.mem.readInt(u64, buf[0..8], .little);
    const rand_lo = std.mem.readInt(u64, buf[8..16], .little);
    return std.fmt.allocPrint(allocator, "{d}-{x}-{x}", .{ ts, rand_hi, rand_lo });
}

// ── PostgresMemory (only available when enable_postgres is true) ──

pub const PostgresMemory = if (build_options.enable_postgres) PostgresMemoryImpl else struct {};

const PostgresMemoryImpl = struct {
    conn: *c.PGconn,
    allocator: std.mem.Allocator,
    owns_self: bool = false,
    schema_q: []const u8, // validated+quoted schema name
    table_q: []const u8, // validated+quoted table name
    instance_id: []const u8 = "",

    // Pre-built query templates
    q_store: []const u8,
    q_get: []const u8,
    q_list_cat: []const u8,
    q_list_all: []const u8,
    q_recall: []const u8,
    q_forget: []const u8,
    q_count: []const u8,
    q_save_msg: []const u8,
    q_load_msgs: []const u8,
    q_clear_msgs: []const u8,
    q_save_usage: []const u8,
    q_load_usage: []const u8,
    q_clear_usage: []const u8,
    q_count_sessions: []const u8,
    q_list_sessions: []const u8,
    q_count_detailed_msgs: []const u8,
    q_load_msgs_detailed: []const u8,
    q_clear_auto: []const u8,
    q_clear_auto_sid: []const u8,
    q_recall_sid: []const u8,
    q_list_cat_sid: []const u8,
    q_list_sid: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, url: [*:0]const u8, schema: []const u8, table: []const u8, instance_id: []const u8) !Self {
        try validateIdentifier(schema);
        try validateIdentifier(table);

        const schema_q = try quoteIdentifier(allocator, schema);
        errdefer allocator.free(schema_q);
        const table_q = try quoteIdentifier(allocator, table);
        errdefer allocator.free(table_q);

        const conn = c.PQconnectdb(url) orelse return error.ConnectionFailed;
        errdefer c.PQfinish(conn);

        if (c.PQstatus(conn) != c.CONNECTION_OK) {
            return error.ConnectionFailed;
        }

        var self_ = Self{
            .conn = conn,
            .allocator = allocator,
            .schema_q = schema_q,
            .table_q = table_q,
            .instance_id = instance_id,
            .q_store = undefined,
            .q_get = undefined,
            .q_list_cat = undefined,
            .q_list_all = undefined,
            .q_recall = undefined,
            .q_forget = undefined,
            .q_count = undefined,
            .q_save_msg = undefined,
            .q_load_msgs = undefined,
            .q_clear_msgs = undefined,
            .q_save_usage = undefined,
            .q_load_usage = undefined,
            .q_clear_usage = undefined,
            .q_count_sessions = undefined,
            .q_list_sessions = undefined,
            .q_count_detailed_msgs = undefined,
            .q_load_msgs_detailed = undefined,
            .q_clear_auto = undefined,
            .q_clear_auto_sid = undefined,
            .q_recall_sid = undefined,
            .q_list_cat_sid = undefined,
            .q_list_sid = undefined,
        };

        // Build query templates
        // instance_id filtering is always included; empty string matches the default column value.
        self_.q_store = try buildQuery(allocator, "INSERT INTO {schema}.{table} (id, key, content, category, session_id, instance_id, created_at, updated_at) " ++
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " ++
            "ON CONFLICT (key, instance_id) DO UPDATE SET content = EXCLUDED.content, category = EXCLUDED.category, " ++
            "session_id = EXCLUDED.session_id, updated_at = EXCLUDED.updated_at", schema_q, table_q);
        errdefer allocator.free(self_.q_store);

        self_.q_get = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE key = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_get);

        self_.q_list_cat = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE category = $1 AND instance_id = $2 ORDER BY updated_at DESC", schema_q, table_q);
        errdefer allocator.free(self_.q_list_cat);

        self_.q_list_all = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE instance_id = $1 ORDER BY updated_at DESC", schema_q, table_q);
        errdefer allocator.free(self_.q_list_all);

        self_.q_recall = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id, " ++
            "CASE WHEN key ILIKE $1 THEN 2.0 ELSE 0.0 END + " ++
            "CASE WHEN content ILIKE $1 THEN 1.0 ELSE 0.0 END AS score " ++
            "FROM {schema}.{table} WHERE (key ILIKE $1 OR content ILIKE $1) AND instance_id = $3 " ++
            "ORDER BY score DESC LIMIT $2", schema_q, table_q);
        errdefer allocator.free(self_.q_recall);

        self_.q_forget = try buildQuery(allocator, "DELETE FROM {schema}.{table} WHERE key = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_forget);

        self_.q_count = try buildQuery(allocator, "SELECT COUNT(*) FROM {schema}.{table} WHERE instance_id = $1", schema_q, table_q);
        errdefer allocator.free(self_.q_count);

        self_.q_save_msg = try buildQuery(allocator, "INSERT INTO {schema}.messages (session_id, instance_id, role, content) VALUES ($1, $2, $3, $4)", schema_q, table_q);
        errdefer allocator.free(self_.q_save_msg);

        self_.q_load_msgs = try buildQuery(allocator, "SELECT role, content FROM {schema}.messages WHERE session_id = $1 AND instance_id = $2 ORDER BY id ASC", schema_q, table_q);
        errdefer allocator.free(self_.q_load_msgs);

        self_.q_clear_msgs = try buildQuery(allocator, "DELETE FROM {schema}.messages WHERE session_id = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_clear_msgs);

        self_.q_save_usage = try buildQuery(allocator, "INSERT INTO {schema}.session_usage (session_id, instance_id, total_tokens, updated_at) VALUES ($1, $2, $3, NOW()) " ++
            "ON CONFLICT (session_id, instance_id) DO UPDATE SET total_tokens = EXCLUDED.total_tokens, updated_at = NOW()", schema_q, table_q);
        errdefer allocator.free(self_.q_save_usage);

        self_.q_load_usage = try buildQuery(allocator, "SELECT total_tokens FROM {schema}.session_usage WHERE session_id = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_load_usage);

        self_.q_clear_usage = try buildQuery(allocator, "DELETE FROM {schema}.session_usage WHERE session_id = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_clear_usage);

        self_.q_count_sessions = try buildQuery(
            allocator,
            "SELECT COUNT(*) FROM (SELECT 1 FROM {schema}.messages WHERE instance_id = $1 AND role <> '" ++ root.RUNTIME_COMMAND_ROLE ++ "' GROUP BY session_id) AS sessions",
            schema_q,
            table_q,
        );
        errdefer allocator.free(self_.q_count_sessions);

        self_.q_list_sessions = try buildQuery(
            allocator,
            "SELECT session_id, COUNT(*), MIN(created_at)::text, MAX(created_at)::text FROM {schema}.messages WHERE instance_id = $1 AND role <> '" ++ root.RUNTIME_COMMAND_ROLE ++ "' GROUP BY session_id ORDER BY MAX(created_at) DESC LIMIT $2 OFFSET $3",
            schema_q,
            table_q,
        );
        errdefer allocator.free(self_.q_list_sessions);

        self_.q_count_detailed_msgs = try buildQuery(
            allocator,
            "SELECT COUNT(*) FROM {schema}.messages WHERE session_id = $1 AND instance_id = $2 AND role <> '" ++ root.RUNTIME_COMMAND_ROLE ++ "'",
            schema_q,
            table_q,
        );
        errdefer allocator.free(self_.q_count_detailed_msgs);

        self_.q_load_msgs_detailed = try buildQuery(
            allocator,
            "SELECT role, content, created_at::text FROM {schema}.messages WHERE session_id = $1 AND instance_id = $2 AND role <> '" ++ root.RUNTIME_COMMAND_ROLE ++ "' ORDER BY id ASC LIMIT $3 OFFSET $4",
            schema_q,
            table_q,
        );
        errdefer allocator.free(self_.q_load_msgs_detailed);

        self_.q_clear_auto = try buildQuery(allocator, "DELETE FROM {schema}.{table} WHERE key LIKE 'autosave_%' AND instance_id = $1", schema_q, table_q);
        errdefer allocator.free(self_.q_clear_auto);

        self_.q_clear_auto_sid = try buildQuery(allocator, "DELETE FROM {schema}.{table} WHERE key LIKE 'autosave_%' AND session_id = $1 AND instance_id = $2", schema_q, table_q);
        errdefer allocator.free(self_.q_clear_auto_sid);

        self_.q_recall_sid = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id, " ++
            "CASE WHEN key ILIKE $1 THEN 2.0 ELSE 0.0 END + " ++
            "CASE WHEN content ILIKE $1 THEN 1.0 ELSE 0.0 END AS score " ++
            "FROM {schema}.{table} WHERE (key ILIKE $1 OR content ILIKE $1) AND session_id = $3 AND instance_id = $4 " ++
            "ORDER BY score DESC LIMIT $2", schema_q, table_q);
        errdefer allocator.free(self_.q_recall_sid);

        self_.q_list_cat_sid = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE category = $1 AND session_id = $2 AND instance_id = $3 ORDER BY updated_at DESC", schema_q, table_q);
        errdefer allocator.free(self_.q_list_cat_sid);

        self_.q_list_sid = try buildQuery(allocator, "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE session_id = $1 AND instance_id = $2 ORDER BY updated_at DESC", schema_q, table_q);
        errdefer allocator.free(self_.q_list_sid);

        // Run migrations
        try self_.migrate(schema, table);

        return self_;
    }

    pub fn deinit(self: *Self) void {
        c.PQfinish(self.conn);
        self.allocator.free(self.q_store);
        self.allocator.free(self.q_get);
        self.allocator.free(self.q_list_cat);
        self.allocator.free(self.q_list_all);
        self.allocator.free(self.q_recall);
        self.allocator.free(self.q_forget);
        self.allocator.free(self.q_count);
        self.allocator.free(self.q_save_msg);
        self.allocator.free(self.q_load_msgs);
        self.allocator.free(self.q_clear_msgs);
        self.allocator.free(self.q_save_usage);
        self.allocator.free(self.q_load_usage);
        self.allocator.free(self.q_clear_usage);
        self.allocator.free(self.q_count_sessions);
        self.allocator.free(self.q_list_sessions);
        self.allocator.free(self.q_count_detailed_msgs);
        self.allocator.free(self.q_load_msgs_detailed);
        self.allocator.free(self.q_clear_auto);
        self.allocator.free(self.q_clear_auto_sid);
        self.allocator.free(self.q_recall_sid);
        self.allocator.free(self.q_list_cat_sid);
        self.allocator.free(self.q_list_sid);
        self.allocator.free(self.schema_q);
        self.allocator.free(self.table_q);
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn migrate(self: *Self, raw_schema: []const u8, raw_table: []const u8) !void {
        // raw_schema/raw_table are pre-validated (alphanumeric + underscore only) so safe where used below.
        // Index names must NOT use quoted identifiers, so we use raw_table directly.
        const ddl = try std.fmt.allocPrintZ(self.allocator,
            \\CREATE TABLE IF NOT EXISTS {s}.{s} (
            \\    id TEXT PRIMARY KEY,
            \\    key TEXT NOT NULL,
            \\    content TEXT NOT NULL,
            \\    category TEXT NOT NULL DEFAULT 'core',
            \\    session_id TEXT,
            \\    instance_id TEXT NOT NULL DEFAULT '',
            \\    created_at TEXT NOT NULL,
            \\    updated_at TEXT NOT NULL
            \\);
            \\ALTER TABLE {s}.{s} ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';
            \\DROP INDEX IF EXISTS {s}.idx_{s}_key;
            \\CREATE UNIQUE INDEX IF NOT EXISTS idx_{s}_key_instance ON {s}.{s}(key, instance_id);
            \\CREATE INDEX IF NOT EXISTS idx_{s}_category ON {s}.{s}(category);
            \\CREATE INDEX IF NOT EXISTS idx_{s}_session ON {s}.{s}(session_id);
            \\CREATE INDEX IF NOT EXISTS idx_{s}_instance ON {s}.{s}(instance_id);
            \\CREATE TABLE IF NOT EXISTS {s}.messages (
            \\    id SERIAL PRIMARY KEY,
            \\    session_id TEXT NOT NULL,
            \\    instance_id TEXT NOT NULL DEFAULT '',
            \\    role TEXT NOT NULL,
            \\    content TEXT NOT NULL,
            \\    created_at TIMESTAMP DEFAULT NOW()
            \\);
            \\ALTER TABLE {s}.messages ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';
            \\CREATE INDEX IF NOT EXISTS idx_messages_instance_session ON {s}.messages(instance_id, session_id);
            \\CREATE TABLE IF NOT EXISTS {s}.session_usage (
            \\    session_id TEXT NOT NULL,
            \\    instance_id TEXT NOT NULL DEFAULT '',
            \\    total_tokens BIGINT NOT NULL DEFAULT 0,
            \\    updated_at TIMESTAMP DEFAULT NOW()
            \\);
            \\ALTER TABLE {s}.session_usage ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';
            \\DO $$
            \\DECLARE
            \\    old_pk_name text;
            \\BEGIN
            \\    SELECT conname INTO old_pk_name
            \\    FROM pg_constraint
            \\    WHERE conrelid = '{s}.session_usage'::regclass
            \\      AND contype = 'p'
            \\      AND array_length(conkey, 1) = 1
            \\    LIMIT 1;
            \\    IF old_pk_name IS NOT NULL THEN
            \\        EXECUTE format('ALTER TABLE %I.session_usage DROP CONSTRAINT %I', '{s}', old_pk_name);
            \\    END IF;
            \\END $$;
            \\CREATE UNIQUE INDEX IF NOT EXISTS idx_session_usage_session_instance ON {s}.session_usage(session_id, instance_id);
            \\CREATE INDEX IF NOT EXISTS idx_session_usage_instance ON {s}.session_usage(instance_id);
        , .{
            self.schema_q,
            self.table_q,
            self.schema_q,
            self.table_q,
            self.schema_q,
            raw_table,
            raw_table,
            self.schema_q,
            self.table_q,
            raw_table,
            self.schema_q,
            self.table_q,
            raw_table,
            self.schema_q,
            self.table_q,
            raw_table,
            self.schema_q,
            self.table_q,
            self.schema_q,
            self.schema_q,
            self.schema_q,
            self.schema_q,
            self.schema_q,
            self.schema_q,
            raw_schema,
            self.schema_q,
            self.schema_q,
        });
        defer self.allocator.free(ddl);

        const result = c.PQexec(self.conn, ddl.ptr);
        defer c.PQclear(result);

        const status = c.PQresultStatus(result);
        if (status != c.PGRES_COMMAND_OK and status != c.PGRES_TUPLES_OK) {
            return error.MigrationFailed;
        }
    }

    fn execParams(self: *Self, query: []const u8, params: []const ?[*:0]const u8, lengths: []const c_int) !*c.PGresult {
        const n: c_int = @intCast(params.len);
        const result = c.PQexecParams(
            self.conn,
            query.ptr,
            n,
            null, // paramTypes — let PG infer
            @ptrCast(params.ptr),
            lengths.ptr,
            null, // paramFormats — text
            0, // resultFormat — text
        ) orelse return error.ExecFailed;

        const status = c.PQresultStatus(result);
        if (status != c.PGRES_COMMAND_OK and status != c.PGRES_TUPLES_OK) {
            c.PQclear(result);
            return error.ExecFailed;
        }
        return result;
    }

    fn dupeResultValue(allocator: std.mem.Allocator, result: *c.PGresult, row: c_int, col: c_int) ![]u8 {
        if (c.PQgetisnull(result, row, col) != 0) {
            return allocator.dupe(u8, "");
        }
        const val = c.PQgetvalue(result, row, col);
        const len: usize = @intCast(c.PQgetlength(result, row, col));
        return allocator.dupe(u8, val[0..len]);
    }

    fn dupeResultValueOpt(allocator: std.mem.Allocator, result: *c.PGresult, row: c_int, col: c_int) !?[]u8 {
        if (c.PQgetisnull(result, row, col) != 0) {
            return null;
        }
        const val = c.PQgetvalue(result, row, col);
        const len: usize = @intCast(c.PQgetlength(result, row, col));
        return try allocator.dupe(u8, val[0..len]);
    }

    fn readEntryFromResult(allocator: std.mem.Allocator, result: *c.PGresult, row: c_int) !MemoryEntry {
        // Columns: id(0), key(1), content(2), category(3), updated_at(4), session_id(5)
        const id = try dupeResultValue(allocator, result, row, 0);
        errdefer allocator.free(id);
        const key = try dupeResultValue(allocator, result, row, 1);
        errdefer allocator.free(key);
        const content = try dupeResultValue(allocator, result, row, 2);
        errdefer allocator.free(content);
        const cat_str = try dupeResultValue(allocator, result, row, 3);
        const category = MemoryCategory.fromString(cat_str);
        // Free cat_str only if it wasn't captured by .custom
        switch (category) {
            .custom => {}, // cat_str is now owned by category.custom
            else => allocator.free(cat_str),
        }
        errdefer switch (category) {
            .custom => |name| allocator.free(name),
            else => {},
        };
        const timestamp = try dupeResultValue(allocator, result, row, 4);
        errdefer allocator.free(timestamp);
        const session_id = try dupeResultValueOpt(allocator, result, row, 5);

        return .{
            .id = id,
            .key = key,
            .content = content,
            .category = category,
            .timestamp = timestamp,
            .session_id = session_id,
        };
    }

    // ── Memory vtable implementation ──────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "postgres";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const now = getNowTimestamp(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(now);
        const now_z = try self_.allocator.dupeZ(u8, now);
        defer self_.allocator.free(now_z);

        const id = generateId(self_.allocator) catch return error.StepFailed;
        defer self_.allocator.free(id);
        const id_z = try self_.allocator.dupeZ(u8, id);
        defer self_.allocator.free(id_z);

        const cat_str = category.toString();
        const key_z = try self_.allocator.dupeZ(u8, key);
        defer self_.allocator.free(key_z);
        const content_z = try self_.allocator.dupeZ(u8, content);
        defer self_.allocator.free(content_z);
        const cat_z = try self_.allocator.dupeZ(u8, cat_str);
        defer self_.allocator.free(cat_z);

        const sid_z: ?[*:0]u8 = if (session_id) |sid| try self_.allocator.dupeZ(u8, sid) else null;
        defer if (sid_z) |s| self_.allocator.free(std.mem.span(s));

        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const params = [_]?[*:0]const u8{
            id_z,
            key_z,
            content_z,
            cat_z,
            sid_z,
            iid_z,
            now_z,
            now_z,
        };
        const lengths = [_]c_int{
            @intCast(id.len),
            @intCast(key.len),
            @intCast(content.len),
            @intCast(cat_str.len),
            if (session_id) |sid| @as(c_int, @intCast(sid.len)) else 0,
            @intCast(self_.instance_id.len),
            @intCast(now.len),
            @intCast(now.len),
        };

        const result = try self_.execParams(self_.q_store, &params, &lengths);
        c.PQclear(result);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const trimmed = std.mem.trim(u8, query, " \t\n\r");
        if (trimmed.len == 0) return allocator.alloc(MemoryEntry, 0);

        // Build ILIKE pattern: %query%
        const pattern = try std.fmt.allocPrintZ(allocator, "%{s}%", .{trimmed});
        defer allocator.free(pattern);

        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrintZ(&limit_buf, "{d}", .{limit});

        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);

        var result: *c.PGresult = undefined;
        if (session_id) |sid| {
            const sid_z = try allocator.dupeZ(u8, sid);
            defer allocator.free(sid_z);
            const params = [_]?[*:0]const u8{ pattern.ptr, limit_str.ptr, sid_z, iid_z };
            const lengths = [_]c_int{ @intCast(pattern.len - 1), @intCast(std.mem.len(limit_str)), @intCast(sid.len), @intCast(self_.instance_id.len) };
            result = try self_.execParams(self_.q_recall_sid, &params, &lengths);
        } else {
            const params = [_]?[*:0]const u8{ pattern.ptr, limit_str.ptr, iid_z };
            const lengths = [_]c_int{ @intCast(pattern.len - 1), @intCast(std.mem.len(limit_str)), @intCast(self_.instance_id.len) };
            result = try self_.execParams(self_.q_recall, &params, &lengths);
        }
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            var entry = try readEntryFromResult(allocator, result, row);
            // Read score from column 6
            if (c.PQgetisnull(result, row, 6) == 0) {
                const score_str = c.PQgetvalue(result, row, 6);
                const score_slice: []const u8 = score_str[0..@intCast(c.PQgetlength(result, row, 6))];
                entry.score = std.fmt.parseFloat(f64, score_slice) catch null;
            }
            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const key_z = try allocator.dupeZ(u8, key);
        defer allocator.free(key_z);
        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ key_z, iid_z };
        const lengths = [_]c_int{ @intCast(key.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_get, &params, &lengths);
        defer c.PQclear(result);

        if (c.PQntuples(result) == 0) return null;
        return try readEntryFromResult(allocator, result, 0);
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);

        var result: *c.PGresult = undefined;
        if (category) |cat| {
            const cat_str = cat.toString();
            const cat_z = try allocator.dupeZ(u8, cat_str);
            defer allocator.free(cat_z);
            if (session_id) |sid| {
                const sid_z = try allocator.dupeZ(u8, sid);
                defer allocator.free(sid_z);
                const params = [_]?[*:0]const u8{ cat_z, sid_z, iid_z };
                const lengths = [_]c_int{ @intCast(cat_str.len), @intCast(sid.len), @intCast(self_.instance_id.len) };
                result = try self_.execParams(self_.q_list_cat_sid, &params, &lengths);
            } else {
                const params = [_]?[*:0]const u8{ cat_z, iid_z };
                const lengths = [_]c_int{ @intCast(cat_str.len), @intCast(self_.instance_id.len) };
                result = try self_.execParams(self_.q_list_cat, &params, &lengths);
            }
        } else if (session_id) |sid| {
            const sid_z = try allocator.dupeZ(u8, sid);
            defer allocator.free(sid_z);
            const params = [_]?[*:0]const u8{ sid_z, iid_z };
            const lengths = [_]c_int{ @intCast(sid.len), @intCast(self_.instance_id.len) };
            result = try self_.execParams(self_.q_list_sid, &params, &lengths);
        } else {
            const params = [_]?[*:0]const u8{iid_z};
            const lengths = [_]c_int{@intCast(self_.instance_id.len)};
            result = try self_.execParams(self_.q_list_all, &params, &lengths);
        }
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            const entry = try readEntryFromResult(allocator, result, row);
            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8, limit: usize, offset: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const template = if (category != null and session_id != null)
            "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE category = $1 AND session_id = $2 AND instance_id = $3 ORDER BY updated_at DESC, id DESC LIMIT $4 OFFSET $5"
        else if (category != null)
            "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE category = $1 AND instance_id = $2 ORDER BY updated_at DESC, id DESC LIMIT $3 OFFSET $4"
        else if (session_id != null)
            "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE session_id = $1 AND instance_id = $2 ORDER BY updated_at DESC, id DESC LIMIT $3 OFFSET $4"
        else
            "SELECT id, key, content, category, updated_at, session_id FROM {schema}.{table} WHERE instance_id = $1 ORDER BY updated_at DESC, id DESC LIMIT $2 OFFSET $3";

        const query = try buildQuery(allocator, template, self_.schema_q, self_.table_q);
        defer allocator.free(query);

        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);

        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrintZ(&limit_buf, "{d}", .{limit});
        var offset_buf: [20]u8 = undefined;
        const offset_str = try std.fmt.bufPrintZ(&offset_buf, "{d}", .{offset});

        var result: *c.PGresult = undefined;
        if (category) |cat| {
            const cat_str = cat.toString();
            const cat_z = try allocator.dupeZ(u8, cat_str);
            defer allocator.free(cat_z);
            if (session_id) |sid| {
                const sid_z = try allocator.dupeZ(u8, sid);
                defer allocator.free(sid_z);
                const params = [_]?[*:0]const u8{ cat_z, sid_z, iid_z, limit_str.ptr, offset_str.ptr };
                const lengths = [_]c_int{
                    @intCast(cat_str.len),
                    @intCast(sid.len),
                    @intCast(self_.instance_id.len),
                    @intCast(std.mem.len(limit_str)),
                    @intCast(std.mem.len(offset_str)),
                };
                result = try self_.execParams(query, &params, &lengths);
            } else {
                const params = [_]?[*:0]const u8{ cat_z, iid_z, limit_str.ptr, offset_str.ptr };
                const lengths = [_]c_int{
                    @intCast(cat_str.len),
                    @intCast(self_.instance_id.len),
                    @intCast(std.mem.len(limit_str)),
                    @intCast(std.mem.len(offset_str)),
                };
                result = try self_.execParams(query, &params, &lengths);
            }
        } else if (session_id) |sid| {
            const sid_z = try allocator.dupeZ(u8, sid);
            defer allocator.free(sid_z);
            const params = [_]?[*:0]const u8{ sid_z, iid_z, limit_str.ptr, offset_str.ptr };
            const lengths = [_]c_int{
                @intCast(sid.len),
                @intCast(self_.instance_id.len),
                @intCast(std.mem.len(limit_str)),
                @intCast(std.mem.len(offset_str)),
            };
            result = try self_.execParams(query, &params, &lengths);
        } else {
            const params = [_]?[*:0]const u8{ iid_z, limit_str.ptr, offset_str.ptr };
            const lengths = [_]c_int{
                @intCast(self_.instance_id.len),
                @intCast(std.mem.len(limit_str)),
                @intCast(std.mem.len(offset_str)),
            };
            result = try self_.execParams(query, &params, &lengths);
        }
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            const entry = try readEntryFromResult(allocator, result, row);
            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const key_z = try self_.allocator.dupeZ(u8, key);
        defer self_.allocator.free(key_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ key_z, iid_z };
        const lengths = [_]c_int{ @intCast(key.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_forget, &params, &lengths);
        defer c.PQclear(result);

        const affected = c.PQcmdTuples(result);
        if (affected == null) return false;
        const affected_str: []const u8 = std.mem.span(affected);
        return !std.mem.eql(u8, affected_str, "0");
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);
        const params = [_]?[*:0]const u8{iid_z};
        const lengths = [_]c_int{@intCast(self_.instance_id.len)};

        const result = try self_.execParams(self_.q_count, &params, &lengths);
        defer c.PQclear(result);

        if (c.PQntuples(result) == 0) return 0;
        const val = c.PQgetvalue(result, 0, 0);
        const len: usize = @intCast(c.PQgetlength(result, 0, 0));
        const count_str: []const u8 = val[0..len];
        return std.fmt.parseInt(usize, count_str, 10) catch 0;
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const result = c.PQexec(self_.conn, "SELECT 1");
        if (result) |r| {
            defer c.PQclear(r);
            return c.PQresultStatus(r) == c.PGRES_TUPLES_OK;
        }
        return false;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        self_.deinit();
    }

    pub const mem_vtable = Memory.VTable{
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
        return .{ .ptr = @ptrCast(self), .vtable = &mem_vtable };
    }

    // ── SessionStore vtable implementation ────────────────────────

    fn implSessionSaveMessage(ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try self_.allocator.dupeZ(u8, session_id);
        defer self_.allocator.free(sid_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);
        const role_z = try self_.allocator.dupeZ(u8, role);
        defer self_.allocator.free(role_z);
        const content_z = try self_.allocator.dupeZ(u8, content);
        defer self_.allocator.free(content_z);

        const params = [_]?[*:0]const u8{ sid_z, iid_z, role_z, content_z };
        const lengths = [_]c_int{
            @intCast(session_id.len),
            @intCast(self_.instance_id.len),
            @intCast(role.len),
            @intCast(content.len),
        };

        const result = try self_.execParams(self_.q_save_msg, &params, &lengths);
        c.PQclear(result);
    }

    fn implSessionLoadMessages(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8) anyerror![]root.MessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try allocator.dupeZ(u8, session_id);
        defer allocator.free(sid_z);
        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ sid_z, iid_z };
        const lengths = [_]c_int{ @intCast(session_id.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_load_msgs, &params, &lengths);
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var messages = try allocator.alloc(root.MessageEntry, @intCast(nrows));
        var filled: usize = 0;
        errdefer {
            for (messages[0..filled]) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
            }
            allocator.free(messages);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            const idx: usize = @intCast(row);
            messages[idx] = .{
                .role = try dupeResultValue(allocator, result, row, 0),
                .content = try dupeResultValue(allocator, result, row, 1),
            };
            filled += 1;
        }

        return messages;
    }

    fn implSessionClearMessages(ptr: *anyopaque, session_id: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try self_.allocator.dupeZ(u8, session_id);
        defer self_.allocator.free(sid_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ sid_z, iid_z };
        const lengths = [_]c_int{ @intCast(session_id.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_clear_msgs, &params, &lengths);
        c.PQclear(result);

        const usage_result = try self_.execParams(self_.q_clear_usage, &params, &lengths);
        c.PQclear(usage_result);
    }

    fn implSessionClearAutoSaved(ptr: *anyopaque, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        if (session_id) |sid| {
            const sid_z = try self_.allocator.dupeZ(u8, sid);
            defer self_.allocator.free(sid_z);
            const params = [_]?[*:0]const u8{ sid_z, iid_z };
            const lengths = [_]c_int{ @intCast(sid.len), @intCast(self_.instance_id.len) };
            const result = try self_.execParams(self_.q_clear_auto_sid, &params, &lengths);
            c.PQclear(result);
        } else {
            const params = [_]?[*:0]const u8{iid_z};
            const lengths = [_]c_int{@intCast(self_.instance_id.len)};
            const result = try self_.execParams(self_.q_clear_auto, &params, &lengths);
            c.PQclear(result);
        }
    }

    fn implSessionSaveUsage(ptr: *anyopaque, session_id: []const u8, total_tokens: u64) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try self_.allocator.dupeZ(u8, session_id);
        defer self_.allocator.free(sid_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const total_z = try std.fmt.allocPrintZ(self_.allocator, "{d}", .{total_tokens});
        defer self_.allocator.free(total_z);
        const params = [_]?[*:0]const u8{ sid_z, iid_z, total_z };
        const lengths = [_]c_int{ @intCast(session_id.len), @intCast(self_.instance_id.len), @intCast(total_z.len) };

        const result = try self_.execParams(self_.q_save_usage, &params, &lengths);
        c.PQclear(result);
    }

    fn implSessionLoadUsage(ptr: *anyopaque, session_id: []const u8) anyerror!?u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try self_.allocator.dupeZ(u8, session_id);
        defer self_.allocator.free(sid_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ sid_z, iid_z };
        const lengths = [_]c_int{ @intCast(session_id.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_load_usage, &params, &lengths);
        defer c.PQclear(result);

        if (c.PQntuples(result) == 0) return null;
        const raw = c.PQgetvalue(result, 0, 0);
        const len: usize = @intCast(c.PQgetlength(result, 0, 0));
        return try std.fmt.parseInt(u64, raw[0..len], 10);
    }

    fn implSessionCountSessions(ptr: *anyopaque) anyerror!u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);
        const params = [_]?[*:0]const u8{iid_z};
        const lengths = [_]c_int{@intCast(self_.instance_id.len)};

        const result = try self_.execParams(self_.q_count_sessions, &params, &lengths);
        defer c.PQclear(result);

        if (c.PQntuples(result) == 0) return 0;
        const raw = c.PQgetvalue(result, 0, 0);
        const len: usize = @intCast(c.PQgetlength(result, 0, 0));
        return std.fmt.parseInt(u64, raw[0..len], 10) catch 0;
    }

    fn implSessionListSessions(ptr: *anyopaque, allocator: std.mem.Allocator, limit: usize, offset: usize) anyerror![]root.SessionInfo {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);
        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrintZ(&limit_buf, "{d}", .{limit});
        var offset_buf: [20]u8 = undefined;
        const offset_str = try std.fmt.bufPrintZ(&offset_buf, "{d}", .{offset});

        const params = [_]?[*:0]const u8{ iid_z, limit_str.ptr, offset_str.ptr };
        const lengths = [_]c_int{ @intCast(self_.instance_id.len), @intCast(std.mem.len(limit_str)), @intCast(std.mem.len(offset_str)) };

        const result = try self_.execParams(self_.q_list_sessions, &params, &lengths);
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var sessions = try allocator.alloc(root.SessionInfo, @intCast(nrows));
        var filled: usize = 0;
        errdefer {
            for (sessions[0..filled]) |info| info.deinit(allocator);
            allocator.free(sessions);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            if (c.PQgetisnull(result, row, 0) != 0) continue;

            const raw_count = c.PQgetvalue(result, row, 1);
            const raw_count_len: usize = @intCast(c.PQgetlength(result, row, 1));

            sessions[filled] = .{
                .session_id = try dupeResultValue(allocator, result, row, 0),
                .message_count = std.fmt.parseInt(u64, raw_count[0..raw_count_len], 10) catch 0,
                .first_message_at = try dupeResultValue(allocator, result, row, 2),
                .last_message_at = try dupeResultValue(allocator, result, row, 3),
            };
            filled += 1;
        }

        if (filled < sessions.len) {
            return allocator.realloc(sessions, filled);
        }
        return sessions;
    }

    fn implSessionCountDetailedMessages(ptr: *anyopaque, session_id: []const u8) anyerror!u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try self_.allocator.dupeZ(u8, session_id);
        defer self_.allocator.free(sid_z);
        const iid_z = try self_.allocator.dupeZ(u8, self_.instance_id);
        defer self_.allocator.free(iid_z);

        const params = [_]?[*:0]const u8{ sid_z, iid_z };
        const lengths = [_]c_int{ @intCast(session_id.len), @intCast(self_.instance_id.len) };

        const result = try self_.execParams(self_.q_count_detailed_msgs, &params, &lengths);
        defer c.PQclear(result);

        if (c.PQntuples(result) == 0) return 0;
        const raw = c.PQgetvalue(result, 0, 0);
        const len: usize = @intCast(c.PQgetlength(result, 0, 0));
        return std.fmt.parseInt(u64, raw[0..len], 10) catch 0;
    }

    fn implSessionLoadMessagesDetailed(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8, limit: usize, offset: usize) anyerror![]root.DetailedMessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const sid_z = try allocator.dupeZ(u8, session_id);
        defer allocator.free(sid_z);
        const iid_z = try allocator.dupeZ(u8, self_.instance_id);
        defer allocator.free(iid_z);
        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrintZ(&limit_buf, "{d}", .{limit});
        var offset_buf: [20]u8 = undefined;
        const offset_str = try std.fmt.bufPrintZ(&offset_buf, "{d}", .{offset});

        const params = [_]?[*:0]const u8{ sid_z, iid_z, limit_str.ptr, offset_str.ptr };
        const lengths = [_]c_int{
            @intCast(session_id.len),
            @intCast(self_.instance_id.len),
            @intCast(std.mem.len(limit_str)),
            @intCast(std.mem.len(offset_str)),
        };

        const result = try self_.execParams(self_.q_load_msgs_detailed, &params, &lengths);
        defer c.PQclear(result);

        const nrows = c.PQntuples(result);
        var messages = try allocator.alloc(root.DetailedMessageEntry, @intCast(nrows));
        var filled: usize = 0;
        errdefer {
            for (messages[0..filled]) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
                allocator.free(entry.created_at);
            }
            allocator.free(messages);
        }

        var row: c_int = 0;
        while (row < nrows) : (row += 1) {
            messages[filled] = .{
                .role = try dupeResultValue(allocator, result, row, 0),
                .content = try dupeResultValue(allocator, result, row, 1),
                .created_at = try dupeResultValue(allocator, result, row, 2),
            };
            filled += 1;
        }

        if (filled < messages.len) {
            return allocator.realloc(messages, filled);
        }
        return messages;
    }

    const session_vtable = SessionStore.VTable{
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

    pub fn sessionStore(self: *Self) SessionStore {
        return .{ .ptr = @ptrCast(self), .vtable = &session_vtable };
    }
};

// ── Tests ──────────────────────────────────────────────────────────

// Pure logic tests (no PG server needed)

test "validateIdentifier accepts valid names" {
    try validateIdentifier("public");
    try validateIdentifier("my_schema");
    try validateIdentifier("table123");
    try validateIdentifier("a");
    try validateIdentifier("A_B_C");
}

test "validateIdentifier rejects empty" {
    try std.testing.expectError(error.EmptyIdentifier, validateIdentifier(""));
}

test "validateIdentifier rejects too long" {
    const long = "a" ** 64;
    try std.testing.expectError(error.IdentifierTooLong, validateIdentifier(long));
}

test "validateIdentifier rejects special chars" {
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my-schema"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my.schema"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my schema"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("table;drop"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("tab\"le"));
}

test "validateIdentifier accepts max length 63" {
    const ok = "a" ** 63;
    try validateIdentifier(ok);
}

test "quoteIdentifier wraps correctly" {
    const result = try quoteIdentifier(std.testing.allocator, "public");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\"public\"", result);
}

test "quoteIdentifier with underscore" {
    const result = try quoteIdentifier(std.testing.allocator, "my_table");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\"my_table\"", result);
}

test "buildQuery replaces schema and table" {
    const result = try buildQuery(
        std.testing.allocator,
        "SELECT * FROM {schema}.{table} WHERE {table}.id = 1",
        "\"public\"",
        "\"memories\"",
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "SELECT * FROM \"public\".\"memories\" WHERE \"memories\".id = 1",
        result,
    );
}

test "buildQuery no placeholders" {
    const result = try buildQuery(std.testing.allocator, "SELECT 1", "\"s\"", "\"t\"");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("SELECT 1", result);
}

test "getNowTimestamp returns numeric string" {
    const ts = try getNowTimestamp(std.testing.allocator);
    defer std.testing.allocator.free(ts);
    try std.testing.expect(ts.len > 0);
    for (ts) |ch| {
        try std.testing.expect(ch == '-' or std.ascii.isDigit(ch));
    }
}

test "generateId produces unique values" {
    const id1 = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(id1);
    const id2 = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(id2);
    try std.testing.expect(!std.mem.eql(u8, id1, id2));
}

test "generateId format has dashes" {
    const id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(id);
    try std.testing.expect(std.mem.indexOf(u8, id, "-") != null);
}

test "buildQuery returns null-terminated string" {
    const result = try buildQuery(std.testing.allocator, "SELECT * FROM {schema}.{table}", "\"public\"", "\"memories\"");
    defer std.testing.allocator.free(result);
    // Verify null sentinel at position result.len
    try std.testing.expectEqual(@as(u8, 0), result[result.len]);
    try std.testing.expectEqualStrings("SELECT * FROM \"public\".\"memories\"", result);
}
