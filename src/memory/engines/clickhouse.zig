//! ClickHouse-backed persistent memory via HTTP API (port 8123).
//!
//! No C dependency — pure Zig HTTP via std.http.Client.
//! Writes are append-only with server-generated Snowflake ordering keys, and
//! reads collapse to the latest row per logical key via argMax. This keeps
//! ordering independent from client clock skew while ReplacingMergeTree(version)
//! provides eventual on-disk compaction. User data is parameterized via
//! ClickHouse query parameters ({name:Type} syntax).

const std = @import("std");
const build_options = @import("build_options");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const SessionStore = root.SessionStore;
const MessageEntry = root.MessageEntry;
const log = std.log.scoped(.clickhouse_memory);

// ── SQL injection protection ──────────────────────────────────────

pub const IdentifierError = error{
    EmptyIdentifier,
    IdentifierTooLong,
    InvalidCharacter,
};

/// Validate a SQL identifier (database/table name).
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

/// Quote a SQL identifier by wrapping in backticks (ClickHouse syntax).
pub fn quoteIdentifier(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "`{s}`", .{name});
}

/// Escape a string for safe inclusion in ClickHouse string literals.
/// Escapes ', \, \n, \r, \t, and \0.
pub fn escapeClickHouseString(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    for (input) |ch| {
        switch (ch) {
            '\'' => try buf.appendSlice(allocator, "\\'"),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            0 => try buf.appendSlice(allocator, "\\0"),
            else => try buf.append(allocator, ch),
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Build the ClickHouse HTTP API base URL from host, port, and TLS setting.
pub fn buildUrl(allocator: std.mem.Allocator, host: []const u8, port: u16, use_https: bool) ![]u8 {
    const scheme = if (use_https) "https" else "http";
    const needs_brackets = std.mem.indexOfScalar(u8, host, ':') != null and
        !(host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']');
    const host_part = if (needs_brackets)
        try std.fmt.allocPrint(allocator, "[{s}]", .{host})
    else
        try allocator.dupe(u8, host);
    defer allocator.free(host_part);
    return std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ scheme, host_part, port });
}

/// Build a Basic auth header value ("Basic base64(user:password)").
/// Returns null if both user and password are empty.
pub fn buildAuthHeader(allocator: std.mem.Allocator, user: []const u8, password: []const u8) !?[]u8 {
    if (user.len == 0 and password.len == 0) return null;

    const credentials = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ user, password });
    defer allocator.free(credentials);

    const Encoder = std.base64.standard.Encoder;
    const encoded_len = Encoder.calcSize(credentials.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = Encoder.encode(encoded, credentials);

    const header = try std.fmt.allocPrint(allocator, "Basic {s}", .{encoded});
    return header;
}

/// Percent-encode a string for use in URL query parameters.
/// Safe characters (unreserved per RFC 3986) are not encoded.
pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    for (input) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try buf.append(allocator, ch);
        } else {
            const hex = "0123456789ABCDEF";
            try buf.append(allocator, '%');
            try buf.append(allocator, hex[ch >> 4]);
            try buf.append(allocator, hex[ch & 0x0f]);
        }
    }

    return buf.toOwnedSlice(allocator);
}

// ── Timestamp / ID helpers ────────────────────────────────────────

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

// ── TSV parsing helpers ───────────────────────────────────────────

/// Unescape a ClickHouse TabSeparated field value.
/// Handles \n, \r, \t, \\, \0, \'.
pub fn unescapeClickHouseValue(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (i + 1 < input.len and input[i] == '\\') {
            switch (input[i + 1]) {
                'n' => try buf.append(allocator, '\n'),
                'r' => try buf.append(allocator, '\r'),
                't' => try buf.append(allocator, '\t'),
                '\\' => try buf.append(allocator, '\\'),
                '0' => try buf.append(allocator, 0),
                '\'' => try buf.append(allocator, '\''),
                else => {
                    try buf.append(allocator, input[i]);
                    try buf.append(allocator, input[i + 1]);
                },
            }
            i += 2;
        } else {
            try buf.append(allocator, input[i]);
            i += 1;
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Parse ClickHouse TabSeparated output into rows of columns.
/// Each row is a slice of column values (unescaped).
pub fn parseTsvRows(allocator: std.mem.Allocator, body: []const u8) ![]const []const []const u8 {
    if (body.len == 0) return allocator.alloc([]const []const u8, 0);

    var rows: std.ArrayList([]const []const u8) = .empty;
    errdefer {
        for (rows.items) |row| {
            for (row) |col| allocator.free(@constCast(col));
            allocator.free(row);
        }
        rows.deinit(allocator);
    }

    var line_iter = std.mem.splitScalar(u8, body, '\n');
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;

        var cols: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (cols.items) |col| allocator.free(@constCast(col));
            cols.deinit(allocator);
        }

        var col_iter = std.mem.splitScalar(u8, line, '\t');
        while (col_iter.next()) |raw_col| {
            const unescaped = try unescapeClickHouseValue(allocator, raw_col);
            try cols.append(allocator, unescaped);
        }

        const row = try cols.toOwnedSlice(allocator);
        try rows.append(allocator, row);
    }

    return rows.toOwnedSlice(allocator);
}

/// Free rows returned by parseTsvRows.
pub fn freeTsvRows(allocator: std.mem.Allocator, rows: []const []const []const u8) void {
    for (rows) |row| {
        for (row) |col| allocator.free(@constCast(col));
        allocator.free(row);
    }
    allocator.free(rows);
}

/// Build a MemoryEntry from a TSV row.
/// Expected columns: [id, key, content, category, timestamp, session_id]
fn buildEntry(allocator: std.mem.Allocator, row: []const []const u8) !MemoryEntry {
    if (row.len < 6) return error.InvalidRow;

    const id = try allocator.dupe(u8, row[0]);
    errdefer allocator.free(id);
    const key = try allocator.dupe(u8, row[1]);
    errdefer allocator.free(key);
    const content = try allocator.dupe(u8, row[2]);
    errdefer allocator.free(content);
    const timestamp = try allocator.dupe(u8, row[4]);
    errdefer allocator.free(timestamp);

    const cat_str = row[3];
    const category = MemoryCategory.fromString(cat_str);
    const final_category: MemoryCategory = switch (category) {
        .custom => .{ .custom = try allocator.dupe(u8, cat_str) },
        else => category,
    };
    errdefer switch (final_category) {
        .custom => |name| allocator.free(name),
        else => {},
    };

    const sid_raw = row[5];
    const session_id: ?[]const u8 = if (sid_raw.len > 0) try allocator.dupe(u8, sid_raw) else null;

    return .{
        .id = id,
        .key = key,
        .content = content,
        .category = final_category,
        .timestamp = timestamp,
        .session_id = session_id,
    };
}

fn isLoopbackHost(host: []const u8) bool {
    const normalized = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
        host[1 .. host.len - 1]
    else
        host;

    if (std.ascii.eqlIgnoreCase(normalized, "localhost")) return true;

    if (std.net.Address.parseIp4(normalized, 0)) |ip4| {
        const octets: *const [4]u8 = @ptrCast(&ip4.in.sa.addr);
        return octets[0] == 127;
    } else |_| {}

    if (std.net.Address.parseIp6(normalized, 0)) |ip6| {
        const bytes = ip6.in6.sa.addr;
        return std.mem.eql(u8, bytes[0..15], &[_]u8{0} ** 15) and bytes[15] == 1;
    } else |_| {}

    return false;
}

fn validateTransportSecurity(host: []const u8, use_https: bool) !void {
    if (use_https or isLoopbackHost(host)) return;
    return error.InsecureTransportNotAllowed;
}

// ── ClickHouseMemory ──────────────────────────────────────────────

pub const ClickHouseMemory = if (build_options.enable_memory_clickhouse) ClickHouseMemoryImpl else struct {};

const ClickHouseMemoryImpl = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    database: []const u8,
    table: []const u8,
    db_q: []const u8,
    table_q: []const u8,
    messages_table_q: []const u8,
    usage_table_q: []const u8,
    instance_id: []const u8,
    auth_header: ?[]const u8,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: struct {
        host: []const u8 = "127.0.0.1",
        port: u16 = 8123,
        database: []const u8 = "default",
        table: []const u8 = "memories",
        user: []const u8 = "",
        password: []const u8 = "",
        use_https: bool = false,
        instance_id: []const u8 = "",
    }) !Self {
        try validateIdentifier(config.database);
        try validateIdentifier(config.table);
        try validateTransportSecurity(config.host, config.use_https);

        const base_url = try buildUrl(allocator, config.host, config.port, config.use_https);
        errdefer allocator.free(base_url);

        const db_q = try quoteIdentifier(allocator, config.database);
        errdefer allocator.free(db_q);
        const table_q = try quoteIdentifier(allocator, config.table);
        errdefer allocator.free(table_q);
        const messages_table_q = try buildQuotedSuffixTable(allocator, config.table, "_messages");
        errdefer allocator.free(messages_table_q);
        const usage_table_q = try buildQuotedSuffixTable(allocator, config.table, "_session_usage");
        errdefer allocator.free(usage_table_q);

        const auth_header = try buildAuthHeader(allocator, config.user, config.password);
        errdefer if (auth_header) |h| allocator.free(h);

        var self_ = Self{
            .allocator = allocator,
            .base_url = base_url,
            .database = config.database,
            .table = config.table,
            .db_q = db_q,
            .table_q = table_q,
            .messages_table_q = messages_table_q,
            .usage_table_q = usage_table_q,
            .instance_id = config.instance_id,
            .auth_header = auth_header,
        };

        try self_.ensureServerCapabilities();
        try self_.migrate();

        return self_;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.base_url);
        self.allocator.free(self.db_q);
        self.allocator.free(self.table_q);
        self.allocator.free(self.messages_table_q);
        self.allocator.free(self.usage_table_q);
        if (self.auth_header) |h| self.allocator.free(h);
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    // ── HTTP execution ────────────────────────────────────────────

    /// POST a query to ClickHouse HTTP API. Returns the response body.
    /// params is a slice of {name, value} pairs for query parameters.
    fn executeQuery(self: *Self, allocator: std.mem.Allocator, query: []const u8, params: []const [2][]const u8) ![]u8 {
        // Build URL with query parameters
        var url_buf: std.ArrayList(u8) = .empty;
        errdefer url_buf.deinit(allocator);

        try url_buf.appendSlice(allocator, self.base_url);
        try url_buf.appendSlice(allocator, "/?");

        for (params, 0..) |param, i| {
            if (i > 0) try url_buf.append(allocator, '&');
            const encoded_name = try urlEncode(allocator, param[0]);
            defer allocator.free(encoded_name);
            const encoded_value = try urlEncode(allocator, param[1]);
            defer allocator.free(encoded_value);
            try url_buf.appendSlice(allocator, "param_");
            try url_buf.appendSlice(allocator, encoded_name);
            try url_buf.append(allocator, '=');
            try url_buf.appendSlice(allocator, encoded_value);
        }

        const url = try url_buf.toOwnedSlice(allocator);
        defer allocator.free(url);

        var client: std.http.Client = .{ .allocator = allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        var extra_headers_buf: [2]std.http.Header = undefined;
        var header_count: usize = 0;

        extra_headers_buf[header_count] = .{ .name = "Content-Type", .value = "text/plain" };
        header_count += 1;

        if (self.auth_header) |auth| {
            extra_headers_buf[header_count] = .{ .name = "Authorization", .value = auth };
            header_count += 1;
        }

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = query,
            .extra_headers = extra_headers_buf[0..header_count],
            .response_writer = &aw.writer,
        }) catch return error.ClickHouseConnectionError;

        if (result.status != .ok) {
            const err_body = aw.writer.buffer[0..aw.writer.end];
            log.err("ClickHouse error (HTTP {d}): {s}", .{ @intFromEnum(result.status), err_body });
            return error.ClickHouseQueryError;
        }

        const body = try allocator.dupe(u8, aw.writer.buffer[0..aw.writer.end]);
        return body;
    }

    /// Execute a query that returns no meaningful body (DDL, INSERT).
    fn executeStatement(self: *Self, query: []const u8, params: []const [2][]const u8) !void {
        const body = try self.executeQuery(self.allocator, query, params);
        self.allocator.free(body);
    }

    /// Execute a mutation (ALTER TABLE DELETE) with mutations_sync=1.
    fn executeMutation(self: *Self, query: []const u8, params: []const [2][]const u8) !void {
        // Build URL with mutations_sync=1 plus query parameters
        var url_buf: std.ArrayList(u8) = .empty;
        errdefer url_buf.deinit(self.allocator);

        try url_buf.appendSlice(self.allocator, self.base_url);
        try url_buf.appendSlice(self.allocator, "/?mutations_sync=1");

        for (params) |param| {
            try url_buf.append(self.allocator, '&');
            const encoded_name = try urlEncode(self.allocator, param[0]);
            defer self.allocator.free(encoded_name);
            const encoded_value = try urlEncode(self.allocator, param[1]);
            defer self.allocator.free(encoded_value);
            try url_buf.appendSlice(self.allocator, "param_");
            try url_buf.appendSlice(self.allocator, encoded_name);
            try url_buf.append(self.allocator, '=');
            try url_buf.appendSlice(self.allocator, encoded_value);
        }

        const url = try url_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        var extra_headers_buf: [2]std.http.Header = undefined;
        var header_count: usize = 0;

        extra_headers_buf[header_count] = .{ .name = "Content-Type", .value = "text/plain" };
        header_count += 1;

        if (self.auth_header) |auth| {
            extra_headers_buf[header_count] = .{ .name = "Authorization", .value = auth };
            header_count += 1;
        }

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = query,
            .extra_headers = extra_headers_buf[0..header_count],
            .response_writer = &aw.writer,
        }) catch return error.ClickHouseConnectionError;

        if (result.status != .ok) {
            const err_body = aw.writer.buffer[0..aw.writer.end];
            log.err("ClickHouse mutation error (HTTP {d}): {s}", .{ @intFromEnum(result.status), err_body });
            return error.ClickHouseQueryError;
        }
    }

    // ── Schema migration ──────────────────────────────────────────

    fn ensureServerCapabilities(self: *Self) !void {
        const body = self.executeQuery(self.allocator, "SELECT generateSnowflakeID()", &.{}) catch |err| switch (err) {
            error.ClickHouseQueryError => {
                log.err("ClickHouse backend requires generateSnowflakeID() support (ClickHouse 24.6+)", .{});
                return error.ClickHouseUnsupportedVersion;
            },
            else => return err,
        };
        self.allocator.free(body);
    }

    fn migrate(self: *Self) !void {
        // 1. Main memories table (ReplacingMergeTree)
        const create_memories = try std.fmt.allocPrint(self.allocator,
            \\CREATE TABLE IF NOT EXISTS {s}.{s} (
            \\    id String,
            \\    key String,
            \\    content String,
            \\    category String DEFAULT '',
            \\    session_id String DEFAULT '',
            \\    instance_id String DEFAULT '',
            \\    created_at DateTime64(3) DEFAULT now64(3),
            \\    updated_at DateTime64(3) DEFAULT now64(3),
            \\    version UInt64 DEFAULT generateSnowflakeID()
            \\) ENGINE = ReplacingMergeTree(version)
            \\ORDER BY (instance_id, key)
        , .{ self.db_q, self.table_q });
        defer self.allocator.free(create_memories);
        try self.executeStatement(create_memories, &.{});

        const alter_memories_version = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\ADD COLUMN IF NOT EXISTS version UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.table_q });
        defer self.allocator.free(alter_memories_version);
        try self.executeStatement(alter_memories_version, &.{});

        const modify_memories_version = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\MODIFY COLUMN version UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.table_q });
        defer self.allocator.free(modify_memories_version);
        try self.executeStatement(modify_memories_version, &.{});

        // 2. Messages table (MergeTree)
        const create_messages = try std.fmt.allocPrint(self.allocator,
            \\CREATE TABLE IF NOT EXISTS {s}.{s} (
            \\    session_id String,
            \\    role String,
            \\    content String,
            \\    instance_id String DEFAULT '',
            \\    created_at DateTime64(3) DEFAULT now64(3),
            \\    message_order UInt64 DEFAULT generateSnowflakeID(),
            \\    message_id String DEFAULT ''
            \\) ENGINE = MergeTree()
            \\ORDER BY (instance_id, session_id, message_order, message_id)
        , .{ self.db_q, self.messages_table_q });
        defer self.allocator.free(create_messages);
        try self.executeStatement(create_messages, &.{});

        const alter_messages_order = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\ADD COLUMN IF NOT EXISTS message_order UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.messages_table_q });
        defer self.allocator.free(alter_messages_order);
        try self.executeStatement(alter_messages_order, &.{});

        const modify_messages_order = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\MODIFY COLUMN message_order UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.messages_table_q });
        defer self.allocator.free(modify_messages_order);
        try self.executeStatement(modify_messages_order, &.{});

        const alter_messages_id = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\ADD COLUMN IF NOT EXISTS message_id String DEFAULT ''
        , .{ self.db_q, self.messages_table_q });
        defer self.allocator.free(alter_messages_id);
        try self.executeStatement(alter_messages_id, &.{});

        // 3. Session usage table (ReplacingMergeTree)
        const create_usage = try std.fmt.allocPrint(self.allocator,
            \\CREATE TABLE IF NOT EXISTS {s}.{s} (
            \\    session_id String,
            \\    instance_id String DEFAULT '',
            \\    total_tokens UInt64 DEFAULT 0,
            \\    updated_at DateTime64(3) DEFAULT now64(3),
            \\    version UInt64 DEFAULT generateSnowflakeID()
            \\) ENGINE = ReplacingMergeTree(version)
            \\ORDER BY (instance_id, session_id)
        , .{ self.db_q, self.usage_table_q });
        defer self.allocator.free(create_usage);
        try self.executeStatement(create_usage, &.{});

        const alter_usage_version = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\ADD COLUMN IF NOT EXISTS version UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.usage_table_q });
        defer self.allocator.free(alter_usage_version);
        try self.executeStatement(alter_usage_version, &.{});

        const modify_usage_version = try std.fmt.allocPrint(self.allocator,
            \\ALTER TABLE {s}.{s}
            \\MODIFY COLUMN version UInt64 DEFAULT generateSnowflakeID()
        , .{ self.db_q, self.usage_table_q });
        defer self.allocator.free(modify_usage_version);
        try self.executeStatement(modify_usage_version, &.{});
    }

    // ── Memory vtable implementation ──────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "clickhouse";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const id = try generateId(self_.allocator);
        defer self_.allocator.free(id);
        const cat_str = category.toString();
        const sid = session_id orelse "";

        const query = try std.fmt.allocPrint(self_.allocator,
            \\INSERT INTO {s}.{s} (id, key, content, category, session_id, instance_id, created_at, updated_at)
            \\VALUES ({{id:String}}, {{key:String}}, {{content:String}}, {{cat:String}}, {{sid:String}}, {{iid:String}}, now64(3), now64(3))
        , .{ self_.db_q, self_.table_q });
        defer self_.allocator.free(query);

        try self_.executeStatement(query, &.{
            .{ "id", id },
            .{ "key", key },
            .{ "content", content },
            .{ "cat", cat_str },
            .{ "sid", sid },
            .{ "iid", self_.instance_id },
        });
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(allocator,
            \\SELECT id, key, content, category, toString(updated_at), session_id
            \\FROM (
            \\    SELECT
            \\        argMax(id, tuple(version, id)) AS id,
            \\        key,
            \\        argMax(content, tuple(version, id)) AS content,
            \\        argMax(category, tuple(version, id)) AS category,
            \\        argMax(updated_at, tuple(version, id)) AS updated_at,
            \\        argMax(session_id, tuple(version, id)) AS session_id
            \\    FROM {s}.{s}
            \\    WHERE key = {{key:String}} AND instance_id = {{iid:String}}
            \\    GROUP BY key
            \\)
            \\LIMIT 1
        , .{ self_.db_q, self_.table_q });
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, &.{
            .{ "key", key },
            .{ "iid", self_.instance_id },
        });
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        if (rows.len == 0) return null;
        return try buildEntry(allocator, rows[0]);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query_str: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const trimmed = std.mem.trim(u8, query_str, " \t\n\r");
        if (trimmed.len == 0) return allocator.alloc(MemoryEntry, 0);

        // Build ILIKE pattern: %query%
        const pattern = try std.fmt.allocPrint(allocator, "%{s}%", .{trimmed});
        defer allocator.free(pattern);

        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "{d}", .{limit});

        var query: []u8 = undefined;
        var params: []const [2][]const u8 = undefined;

        if (session_id) |sid| {
            query = try std.fmt.allocPrint(allocator,
                \\SELECT id, key, content, category, toString(updated_at), session_id,
                \\    CASE WHEN key ILIKE {{q:String}} THEN 2.0 ELSE 0.0 END +
                \\    CASE WHEN content ILIKE {{q:String}} THEN 1.0 ELSE 0.0 END AS score
                \\FROM (
                \\    SELECT
                \\        argMax(id, tuple(version, id)) AS id,
                \\        key,
                \\        argMax(content, tuple(version, id)) AS content,
                \\        argMax(category, tuple(version, id)) AS category,
                \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                \\        argMax(session_id, tuple(version, id)) AS session_id
                \\    FROM {s}.{s}
                \\    WHERE instance_id = {{iid:String}}
                \\    GROUP BY key
                \\)
                \\WHERE (key ILIKE {{q:String}} OR content ILIKE {{q:String}})
                \\  AND session_id = {{sid:String}}
                \\ORDER BY score DESC, updated_at DESC, id DESC
                \\LIMIT {{lim:UInt32}}
            , .{ self_.db_q, self_.table_q });

            params = &.{
                .{ "q", pattern },
                .{ "iid", self_.instance_id },
                .{ "sid", sid },
                .{ "lim", limit_str },
            };
        } else {
            query = try std.fmt.allocPrint(allocator,
                \\SELECT id, key, content, category, toString(updated_at), session_id,
                \\    CASE WHEN key ILIKE {{q:String}} THEN 2.0 ELSE 0.0 END +
                \\    CASE WHEN content ILIKE {{q:String}} THEN 1.0 ELSE 0.0 END AS score
                \\FROM (
                \\    SELECT
                \\        argMax(id, tuple(version, id)) AS id,
                \\        key,
                \\        argMax(content, tuple(version, id)) AS content,
                \\        argMax(category, tuple(version, id)) AS category,
                \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                \\        argMax(session_id, tuple(version, id)) AS session_id
                \\    FROM {s}.{s}
                \\    WHERE instance_id = {{iid:String}}
                \\    GROUP BY key
                \\)
                \\WHERE (key ILIKE {{q:String}} OR content ILIKE {{q:String}})
                \\ORDER BY score DESC, updated_at DESC, id DESC
                \\LIMIT {{lim:UInt32}}
            , .{ self_.db_q, self_.table_q });

            params = &.{
                .{ "q", pattern },
                .{ "iid", self_.instance_id },
                .{ "lim", limit_str },
            };
        }
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, params);
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        for (rows) |row| {
            var entry = try buildEntry(allocator, row);
            errdefer entry.deinit(allocator);

            // Parse score from column 6 if present
            if (row.len > 6) {
                entry.score = std.fmt.parseFloat(f64, row[6]) catch null;
            }

            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var query: []u8 = undefined;
        var params_buf: [3][2][]const u8 = undefined;
        var param_count: usize = 0;

        params_buf[param_count] = .{ "iid", self_.instance_id };
        param_count += 1;

        if (category) |cat| {
            const cat_str = cat.toString();
            if (session_id) |sid| {
                query = try std.fmt.allocPrint(allocator,
                    \\SELECT id, key, content, category, toString(updated_at), session_id
                    \\FROM (
                    \\    SELECT
                    \\        argMax(id, tuple(version, id)) AS id,
                    \\        key,
                    \\        argMax(content, tuple(version, id)) AS content,
                    \\        argMax(category, tuple(version, id)) AS category,
                    \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                    \\        argMax(session_id, tuple(version, id)) AS session_id
                    \\    FROM {s}.{s}
                    \\    WHERE instance_id = {{iid:String}}
                    \\    GROUP BY key
                    \\)
                    \\WHERE category = {{cat:String}} AND session_id = {{sid:String}}
                    \\ORDER BY updated_at DESC, id DESC
                , .{ self_.db_q, self_.table_q });
                params_buf[param_count] = .{ "cat", cat_str };
                param_count += 1;
                params_buf[param_count] = .{ "sid", sid };
                param_count += 1;
            } else {
                query = try std.fmt.allocPrint(allocator,
                    \\SELECT id, key, content, category, toString(updated_at), session_id
                    \\FROM (
                    \\    SELECT
                    \\        argMax(id, tuple(version, id)) AS id,
                    \\        key,
                    \\        argMax(content, tuple(version, id)) AS content,
                    \\        argMax(category, tuple(version, id)) AS category,
                    \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                    \\        argMax(session_id, tuple(version, id)) AS session_id
                    \\    FROM {s}.{s}
                    \\    WHERE instance_id = {{iid:String}}
                    \\    GROUP BY key
                    \\)
                    \\WHERE category = {{cat:String}}
                    \\ORDER BY updated_at DESC, id DESC
                , .{ self_.db_q, self_.table_q });
                params_buf[param_count] = .{ "cat", cat_str };
                param_count += 1;
            }
        } else if (session_id) |sid| {
            query = try std.fmt.allocPrint(allocator,
                \\SELECT id, key, content, category, toString(updated_at), session_id
                \\FROM (
                \\    SELECT
                \\        argMax(id, tuple(version, id)) AS id,
                \\        key,
                \\        argMax(content, tuple(version, id)) AS content,
                \\        argMax(category, tuple(version, id)) AS category,
                \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                \\        argMax(session_id, tuple(version, id)) AS session_id
                \\    FROM {s}.{s}
                \\    WHERE instance_id = {{iid:String}}
                \\    GROUP BY key
                \\)
                \\WHERE session_id = {{sid:String}}
                \\ORDER BY updated_at DESC, id DESC
            , .{ self_.db_q, self_.table_q });
            params_buf[param_count] = .{ "sid", sid };
            param_count += 1;
        } else {
            query = try std.fmt.allocPrint(allocator,
                \\SELECT id, key, content, category, toString(updated_at), session_id
                \\FROM (
                \\    SELECT
                \\        argMax(id, tuple(version, id)) AS id,
                \\        key,
                \\        argMax(content, tuple(version, id)) AS content,
                \\        argMax(category, tuple(version, id)) AS category,
                \\        argMax(updated_at, tuple(version, id)) AS updated_at,
                \\        argMax(session_id, tuple(version, id)) AS session_id
                \\    FROM {s}.{s}
                \\    WHERE instance_id = {{iid:String}}
                \\    GROUP BY key
                \\)
                \\ORDER BY updated_at DESC, id DESC
            , .{ self_.db_q, self_.table_q });
        }
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, params_buf[0..param_count]);
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        for (rows) |row| {
            const entry = try buildEntry(allocator, row);
            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        // Check if any version of the entry exists before deleting all versions.
        const count_query = try std.fmt.allocPrint(self_.allocator,
            \\SELECT count() FROM {s}.{s}
            \\WHERE key = {{key:String}} AND instance_id = {{iid:String}}
        , .{ self_.db_q, self_.table_q });
        defer self_.allocator.free(count_query);

        const count_body = try self_.executeQuery(self_.allocator, count_query, &.{
            .{ "key", key },
            .{ "iid", self_.instance_id },
        });
        defer self_.allocator.free(count_body);

        const count_trimmed = std.mem.trim(u8, count_body, " \t\n\r");
        const count = std.fmt.parseInt(usize, count_trimmed, 10) catch 0;
        if (count == 0) return false;

        // Execute DELETE mutation
        const delete_query = try std.fmt.allocPrint(self_.allocator,
            \\ALTER TABLE {s}.{s} DELETE
            \\WHERE key = {{key:String}} AND instance_id = {{iid:String}}
        , .{ self_.db_q, self_.table_q });
        defer self_.allocator.free(delete_query);

        try self_.executeMutation(delete_query, &.{
            .{ "key", key },
            .{ "iid", self_.instance_id },
        });

        return true;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(self_.allocator,
            \\SELECT count()
            \\FROM (
            \\    SELECT key
            \\    FROM {s}.{s}
            \\    WHERE instance_id = {{iid:String}}
            \\    GROUP BY key
            \\)
        , .{ self_.db_q, self_.table_q });
        defer self_.allocator.free(query);

        const body = try self_.executeQuery(self_.allocator, query, &.{
            .{ "iid", self_.instance_id },
        });
        defer self_.allocator.free(body);

        const trimmed = std.mem.trim(u8, body, " \t\n\r");
        return std.fmt.parseInt(usize, trimmed, 10) catch 0;
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const body = self_.executeQuery(self_.allocator, "SELECT 1", &.{}) catch return false;
        self_.allocator.free(body);
        return true;
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

    // ── SessionStore vtable implementation ─────────────────────────

    fn implSessionSaveMessage(ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const message_id = try generateId(self_.allocator);
        defer self_.allocator.free(message_id);

        const insert_query = try std.fmt.allocPrint(self_.allocator,
            \\INSERT INTO {s}.{s} (session_id, message_id, role, content, instance_id, created_at)
            \\VALUES ({{sid:String}}, {{mid:String}}, {{role:String}}, {{content:String}}, {{iid:String}}, now64(3))
        , .{ self_.db_q, self_.messages_table_q });
        defer self_.allocator.free(insert_query);

        try self_.executeStatement(insert_query, &.{
            .{ "sid", session_id },
            .{ "mid", message_id },
            .{ "role", role },
            .{ "content", content },
            .{ "iid", self_.instance_id },
        });
    }

    fn implSessionLoadMessages(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8) anyerror![]MessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(allocator,
            \\SELECT role, content FROM {s}.{s}
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}}
            \\ORDER BY message_order ASC, message_id ASC
        , .{ self_.db_q, self_.messages_table_q });
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
        });
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        var messages = try allocator.alloc(MessageEntry, rows.len);
        var filled: usize = 0;
        errdefer {
            for (messages[0..filled]) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
            }
            allocator.free(messages);
        }

        for (rows) |row| {
            if (row.len < 2) continue;
            messages[filled] = .{
                .role = try allocator.dupe(u8, row[0]),
                .content = try allocator.dupe(u8, row[1]),
            };
            filled += 1;
        }

        // Shrink if some rows were skipped
        if (filled < messages.len) {
            const result = try allocator.realloc(messages, filled);
            return result;
        }

        return messages;
    }

    fn implSessionClearMessages(ptr: *anyopaque, session_id: []const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(self_.allocator,
            \\ALTER TABLE {s}.{s} DELETE
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}}
        , .{ self_.db_q, self_.messages_table_q });
        defer self_.allocator.free(query);

        try self_.executeMutation(query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
        });

        const clear_usage = try std.fmt.allocPrint(self_.allocator,
            \\ALTER TABLE {s}.{s} DELETE
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}}
        , .{ self_.db_q, self_.usage_table_q });
        defer self_.allocator.free(clear_usage);

        try self_.executeMutation(clear_usage, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
        });
    }

    fn implSessionClearAutoSaved(ptr: *anyopaque, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        if (session_id) |sid| {
            const query = try std.fmt.allocPrint(self_.allocator,
                \\ALTER TABLE {s}.{s} DELETE
                \\WHERE key LIKE 'autosave_%%' AND session_id = {{sid:String}} AND instance_id = {{iid:String}}
            , .{ self_.db_q, self_.table_q });
            defer self_.allocator.free(query);

            try self_.executeMutation(query, &.{
                .{ "sid", sid },
                .{ "iid", self_.instance_id },
            });
        } else {
            const query = try std.fmt.allocPrint(self_.allocator,
                \\ALTER TABLE {s}.{s} DELETE
                \\WHERE key LIKE 'autosave_%%' AND instance_id = {{iid:String}}
            , .{ self_.db_q, self_.table_q });
            defer self_.allocator.free(query);

            try self_.executeMutation(query, &.{
                .{ "iid", self_.instance_id },
            });
        }
    }

    fn implSessionSaveUsage(ptr: *anyopaque, session_id: []const u8, total_tokens: u64) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var tokens_buf: [20]u8 = undefined;
        const tokens_str = try std.fmt.bufPrint(&tokens_buf, "{d}", .{total_tokens});

        const query = try std.fmt.allocPrint(self_.allocator,
            \\INSERT INTO {s}.{s} (session_id, instance_id, total_tokens, updated_at)
            \\VALUES ({{sid:String}}, {{iid:String}}, {{tokens:UInt64}}, now64(3))
        , .{ self_.db_q, self_.usage_table_q });
        defer self_.allocator.free(query);

        try self_.executeStatement(query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
            .{ "tokens", tokens_str },
        });
    }

    fn implSessionLoadUsage(ptr: *anyopaque, session_id: []const u8) anyerror!?u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(self_.allocator,
            \\SELECT if(count() = 0, '', toString(argMax(total_tokens, version))) FROM {s}.{s}
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}}
        , .{ self_.db_q, self_.usage_table_q });
        defer self_.allocator.free(query);

        const body = try self_.executeQuery(self_.allocator, query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
        });
        defer self_.allocator.free(body);

        const trimmed = std.mem.trim(u8, body, " \t\n\r");
        if (trimmed.len == 0) return null;
        return std.fmt.parseInt(u64, trimmed, 10) catch null;
    }

    fn implSessionCountSessions(ptr: *anyopaque) anyerror!u64 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const query = try std.fmt.allocPrint(self_.allocator,
            \\SELECT toString(count()) FROM (
            \\    SELECT session_id
            \\    FROM {s}.{s}
            \\    WHERE instance_id = {{iid:String}} AND role != '{s}'
            \\    GROUP BY session_id
            \\)
        , .{ self_.db_q, self_.messages_table_q, root.RUNTIME_COMMAND_ROLE });
        defer self_.allocator.free(query);

        const body = try self_.executeQuery(self_.allocator, query, &.{
            .{ "iid", self_.instance_id },
        });
        defer self_.allocator.free(body);

        const trimmed = std.mem.trim(u8, body, " \t\n\r");
        if (trimmed.len == 0) return 0;
        return std.fmt.parseInt(u64, trimmed, 10) catch 0;
    }

    fn implSessionListSessions(ptr: *anyopaque, allocator: std.mem.Allocator, limit: usize, offset: usize) anyerror![]root.SessionInfo {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "{d}", .{limit});
        var offset_buf: [20]u8 = undefined;
        const offset_str = try std.fmt.bufPrint(&offset_buf, "{d}", .{offset});

        const query = try std.fmt.allocPrint(allocator,
            \\SELECT session_id, toString(count()), toString(min(created_at)), toString(max(created_at))
            \\FROM {s}.{s}
            \\WHERE instance_id = {{iid:String}} AND role != '{s}'
            \\GROUP BY session_id
            \\ORDER BY max(created_at) DESC
            \\LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
        , .{ self_.db_q, self_.messages_table_q, root.RUNTIME_COMMAND_ROLE });
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, &.{
            .{ "iid", self_.instance_id },
            .{ "limit", limit_str },
            .{ "offset", offset_str },
        });
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        var sessions = try allocator.alloc(root.SessionInfo, rows.len);
        var filled: usize = 0;
        errdefer {
            for (sessions[0..filled]) |info| info.deinit(allocator);
            allocator.free(sessions);
        }

        for (rows) |row| {
            if (row.len < 4) continue;
            sessions[filled] = .{
                .session_id = try allocator.dupe(u8, row[0]),
                .message_count = std.fmt.parseInt(u64, row[1], 10) catch 0,
                .first_message_at = try allocator.dupe(u8, row[2]),
                .last_message_at = try allocator.dupe(u8, row[3]),
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

        const query = try std.fmt.allocPrint(self_.allocator,
            \\SELECT toString(count()) FROM {s}.{s}
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}} AND role != '{s}'
        , .{ self_.db_q, self_.messages_table_q, root.RUNTIME_COMMAND_ROLE });
        defer self_.allocator.free(query);

        const body = try self_.executeQuery(self_.allocator, query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
        });
        defer self_.allocator.free(body);

        const trimmed = std.mem.trim(u8, body, " \t\n\r");
        if (trimmed.len == 0) return 0;
        return std.fmt.parseInt(u64, trimmed, 10) catch 0;
    }

    fn implSessionLoadMessagesDetailed(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8, limit: usize, offset: usize) anyerror![]root.DetailedMessageEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var limit_buf: [20]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "{d}", .{limit});
        var offset_buf: [20]u8 = undefined;
        const offset_str = try std.fmt.bufPrint(&offset_buf, "{d}", .{offset});

        const query = try std.fmt.allocPrint(allocator,
            \\SELECT role, content, toString(created_at) FROM {s}.{s}
            \\WHERE session_id = {{sid:String}} AND instance_id = {{iid:String}} AND role != '{s}'
            \\ORDER BY message_order ASC, message_id ASC
            \\LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
        , .{ self_.db_q, self_.messages_table_q, root.RUNTIME_COMMAND_ROLE });
        defer allocator.free(query);

        const body = try self_.executeQuery(allocator, query, &.{
            .{ "sid", session_id },
            .{ "iid", self_.instance_id },
            .{ "limit", limit_str },
            .{ "offset", offset_str },
        });
        defer allocator.free(body);

        const rows = try parseTsvRows(allocator, body);
        defer freeTsvRows(allocator, rows);

        var messages = try allocator.alloc(root.DetailedMessageEntry, rows.len);
        var filled: usize = 0;
        errdefer {
            for (messages[0..filled]) |entry| {
                allocator.free(entry.role);
                allocator.free(entry.content);
                allocator.free(entry.created_at);
            }
            allocator.free(messages);
        }

        for (rows) |row| {
            if (row.len < 3) continue;
            messages[filled] = .{
                .role = try allocator.dupe(u8, row[0]),
                .content = try allocator.dupe(u8, row[1]),
                .created_at = try allocator.dupe(u8, row[2]),
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
        return .{
            .ptr = @ptrCast(self),
            .vtable = &session_vtable,
        };
    }
};

fn buildQuotedSuffixTable(allocator: std.mem.Allocator, base: []const u8, suffix: []const u8) ![]u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, suffix });
    defer allocator.free(raw);
    return quoteIdentifier(allocator, raw);
}

// ── Unit Tests ────────────────────────────────────────────────────

test "validateIdentifier accepts valid names" {
    try validateIdentifier("default");
    try validateIdentifier("my_database");
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

test "validateIdentifier accepts max length 63" {
    const ok = "a" ** 63;
    try validateIdentifier(ok);
}

test "validateIdentifier rejects special chars" {
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my-database"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my.database"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("my database"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("table;drop"));
    try std.testing.expectError(error.InvalidCharacter, validateIdentifier("tab`le"));
}

test "quoteIdentifier wraps in backticks" {
    const result = try quoteIdentifier(std.testing.allocator, "memories");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("`memories`", result);
}

test "escapeClickHouseString special chars" {
    const result = try escapeClickHouseString(std.testing.allocator, "it's a\nnew\\line\twith\rtab");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("it\\'s a\\nnew\\\\line\\twith\\rtab", result);
}

test "escapeClickHouseString null bytes" {
    const input = "hello\x00world";
    const result = try escapeClickHouseString(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello\\0world", result);
}

test "escapeClickHouseString no-op for safe strings" {
    const result = try escapeClickHouseString(std.testing.allocator, "hello world 123");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello world 123", result);
}

test "buildUrl http" {
    const result = try buildUrl(std.testing.allocator, "127.0.0.1", 8123, false);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("http://127.0.0.1:8123", result);
}

test "buildUrl https" {
    const result = try buildUrl(std.testing.allocator, "clickhouse.internal", 8443, true);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("https://clickhouse.internal:8443", result);
}

test "buildUrl brackets ipv6 hosts" {
    const result = try buildUrl(std.testing.allocator, "::1", 8123, false);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("http://[::1]:8123", result);
}

test "buildAuthHeader returns null for empty credentials" {
    const result = try buildAuthHeader(std.testing.allocator, "", "");
    try std.testing.expect(result == null);
}

test "buildAuthHeader returns Basic header" {
    const result = try buildAuthHeader(std.testing.allocator, "user", "pass");
    defer if (result) |r| std.testing.allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.startsWith(u8, result.?, "Basic "));
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

test "urlEncode safe chars preserved" {
    const result = try urlEncode(std.testing.allocator, "hello-world_123.test~ok");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello-world_123.test~ok", result);
}

test "urlEncode special chars encoded" {
    const result = try urlEncode(std.testing.allocator, "hello world&foo=bar");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello%20world%26foo%3Dbar", result);
}

test "urlEncode percent sign" {
    const result = try urlEncode(std.testing.allocator, "100%done");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("100%25done", result);
}

test "unescapeClickHouseValue escaped sequences" {
    const result = try unescapeClickHouseValue(std.testing.allocator, "hello\\nworld\\t\\\\end\\'s\\0x");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello\nworld\t\\end's\x00x", result);
}

test "unescapeClickHouseValue plain text" {
    const result = try unescapeClickHouseValue(std.testing.allocator, "simple text");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("simple text", result);
}

test "parseTsvRows empty body" {
    const rows = try parseTsvRows(std.testing.allocator, "");
    defer freeTsvRows(std.testing.allocator, rows);
    try std.testing.expectEqual(@as(usize, 0), rows.len);
}

test "parseTsvRows single row" {
    const rows = try parseTsvRows(std.testing.allocator, "a\tb\tc");
    defer freeTsvRows(std.testing.allocator, rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqual(@as(usize, 3), rows[0].len);
    try std.testing.expectEqualStrings("a", rows[0][0]);
    try std.testing.expectEqualStrings("b", rows[0][1]);
    try std.testing.expectEqualStrings("c", rows[0][2]);
}

test "parseTsvRows multiple rows" {
    const rows = try parseTsvRows(std.testing.allocator, "a\tb\nc\td\n");
    defer freeTsvRows(std.testing.allocator, rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqualStrings("a", rows[0][0]);
    try std.testing.expectEqualStrings("b", rows[0][1]);
    try std.testing.expectEqualStrings("c", rows[1][0]);
    try std.testing.expectEqualStrings("d", rows[1][1]);
}

test "validateTransportSecurity allows loopback plaintext" {
    try validateTransportSecurity("127.0.0.1", false);
    try validateTransportSecurity("127.0.0.2", false);
    try validateTransportSecurity("localhost", false);
    try validateTransportSecurity("::1", false);
}

test "validateTransportSecurity rejects remote plaintext" {
    try std.testing.expectError(error.InsecureTransportNotAllowed, validateTransportSecurity("clickhouse.internal", false));
    try std.testing.expectError(error.InsecureTransportNotAllowed, validateTransportSecurity("127.evil.example", false));
}

// ── Integration Tests (gated) ─────────────────────────────────────

const ClickHouseIntegrationConfig = struct {
    host: []const u8,
    port: u16,
    database: []const u8,
    table: []const u8,
    user: []const u8,
    password: []const u8,
    use_https: bool,

    fn deinit(self: ClickHouseIntegrationConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        allocator.free(self.database);
        allocator.free(self.table);
        allocator.free(self.user);
        allocator.free(self.password);
    }
};

fn isTruthy(raw: []const u8) bool {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    return std.mem.eql(u8, trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on");
}

fn envOrDefault(allocator: std.mem.Allocator, name: []const u8, default_value: []const u8) ![]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => allocator.dupe(u8, default_value),
        else => err,
    };
}

fn loadClickHouseIntegrationConfig(allocator: std.mem.Allocator) !?ClickHouseIntegrationConfig {
    const enabled_raw = std.process.getEnvVarOwned(allocator, "NULLCLAW_TEST_CLICKHOUSE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer allocator.free(enabled_raw);
    if (!isTruthy(enabled_raw)) return null;

    const host = try envOrDefault(allocator, "NULLCLAW_TEST_CLICKHOUSE_HOST", "127.0.0.1");
    errdefer allocator.free(host);
    const database = try envOrDefault(allocator, "NULLCLAW_TEST_CLICKHOUSE_DATABASE", "default");
    errdefer allocator.free(database);
    const table = try envOrDefault(allocator, "NULLCLAW_TEST_CLICKHOUSE_TABLE", "memories");
    errdefer allocator.free(table);
    const user = try envOrDefault(allocator, "NULLCLAW_TEST_CLICKHOUSE_USER", "");
    errdefer allocator.free(user);
    const password = try envOrDefault(allocator, "NULLCLAW_TEST_CLICKHOUSE_PASSWORD", "");
    errdefer allocator.free(password);

    const port_raw = std.process.getEnvVarOwned(allocator, "NULLCLAW_TEST_CLICKHOUSE_PORT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (port_raw) |value| allocator.free(value);
    const port = if (port_raw) |value|
        try std.fmt.parseInt(u16, std.mem.trim(u8, value, " \t\r\n"), 10)
    else
        8123;

    const https_raw = std.process.getEnvVarOwned(allocator, "NULLCLAW_TEST_CLICKHOUSE_USE_HTTPS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (https_raw) |value| allocator.free(value);
    const use_https = if (https_raw) |value| isTruthy(value) else false;

    return .{
        .host = host,
        .port = port,
        .database = database,
        .table = table,
        .user = user,
        .password = password,
        .use_https = use_https,
    };
}

test "integration: clickhouse store and get" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("test-ch-key", "hello clickhouse", .core, null);

    const entry = try m.get(std.testing.allocator, "test-ch-key") orelse
        return error.TestUnexpectedResult;
    defer entry.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test-ch-key", entry.key);
    try std.testing.expectEqualStrings("hello clickhouse", entry.content);
    try std.testing.expect(entry.category.eql(.core));
}

test "integration: clickhouse count" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("count-a", "aaa", .core, null);
    try m.store("count-b", "bbb", .daily, null);

    const n = try m.count();
    try std.testing.expect(n >= 2);
}

test "integration: clickhouse recall" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("recall-1", "the quick brown fox", .core, null);
    try m.store("recall-2", "lazy dog sleeps", .core, null);

    const results = try m.recall(std.testing.allocator, "brown fox", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len >= 1);
    try std.testing.expectEqualStrings("the quick brown fox", results[0].content);
}

test "integration: clickhouse forget" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("forget-me", "temp data", .conversation, null);
    const ok = try m.forget("forget-me");
    try std.testing.expect(ok);

    const entry = try m.get(std.testing.allocator, "forget-me");
    try std.testing.expect(entry == null);
}

test "integration: clickhouse health check" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    try std.testing.expect(mem.memory().healthCheck());
}

test "integration: clickhouse name" {
    if (!build_options.enable_memory_clickhouse) return;
    const integration_cfg = (try loadClickHouseIntegrationConfig(std.testing.allocator)) orelse return;
    defer integration_cfg.deinit(std.testing.allocator);

    const instance_id = try generateId(std.testing.allocator);
    defer std.testing.allocator.free(instance_id);

    var mem = try ClickHouseMemoryImpl.init(std.testing.allocator, .{
        .host = integration_cfg.host,
        .port = integration_cfg.port,
        .database = integration_cfg.database,
        .table = integration_cfg.table,
        .user = integration_cfg.user,
        .password = integration_cfg.password,
        .use_https = integration_cfg.use_https,
        .instance_id = instance_id,
    });
    defer mem.deinit();

    try std.testing.expectEqualStrings("clickhouse", mem.memory().name());
}
