//! Redis-backed persistent memory via RESP (REdis Serialization Protocol) over TCP.
//!
//! No C dependency — implements a minimal RESP v2 client directly.
//! Designed for distributed memory sharing across multiple nullclaw instances.

const std = @import("std");
const builtin = @import("builtin");
const std_compat = @import("compat");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const log = std.log.scoped(.redis_memory);

// ── RESP types ──────────────────────────────────────────────────────

pub const RespValue = union(enum) {
    simple_string: []const u8,
    err: []const u8,
    integer: i64,
    bulk_string: ?[]const u8,
    array: ?[]RespValue,

    pub fn deinit(self: *RespValue, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .simple_string => |s| allocator.free(s),
            .err => |s| allocator.free(s),
            .bulk_string => |maybe_s| if (maybe_s) |s| allocator.free(s),
            .array => |maybe_arr| if (maybe_arr) |arr| {
                for (arr) |*item| item.deinit(allocator);
                allocator.free(arr);
            },
            .integer => {},
        }
    }

    /// Return the value as a string slice (simple_string or bulk_string).
    pub fn asString(self: RespValue) ?[]const u8 {
        return switch (self) {
            .simple_string => |s| s,
            .bulk_string => |maybe_s| maybe_s,
            else => null,
        };
    }
};

// ── RESP protocol helpers ───────────────────────────────────────────

/// Format a Redis command as a RESP array of bulk strings.
pub fn formatCommand(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // *N\r\n
    const header = try std.fmt.allocPrint(allocator, "*{d}\r\n", .{args.len});
    defer allocator.free(header);
    try buf.appendSlice(allocator, header);

    for (args) |arg| {
        // $len\r\n{arg}\r\n
        const prefix = try std.fmt.allocPrint(allocator, "${d}\r\n", .{arg.len});
        defer allocator.free(prefix);
        try buf.appendSlice(allocator, prefix);
        try buf.appendSlice(allocator, arg);
        try buf.appendSlice(allocator, "\r\n");
    }

    return buf.toOwnedSlice(allocator);
}

/// Parse a single RESP value from the given data buffer.
/// Returns the parsed value and the number of bytes consumed.
pub fn parseResp(allocator: std.mem.Allocator, data: []const u8) !struct { value: RespValue, consumed: usize } {
    if (data.len == 0) return error.IncompleteData;

    const type_byte = data[0];
    const rest = data[1..];

    switch (type_byte) {
        '+' => {
            // Simple string: +OK\r\n
            const end = std.mem.indexOf(u8, rest, "\r\n") orelse return error.IncompleteData;
            const s = try allocator.dupe(u8, rest[0..end]);
            return .{ .value = .{ .simple_string = s }, .consumed = 1 + end + 2 };
        },
        '-' => {
            // Error: -ERR message\r\n
            const end = std.mem.indexOf(u8, rest, "\r\n") orelse return error.IncompleteData;
            const s = try allocator.dupe(u8, rest[0..end]);
            return .{ .value = .{ .err = s }, .consumed = 1 + end + 2 };
        },
        ':' => {
            // Integer: :42\r\n
            const end = std.mem.indexOf(u8, rest, "\r\n") orelse return error.IncompleteData;
            const n = try std.fmt.parseInt(i64, rest[0..end], 10);
            return .{ .value = .{ .integer = n }, .consumed = 1 + end + 2 };
        },
        '$' => {
            // Bulk string: $len\r\n{data}\r\n  or  $-1\r\n (null)
            const end = std.mem.indexOf(u8, rest, "\r\n") orelse return error.IncompleteData;
            const len = try std.fmt.parseInt(i64, rest[0..end], 10);
            if (len < 0) {
                return .{ .value = .{ .bulk_string = null }, .consumed = 1 + end + 2 };
            }
            const ulen: usize = @intCast(len);
            const data_start = end + 2;
            if (rest.len < data_start + ulen + 2) return error.IncompleteData;
            const s = try allocator.dupe(u8, rest[data_start .. data_start + ulen]);
            return .{ .value = .{ .bulk_string = s }, .consumed = 1 + data_start + ulen + 2 };
        },
        '*' => {
            // Array: *N\r\n...  or  *-1\r\n (null)
            const end = std.mem.indexOf(u8, rest, "\r\n") orelse return error.IncompleteData;
            const count = try std.fmt.parseInt(i64, rest[0..end], 10);
            if (count < 0) {
                return .{ .value = .{ .array = null }, .consumed = 1 + end + 2 };
            }
            const ucount: usize = @intCast(count);
            var items = try allocator.alloc(RespValue, ucount);
            var total_consumed: usize = 1 + end + 2;
            var i: usize = 0;
            errdefer {
                for (items[0..i]) |*item| item.deinit(allocator);
                allocator.free(items);
            }
            while (i < ucount) : (i += 1) {
                const result = try parseResp(allocator, data[total_consumed..]);
                items[i] = result.value;
                total_consumed += result.consumed;
            }
            return .{ .value = .{ .array = items }, .consumed = total_consumed };
        },
        else => return error.UnknownRespType,
    }
}

// ── Redis config ────────────────────────────────────────────────────

pub const RedisConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    password: ?[]const u8 = null,
    db_index: u8 = 0,
    key_prefix: []const u8 = "nullclaw",
    ttl_seconds: ?u32 = null,
    instance_id: []const u8 = "",
};

// ── RedisMemory ─────────────────────────────────────────────────────

pub const RedisMemory = struct {
    allocator: std.mem.Allocator,
    stream: ?std_compat.net.Stream = null,
    host: []const u8,
    port: u16,
    password: ?[]const u8,
    db_index: u8,
    key_prefix: []const u8,
    ttl_seconds: ?u32,
    instance_id: []const u8 = "",
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: RedisConfig) !Self {
        var self_ = Self{
            .allocator = allocator,
            .host = config.host,
            .port = config.port,
            .password = config.password,
            .db_index = config.db_index,
            .key_prefix = config.key_prefix,
            .ttl_seconds = config.ttl_seconds,
            .instance_id = config.instance_id,
        };

        try self_.connect();
        return self_;
    }

    pub fn deinit(self: *Self) void {
        if (self.stream) |stream| {
            stream.close();
            self.stream = null;
        }
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn connect(self: *Self) anyerror!void {
        const addr = try std_compat.net.Address.resolveIp(self.host, self.port);
        const stream = try std_compat.net.tcpConnectToAddress(addr);
        self.stream = stream;

        // AUTH if password set (stream is already connected, ensureConnected is a no-op)
        if (self.password) |pwd| {
            var resp = try self.sendCommandAlloc(self.allocator, &.{ "AUTH", pwd });
            defer resp.deinit(self.allocator);
            switch (resp) {
                .err => |msg| {
                    log.err("AUTH failed: {s}", .{msg});
                    return error.AuthFailed;
                },
                else => {},
            }
        }

        // SELECT database
        if (self.db_index != 0) {
            var db_buf: [4]u8 = undefined;
            const db_str = std.fmt.bufPrint(&db_buf, "{d}", .{self.db_index}) catch unreachable;
            var resp = try self.sendCommandAlloc(self.allocator, &.{ "SELECT", db_str });
            defer resp.deinit(self.allocator);
            switch (resp) {
                .err => |msg| {
                    log.err("SELECT failed: {s}", .{msg});
                    return error.SelectFailed;
                },
                else => {},
            }
        }
    }

    fn ensureConnected(self: *Self) !void {
        if (self.stream != null) return;
        try self.connect();
    }

    // ── Low-level RESP I/O ─────────────────────────────────────────

    fn sendCommand(self: *Self, args: []const []const u8) !RespValue {
        return self.sendCommandAlloc(self.allocator, args);
    }

    fn sendCommandAlloc(self: *Self, allocator: std.mem.Allocator, args: []const []const u8) !RespValue {
        try self.ensureConnected();
        const stream = self.stream orelse return error.NotConnected;

        const cmd = try formatCommand(self.allocator, args);
        defer self.allocator.free(cmd);

        stream.writeAll(cmd) catch |err| {
            self.stream = null;
            return err;
        };

        return self.readResponse(allocator);
    }

    fn readResponse(self: *Self, allocator: std.mem.Allocator) !RespValue {
        const stream = self.stream orelse return error.NotConnected;
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(self.allocator);

        while (true) {
            var buf: [4096]u8 = undefined;
            const n = stream.read(&buf) catch |err| {
                self.stream = null;
                return err;
            };
            if (n == 0) {
                self.stream = null;
                return error.ConnectionClosed;
            }
            try data.appendSlice(self.allocator, buf[0..n]);

            const result = parseResp(allocator, data.items) catch |err| switch (err) {
                error.IncompleteData => continue,
                else => return err,
            };
            return result.value;
        }
    }

    // ── Key helpers ────────────────────────────────────────────────

    fn prefixedKey(self: *Self, comptime suffix: []const u8, key: []const u8) ![]u8 {
        if (self.instance_id.len > 0) {
            return std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}:{s}", .{ self.key_prefix, self.instance_id, suffix, key });
        }
        return std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}", .{ self.key_prefix, suffix, key });
    }

    fn prefixedSimple(self: *Self, comptime suffix: []const u8) ![]u8 {
        if (self.instance_id.len > 0) {
            return std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}", .{ self.key_prefix, self.instance_id, suffix });
        }
        return std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ self.key_prefix, suffix });
    }

    // ── Timestamp / ID helpers ─────────────────────────────────────

    fn getNowTimestamp(allocator: std.mem.Allocator) ![]u8 {
        const ts = std_compat.time.timestamp();
        return std.fmt.allocPrint(allocator, "{d}", .{ts});
    }

    fn generateId(allocator: std.mem.Allocator) ![]u8 {
        const ts = std_compat.time.nanoTimestamp();
        var rand_buf: [16]u8 = undefined;
        std_compat.crypto.random.bytes(&rand_buf);
        const hi = std.mem.readInt(u64, rand_buf[0..8], .little);
        const lo = std.mem.readInt(u64, rand_buf[8..16], .little);
        return std.fmt.allocPrint(allocator, "{d}-{x}-{x}", .{ ts, hi, lo });
    }

    // ── Memory vtable implementation ───────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "redis";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const now = try getNowTimestamp(self_.allocator);
        defer self_.allocator.free(now);
        const id = try generateId(self_.allocator);
        defer self_.allocator.free(id);
        const cat_str = category.toString();

        // entry key: {prefix}:entry:{key}
        const entry_key = try self_.prefixedKey("entry", key);
        defer self_.allocator.free(entry_key);

        // On upsert, clean up stale category/session index sets before overwriting.
        // If the key already exists with a different category or session_id, the old
        // index sets would retain a stale reference to this key.
        var old_cat_resp = try self_.sendCommand(&.{ "HGET", entry_key, "category" });
        const old_cat_str = old_cat_resp.asString();
        defer old_cat_resp.deinit(self_.allocator);

        var old_sid_resp = try self_.sendCommand(&.{ "HGET", entry_key, "session_id" });
        const old_sid_str = old_sid_resp.asString();
        defer old_sid_resp.deinit(self_.allocator);

        if (old_cat_str) |old_cat| {
            if (old_cat.len > 0 and !std.mem.eql(u8, old_cat, cat_str)) {
                const old_cat_set = try self_.prefixedKey("cat", old_cat);
                defer self_.allocator.free(old_cat_set);
                var srem_resp = try self_.sendCommand(&.{ "SREM", old_cat_set, key });
                srem_resp.deinit(self_.allocator);
            }
        }

        if (old_sid_str) |old_sid| {
            const new_sid = session_id orelse "";
            if (old_sid.len > 0 and !std.mem.eql(u8, old_sid, new_sid)) {
                const old_sess_set = try self_.prefixedKey("sessions", old_sid);
                defer self_.allocator.free(old_sess_set);
                var srem_resp = try self_.sendCommand(&.{ "SREM", old_sess_set, key });
                srem_resp.deinit(self_.allocator);
            }
        }

        // HSET {entry_key} id {id} content {content} category {cat} session_id {sid} created_at {ts} updated_at {ts}
        const sid = session_id orelse "";
        var resp = try self_.sendCommand(&.{
            "HSET",       entry_key,
            "id",         id,
            "content",    content,
            "category",   cat_str,
            "session_id", sid,
            "created_at", now,
            "updated_at", now,
        });
        resp.deinit(self_.allocator);

        // SADD {prefix}:keys {key}
        const keys_set = try self_.prefixedSimple("keys");
        defer self_.allocator.free(keys_set);
        resp = try self_.sendCommand(&.{ "SADD", keys_set, key });
        resp.deinit(self_.allocator);

        // SADD {prefix}:cat:{category} {key}
        const cat_set = try self_.prefixedKey("cat", cat_str);
        defer self_.allocator.free(cat_set);
        resp = try self_.sendCommand(&.{ "SADD", cat_set, key });
        resp.deinit(self_.allocator);

        // If session_id: SADD {prefix}:sessions:{sid} {key}
        if (session_id) |sid_val| {
            const sess_set = try self_.prefixedKey("sessions", sid_val);
            defer self_.allocator.free(sess_set);
            resp = try self_.sendCommand(&.{ "SADD", sess_set, key });
            resp.deinit(self_.allocator);
        }

        // If ttl_seconds: EXPIRE {entry_key} {ttl}
        if (self_.ttl_seconds) |ttl| {
            var ttl_buf: [12]u8 = undefined;
            const ttl_str = std.fmt.bufPrint(&ttl_buf, "{d}", .{ttl}) catch unreachable;
            resp = try self_.sendCommand(&.{ "EXPIRE", entry_key, ttl_str });
            resp.deinit(self_.allocator);
        }
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const entry_key = try self_.prefixedKey("entry", key);
        defer self_.allocator.free(entry_key);

        var resp = try self_.sendCommandAlloc(allocator, &.{ "HGETALL", entry_key });
        defer resp.deinit(allocator);

        const fields = switch (resp) {
            .array => |maybe_arr| maybe_arr orelse return null,
            else => return null,
        };

        if (fields.len == 0) return null;

        return try parseHashFields(allocator, key, fields);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const trimmed = std.mem.trim(u8, query, " \t\n\r");
        if (trimmed.len == 0) return allocator.alloc(MemoryEntry, 0);

        // Get all keys
        const keys_set = try self_.prefixedSimple("keys");
        defer self_.allocator.free(keys_set);

        var keys_resp = try self_.sendCommandAlloc(allocator, &.{ "SMEMBERS", keys_set });
        defer keys_resp.deinit(allocator);

        const key_values = switch (keys_resp) {
            .array => |maybe_arr| maybe_arr orelse return allocator.alloc(MemoryEntry, 0),
            else => return allocator.alloc(MemoryEntry, 0),
        };

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        const lower_query = try std.ascii.allocLowerString(allocator, trimmed);
        defer allocator.free(lower_query);

        for (key_values) |kv| {
            const k = kv.asString() orelse continue;

            const entry_key = try self_.prefixedKey("entry", k);
            defer self_.allocator.free(entry_key);

            var hash_resp = try self_.sendCommandAlloc(allocator, &.{ "HGETALL", entry_key });
            defer hash_resp.deinit(allocator);

            const fields = switch (hash_resp) {
                .array => |maybe_arr| maybe_arr orelse continue,
                else => continue,
            };
            if (fields.len == 0) continue;

            var entry = try parseHashFields(allocator, k, fields);
            errdefer entry.deinit(allocator);

            // Filter by session_id if provided
            if (session_id) |sid| {
                if (entry.session_id) |e_sid| {
                    if (!std.mem.eql(u8, e_sid, sid)) {
                        entry.deinit(allocator);
                        continue;
                    }
                } else {
                    entry.deinit(allocator);
                    continue;
                }
            }

            // Substring search (case-insensitive)
            const lower_content = try std.ascii.allocLowerString(allocator, entry.content);
            defer allocator.free(lower_content);
            const lower_key = try std.ascii.allocLowerString(allocator, entry.key);
            defer allocator.free(lower_key);

            const key_match = std.mem.indexOf(u8, lower_key, lower_query) != null;
            const content_match = std.mem.indexOf(u8, lower_content, lower_query) != null;

            if (key_match or content_match) {
                // Score: key match = 2.0, content match = 1.0
                var score: f64 = 0;
                if (key_match) score += 2.0;
                if (content_match) score += 1.0;
                entry.score = score;
                try entries.append(allocator, entry);
            } else {
                entry.deinit(allocator);
            }
        }

        // Sort by updated_at descending, then by score descending
        std.mem.sort(MemoryEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: MemoryEntry, b: MemoryEntry) bool {
                // Higher score first
                const sa = a.score orelse 0;
                const sb = b.score orelse 0;
                if (sa != sb) return sa > sb;
                // Then by timestamp descending
                return std.mem.order(u8, a.timestamp, b.timestamp) == .gt;
            }
        }.lessThan);

        // Truncate to limit
        if (entries.items.len > limit) {
            for (entries.items[limit..]) |*entry| entry.deinit(allocator);
            entries.shrinkRetainingCapacity(limit);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        // Determine which set to query
        const set_key = if (category) |cat|
            try self_.prefixedKey("cat", cat.toString())
        else
            try self_.prefixedSimple("keys");
        defer self_.allocator.free(set_key);

        var keys_resp = try self_.sendCommandAlloc(allocator, &.{ "SMEMBERS", set_key });
        defer keys_resp.deinit(allocator);

        const key_values = switch (keys_resp) {
            .array => |maybe_arr| maybe_arr orelse return allocator.alloc(MemoryEntry, 0),
            else => return allocator.alloc(MemoryEntry, 0),
        };

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        for (key_values) |kv| {
            const k = kv.asString() orelse continue;

            const entry_key = try self_.prefixedKey("entry", k);
            defer self_.allocator.free(entry_key);

            var hash_resp = try self_.sendCommandAlloc(allocator, &.{ "HGETALL", entry_key });
            defer hash_resp.deinit(allocator);

            const fields = switch (hash_resp) {
                .array => |maybe_arr| maybe_arr orelse continue,
                else => continue,
            };
            if (fields.len == 0) continue;

            var entry = try parseHashFields(allocator, k, fields);
            errdefer entry.deinit(allocator);

            // Filter by session_id if provided
            if (session_id) |sid| {
                if (entry.session_id) |e_sid| {
                    if (!std.mem.eql(u8, e_sid, sid)) {
                        entry.deinit(allocator);
                        continue;
                    }
                } else {
                    entry.deinit(allocator);
                    continue;
                }
            }

            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8, limit: usize, offset: usize) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const set_key = if (category) |cat|
            try self_.prefixedKey("cat", cat.toString())
        else
            try self_.prefixedSimple("keys");
        defer self_.allocator.free(set_key);

        var keys_resp = try self_.sendCommandAlloc(allocator, &.{ "SMEMBERS", set_key });
        defer keys_resp.deinit(allocator);

        const key_values = switch (keys_resp) {
            .array => |maybe_arr| maybe_arr orelse return allocator.alloc(MemoryEntry, 0),
            else => return allocator.alloc(MemoryEntry, 0),
        };

        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        var skipped: usize = 0;
        for (key_values) |kv| {
            const k = kv.asString() orelse continue;

            const entry_key = try self_.prefixedKey("entry", k);
            defer self_.allocator.free(entry_key);

            var hash_resp = try self_.sendCommandAlloc(allocator, &.{ "HGETALL", entry_key });
            defer hash_resp.deinit(allocator);

            const fields = switch (hash_resp) {
                .array => |maybe_arr| maybe_arr orelse continue,
                else => continue,
            };
            if (fields.len == 0) continue;

            var entry = try parseHashFields(allocator, k, fields);
            errdefer entry.deinit(allocator);

            if (session_id) |sid| {
                if (entry.session_id) |e_sid| {
                    if (!std.mem.eql(u8, e_sid, sid)) {
                        entry.deinit(allocator);
                        continue;
                    }
                } else {
                    entry.deinit(allocator);
                    continue;
                }
            }

            if (skipped < offset) {
                skipped += 1;
                entry.deinit(allocator);
                continue;
            }
            if (entries.items.len >= limit) {
                entry.deinit(allocator);
                break;
            }

            try entries.append(allocator, entry);
        }

        return entries.toOwnedSlice(allocator);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const entry_key = try self_.prefixedKey("entry", key);
        defer self_.allocator.free(entry_key);

        // Get category and session_id before deleting
        var cat_resp = try self_.sendCommand(&.{ "HGET", entry_key, "category" });
        const cat_str = cat_resp.asString();
        defer cat_resp.deinit(self_.allocator);

        var sid_resp = try self_.sendCommand(&.{ "HGET", entry_key, "session_id" });
        const sid_str = sid_resp.asString();
        defer sid_resp.deinit(self_.allocator);

        // DEL {prefix}:entry:{key}
        var del_resp = try self_.sendCommand(&.{ "DEL", entry_key });
        const deleted = switch (del_resp) {
            .integer => |n| n > 0,
            else => false,
        };
        del_resp.deinit(self_.allocator);

        if (!deleted) return false;

        // SREM {prefix}:keys {key}
        const keys_set = try self_.prefixedSimple("keys");
        defer self_.allocator.free(keys_set);
        var srem_resp = try self_.sendCommand(&.{ "SREM", keys_set, key });
        srem_resp.deinit(self_.allocator);

        // SREM {prefix}:cat:{category} {key}
        if (cat_str) |cat| {
            if (cat.len > 0) {
                const cat_set = try self_.prefixedKey("cat", cat);
                defer self_.allocator.free(cat_set);
                var cat_srem = try self_.sendCommand(&.{ "SREM", cat_set, key });
                cat_srem.deinit(self_.allocator);
            }
        }

        // SREM {prefix}:sessions:{sid} {key}
        if (sid_str) |sid| {
            if (sid.len > 0) {
                const sess_set = try self_.prefixedKey("sessions", sid);
                defer self_.allocator.free(sess_set);
                var sess_srem = try self_.sendCommand(&.{ "SREM", sess_set, key });
                sess_srem.deinit(self_.allocator);
            }
        }

        return true;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        const keys_set = try self_.prefixedSimple("keys");
        defer self_.allocator.free(keys_set);

        var resp = try self_.sendCommand(&.{ "SCARD", keys_set });
        defer resp.deinit(self_.allocator);

        return switch (resp) {
            .integer => |n| if (n >= 0) @intCast(n) else 0,
            else => 0,
        };
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        var resp = self_.sendCommand(&.{"PING"}) catch return false;
        defer resp.deinit(self_.allocator);
        return switch (resp) {
            .simple_string => |s| std.mem.eql(u8, s, "PONG"),
            else => false,
        };
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

// ── Hash field parser ──────────────────────────────────────────────

fn parseHashFields(allocator: std.mem.Allocator, key: []const u8, fields: []RespValue) !MemoryEntry {
    // HGETALL returns [field, value, field, value, ...]
    var id_val: ?[]const u8 = null;
    var content_val: ?[]const u8 = null;
    var category_val: ?[]const u8 = null;
    var session_id_val: ?[]const u8 = null;
    var timestamp_val: ?[]const u8 = null;

    var i: usize = 0;
    while (i + 1 < fields.len) : (i += 2) {
        const field_name = fields[i].asString() orelse continue;
        const field_value = fields[i + 1].asString() orelse continue;

        if (std.mem.eql(u8, field_name, "id")) {
            id_val = field_value;
        } else if (std.mem.eql(u8, field_name, "content")) {
            content_val = field_value;
        } else if (std.mem.eql(u8, field_name, "category")) {
            category_val = field_value;
        } else if (std.mem.eql(u8, field_name, "session_id")) {
            session_id_val = field_value;
        } else if (std.mem.eql(u8, field_name, "updated_at")) {
            timestamp_val = field_value;
        }
    }

    const id = try allocator.dupe(u8, id_val orelse "");
    errdefer allocator.free(id);
    const entry_key = try allocator.dupe(u8, key);
    errdefer allocator.free(entry_key);
    const content = try allocator.dupe(u8, content_val orelse "");
    errdefer allocator.free(content);
    const timestamp = try allocator.dupe(u8, timestamp_val orelse "0");
    errdefer allocator.free(timestamp);

    const cat_str = category_val orelse "core";
    const category = MemoryCategory.fromString(cat_str);
    // If category is .custom, we need to dupe the string since it points into the resp buffer
    const final_category: MemoryCategory = switch (category) {
        .custom => .{ .custom = try allocator.dupe(u8, cat_str) },
        else => category,
    };

    var sid: ?[]const u8 = null;
    if (session_id_val) |sv| {
        if (sv.len > 0) {
            sid = try allocator.dupe(u8, sv);
        }
    }

    return .{
        .id = id,
        .key = entry_key,
        .content = content,
        .category = final_category,
        .timestamp = timestamp,
        .session_id = sid,
    };
}

// ── Tests ──────────────────────────────────────────────────────────

// RESP protocol tests (no Redis server needed)

test "formatCommand SET key value" {
    const cmd = try formatCommand(std.testing.allocator, &.{ "SET", "key", "value" });
    defer std.testing.allocator.free(cmd);
    try std.testing.expectEqualStrings("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n", cmd);
}

test "formatCommand PING (no args)" {
    const cmd = try formatCommand(std.testing.allocator, &.{"PING"});
    defer std.testing.allocator.free(cmd);
    try std.testing.expectEqualStrings("*1\r\n$4\r\nPING\r\n", cmd);
}

test "formatCommand HSET multiple fields" {
    const cmd = try formatCommand(std.testing.allocator, &.{ "HSET", "myhash", "field1", "val1", "field2", "val2" });
    defer std.testing.allocator.free(cmd);
    try std.testing.expectEqualStrings("*6\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n$4\r\nval1\r\n$6\r\nfield2\r\n$4\r\nval2\r\n", cmd);
}

test "formatCommand empty string arg" {
    const cmd = try formatCommand(std.testing.allocator, &.{ "SET", "key", "" });
    defer std.testing.allocator.free(cmd);
    try std.testing.expectEqualStrings("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$0\r\n\r\n", cmd);
}

test "parseResp simple string" {
    const result = try parseResp(std.testing.allocator, "+OK\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("OK", val.simple_string);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseResp error" {
    const result = try parseResp(std.testing.allocator, "-ERR unknown\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ERR unknown", val.err);
    try std.testing.expectEqual(@as(usize, 14), result.consumed);
}

test "parseResp integer" {
    const result = try parseResp(std.testing.allocator, ":42\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i64, 42), val.integer);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseResp negative integer" {
    const result = try parseResp(std.testing.allocator, ":-1\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i64, -1), val.integer);
}

test "parseResp bulk string" {
    const result = try parseResp(std.testing.allocator, "$5\r\nhello\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("hello", val.bulk_string.?);
    try std.testing.expectEqual(@as(usize, 11), result.consumed);
}

test "parseResp null bulk string" {
    const result = try parseResp(std.testing.allocator, "$-1\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expect(val.bulk_string == null);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseResp empty bulk string" {
    const result = try parseResp(std.testing.allocator, "$0\r\n\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", val.bulk_string.?);
}

test "parseResp array" {
    const data = "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
    const result = try parseResp(std.testing.allocator, data);
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    const arr = val.array.?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("foo", arr[0].bulk_string.?);
    try std.testing.expectEqualStrings("bar", arr[1].bulk_string.?);
}

test "parseResp null array" {
    const result = try parseResp(std.testing.allocator, "*-1\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expect(val.array == null);
}

test "parseResp empty array" {
    const result = try parseResp(std.testing.allocator, "*0\r\n");
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), val.array.?.len);
}

test "parseResp nested array" {
    const data = "*2\r\n*2\r\n:1\r\n:2\r\n*1\r\n+OK\r\n";
    const result = try parseResp(std.testing.allocator, data);
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    const arr = val.array.?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    const inner1 = arr[0].array.?;
    try std.testing.expectEqual(@as(i64, 1), inner1[0].integer);
    try std.testing.expectEqual(@as(i64, 2), inner1[1].integer);
    const inner2 = arr[1].array.?;
    try std.testing.expectEqualStrings("OK", inner2[0].simple_string);
}

test "parseResp incomplete data returns error" {
    try std.testing.expectError(error.IncompleteData, parseResp(std.testing.allocator, "+OK\r"));
    try std.testing.expectError(error.IncompleteData, parseResp(std.testing.allocator, "$5\r\nhel"));
    try std.testing.expectError(error.IncompleteData, parseResp(std.testing.allocator, ""));
}

test "parseResp unknown type returns error" {
    try std.testing.expectError(error.UnknownRespType, parseResp(std.testing.allocator, "?invalid\r\n"));
}

test "parseResp mixed array" {
    const data = "*3\r\n:1\r\n$5\r\nhello\r\n+OK\r\n";
    const result = try parseResp(std.testing.allocator, data);
    var val = result.value;
    defer val.deinit(std.testing.allocator);
    const arr = val.array.?;
    try std.testing.expectEqual(@as(usize, 3), arr.len);
    try std.testing.expectEqual(@as(i64, 1), arr[0].integer);
    try std.testing.expectEqualStrings("hello", arr[1].bulk_string.?);
    try std.testing.expectEqualStrings("OK", arr[2].simple_string);
}

test "parseHashFields basic" {
    // Simulate HGETALL response fields: [field, value, field, value, ...]
    var fields = [_]RespValue{
        .{ .bulk_string = "id" },
        .{ .bulk_string = "test-id-123" },
        .{ .bulk_string = "content" },
        .{ .bulk_string = "hello world" },
        .{ .bulk_string = "category" },
        .{ .bulk_string = "core" },
        .{ .bulk_string = "session_id" },
        .{ .bulk_string = "" },
        .{ .bulk_string = "updated_at" },
        .{ .bulk_string = "1700000000" },
    };

    var entry = try parseHashFields(std.testing.allocator, "test-key", &fields);
    defer entry.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test-id-123", entry.id);
    try std.testing.expectEqualStrings("test-key", entry.key);
    try std.testing.expectEqualStrings("hello world", entry.content);
    try std.testing.expect(entry.category.eql(.core));
    try std.testing.expectEqualStrings("1700000000", entry.timestamp);
    try std.testing.expect(entry.session_id == null); // empty string → null
}

test "parseHashFields with session_id" {
    var fields = [_]RespValue{
        .{ .bulk_string = "id" },
        .{ .bulk_string = "id-1" },
        .{ .bulk_string = "content" },
        .{ .bulk_string = "data" },
        .{ .bulk_string = "category" },
        .{ .bulk_string = "daily" },
        .{ .bulk_string = "session_id" },
        .{ .bulk_string = "sess-42" },
        .{ .bulk_string = "updated_at" },
        .{ .bulk_string = "12345" },
    };

    var entry = try parseHashFields(std.testing.allocator, "k", &fields);
    defer entry.deinit(std.testing.allocator);

    try std.testing.expect(entry.category.eql(.daily));
    try std.testing.expectEqualStrings("sess-42", entry.session_id.?);
}

test "parseHashFields custom category" {
    var fields = [_]RespValue{
        .{ .bulk_string = "id" },
        .{ .bulk_string = "id-1" },
        .{ .bulk_string = "content" },
        .{ .bulk_string = "stuff" },
        .{ .bulk_string = "category" },
        .{ .bulk_string = "my_custom" },
        .{ .bulk_string = "session_id" },
        .{ .bulk_string = "" },
        .{ .bulk_string = "updated_at" },
        .{ .bulk_string = "99" },
    };

    var entry = try parseHashFields(std.testing.allocator, "k", &fields);
    defer entry.deinit(std.testing.allocator);

    switch (entry.category) {
        .custom => |name| try std.testing.expectEqualStrings("my_custom", name),
        else => return error.TestUnexpectedResult,
    }
}

test "RespValue deinit frees all memory" {
    // This test verifies no leaks via the testing allocator
    var val = RespValue{ .simple_string = try std.testing.allocator.dupe(u8, "hello") };
    val.deinit(std.testing.allocator);

    var arr_items = try std.testing.allocator.alloc(RespValue, 2);
    arr_items[0] = .{ .bulk_string = try std.testing.allocator.dupe(u8, "a") };
    arr_items[1] = .{ .integer = 42 };
    var val2 = RespValue{ .array = arr_items };
    val2.deinit(std.testing.allocator);
}

test "formatCommand roundtrip with parseResp" {
    // Format a command and verify it starts with the right array header
    const cmd = try formatCommand(std.testing.allocator, &.{ "GET", "mykey" });
    defer std.testing.allocator.free(cmd);

    // Parse the command we just formatted (it's valid RESP)
    const result = try parseResp(std.testing.allocator, cmd);
    var val = result.value;
    defer val.deinit(std.testing.allocator);

    const arr = val.array.?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("GET", arr[0].bulk_string.?);
    try std.testing.expectEqualStrings("mykey", arr[1].bulk_string.?);
}

// Integration tests — guarded by Redis availability
fn canConnectToRedis() bool {
    // Windows CI does not provide Redis, and Zig 0.16's AFD connect path can
    // emit noisy unexpected NTSTATUS traces for a simple connection-refused
    // probe before the error is caught here.
    if (builtin.os.tag == .windows) return false;

    const addr = std_compat.net.Address.resolveIp("127.0.0.1", 6379) catch return false;
    const stream = std_compat.net.tcpConnectToAddress(addr) catch return false;
    stream.close();
    return true;
}

test "integration: redis store and get" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{
        .key_prefix = "nullclaw_test",
    });
    defer mem.deinit();

    const m = mem.memory();

    // Clean up first
    _ = try m.forget("test-integration-key");

    try m.store("test-integration-key", "hello redis", .core, null);

    const entry = try m.get(std.testing.allocator, "test-integration-key") orelse
        return error.TestUnexpectedResult;
    defer entry.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test-integration-key", entry.key);
    try std.testing.expectEqualStrings("hello redis", entry.content);
    try std.testing.expect(entry.category.eql(.core));

    // Cleanup
    _ = try m.forget("test-integration-key");
}

test "integration: redis count" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{
        .key_prefix = "nullclaw_test_count",
    });
    defer mem.deinit();

    const m = mem.memory();

    // Store two entries
    try m.store("count-a", "aaa", .core, null);
    try m.store("count-b", "bbb", .daily, null);

    const n = try m.count();
    try std.testing.expect(n >= 2);

    // Cleanup
    _ = try m.forget("count-a");
    _ = try m.forget("count-b");
}

test "integration: redis recall substring" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{
        .key_prefix = "nullclaw_test_recall",
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("recall-1", "the quick brown fox", .core, null);
    try m.store("recall-2", "lazy dog sleeps", .core, null);

    const results = try m.recall(std.testing.allocator, "brown fox", 10, null);
    defer root.freeEntries(std.testing.allocator, results);

    try std.testing.expect(results.len >= 1);
    try std.testing.expectEqualStrings("the quick brown fox", results[0].content);

    // Cleanup
    _ = try m.forget("recall-1");
    _ = try m.forget("recall-2");
}

test "integration: redis forget" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{
        .key_prefix = "nullclaw_test_forget",
    });
    defer mem.deinit();

    const m = mem.memory();

    try m.store("forget-me", "temp data", .conversation, null);
    const ok = try m.forget("forget-me");
    try std.testing.expect(ok);

    const entry = try m.get(std.testing.allocator, "forget-me");
    try std.testing.expect(entry == null);
}

test "integration: redis health check" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{
        .key_prefix = "nullclaw_test_health",
    });
    defer mem.deinit();

    try std.testing.expect(mem.memory().healthCheck());
}

test "integration: redis name" {
    if (!canConnectToRedis()) return;

    var mem = try RedisMemory.init(std.testing.allocator, .{});
    defer mem.deinit();

    try std.testing.expectEqualStrings("redis", mem.memory().name());
}
