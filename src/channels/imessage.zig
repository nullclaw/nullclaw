const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const config_types = @import("../config_types.zig");
const platform = @import("../platform.zig");

const log = std.log.scoped(.imessage);

const c = @cImport({
    @cInclude("sqlite3.h");
});

const SQLITE_STATIC: c.sqlite3_destructor_type = null;
const CHAT_TARGET_PREFIX = "chat:";
const POLL_BATCH_LIMIT: c_int = 20;

/// iMessage channel — macOS Messages.app bridge.
///
/// Inbound:
///   Polls ~/Library/Messages/chat.db for new messages and publishes them to the event bus.
/// Outbound:
///   Sends via AppleScript (`osascript`) either to participant (phone/email) or chat GUID.
pub const IMessageChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    group_policy: []const u8,
    db_path: ?[]const u8 = null,
    poll_interval_secs: u64,

    bus: ?*bus_mod.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    poll_thread: ?std.Thread = null,

    last_rowid: i64 = 0,
    cursor_initialized: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        allow_from: []const []const u8,
        group_allow_from: []const []const u8,
        group_policy: []const u8,
    ) IMessageChannel {
        return .{
            .allocator = allocator,
            .allow_from = allow_from,
            .group_allow_from = group_allow_from,
            .group_policy = group_policy,
            .poll_interval_secs = 3,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.IMessageConfig) IMessageChannel {
        var ch = init(
            allocator,
            cfg.allow_from,
            cfg.group_allow_from,
            cfg.group_policy,
        );
        ch.account_id = cfg.account_id;
        ch.db_path = cfg.db_path;
        return ch;
    }

    pub fn channelName(_: *IMessageChannel) []const u8 {
        return "imessage";
    }

    pub fn setBus(self: *IMessageChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn isContactAllowed(self: *const IMessageChannel, sender: []const u8) bool {
        return root.isAllowed(self.allow_from, sender);
    }

    fn senderAllowedForContext(self: *const IMessageChannel, sender: []const u8, is_group: bool) bool {
        if (!is_group) return self.isContactAllowed(sender);

        if (std.mem.eql(u8, self.group_policy, "disabled")) return false;
        if (std.mem.eql(u8, self.group_policy, "open")) return true;

        const effective = if (self.group_allow_from.len > 0) self.group_allow_from else self.allow_from;
        return root.isAllowed(effective, sender);
    }

    fn currentChatDbPath(self: *const IMessageChannel, allocator: std.mem.Allocator) ![]u8 {
        if (self.db_path) |path| return allocator.dupe(u8, path);

        if (std.process.getEnvVarOwned(allocator, "IMESSAGE_CHAT_DB_PATH")) |env_path| {
            return env_path;
        } else |_| {}

        const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHomeDir;
        defer allocator.free(home);
        return std.fs.path.join(allocator, &.{ home, "Library", "Messages", "chat.db" });
    }

    fn isLikelyGroupChatGuid(chat_guid: []const u8) bool {
        if (chat_guid.len == 0) return false;
        return std.mem.startsWith(u8, chat_guid, "chat") or
            std.mem.indexOf(u8, chat_guid, ";chat") != null or
            std.mem.indexOf(u8, chat_guid, "chat;") != null;
    }

    fn groupPeerIdFromReplyTarget(reply_target: ?[]const u8) []const u8 {
        const target = reply_target orelse "unknown";
        if (std.mem.startsWith(u8, target, CHAT_TARGET_PREFIX) and target.len > CHAT_TARGET_PREFIX.len) {
            return target[CHAT_TARGET_PREFIX.len..];
        }
        return target;
    }

    pub fn healthCheck(self: *IMessageChannel) bool {
        if (builtin.is_test) return true;
        if (!self.running.load(.acquire)) return false;
        if (builtin.os.tag != .macos) return true;

        const db_path = self.currentChatDbPath(self.allocator) catch return false;
        defer self.allocator.free(db_path);
        std.fs.accessAbsolute(db_path, .{}) catch return false;
        return true;
    }

    fn pollLoop(self: *IMessageChannel) void {
        while (self.running.load(.acquire)) {
            const messages = self.pollMessages(self.allocator) catch |err| {
                log.warn("iMessage poll failed: {}", .{err});
                self.sleepWithStopCheck();
                continue;
            };

            if (messages.len > 0) {
                for (messages) |*msg| {
                    self.publishInboundMessage(msg);
                    msg.deinit(self.allocator);
                }
                self.allocator.free(messages);
            }

            self.sleepWithStopCheck();
        }
    }

    fn sleepWithStopCheck(self: *IMessageChannel) void {
        var slept: u64 = 0;
        while (self.running.load(.acquire) and slept < self.poll_interval_secs) {
            std.Thread.sleep(1 * std.time.ns_per_s);
            slept += 1;
        }
    }

    fn publishInboundMessage(self: *IMessageChannel, msg: *const root.ChannelMessage) void {
        const chat_id = msg.reply_target orelse msg.sender;
        const group_peer_id = groupPeerIdFromReplyTarget(msg.reply_target);

        const session_key = if (msg.is_group)
            std.fmt.allocPrint(self.allocator, "imessage:{s}:group:{s}", .{ self.account_id, group_peer_id }) catch return
        else
            std.fmt.allocPrint(self.allocator, "imessage:{s}:direct:{s}", .{ self.account_id, msg.sender }) catch return;
        defer self.allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(self.allocator);
        const mw = metadata_buf.writer(self.allocator);
        mw.writeByte('{') catch return;
        mw.writeAll("\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        mw.writeAll(",\"is_dm\":") catch return;
        mw.writeAll(if (msg.is_group) "false" else "true") catch return;
        mw.writeAll(",\"is_group\":") catch return;
        mw.writeAll(if (msg.is_group) "true" else "false") catch return;
        if (msg.is_group) {
            mw.writeAll(",\"channel_id\":") catch return;
            root.appendJsonStringW(mw, group_peer_id) catch return;
        }
        mw.writeByte('}') catch return;

        const inbound = bus_mod.makeInboundFull(
            self.allocator,
            "imessage",
            msg.sender,
            chat_id,
            msg.content,
            session_key,
            &.{},
            metadata_buf.items,
        ) catch return;

        if (self.bus) |b| {
            b.publishInbound(inbound) catch {
                inbound.deinit(self.allocator);
            };
        } else {
            inbound.deinit(self.allocator);
        }
    }

    fn queryMaxRowId(self: *IMessageChannel, allocator: std.mem.Allocator, db_path: []const u8) !i64 {
        _ = self;
        var db: ?*c.sqlite3 = null;
        const db_path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_z);

        const open_flags: c_int = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX;
        if (c.sqlite3_open_v2(db_path_z.ptr, &db, open_flags, null) != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }
        defer _ = c.sqlite3_close(db.?);

        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, "SELECT MAX(ROWID) FROM message WHERE is_from_me = 0", -1, &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        const rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_ROW) {
            if (c.sqlite3_column_type(stmt, 0) == c.SQLITE_NULL) return 0;
            return c.sqlite3_column_int64(stmt, 0);
        }
        if (rc == c.SQLITE_DONE) return 0;
        return error.SqliteStepFailed;
    }

    fn pollMessagesFromDb(self: *IMessageChannel, allocator: std.mem.Allocator, db_path: []const u8) ![]root.ChannelMessage {
        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer {
            for (messages.items) |*msg| msg.deinit(allocator);
            messages.deinit(allocator);
        }

        var db: ?*c.sqlite3 = null;
        const db_path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_z);

        const open_flags: c_int = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX;
        if (c.sqlite3_open_v2(db_path_z.ptr, &db, open_flags, null) != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.SqliteOpenFailed;
        }
        defer _ = c.sqlite3_close(db.?);

        const sql =
            \\SELECT m.ROWID, h.id, m.text, c.guid
            \\FROM message m
            \\JOIN handle h ON m.handle_id = h.ROWID
            \\LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
            \\LEFT JOIN chat c ON c.ROWID = cmj.chat_id
            \\WHERE m.ROWID > ?1
            \\  AND m.is_from_me = 0
            \\  AND m.text IS NOT NULL
            \\ORDER BY m.ROWID ASC
            \\LIMIT ?2
        ;

        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, sql, -1, &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        if (c.sqlite3_bind_int64(stmt, 1, self.last_rowid) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_bind_int(stmt, 2, POLL_BATCH_LIMIT) != c.SQLITE_OK) return error.SqliteBindFailed;

        var max_rowid = self.last_rowid;

        while (true) {
            const rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_DONE) break;
            if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;

            const rowid = c.sqlite3_column_int64(stmt, 0);
            if (rowid > max_rowid) max_rowid = rowid;

            const sender_ptr = c.sqlite3_column_text(stmt, 1) orelse continue;
            const sender_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
            if (sender_len == 0) continue;
            const sender = sender_ptr[0..sender_len];

            const text_ptr = c.sqlite3_column_text(stmt, 2) orelse continue;
            const text_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
            if (text_len == 0) continue;
            const text = text_ptr[0..text_len];
            if (std.mem.trim(u8, text, " \t\r\n").len == 0) continue;

            var chat_guid_opt: ?[]const u8 = null;
            if (c.sqlite3_column_type(stmt, 3) != c.SQLITE_NULL) {
                const chat_ptr = c.sqlite3_column_text(stmt, 3);
                const chat_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
                if (chat_len > 0) chat_guid_opt = chat_ptr[0..chat_len];
            }

            const is_group = if (chat_guid_opt) |guid| isLikelyGroupChatGuid(guid) else false;
            if (!self.senderAllowedForContext(sender, is_group)) continue;

            const reply_target = if (is_group and chat_guid_opt != null)
                try std.fmt.allocPrint(allocator, "chat:{s}", .{chat_guid_opt.?})
            else
                try allocator.dupe(u8, sender);
            errdefer allocator.free(reply_target);

            const id = try std.fmt.allocPrint(allocator, "{d}", .{rowid});
            errdefer allocator.free(id);
            const sender_dup = try allocator.dupe(u8, sender);
            errdefer allocator.free(sender_dup);
            const text_dup = try allocator.dupe(u8, text);
            errdefer allocator.free(text_dup);

            try messages.append(allocator, .{
                .id = id,
                .sender = sender_dup,
                .content = text_dup,
                .channel = "imessage",
                .timestamp = root.nowEpochSecs(),
                .reply_target = reply_target,
                .first_name = null,
                .is_group = is_group,
            });
        }

        self.last_rowid = max_rowid;
        return messages.toOwnedSlice(allocator);
    }

    /// Poll messages from Messages.app SQLite database.
    ///
    /// On first call, initializes cursor to latest row and returns empty (skip backlog).
    pub fn pollMessages(self: *IMessageChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        if (builtin.os.tag != .macos and !builtin.is_test) return &.{};

        const db_path = try self.currentChatDbPath(allocator);
        defer allocator.free(db_path);

        std.fs.accessAbsolute(db_path, .{}) catch return &.{};

        if (!self.cursor_initialized) {
            self.last_rowid = try self.queryMaxRowId(allocator, db_path);
            self.cursor_initialized = true;
            return &.{};
        }

        return self.pollMessagesFromDb(allocator, db_path);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message via macOS iMessage using osascript.
    /// Validates target format and escapes all interpolated values.
    pub fn sendMessage(self: *IMessageChannel, target: []const u8, message: []const u8) !void {
        const parsed_target = try parseSendTarget(target);
        const escaped_msg = try escapeAppleScript(self.allocator, message);
        defer self.allocator.free(escaped_msg);

        if (builtin.is_test) return;

        const script = switch (parsed_target) {
            .participant => |participant| blk: {
                const escaped_target = try escapeAppleScript(self.allocator, participant);
                defer self.allocator.free(escaped_target);

                break :blk try std.fmt.allocPrint(
                    self.allocator,
                    "tell application \"Messages\"\n" ++
                        "    set targetService to 1st account whose service type = iMessage\n" ++
                        "    set targetBuddy to participant \"{s}\" of targetService\n" ++
                        "    send \"{s}\" to targetBuddy\n" ++
                        "end tell",
                    .{ escaped_target, escaped_msg },
                );
            },
            .chat_guid => |chat_guid| blk: {
                const escaped_chat_guid = try escapeAppleScript(self.allocator, chat_guid);
                defer self.allocator.free(escaped_chat_guid);

                break :blk try std.fmt.allocPrint(
                    self.allocator,
                    "tell application \"Messages\"\n" ++
                        "    set targetChat to chat id \"{s}\"\n" ++
                        "    send \"{s}\" to targetChat\n" ++
                        "end tell",
                    .{ escaped_chat_guid, escaped_msg },
                );
            },
        };
        defer self.allocator.free(script);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{ "osascript", "-e", script },
        }) catch return error.IMessageSendFailed;
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        switch (result.term) {
            .Exited => |code| if (code != 0) return error.IMessageSendFailed,
            else => return error.IMessageSendFailed,
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);
        errdefer self.running.store(false, .release);

        if (builtin.is_test) return;
        if (builtin.os.tag != .macos) return;

        self.poll_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, pollLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        if (self.poll_thread) |t| {
            t.join();
            self.poll_thread = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *IMessageChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

const ParsedSendTarget = union(enum) {
    participant: []const u8,
    chat_guid: []const u8,
};

fn parseSendTarget(target: []const u8) !ParsedSendTarget {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidTarget;

    if (std.mem.startsWith(u8, trimmed, CHAT_TARGET_PREFIX)) {
        const guid = std.mem.trim(u8, trimmed[CHAT_TARGET_PREFIX.len..], " \t\r\n");
        if (!isValidChatGuid(guid)) return error.InvalidTarget;
        return .{ .chat_guid = guid };
    }

    if (!isValidTarget(trimmed)) return error.InvalidTarget;
    return .{ .participant = trimmed };
}

// ════════════════════════════════════════════════════════════════════════════
// AppleScript Escaping (CWE-78 Prevention)
// ════════════════════════════════════════════════════════════════════════════

/// Escape a string for safe interpolation into AppleScript.
/// Prevents injection by escaping backslashes, quotes, and newlines.
pub fn escapeAppleScript(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    for (s) |ch| {
        switch (ch) {
            '\\' => {
                try result.append(allocator, '\\');
                try result.append(allocator, '\\');
            },
            '"' => {
                try result.append(allocator, '\\');
                try result.append(allocator, '"');
            },
            '\n' => {
                try result.append(allocator, '\\');
                try result.append(allocator, 'n');
            },
            '\r' => {
                try result.append(allocator, '\\');
                try result.append(allocator, 'r');
            },
            else => try result.append(allocator, ch),
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Validate participant target (phone/email).
pub fn isValidTarget(target: []const u8) bool {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return false;

    // Phone number: +digits (with optional spaces/dashes), 7-15 digits
    if (trimmed[0] == '+') {
        var digit_count: usize = 0;
        for (trimmed[1..]) |c1| {
            if (std.ascii.isDigit(c1)) {
                digit_count += 1;
            } else if (c1 != ' ' and c1 != '-') {
                return false;
            }
        }
        return digit_count >= 7 and digit_count <= 15;
    }

    // Email: local@domain.tld
    const at_pos = std.mem.indexOf(u8, trimmed, "@") orelse return false;
    if (at_pos == 0) return false;
    const local = trimmed[0..at_pos];
    const domain = trimmed[at_pos + 1 ..];
    if (domain.len == 0) return false;
    if (std.mem.indexOf(u8, domain, ".") == null) return false;

    for (local) |c1| {
        if (!std.ascii.isAlphanumeric(c1) and c1 != '.' and c1 != '_' and c1 != '+' and c1 != '-') return false;
    }
    for (domain) |c1| {
        if (!std.ascii.isAlphanumeric(c1) and c1 != '.' and c1 != '-') return false;
    }
    return true;
}

/// Validate a chat GUID target used as `chat:<guid>`.
pub fn isValidChatGuid(chat_guid: []const u8) bool {
    if (chat_guid.len == 0) return false;
    for (chat_guid) |c1| {
        if (!std.ascii.isAlphanumeric(c1) and
            c1 != ':' and c1 != ';' and c1 != '-' and c1 != '_' and c1 != '+' and c1 != '.')
        {
            return false;
        }
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

fn createTestDb(allocator: std.mem.Allocator) ![]u8 {
    const tmp_dir = try platform.getTempDir(allocator);
    defer allocator.free(tmp_dir);
    const filename = try std.fmt.allocPrint(allocator, "nullclaw_imessage_{d}_{x}.db", .{
        std.time.microTimestamp(),
        std.crypto.random.int(u32),
    });
    defer allocator.free(filename);
    const path = try std.fs.path.join(allocator, &.{ tmp_dir, filename });

    var db: ?*c.sqlite3 = null;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    if (c.sqlite3_open_v2(path_z.ptr, &db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null) != c.SQLITE_OK) {
        if (db) |d| _ = c.sqlite3_close(d);
        allocator.free(path);
        return error.SqliteOpenFailed;
    }
    defer _ = c.sqlite3_close(db.?);

    const schema =
        \\CREATE TABLE IF NOT EXISTS handle (
        \\  ROWID INTEGER PRIMARY KEY,
        \\  id TEXT NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS message (
        \\  ROWID INTEGER PRIMARY KEY,
        \\  handle_id INTEGER,
        \\  text TEXT,
        \\  is_from_me INTEGER DEFAULT 0
        \\);
        \\CREATE TABLE IF NOT EXISTS chat (
        \\  ROWID INTEGER PRIMARY KEY,
        \\  guid TEXT NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS chat_message_join (
        \\  chat_id INTEGER,
        \\  message_id INTEGER
        \\);
    ;

    var err_msg: [*c]u8 = null;
    if (c.sqlite3_exec(db.?, schema, null, null, &err_msg) != c.SQLITE_OK) {
        if (err_msg != null) c.sqlite3_free(err_msg);
        allocator.free(path);
        return error.SqliteExecFailed;
    }

    return path;
}

fn insertTestMessage(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    rowid: i64,
    sender: []const u8,
    text: []const u8,
    is_from_me: bool,
    chat_guid: ?[]const u8,
) !void {
    var db: ?*c.sqlite3 = null;
    const path_z = try allocator.dupeZ(u8, db_path);
    defer allocator.free(path_z);
    if (c.sqlite3_open_v2(path_z.ptr, &db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null) != c.SQLITE_OK) {
        if (db) |d| _ = c.sqlite3_close(d);
        return error.SqliteOpenFailed;
    }
    defer _ = c.sqlite3_close(db.?);

    // handle row
    {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, "INSERT OR REPLACE INTO handle (ROWID, id) VALUES (1, ?1)", -1, &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        if (c.sqlite3_bind_text(stmt, 1, sender.ptr, @intCast(sender.len), SQLITE_STATIC) != c.SQLITE_OK) {
            return error.SqliteBindFailed;
        }
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.SqliteStepFailed;
    }

    // message row
    {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, "INSERT INTO message (ROWID, handle_id, text, is_from_me) VALUES (?1, 1, ?2, ?3)", -1, &stmt, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        if (c.sqlite3_bind_int64(stmt, 1, rowid) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_bind_text(stmt, 2, text.ptr, @intCast(text.len), SQLITE_STATIC) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_bind_int(stmt, 3, if (is_from_me) 1 else 0) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.SqliteStepFailed;
    }

    if (chat_guid) |guid| {
        var stmt_chat: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, "INSERT OR REPLACE INTO chat (ROWID, guid) VALUES (1, ?1)", -1, &stmt_chat, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt_chat);
        if (c.sqlite3_bind_text(stmt_chat, 1, guid.ptr, @intCast(guid.len), SQLITE_STATIC) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_step(stmt_chat) != c.SQLITE_DONE) return error.SqliteStepFailed;

        var stmt_join: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.?, "INSERT INTO chat_message_join (chat_id, message_id) VALUES (1, ?1)", -1, &stmt_join, null) != c.SQLITE_OK) {
            return error.SqlitePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt_join);
        if (c.sqlite3_bind_int64(stmt_join, 1, rowid) != c.SQLITE_OK) return error.SqliteBindFailed;
        if (c.sqlite3_step(stmt_join) != c.SQLITE_DONE) return error.SqliteStepFailed;
    }
}

test "escape applescript double quotes" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "hello \"world\"");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello \\\"world\\\"", result);
}

test "escape applescript backslashes" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "path\\to\\file");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("path\\\\to\\\\file", result);
}

test "escape applescript newlines" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "line1\nline2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("line1\\nline2", result);
}

test "escape applescript injection attempt" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "\" & do shell script \"id\" & \"");
    defer allocator.free(result);
    for (result, 0..) |c1, i| {
        if (c1 == '"') {
            try std.testing.expect(i > 0 and result[i - 1] == '\\');
        }
    }
}

test "valid target phone" {
    try std.testing.expect(isValidTarget("+1234567890"));
    try std.testing.expect(isValidTarget("+1 415 555 1234"));
}

test "valid target email" {
    try std.testing.expect(isValidTarget("user@example.com"));
    try std.testing.expect(isValidTarget("user+tag@example.com"));
}

test "invalid target injection attempt" {
    try std.testing.expect(!isValidTarget("\" & do shell script \"id\" & \""));
}

test "valid chat guid target" {
    try std.testing.expect(isValidChatGuid("chat1234"));
    try std.testing.expect(isValidChatGuid("iMessage;-;chat123"));
    try std.testing.expect(!isValidChatGuid("chat\nbad"));
}

test "imessage creates with contacts" {
    const contacts = [_][]const u8{"+1234567890"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts, &.{}, "allowlist");
    try std.testing.expectEqual(@as(usize, 1), ch.allow_from.len);
    try std.testing.expectEqual(@as(u64, 3), ch.poll_interval_secs);
}

test "imessage contact allowlist is case insensitive" {
    const contacts = [_][]const u8{"User@iCloud.com"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts, &.{}, "allowlist");
    try std.testing.expect(ch.isContactAllowed("user@icloud.com"));
    try std.testing.expect(ch.isContactAllowed("USER@ICLOUD.COM"));
}

test "pollMessagesFromDb parses direct message" {
    const allocator = std.testing.allocator;
    const db_path = try createTestDb(allocator);
    defer allocator.free(db_path);
    defer std.fs.deleteFileAbsolute(db_path) catch {};

    try insertTestMessage(allocator, db_path, 1, "+1234567890", "hello", false, null);

    var ch = IMessageChannel.init(allocator, &.{"*"}, &.{}, "allowlist");
    ch.cursor_initialized = true;

    const msgs = try ch.pollMessagesFromDb(allocator, db_path);
    defer {
        for (msgs) |*msg| msg.deinit(allocator);
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].reply_target.?);
    try std.testing.expect(!msgs[0].is_group);
}

test "pollMessagesFromDb parses group chat and uses chat reply target" {
    const allocator = std.testing.allocator;
    const db_path = try createTestDb(allocator);
    defer allocator.free(db_path);
    defer std.fs.deleteFileAbsolute(db_path) catch {};

    try insertTestMessage(allocator, db_path, 2, "+1234567890", "group hello", false, "chat12345");

    var ch = IMessageChannel.init(allocator, &.{}, &.{"*"}, "allowlist");
    ch.cursor_initialized = true;

    const msgs = try ch.pollMessagesFromDb(allocator, db_path);
    defer {
        for (msgs) |*msg| msg.deinit(allocator);
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].is_group);
    try std.testing.expectEqualStrings("chat:chat12345", msgs[0].reply_target.?);
}

test "pollMessages initializes cursor and skips backlog on first call" {
    const allocator = std.testing.allocator;
    const db_path = try createTestDb(allocator);
    defer allocator.free(db_path);
    defer std.fs.deleteFileAbsolute(db_path) catch {};

    try insertTestMessage(allocator, db_path, 10, "+1234567890", "old", false, null);

    var ch = IMessageChannel.init(allocator, &.{"*"}, &.{}, "allowlist");
    ch.db_path = db_path;

    const first = try ch.pollMessages(allocator);
    defer allocator.free(first);
    try std.testing.expectEqual(@as(usize, 0), first.len);

    try insertTestMessage(allocator, db_path, 11, "+1234567890", "new", false, null);

    const second = try ch.pollMessages(allocator);
    defer {
        for (second) |*msg| msg.deinit(allocator);
        allocator.free(second);
    }
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqualStrings("new", second[0].content);
}

test "imessage senderAllowedForContext respects group policy and fallback allowlists" {
    const allocator = std.testing.allocator;

    var ch = IMessageChannel.init(allocator, &.{"user-a"}, &.{}, "allowlist");
    try std.testing.expect(ch.senderAllowedForContext("user-a", false));
    try std.testing.expect(!ch.senderAllowedForContext("user-b", false));

    // Group allowlist falls back to allow_from when group_allow_from is empty.
    try std.testing.expect(ch.senderAllowedForContext("user-a", true));
    try std.testing.expect(!ch.senderAllowedForContext("user-b", true));

    // group_allow_from overrides fallback when configured.
    ch.group_allow_from = &.{"user-b"};
    try std.testing.expect(ch.senderAllowedForContext("user-b", true));
    try std.testing.expect(!ch.senderAllowedForContext("user-a", true));

    // Open policy bypasses allowlists.
    ch.group_policy = "open";
    try std.testing.expect(ch.senderAllowedForContext("anyone", true));

    // Disabled policy blocks all group senders.
    ch.group_policy = "disabled";
    try std.testing.expect(!ch.senderAllowedForContext("user-b", true));
}

test "imessage publishInboundMessage emits group session key and metadata" {
    const allocator = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = IMessageChannel.init(allocator, &.{"*"}, &.{}, "allowlist");
    ch.account_id = "ios-main";
    ch.setBus(&eb);

    var msg = root.ChannelMessage{
        .id = try allocator.dupe(u8, "42"),
        .sender = try allocator.dupe(u8, "+15550001111"),
        .content = try allocator.dupe(u8, "hello"),
        .channel = "imessage",
        .timestamp = root.nowEpochSecs(),
        .reply_target = try allocator.dupe(u8, "chat:chat-guid-1"),
        .is_group = true,
    };
    defer msg.deinit(allocator);

    ch.publishInboundMessage(&msg);

    var inbound = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer inbound.deinit(allocator);

    try std.testing.expectEqualStrings("imessage", inbound.channel);
    try std.testing.expectEqualStrings("+15550001111", inbound.sender_id);
    try std.testing.expectEqualStrings("chat:chat-guid-1", inbound.chat_id);
    try std.testing.expectEqualStrings("imessage:ios-main:group:chat-guid-1", inbound.session_key);
    try std.testing.expect(inbound.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, allocator, inbound.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expectEqualStrings("ios-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(meta.value.object.get("is_group").?.bool);
    try std.testing.expectEqualStrings("chat-guid-1", meta.value.object.get("channel_id").?.string);
}

test "imessage publishInboundMessage emits direct session key and dm metadata" {
    const allocator = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = IMessageChannel.init(allocator, &.{"*"}, &.{}, "allowlist");
    ch.account_id = "ios-main";
    ch.setBus(&eb);

    var msg = root.ChannelMessage{
        .id = try allocator.dupe(u8, "99"),
        .sender = try allocator.dupe(u8, "+15550002222"),
        .content = try allocator.dupe(u8, "ping"),
        .channel = "imessage",
        .timestamp = root.nowEpochSecs(),
        .reply_target = null,
        .is_group = false,
    };
    defer msg.deinit(allocator);

    ch.publishInboundMessage(&msg);

    var inbound = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer inbound.deinit(allocator);

    try std.testing.expectEqualStrings("imessage", inbound.channel);
    try std.testing.expectEqualStrings("+15550002222", inbound.sender_id);
    try std.testing.expectEqualStrings("+15550002222", inbound.chat_id);
    try std.testing.expectEqualStrings("imessage:ios-main:direct:+15550002222", inbound.session_key);
    try std.testing.expect(inbound.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, allocator, inbound.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expectEqualStrings("ios-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(meta.value.object.get("is_dm").?.bool);
    try std.testing.expect(!meta.value.object.get("is_group").?.bool);
    try std.testing.expect(meta.value.object.get("channel_id") == null);
}
