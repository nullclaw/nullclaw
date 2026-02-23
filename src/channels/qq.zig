const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");

const log = std.log.scoped(.qq);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

pub const GATEWAY_URL = "wss://api.sgroup.qq.com/websocket";
pub const SANDBOX_GATEWAY_URL = "wss://sandbox.api.sgroup.qq.com/websocket";

pub const API_BASE = "https://api.sgroup.qq.com";
pub const SANDBOX_API_BASE = "https://sandbox.api.sgroup.qq.com";

/// QQ Gateway opcodes.
pub const Opcode = enum(u8) {
    dispatch = 0,
    heartbeat = 1,
    identify = 2,
    @"resume" = 6,
    reconnect = 7,
    invalid_session = 9,
    hello = 10,
    heartbeat_ack = 11,

    pub fn fromInt(val: i64) ?Opcode {
        return switch (val) {
            0 => .dispatch,
            1 => .heartbeat,
            2 => .identify,
            6 => .@"resume",
            7 => .reconnect,
            9 => .invalid_session,
            10 => .hello,
            11 => .heartbeat_ack,
            else => null,
        };
    }
};

/// Default intents bitmask: GUILDS | GUILD_MESSAGES | DIRECT_MESSAGE | GROUP_AT_MESSAGE
/// See: https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html
pub const DEFAULT_INTENTS: u32 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 25);

// ════════════════════════════════════════════════════════════════════════════
// CQ Code Parsing (QQ message format)
// ════════════════════════════════════════════════════════════════════════════

/// Strip CQ codes from message text, returning clean text.
/// [CQ:at,qq=123] -> stripped
/// [CQ:face,id=178] -> stripped
/// [CQ:image,...] -> stripped
/// Regular text is preserved.
pub fn stripCqCodes(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < raw.len) {
        const tag_start = std.mem.indexOfPos(u8, raw, cursor, "[CQ:") orelse {
            try result.appendSlice(allocator, raw[cursor..]);
            break;
        };

        // Append text before the tag
        try result.appendSlice(allocator, raw[cursor..tag_start]);

        // Find closing ]
        const tag_end = std.mem.indexOfPos(u8, raw, tag_start, "]") orelse {
            // Malformed tag — treat as plain text
            try result.appendSlice(allocator, raw[tag_start..]);
            break;
        };

        cursor = tag_end + 1;
    }

    return result.toOwnedSlice(allocator);
}

/// Extract the mentioned QQ number from a CQ-coded string.
/// Returns null if no [CQ:at,qq=...] tag is found.
pub fn extractMentionQQ(raw: []const u8) ?[]const u8 {
    const at_tag = "[CQ:at,qq=";
    const start = std.mem.indexOf(u8, raw, at_tag) orelse return null;
    const val_start = start + at_tag.len;
    const end = std.mem.indexOfPos(u8, raw, val_start, "]") orelse return null;
    return raw[val_start..end];
}

// ════════════════════════════════════════════════════════════════════════════
// Message Deduplication (Ring Buffer)
// ════════════════════════════════════════════════════════════════════════════

pub const DEDUP_RING_SIZE: usize = 1024;

/// Ring buffer for message ID deduplication.
/// Stores the last DEDUP_RING_SIZE message IDs in a circular buffer.
pub const DedupRing = struct {
    buf: [DEDUP_RING_SIZE]u64 = [_]u64{0} ** DEDUP_RING_SIZE,
    idx: u32 = 0,
    count: u32 = 0,

    /// Check if message_id was already seen. If not, record it and return false.
    /// Returns true if the message is a duplicate.
    pub fn isDuplicate(self: *DedupRing, message_id: u64) bool {
        const check_count = @min(self.count, DEDUP_RING_SIZE);
        for (0..check_count) |i| {
            if (self.buf[i] == message_id) return true;
        }
        self.buf[self.idx] = message_id;
        self.idx = @intCast((self.idx + 1) % @as(u32, DEDUP_RING_SIZE));
        if (self.count < DEDUP_RING_SIZE) self.count += 1;
        return false;
    }

    /// Reset the ring buffer.
    pub fn reset(self: *DedupRing) void {
        self.idx = 0;
        self.count = 0;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Message Formatting
// ════════════════════════════════════════════════════════════════════════════

/// Build the IDENTIFY payload for QQ Gateway WebSocket.
/// Format: {"op":2,"d":{"token":"Bot {app_id}.{bot_token}","intents":N,"shard":[0,1]}}
pub fn buildIdentifyPayload(buf: []u8, app_id: []const u8, bot_token: []const u8, intents: u32) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.print("{{\"op\":2,\"d\":{{\"token\":\"Bot {s}.{s}\",\"intents\":{d},\"shard\":[0,1]}}}}", .{
        app_id,
        bot_token,
        intents,
    });
    return fbs.getWritten();
}

/// Build a heartbeat payload.
/// Format: {"op":1,"d":N} where N is the last sequence number (or null).
pub fn buildHeartbeatPayload(buf: []u8, sequence: ?i64) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    if (sequence) |seq| {
        try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
    } else {
        try w.writeAll("{\"op\":1,\"d\":null}");
    }
    return fbs.getWritten();
}

/// Build the REST API URL for sending a message to a channel.
pub fn buildSendUrl(buf: []u8, base: []const u8, channel_id: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.print("{s}/channels/{s}/messages", .{ base, channel_id });
    return fbs.getWritten();
}

/// Build the REST API URL for sending a DM (direct message).
pub fn buildDmUrl(buf: []u8, base: []const u8, guild_id: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.print("{s}/dms/{s}/messages", .{ base, guild_id });
    return fbs.getWritten();
}

/// Build a message send body.
/// Format: {"content":"...", "msg_id":"..."}
pub fn buildSendBody(allocator: std.mem.Allocator, content: []const u8, msg_id: ?[]const u8) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);

    try body_list.appendSlice(allocator, "{\"content\":");
    try root.json_util.appendJsonString(&body_list, allocator, content);
    if (msg_id) |mid| {
        try body_list.appendSlice(allocator, ",\"msg_id\":");
        try root.json_util.appendJsonString(&body_list, allocator, mid);
    }
    try body_list.appendSlice(allocator, "}");

    return body_list.toOwnedSlice(allocator);
}

/// Build auth token string: "Bot {app_id}.{bot_token}"
pub fn buildAuthToken(buf: []u8, app_id: []const u8, bot_token: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.print("Bot {s}.{s}", .{ app_id, bot_token });
    return fbs.getWritten();
}

/// Build auth header value: "Authorization: Bot {app_id}.{bot_token}"
pub fn buildAuthHeader(buf: []u8, app_id: []const u8, bot_token: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.print("Authorization: Bot {s}.{s}", .{ app_id, bot_token });
    return fbs.getWritten();
}

/// Check if a group ID is allowed by the given config.
pub fn isGroupAllowed(config: config_types.QQConfig, group_id: []const u8) bool {
    return switch (config.group_policy) {
        .allow => true,
        .allowlist => root.isAllowedExact(config.allowed_groups, group_id),
    };
}

/// Get the API base URL (sandbox or production).
pub fn apiBase(sandbox: bool) []const u8 {
    return if (sandbox) SANDBOX_API_BASE else API_BASE;
}

/// Get the Gateway URL (sandbox or production).
pub fn gatewayUrl(sandbox: bool) []const u8 {
    return if (sandbox) SANDBOX_GATEWAY_URL else GATEWAY_URL;
}

// ════════════════════════════════════════════════════════════════════════════
// QQChannel
// ════════════════════════════════════════════════════════════════════════════

/// QQ Bot API channel.
///
/// Connects to the QQ Gateway via WebSocket for real-time messages.
/// Handles opcodes: HELLO (10), DISPATCH (0), HEARTBEAT_ACK (11), RECONNECT (7).
/// Sends replies via REST API POST to /channels/{id}/messages or /dms/{id}/messages.
/// Message deduplication via ring buffer of 1024 recent message IDs.
/// Auto-reconnect with 5s backoff.
pub const QQChannel = struct {
    config: config_types.QQConfig,
    allocator: std.mem.Allocator,
    event_bus: ?*bus.Bus,
    dedup: DedupRing,
    sequence: ?i64,
    heartbeat_interval_ms: u32,
    session_id: ?[]const u8,
    running: bool,

    pub const MAX_MESSAGE_LEN: usize = 4096;
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, config: config_types.QQConfig) QQChannel {
        return .{
            .config = config,
            .allocator = allocator,
            .event_bus = null,
            .dedup = .{},
            .sequence = null,
            .heartbeat_interval_ms = 0,
            .session_id = null,
            .running = false,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.QQConfig) QQChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *QQChannel) []const u8 {
        return "qq";
    }

    pub fn healthCheck(self: *QQChannel) bool {
        return self.running;
    }

    /// Set the event bus for publishing inbound messages.
    pub fn setBus(self: *QQChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    // ── Incoming event handling ──────────────────────────────────────

    /// Handle a parsed WebSocket event JSON from the QQ gateway.
    pub fn handleGatewayEvent(self: *QQChannel, raw_json: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, raw_json, .{}) catch {
            log.warn("failed to parse QQ gateway event JSON", .{});
            return;
        };
        defer parsed.deinit();
        const val = parsed.value;

        // Extract opcode
        if (val != .object) return;
        const op_val = val.object.get("op") orelse return;
        const op_int: i64 = switch (op_val) {
            .integer => op_val.integer,
            else => return,
        };
        const op = Opcode.fromInt(op_int) orelse return;

        // Update sequence number
        if (val.object.get("s")) |s_val| {
            if (s_val == .integer) {
                self.sequence = s_val.integer;
            }
        }

        switch (op) {
            .hello => {
                // Extract heartbeat_interval from d.heartbeat_interval
                if (val.object.get("d")) |d_val| {
                    if (d_val == .object) {
                        if (d_val.object.get("heartbeat_interval")) |hb_val| {
                            if (hb_val == .integer and hb_val.integer > 0) {
                                self.heartbeat_interval_ms = @intCast(@min(hb_val.integer, std.math.maxInt(u32)));
                            }
                        }
                    }
                }
                log.info("QQ Gateway HELLO: heartbeat_interval={d}ms", .{self.heartbeat_interval_ms});
            },
            .dispatch => {
                const event_type = getJsonString(val, "t") orelse return;
                if (std.mem.eql(u8, event_type, "READY")) {
                    // Extract session_id from d.session_id
                    if (val.object.get("d")) |d_val| {
                        if (getJsonStringFromObj(d_val, "session_id")) |sid| {
                            if (self.session_id) |old| self.allocator.free(old);
                            self.session_id = self.allocator.dupe(u8, sid) catch null;
                        }
                    }
                    self.running = true;
                    log.info("QQ Gateway READY", .{});
                } else if (std.mem.eql(u8, event_type, "MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "AT_MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "DIRECT_MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "GROUP_AT_MESSAGE_CREATE"))
                {
                    try self.handleMessageCreate(val, event_type);
                }
            },
            .heartbeat_ack => {
                // Heartbeat acknowledged — connection is healthy
            },
            .reconnect => {
                log.info("QQ Gateway RECONNECT requested", .{});
                self.running = false;
            },
            .invalid_session => {
                log.warn("QQ Gateway INVALID_SESSION", .{});
                self.running = false;
            },
            else => {},
        }
    }

    fn handleMessageCreate(self: *QQChannel, val: std.json.Value, event_type: []const u8) !void {
        const d = val.object.get("d") orelse return;
        if (d != .object) return;

        // Extract message ID for dedup
        const msg_id_str = getJsonStringFromObj(d, "id") orelse return;
        const msg_id_hash = std.hash.Fnv1a_64.hash(msg_id_str);
        if (self.dedup.isDuplicate(msg_id_hash)) return;

        // Determine if it's a DM
        const is_dm = std.mem.eql(u8, event_type, "DIRECT_MESSAGE_CREATE");

        // Extract channel_id
        const channel_id = getJsonStringFromObj(d, "channel_id") orelse "";

        // Check group policy
        if (!is_dm and self.config.group_policy == .allowlist) {
            const guild_id = getJsonStringFromObj(d, "guild_id") orelse "";
            if (!isGroupAllowed(self.config, guild_id) and !isGroupAllowed(self.config, channel_id)) {
                return;
            }
        }

        // Extract sender info
        const author = d.object.get("author") orelse return;
        const sender_id = getJsonStringFromObj(author, "id") orelse "unknown";

        // Allowlist check
        if (self.config.allow_from.len > 0 and !root.isAllowed(self.config.allow_from, sender_id)) return;

        // Extract content and strip CQ codes
        const raw_content = getJsonStringFromObj(d, "content") orelse "";
        const content = stripCqCodes(self.allocator, raw_content) catch return;
        defer self.allocator.free(content);

        // Trim whitespace
        const trimmed = std.mem.trim(u8, content, " \t\n\r");
        if (trimmed.len == 0) return;

        // Build session key
        var session_buf: [128]u8 = undefined;
        const session_key = std.fmt.bufPrint(&session_buf, "qq:{s}", .{
            if (channel_id.len > 0) channel_id else sender_id,
        }) catch return;

        // Build target for replies (prefixed for parseTarget compatibility)
        const raw_reply_id = if (is_dm)
            getJsonStringFromObj(d, "guild_id") orelse channel_id
        else
            channel_id;
        if (raw_reply_id.len == 0) return;

        var reply_buf: [160]u8 = undefined;
        const reply_target = if (is_dm)
            std.fmt.bufPrint(&reply_buf, "dm:{s}", .{raw_reply_id}) catch return
        else
            std.fmt.bufPrint(&reply_buf, "channel:{s}", .{raw_reply_id}) catch return;

        // Build metadata JSON
        var meta_buf: [256]u8 = undefined;
        var meta_fbs = std.io.fixedBufferStream(&meta_buf);
        const mw = meta_fbs.writer();
        mw.print("{{\"msg_id\":\"{s}\",\"is_dm\":{s},\"channel_id\":\"{s}\"", .{
            msg_id_str,
            if (is_dm) "true" else "false",
            raw_reply_id,
        }) catch return;
        mw.writeAll(",\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.config.account_id) catch return;
        mw.writeByte('}') catch return;
        const metadata = meta_fbs.getWritten();

        const msg = bus.makeInboundFull(
            self.allocator,
            "qq",
            sender_id,
            reply_target,
            trimmed,
            session_key,
            &.{},
            metadata,
        ) catch |err| {
            log.err("failed to create InboundMessage: {}", .{err});
            return;
        };

        if (self.event_bus) |eb| {
            eb.publishInbound(msg) catch |err| {
                log.err("failed to publish inbound: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            msg.deinit(self.allocator);
        }
    }

    // ── Outbound send ────────────────────────────────────────────────

    /// Send a message to a QQ channel or DM via REST API.
    /// Target format: "channel:<channel_id>" or "dm:<guild_id>" or just "<channel_id>".
    pub fn sendMessage(self: *QQChannel, target: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(target, chunk);
        }
    }

    fn sendChunk(self: *QQChannel, target: []const u8, text: []const u8) !void {
        const msg_type, const id_str = parseTarget(target);

        const base = apiBase(self.config.sandbox);

        // Build URL
        var url_buf: [512]u8 = undefined;
        const url = if (std.mem.eql(u8, msg_type, "dm"))
            try buildDmUrl(&url_buf, base, id_str)
        else
            try buildSendUrl(&url_buf, base, id_str);

        // Build body
        const body = try buildSendBody(self.allocator, text, null);
        defer self.allocator.free(body);

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        const auth_header = try buildAuthHeader(&auth_buf, self.config.app_id, self.config.bot_token);

        const resp = root.http_util.curlPost(self.allocator, url, body, &.{auth_header}) catch |err| {
            log.err("QQ API POST failed: {}", .{err});
            return error.QQApiError;
        };
        self.allocator.free(resp);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
        log.info("QQ channel started (sandbox={s})", .{if (self.config.sandbox) "true" else "false"});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
        if (self.session_id) |sid| {
            self.allocator.free(sid);
            self.session_id = null;
        }
        log.info("QQ channel stopped", .{});
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *QQChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Parse target string into (type, id).
/// "channel:12345" -> ("channel", "12345")
/// "dm:12345"      -> ("dm", "12345")
/// "12345"         -> ("channel", "12345")
fn parseTarget(target: []const u8) struct { []const u8, []const u8 } {
    if (std.mem.indexOf(u8, target, ":")) |colon| {
        return .{ target[0..colon], target[colon + 1 ..] };
    }
    return .{ "channel", target };
}

/// Get a string field from a JSON object value.
fn getJsonString(val: std.json.Value, key: []const u8) ?[]const u8 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return if (field == .string) field.string else null;
}

/// Get a string field from a JSON object value (alias for nested access).
fn getJsonStringFromObj(val: std.json.Value, key: []const u8) ?[]const u8 {
    return getJsonString(val, key);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "qq config defaults" {
    const config = config_types.QQConfig{};
    try std.testing.expectEqualStrings("", config.app_id);
    try std.testing.expectEqualStrings("", config.app_secret);
    try std.testing.expectEqualStrings("", config.bot_token);
    try std.testing.expect(!config.sandbox);
    try std.testing.expect(config.group_policy == .allow);
    try std.testing.expectEqual(@as(usize, 0), config.allowed_groups.len);
}

test "qq config custom values" {
    const list = [_][]const u8{ "group1", "group2" };
    const config = config_types.QQConfig{
        .app_id = "12345",
        .app_secret = "secret",
        .bot_token = "token",
        .sandbox = true,
        .group_policy = .allowlist,
        .allowed_groups = &list,
    };
    try std.testing.expectEqualStrings("12345", config.app_id);
    try std.testing.expectEqualStrings("secret", config.app_secret);
    try std.testing.expect(config.sandbox);
    try std.testing.expect(config.group_policy == .allowlist);
    try std.testing.expectEqual(@as(usize, 2), config.allowed_groups.len);
}

test "qq opcode fromInt" {
    try std.testing.expect(Opcode.fromInt(0) == .dispatch);
    try std.testing.expect(Opcode.fromInt(1) == .heartbeat);
    try std.testing.expect(Opcode.fromInt(2) == .identify);
    try std.testing.expect(Opcode.fromInt(6) == .@"resume");
    try std.testing.expect(Opcode.fromInt(7) == .reconnect);
    try std.testing.expect(Opcode.fromInt(9) == .invalid_session);
    try std.testing.expect(Opcode.fromInt(10) == .hello);
    try std.testing.expect(Opcode.fromInt(11) == .heartbeat_ack);
    try std.testing.expect(Opcode.fromInt(99) == null);
    try std.testing.expect(Opcode.fromInt(-1) == null);
}

test "qq stripCqCodes plain text no tags" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "hello world");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "qq stripCqCodes removes at tag" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "[CQ:at,qq=123456] hello");
    defer alloc.free(result);
    try std.testing.expectEqualStrings(" hello", result);
}

test "qq stripCqCodes removes multiple tags" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "[CQ:at,qq=111] hi [CQ:image,file=pic.png]");
    defer alloc.free(result);
    try std.testing.expectEqualStrings(" hi ", result);
}

test "qq stripCqCodes empty string" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "qq stripCqCodes malformed tag preserved" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "broken [CQ:image,file=x");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("broken [CQ:image,file=x", result);
}

test "qq stripCqCodes face tag stripped" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "hi [CQ:face,id=178] there");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hi  there", result);
}

test "qq extractMentionQQ finds mention" {
    const qq = extractMentionQQ("[CQ:at,qq=123456] hello");
    try std.testing.expectEqualStrings("123456", qq.?);
}

test "qq extractMentionQQ returns null for no mention" {
    try std.testing.expect(extractMentionQQ("hello world") == null);
}

test "qq extractMentionQQ malformed returns null" {
    try std.testing.expect(extractMentionQQ("[CQ:at,qq=") == null);
}

test "qq dedup ring basic" {
    var ring = DedupRing{};
    try std.testing.expect(!ring.isDuplicate(100));
    try std.testing.expect(ring.isDuplicate(100));
    try std.testing.expect(!ring.isDuplicate(200));
    try std.testing.expect(ring.isDuplicate(200));
}

test "qq dedup ring wraps around" {
    var ring = DedupRing{};
    for (1..DEDUP_RING_SIZE + 1) |i| {
        try std.testing.expect(!ring.isDuplicate(@intCast(i)));
    }
    for (1..DEDUP_RING_SIZE + 1) |i| {
        try std.testing.expect(ring.isDuplicate(@intCast(i)));
    }
    // Push one more — should evict the oldest (1)
    try std.testing.expect(!ring.isDuplicate(DEDUP_RING_SIZE + 1));
    // ID 1 was evicted, so it should no longer be found
    try std.testing.expect(!ring.isDuplicate(1));
}

test "qq dedup ring reset" {
    var ring = DedupRing{};
    _ = ring.isDuplicate(42);
    try std.testing.expect(ring.isDuplicate(42));
    ring.reset();
    try std.testing.expect(!ring.isDuplicate(42));
}

test "qq buildIdentifyPayload" {
    var buf: [512]u8 = undefined;
    const payload = try buildIdentifyPayload(&buf, "myapp", "mytoken", DEFAULT_INTENTS);
    // Verify it starts correctly
    try std.testing.expect(std.mem.startsWith(u8, payload, "{\"op\":2,\"d\":{\"token\":\"Bot myapp.mytoken\""));
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"shard\":[0,1]") != null);
}

test "qq buildHeartbeatPayload with sequence" {
    var buf: [64]u8 = undefined;
    const payload = try buildHeartbeatPayload(&buf, 42);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":42}", payload);
}

test "qq buildHeartbeatPayload null sequence" {
    var buf: [64]u8 = undefined;
    const payload = try buildHeartbeatPayload(&buf, null);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":null}", payload);
}

test "qq buildSendUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildSendUrl(&buf, API_BASE, "chan123");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/channels/chan123/messages", url);
}

test "qq buildDmUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildDmUrl(&buf, API_BASE, "guild456");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/dms/guild456/messages", url);
}

test "qq buildSendBody" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "hello world", null);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"hello world\"}", body);
}

test "qq buildSendBody with msg_id" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "reply text", "msg_123");
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"reply text\",\"msg_id\":\"msg_123\"}", body);
}

test "qq buildAuthToken" {
    var buf: [256]u8 = undefined;
    const token = try buildAuthToken(&buf, "app1", "tok1");
    try std.testing.expectEqualStrings("Bot app1.tok1", token);
}

test "qq buildAuthHeader" {
    var buf: [256]u8 = undefined;
    const header = try buildAuthHeader(&buf, "app1", "tok1");
    try std.testing.expectEqualStrings("Authorization: Bot app1.tok1", header);
}

test "qq isGroupAllowed policy allow" {
    const config = config_types.QQConfig{ .group_policy = .allow };
    try std.testing.expect(isGroupAllowed(config, "anygroup"));
}

test "qq isGroupAllowed policy allowlist" {
    const list = [_][]const u8{ "group1", "group2" };
    const config = config_types.QQConfig{ .group_policy = .allowlist, .allowed_groups = &list };
    try std.testing.expect(isGroupAllowed(config, "group1"));
    try std.testing.expect(isGroupAllowed(config, "group2"));
    try std.testing.expect(!isGroupAllowed(config, "group3"));
}

test "qq isGroupAllowed empty allowlist denies all" {
    const config = config_types.QQConfig{ .group_policy = .allowlist, .allowed_groups = &.{} };
    try std.testing.expect(!isGroupAllowed(config, "anygroup"));
}

test "qq apiBase returns correct urls" {
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com", apiBase(false));
    try std.testing.expectEqualStrings("https://sandbox.api.sgroup.qq.com", apiBase(true));
}

test "qq gatewayUrl returns correct urls" {
    try std.testing.expectEqualStrings("wss://api.sgroup.qq.com/websocket", gatewayUrl(false));
    try std.testing.expectEqualStrings("wss://sandbox.api.sgroup.qq.com/websocket", gatewayUrl(true));
}

test "qq parseTarget channel prefix" {
    const msg_type, const id = parseTarget("channel:12345");
    try std.testing.expectEqualStrings("channel", msg_type);
    try std.testing.expectEqualStrings("12345", id);
}

test "qq parseTarget dm prefix" {
    const msg_type, const id = parseTarget("dm:67890");
    try std.testing.expectEqualStrings("dm", msg_type);
    try std.testing.expectEqualStrings("67890", id);
}

test "qq parseTarget no prefix defaults to channel" {
    const msg_type, const id = parseTarget("12345");
    try std.testing.expectEqualStrings("channel", msg_type);
    try std.testing.expectEqualStrings("12345", id);
}

test "qq QQChannel init stores config" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{
        .app_id = "myapp",
        .bot_token = "mytoken",
        .sandbox = true,
    });
    try std.testing.expectEqualStrings("myapp", ch.config.app_id);
    try std.testing.expectEqualStrings("mytoken", ch.config.bot_token);
    try std.testing.expect(ch.config.sandbox);
    try std.testing.expectEqualStrings("qq", ch.channelName());
    try std.testing.expect(!ch.healthCheck());
    try std.testing.expect(ch.sequence == null);
    try std.testing.expectEqual(@as(u32, 0), ch.heartbeat_interval_ms);
}

test "qq QQChannel vtable compiles" {
    const vtable_instance = QQChannel.vtable;
    try std.testing.expect(vtable_instance.start == &QQChannel.vtableStart);
    try std.testing.expect(vtable_instance.stop == &QQChannel.vtableStop);
    try std.testing.expect(vtable_instance.send == &QQChannel.vtableSend);
    try std.testing.expect(vtable_instance.name == &QQChannel.vtableName);
    try std.testing.expect(vtable_instance.healthCheck == &QQChannel.vtableHealthCheck);
}

test "qq QQChannel channel interface" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("qq", iface.name());
}

test "qq handleGatewayEvent HELLO" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const hello_json =
        \\{"op":10,"d":{"heartbeat_interval":41250}}
    ;
    try ch.handleGatewayEvent(hello_json);
    try std.testing.expectEqual(@as(u32, 41250), ch.heartbeat_interval_ms);
}

test "qq handleGatewayEvent READY" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    defer {
        if (ch.session_id) |sid| alloc.free(sid);
    }
    const ready_json =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess_abc123","user":{"id":"bot1"}}}
    ;
    try ch.handleGatewayEvent(ready_json);
    try std.testing.expect(ch.running);
    try std.testing.expectEqualStrings("sess_abc123", ch.session_id.?);
    try std.testing.expectEqual(@as(i64, 1), ch.sequence.?);
}

test "qq handleGatewayEvent MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main" });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const msg_json =
        \\{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"id":"msg001","channel_id":"ch1","guild_id":"g1","content":"hello qq","author":{"id":"user1","username":"tester"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("user1", msg.sender_id);
    try std.testing.expectEqualStrings("channel:ch1", msg.chat_id);
    try std.testing.expectEqualStrings("hello qq", msg.content);
    try std.testing.expectEqualStrings("qq:ch1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    const meta_parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta_parsed.deinit();
    try std.testing.expect(meta_parsed.value == .object);
    try std.testing.expect(meta_parsed.value.object.get("account_id") != null);
    try std.testing.expect(meta_parsed.value.object.get("account_id").? == .string);
    try std.testing.expectEqualStrings("qq-main", meta_parsed.value.object.get("account_id").?.string);
}

test "qq handleGatewayEvent DIRECT_MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const msg_json =
        \\{"op":0,"s":3,"t":"DIRECT_MESSAGE_CREATE","d":{"id":"dm001","channel_id":"dch1","guild_id":"dg1","content":"dm hello","author":{"id":"u2"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("u2", msg.sender_id);
    // For DMs, chat_id must include dm: prefix for sendMessage routing.
    try std.testing.expectEqualStrings("dm:dg1", msg.chat_id);
    try std.testing.expectEqualStrings("dm hello", msg.content);
}

test "qq handleGatewayEvent deduplication" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":4,"t":"MESSAGE_CREATE","d":{"id":"msg_dup","channel_id":"ch1","content":"test","author":{"id":"u1"}}}
    ;

    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    var msg = event_bus_inst.consumeInbound().?;
    msg.deinit(alloc);
}

test "qq handleGatewayEvent group allowlist filters" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    const list = [_][]const u8{"allowed_guild"};
    var ch = QQChannel.init(alloc, .{
        .group_policy = .allowlist,
        .allowed_groups = &list,
    });
    ch.setBus(&event_bus_inst);

    // Message from non-allowed guild — should be filtered
    const blocked_json =
        \\{"op":0,"s":5,"t":"MESSAGE_CREATE","d":{"id":"msg_blocked","channel_id":"ch1","guild_id":"blocked_guild","content":"blocked","author":{"id":"u1"}}}
    ;
    try ch.handleGatewayEvent(blocked_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());

    // Message from allowed guild — should pass
    const allowed_json =
        \\{"op":0,"s":6,"t":"MESSAGE_CREATE","d":{"id":"msg_allowed","channel_id":"ch2","guild_id":"allowed_guild","content":"allowed","author":{"id":"u2"}}}
    ;
    try ch.handleGatewayEvent(allowed_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    var msg = event_bus_inst.consumeInbound().?;
    msg.deinit(alloc);
}

test "qq handleGatewayEvent RECONNECT sets running false" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    ch.running = true;
    try ch.handleGatewayEvent("{\"op\":7}");
    try std.testing.expect(!ch.running);
}

test "qq handleGatewayEvent INVALID_SESSION sets running false" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    ch.running = true;
    // Suppress expected warning from INVALID_SESSION opcode
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    try ch.handleGatewayEvent("{\"op\":9}");
    try std.testing.expect(!ch.running);
}

test "qq handleGatewayEvent HEARTBEAT_ACK is silent" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    try ch.handleGatewayEvent("{\"op\":11}");
    // No crash, no state change
}

test "qq handleGatewayEvent invalid JSON" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    // Suppress expected warnings from invalid input
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    try ch.handleGatewayEvent("not json");
    try ch.handleGatewayEvent("{broken");
    try ch.handleGatewayEvent("");
}

test "qq handleGatewayEvent empty message content ignored" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":7,"t":"MESSAGE_CREATE","d":{"id":"msg_empty","channel_id":"ch1","content":"   ","author":{"id":"u1"}}}
    ;
    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "qq handleGatewayEvent strips CQ codes from content" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{"id":"msg_cq","channel_id":"ch1","content":"[CQ:at,qq=100] help me","author":{"id":"u3"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("help me", msg.content);
}

test "qq MAX_MESSAGE_LEN constant" {
    try std.testing.expectEqual(@as(usize, 4096), QQChannel.MAX_MESSAGE_LEN);
}

test "qq RECONNECT_DELAY_NS constant" {
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), QQChannel.RECONNECT_DELAY_NS);
}

test "qq DEFAULT_INTENTS has expected bits" {
    // GUILDS (bit 0) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 0) != 0);
    // GUILD_MESSAGES (bit 9) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 9) != 0);
    // DIRECT_MESSAGE (bit 12) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 12) != 0);
    // GROUP_AT_MESSAGE (bit 25) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 25) != 0);
}
