const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");

const log = std.log.scoped(.onebot);

// ════════════════════════════════════════════════════════════════════════════
// CQ Code Parsing
// ════════════════════════════════════════════════════════════════════════════

/// Result of parsing CQ-coded message text.
pub const CqParseResult = struct {
    /// Plain text with all CQ tags removed.
    plain_text: []const u8,
    /// Whether the message contains a mention ([CQ:at,...]).
    is_mention: bool = false,
    /// Mentioned QQ number (from [CQ:at,qq=...]), null if no mention.
    mention_qq: ?[]const u8 = null,
    /// Media URLs/files extracted from [CQ:image,...] tags.
    media: []const []const u8 = &.{},
    /// Reply message ID from [CQ:reply,id=...], null if not a reply.
    reply_id: ?[]const u8 = null,

    pub fn deinit(self: *const CqParseResult, allocator: std.mem.Allocator) void {
        allocator.free(self.plain_text);
        if (self.mention_qq) |mq| allocator.free(mq);
        for (self.media) |m| allocator.free(m);
        if (self.media.len > 0) allocator.free(self.media);
        if (self.reply_id) |rid| allocator.free(rid);
    }
};

/// Parse CQ-coded message text, extracting tags and returning clean text.
///
/// Supported CQ tags:
///   [CQ:image,file=xxx]   -> media attachment
///   [CQ:at,qq=123456]     -> mention (sets is_mention)
///   [CQ:reply,id=xxx]     -> reply to message
///   [CQ:face,id=xxx]      -> stripped (emoji)
///   Other [CQ:...] tags   -> stripped
pub fn parseCqTags(allocator: std.mem.Allocator, raw: []const u8) !CqParseResult {
    var plain: std.ArrayListUnmanaged(u8) = .empty;
    errdefer plain.deinit(allocator);

    var media_list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (media_list.items) |m| allocator.free(m);
        media_list.deinit(allocator);
    }

    var mention_qq: ?[]const u8 = null;
    errdefer if (mention_qq) |mq| allocator.free(mq);
    var is_mention = false;

    var reply_id: ?[]const u8 = null;
    errdefer if (reply_id) |rid| allocator.free(rid);

    var cursor: usize = 0;
    while (cursor < raw.len) {
        // Find next [CQ: tag
        const tag_start = std.mem.indexOfPos(u8, raw, cursor, "[CQ:") orelse {
            try plain.appendSlice(allocator, raw[cursor..]);
            break;
        };

        // Append text before the tag
        try plain.appendSlice(allocator, raw[cursor..tag_start]);

        // Find closing ]
        const tag_end = std.mem.indexOfPos(u8, raw, tag_start, "]") orelse {
            // Malformed tag — treat as plain text
            try plain.appendSlice(allocator, raw[tag_start..]);
            cursor = raw.len;
            break;
        };

        const tag_body = raw[tag_start + 4 .. tag_end]; // after "[CQ:" up to "]"

        // Parse tag type (before first comma)
        const comma_pos = std.mem.indexOf(u8, tag_body, ",");
        const tag_type = if (comma_pos) |cp| tag_body[0..cp] else tag_body;
        const tag_params = if (comma_pos) |cp| tag_body[cp + 1 ..] else "";

        if (std.mem.eql(u8, tag_type, "image")) {
            // Extract file= parameter
            if (extractParam(tag_params, "file")) |file_val| {
                try media_list.append(allocator, try allocator.dupe(u8, file_val));
            } else if (extractParam(tag_params, "url")) |url_val| {
                try media_list.append(allocator, try allocator.dupe(u8, url_val));
            }
        } else if (std.mem.eql(u8, tag_type, "at")) {
            is_mention = true;
            if (extractParam(tag_params, "qq")) |qq_val| {
                if (mention_qq) |old| allocator.free(old);
                mention_qq = try allocator.dupe(u8, qq_val);
            }
        } else if (std.mem.eql(u8, tag_type, "reply")) {
            if (extractParam(tag_params, "id")) |id_val| {
                if (reply_id) |old| allocator.free(old);
                reply_id = try allocator.dupe(u8, id_val);
            }
        }
        // All other CQ tags (face, record, etc.) are silently stripped.

        cursor = tag_end + 1;
    }

    const media = try media_list.toOwnedSlice(allocator);

    return .{
        .plain_text = try plain.toOwnedSlice(allocator),
        .is_mention = is_mention,
        .mention_qq = mention_qq,
        .media = media,
        .reply_id = reply_id,
    };
}

/// Extract a parameter value from CQ tag params string.
/// E.g. extractParam("file=abc.jpg,cache=1", "file") -> "abc.jpg"
fn extractParam(params: []const u8, key: []const u8) ?[]const u8 {
    var cursor: usize = 0;
    while (cursor < params.len) {
        // Find next key=value pair
        const eq_pos = std.mem.indexOfPos(u8, params, cursor, "=") orelse break;
        const param_key = params[cursor..eq_pos];

        const val_start = eq_pos + 1;
        const comma_pos = std.mem.indexOfPos(u8, params, val_start, ",");
        const val_end = comma_pos orelse params.len;
        const param_val = params[val_start..val_end];

        if (std.mem.eql(u8, param_key, key)) {
            return param_val;
        }

        cursor = if (comma_pos) |cp| cp + 1 else params.len;
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Message Deduplication
// ════════════════════════════════════════════════════════════════════════════

pub const DEDUP_RING_SIZE: usize = 1024;

/// Ring buffer for message_id deduplication.
/// Stores the last DEDUP_RING_SIZE message IDs in a circular buffer.
pub const DedupRing = struct {
    ring: [DEDUP_RING_SIZE]u64 = [_]u64{0} ** DEDUP_RING_SIZE,
    idx: u32 = 0,
    count: u32 = 0,

    /// Check if message_id was already seen. If not, record it and return false.
    /// Returns true if the message is a duplicate.
    pub fn isDuplicate(self: *DedupRing, message_id: u64) bool {
        // Check existing entries
        const check_count = @min(self.count, DEDUP_RING_SIZE);
        for (0..check_count) |i| {
            if (self.ring[i] == message_id) return true;
        }
        // Not found — record it
        self.ring[self.idx] = message_id;
        self.idx = @intCast((self.idx + 1) % @as(u32, DEDUP_RING_SIZE));
        if (self.count < DEDUP_RING_SIZE) self.count += 1;
        return false;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// OneBotChannel
// ════════════════════════════════════════════════════════════════════════════

/// OneBot v11 protocol channel.
///
/// Connects to a OneBot v11 implementation (go-cqhttp, NapCat, Lagrange, etc.)
/// via WebSocket or HTTP API. Receives messages, parses CQ codes, publishes
/// to the event bus. Sends outgoing messages via HTTP POST to /send_msg.
pub const OneBotChannel = struct {
    config: config_types.OneBotConfig,
    allocator: std.mem.Allocator,
    event_bus: ?*bus.Bus,
    dedup: DedupRing,
    running: bool,

    pub const MAX_MESSAGE_LEN: usize = 4500;
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, config: config_types.OneBotConfig) OneBotChannel {
        return .{
            .config = config,
            .allocator = allocator,
            .event_bus = null,
            .dedup = .{},
            .running = false,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.OneBotConfig) OneBotChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *OneBotChannel) []const u8 {
        return "onebot";
    }

    pub fn healthCheck(self: *OneBotChannel) bool {
        return self.running;
    }

    /// Set the event bus for publishing inbound messages.
    pub fn setBus(self: *OneBotChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    // ── Incoming event handling ──────────────────────────────────────

    /// Parse a raw OneBot v11 event JSON and, if it's a message event,
    /// create an InboundMessage and publish it to the bus.
    pub fn handleEvent(self: *OneBotChannel, raw_json: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, raw_json, .{}) catch {
            log.warn("failed to parse OneBot event JSON", .{});
            return;
        };
        defer parsed.deinit();
        const val = parsed.value;

        // Only handle message events
        const post_type = getJsonString(val, "post_type") orelse return;
        if (!std.mem.eql(u8, post_type, "message")) return;

        // Extract message_id for dedup
        const message_id_val = val.object.get("message_id") orelse return;
        const message_id: u64 = switch (message_id_val) {
            .integer => @intCast(@as(u64, @bitCast(@as(i64, message_id_val.integer)))),
            .number_string => std.fmt.parseInt(u64, message_id_val.number_string, 10) catch return,
            else => return,
        };

        if (self.dedup.isDuplicate(message_id)) return;

        const message_type = getJsonString(val, "message_type") orelse return;
        const is_group = std.mem.eql(u8, message_type, "group");

        // Extract user_id
        const user_id = getJsonInt(val, "user_id") orelse return;
        var user_buf: [32]u8 = undefined;
        const user_str = std.fmt.bufPrint(&user_buf, "{d}", .{user_id}) catch return;

        // Allowlist check
        if (self.config.allow_from.len > 0 and !root.isAllowed(self.config.allow_from, user_str)) return;

        // Extract chat_id (group_id for group messages, user_id for private)
        const chat_id_int = if (is_group) getJsonInt(val, "group_id") orelse return else user_id;
        var chat_buf: [48]u8 = undefined;
        const chat_str = if (is_group)
            std.fmt.bufPrint(&chat_buf, "group:{d}", .{chat_id_int}) catch return
        else
            std.fmt.bufPrint(&chat_buf, "{d}", .{chat_id_int}) catch return;

        // Extract raw message text
        const raw_message = getJsonString(val, "raw_message") orelse
            getJsonString(val, "message") orelse return;

        // Parse CQ tags
        var cq = try parseCqTags(self.allocator, raw_message);
        defer cq.deinit(self.allocator);

        var content = cq.plain_text;

        // Group trigger prefix check
        if (is_group) {
            if (self.config.group_trigger_prefix) |prefix| {
                if (std.mem.startsWith(u8, content, prefix)) {
                    // Strip prefix and leading whitespace
                    content = std.mem.trimLeft(u8, content[prefix.len..], " ");
                } else if (!cq.is_mention) {
                    // Not prefixed and not a mention — skip
                    return;
                }
            }
        }

        // Skip empty messages
        if (content.len == 0 and cq.media.len == 0) return;

        // Build session key
        var session_buf: [128]u8 = undefined;
        const session_key = std.fmt.bufPrint(&session_buf, "onebot:{s}", .{chat_str}) catch return;

        // Build metadata JSON
        var meta_buf: [256]u8 = undefined;
        var meta_fbs = std.io.fixedBufferStream(&meta_buf);
        const mw = meta_fbs.writer();
        mw.print("{{\"message_id\":{d},\"is_group\":{s}", .{
            message_id,
            if (is_group) "true" else "false",
        }) catch return;
        mw.writeAll(",\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.config.account_id) catch return;
        if (cq.reply_id) |rid| {
            mw.writeAll(",\"reply_to\":\"") catch return;
            mw.writeAll(rid) catch return;
            mw.writeByte('"') catch return;
        }
        mw.writeByte('}') catch return;
        const metadata = meta_fbs.getWritten();

        const msg = bus.makeInboundFull(
            self.allocator,
            "onebot",
            user_str,
            chat_str,
            content,
            session_key,
            cq.media,
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

    /// Send a message to a user or group via OneBot HTTP API.
    /// Target format: "private:<user_id>" or "group:<group_id>" or just "<id>" (defaults to private).
    pub fn sendMessage(self: *OneBotChannel, target: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(target, chunk);
        }
    }

    fn sendChunk(self: *OneBotChannel, target: []const u8, text: []const u8) !void {
        // Parse target: "private:12345" or "group:12345" or just "12345"
        const msg_type: []const u8, const id_str: []const u8 = parseTarget(target);

        // Build API URL
        var url_buf: [512]u8 = undefined;
        const api_base = deriveHttpBase(self.config.url);
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/send_msg", .{api_base});
        const url = url_fbs.getWritten();

        // Build JSON body dynamically
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const bw = body_list.writer(self.allocator);
        try bw.writeAll("{\"action\":\"send_msg\",\"params\":{");
        try bw.print("\"message_type\":\"{s}\",", .{msg_type});
        if (std.mem.eql(u8, msg_type, "group")) {
            try bw.print("\"group_id\":{s},", .{id_str});
        } else {
            try bw.print("\"user_id\":{s},", .{id_str});
        }
        try bw.writeAll("\"message\":");
        try root.appendJsonStringW(bw, text);
        try bw.writeAll("}}");
        const body = body_list.items;

        // Build headers
        var headers_buf: [1][]const u8 = undefined;
        var header_storage: [512]u8 = undefined;
        var headers: []const []const u8 = &.{};
        if (self.config.access_token) |token| {
            var hdr_fbs = std.io.fixedBufferStream(&header_storage);
            try hdr_fbs.writer().print("Authorization: Bearer {s}", .{token});
            headers_buf[0] = hdr_fbs.getWritten();
            headers = &headers_buf;
        }

        const resp = root.http_util.curlPost(self.allocator, url, body, headers) catch |err| {
            log.err("OneBot API POST failed: {}", .{err});
            return error.OneBotApiError;
        };
        self.allocator.free(resp);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *OneBotChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
        log.info("OneBot channel started (url={s})", .{self.config.url});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *OneBotChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
        log.info("OneBot channel stopped", .{});
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *OneBotChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *OneBotChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *OneBotChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *OneBotChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Parse target string into (message_type, id).
/// "private:12345" -> ("private", "12345")
/// "group:12345"   -> ("group", "12345")
/// "12345"         -> ("private", "12345")
fn parseTarget(target: []const u8) struct { []const u8, []const u8 } {
    if (std.mem.indexOf(u8, target, ":")) |colon| {
        return .{ target[0..colon], target[colon + 1 ..] };
    }
    return .{ "private", target };
}

/// Derive HTTP API base URL from the WebSocket URL.
/// "ws://localhost:6700" -> "http://localhost:6700"
/// "wss://host:6700"     -> "https://host:6700"
/// If already http(s), return as-is.
fn deriveHttpBase(ws_url: []const u8) []const u8 {
    if (std.mem.startsWith(u8, ws_url, "ws://")) return ws_url; // curl handles ws:// -> http://
    if (std.mem.startsWith(u8, ws_url, "wss://")) return ws_url;
    return ws_url;
}

/// Get a string field from a JSON object value.
fn getJsonString(val: std.json.Value, key: []const u8) ?[]const u8 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return if (field == .string) field.string else null;
}

/// Get an integer field from a JSON object value.
fn getJsonInt(val: std.json.Value, key: []const u8) ?i64 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return switch (field) {
        .integer => field.integer,
        .number_string => std.fmt.parseInt(i64, field.number_string, 10) catch null,
        else => null,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseCqTags plain text no tags" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "hello world");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings("hello world", result.plain_text);
    try std.testing.expect(!result.is_mention);
    try std.testing.expect(result.mention_qq == null);
    try std.testing.expectEqual(@as(usize, 0), result.media.len);
    try std.testing.expect(result.reply_id == null);
}

test "parseCqTags empty string" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings("", result.plain_text);
}

test "parseCqTags image tag" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "look [CQ:image,file=abc.jpg] here");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings("look  here", result.plain_text);
    try std.testing.expectEqual(@as(usize, 1), result.media.len);
    try std.testing.expectEqualStrings("abc.jpg", result.media[0]);
}

test "parseCqTags image tag with url param" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "[CQ:image,file=abc.jpg,url=https://example.com/img.png]");
    defer result.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), result.media.len);
    try std.testing.expectEqualStrings("abc.jpg", result.media[0]);
}

test "parseCqTags at tag" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "[CQ:at,qq=123456] hello");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings(" hello", result.plain_text);
    try std.testing.expect(result.is_mention);
    try std.testing.expectEqualStrings("123456", result.mention_qq.?);
}

test "parseCqTags reply tag" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "[CQ:reply,id=99] response");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings(" response", result.plain_text);
    try std.testing.expectEqualStrings("99", result.reply_id.?);
}

test "parseCqTags multiple tags mixed" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "[CQ:reply,id=5][CQ:at,qq=111] hi [CQ:image,file=pic.png]");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings(" hi ", result.plain_text);
    try std.testing.expect(result.is_mention);
    try std.testing.expectEqualStrings("111", result.mention_qq.?);
    try std.testing.expectEqualStrings("5", result.reply_id.?);
    try std.testing.expectEqual(@as(usize, 1), result.media.len);
    try std.testing.expectEqualStrings("pic.png", result.media[0]);
}

test "parseCqTags face tag stripped" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "hi [CQ:face,id=178] there");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings("hi  there", result.plain_text);
}

test "parseCqTags malformed tag treated as text" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "broken [CQ:image,file=x");
    defer result.deinit(alloc);
    try std.testing.expectEqualStrings("broken [CQ:image,file=x", result.plain_text);
}

test "parseCqTags multiple images" {
    const alloc = std.testing.allocator;
    var result = try parseCqTags(alloc, "[CQ:image,file=a.jpg][CQ:image,file=b.png]");
    defer result.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), result.media.len);
    try std.testing.expectEqualStrings("a.jpg", result.media[0]);
    try std.testing.expectEqualStrings("b.png", result.media[1]);
}

test "isDuplicate basic" {
    var ring = DedupRing{};
    // First time — not duplicate
    try std.testing.expect(!ring.isDuplicate(100));
    // Second time — duplicate
    try std.testing.expect(ring.isDuplicate(100));
    // Different ID — not duplicate
    try std.testing.expect(!ring.isDuplicate(200));
    try std.testing.expect(ring.isDuplicate(200));
}

test "isDuplicate ring wraps around" {
    var ring = DedupRing{};
    // Fill the entire ring
    for (1..DEDUP_RING_SIZE + 1) |i| {
        try std.testing.expect(!ring.isDuplicate(@intCast(i)));
    }
    // All should be found as duplicates
    for (1..DEDUP_RING_SIZE + 1) |i| {
        try std.testing.expect(ring.isDuplicate(@intCast(i)));
    }
    // Push one more — should evict the oldest (1)
    try std.testing.expect(!ring.isDuplicate(DEDUP_RING_SIZE + 1));
    // ID 1 was evicted, so it should no longer be found
    try std.testing.expect(!ring.isDuplicate(1));
}

test "isDuplicate zero id" {
    var ring = DedupRing{};
    // Zero is a valid message_id but ring is initialized with zeros.
    // After the first insert of a non-zero ID, zero should still be in the ring
    // since count hasn't reached the full ring yet.
    try std.testing.expect(!ring.isDuplicate(42));
    try std.testing.expect(ring.isDuplicate(42));
}

test "parseTarget private prefix" {
    const msg_type, const id = parseTarget("private:12345");
    try std.testing.expectEqualStrings("private", msg_type);
    try std.testing.expectEqualStrings("12345", id);
}

test "parseTarget group prefix" {
    const msg_type, const id = parseTarget("group:67890");
    try std.testing.expectEqualStrings("group", msg_type);
    try std.testing.expectEqualStrings("67890", id);
}

test "parseTarget no prefix defaults to private" {
    const msg_type, const id = parseTarget("12345");
    try std.testing.expectEqualStrings("private", msg_type);
    try std.testing.expectEqualStrings("12345", id);
}

test "deriveHttpBase ws url" {
    const result = deriveHttpBase("ws://localhost:6700");
    try std.testing.expectEqualStrings("ws://localhost:6700", result);
}

test "deriveHttpBase http url passthrough" {
    const result = deriveHttpBase("http://localhost:5700");
    try std.testing.expectEqualStrings("http://localhost:5700", result);
}

test "config_types.OneBotConfig defaults" {
    const config = config_types.OneBotConfig{};
    try std.testing.expectEqualStrings("ws://localhost:6700", config.url);
    try std.testing.expect(config.access_token == null);
    try std.testing.expect(config.group_trigger_prefix == null);
}

test "OneBotChannel init stores config" {
    const alloc = std.testing.allocator;
    var ch = OneBotChannel.init(alloc, .{
        .url = "ws://myhost:6700",
        .access_token = "secret",
        .group_trigger_prefix = "/bot",
    });
    try std.testing.expectEqualStrings("ws://myhost:6700", ch.config.url);
    try std.testing.expectEqualStrings("secret", ch.config.access_token.?);
    try std.testing.expectEqualStrings("/bot", ch.config.group_trigger_prefix.?);
    try std.testing.expectEqualStrings("onebot", ch.channelName());
    try std.testing.expect(!ch.healthCheck());
}

test "OneBotChannel vtable compiles" {
    const vtable_instance = OneBotChannel.vtable;
    try std.testing.expect(vtable_instance.start == &OneBotChannel.vtableStart);
    try std.testing.expect(vtable_instance.stop == &OneBotChannel.vtableStop);
    try std.testing.expect(vtable_instance.send == &OneBotChannel.vtableSend);
    try std.testing.expect(vtable_instance.name == &OneBotChannel.vtableName);
    try std.testing.expect(vtable_instance.healthCheck == &OneBotChannel.vtableHealthCheck);
}

test "OneBotChannel channel interface" {
    const alloc = std.testing.allocator;
    var ch = OneBotChannel.init(alloc, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("onebot", iface.name());
}

test "handleEvent private message" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{ .account_id = "onebot-main" });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":1001,
        \\"user_id":12345,"raw_message":"hello onebot","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("onebot", msg.channel);
    try std.testing.expectEqualStrings("12345", msg.sender_id);
    try std.testing.expectEqualStrings("12345", msg.chat_id);
    try std.testing.expectEqualStrings("hello onebot", msg.content);
    try std.testing.expectEqualStrings("onebot:12345", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"account_id\":\"onebot-main\"") != null);
}

test "handleEvent group message with prefix" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{
        .group_trigger_prefix = "/bot",
    });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    // Message with prefix — should be accepted, prefix stripped
    const event_json =
        \\{"post_type":"message","message_type":"group","message_id":2001,
        \\"user_id":111,"group_id":999,"raw_message":"/bot what is Zig?","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("what is Zig?", msg.content);
    try std.testing.expectEqualStrings("group:999", msg.chat_id);
    try std.testing.expectEqualStrings("onebot:group:999", msg.session_key);
}

test "handleEvent group message without prefix skipped" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{
        .group_trigger_prefix = "/bot",
    });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    // Message without prefix and no mention — should be skipped
    const event_json =
        \\{"post_type":"message","message_type":"group","message_id":2002,
        \\"user_id":111,"group_id":999,"raw_message":"random chat","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "handleEvent deduplication" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":3001,
        \\"user_id":42,"raw_message":"test","time":1700000000}
    ;

    // First time — published
    try ch.handleEvent(event_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    // Second time — deduplicated
    try ch.handleEvent(event_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    var msg = event_bus_inst.consumeInbound().?;
    msg.deinit(alloc);
}

test "handleEvent non-message event ignored" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const event_json =
        \\{"post_type":"notice","notice_type":"group_increase","user_id":123}
    ;
    try ch.handleEvent(event_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "handleEvent invalid JSON" {
    const alloc = std.testing.allocator;
    var ch = OneBotChannel.init(alloc, .{});
    // Suppress expected warnings from invalid input
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    // Should not crash on invalid JSON
    try ch.handleEvent("not json at all");
    try ch.handleEvent("{broken");
    try ch.handleEvent("");
}

test "handleEvent with CQ tags in message" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":4001,
        \\"user_id":55,"raw_message":"[CQ:at,qq=100] hey [CQ:image,file=photo.jpg]","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings(" hey ", msg.content);
    try std.testing.expectEqual(@as(usize, 1), msg.media.len);
    try std.testing.expectEqualStrings("photo.jpg", msg.media[0]);
}

test "handleEvent group message with mention passes prefix check" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{
        .group_trigger_prefix = "/bot",
    });
    ch.setBus(&event_bus_inst);

    // Message with @mention but no prefix — should still pass because is_mention
    const event_json =
        \\{"post_type":"message","message_type":"group","message_id":5001,
        \\"user_id":77,"group_id":888,"raw_message":"[CQ:at,qq=100] help me","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings(" help me", msg.content);
}

test "handleEvent allow_from blocks unlisted user" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{
        .allow_from = &.{"99999"},
    });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    // user_id=12345 is NOT in allow_from
    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":6001,
        \\"user_id":12345,"raw_message":"blocked user","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "handleEvent allow_from permits listed user" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{
        .allow_from = &.{"12345"},
    });
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":6002,
        \\"user_id":12345,"raw_message":"allowed user","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("allowed user", msg.content);
}

test "handleEvent allow_from empty allows all" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = OneBotChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);
    ch.running = true;

    const event_json =
        \\{"post_type":"message","message_type":"private","message_id":6003,
        \\"user_id":12345,"raw_message":"anyone allowed","time":1700000000}
    ;
    try ch.handleEvent(event_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("anyone allowed", msg.content);
}

test "extractParam finds correct values" {
    try std.testing.expectEqualStrings("abc.jpg", extractParam("file=abc.jpg", "file").?);
    try std.testing.expectEqualStrings("abc.jpg", extractParam("file=abc.jpg,cache=1", "file").?);
    try std.testing.expectEqualStrings("1", extractParam("file=abc.jpg,cache=1", "cache").?);
    try std.testing.expect(extractParam("file=abc.jpg", "missing") == null);
    try std.testing.expect(extractParam("", "key") == null);
}

test "getJsonString extracts string" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc,
        \\{"name":"alice","count":42}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("alice", getJsonString(parsed.value, "name").?);
    try std.testing.expect(getJsonString(parsed.value, "count") == null);
    try std.testing.expect(getJsonString(parsed.value, "missing") == null);
}

test "getJsonInt extracts integer" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc,
        \\{"count":42,"name":"alice"}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 42), getJsonInt(parsed.value, "count").?);
    try std.testing.expect(getJsonInt(parsed.value, "name") == null);
    try std.testing.expect(getJsonInt(parsed.value, "missing") == null);
}
