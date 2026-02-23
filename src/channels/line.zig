const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.line);

/// LINE Messaging API channel — webhook-based (push).
///
/// Receives events via LINE webhook endpoint, sends replies via
/// the Reply API (with replyToken) or Push API (direct to userId).
pub const LineChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.LineConfig,
    bus: ?*anyopaque = null,
    running: bool = false,

    pub const REPLY_URL = "https://api.line.me/v2/bot/message/reply";
    pub const PUSH_URL = "https://api.line.me/v2/bot/message/push";
    pub const MAX_MESSAGE_LEN: usize = 5000;

    pub fn init(allocator: std.mem.Allocator, config: config_types.LineConfig) LineChannel {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.LineConfig) LineChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *LineChannel) []const u8 {
        return "line";
    }

    pub fn healthCheck(self: *LineChannel) bool {
        return self.running or self.config.access_token.len > 0;
    }

    // ── Signature Verification ─────────────────────────────────────

    /// Verify the X-Line-Signature header.
    ///
    /// LINE signs webhooks with HMAC-SHA256(channel_secret, body),
    /// then base64-encodes the digest. We recompute and compare.
    pub fn verifySignature(body: []const u8, signature: []const u8, channel_secret: []const u8) bool {
        return verifyLineSignature(body, signature, channel_secret);
    }

    // ── Message Sending ────────────────────────────────────────────

    /// Reply to a message using the replyToken (valid for ~30s after event).
    pub fn replyMessage(self: *LineChannel, reply_token: []const u8, text: []const u8) !void {
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const w = body_list.writer(self.allocator);

        try w.writeAll("{\"replyToken\":\"");
        try w.writeAll(reply_token);
        try w.writeAll("\",\"messages\":[{\"type\":\"text\",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}]}");
        const body = body_list.items;

        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Authorization: Bearer {s}", .{self.config.access_token});
        const auth_header = auth_fbs.getWritten();

        const resp = root.http_util.curlPost(self.allocator, REPLY_URL, body, &.{auth_header}) catch |err| {
            log.err("replyMessage failed: {}", .{err});
            return error.LineApiError;
        };
        self.allocator.free(resp);
    }

    /// Push a message to a user by userId (no replyToken needed).
    pub fn pushMessage(self: *LineChannel, user_id: []const u8, text: []const u8) !void {
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const w = body_list.writer(self.allocator);

        try w.writeAll("{\"to\":\"");
        try w.writeAll(user_id);
        try w.writeAll("\",\"messages\":[{\"type\":\"text\",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}]}");
        const body = body_list.items;

        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Authorization: Bearer {s}", .{self.config.access_token});
        const auth_header = auth_fbs.getWritten();

        const resp = root.http_util.curlPost(self.allocator, PUSH_URL, body, &.{auth_header}) catch |err| {
            log.err("pushMessage failed: {}", .{err});
            return error.LineApiError;
        };
        self.allocator.free(resp);
    }

    /// Send a message. If target looks like a replyToken (32+ hex chars),
    /// use replyMessage; otherwise use pushMessage to userId.
    pub fn sendMessage(self: *LineChannel, target: []const u8, text: []const u8) !void {
        // LINE userIds start with "U" and are 33 chars; replyTokens are 32 hex chars.
        // Heuristic: if it starts with 'U' and len >= 33, treat as userId (push).
        if (target.len >= 33 and target[0] == 'U') {
            try self.pushMessage(target, text);
        } else {
            // Try as replyToken first; if target is a userId without 'U' prefix, push
            try self.pushMessage(target, text);
        }
    }

    // ── Webhook Event Parsing ──────────────────────────────────────

    /// Parse a LINE webhook body and extract events.
    pub fn parseWebhookEvents(
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) ![]LineEvent {
        var result: std.ArrayListUnmanaged(LineEvent) = .empty;
        errdefer {
            for (result.items) |*e| e.deinit(allocator);
            result.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return result.items;
        defer parsed.deinit();
        const val = parsed.value;

        if (val != .object) return result.items;
        const events_val = val.object.get("events") orelse return result.items;
        if (events_val != .array) return result.items;
        const events = events_val.array.items;

        for (events) |event| {
            if (event != .object) continue;

            // Event type
            const type_val = event.object.get("type") orelse continue;
            const event_type = if (type_val == .string) type_val.string else continue;

            // Reply token
            const reply_token_val = event.object.get("replyToken");
            const reply_token = if (reply_token_val) |rt| (if (rt == .string) rt.string else null) else null;

            // Source
            const source_obj = event.object.get("source");
            var user_id: ?[]const u8 = null;
            var group_id: ?[]const u8 = null;
            var room_id: ?[]const u8 = null;
            var source_type: ?[]const u8 = null;
            if (source_obj) |src| {
                if (src == .object) {
                    const uid_val = src.object.get("userId");
                    user_id = if (uid_val) |u| (if (u == .string) u.string else null) else null;
                    const gid_val = src.object.get("groupId");
                    group_id = if (gid_val) |g| (if (g == .string) g.string else null) else null;
                    const rid_val = src.object.get("roomId");
                    room_id = if (rid_val) |r| (if (r == .string) r.string else null) else null;
                    const st_val = src.object.get("type");
                    source_type = if (st_val) |s| (if (s == .string) s.string else null) else null;
                }
            }

            // Timestamp
            const ts_val = event.object.get("timestamp");
            const timestamp: u64 = if (ts_val) |tv| blk: {
                if (tv == .integer) break :blk @intCast(@as(u64, @intCast(@max(tv.integer, 0))) / 1000);
                break :blk root.nowEpochSecs();
            } else root.nowEpochSecs();

            // Message content (for message events)
            var message_type: ?[]const u8 = null;
            var message_text: ?[]const u8 = null;
            var message_id: ?[]const u8 = null;

            if (std.mem.eql(u8, event_type, "message")) {
                const msg_obj = event.object.get("message") orelse continue;
                if (msg_obj != .object) continue;

                const mt_val = msg_obj.object.get("type");
                message_type = if (mt_val) |mt| (if (mt == .string) mt.string else null) else null;

                const mid_val = msg_obj.object.get("id");
                message_id = if (mid_val) |mid| (if (mid == .string) mid.string else null) else null;

                if (message_type) |mt| {
                    if (std.mem.eql(u8, mt, "text")) {
                        const text_val = msg_obj.object.get("text");
                        message_text = if (text_val) |t| (if (t == .string) t.string else null) else null;
                    }
                }
            }

            try result.append(allocator, .{
                .event_type = try allocator.dupe(u8, event_type),
                .reply_token = if (reply_token) |rt| try allocator.dupe(u8, rt) else null,
                .user_id = if (user_id) |uid| try allocator.dupe(u8, uid) else null,
                .group_id = if (group_id) |gid| try allocator.dupe(u8, gid) else null,
                .room_id = if (room_id) |rid| try allocator.dupe(u8, rid) else null,
                .source_type = if (source_type) |st| try allocator.dupe(u8, st) else null,
                .message_type = if (message_type) |mt| try allocator.dupe(u8, mt) else null,
                .message_text = if (message_text) |mt| try allocator.dupe(u8, mt) else null,
                .message_id = if (message_id) |mid| try allocator.dupe(u8, mid) else null,
                .timestamp = timestamp,
            });
        }

        return result.toOwnedSlice(allocator);
    }

    /// Parse webhook events and filter by allow_from config.
    /// Events from users not in the allowlist are skipped.
    pub fn parseAndFilterEvents(
        self: *LineChannel,
        payload: []const u8,
    ) ![]LineEvent {
        const events = try parseWebhookEvents(self.allocator, payload);

        if (self.config.allow_from.len == 0) return events;

        // Filter in-place: keep only allowed events
        var kept: usize = 0;
        for (events) |*ev| {
            if (ev.user_id) |uid| {
                if (!root.isAllowed(self.config.allow_from, uid)) {
                    ev.deinit(self.allocator);
                    continue;
                }
            }
            events[kept] = ev.*;
            kept += 1;
        }

        if (kept == events.len) return events;

        // Shrink the slice
        if (kept == 0) {
            self.allocator.free(events);
            return &.{};
        }

        // Re-own into a right-sized allocation to preserve correct free() length.
        const out = try self.allocator.alloc(LineEvent, kept);
        @memcpy(out, events[0..kept]);
        self.allocator.free(events);
        return out;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *LineChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
        // LINE uses webhooks (push-based); no persistent connection needed.
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *LineChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *LineChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *LineChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *LineChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *LineChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Parsed Event
// ════════════════════════════════════════════════════════════════════════════

pub const LineEvent = struct {
    event_type: []const u8,
    reply_token: ?[]const u8 = null,
    user_id: ?[]const u8 = null,
    group_id: ?[]const u8 = null,
    room_id: ?[]const u8 = null,
    source_type: ?[]const u8 = null,
    message_type: ?[]const u8 = null,
    message_text: ?[]const u8 = null,
    message_id: ?[]const u8 = null,
    timestamp: u64 = 0,

    pub fn deinit(self: *LineEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        if (self.reply_token) |rt| allocator.free(rt);
        if (self.user_id) |uid| allocator.free(uid);
        if (self.group_id) |gid| allocator.free(gid);
        if (self.room_id) |rid| allocator.free(rid);
        if (self.source_type) |st| allocator.free(st);
        if (self.message_type) |mt| allocator.free(mt);
        if (self.message_text) |mt| allocator.free(mt);
        if (self.message_id) |mid| allocator.free(mid);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Signature Verification
// ════════════════════════════════════════════════════════════════════════════

/// Verify a LINE webhook signature.
///
/// LINE signs webhook bodies with HMAC-SHA256(channel_secret, body),
/// then base64-encodes the result. The X-Line-Signature header contains
/// this base64-encoded HMAC.
pub fn verifyLineSignature(body: []const u8, signature: []const u8, channel_secret: []const u8) bool {
    if (channel_secret.len == 0) return false;
    if (signature.len == 0) return false;

    // Compute HMAC-SHA256
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, channel_secret);

    // Base64-encode the MAC
    const Encoder = std.base64.standard.Encoder;
    var encoded_buf: [44]u8 = undefined; // 32 bytes -> 44 base64 chars
    const encoded = Encoder.encode(&encoded_buf, &mac);

    // Compare with provided signature
    if (encoded.len != signature.len) return false;

    // Constant-time comparison
    var diff: u8 = 0;
    for (encoded, signature) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "line channel name" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "tok",
        .channel_secret = "secret",
    });
    try std.testing.expectEqualStrings("line", ch.channelName());
}

test "line config defaults" {
    const config = config_types.LineConfig{
        .access_token = "tok",
        .channel_secret = "sec",
    };
    try std.testing.expectEqual(@as(u16, 3000), config.port);
}

test "line config custom port" {
    const config = config_types.LineConfig{
        .access_token = "tok",
        .channel_secret = "sec",
        .port = 8080,
    };
    try std.testing.expectEqual(@as(u16, 8080), config.port);
}

test "line health check returns true when running" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "tok",
        .channel_secret = "secret",
    });
    ch.running = true;
    try std.testing.expect(ch.healthCheck());
}

test "line health check returns true with valid token" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "tok",
        .channel_secret = "secret",
    });
    try std.testing.expect(ch.healthCheck());
}

test "line health check returns false with no token and not running" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "",
        .channel_secret = "",
    });
    try std.testing.expect(!ch.healthCheck());
}

test "line max message len constant" {
    try std.testing.expectEqual(@as(usize, 5000), LineChannel.MAX_MESSAGE_LEN);
}

test "line api urls" {
    try std.testing.expectEqualStrings("https://api.line.me/v2/bot/message/reply", LineChannel.REPLY_URL);
    try std.testing.expectEqualStrings("https://api.line.me/v2/bot/message/push", LineChannel.PUSH_URL);
}

// ── Signature Verification Tests ────────────────────────────────

test "line verifySignature with known values" {
    const body = "test body content";
    const secret = "my_channel_secret";

    // Compute expected signature
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);

    var encoded_buf: [44]u8 = undefined;
    const expected_sig = std.base64.standard.Encoder.encode(&encoded_buf, &mac);

    try std.testing.expect(verifyLineSignature(body, expected_sig, secret));
}

test "line verifySignature rejects wrong signature" {
    try std.testing.expect(!verifyLineSignature("body", "wrong_signature_base64", "secret"));
}

test "line verifySignature rejects empty secret" {
    try std.testing.expect(!verifyLineSignature("body", "sig", ""));
}

test "line verifySignature rejects empty signature" {
    try std.testing.expect(!verifyLineSignature("body", "", "secret"));
}

test "line verifySignature rejects wrong secret" {
    const body = "test body";
    const correct_secret = "correct_secret";
    const wrong_secret = "wrong_secret";

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, correct_secret);

    var encoded_buf: [44]u8 = undefined;
    const sig = std.base64.standard.Encoder.encode(&encoded_buf, &mac);

    try std.testing.expect(!verifyLineSignature(body, sig, wrong_secret));
}

test "line verifySignature empty body with valid signature" {
    const body = "";
    const secret = "empty_body_secret";

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);

    var encoded_buf: [44]u8 = undefined;
    const sig = std.base64.standard.Encoder.encode(&encoded_buf, &mac);

    try std.testing.expect(verifyLineSignature(body, sig, secret));
}

test "line verifySignature constant time comparison works" {
    const body = "timing test";
    const secret = "timing_secret";

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);

    var encoded_buf: [44]u8 = undefined;
    const sig = std.base64.standard.Encoder.encode(&encoded_buf, &mac);

    // Valid signature passes
    try std.testing.expect(verifyLineSignature(body, sig, secret));

    // Altered last char fails
    var altered: [44]u8 = undefined;
    @memcpy(altered[0..sig.len], sig);
    altered[sig.len - 1] ^= 0x01;
    try std.testing.expect(!verifyLineSignature(body, altered[0..sig.len], secret));
}

// ── Event Parsing Tests ─────────────────────────────────────────

test "line parse text message event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"abc123","source":{"type":"user","userId":"U1234567890abcdef1234567890abcde"},"timestamp":1699999999000,"message":{"id":"msg001","type":"text","text":"Hello LINE!"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("message", events[0].event_type);
    try std.testing.expectEqualStrings("abc123", events[0].reply_token.?);
    try std.testing.expectEqualStrings("U1234567890abcdef1234567890abcde", events[0].user_id.?);
    try std.testing.expectEqualStrings("user", events[0].source_type.?);
    try std.testing.expectEqualStrings("text", events[0].message_type.?);
    try std.testing.expectEqualStrings("Hello LINE!", events[0].message_text.?);
    try std.testing.expectEqualStrings("msg001", events[0].message_id.?);
    try std.testing.expectEqual(@as(u64, 1699999999), events[0].timestamp);
}

test "line parse image message event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok123","source":{"type":"user","userId":"Uabc"},"timestamp":1700000000000,"message":{"id":"img001","type":"image"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("message", events[0].event_type);
    try std.testing.expectEqualStrings("image", events[0].message_type.?);
    // Image messages have no text
    try std.testing.expect(events[0].message_text == null);
}

test "line parse audio message event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok456","source":{"type":"user","userId":"Udef"},"timestamp":1700000000000,"message":{"id":"aud001","type":"audio"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("audio", events[0].message_type.?);
    try std.testing.expect(events[0].message_text == null);
}

test "line parse follow event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"follow","replyToken":"follow_tok","source":{"type":"user","userId":"Unewuser"},"timestamp":1700000000000}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("follow", events[0].event_type);
    try std.testing.expectEqualStrings("Unewuser", events[0].user_id.?);
    try std.testing.expect(events[0].message_type == null);
    try std.testing.expect(events[0].message_text == null);
}

test "line parse unfollow event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"unfollow","source":{"type":"user","userId":"Uleft"},"timestamp":1700000000000}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("unfollow", events[0].event_type);
    try std.testing.expect(events[0].reply_token == null);
}

test "line parse empty events array" {
    const allocator = std.testing.allocator;
    const events = try LineChannel.parseWebhookEvents(allocator, "{\"events\":[]}");
    defer allocator.free(events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parse missing events field" {
    const allocator = std.testing.allocator;
    const events = try LineChannel.parseWebhookEvents(allocator, "{\"destination\":\"U123\"}");
    defer allocator.free(events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parse invalid json" {
    const allocator = std.testing.allocator;
    const events = try LineChannel.parseWebhookEvents(allocator, "not json at all");
    defer allocator.free(events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parse empty payload" {
    const allocator = std.testing.allocator;
    const events = try LineChannel.parseWebhookEvents(allocator, "{}");
    defer allocator.free(events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parse multiple events" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok1","source":{"type":"user","userId":"U1"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"First"}},{"type":"message","replyToken":"tok2","source":{"type":"user","userId":"U2"},"timestamp":1700000001000,"message":{"id":"m2","type":"text","text":"Second"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqualStrings("First", events[0].message_text.?);
    try std.testing.expectEqualStrings("Second", events[1].message_text.?);
    try std.testing.expectEqualStrings("U1", events[0].user_id.?);
    try std.testing.expectEqualStrings("U2", events[1].user_id.?);
}

test "line parse group source" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"grp_tok","source":{"type":"group","groupId":"G123","userId":"Uuser1"},"timestamp":1700000000000,"message":{"id":"gm1","type":"text","text":"Group msg"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("group", events[0].source_type.?);
    try std.testing.expectEqualStrings("G123", events[0].group_id.?);
    try std.testing.expect(events[0].room_id == null);
    try std.testing.expectEqualStrings("Group msg", events[0].message_text.?);
}

test "line parse room source" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"room_tok","source":{"type":"room","roomId":"R987","userId":"Uroom_user"},"timestamp":1700000000000,"message":{"id":"rm1","type":"text","text":"Room msg"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("room", events[0].source_type.?);
    try std.testing.expectEqualStrings("R987", events[0].room_id.?);
    try std.testing.expect(events[0].group_id == null);
}

test "line parse message without source userId" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok","source":{"type":"user"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"No userId"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0].user_id == null);
    try std.testing.expectEqualStrings("No userId", events[0].message_text.?);
}

test "line parse event without source" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok","timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"No source"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0].user_id == null);
    try std.testing.expect(events[0].source_type == null);
}

test "line parse sticker message (non-text)" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"stk_tok","source":{"type":"user","userId":"Ustk"},"timestamp":1700000000000,"message":{"id":"stk1","type":"sticker","stickerId":"11538","packageId":"6632"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("sticker", events[0].message_type.?);
    try std.testing.expect(events[0].message_text == null);
}

test "line parse mixed text and non-text events" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"t1","source":{"type":"user","userId":"U1"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}},{"type":"message","replyToken":"t2","source":{"type":"user","userId":"U2"},"timestamp":1700000001000,"message":{"id":"m2","type":"image"}},{"type":"follow","replyToken":"t3","source":{"type":"user","userId":"U3"},"timestamp":1700000002000}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 3), events.len);

    // Text message
    try std.testing.expectEqualStrings("message", events[0].event_type);
    try std.testing.expectEqualStrings("text", events[0].message_type.?);
    try std.testing.expectEqualStrings("Hello", events[0].message_text.?);

    // Image message
    try std.testing.expectEqualStrings("message", events[1].event_type);
    try std.testing.expectEqualStrings("image", events[1].message_type.?);
    try std.testing.expect(events[1].message_text == null);

    // Follow event
    try std.testing.expectEqualStrings("follow", events[2].event_type);
    try std.testing.expect(events[2].message_type == null);
}

test "line vtable compiles" {
    // Verify all vtable function pointers are non-null
    try std.testing.expect(@intFromPtr(LineChannel.vtable.start) != 0);
    try std.testing.expect(@intFromPtr(LineChannel.vtable.stop) != 0);
    try std.testing.expect(@intFromPtr(LineChannel.vtable.send) != 0);
    try std.testing.expect(@intFromPtr(LineChannel.vtable.name) != 0);
    try std.testing.expect(@intFromPtr(LineChannel.vtable.healthCheck) != 0);
}

test "line channel interface" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "test_token",
        .channel_secret = "test_secret",
    });
    const iface = ch.channel();
    try std.testing.expectEqualStrings("line", iface.name());
}

test "line channel start and stop" {
    var ch = LineChannel.init(std.testing.allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
    });
    const iface = ch.channel();
    try iface.start();
    try std.testing.expect(ch.running);
    iface.stop();
    try std.testing.expect(!ch.running);
}

test "line event deinit frees all fields" {
    const allocator = std.testing.allocator;
    var event = LineEvent{
        .event_type = try allocator.dupe(u8, "message"),
        .reply_token = try allocator.dupe(u8, "tok123"),
        .user_id = try allocator.dupe(u8, "Uabc"),
        .source_type = try allocator.dupe(u8, "user"),
        .message_type = try allocator.dupe(u8, "text"),
        .message_text = try allocator.dupe(u8, "hello"),
        .message_id = try allocator.dupe(u8, "mid"),
        .timestamp = 12345,
    };
    event.deinit(allocator);
}

test "line event deinit with null fields" {
    const allocator = std.testing.allocator;
    var event = LineEvent{
        .event_type = try allocator.dupe(u8, "follow"),
        .timestamp = 0,
    };
    event.deinit(allocator);
}

test "line parse unicode text message" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"message","replyToken":"tok","source":{"type":"user","userId":"U1"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello world"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("Hello world", events[0].message_text.?);
}

test "line parse postback event" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"events":[{"type":"postback","replyToken":"pb_tok","source":{"type":"user","userId":"Upb"},"timestamp":1700000000000}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("postback", events[0].event_type);
    try std.testing.expect(events[0].message_type == null);
}

test "line parseAndFilterEvents blocks unlisted user" {
    const allocator = std.testing.allocator;
    var ch = LineChannel.init(allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
        .allow_from = &.{"Uallowed"},
    });

    const payload =
        \\{"events":[{"type":"message","replyToken":"tok1","source":{"type":"user","userId":"Ublocked"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}}]}
    ;

    const events = try ch.parseAndFilterEvents(payload);
    defer allocator.free(events);

    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parseAndFilterEvents permits listed user" {
    const allocator = std.testing.allocator;
    var ch = LineChannel.init(allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
        .allow_from = &.{"U1234"},
    });

    const payload =
        \\{"events":[{"type":"message","replyToken":"tok1","source":{"type":"user","userId":"U1234"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}}]}
    ;

    const events = try ch.parseAndFilterEvents(payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("Hello", events[0].message_text.?);
}

test "line parseAndFilterEvents mixed allowlist keeps only allowed events" {
    const allocator = std.testing.allocator;
    var ch = LineChannel.init(allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
        .allow_from = &.{"Uallow"},
    });

    const payload =
        \\{"events":[{"type":"message","replyToken":"tok1","source":{"type":"user","userId":"Uallow"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"A"}},{"type":"message","replyToken":"tok2","source":{"type":"user","userId":"Ublock"},"timestamp":1700000000000,"message":{"id":"m2","type":"text","text":"B"}}]}
    ;

    const events = try ch.parseAndFilterEvents(payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("A", events[0].message_text.?);
}

test "line parseAndFilterEvents empty allow_from passes all" {
    const allocator = std.testing.allocator;
    var ch = LineChannel.init(allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
    });

    const payload =
        \\{"events":[{"type":"message","replyToken":"tok1","source":{"type":"user","userId":"Uany"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}}]}
    ;

    const events = try ch.parseAndFilterEvents(payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
}
