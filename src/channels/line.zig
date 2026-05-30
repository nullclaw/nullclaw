const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const builtin = @import("builtin");
const std_compat = @import("compat");

const log = std.log.scoped(.line);

const MAX_REPLY_TARGET_LEN: usize = 64;
const MAX_REPLY_TOKEN_LEN: usize = 512;
const REPLY_TOKEN_CACHE_SIZE: usize = 16;
const REPLY_TOKEN_TTL_MS: i64 = 30 * std.time.ms_per_s;

const ReplyTokenData = struct {
    target: [MAX_REPLY_TARGET_LEN]u8,
    target_len: u8,
    token: [MAX_REPLY_TOKEN_LEN]u8,
    token_len: u16,
    received_at_ms: i64,
};

var g_reply_cache_mu: std_compat.sync.Mutex = .{};
var g_reply_cache: [REPLY_TOKEN_CACHE_SIZE]ReplyTokenData = undefined;
var g_reply_cache_count: usize = 0;

pub fn cacheReplyToken(target: []const u8, token: []const u8) void {
    if (target.len > MAX_REPLY_TARGET_LEN or token.len > MAX_REPLY_TOKEN_LEN) return;

    g_reply_cache_mu.lock();
    defer g_reply_cache_mu.unlock();

    const now = std_compat.time.milliTimestamp();

    var i: usize = 0;
    while (i < g_reply_cache_count) : (i += 1) {
        const cached = &g_reply_cache[i];
        if (std.mem.eql(u8, cached.target[0..cached.target_len], target)) {
            @memcpy(cached.token[0..token.len], token);
            cached.token_len = @intCast(token.len);
            cached.received_at_ms = now;
            return;
        }
    }

    if (g_reply_cache_count < g_reply_cache.len) {
        const cached = &g_reply_cache[g_reply_cache_count];
        @memcpy(cached.target[0..target.len], target);
        cached.target_len = @intCast(target.len);
        @memcpy(cached.token[0..token.len], token);
        cached.token_len = @intCast(token.len);
        cached.received_at_ms = now;
        g_reply_cache_count += 1;
    } else {
        var oldest_idx: usize = 0;
        var oldest_time = g_reply_cache[0].received_at_ms;
        var j: usize = 1;
        while (j < g_reply_cache.len) : (j += 1) {
            if (g_reply_cache[j].received_at_ms < oldest_time) {
                oldest_time = g_reply_cache[j].received_at_ms;
                oldest_idx = j;
            }
        }
        const cached = &g_reply_cache[oldest_idx];
        @memcpy(cached.target[0..target.len], target);
        cached.target_len = @intCast(target.len);
        @memcpy(cached.token[0..token.len], token);
        cached.token_len = @intCast(token.len);
        cached.received_at_ms = now;
    }
}

fn removeReplyCacheEntryLocked(index: usize) void {
    const last = g_reply_cache_count - 1;
    if (index != last) {
        g_reply_cache[index] = g_reply_cache[last];
    }
    g_reply_cache_count = last;
}

pub fn takeReplyToken(target: []const u8, out: *[MAX_REPLY_TOKEN_LEN]u8) ?[]const u8 {
    g_reply_cache_mu.lock();
    defer g_reply_cache_mu.unlock();

    const now = std_compat.time.milliTimestamp();
    var i: usize = 0;
    while (i < g_reply_cache_count) : (i += 1) {
        const cached = &g_reply_cache[i];
        if (std.mem.eql(u8, cached.target[0..cached.target_len], target)) {
            if (now - cached.received_at_ms <= REPLY_TOKEN_TTL_MS) {
                @memcpy(out[0..cached.token_len], cached.token[0..cached.token_len]);
                removeReplyCacheEntryLocked(i);
                return out[0..cached.token_len];
            }
            removeReplyCacheEntryLocked(i);
            return null;
        }
    }
    return null;
}

pub fn resetReplyTokenCacheForTest() void {
    if (!builtin.is_test) return;
    g_reply_cache_mu.lock();
    defer g_reply_cache_mu.unlock();
    g_reply_cache_count = 0;
}

fn buildReplyRequestBody(allocator: std.mem.Allocator, reply_token: []const u8, text: []const u8) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);
    var body_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &body_list);
    errdefer body_writer.deinit();
    const w = &body_writer.writer;

    try w.writeAll("{\"replyToken\":");
    try root.appendJsonStringW(w, reply_token);
    try w.writeAll(",\"messages\":[{\"type\":\"text\",\"text\":");
    try root.appendJsonStringW(w, text);
    try w.writeAll("}]}");

    body_list = body_writer.toArrayList();
    return try body_list.toOwnedSlice(allocator);
}

fn buildPushRequestBody(allocator: std.mem.Allocator, user_id: []const u8, text: []const u8) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);
    var body_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &body_list);
    errdefer body_writer.deinit();
    const w = &body_writer.writer;

    try w.writeAll("{\"to\":");
    try root.appendJsonStringW(w, user_id);
    try w.writeAll(",\"messages\":[{\"type\":\"text\",\"text\":");
    try root.appendJsonStringW(w, text);
    try w.writeAll("}]}");

    body_list = body_writer.toArrayList();
    return try body_list.toOwnedSlice(allocator);
}

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

    /// Reply to a message using a LINE replyToken.
    pub fn replyMessage(self: *LineChannel, reply_token: []const u8, text: []const u8) !void {
        if (builtin.is_test) {
            if (std.mem.indexOf(u8, reply_token, "fail_reply") != null or std.mem.indexOf(u8, reply_token, "fail_reply_and_push") != null) {
                return error.LineApiError;
            }
            return;
        }
        const body = try buildReplyRequestBody(self.allocator, reply_token, text);
        defer self.allocator.free(body);

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bearer {s}", .{self.config.access_token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, REPLY_URL, body, &.{auth_header}, null) catch |err| {
            log.err("replyMessage failed: {}", .{err});
            return error.LineApiError;
        };
        self.allocator.free(resp);
    }

    /// Push a message to a user by userId (no replyToken needed).
    pub fn pushMessage(self: *LineChannel, user_id: []const u8, text: []const u8) !void {
        if (builtin.is_test) {
            if (std.mem.indexOf(u8, user_id, "fail_push") != null or std.mem.indexOf(u8, user_id, "fail_reply_and_push") != null) {
                return error.LineApiError;
            }
            return;
        }
        const body = try buildPushRequestBody(self.allocator, user_id, text);
        defer self.allocator.free(body);

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bearer {s}", .{self.config.access_token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, PUSH_URL, body, &.{auth_header}, null) catch |err| {
            log.err("pushMessage failed: {}", .{err});
            return error.LineApiError;
        };
        self.allocator.free(resp);
    }

    /// Send a message. If target is a source ID (exactly 33 characters starting with 'U', 'C', or 'R'),
    /// try to use the cached replyToken first, falling back to pushMessage. Otherwise, treat as a replyToken.
    pub fn sendMessage(self: *LineChannel, target: []const u8, text: []const u8) !void {
        const is_source_id = target.len == 33 and (target[0] == 'U' or target[0] == 'C' or target[0] == 'R');

        if (is_source_id) {
            var reply_token_buf: [MAX_REPLY_TOKEN_LEN]u8 = undefined;
            if (takeReplyToken(target, &reply_token_buf)) |rt| {
                self.replyMessage(rt, text) catch |err| {
                    log.warn("replyMessage failed with cached token ({}), falling back to pushMessage", .{err});
                    try self.pushMessage(target, text);
                };
            } else {
                try self.pushMessage(target, text);
            }
        } else {
            try self.replyMessage(target, text);
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

        // Filter in-place: keep only allowed events
        var kept: usize = 0;
        for (events) |*ev| {
            if (ev.user_id) |uid| {
                if (root.isAllowedScoped("line channel", self.config.allow_from, uid)) {
                    events[kept] = ev.*;
                    kept += 1;
                    continue;
                }
            }
            ev.deinit(self.allocator);
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

test "line buildReplyRequestBody includes non-empty body" {
    const alloc = std.testing.allocator;
    // Regression: Writer.Allocating must be finalized before the LINE POST body is read.
    const body = try buildReplyRequestBody(alloc, "reply-token", "hello line");
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"replyToken\":\"reply-token\",\"messages\":[{\"type\":\"text\",\"text\":\"hello line\"}]}", body);
}

test "line buildPushRequestBody includes non-empty body" {
    const alloc = std.testing.allocator;
    const body = try buildPushRequestBody(alloc, "U123", "hello push");
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"to\":\"U123\",\"messages\":[{\"type\":\"text\",\"text\":\"hello push\"}]}", body);
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

test "line parseAndFilterEvents empty allow_from denies all" {
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

    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "line parseAndFilterEvents wildcard allow_from passes all" {
    const allocator = std.testing.allocator;
    var ch = LineChannel.init(allocator, .{
        .access_token = "tok",
        .channel_secret = "sec",
        .allow_from = &.{"*"},
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

test "LineChannel create + healthCheck + stop leaks zero bytes" {
    // LineChannel holds no heap allocations at init-time.  No deinit needed.
    var ch_struct = LineChannel.initFromConfig(std.testing.allocator, .{
        .access_token = "test-access-token",
        .channel_secret = "test-channel-secret",
    });

    const ch = ch_struct.channel();
    _ = ch.healthCheck();
    ch.stop();
}

test "verifyLineSignature rejects tampered body" {
    // Compute a valid sig for the original body, then verify that presenting
    // the same sig with a different body is rejected.  Guards against future
    // regressions where the HMAC input is silently short-circuited.
    const secret = "channel-secret-abc";
    const original_body = "webhook-body-content";
    const tampered_body = "webhook-body-content_tampered";

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, original_body, secret);

    var encoded_buf: [44]u8 = undefined;
    const valid_sig = std.base64.standard.Encoder.encode(&encoded_buf, &mac);

    // Correct body + correct sig: must accept.
    try std.testing.expect(verifyLineSignature(original_body, valid_sig, secret));
    // Tampered body + original sig: must reject.
    try std.testing.expect(!verifyLineSignature(tampered_body, valid_sig, secret));
}

test "line parseWebhookEvents does not cache reply tokens" {
    resetReplyTokenCacheForTest();
    defer resetReplyTokenCacheForTest();

    const allocator = std.testing.allocator;
    const target = "U" ++ ("9" ** 32);
    const payload =
        \\{"events":[{"type":"message","replyToken":"parse_only_token","source":{"type":"user","userId":"
    ++ target ++
        \\"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}}]}
    ;

    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }

    var token_buf: [MAX_REPLY_TOKEN_LEN]u8 = undefined;
    // Regression: parsing should stay side-effect-free; the gateway caches only
    // after signature and sender allowlist checks have passed.
    try std.testing.expect(takeReplyToken(target, &token_buf) == null);
}

test "line reply token cache take consumes token" {
    resetReplyTokenCacheForTest();
    defer resetReplyTokenCacheForTest();

    const target = "U" ++ ("8" ** 32);
    cacheReplyToken(target, "one_time_token");

    var token_buf: [MAX_REPLY_TOKEN_LEN]u8 = undefined;
    const token = takeReplyToken(target, &token_buf) orelse return error.TestExpectedEqual;
    // Regression: LINE replyTokens are one-use, so cached tokens must not be reused.
    try std.testing.expectEqualStrings("one_time_token", token);
    try std.testing.expect(takeReplyToken(target, &token_buf) == null);
}

test "LineChannel sendMessage routing and fallback" {
    resetReplyTokenCacheForTest();
    defer resetReplyTokenCacheForTest();

    const allocator = std.testing.allocator;

    var ch = LineChannel.init(allocator, .{
        .access_token = "test-token",
        .channel_secret = "test-secret",
    });

    // 1. Target is a source ID (len == 33, starts with U/C/R) and not cached -> pushMessage directly.
    try std.testing.expectError(error.LineApiError, ch.sendMessage("U1234567890123456789012_fail_push", "hello"));
    try ch.sendMessage("U123456789012345678901234567_norm", "hello");

    // 2. Target is a reply token (len != 33) -> replyMessage directly.
    try std.testing.expectError(error.LineApiError, ch.sendMessage("fail_reply_longer_token_value_here", "hello"));
    try ch.sendMessage("normal_reply_token_longer_value_here", "hello");

    // 3. Test caching: cache a webhook reply token, then call sendMessage on that sourceId.
    const payload =
        \\{"events":[{"type":"message","replyToken":"cached_token_abc","source":{"type":"user","userId":"U1234567890123456789012345_cached"},"timestamp":1700000000000,"message":{"id":"m1","type":"text","text":"Hello"}}]}
    ;
    const events = try LineChannel.parseWebhookEvents(allocator, payload);
    defer {
        for (events) |*e| {
            var ev = e.*;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }
    cacheReplyToken(events[0].user_id.?, events[0].reply_token.?);

    // Now sendMessage should use the cached token, which routes to replyMessage and succeeds.
    try ch.sendMessage("U1234567890123456789012345_cached", "hello");

    // 4. Test fallback with cached token: cache a token that fails in replyMessage.
    cacheReplyToken("U12345678901234567890123_fallback", "fail_reply");
    // Since replyMessage fails, it should fallback to pushMessage which succeeds.
    try ch.sendMessage("U12345678901234567890123_fallback", "hello");

    // 5. Both fail with cached token.
    cacheReplyToken("U1234567890123456789012_fail_push", "fail_reply");
    try std.testing.expectError(error.LineApiError, ch.sendMessage("U1234567890123456789012_fail_push", "hello"));
}
