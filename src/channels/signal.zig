//! Signal channel via signal-cli REST API.
//!
//! Connects to a running `signal-cli-rest-api` container (MODE=normal).
//! Receives messages via WebSocket at `/v1/receive/{number}` and sends via
//! REST POST to `/v2/send`.
//!
//! Config example (in config.json):
//! ```json
//! {
//!   "channels": {
//!     "signal": {
//!       "accounts": {
//!         "default": {
//!           "http_url": "http://127.0.0.1:8080",
//!           "account": "+1234567890",
//!           "allow_from": ["+1111111111", "uuid:a1b2c3d4-..."],
//!           "group_allow_from": ["+1111111111"],
//!           "group_policy": "allowlist",
//!           "ignore_attachments": true,
//!           "ignore_stories": true
//!         }
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Environment variable override:
//!   SIGNAL_HTTP_URL, SIGNAL_ACCOUNT
//!
//! Prerequisites:
//!   signal-cli must be running in daemon mode:
//!     signal-cli --account +1234567890 daemon --http 127.0.0.1:8080

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const platform = @import("../platform.zig");

const log = std.log.scoped(.signal);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

/// Prefix used to identify group targets in reply_target strings.
pub const GROUP_TARGET_PREFIX = "group:";

/// Interval for re-sending typing indicator (8 seconds).
const TYPING_INTERVAL_NS: u64 = 8 * std.time.ns_per_s;
const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms; // 100ms sleep steps

/// Extract a stable group peer ID from reply_target.
/// For non-group targets returns the raw target or "unknown".
pub fn signalGroupPeerId(reply_target: ?[]const u8) []const u8 {
    const target = reply_target orelse "unknown";
    if (std.mem.startsWith(u8, target, GROUP_TARGET_PREFIX)) {
        const raw = target[GROUP_TARGET_PREFIX.len..];
        if (raw.len > 0) return raw;
    }
    return target;
}

/// Health check endpoint for the signal-cli daemon.
const SIGNAL_HEALTH_ENDPOINT = "/v1/health";

/// REST endpoint for sending messages.
const SIGNAL_SEND_ENDPOINT = "/v2/send";

/// WebSocket endpoint prefix for receiving messages.
const SIGNAL_RECEIVE_ENDPOINT = "/v1/receive/";

/// Maximum message length for Signal messages (signal-cli has no hard limit,
/// but we chunk at 4096 to match typical messenger UX).
pub const MAX_MESSAGE_LEN: usize = 4096;

// ════════════════════════════════════════════════════════════════════════════
// Recipient Target
// ════════════════════════════════════════════════════════════════════════════

/// Classification of outbound message recipients.
pub const RecipientTarget = union(enum) {
    /// Direct message to a phone number or UUID.
    direct: []const u8,
    /// Group message by group ID.
    group: []const u8,
};

// ════════════════════════════════════════════════════════════════════════════
// Signal Channel
// ════════════════════════════════════════════════════════════════════════════

/// Signal channel — uses signal-cli REST API.
///
/// Sends messages via REST POST to `/v2/send`.
/// Incoming messages are consumed over WebSocket at `/v1/receive/{number}`.
pub const SignalChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    /// Base URL of the signal-cli daemon (e.g. "http://127.0.0.1:8080").
    /// Trailing slashes are stripped on init.
    http_url: []const u8,
    /// Signal account identifier (E.164 phone, e.g. "+1234567890").
    account: []const u8,
    /// Users allowed to interact. Empty = deny all (secure by default).
    allow_from: []const []const u8,
    /// Senders allowed in group chats when group_policy is allowlist.
    /// Empty means fallback to allow_from.
    group_allow_from: []const []const u8,
    /// Group policy: "open" | "allowlist" | "disabled".
    group_policy: []const u8,
    /// Skip messages that contain only attachments (no text).
    ignore_attachments: bool,
    /// Skip story messages.
    ignore_stories: bool,
    /// Persistent WS connection for streaming message delivery.
    /// Initialized on first poll, maintained across polls for real-time delivery.
    ws_conn: ?WsConnection = null,
    /// Backoff for reconnect attempts after WS connect failures.
    ws_retry_delay_secs: u64 = 2,
    /// Earliest wall-clock timestamp (seconds) for the next reconnect attempt.
    ws_next_retry_at: i64 = 0,

    /// Typing indicator management (mirrors Discord implementation).
    typing_mu: std.Thread.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,

    const TypingTask = struct {
        channel: *SignalChannel,
        target: []const u8,
        stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
    };

    const WS_READ_TIMEOUT_MS: i32 = 1000;
    const WS_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

    const WsConnection = struct {
        allocator: std.mem.Allocator,
        stream: std.net.Stream,

        fn connect(allocator: std.mem.Allocator, ws_url: []const u8) !WsConnection {
            var host_buf: [512]u8 = undefined;
            var path_buf: [1024]u8 = undefined;
            const parts = try wsConnectParts(ws_url, &host_buf, &path_buf);

            const addr_list = try std.net.getAddressList(allocator, parts.host, parts.port);
            defer addr_list.deinit();
            if (addr_list.addrs.len == 0) return error.WsConnectFailed;
            const stream = try std.net.tcpConnectToAddress(addr_list.addrs[0]);
            errdefer stream.close();

            var key_raw: [16]u8 = undefined;
            std.crypto.random.bytes(&key_raw);
            var key_b64: [24]u8 = undefined;
            _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

            var req_buf: [4096]u8 = undefined;
            var req_fbs = std.io.fixedBufferStream(&req_buf);
            const req_w = req_fbs.writer();
            try req_w.print("GET {s} HTTP/1.1\r\n", .{parts.path});
            try req_w.print("Host: {s}:{d}\r\n", .{ parts.host, parts.port });
            try req_w.writeAll("Upgrade: websocket\r\n");
            try req_w.writeAll("Connection: Upgrade\r\n");
            try req_w.print("Sec-WebSocket-Key: {s}\r\n", .{key_b64});
            try req_w.writeAll("Sec-WebSocket-Version: 13\r\n");
            try req_w.writeAll("\r\n");
            try stream.writeAll(req_fbs.getWritten());

            var resp_buf: [4096]u8 = undefined;
            var resp_len: usize = 0;
            while (resp_len < resp_buf.len) {
                const n = stream.read(resp_buf[resp_len..]) catch return error.WsHandshakeFailed;
                if (n == 0) return error.WsHandshakeFailed;
                resp_len += n;
                if (std.mem.indexOf(u8, resp_buf[0..resp_len], "\r\n\r\n") != null) break;
            }
            const resp = resp_buf[0..resp_len];
            if (!std.mem.startsWith(u8, resp, "HTTP/1.1 101")) {
                return error.WsHandshakeFailed;
            }

            const expected_accept = computeWsAcceptKey(&key_b64);
            if (std.mem.indexOf(u8, resp, &expected_accept) == null) {
                return error.WsHandshakeFailed;
            }

            return .{
                .allocator = allocator,
                .stream = stream,
            };
        }

        fn deinit(self: *WsConnection) void {
            self.stream.close();
        }

        fn waitReadable(self: *WsConnection, timeout_ms: i32) !bool {
            var poll_fds = [_]std.posix.pollfd{
                .{
                    .fd = self.stream.handle,
                    .events = std.posix.POLL.IN,
                    .revents = undefined,
                },
            };
            const events = std.posix.poll(&poll_fds, timeout_ms) catch return error.WsReadFailed;
            if (events == 0) return false;
            const revents = poll_fds[0].revents;
            if (revents & std.posix.POLL.IN != 0) return true;
            if (revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) {
                return error.ConnectionClosed;
            }
            return false;
        }

        fn readExact(self: *WsConnection, out: []u8) !void {
            var offset: usize = 0;
            while (offset < out.len) {
                const n = self.stream.read(out[offset..]) catch return error.WsReadFailed;
                if (n == 0) return error.ConnectionClosed;
                offset += n;
            }
        }

        fn writeMaskedFrame(self: *WsConnection, opcode: u8, payload: []const u8) !void {
            var header: [14]u8 = undefined;
            var hlen: usize = 0;
            header[0] = 0x80 | (opcode & 0x0F);
            hlen += 1;

            const plen = payload.len;
            if (plen <= 125) {
                header[1] = 0x80 | @as(u8, @intCast(plen));
                hlen += 1;
            } else if (plen <= 65535) {
                header[1] = 0x80 | 126;
                header[2] = @as(u8, @intCast((plen >> 8) & 0xFF));
                header[3] = @as(u8, @intCast(plen & 0xFF));
                hlen += 3;
            } else {
                header[1] = 0x80 | 127;
                const p64: u64 = plen;
                header[2] = @as(u8, @intCast((p64 >> 56) & 0xFF));
                header[3] = @as(u8, @intCast((p64 >> 48) & 0xFF));
                header[4] = @as(u8, @intCast((p64 >> 40) & 0xFF));
                header[5] = @as(u8, @intCast((p64 >> 32) & 0xFF));
                header[6] = @as(u8, @intCast((p64 >> 24) & 0xFF));
                header[7] = @as(u8, @intCast((p64 >> 16) & 0xFF));
                header[8] = @as(u8, @intCast((p64 >> 8) & 0xFF));
                header[9] = @as(u8, @intCast(p64 & 0xFF));
                hlen += 9;
            }

            var mask: [4]u8 = undefined;
            std.crypto.random.bytes(&mask);
            @memcpy(header[hlen..][0..4], &mask);
            hlen += 4;

            try self.stream.writeAll(header[0..hlen]);

            var scratch: [1024]u8 = undefined;
            var written: usize = 0;
            while (written < plen) {
                const chunk_len = @min(plen - written, scratch.len);
                for (0..chunk_len) |i| {
                    scratch[i] = payload[written + i] ^ mask[(written + i) % 4];
                }
                try self.stream.writeAll(scratch[0..chunk_len]);
                written += chunk_len;
            }
        }

        fn sendPong(self: *WsConnection, payload: []const u8) !void {
            try self.writeMaskedFrame(0xA, payload);
        }

        /// Reads one complete text message.
        /// Returns null when no bytes are currently available.
        fn readTextMessage(self: *WsConnection, allocator: std.mem.Allocator, timeout_ms: i32) !?[]u8 {
            if (!(try self.waitReadable(timeout_ms))) return null;

            var message: std.ArrayListUnmanaged(u8) = .empty;
            errdefer message.deinit(allocator);
            var started: bool = false;

            while (true) {
                var header: [2]u8 = undefined;
                try self.readExact(&header);
                const fin = (header[0] & 0x80) != 0;
                const opcode = header[0] & 0x0F;
                const masked = (header[1] & 0x80) != 0;
                var payload_len: u64 = @as(u64, header[1] & 0x7F);

                if (payload_len == 126) {
                    var ext: [2]u8 = undefined;
                    try self.readExact(&ext);
                    payload_len = (@as(u64, ext[0]) << 8) | ext[1];
                } else if (payload_len == 127) {
                    var ext: [8]u8 = undefined;
                    try self.readExact(&ext);
                    payload_len = 0;
                    for (ext) |b| payload_len = (payload_len << 8) | b;
                }

                if (payload_len > WS_MAX_MESSAGE_SIZE) return error.WsFrameTooLarge;

                var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
                if (masked) try self.readExact(&mask_key);

                const plen: usize = @intCast(payload_len);
                const payload = try allocator.alloc(u8, plen);
                defer allocator.free(payload);
                if (plen > 0) try self.readExact(payload);
                if (masked and plen > 0) {
                    for (payload, 0..) |*b, i| {
                        b.* ^= mask_key[i % 4];
                    }
                }

                switch (opcode) {
                    0x8 => return error.ConnectionClosed,
                    0x9 => {
                        try self.sendPong(payload);
                        continue;
                    },
                    0x1 => {
                        started = true;
                        try message.appendSlice(allocator, payload);
                        if (message.items.len > WS_MAX_MESSAGE_SIZE) return error.WsFrameTooLarge;
                        if (fin) return try message.toOwnedSlice(allocator);
                    },
                    0x0 => {
                        if (!started) continue;
                        try message.appendSlice(allocator, payload);
                        if (message.items.len > WS_MAX_MESSAGE_SIZE) return error.WsFrameTooLarge;
                        if (fin) return try message.toOwnedSlice(allocator);
                    },
                    else => {
                        if (started and fin) return try message.toOwnedSlice(allocator);
                    },
                }
            }
        }
    };

    pub fn init(
        allocator: std.mem.Allocator,
        http_url: []const u8,
        account: []const u8,
        allow_from: []const []const u8,
        group_allow_from: []const []const u8,
        ignore_attachments: bool,
        ignore_stories: bool,
    ) SignalChannel {
        return .{
            .allocator = allocator,
            .http_url = stripTrailingSlashes(http_url),
            .account = account,
            .allow_from = allow_from,
            .group_allow_from = group_allow_from,
            .group_policy = "allowlist",
            .ignore_attachments = ignore_attachments,
            .ignore_stories = ignore_stories,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.SignalConfig) SignalChannel {
        var ch = init(
            allocator,
            cfg.http_url,
            cfg.account,
            cfg.allow_from,
            cfg.group_allow_from,
            cfg.ignore_attachments,
            cfg.ignore_stories,
        );
        ch.account_id = cfg.account_id;
        ch.group_policy = cfg.group_policy;
        return ch;
    }

    pub fn channelName(_: *const SignalChannel) []const u8 {
        return "signal";
    }

    // ── URL Builders ────────────────────────────────────────────────

    /// Build the REST send URL.
    pub fn sendUrl(self: *const SignalChannel, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll(self.http_url);
        try w.writeAll(SIGNAL_SEND_ENDPOINT);
        return fbs.getWritten();
    }

    /// Build the WebSocket receive URL.
    pub fn receiveWsUrl(self: *const SignalChannel, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        const scheme = if (std.mem.startsWith(u8, self.http_url, "https://")) "wss://" else "ws://";
        try w.writeAll(scheme);
        const host_with_port = if (std.mem.startsWith(u8, self.http_url, "https://"))
            self.http_url["https://".len..]
        else if (std.mem.startsWith(u8, self.http_url, "http://"))
            self.http_url["http://".len..]
        else
            self.http_url;
        try w.writeAll(host_with_port);
        try w.writeAll(SIGNAL_RECEIVE_ENDPOINT);
        try w.writeAll(self.account);
        return fbs.getWritten();
    }

    fn uriComponentAsSlice(component: std.Uri.Component) []const u8 {
        return switch (component) {
            .raw => |v| v,
            .percent_encoded => |v| v,
        };
    }

    fn wsConnectParts(
        ws_url: []const u8,
        host_buf: []u8,
        path_buf: []u8,
    ) !struct { host: []const u8, port: u16, path: []const u8 } {
        const uri = std.Uri.parse(ws_url) catch return error.InvalidSignalWsUrl;
        const is_secure = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_secure and !std.ascii.eqlIgnoreCase(uri.scheme, "ws")) return error.InvalidSignalWsUrl;

        const host = uri.getHost(host_buf) catch return error.InvalidSignalWsUrl;
        const port: u16 = uri.port orelse (if (is_secure) @as(u16, 443) else @as(u16, 80));
        const raw_path = uriComponentAsSlice(uri.path);
        const query = if (uri.query) |q| uriComponentAsSlice(q) else "";

        var fbs = std.io.fixedBufferStream(path_buf);
        const w = fbs.writer();
        if (raw_path.len == 0) {
            try w.writeByte('/');
        } else {
            if (raw_path[0] != '/') try w.writeByte('/');
            try w.writeAll(raw_path);
        }
        if (query.len > 0) {
            try w.writeByte('?');
            try w.writeAll(query);
        }
        return .{
            .host = host,
            .port = port,
            .path = fbs.getWritten(),
        };
    }

    fn computeWsAcceptKey(key_b64: []const u8) [28]u8 {
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(key_b64);
        sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        sha1.final(&digest);
        var result: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&result, &digest);
        return result;
    }

    /// Build the health check URL.
    pub fn healthUrl(self: *const SignalChannel, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll(self.http_url);
        try w.writeAll(SIGNAL_HEALTH_ENDPOINT);
        return fbs.getWritten();
    }

    // ── Allowlist Checking ──────────────────────────────────────────

    /// Check whether a sender is in the allowed users list.
    ///
    /// - Empty list = deny all (secure by default).
    /// - `*` = allow everyone.
    /// - Entries with `uuid:` prefix are normalized before comparison.
    pub fn isSenderAllowed(self: *const SignalChannel, sender: []const u8) bool {
        if (self.allow_from.len == 0) return false;
        for (self.allow_from) |entry| {
            if (std.mem.eql(u8, entry, "*")) return true;
            if (std.mem.eql(u8, normalizeAllowEntry(entry), normalizeAllowEntry(sender))) return true;
        }
        return false;
    }

    /// Check whether a sender is allowed in group chats.
    ///
    /// - Empty list = use allow_from fallback for group sender checks.
    /// - `*` = allow all group senders.
    pub fn isGroupSenderAllowed(self: *const SignalChannel, sender: []const u8) bool {
        if (self.group_allow_from.len == 0) return false;
        for (self.group_allow_from) |entry| {
            if (std.mem.eql(u8, entry, "*")) return true;
            if (std.mem.eql(u8, normalizeAllowEntry(entry), normalizeAllowEntry(sender))) return true;
        }
        return false;
    }

    // ── Envelope Processing ─────────────────────────────────────────

    /// Process a parsed SSE envelope into a ChannelMessage.
    /// Returns null if the message should be dropped (denied sender, empty text, etc.).
    pub fn processEnvelope(
        self: *const SignalChannel,
        allocator: std.mem.Allocator,
        source: ?[]const u8,
        source_number: ?[]const u8,
        source_name: ?[]const u8,
        envelope_timestamp: ?u64,
        has_story_message: bool,
        // Data message fields (null if no data_message)
        dm_message: ?[]const u8,
        dm_timestamp: ?u64,
        dm_group_id: ?[]const u8,
        dm_attachment_ids: []const []const u8,
    ) !?root.ChannelMessage {
        // Skip story messages when configured.
        if (self.ignore_stories and has_story_message) return null;

        // No data message at all.
        const has_message_text = if (dm_message) |m| m.len > 0 else false;

        // If there's no data message content to process at all, skip.
        if (!has_message_text and dm_attachment_ids.len == 0) return null;

        // Skip attachment-only messages when configured.
        if (self.ignore_attachments and dm_attachment_ids.len > 0 and !has_message_text) return null;

        // Effective sender for reply target: prefer source_number (E.164), fall back to source (UUID).
        const sender_raw = source_number orelse source orelse return null;
        if (sender_raw.len == 0) return null;
        const sender_alt = blk: {
            if (source) |src| {
                if (!std.mem.eql(u8, src, sender_raw)) break :blk src;
            }
            break :blk null;
        };

        // Group/DM policy checks.
        if (dm_group_id != null) {
            if (std.mem.eql(u8, self.group_policy, "disabled")) return null;

            if (!std.mem.eql(u8, self.group_policy, "open")) {
                // Allowlist mode: check group_allow_from for sender, fall back to allow_from.
                const group_allowed = if (self.group_allow_from.len > 0)
                    self.isGroupSenderAllowed(sender_raw) or
                        (if (sender_alt) |alt| self.isGroupSenderAllowed(alt) else false)
                else
                    self.isSenderAllowed(sender_raw) or
                        (if (sender_alt) |alt| self.isSenderAllowed(alt) else false);
                if (!group_allowed) return null;
            }
        } else {
            // DM context: check allow_from
            if (!(self.isSenderAllowed(sender_raw) or
                (if (sender_alt) |alt| self.isSenderAllowed(alt) else false))) return null;
        }

        // Determine message text and fetch attachments.
        var text_buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer text_buf.deinit(allocator);

        if (has_message_text) {
            try text_buf.appendSlice(allocator, dm_message.?);
        }

        if (!self.ignore_attachments and dm_attachment_ids.len > 0) {
            const is_group = dm_group_id != null;
            const target_id = dm_group_id orelse sender_raw;
            for (dm_attachment_ids) |att_id| {
                if (try self.fetchAttachmentLocally(allocator, att_id, is_group, target_id)) |local_path| {
                    if (text_buf.items.len > 0) try text_buf.appendSlice(allocator, "\n");
                    try text_buf.appendSlice(allocator, "[IMAGE:");
                    try text_buf.appendSlice(allocator, local_path);
                    try text_buf.appendSlice(allocator, "]");
                } else {
                    if (text_buf.items.len > 0) try text_buf.appendSlice(allocator, "\n");
                    try text_buf.appendSlice(allocator, "[Attachment]");
                }
            }
        }

        if (text_buf.items.len == 0) return null;
        const text = try text_buf.toOwnedSlice(allocator);
        errdefer allocator.free(text);

        // Build reply target.
        const reply_target_str = if (dm_group_id) |gid| blk: {
            // "group:<gid>"
            var rt_buf: std.ArrayListUnmanaged(u8) = .empty;
            try rt_buf.appendSlice(allocator, GROUP_TARGET_PREFIX);
            try rt_buf.appendSlice(allocator, gid);
            break :blk try rt_buf.toOwnedSlice(allocator);
        } else blk: {
            break :blk try allocator.dupe(u8, sender_raw);
        };
        errdefer allocator.free(reply_target_str);

        // Timestamp: prefer data message, then envelope, then current time.
        const timestamp: u64 = dm_timestamp orelse envelope_timestamp orelse root.nowEpochSecs();

        // Build the channel message.
        const msg = root.ChannelMessage{
            .id = try allocator.dupe(u8, sender_raw),
            .sender = try allocator.dupe(u8, sender_raw),
            .content = text,
            .channel = "signal",
            .timestamp = timestamp,
            .reply_target = reply_target_str,
            .first_name = if (source_name) |sn| if (sn.len > 0) try allocator.dupe(u8, sn) else null else null,
            .is_group = dm_group_id != null,
            .sender_uuid = if (source) |src| if (src.len > 0 and isUuid(src)) try allocator.dupe(u8, src) else null else null,
            .group_id = if (dm_group_id) |gid| try allocator.dupe(u8, gid) else null,
        };

        return msg;
    }

    // ── REST Attachment Fetch ────────────────────────────────────────

    /// Fetch an attachment from the signal-cli daemon via REST GET.
    /// Returns absolute path to a saved temp file.
    pub fn fetchAttachmentLocally(self: *const SignalChannel, allocator: std.mem.Allocator, attachment_id: []const u8, is_group: bool, target_id: []const u8) !?[]const u8 {
        _ = is_group;
        _ = target_id;

        // Build URL: <base>/v1/attachments/<id>
        var url_body: std.ArrayListUnmanaged(u8) = .empty;
        defer url_body.deinit(allocator);
        try url_body.appendSlice(allocator, self.http_url);
        try url_body.appendSlice(allocator, "/v1/attachments/");
        try url_body.appendSlice(allocator, attachment_id);

        const url = try allocator.dupe(u8, url_body.items);
        defer allocator.free(url);

        const resp = root.http_util.curlGet(allocator, url, &.{}, "30") catch |err| {
            log.warn("Signal fetch attachment {s} failed: {}", .{ attachment_id, err });
            return null;
        };
        defer allocator.free(resp);

        // Generate temp file
        const rand = std.crypto.random;
        const rand_id = rand.int(u64);
        var path_buf: [1024]u8 = undefined;
        const local_path = try std.fmt.bufPrint(&path_buf, "/tmp/signal_{x}.dat", .{rand_id});

        var file = std.fs.createFileAbsolute(local_path, .{ .read = false }) catch return null;
        defer file.close();
        try file.writeAll(resp);

        return try allocator.dupe(u8, local_path);
    }

    // ── REST Send ───────────────────────────────────────────────────

    /// Build REST JSON body for the `/v2/send` endpoint.
    ///
    /// Returns caller-owned JSON body string.
    /// For direct targets: `"recipients":["+number"]`
    /// For group targets: `"recipients":["group.<id>"]`
    /// Attachments are passed as base64 strings in `"base64_attachments"`.
    pub fn buildRestBody(
        self: *const SignalChannel,
        allocator: std.mem.Allocator,
        target: RecipientTarget,
        message: ?[]const u8,
        base64_attachments: []const []const u8,
    ) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"number\":");
        try root.json_util.appendJsonString(&body, allocator, self.account);

        try body.appendSlice(allocator, ",\"recipients\":[");
        switch (target) {
            .direct => |id| {
                try root.json_util.appendJsonString(&body, allocator, id);
            },
            .group => |group_id| {
                // REST API uses "group.<id>" prefix for group recipients
                try body.appendSlice(allocator, "\"group.");
                // Append group_id chars (already safe base64/hex), then close quote
                try body.appendSlice(allocator, group_id);
                try body.appendSlice(allocator, "\"");
            },
        }
        try body.appendSlice(allocator, "]");

        if (message) |msg| {
            try body.appendSlice(allocator, ",\"message\":");
            try root.json_util.appendJsonString(&body, allocator, msg);
        }

        if (base64_attachments.len > 0) {
            try body.appendSlice(allocator, ",\"base64_attachments\":[");
            for (base64_attachments, 0..) |att, i| {
                if (i > 0) try body.appendSlice(allocator, ",");
                try root.json_util.appendJsonString(&body, allocator, att);
            }
            try body.appendSlice(allocator, "]");
        }

        try body.appendSlice(allocator, "}");

        return try body.toOwnedSlice(allocator);
    }

    /// Expand ~ to home directory and resolve to absolute path.
    /// If file doesn't exist or path is relative, return as-is (let signal-cli validate).
    fn resolveAttachmentPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
        if (path.len > 0 and path[0] == '~') {
            if (path.len == 1 or path[1] == '/') {
                const home = try platform.getHomeDir(allocator);
                defer allocator.free(home);
                if (path.len == 1) {
                    return try allocator.dupe(u8, home);
                }
                return try std.fs.path.join(allocator, &.{ home, path[2..] });
            }
        }
        if (std.fs.path.isAbsolute(path)) {
            return try allocator.dupe(u8, path);
        }
        // Try to resolve relative path, but if it fails (file doesn't exist),
        // just return the path as-is and let signal-cli handle the error
        return std.fs.cwd().realpathAlloc(allocator, path) catch try allocator.dupe(u8, path);
    }

    /// Parse [IMAGE:path] markers from message text.
    /// Returns extracted image paths and remaining text with markers removed.
    pub fn parseImageMarkers(allocator: std.mem.Allocator, text: []const u8) !struct { paths: [][]const u8, remaining: []const u8 } {
        var paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (paths_list.items) |p| allocator.free(p);
            paths_list.deinit(allocator);
        }

        var remaining: std.ArrayListUnmanaged(u8) = .empty;
        errdefer remaining.deinit(allocator);
        var removed_any_marker = false;

        var cursor: usize = 0;
        while (cursor < text.len) {
            const open_pos = std.mem.indexOfPos(u8, text, cursor, "[IMAGE:") orelse {
                try remaining.appendSlice(allocator, text[cursor..]);
                break;
            };

            // Trim trailing whitespace before the marker
            const before = std.mem.trimRight(u8, text[cursor..open_pos], " \t\n\r");
            try remaining.appendSlice(allocator, before);

            const close_pos = std.mem.indexOfPos(u8, text, open_pos + 7, "]") orelse {
                try remaining.appendSlice(allocator, text[open_pos..]);
                break;
            };

            const path = text[open_pos + 7 .. close_pos];
            if (path.len > 0) {
                const path_owned = try allocator.dupe(u8, path);
                errdefer allocator.free(path_owned);
                try paths_list.append(allocator, path_owned);
                removed_any_marker = true;
                cursor = close_pos + 1;
            } else {
                try remaining.appendSlice(allocator, text[open_pos .. close_pos + 1]);
                cursor = close_pos + 1;
            }
        }

        if (!removed_any_marker) {
            const remaining_owned = try allocator.dupe(u8, text);
            remaining.deinit(allocator);
            return .{
                .paths = try paths_list.toOwnedSlice(allocator),
                .remaining = remaining_owned,
            };
        }

        const trimmed = std.mem.trim(u8, remaining.items, " \t\n\r");
        const remaining_owned = try allocator.dupe(u8, trimmed);
        remaining.deinit(allocator);

        return .{
            .paths = try paths_list.toOwnedSlice(allocator),
            .remaining = remaining_owned,
        };
    }

    const PreparedOutgoingContent = struct {
        message_text: []const u8,
        attachments: [][]const u8,

        fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.message_text);
            for (self.attachments) |path| allocator.free(path);
            allocator.free(self.attachments);
        }
    };

    const OutgoingPayload = struct {
        message: ?[]const u8,
        attachment_index: ?usize = null,
    };

    fn prepareOutgoingContent(self: *SignalChannel, message: []const u8, media: []const []const u8) !PreparedOutgoingContent {
        const parsed = try parseImageMarkers(self.allocator, message);
        errdefer self.allocator.free(parsed.remaining);
        defer {
            for (parsed.paths) |p| self.allocator.free(p);
            self.allocator.free(parsed.paths);
        }

        // Combine explicitly passed media with parsed markers.
        var all_media: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (all_media.items) |m| self.allocator.free(m);
            all_media.deinit(self.allocator);
        }

        // Add explicitly passed media first (convert to absolute paths).
        for (media) |m| {
            const abs_path = try resolveAttachmentPath(self.allocator, m);
            errdefer self.allocator.free(abs_path);
            try all_media.append(self.allocator, abs_path);
        }

        // Add parsed image paths (avoid duplicates, convert to absolute).
        for (parsed.paths) |p| {
            const abs_path = try resolveAttachmentPath(self.allocator, p);
            var found = false;
            for (all_media.items) |m| {
                if (std.mem.eql(u8, m, abs_path)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                errdefer self.allocator.free(abs_path);
                try all_media.append(self.allocator, abs_path);
            } else {
                self.allocator.free(abs_path);
            }
        }

        return .{
            .message_text = parsed.remaining,
            .attachments = try all_media.toOwnedSlice(self.allocator),
        };
    }

    fn planOutgoingPayloads(
        allocator: std.mem.Allocator,
        message_text: []const u8,
        attachment_count: usize,
    ) ![]OutgoingPayload {
        var payloads: std.ArrayListUnmanaged(OutgoingPayload) = .empty;
        errdefer payloads.deinit(allocator);

        if (attachment_count == 0) {
            if (message_text.len == 0) return try allocator.alloc(OutgoingPayload, 0);

            var text_iter = root.splitMessage(message_text, MAX_MESSAGE_LEN);
            while (text_iter.next()) |chunk| {
                try payloads.append(allocator, .{ .message = chunk });
            }
            return try payloads.toOwnedSlice(allocator);
        }

        if (message_text.len > 0) {
            var text_iter = root.splitMessage(message_text, MAX_MESSAGE_LEN);
            while (text_iter.next()) |chunk| {
                try payloads.append(allocator, .{ .message = chunk });
            }
        }

        var i: usize = 0;
        while (i < attachment_count) : (i += 1) {
            try payloads.append(allocator, .{
                .message = null,
                .attachment_index = i,
            });
        }

        return try payloads.toOwnedSlice(allocator);
    }

    fn sendRestPayload(
        self: *SignalChannel,
        target: RecipientTarget,
        message: ?[]const u8,
        attachments: []const []const u8,
    ) !void {
        // Read attachment files from disk and base64-encode them.
        var b64_attachments: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (b64_attachments.items) |b| self.allocator.free(b);
            b64_attachments.deinit(self.allocator);
        }

        for (attachments) |path| {
            const file_data = std.fs.cwd().readFileAlloc(self.allocator, path, 10 * 1024 * 1024) catch |err| {
                log.warn("Signal: failed to read attachment {s}: {}", .{ path, err });
                continue;
            };
            defer self.allocator.free(file_data);

            const encoded_len = std.base64.standard.Encoder.calcSize(file_data.len);
            const encoded = try self.allocator.alloc(u8, encoded_len);
            errdefer self.allocator.free(encoded);
            _ = std.base64.standard.Encoder.encode(encoded, file_data);
            try b64_attachments.append(self.allocator, encoded);
        }

        const rest_body = try self.buildRestBody(self.allocator, target, message, b64_attachments.items);
        defer self.allocator.free(rest_body);

        var url_buf: [1024]u8 = undefined;
        const url = try self.sendUrl(&url_buf);

        const resp = root.http_util.curlPost(self.allocator, url, rest_body, &.{}) catch |err| {
            log.warn("Signal REST send failed: {}", .{err});
            return err;
        };
        self.allocator.free(resp);
    }

    /// Send a message via REST POST to the signal-cli daemon.
    /// Parses [IMAGE:path] markers from message text and sends as attachments.
    pub fn sendMessage(self: *SignalChannel, target_str: []const u8, message: []const u8, media: []const []const u8) !void {
        if (builtin.is_test) return;

        const target = parseRecipientTarget(target_str);
        const prepared = try self.prepareOutgoingContent(message, media);
        defer prepared.deinit(self.allocator);

        const payloads = try planOutgoingPayloads(self.allocator, prepared.message_text, prepared.attachments.len);
        defer self.allocator.free(payloads);

        for (payloads) |payload| {
            const attachments: []const []const u8 = if (payload.attachment_index) |idx|
                prepared.attachments[idx .. idx + 1]
            else
                &.{};
            try self.sendRestPayload(target, payload.message, attachments);
        }
    }

    /// Send a typing indicator (no-op — REST API has no typing endpoint).
    pub fn sendTypingIndicator(self: *SignalChannel, target_str: []const u8) void {
        _ = self;
        _ = target_str;
    }

    pub fn startTyping(self: *SignalChannel, target: []const u8) !void {
        if (target.len == 0) return;

        try self.stopTyping(target);

        const key_copy = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .target = key_copy,
        };

        task.thread = try std.Thread.spawn(.{ .stack_size = 128 * 1024 }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *SignalChannel, target: []const u8) !void {
        var removed_key: ?[]u8 = null;
        var removed_task: ?*TypingTask = null;

        self.typing_mu.lock();
        if (self.typing_handles.fetchRemove(target)) |entry| {
            removed_key = @constCast(entry.key);
            removed_task = entry.value;
        }
        self.typing_mu.unlock();

        if (removed_task) |task| {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
        }
        if (removed_key) |key| {
            self.allocator.free(key);
        }
    }

    fn stopAllTyping(self: *SignalChannel) void {
        self.typing_mu.lock();
        var handles = self.typing_handles;
        self.typing_handles = .empty;
        self.typing_mu.unlock();

        var it = handles.iterator();
        while (it.next()) |entry| {
            const task = entry.value_ptr.*;
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        handles.deinit(self.allocator);
    }

    fn typingLoop(task: *TypingTask) void {
        while (!task.stop_requested.load(.acquire)) {
            task.channel.sendTypingIndicator(task.target);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std.Thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
        }
    }

    // ── Health Check ────────────────────────────────────────────────

    pub fn healthCheck(self: *SignalChannel) bool {
        if (builtin.is_test) return true;

        var url_buf: [1024]u8 = undefined;
        const url = self.healthUrl(&url_buf) catch return false;
        const resp = root.http_util.curlGet(self.allocator, url, &.{}, "10") catch return false;
        defer self.allocator.free(resp);
        // signal-cli health endpoint returns 2xx on success.
        // If we got here, curl succeeded (exit 0), so the endpoint is healthy.
        return true;
    }

    // ── WebSocket Message Polling ───────────────────────────────────

    fn parseSSEEnvelope(self: *const SignalChannel, allocator: std.mem.Allocator, envelope_json: []const u8) !?root.ChannelMessage {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, envelope_json, .{}) catch return null;
        defer parsed.deinit();

        if (parsed.value != .object) return null;
        const envelope = parsed.value.object.get("envelope") orelse return null;
        if (envelope != .object) return null;
        const env_obj = envelope.object;

        const source = env_obj.get("source");
        const source_number = env_obj.get("sourceNumber");
        const source_name = env_obj.get("sourceName");
        const timestamp_val = env_obj.get("timestamp");

        var has_story = false;
        var dm_message: ?[]const u8 = null;
        var dm_timestamp: ?u64 = null;
        var dm_group_id: ?[]const u8 = null;
        var dm_attachment_ids: std.ArrayListUnmanaged([]const u8) = .empty;
        defer dm_attachment_ids.deinit(allocator);

        // Check for story message
        if (env_obj.get("storyMessage")) |story| {
            has_story = true;
            if (story == .object) {
                if (story.object.get("message")) |msg| {
                    if (msg == .string) {
                        dm_message = msg.string;
                    } else if (msg == .object) {
                        if (msg.object.get("timestamp")) |ts| {
                            if (ts == .integer) dm_timestamp = @intCast(ts.integer);
                        }
                    }
                }
            }
        }

        // Check for data message (regular message)
        if (env_obj.get("dataMessage")) |dm| {
            if (dm == .object) {
                const dm_obj = dm.object;
                if (dm_obj.get("message")) |msg| {
                    if (msg == .string) dm_message = msg.string;
                }
                if (dm_obj.get("timestamp")) |ts| {
                    if (ts == .integer) dm_timestamp = @intCast(ts.integer);
                }
                if (dm_obj.get("groupInfo")) |gi| {
                    if (gi == .object) {
                        if (gi.object.get("groupId")) |gid| {
                            if (gid == .string) dm_group_id = gid.string;
                        }
                    }
                }
                if (dm_obj.get("attachments")) |att| {
                    if (att == .array) {
                        for (att.array.items) |item| {
                            if (item == .object) {
                                if (item.object.get("id")) |id_val| {
                                    if (id_val == .string) try dm_attachment_ids.append(allocator, id_val.string);
                                }
                            }
                        }
                    }
                }
            }
        }

        return try self.processEnvelope(
            allocator,
            if (source) |s| if (s == .string) s.string else null else null,
            if (source_number) |s| if (s == .string) s.string else null else null,
            if (source_name) |s| if (s == .string) s.string else null else null,
            if (timestamp_val) |t| if (t == .integer) @intCast(t.integer) else null else null,
            has_story,
            dm_message,
            dm_timestamp,
            dm_group_id,
            dm_attachment_ids.items,
        );
    }

    fn appendReceivedEnvelope(
        self: *SignalChannel,
        allocator: std.mem.Allocator,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        envelope_json: []const u8,
    ) !void {
        if (self.parseSSEEnvelope(allocator, envelope_json)) |msg_opt| {
            if (msg_opt) |msg| {
                log.debug("Received message from {s} on signal ({d} chars) timestamp={d}", .{ msg.sender, msg.content.len, msg.timestamp });
                try messages.append(allocator, msg);
            }
        } else |_| {}
    }

    /// Poll for messages using a persistent WebSocket connection.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    pub fn pollMessages(self: *SignalChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        if (builtin.is_test) return &.{};

        // Initialize WS connection on first poll.
        // Retry is rate-limited with backoff, but each poll call stays bounded.
        if (self.ws_conn == null) {
            const now = std.time.timestamp();
            if (now < self.ws_next_retry_at) return &.{};

            var url_buf: [1024]u8 = undefined;
            const url = try self.receiveWsUrl(&url_buf);

            self.ws_conn = WsConnection.connect(self.allocator, url) catch |err| {
                log.warn("Signal WS connect failed: {}, retrying in {}s", .{ err, self.ws_retry_delay_secs });
                self.ws_next_retry_at = now + @as(i64, @intCast(self.ws_retry_delay_secs));
                self.ws_retry_delay_secs = @min(self.ws_retry_delay_secs * 2, 60);
                return &.{};
            };
            self.ws_retry_delay_secs = 2;
            self.ws_next_retry_at = 0;
            log.info("Signal WS connected ({s})", .{url});
        }

        if (self.ws_conn == null) {
            return &.{};
        }

        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer {
            for (messages.items) |*msg| {
                msg.deinit(allocator);
            }
            messages.deinit(allocator);
        }

        const first_payload = self.ws_conn.?.readTextMessage(self.allocator, WS_READ_TIMEOUT_MS) catch |err| {
            log.warn("Signal WS read error: {}, reconnecting...", .{err});
            if (self.ws_conn) |*conn| {
                conn.deinit();
                self.ws_conn = null;
            }
            self.ws_next_retry_at = 0;
            return &.{};
        };
        if (first_payload == null) return &.{};

        try self.appendReceivedEnvelope(allocator, &messages, first_payload.?);
        self.allocator.free(first_payload.?);

        // Drain additional queued frames without blocking.
        while (true) {
            const maybe_payload = self.ws_conn.?.readTextMessage(self.allocator, 0) catch |err| {
                log.warn("Signal WS drain error: {}, reconnecting...", .{err});
                if (self.ws_conn) |*conn| {
                    conn.deinit();
                    self.ws_conn = null;
                }
                self.ws_next_retry_at = 0;
                break;
            };
            if (maybe_payload == null) break;
            defer self.allocator.free(maybe_payload.?);
            try self.appendReceivedEnvelope(allocator, &messages, maybe_payload.?);
        }

        return try messages.toOwnedSlice(allocator);
    }

    // ── Channel vtable ───────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        if (builtin.is_test) return;
        // Verify connectivity by hitting the health endpoint.
        var url_buf: [1024]u8 = undefined;
        const url = try self.healthUrl(&url_buf);
        const resp = root.http_util.curlGet(self.allocator, url, &.{}, "10") catch |err| {
            log.warn("Signal health check failed on start: {}", .{err});
            return;
        };
        self.allocator.free(resp);
        log.info("Signal channel started (daemon at {s})", .{self.http_url});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        // Clean up WS connection
        if (self.ws_conn) |*conn| {
            conn.deinit();
            self.ws_conn = null;
        }
        // Reset retry state.
        self.ws_retry_delay_secs = 2;
        self.ws_next_retry_at = 0;
        // Clean up typing indicator threads
        self.stopAllTyping();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message, media);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
    };

    pub fn channel(self: *SignalChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Public Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Strip the `uuid:` prefix from an allowlist entry if present.
///
/// This allows `uuid:<id>` and `<id>` to both match against a bare UUID sender.
pub fn normalizeAllowEntry(entry: []const u8) []const u8 {
    const prefix = "uuid:";
    if (entry.len > prefix.len and std.mem.startsWith(u8, entry, prefix)) {
        return entry[prefix.len..];
    }
    return entry;
}

/// Validate an E.164 phone number: starts with `+`, 2-15 digits after.
pub fn isE164(s: []const u8) bool {
    if (s.len < 3) return false; // "+" + at least 2 digits
    if (s[0] != '+') return false;
    const digits = s[1..];
    if (digits.len < 2 or digits.len > 15) return false;
    for (digits) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Check whether a string is a valid UUID (8-4-4-4-12 hex format).
///
/// Signal-cli uses UUIDs for privacy-enabled users who have opted out
/// of sharing their phone number.
pub fn isUuid(s: []const u8) bool {
    // UUID format: 8-4-4-4-12 = 36 chars total
    if (s.len != 36) return false;
    // Check dash positions
    if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') return false;
    // Check all other chars are hex digits
    for (s, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) continue;
        if (!isHexDigit(c)) return false;
    }
    return true;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// Parse a recipient string into a RecipientTarget.
///
/// - "group:<id>" → Group
/// - E.164 phone or UUID → Direct
/// - Anything else → Group (conservative fallback, matches ironclaw)
pub fn parseRecipientTarget(recipient: []const u8) RecipientTarget {
    if (std.mem.startsWith(u8, recipient, GROUP_TARGET_PREFIX)) {
        return .{ .group = recipient[GROUP_TARGET_PREFIX.len..] };
    }
    if (isE164(recipient) or isUuid(recipient)) {
        return .{ .direct = recipient };
    }
    // Unknown format — treat as group (matches ironclaw behavior).
    return .{ .group = recipient };
}

/// Determine the reply target from a data message.
///
/// - If the message is from a group, returns "group:<groupId>".
/// - Otherwise returns the sender's identifier (phone/UUID).
pub fn replyTarget(group_id: ?[]const u8, sender: []const u8) ReplyTargetResult {
    if (group_id) |gid| {
        return .{ .is_group = true, .target = gid, .sender = sender };
    }
    return .{ .is_group = false, .target = sender, .sender = sender };
}

pub const ReplyTargetResult = struct {
    is_group: bool,
    target: []const u8, // group_id or sender
    sender: []const u8,
};

/// Strip trailing slashes from a URL.
pub fn stripTrailingSlashes(url: []const u8) []const u8 {
    var end = url.len;
    while (end > 0 and url[end - 1] == '/') {
        end -= 1;
    }
    return url[0..end];
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "channel name returns signal" {
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expectEqualStrings("signal", ch.channelName());
}

test "creates with correct fields" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expectEqualStrings("http://127.0.0.1:8686", ch.http_url);
    try std.testing.expectEqualStrings("+1234567890", ch.account);
    try std.testing.expectEqual(@as(usize, 1), ch.allow_from.len);
    try std.testing.expectEqual(@as(usize, 0), ch.group_allow_from.len);
    try std.testing.expect(ch.ignore_attachments);
    try std.testing.expect(ch.ignore_stories);
}

test "strips trailing slash" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686/",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expectEqualStrings("http://127.0.0.1:8686", ch.http_url);
}

test "strips multiple trailing slashes" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686///",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expectEqualStrings("http://127.0.0.1:8686", ch.http_url);
}

test "preserves url without trailing slash" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expectEqualStrings("http://127.0.0.1:8686", ch.http_url);
}

test "wildcard allows anyone" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(ch.isSenderAllowed("+9999999999"));
}

test "specific sender allowed" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(ch.isSenderAllowed("+1111111111"));
}

test "unknown sender denied" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(!ch.isSenderAllowed("+9999999999"));
}

test "empty allowlist denies all" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expect(!ch.isSenderAllowed("+1111111111"));
}

test "uuid prefix in allowlist" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{"uuid:" ++ uuid};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    // Should match against bare UUID sender.
    try std.testing.expect(ch.isSenderAllowed(uuid));
    // Should not match phone numbers.
    try std.testing.expect(!ch.isSenderAllowed("+1111111111"));
}

test "bare uuid in allowlist" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{uuid};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(ch.isSenderAllowed(uuid));
}

test "multiple allowed users" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{ "+1111111111", "+2222222222", uuid };
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(ch.isSenderAllowed("+1111111111"));
    try std.testing.expect(ch.isSenderAllowed("+2222222222"));
    try std.testing.expect(ch.isSenderAllowed(uuid));
    try std.testing.expect(!ch.isSenderAllowed("+9999999999"));
}

test "uuid prefix normalization in allowlist" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{ "uuid:" ++ uuid, "+1111111111" };
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    try std.testing.expect(ch.isSenderAllowed(uuid));
    try std.testing.expect(ch.isSenderAllowed("+1111111111"));
    try std.testing.expect(!ch.isSenderAllowed("+9999999999"));
}

test "group sender allowlist filtering" {
    const senders = [_][]const u8{"+15550001111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &senders,
        true,
        true,
    );
    try std.testing.expect(ch.isGroupSenderAllowed("+15550001111"));
    try std.testing.expect(!ch.isGroupSenderAllowed("+15550002222"));
}

test "group sender allowlist supports uuid-prefixed entries" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const senders = [_][]const u8{"uuid:" ++ uuid};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &senders,
        true,
        true,
    );
    try std.testing.expect(ch.isGroupSenderAllowed(uuid));
    try std.testing.expect(!ch.isGroupSenderAllowed("+15550002222"));
}

test "group sender allowlist wildcard" {
    const senders = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &senders,
        true,
        true,
    );
    try std.testing.expect(ch.isGroupSenderAllowed("+15550001111"));
}

test "group sender allowlist empty fallback path has no explicit entries" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    try std.testing.expect(!ch.isGroupSenderAllowed("+15550001111"));
}

test "multiple allowed group senders" {
    const senders = [_][]const u8{ "+15550001111", "+15550002222" };
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &senders,
        true,
        true,
    );
    try std.testing.expect(ch.isGroupSenderAllowed("+15550001111"));
    try std.testing.expect(ch.isGroupSenderAllowed("+15550002222"));
    try std.testing.expect(!ch.isGroupSenderAllowed("+15550003333"));
}

// ── Recipient Target Tests ──────────────────────────────────────────

test "parse recipient target e164 is direct" {
    const target = parseRecipientTarget("+1234567890");
    switch (target) {
        .direct => |id| try std.testing.expectEqualStrings("+1234567890", id),
        .group => unreachable,
    }
}

test "parse recipient target prefixed group is group" {
    const target = parseRecipientTarget("group:abc123");
    switch (target) {
        .group => |id| try std.testing.expectEqualStrings("abc123", id),
        .direct => unreachable,
    }
}

test "parse recipient target uuid is direct" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const target = parseRecipientTarget(uuid);
    switch (target) {
        .direct => |id| try std.testing.expectEqualStrings(uuid, id),
        .group => unreachable,
    }
}

test "parse recipient target non e164 plus is group" {
    const target = parseRecipientTarget("+abc123");
    switch (target) {
        .group => |id| try std.testing.expectEqualStrings("+abc123", id),
        .direct => unreachable,
    }
}

// ── E.164 Validation Tests ──────────────────────────────────────────

test "is e164 valid numbers" {
    try std.testing.expect(isE164("+12345678901"));
    try std.testing.expect(isE164("+44")); // min 2 digits after +
    try std.testing.expect(isE164("+123456789012345")); // max 15 digits
}

test "is e164 invalid numbers" {
    try std.testing.expect(!isE164("12345678901")); // no +
    try std.testing.expect(!isE164("+1")); // too short (1 digit)
    try std.testing.expect(!isE164("+1234567890123456")); // too long (16 digits)
    try std.testing.expect(!isE164("+abc123")); // non-digit
    try std.testing.expect(!isE164("")); // empty
    try std.testing.expect(!isE164("+")); // plus only
}

// ── UUID Validation Tests ───────────────────────────────────────────

test "is uuid valid" {
    try std.testing.expect(isUuid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));
    try std.testing.expect(isUuid("00000000-0000-0000-0000-000000000000"));
}

test "is uuid invalid" {
    try std.testing.expect(!isUuid("+1234567890"));
    try std.testing.expect(!isUuid("not-a-uuid"));
    try std.testing.expect(!isUuid("group:abc123"));
    try std.testing.expect(!isUuid(""));
}

// ── Normalize Allow Entry Tests ─────────────────────────────────────

test "normalize allow entry strips uuid prefix" {
    try std.testing.expectEqualStrings("abc-123", normalizeAllowEntry("uuid:abc-123"));
    try std.testing.expectEqualStrings("+1234567890", normalizeAllowEntry("+1234567890"));
    try std.testing.expectEqualStrings("*", normalizeAllowEntry("*"));
}

// ── Reply Target Tests ──────────────────────────────────────────────

test "reply target dm" {
    const result = replyTarget(null, "+1111111111");
    try std.testing.expect(!result.is_group);
    try std.testing.expectEqualStrings("+1111111111", result.target);
}

test "reply target group" {
    const result = replyTarget("group123", "+1111111111");
    try std.testing.expect(result.is_group);
    try std.testing.expectEqualStrings("group123", result.target);
}

// ── URL Builder Tests ───────────────────────────────────────────────

test "send url built correctly" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    var buf: [1024]u8 = undefined;
    const url = try ch.sendUrl(&buf);
    try std.testing.expectEqualStrings("http://127.0.0.1:8686/v2/send", url);
}

test "receive websocket url built correctly" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    var buf: [1024]u8 = undefined;
    const url = try ch.receiveWsUrl(&buf);
    try std.testing.expectEqualStrings("ws://127.0.0.1:8686/v1/receive/+1234567890", url);
}

test "health url built correctly" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    var buf: [1024]u8 = undefined;
    const url = try ch.healthUrl(&buf);
    try std.testing.expectEqualStrings("http://127.0.0.1:8686/v1/health", url);
}

// ── REST Body Tests ─────────────────────────────────────────────────

test "build rest body direct with message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRestBody(std.testing.allocator, .{ .direct = "+5555555555" }, "Hello!", &.{});
    defer std.testing.allocator.free(body);
    // Verify REST fields are present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"number\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipients\":[\"+5555555555\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"Hello!\"") != null);
    // Must NOT contain JSON-RPC fields.
    try std.testing.expect(std.mem.indexOf(u8, body, "jsonrpc") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"method\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "groupId") == null);
}

test "build rest body direct without message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRestBody(std.testing.allocator, .{ .direct = "+5555555555" }, null, &.{});
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipients\":[\"+5555555555\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"number\":\"+1234567890\"") != null);
    // No message key should be present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") == null);
}

test "signal startTyping and stopTyping are safe in tests" {
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    defer ch.stopAllTyping();
    try ch.startTyping("+15551234567");
    try ch.stopTyping("+15551234567");
}

test "build rest body group with message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRestBody(std.testing.allocator, .{ .group = "abc123" }, "Group msg", &.{});
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipients\":[\"group.abc123\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"number\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"Group msg\"") != null);
}

test "build rest body group without message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRestBody(std.testing.allocator, .{ .group = "abc123" }, null, &.{});
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipients\":[\"group.abc123\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"number\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") == null);
}

test "build rest body uuid direct target" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRestBody(std.testing.allocator, .{ .direct = uuid }, "hi", &.{});
    defer std.testing.allocator.free(body);
    // Verify UUID is in recipients array.
    const expected = "\"recipients\":[\"" ++ uuid ++ "\"]";
    try std.testing.expect(std.mem.indexOf(u8, body, expected) != null);
}

test "build rest body with base64 attachments" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const attachments = &[_][]const u8{ "aGVsbG8=", "d29ybGQ=" };
    const body = try ch.buildRestBody(std.testing.allocator, .{ .direct = "+5555555555" }, "Check this!", attachments);
    defer std.testing.allocator.free(body);
    // Verify base64_attachments array is present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"base64_attachments\":[\"aGVsbG8=\",\"d29ybGQ=\"]") != null);
    // Verify message is still present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"Check this!\"") != null);
    // Verify recipients is present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipients\":[\"+5555555555\"]") != null);
}

test "build rest body with single base64 attachment" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const attachments = &[_][]const u8{"cGhvdG8="};
    const body = try ch.buildRestBody(std.testing.allocator, .{ .direct = "+5555555555" }, "Photo!", attachments);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"base64_attachments\":[\"cGhvdG8=\"]") != null);
}

test "parse image markers extracts paths and strips markers from text" {
    const parsed = try SignalChannel.parseImageMarkers(
        std.testing.allocator,
        "Look [IMAGE:/tmp/a.png] and [IMAGE:/tmp/b.jpg] now",
    );
    defer {
        for (parsed.paths) |p| std.testing.allocator.free(p);
        std.testing.allocator.free(parsed.paths);
        std.testing.allocator.free(parsed.remaining);
    }

    try std.testing.expectEqual(@as(usize, 2), parsed.paths.len);
    try std.testing.expectEqualStrings("/tmp/a.png", parsed.paths[0]);
    try std.testing.expectEqualStrings("/tmp/b.jpg", parsed.paths[1]);
    try std.testing.expectEqualStrings("Look and now", parsed.remaining);
}

test "parse image markers preserves text when there are no markers" {
    const raw = "  keep leading and trailing whitespace \n";
    const parsed = try SignalChannel.parseImageMarkers(std.testing.allocator, raw);
    defer {
        for (parsed.paths) |p| std.testing.allocator.free(p);
        std.testing.allocator.free(parsed.paths);
        std.testing.allocator.free(parsed.remaining);
    }

    try std.testing.expectEqual(@as(usize, 0), parsed.paths.len);
    try std.testing.expectEqualStrings(raw, parsed.remaining);
}

test "parse image markers preserves text for malformed marker" {
    const raw = "prefix [IMAGE:] suffix";
    const parsed = try SignalChannel.parseImageMarkers(std.testing.allocator, raw);
    defer {
        for (parsed.paths) |p| std.testing.allocator.free(p);
        std.testing.allocator.free(parsed.paths);
        std.testing.allocator.free(parsed.remaining);
    }

    try std.testing.expectEqual(@as(usize, 0), parsed.paths.len);
    try std.testing.expectEqualStrings(raw, parsed.remaining);
}

test "prepare outgoing content merges media and deduplicates paths" {
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );

    const prepared = try ch.prepareOutgoingContent(
        "See [IMAGE:/tmp/a.png] and [IMAGE:/tmp/a.png]",
        &[_][]const u8{ "/tmp/b.png", "/tmp/a.png" },
    );
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("See and", prepared.message_text);
    try std.testing.expectEqual(@as(usize, 2), prepared.attachments.len);
    try std.testing.expectEqualStrings("/tmp/b.png", prepared.attachments[0]);
    try std.testing.expectEqualStrings("/tmp/a.png", prepared.attachments[1]);
}

test "prepare outgoing content keeps unresolved relative attachment path" {
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );

    const marker_text = "[IMAGE:nullclaw_nonexistent_attachment_123456789.png]";
    const prepared = try ch.prepareOutgoingContent(marker_text, &.{});
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("", prepared.message_text);
    try std.testing.expectEqual(@as(usize, 1), prepared.attachments.len);
    try std.testing.expectEqualStrings("nullclaw_nonexistent_attachment_123456789.png", prepared.attachments[0]);
}

test "plan outgoing payloads sends attachment payloads without text" {
    const payloads = try SignalChannel.planOutgoingPayloads(std.testing.allocator, "hello", 2);
    defer std.testing.allocator.free(payloads);

    try std.testing.expectEqual(@as(usize, 3), payloads.len);
    try std.testing.expectEqualStrings("hello", payloads[0].message.?);
    try std.testing.expect(payloads[0].attachment_index == null);
    try std.testing.expect(payloads[1].message == null);
    try std.testing.expectEqual(@as(usize, 0), payloads[1].attachment_index.?);
    try std.testing.expect(payloads[2].message == null);
    try std.testing.expectEqual(@as(usize, 1), payloads[2].attachment_index.?);
}

test "plan outgoing payloads splits text-only messages" {
    const long_text = try std.testing.allocator.alloc(u8, MAX_MESSAGE_LEN + 5);
    defer std.testing.allocator.free(long_text);
    @memset(long_text, 'a');

    const payloads = try SignalChannel.planOutgoingPayloads(std.testing.allocator, long_text, 0);
    defer std.testing.allocator.free(payloads);

    try std.testing.expectEqual(@as(usize, 2), payloads.len);
    try std.testing.expect(payloads[0].message != null);
    try std.testing.expectEqual(@as(usize, MAX_MESSAGE_LEN), payloads[0].message.?.len);
    try std.testing.expect(payloads[1].message != null);
    try std.testing.expectEqual(@as(usize, 5), payloads[1].message.?.len);
    try std.testing.expect(payloads[0].attachment_index == null);
    try std.testing.expect(payloads[1].attachment_index == null);
}

// ── Process Envelope Tests ──────────────────────────────────────────

test "process envelope valid dm" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111", // source
        "+1111111111", // source_number
        null, // source_name
        1_700_000_000_000, // envelope_timestamp
        false, // has_story_message
        "Hello!", // dm_message
        1_700_000_000_000, // dm_timestamp
        null, // dm_group_id
        &.{}, // dm_attachment_ids
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Hello!", m.content);
    try std.testing.expectEqualStrings("+1111111111", m.sender);
    try std.testing.expectEqualStrings("signal", m.channel);
    try std.testing.expectEqualStrings("+1111111111", m.reply_target.?);
    try std.testing.expect(!m.is_group);
}

test "process envelope denied sender" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+9999999999",
        "+9999999999",
        null,
        1000,
        false,
        "Hello!",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope empty message" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "", // empty message
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope no data message" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        null, // no data message
        null,
        null,
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope skips stories" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.ignore_stories = true;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        true, // has_story_message
        "story text",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope stories not skipped when disabled" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.ignore_stories = false;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        true, // has_story_message
        "story with text",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("story with text", m.content);
}

test "process envelope skips attachment only" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.ignore_attachments = true;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        null, // no text
        1000,
        null,
        &.{"dummy_id"}, // has attachments
    );
    try std.testing.expect(msg == null);
}

test "process envelope attachment with text not skipped" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.ignore_attachments = true;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Check this out", // has text
        1000,
        null,
        &.{"dummy_id"}, // also has attachments
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Check this out", m.content);
}

test "process envelope attachment only not skipped when ignore disabled" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.ignore_attachments = false;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        null, // no text
        1000,
        null,
        &.{"dummy_id"}, // has attachments
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("[Attachment]", m.content);
}

test "process envelope source name sets first name" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+3333333333",
        "+3333333333",
        "Alice", // source_name
        1000,
        false,
        "Hey",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Alice", m.first_name.?);
}

test "process envelope empty source name not set" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+3333333333",
        "+3333333333",
        "", // empty source_name
        1000,
        false,
        "Hey",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.first_name == null);
}

test "process envelope no source name not set" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null, // no source_name
        1000,
        false,
        "hi",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.first_name == null);
}

test "process envelope dm accepted when group_allow_from is empty" {
    // group_allow_from applies to groups only; DMs are governed by allow_from.
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Hello!",
        1000,
        null, // no group
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(!m.is_group);
}

test "process envelope group with empty group_allow_from falls back to allow_from" {
    // Empty group_allow_from = fall back to allow_from for sender check.
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "hi",
        1000,
        "group123", // group message
        &.{},
    );
    // Sender is in allow_from (wildcard), so accepted via fallback
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.is_group);
}

test "process envelope group denied when sender not in group_allow_from" {
    // group_allow_from has specific senders; this sender is not in the list.
    const users = [_][]const u8{"*"};
    const group_users = [_][]const u8{"+2222222222"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &group_users,
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "hi",
        1000,
        "group123",
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope group accepted when sender in group_allow_from" {
    const users = [_][]const u8{"*"};
    const group_users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &group_users,
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "hi",
        1000,
        "group123",
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.is_group);
    try std.testing.expectEqualStrings("group:group123", m.reply_target.?);

    // Same sender in different group should also be accepted.
    const msg2 = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "hi",
        1000,
        "other_group",
        &.{},
    );
    try std.testing.expect(msg2 != null);
    const m2 = msg2.?;
    defer m2.deinit(std.testing.allocator);
    try std.testing.expect(m2.is_group);
}

test "process envelope group accepts uuid allowlist when source_number is present" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{"*"};
    const group_users = [_][]const u8{"uuid:" ++ uuid};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &group_users,
        true,
        true,
    );

    const msg = try ch.processEnvelope(
        std.testing.allocator,
        uuid, // source (UUID)
        "+1111111111", // source_number present
        null,
        1000,
        false,
        "hi",
        1000,
        "group123",
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.is_group);
    try std.testing.expect(m.sender_uuid != null);
    try std.testing.expectEqualStrings(uuid, m.sender_uuid.?);
}

test "process envelope group sender not in group_allow_from" {
    const users = [_][]const u8{"*"};
    const group_users = [_][]const u8{"+2222222222"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &group_users,
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Hi",
        1000,
        "some_group",
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope group blocked when group_policy disabled" {
    const users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.group_policy = "disabled";
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Hi",
        1000,
        "group123",
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "process envelope group allowed when group_policy open" {
    const users = [_][]const u8{"+2222222222"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    ch.group_policy = "open";
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Hi",
        1000,
        "group123",
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.is_group);
}

test "process envelope uuid sender dm" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        uuid, // source (UUID)
        null, // no source_number (privacy-enabled)
        "Privacy User", // source_name
        1000,
        false,
        "Hello from privacy user",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(uuid, m.sender);
    try std.testing.expect(m.sender_uuid != null);
    try std.testing.expectEqualStrings(uuid, m.sender_uuid.?);
    try std.testing.expectEqualStrings("Privacy User", m.first_name.?);
    try std.testing.expectEqualStrings("Hello from privacy user", m.content);
    try std.testing.expectEqualStrings(uuid, m.reply_target.?);
    // UUID sender in DM should route as Direct.
    const parsed = parseRecipientTarget(m.reply_target.?);
    switch (parsed) {
        .direct => |id| try std.testing.expectEqualStrings(uuid, id),
        .group => unreachable,
    }
}

test "process envelope uuid sender in group" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{"*"};
    const group_users = [_][]const u8{"*"};
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &group_users,
        true,
        true,
    );
    ch.ignore_attachments = false;
    ch.ignore_stories = false;
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        uuid, // source (UUID)
        null, // no source_number
        null,
        1000,
        false,
        "Group msg from privacy user",
        1000,
        "testgroup",
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(uuid, m.sender);
    try std.testing.expect(m.sender_uuid != null);
    try std.testing.expectEqualStrings(uuid, m.sender_uuid.?);
    try std.testing.expectEqualStrings("group:testgroup", m.reply_target.?);
    try std.testing.expect(m.is_group);
    // Group message should still route as Group.
    const parsed = parseRecipientTarget(m.reply_target.?);
    switch (parsed) {
        .group => |id| try std.testing.expectEqualStrings("testgroup", id),
        .direct => unreachable,
    }
}

test "process envelope dm has no is_group flag" {
    const users = [_][]const u8{"+1111111111"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "DM",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(!m.is_group);
}

test "process envelope group sets is_group" {
    const users = [_][]const u8{"*"};
    const groups = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &groups,
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1000,
        false,
        "Group msg",
        1000,
        "grp999",
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(m.is_group);
    try std.testing.expectEqualStrings("group:grp999", m.reply_target.?);
}

test "process envelope uses data message timestamp" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        1111, // envelope_timestamp
        false,
        "hi",
        9999, // dm_timestamp (should take priority)
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 9999), m.timestamp);
}

test "process envelope falls back to envelope timestamp" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        7777, // envelope_timestamp
        false,
        "hi",
        null, // no dm_timestamp
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 7777), m.timestamp);
}

test "process envelope generates timestamp when missing" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "+1111111111",
        "+1111111111",
        null,
        null, // no envelope_timestamp
        false,
        "hi",
        null, // no dm_timestamp
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    // Should generate a current timestamp (positive).
    try std.testing.expect(m.timestamp > 0);
}

test "process envelope sender prefers source number" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        "uuid-123", // source
        "+1111111111", // source_number (preferred)
        null,
        1000,
        false,
        "hi",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("+1111111111", m.sender);
    try std.testing.expect(m.sender_uuid == null);
}

test "process envelope sender falls back to source" {
    const uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        uuid, // source
        null, // no source_number
        null,
        1000,
        false,
        "hi",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg != null);
    const m = msg.?;
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(uuid, m.sender);
    try std.testing.expect(m.sender_uuid != null);
    try std.testing.expectEqualStrings(uuid, m.sender_uuid.?);
}

test "process envelope sender none when both missing" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );
    const msg = try ch.processEnvelope(
        std.testing.allocator,
        null, // no source
        null, // no source_number
        null,
        1000,
        false,
        "hi",
        1000,
        null,
        &.{},
    );
    try std.testing.expect(msg == null);
}

test "parseSSEEnvelope returns owned message content" {
    const users = [_][]const u8{"*"};
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &users,
        &.{},
        true,
        true,
    );

    const raw_json =
        \\{
        \\  "envelope": {
        \\    "source": "uuid-123",
        \\    "sourceNumber": "+1111111111",
        \\    "timestamp": 1700000000,
        \\    "dataMessage": {
        \\      "message": "hello from signal ws",
        \\      "timestamp": 1700000001
        \\    }
        \\  }
        \\}
    ;
    const json_buf = try std.testing.allocator.dupe(u8, raw_json);
    defer std.testing.allocator.free(json_buf);

    const msg_opt = try ch.parseSSEEnvelope(std.testing.allocator, json_buf);
    try std.testing.expect(msg_opt != null);
    const msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    @memset(json_buf, 'x');
    const churn = try std.testing.allocator.alloc(u8, 2048);
    defer std.testing.allocator.free(churn);
    @memset(churn, 'z');

    try std.testing.expectEqualStrings("hello from signal ws", msg.content);
    try std.testing.expectEqualStrings("+1111111111", msg.sender);
}

test "receive websocket url uses wss for https base" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "https://signal.example.com:8443",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    var buf: [1024]u8 = undefined;
    const url = try ch.receiveWsUrl(&buf);
    try std.testing.expectEqualStrings("wss://signal.example.com:8443/v1/receive/+1234567890", url);
}

test "ws connect parts parses host port and path" {
    var host_buf: [256]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    const parts = try SignalChannel.wsConnectParts(
        "ws://127.0.0.1:8080/v1/receive/+1234567890",
        &host_buf,
        &path_buf,
    );
    try std.testing.expectEqualStrings("127.0.0.1", parts.host);
    try std.testing.expectEqual(@as(u16, 8080), parts.port);
    try std.testing.expectEqualStrings("/v1/receive/+1234567890", parts.path);
}

// ── Vtable Tests ────────────────────────────────────────────────────

test "vtable struct has all fields" {
    const T = root.Channel.VTable;
    try std.testing.expect(@hasField(T, "start"));
    try std.testing.expect(@hasField(T, "stop"));
    try std.testing.expect(@hasField(T, "send"));
    try std.testing.expect(@hasField(T, "name"));
    try std.testing.expect(@hasField(T, "healthCheck"));
}

test "vtable compiles and wires correctly" {
    var ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const iface = ch.channel();
    try std.testing.expectEqualStrings("signal", iface.name());
    try std.testing.expect(iface.healthCheck());
}

test "stripTrailingSlashes no slash" {
    try std.testing.expectEqualStrings("http://example.com", stripTrailingSlashes("http://example.com"));
}

test "stripTrailingSlashes one slash" {
    try std.testing.expectEqualStrings("http://example.com", stripTrailingSlashes("http://example.com/"));
}

test "stripTrailingSlashes many slashes" {
    try std.testing.expectEqualStrings("http://example.com", stripTrailingSlashes("http://example.com///"));
}

test "stripTrailingSlashes empty string" {
    try std.testing.expectEqualStrings("", stripTrailingSlashes(""));
}

test "stripTrailingSlashes only slashes" {
    try std.testing.expectEqualStrings("", stripTrailingSlashes("///"));
}
