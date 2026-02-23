//! Signal channel via signal-cli daemon HTTP/JSON-RPC.
//!
//! Connects to a running `signal-cli daemon --http <host:port>`.
//! Receives messages via SSE at `/api/v1/events` and sends via
//! JSON-RPC at `/api/v1/rpc`.
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

const log = std.log.scoped(.signal);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

/// Prefix used to identify group targets in reply_target strings.
pub const GROUP_TARGET_PREFIX = "group:";

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
const SIGNAL_HEALTH_ENDPOINT = "/api/v1/check";

/// JSON-RPC endpoint for sending messages.
const SIGNAL_RPC_ENDPOINT = "/api/v1/rpc";

/// SSE endpoint for receiving messages.
const SIGNAL_SSE_ENDPOINT = "/api/v1/events";

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

/// Signal channel — uses signal-cli daemon's native JSON-RPC + SSE API.
///
/// Sends messages via JSON-RPC POST to `/api/v1/rpc`.
/// The SSE listener (for incoming messages) would be driven by the
/// dispatch loop calling `pollMessages()`.
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

    /// Build the JSON-RPC URL.
    pub fn rpcUrl(self: *const SignalChannel, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll(self.http_url);
        try w.writeAll(SIGNAL_RPC_ENDPOINT);
        return fbs.getWritten();
    }

    /// Build the SSE events URL (with account query param).
    pub fn sseUrl(self: *const SignalChannel, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll(self.http_url);
        try w.writeAll(SIGNAL_SSE_ENDPOINT);
        try w.writeAll("?account=");
        // URL-encode the account (mainly the '+' character)
        for (self.account) |c| {
            if (c == '+') {
                try w.writeAll("%2B");
            } else {
                try w.writeByte(c);
            }
        }
        return fbs.getWritten();
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
        };

        return msg;
    }

    // ── JSON-RPC Attachment Fetch ───────────────────────────────────

    /// Fetch an attachment from the signal-cli daemon via JSON-RPC.
    /// Returns absolute path to a saved temp file.
    pub fn fetchAttachmentLocally(self: *const SignalChannel, allocator: std.mem.Allocator, attachment_id: []const u8, is_group: bool, target_id: []const u8) !?[]const u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"jsonrpc\":\"2.0\",\"method\":\"getAttachment\",\"params\":{\"id\":");
        try root.json_util.appendJsonString(&body, allocator, attachment_id);

        if (is_group) {
            try body.appendSlice(allocator, ",\"groupId\":");
            try root.json_util.appendJsonString(&body, allocator, target_id);
        } else {
            try body.appendSlice(allocator, ",\"recipient\":");
            try root.json_util.appendJsonString(&body, allocator, target_id);
        }

        try body.appendSlice(allocator, ",\"account\":");
        try root.json_util.appendJsonString(&body, allocator, self.account);
        try body.appendSlice(allocator, "},\"id\":\"2\"}");

        var url_buf: [1024]u8 = undefined;
        const url = try self.rpcUrl(&url_buf);

        const rpc_body = try body.toOwnedSlice(allocator);
        defer allocator.free(rpc_body);

        const resp = root.http_util.curlPost(allocator, url, rpc_body, &.{}) catch |err| {
            log.warn("Signal fetch attachment {s} failed: {}", .{ attachment_id, err });
            return null;
        };
        defer allocator.free(resp);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
        defer parsed.deinit();

        if (parsed.value != .object) return null;
        const result = parsed.value.object.get("result") orelse {
            if (parsed.value.object.get("error")) |err_val| {
                log.warn("Signal fetch attachment error: {}", .{err_val});
            }
            return null;
        };
        if (result != .object) return null;
        const data_str = result.object.get("data") orelse return null;
        if (data_str != .string) return null;

        const base64_data = data_str.string;
        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(base64_data);
        const decoded = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded);
        try std.base64.standard.Decoder.decode(decoded, base64_data);

        // Generate temp file
        var rand = std.crypto.random;
        const rand_id = rand.int(u64);
        var path_buf: [1024]u8 = undefined;
        const local_path = try std.fmt.bufPrint(&path_buf, "/tmp/signal_{x}.dat", .{rand_id});

        var file = std.fs.createFileAbsolute(local_path, .{ .read = false }) catch return null;
        defer file.close();
        try file.writeAll(decoded);

        return try allocator.dupe(u8, local_path);
    }

    // ── JSON-RPC Send ───────────────────────────────────────────────

    /// Build JSON-RPC body for a send or sendTyping call.
    ///
    /// Returns caller-owned JSON body string.
    pub fn buildRpcBody(
        self: *const SignalChannel,
        allocator: std.mem.Allocator,
        method: []const u8,
        target: RecipientTarget,
        message: ?[]const u8,
    ) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"jsonrpc\":\"2.0\",\"method\":");
        try root.json_util.appendJsonString(&body, allocator, method);

        try body.appendSlice(allocator, ",\"params\":{");

        switch (target) {
            .direct => |id| {
                try body.appendSlice(allocator, "\"recipient\":[");
                try root.json_util.appendJsonString(&body, allocator, id);
                try body.appendSlice(allocator, "]");
            },
            .group => |group_id| {
                try body.appendSlice(allocator, "\"groupId\":");
                try root.json_util.appendJsonString(&body, allocator, group_id);
            },
        }

        try body.appendSlice(allocator, ",\"account\":");
        try root.json_util.appendJsonString(&body, allocator, self.account);

        if (message) |msg| {
            try body.appendSlice(allocator, ",\"message\":");
            try root.json_util.appendJsonString(&body, allocator, msg);
        }

        try body.appendSlice(allocator, "},\"id\":\"1\"}");

        return try body.toOwnedSlice(allocator);
    }

    /// Send a message via JSON-RPC to the signal-cli daemon.
    pub fn sendMessage(self: *SignalChannel, target_str: []const u8, message: []const u8) !void {
        if (builtin.is_test) return;

        const target = parseRecipientTarget(target_str);

        // Split long messages.
        var iter = root.splitMessage(message, MAX_MESSAGE_LEN);
        while (iter.next()) |chunk| {
            const rpc_body = try self.buildRpcBody(self.allocator, "send", target, chunk);
            defer self.allocator.free(rpc_body);

            var url_buf: [1024]u8 = undefined;
            const url = try self.rpcUrl(&url_buf);

            const resp = root.http_util.curlPost(self.allocator, url, rpc_body, &.{}) catch |err| {
                log.warn("Signal RPC send failed: {}", .{err});
                return err;
            };
            self.allocator.free(resp);
        }
    }

    /// Send a typing indicator (best-effort, errors ignored).
    pub fn sendTypingIndicator(self: *SignalChannel, target_str: []const u8) void {
        if (builtin.is_test) return;

        const target = parseRecipientTarget(target_str);
        const rpc_body = self.buildRpcBody(self.allocator, "sendTyping", target, null) catch return;
        defer self.allocator.free(rpc_body);

        var url_buf: [1024]u8 = undefined;
        const url = self.rpcUrl(&url_buf) catch return;

        const resp = root.http_util.curlPost(self.allocator, url, rpc_body, &.{}) catch return;
        self.allocator.free(resp);
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

    // ── SSE Message Polling ─────────────────────────────────────────

    const ENVELOPE_PREFIX = "data:";
    const ENVELOPE_SUFFIX = "\n\n";

    fn parseSSEEnvelope(self: *const SignalChannel, envelope_json: []const u8) !?root.ChannelMessage {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, envelope_json, .{}) catch return null;
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
        defer dm_attachment_ids.deinit(self.allocator);

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
                                    if (id_val == .string) try dm_attachment_ids.append(self.allocator, id_val.string);
                                }
                            }
                        }
                    }
                }
            }
        }

        return try self.processEnvelope(
            self.allocator,
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

    /// Poll for messages using SSE (Server-Sent Events).
    /// This is a long-poll that waits for incoming messages from signal-cli.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    pub fn pollMessages(self: *SignalChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        if (builtin.is_test) return &.{};

        var url_buf: [1024]u8 = undefined;
        const url = try self.sseUrl(&url_buf);

        // Use curl with SSE flags (-N for no-buffer, Accept header)
        // Use 10 second timeout - SSE returns when data arrives or timeout
        const resp = root.http_util.curlGetSSE(allocator, url, "10") catch |err| {
            log.warn("Signal SSE poll failed: {}", .{err});
            return err;
        };
        defer allocator.free(resp);

        if (resp.len == 0) {
            return &.{};
        }

        log.debug("SSE response: {s}", .{resp[0..@min(500, resp.len)]});

        // Parse SSE response - each line is "data: {json}\n\n"
        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer {
            for (messages.items) |*msg| {
                msg.deinit(allocator);
            }
            messages.deinit(allocator);
        }

        var data_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer data_buf.deinit(allocator);

        var lines = std.mem.splitScalar(u8, resp, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r");
            if (trimmed.len == 0) {
                // End of event — process accumulated data
                if (data_buf.items.len > 0) {
                    if (self.parseSSEEnvelope(data_buf.items)) |msg_opt| {
                        if (msg_opt) |msg| try messages.append(allocator, msg);
                    } else |_| {}
                    data_buf.clearRetainingCapacity();
                }
                continue;
            }
            if (trimmed[0] == ':') continue;
            if (std.mem.startsWith(u8, trimmed, "event:")) continue;
            if (std.mem.startsWith(u8, trimmed, ENVELOPE_PREFIX)) {
                const json_start = trimmed[ENVELOPE_PREFIX.len..];
                const json_trimmed = std.mem.trim(u8, json_start, " \r");
                if (data_buf.items.len > 0) try data_buf.appendSlice(allocator, "\n");
                try data_buf.appendSlice(allocator, json_trimmed);
            }
        }
        // Handle final event if no trailing blank line
        if (data_buf.items.len > 0) {
            if (self.parseSSEEnvelope(data_buf.items)) |msg_opt| {
                if (msg_opt) |msg| try messages.append(allocator, msg);
            } else |_| {}
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
        _ = ptr;
        // Nothing to clean up for HTTP-based channel.
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *SignalChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
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

test "rpc url built correctly" {
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
    const url = try ch.rpcUrl(&buf);
    try std.testing.expectEqualStrings("http://127.0.0.1:8686/api/v1/rpc", url);
}

test "sse url built correctly" {
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
    const url = try ch.sseUrl(&buf);
    try std.testing.expectEqualStrings("http://127.0.0.1:8686/api/v1/events?account=%2B1234567890", url);
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
    try std.testing.expectEqualStrings("http://127.0.0.1:8686/api/v1/check", url);
}

// ── JSON-RPC Body Tests ─────────────────────────────────────────────

test "build rpc body direct with message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRpcBody(std.testing.allocator, "send", .{ .direct = "+5555555555" }, "Hello!");
    defer std.testing.allocator.free(body);
    // Verify key fields are present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"jsonrpc\":\"2.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"method\":\"send\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipient\":[\"+5555555555\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"account\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"Hello!\"") != null);
    // Direct targets must NOT include groupId.
    try std.testing.expect(std.mem.indexOf(u8, body, "groupId") == null);
}

test "build rpc body direct without message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRpcBody(std.testing.allocator, "sendTyping", .{ .direct = "+5555555555" }, null);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipient\":[\"+5555555555\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"account\":\"+1234567890\"") != null);
    // No message key should be present.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") == null);
}

test "build rpc body group with message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRpcBody(std.testing.allocator, "send", .{ .group = "abc123" }, "Group msg");
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"groupId\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"account\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"Group msg\"") != null);
    // Group targets must NOT include recipient.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"recipient\"") == null);
}

test "build rpc body group without message" {
    const ch = SignalChannel.init(
        std.testing.allocator,
        "http://127.0.0.1:8686",
        "+1234567890",
        &.{},
        &.{},
        true,
        true,
    );
    const body = try ch.buildRpcBody(std.testing.allocator, "sendTyping", .{ .group = "abc123" }, null);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"groupId\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"account\":\"+1234567890\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") == null);
}

test "build rpc body uuid direct target" {
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
    const body = try ch.buildRpcBody(std.testing.allocator, "send", .{ .direct = uuid }, "hi");
    defer std.testing.allocator.free(body);
    // Verify UUID is in recipient array.
    const expected = "\"recipient\":[\"" ++ uuid ++ "\"]";
    try std.testing.expect(std.mem.indexOf(u8, body, expected) != null);
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
        \\      "message": "hello from sse",
        \\      "timestamp": 1700000001
        \\    }
        \\  }
        \\}
    ;
    const json_buf = try std.testing.allocator.dupe(u8, raw_json);
    defer std.testing.allocator.free(json_buf);

    const msg_opt = try ch.parseSSEEnvelope(json_buf);
    try std.testing.expect(msg_opt != null);
    const msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    @memset(json_buf, 'x');
    const churn = try std.testing.allocator.alloc(u8, 2048);
    defer std.testing.allocator.free(churn);
    @memset(churn, 'z');

    try std.testing.expectEqualStrings("hello from sse", msg.content);
    try std.testing.expectEqualStrings("+1111111111", msg.sender);
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
