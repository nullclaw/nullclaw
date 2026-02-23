const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");

/// Lark/Feishu channel — receives events via HTTP callback, sends via Open API.
///
/// Supports two regional endpoints (configured via `use_feishu`):
/// - **Feishu** (default): CN endpoints at `open.feishu.cn`
/// - **Lark**: International endpoints at `open.larksuite.com`
///
/// TODO: WebSocket long-connection mode (too complex for now, use HTTP webhook).
pub const LarkChannel = struct {
    allocator: std.mem.Allocator,
    app_id: []const u8,
    app_secret: []const u8,
    verification_token: []const u8,
    port: u16,
    allow_from: []const []const u8,
    /// When true, use Feishu (CN) endpoints; when false, use Lark (international).
    use_feishu: bool = true,
    /// Cached tenant access token (heap-allocated, owned by allocator).
    cached_token: ?[]const u8 = null,
    /// Epoch seconds when cached_token expires.
    token_expires_at: i64 = 0,

    pub const FEISHU_BASE_URL = "https://open.feishu.cn/open-apis";
    pub const LARK_BASE_URL = "https://open.larksuite.com/open-apis";

    pub fn init(
        allocator: std.mem.Allocator,
        app_id: []const u8,
        app_secret: []const u8,
        verification_token: []const u8,
        port: u16,
        allow_from: []const []const u8,
    ) LarkChannel {
        return .{
            .allocator = allocator,
            .app_id = app_id,
            .app_secret = app_secret,
            .verification_token = verification_token,
            .port = port,
            .allow_from = allow_from,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.LarkConfig) LarkChannel {
        var ch = init(
            allocator,
            cfg.app_id,
            cfg.app_secret,
            cfg.verification_token orelse "",
            cfg.port orelse 9000,
            cfg.allow_from,
        );
        ch.use_feishu = cfg.use_feishu;
        return ch;
    }

    /// Return the API base URL based on region setting.
    pub fn apiBase(self: *const LarkChannel) []const u8 {
        return if (self.use_feishu) FEISHU_BASE_URL else LARK_BASE_URL;
    }

    pub fn channelName(_: *LarkChannel) []const u8 {
        return "lark";
    }

    pub fn isUserAllowed(self: *const LarkChannel, open_id: []const u8) bool {
        return root.isAllowedExact(self.allow_from, open_id);
    }

    /// Parse a Lark event callback payload and extract text messages.
    /// Supports both "text" and "post" message types.
    /// For group chats, only responds when the bot is @-mentioned.
    pub fn parseEventPayload(
        self: *const LarkChannel,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) ![]ParsedLarkMessage {
        var result: std.ArrayListUnmanaged(ParsedLarkMessage) = .empty;
        errdefer {
            for (result.items) |*m| m.deinit(allocator);
            result.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return result.items;
        defer parsed.deinit();
        const val = parsed.value;
        if (val != .object) return result.items;

        // Check event type
        const header = val.object.get("header") orelse return result.items;
        if (header != .object) return result.items;
        const event_type_val = header.object.get("event_type") orelse return result.items;
        const event_type = if (event_type_val == .string) event_type_val.string else return result.items;
        if (!std.mem.eql(u8, event_type, "im.message.receive_v1")) return result.items;

        const event = val.object.get("event") orelse return result.items;
        if (event != .object) return result.items;

        // Extract sender open_id
        const sender_obj = event.object.get("sender") orelse return result.items;
        if (sender_obj != .object) return result.items;
        const sender_id_obj = sender_obj.object.get("sender_id") orelse return result.items;
        if (sender_id_obj != .object) return result.items;
        const open_id_val = sender_id_obj.object.get("open_id") orelse return result.items;
        const open_id = if (open_id_val == .string) open_id_val.string else return result.items;
        if (open_id.len == 0) return result.items;

        if (!self.isUserAllowed(open_id)) return result.items;

        // Message content
        const msg_obj = event.object.get("message") orelse return result.items;
        if (msg_obj != .object) return result.items;
        const msg_type_val = msg_obj.object.get("message_type") orelse return result.items;
        const msg_type = if (msg_type_val == .string) msg_type_val.string else return result.items;

        const content_val = msg_obj.object.get("content") orelse return result.items;
        const content_str = if (content_val == .string) content_val.string else return result.items;

        // Parse content based on message type
        const raw_text: []const u8 = if (std.mem.eql(u8, msg_type, "text")) blk: {
            // Content is a JSON string like {"text":"hello"}
            const inner = std.json.parseFromSlice(std.json.Value, allocator, content_str, .{}) catch return result.items;
            defer inner.deinit();
            if (inner.value != .object) return result.items;
            const text_val = inner.value.object.get("text") orelse return result.items;
            const text = if (text_val == .string) text_val.string else return result.items;
            if (text.len == 0) return result.items;
            break :blk try allocator.dupe(u8, text);
        } else if (std.mem.eql(u8, msg_type, "post")) blk: {
            const maybe = parsePostContent(allocator, content_str) catch return result.items;
            break :blk maybe orelse return result.items;
        } else return result.items;
        defer allocator.free(raw_text);

        // Strip @_user_N placeholders
        const stripped = try stripAtPlaceholders(allocator, raw_text);
        defer allocator.free(stripped);

        // Trim whitespace
        const text = std.mem.trim(u8, stripped, " \t\n\r");
        if (text.len == 0) return result.items;

        // Group chat: only respond when bot is @-mentioned
        const chat_type_val = msg_obj.object.get("chat_type");
        const chat_type = if (chat_type_val) |ctv| (if (ctv == .string) ctv.string else "") else "";
        const chat_id_val = msg_obj.object.get("chat_id");
        const chat_id = if (chat_id_val) |cv| (if (cv == .string) cv.string else open_id) else open_id;

        if (std.mem.eql(u8, chat_type, "group")) {
            // Check mentions array in the event
            const mentions_val = msg_obj.object.get("mentions");
            if (!shouldRespondInGroup(mentions_val, raw_text, "")) {
                return result.items;
            }
        }

        // Timestamp (Lark timestamps are in milliseconds)
        const create_time_val = msg_obj.object.get("create_time");
        const timestamp = blk: {
            if (create_time_val) |ctv| {
                if (ctv == .string) {
                    const ms = std.fmt.parseInt(u64, ctv.string, 10) catch break :blk root.nowEpochSecs();
                    break :blk ms / 1000;
                }
            }
            break :blk root.nowEpochSecs();
        };

        try result.append(allocator, .{
            .sender = try allocator.dupe(u8, chat_id),
            .content = try allocator.dupe(u8, text),
            .timestamp = timestamp,
            .is_group = std.mem.eql(u8, chat_type, "group"),
        });

        return result.toOwnedSlice(allocator);
    }

    pub fn healthCheck(_: *LarkChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Obtain a tenant access token from the Feishu/Lark API.
    /// POST /auth/v3/tenant_access_token/internal
    /// Uses cached token if still valid (with 60s safety margin).
    pub fn getTenantAccessToken(self: *LarkChannel) ![]const u8 {
        // Check cache first
        if (self.cached_token) |token| {
            const now = std.time.timestamp();
            if (now < self.token_expires_at - 60) {
                return self.allocator.dupe(u8, token);
            }
            // Token expired, free it
            self.allocator.free(token);
            self.cached_token = null;
            self.token_expires_at = 0;
        }

        const token = try self.fetchTenantToken();

        // Cache the token (2 hour typical expiry)
        self.cached_token = self.allocator.dupe(u8, token) catch null;
        self.token_expires_at = std.time.timestamp() + 7200;

        return token;
    }

    /// Invalidate cached token (called on 401).
    pub fn invalidateToken(self: *LarkChannel) void {
        if (self.cached_token) |token| {
            self.allocator.free(token);
            self.cached_token = null;
            self.token_expires_at = 0;
        }
    }

    /// Fetch a fresh tenant access token from the API.
    fn fetchTenantToken(self: *LarkChannel) ![]const u8 {
        const base = self.apiBase();

        // Build URL: base ++ "/auth/v3/tenant_access_token/internal"
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/auth/v3/tenant_access_token/internal", .{base});
        const url = url_fbs.getWritten();

        // Build JSON body
        var body_buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        try fbs.writer().print("{{\"app_id\":\"{s}\",\"app_secret\":\"{s}\"}}", .{ self.app_id, self.app_secret });
        const body = fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
            },
            .response_writer = &aw.writer,
        }) catch return error.LarkApiError;

        if (result.status != .ok) return error.LarkApiError;

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.LarkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.LarkApiError;

        const token_val = parsed.value.object.get("tenant_access_token") orelse return error.LarkApiError;
        if (token_val != .string) return error.LarkApiError;
        return self.allocator.dupe(u8, token_val.string);
    }

    /// Send a message to a Lark chat via the Open API.
    /// POST /im/v1/messages?receive_id_type=chat_id
    /// On 401, invalidates cached token and retries once.
    pub fn sendMessage(self: *LarkChannel, recipient: []const u8, text: []const u8) !void {
        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        const base = self.apiBase();

        // Build URL
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages?receive_id_type=chat_id", .{base});
        const url = url_fbs.getWritten();

        // Build inner content JSON: {"text":"..."}
        var content_buf: [4096]u8 = undefined;
        var content_fbs = std.io.fixedBufferStream(&content_buf);
        const cw = content_fbs.writer();
        try cw.writeAll("{\"text\":");
        try root.appendJsonStringW(cw, text);
        try cw.writeAll("}");
        const content_json = content_fbs.getWritten();

        // Build outer body JSON
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"receive_id\":\"");
        try w.writeAll(recipient);
        try w.writeAll("\",\"msg_type\":\"text\",\"content\":");
        // Escape the content JSON string for embedding
        try root.appendJsonStringW(w, content_json);
        try w.writeAll("}");
        const body = fbs.getWritten();

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const send_result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.LarkApiError;

        if (send_result.status == .unauthorized) {
            // Token expired — invalidate cache and retry once
            self.invalidateToken();
            const new_token = self.getTenantAccessToken() catch return error.LarkApiError;
            defer self.allocator.free(new_token);

            var retry_auth_buf: [512]u8 = undefined;
            var retry_auth_fbs = std.io.fixedBufferStream(&retry_auth_buf);
            try retry_auth_fbs.writer().print("Bearer {s}", .{new_token});
            const retry_auth_value = retry_auth_fbs.getWritten();

            var retry_client = std.http.Client{ .allocator = self.allocator };
            defer retry_client.deinit();

            const retry_result = retry_client.fetch(.{
                .location = .{ .url = url },
                .method = .POST,
                .payload = body,
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                    .{ .name = "Authorization", .value = retry_auth_value },
                },
            }) catch return error.LarkApiError;

            if (retry_result.status != .ok) {
                return error.LarkApiError;
            }
            return;
        }

        if (send_result.status != .ok) {
            return error.LarkApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Lark: receives events via HTTP callback; no persistent connection.
        // TODO: WebSocket long-connection mode
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *LarkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedLarkMessage = struct {
    sender: []const u8,
    content: []const u8,
    timestamp: u64,
    is_group: bool = false,

    pub fn deinit(self: *ParsedLarkMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Helper functions
// ════════════════════════════════════════════════════════════════════════════

/// Flatten a Lark "post" rich-text message to plain text.
/// Post format: {"zh_cn": {"title": "...", "content": [[{"tag": "text", "text": "..."}]]}}
/// Returns null when content cannot be parsed or yields no usable text.
pub fn parsePostContent(allocator: std.mem.Allocator, post_json: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, post_json, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    // Try locale keys: zh_cn, en_us, or first object value
    const locale = parsed.value.object.get("zh_cn") orelse
        parsed.value.object.get("en_us") orelse blk: {
        var it = parsed.value.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == .object) break :blk entry.value_ptr.*;
        }
        return null;
    };
    if (locale != .object) return null;

    var text_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer text_buf.deinit(allocator);

    // Title
    if (locale.object.get("title")) |title_val| {
        if (title_val == .string and title_val.string.len > 0) {
            try text_buf.appendSlice(allocator, title_val.string);
            try text_buf.appendSlice(allocator, "\n\n");
        }
    }

    // Content paragraphs: [[{tag, text}, ...], ...]
    const content = locale.object.get("content") orelse return null;
    if (content != .array) return null;

    for (content.array.items) |para| {
        if (para != .array) continue;
        for (para.array.items) |el| {
            if (el != .object) continue;
            const tag_val = el.object.get("tag") orelse continue;
            const tag = if (tag_val == .string) tag_val.string else continue;

            if (std.mem.eql(u8, tag, "text")) {
                if (el.object.get("text")) |t| {
                    if (t == .string) try text_buf.appendSlice(allocator, t.string);
                }
            } else if (std.mem.eql(u8, tag, "a")) {
                // Link: prefer text, fallback to href
                const link_text = if (el.object.get("text")) |t| (if (t == .string and t.string.len > 0) t.string else null) else null;
                const href_text = if (el.object.get("href")) |h| (if (h == .string) h.string else null) else null;
                if (link_text) |lt| {
                    try text_buf.appendSlice(allocator, lt);
                } else if (href_text) |ht| {
                    try text_buf.appendSlice(allocator, ht);
                }
            } else if (std.mem.eql(u8, tag, "at")) {
                const name = if (el.object.get("user_name")) |n| (if (n == .string) n.string else null) else null;
                const uid = if (el.object.get("user_id")) |i| (if (i == .string) i.string else null) else null;
                try text_buf.append(allocator, '@');
                try text_buf.appendSlice(allocator, name orelse uid orelse "user");
            }
        }
        try text_buf.append(allocator, '\n');
    }

    // Trim and return
    const raw = text_buf.items;
    const trimmed = std.mem.trim(u8, raw, " \t\n\r");
    if (trimmed.len == 0) return null;

    return try allocator.dupe(u8, trimmed);
}

/// Remove `@_user_N` placeholder tokens injected by Feishu in group chats.
/// Patterns like "@_user_1", "@_user_2" are replaced with empty string.
pub fn stripAtPlaceholders(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, text.len);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '@' and i + 1 < text.len) {
            // Check for "_user_" prefix after '@'
            const rest = text[i + 1 ..];
            if (std.mem.startsWith(u8, rest, "_user_")) {
                // Skip past "@_user_"
                var skip: usize = 1 + "_user_".len; // '@' + "_user_"
                // Skip digits
                while (i + skip < text.len and text[i + skip] >= '0' and text[i + skip] <= '9') {
                    skip += 1;
                }
                // Skip trailing space
                if (i + skip < text.len and text[i + skip] == ' ') {
                    skip += 1;
                }
                i += skip;
                continue;
            }
        }
        out.appendAssumeCapacity(text[i]);
        i += 1;
    }

    return try allocator.dupe(u8, out.items);
}

/// In group chats, only respond when the bot is explicitly @-mentioned.
/// For direct messages (p2p), always respond.
/// Checks: (1) mentions array is non-empty, or (2) text contains @bot_name.
pub fn shouldRespondInGroup(mentions_val: ?std.json.Value, text: []const u8, bot_name: []const u8) bool {
    // Check mentions array
    if (mentions_val) |mv| {
        if (mv == .array and mv.array.items.len > 0) return true;
    }
    // Check @bot_name in text
    if (bot_name.len > 0) {
        if (std.mem.indexOf(u8, text, bot_name)) |_| return true;
    }
    return false;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "lark parse valid text message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_testuser123"}},"message":{"message_type":"text","content":"{\"text\":\"Hello nullclaw!\"}","chat_id":"oc_chat123","create_time":"1699999999000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Hello nullclaw!", msgs[0].content);
    try std.testing.expectEqualStrings("oc_chat123", msgs[0].sender);
    try std.testing.expectEqual(@as(u64, 1_699_999_999), msgs[0].timestamp);
    try std.testing.expect(!msgs[0].is_group);
}

test "lark parse group message marks is_group" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_group_user"}},"message":{"message_type":"text","content":"{\"text\":\"hello group\"}","chat_type":"group","mentions":[{"key":"@_user_1"}],"chat_id":"oc_group_1","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].is_group);
}

test "lark parse unauthorized user" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_unauthorized"}},"message":{"message_type":"text","content":"{\"text\":\"spam\"}","chat_id":"oc_chat","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse non-text skipped" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"image","content":"{}","chat_id":"oc_chat"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse wrong event type" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.chat.disbanded_v1"},"event":{}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse empty text skipped" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"\"}","chat_id":"oc_chat"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Lark Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "lark parse challenge produces no messages" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"challenge":"abc123","token":"test_verification_token","type":"url_verification"}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse non-object payload is ignored safely" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const msgs = try ch.parseEventPayload(allocator, "\"not an object\"");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse invalid header shape is ignored safely" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload = "{\"header\":\"oops\",\"event\":{}}";
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse missing sender" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"message":{"message_type":"text","content":"{\"text\":\"hello\"}","chat_id":"oc_chat"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse missing event" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse invalid content json" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"not valid json","chat_id":"oc_chat"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse unicode message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"Hello World\"}","chat_id":"oc_chat","create_time":"1000"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Hello World", msgs[0].content);
}

test "lark parse fallback sender to open_id when no chat_id" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    // No chat_id field at all
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"hello\"}","create_time":"1000"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    // sender should fall back to open_id
    try std.testing.expectEqualStrings("ou_user", msgs[0].sender);
}

test "lark feishu base url constant" {
    try std.testing.expectEqualStrings("https://open.feishu.cn/open-apis", LarkChannel.FEISHU_BASE_URL);
}

test "lark stores all fields" {
    const users = [_][]const u8{ "ou_1", "ou_2" };
    const ch = LarkChannel.init(std.testing.allocator, "my_app_id", "my_secret", "my_token", 8080, &users);
    try std.testing.expectEqualStrings("my_app_id", ch.app_id);
    try std.testing.expectEqualStrings("my_secret", ch.app_secret);
    try std.testing.expectEqualStrings("my_token", ch.verification_token);
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
}

// ════════════════════════════════════════════════════════════════════════════
// New feature tests
// ════════════════════════════════════════════════════════════════════════════

test "lark apiBase returns feishu URL when use_feishu is true" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = true;
    try std.testing.expectEqualStrings("https://open.feishu.cn/open-apis", ch.apiBase());
}

test "lark apiBase returns larksuite URL when use_feishu is false" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = false;
    try std.testing.expectEqualStrings("https://open.larksuite.com/open-apis", ch.apiBase());
}

test "lark parsePostContent extracts text from single tag" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[[{"tag":"text","text":"hello world"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("hello world", result.?);
}

test "lark parsePostContent handles nested content array" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"My Title","content":[[{"tag":"text","text":"line one"}],[{"tag":"text","text":"line two"},{"tag":"a","text":"click here","href":"https://example.com"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    // Should contain title, both lines, and link text
    try std.testing.expect(std.mem.indexOf(u8, result.?, "My Title") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "line one") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "line two") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "click here") != null);
}

test "lark parsePostContent handles empty content" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    try std.testing.expect(result == null);
}

test "lark stripAtPlaceholders removes @_user_1" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello @_user_1 how are you?");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello how are you?", result);
}

test "lark stripAtPlaceholders removes multiple placeholders" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "@_user_1 hello @_user_2 world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "lark stripAtPlaceholders no-op on clean text" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello world, no mentions here");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello world, no mentions here", result);
}

test "lark shouldRespondInGroup true for DM" {
    // For DMs (p2p), the caller skips the group check entirely.
    // But if called with a non-empty mentions array, should return true.
    const allocator = std.testing.allocator;
    const mentions_json = "[{\"key\":\"@_user_1\",\"id\":{\"open_id\":\"ou_bot\"}}]";
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, mentions_json, .{});
    defer parsed.deinit();
    try std.testing.expect(shouldRespondInGroup(parsed.value, "hello", ""));
}

test "lark shouldRespondInGroup false when no mentions" {
    try std.testing.expect(!shouldRespondInGroup(null, "hello world", ""));
}

test "lark shouldRespondInGroup true when bot name in text" {
    try std.testing.expect(shouldRespondInGroup(null, "hey @TestBot check this", "TestBot"));
}

test "lark token caching returns same token within expiry" {
    // We can only test the caching logic without a real API.
    // Verify that setting cached_token and a future expiry works.
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    // Simulate a cached token
    ch.cached_token = try std.testing.allocator.dupe(u8, "test_cached_token_123");
    ch.token_expires_at = std.time.timestamp() + 3600; // 1 hour from now

    // getTenantAccessToken should return the cached token without hitting API
    const token = try ch.getTenantAccessToken();
    defer std.testing.allocator.free(token);
    try std.testing.expectEqualStrings("test_cached_token_123", token);

    // Clean up
    ch.invalidateToken();
    try std.testing.expect(ch.cached_token == null);
    try std.testing.expectEqual(@as(i64, 0), ch.token_expires_at);
}

test "lark parse post message type via parseEventPayload" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"post","content":"{\"zh_cn\":{\"title\":\"\",\"content\":[[{\"tag\":\"text\",\"text\":\"post message\"}]]}}","chat_id":"oc_chat","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("post message", msgs[0].content);
}

test "lark lark base url constant" {
    try std.testing.expectEqualStrings("https://open.larksuite.com/open-apis", LarkChannel.LARK_BASE_URL);
}

test "lark parsePostContent at tag with user_name" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[[{"tag":"at","user_name":"TestBot","user_id":"ou_123"},{"tag":"text","text":" do something"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "@TestBot") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "do something") != null);
}

test "lark parsePostContent en_us locale fallback" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"en_us":{"title":"English Title","content":[[{"tag":"text","text":"english content"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "English Title") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "english content") != null);
}

test "lark parsePostContent invalid json returns null" {
    const allocator = std.testing.allocator;
    const result = try parsePostContent(allocator, "not json at all");
    try std.testing.expect(result == null);
}

test "lark stripAtPlaceholders preserves normal @ mentions" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello @john how are you?");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello @john how are you?", result);
}
