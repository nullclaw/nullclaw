const std = @import("std");
const root = @import("root.zig");

/// Lark/Feishu channel — receives events via HTTP callback, sends via Open API.
pub const LarkChannel = struct {
    allocator: std.mem.Allocator,
    app_id: []const u8,
    app_secret: []const u8,
    verification_token: []const u8,
    port: u16,
    allowed_users: []const []const u8,

    pub const FEISHU_BASE_URL = "https://open.feishu.cn/open-apis";

    pub fn init(
        allocator: std.mem.Allocator,
        app_id: []const u8,
        app_secret: []const u8,
        verification_token: []const u8,
        port: u16,
        allowed_users: []const []const u8,
    ) LarkChannel {
        return .{
            .allocator = allocator,
            .app_id = app_id,
            .app_secret = app_secret,
            .verification_token = verification_token,
            .port = port,
            .allowed_users = allowed_users,
        };
    }

    pub fn channelName(_: *LarkChannel) []const u8 {
        return "lark";
    }

    pub fn isUserAllowed(self: *const LarkChannel, open_id: []const u8) bool {
        return root.isAllowedExact(self.allowed_users, open_id);
    }

    /// Parse a Lark event callback payload and extract text messages.
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

        // Check event type
        const header = val.object.get("header") orelse return result.items;
        const event_type_val = header.object.get("event_type") orelse return result.items;
        const event_type = if (event_type_val == .string) event_type_val.string else return result.items;
        if (!std.mem.eql(u8, event_type, "im.message.receive_v1")) return result.items;

        const event = val.object.get("event") orelse return result.items;

        // Extract sender open_id
        const sender_obj = event.object.get("sender") orelse return result.items;
        const sender_id_obj = sender_obj.object.get("sender_id") orelse return result.items;
        const open_id_val = sender_id_obj.object.get("open_id") orelse return result.items;
        const open_id = if (open_id_val == .string) open_id_val.string else return result.items;
        if (open_id.len == 0) return result.items;

        if (!self.isUserAllowed(open_id)) return result.items;

        // Message content
        const msg_obj = event.object.get("message") orelse return result.items;
        const msg_type_val = msg_obj.object.get("message_type") orelse return result.items;
        const msg_type = if (msg_type_val == .string) msg_type_val.string else return result.items;
        if (!std.mem.eql(u8, msg_type, "text")) return result.items;

        const content_val = msg_obj.object.get("content") orelse return result.items;
        const content_str = if (content_val == .string) content_val.string else return result.items;

        // Content is a JSON string like {"text":"hello"}
        const inner = std.json.parseFromSlice(std.json.Value, allocator, content_str, .{}) catch return result.items;
        defer inner.deinit();
        const text_val = inner.value.object.get("text") orelse return result.items;
        const text = if (text_val == .string) text_val.string else return result.items;
        if (text.len == 0) return result.items;

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

        // Chat ID (fallback to open_id)
        const chat_id_val = msg_obj.object.get("chat_id");
        const chat_id = if (chat_id_val) |cv| (if (cv == .string) cv.string else open_id) else open_id;

        try result.append(allocator, .{
            .sender = try allocator.dupe(u8, chat_id),
            .content = try allocator.dupe(u8, text),
            .timestamp = timestamp,
        });

        return result.toOwnedSlice(allocator);
    }

    pub fn healthCheck(_: *LarkChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Obtain a tenant access token from the Feishu API.
    /// POST /auth/v3/tenant_access_token/internal
    pub fn getTenantAccessToken(self: *LarkChannel) ![]const u8 {
        const url = FEISHU_BASE_URL ++ "/auth/v3/tenant_access_token/internal";

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

        const token_val = parsed.value.object.get("tenant_access_token") orelse return error.LarkApiError;
        if (token_val != .string) return error.LarkApiError;
        return self.allocator.dupe(u8, token_val.string);
    }

    /// Send a message to a Lark chat via the Feishu Open API.
    /// POST /im/v1/messages?receive_id_type=chat_id
    pub fn sendMessage(self: *LarkChannel, recipient: []const u8, text: []const u8) !void {
        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        const url = FEISHU_BASE_URL ++ "/im/v1/messages?receive_id_type=chat_id";

        // Build inner content JSON: {"text":"..."}
        var content_buf: [4096]u8 = undefined;
        var content_fbs = std.io.fixedBufferStream(&content_buf);
        const cw = content_fbs.writer();
        try cw.writeAll("{\"text\":\"");
        for (text) |c| {
            switch (c) {
                '"' => try cw.writeAll("\\\""),
                '\\' => try cw.writeAll("\\\\"),
                '\n' => try cw.writeAll("\\n"),
                '\r' => try cw.writeAll("\\r"),
                else => try cw.writeByte(c),
            }
        }
        try cw.writeAll("\"}");
        const content_json = content_fbs.getWritten();

        // Build outer body JSON
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"receive_id\":\"");
        try w.writeAll(recipient);
        try w.writeAll("\",\"msg_type\":\"text\",\"content\":\"");
        // Escape the content JSON string for embedding
        for (content_json) |c| {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                else => try w.writeByte(c),
            }
        }
        try w.writeAll("\"}");
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

        if (send_result.status != .ok) {
            return error.LarkApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Lark: receives events via HTTP callback; no persistent connection.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
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

    pub fn deinit(self: *ParsedLarkMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "lark channel name" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    try std.testing.expectEqualStrings("lark", ch.channelName());
}

test "lark user allowed exact" {
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &users);
    try std.testing.expect(ch.isUserAllowed("ou_testuser123"));
    try std.testing.expect(!ch.isUserAllowed("ou_other"));
}

test "lark user allowed wildcard" {
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &users);
    try std.testing.expect(ch.isUserAllowed("ou_anyone"));
}

test "lark user denied empty" {
    const ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    try std.testing.expect(!ch.isUserAllowed("ou_anyone"));
}

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

test "lark vtable interface" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("lark", iface.name());
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

test "lark health check returns true" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    try std.testing.expect(ch.healthCheck());
}

test "lark stores all fields" {
    const users = [_][]const u8{ "ou_1", "ou_2" };
    const ch = LarkChannel.init(std.testing.allocator, "my_app_id", "my_secret", "my_token", 8080, &users);
    try std.testing.expectEqualStrings("my_app_id", ch.app_id);
    try std.testing.expectEqualStrings("my_secret", ch.app_secret);
    try std.testing.expectEqualStrings("my_token", ch.verification_token);
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqual(@as(usize, 2), ch.allowed_users.len);
}
