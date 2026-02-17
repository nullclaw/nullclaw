const std = @import("std");
const root = @import("root.zig");

/// WhatsApp channel — uses WhatsApp Business Cloud API.
/// Operates in webhook mode (push-based); messages received via gateway endpoint.
pub const WhatsAppChannel = struct {
    allocator: std.mem.Allocator,
    access_token: []const u8,
    phone_number_id: []const u8,
    verify_token: []const u8,
    allowed_numbers: []const []const u8,

    pub const API_VERSION = "v18.0";

    pub fn init(
        allocator: std.mem.Allocator,
        access_token: []const u8,
        phone_number_id: []const u8,
        verify_token: []const u8,
        allowed_numbers: []const []const u8,
    ) WhatsAppChannel {
        return .{
            .allocator = allocator,
            .access_token = access_token,
            .phone_number_id = phone_number_id,
            .verify_token = verify_token,
            .allowed_numbers = allowed_numbers,
        };
    }

    pub fn channelName(_: *WhatsAppChannel) []const u8 {
        return "whatsapp";
    }

    pub fn getVerifyToken(self: *const WhatsAppChannel) []const u8 {
        return self.verify_token;
    }

    /// Check if a phone number is allowed (E.164 format: +1234567890).
    pub fn isNumberAllowed(self: *const WhatsAppChannel, phone: []const u8) bool {
        return root.isAllowedExact(self.allowed_numbers, phone);
    }

    /// Normalize a phone number to E.164 (prepend + if missing).
    pub fn normalizePhone(buf: []u8, phone: []const u8) []const u8 {
        if (phone.len == 0) return phone;
        if (phone[0] == '+') return phone;
        if (phone.len + 1 > buf.len) return phone;
        buf[0] = '+';
        @memcpy(buf[1..][0..phone.len], phone);
        return buf[0 .. phone.len + 1];
    }

    /// Parse a webhook payload and extract text messages.
    /// Returns message tuples (sender, content, timestamp) allocated on the given allocator.
    pub fn parseWebhookPayload(
        self: *const WhatsAppChannel,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) ![]ParsedMessage {
        var result: std.ArrayListUnmanaged(ParsedMessage) = .empty;
        errdefer {
            for (result.items) |*m| m.deinit(allocator);
            result.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return result.items;
        defer parsed.deinit();
        const val = parsed.value;

        // Navigate: entry[] -> changes[] -> value -> messages[]
        const entries = (val.object.get("entry") orelse return result.items).array.items;
        for (entries) |entry| {
            const changes = ((entry.object.get("changes")) orelse continue).array.items;
            for (changes) |change| {
                const value_obj = (change.object.get("value") orelse continue).object;
                const messages = ((value_obj.get("messages")) orelse continue).array.items;

                for (messages) |msg| {
                    const from_val = msg.object.get("from") orelse continue;
                    const from = if (from_val == .string) from_val.string else continue;

                    // Normalize phone
                    var phone_buf: [32]u8 = undefined;
                    const normalized = normalizePhone(&phone_buf, from);

                    // Check allowlist
                    if (!self.isNumberAllowed(normalized)) continue;

                    // Extract text only
                    const text_obj = msg.object.get("text") orelse continue;
                    const body_val = text_obj.object.get("body") orelse continue;
                    const body = if (body_val == .string) body_val.string else continue;
                    if (body.len == 0) continue;

                    // Extract timestamp
                    const ts_val = msg.object.get("timestamp");
                    const timestamp = blk: {
                        if (ts_val) |tv| {
                            if (tv == .string) {
                                break :blk std.fmt.parseInt(u64, tv.string, 10) catch root.nowEpochSecs();
                            }
                        }
                        break :blk root.nowEpochSecs();
                    };

                    try result.append(allocator, .{
                        .sender = try allocator.dupe(u8, normalized),
                        .content = try allocator.dupe(u8, body),
                        .timestamp = timestamp,
                    });
                }
            }
        }

        return result.toOwnedSlice(allocator);
    }

    pub fn healthCheck(_: *WhatsAppChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a text message via WhatsApp Business Cloud API.
    /// POST https://graph.facebook.com/v18.0/{phone_number_id}/messages
    pub fn sendMessage(self: *WhatsAppChannel, recipient: []const u8, text: []const u8) !void {
        // Build URL
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("https://graph.facebook.com/{s}/{s}/messages", .{ API_VERSION, self.phone_number_id });
        const url = url_fbs.getWritten();

        // Strip leading '+' from recipient for the API
        const to = if (recipient.len > 0 and recipient[0] == '+') recipient[1..] else recipient;

        // Build JSON body
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"messaging_product\":\"whatsapp\",\"recipient_type\":\"individual\",\"to\":\"");
        try w.writeAll(to);
        try w.writeAll("\",\"type\":\"text\",\"text\":{\"preview_url\":false,\"body\":\"");
        for (text) |c| {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                else => try w.writeByte(c),
            }
        }
        try w.writeAll("\"}}");
        const body = fbs.getWritten();

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{self.access_token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.WhatsAppApiError;

        if (result.status != .ok) {
            return error.WhatsAppApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // WhatsApp uses webhooks (push-based); no persistent connection needed.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *WhatsAppChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WhatsAppChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WhatsAppChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WhatsAppChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedMessage = struct {
    sender: []const u8,
    content: []const u8,
    timestamp: u64,

    pub fn deinit(self: *ParsedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "whatsapp channel name" {
    var ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &.{});
    try std.testing.expectEqualStrings("whatsapp", ch.channelName());
}

test "whatsapp verify token" {
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "my-verify", &.{});
    try std.testing.expectEqualStrings("my-verify", ch.getVerifyToken());
}

test "whatsapp number allowed exact" {
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums);
    try std.testing.expect(ch.isNumberAllowed("+1234567890"));
    try std.testing.expect(!ch.isNumberAllowed("+9876543210"));
}

test "whatsapp number allowed wildcard" {
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums);
    try std.testing.expect(ch.isNumberAllowed("+1234567890"));
    try std.testing.expect(ch.isNumberAllowed("+9999999999"));
}

test "whatsapp number denied empty" {
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &.{});
    try std.testing.expect(!ch.isNumberAllowed("+1234567890"));
}

test "whatsapp normalize phone" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("+1234567890", WhatsAppChannel.normalizePhone(&buf, "1234567890"));
    try std.testing.expectEqualStrings("+1234567890", WhatsAppChannel.normalizePhone(&buf, "+1234567890"));
}

test "whatsapp parse empty payload" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse valid text message" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);

    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"1234567890","timestamp":"1699999999","type":"text","text":{"body":"Hello nullclaw!"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
    try std.testing.expectEqualStrings("Hello nullclaw!", msgs[0].content);
    try std.testing.expectEqual(@as(u64, 1_699_999_999), msgs[0].timestamp);
}

test "whatsapp parse unauthorized number filtered" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);

    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"9999999999","timestamp":"1","type":"text","text":{"body":"Spam"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse non-text message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);

    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"image","image":{"id":"img123"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp vtable interface" {
    var ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("whatsapp", iface.name());
}

// ════════════════════════════════════════════════════════════════════════════
// Edge Cases — Comprehensive coverage (ported from ZeroClaw Rust tests)
// ════════════════════════════════════════════════════════════════════════════

test "whatsapp parse missing entry array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"object\":\"whatsapp_business_account\"}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing changes array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"id\":\"123\"}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing value" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"field\":\"messages\"}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing messages array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"value\":{\"metadata\":{}}}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing from field" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"timestamp":"1","type":"text","text":{"body":"No sender"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing text body" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse null text body" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":null}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse invalid timestamp uses current" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"not_a_number","type":"text","text":{"body":"Hello"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].timestamp > 0);
}

test "whatsapp parse missing timestamp uses current" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","type":"text","text":{"body":"Hello"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].timestamp > 0);
}

test "whatsapp parse multiple messages" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"First"}},{"from":"222","timestamp":"2","type":"text","text":{"body":"Second"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("First", msgs[0].content);
    try std.testing.expectEqualStrings("Second", msgs[1].content);
}

test "whatsapp parse multiple entries" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"Entry 1"}}]}}]},{"changes":[{"value":{"messages":[{"from":"222","timestamp":"2","type":"text","text":{"body":"Entry 2"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("Entry 1", msgs[0].content);
    try std.testing.expectEqualStrings("Entry 2", msgs[1].content);
}

test "whatsapp parse multiple changes" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"Change 1"}}]}},{"value":{"messages":[{"from":"222","timestamp":"2","type":"text","text":{"body":"Change 2"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("Change 1", msgs[0].content);
    try std.testing.expectEqualStrings("Change 2", msgs[1].content);
}

test "whatsapp parse status update ignored" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"statuses":[{"id":"wamid.xxx","status":"delivered","timestamp":"1699999999"}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse audio message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"audio","audio":{"id":"audio123"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse video message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"video","video":{"id":"video123"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse document message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"document","document":{"id":"doc123"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse sticker message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"sticker","sticker":{"id":"sticker123"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse location message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"location","location":{"latitude":40.7128}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse contacts message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"contacts","contacts":[]}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse mixed authorized unauthorized" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1111111111"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"1111111111","timestamp":"1","type":"text","text":{"body":"Allowed"}},{"from":"9999999999","timestamp":"2","type":"text","text":{"body":"Blocked"}},{"from":"1111111111","timestamp":"3","type":"text","text":{"body":"Also allowed"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("Allowed", msgs[0].content);
    try std.testing.expectEqualStrings("Also allowed", msgs[1].content);
}

test "whatsapp parse unicode message" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"Hello world"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Hello world", msgs[0].content);
}

test "whatsapp parse whitespace only message passes through" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"   "}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    // Whitespace-only is NOT empty, so it passes through
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("   ", msgs[0].content);
}

test "whatsapp number allowed multiple numbers" {
    const nums = [_][]const u8{ "+1111111111", "+2222222222", "+3333333333" };
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums);
    try std.testing.expect(ch.isNumberAllowed("+1111111111"));
    try std.testing.expect(ch.isNumberAllowed("+2222222222"));
    try std.testing.expect(ch.isNumberAllowed("+3333333333"));
    try std.testing.expect(!ch.isNumberAllowed("+4444444444"));
}

test "whatsapp number allowed case sensitive" {
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums);
    try std.testing.expect(ch.isNumberAllowed("+1234567890"));
    try std.testing.expect(!ch.isNumberAllowed("+1234567891"));
}

test "whatsapp parse phone already has plus" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"+1234567890","timestamp":"1","type":"text","text":{"body":"Hi"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
}

test "whatsapp parse normalizes phone with plus" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"1234567890","timestamp":"1","type":"text","text":{"body":"Hi"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
}

test "whatsapp channel fields stored correctly" {
    const nums = [_][]const u8{ "+111", "+222" };
    const ch = WhatsAppChannel.init(std.testing.allocator, "my-access-token", "phone-id-123", "my-verify-token", &nums);
    try std.testing.expectEqualStrings("my-verify-token", ch.getVerifyToken());
    try std.testing.expect(ch.isNumberAllowed("+111"));
    try std.testing.expect(ch.isNumberAllowed("+222"));
    try std.testing.expect(!ch.isNumberAllowed("+333"));
}

test "whatsapp parse empty messages array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"value\":{\"messages\":[]}}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse empty entry array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse empty changes array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse newlines preserved" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"Line 1\nLine 2\nLine 3"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Line 1\nLine 2\nLine 3", msgs[0].content);
}

test "whatsapp parse special characters" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":"quotes and 'apostrophe'"}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("quotes and 'apostrophe'", msgs[0].content);
}

test "whatsapp empty text skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums);
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"text","text":{"body":""}}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp normalize phone empty" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("", WhatsAppChannel.normalizePhone(&buf, ""));
}

test "whatsapp normalize phone buffer too small" {
    var buf: [2]u8 = undefined;
    // Phone "123" needs 4 bytes ("+123"), but buf is only 2 bytes
    try std.testing.expectEqualStrings("123", WhatsAppChannel.normalizePhone(&buf, "123"));
}
