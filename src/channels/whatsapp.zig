const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");

/// WhatsApp channel — uses WhatsApp Business Cloud API.
/// Operates in webhook mode (push-based); messages received via gateway endpoint.
pub const WhatsAppChannel = struct {
    allocator: std.mem.Allocator,
    access_token: []const u8,
    phone_number_id: []const u8,
    verify_token: []const u8,
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    group_policy: []const u8,

    pub const API_VERSION = "v18.0";

    pub fn init(
        allocator: std.mem.Allocator,
        access_token: []const u8,
        phone_number_id: []const u8,
        verify_token: []const u8,
        allow_from: []const []const u8,
        group_allow_from: []const []const u8,
        group_policy: []const u8,
    ) WhatsAppChannel {
        return .{
            .allocator = allocator,
            .access_token = access_token,
            .phone_number_id = phone_number_id,
            .verify_token = verify_token,
            .allow_from = allow_from,
            .group_allow_from = group_allow_from,
            .group_policy = group_policy,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WhatsAppConfig) WhatsAppChannel {
        return init(
            allocator,
            cfg.access_token,
            cfg.phone_number_id,
            cfg.verify_token,
            cfg.allow_from,
            cfg.group_allow_from,
            cfg.group_policy,
        );
    }

    pub fn channelName(_: *WhatsAppChannel) []const u8 {
        return "whatsapp";
    }

    pub fn getVerifyToken(self: *const WhatsAppChannel) []const u8 {
        return self.verify_token;
    }

    /// Check if a phone number is allowed (E.164 format: +1234567890).
    pub fn isNumberAllowed(self: *const WhatsAppChannel, phone: []const u8) bool {
        return root.isAllowed(self.allow_from, phone);
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
        if (val != .object) return result.items;
        const entry_val = val.object.get("entry") orelse return result.items;
        if (entry_val != .array) return result.items;
        const entries = entry_val.array.items;
        for (entries) |entry| {
            if (entry != .object) continue;
            const changes_val = entry.object.get("changes") orelse continue;
            if (changes_val != .array) continue;
            const changes = changes_val.array.items;
            for (changes) |change| {
                if (change != .object) continue;
                const value_val = change.object.get("value") orelse continue;
                if (value_val != .object) continue;
                const value_obj = value_val.object;
                const messages_val = value_obj.get("messages") orelse continue;
                if (messages_val != .array) continue;
                const messages = messages_val.array.items;

                for (messages) |msg| {
                    if (msg != .object) continue;
                    const msg_obj = msg.object;

                    const from_val = msg_obj.get("from") orelse continue;
                    const from = if (from_val == .string) from_val.string else continue;

                    // Normalize phone
                    var phone_buf: [32]u8 = undefined;
                    const normalized = normalizePhone(&phone_buf, from);

                    // Check group policy
                    const is_group_msg = if (msg_obj.get("context")) |ctx|
                        if (ctx == .object) (ctx.object.get("group_jid") != null) else false
                    else
                        false;

                    if (!is_group_msg) {
                        if (self.allow_from.len > 0 and !self.isNumberAllowed(normalized)) continue;
                    } else {
                        if (std.mem.eql(u8, self.group_policy, "disabled")) continue;
                        if (!std.mem.eql(u8, self.group_policy, "open")) {
                            const effective_allow_from = if (self.group_allow_from.len > 0)
                                self.group_allow_from
                            else
                                self.allow_from;
                            if (effective_allow_from.len == 0) continue;
                            if (!root.isAllowed(effective_allow_from, normalized)) continue;
                        }
                    }

                    // Extract text only
                    const text_obj = msg_obj.get("text") orelse continue;
                    if (text_obj != .object) continue;
                    const body_val = text_obj.object.get("body") orelse continue;
                    const body = if (body_val == .string) body_val.string else continue;
                    if (body.len == 0) continue;

                    // Extract timestamp
                    const ts_val = msg_obj.get("timestamp");
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

    /// Fetches an image media from WhatsApp Cloud API using its ID, saves it to a temp file,
    /// and returns the path formatted as `[IMAGE:/path]`.
    pub fn downloadMediaFromPayload(allocator: std.mem.Allocator, access_token: []const u8, payload: []const u8) ?[]const u8 {
        if (access_token.len == 0) return null;

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
        defer parsed.deinit();

        // Navigate to the image ID
        const val = parsed.value;
        if (val != .object) return null;
        const entry_raw = val.object.get("entry") orelse return null;
        if (entry_raw != .array) return null;
        const entries = entry_raw.array.items;
        if (entries.len == 0) return null;
        if (entries[0] != .object) return null;
        const changes_raw = entries[0].object.get("changes") orelse return null;
        if (changes_raw != .array) return null;
        const changes = changes_raw.array.items;
        if (changes.len == 0) return null;
        if (changes[0] != .object) return null;
        const value_raw = changes[0].object.get("value") orelse return null;
        if (value_raw != .object) return null;
        const value_obj = value_raw.object;
        const messages_val = value_obj.get("messages") orelse return null;
        if (messages_val != .array) return null;
        const messages = messages_val.array.items;
        if (messages.len == 0) return null;
        if (messages[0] != .object) return null;
        const msg = messages[0].object;

        const img_obj = msg.get("image") orelse return null;
        if (img_obj != .object) return null;
        const id_val = img_obj.object.get("id") orelse return null;
        if (id_val != .string) return null;
        const media_id = id_val.string;

        // Step 1: Get media URL
        var url_buf: [256]u8 = undefined;
        const info_url = std.fmt.bufPrint(&url_buf, "https://graph.facebook.com/{s}/{s}", .{ API_VERSION, media_id }) catch return null;

        var auth_buf: [512]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_buf, "Authorization: Bearer {s}", .{access_token}) catch return null;

        const info_resp = root.http_util.curlGet(allocator, info_url, &.{auth_header}, "10") catch return null;
        defer allocator.free(info_resp);

        var info_parsed = std.json.parseFromSlice(std.json.Value, allocator, info_resp, .{}) catch return null;
        defer info_parsed.deinit();

        if (info_parsed.value != .object) return null;
        const url_val = info_parsed.value.object.get("url") orelse return null;
        if (url_val != .string) return null;
        const media_url = url_val.string;

        // Step 2: Download media bytes
        const media_resp = root.http_util.curlGet(allocator, media_url, &.{auth_header}, "30") catch return null;
        defer allocator.free(media_resp);

        // Step 3: Write to tmp file
        var rand = std.crypto.random;
        var path_buf: [1024]u8 = undefined;
        const local_path = std.fmt.bufPrint(&path_buf, "/tmp/whatsapp_{x}.dat", .{rand.int(u64)}) catch return null;

        if (std.fs.createFileAbsolute(local_path, .{ .read = false })) |file| {
            file.writeAll(media_resp) catch {
                file.close();
                return null;
            };
            file.close();

            // Format as [IMAGE:path]
            var out_buf: std.ArrayListUnmanaged(u8) = .empty;
            out_buf.appendSlice(allocator, "[IMAGE:") catch return null;
            out_buf.appendSlice(allocator, local_path) catch return null;
            out_buf.appendSlice(allocator, "]") catch return null;
            return out_buf.toOwnedSlice(allocator) catch null;
        } else |_| {
            return null;
        }
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

        // Build JSON body dynamically
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const w = body_list.writer(self.allocator);
        try w.writeAll("{\"messaging_product\":\"whatsapp\",\"recipient_type\":\"individual\",\"to\":\"");
        try w.writeAll(to);
        try w.writeAll("\",\"type\":\"text\",\"text\":{\"preview_url\":false,\"body\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}}");
        const body = body_list.items;

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

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
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

test "whatsapp verify token" {
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "my-verify", &.{}, &.{}, "allowlist");
    try std.testing.expectEqualStrings("my-verify", ch.getVerifyToken());
}

test "whatsapp normalize phone" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("+1234567890", WhatsAppChannel.normalizePhone(&buf, "1234567890"));
    try std.testing.expectEqualStrings("+1234567890", WhatsAppChannel.normalizePhone(&buf, "+1234567890"));
}

test "whatsapp parse empty payload" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse invalid shapes returns empty" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":42,"text":"oops"}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse valid text message" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");

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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");

    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"9999999999","timestamp":"1","type":"text","text":{"body":"Spam"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp group open bypasses allow_from" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "open");
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"9999999999","timestamp":"1","type":"text","context":{"group_jid":"1203630@g.us"},"text":{"body":"Group hello"}}]}}]}]}
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
    try std.testing.expectEqualStrings("Group hello", msgs[0].content);
}

test "whatsapp group allowlist falls back to allow_from" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1111111111"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"1111111111","timestamp":"1","type":"text","context":{"group_jid":"1203630@g.us"},"text":{"body":"Allowed in group"}}]}}]}]}
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
}

test "whatsapp group allowlist blocks when allowlists are empty" {
    const allocator = std.testing.allocator;
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &.{}, &.{}, "allowlist");
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"1111111111","timestamp":"1","type":"text","context":{"group_jid":"1203630@g.us"},"text":{"body":"Blocked in group"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse non-text message skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");

    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":[{"from":"111","timestamp":"1","type":"image","image":{"id":"img123"}}]}}]}]}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

// ════════════════════════════════════════════════════════════════════════════
// Edge Cases — Comprehensive coverage (ported from ZeroClaw Rust tests)
// ════════════════════════════════════════════════════════════════════════════

test "whatsapp parse missing entry array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"object\":\"whatsapp_business_account\"}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing changes array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"id\":\"123\"}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing value" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"field\":\"messages\"}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse missing messages array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"value\":{\"metadata\":{}}}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse malformed message types are ignored" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":["not-an-object",{"from":"111","timestamp":"1","type":"text","text":"not-an-object"}]}}]}]}
    ;
    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp download media malformed messages type returns null" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"entry":[{"changes":[{"value":{"messages":{"id":"oops"}}}]}]}
    ;
    try std.testing.expect(WhatsAppChannel.downloadMediaFromPayload(allocator, "tok", payload) == null);
}

test "whatsapp parse missing from field" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    try std.testing.expect(ch.isNumberAllowed("+1111111111"));
    try std.testing.expect(ch.isNumberAllowed("+2222222222"));
    try std.testing.expect(ch.isNumberAllowed("+3333333333"));
    try std.testing.expect(!ch.isNumberAllowed("+4444444444"));
}

test "whatsapp number allowed case sensitive" {
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(std.testing.allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    try std.testing.expect(ch.isNumberAllowed("+1234567890"));
    try std.testing.expect(!ch.isNumberAllowed("+1234567891"));
}

test "whatsapp parse phone already has plus" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(std.testing.allocator, "my-access-token", "phone-id-123", "my-verify-token", &nums, &.{}, "allowlist");
    try std.testing.expectEqualStrings("my-verify-token", ch.getVerifyToken());
    try std.testing.expect(ch.isNumberAllowed("+111"));
    try std.testing.expect(ch.isNumberAllowed("+222"));
    try std.testing.expect(!ch.isNumberAllowed("+333"));
}

test "whatsapp parse empty messages array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[{\"value\":{\"messages\":[]}}]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse empty entry array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse empty changes array" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{\"entry\":[{\"changes\":[]}]}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp parse newlines preserved" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
    const ch = WhatsAppChannel.init(allocator, "tok", "123", "ver", &nums, &.{}, "allowlist");
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
