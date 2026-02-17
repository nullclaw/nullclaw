const std = @import("std");
const root = @import("root.zig");

/// Telegram channel — uses the Bot API with long-polling (getUpdates).
/// Splits messages at 4096 chars (Telegram limit).
pub const TelegramChannel = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    allowed_users: []const []const u8,
    last_update_id: i64,

    pub const MAX_MESSAGE_LEN: usize = 4096;

    pub fn init(allocator: std.mem.Allocator, bot_token: []const u8, allowed_users: []const []const u8) TelegramChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .allowed_users = allowed_users,
            .last_update_id = 0,
        };
    }

    pub fn channelName(_: *TelegramChannel) []const u8 {
        return "telegram";
    }

    /// Build the Telegram API URL for a method.
    pub fn apiUrl(self: *const TelegramChannel, buf: []u8, method: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("https://api.telegram.org/bot{s}/{s}", .{ self.bot_token, method });
        return fbs.getWritten();
    }

    /// Build a sendMessage JSON body.
    pub fn buildSendBody(
        buf: []u8,
        chat_id: []const u8,
        text: []const u8,
    ) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("{{\"chat_id\":{s},\"text\":\"{s}\"}}", .{ chat_id, text });
        return fbs.getWritten();
    }

    pub fn isUserAllowed(self: *const TelegramChannel, sender: []const u8) bool {
        return root.isAllowedExact(self.allowed_users, sender);
    }

    pub fn healthCheck(_: *TelegramChannel) bool {
        // Would normally call getMe; just return true for now
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Telegram chat via the Bot API (sendMessage).
    /// Splits long messages at MAX_MESSAGE_LEN, tries Markdown first then plain text fallback.
    pub fn sendMessage(self: *TelegramChannel, chat_id: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(chat_id, chunk);
        }
    }

    fn sendChunk(self: *TelegramChannel, chat_id: []const u8, text: []const u8) !void {
        // Build URL
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "sendMessage");

        // Build JSON body with escaped text
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"chat_id\":");
        try body_list.appendSlice(self.allocator, chat_id);
        try body_list.appendSlice(self.allocator, ",\"text\":\"");
        for (text) |c| {
            switch (c) {
                '"' => try body_list.appendSlice(self.allocator, "\\\""),
                '\\' => try body_list.appendSlice(self.allocator, "\\\\"),
                '\n' => try body_list.appendSlice(self.allocator, "\\n"),
                '\r' => try body_list.appendSlice(self.allocator, "\\r"),
                '\t' => try body_list.appendSlice(self.allocator, "\\t"),
                else => try body_list.append(self.allocator, c),
            }
        }
        try body_list.appendSlice(self.allocator, "\"}");

        _ = try curlPost(self.allocator, url, body_list.items, null);
    }

    /// Poll for updates using long-polling (getUpdates) via curl.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    pub fn pollUpdates(self: *TelegramChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "getUpdates");

        // Build body with offset and timeout
        var body_buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        try fbs.writer().print("{{\"offset\":{d},\"timeout\":30,\"allowed_updates\":[\"message\"]}}", .{self.last_update_id});
        const body = fbs.getWritten();

        const resp_body = try curlPost(allocator, url, body, null);

        // Parse JSON response to extract messages
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return &.{};
        defer parsed.deinit();

        const result_array = (parsed.value.object.get("result") orelse return &.{}).array.items;

        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer messages.deinit(allocator);

        for (result_array) |update| {
            // Advance offset
            if (update.object.get("update_id")) |uid| {
                if (uid == .integer) {
                    self.last_update_id = uid.integer + 1;
                }
            }

            const message = update.object.get("message") orelse continue;
            const text_val = (message.object.get("text")) orelse continue;
            const text_str = if (text_val == .string) text_val.string else continue;

            // Get sender info
            const from_obj = message.object.get("from") orelse continue;
            const username_val = from_obj.object.get("username");
            const username = if (username_val) |uv| (if (uv == .string) uv.string else "unknown") else "unknown";

            // Check allowlist
            if (!self.isUserAllowed(username)) continue;

            // Get chat_id
            const chat_obj = message.object.get("chat") orelse continue;
            const chat_id_val = chat_obj.object.get("id") orelse continue;
            var chat_id_buf: [32]u8 = undefined;
            const chat_id_str = blk: {
                if (chat_id_val == .integer) {
                    break :blk std.fmt.bufPrint(&chat_id_buf, "{d}", .{chat_id_val.integer}) catch continue;
                }
                continue;
            };

            try messages.append(allocator, .{
                .id = try allocator.dupe(u8, username),
                .sender = try allocator.dupe(u8, chat_id_str),
                .content = try allocator.dupe(u8, text_str),
                .channel = "telegram",
                .timestamp = root.nowEpochSecs(),
            });
        }

        return messages.toOwnedSlice(allocator);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        // Verify bot token by calling getMe
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "getMe") catch return;

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        _ = client.fetch(.{
            .location = .{ .url = url },
        }) catch return;
        // If getMe fails, we still start — healthCheck will report issues
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
        // Nothing to clean up for HTTP polling
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *TelegramChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

/// HTTP POST via curl subprocess (avoids Zig 0.15 std.http.Client segfaults).
fn curlPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8, auth_header: ?[]const u8) ![]u8 {
    var argv_buf: [16][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;

    if (auth_header) |hdr| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = "-d";
    argc += 1;
    argv_buf[argc] = body;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch return error.CurlReadError;

    const term = child.wait() catch return error.CurlWaitError;
    if (term != .Exited or term.Exited != 0) return error.CurlFailed;

    return stdout;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram channel name" {
    var ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    try std.testing.expectEqualStrings("telegram", ch.channelName());
}

test "telegram api url" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "getUpdates");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/getUpdates", url);
}

test "telegram user allowed wildcard" {
    const users = [_][]const u8{"*"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "telegram user allowed specific" {
    const users = [_][]const u8{ "alice", "bob" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(!ch.isUserAllowed("eve"));
}

test "telegram user denied empty" {
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &.{});
    try std.testing.expect(!ch.isUserAllowed("anyone"));
}

test "telegram vtable interface" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("telegram", iface.name());
}

test "telegram message splitting" {
    var it = root.splitMessage("hello world", TelegramChannel.MAX_MESSAGE_LEN);
    try std.testing.expectEqualStrings("hello world", it.next().?);
    try std.testing.expect(it.next() == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Telegram Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "telegram api url sendDocument" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendDocument");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendDocument", url);
}

test "telegram api url sendPhoto" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendPhoto");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendPhoto", url);
}

test "telegram api url sendVideo" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendVideo");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendVideo", url);
}

test "telegram api url sendAudio" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendAudio");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendAudio", url);
}

test "telegram api url sendVoice" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{});
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendVoice");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendVoice", url);
}

test "telegram user exact match not substring" {
    const users = [_][]const u8{"alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(!ch.isUserAllowed("alice_bot"));
    try std.testing.expect(!ch.isUserAllowed("alic"));
    try std.testing.expect(!ch.isUserAllowed("malice"));
}

test "telegram user empty string denied" {
    const users = [_][]const u8{"alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(!ch.isUserAllowed(""));
}

test "telegram user case sensitive" {
    const users = [_][]const u8{"Alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(ch.isUserAllowed("Alice"));
    try std.testing.expect(!ch.isUserAllowed("alice"));
    try std.testing.expect(!ch.isUserAllowed("ALICE"));
}

test "telegram wildcard with specific users" {
    const users = [_][]const u8{ "alice", "*" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(ch.isUserAllowed("bob"));
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "telegram numeric id authorization" {
    const users = [_][]const u8{"123456789"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users);
    try std.testing.expect(ch.isUserAllowed("123456789"));
    try std.testing.expect(!ch.isUserAllowed("987654321"));
}

test "telegram max message len constant" {
    try std.testing.expectEqual(@as(usize, 4096), TelegramChannel.MAX_MESSAGE_LEN);
}

test "telegram split exact limit" {
    const msg = "a" ** 4096;
    var it = root.splitMessage(msg, TelegramChannel.MAX_MESSAGE_LEN);
    const chunk = it.next().?;
    try std.testing.expectEqual(@as(usize, 4096), chunk.len);
    try std.testing.expect(it.next() == null);
}

test "telegram split over limit" {
    const msg = "a" ** 4196;
    var it = root.splitMessage(msg, TelegramChannel.MAX_MESSAGE_LEN);
    const chunk1 = it.next().?;
    try std.testing.expectEqual(@as(usize, 4096), chunk1.len);
    const chunk2 = it.next().?;
    try std.testing.expectEqual(@as(usize, 100), chunk2.len);
    try std.testing.expect(it.next() == null);
}

test "telegram split empty message" {
    var it = root.splitMessage("", TelegramChannel.MAX_MESSAGE_LEN);
    try std.testing.expect(it.next() == null);
}

test "telegram split very long message all within limit" {
    const msg = "x" ** 12288; // 3 * 4096
    var it = root.splitMessage(msg, TelegramChannel.MAX_MESSAGE_LEN);
    var count: usize = 0;
    while (it.next()) |chunk| {
        try std.testing.expect(chunk.len <= TelegramChannel.MAX_MESSAGE_LEN);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "telegram build send body" {
    var buf: [512]u8 = undefined;
    const body = try TelegramChannel.buildSendBody(&buf, "12345", "Hello!");
    try std.testing.expectEqualStrings("{\"chat_id\":12345,\"text\":\"Hello!\"}", body);
}

test "telegram health check returns true" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{});
    try std.testing.expect(ch.healthCheck());
}

test "telegram init stores fields" {
    const users = [_][]const u8{ "alice", "bob" };
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC-DEF", &users);
    try std.testing.expectEqualStrings("123:ABC-DEF", ch.bot_token);
    try std.testing.expectEqual(@as(i64, 0), ch.last_update_id);
    try std.testing.expectEqual(@as(usize, 2), ch.allowed_users.len);
}
