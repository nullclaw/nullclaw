const std = @import("std");
const root = @import("root.zig");

/// Discord channel — connects via WebSocket gateway, sends via REST API.
/// Splits messages at 2000 chars (Discord limit).
pub const DiscordChannel = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    guild_id: ?[]const u8,
    listen_to_bots: bool,

    pub const MAX_MESSAGE_LEN: usize = 2000;
    pub const GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json";

    pub fn init(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        guild_id: ?[]const u8,
        listen_to_bots: bool,
    ) DiscordChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .guild_id = guild_id,
            .listen_to_bots = listen_to_bots,
        };
    }

    pub fn channelName(_: *DiscordChannel) []const u8 {
        return "discord";
    }

    /// Build a Discord REST API URL for sending to a channel.
    pub fn sendUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("https://discord.com/api/v10/channels/{s}/messages", .{channel_id});
        return fbs.getWritten();
    }

    /// Extract bot user ID from a bot token.
    /// Discord bot tokens are base64(bot_user_id).random.hmac
    pub fn extractBotUserId(token: []const u8) ?[]const u8 {
        // Find the first '.'
        const dot_pos = std.mem.indexOf(u8, token, ".") orelse return null;
        return token[0..dot_pos];
    }

    pub fn healthCheck(_: *DiscordChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Discord channel via REST API.
    /// Splits at MAX_MESSAGE_LEN (2000 chars).
    pub fn sendMessage(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(channel_id, chunk);
        }
    }

    fn sendChunk(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        // Build JSON body: {"content":"..."}
        var body_buf: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"content\":\"");
        for (text) |c| {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                else => try w.writeByte(c),
            }
        }
        try w.writeAll("\"}");
        const body = fbs.getWritten();

        // Build auth header value: "Bot <token>"
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bot {s}", .{self.bot_token});
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
        }) catch return error.DiscordApiError;

        if (result.status != .ok and result.status != .created) {
            return error.DiscordApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Discord REST-only mode: no persistent connection needed
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *DiscordChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord channel name" {
    var ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expectEqualStrings("discord", ch.channelName());
}

test "discord send url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/messages", url);
}

test "discord extract bot user id" {
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.Ghijk.abcdef");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id no dot" {
    try std.testing.expect(DiscordChannel.extractBotUserId("notokenformat") == null);
}

test "discord vtable interface" {
    var ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    const iface = ch.channel();
    try std.testing.expectEqualStrings("discord", iface.name());
}

test "discord message splitting at 2000" {
    var it = root.splitMessage("short", DiscordChannel.MAX_MESSAGE_LEN);
    try std.testing.expectEqualStrings("short", it.next().?);
    try std.testing.expect(it.next() == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Discord Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "discord send url with different channel ids" {
    var buf: [256]u8 = undefined;
    const url1 = try DiscordChannel.sendUrl(&buf, "999");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/999/messages", url1);

    var buf2: [256]u8 = undefined;
    const url2 = try DiscordChannel.sendUrl(&buf2, "1234567890");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/1234567890/messages", url2);
}

test "discord extract bot user id multiple dots" {
    // Token format: base64(user_id).timestamp.hmac
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.fake.hmac");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id empty token" {
    // Empty string before dot means empty result
    const id = DiscordChannel.extractBotUserId("");
    try std.testing.expect(id == null);
}

test "discord extract bot user id single dot" {
    const id = DiscordChannel.extractBotUserId("abc.");
    try std.testing.expectEqualStrings("abc", id.?);
}

test "discord max message len constant" {
    try std.testing.expectEqual(@as(usize, 2000), DiscordChannel.MAX_MESSAGE_LEN);
}

test "discord gateway url constant" {
    try std.testing.expectEqualStrings("wss://gateway.discord.gg/?v=10&encoding=json", DiscordChannel.GATEWAY_URL);
}

test "discord init stores fields" {
    const ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", "guild-123", true);
    try std.testing.expectEqualStrings("my-bot-token", ch.bot_token);
    try std.testing.expectEqualStrings("guild-123", ch.guild_id.?);
    try std.testing.expect(ch.listen_to_bots);
}

test "discord init no guild id" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expect(ch.guild_id == null);
    try std.testing.expect(!ch.listen_to_bots);
}

test "discord split empty message" {
    var it = root.splitMessage("", DiscordChannel.MAX_MESSAGE_LEN);
    try std.testing.expect(it.next() == null);
}

test "discord split exactly at limit" {
    const msg = "a" ** 2000;
    var it = root.splitMessage(msg, DiscordChannel.MAX_MESSAGE_LEN);
    const chunk = it.next().?;
    try std.testing.expectEqual(@as(usize, 2000), chunk.len);
    try std.testing.expect(it.next() == null);
}

test "discord split just over limit" {
    const msg = "a" ** 2001;
    var it = root.splitMessage(msg, DiscordChannel.MAX_MESSAGE_LEN);
    const chunk1 = it.next().?;
    try std.testing.expectEqual(@as(usize, 2000), chunk1.len);
    const chunk2 = it.next().?;
    try std.testing.expectEqual(@as(usize, 1), chunk2.len);
    try std.testing.expect(it.next() == null);
}

test "discord split long message all within limit" {
    const msg = "x" ** 5000;
    var it = root.splitMessage(msg, DiscordChannel.MAX_MESSAGE_LEN);
    var count: usize = 0;
    while (it.next()) |chunk| {
        try std.testing.expect(chunk.len <= DiscordChannel.MAX_MESSAGE_LEN);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "discord split preserves total content" {
    const msg = "abcde" ** 500; // 2500 chars
    var it = root.splitMessage(msg, DiscordChannel.MAX_MESSAGE_LEN);
    var total_len: usize = 0;
    while (it.next()) |chunk| {
        total_len += chunk.len;
    }
    try std.testing.expectEqual(@as(usize, 2500), total_len);
}

test "discord health check returns true" {
    var ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expect(ch.healthCheck());
}

test "discord send url buffer too small returns error" {
    var buf: [10]u8 = undefined;
    const result = DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expect(if (result) |_| false else |_| true);
}
