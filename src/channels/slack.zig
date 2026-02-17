const std = @import("std");
const root = @import("root.zig");

/// Slack channel — polls conversations.history for new messages, sends via chat.postMessage.
pub const SlackChannel = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    app_token: ?[]const u8,
    channel_id: ?[]const u8,
    allowed_users: []const []const u8,
    last_ts: []const u8,

    pub const API_BASE = "https://slack.com/api";

    pub fn init(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        app_token: ?[]const u8,
        channel_id: ?[]const u8,
        allowed_users: []const []const u8,
    ) SlackChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .app_token = app_token,
            .channel_id = channel_id,
            .allowed_users = allowed_users,
            .last_ts = "0",
        };
    }

    pub fn channelName(_: *SlackChannel) []const u8 {
        return "slack";
    }

    pub fn isUserAllowed(self: *const SlackChannel, sender: []const u8) bool {
        return root.isAllowed(self.allowed_users, sender);
    }

    pub fn healthCheck(_: *SlackChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Slack channel via chat.postMessage API.
    pub fn sendMessage(self: *SlackChannel, target_channel: []const u8, text: []const u8) !void {
        const url = API_BASE ++ "/chat.postMessage";

        // Build JSON body
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"channel\":\"");
        try w.writeAll(target_channel);
        try w.writeAll("\",\"text\":\"");
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

        // Build auth header: "Bearer xoxb-..."
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{self.bot_token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.SlackApiError;

        if (result.status != .ok) {
            return error.SlackApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *SlackChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "slack channel name" {
    var ch = SlackChannel.init(std.testing.allocator, "xoxb-test", null, null, &.{});
    try std.testing.expectEqualStrings("slack", ch.channelName());
}

test "slack user allowed wildcard" {
    const users = [_][]const u8{"*"};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &users);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "slack user allowed specific" {
    const users = [_][]const u8{ "U12345", "U67890" };
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &users);
    try std.testing.expect(ch.isUserAllowed("U12345"));
    try std.testing.expect(!ch.isUserAllowed("U99999"));
}

test "slack user denied empty" {
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &.{});
    try std.testing.expect(!ch.isUserAllowed("anyone"));
}

test "slack vtable interface" {
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("slack", iface.name());
}
