const std = @import("std");
const root = @import("root.zig");

/// DingTalk channel — connects via Stream Mode WebSocket for real-time messages.
/// Replies are sent through per-message session webhook URLs.
pub const DingTalkChannel = struct {
    allocator: std.mem.Allocator,
    client_id: []const u8,
    client_secret: []const u8,
    allowed_users: []const []const u8,

    pub const GATEWAY_URL = "https://api.dingtalk.com/v1.0/gateway/connections/open";

    pub fn init(
        allocator: std.mem.Allocator,
        client_id: []const u8,
        client_secret: []const u8,
        allowed_users: []const []const u8,
    ) DingTalkChannel {
        return .{
            .allocator = allocator,
            .client_id = client_id,
            .client_secret = client_secret,
            .allowed_users = allowed_users,
        };
    }

    pub fn channelName(_: *DingTalkChannel) []const u8 {
        return "dingtalk";
    }

    pub fn isUserAllowed(self: *const DingTalkChannel, user_id: []const u8) bool {
        return root.isAllowedExact(self.allowed_users, user_id);
    }

    pub fn healthCheck(_: *DingTalkChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message via DingTalk session webhook URL.
    /// The target is expected to be the per-session webhook URL provided by the DingTalk Stream API.
    pub fn sendMessage(self: *DingTalkChannel, webhook_url: []const u8, text: []const u8) !void {
        // Build JSON body: {"msgtype":"markdown","markdown":{"title":"nullclaw","text":"..."}}
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"msgtype\":\"markdown\",\"markdown\":{\"title\":\"nullclaw\",\"text\":\"");
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

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = webhook_url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        }) catch return error.DingTalkApiError;

        if (result.status != .ok) {
            return error.DingTalkApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // DingTalk: full implementation would connect via Stream Mode WebSocket.
        // Messages arrive with per-session webhook URLs for replies.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *DingTalkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "dingtalk channel name" {
    var ch = DingTalkChannel.init(std.testing.allocator, "id", "secret", &.{});
    try std.testing.expectEqualStrings("dingtalk", ch.channelName());
}

test "dingtalk user allowed wildcard" {
    const users = [_][]const u8{"*"};
    const ch = DingTalkChannel.init(std.testing.allocator, "id", "secret", &users);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "dingtalk user allowed specific" {
    const users = [_][]const u8{"user123"};
    const ch = DingTalkChannel.init(std.testing.allocator, "id", "secret", &users);
    try std.testing.expect(ch.isUserAllowed("user123"));
    try std.testing.expect(!ch.isUserAllowed("other"));
}

test "dingtalk user denied empty" {
    const ch = DingTalkChannel.init(std.testing.allocator, "id", "secret", &.{});
    try std.testing.expect(!ch.isUserAllowed("anyone"));
}

test "dingtalk vtable interface" {
    var ch = DingTalkChannel.init(std.testing.allocator, "id", "secret", &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("dingtalk", iface.name());
}
