const std = @import("std");
const root = @import("root.zig");

/// Matrix channel — uses the Client-Server API with long-polling /sync.
pub const MatrixChannel = struct {
    allocator: std.mem.Allocator,
    homeserver: []const u8,
    access_token: []const u8,
    room_id: []const u8,
    allowed_users: []const []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        homeserver: []const u8,
        access_token: []const u8,
        room_id: []const u8,
        allowed_users: []const []const u8,
    ) MatrixChannel {
        // Strip trailing slash from homeserver
        const hs = if (homeserver.len > 0 and homeserver[homeserver.len - 1] == '/')
            homeserver[0 .. homeserver.len - 1]
        else
            homeserver;

        return .{
            .allocator = allocator,
            .homeserver = hs,
            .access_token = access_token,
            .room_id = room_id,
            .allowed_users = allowed_users,
        };
    }

    pub fn channelName(_: *MatrixChannel) []const u8 {
        return "matrix";
    }

    pub fn isUserAllowed(self: *const MatrixChannel, sender: []const u8) bool {
        return root.isAllowed(self.allowed_users, sender);
    }

    pub fn healthCheck(_: *MatrixChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to the configured Matrix room via PUT /_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}.
    pub fn sendMessage(self: *MatrixChannel, text: []const u8) !void {
        // Build URL with unique transaction ID
        var url_buf: [1024]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        const txn_id = @as(u64, @intCast(@as(u128, @intCast(std.time.nanoTimestamp())) / 1_000_000));
        try url_fbs.writer().print("{s}/_matrix/client/v3/rooms/{s}/send/m.room.message/yc_{d}", .{ self.homeserver, self.room_id, txn_id });
        const url = url_fbs.getWritten();

        // Build JSON body: {"msgtype":"m.text","body":"..."}
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"msgtype\":\"m.text\",\"body\":\"");
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

        // Build auth header: "Bearer <access_token>"
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{self.access_token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .PUT,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.MatrixApiError;

        if (result.status != .ok) {
            return error.MatrixApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, _: []const u8, message: []const u8) anyerror!void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *MatrixChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "matrix channel name" {
    var ch = MatrixChannel.init(std.testing.allocator, "https://matrix.org", "tok", "!room:m", &.{});
    try std.testing.expectEqualStrings("matrix", ch.channelName());
}

test "matrix strips trailing slash" {
    const ch = MatrixChannel.init(std.testing.allocator, "https://matrix.org/", "tok", "!r:m", &.{});
    try std.testing.expectEqualStrings("https://matrix.org", ch.homeserver);
}

test "matrix no trailing slash unchanged" {
    const ch = MatrixChannel.init(std.testing.allocator, "https://matrix.org", "tok", "!r:m", &.{});
    try std.testing.expectEqualStrings("https://matrix.org", ch.homeserver);
}

test "matrix wildcard allows anyone" {
    const users = [_][]const u8{"*"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(ch.isUserAllowed("@anyone:matrix.org"));
}

test "matrix specific user allowed" {
    const users = [_][]const u8{"@user:matrix.org"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(ch.isUserAllowed("@user:matrix.org"));
    try std.testing.expect(!ch.isUserAllowed("@stranger:matrix.org"));
}

test "matrix empty allowlist denies all" {
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &.{});
    try std.testing.expect(!ch.isUserAllowed("@anyone:matrix.org"));
}

test "matrix vtable interface" {
    var ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("matrix", iface.name());
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Matrix Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "matrix multiple trailing slashes strips one" {
    const ch = MatrixChannel.init(std.testing.allocator, "https://matrix.org//", "tok", "!r:m", &.{});
    // Zig implementation strips exactly one trailing slash
    try std.testing.expectEqualStrings("https://matrix.org/", ch.homeserver);
}

test "matrix creates with correct fields" {
    const users = [_][]const u8{"@user:matrix.org"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://matrix.org", "syt_test_token", "!room:matrix.org", &users);
    try std.testing.expectEqualStrings("https://matrix.org", ch.homeserver);
    try std.testing.expectEqualStrings("syt_test_token", ch.access_token);
    try std.testing.expectEqualStrings("!room:matrix.org", ch.room_id);
    try std.testing.expectEqual(@as(usize, 1), ch.allowed_users.len);
}

test "matrix user case insensitive" {
    const users = [_][]const u8{"@User:Matrix.org"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(ch.isUserAllowed("@user:matrix.org"));
    try std.testing.expect(ch.isUserAllowed("@USER:MATRIX.ORG"));
    try std.testing.expect(ch.isUserAllowed("@User:Matrix.org"));
}

test "matrix unknown user denied" {
    const users = [_][]const u8{"@user:matrix.org"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(!ch.isUserAllowed("@stranger:matrix.org"));
    try std.testing.expect(!ch.isUserAllowed("@evil:hacker.org"));
}

test "matrix wildcard allows hacker domains too" {
    const users = [_][]const u8{"*"};
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(ch.isUserAllowed("@hacker:evil.org"));
}

test "matrix health check returns true" {
    var ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &.{});
    try std.testing.expect(ch.healthCheck());
}

test "matrix empty homeserver" {
    const ch = MatrixChannel.init(std.testing.allocator, "", "tok", "!r:m", &.{});
    try std.testing.expectEqualStrings("", ch.homeserver);
}

test "matrix single slash homeserver" {
    const ch = MatrixChannel.init(std.testing.allocator, "/", "tok", "!r:m", &.{});
    try std.testing.expectEqualStrings("", ch.homeserver);
}

test "matrix multiple users allowed" {
    const users = [_][]const u8{ "@alice:matrix.org", "@bob:matrix.org" };
    const ch = MatrixChannel.init(std.testing.allocator, "https://m.org", "tok", "!r:m", &users);
    try std.testing.expect(ch.isUserAllowed("@alice:matrix.org"));
    try std.testing.expect(ch.isUserAllowed("@bob:matrix.org"));
    try std.testing.expect(!ch.isUserAllowed("@eve:matrix.org"));
}
