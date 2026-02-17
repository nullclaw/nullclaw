const std = @import("std");
const root = @import("root.zig");

/// IRC channel over TLS.
/// Joins configured channels, forwards PRIVMSG messages.
pub const IrcChannel = struct {
    allocator: std.mem.Allocator,
    server: []const u8,
    port: u16,
    nickname: []const u8,
    username: []const u8,
    channels: []const []const u8,
    allowed_users: []const []const u8,
    server_password: ?[]const u8,
    nickserv_password: ?[]const u8,
    sasl_password: ?[]const u8,
    verify_tls: bool,
    stream: ?std.net.Stream = null,

    /// Max IRC line length (RFC 2812).
    pub const MAX_LINE_LEN: usize = 512;
    /// Reserved for :nick!user@host prefix.
    pub const SENDER_PREFIX_RESERVE: usize = 64;

    pub fn init(
        allocator: std.mem.Allocator,
        server: []const u8,
        port: u16,
        nickname: []const u8,
        username: ?[]const u8,
        channels: []const []const u8,
        allowed_users: []const []const u8,
        server_password: ?[]const u8,
        nickserv_password: ?[]const u8,
        sasl_password: ?[]const u8,
        verify_tls: bool,
    ) IrcChannel {
        return .{
            .allocator = allocator,
            .server = server,
            .port = port,
            .nickname = nickname,
            .username = username orelse nickname,
            .channels = channels,
            .allowed_users = allowed_users,
            .server_password = server_password,
            .nickserv_password = nickserv_password,
            .sasl_password = sasl_password,
            .verify_tls = verify_tls,
        };
    }

    pub fn channelName(_: *IrcChannel) []const u8 {
        return "irc";
    }

    pub fn isUserAllowed(self: *const IrcChannel, nick: []const u8) bool {
        return root.isAllowed(self.allowed_users, nick);
    }

    pub fn healthCheck(_: *IrcChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to an IRC channel/user via PRIVMSG.
    /// Splits long messages respecting IRC's 512-byte line limit.
    pub fn sendMessage(self: *IrcChannel, target: []const u8, message: []const u8) !void {
        const stream = self.stream orelse return error.IrcNotConnected;

        // Calculate max payload: 512 - prefix reserve - "PRIVMSG " - target - " :" - "\r\n"
        const overhead = SENDER_PREFIX_RESERVE + 10 + target.len + 2;
        const max_payload = if (MAX_LINE_LEN > overhead) MAX_LINE_LEN - overhead else 64;

        const chunks = try splitIrcMessage(self.allocator, message, max_payload);
        defer self.allocator.free(chunks);

        for (chunks) |chunk| {
            // Build: "PRIVMSG <target> :<chunk>\r\n"
            var line_buf: [MAX_LINE_LEN]u8 = undefined;
            var line_fbs = std.io.fixedBufferStream(&line_buf);
            const lw = line_fbs.writer();
            try lw.print("PRIVMSG {s} :{s}\r\n", .{ target, chunk });
            const line = line_fbs.getWritten();

            try stream.writeAll(line);
        }
    }

    /// Send a raw IRC line (used for NICK, USER, PASS, JOIN, PONG, etc.).
    pub fn sendRaw(self: *IrcChannel, line: []const u8) !void {
        const stream = self.stream orelse return error.IrcNotConnected;
        try stream.writeAll(line);
        try stream.writeAll("\r\n");
    }

    /// Connect to the IRC server via plain TCP.
    pub fn connect(self: *IrcChannel) !void {
        const addr = try std.net.Address.resolveIp(self.server, self.port);
        self.stream = try std.net.tcpConnectToAddress(addr);
    }

    /// Disconnect from the IRC server.
    pub fn disconnect(self: *IrcChannel) void {
        if (self.stream) |stream| {
            // Try to send QUIT gracefully
            stream.writeAll("QUIT :nullclaw shutting down\r\n") catch {};
            stream.close();
            self.stream = null;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        try self.connect();

        // Send PASS if configured
        if (self.server_password) |pass| {
            var pass_buf: [MAX_LINE_LEN]u8 = undefined;
            var pass_fbs = std.io.fixedBufferStream(&pass_buf);
            try pass_fbs.writer().print("PASS {s}", .{pass});
            try self.sendRaw(pass_fbs.getWritten());
        }

        // Send NICK and USER
        var nick_buf: [MAX_LINE_LEN]u8 = undefined;
        var nick_fbs = std.io.fixedBufferStream(&nick_buf);
        try nick_fbs.writer().print("NICK {s}", .{self.nickname});
        try self.sendRaw(nick_fbs.getWritten());

        var user_buf: [MAX_LINE_LEN]u8 = undefined;
        var user_fbs = std.io.fixedBufferStream(&user_buf);
        try user_fbs.writer().print("USER {s} 0 * :{s}", .{ self.username, self.nickname });
        try self.sendRaw(user_fbs.getWritten());

        // Join configured channels
        for (self.channels) |ch| {
            var join_buf: [MAX_LINE_LEN]u8 = undefined;
            var join_fbs = std.io.fixedBufferStream(&join_buf);
            try join_fbs.writer().print("JOIN {s}", .{ch});
            try self.sendRaw(join_fbs.getWritten());
        }
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        self.disconnect();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *IrcChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// IRC Message Parsing
// ════════════════════════════════════════════════════════════════════════════

/// A parsed IRC message.
pub const IrcMessage = struct {
    prefix: ?[]const u8,
    command: []const u8,
    params: []const []const u8,

    /// Parse a raw IRC line.
    /// IRC format: [:<prefix>] <command> [<params>] [:<trailing>]
    /// Returns null for empty/unparseable lines.
    /// NOTE: returned slices point into `line`; caller must not free `line` while using them.
    pub fn parse(allocator: std.mem.Allocator, line: []const u8) !?IrcMessage {
        var trimmed = std.mem.trim(u8, line, "\r\n");
        if (trimmed.len == 0) return null;

        // Extract prefix
        var prefix: ?[]const u8 = null;
        if (trimmed[0] == ':') {
            const space = std.mem.indexOf(u8, trimmed, " ") orelse return null;
            prefix = trimmed[1..space];
            trimmed = trimmed[space + 1 ..];
        }

        // Split at trailing (:)
        var trailing: ?[]const u8 = null;
        var params_part = trimmed;
        if (std.mem.indexOf(u8, trimmed, " :")) |colon_pos| {
            params_part = trimmed[0..colon_pos];
            trailing = trimmed[colon_pos + 2 ..];
        }

        // Split remaining into command + params
        var param_list: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer param_list.deinit(allocator);

        var it = std.mem.splitScalar(u8, params_part, ' ');
        const command = it.next() orelse return null;

        while (it.next()) |p| {
            if (p.len > 0) try param_list.append(allocator, p);
        }
        if (trailing) |t| {
            try param_list.append(allocator, t);
        }

        return IrcMessage{
            .prefix = prefix,
            .command = command,
            .params = try param_list.toOwnedSlice(allocator),
        };
    }

    pub fn deinit(self: *const IrcMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.params);
    }

    /// Extract nickname from prefix (nick!user@host -> nick).
    pub fn nick(self: *const IrcMessage) ?[]const u8 {
        const p = self.prefix orelse return null;
        const end = std.mem.indexOf(u8, p, "!") orelse p.len;
        if (end == 0) return null;
        return p[0..end];
    }
};

/// Encode SASL PLAIN credentials: base64(\0nick\0password).
pub fn encodeSaslPlain(buf: []u8, nickname: []const u8, password: []const u8) []const u8 {
    // Build the payload: \0nick\0password
    var payload_buf: [256]u8 = undefined;
    const payload_len = 1 + nickname.len + 1 + password.len;
    if (payload_len > payload_buf.len) return "";
    payload_buf[0] = 0;
    @memcpy(payload_buf[1..][0..nickname.len], nickname);
    payload_buf[1 + nickname.len] = 0;
    @memcpy(payload_buf[2 + nickname.len ..][0..password.len], password);
    const payload = payload_buf[0..payload_len];

    return std.base64.standard.Encoder.encode(buf, payload);
}

/// Split a message for IRC transmission (newlines become separate lines, long lines split).
pub fn splitIrcMessage(allocator: std.mem.Allocator, message: []const u8, max_bytes: usize) ![][]const u8 {
    var chunks: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer chunks.deinit(allocator);

    if (max_bytes == 0) {
        try chunks.append(allocator, message);
        return chunks.toOwnedSlice(allocator);
    }

    var line_it = std.mem.splitScalar(u8, message, '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) continue;

        if (line.len <= max_bytes) {
            try chunks.append(allocator, line);
            continue;
        }

        // Split long line at UTF-8 boundaries
        var it = root.splitMessage(line, max_bytes);
        while (it.next()) |chunk| {
            try chunks.append(allocator, chunk);
        }
    }

    if (chunks.items.len == 0) {
        try chunks.append(allocator, "");
    }

    return chunks.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "irc channel name" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expectEqualStrings("irc", ch.channelName());
}

test "irc default username to nickname" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "mybot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expectEqualStrings("mybot", ch.username);
}

test "irc explicit username" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "mybot", "customuser", &.{}, &.{}, null, null, null, true);
    try std.testing.expectEqualStrings("customuser", ch.username);
    try std.testing.expectEqualStrings("mybot", ch.nickname);
}

test "irc wildcard allows anyone" {
    const users = [_][]const u8{"*"};
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &users, null, null, null, true);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "irc specific user allowed case insensitive" {
    const users = [_][]const u8{ "alice", "bob" };
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &users, null, null, null, true);
    try std.testing.expect(ch.isUserAllowed("Alice"));
    try std.testing.expect(ch.isUserAllowed("bob"));
    try std.testing.expect(!ch.isUserAllowed("eve"));
}

test "irc empty allowlist denies all" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expect(!ch.isUserAllowed("anyone"));
}

test "irc parse privmsg" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":nick!user@host PRIVMSG #channel :Hello world")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("nick!user@host", msg.prefix.?);
    try std.testing.expectEqualStrings("PRIVMSG", msg.command);
    try std.testing.expectEqual(@as(usize, 2), msg.params.len);
    try std.testing.expectEqualStrings("#channel", msg.params[0]);
    try std.testing.expectEqualStrings("Hello world", msg.params[1]);
}

test "irc parse ping" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, "PING :server.example.com")).?;
    defer msg.deinit(allocator);
    try std.testing.expect(msg.prefix == null);
    try std.testing.expectEqualStrings("PING", msg.command);
    try std.testing.expectEqualStrings("server.example.com", msg.params[0]);
}

test "irc parse empty returns null" {
    const allocator = std.testing.allocator;
    try std.testing.expect(try IrcMessage.parse(allocator, "") == null);
    try std.testing.expect(try IrcMessage.parse(allocator, "\r\n") == null);
}

test "irc nick extraction" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":nick!user@host PRIVMSG #ch :msg")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("nick", msg.nick().?);
}

test "irc nick no prefix" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, "PING :token")).?;
    defer msg.deinit(allocator);
    try std.testing.expect(msg.nick() == null);
}

test "irc sasl encode" {
    var buf: [256]u8 = undefined;
    const encoded = encodeSaslPlain(&buf, "jilles", "sesame");
    try std.testing.expectEqualStrings("AGppbGxlcwBzZXNhbWU=", encoded);
}

test "irc split short message" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "hello", 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqualStrings("hello", chunks[0]);
}

test "irc split newlines" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "line one\nline two\nline three", 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 3), chunks.len);
    try std.testing.expectEqualStrings("line one", chunks[0]);
    try std.testing.expectEqualStrings("line two", chunks[1]);
    try std.testing.expectEqualStrings("line three", chunks[2]);
}

test "irc split skips empty lines" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "hello\n\n\nworld", 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqualStrings("hello", chunks[0]);
    try std.testing.expectEqualStrings("world", chunks[1]);
}

test "irc vtable interface" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    const iface = ch.channel();
    try std.testing.expectEqualStrings("irc", iface.name());
}

// ════════════════════════════════════════════════════════════════════════════
// Additional IRC Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "irc parse privmsg dm" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":alice!a@host PRIVMSG botname :hi there")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("PRIVMSG", msg.command);
    try std.testing.expectEqual(@as(usize, 2), msg.params.len);
    try std.testing.expectEqualStrings("botname", msg.params[0]);
    try std.testing.expectEqualStrings("hi there", msg.params[1]);
    try std.testing.expectEqualStrings("alice", msg.nick().?);
}

test "irc parse numeric reply" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":server 001 botname :Welcome to the IRC network")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("server", msg.prefix.?);
    try std.testing.expectEqualStrings("001", msg.command);
    try std.testing.expectEqual(@as(usize, 2), msg.params.len);
    try std.testing.expectEqualStrings("botname", msg.params[0]);
    try std.testing.expectEqualStrings("Welcome to the IRC network", msg.params[1]);
}

test "irc parse no trailing" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":server 433 * botname")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("433", msg.command);
    try std.testing.expectEqual(@as(usize, 2), msg.params.len);
    try std.testing.expectEqualStrings("*", msg.params[0]);
    try std.testing.expectEqualStrings("botname", msg.params[1]);
}

test "irc parse cap ack" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":server CAP * ACK :sasl")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("CAP", msg.command);
    try std.testing.expectEqual(@as(usize, 3), msg.params.len);
    try std.testing.expectEqualStrings("*", msg.params[0]);
    try std.testing.expectEqualStrings("ACK", msg.params[1]);
    try std.testing.expectEqualStrings("sasl", msg.params[2]);
}

test "irc parse strips crlf" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, "PING :test\r\n")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("test", msg.params[0]);
}

test "irc parse authenticate plus" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, "AUTHENTICATE +")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("AUTHENTICATE", msg.command);
    try std.testing.expectEqual(@as(usize, 1), msg.params.len);
    try std.testing.expectEqualStrings("+", msg.params[0]);
}

test "irc nick extraction nick only prefix" {
    const allocator = std.testing.allocator;
    const msg = (try IrcMessage.parse(allocator, ":server 001 bot :Welcome")).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("server", msg.nick().?);
}

test "irc sasl empty password" {
    var buf: [256]u8 = undefined;
    const encoded = encodeSaslPlain(&buf, "nick", "");
    try std.testing.expectEqualStrings("AG5pY2sA", encoded);
}

test "irc split crlf newlines" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "hello\r\nworld", 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqualStrings("hello", chunks[0]);
    try std.testing.expectEqualStrings("world", chunks[1]);
}

test "irc split trailing newline" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "hello\n", 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqualStrings("hello", chunks[0]);
}

test "irc split multiline with long line" {
    const allocator = std.testing.allocator;
    const long = "a" ** 800;
    const msg = "short\n" ++ long ++ "\nend";
    const chunks = try splitIrcMessage(allocator, msg, 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 4), chunks.len);
    try std.testing.expectEqualStrings("short", chunks[0]);
    try std.testing.expectEqual(@as(usize, 400), chunks[1].len);
    try std.testing.expectEqual(@as(usize, 400), chunks[2].len);
    try std.testing.expectEqualStrings("end", chunks[3]);
}

test "irc split only newlines" {
    const allocator = std.testing.allocator;
    const chunks = try splitIrcMessage(allocator, "\n\n\n", 400);
    defer allocator.free(chunks);
    // splitIrcMessage returns [""] for empty-only content
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqualStrings("", chunks[0]);
}

test "irc stores all fields" {
    const users = [_][]const u8{"alice"};
    const chans = [_][]const u8{"#test"};
    const ch = IrcChannel.init(
        std.testing.allocator,
        "irc.example.com",
        6697,
        "zcbot",
        "zeroclaw",
        &chans,
        &users,
        "serverpass",
        "nspass",
        "saslpass",
        false,
    );
    try std.testing.expectEqualStrings("irc.example.com", ch.server);
    try std.testing.expectEqual(@as(u16, 6697), ch.port);
    try std.testing.expectEqualStrings("zcbot", ch.nickname);
    try std.testing.expectEqualStrings("zeroclaw", ch.username);
    try std.testing.expectEqual(@as(usize, 1), ch.channels.len);
    try std.testing.expectEqualStrings("#test", ch.channels[0]);
    try std.testing.expectEqual(@as(usize, 1), ch.allowed_users.len);
    try std.testing.expectEqualStrings("serverpass", ch.server_password.?);
    try std.testing.expectEqualStrings("nspass", ch.nickserv_password.?);
    try std.testing.expectEqualStrings("saslpass", ch.sasl_password.?);
    try std.testing.expect(!ch.verify_tls);
}

test "irc max line len constant" {
    try std.testing.expectEqual(@as(usize, 512), IrcChannel.MAX_LINE_LEN);
}

test "irc sender prefix reserve constant" {
    try std.testing.expectEqual(@as(usize, 64), IrcChannel.SENDER_PREFIX_RESERVE);
}

test "irc health check returns true" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expect(ch.healthCheck());
}

test "irc split long exact boundary" {
    const allocator = std.testing.allocator;
    const msg = "a" ** 400;
    const chunks = try splitIrcMessage(allocator, msg, 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
}

test "irc split long message" {
    const allocator = std.testing.allocator;
    const msg = "a" ** 800;
    const chunks = try splitIrcMessage(allocator, msg, 400);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqual(@as(usize, 400), chunks[0].len);
    try std.testing.expectEqual(@as(usize, 400), chunks[1].len);
}
