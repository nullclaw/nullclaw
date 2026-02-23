const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus_mod = @import("../bus.zig");

const log = std.log.scoped(.irc);

/// IRC style prefix prepended to messages before they reach the LLM.
const IRC_STYLE_PREFIX =
    "[context: you are responding over IRC. " ++
    "Plain text only. No markdown, no tables, no XML/HTML tags. " ++
    "Never use triple backtick code fences. Use a single blank line to separate blocks instead. " ++
    "Be terse and concise. " ++
    "Use short lines. Avoid walls of text.]\n";

/// Max nick collision retries before giving up.
const MAX_NICK_RETRIES: usize = 5;

/// IRC service bot names to filter out.
const SERVICE_BOTS = [_][]const u8{ "NickServ", "ChanServ", "BotServ", "MemoServ" };

/// IRC channel with optional TLS support.
/// Joins configured channels, forwards PRIVMSG messages.
pub const IrcChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    host: []const u8,
    port: u16,
    nick: []const u8,
    username: []const u8,
    channels: []const []const u8,
    allow_from: []const []const u8,
    server_password: ?[]const u8,
    nickserv_password: ?[]const u8,
    sasl_password: ?[]const u8,
    tls: bool = true,
    use_tls: bool = false,
    stream: ?std.net.Stream = null,
    tls_state: ?*TlsState = null,
    bus: ?*bus_mod.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    reader_thread: ?std.Thread = null,
    write_mu: std.Thread.Mutex = .{},

    /// Heap-allocated TLS state that wraps a TCP stream with encryption.
    /// Must be heap-allocated so that pointers remain stable for the TLS client.
    pub const TlsState = struct {
        stream_reader: std.net.Stream.Reader,
        stream_writer: std.net.Stream.Writer,
        tls_client: std.crypto.tls.Client,
        /// Backing buffers owned by the allocator.
        read_buf: []u8,
        write_buf: []u8,
        tls_read_buf: []u8,
        tls_write_buf: []u8,

        pub fn deinit(self: *TlsState, allocator: std.mem.Allocator) void {
            allocator.free(self.read_buf);
            allocator.free(self.write_buf);
            allocator.free(self.tls_read_buf);
            allocator.free(self.tls_write_buf);
            allocator.destroy(self);
        }
    };

    /// Max IRC line length (RFC 2812).
    pub const MAX_LINE_LEN: usize = 512;
    /// Reserved for :nick!user@host prefix.
    pub const SENDER_PREFIX_RESERVE: usize = 64;

    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        nick_param: []const u8,
        username: ?[]const u8,
        channels: []const []const u8,
        allow_from: []const []const u8,
        server_password: ?[]const u8,
        nickserv_password: ?[]const u8,
        sasl_password: ?[]const u8,
        tls_verify: bool,
    ) IrcChannel {
        return .{
            .allocator = allocator,
            .host = host,
            .port = port,
            .nick = nick_param,
            .username = username orelse nick_param,
            .channels = channels,
            .allow_from = allow_from,
            .server_password = server_password,
            .nickserv_password = nickserv_password,
            .sasl_password = sasl_password,
            .tls = tls_verify,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.IrcConfig) IrcChannel {
        var ch = init(
            allocator,
            cfg.host,
            cfg.port,
            cfg.nick,
            cfg.username,
            cfg.channels,
            cfg.allow_from,
            cfg.server_password,
            cfg.nickserv_password,
            cfg.sasl_password,
            cfg.tls,
        );
        ch.account_id = cfg.account_id;
        return ch;
    }

    pub fn channelName(_: *IrcChannel) []const u8 {
        return "irc";
    }

    pub fn isUserAllowed(self: *const IrcChannel, nick: []const u8) bool {
        return root.isAllowed(self.allow_from, nick);
    }

    pub fn setBus(self: *IrcChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn healthCheck(self: *IrcChannel) bool {
        return self.running.load(.acquire) and self.stream != null;
    }

    /// Check if a sender nick belongs to an IRC service bot.
    pub fn isServiceBot(sender_nick: []const u8) bool {
        for (&SERVICE_BOTS) |bot| {
            if (std.ascii.eqlIgnoreCase(bot, sender_nick)) return true;
        }
        return false;
    }

    /// Determine reply target: channel messages reply to the channel,
    /// DMs (target == bot nick) reply to the sender.
    pub fn replyTarget(target: []const u8, sender_nick: []const u8) []const u8 {
        const is_channel = target.len > 0 and (target[0] == '#' or target[0] == '&');
        return if (is_channel) target else sender_nick;
    }

    /// Append '_' to nick for collision handling. Returns new nick or error.
    pub fn handleNickCollision(allocator: std.mem.Allocator, current_nick: []const u8, retries: usize) ![]const u8 {
        if (retries >= MAX_NICK_RETRIES) return error.NickCollisionLimitReached;
        const new_nick = try allocator.alloc(u8, current_nick.len + 1);
        @memcpy(new_nick[0..current_nick.len], current_nick);
        new_nick[current_nick.len] = '_';
        return new_nick;
    }

    /// Perform SASL PLAIN negotiation. Encodes credentials and returns the
    /// AUTHENTICATE line payload (base64-encoded "\0nick\0password").
    pub fn buildSaslPayload(buf: []u8, nick: []const u8, password: []const u8) []const u8 {
        return encodeSaslPlain(buf, nick, password);
    }

    // ── I/O helpers ──────────────────────────────────────────────────

    /// Write bytes through TLS or plain TCP depending on connection mode.
    /// Abstracts away the write path so callers do not need to check use_tls.
    pub fn ircWriteAll(self: *IrcChannel, data: []const u8) !void {
        self.write_mu.lock();
        defer self.write_mu.unlock();

        if (self.tls_state) |tls| {
            try tls.tls_client.writer.writeAll(data);
            try tls.tls_client.writer.flush();
            // Flush the underlying stream writer to push ciphertext to the socket
            try tls.stream_writer.interface.flush();
        } else if (self.stream) |stream| {
            try stream.writeAll(data);
        } else {
            return error.IrcNotConnected;
        }
    }

    fn readFromConnection(self: *IrcChannel, out: []u8) !usize {
        if (self.tls_state) |tls| {
            var rd: [1][]u8 = .{out};
            return tls.tls_client.reader.readVec(&rd) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => err,
            };
        }
        if (self.stream) |stream| {
            return stream.read(out);
        }
        return error.IrcNotConnected;
    }

    fn handleInboundLine(self: *IrcChannel, line: []const u8) !void {
        const parsed = (try IrcMessage.parse(self.allocator, line)) orelse return;
        defer parsed.deinit(self.allocator);

        if (std.ascii.eqlIgnoreCase(parsed.command, "PING")) {
            if (parsed.params.len == 0) return;
            var pong_buf: [MAX_LINE_LEN]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&pong_buf);
            try fbs.writer().print("PONG :{s}", .{parsed.params[parsed.params.len - 1]});
            try self.sendRaw(fbs.getWritten());
            return;
        }

        if (!std.ascii.eqlIgnoreCase(parsed.command, "PRIVMSG")) return;
        if (parsed.params.len < 2) return;

        const sender_nick = parsed.nick() orelse return;
        if (IrcChannel.isServiceBot(sender_nick)) return;
        if (self.allow_from.len > 0 and !self.isUserAllowed(sender_nick)) return;

        const target = parsed.params[0];
        const text = std.mem.trim(u8, parsed.params[parsed.params.len - 1], " \t\r\n");
        if (text.len == 0) return;

        const is_channel = target.len > 0 and (target[0] == '#' or target[0] == '&');
        const chat_id = if (is_channel) target else sender_nick;
        const session_key = if (is_channel)
            try std.fmt.allocPrint(self.allocator, "irc:{s}:group:{s}", .{ self.account_id, chat_id })
        else
            try std.fmt.allocPrint(self.allocator, "irc:{s}:direct:{s}", .{ self.account_id, sender_nick });
        defer self.allocator.free(session_key);

        var content_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer content_buf.deinit(self.allocator);
        try content_buf.appendSlice(self.allocator, IRC_STYLE_PREFIX);
        if (is_channel) {
            try content_buf.appendSlice(self.allocator, sender_nick);
            try content_buf.appendSlice(self.allocator, ": ");
        }
        try content_buf.appendSlice(self.allocator, text);
        const content = try content_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(content);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(self.allocator);
        const mw = metadata_buf.writer(self.allocator);
        try mw.writeByte('{');
        try mw.writeAll("\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        try mw.writeAll(",\"is_dm\":");
        try mw.writeAll(if (is_channel) "false" else "true");
        try mw.writeAll(",\"is_group\":");
        try mw.writeAll(if (is_channel) "true" else "false");
        if (is_channel) {
            try mw.writeAll(",\"channel_id\":");
            try root.appendJsonStringW(mw, chat_id);
        }
        try mw.writeByte('}');

        const msg = try bus_mod.makeInboundFull(
            self.allocator,
            "irc",
            sender_nick,
            chat_id,
            content,
            session_key,
            &.{},
            metadata_buf.items,
        );
        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("IRC publishInbound failed: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            msg.deinit(self.allocator);
        }
    }

    fn readerLoop(self: *IrcChannel) void {
        var recv_buf: [4096]u8 = undefined;
        var pending: std.ArrayListUnmanaged(u8) = .empty;
        defer pending.deinit(self.allocator);

        while (self.running.load(.acquire)) {
            const n = self.readFromConnection(&recv_buf) catch |err| {
                if (self.running.load(.acquire)) {
                    log.warn("IRC read error: {}", .{err});
                }
                break;
            };
            if (n == 0) break;

            pending.appendSlice(self.allocator, recv_buf[0..n]) catch {
                log.err("IRC pending buffer OOM", .{});
                break;
            };

            while (std.mem.indexOfScalar(u8, pending.items, '\n')) |idx| {
                const line = pending.items[0 .. idx + 1];
                self.handleInboundLine(line) catch |err| {
                    log.warn("IRC inbound parse failed: {}", .{err});
                };

                const rem_start = idx + 1;
                const rem_len = pending.items.len - rem_start;
                if (rem_len > 0) {
                    std.mem.copyForwards(u8, pending.items[0..rem_len], pending.items[rem_start..]);
                }
                pending.items = pending.items[0..rem_len];
            }
        }

        self.running.store(false, .release);
        self.disconnect();
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to an IRC channel/user via PRIVMSG.
    /// Splits long messages respecting IRC's 512-byte line limit.
    pub fn sendMessage(self: *IrcChannel, target: []const u8, message: []const u8) !void {
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

            try self.ircWriteAll(line);
        }
    }

    /// Send a raw IRC line (used for NICK, USER, PASS, JOIN, PONG, etc.).
    pub fn sendRaw(self: *IrcChannel, line: []const u8) !void {
        try self.ircWriteAll(line);
        try self.ircWriteAll("\r\n");
    }

    /// Connect to the IRC server via TCP.
    /// When use_tls is true, wraps the TCP stream with std.crypto.tls.Client
    /// for TLS encryption. Otherwise connects via plain TCP.
    pub fn connect(self: *IrcChannel) !void {
        const addr = try std.net.Address.resolveIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(addr);
        self.stream = stream;

        if (self.use_tls) {
            try self.initTls(stream);
        }
    }

    /// Initialize TLS over an existing TCP stream.
    fn initTls(self: *IrcChannel, stream: std.net.Stream) !void {
        const tls_buf_len = std.crypto.tls.Client.min_buffer_len;

        // Allocate buffers for stream and TLS I/O
        const read_buf = try self.allocator.alloc(u8, tls_buf_len);
        errdefer self.allocator.free(read_buf);
        const write_buf = try self.allocator.alloc(u8, tls_buf_len);
        errdefer self.allocator.free(write_buf);
        const tls_read_buf = try self.allocator.alloc(u8, tls_buf_len);
        errdefer self.allocator.free(tls_read_buf);
        const tls_write_buf = try self.allocator.alloc(u8, tls_buf_len);
        errdefer self.allocator.free(tls_write_buf);

        // Heap-allocate TlsState so pointers remain stable
        const tls = try self.allocator.create(TlsState);
        errdefer self.allocator.destroy(tls);

        tls.read_buf = read_buf;
        tls.write_buf = write_buf;
        tls.tls_read_buf = tls_read_buf;
        tls.tls_write_buf = tls_write_buf;
        tls.stream_reader = stream.reader(read_buf);
        tls.stream_writer = stream.writer(write_buf);

        tls.tls_client = std.crypto.tls.Client.init(
            tls.stream_reader.interface(),
            &tls.stream_writer.interface,
            .{
                .host = if (self.tls) .{ .explicit = self.host } else .no_verification,
                .ca = .no_verification,
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .allow_truncation_attacks = true,
            },
        ) catch return error.TlsInitializationFailed;

        self.tls_state = tls;
    }

    /// Disconnect from the IRC server.
    pub fn disconnect(self: *IrcChannel) void {
        // Clean up TLS state first
        if (self.tls_state) |tls| {
            // Send TLS close_notify
            tls.tls_client.end() catch |err| log.err("TLS close_notify failed: {}", .{err});
            tls.deinit(self.allocator);
            self.tls_state = null;
        }

        if (self.stream) |stream| {
            // Try to send QUIT gracefully (only for plain TCP; TLS already sent close_notify)
            if (self.tls_state == null) {
                stream.writeAll("QUIT :nullclaw shutting down\r\n") catch |err| log.err("QUIT send failed: {}", .{err});
            }
            stream.close();
            self.stream = null;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);
        errdefer self.running.store(false, .release);
        errdefer self.disconnect();
        try self.connect();

        // SASL: request capability before registration
        if (self.sasl_password != null) {
            try self.sendRaw("CAP REQ :sasl");
        }

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
        try nick_fbs.writer().print("NICK {s}", .{self.nick});
        try self.sendRaw(nick_fbs.getWritten());

        var user_buf: [MAX_LINE_LEN]u8 = undefined;
        var user_fbs = std.io.fixedBufferStream(&user_buf);
        try user_fbs.writer().print("USER {s} 0 * :{s}", .{ self.username, self.nick });
        try self.sendRaw(user_fbs.getWritten());

        // Join configured channels
        for (self.channels) |ch| {
            var join_buf: [MAX_LINE_LEN]u8 = undefined;
            var join_fbs = std.io.fixedBufferStream(&join_buf);
            try join_fbs.writer().print("JOIN {s}", .{ch});
            try self.sendRaw(join_fbs.getWritten());
        }

        self.reader_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, readerLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *IrcChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.disconnect();
        if (self.reader_thread) |t| {
            t.join();
            self.reader_thread = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
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

test "irc default username to nickname" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "mybot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expectEqualStrings("mybot", ch.username);
}

test "irc explicit username" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "mybot", "customuser", &.{}, &.{}, null, null, null, true);
    try std.testing.expectEqualStrings("customuser", ch.username);
    try std.testing.expectEqualStrings("mybot", ch.nick);
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
    try std.testing.expectEqualStrings("irc.example.com", ch.host);
    try std.testing.expectEqual(@as(u16, 6697), ch.port);
    try std.testing.expectEqualStrings("zcbot", ch.nick);
    try std.testing.expectEqualStrings("zeroclaw", ch.username);
    try std.testing.expectEqual(@as(usize, 1), ch.channels.len);
    try std.testing.expectEqualStrings("#test", ch.channels[0]);
    try std.testing.expectEqual(@as(usize, 1), ch.allow_from.len);
    try std.testing.expectEqualStrings("serverpass", ch.server_password.?);
    try std.testing.expectEqualStrings("nspass", ch.nickserv_password.?);
    try std.testing.expectEqualStrings("saslpass", ch.sasl_password.?);
    try std.testing.expect(!ch.tls);
    // use_tls defaults to false
    try std.testing.expect(!ch.use_tls);
}

test "irc max line len constant" {
    try std.testing.expectEqual(@as(usize, 512), IrcChannel.MAX_LINE_LEN);
}

test "irc sender prefix reserve constant" {
    try std.testing.expectEqual(@as(usize, 64), IrcChannel.SENDER_PREFIX_RESERVE);
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

// ════════════════════════════════════════════════════════════════════════════
// TLS, SASL, Nick Collision, Service Filtering, DM Routing Tests
// ════════════════════════════════════════════════════════════════════════════

test "irc use_tls defaults to false" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expect(!ch.use_tls);
}

test "irc sasl negotiation base64 encoding correct" {
    var buf: [256]u8 = undefined;
    // SASL PLAIN format: \0nick\0password
    const encoded = IrcChannel.buildSaslPayload(&buf, "testbot", "s3cret");
    // Manually verify: "\0testbot\0s3cret" base64
    var verify_buf: [256]u8 = undefined;
    const expected = encodeSaslPlain(&verify_buf, "testbot", "s3cret");
    try std.testing.expectEqualStrings(expected, encoded);

    // Also check against known value: \0testbot\0s3cret
    // = 0x00 t e s t b o t 0x00 s 3 c r e t (15 bytes)
    var known_buf: [256]u8 = undefined;
    const known = encodeSaslPlain(&known_buf, "jilles", "sesame");
    try std.testing.expectEqualStrings("AGppbGxlcwBzZXNhbWU=", known);
}

test "irc nick collision appends underscore" {
    const allocator = std.testing.allocator;
    const new_nick = try IrcChannel.handleNickCollision(allocator, "mybot", 0);
    defer allocator.free(new_nick);
    try std.testing.expectEqualStrings("mybot_", new_nick);
}

test "irc nick collision multiple retries" {
    const allocator = std.testing.allocator;
    const nick1 = try IrcChannel.handleNickCollision(allocator, "bot", 0);
    defer allocator.free(nick1);
    try std.testing.expectEqualStrings("bot_", nick1);

    const nick2 = try IrcChannel.handleNickCollision(allocator, nick1, 1);
    defer allocator.free(nick2);
    try std.testing.expectEqualStrings("bot__", nick2);
}

test "irc nick collision limit reached" {
    const result = IrcChannel.handleNickCollision(std.testing.allocator, "bot", MAX_NICK_RETRIES);
    try std.testing.expectError(error.NickCollisionLimitReached, result);
}

test "irc service bot messages are filtered" {
    try std.testing.expect(IrcChannel.isServiceBot("NickServ"));
    try std.testing.expect(IrcChannel.isServiceBot("ChanServ"));
    try std.testing.expect(IrcChannel.isServiceBot("BotServ"));
    try std.testing.expect(IrcChannel.isServiceBot("MemoServ"));
    // Case insensitive
    try std.testing.expect(IrcChannel.isServiceBot("nickserv"));
    try std.testing.expect(IrcChannel.isServiceBot("CHANSERV"));
    // Not a service bot
    try std.testing.expect(!IrcChannel.isServiceBot("alice"));
    try std.testing.expect(!IrcChannel.isServiceBot("randomuser"));
}

test "irc dm reply_target is nick not channel" {
    // When target is the bot's own nick (DM), reply_target should be the sender
    const reply = IrcChannel.replyTarget("mybot", "alice");
    try std.testing.expectEqualStrings("alice", reply);
}

test "irc channel reply_target is channel name" {
    // When target starts with #, reply_target should be the channel
    const reply = IrcChannel.replyTarget("#general", "alice");
    try std.testing.expectEqualStrings("#general", reply);
}

test "irc ampersand channel reply_target is channel name" {
    const reply = IrcChannel.replyTarget("&local", "bob");
    try std.testing.expectEqualStrings("&local", reply);
}

test "irc style prefix exists" {
    try std.testing.expect(IRC_STYLE_PREFIX.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, IRC_STYLE_PREFIX, "IRC") != null);
}

test "irc handleInboundLine publishes allowed group message to bus" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = IrcChannel.init(alloc, "irc.test", 6667, "mybot", null, &.{}, &.{"alice"}, null, null, null, false);
    ch.account_id = "irc-main";
    ch.setBus(&eb);

    try ch.handleInboundLine(":alice!u@h PRIVMSG #general :hello team\r\n");

    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("irc", msg.channel);
    try std.testing.expectEqualStrings("alice", msg.sender_id);
    try std.testing.expectEqualStrings("#general", msg.chat_id);
    try std.testing.expectEqualStrings("irc:irc-main:group:#general", msg.session_key);
    try std.testing.expect(std.mem.startsWith(u8, msg.content, IRC_STYLE_PREFIX));
    try std.testing.expect(std.mem.indexOf(u8, msg.content, "alice: hello team") != null);
    try std.testing.expect(msg.metadata_json != null);
}

test "irc handleInboundLine drops disallowed sender" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = IrcChannel.init(alloc, "irc.test", 6667, "mybot", null, &.{}, &.{"alice"}, null, null, null, false);
    ch.account_id = "irc-main";
    ch.setBus(&eb);

    try ch.handleInboundLine(":mallory!u@h PRIVMSG #general :hello team\r\n");
    eb.close();
    try std.testing.expect(eb.consumeInbound() == null);
}

test "irc max nick retries constant" {
    try std.testing.expectEqual(@as(usize, 5), MAX_NICK_RETRIES);
}

// ════════════════════════════════════════════════════════════════════════════
// TLS Wrapping Tests
// ════════════════════════════════════════════════════════════════════════════

test "irc tls config defaults" {
    const ch = IrcChannel.init(std.testing.allocator, "irc.libera.chat", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    // use_tls defaults to false (plain TCP by default)
    try std.testing.expect(!ch.use_tls);
    // verify_tls uses the value passed to init
    try std.testing.expect(ch.tls);
    // No TLS state or stream until connect() is called
    try std.testing.expect(ch.tls_state == null);
    try std.testing.expect(ch.stream == null);
}

test "irc tls disabled uses plain stream" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6667, "bot", null, &.{}, &.{}, null, null, null, false);
    // use_tls is false by default — no TLS wrapping should occur
    try std.testing.expect(!ch.use_tls);
    try std.testing.expect(ch.tls_state == null);
    // sendRaw without a connection should return IrcNotConnected
    try std.testing.expectError(error.IrcNotConnected, ch.sendRaw("PING"));
    // ircWriteAll without a connection should return IrcNotConnected
    try std.testing.expectError(error.IrcNotConnected, ch.ircWriteAll("test"));
}

test "irc verify_tls field" {
    // verify_tls=true (default when not overridden)
    const ch1 = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expect(ch1.tls);

    // verify_tls=false
    const ch2 = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, false);
    try std.testing.expect(!ch2.tls);
}

test "irc ircWriteAll without connection returns error" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    // No stream, no TLS — should return IrcNotConnected
    try std.testing.expect(ch.stream == null);
    try std.testing.expect(ch.tls_state == null);
    try std.testing.expectError(error.IrcNotConnected, ch.ircWriteAll("NICK bot\r\n"));
}

test "irc sendRaw without connection returns error" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expectError(error.IrcNotConnected, ch.sendRaw("NICK bot"));
}

test "irc sendMessage without connection returns error" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    try std.testing.expectError(error.IrcNotConnected, ch.sendMessage("#test", "hello"));
}

test "irc disconnect without connection is safe" {
    var ch = IrcChannel.init(std.testing.allocator, "irc.test", 6697, "bot", null, &.{}, &.{}, null, null, null, true);
    // Should not crash when called without an active connection
    ch.disconnect();
    try std.testing.expect(ch.stream == null);
    try std.testing.expect(ch.tls_state == null);
}
