const std = @import("std");
const root = @import("root.zig");

/// Email channel — IMAP polling for inbound, SMTP for outbound.
pub const EmailChannel = struct {
    allocator: std.mem.Allocator,
    config: EmailConfig,

    pub fn init(allocator: std.mem.Allocator, config: EmailConfig) EmailChannel {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn channelName(_: *EmailChannel) []const u8 {
        return "email";
    }

    /// Check if a sender email is in the allowlist.
    /// Supports full addresses, @domain, or bare domain matching.
    pub fn isSenderAllowed(self: *const EmailChannel, email_addr: []const u8) bool {
        if (self.config.allowed_senders.len == 0) return false;

        for (self.config.allowed_senders) |allowed| {
            if (std.mem.eql(u8, allowed, "*")) return true;

            if (allowed.len > 0 and allowed[0] == '@') {
                // Domain match with @ prefix: "@example.com"
                if (std.ascii.endsWithIgnoreCase(email_addr, allowed)) return true;
            } else if (std.mem.indexOf(u8, allowed, "@") != null) {
                // Full email address match
                if (std.ascii.eqlIgnoreCase(allowed, email_addr)) return true;
            } else {
                // Domain match without @: "example.com" -> match @example.com
                if (email_addr.len > allowed.len + 1) {
                    const suffix_start = email_addr.len - allowed.len - 1;
                    if (email_addr[suffix_start] == '@' and
                        std.ascii.eqlIgnoreCase(email_addr[suffix_start + 1 ..], allowed))
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    pub fn healthCheck(_: *EmailChannel) bool {
        return true;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send an email via SMTP.
    /// If message starts with "Subject: <line>\n", extracts the subject.
    /// Otherwise uses a default subject.
    pub fn sendMessage(self: *EmailChannel, recipient: []const u8, message: []const u8) !void {
        // Extract subject if present
        var subject: []const u8 = "nullclaw Message";
        var body = message;
        if (std.mem.startsWith(u8, message, "Subject: ")) {
            if (std.mem.indexOf(u8, message, "\n")) |nl_pos| {
                subject = message[9..nl_pos];
                body = std.mem.trimLeft(u8, message[nl_pos + 1 ..], " \t\r\n");
            }
        }

        // Connect to SMTP server via TCP
        const addr = std.net.Address.resolveIp(self.config.smtp_host, self.config.smtp_port) catch return error.SmtpConnectError;
        const stream = std.net.tcpConnectToAddress(addr) catch return error.SmtpConnectError;
        defer stream.close();

        // Read greeting
        var greeting_buf: [1024]u8 = undefined;
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // EHLO
        var ehlo_buf: [256]u8 = undefined;
        var ehlo_fbs = std.io.fixedBufferStream(&ehlo_buf);
        try ehlo_fbs.writer().print("EHLO nullclaw\r\n", .{});
        try stream.writeAll(ehlo_fbs.getWritten());
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // MAIL FROM
        var from_buf: [512]u8 = undefined;
        var from_fbs = std.io.fixedBufferStream(&from_buf);
        try from_fbs.writer().print("MAIL FROM:<{s}>\r\n", .{self.config.from_address});
        try stream.writeAll(from_fbs.getWritten());
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // RCPT TO
        var rcpt_buf: [512]u8 = undefined;
        var rcpt_fbs = std.io.fixedBufferStream(&rcpt_buf);
        try rcpt_fbs.writer().print("RCPT TO:<{s}>\r\n", .{recipient});
        try stream.writeAll(rcpt_fbs.getWritten());
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // DATA
        try stream.writeAll("DATA\r\n");
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // Build email headers + body
        var data_buf: [16384]u8 = undefined;
        var data_fbs = std.io.fixedBufferStream(&data_buf);
        const dw = data_fbs.writer();
        try dw.print("From: {s}\r\n", .{self.config.from_address});
        try dw.print("To: {s}\r\n", .{recipient});
        try dw.print("Subject: {s}\r\n", .{subject});
        try dw.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        try dw.writeAll("\r\n");
        try dw.writeAll(body);
        try dw.writeAll("\r\n.\r\n");
        try stream.writeAll(data_fbs.getWritten());
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // QUIT
        try stream.writeAll("QUIT\r\n");
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Email uses polling for IMAP; no persistent connection to start.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *EmailChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *EmailChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *EmailChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *EmailChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

/// Email channel configuration.
pub const EmailConfig = struct {
    imap_host: []const u8 = "",
    imap_port: u16 = 993,
    imap_folder: []const u8 = "INBOX",
    smtp_host: []const u8 = "",
    smtp_port: u16 = 587,
    smtp_tls: bool = true,
    username: []const u8 = "",
    password: []const u8 = "",
    from_address: []const u8 = "",
    poll_interval_secs: u64 = 60,
    allowed_senders: []const []const u8 = &.{},
};

/// Bounded dedup set that evicts oldest entries when capacity is reached.
pub const BoundedSeenSet = struct {
    allocator: std.mem.Allocator,
    set: std.StringHashMapUnmanaged(void),
    order: std.ArrayListUnmanaged([]const u8),
    capacity: usize,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) BoundedSeenSet {
        return .{
            .allocator = allocator,
            .set = .empty,
            .order = .empty,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *BoundedSeenSet) void {
        for (self.order.items) |key| self.allocator.free(key);
        self.order.deinit(self.allocator);
        self.set.deinit(self.allocator);
    }

    pub fn contains(self: *const BoundedSeenSet, id: []const u8) bool {
        return self.set.get(id) != null;
    }

    pub fn insert(self: *BoundedSeenSet, id: []const u8) !bool {
        if (self.set.get(id) != null) return false;

        if (self.order.items.len >= self.capacity) {
            const oldest = self.order.orderedRemove(0);
            _ = self.set.remove(oldest);
            self.allocator.free(oldest);
        }

        const duped = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(duped);
        try self.set.put(self.allocator, duped, {});
        try self.order.append(self.allocator, duped);
        return true;
    }

    pub fn len(self: *const BoundedSeenSet) usize {
        return self.set.count();
    }
};

/// Strip HTML tags from content (basic).
pub fn stripHtml(allocator: std.mem.Allocator, html: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var in_tag = false;
    for (html) |c| {
        switch (c) {
            '<' => in_tag = true,
            '>' => in_tag = false,
            else => {
                if (!in_tag) try result.append(allocator, c);
            },
        }
    }

    return result.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "email channel name" {
    var ch = EmailChannel.init(std.testing.allocator, .{});
    try std.testing.expectEqualStrings("email", ch.channelName());
}

test "email sender allowed wildcard" {
    const senders = [_][]const u8{"*"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@example.com"));
}

test "email sender allowed full address" {
    const senders = [_][]const u8{"user@example.com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("user@example.com"));
    try std.testing.expect(!ch.isSenderAllowed("other@example.com"));
}

test "email sender allowed domain with @" {
    const senders = [_][]const u8{"@example.com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@example.com"));
    try std.testing.expect(!ch.isSenderAllowed("anyone@other.com"));
}

test "email sender allowed domain without @" {
    const senders = [_][]const u8{"example.com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@example.com"));
    try std.testing.expect(!ch.isSenderAllowed("anyone@other.com"));
}

test "email sender denied empty" {
    const ch = EmailChannel.init(std.testing.allocator, .{});
    try std.testing.expect(!ch.isSenderAllowed("anyone@example.com"));
}

test "bounded seen set insert and contains" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 10);
    defer set.deinit();
    try std.testing.expect(try set.insert("a"));
    try std.testing.expect(set.contains("a"));
    try std.testing.expect(!set.contains("b"));
}

test "bounded seen set rejects duplicates" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 10);
    defer set.deinit();
    try std.testing.expect(try set.insert("a"));
    try std.testing.expect(!(try set.insert("a")));
    try std.testing.expectEqual(@as(usize, 1), set.len());
}

test "bounded seen set evicts oldest at capacity" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 3);
    defer set.deinit();
    _ = try set.insert("a");
    _ = try set.insert("b");
    _ = try set.insert("c");
    try std.testing.expectEqual(@as(usize, 3), set.len());

    _ = try set.insert("d");
    try std.testing.expectEqual(@as(usize, 3), set.len());
    try std.testing.expect(!set.contains("a"));
    try std.testing.expect(set.contains("b"));
    try std.testing.expect(set.contains("c"));
    try std.testing.expect(set.contains("d"));
}

test "bounded seen set capacity one" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 1);
    defer set.deinit();
    _ = try set.insert("a");
    try std.testing.expect(set.contains("a"));
    _ = try set.insert("b");
    try std.testing.expect(!set.contains("a"));
    try std.testing.expect(set.contains("b"));
    try std.testing.expectEqual(@as(usize, 1), set.len());
}

test "strip html basic" {
    const allocator = std.testing.allocator;
    const result = try stripHtml(allocator, "<p>Hello <b>world</b>!</p>");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello world!", result);
}

test "strip html no tags" {
    const allocator = std.testing.allocator;
    const result = try stripHtml(allocator, "plain text");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("plain text", result);
}

test "email vtable interface" {
    var ch = EmailChannel.init(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("email", iface.name());
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Email Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "bounded seen set evicts in fifo order" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 2);
    defer set.deinit();
    _ = try set.insert("first");
    _ = try set.insert("second");
    _ = try set.insert("third");
    try std.testing.expect(!set.contains("first"));
    try std.testing.expect(set.contains("second"));
    try std.testing.expect(set.contains("third"));

    _ = try set.insert("fourth");
    try std.testing.expect(!set.contains("second"));
    try std.testing.expect(set.contains("third"));
    try std.testing.expect(set.contains("fourth"));
}

test "email sender allowed case insensitive full address" {
    const senders = [_][]const u8{"User@Example.COM"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("user@example.com"));
    try std.testing.expect(ch.isSenderAllowed("USER@EXAMPLE.COM"));
}

test "email sender domain with @ case insensitive" {
    const senders = [_][]const u8{"@Example.Com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@example.com"));
    try std.testing.expect(ch.isSenderAllowed("USER@EXAMPLE.COM"));
}

test "email sender multiple senders" {
    const senders = [_][]const u8{ "alice@example.com", "bob@test.com" };
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("alice@example.com"));
    try std.testing.expect(ch.isSenderAllowed("bob@test.com"));
    try std.testing.expect(!ch.isSenderAllowed("eve@evil.com"));
}

test "email config defaults" {
    const config = EmailConfig{};
    try std.testing.expectEqual(@as(u16, 993), config.imap_port);
    try std.testing.expectEqualStrings("INBOX", config.imap_folder);
    try std.testing.expectEqual(@as(u16, 587), config.smtp_port);
    try std.testing.expect(config.smtp_tls);
    try std.testing.expectEqual(@as(u64, 60), config.poll_interval_secs);
}

test "strip html nested tags" {
    const allocator = std.testing.allocator;
    const result = try stripHtml(allocator, "<div><p>Hello</p><br/><p>World</p></div>");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("HelloWorld", result);
}

test "strip html empty input" {
    const allocator = std.testing.allocator;
    const result = try stripHtml(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "strip html only tags" {
    const allocator = std.testing.allocator;
    const result = try stripHtml(allocator, "<br/><hr/><img src=\"x\"/>");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "email health check returns true" {
    var ch = EmailChannel.init(std.testing.allocator, .{});
    try std.testing.expect(ch.healthCheck());
}

test "bounded seen set empty contains false" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 10);
    defer set.deinit();
    try std.testing.expect(!set.contains("anything"));
    try std.testing.expectEqual(@as(usize, 0), set.len());
}

test "bounded seen set large capacity" {
    const allocator = std.testing.allocator;
    var set = BoundedSeenSet.init(allocator, 100);
    defer set.deinit();
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var buf: [20]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "key_{d}", .{i}) catch unreachable;
        _ = try set.insert(key);
    }
    try std.testing.expectEqual(@as(usize, 50), set.len());
}

test "email sender wildcard with specific" {
    const senders = [_][]const u8{ "alice@example.com", "*" };
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@anything.com"));
}

test "email sender short address not domain match" {
    // An address shorter than the domain should not match
    const senders = [_][]const u8{"example.com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allowed_senders = &senders });
    try std.testing.expect(!ch.isSenderAllowed("@example.com")); // needs local part > 0
}
