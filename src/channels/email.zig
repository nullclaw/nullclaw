const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");

/// Email channel — IMAP polling for inbound, SMTP for outbound.
pub const EmailChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.EmailConfig,
    /// Tracks last Message-ID per sender for In-Reply-To/References headers.
    reply_message_ids: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, config: config_types.EmailConfig) EmailChannel {
        return .{ .allocator = allocator, .config = config, .reply_message_ids = .empty };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.EmailConfig) EmailChannel {
        return init(allocator, cfg);
    }

    pub fn deinit(self: *EmailChannel) void {
        var it = self.reply_message_ids.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.reply_message_ids.deinit(self.allocator);
    }

    /// Record a Message-ID for a sender (for threading replies).
    pub fn trackMessageId(self: *EmailChannel, sender: []const u8, message_id: []const u8) !void {
        const gop = try self.reply_message_ids.getOrPut(self.allocator, sender);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = try self.allocator.dupe(u8, message_id);
        } else {
            gop.key_ptr.* = try self.allocator.dupe(u8, sender);
            gop.value_ptr.* = try self.allocator.dupe(u8, message_id);
        }
    }

    pub fn channelName(_: *EmailChannel) []const u8 {
        return "email";
    }

    /// Check if a sender email is in the allowlist.
    /// Supports full addresses, @domain, or bare domain matching.
    pub fn isSenderAllowed(self: *const EmailChannel, email_addr: []const u8) bool {
        if (self.config.allow_from.len == 0) return false;

        for (self.config.allow_from) |allowed| {
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
        if (!self.config.consent_granted) return error.ConsentNotGranted;

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

        // Add In-Reply-To/References headers if we have a tracked message-id
        if (self.reply_message_ids.get(recipient)) |msg_id| {
            try dw.print("In-Reply-To: <{s}>\r\n", .{msg_id});
            try dw.print("References: <{s}>\r\n", .{msg_id});
        }

        try dw.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        try dw.writeAll("\r\n");
        try dw.writeAll(body);
        try dw.writeAll("\r\n.\r\n");
        try stream.writeAll(data_fbs.getWritten());
        _ = stream.read(&greeting_buf) catch return error.SmtpError;

        // QUIT
        try stream.writeAll("QUIT\r\n");
    }

    /// Send a reply email — applies Re: prefix to subject and includes threading headers.
    pub fn sendReply(self: *EmailChannel, recipient: []const u8, original_subject: []const u8, message: []const u8) !void {
        var buf: [16384]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        if (hasReplyPrefix(original_subject)) {
            try fbs.writer().print("Subject: {s}\n{s}", .{ original_subject, message });
        } else {
            try fbs.writer().print("Subject: Re: {s}\n{s}", .{ original_subject, message });
        }
        try self.sendMessage(recipient, fbs.getWritten());
    }

    /// Send IMAP UID STORE command to mark a message as \Seen.
    pub fn markMessageSeen(self: *EmailChannel, stream: std.net.Stream, uid: u32) !void {
        _ = self;
        var cmd_buf: [256]u8 = undefined;
        var cmd_fbs = std.io.fixedBufferStream(&cmd_buf);
        try cmd_fbs.writer().print("A003 UID STORE {d} +FLAGS (\\Seen)\r\n", .{uid});
        try stream.writeAll(cmd_fbs.getWritten());
        // Read response (discard for now)
        var resp_buf: [1024]u8 = undefined;
        _ = stream.read(&resp_buf) catch return error.ImapError;
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Email uses polling for IMAP; no persistent connection to start.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
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

/// Check if subject already has a "Re:" prefix (case-insensitive).
pub fn hasReplyPrefix(subject: []const u8) bool {
    return subject.len >= 3 and std.ascii.eqlIgnoreCase(subject[0..3], "Re:");
}

/// Return the reply subject: if it already starts with "Re:" (case-insensitive),
/// return as-is; otherwise return as-is (callers should use replySubjectAlloc for prefix).
/// This non-allocating version is used when the subject is written via format string.
pub fn replySubject(original: []const u8) []const u8 {
    return original;
}

/// Allocating version of replySubject — always returns "Re: <subject>" if not already prefixed.
pub fn replySubjectAlloc(allocator: std.mem.Allocator, original: []const u8) ![]u8 {
    if (original.len >= 3 and std.ascii.eqlIgnoreCase(original[0..3], "Re:")) {
        return allocator.dupe(u8, original);
    }
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "Re: ");
    try result.appendSlice(allocator, original);
    return result.toOwnedSlice(allocator);
}

/// Decode RFC 2047 encoded-word headers.
/// Supports =?CHARSET?B?BASE64?= and =?CHARSET?Q?QUOTED-PRINTABLE?=.
/// Non-encoded text is passed through as-is.
pub fn decodeRfc2047(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < encoded.len) {
        // Look for =? start of encoded-word
        if (i + 1 < encoded.len and encoded[i] == '=' and encoded[i + 1] == '?') {
            if (parseEncodedWord(encoded[i..])) |ew| {
                // Decode the payload
                if (std.ascii.eqlIgnoreCase(ew.encoding, "B")) {
                    // Base64 decode
                    const out_size = std.base64.standard.Decoder.calcSizeForSlice(ew.payload) catch {
                        try result.appendSlice(allocator, encoded[i .. i + ew.total_len]);
                        i += ew.total_len;
                        continue;
                    };
                    const start_len = result.items.len;
                    try result.resize(allocator, start_len + out_size);
                    std.base64.standard.Decoder.decode(result.items[start_len..][0..out_size], ew.payload) catch {
                        // Invalid base64 — pass through raw
                        result.shrinkRetainingCapacity(start_len);
                        try result.appendSlice(allocator, encoded[i .. i + ew.total_len]);
                        i += ew.total_len;
                        continue;
                    };
                } else if (std.ascii.eqlIgnoreCase(ew.encoding, "Q")) {
                    // Quoted-printable (index-based for =XX lookahead)
                    var qi: usize = 0;
                    while (qi < ew.payload.len) {
                        const qc = ew.payload[qi];
                        if (qc == '_') {
                            try result.append(allocator, ' ');
                            qi += 1;
                        } else if (qc == '=' and qi + 2 < ew.payload.len) {
                            const hi = hexDigit(ew.payload[qi + 1]) orelse {
                                try result.append(allocator, qc);
                                qi += 1;
                                continue;
                            };
                            const lo = hexDigit(ew.payload[qi + 2]) orelse {
                                try result.append(allocator, qc);
                                qi += 1;
                                continue;
                            };
                            try result.append(allocator, (hi << 4) | lo);
                            qi += 3;
                        } else {
                            try result.append(allocator, qc);
                            qi += 1;
                        }
                    }
                } else {
                    // Unknown encoding — pass through
                    try result.appendSlice(allocator, encoded[i .. i + ew.total_len]);
                }
                i += ew.total_len;
            } else {
                try result.append(allocator, encoded[i]);
                i += 1;
            }
        } else {
            try result.append(allocator, encoded[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

const EncodedWord = struct {
    encoding: []const u8, // "B" or "Q"
    payload: []const u8,
    total_len: usize,
};

/// Parse an RFC 2047 encoded-word starting at the given slice.
/// Format: =?charset?encoding?payload?=
fn parseEncodedWord(s: []const u8) ?EncodedWord {
    if (s.len < 6 or s[0] != '=' or s[1] != '?') return null;

    // Find charset end (second ?)
    const charset_end = std.mem.indexOf(u8, s[2..], "?") orelse return null;
    const enc_start = 2 + charset_end + 1;
    if (enc_start >= s.len) return null;

    // Find encoding end (third ?)
    const enc_end_rel = std.mem.indexOf(u8, s[enc_start..], "?") orelse return null;
    const encoding = s[enc_start .. enc_start + enc_end_rel];
    const payload_start = enc_start + enc_end_rel + 1;
    if (payload_start >= s.len) return null;

    // Find ?= terminator
    const term_pos = std.mem.indexOf(u8, s[payload_start..], "?=") orelse return null;
    const payload = s[payload_start .. payload_start + term_pos];
    const total_len = payload_start + term_pos + 2;

    return .{
        .encoding = encoding,
        .payload = payload,
        .total_len = total_len,
    };
}

fn hexDigit(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

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
    const ch = EmailChannel.init(std.testing.allocator, .{ .allow_from = &senders });
    try std.testing.expect(ch.isSenderAllowed("user@example.com"));
    try std.testing.expect(ch.isSenderAllowed("USER@EXAMPLE.COM"));
}

test "email sender domain with @ case insensitive" {
    const senders = [_][]const u8{"@Example.Com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allow_from = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@example.com"));
    try std.testing.expect(ch.isSenderAllowed("USER@EXAMPLE.COM"));
}

test "email sender multiple senders" {
    const senders = [_][]const u8{ "alice@example.com", "bob@test.com" };
    const ch = EmailChannel.init(std.testing.allocator, .{ .allow_from = &senders });
    try std.testing.expect(ch.isSenderAllowed("alice@example.com"));
    try std.testing.expect(ch.isSenderAllowed("bob@test.com"));
    try std.testing.expect(!ch.isSenderAllowed("eve@evil.com"));
}

test "email config defaults" {
    const config = config_types.EmailConfig{};
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
    const ch = EmailChannel.init(std.testing.allocator, .{ .allow_from = &senders });
    try std.testing.expect(ch.isSenderAllowed("anyone@anything.com"));
}

test "email sender short address not domain match" {
    // An address shorter than the domain should not match
    const senders = [_][]const u8{"example.com"};
    const ch = EmailChannel.init(std.testing.allocator, .{ .allow_from = &senders });
    try std.testing.expect(!ch.isSenderAllowed("@example.com")); // needs local part > 0
}

// ════════════════════════════════════════════════════════════════════════════
// Consent Gates Tests
// ════════════════════════════════════════════════════════════════════════════

test "consent granted default is true" {
    const config = config_types.EmailConfig{};
    try std.testing.expect(config.consent_granted);
}

test "consent not granted blocks send" {
    var ch = EmailChannel.init(std.testing.allocator, .{ .consent_granted = false });
    defer ch.deinit();
    const result = ch.sendMessage("test@example.com", "hello");
    try std.testing.expectError(error.ConsentNotGranted, result);
}

test "consent granted allows send attempt" {
    // With consent but invalid host, we expect SmtpConnectError (not ConsentNotGranted)
    var ch = EmailChannel.init(std.testing.allocator, .{
        .consent_granted = true,
        .smtp_host = "999.999.999.999",
    });
    defer ch.deinit();
    const result = ch.sendMessage("test@example.com", "hello");
    try std.testing.expectError(error.SmtpConnectError, result);
}

// ════════════════════════════════════════════════════════════════════════════
// In-Reply-To / References Tests
// ════════════════════════════════════════════════════════════════════════════

test "track message id stores and retrieves" {
    const allocator = std.testing.allocator;
    var ch = EmailChannel.init(allocator, .{});
    defer ch.deinit();

    try ch.trackMessageId("alice@example.com", "msg-001");
    const got = ch.reply_message_ids.get("alice@example.com");
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("msg-001", got.?);
}

test "track message id overwrites previous" {
    const allocator = std.testing.allocator;
    var ch = EmailChannel.init(allocator, .{});
    defer ch.deinit();

    try ch.trackMessageId("alice@example.com", "msg-001");
    try ch.trackMessageId("alice@example.com", "msg-002");
    const got = ch.reply_message_ids.get("alice@example.com");
    try std.testing.expectEqualStrings("msg-002", got.?);
}

test "track message id multiple senders" {
    const allocator = std.testing.allocator;
    var ch = EmailChannel.init(allocator, .{});
    defer ch.deinit();

    try ch.trackMessageId("alice@example.com", "msg-a");
    try ch.trackMessageId("bob@example.com", "msg-b");
    try std.testing.expectEqualStrings("msg-a", ch.reply_message_ids.get("alice@example.com").?);
    try std.testing.expectEqualStrings("msg-b", ch.reply_message_ids.get("bob@example.com").?);
}

// ════════════════════════════════════════════════════════════════════════════
// Subject Tracking Tests
// ════════════════════════════════════════════════════════════════════════════

test "hasReplyPrefix detects Re prefix" {
    try std.testing.expect(hasReplyPrefix("Re: Hello"));
    try std.testing.expect(hasReplyPrefix("re: Hello"));
    try std.testing.expect(hasReplyPrefix("RE: Hello"));
    try std.testing.expect(hasReplyPrefix("Re:no space"));
}

test "hasReplyPrefix rejects non-Re" {
    try std.testing.expect(!hasReplyPrefix("Hello"));
    try std.testing.expect(!hasReplyPrefix("Fwd: Hello"));
    try std.testing.expect(!hasReplyPrefix(""));
    try std.testing.expect(!hasReplyPrefix("Re"));
}

test "replySubjectAlloc adds prefix" {
    const allocator = std.testing.allocator;
    const result = try replySubjectAlloc(allocator, "Hello World");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Re: Hello World", result);
}

test "replySubjectAlloc preserves existing Re" {
    const allocator = std.testing.allocator;
    const result = try replySubjectAlloc(allocator, "Re: Hello World");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Re: Hello World", result);
}

test "replySubjectAlloc empty subject" {
    const allocator = std.testing.allocator;
    const result = try replySubjectAlloc(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Re: ", result);
}

test "replySubjectAlloc case insensitive RE" {
    const allocator = std.testing.allocator;
    const result = try replySubjectAlloc(allocator, "RE: Already");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("RE: Already", result);
}

// ════════════════════════════════════════════════════════════════════════════
// RFC 2047 Decoding Tests
// ════════════════════════════════════════════════════════════════════════════

test "decodeRfc2047 base64 utf8" {
    const allocator = std.testing.allocator;
    // "Hello" in base64 = "SGVsbG8="
    const result = try decodeRfc2047(allocator, "=?UTF-8?B?SGVsbG8=?=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "decodeRfc2047 quoted printable" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "=?UTF-8?Q?Hello_World?=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World", result);
}

test "decodeRfc2047 quoted printable hex escape" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "=?UTF-8?Q?caf=C3=A9?=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("caf\xc3\xa9", result);
}

test "decodeRfc2047 plain text passthrough" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "Just plain text");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Just plain text", result);
}

test "decodeRfc2047 mixed encoded and plain" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "Hello =?UTF-8?B?V29ybGQ=?= !");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World !", result);
}

test "decodeRfc2047 empty input" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "decodeRfc2047 case insensitive encoding" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "=?utf-8?b?SGVsbG8=?=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "decodeRfc2047 quoted printable underscore to space" {
    const allocator = std.testing.allocator;
    const result = try decodeRfc2047(allocator, "=?UTF-8?Q?Re:_Your_Order?=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Re: Your Order", result);
}

test "parseEncodedWord valid base64" {
    const ew = parseEncodedWord("=?UTF-8?B?SGVsbG8=?=").?;
    try std.testing.expectEqualStrings("B", ew.encoding);
    try std.testing.expectEqualStrings("SGVsbG8=", ew.payload);
    try std.testing.expectEqual(@as(usize, 20), ew.total_len);
}

test "parseEncodedWord invalid returns null" {
    try std.testing.expect(parseEncodedWord("not encoded") == null);
    try std.testing.expect(parseEncodedWord("=?") == null);
    try std.testing.expect(parseEncodedWord("") == null);
}

test "hexDigit valid digits" {
    try std.testing.expectEqual(@as(u8, 0), hexDigit('0').?);
    try std.testing.expectEqual(@as(u8, 9), hexDigit('9').?);
    try std.testing.expectEqual(@as(u8, 10), hexDigit('A').?);
    try std.testing.expectEqual(@as(u8, 15), hexDigit('F').?);
    try std.testing.expectEqual(@as(u8, 10), hexDigit('a').?);
    try std.testing.expectEqual(@as(u8, 15), hexDigit('f').?);
}

test "hexDigit invalid returns null" {
    try std.testing.expect(hexDigit('G') == null);
    try std.testing.expect(hexDigit(' ') == null);
    try std.testing.expect(hexDigit('z') == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Mark-as-Seen Test
// ════════════════════════════════════════════════════════════════════════════

test "markMessageSeen method exists" {
    // Verify the method signature compiles correctly
    var ch = EmailChannel.init(std.testing.allocator, .{});
    defer ch.deinit();
    const info = @typeInfo(@TypeOf(EmailChannel.markMessageSeen));
    try std.testing.expect(info == .@"fn");
}
