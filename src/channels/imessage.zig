const std = @import("std");
const root = @import("root.zig");

/// iMessage channel — uses macOS AppleScript bridge.
/// Polls ~/Library/Messages/chat.db for new messages, sends via osascript.
pub const IMessageChannel = struct {
    allocator: std.mem.Allocator,
    allowed_contacts: []const []const u8,
    poll_interval_secs: u64,

    pub fn init(allocator: std.mem.Allocator, allowed_contacts: []const []const u8) IMessageChannel {
        return .{
            .allocator = allocator,
            .allowed_contacts = allowed_contacts,
            .poll_interval_secs = 3,
        };
    }

    pub fn channelName(_: *IMessageChannel) []const u8 {
        return "imessage";
    }

    pub fn isContactAllowed(self: *const IMessageChannel, sender: []const u8) bool {
        return root.isAllowed(self.allowed_contacts, sender);
    }

    pub fn healthCheck(_: *IMessageChannel) bool {
        // Only works on macOS
        return @import("builtin").os.tag == .macos;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message via macOS iMessage using osascript.
    /// Validates target format and escapes both message and target for AppleScript injection prevention.
    pub fn sendMessage(self: *IMessageChannel, target: []const u8, message: []const u8) !void {
        // Defense-in-depth: validate target format
        if (!isValidTarget(target)) {
            return error.InvalidTarget;
        }

        // Escape both message and target for AppleScript
        const escaped_msg = try escapeAppleScript(self.allocator, message);
        defer self.allocator.free(escaped_msg);
        const escaped_target = try escapeAppleScript(self.allocator, target);
        defer self.allocator.free(escaped_target);

        // Build AppleScript
        const script = try std.fmt.allocPrint(
            self.allocator,
            "tell application \"Messages\"\n" ++
                "    set targetService to 1st account whose service type = iMessage\n" ++
                "    set targetBuddy to participant \"{s}\" of targetService\n" ++
                "    send \"{s}\" to targetBuddy\n" ++
                "end tell",
            .{ escaped_target, escaped_msg },
        );
        defer self.allocator.free(script);

        // Execute via osascript
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{ "osascript", "-e", script },
        }) catch return error.IMessageSendFailed;
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term.Exited != 0) {
            return error.IMessageSendFailed;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // iMessage: no persistent connection; polls chat.db and sends via osascript.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *IMessageChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *IMessageChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// AppleScript Escaping (CWE-78 Prevention)
// ════════════════════════════════════════════════════════════════════════════

/// Escape a string for safe interpolation into AppleScript.
/// Prevents injection by escaping backslashes, quotes, and newlines.
pub fn escapeAppleScript(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    for (s) |c| {
        switch (c) {
            '\\' => {
                try result.append(allocator, '\\');
                try result.append(allocator, '\\');
            },
            '"' => {
                try result.append(allocator, '\\');
                try result.append(allocator, '"');
            },
            '\n' => {
                try result.append(allocator, '\\');
                try result.append(allocator, 'n');
            },
            '\r' => {
                try result.append(allocator, '\\');
                try result.append(allocator, 'r');
            },
            else => try result.append(allocator, c),
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Validate that a target looks like a valid phone number or email address.
/// Defense-in-depth: rejects obviously malicious targets before AppleScript interpolation.
pub fn isValidTarget(target: []const u8) bool {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return false;

    // Phone number: +digits (with optional spaces/dashes), 7-15 digits
    if (trimmed[0] == '+') {
        var digit_count: usize = 0;
        for (trimmed[1..]) |c| {
            if (std.ascii.isDigit(c)) {
                digit_count += 1;
            } else if (c != ' ' and c != '-') {
                return false;
            }
        }
        return digit_count >= 7 and digit_count <= 15;
    }

    // Email: local@domain.tld
    const at_pos = std.mem.indexOf(u8, trimmed, "@") orelse return false;
    if (at_pos == 0) return false;
    const local = trimmed[0..at_pos];
    const domain = trimmed[at_pos + 1 ..];
    if (domain.len == 0) return false;
    if (std.mem.indexOf(u8, domain, ".") == null) return false;

    // Validate local part
    for (local) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and c != '+' and c != '-') return false;
    }

    // Validate domain
    for (domain) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') return false;
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "imessage channel name" {
    var ch = IMessageChannel.init(std.testing.allocator, &.{});
    try std.testing.expectEqualStrings("imessage", ch.channelName());
}

test "imessage wildcard allows anyone" {
    const contacts = [_][]const u8{"*"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(ch.isContactAllowed("+1234567890"));
    try std.testing.expect(ch.isContactAllowed("random@icloud.com"));
}

test "imessage specific contact allowed" {
    const contacts = [_][]const u8{ "+1234567890", "user@icloud.com" };
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(ch.isContactAllowed("+1234567890"));
    try std.testing.expect(ch.isContactAllowed("user@icloud.com"));
}

test "imessage unknown contact denied" {
    const contacts = [_][]const u8{"+1234567890"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(!ch.isContactAllowed("+9999999999"));
}

test "imessage empty allowlist denies all" {
    const ch = IMessageChannel.init(std.testing.allocator, &.{});
    try std.testing.expect(!ch.isContactAllowed("+1234567890"));
}

test "escape applescript double quotes" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "hello \"world\"");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello \\\"world\\\"", result);
}

test "escape applescript backslashes" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "path\\to\\file");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("path\\\\to\\\\file", result);
}

test "escape applescript newlines" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "line1\nline2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("line1\\nline2", result);
}

test "escape applescript injection attempt" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "\" & do shell script \"id\" & \"");
    defer allocator.free(result);
    // All quotes should be escaped
    for (result, 0..) |c, i| {
        if (c == '"') {
            try std.testing.expect(i > 0 and result[i - 1] == '\\');
        }
    }
}

test "escape applescript empty string" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "valid target phone" {
    try std.testing.expect(isValidTarget("+1234567890"));
    try std.testing.expect(isValidTarget("+14155551234"));
    try std.testing.expect(isValidTarget("+1 415 555 1234"));
    try std.testing.expect(isValidTarget("+1-415-555-1234"));
}

test "valid target email" {
    try std.testing.expect(isValidTarget("user@example.com"));
    try std.testing.expect(isValidTarget("user@icloud.com"));
    try std.testing.expect(isValidTarget("user+tag@example.com"));
    try std.testing.expect(isValidTarget("first.last@example.com"));
}

test "invalid target empty" {
    try std.testing.expect(!isValidTarget(""));
    try std.testing.expect(!isValidTarget("   "));
}

test "invalid target no plus prefix" {
    try std.testing.expect(!isValidTarget("1234567890"));
}

test "invalid target too short phone" {
    try std.testing.expect(!isValidTarget("+123456"));
}

test "invalid target too long phone" {
    try std.testing.expect(!isValidTarget("+1234567890123456"));
}

test "invalid target email no at" {
    try std.testing.expect(!isValidTarget("userexample.com"));
}

test "invalid target email no domain" {
    try std.testing.expect(!isValidTarget("user@"));
}

test "invalid target email no dot in domain" {
    try std.testing.expect(!isValidTarget("user@localhost"));
}

test "invalid target injection attempt" {
    try std.testing.expect(!isValidTarget("\" & do shell script \"id\" & \""));
}

test "imessage vtable interface" {
    var ch = IMessageChannel.init(std.testing.allocator, &.{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("imessage", iface.name());
}

// ════════════════════════════════════════════════════════════════════════════
// Additional iMessage Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "imessage creates with contacts" {
    const contacts = [_][]const u8{"+1234567890"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expectEqual(@as(usize, 1), ch.allowed_contacts.len);
    try std.testing.expectEqual(@as(u64, 3), ch.poll_interval_secs);
}

test "imessage creates with empty contacts" {
    const ch = IMessageChannel.init(std.testing.allocator, &.{});
    try std.testing.expectEqual(@as(usize, 0), ch.allowed_contacts.len);
}

test "imessage contact case insensitive" {
    const contacts = [_][]const u8{"User@iCloud.com"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(ch.isContactAllowed("user@icloud.com"));
    try std.testing.expect(ch.isContactAllowed("USER@ICLOUD.COM"));
}

test "imessage wildcard among others still allows all" {
    const contacts = [_][]const u8{ "+111", "*", "+222" };
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(ch.isContactAllowed("totally-unknown"));
}

test "imessage unknown contact denied with hacker email" {
    const contacts = [_][]const u8{"+1234567890"};
    const ch = IMessageChannel.init(std.testing.allocator, &contacts);
    try std.testing.expect(!ch.isContactAllowed("hacker@evil.com"));
}

test "escape applescript no special chars" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "hello world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "escape applescript unicode preserved" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "hello \xf0\x9f\xa6\x80 world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello \xf0\x9f\xa6\x80 world", result);
}

test "escape applescript mixed quotes and backslashes" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "say \"hello\\\" world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("say \\\"hello\\\\\\\" world", result);
}

test "escape applescript carriage return" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "line1\rline2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("line1\\rline2", result);
}

test "escape applescript crlf" {
    const allocator = std.testing.allocator;
    const result = try escapeAppleScript(allocator, "line1\r\nline2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("line1\\r\\nline2", result);
}

test "valid target phone international" {
    try std.testing.expect(isValidTarget("+447911123456")); // UK
    try std.testing.expect(isValidTarget("+81312345678")); // Japan
}

test "valid target email with subdomain" {
    try std.testing.expect(isValidTarget("user@mail.example.com"));
}

test "valid target email icloud and me" {
    try std.testing.expect(isValidTarget("user@icloud.com"));
    try std.testing.expect(isValidTarget("user@me.com"));
}

test "invalid target email no local" {
    try std.testing.expect(!isValidTarget("@example.com"));
}

test "invalid target special chars in email" {
    try std.testing.expect(!isValidTarget("user<script>@example.com"));
    try std.testing.expect(!isValidTarget("user@example.com; rm -rf /"));
}

test "invalid target null byte" {
    try std.testing.expect(!isValidTarget("user\x00@example.com"));
}

test "invalid target newline" {
    try std.testing.expect(!isValidTarget("user\n@example.com"));
}

test "valid target with whitespace trimmed" {
    try std.testing.expect(isValidTarget("  +1234567890  "));
    try std.testing.expect(isValidTarget("  user@example.com  "));
}

test "invalid target applescript injection variants" {
    try std.testing.expect(!isValidTarget("test\" & quit"));
    try std.testing.expect(!isValidTarget("test\\ndo shell script"));
}
