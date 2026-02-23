//! Channels — messaging platform integrations.
//! Each channel implements the Channel interface (vtable-based polymorphism).
//!
//! Channels (matching ZeroClaw):
//!   - CLI (built-in stdin/stdout)
//!   - Telegram (long-polling)
//!   - Discord (WebSocket gateway)
//!   - Slack (socket/http event pipeline)
//!   - WhatsApp (webhook-based)
//!   - Matrix (long-polling /sync)
//!   - Mattermost (WebSocket + REST API)
//!   - IRC (TLS socket)
//!   - iMessage (AppleScript + SQLite on macOS)
//!   - Email (IMAP/SMTP)
//!   - Lark/Feishu (HTTP callback)
//!   - DingTalk (WebSocket stream mode)

const std = @import("std");

// ════════════════════════════════════════════════════════════════════════════
// Shared Types
// ════════════════════════════════════════════════════════════════════════════

/// A message received from or sent to a channel.
pub const ChannelMessage = struct {
    id: []const u8,
    sender: []const u8,
    content: []const u8,
    channel: []const u8,
    timestamp: u64,
    /// Where to send a reply (e.g., DM sender vs channel name in IRC, thread ID in Telegram).
    reply_target: ?[]const u8 = null,
    /// Platform message ID (e.g. Telegram message_id for reply-to).
    message_id: ?i64 = null,
    /// Sender's first name (for personalized greetings).
    first_name: ?[]const u8 = null,
    /// Whether the message came from a group chat.
    is_group: bool = false,

    pub fn deinit(self: *const ChannelMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.sender);
        allocator.free(self.content);
        // channel is a string literal or long-lived config pointer — not owned, don't free
        if (self.reply_target) |rt| allocator.free(rt);
        if (self.first_name) |fn_| allocator.free(fn_);
    }
};

/// Channel interface — Zig equivalent of ZeroClaw's Channel trait.
/// Uses vtable-based polymorphism for runtime dispatch.
pub const Channel = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Start the channel (connect, begin listening).
        start: *const fn (ptr: *anyopaque) anyerror!void,
        /// Stop the channel (disconnect, clean up).
        stop: *const fn (ptr: *anyopaque) void,
        /// Send a message to a target (user, channel, room, etc.).
        send: *const fn (ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void,
        /// Return the channel name (e.g. "telegram", "discord").
        name: *const fn (ptr: *anyopaque) []const u8,
        /// Health check — return true if the channel is operational.
        healthCheck: *const fn (ptr: *anyopaque) bool,
    };

    pub fn start(self: Channel) !void {
        return self.vtable.start(self.ptr);
    }

    pub fn stop(self: Channel) void {
        self.vtable.stop(self.ptr);
    }

    pub fn send(self: Channel, target: []const u8, message: []const u8, media: []const []const u8) !void {
        return self.vtable.send(self.ptr, target, message, media);
    }

    pub fn name(self: Channel) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn healthCheck(self: Channel) bool {
        return self.vtable.healthCheck(self.ptr);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Channel Sub-modules
// ════════════════════════════════════════════════════════════════════════════

pub const cli = @import("cli.zig");
pub const telegram = @import("telegram.zig");
pub const discord = @import("discord.zig");
pub const slack = @import("slack.zig");
pub const whatsapp = @import("whatsapp.zig");
pub const matrix = @import("matrix.zig");
pub const mattermost = @import("mattermost.zig");
pub const irc = @import("irc.zig");
pub const imessage = @import("imessage.zig");
pub const email = @import("email.zig");
pub const lark = @import("lark.zig");
pub const dingtalk = @import("dingtalk.zig");
pub const line = @import("line.zig");
pub const onebot = @import("onebot.zig");
pub const qq = @import("qq.zig");
pub const maixcam = @import("maixcam.zig");
pub const signal = @import("signal.zig");
pub const dispatch = @import("dispatch.zig");

// ════════════════════════════════════════════════════════════════════════════
// Utility
// ════════════════════════════════════════════════════════════════════════════

/// Split a message at `max_bytes`, respecting UTF-8 char boundaries.
/// Returns slices into the original `msg` buffer.
pub fn splitMessage(msg: []const u8, max_bytes: usize) SplitIterator {
    return SplitIterator{ .remaining = msg, .max = max_bytes };
}

pub const SplitIterator = struct {
    remaining: []const u8,
    max: usize,

    pub fn next(self: *SplitIterator) ?[]const u8 {
        if (self.remaining.len == 0) return null;
        if (self.remaining.len <= self.max) {
            const chunk = self.remaining;
            self.remaining = self.remaining[self.remaining.len..];
            return chunk;
        }
        var split_at = self.max;
        // Walk backwards to find a valid UTF-8 char boundary
        while ((self.remaining[split_at] & 0xC0) == 0x80) {
            if (split_at > 0) split_at -= 1 else break;
        }
        if (split_at == 0) {
            // No valid boundary found going backward; advance forward
            split_at = self.max;
            while (split_at < self.remaining.len and (self.remaining[split_at] & 0xC0) == 0x80) {
                split_at += 1;
            }
        }
        const chunk = self.remaining[0..split_at];
        self.remaining = self.remaining[split_at..];
        return chunk;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Per-Channel Permission Policies
// ════════════════════════════════════════════════════════════════════════════

/// DM (direct message) permission policy.
pub const DmPolicy = enum {
    /// Allow all DMs.
    allow,
    /// Deny all DMs.
    deny,
    /// Only allow DMs from senders in the allowlist.
    allowlist,
};

/// Group/channel message permission policy.
pub const GroupPolicy = enum {
    /// Allow all group messages.
    open,
    /// Only respond when explicitly mentioned.
    mention_only,
    /// Only allow messages from senders in the allowlist.
    allowlist,
};

/// Per-channel permission policy configuration.
pub const ChannelPolicy = struct {
    dm: DmPolicy = .allow,
    group: GroupPolicy = .open,
    allowlist: []const []const u8 = &.{},
};

/// Check if a message is permitted under the given policy.
///
/// - `policy`: the channel permission policy to evaluate
/// - `sender_id`: the sender of the message
/// - `is_dm`: true if this is a direct message, false if group
/// - `is_mention`: true if the bot was mentioned (relevant for group mention_only)
pub fn checkPolicy(policy: ChannelPolicy, sender_id: []const u8, is_dm: bool, is_mention: bool) bool {
    if (is_dm) {
        return switch (policy.dm) {
            .allow => true,
            .deny => false,
            .allowlist => inAllowlist(policy.allowlist, sender_id),
        };
    } else {
        return switch (policy.group) {
            .open => true,
            .mention_only => is_mention,
            .allowlist => inAllowlist(policy.allowlist, sender_id),
        };
    }
}

/// Check if sender_id is in the given allowlist (case-insensitive, supports "*" wildcard).
fn inAllowlist(allowlist: []const []const u8, sender_id: []const u8) bool {
    for (allowlist) |entry| {
        if (std.mem.eql(u8, entry, "*")) return true;
        if (std.ascii.eqlIgnoreCase(entry, sender_id)) return true;
    }
    return false;
}

/// Check if a user/sender is in an allowlist.
/// Supports "*" wildcard for allow-all.
pub fn isAllowed(allowed: []const []const u8, sender: []const u8) bool {
    for (allowed) |a| {
        if (std.mem.eql(u8, a, "*")) return true;
        if (std.ascii.eqlIgnoreCase(a, sender)) return true;
    }
    return false;
}

/// Check if a user/sender is in an allowlist (exact match, no case folding).
pub fn isAllowedExact(allowed: []const []const u8, sender: []const u8) bool {
    for (allowed) |a| {
        if (std.mem.eql(u8, a, "*")) return true;
        if (std.mem.eql(u8, a, sender)) return true;
    }
    return false;
}

/// Get current UNIX epoch seconds.
pub fn nowEpochSecs() u64 {
    const ns = std.time.nanoTimestamp();
    if (ns < 0) return 0;
    return @intCast(@as(u128, @intCast(ns)) / 1_000_000_000);
}

// ════════════════════════════════════════════════════════════════════════════
// Shared Utilities (re-exported from top-level modules)
// ════════════════════════════════════════════════════════════════════════════

/// HTTP POST via curl subprocess (safe on Zig 0.15, avoids std.http.Client segfaults).
pub const http_util = @import("../http_util.zig");

/// JSON string escaping (RFC 8259). appendJsonString adds enclosing quotes.
pub const json_util = @import("../json_util.zig");

/// Append a JSON-escaped string with enclosing quotes to any writer.
/// Writer-based variant of json_util.appendJsonString for fixed-buffer streams.
pub fn appendJsonStringW(writer: anytype, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    var esc: [6]u8 = undefined;
                    const escape = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch unreachable;
                    try writer.writeAll(escape);
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "channel interface compiles" {
    // Compile-time check only — ensures the vtable types are coherent
    const vtable = Channel.VTable{
        .start = undefined,
        .stop = undefined,
        .send = undefined,
        .name = undefined,
        .healthCheck = undefined,
    };
    _ = vtable;
}

test "splitMessage basic" {
    var it = splitMessage("hello world", 5);
    const a = it.next().?;
    try std.testing.expectEqualStrings("hello", a);
    const b = it.next().?;
    try std.testing.expectEqualStrings(" worl", b);
    const c = it.next().?;
    try std.testing.expectEqualStrings("d", c);
    try std.testing.expect(it.next() == null);
}

test "splitMessage exact boundary" {
    var it = splitMessage("abcde", 5);
    try std.testing.expectEqualStrings("abcde", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "splitMessage empty" {
    var it = splitMessage("", 100);
    try std.testing.expect(it.next() == null);
}

test "isAllowed wildcard" {
    const list = [_][]const u8{"*"};
    try std.testing.expect(isAllowed(&list, "anyone"));
}

test "isAllowed specific" {
    const list = [_][]const u8{ "alice", "bob" };
    try std.testing.expect(isAllowed(&list, "Alice"));
    try std.testing.expect(isAllowed(&list, "bob"));
    try std.testing.expect(!isAllowed(&list, "eve"));
}

test "isAllowed empty denies all" {
    const list = [_][]const u8{};
    try std.testing.expect(!isAllowed(&list, "anyone"));
}

test "isAllowedExact case sensitive" {
    const list = [_][]const u8{"Alice"};
    try std.testing.expect(isAllowedExact(&list, "Alice"));
    try std.testing.expect(!isAllowedExact(&list, "alice"));
}

test "nowEpochSecs returns nonzero" {
    const t = nowEpochSecs();
    try std.testing.expect(t > 1_000_000_000);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Root Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "splitMessage single char max" {
    var it = splitMessage("abcdef", 1);
    try std.testing.expectEqualStrings("a", it.next().?);
    try std.testing.expectEqualStrings("b", it.next().?);
    try std.testing.expectEqualStrings("c", it.next().?);
    try std.testing.expectEqualStrings("d", it.next().?);
    try std.testing.expectEqualStrings("e", it.next().?);
    try std.testing.expectEqualStrings("f", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "splitMessage utf8 multibyte respected" {
    // UTF-8: each CJK char is 3 bytes. With max_bytes=5, we can fit 1 char (3 bytes) but not 2 (6 bytes).
    var it = splitMessage("\xe4\xb8\x96\xe7\x95\x8c", 5); // "世界" (2 chars, 6 bytes)
    const chunk1 = it.next().?;
    try std.testing.expectEqual(@as(usize, 3), chunk1.len); // first char
    const chunk2 = it.next().?;
    try std.testing.expectEqual(@as(usize, 3), chunk2.len); // second char
    try std.testing.expect(it.next() == null);
}

test "splitMessage large max returns whole" {
    const msg = "hello world this is a test";
    var it = splitMessage(msg, 10000);
    try std.testing.expectEqualStrings(msg, it.next().?);
    try std.testing.expect(it.next() == null);
}

test "splitMessage two byte utf8" {
    // "aàb" - 'à' is 2 bytes (0xC3 0xA0), total 4 bytes
    const msg = "a\xc3\xa0b";
    var it = splitMessage(msg, 2);
    const chunk1 = it.next().?;
    // 'a' is 1 byte, 'à' is 2 bytes, so max=2 means: 'a' + partial 'à' won't fit, split at 1
    try std.testing.expect(chunk1.len <= 2);
    // Remaining should be valid UTF-8
    var total_len: usize = 0;
    total_len += chunk1.len;
    while (it.next()) |c| {
        total_len += c.len;
    }
    try std.testing.expectEqual(@as(usize, 4), total_len);
}

test "isAllowed multiple entries" {
    const list = [_][]const u8{ "alice", "bob", "charlie" };
    try std.testing.expect(isAllowed(&list, "alice"));
    try std.testing.expect(isAllowed(&list, "bob"));
    try std.testing.expect(isAllowed(&list, "charlie"));
    try std.testing.expect(!isAllowed(&list, "dave"));
}

test "isAllowed case insensitive" {
    const list = [_][]const u8{"Alice"};
    try std.testing.expect(isAllowed(&list, "alice"));
    try std.testing.expect(isAllowed(&list, "ALICE"));
    try std.testing.expect(isAllowed(&list, "Alice"));
}

test "isAllowed empty sender" {
    const list = [_][]const u8{"alice"};
    try std.testing.expect(!isAllowed(&list, ""));
}

test "isAllowedExact wildcard" {
    const list = [_][]const u8{"*"};
    try std.testing.expect(isAllowedExact(&list, "anyone"));
    try std.testing.expect(isAllowedExact(&list, ""));
}

test "isAllowedExact empty list denies" {
    const list = [_][]const u8{};
    try std.testing.expect(!isAllowedExact(&list, "anyone"));
}

test "isAllowedExact exact match only" {
    const list = [_][]const u8{"alice"};
    try std.testing.expect(isAllowedExact(&list, "alice"));
    try std.testing.expect(!isAllowedExact(&list, "Alice"));
    try std.testing.expect(!isAllowedExact(&list, "alice "));
    try std.testing.expect(!isAllowedExact(&list, " alice"));
}

test "isAllowedExact multiple entries" {
    const list = [_][]const u8{ "alice", "bob" };
    try std.testing.expect(isAllowedExact(&list, "alice"));
    try std.testing.expect(isAllowedExact(&list, "bob"));
    try std.testing.expect(!isAllowedExact(&list, "charlie"));
}

test "isAllowed wildcard mixed with specific" {
    const list = [_][]const u8{ "alice", "*" };
    try std.testing.expect(isAllowed(&list, "alice"));
    try std.testing.expect(isAllowed(&list, "anyone_else"));
}

test "channel message struct fields" {
    const msg = ChannelMessage{
        .id = "msg_abc123",
        .sender = "U123",
        .content = "hello",
        .channel = "slack",
        .timestamp = 1699999999,
    };
    try std.testing.expectEqualStrings("msg_abc123", msg.id);
    try std.testing.expectEqualStrings("U123", msg.sender);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("slack", msg.channel);
    try std.testing.expectEqual(@as(u64, 1699999999), msg.timestamp);
    try std.testing.expect(msg.reply_target == null);
}

test "channel message reply_target defaults to null" {
    const msg = ChannelMessage{
        .id = "id1",
        .sender = "u1",
        .content = "hi",
        .channel = "irc",
        .timestamp = 0,
    };
    try std.testing.expect(msg.reply_target == null);
}

test "channel message reply_target can be set" {
    const msg = ChannelMessage{
        .id = "id2",
        .sender = "u2",
        .content = "hi",
        .channel = "irc",
        .timestamp = 0,
        .reply_target = "#mychannel",
    };
    try std.testing.expectEqualStrings("#mychannel", msg.reply_target.?);
}

test "channel vtable struct has all fields" {
    // Compile-time check that all vtable fields exist
    const T = Channel.VTable;
    try std.testing.expect(@hasField(T, "start"));
    try std.testing.expect(@hasField(T, "stop"));
    try std.testing.expect(@hasField(T, "send"));
    try std.testing.expect(@hasField(T, "name"));
    try std.testing.expect(@hasField(T, "healthCheck"));
}

test "splitMessage iterator is reusable after exhaust" {
    var it = splitMessage("ab", 1);
    _ = it.next();
    _ = it.next();
    try std.testing.expect(it.next() == null);
    // Calling again should still return null
    try std.testing.expect(it.next() == null);
}

test "nowEpochSecs returns recent timestamp" {
    const t = nowEpochSecs();
    // Should be after 2020-01-01
    try std.testing.expect(t > 1_577_836_800);
    // Should be before 2100-01-01
    try std.testing.expect(t < 4_102_444_800);
}

test "splitMessage emoji preserved" {
    // Single emoji is 4 bytes in UTF-8
    const msg = "\xf0\x9f\xa6\x80"; // 🦀
    var it = splitMessage(msg, 10);
    try std.testing.expectEqualStrings(msg, it.next().?);
    try std.testing.expect(it.next() == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Per-Channel Permission Policy Tests
// ════════════════════════════════════════════════════════════════════════════

test "checkPolicy dm allow permits all" {
    const policy = ChannelPolicy{ .dm = .allow };
    try std.testing.expect(checkPolicy(policy, "alice", true, false));
    try std.testing.expect(checkPolicy(policy, "bob", true, false));
    try std.testing.expect(checkPolicy(policy, "", true, false));
}

test "checkPolicy dm deny blocks all" {
    const policy = ChannelPolicy{ .dm = .deny };
    try std.testing.expect(!checkPolicy(policy, "alice", true, false));
    try std.testing.expect(!checkPolicy(policy, "bob", true, false));
    try std.testing.expect(!checkPolicy(policy, "", true, false));
}

test "checkPolicy dm allowlist permits listed senders" {
    const list = [_][]const u8{ "alice", "bob" };
    const policy = ChannelPolicy{ .dm = .allowlist, .allowlist = &list };
    try std.testing.expect(checkPolicy(policy, "alice", true, false));
    try std.testing.expect(checkPolicy(policy, "bob", true, false));
    try std.testing.expect(!checkPolicy(policy, "eve", true, false));
    try std.testing.expect(!checkPolicy(policy, "", true, false));
}

test "checkPolicy dm allowlist case insensitive" {
    const list = [_][]const u8{"Alice"};
    const policy = ChannelPolicy{ .dm = .allowlist, .allowlist = &list };
    try std.testing.expect(checkPolicy(policy, "alice", true, false));
    try std.testing.expect(checkPolicy(policy, "ALICE", true, false));
    try std.testing.expect(checkPolicy(policy, "Alice", true, false));
    try std.testing.expect(!checkPolicy(policy, "bob", true, false));
}

test "checkPolicy dm allowlist wildcard" {
    const list = [_][]const u8{"*"};
    const policy = ChannelPolicy{ .dm = .allowlist, .allowlist = &list };
    try std.testing.expect(checkPolicy(policy, "anyone", true, false));
    try std.testing.expect(checkPolicy(policy, "", true, false));
}

test "checkPolicy dm allowlist empty denies all" {
    const policy = ChannelPolicy{ .dm = .allowlist, .allowlist = &.{} };
    try std.testing.expect(!checkPolicy(policy, "alice", true, false));
}

test "checkPolicy group open permits all" {
    const policy = ChannelPolicy{ .group = .open };
    try std.testing.expect(checkPolicy(policy, "alice", false, false));
    try std.testing.expect(checkPolicy(policy, "bob", false, true));
    try std.testing.expect(checkPolicy(policy, "", false, false));
}

test "checkPolicy group mention_only requires mention" {
    const policy = ChannelPolicy{ .group = .mention_only };
    try std.testing.expect(!checkPolicy(policy, "alice", false, false));
    try std.testing.expect(checkPolicy(policy, "alice", false, true));
    try std.testing.expect(!checkPolicy(policy, "bob", false, false));
    try std.testing.expect(checkPolicy(policy, "bob", false, true));
}

test "checkPolicy group allowlist permits listed senders" {
    const list = [_][]const u8{ "alice", "bob" };
    const policy = ChannelPolicy{ .group = .allowlist, .allowlist = &list };
    try std.testing.expect(checkPolicy(policy, "alice", false, false));
    try std.testing.expect(checkPolicy(policy, "bob", false, true));
    try std.testing.expect(!checkPolicy(policy, "eve", false, false));
    try std.testing.expect(!checkPolicy(policy, "eve", false, true));
}

test "checkPolicy group allowlist ignores mention flag" {
    const list = [_][]const u8{"alice"};
    const policy = ChannelPolicy{ .group = .allowlist, .allowlist = &list };
    // allowlist permits regardless of mention status
    try std.testing.expect(checkPolicy(policy, "alice", false, false));
    try std.testing.expect(checkPolicy(policy, "alice", false, true));
    // non-listed sender denied regardless of mention
    try std.testing.expect(!checkPolicy(policy, "eve", false, false));
    try std.testing.expect(!checkPolicy(policy, "eve", false, true));
}

test "checkPolicy group allowlist empty denies all" {
    const policy = ChannelPolicy{ .group = .allowlist, .allowlist = &.{} };
    try std.testing.expect(!checkPolicy(policy, "alice", false, false));
    try std.testing.expect(!checkPolicy(policy, "alice", false, true));
}

test "checkPolicy mixed dm and group on same policy" {
    const list = [_][]const u8{"alice"};
    const policy = ChannelPolicy{
        .dm = .allowlist,
        .group = .mention_only,
        .allowlist = &list,
    };
    // DM: only alice allowed
    try std.testing.expect(checkPolicy(policy, "alice", true, false));
    try std.testing.expect(!checkPolicy(policy, "bob", true, false));
    // Group: mention_only (allowlist not used for group in mention_only mode)
    try std.testing.expect(!checkPolicy(policy, "alice", false, false));
    try std.testing.expect(checkPolicy(policy, "alice", false, true));
    try std.testing.expect(checkPolicy(policy, "bob", false, true));
}

test "checkPolicy default policy allows everything" {
    const policy = ChannelPolicy{};
    // Default: dm=allow, group=open
    try std.testing.expect(checkPolicy(policy, "anyone", true, false));
    try std.testing.expect(checkPolicy(policy, "anyone", false, false));
    try std.testing.expect(checkPolicy(policy, "anyone", false, true));
}

test "ChannelPolicy struct defaults" {
    const policy = ChannelPolicy{};
    try std.testing.expect(policy.dm == .allow);
    try std.testing.expect(policy.group == .open);
    try std.testing.expectEqual(@as(usize, 0), policy.allowlist.len);
}

test "DmPolicy enum values" {
    try std.testing.expect(@intFromEnum(DmPolicy.allow) != @intFromEnum(DmPolicy.deny));
    try std.testing.expect(@intFromEnum(DmPolicy.deny) != @intFromEnum(DmPolicy.allowlist));
    try std.testing.expect(@intFromEnum(DmPolicy.allow) != @intFromEnum(DmPolicy.allowlist));
}

test "GroupPolicy enum values" {
    try std.testing.expect(@intFromEnum(GroupPolicy.open) != @intFromEnum(GroupPolicy.mention_only));
    try std.testing.expect(@intFromEnum(GroupPolicy.mention_only) != @intFromEnum(GroupPolicy.allowlist));
    try std.testing.expect(@intFromEnum(GroupPolicy.open) != @intFromEnum(GroupPolicy.allowlist));
}

test {
    @import("std").testing.refAllDecls(@This());
}
