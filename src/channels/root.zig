//! Channels — messaging platform integrations.
//! Each channel implements the Channel interface (vtable-based polymorphism).
//!
//! Channels (matching ZeroClaw):
//!   - CLI (built-in stdin/stdout)
//!   - Telegram (long-polling)
//!   - Discord (WebSocket gateway)
//!   - Slack (polling conversations.history)
//!   - WhatsApp (webhook-based)
//!   - Matrix (long-polling /sync)
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

    pub fn deinit(self: *const ChannelMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.sender);
        allocator.free(self.content);
        allocator.free(self.channel);
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
        send: *const fn (ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void,
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

    pub fn send(self: Channel, target: []const u8, message: []const u8) !void {
        return self.vtable.send(self.ptr, target, message);
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
pub const irc = @import("irc.zig");
pub const imessage = @import("imessage.zig");
pub const email = @import("email.zig");
pub const lark = @import("lark.zig");
pub const dingtalk = @import("dingtalk.zig");
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
        while (split_at > 0 and (self.remaining[split_at] & 0xC0) == 0x80) {
            split_at -= 1;
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

test {
    @import("std").testing.refAllDecls(@This());
}
