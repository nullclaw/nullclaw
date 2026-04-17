const std = @import("std");
const root = @import("root.zig");

pub const TEXT_MESSAGE_DEBOUNCE_SECS: u64 = 3;
pub const LARGE_TEXT_CHAIN_DEBOUNCE_SECS: u64 = 8;
pub const LARGE_TEXT_CHAIN_MIN_PARTS: usize = 4;
pub const LARGE_TEXT_CHAIN_MIN_BYTES: usize = 16 * 1024;
pub const TEXT_SPLIT_LIKELY_MIN_LEN: usize = 500;

pub const PendingTextChainStats = struct {
    latest: u64,
    parts: usize,
    total_bytes: usize,
};

fn sameSenderAndChat(a: root.ChannelMessage, b: root.ChannelMessage) bool {
    return std.mem.eql(u8, a.sender, b.sender) and std.mem.eql(u8, a.id, b.id);
}

fn sameChat(a: root.ChannelMessage, b: root.ChannelMessage) bool {
    return std.mem.eql(u8, a.sender, b.sender);
}

fn matchesPendingTextKey(msg: root.ChannelMessage, id: []const u8, sender: []const u8) bool {
    return std.mem.eql(u8, msg.id, id) and std.mem.eql(u8, msg.sender, sender);
}

fn hasMessageId(msg: root.ChannelMessage) bool {
    return msg.message_id != null;
}

fn isLikelySplitTextChunk(msg: root.ChannelMessage) bool {
    return msg.content.len >= TEXT_SPLIT_LIKELY_MIN_LEN;
}

pub fn isSlashCommandMessage(content: []const u8) bool {
    const trimmed = std.mem.trim(u8, content, " \t\r\n");
    return std.mem.startsWith(u8, trimmed, "/");
}

pub fn pendingTextChainStatsForKey(
    id: []const u8,
    sender: []const u8,
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
) ?PendingTextChainStats {
    const n = @min(pending_messages.len, received_at.len);
    var seen = false;
    var latest: u64 = 0;
    var parts: usize = 0;
    var total_bytes: usize = 0;
    for (0..n) |i| {
        const msg = pending_messages[i];
        if (!matchesPendingTextKey(msg, id, sender)) continue;
        if (!seen or received_at[i] > latest) latest = received_at[i];
        seen = true;
        parts += 1;
        total_bytes += msg.content.len;
    }
    if (!seen) return null;
    return .{ .latest = latest, .parts = parts, .total_bytes = total_bytes };
}

pub fn textDebounceSecsForChainWithBase(parts: usize, total_bytes: usize, base_debounce_secs: u64) u64 {
    if (base_debounce_secs == 0) return 0;
    if (parts >= LARGE_TEXT_CHAIN_MIN_PARTS or total_bytes >= LARGE_TEXT_CHAIN_MIN_BYTES) {
        return @max(base_debounce_secs, LARGE_TEXT_CHAIN_DEBOUNCE_SECS);
    }
    return base_debounce_secs;
}

pub fn textDebounceSecsForChain(parts: usize, total_bytes: usize) u64 {
    return textDebounceSecsForChainWithBase(parts, total_bytes, TEXT_MESSAGE_DEBOUNCE_SECS);
}

fn chainStillWarm(now: u64, stats: PendingTextChainStats, base_debounce_secs: u64) bool {
    const debounce_secs = textDebounceSecsForChainWithBase(
        stats.parts,
        stats.total_bytes,
        base_debounce_secs,
    );
    if (debounce_secs == 0) return false;
    return now <= stats.latest + debounce_secs;
}

fn chainIsMature(now: u64, stats: PendingTextChainStats, base_debounce_secs: u64) bool {
    return !chainStillWarm(now, stats, base_debounce_secs);
}

pub fn pendingTextBuffersInSync(
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
) bool {
    return pending_messages.len == received_at.len;
}

pub fn nextPendingTextDeadline(
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
) ?u64 {
    return nextPendingTextDeadlineWithBase(pending_messages, received_at, TEXT_MESSAGE_DEBOUNCE_SECS);
}

pub fn nextPendingTextDeadlineWithBase(
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
    base_debounce_secs: u64,
) ?u64 {
    if (base_debounce_secs == 0) return null;

    const n = @min(pending_messages.len, received_at.len);
    var seen = false;
    var next_deadline: u64 = 0;
    for (0..n) |i| {
        const stats = pendingTextChainStatsForKey(
            pending_messages[i].id,
            pending_messages[i].sender,
            pending_messages,
            received_at,
        ) orelse continue;
        const deadline = stats.latest + textDebounceSecsForChainWithBase(
            stats.parts,
            stats.total_bytes,
            base_debounce_secs,
        );
        if (!seen or deadline < next_deadline) next_deadline = deadline;
        seen = true;
    }
    return if (seen) next_deadline else null;
}

pub fn shouldDebounceTextMessage(
    now: u64,
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
    msg: root.ChannelMessage,
) bool {
    return shouldDebounceTextMessageWithBase(
        now,
        pending_messages,
        received_at,
        msg,
        TEXT_MESSAGE_DEBOUNCE_SECS,
    );
}

pub fn shouldDebounceTextMessageWithBase(
    now: u64,
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
    msg: root.ChannelMessage,
    base_debounce_secs: u64,
) bool {
    if (base_debounce_secs == 0) return false;
    if (!hasMessageId(msg)) return false;
    if (msg.is_interaction) return false;
    if (isSlashCommandMessage(msg.content)) return false;
    if (isLikelySplitTextChunk(msg)) return true;

    const stats = pendingTextChainStatsForKey(
        msg.id,
        msg.sender,
        pending_messages,
        received_at,
    ) orelse return false;
    return chainStillWarm(now, stats, base_debounce_secs);
}

pub fn pendingTextChainMatureAtIndex(
    now: u64,
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
    index: usize,
) bool {
    return pendingTextChainMatureAtIndexWithBase(
        now,
        pending_messages,
        received_at,
        index,
        TEXT_MESSAGE_DEBOUNCE_SECS,
    );
}

pub fn pendingTextChainMatureAtIndexWithBase(
    now: u64,
    pending_messages: []const root.ChannelMessage,
    received_at: []const u64,
    index: usize,
    base_debounce_secs: u64,
) bool {
    if (index >= pending_messages.len or index >= received_at.len) return false;

    const msg = pending_messages[index];
    const stats = pendingTextChainStatsForKey(
        msg.id,
        msg.sender,
        pending_messages,
        received_at,
    ) orelse return false;
    return chainIsMature(now, stats, base_debounce_secs);
}

pub fn cancelPendingTextChainForKey(
    allocator: std.mem.Allocator,
    pending_messages: *std.ArrayListUnmanaged(root.ChannelMessage),
    received_at: *std.ArrayListUnmanaged(u64),
    id: []const u8,
    sender: []const u8,
) void {
    var i: usize = 0;
    while (i < pending_messages.items.len and i < received_at.items.len) {
        const pending = pending_messages.items[i];
        if (!matchesPendingTextKey(pending, id, sender)) {
            i += 1;
            continue;
        }

        const removed = pending_messages.orderedRemove(i);
        _ = received_at.orderedRemove(i);
        removed.deinit(allocator);
    }
}

fn findNextMergeCandidateIndex(messages: []const root.ChannelMessage, start: usize) ?usize {
    const current = messages[start];
    const current_message_id = current.message_id orelse return null;
    for (start + 1..messages.len) |idx| {
        const next = messages[idx];
        if (!sameChat(current, next)) continue;
        if (!sameSenderAndChat(current, next)) break;
        const next_message_id = next.message_id orelse break;
        if (isSlashCommandMessage(next.content)) break;

        // Never merge synthetic messages from interactions (like button clicks)
        // or messages with identical IDs (reused bot message IDs).
        if (current.is_interaction or next.is_interaction or next_message_id == current_message_id) break;

        const split_like = isLikelySplitTextChunk(current) or isLikelySplitTextChunk(next);
        // Only merge if consecutive.
        if (next_message_id == current_message_id + 1) {
            // Merge if split-like OR just regular text messages (to avoid turn fragmentation).
            return idx;
        } else if (split_like) {
            // Non-consecutive but one is very long? Still risky but kept for
            // compatibility with very large split chains where some IDs might be
            // skipped or filtered.
            return idx;
        }
        break;
    }
    return null;
}

fn buildMergedContent(
    allocator: std.mem.Allocator,
    first: []const u8,
    second: []const u8,
) ?[]u8 {
    var merged: std.ArrayListUnmanaged(u8) = .empty;
    defer merged.deinit(allocator);

    merged.appendSlice(allocator, first) catch return null;
    merged.appendSlice(allocator, "\n") catch return null;
    merged.appendSlice(allocator, second) catch return null;
    return merged.toOwnedSlice(allocator) catch null;
}

fn replaceMergedContent(
    allocator: std.mem.Allocator,
    dst: *root.ChannelMessage,
    src: root.ChannelMessage,
) bool {
    const new_content = buildMergedContent(allocator, dst.content, src.content) orelse return false;
    allocator.free(dst.content);
    dst.content = new_content;
    dst.message_id = src.message_id;
    return true;
}

pub fn mergeConsecutiveMessages(
    allocator: std.mem.Allocator,
    messages: *std.ArrayListUnmanaged(root.ChannelMessage),
) void {
    if (messages.items.len <= 1) return;

    var i: usize = 0;
    while (i < messages.items.len) {
        if (!hasMessageId(messages.items[i])) {
            i += 1;
            continue;
        }
        if (isSlashCommandMessage(messages.items[i].content)) {
            i += 1;
            continue;
        }

        const found_idx = findNextMergeCandidateIndex(messages.items, i) orelse {
            i += 1;
            continue;
        };

        if (!replaceMergedContent(allocator, &messages.items[i], messages.items[found_idx])) {
            i += 1;
            continue;
        }

        var extra = messages.orderedRemove(found_idx);
        extra.deinit(allocator);
    }
}

test "telegram ingress mergeConsecutiveMessages does not merge synthetic interactions" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    // User message (ID 100)
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Do check?", 100);
    // Synthetic interaction message from button click (reusing assistant's ID 101)
    // Even though 101 == 100 + 1, it represents a separate interaction and should not be merged.
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "Yes, please"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 101,
        .is_interaction = true,
    });

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("Do check?", messages.items[0].content);
    try std.testing.expectEqualStrings("Yes, please", messages.items[1].content);
}

test "telegram ingress mergeConsecutiveMessages does not merge identical IDs" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "First", 100);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Second", 100);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
}

test "telegram ingress mergeConsecutiveMessages still merges split text" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    const split_like = try alloc.alloc(u8, TEXT_SPLIT_LIKELY_MIN_LEN);
    @memset(split_like, 'x');

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = split_like,
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 100,
    });
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "tail", 101);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
}

fn appendOwnedTestMessage(
    allocator: std.mem.Allocator,
    messages: *std.ArrayListUnmanaged(root.ChannelMessage),
    id: []const u8,
    sender: []const u8,
    content: []const u8,
    message_id: ?i64,
) !void {
    const id_dup = try allocator.dupe(u8, id);
    errdefer allocator.free(id_dup);
    const sender_dup = try allocator.dupe(u8, sender);
    errdefer allocator.free(sender_dup);
    const content_dup = try allocator.dupe(u8, content);
    errdefer allocator.free(content_dup);

    try messages.append(allocator, .{
        .id = id_dup,
        .sender = sender_dup,
        .content = content_dup,
        .channel = "telegram",
        .timestamp = 0,
        .message_id = message_id,
    });
}

fn deinitOwnedTestMessages(
    allocator: std.mem.Allocator,
    messages: *std.ArrayListUnmanaged(root.ChannelMessage),
) void {
    for (messages.items) |msg| {
        var tmp = msg;
        tmp.deinit(allocator);
    }
    messages.deinit(allocator);
}

fn testMessage(id: []const u8, sender: []const u8, content: []const u8, timestamp: u64, message_id: ?i64) root.ChannelMessage {
    return .{
        .id = id,
        .sender = sender,
        .content = content,
        .channel = "telegram",
        .timestamp = timestamp,
        .message_id = message_id,
    };
}

test "telegram ingress mergeConsecutiveMessages handles interleaved chats" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Part 1", 10);
    try appendOwnedTestMessage(alloc, &messages, "user2", "chat2", "Hello from chat 2", 50);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Part 2", 11);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("Part 1\nPart 2", messages.items[0].content);
    try std.testing.expectEqual(@as(i64, 11), messages.items[0].message_id.?);
    try std.testing.expectEqualStrings("Hello from chat 2", messages.items[1].content);
}

test "telegram ingress mergeConsecutiveMessages stops at interleaved sender in same chat" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Part 1", 10);
    try appendOwnedTestMessage(alloc, &messages, "user2", "chat1", "Interrupting reply", 11);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Part 2", 12);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 3), messages.items.len);
    try std.testing.expectEqualStrings("Part 1", messages.items[0].content);
    try std.testing.expectEqualStrings("Interrupting reply", messages.items[1].content);
    try std.testing.expectEqualStrings("Part 2", messages.items[2].content);
}

test "telegram ingress mergeConsecutiveMessages skips commands" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "/help", 10);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "some text", 11);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("/help", messages.items[0].content);
    try std.testing.expectEqualStrings("some text", messages.items[1].content);
}

test "telegram ingress mergeConsecutiveMessages skips whitespace-padded commands" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", " \t/help", 10);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "some text", 11);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "\n/new", 12);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 3), messages.items.len);
    try std.testing.expectEqualStrings(" \t/help", messages.items[0].content);
    try std.testing.expectEqualStrings("some text", messages.items[1].content);
    try std.testing.expectEqualStrings("\n/new", messages.items[2].content);
}

test "telegram ingress mergeConsecutiveMessages chain merges three parts" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "A", 1);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "B", 2);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "C", 3);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("A\nB\nC", messages.items[0].content);
    try std.testing.expectEqual(@as(i64, 3), messages.items[0].message_id.?);
}

test "telegram ingress mergeConsecutiveMessages single message no-op" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Hello", 42);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("Hello", messages.items[0].content);
}

test "telegram ingress shouldDebounceTextMessage handles long chunk and active chain" {
    const alloc = std.testing.allocator;
    var pending_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &pending_messages);
    var received_at: std.ArrayListUnmanaged(u64) = .empty;
    defer received_at.deinit(alloc);

    const now = root.nowEpochSecs();
    const long_content = try alloc.alloc(u8, TEXT_SPLIT_LIKELY_MIN_LEN);
    defer alloc.free(long_content);
    @memset(long_content, 'x');

    const long_msg = testMessage("user-a", "chat-a", long_content, now, 1);
    try std.testing.expect(shouldDebounceTextMessage(now, pending_messages.items, received_at.items, long_msg));

    const short_msg = testMessage("user-a", "chat-a", "short", now, 2);
    try std.testing.expect(!shouldDebounceTextMessage(now, pending_messages.items, received_at.items, short_msg));

    try appendOwnedTestMessage(alloc, &pending_messages, "user-a", "chat-a", "pending", 0);
    try received_at.append(alloc, now);

    try std.testing.expect(shouldDebounceTextMessage(now, pending_messages.items, received_at.items, short_msg));
}

test "telegram ingress shouldDebounceTextMessage does not debounce stale pending chain follow-up" {
    const alloc = std.testing.allocator;
    var pending_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &pending_messages);
    var received_at: std.ArrayListUnmanaged(u64) = .empty;
    defer received_at.deinit(alloc);

    const now = root.nowEpochSecs();
    const short_msg = testMessage("user-a", "chat-a", "oi", now, 77);

    try appendOwnedTestMessage(alloc, &pending_messages, "user-a", "chat-a", "pending old", 0);
    try received_at.append(alloc, now - (TEXT_MESSAGE_DEBOUNCE_SECS + 5));

    try std.testing.expect(!shouldDebounceTextMessage(now, pending_messages.items, received_at.items, short_msg));
}

test "telegram ingress shouldDebounceTextMessage skips interaction messages" {
    const now = root.nowEpochSecs();
    const interaction_msg = root.ChannelMessage{
        .id = "user-a",
        .sender = "chat-a",
        .content = "Yes, please",
        .channel = "telegram",
        .timestamp = now,
        .message_id = 77,
        .is_interaction = true,
    };

    try std.testing.expect(!shouldDebounceTextMessage(now, &.{}, &.{}, interaction_msg));
}

test "telegram ingress shouldDebounceTextMessage catches real-world ~3.4k split chunk" {
    const alloc = std.testing.allocator;
    var pending_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &pending_messages);
    var received_at: std.ArrayListUnmanaged(u64) = .empty;
    defer received_at.deinit(alloc);

    const now = root.nowEpochSecs();
    const split_like_content = try alloc.alloc(u8, 3414);
    defer alloc.free(split_like_content);
    @memset(split_like_content, 'x');

    const msg = testMessage("user-a", "chat-a", split_like_content, now, 100);
    try std.testing.expect(shouldDebounceTextMessage(now, pending_messages.items, received_at.items, msg));
}

test "telegram ingress textDebounceSecsForChain extends window for large chains" {
    try std.testing.expectEqual(@as(u64, TEXT_MESSAGE_DEBOUNCE_SECS), textDebounceSecsForChain(1, 900));
    try std.testing.expectEqual(@as(u64, LARGE_TEXT_CHAIN_DEBOUNCE_SECS), textDebounceSecsForChain(4, 900));
    try std.testing.expectEqual(@as(u64, LARGE_TEXT_CHAIN_DEBOUNCE_SECS), textDebounceSecsForChain(2, LARGE_TEXT_CHAIN_MIN_BYTES));
}

test "telegram ingress textDebounceSecsForChainWithBase honors configured debounce" {
    try std.testing.expectEqual(@as(u64, 5), textDebounceSecsForChainWithBase(1, 900, 5));
    try std.testing.expectEqual(@as(u64, 8), textDebounceSecsForChainWithBase(4, 900, 5));
    try std.testing.expectEqual(@as(u64, 0), textDebounceSecsForChainWithBase(1, 900, 0));
}

test "telegram ingress shouldDebounceTextMessage debounces medium chunk (~900 bytes)" {
    const alloc = std.testing.allocator;
    var pending_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &pending_messages);
    var received_at: std.ArrayListUnmanaged(u64) = .empty;
    defer received_at.deinit(alloc);

    const now = root.nowEpochSecs();
    const medium_content = try alloc.alloc(u8, 900);
    defer alloc.free(medium_content);
    @memset(medium_content, 'x');

    const msg = testMessage("user-b", "chat-b", medium_content, now, 101);
    try std.testing.expect(shouldDebounceTextMessage(now, pending_messages.items, received_at.items, msg));
}

test "telegram ingress mergeConsecutiveMessages does not merge short non-consecutive ids" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "First", 10);
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "Second", 15);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("First", messages.items[0].content);
    try std.testing.expectEqualStrings("Second", messages.items[1].content);
}

test "telegram ingress mergeConsecutiveMessages merges split-like non-consecutive ids" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    const split_like = try alloc.alloc(u8, TEXT_SPLIT_LIKELY_MIN_LEN);
    @memset(split_like, 'x');

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = split_like,
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 10,
    });
    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "tail", 15);

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expect(std.mem.startsWith(u8, messages.items[0].content, "xxxx"));
    try std.testing.expect(std.mem.endsWith(u8, messages.items[0].content, "\ntail"));
}

test "telegram ingress mergeConsecutiveMessages allocation failure does not leak" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &messages);

    const large_len = 32 * 1024;
    const large_payload = try alloc.alloc(u8, large_len);
    @memset(large_payload, 'x');

    try appendOwnedTestMessage(alloc, &messages, "user1", "chat1", "A", 1);
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = large_payload,
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 2,
    });

    var failing = std.testing.FailingAllocator.init(alloc, .{});
    failing.fail_index = failing.alloc_index + 1;

    mergeConsecutiveMessages(failing.allocator(), &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("A", messages.items[0].content);
    try std.testing.expectEqual(@as(usize, large_len), messages.items[1].content.len);
    try std.testing.expectEqual(@as(u8, 'x'), messages.items[1].content[0]);
}

test "telegram ingress cancelPendingTextChainForKey removes only matching sender chat chain" {
    const alloc = std.testing.allocator;
    var pending_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer deinitOwnedTestMessages(alloc, &pending_messages);
    var received_at: std.ArrayListUnmanaged(u64) = .empty;
    defer received_at.deinit(alloc);

    const now = root.nowEpochSecs();
    try appendOwnedTestMessage(alloc, &pending_messages, "user-a", "chat-a", "old-part-a1", 1);
    try received_at.append(alloc, now - 30);
    try appendOwnedTestMessage(alloc, &pending_messages, "user-a", "chat-a", "old-part-a2", 2);
    try received_at.append(alloc, now - 29);
    try appendOwnedTestMessage(alloc, &pending_messages, "user-b", "chat-b", "keep-me", 3);
    try received_at.append(alloc, now - 28);

    cancelPendingTextChainForKey(alloc, &pending_messages, &received_at, "user-a", "chat-a");

    try std.testing.expectEqual(@as(usize, 1), pending_messages.items.len);
    try std.testing.expectEqualStrings("user-b", pending_messages.items[0].id);
    try std.testing.expectEqualStrings("chat-b", pending_messages.items[0].sender);
    try std.testing.expectEqual(@as(usize, 1), received_at.items.len);
}

test "telegram ingress nextPendingTextDeadline returns earliest chain deadline" {
    const messages = [_]root.ChannelMessage{
        .{
            .id = "user-a",
            .sender = "chat-a",
            .content = "a1",
            .channel = "telegram",
            .timestamp = 0,
            .message_id = 1,
        },
        .{
            .id = "user-b",
            .sender = "chat-b",
            .content = "b1",
            .channel = "telegram",
            .timestamp = 0,
            .message_id = 100,
        },
        .{
            .id = "user-a",
            .sender = "chat-a",
            .content = "a2",
            .channel = "telegram",
            .timestamp = 0,
            .message_id = 2,
        },
    };
    const received_at = [_]u64{ 10, 9, 12 };

    const deadline = nextPendingTextDeadline(messages[0..], received_at[0..]);
    try std.testing.expect(deadline != null);
    try std.testing.expectEqual(@as(u64, 12), deadline.?);
}
