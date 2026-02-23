//! Event Bus — inter-component message bus for nullClaw.
//!
//! Two blocking queues (inbound: channels→agent, outbound: agent→channels)
//! on a ring buffer with Mutex+Condition. Foundation for Session Manager,
//! Message tool, Heartbeat execution, Cron dispatch, USB hotplug.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

pub const InboundMessage = struct {
    channel: []const u8, // "telegram", "discord", "webhook", "system"
    sender_id: []const u8, // sender identifier
    chat_id: []const u8, // chat/room identifier
    content: []const u8, // message text
    session_key: []const u8, // "channel:chatID" for session lookup
    media: []const []const u8 = &.{}, // file paths/URLs (images, voice, docs)
    metadata_json: ?[]const u8 = null, // channel-specific JSON (message_id, thread_ts, is_group)

    pub fn deinit(self: *const InboundMessage, allocator: Allocator) void {
        for (self.media) |m| allocator.free(m);
        if (self.media.len > 0) allocator.free(self.media);
        if (self.metadata_json) |md| allocator.free(md);
        // channel is a string literal or long-lived config pointer — not owned, don't free
        allocator.free(self.sender_id);
        allocator.free(self.chat_id);
        allocator.free(self.content);
        allocator.free(self.session_key);
    }
};

pub const OutboundMessage = struct {
    channel: []const u8, // target channel
    account_id: ?[]const u8 = null, // target account (multi-account channels)
    chat_id: []const u8, // target chat
    content: []const u8, // response text
    media: []const []const u8 = &.{}, // file paths/URLs to send

    pub fn deinit(self: *const OutboundMessage, allocator: Allocator) void {
        for (self.media) |m| allocator.free(m);
        if (self.media.len > 0) allocator.free(self.media);
        // channel is a string literal or long-lived config pointer — not owned, don't free
        if (self.account_id) |aid| allocator.free(aid);
        allocator.free(self.chat_id);
        allocator.free(self.content);
    }
};

// ---------------------------------------------------------------------------
// Helpers — duplicate all strings so producer can free its originals
// ---------------------------------------------------------------------------

pub fn makeInbound(
    allocator: Allocator,
    channel: []const u8,
    sender_id: []const u8,
    chat_id: []const u8,
    content: []const u8,
    session_key: []const u8,
) Allocator.Error!InboundMessage {
    // channel is not duped — must be a literal or long-lived config pointer
    const sid = try allocator.dupe(u8, sender_id);
    errdefer allocator.free(sid);
    const cid = try allocator.dupe(u8, chat_id);
    errdefer allocator.free(cid);
    const ct = try allocator.dupe(u8, content);
    errdefer allocator.free(ct);
    const sk = try allocator.dupe(u8, session_key);

    return .{
        .channel = channel,
        .sender_id = sid,
        .chat_id = cid,
        .content = ct,
        .session_key = sk,
    };
}

/// Create an InboundMessage with media and metadata.
pub fn makeInboundFull(
    allocator: Allocator,
    channel: []const u8,
    sender_id: []const u8,
    chat_id: []const u8,
    content: []const u8,
    session_key: []const u8,
    media_src: []const []const u8,
    metadata_json: ?[]const u8,
) Allocator.Error!InboundMessage {
    // channel is not duped — must be a literal or long-lived config pointer
    const sid = try allocator.dupe(u8, sender_id);
    errdefer allocator.free(sid);
    const cid = try allocator.dupe(u8, chat_id);
    errdefer allocator.free(cid);
    const ct = try allocator.dupe(u8, content);
    errdefer allocator.free(ct);
    const sk = try allocator.dupe(u8, session_key);
    errdefer allocator.free(sk);

    // Dupe media array
    const media = if (media_src.len > 0) blk: {
        const arr = try allocator.alloc([]const u8, media_src.len);
        var i: usize = 0;
        errdefer {
            for (arr[0..i]) |m| allocator.free(m);
            allocator.free(arr);
        }
        while (i < media_src.len) : (i += 1) {
            arr[i] = try allocator.dupe(u8, media_src[i]);
        }
        break :blk arr;
    } else &[_][]const u8{};

    errdefer {
        if (media.len > 0) {
            for (media) |m| allocator.free(m);
            allocator.free(media);
        }
    }

    const md = if (metadata_json) |mj| try allocator.dupe(u8, mj) else null;

    return .{
        .channel = channel,
        .sender_id = sid,
        .chat_id = cid,
        .content = ct,
        .session_key = sk,
        .media = media,
        .metadata_json = md,
    };
}

pub fn makeOutbound(
    allocator: Allocator,
    channel: []const u8,
    chat_id: []const u8,
    content: []const u8,
) Allocator.Error!OutboundMessage {
    // channel is not duped — must be a literal or long-lived config pointer
    const cid = try allocator.dupe(u8, chat_id);
    errdefer allocator.free(cid);
    const ct = try allocator.dupe(u8, content);

    return .{
        .channel = channel,
        .chat_id = cid,
        .content = ct,
    };
}

pub fn makeOutboundWithAccount(
    allocator: Allocator,
    channel: []const u8,
    account_id: []const u8,
    chat_id: []const u8,
    content: []const u8,
) Allocator.Error!OutboundMessage {
    const cid = try allocator.dupe(u8, chat_id);
    errdefer allocator.free(cid);
    const ct = try allocator.dupe(u8, content);
    errdefer allocator.free(ct);
    const aid = try allocator.dupe(u8, account_id);

    return .{
        .channel = channel,
        .account_id = aid,
        .chat_id = cid,
        .content = ct,
    };
}

/// Create an OutboundMessage with media attachments.
fn makeOutboundWithMedia(
    allocator: Allocator,
    channel: []const u8,
    chat_id: []const u8,
    content: []const u8,
    media_src: []const []const u8,
) Allocator.Error!OutboundMessage {
    // channel is not duped — must be a literal or long-lived config pointer
    const cid = try allocator.dupe(u8, chat_id);
    errdefer allocator.free(cid);
    const ct = try allocator.dupe(u8, content);
    errdefer allocator.free(ct);

    const media = if (media_src.len > 0) blk: {
        const arr = try allocator.alloc([]const u8, media_src.len);
        var i: usize = 0;
        errdefer {
            for (arr[0..i]) |m| allocator.free(m);
            allocator.free(arr);
        }
        while (i < media_src.len) : (i += 1) {
            arr[i] = try allocator.dupe(u8, media_src[i]);
        }
        break :blk arr;
    } else &[_][]const u8{};

    return .{
        .channel = channel,
        .chat_id = cid,
        .content = ct,
        .media = media,
    };
}

// ---------------------------------------------------------------------------
// BoundedQueue — generic ring buffer with Mutex + Condition
// ---------------------------------------------------------------------------

pub fn BoundedQueue(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();

        buf: [capacity]T = undefined,
        head: usize = 0,
        tail: usize = 0,
        len: usize = 0,
        closed: bool = false,
        mutex: std.Thread.Mutex = .{},
        not_empty: std.Thread.Condition = .{},
        not_full: std.Thread.Condition = .{},

        pub fn init() Self {
            return .{};
        }

        /// Blocks if the queue is full. Returns error.Closed if the bus is closed.
        pub fn publish(self: *Self, item: T) error{Closed}!void {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.len == capacity and !self.closed) {
                self.not_full.wait(&self.mutex);
            }
            if (self.closed) return error.Closed;

            self.buf[self.tail] = item;
            self.tail = (self.tail + 1) % capacity;
            self.len += 1;

            self.not_empty.signal();
        }

        /// Blocks if the queue is empty. Returns null if closed and the queue is empty.
        pub fn consume(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.len == 0 and !self.closed) {
                self.not_empty.wait(&self.mutex);
            }
            if (self.len == 0) return null; // closed + drained

            const item = self.buf[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;

            self.not_full.signal();
            return item;
        }

        /// Closes the queue, waking all waiting threads.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.closed = true;
            self.not_empty.broadcast();
            self.not_full.broadcast();
        }

        /// Current queue depth (for metrics).
        pub fn depth(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.len;
        }
    };
}

// ---------------------------------------------------------------------------
// Bus — top-level structure
// ---------------------------------------------------------------------------

pub const QUEUE_CAPACITY: usize = 100;

pub const Bus = struct {
    inbound: BoundedQueue(InboundMessage, QUEUE_CAPACITY) = .{},
    outbound: BoundedQueue(OutboundMessage, QUEUE_CAPACITY) = .{},

    pub fn init() Bus {
        return .{};
    }

    // -- Inbound: channels/gateway → agent --

    pub fn publishInbound(self: *Bus, msg: InboundMessage) error{Closed}!void {
        return self.inbound.publish(msg);
    }

    pub fn consumeInbound(self: *Bus) ?InboundMessage {
        return self.inbound.consume();
    }

    // -- Outbound: agent/cron/heartbeat → channels --

    pub fn publishOutbound(self: *Bus, msg: OutboundMessage) error{Closed}!void {
        return self.outbound.publish(msg);
    }

    pub fn consumeOutbound(self: *Bus) ?OutboundMessage {
        return self.outbound.consume();
    }

    // -- Lifecycle --

    pub fn close(self: *Bus) void {
        self.inbound.close();
        self.outbound.close();
    }

    // -- Metrics --

    pub fn inboundDepth(self: *Bus) usize {
        return self.inbound.depth();
    }

    pub fn outboundDepth(self: *Bus) usize {
        return self.outbound.depth();
    }
};

// ===========================================================================
// Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. Struct tests
// ---------------------------------------------------------------------------

test "InboundMessage.deinit frees all fields" {
    const alloc = testing.allocator;
    var msg = try makeInbound(alloc, "telegram", "user1", "chat42", "hello", "telegram:chat42");
    msg.deinit(alloc);
}

test "OutboundMessage.deinit frees all fields" {
    const alloc = testing.allocator;
    var msg = try makeOutbound(alloc, "discord", "room7", "world");
    msg.deinit(alloc);
}

test "makeInbound produces owned copies of non-channel fields" {
    const alloc = testing.allocator;
    var src_content = try alloc.dupe(u8, "body");
    defer alloc.free(src_content);

    const msg = try makeInbound(alloc, "webhook", "s", "c", src_content, "webhook:c");
    defer msg.deinit(alloc);

    // Mutate source — message must be unaffected (channel is borrowed, not duped)
    src_content[0] = 'X';
    try testing.expectEqualStrings("body", msg.content);
    try testing.expectEqualStrings("webhook", msg.channel);
}

test "makeOutbound produces owned copies" {
    const alloc = testing.allocator;
    var src_content = try alloc.dupe(u8, "reply");
    defer alloc.free(src_content);

    const msg = try makeOutbound(alloc, "telegram", "c1", src_content);
    defer msg.deinit(alloc);

    src_content[0] = 'Z';
    try testing.expectEqualStrings("reply", msg.content);
}

test "makeOutboundWithAccount stores account_id" {
    const alloc = testing.allocator;
    const msg = try makeOutboundWithAccount(alloc, "telegram", "backup", "c1", "reply");
    defer msg.deinit(alloc);
    try testing.expect(msg.account_id != null);
    try testing.expectEqualStrings("backup", msg.account_id.?);
}

// ---------------------------------------------------------------------------
// 2. Queue tests
// ---------------------------------------------------------------------------

test "queue init has zero depth" {
    var q = BoundedQueue(u32, 4).init();
    try testing.expectEqual(@as(usize, 0), q.depth());
}

test "queue publish + consume single item" {
    var q = BoundedQueue(u32, 4).init();
    try q.publish(42);
    try testing.expectEqual(@as(usize, 1), q.depth());
    const v = q.consume();
    try testing.expectEqual(@as(u32, 42), v.?);
    try testing.expectEqual(@as(usize, 0), q.depth());
}

test "queue FIFO order" {
    var q = BoundedQueue(u32, 8).init();
    for (0..5) |i| {
        try q.publish(@intCast(i));
    }
    for (0..5) |i| {
        try testing.expectEqual(@as(u32, @intCast(i)), q.consume().?);
    }
}

test "queue fill to capacity" {
    var q = BoundedQueue(u32, 4).init();
    for (0..4) |i| {
        try q.publish(@intCast(i));
    }
    try testing.expectEqual(@as(usize, 4), q.depth());
    // Consume one to make room
    _ = q.consume();
    try testing.expectEqual(@as(usize, 3), q.depth());
    try q.publish(99);
    try testing.expectEqual(@as(usize, 4), q.depth());
}

test "queue close wakes consumer — returns null" {
    var q = BoundedQueue(u32, 4).init();

    const handle = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, struct {
        fn run(qp: *BoundedQueue(u32, 4)) void {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            qp.close();
        }
    }.run, .{&q});

    const val = q.consume(); // blocks until close
    try testing.expect(val == null);
    handle.join();
}

test "queue close returns Closed to producer" {
    var q = BoundedQueue(u32, 2).init();
    q.close();
    try testing.expectError(error.Closed, q.publish(1));
}

test "queue depth reflects current length" {
    var q = BoundedQueue(u32, 8).init();
    try q.publish(1);
    try q.publish(2);
    try testing.expectEqual(@as(usize, 2), q.depth());
    _ = q.consume();
    try testing.expectEqual(@as(usize, 1), q.depth());
}

// ---------------------------------------------------------------------------
// 3. Bus integration tests
// ---------------------------------------------------------------------------

test "bus roundtrip inbound" {
    const alloc = testing.allocator;
    var bus = Bus.init();
    defer bus.close();

    const msg = try makeInbound(alloc, "telegram", "user1", "chat1", "hi", "telegram:chat1");
    try bus.publishInbound(msg);
    try testing.expectEqual(@as(usize, 1), bus.inboundDepth());

    var got = bus.consumeInbound().?;
    defer got.deinit(alloc);
    try testing.expectEqualStrings("hi", got.content);
    try testing.expectEqualStrings("telegram:chat1", got.session_key);
}

test "bus roundtrip outbound" {
    const alloc = testing.allocator;
    var bus = Bus.init();
    defer bus.close();

    const msg = try makeOutbound(alloc, "discord", "room1", "pong");
    try bus.publishOutbound(msg);
    try testing.expectEqual(@as(usize, 1), bus.outboundDepth());

    var got = bus.consumeOutbound().?;
    defer got.deinit(alloc);
    try testing.expectEqualStrings("pong", got.content);
}

test "bus close stops both queues" {
    var bus = Bus.init();
    bus.close();

    const alloc = testing.allocator;
    const in_msg = try makeInbound(alloc, "x", "x", "x", "x", "x:x");
    try testing.expectError(error.Closed, bus.publishInbound(in_msg));
    in_msg.deinit(alloc);

    const out_msg = try makeOutbound(alloc, "x", "x", "x");
    try testing.expectError(error.Closed, bus.publishOutbound(out_msg));
    out_msg.deinit(alloc);
}

test "bus close is idempotent" {
    var bus = Bus.init();
    bus.close();
    bus.close();
    bus.close();
    // No crash — idempotent
}

test "bus multiple inbound producers" {
    const alloc = testing.allocator;
    var bus = Bus.init();
    defer bus.close();

    const num_threads = 5;
    const msgs_per_thread = 10;

    var handles: [num_threads]std.Thread = undefined;
    for (0..num_threads) |t| {
        handles[t] = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, struct {
            fn run(b: *Bus, tid: usize, a: Allocator) void {
                for (0..msgs_per_thread) |i| {
                    var id_buf: [32]u8 = undefined;
                    const id_str = std.fmt.bufPrint(&id_buf, "{d}:{d}", .{ tid, i }) catch "?";
                    const msg = makeInbound(a, "test", id_str, "c", "body", "test:c") catch return;
                    b.publishInbound(msg) catch return;
                }
            }
        }.run, .{ &bus, t, alloc });
    }

    var count: usize = 0;
    // Consumer: drain until we have all messages
    while (count < num_threads * msgs_per_thread) {
        if (bus.consumeInbound()) |msg| {
            msg.deinit(alloc);
            count += 1;
        }
    }

    for (handles) |h| h.join();
    try testing.expectEqual(num_threads * msgs_per_thread, count);
}

// ---------------------------------------------------------------------------
// 4. Stress test
// ---------------------------------------------------------------------------

test "bus stress: 10 producers × 100 messages" {
    const alloc = testing.allocator;
    var bus = Bus.init();

    const num_threads = 10;
    const msgs_per_thread = 100;
    const total = num_threads * msgs_per_thread;

    var producers: [num_threads]std.Thread = undefined;
    for (0..num_threads) |t| {
        producers[t] = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, struct {
            fn run(b: *Bus, tid: usize, a: Allocator) void {
                for (0..msgs_per_thread) |i| {
                    var id_buf: [32]u8 = undefined;
                    const id_str = std.fmt.bufPrint(&id_buf, "{d}:{d}", .{ tid, i }) catch "?";
                    const msg = makeInbound(a, "stress", id_str, "c", "x", "stress:c") catch return;
                    b.publishInbound(msg) catch return;
                }
            }
        }.run, .{ &bus, t, alloc });
    }

    var count: usize = 0;
    const consumer = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, struct {
        fn run(b: *Bus, cnt: *usize, a: Allocator) void {
            while (b.consumeInbound()) |msg| {
                msg.deinit(a);
                cnt.* += 1;
            }
        }
    }.run, .{ &bus, &count, alloc });

    for (producers) |p| p.join();
    bus.close();
    consumer.join();

    try testing.expectEqual(total, count);
}

// ---------------------------------------------------------------------------
// Extra edge-case tests
// ---------------------------------------------------------------------------

test "queue wraparound ring buffer" {
    var q = BoundedQueue(u32, 4).init();
    // Fill and drain twice to exercise wraparound
    for (0..2) |_| {
        for (0..4) |i| try q.publish(@intCast(i));
        for (0..4) |i| try testing.expectEqual(@as(u32, @intCast(i)), q.consume().?);
    }
    try testing.expectEqual(@as(usize, 0), q.depth());
}

test "queue consume drains remaining after close" {
    var q = BoundedQueue(u32, 8).init();
    try q.publish(10);
    try q.publish(20);
    q.close();
    // Should still be able to drain existing items
    try testing.expectEqual(@as(u32, 10), q.consume().?);
    try testing.expectEqual(@as(u32, 20), q.consume().?);
    // Then null
    try testing.expect(q.consume() == null);
}

test "queue publish after close always errors" {
    var q = BoundedQueue(u32, 4).init();
    try q.publish(1);
    q.close();
    try testing.expectError(error.Closed, q.publish(2));
}

test "bus inbound and outbound are independent" {
    const alloc = testing.allocator;
    var bus = Bus.init();
    defer bus.close();

    const in_msg = try makeInbound(alloc, "ch", "s", "c", "in", "ch:c");
    try bus.publishInbound(in_msg);

    const out_msg = try makeOutbound(alloc, "ch", "c", "out");
    try bus.publishOutbound(out_msg);

    try testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    try testing.expectEqual(@as(usize, 1), bus.outboundDepth());

    var got_in = bus.consumeInbound().?;
    defer got_in.deinit(alloc);
    try testing.expectEqualStrings("in", got_in.content);

    var got_out = bus.consumeOutbound().?;
    defer got_out.deinit(alloc);
    try testing.expectEqualStrings("out", got_out.content);
}

// ---------------------------------------------------------------------------
// 5. Media + Metadata tests
// ---------------------------------------------------------------------------

test "InboundMessage with media and metadata" {
    const alloc = testing.allocator;
    const media_src = [_][]const u8{ "/tmp/photo.jpg", "/tmp/voice.ogg" };
    var msg = try makeInboundFull(
        alloc,
        "telegram",
        "user1",
        "chat1",
        "see photo",
        "telegram:chat1",
        &media_src,
        "{\"message_id\":123,\"is_group\":true}",
    );
    defer msg.deinit(alloc);

    try testing.expectEqual(@as(usize, 2), msg.media.len);
    try testing.expectEqualStrings("/tmp/photo.jpg", msg.media[0]);
    try testing.expectEqualStrings("/tmp/voice.ogg", msg.media[1]);
    try testing.expectEqualStrings("{\"message_id\":123,\"is_group\":true}", msg.metadata_json.?);
}

test "InboundMessage without media defaults to empty" {
    const alloc = testing.allocator;
    var msg = try makeInbound(alloc, "ch", "s", "c", "hi", "ch:c");
    defer msg.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), msg.media.len);
    try testing.expect(msg.metadata_json == null);
}

test "OutboundMessage with media" {
    const alloc = testing.allocator;
    const media_src = [_][]const u8{"/tmp/result.png"};
    var msg = try makeOutboundWithMedia(alloc, "discord", "room1", "here", &media_src);
    defer msg.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), msg.media.len);
    try testing.expectEqualStrings("/tmp/result.png", msg.media[0]);
}

test "OutboundMessage without media defaults to empty" {
    const alloc = testing.allocator;
    var msg = try makeOutbound(alloc, "ch", "c", "hi");
    defer msg.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), msg.media.len);
}

test "makeInboundFull with null metadata" {
    const alloc = testing.allocator;
    var msg = try makeInboundFull(alloc, "ch", "s", "c", "hi", "ch:c", &.{}, null);
    defer msg.deinit(alloc);
    try testing.expect(msg.metadata_json == null);
    try testing.expectEqual(@as(usize, 0), msg.media.len);
}

test "makeInboundFull media is owned copy" {
    const alloc = testing.allocator;
    var src = try alloc.dupe(u8, "/tmp/test.jpg");
    defer alloc.free(src);
    const media_src = [_][]const u8{src};
    var msg = try makeInboundFull(alloc, "ch", "s", "c", "hi", "ch:c", &media_src, null);
    defer msg.deinit(alloc);
    src[0] = 'X';
    try testing.expectEqualStrings("/tmp/test.jpg", msg.media[0]);
}

test "bus outbound multiple producers" {
    const alloc = testing.allocator;
    var bus = Bus.init();
    defer bus.close();

    const num_threads = 5;
    const msgs_per_thread = 10;

    var handles: [num_threads]std.Thread = undefined;
    for (0..num_threads) |t| {
        handles[t] = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, struct {
            fn run(b: *Bus, tid: usize, a: Allocator) void {
                for (0..msgs_per_thread) |i| {
                    var id_buf: [32]u8 = undefined;
                    const id_str = std.fmt.bufPrint(&id_buf, "{d}:{d}", .{ tid, i }) catch "?";
                    const msg = makeOutbound(a, "test", id_str, "reply") catch return;
                    b.publishOutbound(msg) catch return;
                }
            }
        }.run, .{ &bus, t, alloc });
    }

    var count: usize = 0;
    while (count < num_threads * msgs_per_thread) {
        if (bus.consumeOutbound()) |msg| {
            msg.deinit(alloc);
            count += 1;
        }
    }

    for (handles) |h| h.join();
    try testing.expectEqual(num_threads * msgs_per_thread, count);
}
