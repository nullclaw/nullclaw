const std = @import("std");
const builtin = @import("builtin");

const buffer = @import("buffer.zig");
const Compression = @import("websocket.zig").Compression;

const backend_supports_vectors = switch (builtin.zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

pub const Message = struct {
    type: Type,
    data: []u8,

    pub const Type = enum {
        text,
        binary,
        close,
        ping,
        pong,
    };

    pub const TextType = enum {
        text,
        binary,
    };
};

pub const OpCode = enum(u8) {
    text = 128 | 1,
    binary = 128 | 2,
    close = 128 | 8,
    ping = 128 | 9,
    pong = 128 | 10,
};

// The reader has a static buffer. But it can go to the BufferProvider to ask
// for a larger buffer. Depending on how it's configured, the BufferProvider could
// reject the request, return a buffer from a pool or return a dynamically allocated
// buffer.
//
// Also, when we read data from the stream, we read up to the entire buffer length
// This can result in an "over-read", meaning we might read more than a single message.
//
// Ove-reads make managing buffers complicated. In a simple case,
// we could copy any over-read back into our static buffer, but our over-read
// could be larger than our static buffer, requiring the dynamic/pooled buffer
// to be pinned for a potentially long time.
//
// The way we solve this is that when we ask the buffer provider for a larger
// buffer, we ask it for exactly the size of the message. (Even if the buffer
// comes from a pool, the buffer provider will shrink its length).
//
// In other words, when we're reading into our static buffer (which, ideally is
// most of the time), we'll over-read. But when we're reading into a dynamic buffer
// we'll only ever read 1 message, with no chance of an overread. The buffer
// management in Reader depends on this fact.
//
// TOOD: we could optimize the above. Specifically, when we get a buffer from
// the pool, we could ask for + static.data.len. This would allow us to over-read
// into a pooled buffer, yet make sure any over-read fits back into our static buffer.

pub const Reader = struct {
    // The current buffer that we're reading into. This could be our initial static buffer.
    // If the current message is larger than the static buffer (but staticer than
    // our max-allowed message), this could point to a pooled buffer from the large
    // buffer pool, or a dynamic buffer.
    buf: buffer.Buffer,

    static: []u8,

    large_buffer_provider: *buffer.Provider,

    // Position within buf that we've read into. We might read more than one
    // message in a single read, so this could span beyond 1 message.
    pos: usize,

    // Position in buf where the current message starts
    start: usize,

    // Length of the current message.
    // This is set to 0 if we don't know yet
    message_len: usize,

    // If we're dealing with a fragmented message (websocket fragment, not tcp
    // fragment), the state of the fragmented message is maintained here.)
    fragment: ?Fragmented,

    allow_compressed: bool,

    // if we returned a decompressed message, it's stored here so that we can
    // cleanup when the user is done with the message
    decompress_writer: ?buffer.Writer,

    const DecompressorType = std.compress.flate.Decompress;

    pub fn init(static: []u8, large_buffer_provider: *buffer.Provider, compression: ?Compression) Reader {
        return .{
            .pos = 0,
            .start = 0,
            .buf = .{ .type = .static, .data = static },
            .static = static,
            .message_len = 0,
            .fragment = null,
            .decompress_writer = null,
            .allow_compressed = compression != null,
            .large_buffer_provider = large_buffer_provider,
        };
    }

    pub fn deinit(self: *Reader) void {
        if (self.fragment) |*f| {
            f.deinit();
        }
        if (self.decompress_writer) |*dw| {
            dw.deinit();
        }

        // not our job to manage the static buffer, its buf was given to us an init and we
        // can't know where it came from.
        if (self.usingLargeBuffer()) {
            self.large_buffer_provider.release(self.buf);
        }
    }

    pub fn fill(self: *Reader, stream: anytype) !void {
        const pos = self.pos;
        std.debug.assert(self.buf.data.len > pos);
        const n = try stream.read(self.buf.data[pos..]);
        if (n == 0) {
            return error.Closed;
        }
        self.pos = pos + n;
    }

    pub fn read(self: *Reader) !?struct { bool, Message } {
        // read can return null if self.buf doesn't contain a full message.
        // But, because control messages can come between normal messages, we might
        // have to process more than one message per call.
        // For example, say we get a text message but it's fragmented. We can't return
        // it until we get the remaining fragments. If there's no other data in buf,
        // then we return null to signal that we need more data, as normal.
        // But if there IS more data, we need to process it then and there.

        loop: while (true) {
            const pos = self.pos;
            const start = self.start;
            var buf = self.buf.data[start..pos];

            if (buf.len < 2) {
                // not enough data yet
                return null;
            }

            const byte1 = buf[0];
            const byte2 = buf[1];
            const data_len = pos - start;

            var masked = false;
            var length_of_len: usize = 0;
            var message_len = self.message_len;

            if (message_len == 0) {
                masked, length_of_len = payloadMeta(byte2);

                // + 2 for the first 2 bytes
                if (buf.len < length_of_len + 2) {
                    // at this point, we don't have enough bytes to know the length of
                    // the message. We need more data
                    return null;
                }

                // At this point, we're sure that we have at least enough bytes to know
                // the total length of the message.
                var ml = switch (length_of_len) {
                    2 => @as(u16, @intCast(buf[3])) | @as(u16, @intCast(buf[2])) << 8,
                    8 => @as(u64, @intCast(buf[9])) | @as(u64, @intCast(buf[8])) << 8 | @as(u64, @intCast(buf[7])) << 16 | @as(u64, @intCast(buf[6])) << 24 | @as(u64, @intCast(buf[5])) << 32 | @as(u64, @intCast(buf[4])) << 40 | @as(u64, @intCast(buf[3])) << 48 | @as(u64, @intCast(buf[2])) << 56,
                    else => buf[1] & 127,
                } + length_of_len + 2; // + 2 for the 2 byte prefix

                masked = byte2 & 128 == 128;
                if (masked) {
                    // message is masked
                    ml += 4;
                }

                if (comptime builtin.target.ptrBitWidth() < 64) {
                    if (ml > std.math.maxInt(usize)) {
                        return error.TooLarge;
                    }
                }

                message_len = @intCast(ml);
                self.message_len = message_len;

                if (self.buf.data.len < message_len) {
                    // We don't have enough space in our buffer.

                    const current_buf = self.buf;
                    defer self.large_buffer_provider.release(current_buf);

                    const new_buffer = try self.large_buffer_provider.alloc(message_len);
                    @memcpy(new_buffer.data[0..data_len], current_buf.data[start..pos]);

                    self.buf = new_buffer;
                    self.start = 0;
                    self.pos = data_len;
                    buf = new_buffer.data[0..data_len];
                } else if (start > 0) {
                    // Our buffer is big enough to hold the message, but it might need to
                    // be compacted to do so.

                    const available_space = self.buf.data.len - start;
                    if (available_space < message_len) {
                        std.mem.copyForwards(u8, self.buf.data[0..data_len], self.buf.data[start..pos]);
                        self.start = 0;
                        self.pos = data_len;
                        buf = self.buf.data[0..data_len];
                    }
                }
            }

            if (data_len < message_len) {
                // we don't have enough data for the full message
                return null;
            }

            // At this point, we have a full message in buf (we might even have more than
            // 1 message, but we'll worry about that later);

            // Since we're sure we're going to process the current message, we set
            // self.message_len back to 0, so that wherever we return (or continue
            // to loop because of fragmentation), we'll start a new message from scratch.
            self.message_len = 0;

            if (length_of_len == 0) {
                masked, length_of_len = payloadMeta(byte2);
            }

            var is_continuation = false;
            var message_type: Message.Type = undefined;
            switch (byte1 & 15) {
                0 => is_continuation = true,
                1 => message_type = .text,
                2 => message_type = .binary,
                8 => message_type = .close,
                9 => message_type = .ping,
                10 => message_type = .pong,
                else => return error.InvalidMessageType,
            }

            // FIN, RSV1, RSV2, RSV3, OP,OP,OP,OP
            // RSV2 and RSV3 should never be set, and RSV1 should not be set
            // when compression is disabled
            const rsv_bits: u8 = if (self.allow_compressed == false or is_continuation) 112 else 48;
            if (byte1 & rsv_bits != 0) {
                return error.ReservedFlags;
            }

            const compressed = byte1 & 64 == 64;
            if (compressed) {
                if (self.allow_compressed == false) {
                    return error.CompressionDisabled;
                }
            }

            if (!is_continuation and length_of_len != 0 and (message_type == .ping or message_type == .close or message_type == .pong)) {
                return error.LargeControl;
            }

            const header_length = 2 + length_of_len + @as(usize, if (masked) 4 else 0);

            const fin = byte1 & 128 == 128;
            const payload = buf[header_length..message_len];

            if (masked) {
                const mask_bytes = buf[header_length - 4 .. header_length];
                mask(mask_bytes, payload);
            }

            var more = false;
            const next = self.start + header_length + payload.len;
            if (next == self.pos) {
                // Best case. We didn't read part (of a whole) 2nd message, we can just
                // reset our pos & start to 0.
                // This should always be true if we're into a dynamic buffer, since the
                // dynamic buffer would have been sized exactly for the message, with no
                // spare room for more data.
                self.pos = 0;
                self.start = 0;
            } else {
                more = true;
                std.debug.assert(next < self.pos);

                // We've read some of the next message. This can get complicated.
                // Our buf might be dynamic. Our buf could be static, but there might
                // not be enough room for another message, or maybe we can't tell.
                // Whatever the case, we can't handle it here because the message
                // we're going to return references buf.
                self.start = next;
            }

            if (fin) {
                if (is_continuation) {
                    if (self.fragment) |*f| {
                        if (f.compressed) {
                            return .{ more, .{ .data = try self.decompress(try f.last(payload)), .type = f.type } };
                        }
                        return .{ more, .{ .type = f.type, .data = try f.last(payload) } };
                    }

                    return error.UnfragmentedContinuation;
                }

                if (self.fragment != null and (message_type == .text or message_type == .binary)) {
                    return error.NestedFragment;
                }

                if (compressed) {
                    return .{ more, .{ .data = try self.decompress(payload), .type = message_type } };
                }

                // just a normal single-fragment message (most common case)
                return .{ more, .{ .data = payload, .type = message_type } };
            }

            if (is_continuation) {
                if (self.fragment) |*f| {
                    try f.add(payload);
                    self.restoreStatic();

                    if (more) {
                        continue :loop;
                    }
                    return null;
                }
                return error.UnfragmentedContinuation;
            } else if (message_type != .text and message_type != .binary) {
                return error.FragmentedControl;
            }

            if (self.fragment != null) {
                return error.NestedFragment;
            }

            self.fragment = try Fragmented.init(self.large_buffer_provider, compressed, message_type, payload);
            self.restoreStatic();

            if (more) {
                continue :loop;
            }
            return null;
        }
    }

    // There's some cleanup in read that we can't do until after the client has
    // had the chance to read the message. We don't want to wait for the next
    // call to "read" to do this, because we don't know when that'll be.
    pub fn done(self: *Reader, message_type: Message.Type) void {
        if (message_type == .text or message_type == .binary) {
            if (self.fragment) |*f| {
                f.deinit();
                self.fragment = null;
            }
            if (self.decompress_writer) |*dw| {
                dw.deinit();
                self.decompress_writer = null;
            }
        }

        self.restoreStatic();
    }

    pub fn isEmpty(self: *Reader) bool {
        return self.pos == 0 and self.fragment == null and self.usingLargeBuffer() == false;
    }

    fn restoreStatic(self: *Reader) void {
        if (self.usingLargeBuffer()) {
            std.debug.assert(self.pos == 0);
            std.debug.assert(self.start == 0);
            self.large_buffer_provider.release(self.buf);
            self.buf = .{ .type = .static, .data = self.static };
            return;
        }

        const start = self.start;
        if (start > self.static.len / 2) {
            // only copy the data back to the start of our static buffer If
            // we've used up half the buffer.

            // TODO: this could be further optimized by seeing if we know the length
            // of the next message and using that to decide if we need to compact
            // the static buffer or not.
            const pos = self.pos;
            const data_len = pos - start;
            std.mem.copyForwards(u8, self.static[0..data_len], self.static[start..pos]);
            self.pos = data_len;
            self.start = 0;
        }
    }

    fn decompress(self: *Reader, compressed: []const u8) ![]u8 {
        const provider = self.large_buffer_provider;

        var dumb: [32]u8 = undefined;
        var writer: buffer.Writer = undefined;
        if (compressed.len < provider.pool_buffer_size) {
            const buf = try provider.pool.acquireOrCreate();
            writer = .init(buf, true, provider, &dumb);
        } else {
            const buf = try provider.allocator.alloc(u8, @intFromFloat(@as(f64, @floatFromInt(compressed.len)) * 1.25));
            writer = .init(buf, false, provider, &dumb);
        }

        errdefer writer.deinit();

        var reader = std.Io.Reader.fixed(compressed);
        var decompressor = std.compress.flate.Decompress.init(&reader, .raw, &.{});
        const n = decompressor.reader.streamRemaining(&writer.interface) catch {
            return error.CompressionError;
        };

        self.decompress_writer = writer;
        return writer.buf[0..n];
    }

    inline fn usingLargeBuffer(self: *const Reader) bool {
        return self.buf.type != .static;
    }
};

fn payloadMeta(byte2: u8) struct { bool, usize } {
    const masked = byte2 & 128 == 128;
    const length_of_length: usize = switch (byte2 & 127) {
        126 => 2,
        127 => 8,
        else => 0,
    };
    return .{ masked, length_of_length };
}

const Fragmented = struct {
    max: usize,
    compressed: bool,
    type: Message.Type,
    buf: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(bp: *buffer.Provider, compressed: bool, message_type: Message.Type, value: []const u8) !Fragmented {
        var buf: std.ArrayList(u8) = .empty;
        try buf.ensureTotalCapacity(bp.allocator, value.len * 2);
        buf.appendSliceAssumeCapacity(value);

        return .{
            .buf = buf,
            .type = message_type,
            .compressed = compressed,
            .max = bp.max_buffer_size,
            .allocator = bp.allocator,
        };
    }

    pub fn deinit(self: *Fragmented) void {
        self.buf.deinit(self.allocator);
    }

    pub fn add(self: *Fragmented, value: []const u8) !void {
        if (self.buf.items.len + value.len > self.max) {
            return error.TooLarge;
        }
        try self.buf.appendSlice(self.allocator, value);
    }

    // Optimization so that we don't over-allocate on our last frame.
    pub fn last(self: *Fragmented, value: []const u8) ![]u8 {
        const total_len = self.buf.items.len + value.len;
        if (total_len > self.max) {
            return error.TooLarge;
        }
        try self.buf.ensureTotalCapacityPrecise(self.allocator, total_len);
        self.buf.appendSliceAssumeCapacity(value);
        return self.buf.items;
    }
};

pub fn mask(m: []const u8, payload: []u8) void {
    var data = payload;

    if (!comptime backend_supports_vectors) return simpleMask(m, data);

    const vector_size = std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
    if (data.len >= vector_size) {
        const mask_vector = std.simd.repeat(vector_size, @as(@Vector(4, u8), m[0..4].*));
        while (data.len >= vector_size) {
            const slice = data[0..vector_size];
            const masked_data_slice: @Vector(vector_size, u8) = slice.*;
            slice.* = masked_data_slice ^ mask_vector;
            data = data[vector_size..];
        }
    }
    simpleMask(m, data);
}

fn simpleMask(m: []const u8, payload: []u8) void {
    @setRuntimeSafety(false);
    for (payload, 0..) |b, i| {
        payload[i] = b ^ m[i & 3];
    }
}

pub fn frame(op_code: OpCode, comptime msg: []const u8) [calculateFrameLen(msg)]u8 {
    var framed: [calculateFrameLen(msg)]u8 = undefined;
    const header = writeFrameHeader(&framed, op_code, msg.len, false);
    @memcpy(framed[header.len..], msg);
    return framed;
}

pub fn writeFrameHeader(buf: []u8, op_code: OpCode, l: usize, compressed: bool) []u8 {
    buf[0] = @intFromEnum(op_code);
    if (compressed) {
        buf[0] |= 64;
    }

    if (l <= 125) {
        buf[1] = @intCast(l);
        return buf[0..2];
    }
    if (l < 65536) {
        buf[1] = 126;
        buf[2] = @intCast((l >> 8) & 0xFF);
        buf[3] = @intCast(l & 0xFF);
        return buf[0..4];
    }

    buf[1] = 127;
    if (comptime builtin.target.ptrBitWidth() >= 64) {
        buf[2] = @intCast((l >> 56) & 0xFF);
        buf[3] = @intCast((l >> 48) & 0xFF);
        buf[4] = @intCast((l >> 40) & 0xFF);
        buf[5] = @intCast((l >> 32) & 0xFF);
    } else {
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
    }
    buf[6] = @intCast((l >> 24) & 0xFF);
    buf[7] = @intCast((l >> 16) & 0xFF);
    buf[8] = @intCast((l >> 8) & 0xFF);
    buf[9] = @intCast(l & 0xFF);
    return buf[0..10];
}

pub fn calculateFrameLen(comptime msg: []const u8) usize {
    if (msg.len <= 125) return msg.len + 2;
    if (msg.len < 65536) return msg.len + 4;
    return msg.len + 10;
}

const t = @import("t.zig");
test "mask" {
    var r = t.getRandom();
    const random = r.random();
    const m = [4]u8{ 10, 20, 55, 200 };

    var original = try t.allocator.alloc(u8, 10000);
    var payload = try t.allocator.alloc(u8, 10000);

    var size: usize = 0;
    while (size < 1000) {
        const slice = original[0..size];
        random.bytes(slice);
        @memcpy(payload[0..size], slice);
        mask(m[0..], payload[0..size]);

        for (slice, 0..) |b, i| {
            try t.expectEqual(b ^ m[i & 3], payload[i]);
        }

        size += 1;
    }
    t.allocator.free(original);
    t.allocator.free(payload);
}

test "Reader: read too large" {
    defer t.reset();

    var pair = t.SocketPair.init(.{});
    defer pair.deinit();
    pair.textFrame(true, "hello world");
    pair.sendBuf();

    var reader = testReader(.{ .max = 16, .static = 16 });
    defer reader.deinit();
    try t.expectError(error.TooLarge, testRead(&reader, pair));
}

test "Reader: read too large over multiple fragments" {
    defer t.reset();

    var pair = t.SocketPair.init(.{});
    defer pair.deinit();
    pair.textFrame(false, "hello world");
    pair.cont(false, " !!!_!!! ");
    pair.cont(true, "how are you doing?");
    pair.sendBuf();

    var reader = testReader(.{ .max = 32, .static = 32 });
    defer reader.deinit();
    try t.expectError(error.TooLarge, testRead(&reader, pair));
}

test "Reader: exact read into static with no overflow" {
    defer t.reset();

    var pair = t.SocketPair.init(.{});
    defer pair.deinit();
    pair.textFrame(true, "hello!");
    pair.sendBuf();

    var reader = testReader(.{ .max = 12, .static = 12 });
    defer reader.deinit();
    try t.expectString("hello!", (try testRead(&reader, pair)).data);
}

test "Reader: fuzz" {
    defer t.reset();
    var r = t.getRandom();
    const random = r.random();

    for (0..250) |_| {
        defer _ = t.arena.reset(.{ .retain_capacity = {} });
        const arena = t.arena.allocator();

        const MAX_FRAGMENTS = random.intRangeAtMost(u32, 1, 4);
        const MESSAGE_TO_SEND = random.intRangeAtMost(u32, 1, 500);
        const MAX_PAYLOAD_SIZE = random.intRangeAtMost(u32, 200, 1000);
        const MAX_MESSAGE_SIZE = MAX_PAYLOAD_SIZE + 14;
        var scrap = try arena.alloc(u8, MAX_PAYLOAD_SIZE);

        var writer = t.Writer.init();
        defer writer.deinit();

        var expected = try arena.alloc(Message, MESSAGE_TO_SEND);

        var is_fragmented = false;
        var fragment_count: usize = 0;
        var fragment: std.ArrayList(u8) = .empty;

        var i: usize = 0;
        while (i < MESSAGE_TO_SEND) {
            if (is_fragmented == false) {
                // this is rare
                is_fragmented = random.intRangeAtMost(u8, 0, 8) == 0;
                fragment_count = 0;
            }

            // a non-fragmented message is always "fin"
            // and we'll force a "fin" after ~ 4 messages.
            const is_fin = is_fragmented == false or random.intRangeAtMost(u8, 0, 3) == 0 or fragment_count == MAX_FRAGMENTS;
            switch (random.intRangeAtMost(u16, 0, 11)) {
                0...8 => { // we mostly expect text or binary messages
                    const buf = scrap[0..random.intRangeAtMost(u32, 0, MAX_PAYLOAD_SIZE)];
                    random.bytes(buf);
                    if (is_fragmented == false) {
                        writer.textFrame(true, buf);
                        expected[i] = .{ .type = .text, .data = try arena.dupe(u8, buf) };
                        i += 1;
                    } else {
                        if (fragment_count == 0) {
                            // the first part of our fragmented message
                            writer.textFrame(is_fin, buf);
                        } else {
                            writer.cont(is_fin, buf);
                        }
                        fragment_count += 1;

                        try fragment.appendSlice(arena, try arena.dupe(u8, buf));

                        if (is_fin) {
                            // this was the last message in our fragment
                            expected[i] = .{ .type = .text, .data = try arena.dupe(u8, fragment.items) };

                            i += 1;
                            is_fragmented = false;
                            fragment.clearRetainingCapacity();
                        }
                    }
                },
                9 => {
                    // empty ping
                    writer.ping();
                    expected[i] = .{ .type = .ping, .data = "" };
                    i += 1;
                },
                10 => {
                    // ping with data
                    const buf = scrap[0..random.intRangeAtMost(u32, 1, 125)];
                    random.bytes(buf);
                    writer.pingPayload(buf);
                    expected[i] = .{ .type = .ping, .data = try arena.dupe(u8, buf) };
                    i += 1;
                },
                11 => {
                    writer.pong();
                    expected[i] = .{ .type = .pong, .data = "" };
                    i += 1;
                },
                else => unreachable,
            }
        }

        // test with various buffer sizes, and large buffer pools enabled/disabled
        const static_size = random.intRangeAtMost(u32, 20, MAX_MESSAGE_SIZE + 200);
        const large_buffer_count = random.intRangeAtMost(u16, 0, 1);
        const large_buffer_size = random.intRangeAtMost(u32, static_size, MAX_MESSAGE_SIZE * 2);

        // fragmentation could make messages very large
        var reader = testReader(.{ .max = MAX_MESSAGE_SIZE * (MAX_FRAGMENTS + 1), .static = static_size, .count = large_buffer_count, .size = large_buffer_size });
        defer reader.large_buffer_provider.deinit();
        defer reader.deinit();

        i = 0;
        while (true) {
            reader.fill(&writer) catch |err| switch (err) {
                error.Closed => {
                    try t.expectEqual(@as(u32, @intCast(i)), MESSAGE_TO_SEND);
                    break;
                },
                else => return err,
            };

            while (true) {
                const has_more, const message = (try reader.read()) orelse break;
                try t.expectEqual(expected[i].type, message.type);
                try t.expectString(expected[i].data, message.data);
                reader.done(message.type);

                i += 1;
                if (has_more == false) {
                    break;
                }
            }
        }
    }
}

test "Fragmented" {
    {
        var bp = try buffer.Provider.init(t.allocator, .{ .count = 0, .size = 0, .max = 500 });
        var f = try Fragmented.init(&bp, false, .text, "hello");
        defer f.deinit();

        try t.expectString("hello", f.buf.items);

        try f.add(" ");
        try t.expectString("hello ", f.buf.items);

        try f.add("world");
        try t.expectString("hello world", f.buf.items);
    }

    {
        var bp = try buffer.Provider.init(t.allocator, .{ .count = 0, .size = 0, .max = 10 });
        var f = try Fragmented.init(&bp, false, .text, "hello");
        defer f.deinit();
        try f.add(" ");
        try t.expectError(error.TooLarge, f.add("world"));
    }

    {
        var bp = try buffer.Provider.init(t.allocator, .{ .count = 0, .size = 0, .max = 5000 });

        var r = std.Random.DefaultPrng.init(0);
        var random = r.random();

        var count: usize = 0;
        var buf: [100]u8 = undefined;
        while (count < 1000) : (count += 1) {
            var payload = buf[0 .. random.uintAtMost(usize, 99) + 1];
            random.bytes(payload);

            var f = try Fragmented.init(&bp, false, .binary, payload);
            defer f.deinit();

            var expected: std.ArrayList(u8) = .empty;
            defer expected.deinit(t.allocator);
            try expected.appendSlice(t.allocator, payload);

            const number_of_adds = random.uintAtMost(usize, 30);
            for (0..number_of_adds) |_| {
                payload = buf[0 .. random.uintAtMost(usize, 99) + 1];
                random.bytes(payload);
                try f.add(payload);
                try expected.appendSlice(t.allocator, payload);
            }
            payload = buf[0 .. random.uintAtMost(usize, 99) + 1];
            random.bytes(payload);
            try expected.appendSlice(t.allocator, payload);

            try t.expectString(expected.items, try f.last(payload));
        }
    }
}

fn testReader(opts: anytype) Reader {
    const T = @TypeOf(opts);

    const aa = t.arena.allocator();

    const bp = aa.create(buffer.Provider) catch unreachable;
    bp.* = buffer.Provider.init(t.allocator, .{
        .max = if (@hasField(T, "max")) opts.max else 20,
        .size = if (@hasField(T, "size")) opts.size else 0,
        .count = if (@hasField(T, "count")) opts.count else 0,
    }) catch unreachable;

    const static_size = if (@hasField(T, "static")) opts.static else 16;
    const reader_buf = aa.alloc(u8, static_size) catch unreachable;
    return Reader.init(reader_buf, bp, null);
}

fn testRead(reader: *Reader, pair: t.SocketPair) !Message {
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try reader.fill(pair.server);
        if (try reader.read()) |result| {
            return result.@"1";
        }
    } else {
        return error.LoopReadOverflow;
    }
}
