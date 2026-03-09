const std = @import("std");
const proto = @import("proto.zig");

const posix = std.posix;
const ArrayList = std.ArrayList;

const Message = proto.Message;

pub const allocator = std.testing.allocator;

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

pub const expectError = std.testing.expectError;
pub const expectString = std.testing.expectEqualStrings;
pub const expectSlice = std.testing.expectEqualSlices;

pub fn getRandom() std.Random.DefaultPrng {
    var seed: u64 = undefined;
    std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
    return std.Random.DefaultPrng.init(seed);
}

pub var arena = std.heap.ArenaAllocator.init(allocator);
pub fn reset() void {
    _ = arena.reset(.free_all);
}

pub const Writer = struct {
    pos: usize,
    buf: std.ArrayList(u8),
    random: std.Random.DefaultPrng,

    pub fn init() Writer {
        return .{
            .pos = 0,
            .buf = .empty,
            .random = getRandom(),
        };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(allocator);
    }

    pub fn ping(self: *Writer) void {
        return self.pingPayload("");
    }

    pub fn pong(self: *Writer) void {
        return self.frame(true, 10, "", 0);
    }

    pub fn pingPayload(self: *Writer, payload: []const u8) void {
        return self.frame(true, 9, payload, 0);
    }

    pub fn textFrame(self: *Writer, fin: bool, payload: []const u8) void {
        return self.frame(fin, 1, payload, 0);
    }

    pub fn cont(self: *Writer, fin: bool, payload: []const u8) void {
        return self.frame(fin, 0, payload, 0);
    }

    pub fn frame(self: *Writer, fin: bool, op_code: u8, payload: []const u8, reserved: u8) void {
        var buf = &self.buf;

        const l = payload.len;
        var length_of_length: usize = 0;

        if (l > 125) {
            if (l < 65536) {
                length_of_length = 2;
            } else {
                length_of_length = 8;
            }
        }

        // 2 byte header + length_of_length + mask + payload_length
        const needed = 2 + length_of_length + 4 + l;
        buf.ensureUnusedCapacity(allocator, needed) catch unreachable;

        if (fin) {
            buf.appendAssumeCapacity(128 | op_code | reserved);
        } else {
            buf.appendAssumeCapacity(op_code | reserved);
        }

        if (length_of_length == 0) {
            buf.appendAssumeCapacity(128 | @as(u8, @intCast(l)));
        } else if (length_of_length == 2) {
            buf.appendAssumeCapacity(128 | 126);
            buf.appendAssumeCapacity(@intCast((l >> 8) & 0xFF));
            buf.appendAssumeCapacity(@intCast(l & 0xFF));
        } else {
            buf.appendAssumeCapacity(128 | 127);
            buf.appendAssumeCapacity(@intCast((l >> 56) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 48) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 40) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 32) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 24) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 16) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 8) & 0xFF));
            buf.appendAssumeCapacity(@intCast(l & 0xFF));
        }

        var mask: [4]u8 = undefined;
        self.random.random().bytes(&mask);
        // var mask = [_]u8{1, 1, 1, 1};

        buf.appendSliceAssumeCapacity(&mask);
        for (payload, 0..) |b, i| {
            buf.appendAssumeCapacity(b ^ mask[i & 3]);
        }
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn clear(self: *Writer) void {
        self.pos = 0;
        self.buf.clearRetainingCapacity();
    }

    pub fn read(
        self: *Writer,
        buf: []u8,
    ) !usize {
        const data = self.buf.items[self.pos..];

        if (data.len == 0 or buf.len == 0) {
            return 0;
        }

        // randomly fragment the data
        const to_read = self.random.random().intRangeAtMost(usize, 1, @min(data.len, buf.len));
        @memcpy(buf[0..to_read], data[0..to_read]);
        self.pos += to_read;
        return to_read;
    }
};

pub const SocketPair = struct {
    writer: Writer,
    client: std.net.Stream,
    server: std.net.Stream,

    const Opts = struct {
        port: ?u16 = null,
    };

    pub fn init(opts: Opts) SocketPair {
        var address = std.net.Address.parseIp("127.0.0.1", opts.port orelse 0) catch unreachable;
        var address_len = address.getOsSockLen();

        const listener = posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP) catch unreachable;
        defer posix.close(listener);

        {
            // setup our listener
            posix.bind(listener, &address.any, address_len) catch unreachable;
            posix.listen(listener, 1) catch unreachable;
            posix.getsockname(listener, &address.any, &address_len) catch unreachable;
        }

        const client = posix.socket(address.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch unreachable;
        {
            // connect the client
            const flags = posix.fcntl(client, posix.F.GETFL, 0) catch unreachable;
            _ = posix.fcntl(client, posix.F.SETFL, flags | posix.SOCK.NONBLOCK) catch unreachable;
            posix.connect(client, &address.any, address_len) catch |err| switch (err) {
                error.WouldBlock => {},
                else => unreachable,
            };
            _ = posix.fcntl(client, posix.F.SETFL, flags) catch unreachable;
        }

        const server = posix.accept(listener, &address.any, &address_len, posix.SOCK.CLOEXEC) catch unreachable;

        return .{
            .client = .{ .handle = client },
            .server = .{ .handle = server },
            .writer = Writer.init(),
        };
    }

    pub fn deinit(self: *SocketPair) void {
        self.writer.deinit();
        // assume test closes self.server
        self.client.close();
    }

    pub fn pingPayload(self: *SocketPair, payload: []const u8) void {
        self.writer.pingPayload(payload);
    }

    pub fn textFrame(self: *SocketPair, fin: bool, payload: []const u8) void {
        self.writer.textFrame(fin, payload);
    }

    pub fn cont(self: *SocketPair, fin: bool, payload: []const u8) void {
        self.writer.cont(fin, payload);
    }

    pub fn sendBuf(self: *SocketPair) void {
        self.client.writeAll(self.writer.bytes()) catch unreachable;
        self.writer.clear();
    }
};
