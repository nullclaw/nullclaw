const std = @import("std");
const t = @import("t.zig");
const ws = @import("websocket.zig");

pub fn init() Testing {
    return Testing.init();
}

pub const Testing = struct {
    closed: bool,
    conn: ws.Conn,
    pair: t.SocketPair,
    reader: ws.proto.Reader,
    arena: *std.heap.ArenaAllocator,

    received: std.ArrayList(ws.Message),
    received_index: usize,

    const Opts = struct {
        port: ?u16 = null,
    };
    fn init(opts: Opts) Testing {
        const arena = t.allocator.create(std.heap.ArenaAllocator) catch unreachable;
        errdefer t.allocator.destroy(arena);

        arena.* = std.heap.ArenaAllocator.init(t.allocator);
        errdefer arena.deinit();

        const port = opts.port orelse 0;
        const pair = t.SocketPair.init(.{ .port = port });
        const timeout = std.mem.toBytes(std.posix.timeval{
            .sec = 0,
            .usec = 50_000,
        });
        std.posix.setsockopt(pair.client.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &timeout) catch unreachable;

        const aa = arena.allocator();
        const buffer_provider = aa.create(ws.buffer.Provider) catch unreachable;
        buffer_provider.* = ws.buffer.Provider.init(aa, .{
            .size = 0,
            .count = 0,
            .max = 20_971_520,
        }) catch unreachable;

        const reader_buf = aa.alloc(u8, 1024) catch unreachable;
        const reader = ws.proto.Reader.init(reader_buf, buffer_provider, null);

        return .{
            .closed = false,
            .pair = pair,
            .arena = arena,
            .conn = .{
                ._closed = false,
                .started = 0,
                .stream = pair.server,
                .address = std.net.Address.parseIp("127.0.0.1", port) catch unreachable,
            },
            .reader = reader,
            .received = std.ArrayList(ws.Message).init(aa),
            .received_index = 0,
        };
    }

    pub fn deinit(self: *Testing) void {
        self.pair.writer.deinit();
        close(self.pair.client.handle);
        close(self.pair.server.handle);

        self.arena.deinit();
        t.allocator.destroy(self.arena);
    }

    pub fn expectMessage(self: *Testing, op: ws.Message.Type, data: []const u8) !void {
        try self.ensureMessage();

        const message = self.received.items[self.received_index];
        self.received_index += 1;

        try t.expectEqual(op, message.type);
        if (op == .text) {
            try t.expectString(data, message.data);
        } else {
            try t.expectSlice(u8, data, message.data);
        }
    }

    pub fn expectClose(self: *Testing) !void {
        if (self.closed) {
            return;
        }

        self.fill() catch if (self.closed) {
            return;
        };

        return error.NotClosed;
    }

    // we have a 50ms timeout on this socket. It's all localhost. We expect
    // to be able to read messages in that time.
    pub fn ensureMessage(self: *Testing) !void {
        if (self.received_index < self.received.items.len) {
            return;
        }
        return self.fill();
    }

    fn fill(self: *Testing) !void {
        self.reader.fill(self.pair.client) catch |err| switch (err) {
            error.WouldBlock => return error.NoMoreData,
            else => {
                self.closed = true;
                return err;
            },
        };

        while (true) {
            const more, const message = (try self.reader.read()) orelse return error.NoMoreData;
            try self.received.append(message);
            if (more == false) {
                return;
            }
        }
    }
};

// std.posix.close panics on EBADF
// This is a general issue in Zig:
// https://github.com/ziglang/zig/issues/6389
//
// For these tests, we realy don't know if the server-side of the connection
// is closed, so we try to close and ignore any errors.
fn close(fd: std.posix.fd_t) void {
    const builtin = @import("builtin");
    const native_os = builtin.os.tag;
    if (native_os == .windows) {
        return std.os.windows.CloseHandle(fd);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        _ = std.os.wasi.fd_close(fd);
        return;
    }
    _ = std.posix.system.close(fd);
}
