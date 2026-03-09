const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Buffer = struct {
    data: []u8,
    type: Type,

    const Type = enum {
        static,
        pooled,
        dynamic,
    };
};

pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,
    pooled: bool,
    provider: *Provider,
    interface: std.Io.Writer,

    pub fn init(buf: []u8, pooled: bool, provider: *Provider, dumb: []u8) Writer {
        return .{
            .buf = buf,
            .pooled = pooled,
            .provider = provider,
            .interface = .{
                .buffer = dumb,
                .vtable = &.{
                    .drain = drain,
                },
            },
        };
    }

    pub fn deinit(self: *Writer) void {
        if (self.pooled) {
            self.provider.pool.release(self.buf);
        } else {
            self.provider.allocator.free(self.buf);
        }
    }

    pub fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
        std.debug.print("drain: {d}\n", .{data[0].len});
        _ = splat;
        const self: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
        self.writeAll(data[0]) catch return error.WriteFailed;
        return data[0].len;
    }

    pub fn writeAll(self: *Writer, data: []const u8) !void {
        const pos = self.pos;
        const total_len = pos + data.len;
        if (total_len > self.provider.max_buffer_size) {
            return error.TooLarge;
        }
        try self.ensureTotalCapacity(total_len);

        @memcpy(self.buf[pos..total_len], data);
        self.pos = total_len;
    }

    fn ensureTotalCapacity(self: *Writer, required_capacity: usize) !void {
        const buf = self.buf;
        if (required_capacity <= buf.len) {
            return;
        }

        // from std.ArrayList
        var new_capacity = buf.len;
        while (true) {
            new_capacity +|= new_capacity / 2 + 8;
            if (new_capacity >= required_capacity) break;
        }

        const allocator = self.provider.allocator;
        if (self.pooled or !allocator.resize(buf, new_capacity)) {
            const new_buffer = try allocator.alloc(u8, new_capacity);
            @memcpy(new_buffer[0..buf.len], buf);

            if (self.pooled) {
                self.provider.pool.release(buf);
            }

            self.buf = new_buffer;
            self.pooled = false;
        } else {
            const new_buffer = buf.ptr[0..new_capacity];
            self.buf = new_buffer;
        }
    }
};

pub const Config = struct {
    count: u16 = 1,
    size: usize = 65536,
    max: usize = 65536,
};

// Manages all buffer access and types. It's where code goes to ask
// for and release buffers.
pub const Provider = struct {
    pool: Pool,
    allocator: Allocator,

    max_buffer_size: usize,

    // If this is 0, pool is undefined. We need this field here anyways.
    pool_buffer_size: usize,

    pub fn init(allocator: Allocator, config: Config) !Provider {
        const size = config.size;
        const count = config.count;

        if (count == 0 or size == 0) {

            // Large buffering can be disabled, in which case any large buffers will
            // be dynamically allocated using the allocator (assuming the requested
            // size is less than the max_message_size)
            return .{
                // this is safe to do, because we set size = 0, so we'll
                // never try to access the pool
                .pool = undefined,
                .pool_buffer_size = 0,
                .allocator = allocator,
                .max_buffer_size = config.max,
            };
        }

        return .{
            .allocator = allocator,
            .pool_buffer_size = size,
            .max_buffer_size = config.max,
            .pool = try Pool.init(allocator, count, size),
        };
    }

    pub fn deinit(self: *Provider) void {
        if (self.pool_buffer_size > 0) {
            // else, pool is undefined
            self.pool.deinit();
        }
    }

    pub fn alloc(self: *Provider, size: usize) !Buffer {
        if (size > self.max_buffer_size) {
            return error.TooLarge;
        }

        // remember: if self.pool_buffer_size == 0, then self.pool is undefined.
        if (size <= self.pool_buffer_size) {
            if (self.pool.acquire()) |buffer| {
                // See the Reader struct comment to see why this is necessary
                var copy = buffer;
                copy.len = size;
                return .{ .type = .pooled, .data = copy };
            }
        }

        return .{
            .type = .dynamic,
            .data = try self.allocator.alloc(u8, size),
        };
    }

    pub fn grow(self: *Provider, buffer: Buffer, current_size: usize, new_size: usize) !Buffer {
        if (new_size > self.max_buffer_size) {
            return error.TooLarge;
        }

        if (buffer.type == .dynamic) {
            var copy = buffer;
            copy.data = try self.allocator.realloc(buffer.data, new_size);
            return copy;
        }

        defer self.release(buffer);

        const new_buffer = try self.alloc(new_size);
        @memcpy(new_buffer.data[0..current_size], buffer.data[0..current_size]);
        return new_buffer;
    }

    pub fn free(self: *Provider, buffer: Buffer) void {
        switch (buffer.type) {
            .pooled => {
                // this resize is necessary because on alloc, we potentially shrink data
                var copy = buffer.data;
                copy.len = self.pool_buffer_size;
                self.pool.release(copy);
            },
            .static => self.allocator.free(buffer.data),
            .dynamic => self.allocator.free(buffer.data),
        }
    }

    pub fn release(self: *Provider, buffer: Buffer) void {
        switch (buffer.type) {
            .static => {},
            .pooled => {
                // this resize is necessary because on alloc, we potentially shrink data
                var copy = buffer.data;
                copy.len = self.pool_buffer_size;
                self.pool.release(copy);
            },
            .dynamic => self.allocator.free(buffer.data),
        }
    }
};

pub const Pool = struct {
    buffer_size: usize,
    available: usize,
    buffers: [][]u8,
    allocator: Allocator,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: Allocator, count: usize, buffer_size: usize) !Pool {
        const buffers = try allocator.alloc([]u8, count);

        for (0..count) |i| {
            buffers[i] = try allocator.alloc(u8, buffer_size);
        }

        return .{
            .mutex = .{},
            .buffers = buffers,
            .available = count,
            .allocator = allocator,
            .buffer_size = buffer_size,
        };
    }

    pub fn deinit(self: *Pool) void {
        const allocator = self.allocator;
        for (self.buffers) |buf| {
            allocator.free(buf);
        }
        allocator.free(self.buffers);
    }

    pub fn acquire(self: *Pool) ?[]u8 {
        const buffers = self.buffers;

        self.mutex.lock();
        defer self.mutex.unlock();
        const available = self.available;
        if (available == 0) {
            return null;
        }
        const index = available - 1;
        const buffer = buffers[index];
        self.available = index;
        return buffer;
    }

    pub fn acquireOrCreate(self: *Pool) ![]u8 {
        return self.acquire() orelse self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *Pool, buffer: []u8) void {
        var buffers = self.buffers;

        self.mutex.lock();
        const available = self.available;
        if (available == buffers.len) {
            self.mutex.unlock();
            self.allocator.free(buffer);
            return;
        }
        buffers[available] = buffer;
        self.available = available + 1;
        self.mutex.unlock();
    }
};

const t = @import("t.zig");
test "buffer: no pool" {
    var p = try Provider.init(t.allocator, .{ .count = 0, .size = 0, .max = 100 });

    const buffer = try p.alloc(100);
    defer p.free(buffer);
    try t.expectEqual(.dynamic, buffer.type);
    try t.expectEqual(100, buffer.data.len);
}

test "buffer: pool" {
    var p = try Provider.init(t.allocator, .{ .count = 2, .size = 10, .max = 15 });
    defer p.deinit();

    {
        // bigger than allowed
        try t.expectError(error.TooLarge, p.alloc(16));
    }

    {
        // bigger than our buffers in pool
        const buffer = try p.alloc(15);
        defer p.free(buffer);
        try t.expectEqual(.dynamic, buffer.type);
        try t.expectEqual(15, buffer.data.len);
    }

    {
        // smaller than our buffers in pool
        const buf1 = try p.alloc(4);
        try t.expectEqual(.pooled, buf1.type);
        try t.expectEqual(4, buf1.data.len);

        const buf2 = try p.alloc(5);
        try t.expectEqual(.pooled, buf2.type);
        try t.expectEqual(5, buf2.data.len);
        try t.expectEqual(true, buf1.data.ptr != buf2.data.ptr);

        // no more buffers in the pool, creats a dynamic buffer
        const buf3 = try p.alloc(6);
        try t.expectEqual(.dynamic, buf3.type);
        try t.expectEqual(6, buf3.data.len);

        p.release(buf1);

        const buf4 = try p.alloc(7);
        try t.expectEqual(.pooled, buf4.type);
        try t.expectEqual(7, buf4.data.len);
        try t.expectEqual(true, buf1.data.ptr == buf4.data.ptr);

        p.release(buf2);
        p.release(buf3);
    }
}

test "buffer: grow" {
    var p = try Provider.init(t.allocator, .{ .count = 1, .size = 10, .max = 30 });
    defer p.deinit();

    {
        // grow a dynamic buffer
        var buf1 = try p.alloc(15);
        @memcpy(buf1.data[0..5], "hello");
        const buf2 = try p.grow(buf1, 5, 20);
        defer p.free(buf2);
        try t.expectEqual(20, buf2.data.len);
        try t.expectString("hello", buf2.data[0..5]);
    }

    {
        // grow a static buffer
        var buf1 = Buffer{ .type = .static, .data = try t.allocator.alloc(u8, 15) };
        defer t.allocator.free(buf1.data);
        @memcpy(buf1.data[0..6], "hello2");

        const buf2 = try p.grow(buf1, 6, 21);
        defer p.free(buf2);
        try t.expectEqual(21, buf2.data.len);
        try t.expectString("hello2", buf2.data[0..6]);
    }

    {
        // grow a pooled buffer
        var buf1 = try p.alloc(8);

        @memcpy(buf1.data[0..7], "hello2a");
        const buf2 = try p.grow(buf1, 7, 14);
        defer p.free(buf2);
        try t.expectEqual(14, buf2.data.len);
        try t.expectString("hello2a", buf2.data[0..7]);
        try t.expectEqual(1, p.pool.available);
    }
}
