const std = @import("std");

const posix = std.posix;
const ascii = std.ascii;
const Allocator = std.mem.Allocator;
const websocket = @import("../websocket.zig");

const M = @This();

const SpecialHeader = enum {
    none,
    upgrade,
    connection,
    @"sec-websocket-key",
    @"sec-websocket-version",
    @"sec-websocket-extensions",
};

pub const Handshake = struct {
    url: []const u8,
    key: []const u8,
    method: []const u8,
    headers: *KeyValue,
    res_headers: *KeyValue,
    raw_header: []const u8,
    compression: ?Compression,

    pub const Pool = M.Pool;

    pub const Compression = struct {
        client_no_context_takeover: bool,
        server_no_context_takeover: bool,
    };

    // returns null if the request isn't full
    pub fn parse(state: *State) !?Handshake {
        const request = state.buf[0..state.len];

        var buf = request;
        if (std.mem.endsWith(u8, buf, "\r\n\r\n") == false) {
            return null;
        }

        const request_line_end = std.mem.indexOfScalar(u8, buf, '\r') orelse unreachable;
        var request_line = buf[0..request_line_end];

        if (!ascii.endsWithIgnoreCase(request_line, "http/1.1")) {
            return error.InvalidProtocol;
        }

        var headers = &state.req_headers;

        var key: []const u8 = "";
        var required_headers: u8 = 0;

        var compression: ?Handshake.Compression = null;

        var request_length = request_line_end;

        buf = buf[request_line_end + 2 ..];

        while (buf.len > 4) {
            const index = std.mem.indexOfScalar(u8, buf, '\r') orelse unreachable;
            const separator = std.mem.indexOfScalar(u8, buf[0..index], ':') orelse return error.InvalidHeader;

            const name = std.mem.trim(u8, toLower(buf[0..separator]), &ascii.whitespace);
            const value = std.mem.trim(u8, buf[(separator + 1)..index], &ascii.whitespace);

            headers.add(name, value);
            switch (std.meta.stringToEnum(SpecialHeader, name) orelse .none) {
                .upgrade => {
                    if (!ascii.eqlIgnoreCase("websocket", value)) {
                        return error.InvalidUpgrade;
                    }
                    required_headers |= 1;
                },
                .connection => {
                    // find if connection header has upgrade in it, example header:
                    // Connection: keep-alive, Upgrade
                    if (std.ascii.indexOfIgnoreCase(value, "upgrade") == null) {
                        return error.InvalidConnection;
                    }
                    required_headers |= 4;
                },
                .@"sec-websocket-key" => {
                    key = value;
                    required_headers |= 8;
                },
                .@"sec-websocket-version" => {
                    if (value.len != 2 or value[0] != '1' or value[1] != '3') {
                        return error.InvalidVersion;
                    }
                    required_headers |= 2;
                },
                .@"sec-websocket-extensions" => compression = try parseExtension(value),
                .none => {},
            }

            const next = index + 2;
            request_length += next;
            buf = buf[next..];
        }

        if (required_headers != 15) {
            return error.MissingHeaders;
        }

        // we already established that request_line ends with http/1.1, so this buys
        // us some leeway into parsing it
        const separator = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.InvalidRequestLine;
        const method = request_line[0..separator];
        const url = std.mem.trim(u8, request_line[separator + 1 .. request_line.len - 9], &ascii.whitespace);

        return .{
            .key = key,
            .url = url,
            .method = method,
            .headers = headers,
            .compression = compression,
            .res_headers = &state.res_headers,
            .raw_header = request[request_line_end + 2 .. request_length + 2],
        };
    }

    pub fn createReply(key: []const u8, headers_: ?*KeyValue, compression: bool, buf: []u8) ![]const u8 {
        const HEADER =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: ";

        @memcpy(buf[0..HEADER.len], HEADER);
        var pos = HEADER.len;

        {
            var h: [20]u8 = undefined;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(key);
            // websocket spec always used this value
            hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            hasher.final(&h);

            const end = pos + 28;
            _ = std.base64.standard.Encoder.encode(buf[pos..end], h[0..]);
            pos = end;
        }

        if (compression) {
            const permessage_deflate =
                "\r\nSec-WebSocket-Extensions: permessage-deflate" ++
                "; server_no_context_takeover" ++
                "; client_no_context_takeover";

            const end = pos + permessage_deflate.len;
            @memcpy(buf[pos..end], permessage_deflate);
            pos = end;
        }

        if (headers_) |headers| {
            for (headers.keys[0..headers.len], headers.values[0..headers.len]) |k, v| {
                pos += (try std.fmt.bufPrint(buf[pos..], "\r\n{s}: {s}", .{ k, v })).len;
            }
        }

        const end = pos + 4;
        @memcpy(buf[pos..end], "\r\n\r\n");
        return buf[0..end];
    }

    pub fn parseExtension(value: []const u8) !?Handshake.Compression {
        var deflate = false;
        var server_max_bits: u8 = 15;
        var client_no_context_takeover = false;
        var server_no_context_takeover = false;

        var it = std.mem.splitScalar(u8, value, ';');
        while (it.next()) |param_| {
            const param = std.mem.trim(u8, param_, &ascii.whitespace);
            if (std.mem.eql(u8, param, "permessage-deflate")) {
                deflate = true;
                continue;
            }
            if (std.mem.eql(u8, param, "client_no_context_takeover")) {
                client_no_context_takeover = true;
                continue;
            }
            if (std.mem.eql(u8, param, "server_no_context_takeover")) {
                server_no_context_takeover = true;
                continue;
            }
            const server_max_window_bits = "server_max_window_bits=";
            if (std.mem.startsWith(u8, param, server_max_window_bits)) {
                server_max_bits = std.fmt.parseInt(u8, param[server_max_window_bits.len..], 10) catch {
                    return error.InvalidCompressionServerMaxBits;
                };
            }
        }
        if (deflate == false) {
            return null;
        }

        if (server_max_bits != 15) {
            // Zig doesn't support a sliding deflate window. If the client asks
            // for a sliding window < 15, we can't accomodate it. This logic
            // should be pushed into the worker, but putting it here makes it
            // easier for any integration to also use this (i..e httz)
            return null;
        }

        return .{
            .client_no_context_takeover = client_no_context_takeover,
            .server_no_context_takeover = server_no_context_takeover,
        };
    }

    // This is what we're pooling
    pub const State = struct {
        // length of data we have in buf
        len: usize = 0,

        // a buffer to read data into
        buf: []u8,

        // Headers from the request
        req_headers: KeyValue,

        // Headers that we want to send in the response
        res_headers: KeyValue,

        pool: *M.Pool,

        fn init(pool: *M.Pool) !State {
            const allocator = pool.allocator;
            const buf = try allocator.alloc(u8, pool.buffer_size);
            errdefer allocator.free(buf);

            const req_headers = try Handshake.KeyValue.init(allocator, pool.max_req_headers);
            errdefer req_headers.deinit(allocator);

            const res_headers = try Handshake.KeyValue.init(allocator, pool.max_res_headers);
            errdefer res_headers.deinit(allocator);

            return .{
                .buf = buf,
                .pool = pool,
                .req_headers = req_headers,
                .res_headers = res_headers,
            };
        }

        fn deinit(self: *State) void {
            const allocator = self.pool.allocator;
            allocator.free(self.buf);
            self.req_headers.deinit(allocator);
            self.res_headers.deinit(allocator);
        }

        pub fn release(self: *State) void {
            self.len = 0;
            self.req_headers.len = 0;
            self.res_headers.len = 0;
            self.pool.release(self);
        }
    };

    pub const KeyValue = struct {
        len: usize,
        keys: [][]const u8,
        values: [][]const u8,

        fn init(allocator: Allocator, max: usize) !KeyValue {
            const keys = try allocator.alloc([]const u8, max);
            errdefer allocator.free(keys);

            const values = try allocator.alloc([]const u8, max);
            errdefer allocator.free(values);

            return .{
                .len = 0,
                .keys = keys,
                .values = values,
            };
        }

        fn deinit(self: *const KeyValue, allocator: Allocator) void {
            allocator.free(self.keys);
            allocator.free(self.values);
        }

        pub fn add(self: *KeyValue, key: []const u8, value: []const u8) void {
            const len = self.len;
            var keys = self.keys;
            if (len == keys.len) {
                return;
            }

            keys[len] = key;
            self.values[len] = value;
            self.len = len + 1;
        }

        pub fn get(self: *const KeyValue, needle: []const u8) ?[]const u8 {
            const keys = self.keys[0..self.len];
            loop: for (keys, 0..) |key, i| {
                // This is largely a reminder to myself that std.mem.eql isn't
                // particularly fast. Here we at least avoid the 1 extra ptr
                // equality check that std.mem.eql does, but we could do better
                // TODO: monitor https://github.com/ziglang/zig/issues/8689
                if (needle.len != key.len) {
                    continue;
                }
                for (needle, key) |n, k| {
                    if (n != k) {
                        continue :loop;
                    }
                }
                return self.values[i];
            }

            return null;
        }

        pub fn iterator(self: *const KeyValue) Iterator {
            const len = self.len;
            return .{
                .pos = 0,
                .keys = self.keys[0..len],
                .values = self.values[0..len],
            };
        }

        pub const Iterator = struct {
            pos: usize,
            keys: [][]const u8,
            values: [][]const u8,

            const KV = struct {
                key: []const u8,
                value: []const u8,
            };

            pub fn next(self: *Iterator) ?KV {
                const pos = self.pos;
                if (pos == self.keys.len) {
                    return null;
                }

                self.pos = pos + 1;
                return .{
                    .key = self.keys[pos],
                    .value = self.values[pos],
                };
            }
        };
    };
};

pub const Pool = struct {
    mutex: std.Thread.Mutex,
    available: usize,
    allocator: Allocator,
    buffer_size: usize,
    max_req_headers: usize,
    max_res_headers: usize,
    states: []*Handshake.State,

    pub fn init(allocator: Allocator, count: usize, buffer_size: usize, max_req_headers: usize, max_res_headers: usize) !*Pool {
        const states = try allocator.alloc(*Handshake.State, count);
        errdefer allocator.free(states);

        const pool = try allocator.create(Pool);
        errdefer allocator.destroy(pool);

        pool.* = .{
            .mutex = .{},
            .states = states,
            .allocator = allocator,
            .available = count,
            .buffer_size = buffer_size,
            .max_req_headers = max_req_headers,
            .max_res_headers = max_res_headers,
        };

        for (0..count) |i| {
            const state = try allocator.create(Handshake.State);
            errdefer allocator.destroy(state);

            state.* = try Handshake.State.init(pool);
            states[i] = state;
        }

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        const allocator = self.allocator;
        for (self.states) |s| {
            s.deinit();
            allocator.destroy(s);
        }
        allocator.free(self.states);
        allocator.destroy(self);
    }

    pub fn acquire(self: *Pool) !*Handshake.State {
        const states = self.states;

        self.mutex.lock();
        const available = self.available;
        if (available == 0) {
            // dont hold the lock over factory
            self.mutex.unlock();

            const allocator = self.allocator;
            const state = try allocator.create(Handshake.State);
            errdefer allocator.destroy(state);
            state.* = try Handshake.State.init(self);
            return state;
        }
        const index = available - 1;
        const state = states[index];
        self.available = index;
        self.mutex.unlock();
        return state;
    }

    fn release(self: *Pool, state: *Handshake.State) void {
        var states = self.states;

        self.mutex.lock();
        const available = self.available;
        if (available == states.len) {
            self.mutex.unlock();
            state.deinit();
            self.allocator.destroy(state);
            return;
        }
        states[available] = state;
        self.available = available + 1;
        self.mutex.unlock();
    }
};

fn toLower(str: []u8) []u8 {
    for (str, 0..) |c, i| {
        str[i] = ascii.toLower(c);
    }
    return str;
}

const t = @import("../t.zig");
test "handshake: parse" {
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    {
        var state = try pool.acquire();
        defer state.release();

        try t.expectEqual(null, try testHandshake("", state));
        try t.expectEqual(null, try testHandshake("GET", state));
        try t.expectEqual(null, try testHandshake("GET 1 HTTP/1.0\r", state));
        try t.expectEqual(null, try testHandshake("GET 1 HTTP/1.0\r\n", state));

        try t.expectError(error.InvalidProtocol, testHandshake("GET / HTTP/1.0\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection:  upgrade\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\n\r\n", state));
    }

    {
        var state = try pool.acquire();
        defer state.release();

        const h = (try testHandshake("GET /test?a=1   HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: 9000!\r\nCustom:  Header-Value\r\n\r\n", state)).?;
        try t.expectString("9000!", h.key);
        try t.expectString("GET", h.method);
        try t.expectString("/test?a=1", h.url);
        try t.expectString("connection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: 9000!\r\ncustom:  Header-Value\r\n", h.raw_header);
        try t.expectString("Header-Value", h.headers.get("custom").?);

        var it = h.headers.iterator();
        {
            const kv = it.next().?;
            try t.expectString("connection", kv.key);
            try t.expectString("upgrade", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("upgrade", kv.key);
            try t.expectString("websocket", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("sec-websocket-version", kv.key);
            try t.expectString("13", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("sec-websocket-key", kv.key);
            try t.expectString("9000!", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("custom", kv.key);
            try t.expectString("Header-Value", kv.value);
        }

        try t.expectEqual(null, it.next());
    }
}

test "handshake: reply" {
    var buf: [512]u8 = undefined;

    {
        // no compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", null, false, &buf));
    }

    {
        // compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", null, true, &buf));
    }

    // With custom headers
    var res_headers = try Handshake.KeyValue.init(t.allocator, 2);
    defer res_headers.deinit(t.allocator);
    res_headers.add("Set-Cookie", "Yummy!");

    {
        // no compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Set-Cookie: Yummy!\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", &res_headers, false, &buf));
    }

    {
        // compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
            "Set-Cookie: Yummy!\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", &res_headers, true, &buf));
    }
}

test "KeyValue: get" {
    const allocator = t.allocator;
    var kv = try Handshake.KeyValue.init(allocator, 2);
    defer kv.deinit(t.allocator);

    var key = "content-type".*;
    kv.add(&key, "application/json");

    try t.expectString("application/json", kv.get("content-type").?);

    kv.len = 0;
    try t.expectEqual(null, kv.get("content-type"));
    kv.add(&key, "application/json2");
    try t.expectString("application/json2", kv.get("content-type").?);
}

test "KeyValue: ignores beyond max" {
    var kv = try Handshake.KeyValue.init(t.allocator, 2);
    defer kv.deinit(t.allocator);

    var n1 = "content-length".*;
    kv.add(&n1, "cl");

    var n2 = "host".*;
    kv.add(&n2, "www");

    var n3 = "authorization".*;
    kv.add(&n3, "hack");

    try t.expectString("cl", kv.get("content-length").?);
    try t.expectString("www", kv.get("host").?);
    try t.expectEqual(null, kv.get("authorization"));
}

test "pool: acquire and release" {
    // not 100% sure this is testing exactly what I want, but it's ....something ?
    var p = try Pool.init(t.allocator, 2, 10, 3, 1);
    defer p.deinit();

    var hs1a = p.acquire() catch unreachable;
    var hs2a = p.acquire() catch unreachable;
    var hs3a = p.acquire() catch unreachable; // this should be dynamically generated

    try t.expectEqual(false, &hs1a.buf[0] == &hs2a.buf[0]);
    try t.expectEqual(false, &hs2a.buf[0] == &hs3a.buf[0]);
    try t.expectEqual(10, hs1a.buf.len);
    try t.expectEqual(10, hs2a.buf.len);
    try t.expectEqual(10, hs3a.buf.len);
    try t.expectEqual(0, hs1a.req_headers.len);
    try t.expectEqual(0, hs2a.req_headers.len);
    try t.expectEqual(0, hs3a.req_headers.len);
    try t.expectEqual(3, hs1a.req_headers.keys.len);
    try t.expectEqual(3, hs2a.req_headers.keys.len);
    try t.expectEqual(3, hs3a.req_headers.keys.len);

    p.release(hs1a);

    var hs1b = p.acquire() catch unreachable;
    try t.expectEqual(true, &hs1a.buf[0] == &hs1b.buf[0]);

    p.release(hs3a);
    p.release(hs2a);
    p.release(hs1b);
}

test "Handshake.Pool: threadsafety" {
    var p = try Pool.init(t.allocator, 4, 10, 2, 2);
    defer p.deinit();

    for (p.states) |hs| {
        hs.buf[0] = 0;
    }

    const t1 = try std.Thread.spawn(.{}, testPool, .{p});
    const t2 = try std.Thread.spawn(.{}, testPool, .{p});
    const t3 = try std.Thread.spawn(.{}, testPool, .{p});
    const t4 = try std.Thread.spawn(.{}, testPool, .{p});

    t1.join();
    t2.join();
    t3.join();
    t4.join();
}

fn testPool(p: *Pool) void {
    var r = t.getRandom();
    const random = r.random();

    for (0..5000) |_| {
        var hs = p.acquire() catch unreachable;
        std.debug.assert(hs.buf[0] == 0);
        hs.buf[0] = 255;
        std.Thread.sleep(random.uintAtMost(u32, 100000));
        hs.buf[0] = 0;
        p.release(hs);
    }
}

fn testHandshake(request: []const u8, state: *Handshake.State) !?Handshake {
    @memcpy(state.buf[0..request.len], request);
    state.len = request.len;
    return Handshake.parse(state);
}
