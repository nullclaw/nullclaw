//! Generic RFC 6455 WebSocket client.
//! Used by Discord, Lark, DingTalk, QQ gateway channels and OneBot.
//! Supports both `wss://` and `ws://` transports.

const std = @import("std");
const std_compat = @import("compat");

const log = std.log.scoped(.websocket);

/// RFC 6455 handshake magic string.
pub const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket opcodes (RFC 6455 §5.2).
pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,
};

/// A parsed WebSocket frame.
/// `payload.len > 0` → heap-allocated; free with allocator.free(frame.payload).
/// `payload.len == 0` → empty static slice; do NOT free.
pub const Frame = struct {
    opcode: Opcode,
    fin: bool,
    payload: []u8,
};

/// Heap-allocated TLS state.
/// Must be heap-allocated so internal pointers remain stable after init.
pub const TlsState = struct {
    stream_reader: std_compat.net.Stream.Reader,
    stream_writer: std_compat.net.Stream.Writer,
    tls_client: std.crypto.tls.Client,
    read_buf: []u8,
    write_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
    ca_bundle: std.crypto.Certificate.Bundle = .empty,
    ca_bundle_lock: std.Io.RwLock = .init,
    owns_ca_bundle: bool = false,

    pub fn deinit(self: *TlsState, allocator: std.mem.Allocator) void {
        if (self.owns_ca_bundle) self.ca_bundle.deinit(allocator);
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
        allocator.free(self.tls_read_buf);
        allocator.free(self.tls_write_buf);
        allocator.destroy(self);
    }
};

/// WebSocket client over TLS.
/// `write_mu` serializes concurrent writes (heartbeat + gateway threads).
pub const WsClient = struct {
    allocator: std.mem.Allocator,
    stream: std_compat.net.Stream,
    tls: ?*TlsState,
    write_mu: std_compat.sync.Mutex,

    pub const Message = struct {
        opcode: Opcode,
        payload: []u8,
    };

    /// Connect to wss://host:port/path.
    /// `extra_headers`: additional HTTP request headers (without trailing CRLF).
    pub fn connect(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        path: []const u8,
        extra_headers: []const []const u8,
    ) !WsClient {
        // DNS + TCP
        const addr_list = try std_compat.net.getAddressList(allocator, host, port);
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return error.DnsResolutionFailed;
        const stream = try std_compat.net.tcpConnectToAddress(addr_list.addrs[0]);
        errdefer stream.close();

        // Allocate TLS buffers (pattern from irc.zig)
        const tls_buf_len = std.crypto.tls.Client.min_buffer_len;
        const read_buf = try allocator.alloc(u8, tls_buf_len);
        errdefer allocator.free(read_buf);
        const write_buf = try allocator.alloc(u8, tls_buf_len);
        errdefer allocator.free(write_buf);
        const tls_read_buf = try allocator.alloc(u8, tls_buf_len);
        errdefer allocator.free(tls_read_buf);
        const tls_write_buf = try allocator.alloc(u8, tls_buf_len);
        errdefer allocator.free(tls_write_buf);

        const tls_state = try allocator.create(TlsState);
        errdefer allocator.destroy(tls_state);

        tls_state.read_buf = read_buf;
        tls_state.write_buf = write_buf;
        tls_state.tls_read_buf = tls_read_buf;
        tls_state.tls_write_buf = tls_write_buf;
        tls_state.stream_reader = stream.reader(read_buf);
        tls_state.stream_writer = stream.writer(write_buf);
        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        std_compat.crypto.random.bytes(&entropy);

        var ca_bundle = std.crypto.Certificate.Bundle.empty;
        var has_ca_bundle = false;
        if (ca_bundle.rescan(allocator, std_compat.io(), std.Io.Timestamp.now(std_compat.io(), .real))) |_| {
            has_ca_bundle = true;
        } else |err| {
            // Preserve current behavior on platforms/environments where system CAs
            // are unavailable, but prefer verified TLS whenever possible.
            log.warn("WS TLS: system CA bundle unavailable, fallback to no verification: {}", .{err});
        }
        if (has_ca_bundle) {
            tls_state.ca_bundle = ca_bundle;
            tls_state.owns_ca_bundle = true;
        }

        const tls_options: std.crypto.tls.Client.Options = .{
            .host = .{ .explicit = host },
            .ca = if (has_ca_bundle) .{ .bundle = .{
                .gpa = allocator,
                .io = std_compat.io(),
                .lock = &tls_state.ca_bundle_lock,
                .bundle = &tls_state.ca_bundle,
            } } else .no_verification,
            .read_buffer = tls_read_buf,
            .write_buffer = tls_write_buf,
            .entropy = &entropy,
            .realtime_now = std.Io.Timestamp.now(std_compat.io(), .real),
            .allow_truncation_attacks = true,
        };

        tls_state.tls_client = std.crypto.tls.Client.init(
            &tls_state.stream_reader.interface,
            &tls_state.stream_writer.interface,
            tls_options,
        ) catch return error.TlsInitializationFailed;

        var client = WsClient{
            .allocator = allocator,
            .stream = stream,
            .tls = tls_state,
            .write_mu = .{},
        };
        errdefer client.deinit();

        try client.performHandshake(host, path, extra_headers);
        return client;
    }

    /// Connect to ws://host:port/path without TLS.
    pub fn connectPlain(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        path: []const u8,
        extra_headers: []const []const u8,
    ) !WsClient {
        const addr_list = try std_compat.net.getAddressList(allocator, host, port);
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return error.DnsResolutionFailed;
        const stream = try std_compat.net.tcpConnectToAddress(addr_list.addrs[0]);
        errdefer stream.close();

        var client = WsClient{
            .allocator = allocator,
            .stream = stream,
            .tls = null,
            .write_mu = .{},
        };
        errdefer client.deinit();

        try client.performHandshake(host, path, extra_headers);
        return client;
    }

    fn performHandshake(
        self: *WsClient,
        host: []const u8,
        path: []const u8,
        extra_headers: []const []const u8,
    ) !void {
        var key_raw: [16]u8 = undefined;
        std_compat.crypto.random.bytes(&key_raw);
        var key_b64: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

        var req_buf: [4096]u8 = undefined;
        var rw: std.Io.Writer = .fixed(&req_buf);
        try rw.print("GET {s} HTTP/1.1\r\n", .{path});
        try rw.print("Host: {s}\r\n", .{host});
        try rw.writeAll("Upgrade: websocket\r\n");
        try rw.writeAll("Connection: Upgrade\r\n");
        try rw.print("Sec-WebSocket-Key: {s}\r\n", .{key_b64});
        try rw.writeAll("Sec-WebSocket-Version: 13\r\n");
        for (extra_headers) |hdr| {
            try rw.print("{s}\r\n", .{hdr});
        }
        try rw.writeAll("\r\n");

        try self.writeTransport(rw.buffered());
        try self.flushTransport();

        var resp_buf: [4096]u8 = undefined;
        var resp_len: usize = 0;
        var headers_complete = false;
        while (resp_len < resp_buf.len) {
            if (self.tls) |tls| {
                const byte_ptr = tls.tls_client.reader.take(1) catch return error.WsHandshakeFailed;
                resp_buf[resp_len] = byte_ptr[0];
            } else {
                self.readExact(resp_buf[resp_len .. resp_len + 1]) catch return error.WsHandshakeFailed;
            }
            resp_len += 1;
            if (resp_len >= 4 and
                resp_buf[resp_len - 4] == '\r' and
                resp_buf[resp_len - 3] == '\n' and
                resp_buf[resp_len - 2] == '\r' and
                resp_buf[resp_len - 1] == '\n')
            {
                headers_complete = true;
                break;
            }
        }
        if (!headers_complete) {
            log.err("WS handshake: header block exceeded {d} bytes", .{resp_buf.len});
            return error.WsHandshakeFailed;
        }

        const resp = resp_buf[0..resp_len];
        if (!std.mem.startsWith(u8, resp, "HTTP/1.1 101")) {
            log.err("WS handshake: unexpected response: {s}", .{resp[0..@min(resp_len, 80)]});
            return error.WsHandshakeFailed;
        }

        const expected = computeAcceptKey(&key_b64);
        if (std.mem.indexOf(u8, resp, &expected) == null) {
            log.err("WS handshake: invalid Sec-WebSocket-Accept", .{});
            return error.WsHandshakeFailed;
        }
    }

    /// Compute expected Sec-WebSocket-Accept: base64(SHA1(key_b64 + WS_MAGIC)).
    pub fn computeAcceptKey(key_b64: []const u8) [28]u8 {
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(key_b64);
        sha1.update(WS_MAGIC);
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        sha1.final(&digest);
        var result: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&result, &digest);
        return result;
    }

    /// Read exactly buf.len bytes from the transport (TLS or plain socket).
    fn readExact(self: *WsClient, buf: []u8) !void {
        var total: usize = 0;
        while (total < buf.len) {
            const n = if (self.tls) |tls| blk: {
                var rd: [1][]u8 = .{buf[total..]};
                break :blk tls.tls_client.reader.readVec(&rd) catch |err| switch (err) {
                    error.EndOfStream => return error.ConnectionClosed,
                    else => |e| return e,
                };
            } else blk: {
                const bytes = self.stream.read(buf[total..]) catch |e| return e;
                if (bytes == 0) return error.ConnectionClosed;
                break :blk bytes;
            };
            total += n;
        }
    }

    fn writeTransport(self: *WsClient, bytes: []const u8) !void {
        if (self.tls) |tls| {
            try tls.tls_client.writer.writeAll(bytes);
            return;
        }
        try self.stream.writeAll(bytes);
    }

    fn flushTransport(self: *WsClient) !void {
        if (self.tls) |tls| {
            try tls.tls_client.writer.flush();
            try tls.stream_writer.interface.flush();
        }
    }

    /// Read one WebSocket frame.
    /// Returns null on graceful close (opcode=close from server).
    /// Ping frames are auto-answered with Pong internally.
    /// Non-empty payload is heap-allocated; free with allocator.free when len > 0.
    pub fn readFrame(self: *WsClient) !?Frame {
        var hdr: [2]u8 = undefined;
        try self.readExact(&hdr);

        const fin = (hdr[0] & 0x80) != 0;
        const opcode: Opcode = @enumFromInt(hdr[0] & 0x0F);
        const is_masked = (hdr[1] & 0x80) != 0;
        var payload_len: u64 = hdr[1] & 0x7F;

        if (payload_len == 126) {
            var ext: [2]u8 = undefined;
            try self.readExact(&ext);
            payload_len = @as(u64, ext[0]) << 8 | ext[1];
        } else if (payload_len == 127) {
            var ext: [8]u8 = undefined;
            try self.readExact(&ext);
            payload_len = 0;
            for (ext) |b| payload_len = (payload_len << 8) | b;
        }

        var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
        if (is_masked) try self.readExact(&mask_key);

        if (payload_len > 4 * 1024 * 1024) return error.FrameTooLarge;

        const plen: usize = @intCast(payload_len);
        const payload: []u8 = if (plen > 0) blk: {
            const p = try self.allocator.alloc(u8, plen);
            errdefer self.allocator.free(p);
            try self.readExact(p);
            if (is_masked) {
                for (p, 0..) |*b, i| b.* ^= mask_key[i % 4];
            }
            break :blk p;
        } else @constCast(&[_]u8{});

        switch (opcode) {
            .ping => {
                // Auto-reply with pong
                {
                    self.write_mu.lock();
                    defer self.write_mu.unlock();
                    self.writeFrameLocked(.pong, payload) catch |err| {
                        log.warn("WS auto-pong failed: {}", .{err});
                    };
                }
                return Frame{ .opcode = .ping, .fin = true, .payload = payload };
            },
            .close => {
                if (plen > 0) self.allocator.free(payload);
                return null;
            },
            else => {},
        }

        return Frame{ .opcode = opcode, .fin = fin, .payload = payload };
    }

    /// Build and write a masked WebSocket frame (caller must hold write_mu).
    fn writeFrameLocked(self: *WsClient, opcode: Opcode, payload: []const u8) !void {
        var header: [14]u8 = undefined;
        var hlen: usize = 0;

        // FIN=1, RSV=0, opcode
        header[0] = 0x80 | @as(u8, @intFromEnum(opcode));
        hlen = 1;

        // MASK=1 + payload length
        const plen = payload.len;
        if (plen <= 125) {
            header[1] = 0x80 | @as(u8, @intCast(plen));
            hlen += 1;
        } else if (plen <= 65535) {
            header[1] = 0x80 | 126;
            header[2] = @as(u8, @intCast((plen >> 8) & 0xFF));
            header[3] = @as(u8, @intCast(plen & 0xFF));
            hlen += 3;
        } else {
            header[1] = 0x80 | 127;
            const p64: u64 = plen;
            header[2] = @as(u8, @intCast((p64 >> 56) & 0xFF));
            header[3] = @as(u8, @intCast((p64 >> 48) & 0xFF));
            header[4] = @as(u8, @intCast((p64 >> 40) & 0xFF));
            header[5] = @as(u8, @intCast((p64 >> 32) & 0xFF));
            header[6] = @as(u8, @intCast((p64 >> 24) & 0xFF));
            header[7] = @as(u8, @intCast((p64 >> 16) & 0xFF));
            header[8] = @as(u8, @intCast((p64 >> 8) & 0xFF));
            header[9] = @as(u8, @intCast(p64 & 0xFF));
            hlen += 9;
        }

        // Random 4-byte masking key (RFC 6455 §5.3: client→server MUST mask)
        var mask: [4]u8 = undefined;
        std_compat.crypto.random.bytes(&mask);
        @memcpy(header[hlen..][0..4], &mask);
        hlen += 4;

        try self.writeTransport(header[0..hlen]);

        // Write masked payload in chunks
        var chunk_buf: [4096]u8 = undefined;
        var offset: usize = 0;
        while (offset < plen) {
            const chunk_len = @min(plen - offset, chunk_buf.len);
            for (0..chunk_len) |i| {
                chunk_buf[i] = payload[offset + i] ^ mask[(offset + i) % 4];
            }
            try self.writeTransport(chunk_buf[0..chunk_len]);
            offset += chunk_len;
        }

        try self.flushTransport();
    }

    /// Send a text frame (acquires write_mu).
    pub fn writeText(self: *WsClient, text: []const u8) !void {
        self.write_mu.lock();
        defer self.write_mu.unlock();
        try self.writeFrameLocked(.text, text);
    }

    /// Send a binary frame (acquires write_mu).
    pub fn writeBinary(self: *WsClient, payload: []const u8) !void {
        self.write_mu.lock();
        defer self.write_mu.unlock();
        try self.writeFrameLocked(.binary, payload);
    }

    /// Send a close frame (acquires write_mu, ignores errors).
    pub fn writeClose(self: *WsClient) void {
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeFrameLocked(.close, &.{}) catch |err| {
            log.warn("WS close frame error: {}", .{err});
        };
    }

    /// Read a complete text message, aggregating continuation frames.
    /// Returns heap-allocated string (caller frees) or null on graceful close.
    pub fn readTextMessage(self: *WsClient) !?[]u8 {
        var message: std.ArrayListUnmanaged(u8) = .empty;
        errdefer message.deinit(self.allocator);

        while (true) {
            const maybe_frame = try self.readFrame();
            if (maybe_frame == null) {
                message.deinit(self.allocator);
                return null;
            }
            const frame = maybe_frame.?;
            defer if (frame.payload.len > 0) self.allocator.free(frame.payload);

            switch (frame.opcode) {
                .text, .continuation => {
                    try message.appendSlice(self.allocator, frame.payload);
                    if (message.items.len > 4 * 1024 * 1024) {
                        message.deinit(self.allocator);
                        return error.MessageTooLarge;
                    }
                    if (frame.fin) {
                        const slice = try message.toOwnedSlice(self.allocator);
                        return slice;
                    }
                },
                .ping => {}, // auto-handled inside readFrame
                .binary => {}, // Discord uses text only
                else => {},
            }
        }
    }

    /// Read a complete text or binary message, aggregating continuation frames.
    /// Returns heap-allocated payload (caller frees) or null on graceful close.
    pub fn readMessage(self: *WsClient) !?Message {
        var message: std.ArrayListUnmanaged(u8) = .empty;
        errdefer message.deinit(self.allocator);
        var message_opcode: ?Opcode = null;

        while (true) {
            const maybe_frame = try self.readFrame();
            if (maybe_frame == null) {
                message.deinit(self.allocator);
                return null;
            }
            const frame = maybe_frame.?;
            defer if (frame.payload.len > 0) self.allocator.free(frame.payload);

            switch (frame.opcode) {
                .text, .binary => {
                    if (message_opcode == null) {
                        message_opcode = frame.opcode;
                    } else if (message_opcode.? != frame.opcode) {
                        message.deinit(self.allocator);
                        return error.WsProtocolError;
                    }
                    try message.appendSlice(self.allocator, frame.payload);
                    if (message.items.len > 4 * 1024 * 1024) {
                        message.deinit(self.allocator);
                        return error.MessageTooLarge;
                    }
                    if (frame.fin) {
                        const payload = try message.toOwnedSlice(self.allocator);
                        return .{
                            .opcode = message_opcode.?,
                            .payload = payload,
                        };
                    }
                },
                .continuation => {
                    if (message_opcode == null) {
                        message.deinit(self.allocator);
                        return error.WsProtocolError;
                    }
                    try message.appendSlice(self.allocator, frame.payload);
                    if (message.items.len > 4 * 1024 * 1024) {
                        message.deinit(self.allocator);
                        return error.MessageTooLarge;
                    }
                    if (frame.fin) {
                        const payload = try message.toOwnedSlice(self.allocator);
                        return .{
                            .opcode = message_opcode.?,
                            .payload = payload,
                        };
                    }
                },
                .ping => {}, // auto-handled inside readFrame
                else => {},
            }
        }
    }

    pub fn deinit(self: *WsClient) void {
        if (self.tls) |tls| {
            tls.tls_client.end() catch |err| {
                log.warn("TLS close_notify failed: {}", .{err});
            };
            tls.deinit(self.allocator);
        }
        self.stream.close();
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Pure utility functions (testable without network)
// ════════════════════════════════════════════════════════════════════════════

/// Build a masked WebSocket frame into `buf`. Returns bytes written.
/// mask_key: 4-byte masking key to use (caller controls for deterministic tests).
pub fn buildFrame(
    buf: []u8,
    opcode: Opcode,
    payload: []const u8,
    mask_key: [4]u8,
) !usize {
    var w: std.Io.Writer = .fixed(buf);

    // Byte 0: FIN=1, RSV=0, opcode
    try w.writeByte(0x80 | @as(u8, @intFromEnum(opcode)));

    // Byte 1: MASK=1 + payload length
    const plen = payload.len;
    if (plen <= 125) {
        try w.writeByte(0x80 | @as(u8, @intCast(plen)));
    } else if (plen <= 65535) {
        try w.writeByte(0x80 | 126);
        try w.writeByte(@as(u8, @intCast((plen >> 8) & 0xFF)));
        try w.writeByte(@as(u8, @intCast(plen & 0xFF)));
    } else {
        try w.writeByte(0x80 | 127);
        const p64: u64 = plen;
        try w.writeByte(@as(u8, @intCast((p64 >> 56) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 48) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 40) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 32) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 24) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 16) & 0xFF)));
        try w.writeByte(@as(u8, @intCast((p64 >> 8) & 0xFF)));
        try w.writeByte(@as(u8, @intCast(p64 & 0xFF)));
    }

    // Masking key
    try w.writeAll(&mask_key);

    // Masked payload
    for (payload, 0..) |b, i| {
        try w.writeByte(b ^ mask_key[i % 4]);
    }

    return w.buffered().len;
}

/// Parse a WebSocket frame header from raw bytes (server→client, unmasked).
/// Returns header metadata and how many bytes the header consumed.
pub const ParsedHeader = struct {
    opcode: Opcode,
    fin: bool,
    masked: bool,
    payload_len: u64,
    header_bytes: usize, // how many bytes the header occupies
};

pub fn parseFrameHeader(bytes: []const u8) !ParsedHeader {
    if (bytes.len < 2) return error.InsufficientData;
    const fin = (bytes[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(bytes[0] & 0x0F);
    const masked = (bytes[1] & 0x80) != 0;
    var payload_len: u64 = bytes[1] & 0x7F;
    var hlen: usize = 2;

    if (payload_len == 126) {
        if (bytes.len < 4) return error.InsufficientData;
        payload_len = @as(u64, bytes[2]) << 8 | bytes[3];
        hlen = 4;
    } else if (payload_len == 127) {
        if (bytes.len < 10) return error.InsufficientData;
        payload_len = 0;
        for (bytes[2..10]) |b| payload_len = (payload_len << 8) | b;
        hlen = 10;
    }

    if (masked) hlen += 4;
    return ParsedHeader{ .opcode = opcode, .fin = fin, .masked = masked, .payload_len = payload_len, .header_bytes = hlen };
}

/// Apply WebSocket XOR masking in-place.
pub fn applyMask(payload: []u8, mask_key: [4]u8) void {
    for (payload, 0..) |*b, i| b.* ^= mask_key[i % 4];
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "ws accept key known value" {
    // Known test vector from RFC 6455 Section 1.3
    // Client key: "dGhlIHNhbXBsZSBub25jZQ=="
    // Expected:   "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = WsClient.computeAcceptKey(key);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "ws connectPlain compiles with nullable tls transport" {
    const client = WsClient{
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls = null,
        .write_mu = .{},
    };
    try std.testing.expect(client.tls == null);
}

test "ws accept key length" {
    var key: [24]u8 = undefined;
    std_compat.crypto.random.bytes(&key);
    const accept = WsClient.computeAcceptKey(&key);
    try std.testing.expectEqual(@as(usize, 28), accept.len);
}

test "ws handshake key is 24 chars base64" {
    var key_raw: [16]u8 = undefined;
    std_compat.crypto.random.bytes(&key_raw);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);
    // 16 bytes → 24 base64 chars (no padding needed since 16 is divisible by 3? No, 16/3=5r1 → 24 with padding)
    // Actually 16 bytes = 128 bits → ceil(128/6) = 22 chars + 2 padding = 24. Correct.
    try std.testing.expectEqual(@as(usize, 24), key_b64.len);
    // Verify all chars are valid base64
    for (key_b64) |c| {
        const valid = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '+' or c == '/' or c == '=';
        try std.testing.expect(valid);
    }
}

test "ws opcode enum values" {
    try std.testing.expectEqual(@as(u4, 0), @intFromEnum(Opcode.continuation));
    try std.testing.expectEqual(@as(u4, 1), @intFromEnum(Opcode.text));
    try std.testing.expectEqual(@as(u4, 2), @intFromEnum(Opcode.binary));
    try std.testing.expectEqual(@as(u4, 8), @intFromEnum(Opcode.close));
    try std.testing.expectEqual(@as(u4, 9), @intFromEnum(Opcode.ping));
    try std.testing.expectEqual(@as(u4, 10), @intFromEnum(Opcode.pong));
}

test "ws buildFrame text empty payload" {
    var buf: [16]u8 = undefined;
    const mask: [4]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
    const n = try buildFrame(&buf, .text, &.{}, mask);
    // Header: 0x81 (FIN+text), 0x80 (MASK+len=0), 4-byte mask
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]); // FIN=1, opcode=1 (text)
    try std.testing.expectEqual(@as(u8, 0x80), buf[1]); // MASK=1, len=0
    try std.testing.expectEqual(@as(u8, 0x01), buf[2]); // mask[0]
    try std.testing.expectEqual(@as(u8, 0x02), buf[3]); // mask[1]
    try std.testing.expectEqual(@as(u8, 0x03), buf[4]); // mask[2]
    try std.testing.expectEqual(@as(u8, 0x04), buf[5]); // mask[3]
}

test "ws buildFrame text short payload" {
    var buf: [32]u8 = undefined;
    const mask: [4]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD };
    const payload = "Hi";
    const n = try buildFrame(&buf, .text, payload, mask);
    // Header: 0x81, 0x82 (MASK+len=2), 4-byte mask, 2 masked bytes
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]); // FIN+text
    try std.testing.expectEqual(@as(u8, 0x82), buf[1]); // MASK+len=2
    // Masked: 'H' ^ 0xAA, 'i' ^ 0xBB
    try std.testing.expectEqual(@as(u8, 'H' ^ 0xAA), buf[6]);
    try std.testing.expectEqual(@as(u8, 'i' ^ 0xBB), buf[7]);
}

test "ws buildFrame ping opcode" {
    var buf: [16]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    const n = try buildFrame(&buf, .ping, &.{}, mask);
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqual(@as(u8, 0x89), buf[0]); // FIN=1, opcode=9 (ping)
}

test "ws buildFrame close opcode" {
    var buf: [16]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    _ = try buildFrame(&buf, .close, &.{}, mask);
    try std.testing.expectEqual(@as(u8, 0x88), buf[0]); // FIN=1, opcode=8 (close)
}

test "ws buildFrame pong opcode" {
    var buf: [16]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    _ = try buildFrame(&buf, .pong, &.{}, mask);
    try std.testing.expectEqual(@as(u8, 0x8A), buf[0]); // FIN=1, opcode=10 (pong)
}

test "ws buildFrame 126-byte payload" {
    // Payload of exactly 126 bytes requires 2-byte extended length
    var buf: [256]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    var payload: [126]u8 = undefined;
    @memset(&payload, 'A');
    const n = try buildFrame(&buf, .text, &payload, mask);
    // Header: 2 + 2 (extended len) + 4 (mask) = 8 bytes, plus 126 payload = 134
    try std.testing.expectEqual(@as(usize, 134), n);
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x80 | 126), buf[1]); // MASK + 126 sentinel
    try std.testing.expectEqual(@as(u8, 0), buf[2]); // extended len high byte
    try std.testing.expectEqual(@as(u8, 126), buf[3]); // extended len low byte
}

test "ws buildFrame 65535-byte payload uses 2-byte extended length" {
    // Verify header bytes for 65535-byte payload
    var buf: [65535 + 14]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    var payload: [65535]u8 = undefined;
    @memset(&payload, 0x42);
    const n = try buildFrame(&buf, .binary, &payload, mask);
    // Header: 2 + 2 + 4 = 8 bytes + 65535 = 65543
    try std.testing.expectEqual(@as(usize, 65543), n);
    try std.testing.expectEqual(@as(u8, 0x80 | 126), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xFF), buf[2]); // 65535 >> 8
    try std.testing.expectEqual(@as(u8, 0xFF), buf[3]); // 65535 & 0xFF
}

test "ws buildFrame 65536-byte payload uses 8-byte extended length" {
    // 65536 bytes requires 8-byte extended length
    const payload_len = 65536;
    var buf: [payload_len + 14]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    var payload: [payload_len]u8 = undefined;
    @memset(&payload, 0x42);
    const n = try buildFrame(&buf, .binary, &payload, mask);
    // Header: 2 + 8 + 4 = 14 bytes + 65536 = 65550
    try std.testing.expectEqual(@as(usize, 65550), n);
    try std.testing.expectEqual(@as(u8, 0x80 | 127), buf[1]);
    // Extended length: 65536 = 0x00_00_00_00_00_01_00_00
    try std.testing.expectEqual(@as(u8, 0), buf[2]);
    try std.testing.expectEqual(@as(u8, 0), buf[3]);
    try std.testing.expectEqual(@as(u8, 0), buf[4]);
    try std.testing.expectEqual(@as(u8, 0), buf[5]);
    try std.testing.expectEqual(@as(u8, 0), buf[6]);
    try std.testing.expectEqual(@as(u8, 1), buf[7]);
    try std.testing.expectEqual(@as(u8, 0), buf[8]);
    try std.testing.expectEqual(@as(u8, 0), buf[9]);
}

test "ws parseFrameHeader short text frame unmasked" {
    // Server sends unmasked text frame: FIN=1, op=1, len=5
    const bytes = [_]u8{ 0x81, 0x05 };
    const h = try parseFrameHeader(&bytes);
    try std.testing.expect(h.fin);
    try std.testing.expectEqual(Opcode.text, h.opcode);
    try std.testing.expect(!h.masked);
    try std.testing.expectEqual(@as(u64, 5), h.payload_len);
    try std.testing.expectEqual(@as(usize, 2), h.header_bytes);
}

test "ws parseFrameHeader 126 extended length" {
    const bytes = [_]u8{ 0x82, 0x7E, 0x00, 0x80 }; // binary, len=128
    const h = try parseFrameHeader(&bytes);
    try std.testing.expectEqual(Opcode.binary, h.opcode);
    try std.testing.expectEqual(@as(u64, 128), h.payload_len);
    try std.testing.expectEqual(@as(usize, 4), h.header_bytes);
}

test "ws parseFrameHeader 127 extended length" {
    // 8-byte extended length = 70000
    const bytes = [_]u8{ 0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70 }; // 70000
    const h = try parseFrameHeader(&bytes);
    try std.testing.expectEqual(@as(u64, 70000), h.payload_len);
    try std.testing.expectEqual(@as(usize, 10), h.header_bytes);
}

test "ws parseFrameHeader continuation frame" {
    const bytes = [_]u8{ 0x00, 0x03 }; // FIN=0, op=0 (continuation), len=3
    const h = try parseFrameHeader(&bytes);
    try std.testing.expect(!h.fin);
    try std.testing.expectEqual(Opcode.continuation, h.opcode);
    try std.testing.expectEqual(@as(u64, 3), h.payload_len);
}

test "ws parseFrameHeader masked frame header_bytes includes mask" {
    // Masked frame: MASK bit set → header_bytes includes 4 mask bytes
    const bytes = [_]u8{ 0x81, 0x85, 0xAA, 0xBB, 0xCC, 0xDD }; // text, masked, len=5
    const h = try parseFrameHeader(&bytes);
    try std.testing.expect(h.masked);
    try std.testing.expectEqual(@as(u64, 5), h.payload_len);
    try std.testing.expectEqual(@as(usize, 6), h.header_bytes); // 2 + 4 mask
}

test "ws parseFrameHeader insufficient data returns error" {
    const bytes = [_]u8{0x81};
    const result = parseFrameHeader(&bytes);
    try std.testing.expectError(error.InsufficientData, result);
}

test "ws applyMask XOR correctness" {
    var payload = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    const mask = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    applyMask(&payload, mask);
    // Masked
    try std.testing.expectEqual(@as(u8, 'H' ^ 0x37), payload[0]);
    try std.testing.expectEqual(@as(u8, 'e' ^ 0xFA), payload[1]);
    try std.testing.expectEqual(@as(u8, 'l' ^ 0x21), payload[2]);
    try std.testing.expectEqual(@as(u8, 'l' ^ 0x3D), payload[3]);
    try std.testing.expectEqual(@as(u8, 'o' ^ 0x37), payload[4]); // mask repeats
    // Double-mask restores original
    applyMask(&payload, mask);
    try std.testing.expectEqualStrings("Hello", &payload);
}

test "ws applyMask empty payload is no-op" {
    var payload: [0]u8 = .{};
    const mask = [4]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    applyMask(&payload, mask); // must not crash
}

test "ws applyMask single byte" {
    var payload = [_]u8{0x42};
    const mask = [4]u8{ 0xAA, 0, 0, 0 };
    applyMask(&payload, mask);
    try std.testing.expectEqual(@as(u8, 0x42 ^ 0xAA), payload[0]);
}

test "ws buildFrame masking is correct" {
    // Build frame and verify masking
    const payload = "Test";
    const mask = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    var buf: [32]u8 = undefined;
    const n = try buildFrame(&buf, .text, payload, mask);
    // Mask bytes are at buf[2..6], masked payload at buf[6..10]
    try std.testing.expectEqual(@as(usize, 10), n);
    try std.testing.expectEqual(@as(u8, 'T' ^ 0x12), buf[6]);
    try std.testing.expectEqual(@as(u8, 'e' ^ 0x34), buf[7]);
    try std.testing.expectEqual(@as(u8, 's' ^ 0x56), buf[8]);
    try std.testing.expectEqual(@as(u8, 't' ^ 0x78), buf[9]);
}

test "ws WS_MAGIC constant" {
    try std.testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", WS_MAGIC);
}

test "ws computeAcceptKey is deterministic" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const a1 = WsClient.computeAcceptKey(key);
    const a2 = WsClient.computeAcceptKey(key);
    try std.testing.expectEqualStrings(&a1, &a2);
}

test "ws parseFrameHeader close frame" {
    const bytes = [_]u8{ 0x88, 0x00 }; // FIN=1, close, len=0
    const h = try parseFrameHeader(&bytes);
    try std.testing.expectEqual(Opcode.close, h.opcode);
    try std.testing.expect(h.fin);
    try std.testing.expectEqual(@as(u64, 0), h.payload_len);
}

test "ws parseFrameHeader ping frame" {
    const bytes = [_]u8{ 0x89, 0x00 }; // FIN=1, ping, len=0
    const h = try parseFrameHeader(&bytes);
    try std.testing.expectEqual(Opcode.ping, h.opcode);
    try std.testing.expect(h.fin);
}

test "ws buildFrame zero-len payload close" {
    var buf: [16]u8 = undefined;
    const mask: [4]u8 = .{ 0, 0, 0, 0 };
    const n = try buildFrame(&buf, .close, &.{}, mask);
    try std.testing.expectEqual(@as(usize, 6), n); // 2 header + 4 mask
    try std.testing.expectEqual(@as(u8, 0x88), buf[0]); // close
    try std.testing.expectEqual(@as(u8, 0x80), buf[1]); // MASK=1, len=0
}

// Regression: v2026.3.12 applied a blanket `n == 0 → ConnectionClosed` check
// to both TLS and plain socket paths. TLS readVec may return 0 while it
// refills its internal buffer or processes post-handshake records, so only
// plain sockets should treat a zero-byte read as EOF.

fn fake_tls_test_stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
    return error.EndOfStream;
}

fn fake_tls_read_vec_zero_then_byte(reader: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    if (reader.seek == 0 and reader.end == 0) {
        // Mimic std.crypto.tls.Client.readVec buffering internal TLS records
        // before returning any application bytes to the caller.
        reader.seek = 1;
        reader.end = 1;
        return 0;
    }
    data[0][0] = 'Z';
    return 1;
}

test "ws readExact TLS tolerates transient zero readVec return" {
    var tls_reader_storage = [_]u8{0};
    var tls_state: TlsState = undefined;
    tls_state.tls_client = undefined;
    tls_state.tls_client.reader = .{
        .buffer = &tls_reader_storage,
        .seek = 0,
        .end = 0,
        .vtable = &.{
            .stream = fake_tls_test_stream,
            .readVec = fake_tls_read_vec_zero_then_byte,
        },
    };

    var client = WsClient{
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls = &tls_state,
        .write_mu = .{},
    };

    var buf: [1]u8 = undefined;
    try client.readExact(&buf);
    try std.testing.expectEqual(@as(u8, 'Z'), buf[0]);
}

test "ws readExact plain returns ConnectionClosed on immediate EOF" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fds = try std.Io.Threaded.pipe2(.{});
    std.Io.Threaded.closeFd(fds[1]); // close write end → read returns 0

    var client = WsClient{
        .allocator = std.testing.allocator,
        .stream = .{ .handle = fds[0] },
        .tls = null,
        .write_mu = .{},
    };
    defer std.Io.Threaded.closeFd(fds[0]);

    var buf: [1]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, client.readExact(&buf));
}

test "ws readExact plain reads data then ConnectionClosed on EOF" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fds = try std.Io.Threaded.pipe2(.{});

    switch (std.posix.errno(std.posix.system.write(fds[1], "OK".ptr, "OK".len))) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    std.Io.Threaded.closeFd(fds[1]);

    var client = WsClient{
        .allocator = std.testing.allocator,
        .stream = .{ .handle = fds[0] },
        .tls = null,
        .write_mu = .{},
    };
    defer std.Io.Threaded.closeFd(fds[0]);

    // First read succeeds
    var buf: [2]u8 = undefined;
    try client.readExact(&buf);
    try std.testing.expectEqualStrings("OK", &buf);

    // Next read hits EOF
    var buf2: [1]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, client.readExact(&buf2));
}
