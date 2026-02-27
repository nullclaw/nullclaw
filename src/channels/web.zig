const std = @import("std");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const config_types = @import("../config_types.zig");
const websocket = @import("websocket");

const log = std.log.scoped(.web);

pub const WebChannel = struct {
    allocator: std.mem.Allocator,
    port: u16,
    listen_address: []const u8,
    max_connections: u16,
    account_id: []const u8,
    bus: ?*bus_mod.Bus = null,

    // Auth token: 32 random bytes → 64 hex chars
    token: [64]u8 = undefined,
    token_initialized: bool = false,

    // Runtime state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    server: ?WsServer = null,
    server_thread: ?std.Thread = null,

    // Connection tracking
    connections: ConnectionList = .{},

    const WsServer = websocket.Server(WsHandler);

    const vtable = root.Channel.VTable{
        .start = wsStart,
        .stop = wsStop,
        .send = wsSend,
        .name = wsName,
        .healthCheck = wsHealthCheck,
    };

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WebConfig) WebChannel {
        return .{
            .allocator = allocator,
            .port = cfg.port,
            .listen_address = cfg.listen,
            .max_connections = cfg.max_connections,
            .account_id = cfg.account_id,
        };
    }

    pub fn channel(self: *WebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setBus(self: *WebChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    /// Generate a random auth token (64 hex chars from 32 random bytes).
    pub fn generateToken(self: *WebChannel) void {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        self.token = std.fmt.bytesToHex(random_bytes, .lower);
        self.token_initialized = true;
    }

    /// Validate a token string against the stored token.
    pub fn validateToken(self: *const WebChannel, candidate: []const u8) bool {
        if (!self.token_initialized) return false;
        if (candidate.len != 64) return false;
        return std.crypto.timing_safe.eql([64]u8, candidate[0..64].*, self.token);
    }

    // ── vtable implementations ──

    fn wsStart(ctx: *anyopaque) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        self.generateToken();

        self.server = WsServer.init(self.allocator, .{
            .port = self.port,
            .address = self.listen_address,
            .max_conn = @intCast(self.max_connections),
        }) catch |err| {
            log.err("Failed to init WebSocket server: {}", .{err});
            return err;
        };

        self.running.store(true, .release);

        self.server_thread = std.Thread.spawn(.{}, serverListenThread, .{self}) catch |err| {
            log.err("Failed to spawn WS server thread: {}", .{err});
            self.running.store(false, .release);
            if (self.server) |*s| s.deinit();
            self.server = null;
            return err;
        };

        log.info("Web channel ready on {s}:{d}", .{ self.listen_address, self.port });
        log.info("Connect: ws://{s}:{d}/ws?token={s}", .{ self.listen_address, self.port, &self.token });
    }

    fn serverListenThread(self: *WebChannel) void {
        if (self.server) |*s| {
            s.listen(self) catch |err| {
                if (self.running.load(.acquire)) {
                    log.err("WebSocket server listen error: {}", .{err});
                }
            };
        }
    }

    fn wsStop(ctx: *anyopaque) void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        self.running.store(false, .release);

        // Stop the server (closes listening socket, triggers listen loop exit)
        if (self.server) |*s| {
            s.stop();
        }

        // Wait for server thread to finish
        if (self.server_thread) |t| {
            t.join();
            self.server_thread = null;
        }

        // Clean up connections
        self.connections.closeAll();

        if (self.server) |*s| {
            s.deinit();
            self.server = null;
        }
    }

    fn wsSend(ctx: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));

        // Build JSON response: {"type":"assistant_message","content":"...","session_id":"..."}
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeAll("{\"type\":\"assistant_message\",\"content\":");
        try root.appendJsonStringW(w, message);
        try w.writeAll(",\"session_id\":");
        try root.appendJsonStringW(w, target);
        try w.writeByte('}');

        self.connections.broadcast(target, buf.items);
    }

    fn wsName(_: *anyopaque) []const u8 {
        return "web";
    }

    fn wsHealthCheck(ctx: *anyopaque) bool {
        const self: *const WebChannel = @ptrCast(@alignCast(ctx));
        return self.running.load(.acquire);
    }

    // ── Connection tracking ──

    pub const ConnectionList = struct {
        mutex: std.Thread.Mutex = .{},
        entries: [MAX_TRACKED]?ConnEntry = [_]?ConnEntry{null} ** MAX_TRACKED,

        const MAX_TRACKED = 64;

        const ConnEntry = struct {
            conn: *websocket.Conn,
            session_id: [64]u8 = [_]u8{0} ** 64,
            session_len: u8 = 0,
        };

        fn add(self: *ConnectionList, conn: *websocket.Conn, session_id: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    var entry = ConnEntry{ .conn = conn };
                    const len = @min(session_id.len, 64);
                    @memcpy(entry.session_id[0..len], session_id[0..len]);
                    entry.session_len = @intCast(len);
                    slot.* = entry;
                    return;
                }
            }
            log.warn("Connection list full, dropping connection", .{});
        }

        fn remove(self: *ConnectionList, conn: *websocket.Conn) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    if (entry.conn == conn) {
                        slot.* = null;
                        return;
                    }
                }
            }
        }

        fn broadcast(self: *ConnectionList, session_id: []const u8, data: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    const sid = entry.session_id[0..entry.session_len];
                    if (std.mem.eql(u8, sid, session_id)) {
                        entry.conn.write(data) catch |err| {
                            log.warn("Failed to send to WS client: {}", .{err});
                        };
                    }
                }
            }
        }

        fn closeAll(self: *ConnectionList) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    entry.conn.close(.{ .code = 1001, .reason = "server shutting down" }) catch {};
                    slot.* = null;
                }
            }
        }
    };

    // ── WebSocket Handler (used by websocket.Server) ──

    const WsHandler = struct {
        web_channel: *WebChannel,
        conn: *websocket.Conn,
        session_id: [64]u8 = [_]u8{0} ** 64,
        session_len: u8 = 0,

        pub fn init(h: *websocket.Handshake, conn: *websocket.Conn, web_channel: *WebChannel) !WsHandler {
            // Validate token from URL query string: /ws?token=<64hex>
            const url = h.url;
            const token = extractQueryParam(url, "token") orelse {
                log.warn("WS connection rejected: no token", .{});
                return error.Forbidden;
            };

            if (!web_channel.validateToken(token)) {
                log.warn("WS connection rejected: invalid token", .{});
                return error.Forbidden;
            }

            // Extract session_id from query (optional, default to "default")
            const sid = extractQueryParam(url, "session_id") orelse "default";

            var handler = WsHandler{
                .web_channel = web_channel,
                .conn = conn,
            };
            const len = @min(sid.len, 64);
            @memcpy(handler.session_id[0..len], sid[0..len]);
            handler.session_len = @intCast(len);

            web_channel.connections.add(conn, sid);
            log.info("WS client connected (session={s})", .{sid});

            return handler;
        }

        pub fn clientMessage(self: *WsHandler, data: []const u8) !void {
            // Parse incoming JSON: {"type":"user_message","content":"...","session_id":"..."}
            const parsed = std.json.parseFromSlice(std.json.Value, self.web_channel.allocator, data, .{}) catch {
                log.warn("WS: invalid JSON from client", .{});
                return;
            };
            defer parsed.deinit();

            const obj = switch (parsed.value) {
                .object => |o| o,
                else => {
                    log.warn("WS: expected JSON object", .{});
                    return;
                },
            };

            const content = switch (obj.get("content") orelse return) {
                .string => |s| s,
                else => return,
            };

            // Use session_id from message if provided, otherwise from connection
            const msg_session = switch (obj.get("session_id") orelse .null) {
                .string => |s| s,
                else => self.session_id[0..self.session_len],
            };

            // Use sender_id from message if provided, otherwise "web-user"
            const sender_id = switch (obj.get("sender_id") orelse .null) {
                .string => |s| s,
                else => "web-user",
            };

            const allocator = self.web_channel.allocator;
            const session_key = std.fmt.allocPrint(allocator, "web:{s}:direct:{s}", .{
                self.web_channel.account_id,
                msg_session,
            }) catch return;
            defer allocator.free(session_key);

            // Build metadata JSON
            var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
            defer metadata_buf.deinit(allocator);
            const mw = metadata_buf.writer(allocator);
            mw.writeAll("{\"is_dm\":true,\"account_id\":") catch return;
            root.appendJsonStringW(mw, self.web_channel.account_id) catch return;
            mw.writeByte('}') catch return;

            const msg = bus_mod.makeInboundFull(
                allocator,
                "web",
                sender_id,
                msg_session,
                content,
                session_key,
                &.{},
                metadata_buf.items,
            ) catch |err| {
                log.warn("WS: failed to create inbound message: {}", .{err});
                return;
            };

            if (self.web_channel.bus) |b| {
                b.publishInbound(msg) catch |err| {
                    log.warn("WS: failed to publish inbound: {}", .{err});
                    msg.deinit(allocator);
                };
            } else {
                msg.deinit(allocator);
            }
        }

        pub fn close(self: *WsHandler) void {
            self.web_channel.connections.remove(self.conn);
            log.info("WS client disconnected", .{});
        }
    };
};

/// Extract a query parameter value from a URL string.
/// Returns the value slice or null if not found.
fn extractQueryParam(url: []const u8, param_name: []const u8) ?[]const u8 {
    // Find '?' start of query string
    const query_start = std.mem.indexOfScalar(u8, url, '?') orelse return null;
    var remaining = url[query_start + 1 ..];

    while (remaining.len > 0) {
        // Find end of this param (& or end of string)
        const amp = std.mem.indexOfScalar(u8, remaining, '&');
        const pair = if (amp) |i| remaining[0..i] else remaining;

        // Split on '='
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }

        remaining = if (amp) |i| remaining[i + 1 ..] else &.{};
    }

    return null;
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

test "WebChannel initFromConfig uses defaults" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectEqual(@as(u16, 32123), ch.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.listen_address);
    try std.testing.expectEqual(@as(u16, 10), ch.max_connections);
    try std.testing.expectEqualStrings("default", ch.account_id);
    try std.testing.expect(ch.bus == null);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "WebChannel initFromConfig uses custom values" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .port = 8080,
        .listen = "0.0.0.0",
        .max_connections = 5,
        .account_id = "web-main",
    });
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqualStrings("0.0.0.0", ch.listen_address);
    try std.testing.expectEqual(@as(u16, 5), ch.max_connections);
    try std.testing.expectEqualStrings("web-main", ch.account_id);
}

test "WebChannel vtable name returns web" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("web", iface.name());
}

test "WebChannel generateToken produces 64 hex chars" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.token_initialized);
    ch.generateToken();
    try std.testing.expect(ch.token_initialized);
    try std.testing.expectEqual(@as(usize, 64), ch.token.len);
    for (&ch.token) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "WebChannel validateToken accepts correct token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(ch.validateToken(&ch.token));
}

test "WebChannel validateToken rejects wrong token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    var bad_token: [64]u8 = undefined;
    @memset(&bad_token, 'x');
    try std.testing.expect(!ch.validateToken(&bad_token));
}

test "WebChannel validateToken rejects wrong length" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(!ch.validateToken("short"));
    try std.testing.expect(!ch.validateToken(""));
}

test "WebChannel validateToken rejects before init" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.validateToken("a" ** 64));
}

test "WebChannel setBus stores bus reference" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    try std.testing.expect(ch.bus == &bus);
}

test "WebChannel two instances have different tokens" {
    var ch1 = WebChannel.initFromConfig(std.testing.allocator, .{});
    var ch2 = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch1.generateToken();
    ch2.generateToken();
    try std.testing.expect(!std.mem.eql(u8, &ch1.token, &ch2.token));
}

test "extractQueryParam finds token" {
    try std.testing.expectEqualStrings("abc123", extractQueryParam("/ws?token=abc123", "token").?);
}

test "extractQueryParam finds param among multiple" {
    try std.testing.expectEqualStrings("hello", extractQueryParam("/ws?token=abc&session_id=hello", "session_id").?);
    try std.testing.expectEqualStrings("abc", extractQueryParam("/ws?token=abc&session_id=hello", "token").?);
}

test "extractQueryParam returns null for missing param" {
    try std.testing.expect(extractQueryParam("/ws?token=abc", "session_id") == null);
    try std.testing.expect(extractQueryParam("/ws", "token") == null);
    try std.testing.expect(extractQueryParam("/ws?", "token") == null);
}

test "ConnectionList add and remove" {
    const list = WebChannel.ConnectionList{};
    // We can't create real websocket.Conn in tests, but we can verify the structure compiles
    try std.testing.expectEqual(@as(usize, 64), list.entries.len);
}

test {
    @import("std").testing.refAllDecls(@This());
}
