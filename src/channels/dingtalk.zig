const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const websocket = @import("../websocket.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.dingtalk);

/// DingTalk channel — connects via Stream Mode WebSocket for real-time messages.
/// Replies are sent through per-message session webhook URLs.
pub const DingTalkChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    allow_from: []const []const u8,
    subscribe_events: bool = false,
    subscriptions: []const config_types.DingTalkSubscription = &.{},
    ua: ?[]const u8 = null,
    local_ip: ?[]const u8 = null,
    bus: ?*bus_mod.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    gateway_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),

    const SocketFd = std.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std.os.windows.ws2_32.INVALID_SOCKET,
        else => -1,
    };

    pub const GATEWAY_URL = "https://api.dingtalk.com/v1.0/gateway/connections/open";
    pub const BOT_MESSAGE_TOPIC = "/v1.0/im/bot/messages/get";
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    const ConnectionInfo = struct {
        endpoint: []const u8,
        ticket: []const u8,
    };

    const EndpointParts = struct {
        host: []const u8,
        port: u16,
        path: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        client_id: []const u8,
        client_secret: []const u8,
        allow_from: []const []const u8,
    ) DingTalkChannel {
        return .{
            .allocator = allocator,
            .account_id = "default",
            .client_id = client_id,
            .client_secret = client_secret,
            .allow_from = allow_from,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.DingTalkConfig) DingTalkChannel {
        return .{
            .allocator = allocator,
            .account_id = cfg.account_id,
            .client_id = cfg.client_id,
            .client_secret = cfg.client_secret,
            .allow_from = cfg.allow_from,
            .subscribe_events = cfg.subscribe_events,
            .subscriptions = cfg.subscriptions,
            .ua = cfg.ua,
            .local_ip = cfg.local_ip,
        };
    }

    pub fn setBus(self: *DingTalkChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn channelName(_: *DingTalkChannel) []const u8 {
        return "dingtalk";
    }

    pub fn isUserAllowed(self: *const DingTalkChannel, user_id: []const u8) bool {
        return root.isAllowedExact(self.allow_from, user_id);
    }

    pub fn healthCheck(self: *DingTalkChannel) bool {
        return self.running.load(.acquire);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message via DingTalk session webhook URL.
    /// The target is expected to be the per-session webhook URL provided by the DingTalk Stream API.
    pub fn sendMessage(self: *DingTalkChannel, webhook_url: []const u8, text: []const u8) !void {
        // Build JSON body: {"msgtype":"markdown","markdown":{"title":"nullclaw","text":"..."}}
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"msgtype\":\"markdown\",\"markdown\":{\"title\":\"nullclaw\",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}}");
        const body = fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = webhook_url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        }) catch return error.DingTalkApiError;

        if (result.status != .ok) {
            return error.DingTalkApiError;
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(fd);
            } else {
                std.posix.close(fd);
            }
        }
        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *DingTalkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn gatewayLoop(self: *DingTalkChannel) void {
        while (self.running.load(.acquire)) {
            self.runGatewayOnce() catch |err| {
                log.warn("DingTalk gateway error: {}", .{err});
            };
            if (!self.running.load(.acquire)) break;
            var slept: u64 = 0;
            while (slept < RECONNECT_DELAY_NS and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                slept += 100 * std.time.ns_per_ms;
            }
        }
        self.ws_fd.store(invalid_socket, .release);
    }

    fn runGatewayOnce(self: *DingTalkChannel) !void {
        const conn = try self.openConnection();
        defer {
            self.allocator.free(conn.endpoint);
            self.allocator.free(conn.ticket);
        }

        const parts = try parseEndpoint(conn.endpoint);
        const path = try buildTicketPath(self.allocator, parts.path, conn.ticket);
        defer self.allocator.free(path);

        var ws = try websocket.WsClient.connect(
            self.allocator,
            parts.host,
            parts.port,
            path,
            &.{},
        );
        defer ws.deinit();
        self.ws_fd.store(ws.stream.handle, .release);
        defer self.ws_fd.store(invalid_socket, .release);

        while (self.running.load(.acquire)) {
            const msg = ws.readTextMessage() catch |err| {
                log.warn("DingTalk read error: {}", .{err});
                break;
            };
            if (msg == null) break;
            const text = msg.?;
            defer self.allocator.free(text);
            if (!self.handleMessage(&ws, text)) break;
        }
    }

    fn openConnection(self: *DingTalkChannel) !ConnectionInfo {
        const body = try self.buildOpenBody();
        defer self.allocator.free(body);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = GATEWAY_URL },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                .{ .name = "Accept", .value = "application/json" },
            },
            .response_writer = &aw.writer,
        }) catch return error.DingTalkApiError;

        if (result.status != .ok) return error.DingTalkApiError;

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.DingTalkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.DingTalkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.DingTalkApiError;

        const endpoint_val = parsed.value.object.get("endpoint") orelse return error.DingTalkApiError;
        const ticket_val = parsed.value.object.get("ticket") orelse return error.DingTalkApiError;
        if (endpoint_val != .string or ticket_val != .string) return error.DingTalkApiError;

        return .{
            .endpoint = try self.allocator.dupe(u8, endpoint_val.string),
            .ticket = try self.allocator.dupe(u8, ticket_val.string),
        };
    }

    fn buildOpenBody(self: *DingTalkChannel) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(self.allocator);
        const w = body.writer(self.allocator);

        try w.writeAll("{\"clientId\":");
        try root.appendJsonStringW(w, self.client_id);
        try w.writeAll(",\"clientSecret\":");
        try root.appendJsonStringW(w, self.client_secret);
        try w.writeAll(",\"subscriptions\":[");

        var wrote_any = false;
        if (!self.hasSubscription(BOT_MESSAGE_TOPIC, "CALLBACK")) {
            try appendSubscription(w, BOT_MESSAGE_TOPIC, "CALLBACK", &wrote_any);
        }
        if (self.subscribe_events and !self.hasSubscription("*", "EVENT")) {
            try appendSubscription(w, "*", "EVENT", &wrote_any);
        }
        for (self.subscriptions) |sub| {
            const sub_type = if (sub.subscription_type.len > 0) sub.subscription_type else "CALLBACK";
            try appendSubscription(w, sub.topic, sub_type, &wrote_any);
        }

        try w.writeAll("]");

        if (self.ua) |ua_val| {
            try w.writeAll(",\"ua\":");
            try root.appendJsonStringW(w, ua_val);
        }
        if (self.local_ip) |ip_val| {
            try w.writeAll(",\"localIp\":");
            try root.appendJsonStringW(w, ip_val);
        }

        try w.writeByte('}');
        return body.toOwnedSlice(self.allocator);
    }

    fn hasSubscription(self: *const DingTalkChannel, topic: []const u8, subscription_type: []const u8) bool {
        for (self.subscriptions) |sub| {
            if (std.mem.eql(u8, sub.topic, topic) and std.mem.eql(u8, sub.subscription_type, subscription_type)) {
                return true;
            }
        }
        return false;
    }

    fn appendSubscription(w: anytype, topic: []const u8, subscription_type: []const u8, wrote_any: *bool) !void {
        if (wrote_any.*) {
            try w.writeByte(',');
        }
        wrote_any.* = true;
        try w.writeAll("{\"topic\":");
        try root.appendJsonStringW(w, topic);
        try w.writeAll(",\"type\":");
        try root.appendJsonStringW(w, subscription_type);
        try w.writeByte('}');
    }

    fn parseEndpoint(endpoint: []const u8) !EndpointParts {
        const is_ws = std.mem.startsWith(u8, endpoint, "ws://");
        const is_wss = std.mem.startsWith(u8, endpoint, "wss://");
        const no_scheme = if (is_wss)
            endpoint[6..]
        else if (is_ws)
            endpoint[5..]
        else
            endpoint;

        const slash_pos = std.mem.indexOfScalar(u8, no_scheme, '/') orelse no_scheme.len;
        const host_port = no_scheme[0..slash_pos];
        const path = if (slash_pos < no_scheme.len) no_scheme[slash_pos..] else "/";

        var host = host_port;
        var port: u16 = if (is_ws) 80 else 443;
        if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |idx| {
            host = host_port[0..idx];
            const port_str = host_port[idx + 1 ..];
            if (port_str.len > 0) {
                port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidEndpoint;
            }
        }
        if (host.len == 0) return error.InvalidEndpoint;
        return .{ .host = host, .port = port, .path = path };
    }

    fn buildTicketPath(allocator: std.mem.Allocator, base_path: []const u8, ticket: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);
        if (base_path.len == 0) {
            try w.writeByte('/');
        } else {
            try w.writeAll(base_path);
        }
        if (std.mem.indexOfScalar(u8, base_path, '?') != null) {
            try w.writeAll("&ticket=");
        } else {
            try w.writeAll("?ticket=");
        }
        try w.writeAll(ticket);
        return buf.toOwnedSlice(allocator);
    }

    fn handleMessage(self: *DingTalkChannel, ws: *websocket.WsClient, text: []const u8) bool {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, text, .{}) catch {
            return true;
        };
        defer parsed.deinit();
        if (parsed.value != .object) return true;

        const msg_obj = parsed.value.object;
        const type_val = msg_obj.get("type") orelse return true;
        if (type_val != .string) return true;
        const msg_type = type_val.string;

        const headers_val = msg_obj.get("headers") orelse return true;
        if (headers_val != .object) return true;
        const headers = headers_val.object;
        const message_id = getJsonStringObj(headers, "messageId") orelse return true;
        const topic = getJsonStringObj(headers, "topic") orelse "";

        const data_val = msg_obj.get("data") orelse return true;
        if (data_val != .string) return true;
        const data_str = data_val.string;

        if (std.mem.eql(u8, msg_type, "SYSTEM")) {
            if (std.mem.eql(u8, topic, "ping")) {
                const ping_data = self.buildPingData(data_str);
                const data_payload = ping_data orelse "{\"opaque\":\"\"}";
                defer if (ping_data) |pd| self.allocator.free(pd);
                _ = self.sendAck(ws, message_id, data_payload) catch {};
            }
            if (std.mem.eql(u8, topic, "disconnect")) {
                return false;
            }
            return true;
        }

        if (std.mem.eql(u8, msg_type, "EVENT")) {
            _ = self.sendAck(ws, message_id, "{\"status\":\"SUCCESS\",\"message\":\"success\"}") catch {};
            return true;
        }

        if (std.mem.eql(u8, msg_type, "CALLBACK")) {
            if (std.mem.eql(u8, topic, BOT_MESSAGE_TOPIC)) {
                self.handleBotMessage(data_str);
            }
            _ = self.sendAck(ws, message_id, "{\"response\":null}") catch {};
        }
        return true;
    }

    fn handleBotMessage(self: *DingTalkChannel, data_str: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data_str, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const obj = parsed.value.object;

        const sender_id = getJsonStringObj(obj, "senderId") orelse getJsonStringObj(obj, "senderStaffId") orelse return;
        if (!self.isUserAllowed(sender_id)) return;

        const msg_type = getJsonStringObj(obj, "msgtype") orelse "";
        if (!std.mem.eql(u8, msg_type, "text")) return;

        const text_obj_val = obj.get("text") orelse return;
        if (text_obj_val != .object) return;
        const text_obj = text_obj_val.object;
        const content = getJsonStringObj(text_obj, "content") orelse return;
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len == 0) return;

        const session_webhook = getJsonStringObj(obj, "sessionWebhook") orelse return;
        if (session_webhook.len == 0) return;

        const conversation_type = getJsonStringObj(obj, "conversationType") orelse "";
        const is_group = std.mem.eql(u8, conversation_type, "2");
        const conversation_id = getJsonStringObj(obj, "conversationId") orelse "";
        const msg_id = getJsonStringObj(obj, "msgId") orelse "";

        const peer_kind = if (is_group) "group" else "direct";
        const peer_id = if (is_group and conversation_id.len > 0) conversation_id else sender_id;

        var session_buf: [256]u8 = undefined;
        const session_key = std.fmt.bufPrint(&session_buf, "dingtalk:{s}:{s}:{s}", .{
            self.account_id,
            peer_kind,
            peer_id,
        }) catch return;

        var meta: std.ArrayListUnmanaged(u8) = .empty;
        defer meta.deinit(self.allocator);
        const mw = meta.writer(self.allocator);
        mw.writeAll("{\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        mw.writeAll(",\"peer_kind\":") catch return;
        root.appendJsonStringW(mw, peer_kind) catch return;
        mw.writeAll(",\"peer_id\":") catch return;
        root.appendJsonStringW(mw, peer_id) catch return;
        mw.writeAll(",\"is_dm\":") catch return;
        mw.writeAll(if (is_group) "false" else "true") catch return;
        mw.writeAll(",\"is_group\":") catch return;
        mw.writeAll(if (is_group) "true" else "false") catch return;
        if (conversation_id.len > 0) {
            mw.writeAll(",\"channel_id\":") catch return;
            root.appendJsonStringW(mw, conversation_id) catch return;
        }
        if (msg_id.len > 0) {
            mw.writeAll(",\"message_id\":") catch return;
            root.appendJsonStringW(mw, msg_id) catch return;
        }
        mw.writeByte('}') catch return;

        const msg = bus_mod.makeInboundFull(
            self.allocator,
            "dingtalk",
            sender_id,
            session_webhook,
            trimmed,
            session_key,
            &.{},
            meta.items,
        ) catch |err| {
            log.err("DingTalk makeInbound failed: {}", .{err});
            return;
        };

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.err("DingTalk publishInbound failed: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            msg.deinit(self.allocator);
        }
    }

    fn buildPingData(self: *DingTalkChannel, data_str: []const u8) ?[]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data_str, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const obj = parsed.value.object;
        const opaque_value = getJsonStringObj(obj, "opaque") orelse "";
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        w.writeAll("{\"opaque\":") catch return null;
        root.appendJsonStringW(w, opaque_value) catch return null;
        w.writeByte('}') catch return null;
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn sendAck(self: *DingTalkChannel, ws: *websocket.WsClient, message_id: []const u8, data_payload: []const u8) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        const w = body.writer(self.allocator);
        try w.writeAll("{\"code\":200,\"headers\":{\"messageId\":");
        try root.appendJsonStringW(w, message_id);
        try w.writeAll(",\"contentType\":\"application/json\"},\"message\":\"OK\",\"data\":");
        try root.appendJsonStringW(w, data_payload);
        try w.writeByte('}');
        try ws.writeText(body.items);
    }

    fn getJsonStringObj(obj: anytype, key: []const u8) ?[]const u8 {
        const val = obj.get(key) orelse return null;
        if (val != .string) return null;
        return val.string;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════
test "dingtalk parseEndpoint" {
    const parts = try DingTalkChannel.parseEndpoint("wss://wss-open-connection.dingtalk.com:443/connect");
    try std.testing.expectEqualStrings("wss-open-connection.dingtalk.com", parts.host);
    try std.testing.expectEqual(@as(u16, 443), parts.port);
    try std.testing.expectEqualStrings("/connect", parts.path);
}

test "dingtalk buildTicketPath appends ticket" {
    const alloc = std.testing.allocator;
    const path = try DingTalkChannel.buildTicketPath(alloc, "/connect", "abc");
    defer alloc.free(path);
    try std.testing.expectEqualStrings("/connect?ticket=abc", path);
}
