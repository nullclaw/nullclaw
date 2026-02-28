const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");
const websocket = @import("../websocket.zig");

const log = std.log.scoped(.lark);

const SocketFd = std.net.Stream.Handle;
const invalid_socket: SocketFd = switch (builtin.os.tag) {
    .windows => std.os.windows.ws2_32.INVALID_SOCKET,
    else => -1,
};

/// Lark/Feishu channel — receives events via WebSocket or HTTP callback, sends via Open API.
///
/// Supports two regional endpoints (configured via `use_feishu`):
/// - **Feishu** (default): CN endpoints at `open.feishu.cn`
/// - **Lark**: International endpoints at `open.larksuite.com`
pub const LarkChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    app_id: []const u8,
    app_secret: []const u8,
    verification_token: []const u8,
    port: u16,
    allow_from: []const []const u8,
    receive_mode: config_types.LarkReceiveMode = .websocket,
    /// When true, use Feishu (CN) endpoints; when false, use Lark (international).
    use_feishu: bool = true,
    event_bus: ?*bus.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ws_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    /// Cached tenant access token (heap-allocated, owned by allocator).
    cached_token: ?[]const u8 = null,
    /// Epoch seconds when cached_token expires.
    token_expires_at: i64 = 0,

    pub const FEISHU_BASE_URL = "https://open.feishu.cn/open-apis";
    pub const LARK_BASE_URL = "https://open.larksuite.com/open-apis";

    pub fn init(
        allocator: std.mem.Allocator,
        app_id: []const u8,
        app_secret: []const u8,
        verification_token: []const u8,
        port: u16,
        allow_from: []const []const u8,
    ) LarkChannel {
        return .{
            .allocator = allocator,
            .app_id = app_id,
            .app_secret = app_secret,
            .verification_token = verification_token,
            .port = port,
            .allow_from = allow_from,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.LarkConfig) LarkChannel {
        var ch = init(
            allocator,
            cfg.app_id,
            cfg.app_secret,
            cfg.verification_token orelse "",
            cfg.port orelse 9000,
            cfg.allow_from,
        );
        ch.account_id = cfg.account_id;
        ch.receive_mode = cfg.receive_mode;
        ch.use_feishu = cfg.use_feishu;
        return ch;
    }

    /// Return the API base URL based on region setting.
    pub fn apiBase(self: *const LarkChannel) []const u8 {
        return if (self.use_feishu) FEISHU_BASE_URL else LARK_BASE_URL;
    }

    pub fn channelName(_: *LarkChannel) []const u8 {
        return "lark";
    }

    pub fn isUserAllowed(self: *const LarkChannel, open_id: []const u8) bool {
        return root.isAllowedExact(self.allow_from, open_id);
    }

    pub fn setBus(self: *LarkChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    /// Parse a Lark event callback payload and extract text messages.
    /// Supports both "text" and "post" message types.
    /// For group chats, only responds when the bot is @-mentioned.
    pub fn parseEventPayload(
        self: *const LarkChannel,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) ![]ParsedLarkMessage {
        var result: std.ArrayListUnmanaged(ParsedLarkMessage) = .empty;
        errdefer {
            for (result.items) |*m| m.deinit(allocator);
            result.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return result.items;
        defer parsed.deinit();
        const val = parsed.value;
        if (val != .object) return result.items;

        // Check event type
        const header = val.object.get("header") orelse return result.items;
        if (header != .object) return result.items;
        const event_type_val = header.object.get("event_type") orelse return result.items;
        const event_type = if (event_type_val == .string) event_type_val.string else return result.items;
        if (!std.mem.eql(u8, event_type, "im.message.receive_v1")) return result.items;

        const event = val.object.get("event") orelse return result.items;
        if (event != .object) return result.items;

        // Extract sender open_id
        const sender_obj = event.object.get("sender") orelse return result.items;
        if (sender_obj != .object) return result.items;
        const sender_id_obj = sender_obj.object.get("sender_id") orelse return result.items;
        if (sender_id_obj != .object) return result.items;
        const open_id_val = sender_id_obj.object.get("open_id") orelse return result.items;
        const open_id = if (open_id_val == .string) open_id_val.string else return result.items;
        if (open_id.len == 0) return result.items;

        if (!self.isUserAllowed(open_id)) return result.items;

        // Message content
        const msg_obj = event.object.get("message") orelse return result.items;
        if (msg_obj != .object) return result.items;
        const msg_type_val = msg_obj.object.get("message_type") orelse return result.items;
        const msg_type = if (msg_type_val == .string) msg_type_val.string else return result.items;

        const content_val = msg_obj.object.get("content") orelse return result.items;
        const content_str = if (content_val == .string) content_val.string else return result.items;

        // Parse content based on message type
        const raw_text: []const u8 = if (std.mem.eql(u8, msg_type, "text")) blk: {
            // Content is a JSON string like {"text":"hello"}
            const inner = std.json.parseFromSlice(std.json.Value, allocator, content_str, .{}) catch return result.items;
            defer inner.deinit();
            if (inner.value != .object) return result.items;
            const text_val = inner.value.object.get("text") orelse return result.items;
            const text = if (text_val == .string) text_val.string else return result.items;
            if (text.len == 0) return result.items;
            break :blk try allocator.dupe(u8, text);
        } else if (std.mem.eql(u8, msg_type, "post")) blk: {
            const maybe = parsePostContent(allocator, content_str) catch return result.items;
            break :blk maybe orelse return result.items;
        } else return result.items;
        defer allocator.free(raw_text);

        // Strip @_user_N placeholders
        const stripped = try stripAtPlaceholders(allocator, raw_text);
        defer allocator.free(stripped);

        // Trim whitespace
        const text = std.mem.trim(u8, stripped, " \t\n\r");
        if (text.len == 0) return result.items;

        // Group chat: only respond when bot is @-mentioned
        const chat_type_val = msg_obj.object.get("chat_type");
        const chat_type = if (chat_type_val) |ctv| (if (ctv == .string) ctv.string else "") else "";
        const chat_id_val = msg_obj.object.get("chat_id");
        const chat_id = if (chat_id_val) |cv| (if (cv == .string) cv.string else open_id) else open_id;

        if (std.mem.eql(u8, chat_type, "group")) {
            // Check mentions array in the event
            const mentions_val = msg_obj.object.get("mentions");
            if (!shouldRespondInGroup(mentions_val, raw_text, "")) {
                return result.items;
            }
        }

        // Timestamp (Lark timestamps are in milliseconds)
        const create_time_val = msg_obj.object.get("create_time");
        const timestamp = blk: {
            if (create_time_val) |ctv| {
                if (ctv == .string) {
                    const ms = std.fmt.parseInt(u64, ctv.string, 10) catch break :blk root.nowEpochSecs();
                    break :blk ms / 1000;
                }
            }
            break :blk root.nowEpochSecs();
        };

        try result.append(allocator, .{
            .sender = try allocator.dupe(u8, chat_id),
            .content = try allocator.dupe(u8, text),
            .timestamp = timestamp,
            .is_group = std.mem.eql(u8, chat_type, "group"),
        });

        return result.toOwnedSlice(allocator);
    }

    pub fn healthCheck(self: *LarkChannel) bool {
        return switch (self.receive_mode) {
            .webhook => self.running.load(.acquire),
            .websocket => self.running.load(.acquire) and self.connected.load(.acquire),
        };
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Obtain a tenant access token from the Feishu/Lark API.
    /// POST /auth/v3/tenant_access_token/internal
    /// Uses cached token if still valid (with 60s safety margin).
    pub fn getTenantAccessToken(self: *LarkChannel) ![]const u8 {
        // Check cache first
        if (self.cached_token) |token| {
            const now = std.time.timestamp();
            if (now < self.token_expires_at - 60) {
                return self.allocator.dupe(u8, token);
            }
            // Token expired, free it
            self.allocator.free(token);
            self.cached_token = null;
            self.token_expires_at = 0;
        }

        const token = try self.fetchTenantToken();

        // Cache the token (2 hour typical expiry)
        self.cached_token = self.allocator.dupe(u8, token) catch null;
        self.token_expires_at = std.time.timestamp() + 7200;

        return token;
    }

    /// Invalidate cached token (called on 401).
    pub fn invalidateToken(self: *LarkChannel) void {
        if (self.cached_token) |token| {
            self.allocator.free(token);
            self.cached_token = null;
            self.token_expires_at = 0;
        }
    }

    /// Fetch a fresh tenant access token from the API.
    fn fetchTenantToken(self: *LarkChannel) ![]const u8 {
        const base = self.apiBase();

        // Build URL: base ++ "/auth/v3/tenant_access_token/internal"
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/auth/v3/tenant_access_token/internal", .{base});
        const url = url_fbs.getWritten();

        // Build JSON body
        var body_buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        try fbs.writer().print("{{\"app_id\":\"{s}\",\"app_secret\":\"{s}\"}}", .{ self.app_id, self.app_secret });
        const body = fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
            },
            .response_writer = &aw.writer,
        }) catch return error.LarkApiError;

        if (result.status != .ok) return error.LarkApiError;

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.LarkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.LarkApiError;

        const token_val = parsed.value.object.get("tenant_access_token") orelse return error.LarkApiError;
        if (token_val != .string) return error.LarkApiError;
        return self.allocator.dupe(u8, token_val.string);
    }

    /// Send a message to a Lark chat via the Open API.
    /// POST /im/v1/messages?receive_id_type=chat_id
    /// On 401, invalidates cached token and retries once.
    pub fn sendMessage(self: *LarkChannel, recipient: []const u8, text: []const u8) !void {
        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        const base = self.apiBase();

        // Build URL
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages?receive_id_type=chat_id", .{base});
        const url = url_fbs.getWritten();

        // Build inner content JSON: {"text":"..."}
        var content_buf: [4096]u8 = undefined;
        var content_fbs = std.io.fixedBufferStream(&content_buf);
        const cw = content_fbs.writer();
        try cw.writeAll("{\"text\":");
        try root.appendJsonStringW(cw, text);
        try cw.writeAll("}");
        const content_json = content_fbs.getWritten();

        // Build outer body JSON
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"receive_id\":\"");
        try w.writeAll(recipient);
        try w.writeAll("\",\"msg_type\":\"text\",\"content\":");
        // Escape the content JSON string for embedding
        try root.appendJsonStringW(w, content_json);
        try w.writeAll("}");
        const body = fbs.getWritten();

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const send_result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.LarkApiError;

        if (send_result.status == .unauthorized) {
            // Token expired — invalidate cache and retry once
            self.invalidateToken();
            const new_token = self.getTenantAccessToken() catch return error.LarkApiError;
            defer self.allocator.free(new_token);

            var retry_auth_buf: [512]u8 = undefined;
            var retry_auth_fbs = std.io.fixedBufferStream(&retry_auth_buf);
            try retry_auth_fbs.writer().print("Bearer {s}", .{new_token});
            const retry_auth_value = retry_auth_fbs.getWritten();

            var retry_client = std.http.Client{ .allocator = self.allocator };
            defer retry_client.deinit();

            const retry_result = retry_client.fetch(.{
                .location = .{ .url = url },
                .method = .POST,
                .payload = body,
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
                    .{ .name = "Authorization", .value = retry_auth_value },
                },
            }) catch return error.LarkApiError;

            if (retry_result.status != .ok) {
                return error.LarkApiError;
            }
            return;
        }

        if (send_result.status != .ok) {
            return error.LarkApiError;
        }
    }

    fn websocketHost(self: *const LarkChannel) []const u8 {
        return if (self.use_feishu) "open.feishu.cn" else "open.larksuite.com";
    }

    fn buildWebsocketPath(buf: []u8, app_id: []const u8, app_access_token: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("/ws/v2?app_id={s}&access_token={s}", .{ app_id, app_access_token });
        return fbs.getWritten();
    }

    fn buildWebsocketPong(buf: []u8, ts: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll("{\"type\":\"pong\",\"ts\":");
        try root.appendJsonStringW(w, ts);
        try w.writeAll("}");
        return fbs.getWritten();
    }

    fn buildWebsocketAck(buf: []u8, uuid: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll("{\"uuid\":");
        try root.appendJsonStringW(w, uuid);
        try w.writeAll("}");
        return fbs.getWritten();
    }

    fn fetchAppAccessToken(self: *LarkChannel) ![]const u8 {
        const base = self.apiBase();

        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/auth/v3/app_access_token/internal", .{base});
        const url = url_fbs.getWritten();

        var body_buf: [512]u8 = undefined;
        var body_fbs = std.io.fixedBufferStream(&body_buf);
        try body_fbs.writer().print("{{\"app_id\":\"{s}\",\"app_secret\":\"{s}\"}}", .{ self.app_id, self.app_secret });
        const body = body_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
            },
            .response_writer = &aw.writer,
        }) catch return error.LarkApiError;

        if (result.status != .ok) return error.LarkApiError;

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.LarkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.LarkApiError;

        const token_val = parsed.value.object.get("app_access_token") orelse return error.LarkApiError;
        if (token_val != .string) return error.LarkApiError;
        return self.allocator.dupe(u8, token_val.string);
    }

    fn publishInboundMessage(self: *LarkChannel, msg: ParsedLarkMessage) void {
        var key_buf: [256]u8 = undefined;
        const session_key = std.fmt.bufPrint(&key_buf, "lark:{s}", .{msg.sender}) catch "lark:unknown";

        var meta_buf: [384]u8 = undefined;
        var meta_fbs = std.io.fixedBufferStream(&meta_buf);
        const mw = meta_fbs.writer();
        mw.writeAll("{\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        mw.writeAll(",\"peer_kind\":") catch return;
        root.appendJsonStringW(mw, if (msg.is_group) "group" else "direct") catch return;
        mw.writeAll(",\"peer_id\":") catch return;
        root.appendJsonStringW(mw, msg.sender) catch return;
        mw.writeAll("}") catch return;
        const metadata = meta_fbs.getWritten();

        const inbound = bus.makeInboundFull(
            self.allocator,
            "lark",
            msg.sender,
            msg.sender,
            msg.content,
            session_key,
            &.{},
            metadata,
        ) catch |err| {
            log.warn("lark makeInboundFull failed: {}", .{err});
            return;
        };

        if (self.event_bus) |eb| {
            eb.publishInbound(inbound) catch |err| {
                log.warn("lark publishInbound failed: {}", .{err});
                inbound.deinit(self.allocator);
            };
        } else {
            inbound.deinit(self.allocator);
        }
    }

    fn handleWebsocketPayload(self: *LarkChannel, ws: *websocket.WsClient, payload: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch null;
        if (parsed) |pp| {
            var p = pp;
            defer p.deinit();
            if (p.value == .object) {
                if (p.value.object.get("type")) |type_val| {
                    if (type_val == .string and std.mem.eql(u8, type_val.string, "ping")) {
                        const ts = if (p.value.object.get("ts")) |ts_val|
                            (if (ts_val == .string) ts_val.string else "0")
                        else
                            "0";
                        var pong_buf: [128]u8 = undefined;
                        const pong = buildWebsocketPong(&pong_buf, ts) catch return;
                        ws.writeText(pong) catch |err| {
                            log.warn("lark websocket pong failed: {}", .{err});
                        };
                        return;
                    }
                }

                if (p.value.object.get("uuid")) |uuid_val| {
                    if (uuid_val == .string) {
                        var ack_buf: [160]u8 = undefined;
                        const ack = buildWebsocketAck(&ack_buf, uuid_val.string) catch return;
                        ws.writeText(ack) catch |err| {
                            log.warn("lark websocket ack failed: {}", .{err});
                        };
                    }
                }
            }
        }

        const messages = try self.parseEventPayload(self.allocator, payload);
        defer if (messages.len > 0) {
            for (messages) |*m| m.deinit(self.allocator);
            self.allocator.free(messages);
        };

        for (messages) |m| {
            self.publishInboundMessage(m);
        }
    }

    fn runWebsocketOnce(self: *LarkChannel) !void {
        const app_access_token = try self.fetchAppAccessToken();
        defer self.allocator.free(app_access_token);

        var path_buf: [1024]u8 = undefined;
        const path = try buildWebsocketPath(&path_buf, self.app_id, app_access_token);

        var ws = try websocket.WsClient.connect(
            self.allocator,
            self.websocketHost(),
            443,
            path,
            &.{},
        );

        self.ws_fd.store(ws.stream.handle, .release);
        self.connected.store(true, .release);
        defer {
            self.connected.store(false, .release);
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| {
                log.warn("lark websocket read failed: {}", .{err});
                break;
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);

            self.handleWebsocketPayload(&ws, text) catch |err| {
                log.warn("lark websocket payload handling failed: {}", .{err});
            };
        }
    }

    fn websocketLoop(self: *LarkChannel) void {
        while (self.running.load(.acquire)) {
            self.runWebsocketOnce() catch |err| {
                if (self.running.load(.acquire)) {
                    log.warn("lark websocket cycle failed: {}", .{err});
                }
            };

            if (!self.running.load(.acquire)) break;

            var slept_ms: u64 = 0;
            while (slept_ms < 5000 and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                slept_ms += 100;
            }
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        if (self.receive_mode == .webhook) {
            self.connected.store(true, .release);
            return;
        }

        self.connected.store(false, .release);
        self.ws_thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, websocketLoop, .{self}) catch |err| {
            self.running.store(false, .release);
            return err;
        };
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.connected.store(false, .release);

        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(fd);
            } else {
                std.posix.close(fd);
            }
        }

        if (self.ws_thread) |t| {
            t.join();
            self.ws_thread = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *LarkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedLarkMessage = struct {
    sender: []const u8,
    content: []const u8,
    timestamp: u64,
    is_group: bool = false,

    pub fn deinit(self: *ParsedLarkMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Helper functions
// ════════════════════════════════════════════════════════════════════════════

/// Flatten a Lark "post" rich-text message to plain text.
/// Post format: {"zh_cn": {"title": "...", "content": [[{"tag": "text", "text": "..."}]]}}
/// Returns null when content cannot be parsed or yields no usable text.
pub fn parsePostContent(allocator: std.mem.Allocator, post_json: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, post_json, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    // Try locale keys: zh_cn, en_us, or first object value
    const locale = parsed.value.object.get("zh_cn") orelse
        parsed.value.object.get("en_us") orelse blk: {
        var it = parsed.value.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == .object) break :blk entry.value_ptr.*;
        }
        return null;
    };
    if (locale != .object) return null;

    var text_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer text_buf.deinit(allocator);

    // Title
    if (locale.object.get("title")) |title_val| {
        if (title_val == .string and title_val.string.len > 0) {
            try text_buf.appendSlice(allocator, title_val.string);
            try text_buf.appendSlice(allocator, "\n\n");
        }
    }

    // Content paragraphs: [[{tag, text}, ...], ...]
    const content = locale.object.get("content") orelse return null;
    if (content != .array) return null;

    for (content.array.items) |para| {
        if (para != .array) continue;
        for (para.array.items) |el| {
            if (el != .object) continue;
            const tag_val = el.object.get("tag") orelse continue;
            const tag = if (tag_val == .string) tag_val.string else continue;

            if (std.mem.eql(u8, tag, "text")) {
                if (el.object.get("text")) |t| {
                    if (t == .string) try text_buf.appendSlice(allocator, t.string);
                }
            } else if (std.mem.eql(u8, tag, "a")) {
                // Link: prefer text, fallback to href
                const link_text = if (el.object.get("text")) |t| (if (t == .string and t.string.len > 0) t.string else null) else null;
                const href_text = if (el.object.get("href")) |h| (if (h == .string) h.string else null) else null;
                if (link_text) |lt| {
                    try text_buf.appendSlice(allocator, lt);
                } else if (href_text) |ht| {
                    try text_buf.appendSlice(allocator, ht);
                }
            } else if (std.mem.eql(u8, tag, "at")) {
                const name = if (el.object.get("user_name")) |n| (if (n == .string) n.string else null) else null;
                const uid = if (el.object.get("user_id")) |i| (if (i == .string) i.string else null) else null;
                try text_buf.append(allocator, '@');
                try text_buf.appendSlice(allocator, name orelse uid orelse "user");
            }
        }
        try text_buf.append(allocator, '\n');
    }

    // Trim and return
    const raw = text_buf.items;
    const trimmed = std.mem.trim(u8, raw, " \t\n\r");
    if (trimmed.len == 0) return null;

    return try allocator.dupe(u8, trimmed);
}

/// Remove `@_user_N` placeholder tokens injected by Feishu in group chats.
/// Patterns like "@_user_1", "@_user_2" are replaced with empty string.
pub fn stripAtPlaceholders(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, text.len);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '@' and i + 1 < text.len) {
            // Check for "_user_" prefix after '@'
            const rest = text[i + 1 ..];
            if (std.mem.startsWith(u8, rest, "_user_")) {
                // Skip past "@_user_"
                var skip: usize = 1 + "_user_".len; // '@' + "_user_"
                // Skip digits
                while (i + skip < text.len and text[i + skip] >= '0' and text[i + skip] <= '9') {
                    skip += 1;
                }
                // Skip trailing space
                if (i + skip < text.len and text[i + skip] == ' ') {
                    skip += 1;
                }
                i += skip;
                continue;
            }
        }
        out.appendAssumeCapacity(text[i]);
        i += 1;
    }

    return try allocator.dupe(u8, out.items);
}

/// In group chats, only respond when the bot is explicitly @-mentioned.
/// For direct messages (p2p), always respond.
/// Checks: (1) mentions array is non-empty, or (2) text contains @bot_name.
pub fn shouldRespondInGroup(mentions_val: ?std.json.Value, text: []const u8, bot_name: []const u8) bool {
    // Check mentions array
    if (mentions_val) |mv| {
        if (mv == .array and mv.array.items.len > 0) return true;
    }
    // Check @bot_name in text
    if (bot_name.len > 0) {
        if (std.mem.indexOf(u8, text, bot_name)) |_| return true;
    }
    return false;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "lark parse valid text message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_testuser123"}},"message":{"message_type":"text","content":"{\"text\":\"Hello nullclaw!\"}","chat_id":"oc_chat123","create_time":"1699999999000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Hello nullclaw!", msgs[0].content);
    try std.testing.expectEqualStrings("oc_chat123", msgs[0].sender);
    try std.testing.expectEqual(@as(u64, 1_699_999_999), msgs[0].timestamp);
    try std.testing.expect(!msgs[0].is_group);
}

test "lark parse group message marks is_group" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_group_user"}},"message":{"message_type":"text","content":"{\"text\":\"hello group\"}","chat_type":"group","mentions":[{"key":"@_user_1"}],"chat_id":"oc_group_1","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].is_group);
}

test "lark parse unauthorized user" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_unauthorized"}},"message":{"message_type":"text","content":"{\"text\":\"spam\"}","chat_id":"oc_chat","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse non-text skipped" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"image","content":"{}","chat_id":"oc_chat"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse wrong event type" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.chat.disbanded_v1"},"event":{}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse empty text skipped" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"\"}","chat_id":"oc_chat"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Lark Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "lark parse challenge produces no messages" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"challenge":"abc123","token":"test_verification_token","type":"url_verification"}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse non-object payload is ignored safely" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const msgs = try ch.parseEventPayload(allocator, "\"not an object\"");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse invalid header shape is ignored safely" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload = "{\"header\":\"oops\",\"event\":{}}";
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse missing sender" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"message":{"message_type":"text","content":"{\"text\":\"hello\"}","chat_id":"oc_chat"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse missing event" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_testuser123"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse invalid content json" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"not valid json","chat_id":"oc_chat"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "lark parse unicode message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"Hello World\"}","chat_id":"oc_chat","create_time":"1000"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Hello World", msgs[0].content);
}

test "lark parse fallback sender to open_id when no chat_id" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);
    // No chat_id field at all
    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"hello\"}","create_time":"1000"}}}
    ;
    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    // sender should fall back to open_id
    try std.testing.expectEqualStrings("ou_user", msgs[0].sender);
}

test "lark feishu base url constant" {
    try std.testing.expectEqualStrings("https://open.feishu.cn/open-apis", LarkChannel.FEISHU_BASE_URL);
}

test "lark stores all fields" {
    const users = [_][]const u8{ "ou_1", "ou_2" };
    const ch = LarkChannel.init(std.testing.allocator, "my_app_id", "my_secret", "my_token", 8080, &users);
    try std.testing.expectEqualStrings("my_app_id", ch.app_id);
    try std.testing.expectEqualStrings("my_secret", ch.app_secret);
    try std.testing.expectEqualStrings("my_token", ch.verification_token);
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
}

// ════════════════════════════════════════════════════════════════════════════
// New feature tests
// ════════════════════════════════════════════════════════════════════════════

test "lark apiBase returns feishu URL when use_feishu is true" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = true;
    try std.testing.expectEqualStrings("https://open.feishu.cn/open-apis", ch.apiBase());
}

test "lark apiBase returns larksuite URL when use_feishu is false" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = false;
    try std.testing.expectEqualStrings("https://open.larksuite.com/open-apis", ch.apiBase());
}

test "lark websocketHost follows region" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = true;
    try std.testing.expectEqualStrings("open.feishu.cn", ch.websocketHost());
    ch.use_feishu = false;
    try std.testing.expectEqualStrings("open.larksuite.com", ch.websocketHost());
}

test "lark buildWebsocketPath formats query parameters" {
    var buf: [256]u8 = undefined;
    const path = try LarkChannel.buildWebsocketPath(&buf, "cli_app", "tok_123");
    try std.testing.expectEqualStrings("/ws/v2?app_id=cli_app&access_token=tok_123", path);
}

test "lark websocket pong and ack payload format" {
    var pong_buf: [128]u8 = undefined;
    const pong = try LarkChannel.buildWebsocketPong(&pong_buf, "123456");
    try std.testing.expectEqualStrings("{\"type\":\"pong\",\"ts\":\"123456\"}", pong);

    var ack_buf: [128]u8 = undefined;
    const ack = try LarkChannel.buildWebsocketAck(&ack_buf, "uuid-1");
    try std.testing.expectEqualStrings("{\"uuid\":\"uuid-1\"}", ack);
}

test "lark initFromConfig stores account and receive mode" {
    const cfg = config_types.LarkConfig{
        .account_id = "lark-main",
        .app_id = "cli_abc",
        .app_secret = "sec_xyz",
        .receive_mode = .webhook,
        .use_feishu = true,
    };
    const ch = LarkChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("lark-main", ch.account_id);
    try std.testing.expect(ch.receive_mode == .webhook);
    try std.testing.expect(ch.use_feishu);
}

test "lark healthCheck reflects receive mode state" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.receive_mode = .websocket;
    ch.running.store(true, .release);
    ch.connected.store(false, .release);
    try std.testing.expect(!ch.healthCheck());

    ch.connected.store(true, .release);
    try std.testing.expect(ch.healthCheck());

    ch.receive_mode = .webhook;
    ch.connected.store(false, .release);
    try std.testing.expect(ch.healthCheck());
}

test "lark parsePostContent extracts text from single tag" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[[{"tag":"text","text":"hello world"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("hello world", result.?);
}

test "lark parsePostContent handles nested content array" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"My Title","content":[[{"tag":"text","text":"line one"}],[{"tag":"text","text":"line two"},{"tag":"a","text":"click here","href":"https://example.com"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    // Should contain title, both lines, and link text
    try std.testing.expect(std.mem.indexOf(u8, result.?, "My Title") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "line one") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "line two") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "click here") != null);
}

test "lark parsePostContent handles empty content" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    try std.testing.expect(result == null);
}

test "lark stripAtPlaceholders removes @_user_1" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello @_user_1 how are you?");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello how are you?", result);
}

test "lark stripAtPlaceholders removes multiple placeholders" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "@_user_1 hello @_user_2 world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "lark stripAtPlaceholders no-op on clean text" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello world, no mentions here");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello world, no mentions here", result);
}

test "lark shouldRespondInGroup true for DM" {
    // For DMs (p2p), the caller skips the group check entirely.
    // But if called with a non-empty mentions array, should return true.
    const allocator = std.testing.allocator;
    const mentions_json = "[{\"key\":\"@_user_1\",\"id\":{\"open_id\":\"ou_bot\"}}]";
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, mentions_json, .{});
    defer parsed.deinit();
    try std.testing.expect(shouldRespondInGroup(parsed.value, "hello", ""));
}

test "lark shouldRespondInGroup false when no mentions" {
    try std.testing.expect(!shouldRespondInGroup(null, "hello world", ""));
}

test "lark shouldRespondInGroup true when bot name in text" {
    try std.testing.expect(shouldRespondInGroup(null, "hey @TestBot check this", "TestBot"));
}

test "lark token caching returns same token within expiry" {
    // We can only test the caching logic without a real API.
    // Verify that setting cached_token and a future expiry works.
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    // Simulate a cached token
    ch.cached_token = try std.testing.allocator.dupe(u8, "test_cached_token_123");
    ch.token_expires_at = std.time.timestamp() + 3600; // 1 hour from now

    // getTenantAccessToken should return the cached token without hitting API
    const token = try ch.getTenantAccessToken();
    defer std.testing.allocator.free(token);
    try std.testing.expectEqualStrings("test_cached_token_123", token);

    // Clean up
    ch.invalidateToken();
    try std.testing.expect(ch.cached_token == null);
    try std.testing.expectEqual(@as(i64, 0), ch.token_expires_at);
}

test "lark parse post message type via parseEventPayload" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"post","content":"{\"zh_cn\":{\"title\":\"\",\"content\":[[{\"tag\":\"text\",\"text\":\"post message\"}]]}}","chat_id":"oc_chat","create_time":"1000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("post message", msgs[0].content);
}

test "lark lark base url constant" {
    try std.testing.expectEqualStrings("https://open.larksuite.com/open-apis", LarkChannel.LARK_BASE_URL);
}

test "lark parsePostContent at tag with user_name" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"zh_cn":{"title":"","content":[[{"tag":"at","user_name":"TestBot","user_id":"ou_123"},{"tag":"text","text":" do something"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "@TestBot") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "do something") != null);
}

test "lark parsePostContent en_us locale fallback" {
    const allocator = std.testing.allocator;
    const post_json =
        \\{"en_us":{"title":"English Title","content":[[{"tag":"text","text":"english content"}]]}}
    ;
    const result = try parsePostContent(allocator, post_json);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "English Title") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "english content") != null);
}

test "lark parsePostContent invalid json returns null" {
    const allocator = std.testing.allocator;
    const result = try parsePostContent(allocator, "not json at all");
    try std.testing.expect(result == null);
}

test "lark stripAtPlaceholders preserves normal @ mentions" {
    const allocator = std.testing.allocator;
    const result = try stripAtPlaceholders(allocator, "Hello @john how are you?");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello @john how are you?", result);
}
// ════════════════════════════════════════════════════════════════════════════
// WebSocket Tests
// ════════════════════════════════════════════════════════════════════════════

test "lark receive_mode defaults to websocket" {
    const ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    try std.testing.expect(ch.receive_mode == .websocket);
}

test "lark healthCheck webhook mode only checks running" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.receive_mode = .webhook;

    // In webhook mode, only running state matters
    ch.running.store(false, .release);
    try std.testing.expect(!ch.healthCheck());

    ch.running.store(true, .release);
    try std.testing.expect(ch.healthCheck());
}

test "lark healthCheck websocket mode requires both running and connected" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.receive_mode = .websocket;

    // Test all combinations
    ch.running.store(false, .release);
    ch.connected.store(false, .release);
    try std.testing.expect(!ch.healthCheck());

    ch.running.store(false, .release);
    ch.connected.store(true, .release);
    try std.testing.expect(!ch.healthCheck());

    ch.running.store(true, .release);
    ch.connected.store(false, .release);
    try std.testing.expect(!ch.healthCheck());

    ch.running.store(true, .release);
    ch.connected.store(true, .release);
    try std.testing.expect(ch.healthCheck());
}

test "lark buildWebsocketPath handles special characters in token" {
    var buf: [512]u8 = undefined;
    const path = try LarkChannel.buildWebsocketPath(&buf, "app_id_with_special_chars", "token+with/special=chars");
    try std.testing.expect(std.mem.indexOf(u8, path, "app_id=app_id_with_special_chars") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "access_token=token+with/special=chars") != null);
}

test "lark buildWebsocketPong handles empty timestamp" {
    var pong_buf: [128]u8 = undefined;
    const pong = try LarkChannel.buildWebsocketPong(&pong_buf, "");
    try std.testing.expectEqualStrings("{\"type\":\"pong\",\"ts\":\"\"}", pong);
}

test "lark buildWebsocketAck handles empty uuid" {
    var ack_buf: [128]u8 = undefined;
    const ack = try LarkChannel.buildWebsocketAck(&ack_buf, "");
    try std.testing.expectEqualStrings("{\"uuid\":\"\"}", ack);
}

test "lark buildWebsocketPong handles unicode timestamp" {
    var pong_buf: [128]u8 = undefined;
    const pong = try LarkChannel.buildWebsocketPong(&pong_buf, "1234567890");
    try std.testing.expectEqualStrings("{\"type\":\"pong\",\"ts\":\"1234567890\"}", pong);
}

test "lark parseEventPayload handles websocket message format" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    // WebSocket payload format includes uuid field
    const payload =
        \\{"uuid":"uuid-123-456","header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"text","content":"{\"text\":\"websocket message\"}","chat_id":"oc_chat","create_time":"1700000000000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("websocket message", msgs[0].content);
    try std.testing.expectEqualStrings("oc_chat", msgs[0].sender);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), msgs[0].timestamp);
}

test "lark parseEventPayload handles websocket message with mentions" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    // WebSocket payload with mentions array
    const payload =
        \\{"uuid":"msg-uuid-789","header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_group_user"}},"message":{"message_type":"text","content":"{\"text\":\"@_user_1 Hello everyone\"}","chat_type":"group","mentions":[{"key":"@_user_1","id":{"open_id":"ou_bot"}}],"chat_id":"oc_group_chat","create_time":"1000000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].is_group);
    // Should strip @_user_1 placeholder
    try std.testing.expectEqualStrings("Hello everyone", msgs[0].content);
}

test "lark websocketHost returns correct host for feishu" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = true;
    const host = ch.websocketHost();
    try std.testing.expectEqualStrings("open.feishu.cn", host);
}

test "lark websocketHost returns correct host for lark" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = false;
    const host = ch.websocketHost();
    try std.testing.expectEqualStrings("open.larksuite.com", host);
}

test "lark initFromConfig with websocket mode" {
    const cfg = config_types.LarkConfig{
        .account_id = "lark-websocket-test",
        .app_id = "cli_abc",
        .app_secret = "sec_xyz",
        .receive_mode = .websocket,
        .use_feishu = true,
    };
    const ch = LarkChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("lark-websocket-test", ch.account_id);
    try std.testing.expect(ch.receive_mode == .websocket);
    try std.testing.expect(ch.use_feishu);
}

test "lark initFromConfig with webhook mode" {
    const cfg = config_types.LarkConfig{
        .account_id = "lark-webhook-test",
        .app_id = "cli_def",
        .app_secret = "sec_123",
        .receive_mode = .webhook,
        .use_feishu = false,
    };
    const ch = LarkChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("lark-webhook-test", ch.account_id);
    try std.testing.expect(ch.receive_mode == .webhook);
    try std.testing.expect(!ch.use_feishu);
}

test "lark running and connected defaults" {
    const ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    try std.testing.expect(!ch.running.load(.acquire));
    try std.testing.expect(!ch.connected.load(.acquire));
    try std.testing.expect(ch.cached_token == null);
    try std.testing.expectEqual(@as(i64, 0), ch.token_expires_at);
}

test "lark invalidateToken clears cached token" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});

    // Setup a cached token
    ch.cached_token = try std.testing.allocator.dupe(u8, "cached_tok_123");
    ch.token_expires_at = std.time.timestamp() + 7200;

    // Invalidate should clear everything
    ch.invalidateToken();

    try std.testing.expect(ch.cached_token == null);
    try std.testing.expectEqual(@as(i64, 0), ch.token_expires_at);
}

test "lark parseEventPayload websocket payload with post message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    // WebSocket payload with post message type
    const payload =
        \\{"uuid":"post-msg-uuid","header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_type":"post","content":"{\"zh_cn\":{\"title\":\"WebSocket Post\",\"content\":[[{\"tag\":\"text\",\"text\":\"Hello from websocket\"}]]}}","chat_id":"oc_chat","create_time":"1700000000000"}}}
    ;

    const msgs = try ch.parseEventPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(std.mem.indexOf(u8, msgs[0].content, "Hello from websocket") != null);
    try std.testing.expect(std.mem.indexOf(u8, msgs[0].content, "WebSocket Post") != null);
}
