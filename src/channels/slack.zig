const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus_mod = @import("../bus.zig");
const websocket = @import("../websocket.zig");

const log = std.log.scoped(.slack);

const SocketFd = std.net.Stream.Handle;
const invalid_socket: SocketFd = switch (builtin.os.tag) {
    .windows => std.os.windows.ws2_32.INVALID_SOCKET,
    else => -1,
};

/// Slack channel — socket/http event pipeline for inbound, chat.postMessage for outbound.
pub const SlackChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    mode: config_types.SlackReceiveMode = .socket,
    bot_token: []const u8,
    app_token: ?[]const u8,
    signing_secret: ?[]const u8 = null,
    webhook_path: []const u8 = "/slack/events",
    channel_id: ?[]const u8,
    allow_from: []const []const u8,
    last_ts: []const u8,
    last_ts_owned: bool = false,
    last_ts_by_channel: std.StringHashMapUnmanaged([]u8) = .empty,
    thread_ts: ?[]const u8 = null,
    policy: root.ChannelPolicy = .{},
    bus: ?*bus_mod.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    poll_thread: ?std.Thread = null,
    socket_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    bot_user_id: ?[]u8 = null,

    pub const API_BASE = "https://slack.com/api";
    pub const DEFAULT_WEBHOOK_PATH = "/slack/events";
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;
    pub const POLL_INTERVAL_SECS: u64 = 3;

    pub fn init(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        app_token: ?[]const u8,
        channel_id: ?[]const u8,
        allow_from: []const []const u8,
    ) SlackChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .app_token = app_token,
            .channel_id = channel_id,
            .allow_from = allow_from,
            .last_ts = "0",
        };
    }

    fn parseDmPolicy(raw: []const u8) root.DmPolicy {
        if (std.mem.eql(u8, raw, "allow")) return .allow;
        if (std.mem.eql(u8, raw, "deny")) return .deny;
        if (std.mem.eql(u8, raw, "allowlist") or std.mem.eql(u8, raw, "pairing")) return .allowlist;
        return .allowlist;
    }

    fn parseGroupPolicy(raw: []const u8) root.GroupPolicy {
        if (std.mem.eql(u8, raw, "open")) return .open;
        if (std.mem.eql(u8, raw, "allowlist")) return .allowlist;
        return .mention_only;
    }

    pub fn normalizeWebhookPath(raw: []const u8) []const u8 {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return DEFAULT_WEBHOOK_PATH;
        if (trimmed[0] != '/') return DEFAULT_WEBHOOK_PATH;
        return trimmed;
    }

    pub fn initWithPolicy(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        app_token: ?[]const u8,
        channel_id: ?[]const u8,
        allow_from: []const []const u8,
        policy: root.ChannelPolicy,
    ) SlackChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .app_token = app_token,
            .channel_id = channel_id,
            .allow_from = allow_from,
            .last_ts = "0",
            .policy = policy,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.SlackConfig) SlackChannel {
        const policy = root.ChannelPolicy{
            .dm = parseDmPolicy(cfg.dm_policy),
            .group = parseGroupPolicy(cfg.group_policy),
            .allowlist = cfg.allow_from,
        };
        var ch = initWithPolicy(
            allocator,
            cfg.bot_token,
            cfg.app_token,
            cfg.channel_id,
            cfg.allow_from,
            policy,
        );
        ch.account_id = cfg.account_id;
        ch.mode = cfg.mode;
        ch.signing_secret = cfg.signing_secret;
        ch.webhook_path = normalizeWebhookPath(cfg.webhook_path);
        return ch;
    }

    /// Set the thread timestamp for threaded replies.
    pub fn setThreadTs(self: *SlackChannel, ts: ?[]const u8) void {
        self.thread_ts = ts;
    }

    /// Parse a target string, splitting "channel_id:thread_ts" if colon-separated.
    /// Returns the channel ID and optionally sets thread_ts on the instance.
    pub fn parseTarget(self: *SlackChannel, target: []const u8) []const u8 {
        if (std.mem.indexOfScalar(u8, target, ':')) |idx| {
            const parsed_thread = target[idx + 1 ..];
            self.thread_ts = if (parsed_thread.len > 0) parsed_thread else null;
            return target[0..idx];
        }
        self.thread_ts = null;
        return target;
    }

    pub fn channelName(_: *SlackChannel) []const u8 {
        return "slack";
    }

    pub fn setBus(self: *SlackChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn isUserAllowed(self: *const SlackChannel, sender: []const u8) bool {
        return root.isAllowed(self.allow_from, sender);
    }

    /// Check if an incoming message should be handled based on the channel policy.
    /// `sender_id`: the Slack user ID of the message sender.
    /// `is_dm`: true if the message is a direct message (IM channel).
    /// `message_text`: the raw message text (used to detect bot mention).
    /// `bot_user_id`: the bot's own Slack user ID (for mention detection).
    pub fn shouldHandle(self: *const SlackChannel, sender_id: []const u8, is_dm: bool, message_text: []const u8, bot_user_id: ?[]const u8) bool {
        const is_mention = if (bot_user_id) |bid| containsMention(message_text, bid) else false;
        return root.checkPolicy(self.policy, sender_id, is_dm, is_mention);
    }

    pub fn healthCheck(self: *SlackChannel) bool {
        if (!self.running.load(.acquire)) return false;
        return switch (self.mode) {
            .http => true,
            .socket => (self.connected.load(.acquire) and self.socket_thread != null) or self.poll_thread != null,
        };
    }

    fn setLastTs(self: *SlackChannel, ts: []const u8) !void {
        if (self.last_ts_owned) {
            self.allocator.free(self.last_ts);
            self.last_ts_owned = false;
        }
        self.last_ts = try self.allocator.dupe(u8, ts);
        self.last_ts_owned = true;
    }

    fn channelLastTs(self: *const SlackChannel, channel_id: []const u8) []const u8 {
        if (self.last_ts_by_channel.get(channel_id)) |ts| return ts;
        if (self.channel_id) |configured| {
            const cfg_trimmed = std.mem.trim(u8, configured, " \t\r\n");
            if (std.mem.indexOfScalar(u8, configured, ',') == null and std.mem.eql(u8, cfg_trimmed, channel_id)) {
                return self.last_ts;
            }
        }
        return "0";
    }

    fn setChannelLastTs(self: *SlackChannel, channel_id: []const u8, ts: []const u8) !void {
        if (self.channel_id) |configured| {
            const cfg_trimmed = std.mem.trim(u8, configured, " \t\r\n");
            if (std.mem.indexOfScalar(u8, configured, ',') == null and std.mem.eql(u8, cfg_trimmed, channel_id)) {
                return self.setLastTs(ts);
            }
        }

        if (self.last_ts_by_channel.getEntry(channel_id)) |entry| {
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = try self.allocator.dupe(u8, ts);
            return;
        }

        const key_copy = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key_copy);
        const ts_copy = try self.allocator.dupe(u8, ts);
        errdefer self.allocator.free(ts_copy);
        try self.last_ts_by_channel.put(self.allocator, key_copy, ts_copy);
    }

    fn clearChannelCursors(self: *SlackChannel) void {
        var it = self.last_ts_by_channel.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.last_ts_by_channel.deinit(self.allocator);
        self.last_ts_by_channel = .empty;
    }

    fn parseTs(ts: []const u8) f64 {
        return std.fmt.parseFloat(f64, ts) catch 0.0;
    }

    fn isDirectConversationId(channel_id: []const u8) bool {
        return channel_id.len > 0 and channel_id[0] == 'D';
    }

    fn fetchBotUserId(self: *SlackChannel) !void {
        const url = API_BASE ++ "/auth.test";
        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};
        const resp = root.http_util.curlGet(self.allocator, url, &headers, "15") catch return error.SlackApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.SlackApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SlackApiError;
        const ok_val = parsed.value.object.get("ok") orelse return error.SlackApiError;
        if (ok_val != .bool or !ok_val.bool) return error.SlackApiError;
        const uid_val = parsed.value.object.get("user_id") orelse return error.SlackApiError;
        if (uid_val != .string or uid_val.string.len == 0) return error.SlackApiError;

        if (self.bot_user_id) |old| self.allocator.free(old);
        self.bot_user_id = try self.allocator.dupe(u8, uid_val.string);
    }

    fn processHistoryMessage(
        self: *SlackChannel,
        msg_obj: std.json.ObjectMap,
        channel_id: []const u8,
    ) !void {
        if (msg_obj.get("subtype")) |sub_val| {
            if (sub_val == .string and sub_val.string.len > 0) return;
        }

        const user_val = msg_obj.get("user") orelse return;
        if (user_val != .string or user_val.string.len == 0) return;
        const sender_id = user_val.string;
        if (self.bot_user_id) |bot_uid| {
            if (std.mem.eql(u8, sender_id, bot_uid)) return;
        }

        const text_val = msg_obj.get("text") orelse return;
        if (text_val != .string) return;
        const text = std.mem.trim(u8, text_val.string, " \t\r\n");
        if (text.len == 0) return;

        const is_dm = isDirectConversationId(channel_id);
        if (!self.shouldHandle(sender_id, is_dm, text, self.bot_user_id)) return;

        const session_key = if (is_dm)
            try std.fmt.allocPrint(self.allocator, "slack:{s}:direct:{s}", .{ self.account_id, sender_id })
        else
            try std.fmt.allocPrint(self.allocator, "slack:{s}:channel:{s}", .{ self.account_id, channel_id });
        defer self.allocator.free(session_key);

        var metadata: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata.deinit(self.allocator);
        const mw = metadata.writer(self.allocator);
        try mw.writeByte('{');
        try mw.writeAll("\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        try mw.writeAll(",\"is_dm\":");
        try mw.writeAll(if (is_dm) "true" else "false");
        try mw.writeAll(",\"channel_id\":");
        try root.appendJsonStringW(mw, channel_id);
        try mw.writeByte('}');

        const inbound = try bus_mod.makeInboundFull(
            self.allocator,
            "slack",
            sender_id,
            channel_id,
            text,
            session_key,
            &.{},
            metadata.items,
        );
        if (self.bus) |b| {
            b.publishInbound(inbound) catch |err| {
                log.warn("Slack publishInbound failed: {}", .{err});
                inbound.deinit(self.allocator);
            };
        } else {
            inbound.deinit(self.allocator);
        }
    }

    fn pollChannelHistory(self: *SlackChannel, channel_id: []const u8) !void {
        var url_buf: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&url_buf);
        const w = fbs.writer();
        const oldest = self.channelLastTs(channel_id);
        try w.print("{s}/conversations.history?channel={s}&oldest={s}&inclusive=false&limit=100", .{ API_BASE, channel_id, oldest });
        const url = fbs.getWritten();

        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};
        const resp = root.http_util.curlGet(self.allocator, url, &headers, "30") catch return error.SlackApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.SlackApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SlackApiError;

        const ok_val = parsed.value.object.get("ok") orelse return error.SlackApiError;
        if (ok_val != .bool or !ok_val.bool) return error.SlackApiError;

        const messages_val = parsed.value.object.get("messages") orelse return;
        if (messages_val != .array) return;

        const current_last_ts = parseTs(oldest);
        var max_seen = current_last_ts;
        var max_ts_raw: ?[]const u8 = null;

        var idx: usize = messages_val.array.items.len;
        while (idx > 0) {
            idx -= 1;
            const msg = messages_val.array.items[idx];
            if (msg != .object) continue;
            const ts_val = msg.object.get("ts") orelse continue;
            if (ts_val != .string) continue;
            const ts_num = parseTs(ts_val.string);
            if (ts_num <= current_last_ts) continue;
            if (ts_num > max_seen) {
                max_seen = ts_num;
                max_ts_raw = ts_val.string;
            }
            try self.processHistoryMessage(msg.object, channel_id);
        }

        if (max_ts_raw) |ts| {
            try self.setChannelLastTs(channel_id, ts);
        }
    }

    fn pollOnce(self: *SlackChannel) !void {
        const channel_ids = self.channel_id orelse return;

        var saw_any = false;
        var it = std.mem.splitScalar(u8, channel_ids, ',');
        while (it.next()) |raw_channel_id| {
            const channel_id = std.mem.trim(u8, raw_channel_id, " \t\r\n");
            if (channel_id.len == 0) continue;
            saw_any = true;
            try self.pollChannelHistory(channel_id);
        }

        if (!saw_any) {
            return error.SlackChannelIdRequired;
        }
    }

    fn pollLoop(self: *SlackChannel) void {
        while (self.running.load(.acquire)) {
            self.pollOnce() catch |err| {
                log.warn("Slack poll error: {}", .{err});
            };

            var slept: u64 = 0;
            while (slept < POLL_INTERVAL_SECS and self.running.load(.acquire)) : (slept += 1) {
                std.Thread.sleep(std.time.ns_per_s);
            }
        }
    }

    fn componentAsSlice(component: std.Uri.Component) []const u8 {
        return switch (component) {
            .raw => |v| v,
            .percent_encoded => |v| v,
        };
    }

    fn parseSocketConnectParts(
        socket_url: []const u8,
        host_buf: []u8,
        path_buf: []u8,
    ) !struct { host: []const u8, port: u16, path: []const u8 } {
        const uri = std.Uri.parse(socket_url) catch return error.SlackApiError;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "wss")) return error.SlackApiError;

        const host = uri.getHost(host_buf) catch return error.SlackApiError;
        const port = uri.port orelse 443;
        const raw_path = componentAsSlice(uri.path);
        const query = if (uri.query) |q| componentAsSlice(q) else "";

        var fbs = std.io.fixedBufferStream(path_buf);
        const w = fbs.writer();
        if (raw_path.len == 0) {
            try w.writeByte('/');
        } else {
            if (raw_path[0] != '/') try w.writeByte('/');
            try w.writeAll(raw_path);
        }
        if (query.len > 0) {
            try w.writeByte('?');
            try w.writeAll(query);
        }
        return .{
            .host = host,
            .port = port,
            .path = fbs.getWritten(),
        };
    }

    fn openSocketUrl(self: *SlackChannel) ![]u8 {
        const app_token = self.app_token orelse return error.SlackAppTokenRequired;
        const url = API_BASE ++ "/apps.connections.open";
        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{app_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};
        const resp = root.http_util.curlPost(self.allocator, url, "{}", &headers) catch return error.SlackApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.SlackApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SlackApiError;
        const ok_val = parsed.value.object.get("ok") orelse return error.SlackApiError;
        if (ok_val != .bool or !ok_val.bool) return error.SlackApiError;
        const ws_url = parsed.value.object.get("url") orelse return error.SlackApiError;
        if (ws_url != .string or ws_url.string.len == 0) return error.SlackApiError;
        return self.allocator.dupe(u8, ws_url.string);
    }

    fn ackSocketEnvelope(self: *SlackChannel, ws: *websocket.WsClient, envelope_id: []const u8) !void {
        var buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();
        try w.writeAll("{\"envelope_id\":");
        try root.appendJsonStringW(w, envelope_id);
        try w.writeAll("}");
        try ws.writeText(fbs.getWritten());
        _ = self;
    }

    fn handleSocketPayload(self: *SlackChannel, ws: *websocket.WsClient, payload: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        const msg_type = if (parsed.value.object.get("type")) |tv|
            if (tv == .string) tv.string else ""
        else
            "";

        if (std.mem.eql(u8, msg_type, "disconnect")) return error.ShouldReconnect;

        if (parsed.value.object.get("envelope_id")) |env_val| {
            if (env_val == .string and env_val.string.len > 0) {
                self.ackSocketEnvelope(ws, env_val.string) catch |err| {
                    log.warn("Slack socket ack failed: {}", .{err});
                };
            }
        }

        if (!std.mem.eql(u8, msg_type, "events_api")) return;

        const payload_val = parsed.value.object.get("payload") orelse return;
        if (payload_val != .object) return;
        const event_val = payload_val.object.get("event") orelse return;
        if (event_val != .object) return;

        const event_type_val = event_val.object.get("type") orelse return;
        if (event_type_val != .string) return;
        const event_type = event_type_val.string;
        if (!std.mem.eql(u8, event_type, "message") and !std.mem.eql(u8, event_type, "app_mention")) {
            return;
        }

        const channel_val = event_val.object.get("channel") orelse return;
        if (channel_val != .string or channel_val.string.len == 0) return;
        try self.processHistoryMessage(event_val.object, channel_val.string);
    }

    fn runSocketOnce(self: *SlackChannel) !void {
        const ws_url = try self.openSocketUrl();
        defer self.allocator.free(ws_url);

        var host_buf: [512]u8 = undefined;
        var path_buf: [2048]u8 = undefined;
        const parts = try parseSocketConnectParts(ws_url, &host_buf, &path_buf);
        var ws = try websocket.WsClient.connect(self.allocator, parts.host, parts.port, parts.path, &.{});
        defer {
            self.connected.store(false, .release);
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }
        self.ws_fd.store(ws.stream.handle, .release);
        self.connected.store(true, .release);

        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);
            self.handleSocketPayload(&ws, text) catch |err| {
                if (err == error.ShouldReconnect) return err;
                log.warn("Slack socket payload error: {}", .{err});
            };
        }
    }

    fn socketLoop(self: *SlackChannel) void {
        while (self.running.load(.acquire)) {
            self.runSocketOnce() catch |err| {
                if (err != error.SlackAppTokenRequired) {
                    log.warn("Slack socket cycle failed: {}", .{err});
                }
            };
            if (!self.running.load(.acquire)) break;

            var slept: u64 = 0;
            while (slept < RECONNECT_DELAY_NS and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                slept += 100 * std.time.ns_per_ms;
            }
        }
        self.connected.store(false, .release);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Slack channel via chat.postMessage API.
    /// The target may contain "channel_id:thread_ts" for threaded replies.
    pub fn sendMessage(self: *SlackChannel, target_channel: []const u8, text: []const u8) !void {
        const url = API_BASE ++ "/chat.postMessage";

        // Parse target for thread_ts (channel_id:thread_ts)
        const actual_channel = self.parseTarget(target_channel);

        // Build JSON body
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"channel\":\"");
        try body_list.appendSlice(self.allocator, actual_channel);
        try body_list.appendSlice(self.allocator, "\",\"mrkdwn\":true,\"text\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        if (self.thread_ts) |tts| {
            try body_list.appendSlice(self.allocator, ",\"thread_ts\":\"");
            try body_list.appendSlice(self.allocator, tts);
            try body_list.append(self.allocator, '"');
        }
        try body_list.append(self.allocator, '}');

        // Build auth header: "Authorization: Bearer xoxb-..."
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Authorization: Bearer {s}", .{self.bot_token});
        const auth_header = auth_fbs.getWritten();

        const resp = root.http_util.curlPost(self.allocator, url, body_list.items, &.{auth_header}) catch |err| {
            log.err("Slack API POST failed: {}", .{err});
            return error.SlackApiError;
        };
        self.allocator.free(resp);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);
        errdefer self.running.store(false, .release);
        self.connected.store(false, .release);

        // Best-effort bot identity fetch for mention-only policies.
        self.fetchBotUserId() catch |err| {
            log.warn("Slack auth.test failed: {}", .{err});
        };

        switch (self.mode) {
            .socket => {
                if (self.app_token == null) return error.SlackAppTokenRequired;
                self.socket_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, socketLoop, .{self});
            },
            .http => {
                const secret = self.signing_secret orelse return error.SlackSigningSecretRequired;
                if (std.mem.trim(u8, secret, " \t\r\n").len == 0) return error.SlackSigningSecretRequired;
            },
        }
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.connected.store(false, .release);

        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(fd);
            } else {
                std.posix.close(fd);
            }
            self.ws_fd.store(invalid_socket, .release);
        }

        if (self.socket_thread) |t| {
            t.join();
            self.socket_thread = null;
        }

        if (self.poll_thread) |t| {
            t.join();
            self.poll_thread = null;
        }
        if (self.bot_user_id) |uid| {
            self.allocator.free(uid);
            self.bot_user_id = null;
        }
        self.clearChannelCursors();
        if (self.last_ts_owned) {
            self.allocator.free(self.last_ts);
            self.last_ts = "0";
            self.last_ts_owned = false;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *SlackChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *SlackChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

/// Check if a message text contains a Slack mention of the given user ID.
/// Slack mentions use the format `<@U12345>`.
pub fn containsMention(text: []const u8, user_id: []const u8) bool {
    // Search for "<@USER_ID>" pattern
    var i: usize = 0;
    while (i + 3 + user_id.len <= text.len) {
        if (text[i] == '<' and text[i + 1] == '@') {
            const start = i + 2;
            if (start + user_id.len <= text.len and
                std.mem.eql(u8, text[start .. start + user_id.len], user_id) and
                start + user_id.len < text.len and text[start + user_id.len] == '>')
            {
                return true;
            }
        }
        i += 1;
    }
    return false;
}

/// Convert standard Markdown to Slack mrkdwn format.
///
/// Conversions:
///   **bold**         -> *bold*
///   ~~strike~~       -> ~strike~
///   ```code```       -> ```code``` (preserved)
///   `inline code`    -> `inline code` (preserved)
///   [text](url)      -> <url|text>
///   # Header         -> *Header*
///   - bullet         -> bullet (with bullet char)
pub fn markdownToSlackMrkdwn(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    var line_start = true;

    while (i < input.len) {
        // ── Fenced code blocks (```) — preserve as-is ──
        if (i + 3 <= input.len and std.mem.eql(u8, input[i..][0..3], "```")) {
            try result.appendSlice(allocator, input[i..][0..3]);
            i += 3;
            // Copy everything until closing ```
            while (i < input.len) {
                if (i + 3 <= input.len and std.mem.eql(u8, input[i..][0..3], "```")) {
                    try result.appendSlice(allocator, input[i..][0..3]);
                    i += 3;
                    break;
                }
                try result.append(allocator, input[i]);
                i += 1;
            }
            line_start = false;
            continue;
        }

        // ── Headers at start of line: "# " -> bold ──
        if (line_start and i < input.len and input[i] == '#') {
            var hashes: usize = 0;
            var hi = i;
            while (hi < input.len and input[hi] == '#') {
                hashes += 1;
                hi += 1;
            }
            if (hashes > 0 and hi < input.len and input[hi] == ' ') {
                hi += 1; // skip space after #
                // Find end of line
                var end = hi;
                while (end < input.len and input[end] != '\n') {
                    end += 1;
                }
                try result.append(allocator, '*');
                try result.appendSlice(allocator, input[hi..end]);
                try result.append(allocator, '*');
                i = end;
                line_start = false;
                continue;
            }
        }

        // ── Bullet points at start of line: "- " -> "* " ──
        if (line_start and i + 1 < input.len and input[i] == '-' and input[i + 1] == ' ') {
            try result.appendSlice(allocator, "\xe2\x80\xa2 "); // bullet char U+2022
            i += 2;
            line_start = false;
            continue;
        }

        // ── Bold: **text** -> *text* ──
        if (i + 2 <= input.len and std.mem.eql(u8, input[i..][0..2], "**")) {
            // Find closing **
            const start = i + 2;
            if (std.mem.indexOf(u8, input[start..], "**")) |close_offset| {
                try result.append(allocator, '*');
                try result.appendSlice(allocator, input[start .. start + close_offset]);
                try result.append(allocator, '*');
                i = start + close_offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Strikethrough: ~~text~~ -> ~text~ ──
        if (i + 2 <= input.len and std.mem.eql(u8, input[i..][0..2], "~~")) {
            const start = i + 2;
            if (std.mem.indexOf(u8, input[start..], "~~")) |close_offset| {
                try result.append(allocator, '~');
                try result.appendSlice(allocator, input[start .. start + close_offset]);
                try result.append(allocator, '~');
                i = start + close_offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Inline code: `code` -> `code` (preserved) ──
        if (i < input.len and input[i] == '`') {
            try result.append(allocator, '`');
            i += 1;
            while (i < input.len and input[i] != '`') {
                try result.append(allocator, input[i]);
                i += 1;
            }
            if (i < input.len) {
                try result.append(allocator, '`');
                i += 1;
            }
            line_start = false;
            continue;
        }

        // ── Links: [text](url) -> <url|text> ──
        if (i < input.len and input[i] == '[') {
            const text_start = i + 1;
            if (std.mem.indexOfScalar(u8, input[text_start..], ']')) |close_bracket_offset| {
                const text_end = text_start + close_bracket_offset;
                const after_bracket = text_end + 1;
                if (after_bracket < input.len and input[after_bracket] == '(') {
                    const url_start = after_bracket + 1;
                    if (std.mem.indexOfScalar(u8, input[url_start..], ')')) |close_paren_offset| {
                        const url_end = url_start + close_paren_offset;
                        try result.append(allocator, '<');
                        try result.appendSlice(allocator, input[url_start..url_end]);
                        try result.append(allocator, '|');
                        try result.appendSlice(allocator, input[text_start..text_end]);
                        try result.append(allocator, '>');
                        i = url_end + 1;
                        line_start = false;
                        continue;
                    }
                }
            }
        }

        // ── Track newlines for line_start ──
        if (input[i] == '\n') {
            try result.append(allocator, '\n');
            i += 1;
            line_start = true;
            continue;
        }

        // ── Default: copy character ──
        try result.append(allocator, input[i]);
        i += 1;
        line_start = false;
    }

    return result.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "slack channel init defaults" {
    const allowed = [_][]const u8{"U123"};
    var ch = SlackChannel.init(std.testing.allocator, "xoxb-test", null, "C123", &allowed);
    try std.testing.expectEqualStrings("xoxb-test", ch.bot_token);
    try std.testing.expectEqualStrings("C123", ch.channel_id.?);
    try std.testing.expectEqualStrings("0", ch.last_ts);
    try std.testing.expect(ch.thread_ts == null);
    try std.testing.expect(ch.app_token == null);
    _ = ch.channelName();
}

test "slack initFromConfig maps pairing dm_policy to allowlist" {
    const cfg = config_types.SlackConfig{
        .account_id = "main",
        .mode = .socket,
        .bot_token = "xoxb-test",
        .app_token = "xapp-test",
        .dm_policy = "pairing",
        .group_policy = "mention_only",
        .allow_from = &.{"U123"},
    };
    const ch = SlackChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqual(root.DmPolicy.allowlist, ch.policy.dm);
    try std.testing.expectEqual(config_types.SlackReceiveMode.socket, ch.mode);
    try std.testing.expectEqualStrings(SlackChannel.DEFAULT_WEBHOOK_PATH, ch.webhook_path);
}

test "slack initFromConfig unknown dm_policy fails closed to allowlist" {
    const cfg = config_types.SlackConfig{
        .account_id = "main",
        .mode = .socket,
        .bot_token = "xoxb-test",
        .app_token = "xapp-test",
        .dm_policy = "something-unknown",
        .group_policy = "mention_only",
        .allow_from = &.{"U123"},
    };
    const ch = SlackChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqual(root.DmPolicy.allowlist, ch.policy.dm);
}

test "slack initFromConfig stores http mode signing secret and webhook path" {
    const cfg = config_types.SlackConfig{
        .account_id = "sl-http",
        .mode = .http,
        .bot_token = "xoxb-test",
        .signing_secret = "sign-secret",
        .webhook_path = "/slack/custom-events",
    };
    const ch = SlackChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqual(config_types.SlackReceiveMode.http, ch.mode);
    try std.testing.expectEqualStrings("sign-secret", ch.signing_secret.?);
    try std.testing.expectEqualStrings("/slack/custom-events", ch.webhook_path);
}

test "slack channel name" {
    const allowed = [_][]const u8{"*"};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    try std.testing.expectEqualStrings("slack", ch.channelName());
}

test "slack channel health check" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    try std.testing.expect(!ch.healthCheck());

    const Noop = struct {
        fn run() void {}
    };
    const t = try std.Thread.spawn(.{}, Noop.run, .{});
    defer t.join();

    ch.running.store(true, .release);
    ch.poll_thread = t;
    defer ch.poll_thread = null;
    try std.testing.expect(ch.healthCheck());
}

test "slack channel user allowed wildcard" {
    const allowed = [_][]const u8{"*"};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "slack channel user denied" {
    const allowed = [_][]const u8{"alice"};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    try std.testing.expect(!ch.isUserAllowed("bob"));
}

test "thread_ts field defaults to null" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, "C1", &allowed);
    try std.testing.expect(ch.thread_ts == null);
}

test "setThreadTs sets and clears thread_ts" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, "C1", &allowed);

    ch.setThreadTs("1234567890.123456");
    try std.testing.expectEqualStrings("1234567890.123456", ch.thread_ts.?);

    ch.setThreadTs(null);
    try std.testing.expect(ch.thread_ts == null);
}

test "setThreadTs overwrites previous value" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, "C1", &allowed);

    ch.setThreadTs("111.111");
    try std.testing.expectEqualStrings("111.111", ch.thread_ts.?);

    ch.setThreadTs("222.222");
    try std.testing.expectEqualStrings("222.222", ch.thread_ts.?);
}

test "setChannelLastTs keeps independent cursors for multi-channel polling" {
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, "C1,C2", &.{});
    defer ch.clearChannelCursors();

    try ch.setChannelLastTs("C1", "111.111");
    try ch.setChannelLastTs("C2", "222.222");

    try std.testing.expectEqualStrings("111.111", ch.channelLastTs("C1"));
    try std.testing.expectEqualStrings("222.222", ch.channelLastTs("C2"));
    try std.testing.expectEqualStrings("0", ch.channelLastTs("C3"));
}

test "parseTarget without colon returns full target" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);

    const result = ch.parseTarget("C12345");
    try std.testing.expectEqualStrings("C12345", result);
    try std.testing.expect(ch.thread_ts == null);
}

test "parseTarget with colon splits channel and thread_ts" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);

    const result = ch.parseTarget("C12345:1699999999.000100");
    try std.testing.expectEqualStrings("C12345", result);
    try std.testing.expectEqualStrings("1699999999.000100", ch.thread_ts.?);
}

test "parseTarget colon at end clears thread_ts" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);

    const result = ch.parseTarget("C999:");
    try std.testing.expectEqualStrings("C999", result);
    try std.testing.expect(ch.thread_ts == null);
}

test "parseTarget clears stale thread_ts for non-thread target" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);

    _ = ch.parseTarget("C12345:1699999999.000100");
    try std.testing.expectEqualStrings("1699999999.000100", ch.thread_ts.?);

    const result = ch.parseTarget("C12345");
    try std.testing.expectEqualStrings("C12345", result);
    try std.testing.expect(ch.thread_ts == null);
}

test "slack processHistoryMessage publishes inbound message to bus" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    const allowed = [_][]const u8{"*"};
    var ch = SlackChannel.init(alloc, "tok", null, "C12345", &allowed);
    ch.account_id = "sl-main";
    ch.setBus(&eb);

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        \\{"user":"U123","text":"hello from slack"}
    ,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);

    try ch.processHistoryMessage(parsed.value.object, "C12345");

    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("slack", msg.channel);
    try std.testing.expectEqualStrings("U123", msg.sender_id);
    try std.testing.expectEqualStrings("C12345", msg.chat_id);
    try std.testing.expectEqualStrings("slack:sl-main:channel:C12345", msg.session_key);
    try std.testing.expectEqualStrings("hello from slack", msg.content);
}

test "mrkdwn bold conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "This is **bold** text");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("This is *bold* text", result);
}

test "mrkdwn strikethrough conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "This is ~~deleted~~ text");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("This is ~deleted~ text", result);
}

test "mrkdwn inline code preserved" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "Use `fmt.Println` here");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Use `fmt.Println` here", result);
}

test "mrkdwn code block preserved" {
    const input = "Before\n```\ncode here\n```\nAfter";
    const result = try markdownToSlackMrkdwn(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(input, result);
}

test "mrkdwn link conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "Visit [Google](https://google.com) now");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Visit <https://google.com|Google> now", result);
}

test "mrkdwn header conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "# My Header");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*My Header*", result);
}

test "mrkdwn h2 header conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "## Sub Header");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*Sub Header*", result);
}

test "mrkdwn bullet conversion" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "- item one\n- item two");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\xe2\x80\xa2 item one\n\xe2\x80\xa2 item two", result);
}

test "mrkdwn combined bold and strikethrough" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "**bold** and ~~strike~~");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*bold* and ~strike~", result);
}

test "mrkdwn combined link and bold" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "**Click** [here](https://example.com)");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*Click* <https://example.com|here>", result);
}

test "mrkdwn empty input" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "mrkdwn plain text unchanged" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "Hello world, no markdown here.");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello world, no markdown here.", result);
}

test "mrkdwn multiple headers" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "# Title\n## Subtitle");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*Title*\n*Subtitle*", result);
}

test "mrkdwn link with special chars in text" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "[my site!](https://example.com/path?q=1)");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("<https://example.com/path?q=1|my site!>", result);
}

test "mrkdwn bullets with bold items" {
    const result = try markdownToSlackMrkdwn(std.testing.allocator, "- **first**\n- second");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\xe2\x80\xa2 *first*\n\xe2\x80\xa2 second", result);
}

test "slack channel vtable compiles" {
    const vt = SlackChannel.vtable;
    try std.testing.expect(@TypeOf(vt) == root.Channel.VTable);
}

test "slack channel interface returns slack name" {
    const allowed = [_][]const u8{};
    var ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    const iface = ch.channel();
    try std.testing.expectEqualStrings("slack", iface.name());
}

test "slack channel api base constant" {
    try std.testing.expectEqualStrings("https://slack.com/api", SlackChannel.API_BASE);
}

// ════════════════════════════════════════════════════════════════════════════
// containsMention tests
// ════════════════════════════════════════════════════════════════════════════

test "containsMention detects mention" {
    try std.testing.expect(containsMention("Hello <@U12345> how are you?", "U12345"));
}

test "containsMention no mention" {
    try std.testing.expect(!containsMention("Hello world", "U12345"));
}

test "containsMention at start" {
    try std.testing.expect(containsMention("<@UBOT> do something", "UBOT"));
}

test "containsMention at end" {
    try std.testing.expect(containsMention("ping <@UBOT>", "UBOT"));
}

test "containsMention wrong user" {
    try std.testing.expect(!containsMention("Hey <@UOTHER>", "UBOT"));
}

test "containsMention empty text" {
    try std.testing.expect(!containsMention("", "UBOT"));
}

test "containsMention partial match not detected" {
    try std.testing.expect(!containsMention("<@UBOT", "UBOT"));
    try std.testing.expect(!containsMention("@UBOT>", "UBOT"));
}

// ════════════════════════════════════════════════════════════════════════════
// Per-channel policy integration tests (shouldHandle)
// ════════════════════════════════════════════════════════════════════════════

test "shouldHandle default policy allows DM" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    // Default policy: dm=allow, group=open
    try std.testing.expect(ch.shouldHandle("U123", true, "hello", null));
}

test "shouldHandle default policy allows group without mention" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.init(std.testing.allocator, "tok", null, null, &allowed);
    try std.testing.expect(ch.shouldHandle("U123", false, "hello", "UBOT"));
}

test "shouldHandle mention_only group requires mention" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        null,
        null,
        &allowed,
        .{ .group = .mention_only },
    );
    try std.testing.expect(!ch.shouldHandle("U123", false, "hello", "UBOT"));
    try std.testing.expect(ch.shouldHandle("U123", false, "hey <@UBOT> help", "UBOT"));
}

test "shouldHandle deny dm blocks all DMs" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        null,
        null,
        &allowed,
        .{ .dm = .deny },
    );
    try std.testing.expect(!ch.shouldHandle("U123", true, "hello", null));
    try std.testing.expect(!ch.shouldHandle("U456", true, "hi", "UBOT"));
}

test "shouldHandle dm allowlist permits listed users" {
    const allowed = [_][]const u8{};
    const list = [_][]const u8{ "alice", "bob" };
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        null,
        null,
        &allowed,
        .{ .dm = .allowlist, .allowlist = &list },
    );
    try std.testing.expect(ch.shouldHandle("alice", true, "hi", null));
    try std.testing.expect(ch.shouldHandle("bob", true, "hi", null));
    try std.testing.expect(!ch.shouldHandle("eve", true, "hi", null));
}

test "shouldHandle group allowlist permits listed users" {
    const allowed = [_][]const u8{};
    const list = [_][]const u8{"trusted"};
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        null,
        null,
        &allowed,
        .{ .group = .allowlist, .allowlist = &list },
    );
    try std.testing.expect(ch.shouldHandle("trusted", false, "msg", "UBOT"));
    try std.testing.expect(!ch.shouldHandle("stranger", false, "msg", "UBOT"));
}

test "shouldHandle mention_only without bot_user_id treats as no mention" {
    const allowed = [_][]const u8{};
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        null,
        null,
        &allowed,
        .{ .group = .mention_only },
    );
    // No bot_user_id means mention cannot be detected
    try std.testing.expect(!ch.shouldHandle("U123", false, "hey <@UBOT> help", null));
}

test "initWithPolicy sets policy correctly" {
    const allowed = [_][]const u8{};
    const list = [_][]const u8{"admin"};
    const ch = SlackChannel.initWithPolicy(
        std.testing.allocator,
        "tok",
        "xapp-test",
        "C999",
        &allowed,
        .{ .dm = .deny, .group = .allowlist, .allowlist = &list },
    );
    try std.testing.expect(ch.policy.dm == .deny);
    try std.testing.expect(ch.policy.group == .allowlist);
    try std.testing.expectEqual(@as(usize, 1), ch.policy.allowlist.len);
    try std.testing.expectEqualStrings("admin", ch.policy.allowlist[0]);
    try std.testing.expectEqualStrings("tok", ch.bot_token);
    try std.testing.expectEqualStrings("xapp-test", ch.app_token.?);
    try std.testing.expectEqualStrings("C999", ch.channel_id.?);
}

test "normalizeWebhookPath falls back for invalid values" {
    try std.testing.expectEqualStrings(SlackChannel.DEFAULT_WEBHOOK_PATH, SlackChannel.normalizeWebhookPath(""));
    try std.testing.expectEqualStrings(SlackChannel.DEFAULT_WEBHOOK_PATH, SlackChannel.normalizeWebhookPath("slack/events"));
    try std.testing.expectEqualStrings("/slack/events", SlackChannel.normalizeWebhookPath("/slack/events"));
}

test "parseSocketConnectParts extracts host port and path" {
    var host_buf: [128]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const parts = try SlackChannel.parseSocketConnectParts(
        "wss://wss-primary.slack.com/link/?ticket=abc123",
        &host_buf,
        &path_buf,
    );
    try std.testing.expectEqualStrings("wss-primary.slack.com", parts.host);
    try std.testing.expectEqual(@as(u16, 443), parts.port);
    try std.testing.expectEqualStrings("/link/?ticket=abc123", parts.path);
}
