const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const websocket = @import("../websocket.zig");
const bus_mod = @import("../bus.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.mattermost);

const SocketFd = std.net.Stream.Handle;
const invalid_socket: SocketFd = switch (builtin.os.tag) {
    .windows => std.os.windows.ws2_32.INVALID_SOCKET,
    else => -1,
};

const DEFAULT_ONCHAR_PREFIXES = [_][]const u8{ ">", "!" };

const ParsedTarget = struct {
    kind: Kind,
    value: []const u8,
    thread_id: ?[]const u8 = null,

    const Kind = enum {
        channel,
        user,
        username,
    };
};

const ChannelKind = enum {
    direct,
    group,
    channel,
};

const ChatMode = enum {
    oncall,
    onmessage,
    onchar,
};

pub const DEDUP_RING_SIZE: usize = 1024;

/// Fixed-size ring buffer for post-id deduplication in the websocket loop.
pub const DedupRing = struct {
    ring: [DEDUP_RING_SIZE]u64 = [_]u64{0} ** DEDUP_RING_SIZE,
    idx: u32 = 0,
    count: u32 = 0,

    pub fn isDuplicate(self: *DedupRing, id_hash: u64) bool {
        const check_count = @min(self.count, DEDUP_RING_SIZE);
        for (0..check_count) |i| {
            if (self.ring[i] == id_hash) return true;
        }
        self.ring[self.idx] = id_hash;
        self.idx = @intCast((self.idx + 1) % @as(u32, DEDUP_RING_SIZE));
        if (self.count < DEDUP_RING_SIZE) self.count += 1;
        return false;
    }
};

pub const MattermostChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    bot_token: []const u8,
    base_url: []const u8,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    dm_policy: []const u8 = "allowlist",
    group_policy: []const u8 = "allowlist",
    chatmode: []const u8 = "oncall",
    onchar_prefixes: []const []const u8 = &.{},
    require_mention: bool = true,

    bus: ?*bus_mod.Bus = null,
    dedup: DedupRing = .{},

    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ws_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    tmp_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    gateway_thread: ?std.Thread = null,

    bot_state_mu: std.Thread.Mutex = .{},
    bot_user_id: ?[]u8 = null,
    bot_username: ?[]u8 = null,

    pub const MAX_MESSAGE_LEN: usize = 4000;
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    pub fn init(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        base_url: []const u8,
    ) MattermostChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .base_url = normalizeBaseUrl(base_url),
            .onchar_prefixes = &DEFAULT_ONCHAR_PREFIXES,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.MattermostConfig) MattermostChannel {
        var ch = init(allocator, cfg.bot_token, cfg.base_url);
        ch.account_id = cfg.account_id;
        ch.allow_from = cfg.allow_from;
        ch.group_allow_from = cfg.group_allow_from;
        ch.dm_policy = cfg.dm_policy;
        ch.group_policy = cfg.group_policy;
        ch.chatmode = cfg.chatmode;
        ch.onchar_prefixes = cfg.onchar_prefixes;
        ch.require_mention = cfg.require_mention;
        return ch;
    }

    pub fn channelName(_: *const MattermostChannel) []const u8 {
        return "mattermost";
    }

    pub fn setBus(self: *MattermostChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn healthCheck(self: *const MattermostChannel) bool {
        return self.running.load(.acquire);
    }

    pub fn sendMessage(self: *MattermostChannel, target: []const u8, text: []const u8) !void {
        const parsed_target = try parseTarget(target);
        const trimmed_text = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed_text.len == 0) return;

        var resolved_channel_id: ?[]u8 = null;
        defer if (resolved_channel_id) |cid| self.allocator.free(cid);

        const channel_id: []const u8 = switch (parsed_target.kind) {
            .channel => parsed_target.value,
            .user => blk: {
                resolved_channel_id = try self.resolveDirectChannelId(parsed_target.value);
                break :blk resolved_channel_id.?;
            },
            .username => blk: {
                const user_id = try self.resolveUserIdByUsername(parsed_target.value);
                defer self.allocator.free(user_id);
                resolved_channel_id = try self.resolveDirectChannelId(user_id);
                break :blk resolved_channel_id.?;
            },
        };

        var it = root.splitMessage(trimmed_text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            const c = std.mem.trim(u8, chunk, " \t\r\n");
            if (c.len == 0) continue;
            try self.sendPost(channel_id, c, parsed_target.thread_id);
        }
    }

    fn sendPost(self: *MattermostChannel, channel_id: []const u8, text: []const u8, thread_id: ?[]const u8) !void {
        const url = try std.fmt.allocPrint(self.allocator, "{s}/api/v4/posts", .{self.base_url});
        defer self.allocator.free(url);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        const bw = body.writer(self.allocator);
        try bw.writeAll("{\"channel_id\":");
        try root.appendJsonStringW(bw, channel_id);
        try bw.writeAll(",\"message\":");
        try root.appendJsonStringW(bw, text);
        if (thread_id) |tid| {
            if (tid.len > 0) {
                try bw.writeAll(",\"root_id\":");
                try root.appendJsonStringW(bw, tid);
            }
        }
        try bw.writeByte('}');

        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlPost(self.allocator, url, body.items, &headers) catch return error.MattermostApiError;
        defer self.allocator.free(resp);

        if (std.mem.indexOf(u8, resp, "\"id\"") == null) {
            return error.MattermostApiError;
        }
    }

    fn resolveUserIdByUsername(self: *MattermostChannel, username: []const u8) ![]u8 {
        var url_buf: [2048]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&url_buf);
        const w = fbs.writer();
        try w.print("{s}/api/v4/users/username/", .{self.base_url});
        try appendUrlEncoded(w, username);
        const url = fbs.getWritten();

        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlGet(self.allocator, url, &headers, "15") catch return error.MattermostApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.MattermostApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.MattermostApiError;
        const id_val = parsed.value.object.get("id") orelse return error.MattermostApiError;
        if (id_val != .string) return error.MattermostApiError;
        return self.allocator.dupe(u8, id_val.string);
    }

    fn resolveDirectChannelId(self: *MattermostChannel, user_id: []const u8) ![]u8 {
        const bot_id = try self.fetchBotUserId();

        const url = try std.fmt.allocPrint(self.allocator, "{s}/api/v4/channels/direct", .{self.base_url});
        defer self.allocator.free(url);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        const bw = body.writer(self.allocator);
        try bw.writeByte('[');
        try root.appendJsonStringW(bw, bot_id);
        try bw.writeByte(',');
        try root.appendJsonStringW(bw, user_id);
        try bw.writeByte(']');

        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlPost(self.allocator, url, body.items, &headers) catch return error.MattermostApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.MattermostApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.MattermostApiError;
        const id_val = parsed.value.object.get("id") orelse return error.MattermostApiError;
        if (id_val != .string) return error.MattermostApiError;
        return self.allocator.dupe(u8, id_val.string);
    }

    fn fetchBotUserId(self: *MattermostChannel) ![]const u8 {
        self.bot_state_mu.lock();
        defer self.bot_state_mu.unlock();
        if (self.bot_user_id) |uid| return uid;

        const url = try std.fmt.allocPrint(self.allocator, "{s}/api/v4/users/me", .{self.base_url});
        defer self.allocator.free(url);
        const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token});
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlGet(self.allocator, url, &headers, "15") catch return error.MattermostApiError;
        defer self.allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch return error.MattermostApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.MattermostApiError;

        const id_val = parsed.value.object.get("id") orelse return error.MattermostApiError;
        if (id_val != .string) return error.MattermostApiError;
        self.bot_user_id = try self.allocator.dupe(u8, id_val.string);

        if (parsed.value.object.get("username")) |u| {
            if (u == .string and u.string.len > 0) {
                self.bot_username = try self.allocator.dupe(u8, u.string);
            }
        }

        return self.bot_user_id.?;
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *MattermostChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        errdefer self.running.store(false, .release);
        self.connected.store(false, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *MattermostChannel = @ptrCast(@alignCast(ptr));
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

        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }

        self.bot_state_mu.lock();
        defer self.bot_state_mu.unlock();
        if (self.bot_user_id) |uid| {
            self.allocator.free(uid);
            self.bot_user_id = null;
        }
        if (self.bot_username) |uname| {
            self.allocator.free(uname);
            self.bot_username = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *MattermostChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *MattermostChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *MattermostChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *MattermostChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn gatewayLoop(self: *MattermostChannel) void {
        while (self.running.load(.acquire)) {
            self.runGatewayOnce() catch |err| {
                log.warn("mattermost websocket cycle failed: {}", .{err});
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

    fn runGatewayOnce(self: *MattermostChannel) !void {
        // Prime bot identity once per connection cycle so mention checks and
        // self-message filtering are reliable.
        _ = try self.fetchBotUserId();

        var host_buf: [512]u8 = undefined;
        var path_buf: [1024]u8 = undefined;
        const parts = try self.websocketConnectParts(&host_buf, &path_buf);

        var ws = try websocket.WsClient.connect(
            self.allocator,
            parts.host,
            parts.port,
            parts.path,
            &.{},
        );
        defer {
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }
        self.ws_fd.store(ws.stream.handle, .release);

        var auth_buf: [1024]u8 = undefined;
        const seq = self.ws_seq.fetchAdd(1, .monotonic) + 1;
        const auth_payload = std.fmt.bufPrint(
            &auth_buf,
            "{{\"seq\":{d},\"action\":\"authentication_challenge\",\"data\":{{\"token\":",
            .{seq},
        ) catch return error.MattermostProtocolError;

        var auth_list: std.ArrayListUnmanaged(u8) = .empty;
        defer auth_list.deinit(self.allocator);
        try auth_list.appendSlice(self.allocator, auth_payload);
        try root.json_util.appendJsonString(&auth_list, self.allocator, self.bot_token);
        try auth_list.appendSlice(self.allocator, "}}");

        try ws.writeText(auth_list.items);

        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);

            self.connected.store(true, .release);
            self.handleGatewayMessage(text) catch |err| {
                log.warn("mattermost websocket message handling error: {}", .{err});
            };
        }

        self.connected.store(false, .release);
    }

    fn websocketConnectParts(
        self: *const MattermostChannel,
        host_buf: []u8,
        path_buf: []u8,
    ) !struct { host: []const u8, port: u16, path: []const u8 } {
        const uri = std.Uri.parse(self.base_url) catch return error.InvalidBaseUrl;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return error.MattermostRequiresHttps;
        }
        const host = uri.getHost(host_buf) catch return error.InvalidBaseUrl;
        const port = uri.port orelse 443;
        const raw_path = componentAsSlice(uri.path);
        var prefix = raw_path;
        if (prefix.len == 1 and prefix[0] == '/') prefix = "";
        while (prefix.len > 0 and prefix[prefix.len - 1] == '/') {
            prefix = prefix[0 .. prefix.len - 1];
        }

        var fbs = std.io.fixedBufferStream(path_buf);
        const w = fbs.writer();
        if (prefix.len > 0) {
            if (prefix[0] != '/') try w.writeByte('/');
            try w.writeAll(prefix);
        }
        try w.writeAll("/api/v4/websocket");
        return .{
            .host = host,
            .port = port,
            .path = fbs.getWritten(),
        };
    }

    fn handleGatewayMessage(self: *MattermostChannel, payload: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        const event_val = parsed.value.object.get("event") orelse return;
        if (event_val != .string) return;

        if (std.mem.eql(u8, event_val.string, "posted")) {
            try self.handlePostedPayload(parsed.value.object);
        }
    }

    fn handlePostedPayload(self: *MattermostChannel, payload_obj: std.json.ObjectMap) !void {
        const data_val = payload_obj.get("data") orelse return;
        if (data_val != .object) return;
        const data_obj = data_val.object;

        var parsed_post: ?std.json.Parsed(std.json.Value) = null;
        defer if (parsed_post) |*pp| pp.deinit();

        const post_val = data_obj.get("post") orelse return;
        var post_root: std.json.Value = undefined;
        if (post_val == .object) {
            post_root = post_val;
        } else if (post_val == .string) {
            parsed_post = std.json.parseFromSlice(std.json.Value, self.allocator, post_val.string, .{}) catch return;
            post_root = parsed_post.?.value;
        } else return;

        if (post_root != .object) return;
        const post_obj = post_root.object;

        const post_id = jsonString(post_obj, "id") orelse return;
        if (post_id.len > 0) {
            const post_hash = std.hash.Fnv1a_64.hash(post_id);
            if (self.dedup.isDuplicate(post_hash)) return;
        }

        const sender_id = jsonString(post_obj, "user_id") orelse return;
        self.bot_state_mu.lock();
        const bot_id = self.bot_user_id;
        self.bot_state_mu.unlock();
        if (bot_id) |bid| {
            if (std.mem.eql(u8, bid, sender_id)) return;
        }

        const post_type = jsonString(post_obj, "type") orelse "";
        if (post_type.len > 0) return;

        const channel_id = jsonString(post_obj, "channel_id") orelse jsonString(data_obj, "channel_id") orelse return;
        const sender_name = jsonString(data_obj, "sender_name");
        const team_id = jsonString(data_obj, "team_id") orelse blk: {
            if (payload_obj.get("broadcast")) |b| {
                if (b == .object) {
                    if (jsonString(b.object, "team_id")) |tid| break :blk tid;
                }
            }
            break :blk null;
        };

        const kind = channelKindFromType(jsonString(data_obj, "channel_type"));

        if (kind == .direct) {
            if (!self.isDirectSenderAllowed(sender_id, sender_name)) return;
        } else {
            if (!self.isGroupSenderAllowed(sender_id, sender_name)) return;
        }

        const message_raw = std.mem.trim(u8, jsonString(post_obj, "message") orelse "", " \t\r\n");
        var message_body = message_raw;

        if (kind != .direct) {
            const was_mentioned = self.isBotMentioned(message_raw);
            switch (self.resolveChatMode()) {
                .onmessage => {},
                .oncall => if (!was_mentioned) return,
                .onchar => {
                    if (self.stripOncharPrefix(message_raw)) |stripped| {
                        message_body = stripped;
                    } else if (!was_mentioned) {
                        return;
                    }
                },
            }
        }
        message_body = std.mem.trim(u8, message_body, " \t\r\n");

        var content: std.ArrayListUnmanaged(u8) = .empty;
        defer content.deinit(self.allocator);
        if (message_body.len > 0) {
            try content.appendSlice(self.allocator, message_body);
        }

        if (post_obj.get("file_ids")) |fids| {
            if (fids == .array) {
                for (fids.array.items) |fid| {
                    if (fid != .string or fid.string.len == 0) continue;
                    const maybe_path = self.downloadAttachmentToTemp(fid.string);
                    if (maybe_path) |path| {
                        defer self.allocator.free(path);
                        if (content.items.len > 0) try content.appendSlice(self.allocator, "\n");
                        try content.appendSlice(self.allocator, "[IMAGE:");
                        try content.appendSlice(self.allocator, path);
                        try content.appendSlice(self.allocator, "]");
                    }
                }
            }
        }

        if (content.items.len == 0) return;

        const root_id_raw = std.mem.trim(u8, jsonString(post_obj, "root_id") orelse "", " \t\r\n");
        const thread_id: ?[]const u8 = if (root_id_raw.len > 0) root_id_raw else null;

        const reply_target = if (thread_id) |tid|
            try std.fmt.allocPrint(self.allocator, "channel:{s}:thread:{s}", .{ channel_id, tid })
        else
            try std.fmt.allocPrint(self.allocator, "channel:{s}", .{channel_id});
        defer self.allocator.free(reply_target);

        const kind_label = switch (kind) {
            .direct => "direct",
            .group => "group",
            .channel => "channel",
        };
        const session_key = if (thread_id) |tid|
            try std.fmt.allocPrint(self.allocator, "mattermost:{s}:{s}:{s}:thread:{s}", .{ self.account_id, kind_label, channel_id, tid })
        else
            try std.fmt.allocPrint(self.allocator, "mattermost:{s}:{s}:{s}", .{ self.account_id, kind_label, channel_id });
        defer self.allocator.free(session_key);

        var meta: std.ArrayListUnmanaged(u8) = .empty;
        defer meta.deinit(self.allocator);
        const mw = meta.writer(self.allocator);
        try mw.writeByte('{');
        try mw.writeAll("\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        try mw.writeAll(",\"is_dm\":");
        try mw.writeAll(if (kind == .direct) "true" else "false");
        try mw.writeAll(",\"is_group\":");
        try mw.writeAll(if (kind == .group) "true" else "false");
        try mw.writeAll(",\"channel_id\":");
        try root.appendJsonStringW(mw, channel_id);
        try mw.writeAll(",\"channel_kind\":");
        try root.appendJsonStringW(mw, kind_label);
        if (team_id) |tid| {
            try mw.writeAll(",\"team_id\":");
            try root.appendJsonStringW(mw, tid);
        }
        if (thread_id) |tid| {
            try mw.writeAll(",\"thread_id\":");
            try root.appendJsonStringW(mw, tid);
        }
        if (sender_name) |sname| {
            try mw.writeAll(",\"sender_name\":");
            try root.appendJsonStringW(mw, sname);
        }
        try mw.writeByte('}');

        const content_owned = try content.toOwnedSlice(self.allocator);
        defer self.allocator.free(content_owned);

        const inbound = try bus_mod.makeInboundFull(
            self.allocator,
            "mattermost",
            sender_id,
            reply_target,
            content_owned,
            session_key,
            &.{},
            meta.items,
        );

        if (self.bus) |b| {
            b.publishInbound(inbound) catch |err| {
                log.warn("mattermost publishInbound failed: {}", .{err});
                inbound.deinit(self.allocator);
            };
        } else {
            inbound.deinit(self.allocator);
        }
    }

    fn downloadAttachmentToTemp(self: *MattermostChannel, file_id: []const u8) ?[]u8 {
        const url = std.fmt.allocPrint(self.allocator, "{s}/api/v4/files/{s}", .{ self.base_url, file_id }) catch return null;
        defer self.allocator.free(url);

        const auth_header = std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{self.bot_token}) catch return null;
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const data = root.http_util.curlGet(self.allocator, url, &headers, "20") catch return null;
        defer self.allocator.free(data);
        if (data.len == 0) return null;

        const tmp_env = std.process.getEnvVarOwned(self.allocator, "TMPDIR") catch null;
        defer if (tmp_env) |v| self.allocator.free(v);
        const tmp_dir = blk: {
            if (tmp_env) |v| {
                const trimmed = std.mem.trimRight(u8, v, "/");
                if (trimmed.len > 0) break :blk trimmed;
            }
            break :blk "/tmp";
        };

        const counter = self.tmp_counter.fetchAdd(1, .monotonic) + 1;
        const path = std.fmt.allocPrint(
            self.allocator,
            "{s}/nullclaw_mattermost_{d}_{d}.bin",
            .{ tmp_dir, std.time.timestamp(), counter },
        ) catch return null;
        errdefer self.allocator.free(path);

        const file = std.fs.createFileAbsolute(path, .{ .read = false }) catch return null;
        defer file.close();
        file.writeAll(data) catch return null;
        return path;
    }

    fn isDirectSenderAllowed(self: *const MattermostChannel, sender_id: []const u8, sender_name: ?[]const u8) bool {
        if (std.mem.eql(u8, self.dm_policy, "disabled")) return false;
        if (std.mem.eql(u8, self.dm_policy, "open")) return true;
        return senderMatchesAllowlist(self.allow_from, sender_id, sender_name);
    }

    fn isGroupSenderAllowed(self: *const MattermostChannel, sender_id: []const u8, sender_name: ?[]const u8) bool {
        if (std.mem.eql(u8, self.group_policy, "disabled")) return false;
        if (std.mem.eql(u8, self.group_policy, "open")) return true;
        const effective = if (self.group_allow_from.len > 0) self.group_allow_from else self.allow_from;
        if (effective.len == 0) return false;
        return senderMatchesAllowlist(effective, sender_id, sender_name);
    }

    fn resolveChatMode(self: *const MattermostChannel) ChatMode {
        if (std.mem.eql(u8, self.chatmode, "onmessage")) return .onmessage;
        if (std.mem.eql(u8, self.chatmode, "onchar")) return .onchar;
        if (std.mem.eql(u8, self.chatmode, "oncall")) return .oncall;
        return if (self.require_mention) .oncall else .onmessage;
    }

    fn isBotMentioned(self: *const MattermostChannel, text: []const u8) bool {
        const username = self.bot_username orelse return false;

        var mention_buf: [256]u8 = undefined;
        const mention = std.fmt.bufPrint(&mention_buf, "@{s}", .{username}) catch return false;
        return std.ascii.indexOfIgnoreCase(text, mention) != null;
    }

    fn stripOncharPrefix(self: *const MattermostChannel, text: []const u8) ?[]const u8 {
        const prefixes = if (self.onchar_prefixes.len > 0) self.onchar_prefixes else &DEFAULT_ONCHAR_PREFIXES;
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        for (prefixes) |prefix| {
            const p = std.mem.trim(u8, prefix, " \t\r\n");
            if (p.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, p)) {
                return std.mem.trimLeft(u8, trimmed[p.len..], " \t\r\n");
            }
        }
        return null;
    }
};

fn normalizeBaseUrl(input: []const u8) []const u8 {
    var out = std.mem.trim(u8, input, " \t\r\n");
    while (out.len > 0 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    if (endsWithIgnoreCase(out, "/api/v4")) {
        out = out[0 .. out.len - "/api/v4".len];
        while (out.len > 0 and out[out.len - 1] == '/') {
            out = out[0 .. out.len - 1];
        }
    }
    return out;
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

fn trimPrefixIgnoreCase(value: []const u8, prefix: []const u8) ?[]const u8 {
    if (value.len < prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix)) return null;
    return value[prefix.len..];
}

fn normalizeAllowEntry(entry: []const u8) []const u8 {
    var out = std.mem.trim(u8, entry, " \t\r\n");
    if (trimPrefixIgnoreCase(out, "mattermost:")) |rest| out = std.mem.trim(u8, rest, " \t\r\n");
    if (trimPrefixIgnoreCase(out, "user:")) |rest| out = std.mem.trim(u8, rest, " \t\r\n");
    if (out.len > 0 and out[0] == '@') out = std.mem.trim(u8, out[1..], " \t\r\n");
    return out;
}

fn allowEntryMatches(entry: []const u8, sender_id: []const u8, sender_name: ?[]const u8) bool {
    const normalized = normalizeAllowEntry(entry);
    if (normalized.len == 0) return false;
    if (std.mem.eql(u8, normalized, "*")) return true;
    if (std.ascii.eqlIgnoreCase(normalized, normalizeAllowEntry(sender_id))) return true;
    if (sender_name) |name| {
        if (std.ascii.eqlIgnoreCase(normalized, normalizeAllowEntry(name))) return true;
    }
    return false;
}

fn senderMatchesAllowlist(allow_from: []const []const u8, sender_id: []const u8, sender_name: ?[]const u8) bool {
    if (allow_from.len == 0) return false;
    for (allow_from) |entry| {
        if (allowEntryMatches(entry, sender_id, sender_name)) return true;
    }
    return false;
}

fn channelKindFromType(raw_type: ?[]const u8) ChannelKind {
    const channel_type = raw_type orelse return .channel;
    if (channel_type.len == 0) return .channel;
    const first = std.ascii.toUpper(channel_type[0]);
    return switch (first) {
        'D' => .direct,
        'G' => .group,
        else => .channel,
    };
}

fn componentAsSlice(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |v| v,
        .percent_encoded => |v| v,
    };
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

fn appendUrlEncoded(writer: anytype, text: []const u8) !void {
    for (text) |c| {
        if (isUnreserved(c)) {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

fn parseTarget(target: []const u8) !ParsedTarget {
    var t = std.mem.trim(u8, target, " \t\r\n");
    if (t.len == 0) return error.InvalidTarget;

    var thread_id: ?[]const u8 = null;
    if (std.mem.indexOf(u8, t, ":thread:")) |idx| {
        const raw_thread = std.mem.trim(u8, t[idx + ":thread:".len ..], " \t\r\n");
        if (raw_thread.len == 0) return error.InvalidTarget;
        thread_id = raw_thread;
        t = std.mem.trim(u8, t[0..idx], " \t\r\n");
    }
    if (t.len == 0) return error.InvalidTarget;

    if (trimPrefixIgnoreCase(t, "channel:")) |rest| {
        const id = std.mem.trim(u8, rest, " \t\r\n");
        if (id.len == 0) return error.InvalidTarget;
        return .{ .kind = .channel, .value = id, .thread_id = thread_id };
    }
    if (trimPrefixIgnoreCase(t, "group:")) |rest| {
        const id = std.mem.trim(u8, rest, " \t\r\n");
        if (id.len == 0) return error.InvalidTarget;
        return .{ .kind = .channel, .value = id, .thread_id = thread_id };
    }
    if (trimPrefixIgnoreCase(t, "user:")) |rest| {
        const id = std.mem.trim(u8, rest, " \t\r\n");
        if (id.len == 0) return error.InvalidTarget;
        return .{ .kind = .user, .value = id, .thread_id = thread_id };
    }
    if (trimPrefixIgnoreCase(t, "mattermost:")) |rest| {
        const id = std.mem.trim(u8, rest, " \t\r\n");
        if (id.len == 0) return error.InvalidTarget;
        return .{ .kind = .user, .value = id, .thread_id = thread_id };
    }
    if (t[0] == '@') {
        const username = std.mem.trim(u8, t[1..], " \t\r\n");
        if (username.len == 0) return error.InvalidTarget;
        return .{ .kind = .username, .value = username, .thread_id = thread_id };
    }
    if (t[0] == '#') {
        const id = std.mem.trim(u8, t[1..], " \t\r\n");
        if (id.len == 0) return error.InvalidTarget;
        return .{ .kind = .channel, .value = id, .thread_id = thread_id };
    }
    return .{ .kind = .channel, .value = t, .thread_id = thread_id };
}

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return if (val == .string) val.string else null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "mattermost parseTarget supports prefixes and thread suffix" {
    const a = try parseTarget("channel:chan-1");
    try std.testing.expect(a.kind == .channel);
    try std.testing.expectEqualStrings("chan-1", a.value);
    try std.testing.expect(a.thread_id == null);

    const b = try parseTarget("user:uid-1");
    try std.testing.expect(b.kind == .user);
    try std.testing.expectEqualStrings("uid-1", b.value);

    const c = try parseTarget("@alice");
    try std.testing.expect(c.kind == .username);
    try std.testing.expectEqualStrings("alice", c.value);

    const d = try parseTarget("channel:chan-1:thread:root-9");
    try std.testing.expect(d.kind == .channel);
    try std.testing.expectEqualStrings("chan-1", d.value);
    try std.testing.expectEqualStrings("root-9", d.thread_id.?);

    const e = try parseTarget("group:grp-1");
    try std.testing.expect(e.kind == .channel);
    try std.testing.expectEqualStrings("grp-1", e.value);

    const f = try parseTarget("#town-square");
    try std.testing.expect(f.kind == .channel);
    try std.testing.expectEqualStrings("town-square", f.value);
}

test "mattermost normalizeBaseUrl strips trailing slash and api suffix" {
    try std.testing.expectEqualStrings("https://chat.example.com", normalizeBaseUrl("https://chat.example.com/"));
    try std.testing.expectEqualStrings("https://chat.example.com", normalizeBaseUrl("https://chat.example.com/api/v4"));
    try std.testing.expectEqualStrings("https://chat.example.com/team", normalizeBaseUrl("https://chat.example.com/team/api/v4/"));
}

test "mattermost allow entry matching supports user id username and prefixes" {
    try std.testing.expect(allowEntryMatches("user:U123", "u123", null));
    try std.testing.expect(allowEntryMatches("@Alice", "u123", "alice"));
    try std.testing.expect(!allowEntryMatches("@Bob", "u123", "alice"));
    try std.testing.expect(allowEntryMatches("*", "u123", null));
}

test "mattermost handleGatewayMessage publishes allowed direct message" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{"user-1"},
        .dm_policy = "allowlist",
        .group_policy = "allowlist",
        .chatmode = "onmessage",
        .require_mention = false,
    });
    ch.setBus(&eb);

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p1\",\"user_id\":\"user-1\",\"channel_id\":\"dm-1\",\"message\":\"hello\"}","channel_type":"D","channel_id":"dm-1","sender_name":"alice"},"broadcast":{"channel_id":"dm-1","user_id":"user-1"}}
    ;
    try ch.handleGatewayMessage(payload);

    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("mattermost", msg.channel);
    try std.testing.expectEqualStrings("user-1", msg.sender_id);
    try std.testing.expectEqualStrings("channel:dm-1", msg.chat_id);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("mattermost:mm-main:direct:dm-1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expectEqualStrings("mm-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(meta.value.object.get("is_dm").?.bool);
    try std.testing.expectEqualStrings("dm-1", meta.value.object.get("channel_id").?.string);
}

test "mattermost handleGatewayMessage drops disallowed group messages" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{},
        .group_allow_from = &.{},
        .dm_policy = "allowlist",
        .group_policy = "allowlist",
        .chatmode = "onmessage",
        .require_mention = false,
    });
    ch.setBus(&eb);

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p2\",\"user_id\":\"user-2\",\"channel_id\":\"grp-1\",\"message\":\"hello group\"}","channel_type":"G","channel_id":"grp-1","sender_name":"bob"},"broadcast":{"channel_id":"grp-1","user_id":"user-2"}}
    ;
    try ch.handleGatewayMessage(payload);
    eb.close();
    try std.testing.expect(eb.consumeInbound() == null);
}

test "mattermost handleGatewayMessage publishes thread metadata for channel posts" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{},
        .group_policy = "open",
        .chatmode = "onmessage",
        .require_mention = false,
    });
    ch.setBus(&eb);

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p3\",\"user_id\":\"user-3\",\"channel_id\":\"town\",\"message\":\"thread reply\",\"root_id\":\"root-42\"}","channel_type":"O","channel_id":"town","sender_name":"carol","team_id":"team-1"},"broadcast":{"channel_id":"town","user_id":"user-3","team_id":"team-1"}}
    ;
    try ch.handleGatewayMessage(payload);

    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("channel:town:thread:root-42", msg.chat_id);
    try std.testing.expectEqualStrings("mattermost:mm-main:channel:town:thread:root-42", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expectEqualStrings("team-1", meta.value.object.get("team_id").?.string);
    try std.testing.expectEqualStrings("root-42", meta.value.object.get("thread_id").?.string);
    try std.testing.expectEqualStrings("town", meta.value.object.get("channel_id").?.string);
}

test "mattermost chatmode oncall requires mention in non-direct chats" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{},
        .group_policy = "open",
        .chatmode = "oncall",
        .require_mention = true,
    });
    ch.setBus(&eb);

    ch.bot_username = try alloc.dupe(u8, "nullclaw");
    defer {
        if (ch.bot_username) |u| alloc.free(u);
        ch.bot_username = null;
    }

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p4\",\"user_id\":\"user-4\",\"channel_id\":\"town\",\"message\":\"no mention\"}","channel_type":"O","channel_id":"town","sender_name":"dave"},"broadcast":{"channel_id":"town","user_id":"user-4"}}
    ;
    try ch.handleGatewayMessage(payload);
    eb.close();
    try std.testing.expect(eb.consumeInbound() == null);
}

test "mattermost group_allow_from overrides allow_from in group allowlist mode" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{"user-a"},
        .group_allow_from = &.{"user-b"},
        .group_policy = "allowlist",
        .chatmode = "onmessage",
        .require_mention = false,
    });
    ch.setBus(&eb);

    const blocked_payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p5\",\"user_id\":\"user-a\",\"channel_id\":\"grp-1\",\"message\":\"blocked\"}","channel_type":"G","channel_id":"grp-1","sender_name":"alice"},"broadcast":{"channel_id":"grp-1","user_id":"user-a"}}
    ;
    try ch.handleGatewayMessage(blocked_payload);

    const allowed_payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p6\",\"user_id\":\"user-b\",\"channel_id\":\"grp-1\",\"message\":\"allowed\"}","channel_type":"G","channel_id":"grp-1","sender_name":"bob"},"broadcast":{"channel_id":"grp-1","user_id":"user-b"}}
    ;
    try ch.handleGatewayMessage(allowed_payload);

    eb.close();

    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("user-b", msg.sender_id);
    try std.testing.expectEqualStrings("allowed", msg.content);
    try std.testing.expectEqualStrings("mattermost:mm-main:group:grp-1", msg.session_key);
    try std.testing.expect(eb.consumeInbound() == null);
}

test "mattermost dm_policy disabled blocks direct messages" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .allow_from = &.{"user-1"},
        .dm_policy = "disabled",
        .group_policy = "open",
        .chatmode = "onmessage",
        .require_mention = false,
    });
    ch.setBus(&eb);

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p7\",\"user_id\":\"user-1\",\"channel_id\":\"dm-1\",\"message\":\"hello\"}","channel_type":"D","channel_id":"dm-1","sender_name":"alice"},"broadcast":{"channel_id":"dm-1","user_id":"user-1"}}
    ;
    try ch.handleGatewayMessage(payload);
    eb.close();
    try std.testing.expect(eb.consumeInbound() == null);
}

test "mattermost chatmode onchar strips configured prefix before publish" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    const prefixes = [_][]const u8{"?"};
    var ch = MattermostChannel.initFromConfig(alloc, .{
        .account_id = "mm-main",
        .bot_token = "tok",
        .base_url = "https://chat.example.com",
        .group_policy = "open",
        .chatmode = "onchar",
        .onchar_prefixes = &prefixes,
        .require_mention = false,
    });
    ch.setBus(&eb);

    const payload =
        \\{"event":"posted","data":{"post":"{\"id\":\"p8\",\"user_id\":\"user-8\",\"channel_id\":\"town\",\"message\":\"? status now\"}","channel_type":"O","channel_id":"town","sender_name":"eve"},"broadcast":{"channel_id":"town","user_id":"user-8"}}
    ;
    try ch.handleGatewayMessage(payload);

    eb.close();
    var msg = eb.consumeInbound() orelse return error.TestExpectedEqual;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("status now", msg.content);
    try std.testing.expectEqualStrings("mattermost:mm-main:channel:town", msg.session_key);
    try std.testing.expect(eb.consumeInbound() == null);
}
