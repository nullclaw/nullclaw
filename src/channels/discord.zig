const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const websocket = @import("../websocket.zig");

const log = std.log.scoped(.discord);

/// Discord channel — connects via WebSocket gateway, sends via REST API.
/// Splits messages at 2000 chars (Discord limit).
pub const DiscordChannel = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    guild_id: ?[]const u8,
    allow_bots: bool,
    account_id: []const u8 = "default",

    // Optional gateway fields (have defaults so existing init works)
    allow_from: []const []const u8 = &.{},
    require_mention: bool = false,
    intents: u32 = 37377, // GUILDS|GUILD_MESSAGES|MESSAGE_CONTENT|DIRECT_MESSAGES
    bus: ?*bus_mod.Bus = null,

    // Gateway state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    sequence: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    heartbeat_interval_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    heartbeat_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    session_id: ?[]u8 = null,
    resume_gateway_url: ?[]u8 = null,
    bot_user_id: ?[]u8 = null,
    gateway_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),

    const SocketFd = std.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std.os.windows.ws2_32.INVALID_SOCKET,
        else => -1,
    };

    pub const MAX_MESSAGE_LEN: usize = 2000;
    pub const GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json";

    pub fn init(
        allocator: std.mem.Allocator,
        token: []const u8,
        guild_id: ?[]const u8,
        allow_bots: bool,
    ) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = token,
            .guild_id = guild_id,
            .allow_bots = allow_bots,
        };
    }

    /// Initialize from a full DiscordConfig, passing all fields.
    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: @import("../config_types.zig").DiscordConfig) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = cfg.token,
            .guild_id = cfg.guild_id,
            .allow_bots = cfg.allow_bots,
            .account_id = cfg.account_id,
            .allow_from = cfg.allow_from,
            .require_mention = cfg.require_mention,
            .intents = cfg.intents,
        };
    }

    pub fn channelName(_: *DiscordChannel) []const u8 {
        return "discord";
    }

    /// Build a Discord REST API URL for sending to a channel.
    pub fn sendUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("https://discord.com/api/v10/channels/{s}/messages", .{channel_id});
        return fbs.getWritten();
    }

    /// Extract bot user ID from a bot token.
    /// Discord bot tokens are base64(bot_user_id).random.hmac
    pub fn extractBotUserId(token: []const u8) ?[]const u8 {
        // Find the first '.'
        const dot_pos = std.mem.indexOf(u8, token, ".") orelse return null;
        return token[0..dot_pos];
    }

    pub fn healthCheck(_: *DiscordChannel) bool {
        return true;
    }

    pub fn setBus(self: *DiscordChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    // ── Pure helper functions ─────────────────────────────────────────────

    /// Build IDENTIFY JSON payload (op=2).
    /// Example: {"op":2,"d":{"token":"Bot TOKEN","intents":37377,"properties":{"os":"linux","browser":"nullclaw","device":"nullclaw"}}}
    pub fn buildIdentifyJson(buf: []u8, token: []const u8, intents: u32) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print(
            "{{\"op\":2,\"d\":{{\"token\":\"Bot {s}\",\"intents\":{d},\"properties\":{{\"os\":\"linux\",\"browser\":\"nullclaw\",\"device\":\"nullclaw\"}}}}}}",
            .{ token, intents },
        );
        return fbs.getWritten();
    }

    /// Build HEARTBEAT JSON payload (op=1).
    /// seq==0 → {"op":1,"d":null}, else {"op":1,"d":42}
    pub fn buildHeartbeatJson(buf: []u8, seq: i64) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        if (seq == 0) {
            try w.writeAll("{\"op\":1,\"d\":null}");
        } else {
            try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
        }
        return fbs.getWritten();
    }

    /// Build RESUME JSON payload (op=6).
    /// {"op":6,"d":{"token":"Bot TOKEN","session_id":"SESSION","seq":42}}
    pub fn buildResumeJson(buf: []u8, token: []const u8, session_id: []const u8, seq: i64) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print(
            "{{\"op\":6,\"d\":{{\"token\":\"Bot {s}\",\"session_id\":\"{s}\",\"seq\":{d}}}}}",
            .{ token, session_id, seq },
        );
        return fbs.getWritten();
    }

    /// Parse gateway host from wss:// URL.
    /// "wss://us-east1.gateway.discord.gg" -> "us-east1.gateway.discord.gg"
    /// "wss://gateway.discord.gg/?v=10&encoding=json" -> "gateway.discord.gg"
    /// Returns slice into wss_url (no allocation).
    pub fn parseGatewayHost(wss_url: []const u8) []const u8 {
        // Strip scheme prefix if present
        const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
            wss_url[6..]
        else if (std.mem.startsWith(u8, wss_url, "ws://"))
            wss_url[5..]
        else
            wss_url;

        // Strip path (everything after first '/' or '?')
        const slash_pos = std.mem.indexOf(u8, no_scheme, "/");
        const query_pos = std.mem.indexOf(u8, no_scheme, "?");

        const end = blk: {
            if (slash_pos != null and query_pos != null) {
                break :blk @min(slash_pos.?, query_pos.?);
            } else if (slash_pos != null) {
                break :blk slash_pos.?;
            } else if (query_pos != null) {
                break :blk query_pos.?;
            } else {
                break :blk no_scheme.len;
            }
        };

        return no_scheme[0..end];
    }

    /// Check if bot is mentioned in message content.
    /// Returns true if "<@BOT_ID>" or "<@!BOT_ID>" appears in content.
    pub fn isMentioned(content: []const u8, bot_user_id: []const u8) bool {
        // Check for <@BOT_ID>
        var buf1: [64]u8 = undefined;
        const mention1 = std.fmt.bufPrint(&buf1, "<@{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention1) != null) return true;

        // Check for <@!BOT_ID>
        var buf2: [64]u8 = undefined;
        const mention2 = std.fmt.bufPrint(&buf2, "<@!{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention2) != null) return true;

        return false;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Discord channel via REST API.
    /// Splits at MAX_MESSAGE_LEN (2000 chars).
    pub fn sendMessage(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(channel_id, chunk);
        }
    }

    fn sendChunk(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        // Build JSON body: {"content":"..."}
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try body_list.appendSlice(self.allocator, "}");

        // Build auth header value: "Authorization: Bot <token>"
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_fbs.getWritten();

        const resp = root.http_util.curlPost(self.allocator, url, body_list.items, &.{auth_header}) catch |err| {
            log.err("Discord API POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        self.allocator.free(resp);
    }

    // ── Gateway ──────────────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.heartbeat_stop.store(true, .release);
        // Close socket to unblock blocking read
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
        // Free session state
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        if (self.bot_user_id) |u| {
            self.allocator.free(u);
            self.bot_user_id = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *DiscordChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Gateway loop ─────────────────────────────────────────────────

    fn gatewayLoop(self: *DiscordChannel) void {
        while (self.running.load(.acquire)) {
            self.runGatewayOnce() catch |err| {
                log.warn("Discord gateway error: {}", .{err});
            };
            if (!self.running.load(.acquire)) break;
            // 5 second backoff between reconnects (interruptible)
            var slept: u64 = 0;
            while (slept < 5000 and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                slept += 100;
            }
        }
    }

    fn runGatewayOnce(self: *DiscordChannel) !void {
        // Determine host
        const default_host = "gateway.discord.gg";
        const host: []const u8 = if (self.resume_gateway_url) |u| parseGatewayHost(u) else default_host;

        var ws = try websocket.WsClient.connect(
            self.allocator,
            host,
            443,
            "/?v=10&encoding=json",
            &.{},
        );

        // Store fd for interrupt-on-stop
        self.ws_fd.store(ws.stream.handle, .release);

        // Start heartbeat thread — on failure, clean up ws manually (no errdefer to avoid
        // double-deinit with the defer block below once spawn succeeds).
        self.heartbeat_stop.store(false, .release);
        self.heartbeat_interval_ms.store(0, .release);
        const hbt = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, heartbeatLoop, .{ self, &ws }) catch |err| {
            ws.deinit();
            return err;
        };
        defer {
            self.heartbeat_stop.store(true, .release);
            hbt.join();
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        // Wait for HELLO (first message)
        const hello_text = try ws.readTextMessage() orelse return error.ConnectionClosed;
        defer self.allocator.free(hello_text);
        try self.handleHello(&ws, hello_text);

        // IDENTIFY or RESUME
        if (self.session_id != null) {
            try self.sendResumePayload(&ws);
        } else {
            try self.sendIdentifyPayload(&ws);
        }

        // Main read loop
        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch break;
            const text = maybe_text orelse break;
            defer self.allocator.free(text);
            self.handleGatewayMessage(&ws, text) catch |err| {
                log.err("Discord gateway msg error: {}", .{err});
                if (err == error.ShouldReconnect) break;
            };
        }
    }

    // ── Heartbeat thread ─────────────────────────────────────────────

    fn heartbeatLoop(self: *DiscordChannel, ws: *websocket.WsClient) void {
        // Wait for interval to be set
        while (!self.heartbeat_stop.load(.acquire) and self.heartbeat_interval_ms.load(.acquire) == 0) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
        while (!self.heartbeat_stop.load(.acquire)) {
            const interval_ms = self.heartbeat_interval_ms.load(.acquire);
            var elapsed: u64 = 0;
            while (elapsed < interval_ms) {
                if (self.heartbeat_stop.load(.acquire)) return;
                std.Thread.sleep(100 * std.time.ns_per_ms);
                elapsed += 100;
            }
            if (self.heartbeat_stop.load(.acquire)) return;

            const seq = self.sequence.load(.acquire);
            var hb_buf: [64]u8 = undefined;
            const hb_json = buildHeartbeatJson(&hb_buf, seq) catch continue;
            ws.writeText(hb_json) catch |err| {
                log.warn("Discord heartbeat failed: {}", .{err});
            };
        }
    }

    // ── Message handlers ─────────────────────────────────────────────

    /// Parse HELLO payload and store heartbeat interval.
    fn handleHello(self: *DiscordChannel, _: *websocket.WsClient, text: []const u8) !void {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, text, .{});
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        switch (d_val) {
            .object => |d_obj| {
                const hb_val = d_obj.get("heartbeat_interval") orelse return;
                switch (hb_val) {
                    .integer => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intCast(ms), .release);
                        }
                    },
                    .float => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intFromFloat(ms), .release);
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    /// Handle a gateway message, switching on op code.
    fn handleGatewayMessage(self: *DiscordChannel, ws: *websocket.WsClient, text: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, text, .{}) catch |err| {
            log.warn("Discord: failed to parse gateway message: {}", .{err});
            return;
        };
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) {
            log.warn("Discord: gateway message root is not an object", .{});
            return;
        }

        // Get op code
        const op_val = root_val.object.get("op") orelse {
            log.warn("Discord: gateway message missing 'op' field", .{});
            return;
        };
        const op: i64 = switch (op_val) {
            .integer => |i| i,
            else => {
                log.warn("Discord: gateway 'op' is not an integer", .{});
                return;
            },
        };

        switch (op) {
            10 => { // HELLO
                self.handleHello(ws, text) catch |err| {
                    log.warn("Discord: handleHello error: {}", .{err});
                };
            },
            0 => { // DISPATCH
                // Update sequence from "s" field
                if (root_val.object.get("s")) |s_val| {
                    switch (s_val) {
                        .integer => |s| {
                            if (s > self.sequence.load(.acquire)) {
                                self.sequence.store(s, .release);
                            }
                        },
                        else => {},
                    }
                }

                // Get event type "t"
                const t_val = root_val.object.get("t") orelse return;
                const event_type: []const u8 = switch (t_val) {
                    .string => |s| s,
                    else => return,
                };

                if (std.mem.eql(u8, event_type, "READY")) {
                    self.handleReady(root_val) catch |err| {
                        log.warn("Discord: handleReady error: {}", .{err});
                    };
                } else if (std.mem.eql(u8, event_type, "MESSAGE_CREATE")) {
                    self.handleMessageCreate(root_val) catch |err| {
                        log.warn("Discord: handleMessageCreate error: {}", .{err});
                    };
                }
            },
            1 => { // HEARTBEAT — server requests immediate heartbeat
                const seq = self.sequence.load(.acquire);
                var hb_buf: [64]u8 = undefined;
                const hb_json = buildHeartbeatJson(&hb_buf, seq) catch return;
                ws.writeText(hb_json) catch |err| {
                    log.warn("Discord: immediate heartbeat failed: {}", .{err});
                };
            },
            11 => { // HEARTBEAT_ACK
                // No-op — heartbeat acknowledged
            },
            7 => { // RECONNECT
                log.info("Discord: server requested reconnect", .{});
                return error.ShouldReconnect;
            },
            9 => { // INVALID_SESSION
                // Check if resumable (d field)
                const d_val = root_val.object.get("d");
                const resumable = if (d_val) |d| switch (d) {
                    .bool => |b| b,
                    else => false,
                } else false;

                if (!resumable) {
                    // Free session state — must re-identify
                    if (self.session_id) |s| {
                        self.allocator.free(s);
                        self.session_id = null;
                    }
                    if (self.resume_gateway_url) |u| {
                        self.allocator.free(u);
                        self.resume_gateway_url = null;
                    }
                }

                // Send IDENTIFY
                self.sendIdentifyPayload(ws) catch |err| {
                    log.warn("Discord: re-identify failed: {}", .{err});
                    return error.ShouldReconnect;
                };
            },
            else => {
                log.warn("Discord: unhandled gateway op={d}", .{op});
            },
        }
    }

    /// Handle READY event: extract session_id, resume_gateway_url, bot_user_id.
    fn handleReady(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord READY: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord READY: 'd' is not an object", .{});
                return;
            },
        };

        // Extract session_id
        if (d_obj.get("session_id")) |sid_val| {
            switch (sid_val) {
                .string => |s| {
                    if (self.session_id) |old| self.allocator.free(old);
                    self.session_id = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract resume_gateway_url
        if (d_obj.get("resume_gateway_url")) |rgu_val| {
            switch (rgu_val) {
                .string => |s| {
                    if (self.resume_gateway_url) |old| self.allocator.free(old);
                    self.resume_gateway_url = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract bot user ID from d.user.id
        if (d_obj.get("user")) |user_val| {
            switch (user_val) {
                .object => |user_obj| {
                    if (user_obj.get("id")) |id_val| {
                        switch (id_val) {
                            .string => |s| {
                                if (self.bot_user_id) |old| self.allocator.free(old);
                                self.bot_user_id = try self.allocator.dupe(u8, s);
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }

        log.info("Discord READY: session_id={s}", .{self.session_id orelse "<none>"});
    }

    /// Handle MESSAGE_CREATE event and publish to bus if filters pass.
    fn handleMessageCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord MESSAGE_CREATE: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'd' is not an object", .{});
                return;
            },
        };

        // Extract channel_id
        const channel_id: []const u8 = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'channel_id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'channel_id'", .{});
            return;
        };

        // Extract content
        const content: []const u8 = if (d_obj.get("content")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        // Extract guild_id (optional — absent for DMs)
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author object
        const author_obj = if (d_obj.get("author")) |v| switch (v) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author' is not an object", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author'", .{});
            return;
        };

        // Extract author.id
        const author_id: []const u8 = if (author_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author.id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author.id'", .{});
            return;
        };

        // Extract author.bot (defaults to false if absent)
        const author_is_bot: bool = if (author_obj.get("bot")) |v| switch (v) {
            .bool => |b| b,
            else => false,
        } else false;

        // Filter 1: bot author
        if (author_is_bot and !self.allow_bots) {
            return;
        }

        // Filter 2: require_mention for guild (non-DM) messages
        if (self.require_mention and guild_id != null) {
            const bot_uid = self.bot_user_id orelse "";
            if (!isMentioned(content, bot_uid)) {
                return;
            }
        }

        // Filter 3: allow_from allowlist
        if (self.allow_from.len > 0) {
            if (!root.isAllowed(self.allow_from, author_id)) {
                return;
            }
        }

        // Process attachments (if any)
        var content_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer content_buf.deinit(self.allocator);

        if (content.len > 0) {
            content_buf.appendSlice(self.allocator, content) catch {};
        }

        if (d_obj.get("attachments")) |att_val| {
            if (att_val == .array) {
                var rand = std.crypto.random;
                for (att_val.array.items) |att_item| {
                    if (att_item == .object) {
                        if (att_item.object.get("url")) |url_val| {
                            if (url_val == .string) {
                                const attach_url = url_val.string;

                                // Download it
                                if (root.http_util.curlGet(self.allocator, attach_url, &.{}, "30")) |img_data| {
                                    defer self.allocator.free(img_data);

                                    // Make temp file
                                    const rand_id = rand.int(u64);
                                    var path_buf: [1024]u8 = undefined;
                                    const local_path = std.fmt.bufPrint(&path_buf, "/tmp/discord_{x}.dat", .{rand_id}) catch continue;

                                    if (std.fs.createFileAbsolute(local_path, .{ .read = false })) |file| {
                                        file.writeAll(img_data) catch {
                                            file.close();
                                            continue;
                                        };
                                        file.close();

                                        if (content_buf.items.len > 0) content_buf.appendSlice(self.allocator, "\n") catch {};
                                        content_buf.appendSlice(self.allocator, "[IMAGE:") catch {};
                                        content_buf.appendSlice(self.allocator, local_path) catch {};
                                        content_buf.appendSlice(self.allocator, "]") catch {};
                                    } else |_| {}
                                } else |err| {
                                    log.warn("Discord: failed to download attachment: {}", .{err});
                                }
                            }
                        }
                    }
                }
            }
        }

        const final_content = content_buf.toOwnedSlice(self.allocator) catch blk: {
            break :blk try self.allocator.dupe(u8, content);
        };
        defer self.allocator.free(final_content);

        // Build account-aware session key fallback to prevent cross-account bleed
        // when route resolution is unavailable.
        const session_key = if (guild_id == null)
            try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, author_id })
        else
            try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
        defer self.allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(self.allocator);
        const mw = metadata_buf.writer(self.allocator);
        try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
        try mw.writeAll(",\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        if (guild_id) |gid| {
            try mw.writeAll(",\"guild_id\":");
            try root.appendJsonStringW(mw, gid);
        }
        try mw.writeByte('}');

        const msg = try bus_mod.makeInboundFull(
            self.allocator,
            "discord",
            author_id,
            channel_id,
            final_content,
            session_key,
            &.{},
            metadata_buf.items,
        );

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("Discord: failed to publish inbound message: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            // No bus configured — free the message
            msg.deinit(self.allocator);
        }
    }

    /// Send IDENTIFY payload.
    fn sendIdentifyPayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        var buf: [1024]u8 = undefined;
        const json = try buildIdentifyJson(&buf, self.token, self.intents);
        try ws.writeText(json);
    }

    /// Send RESUME payload.
    fn sendResumePayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        const sid = self.session_id orelse return error.NoSessionId;
        const seq = self.sequence.load(.acquire);
        var buf: [512]u8 = undefined;
        const json = try buildResumeJson(&buf, self.token, sid, seq);
        try ws.writeText(json);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord send url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/messages", url);
}

test "discord extract bot user id" {
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.Ghijk.abcdef");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id no dot" {
    try std.testing.expect(DiscordChannel.extractBotUserId("notokenformat") == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Discord Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "discord send url with different channel ids" {
    var buf: [256]u8 = undefined;
    const url1 = try DiscordChannel.sendUrl(&buf, "999");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/999/messages", url1);

    var buf2: [256]u8 = undefined;
    const url2 = try DiscordChannel.sendUrl(&buf2, "1234567890");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/1234567890/messages", url2);
}

test "discord extract bot user id multiple dots" {
    // Token format: base64(user_id).timestamp.hmac
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.fake.hmac");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id empty token" {
    // Empty string before dot means empty result
    const id = DiscordChannel.extractBotUserId("");
    try std.testing.expect(id == null);
}

test "discord extract bot user id single dot" {
    const id = DiscordChannel.extractBotUserId("abc.");
    try std.testing.expectEqualStrings("abc", id.?);
}

test "discord max message len constant" {
    try std.testing.expectEqual(@as(usize, 2000), DiscordChannel.MAX_MESSAGE_LEN);
}

test "discord gateway url constant" {
    try std.testing.expectEqualStrings("wss://gateway.discord.gg/?v=10&encoding=json", DiscordChannel.GATEWAY_URL);
}

test "discord init stores fields" {
    const ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", "guild-123", true);
    try std.testing.expectEqualStrings("my-bot-token", ch.token);
    try std.testing.expectEqualStrings("guild-123", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
}

test "discord init no guild id" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expect(ch.guild_id == null);
    try std.testing.expect(!ch.allow_bots);
}

test "discord send url buffer too small returns error" {
    var buf: [10]u8 = undefined;
    const result = DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expect(if (result) |_| false else |_| true);
}

// ════════════════════════════════════════════════════════════════════════════
// New Gateway Helper Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord buildIdentifyJson" {
    var buf: [512]u8 = undefined;
    const json = try DiscordChannel.buildIdentifyJson(&buf, "mytoken", 37377);
    // Should contain op:2 and the token and intents
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "mytoken") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "37377") != null);
}

test "discord buildHeartbeatJson no sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 0);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":null}", json);
}

test "discord buildHeartbeatJson with sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 42);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":42}", json);
}

test "discord buildResumeJson" {
    var buf: [256]u8 = undefined;
    const json = try DiscordChannel.buildResumeJson(&buf, "mytoken", "session123", 99);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":6") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "session123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "99") != null);
}

test "discord parseGatewayHost from wss url" {
    const host = DiscordChannel.parseGatewayHost("wss://us-east1.gateway.discord.gg");
    try std.testing.expectEqualStrings("us-east1.gateway.discord.gg", host);
}

test "discord parseGatewayHost with path" {
    const host = DiscordChannel.parseGatewayHost("wss://gateway.discord.gg/?v=10&encoding=json");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord parseGatewayHost no scheme returns original" {
    const host = DiscordChannel.parseGatewayHost("gateway.discord.gg");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord isMentioned with user id" {
    try std.testing.expect(DiscordChannel.isMentioned("<@123456> hello", "123456"));
    try std.testing.expect(DiscordChannel.isMentioned("hello <@!123456>", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("hello world", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("<@999999> hello", "123456"));
}

test "discord intents default" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expectEqual(@as(u32, 37377), ch.intents);
}

test "discord initFromConfig passes all fields" {
    const config_types = @import("../config_types.zig");
    const cfg = config_types.DiscordConfig{
        .account_id = "discord-main",
        .token = "my-token",
        .guild_id = "guild-1",
        .allow_bots = true,
        .allow_from = &.{ "user1", "user2" },
        .require_mention = true,
        .intents = 512,
    };
    const ch = DiscordChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("my-token", ch.token);
    try std.testing.expectEqualStrings("guild-1", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
    try std.testing.expectEqualStrings("discord-main", ch.account_id);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
    try std.testing.expect(ch.require_mention);
    try std.testing.expectEqual(@as(u32, 512), ch.intents);
}

test "discord handleMessageCreate publishes inbound guild message with metadata" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-1", msg.sender_id);
    try std.testing.expectEqualStrings("c-1", msg.chat_id);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("account_id") != null);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("guild_id") != null);
    try std.testing.expectEqualStrings("dc-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(!meta.value.object.get("is_dm").?.bool);
    try std.testing.expectEqualStrings("g-1", meta.value.object.get("guild_id").?.string);
}

test "discord handleMessageCreate sets is_dm metadata for direct messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"dm-7","content":"hi dm","author":{"id":"u-7","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord:dc-main:direct:u-7", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("is_dm").?.bool);
    try std.testing.expect(meta.value.object.get("guild_id") == null);
}

test "discord handleMessageCreate require_mention blocks unmentioned guild messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","content":"plain text","author":{"id":"u-2","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord intent bitmask guilds" {
    // GUILDS = 1
    try std.testing.expectEqual(@as(u32, 1), 1);
    // GUILD_MESSAGES = 512
    try std.testing.expectEqual(@as(u32, 512), 512);
    // MESSAGE_CONTENT = 32768
    try std.testing.expectEqual(@as(u32, 32768), 32768);
    // DIRECT_MESSAGES = 4096
    try std.testing.expectEqual(@as(u32, 4096), 4096);
    // Default intents = 1|512|32768|4096 = 37377
    try std.testing.expectEqual(@as(u32, 37377), 1 | 512 | 32768 | 4096);
}
