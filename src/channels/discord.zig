const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const interaction_choices = @import("../interactions/choices.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");

const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.discord);

const PENDING_INTERACTION_TTL_MS: u64 = 60 * std.time.ms_per_min;

const PendingInteractionOption = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    fn deinit(self: *const PendingInteractionOption, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

const PendingInteraction = struct {
    expires_at_ms: u64,
    chat_id: []const u8,
    options: []PendingInteractionOption,

    fn deinit(self: *const PendingInteraction, allocator: std.mem.Allocator) void {
        allocator.free(self.chat_id);
        for (self.options) |opt| opt.deinit(allocator);
        allocator.free(self.options);
    }
};

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

    typing_mu: std_compat.sync.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,
    interaction_mu: std_compat.sync.Mutex = .{},
    pending_interactions: std.StringHashMapUnmanaged(PendingInteraction) = .empty,
    interaction_seq: Atomic(u64) = Atomic(u64).init(1),

    // Gateway state
    running: Atomic(bool) = Atomic(bool).init(false),
    sequence: Atomic(i64) = Atomic(i64).init(0),
    heartbeat_interval_ms: Atomic(u64) = Atomic(u64).init(0),
    heartbeat_stop: Atomic(bool) = Atomic(bool).init(false),
    session_id: ?[]u8 = null,
    resume_gateway_url: ?[]u8 = null,
    bot_user_id: ?[]u8 = null,
    gateway_thread: ?std.Thread = null,
    ws_fd: Atomic(SocketFd) = Atomic(SocketFd).init(invalid_socket),

    const SocketFd = std_compat.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std_compat.net.invalidHandle(SocketFd),
        else => -1,
    };

    pub const MAX_MESSAGE_LEN: usize = 2000;
    pub const GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json";
    const TYPING_INTERVAL_NS: u64 = 8 * std.time.ns_per_s;
    const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;
    const InvalidSessionAction = enum {
        identify,
        resume_session,
    };

    const TypingTask = struct {
        channel: *DiscordChannel,
        channel_id: []const u8,
        stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
    };

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
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages", .{channel_id});
        return w.buffered();
    }

    /// Build a Discord REST API URL for triggering typing in a channel.
    pub fn typingUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/typing", .{channel_id});
        return w.buffered();
    }

    pub fn editMessageUrl(buf: []u8, channel_id: []const u8, message_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages/{s}", .{ channel_id, message_id });
        return w.buffered();
    }

    fn interactionCallbackUrl(buf: []u8, interaction_id: []const u8, interaction_token: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/interactions/{s}/{s}/callback", .{ interaction_id, interaction_token });
        return w.buffered();
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
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":2,\"d\":{{\"token\":\"Bot {s}\",\"intents\":{d},\"properties\":{{\"os\":\"linux\",\"browser\":\"nullclaw\",\"device\":\"nullclaw\"}}}}}}",
            .{ token, intents },
        );
        return w.buffered();
    }

    /// Build HEARTBEAT JSON payload (op=1).
    /// seq==0 → {"op":1,"d":null}, else {"op":1,"d":42}
    pub fn buildHeartbeatJson(buf: []u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        if (seq == 0) {
            try w.writeAll("{\"op\":1,\"d\":null}");
        } else {
            try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
        }
        return w.buffered();
    }

    /// Build RESUME JSON payload (op=6).
    /// {"op":6,"d":{"token":"Bot TOKEN","session_id":"SESSION","seq":42}}
    pub fn buildResumeJson(buf: []u8, token: []const u8, session_id: []const u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":6,\"d\":{{\"token\":\"Bot {s}\",\"session_id\":\"{s}\",\"seq\":{d}}}}}",
            .{ token, session_id, seq },
        );
        return w.buffered();
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

    fn isReplyToBot(d_obj: std.json.ObjectMap, bot_user_id: []const u8) bool {
        if (bot_user_id.len == 0) return false;
        const message_type = d_obj.get("type") orelse return false;
        switch (message_type) {
            .integer => |value| if (value != 19) return false,
            else => return false,
        }
        const referenced_message = d_obj.get("referenced_message") orelse return false;
        const referenced_obj = switch (referenced_message) {
            .object => |o| o,
            else => return false,
        };
        const author_val = referenced_obj.get("author") orelse return false;
        const author_obj = switch (author_val) {
            .object => |o| o,
            else => return false,
        };
        const author_id_val = author_obj.get("id") orelse return false;
        const author_id = switch (author_id_val) {
            .string => |s| s,
            else => return false,
        };
        return std.mem.eql(u8, author_id, bot_user_id);
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

    /// Send a Discord typing indicator (best-effort, errors ignored).
    pub fn sendTypingIndicator(self: *DiscordChannel, channel_id: []const u8) void {
        if (builtin.is_test) return;
        if (channel_id.len == 0) return;

        var url_buf: [256]u8 = undefined;
        const url = typingUrl(&url_buf, channel_id) catch return;

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        auth_writer.print("Authorization: Bot {s}", .{self.token}) catch return;
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.curlPost(self.allocator, url, "{}", &.{auth_header}) catch return;
        self.allocator.free(resp);
    }

    pub fn startTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        if (!self.running.load(.acquire)) return;
        if (channel_id.len == 0) return;

        try self.stopTyping(channel_id);

        const key_copy = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .channel_id = key_copy,
        };

        task.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        var removed_key: ?[]u8 = null;
        var removed_task: ?*TypingTask = null;

        self.typing_mu.lock();
        if (self.typing_handles.fetchRemove(channel_id)) |entry| {
            removed_key = @constCast(entry.key);
            removed_task = entry.value;
        }
        self.typing_mu.unlock();

        if (removed_task) |task| {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
        }
        if (removed_key) |key| {
            self.allocator.free(key);
        }
    }

    fn stopAllTyping(self: *DiscordChannel) void {
        self.typing_mu.lock();
        var handles = self.typing_handles;
        self.typing_handles = .empty;
        self.typing_mu.unlock();

        var it = handles.iterator();
        while (it.next()) |entry| {
            const task = entry.value_ptr.*;
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        handles.deinit(self.allocator);
    }

    fn typingLoop(task: *TypingTask) void {
        while (!task.stop_requested.load(.acquire)) {
            task.channel.sendTypingIndicator(task.channel_id);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std_compat.thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
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
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.curlPost(self.allocator, url, body_list.items, &.{auth_header}) catch |err| {
            log.err("Discord API POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        self.allocator.free(resp);
    }

    fn sendJsonMethod(self: *DiscordChannel, method: []const u8, url: []const u8, body: []const u8) !void {
        var argv_buf: [16][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-s";
        argc += 1;
        argv_buf[argc] = "-X";
        argc += 1;
        argv_buf[argc] = method;
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = "Content-Type: application/json";
        argc += 1;

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = auth_writer.buffered();
        argc += 1;
        argv_buf[argc] = "--data-binary";
        argc += 1;
        argv_buf[argc] = "@-";
        argc += 1;
        argv_buf[argc] = url;
        argc += 1;

        var child = std_compat.process.Child.init(argv_buf[0..argc], self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        try child.spawn();

        if (child.stdin) |stdin_file| {
            stdin_file.writeAll(body) catch {
                stdin_file.close();
                child.stdin = null;
                _ = child.kill() catch {};
                _ = child.wait() catch {};
                return error.CurlWriteError;
            };
            stdin_file.close();
            child.stdin = null;
        } else {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return error.CurlWriteError;
        }

        const stdout = child.stdout.?.readToEndAlloc(self.allocator, 64 * 1024) catch {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return error.CurlReadError;
        };
        defer self.allocator.free(stdout);

        const term = child.wait() catch return error.CurlWaitError;
        switch (term) {
            .exited => |code| if (code != 0) return error.DiscordApiError,
            else => return error.DiscordApiError,
        }
    }

    fn nextInteractionToken(self: *DiscordChannel) ![]u8 {
        const seq = self.interaction_seq.fetchAdd(1, .monotonic) + 1;
        var buf: [32]u8 = undefined;
        const token = try std.fmt.bufPrint(&buf, "{x}", .{seq});
        return self.allocator.dupe(u8, token);
    }

    fn buildChoicesDirectiveFromPayload(
        self: *DiscordChannel,
        choices: []const root.Channel.OutboundChoice,
    ) !interaction_choices.ChoicesDirective {
        if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) {
            return error.InvalidChoices;
        }

        var options = try self.allocator.alloc(interaction_choices.ChoiceOption, choices.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (choices, 0..) |choice, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, choice.id),
                .label = try self.allocator.dupe(u8, choice.label),
                .submit_text = try self.allocator.dupe(u8, choice.submit_text),
            };
            built += 1;
        }

        return .{
            .version = 1,
            .options = options,
        };
    }

    fn buildComponentsJson(
        self: *DiscordChannel,
        directive: interaction_choices.ChoicesDirective,
        token: []const u8,
    ) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "[");
        var row_start: usize = 0;
        while (row_start < directive.options.len) {
            if (row_start > 0) try out.appendSlice(self.allocator, ",");
            try out.appendSlice(self.allocator, "{\"type\":1,\"components\":[");

            const row_end = @min(row_start + 5, directive.options.len);
            for (directive.options[row_start..row_end], row_start..) |opt, idx| {
                if (idx > row_start) try out.appendSlice(self.allocator, ",");
                var cb_buf: [100]u8 = undefined;
                const custom_id = try interaction_choices.formatChoiceCallbackData(&cb_buf, token, opt.id, 100);
                try out.appendSlice(self.allocator, "{\"type\":2,\"style\":1,\"label\":");
                try root.json_util.appendJsonString(&out, self.allocator, opt.label);
                try out.appendSlice(self.allocator, ",\"custom_id\":");
                try root.json_util.appendJsonString(&out, self.allocator, custom_id);
                try out.appendSlice(self.allocator, "}");
            }
            try out.appendSlice(self.allocator, "]}");
            row_start = row_end;
        }
        try out.appendSlice(self.allocator, "]");
        return try out.toOwnedSlice(self.allocator);
    }

    fn registerPendingInteraction(
        self: *DiscordChannel,
        token: []const u8,
        chat_id: []const u8,
        directive: interaction_choices.ChoicesDirective,
    ) !void {
        var options = try self.allocator.alloc(PendingInteractionOption, directive.options.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (directive.options, 0..) |opt, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, opt.id),
                .label = try self.allocator.dupe(u8, opt.label),
                .submit_text = try self.allocator.dupe(u8, opt.submit_text),
            };
            built += 1;
        }

        const key = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(key);
        const chat_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(chat_copy);

        const now_ms = std_compat.time.milliTimestamp();
        if (now_ms < 0) return error.InvalidTimestamp;
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();
        try self.pending_interactions.put(self.allocator, key, .{
            .expires_at_ms = @as(u64, @intCast(now_ms)) + PENDING_INTERACTION_TTL_MS,
            .chat_id = chat_copy,
            .options = options,
        });
    }

    fn pruneExpiredInteractions(self: *DiscordChannel) void {
        const now_ms: i64 = std_compat.time.milliTimestamp();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        var it = self.pending_interactions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= @as(u64, @intCast(now_ms))) {
                const key = entry.key_ptr.*;
                if (self.pending_interactions.fetchRemove(key)) |kv| {
                    self.allocator.free(@constCast(kv.key));
                    kv.value.deinit(self.allocator);
                }
            }
        }
    }

    const CallbackSelection = union(enum) {
        ok: []u8,
        not_found,
        expired,
        invalid_chat,
        invalid_option,
    };

    fn consumeCallbackSelection(
        self: *DiscordChannel,
        allocator: std.mem.Allocator,
        token: []const u8,
        option_id: []const u8,
        chat_id: []const u8,
    ) !CallbackSelection {
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        const pending_ptr = self.pending_interactions.getPtr(token) orelse return .not_found;
        if (pending_ptr.expires_at_ms <= @as(u64, @intCast(std_compat.time.milliTimestamp()))) {
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .expired;
        }
        if (!std.mem.eql(u8, pending_ptr.chat_id, chat_id)) return .invalid_chat;

        for (pending_ptr.options) |opt| {
            if (!std.mem.eql(u8, opt.id, option_id)) continue;
            const submit_text = try allocator.dupe(u8, opt.submit_text);
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .{ .ok = submit_text };
        }
        return .invalid_option;
    }

    fn deinitPendingInteractions(self: *DiscordChannel) void {
        self.interaction_mu.lock();
        var pending = self.pending_interactions;
        self.pending_interactions = .empty;
        self.interaction_mu.unlock();

        var it = pending.iterator();
        while (it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            entry.value_ptr.deinit(self.allocator);
        }
        pending.deinit(self.allocator);
    }

    fn sendRichMessage(self: *DiscordChannel, channel_id: []const u8, payload: root.Channel.OutboundPayload) !void {
        if (payload.attachments.len > 0) return error.NotSupported;
        if (payload.choices.len == 0) return self.sendMessage(channel_id, payload.text);

        var directive = try self.buildChoicesDirectiveFromPayload(payload.choices);
        defer directive.deinit(self.allocator);

        const token = try self.nextInteractionToken();
        defer self.allocator.free(token);
        const components_json = try self.buildComponentsJson(directive, token);
        defer self.allocator.free(components_json);

        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, payload.text);
        try body.appendSlice(self.allocator, ",\"components\":");
        try body.appendSlice(self.allocator, components_json);
        try body.appendSlice(self.allocator, "}");

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.curlPost(self.allocator, url, body.items, &.{auth_header}) catch |err| {
            log.err("Discord API rich POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        defer self.allocator.free(resp);

        try self.registerPendingInteraction(token, channel_id, directive);
    }

    fn editRichMessage(self: *DiscordChannel, edit: root.Channel.MessageEdit) !void {
        if (edit.payload.attachments.len > 0) return error.NotSupported;

        var components_json: ?[]u8 = null;
        defer if (components_json) |json| self.allocator.free(json);

        if (edit.payload.choices.len > 0) {
            var directive = try self.buildChoicesDirectiveFromPayload(edit.payload.choices);
            defer directive.deinit(self.allocator);

            const token = try self.nextInteractionToken();
            defer self.allocator.free(token);
            components_json = try self.buildComponentsJson(directive, token);
            try self.registerPendingInteraction(token, edit.target, directive);
        }

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, edit.payload.text);
        if (components_json) |json| {
            try body.appendSlice(self.allocator, ",\"components\":");
            try body.appendSlice(self.allocator, json);
        } else {
            try body.appendSlice(self.allocator, ",\"components\":[]");
        }
        try body.appendSlice(self.allocator, "}");

        var url_buf: [256]u8 = undefined;
        const url = try editMessageUrl(&url_buf, edit.target, edit.message_id);
        try self.sendJsonMethod("PATCH", url, body.items);
    }

    fn answerInteraction(self: *DiscordChannel, interaction_id: []const u8, interaction_token: []const u8, message: ?[]const u8) void {
        if (builtin.is_test) return;

        var url_buf: [512]u8 = undefined;
        const url = interactionCallbackUrl(&url_buf, interaction_id, interaction_token) catch return;

        const body = if (message) |msg|
            std.fmt.allocPrint(self.allocator, "{{\"type\":4,\"data\":{{\"content\":{f},\"flags\":64}}}}", .{std.json.fmt(msg, .{})})
        else
            self.allocator.dupe(u8, "{\"type\":6}");
        const owned_body = body catch return;
        defer self.allocator.free(owned_body);

        const resp = root.http_util.curlPost(self.allocator, url, owned_body, &.{}) catch return;
        self.allocator.free(resp);
    }

    // ── Gateway ──────────────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.heartbeat_stop.store(true, .release);
        self.stopAllTyping();
        self.deinitPendingInteractions();
        // Close socket to unblock blocking read
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            (std_compat.net.Stream{ .handle = fd }).close();
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

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichMessage(target, payload);
    }

    fn vtableEditMessage(ptr: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.editRichMessage(edit);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendRich = &vtableSendRich,
        .editMessage = &vtableEditMessage,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
    };

    pub fn channel(self: *DiscordChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Gateway loop ─────────────────────────────────────────────────

    fn gatewayLoop(self: *DiscordChannel) void {
        while (self.running.load(.acquire)) {
            var backoff_ms: u64 = 5000;
            self.runGatewayOnce() catch |err| switch (err) {
                error.ShouldReconnect => {
                    // OP7 RECONNECT is a normal control signal from Discord.
                    // Reconnect quickly to minimize missed events.
                    log.info("Discord gateway reconnect requested by server", .{});
                    backoff_ms = 250;
                },
                else => {
                    log.warn("Discord gateway error: {}", .{err});
                },
            };
            if (!self.running.load(.acquire)) break;
            // Backoff between reconnects (interruptible).
            var slept: u64 = 0;
            while (slept < backoff_ms and self.running.load(.acquire)) {
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
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
        const hbt = std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, heartbeatLoop, .{ self, &ws }) catch |err| {
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
            self.sequence.store(0, .release);
            try self.sendIdentifyPayload(&ws);
        }

        // Main read loop
        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| {
                log.warn("Discord gateway read failed: {}", .{err});
                break;
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);
            self.handleGatewayMessage(&ws, text) catch |err| {
                if (err == error.ShouldReconnect) return err;
                log.err("Discord gateway msg error: {}", .{err});
            };
        }
    }

    // ── Heartbeat thread ─────────────────────────────────────────────

    fn heartbeatLoop(self: *DiscordChannel, ws: *websocket.WsClient) void {
        // Wait for interval to be set
        while (!self.heartbeat_stop.load(.acquire) and self.heartbeat_interval_ms.load(.acquire) == 0) {
            std_compat.thread.sleep(10 * std.time.ns_per_ms);
        }
        while (!self.heartbeat_stop.load(.acquire)) {
            const interval_ms = self.heartbeat_interval_ms.load(.acquire);
            var elapsed: u64 = 0;
            while (elapsed < interval_ms) {
                if (self.heartbeat_stop.load(.acquire)) return;
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
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
                            // Sequence comes from the active gateway session and is ordered.
                            // Always overwrite to avoid stale seq after a fresh IDENTIFY.
                            self.sequence.store(s, .release);
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
                } else if (std.mem.eql(u8, event_type, "INTERACTION_CREATE")) {
                    self.handleInteractionCreate(root_val) catch |err| {
                        log.warn("Discord: handleInteractionCreate error: {}", .{err});
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
                switch (self.resolveInvalidSessionAction(resumable)) {
                    .resume_session => {
                        self.sendResumePayload(ws) catch |err| {
                            log.warn("Discord: resume after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                    .identify => {
                        self.sendIdentifyPayload(ws) catch |err| {
                            log.warn("Discord: re-identify after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                }
            },
            else => {
                log.warn("Discord: unhandled gateway op={d}", .{op});
            },
        }
    }

    fn clearSessionStateForIdentify(self: *DiscordChannel) void {
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        self.sequence.store(0, .release);
    }

    fn resolveInvalidSessionAction(self: *DiscordChannel, resumable: bool) InvalidSessionAction {
        if (resumable and self.session_id != null) {
            return .resume_session;
        }
        // Either explicitly non-resumable OR resumable but local session state is absent.
        // In both cases fall back to a clean IDENTIFY path.
        self.clearSessionStateForIdentify();
        return .identify;
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

        // Extract author.username
        const author_username: ?[]const u8 = if (author_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author.global_name (Discord display name)
        const author_display_name: ?[]const u8 = if (author_obj.get("global_name")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

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
            if (!isMentioned(content, bot_uid) and !isReplyToBot(d_obj, bot_uid)) {
                return;
            }
        }

        // Filter 3: allow_from allowlist
        if (self.allow_from.len > 0) {
            if (!root.isAllowedScoped("discord channel", self.allow_from, author_id)) {
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
                const rand = std_compat.crypto.random;
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

                                    if (std_compat.fs.createFileAbsolute(local_path, .{ .read = false })) |file| {
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
        var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
        const mw = &metadata_writer.writer;
        try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
        try mw.writeAll(",\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        if (guild_id) |gid| {
            try mw.writeAll(",\"guild_id\":");
            try root.appendJsonStringW(mw, gid);
        }
        if (author_username) |uname| {
            try mw.writeAll(",\"sender_username\":");
            try root.appendJsonStringW(mw, uname);
        }
        if (author_display_name) |dname| {
            try mw.writeAll(",\"sender_display_name\":");
            try root.appendJsonStringW(mw, dname);
        }
        try mw.writeByte('}');
        metadata_buf = metadata_writer.toArrayList();

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

    fn handleInteractionCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => return,
        };

        const interaction_id = if (d_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_token = if (d_obj.get("token")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const channel_id = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_message_id: ?[]const u8 = if (d_obj.get("message")) |v| switch (v) {
            .object => |msg_obj| if (msg_obj.get("id")) |id_val| switch (id_val) {
                .string => |s| s,
                else => null,
            } else null,
            else => null,
        } else null;
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        const data_val = d_obj.get("data") orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
            return;
        };
        const data_obj = switch (data_val) {
            .object => |o| o,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
                return;
            },
        };
        const custom_id = if (data_obj.get("custom_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
                return;
            },
        } else {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };
        const parsed_cb = interaction_choices.parseChoiceCallbackData(custom_id) orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };

        const member_user_obj = if (d_obj.get("member")) |member_val| switch (member_val) {
            .object => |member_obj| if (member_obj.get("user")) |uval| switch (uval) {
                .object => |uobj| uobj,
                else => null,
            } else null,
            else => null,
        } else null;
        const direct_user_obj = if (d_obj.get("user")) |user_val| switch (user_val) {
            .object => |uobj| uobj,
            else => null,
        } else null;
        const user_obj = member_user_obj orelse direct_user_obj orelse {
            self.answerInteraction(interaction_id, interaction_token, "Missing user context");
            return;
        };

        const user_id = if (user_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const username: ?[]const u8 = if (user_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        const display_name: ?[]const u8 = if (user_obj.get("global_name")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        if (self.allow_from.len > 0 and !root.isAllowedScoped("discord channel", self.allow_from, user_id)) {
            self.answerInteraction(interaction_id, interaction_token, "You are not allowed to use this button");
            return;
        }

        const selection = try self.consumeCallbackSelection(self.allocator, parsed_cb.token, parsed_cb.option_id, channel_id);
        switch (selection) {
            .ok => |submit_text| {
                defer self.allocator.free(submit_text);
                self.answerInteraction(interaction_id, interaction_token, null);

                const session_key = if (guild_id == null)
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, user_id })
                else
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
                defer self.allocator.free(session_key);

                var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
                defer metadata_buf.deinit(self.allocator);
                var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
                const mw = &metadata_writer.writer;
                try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
                try mw.writeAll(",\"account_id\":");
                try root.appendJsonStringW(mw, self.account_id);
                try mw.writeAll(",\"interaction\":\"button\"");
                if (std.mem.startsWith(u8, submit_text, "/model ")) {
                    try mw.writeAll(",\"replace_message\":true");
                }
                if (interaction_message_id) |message_id| {
                    try mw.writeAll(",\"message_id\":");
                    try root.appendJsonStringW(mw, message_id);
                }
                if (guild_id) |gid| {
                    try mw.writeAll(",\"guild_id\":");
                    try root.appendJsonStringW(mw, gid);
                }
                if (username) |uname| {
                    try mw.writeAll(",\"sender_username\":");
                    try root.appendJsonStringW(mw, uname);
                }
                if (display_name) |dname| {
                    try mw.writeAll(",\"sender_display_name\":");
                    try root.appendJsonStringW(mw, dname);
                }
                try mw.writeByte('}');
                metadata_buf = metadata_writer.toArrayList();

                const msg = try bus_mod.makeInboundFull(
                    self.allocator,
                    "discord",
                    user_id,
                    channel_id,
                    submit_text,
                    session_key,
                    &.{},
                    metadata_buf.items,
                );
                if (self.bus) |b| {
                    b.publishInbound(msg) catch |err| {
                        log.warn("Discord: failed to publish interaction message: {}", .{err});
                        msg.deinit(self.allocator);
                    };
                } else {
                    msg.deinit(self.allocator);
                }
            },
            .not_found, .expired => self.answerInteraction(interaction_id, interaction_token, "This menu has expired"),
            .invalid_chat => self.answerInteraction(interaction_id, interaction_token, "This button belongs to another chat"),
            .invalid_option => self.answerInteraction(interaction_id, interaction_token, "Unknown button selection"),
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

test "discord typing url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.typingUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/typing", url);
}

test "discord sendTypingIndicator is no-op in tests" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.sendTypingIndicator("123456");
}

test "discord typing handles start empty" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord startTyping stores handle and stopTyping clears it" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.running.store(true, .release);
    defer ch.stopAllTyping();

    try ch.startTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") != null);
    std_compat.thread.sleep(50 * std.time.ns_per_ms);
    try ch.stopTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord stopTyping is idempotent" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try ch.stopTyping("123456");
    try ch.stopTyping("123456");
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

test "discord buildComponentsJson packs sixth option into final row" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "One", .submit_text = "/model one" },
        .{ .id = "m2", .label = "Two", .submit_text = "/model two" },
        .{ .id = "m3", .label = "Three", .submit_text = "/model three" },
        .{ .id = "m4", .label = "Four", .submit_text = "/model four" },
        .{ .id = "prev", .label = "Prev", .submit_text = "/model page 1" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 3" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);

    const json = try ch.buildComponentsJson(directive, "abc");
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:m1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:prev\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:next\"") != null);
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
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","username":"discord-user","global_name":"Discord User","bot":false}}}
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
    try std.testing.expect(meta.value.object.get("sender_username") != null);
    try std.testing.expect(meta.value.object.get("sender_display_name") != null);
    try std.testing.expectEqualStrings("dc-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(!meta.value.object.get("is_dm").?.bool);
    try std.testing.expectEqualStrings("g-1", meta.value.object.get("guild_id").?.string);
    try std.testing.expectEqualStrings("discord-user", meta.value.object.get("sender_username").?.string);
    try std.testing.expectEqualStrings("Discord User", meta.value.object.get("sender_display_name").?.string);
}

test "discord handleInteractionCreate publishes synthetic inbound command" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
    });
    ch.setBus(&event_bus);
    defer ch.deinitPendingInteractions();

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "Alpha", .submit_text = "/model alpha" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 2" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);
    try ch.registerPendingInteraction("tok1", "c-9", directive);

    const interaction_json =
        \\{"d":{"id":"i-1","token":"itok","channel_id":"c-9","guild_id":"g-9","member":{"user":{"id":"u-9","username":"discord-user","global_name":"Discord User"}},"data":{"custom_id":"nc1:tok1:m1"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, interaction_json, .{});
    defer parsed.deinit();

    try ch.handleInteractionCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-9", msg.sender_id);
    try std.testing.expectEqualStrings("c-9", msg.chat_id);
    try std.testing.expectEqualStrings("/model alpha", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-9", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"interaction\":\"button\"") != null);
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

test "discord handleMessageCreate require_mention accepts reply to bot message" {
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
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 1), event_bus.inboundDepth());

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
}

test "discord handleMessageCreate require_mention still blocks reply to non-bot message" {
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
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"other-user","bot":false}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate require_mention ignores non-reply references to bot message" {
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
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":21,"content":"","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord dispatch sequence accepts lower values after session reset" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    defer {
        if (ch.session_id) |s| std.testing.allocator.free(s);
        if (ch.resume_gateway_url) |u| std.testing.allocator.free(u);
        if (ch.bot_user_id) |u| std.testing.allocator.free(u);
    }

    // Simulate stale sequence from an old session.
    ch.sequence.store(42, .release);

    var ws_dummy: websocket.WsClient = undefined;
    const ready_dispatch =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess-1","resume_gateway_url":"wss://gateway.discord.gg/?v=10&encoding=json","user":{"id":"bot-1"}}}
    ;
    try ch.handleGatewayMessage(&ws_dummy, ready_dispatch);

    try std.testing.expectEqual(@as(i64, 1), ch.sequence.load(.acquire));
}

test "discord invalid session non-resumable clears state and identifies" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-1");
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(77, .release);

    const action = ch.resolveInvalidSessionAction(false);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "discord invalid session resumable keeps state and resumes" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-2");
    defer {
        if (ch.session_id) |s| alloc.free(s);
    }
    ch.sequence.store(123, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.resume_session, action);
    try std.testing.expect(ch.session_id != null);
    try std.testing.expectEqual(@as(i64, 123), ch.sequence.load(.acquire));
}

test "discord invalid session resumable without session falls back to identify" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(33, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
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
