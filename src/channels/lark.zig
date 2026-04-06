const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");
const http_util = @import("../http_util.zig");
const outbound = @import("../outbound.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");

const log = std.log.scoped(.lark);

const SocketFd = std.net.Stream.Handle;
const invalid_socket: SocketFd = switch (builtin.os.tag) {
    .windows => std.os.windows.ws2_32.INVALID_SOCKET,
    else => -1,
};
const AtomicU32 = std.atomic.Value(u32);
const PendingReactionQueue = std.ArrayListUnmanaged([]const u8);
const DEFAULT_LARK_PING_INTERVAL_MS: u32 = 120 * std.time.ms_per_s;
const EVENT_CACHE_TTL_MS: i64 = 10_000;
const LARK_WS_METHOD_CONTROL: i32 = 0;
const LARK_WS_METHOD_DATA: i32 = 1;

const LarkWsConnectConfig = struct {
    url: []u8,
    ping_interval_ms: u32 = DEFAULT_LARK_PING_INTERVAL_MS,

    fn deinit(self: *LarkWsConnectConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

const LarkWsHeader = struct {
    key: []const u8,
    value: []const u8,
};

const LarkWsFrame = struct {
    seq_id: u64,
    log_id: u64,
    service: i32,
    method: i32,
    headers: []LarkWsHeader,
    payload_encoding: ?[]const u8 = null,
    payload_type: ?[]const u8 = null,
    payload: []const u8 = &.{},
    log_id_new: ?[]const u8 = null,

    fn deinit(self: *LarkWsFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
    }
};

const LarkWsEventBuffer = struct {
    trace_id: []u8,
    parts: []?[]u8,
    created_at_ms: i64,

    fn deinit(self: *LarkWsEventBuffer, allocator: std.mem.Allocator) void {
        allocator.free(self.trace_id);
        for (self.parts) |part| {
            if (part) |payload| allocator.free(payload);
        }
        allocator.free(self.parts);
    }
};

const LarkWsPingLoopCtx = struct {
    ws: *websocket.WsClient,
    running: *const std.atomic.Value(bool),
    ping_interval_ms: *AtomicU32,
    service_id: i32,
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
    reaction_emojis: []const []const u8 = &.{},
    /// Pending reaction message_ids queued per chat_id (for undo after responses are sent).
    pending_reactions: std.StringHashMapUnmanaged(PendingReactionQueue) = .empty,

    pub const FEISHU_BASE_URL = "https://open.feishu.cn/open-apis";
    pub const LARK_BASE_URL = "https://open.larksuite.com/open-apis";
    /// Host root for callback endpoints (e.g. websocket config). Path is /callback/ws/endpoint, not under /open-apis.
    pub const FEISHU_CALLBACK_HOST = "https://open.feishu.cn";
    pub const LARK_CALLBACK_HOST = "https://open.larksuite.com";

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
        ch.reaction_emojis = cfg.reaction_emojis;
        return ch;
    }

    fn deinitPendingReactionQueue(allocator: std.mem.Allocator, queue: *PendingReactionQueue) void {
        for (queue.items) |message_id| allocator.free(message_id);
        queue.deinit(allocator);
    }

    fn deinitPendingReactions(self: *LarkChannel) void {
        var pending = self.pending_reactions;
        self.pending_reactions = .empty;

        var it = pending.iterator();
        while (it.next()) |entry| {
            deinitPendingReactionQueue(self.allocator, entry.value_ptr);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        pending.deinit(self.allocator);
    }

    fn resetOwnedState(self: *LarkChannel) void {
        self.invalidateToken();
        self.deinitPendingReactions();
    }

    fn enqueuePendingReaction(self: *LarkChannel, chat_id: []const u8, message_id: []const u8) !void {
        const gop = try self.pending_reactions.getOrPut(self.allocator, chat_id);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, chat_id);
            gop.value_ptr.* = .empty;
            errdefer {
                if (self.pending_reactions.fetchRemove(chat_id)) |entry| {
                    var queue = entry.value;
                    queue.deinit(self.allocator);
                    self.allocator.free(@constCast(entry.key));
                }
            }
        }

        const message_copy = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(message_copy);
        try gop.value_ptr.append(self.allocator, message_copy);
    }

    /// Return the API base URL based on region setting.
    pub fn apiBase(self: *const LarkChannel) []const u8 {
        return if (self.use_feishu) FEISHU_BASE_URL else LARK_BASE_URL;
    }

    pub fn channelName(_: *LarkChannel) []const u8 {
        return "lark";
    }

    pub fn isUserAllowed(self: *const LarkChannel, open_id: []const u8) bool {
        return root.isAllowedExactScoped("lark channel", self.allow_from, open_id);
    }

    pub fn setBus(self: *LarkChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    /// Parse a Lark event callback payload and extract text messages or card actions.
    /// Supports "text", "post", and card action callback events.
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
        if (std.mem.eql(u8, event_type, "im.message.receive_v1")) {
            // Continue below.
        } else if (isCardActionEventType(event_type)) {
            const event = val.object.get("event") orelse return result.items;
            if (event != .object) return result.items;

            const root_context = val.object.get("context");
            const open_id = extractCardActionOpenId(event);
            if (!isCardActionAllowed(self, event)) return result.items;

            const chat_id = extractCardActionChatId(event, root_context) orelse open_id orelse return result.items;
            const choice_text = extractCardActionText(allocator, event) orelse return result.items;
            defer allocator.free(choice_text);

            const text = std.mem.trim(u8, choice_text, " \t\n\r");
            if (text.len == 0) return result.items;

            try result.append(allocator, .{
                .sender = try allocator.dupe(u8, chat_id),
                .content = try allocator.dupe(u8, text),
                .timestamp = root.nowEpochSecs(),
                .is_group = extractCardActionIsGroup(event, root_context),
                .message_id = &.{},
            });
            return result.toOwnedSlice(allocator);
        } else {
            return result.items;
        }

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

        // Extract message_id for reaction support
        const msg_id_val = msg_obj.object.get("message_id");
        const message_id = if (msg_id_val) |mid_val| (if (mid_val == .string) mid_val.string else "") else "";

        try result.append(allocator, .{
            .sender = try allocator.dupe(u8, chat_id),
            .content = try allocator.dupe(u8, text),
            .timestamp = timestamp,
            .is_group = std.mem.eql(u8, chat_type, "group"),
            .message_id = if (message_id.len > 0) try allocator.dupe(u8, message_id) else &.{},
        });

        return result.toOwnedSlice(allocator);
    }

    pub fn healthCheck(self: *LarkChannel) bool {
        return switch (self.receive_mode) {
            .webhook => self.running.load(.acquire),
            .websocket => self.running.load(.acquire) and self.connected.load(.acquire),
        };
    }

    fn componentAsSlice(component: std.Uri.Component) []const u8 {
        return switch (component) {
            .raw => |v| v,
            .percent_encoded => |v| v,
        };
    }

    fn statusCodeIsSuccess(code: u16) bool {
        return code >= 200 and code < 300;
    }

    fn messageSuggestsPermissionIssue(msg: []const u8) bool {
        if (msg.len == 0) return false;
        if (std.mem.indexOf(u8, msg, "权限") != null) return true;

        var lower_buf: [512]u8 = undefined;
        const n = @min(msg.len, lower_buf.len);
        for (msg[0..n], 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }
        const lower = lower_buf[0..n];
        return std.mem.indexOf(u8, lower, "permission") != null or
            std.mem.indexOf(u8, lower, "scope") != null or
            std.mem.indexOf(u8, lower, "forbidden") != null or
            std.mem.indexOf(u8, lower, "unauthorized") != null;
    }

    fn validateBusinessResponse(allocator: std.mem.Allocator, op: []const u8, body: []const u8) !void {
        if (body.len == 0) return;
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        const code_val = parsed.value.object.get("code") orelse return;
        const code = switch (code_val) {
            .integer => |v| v,
            .float => |v| @as(i64, @intFromFloat(v)),
            else => return,
        };
        if (code == 0) return;

        const msg = if (parsed.value.object.get("msg")) |msg_val|
            (if (msg_val == .string) msg_val.string else "")
        else
            "";

        log.warn("lark {s} failed with API code {d}: {s}", .{ op, code, msg });
        if (messageSuggestsPermissionIssue(msg)) {
            log.warn("lark {s} likely requires additional app permissions/scopes in Feishu/Lark console", .{op});
        }
        return error.LarkApiError;
    }

    fn extractCardActionOpenId(event: std.json.Value) ?[]const u8 {
        if (event != .object) return null;

        if (event.object.get("operator")) |operator_val| {
            if (operator_val == .object) {
                if (operator_val.object.get("open_id")) |open_id_val| {
                    if (open_id_val == .string and open_id_val.string.len > 0) return open_id_val.string;
                }
                if (operator_val.object.get("operator_id")) |operator_id_val| {
                    if (operator_id_val == .object) {
                        if (operator_id_val.object.get("open_id")) |open_id_val| {
                            if (open_id_val == .string and open_id_val.string.len > 0) return open_id_val.string;
                        }
                    }
                }
            }
        }

        if (event.object.get("open_id")) |open_id_val| {
            if (open_id_val == .string and open_id_val.string.len > 0) return open_id_val.string;
        }

        return null;
    }

    fn extractCardActionChatId(event: std.json.Value, root_context: ?std.json.Value) ?[]const u8 {
        if (event != .object) return null;

        if (event.object.get("context")) |context_val| {
            if (context_val == .object) {
                if (context_val.object.get("open_chat_id")) |chat_id_val| {
                    if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
                }
                if (context_val.object.get("chat_id")) |chat_id_val| {
                    if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
                }
            }
        }

        if (event.object.get("open_chat_id")) |chat_id_val| {
            if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
        }
        if (event.object.get("chat_id")) |chat_id_val| {
            if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
        }

        if (root_context) |context_val| {
            if (context_val == .object) {
                if (context_val.object.get("open_chat_id")) |chat_id_val| {
                    if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
                }
                if (context_val.object.get("chat_id")) |chat_id_val| {
                    if (chat_id_val == .string and chat_id_val.string.len > 0) return chat_id_val.string;
                }
            }
        }

        return null;
    }

    fn extractCardActionChatTypeField(value: std.json.Value) ?[]const u8 {
        if (value != .object) return null;
        const chat_type_val = value.object.get("chat_type") orelse return null;
        if (chat_type_val != .string or chat_type_val.string.len == 0) return null;
        return chat_type_val.string;
    }

    fn extractCardActionIsGroup(event: std.json.Value, root_context: ?std.json.Value) bool {
        if (event != .object) return false;

        if (event.object.get("context")) |context_val| {
            if (extractCardActionChatTypeField(context_val)) |chat_type| {
                return std.mem.eql(u8, chat_type, "group");
            }
        }

        if (extractCardActionChatTypeField(event)) |chat_type| {
            return std.mem.eql(u8, chat_type, "group");
        }

        if (root_context) |context_val| {
            if (extractCardActionChatTypeField(context_val)) |chat_type| {
                return std.mem.eql(u8, chat_type, "group");
            }
        }

        return false;
    }

    fn extractCardActionText(allocator: std.mem.Allocator, event: std.json.Value) ?[]u8 {
        if (event != .object) return null;
        const action_val = event.object.get("action") orelse return null;
        if (action_val != .object) return null;

        if (action_val.object.get("form_value")) |form_value_val| {
            if (form_value_val == .object) {
                if (form_value_val.object.get("choice_select")) |choice_val| {
                    if (choice_val == .string and choice_val.string.len > 0) {
                        return allocator.dupe(u8, choice_val.string) catch null;
                    }
                    if (choice_val == .array and choice_val.array.items.len > 0) {
                        const first = choice_val.array.items[0];
                        if (first == .string and first.string.len > 0) return allocator.dupe(u8, first.string) catch null;
                    }
                }

                var form_iter = form_value_val.object.iterator();
                while (form_iter.next()) |entry| {
                    if (entry.value_ptr.* == .string and entry.value_ptr.string.len > 0) {
                        return allocator.dupe(u8, entry.value_ptr.string) catch null;
                    }
                    if (entry.value_ptr.* == .array and entry.value_ptr.array.items.len > 0) {
                        const first = entry.value_ptr.array.items[0];
                        if (first == .string and first.string.len > 0) return allocator.dupe(u8, first.string) catch null;
                    }
                }
            }
        }

        if (action_val.object.get("value")) |value_val| {
            if (value_val == .object) {
                if (value_val.object.get("submit_text")) |submit_text_val| {
                    if (submit_text_val == .string and submit_text_val.string.len > 0) {
                        return allocator.dupe(u8, submit_text_val.string) catch null;
                    }
                }
                if (value_val.object.get("choice_id")) |choice_id_val| {
                    if (choice_id_val == .string and choice_id_val.string.len > 0) {
                        return allocator.dupe(u8, choice_id_val.string) catch null;
                    }
                }
                if (value_val.object.get("command")) |command_val| {
                    if (command_val == .string and command_val.string.len > 0) {
                        return allocator.dupe(u8, command_val.string) catch null;
                    }
                }

                var value_iter = value_val.object.iterator();
                while (value_iter.next()) |entry| {
                    if (entry.value_ptr.* == .string and entry.value_ptr.string.len > 0) {
                        return allocator.dupe(u8, entry.value_ptr.string) catch null;
                    }
                }
            }
        }

        if (action_val.object.get("option")) |option_val| {
            if (option_val == .object) {
                if (option_val.object.get("text")) |text_val| {
                    if (text_val == .string and text_val.string.len > 0) {
                        return allocator.dupe(u8, text_val.string) catch null;
                    }
                }
                if (option_val.object.get("value")) |value_val| {
                    if (value_val == .string and value_val.string.len > 0) {
                        return allocator.dupe(u8, value_val.string) catch null;
                    }
                }
            }
        }

        if (action_val.object.get("options")) |options_val| {
            if (options_val == .array and options_val.array.items.len > 0) {
                const first = options_val.array.items[0];
                if (first == .object) {
                    if (first.object.get("text")) |text_val| {
                        if (text_val == .string and text_val.string.len > 0) {
                            return allocator.dupe(u8, text_val.string) catch null;
                        }
                    }
                    if (first.object.get("value")) |value_val| {
                        if (value_val == .string and value_val.string.len > 0) {
                            return allocator.dupe(u8, value_val.string) catch null;
                        }
                    }
                }
            }
        }

        return null;
    }

    fn buildActionResultCardJson(
        allocator: std.mem.Allocator,
        choice_text: []const u8,
    ) ![]u8 {
        var markdown: std.ArrayListUnmanaged(u8) = .empty;
        defer markdown.deinit(allocator);
        try markdown.appendSlice(allocator, "✅ 你已选择：`");
        try markdown.appendSlice(allocator, choice_text);
        try markdown.appendSlice(allocator, "`\n\n已提交处理，稍后会继续回复。");

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        const writer = out.writer(allocator);
        try writer.writeAll("{\"schema\":\"2.0\",\"config\":{\"update_multi\":true},\"body\":{\"elements\":[");
        try writer.writeAll("{\"tag\":\"markdown\",\"content\":");
        try root.appendJsonStringW(writer, markdown.items);
        try writer.writeAll("}]}}");
        return try out.toOwnedSlice(allocator);
    }

    fn buildCardActionCallbackResponse(
        self: *const LarkChannel,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) !?[]u8 {
        if (!isCardActionPayload(payload)) return null;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const event = parsed.value.object.get("event") orelse return null;
        if (event != .object) return null;

        if (!isCardActionAllowed(self, event)) return null;

        const choice_text = extractCardActionText(allocator, event) orelse return null;
        defer allocator.free(choice_text);

        const trimmed = std.mem.trim(u8, choice_text, " \t\n\r");
        if (trimmed.len == 0) return null;

        const card_json = try buildActionResultCardJson(allocator, trimmed);
        defer allocator.free(card_json);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        const writer = out.writer(allocator);
        try writer.writeAll("{\"toast\":{\"type\":\"success\",\"content\":\"已提交，正在处理\"},\"card\":{\"type\":\"raw\",\"data\":");
        try writer.writeAll(card_json);
        try writer.writeAll("}}");
        return try out.toOwnedSlice(allocator);
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

        const resp = http_util.curlPostWithStatus(
            self.allocator,
            url,
            body,
            &.{},
        ) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        try validateBusinessResponse(self.allocator, "tenant_access_token", resp.body);

        const resp_body = resp.body;
        if (resp_body.len == 0) return error.LarkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.LarkApiError;

        const token_val = parsed.value.object.get("tenant_access_token") orelse return error.LarkApiError;
        if (token_val != .string) return error.LarkApiError;
        return self.allocator.dupe(u8, token_val.string);
    }

    /// POST body to url with Lark bearer auth, retrying once on 401 token expiry.
    fn postWithTokenRetry(self: *LarkChannel, url: []const u8, body: []const u8) !void {
        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        var auth_buf: [512]u8 = undefined;
        const auth_value = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token}) catch return error.LarkApiError;
        var auth_header_buf: [576]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "Authorization: {s}", .{auth_value}) catch return error.LarkApiError;

        const resp = http_util.curlPostWithStatus(self.allocator, url, body, &.{auth_header}) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (resp.status_code == 401) {
            self.invalidateToken();
            const new_token = self.getTenantAccessToken() catch return error.LarkApiError;
            defer self.allocator.free(new_token);

            var retry_buf: [512]u8 = undefined;
            const retry_value = std.fmt.bufPrint(&retry_buf, "Bearer {s}", .{new_token}) catch return error.LarkApiError;
            var retry_header_buf: [576]u8 = undefined;
            const retry_header = std.fmt.bufPrint(&retry_header_buf, "Authorization: {s}", .{retry_value}) catch return error.LarkApiError;

            const retry_resp = http_util.curlPostWithStatus(self.allocator, url, body, &.{retry_header}) catch return error.LarkApiError;
            defer self.allocator.free(retry_resp.body);

            if (!statusCodeIsSuccess(retry_resp.status_code)) {
                return error.LarkApiError;
            }
            try validateBusinessResponse(self.allocator, "send_message", retry_resp.body);
            return;
        }

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        try validateBusinessResponse(self.allocator, "send_message", resp.body);
    }

    fn curlDeleteWithStatus(
        allocator: std.mem.Allocator,
        url: []const u8,
        headers: []const []const u8,
    ) !http_util.HttpResponse {
        var argv_buf: [24][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-s";
        argc += 1;
        argv_buf[argc] = "-X";
        argc += 1;
        argv_buf[argc] = "DELETE";
        argc += 1;

        for (headers) |header| {
            if (argc + 2 > argv_buf.len) break;
            argv_buf[argc] = "-H";
            argc += 1;
            argv_buf[argc] = header;
            argc += 1;
        }

        argv_buf[argc] = "-w";
        argc += 1;
        argv_buf[argc] = "\n%{http_code}";
        argc += 1;
        argv_buf[argc] = url;
        argc += 1;

        var child = std.process.Child.init(argv_buf[0..argc], allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return error.LarkApiError;

        const stdout = child.stdout.?.readToEndAlloc(allocator, 256 * 1024) catch {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return error.LarkApiError;
        };
        errdefer allocator.free(stdout);

        const term = child.wait() catch return error.LarkApiError;
        switch (term) {
            .Exited => |code| if (code != 0) return error.LarkApiError,
            else => return error.LarkApiError,
        }

        const status_sep = std.mem.lastIndexOfScalar(u8, stdout, '\n') orelse return error.LarkApiError;
        const status_raw = std.mem.trim(u8, stdout[status_sep + 1 ..], " \t\r\n");
        if (status_raw.len != 3) return error.LarkApiError;
        const status_code = std.fmt.parseInt(u16, status_raw, 10) catch return error.LarkApiError;
        const body = try allocator.dupe(u8, stdout[0..status_sep]);
        allocator.free(stdout);

        return .{
            .status_code = status_code,
            .body = body,
        };
    }

    fn buildRichCardContent(buf: []u8, payload: root.Channel.OutboundPayload) ![]const u8 {
        var card_fbs = std.io.fixedBufferStream(buf);
        const writer = card_fbs.writer();

        try writer.writeAll("{\"schema\":\"2.0\"");
        if (payload.card_title.len > 0) {
            try writer.writeAll(",\"header\":{\"title\":{\"tag\":\"plain_text\",\"content\":");
            try root.appendJsonStringW(writer, payload.card_title);
            try writer.writeAll("}}");
        }
        try writer.writeAll(",\"body\":{\"elements\":[");

        var first_element = true;
        if (payload.text.len > 0) {
            first_element = false;
            try writer.writeAll("{\"tag\":\"div\",\"text\":{\"tag\":\"lark_md\",\"content\":");
            try root.appendJsonStringW(writer, payload.text);
            try writer.writeAll("}}");
        }
        for (payload.card_sections) |section| {
            if (!first_element) try writer.writeByte(',');
            first_element = false;

            var section_buf: [4096]u8 = undefined;
            var section_fbs = std.io.fixedBufferStream(&section_buf);
            if (section.title.len > 0) {
                try section_fbs.writer().print("**{s}**\n{s}", .{ section.title, section.body });
            } else {
                try section_fbs.writer().writeAll(section.body);
            }

            try writer.writeAll("{\"tag\":\"div\",\"text\":{\"tag\":\"lark_md\",\"content\":");
            try root.appendJsonStringW(writer, section_fbs.getWritten());
            try writer.writeAll("}}");
        }

        const has_action_groups = for (payload.action_groups) |group| {
            if (group.actions.len > 0) break true;
        } else false;

        if (has_action_groups) {
            for (payload.action_groups) |group| {
                if (group.actions.len == 0) continue;
                if (!first_element) try writer.writeByte(',');
                first_element = false;
                try writer.writeAll("{\"tag\":\"action\",\"actions\":[");
                var first_button = true;
                for (group.actions) |button| {
                    if (!first_button) try writer.writeByte(',');
                    first_button = false;
                    try writer.writeAll("{\"tag\":\"button\",\"text\":{\"tag\":\"plain_text\",\"content\":");
                    try root.appendJsonStringW(writer, button.label);
                    try writer.writeAll("},\"type\":\"primary\",\"value\":{\"choice_id\":");
                    try root.appendJsonStringW(writer, button.id);
                    try writer.writeAll("}}");
                }
                try writer.writeAll("]}");
            }
        } else if (payload.choices.len > 0) {
            if (!first_element) try writer.writeByte(',');
            try writer.writeAll("{\"tag\":\"action\",\"actions\":[");
            for (payload.choices, 0..) |choice, index| {
                if (index != 0) try writer.writeByte(',');
                try writer.writeAll("{\"tag\":\"button\",\"text\":{\"tag\":\"plain_text\",\"content\":");
                try root.appendJsonStringW(writer, choice.label);
                try writer.writeAll("},\"type\":\"primary\",\"value\":{\"submit_text\":");
                try root.appendJsonStringW(writer, choice.submit_text);
                try writer.writeAll(",\"choice_id\":");
                try root.appendJsonStringW(writer, choice.id);
                try writer.writeAll("}}");
            }
            try writer.writeAll("]}");
        }

        try writer.writeAll("]}}");
        return card_fbs.getWritten();
    }

    /// Send a plain text message to a Lark chat via the Open API.
    /// POST /im/v1/messages?receive_id_type=chat_id
    pub fn sendMessage(self: *LarkChannel, recipient: []const u8, text: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages?receive_id_type=chat_id", .{self.apiBase()});
        const url = url_fbs.getWritten();

        var content_buf: [4096]u8 = undefined;
        var content_fbs = std.io.fixedBufferStream(&content_buf);
        try content_fbs.writer().writeAll("{\"text\":");
        try root.appendJsonStringW(content_fbs.writer(), text);
        try content_fbs.writer().writeAll("}");

        var body_buf: [8192]u8 = undefined;
        var body_fbs = std.io.fixedBufferStream(&body_buf);
        const w = body_fbs.writer();
        try w.writeAll("{\"receive_id\":\"");
        try w.writeAll(recipient);
        try w.writeAll("\",\"msg_type\":\"text\",\"content\":");
        try root.appendJsonStringW(w, content_fbs.getWritten());
        try w.writeAll("}");

        try self.postWithTokenRetry(url, body_fbs.getWritten());
    }

    /// Send a rich interactive card to a Lark chat via the Open API.
    /// Renders as a Lark Card 2.0 (schema 2.0) interactive message.
    pub fn sendRichMessage(self: *LarkChannel, recipient: []const u8, payload: root.Channel.OutboundPayload) !void {
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages?receive_id_type=chat_id", .{self.apiBase()});
        const url = url_fbs.getWritten();

        var card_buf: [16384]u8 = undefined;
        const card_content = try buildRichCardContent(&card_buf, payload);
        var body_buf: [20480]u8 = undefined;
        var body_fbs = std.io.fixedBufferStream(&body_buf);
        const bw = body_fbs.writer();
        try bw.writeAll("{\"receive_id\":\"");
        try bw.writeAll(recipient);
        try bw.writeAll("\",\"msg_type\":\"interactive\",\"content\":");
        try root.appendJsonStringW(bw, card_content);
        try bw.writeAll("}");

        try self.postWithTokenRetry(url, body_fbs.getWritten());
    }

    /// Add a reaction emoji to a message. Randomly picks from reaction_emojis config.
    /// Stores the reaction for later undo (via deletePendingReaction).
    fn reactToMessage(self: *LarkChannel, message_id: []const u8, chat_id: []const u8) !void {
        if (message_id.len == 0) return;
        if (self.reaction_emojis.len == 0) return;

        const idx = if (self.reaction_emojis.len == 1) 0 else blk: {
            const seed = @as(u64, @bitCast(std.time.timestamp()));
            break :blk @as(usize, @intCast(@mod(seed, @as(u64, @intCast(self.reaction_emojis.len)))));
        };
        const emoji = self.reaction_emojis[idx];

        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages/{s}/reactions", .{ self.apiBase(), message_id });

        var body_buf: [256]u8 = undefined;
        var body_fbs = std.io.fixedBufferStream(&body_buf);
        try body_fbs.writer().writeAll("{\"reaction_type\":{\"emoji_type\":\"");
        try body_fbs.writer().writeAll(emoji);
        try body_fbs.writer().writeAll("\"}}");

        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        var auth_buf: [512]u8 = undefined;
        const auth_value = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token}) catch return error.LarkApiError;
        var auth_header_buf: [576]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "Authorization: {s}", .{auth_value}) catch return error.LarkApiError;

        const resp = http_util.curlPostWithStatus(self.allocator, url_fbs.getWritten(), body_fbs.getWritten(), &.{auth_header}) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        try validateBusinessResponse(self.allocator, "add_reaction", resp.body);

        if (chat_id.len > 0) {
            try self.enqueuePendingReaction(chat_id, message_id);
        }
    }

    /// Delete pending reaction for a chat (called after sending response).
    fn deletePendingReaction(self: *LarkChannel, chat_id: []const u8) void {
        const queue = self.pending_reactions.getPtr(chat_id) orelse return;
        if (queue.items.len == 0) return;

        const message_id = queue.items[0];
        self.deleteReaction(message_id) catch |err| {
            log.warn("lark deletePendingReaction failed: {}", .{err});
            return;
        };

        self.allocator.free(queue.orderedRemove(0));
        if (queue.items.len == 0) {
            if (self.pending_reactions.fetchRemove(chat_id)) |entry| {
                var pending_queue = entry.value;
                pending_queue.deinit(self.allocator);
                self.allocator.free(@constCast(entry.key));
            }
        }
    }

    /// List reactions on a message and delete ones matching our configured emojis.
    fn deleteReaction(self: *LarkChannel, message_id: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages/{s}/reactions", .{ self.apiBase(), message_id });

        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        var auth_buf: [512]u8 = undefined;
        const auth_value = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token}) catch return error.LarkApiError;
        var auth_header_buf: [576]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "Authorization: {s}", .{auth_value}) catch return error.LarkApiError;

        const resp = http_util.curlGetWithStatus(self.allocator, url_fbs.getWritten(), &.{auth_header}) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        try validateBusinessResponse(self.allocator, "list_reactions", resp.body);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp.body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        const data = parsed.value.object.get("data") orelse return;
        if (data != .object) return;
        const items = data.object.get("items") orelse return;
        if (items != .array) return;

        for (items.array.items) |item| {
            if (item != .object) continue;
            const reaction_type = item.object.get("reaction_type") orelse continue;
            if (reaction_type != .object) continue;
            const emoji_type = reaction_type.object.get("emoji_type") orelse continue;
            if (emoji_type != .string) continue;
            const reaction_id = item.object.get("reaction_id") orelse continue;
            if (reaction_id != .string) continue;

            for (self.reaction_emojis) |our_emoji| {
                if (std.mem.eql(u8, emoji_type.string, our_emoji)) {
                    self.deleteReactionById(message_id, reaction_id.string) catch |err| {
                        log.warn("lark deleteReactionById failed: {}", .{err});
                    };
                    break;
                }
            }
        }
    }

    fn deleteReactionById(self: *LarkChannel, message_id: []const u8, reaction_id: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/im/v1/messages/{s}/reactions/{s}", .{ self.apiBase(), message_id, reaction_id });

        const token = try self.getTenantAccessToken();
        defer self.allocator.free(token);

        var auth_buf: [512]u8 = undefined;
        const auth_value = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token}) catch return error.LarkApiError;
        var auth_header_buf: [576]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "Authorization: {s}", .{auth_value}) catch return error.LarkApiError;

        const resp = curlDeleteWithStatus(self.allocator, url_fbs.getWritten(), &.{auth_header}) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        try validateBusinessResponse(self.allocator, "delete_reaction", resp.body);
    }

    fn buildWebsocketConfigUrl(self: *const LarkChannel, buf: []u8) ![]const u8 {
        const host = if (self.use_feishu) FEISHU_CALLBACK_HOST else LARK_CALLBACK_HOST;
        var fbs = std.io.fixedBufferStream(buf);
        try fbs.writer().print("{s}/callback/ws/endpoint", .{host});
        return fbs.getWritten();
    }

    fn buildWebsocketConfigBody(buf: []u8, app_id: []const u8, app_secret: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll("{\"AppID\":");
        try root.appendJsonStringW(w, app_id);
        try w.writeAll(",\"AppSecret\":");
        try root.appendJsonStringW(w, app_secret);
        try w.writeAll("}");
        return fbs.getWritten();
    }

    fn extractWebsocketConnectConfig(allocator: std.mem.Allocator, resp_body: []const u8) !LarkWsConnectConfig {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.LarkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.LarkApiError;

        if (parsed.value.object.get("code")) |code_val| {
            if (code_val == .integer and code_val.integer != 0) return error.LarkApiError;
        }

        const data_val = parsed.value.object.get("data") orelse return error.LarkApiError;
        if (data_val != .object) return error.LarkApiError;

        const url_val = data_val.object.get("URL") orelse data_val.object.get("url") orelse return error.LarkApiError;
        if (url_val != .string or url_val.string.len == 0) return error.LarkApiError;

        var cfg = LarkWsConnectConfig{
            .url = try allocator.dupe(u8, url_val.string),
        };
        errdefer cfg.deinit(allocator);

        if (data_val.object.get("ClientConfig")) |client_cfg_val| {
            if (client_cfg_val == .object) {
                if (client_cfg_val.object.get("PingInterval")) |ping_val| {
                    const ping_secs = switch (ping_val) {
                        .integer => |v| if (v > 0) @as(u64, @intCast(v)) else 0,
                        .float => |v| if (v > 0) @as(u64, @intFromFloat(v)) else 0,
                        else => 0,
                    };
                    if (ping_secs > 0) {
                        cfg.ping_interval_ms = std.math.cast(u32, ping_secs * std.time.ms_per_s) orelse return error.LarkApiError;
                    }
                }
            }
        }

        return cfg;
    }

    fn extractWebsocketConnectUrl(allocator: std.mem.Allocator, resp_body: []const u8) ![]u8 {
        const cfg = try extractWebsocketConnectConfig(allocator, resp_body);
        return cfg.url;
    }

    fn parseWebsocketConnectUrl(
        connect_url: []const u8,
        host_buf: []u8,
        path_buf: []u8,
    ) !struct { host: []const u8, port: u16, path: []const u8, service_id: ?i32 } {
        const uri = std.Uri.parse(connect_url) catch return error.LarkApiError;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "wss")) return error.LarkApiError;

        const host = uri.getHost(host_buf) catch return error.LarkApiError;
        const port = uri.port orelse 443;
        const raw_path = componentAsSlice(uri.path);
        const query = if (uri.query) |q| componentAsSlice(q) else "";
        const service_id = if (query.len > 0) blk: {
            const raw_service = queryParam(query, "service_id") orelse break :blk null;
            break :blk std.fmt.parseInt(i32, raw_service, 10) catch null;
        } else null;

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
            .service_id = service_id,
        };
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

    fn fetchWebsocketConnectConfig(self: *LarkChannel) !LarkWsConnectConfig {
        var url_buf: [256]u8 = undefined;
        const url = try buildWebsocketConfigUrl(self, &url_buf);

        var body_buf: [512]u8 = undefined;
        const body = try buildWebsocketConfigBody(&body_buf, self.app_id, self.app_secret);

        const resp = http_util.curlPostWithStatus(
            self.allocator,
            url,
            body,
            &.{
                "locale: zh",
            },
        ) catch return error.LarkApiError;
        defer self.allocator.free(resp.body);

        if (!statusCodeIsSuccess(resp.status_code)) return error.LarkApiError;
        return extractWebsocketConnectConfig(self.allocator, resp.body);
    }

    fn publishInboundMessage(self: *LarkChannel, msg: ParsedLarkMessage) void {
        if (msg.message_id.len > 0) {
            self.reactToMessage(msg.message_id, msg.sender) catch |err| {
                log.warn("lark reactToMessage failed: {}", .{err});
            };
        }

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

    fn processEventPayload(self: *LarkChannel, payload: []const u8) !void {
        const messages = try self.parseEventPayload(self.allocator, payload);
        defer if (messages.len > 0) {
            for (messages) |*m| m.deinit(self.allocator);
            self.allocator.free(messages);
        };

        for (messages) |m| {
            self.publishInboundMessage(m);
        }
    }

    fn handleLegacyWebsocketPayload(self: *LarkChannel, ws: *websocket.WsClient, payload: []const u8) !void {
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

        try self.processEventPayload(payload);
    }

    fn handleBinaryWebsocketPayload(
        self: *LarkChannel,
        ws: *websocket.WsClient,
        payload: []const u8,
        event_buffers: *std.StringHashMapUnmanaged(LarkWsEventBuffer),
        ping_interval_ms: *AtomicU32,
    ) !void {
        var frame = try decodeLarkWsFrame(self.allocator, payload);
        defer frame.deinit(self.allocator);

        if (frame.method == LARK_WS_METHOD_CONTROL) {
            const msg_type = larkWsHeaderValue(frame.headers, "type") orelse return;
            if (std.mem.eql(u8, msg_type, "pong") and frame.payload.len > 0) {
                updatePingIntervalFromControlPayload(ping_interval_ms, frame.payload);
            }
            return;
        }

        if (frame.method != LARK_WS_METHOD_DATA) return;

        const msg_type = larkWsHeaderValue(frame.headers, "type") orelse return;
        if (!std.mem.eql(u8, msg_type, "event")) return;

        const started_at_ms = std.time.milliTimestamp();
        const maybe_payload = try mergeLarkWsEventPayload(self.allocator, event_buffers, frame);
        defer if (maybe_payload) |merged_payload| self.allocator.free(merged_payload);

        if (maybe_payload) |merged_payload| {
            const callback_response = self.buildCardActionCallbackResponse(self.allocator, merged_payload) catch null;
            defer if (callback_response) |response| self.allocator.free(response);

            const ack_payload = buildLarkWsAckPayload(self.allocator, callback_response) catch return;
            defer self.allocator.free(ack_payload);

            self.processEventPayload(merged_payload) catch |err| {
                log.warn("lark websocket event handling failed: {}", .{err});
            };

            const elapsed_ms: u64 = @intCast(@max(std.time.milliTimestamp() - started_at_ms, 0));
            const ack = buildLarkWsEventAckFrame(self.allocator, frame, elapsed_ms, ack_payload) catch return;
            defer self.allocator.free(ack);
            ws.writeBinary(ack) catch |err| {
                log.warn("lark websocket protobuf ack failed: {}", .{err});
            };
        }
    }

    fn runWebsocketOnce(self: *LarkChannel) !void {
        var connect_cfg = try self.fetchWebsocketConnectConfig();
        defer connect_cfg.deinit(self.allocator);

        var host_buf: [256]u8 = undefined;
        var path_buf: [2048]u8 = undefined;
        const connect_parts = try parseWebsocketConnectUrl(connect_cfg.url, &host_buf, &path_buf);

        var ws = try websocket.WsClient.connect(
            self.allocator,
            connect_parts.host,
            connect_parts.port,
            connect_parts.path,
            &.{},
        );

        self.ws_fd.store(ws.stream.handle, .release);
        self.connected.store(true, .release);
        defer {
            self.connected.store(false, .release);
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        var event_buffers: std.StringHashMapUnmanaged(LarkWsEventBuffer) = .empty;
        defer deinitLarkWsEventBuffers(self.allocator, &event_buffers);

        var ping_interval_ms = AtomicU32.init(connect_cfg.ping_interval_ms);
        var ping_thread: ?std.Thread = null;
        var ping_ctx: LarkWsPingLoopCtx = undefined;
        if (connect_parts.service_id) |service_id| {
            ping_ctx = .{
                .ws = &ws,
                .running = &self.running,
                .ping_interval_ms = &ping_interval_ms,
                .service_id = service_id,
            };
            ping_thread = std.Thread.spawn(.{}, larkWsPingLoop, .{&ping_ctx}) catch |err| blk: {
                log.warn("lark websocket ping loop spawn failed: {}", .{err});
                break :blk null;
            };
        }
        defer if (ping_thread) |t| t.join();

        while (self.running.load(.acquire)) {
            const maybe_message = ws.readMessage() catch |err| {
                const err_name = @errorName(err);
                if (std.mem.eql(u8, err_name, "ConnectionClosed") or std.mem.eql(u8, err_name, "EndOfStream")) {
                    log.info("lark websocket closed by remote, reconnecting", .{});
                } else {
                    log.warn("lark websocket read failed: {}", .{err});
                }
                break;
            };
            if (maybe_message == null) break;
            const message = maybe_message.?;
            defer self.allocator.free(message.payload);

            switch (message.opcode) {
                .text => self.handleLegacyWebsocketPayload(&ws, message.payload) catch |err| {
                    log.warn("lark websocket text payload handling failed: {}", .{err});
                },
                .binary => self.handleBinaryWebsocketPayload(&ws, message.payload, &event_buffers, &ping_interval_ms) catch |err| {
                    log.warn("lark websocket binary payload handling failed: {}", .{err});
                },
                else => {},
            }
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
        self.ws_thread = std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, websocketLoop, .{self}) catch |err| {
            self.running.store(false, .release);
            return err;
        };
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.connected.store(false, .release);

        const fd = self.ws_fd.swap(invalid_socket, .acq_rel);
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

        self.resetOwnedState();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
        self.deletePendingReaction(target);
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *LarkChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichMessage(target, payload);
        self.deletePendingReaction(target);
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
        .sendRich = &vtableSendRich,
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
    message_id: []const u8 = &.{},

    pub fn deinit(self: *ParsedLarkMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
        if (self.message_id.len > 0) allocator.free(self.message_id);
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

fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |entry| {
        const eq_idx = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..eq_idx], key)) return entry[eq_idx + 1 ..];
    }
    return null;
}

fn protoReadVarint(bytes: []const u8, index: *usize) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (index.* < bytes.len and shift < 64) {
        const byte = bytes[index.*];
        index.* += 1;
        result |= (@as(u64, byte & 0x7F) << shift);
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
    return error.LarkApiError;
}

fn protoReadLengthDelimited(bytes: []const u8, index: *usize) ![]const u8 {
    const raw_len = try protoReadVarint(bytes, index);
    const len: usize = std.math.cast(usize, raw_len) orelse return error.LarkApiError;
    if (index.* + len > bytes.len) return error.LarkApiError;
    const out = bytes[index.* .. index.* + len];
    index.* += len;
    return out;
}

fn protoSkipField(bytes: []const u8, index: *usize, wire_type: u64) !void {
    switch (wire_type) {
        0 => _ = try protoReadVarint(bytes, index),
        2 => _ = try protoReadLengthDelimited(bytes, index),
        else => return error.LarkApiError,
    }
}

fn decodeLarkWsHeader(bytes: []const u8) !LarkWsHeader {
    var index: usize = 0;
    var key: ?[]const u8 = null;
    var value: ?[]const u8 = null;

    while (index < bytes.len) {
        const tag = try protoReadVarint(bytes, &index);
        const field_number = tag >> 3;
        const wire_type = tag & 0x07;

        switch (field_number) {
            1 => {
                if (wire_type != 2) return error.LarkApiError;
                key = try protoReadLengthDelimited(bytes, &index);
            },
            2 => {
                if (wire_type != 2) return error.LarkApiError;
                value = try protoReadLengthDelimited(bytes, &index);
            },
            else => try protoSkipField(bytes, &index, wire_type),
        }
    }

    return .{
        .key = key orelse return error.LarkApiError,
        .value = value orelse return error.LarkApiError,
    };
}

fn decodeLarkWsFrame(allocator: std.mem.Allocator, bytes: []const u8) !LarkWsFrame {
    var index: usize = 0;
    var headers: std.ArrayListUnmanaged(LarkWsHeader) = .empty;
    errdefer headers.deinit(allocator);

    var seq_id: u64 = 0;
    var log_id: u64 = 0;
    var service: i32 = 0;
    var method: i32 = 0;
    var payload_encoding: ?[]const u8 = null;
    var payload_type: ?[]const u8 = null;
    var payload: []const u8 = &.{};
    var log_id_new: ?[]const u8 = null;

    var saw_seq_id = false;
    var saw_log_id = false;
    var saw_service = false;
    var saw_method = false;

    while (index < bytes.len) {
        const tag = try protoReadVarint(bytes, &index);
        const field_number = tag >> 3;
        const wire_type = tag & 0x07;

        switch (field_number) {
            1 => {
                if (wire_type != 0) return error.LarkApiError;
                seq_id = try protoReadVarint(bytes, &index);
                saw_seq_id = true;
            },
            2 => {
                if (wire_type != 0) return error.LarkApiError;
                log_id = try protoReadVarint(bytes, &index);
                saw_log_id = true;
            },
            3 => {
                if (wire_type != 0) return error.LarkApiError;
                const raw = try protoReadVarint(bytes, &index);
                service = std.math.cast(i32, raw) orelse return error.LarkApiError;
                saw_service = true;
            },
            4 => {
                if (wire_type != 0) return error.LarkApiError;
                const raw = try protoReadVarint(bytes, &index);
                method = std.math.cast(i32, raw) orelse return error.LarkApiError;
                saw_method = true;
            },
            5 => {
                if (wire_type != 2) return error.LarkApiError;
                const header_bytes = try protoReadLengthDelimited(bytes, &index);
                try headers.append(allocator, try decodeLarkWsHeader(header_bytes));
            },
            6 => {
                if (wire_type != 2) return error.LarkApiError;
                payload_encoding = try protoReadLengthDelimited(bytes, &index);
            },
            7 => {
                if (wire_type != 2) return error.LarkApiError;
                payload_type = try protoReadLengthDelimited(bytes, &index);
            },
            8 => {
                if (wire_type != 2) return error.LarkApiError;
                payload = try protoReadLengthDelimited(bytes, &index);
            },
            9 => {
                if (wire_type != 2) return error.LarkApiError;
                log_id_new = try protoReadLengthDelimited(bytes, &index);
            },
            else => try protoSkipField(bytes, &index, wire_type),
        }
    }

    if (!saw_seq_id or !saw_log_id or !saw_service or !saw_method) return error.LarkApiError;

    return .{
        .seq_id = seq_id,
        .log_id = log_id,
        .service = service,
        .method = method,
        .headers = try headers.toOwnedSlice(allocator),
        .payload_encoding = payload_encoding,
        .payload_type = payload_type,
        .payload = payload,
        .log_id_new = log_id_new,
    };
}

fn protoWriteVarint(writer: anytype, value: u64) !void {
    var tmp = value;
    while (true) {
        var byte: u8 = @intCast(tmp & 0x7F);
        tmp >>= 7;
        if (tmp != 0) byte |= 0x80;
        try writer.writeByte(byte);
        if (tmp == 0) break;
    }
}

fn protoWriteTag(writer: anytype, field_number: u32, wire_type: u3) !void {
    try protoWriteVarint(writer, (@as(u64, field_number) << 3) | wire_type);
}

fn protoWriteU64(writer: anytype, field_number: u32, value: u64) !void {
    try protoWriteTag(writer, field_number, 0);
    try protoWriteVarint(writer, value);
}

fn protoWriteInt32(writer: anytype, field_number: u32, value: i32) !void {
    if (value < 0) return error.LarkApiError;
    try protoWriteU64(writer, field_number, @intCast(value));
}

fn protoWriteBytes(writer: anytype, field_number: u32, value: []const u8) !void {
    try protoWriteTag(writer, field_number, 2);
    try protoWriteVarint(writer, value.len);
    try writer.writeAll(value);
}

fn protoWriteString(writer: anytype, field_number: u32, value: []const u8) !void {
    try protoWriteBytes(writer, field_number, value);
}

fn protoWriteHeader(writer: anytype, key: []const u8, value: []const u8) !void {
    var header_buf: [1024]u8 = undefined;
    var header_fbs = std.io.fixedBufferStream(&header_buf);
    const header_writer = header_fbs.writer();
    try protoWriteString(header_writer, 1, key);
    try protoWriteString(header_writer, 2, value);
    try protoWriteBytes(writer, 5, header_fbs.getWritten());
}

fn larkWsHeaderValue(headers: []const LarkWsHeader, key: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.key, key)) return header.value;
    }
    return null;
}

fn isCardActionEventType(event_type: []const u8) bool {
    return std.mem.eql(u8, event_type, "card.action.trigger") or
        std.mem.eql(u8, event_type, "card.action.trigger_v1");
}

fn isCardActionPayload(payload: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, payload, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const header_val = parsed.value.object.get("header") orelse return false;
    if (header_val != .object) return false;
    const event_type_val = header_val.object.get("event_type") orelse return false;
    if (event_type_val != .string) return false;
    return isCardActionEventType(event_type_val.string);
}

fn isCardActionAllowed(self: *const LarkChannel, event: std.json.Value) bool {
    if (LarkChannel.extractCardActionOpenId(event)) |open_id| {
        return self.isUserAllowed(open_id);
    }
    return root.isAllowedExact(self.allow_from, "*");
}

fn buildLarkWsAckPayload(
    allocator: std.mem.Allocator,
    callback_response_json: ?[]const u8,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try writer.writeAll("{\"code\":200,\"headers\":null,\"data\":");
    if (callback_response_json) |raw| {
        const encoded_len = std.base64.standard.Encoder.calcSize(raw.len);
        const encoded_buf = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded_buf);
        const encoded = std.base64.standard.Encoder.encode(encoded_buf, raw);
        try root.appendJsonStringW(writer, encoded);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}");
    return out.toOwnedSlice(allocator);
}

fn buildLarkWsPingFrame(buf: []u8, service_id: i32) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();
    try protoWriteU64(writer, 1, 0);
    try protoWriteU64(writer, 2, 0);
    try protoWriteInt32(writer, 3, service_id);
    try protoWriteInt32(writer, 4, LARK_WS_METHOD_CONTROL);
    try protoWriteHeader(writer, "type", "ping");
    return fbs.getWritten();
}

fn buildLarkWsEventAckFrame(
    allocator: std.mem.Allocator,
    frame: LarkWsFrame,
    biz_rt_ms: u64,
    ack_payload: []const u8,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try protoWriteU64(writer, 1, frame.seq_id);
    try protoWriteU64(writer, 2, frame.log_id);
    try protoWriteInt32(writer, 3, frame.service);
    try protoWriteInt32(writer, 4, frame.method);
    for (frame.headers) |header| {
        try protoWriteHeader(writer, header.key, header.value);
    }

    var biz_rt_buf: [32]u8 = undefined;
    const biz_rt = std.fmt.bufPrint(&biz_rt_buf, "{d}", .{biz_rt_ms}) catch return error.LarkApiError;
    try protoWriteHeader(writer, "biz_rt", biz_rt);

    if (frame.payload_encoding) |payload_encoding| {
        try protoWriteString(writer, 6, payload_encoding);
    }
    if (frame.payload_type) |payload_type| {
        try protoWriteString(writer, 7, payload_type);
    }
    try protoWriteBytes(writer, 8, ack_payload);
    if (frame.log_id_new) |log_id_new| {
        try protoWriteString(writer, 9, log_id_new);
    }
    return out.toOwnedSlice(allocator);
}

fn updatePingIntervalFromControlPayload(ping_interval_ms: *AtomicU32, payload: []const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, payload, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const ping_val = parsed.value.object.get("PingInterval") orelse return;
    const ping_secs = switch (ping_val) {
        .integer => |v| if (v > 0) @as(u64, @intCast(v)) else return,
        .float => |v| if (v > 0) @as(u64, @intFromFloat(v)) else return,
        else => return,
    };
    const ping_interval_ms_value = std.math.cast(u32, ping_secs * std.time.ms_per_s) orelse return;
    ping_interval_ms.store(ping_interval_ms_value, .release);
}

fn cleanupExpiredLarkWsEventBuffers(
    allocator: std.mem.Allocator,
    event_buffers: *std.StringHashMapUnmanaged(LarkWsEventBuffer),
    now_ms: i64,
) !void {
    var stale_keys: std.ArrayListUnmanaged([]const u8) = .empty;
    defer stale_keys.deinit(allocator);

    var it = event_buffers.iterator();
    while (it.next()) |entry| {
        if (now_ms - entry.value_ptr.created_at_ms > EVENT_CACHE_TTL_MS) {
            try stale_keys.append(allocator, entry.key_ptr.*);
        }
    }

    for (stale_keys.items) |key| {
        if (event_buffers.fetchRemove(key)) |entry| {
            var value = entry.value;
            value.deinit(allocator);
            allocator.free(@constCast(entry.key));
        }
    }
}

fn mergeLarkWsEventPayload(
    allocator: std.mem.Allocator,
    event_buffers: *std.StringHashMapUnmanaged(LarkWsEventBuffer),
    frame: LarkWsFrame,
) !?[]u8 {
    try cleanupExpiredLarkWsEventBuffers(allocator, event_buffers, std.time.milliTimestamp());

    const message_id = larkWsHeaderValue(frame.headers, "message_id") orelse {
        if (frame.payload.len == 0) return null;
        return try allocator.dupe(u8, frame.payload);
    };
    const sum_raw = larkWsHeaderValue(frame.headers, "sum") orelse {
        if (frame.payload.len == 0) return null;
        return try allocator.dupe(u8, frame.payload);
    };
    const seq_raw = larkWsHeaderValue(frame.headers, "seq") orelse {
        if (frame.payload.len == 0) return null;
        return try allocator.dupe(u8, frame.payload);
    };

    const sum = std.fmt.parseInt(usize, sum_raw, 10) catch return error.LarkApiError;
    const seq = std.fmt.parseInt(usize, seq_raw, 10) catch return error.LarkApiError;
    if (sum <= 1) {
        if (frame.payload.len == 0) return null;
        return try allocator.dupe(u8, frame.payload);
    }
    if (seq >= sum) return error.LarkApiError;

    const trace_id = larkWsHeaderValue(frame.headers, "trace_id") orelse "";
    const gop = try event_buffers.getOrPut(allocator, message_id);
    if (!gop.found_existing) {
        const key_copy = try allocator.dupe(u8, message_id);
        errdefer allocator.free(key_copy);

        const trace_id_copy = try allocator.dupe(u8, trace_id);
        errdefer allocator.free(trace_id_copy);

        const parts = try allocator.alloc(?[]u8, sum);
        errdefer allocator.free(parts);
        for (parts) |*part| part.* = null;

        gop.key_ptr.* = key_copy;
        gop.value_ptr.* = .{
            .trace_id = trace_id_copy,
            .parts = parts,
            .created_at_ms = std.time.milliTimestamp(),
        };
    } else if (gop.value_ptr.parts.len != sum) {
        gop.value_ptr.deinit(allocator);

        const trace_id_copy = try allocator.dupe(u8, trace_id);
        errdefer allocator.free(trace_id_copy);

        const parts = try allocator.alloc(?[]u8, sum);
        errdefer allocator.free(parts);
        for (parts) |*part| part.* = null;

        gop.value_ptr.* = .{
            .trace_id = trace_id_copy,
            .parts = parts,
            .created_at_ms = std.time.milliTimestamp(),
        };
    }

    if (gop.value_ptr.parts[seq]) |existing| allocator.free(existing);
    gop.value_ptr.parts[seq] = try allocator.dupe(u8, frame.payload);

    for (gop.value_ptr.parts) |part| {
        if (part == null) return null;
    }

    var merged: std.ArrayListUnmanaged(u8) = .empty;
    defer merged.deinit(allocator);
    for (gop.value_ptr.parts) |part| {
        try merged.appendSlice(allocator, part.?);
    }
    const merged_payload = try merged.toOwnedSlice(allocator);

    if (event_buffers.fetchRemove(message_id)) |entry| {
        var value = entry.value;
        value.deinit(allocator);
        allocator.free(@constCast(entry.key));
    }

    return merged_payload;
}

fn deinitLarkWsEventBuffers(
    allocator: std.mem.Allocator,
    event_buffers: *std.StringHashMapUnmanaged(LarkWsEventBuffer),
) void {
    var it = event_buffers.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.deinit(allocator);
        allocator.free(entry.key_ptr.*);
    }
    event_buffers.deinit(allocator);
}

fn larkWsPingLoop(ctx: *LarkWsPingLoopCtx) void {
    while (ctx.running.load(.acquire)) {
        const interval_ms = blk: {
            const current = ctx.ping_interval_ms.load(.acquire);
            break :blk if (current > 0) current else DEFAULT_LARK_PING_INTERVAL_MS;
        };

        var waited_ms: u32 = 0;
        while (waited_ms < interval_ms and ctx.running.load(.acquire)) {
            const step_ms: u32 = @min(interval_ms - waited_ms, @as(u32, 1000));
            std.Thread.sleep(@as(u64, step_ms) * std.time.ns_per_ms);
            waited_ms += step_ms;
        }
        if (!ctx.running.load(.acquire)) break;

        var ping_buf: [256]u8 = undefined;
        const ping = buildLarkWsPingFrame(&ping_buf, ctx.service_id) catch {
            log.warn("lark websocket ping build failed", .{});
            continue;
        };
        ctx.ws.writeBinary(ping) catch |err| {
            if (ctx.running.load(.acquire)) {
                log.warn("lark websocket ping failed: {}", .{err});
            }
            break;
        };
    }
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

test "lark buildWebsocketConfigUrl follows region" {
    var ch = LarkChannel.init(std.testing.allocator, "id", "secret", "token", 9898, &.{});
    ch.use_feishu = true;
    var feishu_buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "https://open.feishu.cn/callback/ws/endpoint",
        try ch.buildWebsocketConfigUrl(&feishu_buf),
    );

    ch.use_feishu = false;
    var lark_buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "https://open.larksuite.com/callback/ws/endpoint",
        try ch.buildWebsocketConfigUrl(&lark_buf),
    );
}

test "lark buildWebsocketConfigBody uses official field names" {
    var buf: [256]u8 = undefined;
    const body = try LarkChannel.buildWebsocketConfigBody(&buf, "cli_app", "sec_123");
    try std.testing.expectEqualStrings("{\"AppID\":\"cli_app\",\"AppSecret\":\"sec_123\"}", body);
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

test "lark messageSuggestsPermissionIssue matches english keywords" {
    try std.testing.expect(LarkChannel.messageSuggestsPermissionIssue("forbidden: missing permission scope"));
    try std.testing.expect(LarkChannel.messageSuggestsPermissionIssue("Unauthorized app scope"));
    try std.testing.expect(!LarkChannel.messageSuggestsPermissionIssue("request timeout"));
}

test "lark messageSuggestsPermissionIssue matches chinese keyword" {
    try std.testing.expect(LarkChannel.messageSuggestsPermissionIssue("需要开放权限"));
}

test "lark validateBusinessResponse accepts success code" {
    try LarkChannel.validateBusinessResponse(std.testing.allocator, "send_message", "{\"code\":0,\"msg\":\"ok\"}");
}

test "lark validateBusinessResponse rejects nonzero code" {
    try std.testing.expectError(
        error.LarkApiError,
        LarkChannel.validateBusinessResponse(std.testing.allocator, "send_message", "{\"code\":999,\"msg\":\"forbidden\"}"),
    );
}

test "lark buildRichCardContent preserves submit text for choice buttons" {
    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "Confirm action" },
        .{ .id = "no", .label = "No", .submit_text = "Cancel action" },
    };

    var buf: [4096]u8 = undefined;
    const body = try LarkChannel.buildRichCardContent(&buf, .{
        .text = "Pick one option.",
        .choices = &choices,
    });

    try std.testing.expect(std.mem.indexOf(u8, body, "\"submit_text\":\"Confirm action\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"choice_id\":\"yes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"content\":\"Yes\"") != null);
}

test "lark buildRichCardContent uses action group button ids directly" {
    const buttons = [_]outbound.ActionButton{
        .{ .id = "approve", .label = "Approve" },
    };
    const groups = [_]outbound.ActionGroup{.{ .actions = &buttons }};

    var buf: [4096]u8 = undefined;
    const body = try LarkChannel.buildRichCardContent(&buf, .{
        .card_title = "Review",
        .action_groups = &groups,
    });

    try std.testing.expect(std.mem.indexOf(u8, body, "\"choice_id\":\"approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"content\":\"Approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"submit_text\"") == null);
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

test "lark extractWebsocketConnectUrl parses official response shape" {
    const allocator = std.testing.allocator;
    const resp =
        \\{"code":0,"data":{"URL":"wss://ws-client.feishu.cn/ws/?app_id=cli_xxx&device_id=dev1","ClientConfig":{"PingInterval":30}}}
    ;
    const url = try LarkChannel.extractWebsocketConnectUrl(allocator, resp);
    defer allocator.free(url);
    try std.testing.expectEqualStrings("wss://ws-client.feishu.cn/ws/?app_id=cli_xxx&device_id=dev1", url);
}

test "lark extractWebsocketConnectConfig captures ping interval" {
    const allocator = std.testing.allocator;
    const resp =
        \\{"code":0,"data":{"URL":"wss://ws-client.feishu.cn/ws/?app_id=cli_xxx&device_id=dev1&service_id=7","ClientConfig":{"PingInterval":45}}}
    ;
    var cfg = try LarkChannel.extractWebsocketConnectConfig(allocator, resp);
    defer cfg.deinit(allocator);
    try std.testing.expectEqualStrings("wss://ws-client.feishu.cn/ws/?app_id=cli_xxx&device_id=dev1&service_id=7", cfg.url);
    try std.testing.expectEqual(@as(u32, 45 * std.time.ms_per_s), cfg.ping_interval_ms);
}

test "lark parseWebsocketConnectUrl extracts host port and path" {
    var host_buf: [256]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const parsed = try LarkChannel.parseWebsocketConnectUrl(
        "wss://ws-client.feishu.cn/v1/ws?app_id=cli_xxx&device_id=dev1&service_id=7",
        &host_buf,
        &path_buf,
    );
    try std.testing.expectEqualStrings("ws-client.feishu.cn", parsed.host);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
    try std.testing.expectEqualStrings("/v1/ws?app_id=cli_xxx&device_id=dev1&service_id=7", parsed.path);
    try std.testing.expectEqual(@as(?i32, 7), parsed.service_id);
}

test "lark protobuf ping frame round-trips" {
    var buf: [256]u8 = undefined;
    const encoded = try buildLarkWsPingFrame(&buf, 9);
    var frame = try decodeLarkWsFrame(std.testing.allocator, encoded);
    defer frame.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), frame.seq_id);
    try std.testing.expectEqual(@as(u64, 0), frame.log_id);
    try std.testing.expectEqual(@as(i32, 9), frame.service);
    try std.testing.expectEqual(@as(i32, LARK_WS_METHOD_CONTROL), frame.method);
    try std.testing.expectEqualStrings("ping", larkWsHeaderValue(frame.headers, "type").?);
}

test "lark mergeLarkWsEventPayload merges chunked protobuf payload" {
    const allocator = std.testing.allocator;
    var event_buffers: std.StringHashMapUnmanaged(LarkWsEventBuffer) = .empty;
    defer deinitLarkWsEventBuffers(allocator, &event_buffers);

    const headers_0 = [_]LarkWsHeader{
        .{ .key = "type", .value = "event" },
        .{ .key = "message_id", .value = "msg-1" },
        .{ .key = "sum", .value = "2" },
        .{ .key = "seq", .value = "0" },
        .{ .key = "trace_id", .value = "trace-1" },
    };
    const headers_1 = [_]LarkWsHeader{
        .{ .key = "type", .value = "event" },
        .{ .key = "message_id", .value = "msg-1" },
        .{ .key = "sum", .value = "2" },
        .{ .key = "seq", .value = "1" },
        .{ .key = "trace_id", .value = "trace-1" },
    };

    const frame_0 = LarkWsFrame{
        .seq_id = 1,
        .log_id = 2,
        .service = 3,
        .method = LARK_WS_METHOD_DATA,
        .headers = @constCast(headers_0[0..]),
        .payload = "{\"foo\":",
    };
    const frame_1 = LarkWsFrame{
        .seq_id = 1,
        .log_id = 2,
        .service = 3,
        .method = LARK_WS_METHOD_DATA,
        .headers = @constCast(headers_1[0..]),
        .payload = "1}",
    };

    const maybe_first = try mergeLarkWsEventPayload(allocator, &event_buffers, frame_0);
    try std.testing.expect(maybe_first == null);

    const merged = (try mergeLarkWsEventPayload(allocator, &event_buffers, frame_1)).?;
    defer allocator.free(merged);
    try std.testing.expectEqualStrings("{\"foo\":1}", merged);
}

test "lark protobuf event ack preserves frame metadata" {
    const headers = [_]LarkWsHeader{
        .{ .key = "type", .value = "event" },
        .{ .key = "message_id", .value = "msg-1" },
    };
    const src = LarkWsFrame{
        .seq_id = 11,
        .log_id = 22,
        .service = 33,
        .method = LARK_WS_METHOD_DATA,
        .headers = @constCast(headers[0..]),
        .payload_encoding = "json",
        .payload_type = "application/json",
        .log_id_new = "log-new",
    };

    const encoded = try buildLarkWsEventAckFrame(
        std.testing.allocator,
        src,
        17,
        "{\"code\":200,\"headers\":null,\"data\":null}",
    );
    defer std.testing.allocator.free(encoded);
    var decoded = try decodeLarkWsFrame(std.testing.allocator, encoded);
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 11), decoded.seq_id);
    try std.testing.expectEqual(@as(u64, 22), decoded.log_id);
    try std.testing.expectEqual(@as(i32, 33), decoded.service);
    try std.testing.expectEqual(@as(i32, LARK_WS_METHOD_DATA), decoded.method);
    try std.testing.expectEqualStrings("{\"code\":200,\"headers\":null,\"data\":null}", decoded.payload);
    try std.testing.expectEqualStrings("json", decoded.payload_encoding.?);
    try std.testing.expectEqualStrings("application/json", decoded.payload_type.?);
    try std.testing.expectEqualStrings("log-new", decoded.log_id_new.?);
    try std.testing.expectEqualStrings("event", larkWsHeaderValue(decoded.headers, "type").?);
    try std.testing.expect(larkWsHeaderValue(decoded.headers, "biz_rt") != null);
}

test "lark websocket ack payload base64 encodes callback response" {
    const allocator = std.testing.allocator;
    const payload = try buildLarkWsAckPayload(allocator, "{\"toast\":{\"type\":\"success\"}}");
    defer allocator.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value == .object);
    try std.testing.expectEqual(@as(i64, 200), parsed.value.object.get("code").?.integer);
    try std.testing.expect(parsed.value.object.get("headers").? == .null);

    const data_val = parsed.value.object.get("data").?;
    try std.testing.expect(data_val == .string);

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_val.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_val.string);
    try std.testing.expectEqualStrings("{\"toast\":{\"type\":\"success\"}}", decoded);
}

test "lark protobuf event ack handles large callback payload" {
    const allocator = std.testing.allocator;
    const raw = try allocator.alloc(u8, 20_000);
    defer allocator.free(raw);
    @memset(raw, 'a');

    const callback_response = try std.fmt.allocPrint(
        allocator,
        "{{\"toast\":{{\"type\":\"success\",\"content\":\"{s}\"}}}}",
        .{raw},
    );
    defer allocator.free(callback_response);

    const ack_payload = try buildLarkWsAckPayload(allocator, callback_response);
    defer allocator.free(ack_payload);

    const headers = [_]LarkWsHeader{
        .{ .key = "type", .value = "event" },
    };
    const src = LarkWsFrame{
        .seq_id = 1,
        .log_id = 2,
        .service = 3,
        .method = LARK_WS_METHOD_DATA,
        .headers = @constCast(headers[0..]),
        .payload_encoding = "json",
        .payload_type = "application/json",
    };

    const encoded = try buildLarkWsEventAckFrame(allocator, src, 99, ack_payload);
    defer allocator.free(encoded);

    var decoded = try decodeLarkWsFrame(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings(ack_payload, decoded.payload);
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

test "lark parseEventPayload captures message_id for reactions" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"uuid":"uuid-123-456","header":{"event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_user"}},"message":{"message_id":"om_456","message_type":"text","content":"{\"text\":\"websocket message\"}","chat_id":"oc_chat","create_time":"1700000000000"}}}
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
    try std.testing.expectEqualStrings("om_456", msgs[0].message_id);
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

test "lark initFromConfig carries reaction emojis" {
    const cfg = config_types.LarkConfig{
        .account_id = "lark-reactions-test",
        .app_id = "cli_react",
        .app_secret = "sec_react",
        .reaction_emojis = &.{ "SMILE", "THUMBSUP" },
    };
    const ch = LarkChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqual(@as(usize, 2), ch.reaction_emojis.len);
    try std.testing.expectEqualStrings("SMILE", ch.reaction_emojis[0]);
    try std.testing.expectEqualStrings("THUMBSUP", ch.reaction_emojis[1]);
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

test "lark resetOwnedState keeps pending reactions FIFO and frees allocations" {
    const allocator = std.testing.allocator;
    var ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &.{});

    // Regression: multiple inbound messages in one chat must not overwrite or leak pending reactions.
    try ch.enqueuePendingReaction("chat-1", "msg-1");
    try ch.enqueuePendingReaction("chat-1", "msg-2");
    try ch.enqueuePendingReaction("chat-2", "msg-3");
    ch.cached_token = try allocator.dupe(u8, "cached_tok_123");
    ch.token_expires_at = std.time.timestamp() + 7200;

    try std.testing.expectEqual(@as(usize, 2), ch.pending_reactions.getPtr("chat-1").?.items.len);
    try std.testing.expectEqualStrings("msg-1", ch.pending_reactions.getPtr("chat-1").?.items[0]);
    try std.testing.expectEqualStrings("msg-2", ch.pending_reactions.getPtr("chat-1").?.items[1]);
    try std.testing.expectEqual(@as(usize, 1), ch.pending_reactions.getPtr("chat-2").?.items.len);

    ch.resetOwnedState();

    try std.testing.expect(ch.cached_token == null);
    try std.testing.expectEqual(@as(i64, 0), ch.token_expires_at);
    try std.testing.expect(ch.pending_reactions.get("chat-1") == null);
    try std.testing.expect(ch.pending_reactions.get("chat-2") == null);
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

test "lark parse card action trigger emits choice message" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_user"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger"},"event":{"operator":{"operator_id":{"open_id":"ou_user"}},"context":{"open_chat_id":"oc_chat_1","chat_type":"group"},"action":{"tag":"button","value":{"choice_id":"yes"}}}}
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
    try std.testing.expectEqualStrings("oc_chat_1", msgs[0].sender);
    try std.testing.expectEqualStrings("yes", msgs[0].content);
    try std.testing.expect(msgs[0].is_group);
}

test "lark parse card action trigger_v1 reads submit text" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_user"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger_v1"},"context":{"open_chat_id":"oc_chat_2"},"event":{"operator":{"operator_id":{"open_id":"ou_user"}},"action":{"tag":"button","value":{"submit_text":"confirm"}}}}
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
    try std.testing.expectEqualStrings("oc_chat_2", msgs[0].sender);
    try std.testing.expectEqualStrings("confirm", msgs[0].content);
}

test "lark parse direct card action trigger keeps direct route" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_user"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger"},"event":{"operator":{"operator_id":{"open_id":"ou_user"}},"context":{"open_chat_id":"oc_dm_1","chat_type":"p2p"},"action":{"tag":"button","value":{"choice_id":"yes"}}}}
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
    try std.testing.expectEqualStrings("oc_dm_1", msgs[0].sender);
    try std.testing.expectEqualStrings("yes", msgs[0].content);
    try std.testing.expect(!msgs[0].is_group);
}

test "lark parse card action trigger reads form value" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_user"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger"},"event":{"operator":{"operator_id":{"open_id":"ou_user"}},"context":{"open_chat_id":"oc_chat_3"},"action":{"tag":"form","form_value":{"choice_select":["picked"]}}}}
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
    try std.testing.expectEqualStrings("oc_chat_3", msgs[0].sender);
    try std.testing.expectEqualStrings("picked", msgs[0].content);
}

test "lark parse card action trigger without open id requires wildcard allowlist" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"*"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger"},"event":{"context":{"open_chat_id":"oc_chat_4","chat_type":"group"},"action":{"tag":"button","value":{"choice_id":"yes"}}}}
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
    try std.testing.expectEqualStrings("oc_chat_4", msgs[0].sender);
    try std.testing.expectEqualStrings("yes", msgs[0].content);
    try std.testing.expect(msgs[0].is_group);

    const response = (try ch.buildCardActionCallbackResponse(allocator, payload)).?;
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"toast\":{\"type\":\"success\"") != null);
}

test "lark build card action callback response returns raw card" {
    const allocator = std.testing.allocator;
    const users = [_][]const u8{"ou_user"};
    const ch = LarkChannel.init(allocator, "id", "secret", "token", 9898, &users);

    const payload =
        \\{"header":{"event_type":"card.action.trigger"},"event":{"operator":{"operator_id":{"open_id":"ou_user"}},"action":{"tag":"button","value":{"choice_id":"yes"}}}}
    ;

    const response = (try ch.buildCardActionCallbackResponse(allocator, payload)).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"toast\":{\"type\":\"success\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"card\":{\"type\":\"raw\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "yes") != null);
}
