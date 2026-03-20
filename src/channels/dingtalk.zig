const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");
const http_util = @import("../http_util.zig");
const platform = @import("../platform.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");

const log = std.log.scoped(.dingtalk);

const SocketFd = std.net.Stream.Handle;
const invalid_socket: SocketFd = switch (builtin.os.tag) {
    .windows => std.os.windows.ws2_32.INVALID_SOCKET,
    else => -1,
};

const OPEN_CONNECTION_URL = "https://api.dingtalk.com/v1.0/gateway/connections/open";
const ACCESS_TOKEN_URL = "https://api.dingtalk.com/v1.0/oauth2/accessToken";
const DOWNLOAD_FILE_URL = "https://api.dingtalk.com/v1.0/robot/messageFiles/download";
const AI_INTERACTION_SEND_URL = "https://api.dingtalk.com/v1.0/aiInteraction/send";
const AI_INTERACTION_PREPARE_URL = "https://api.dingtalk.com/v1.0/aiInteraction/prepare";
const AI_INTERACTION_UPDATE_URL = "https://api.dingtalk.com/v1.0/aiInteraction/update";
const AI_INTERACTION_FINISH_URL = "https://api.dingtalk.com/v1.0/aiInteraction/finish";
const CALLBACK_TOPIC = "/v1.0/im/bot/messages/get";
const SYSTEM_TOPIC_DISCONNECT = "disconnect";
const USER_AGENT = "nullclaw-dingtalk/0.1.0";
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;
const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;
const ATTACHMENT_CACHE_SUBDIR = "nullclaw_dingtalk_media";
const ATTACHMENT_MAX_BYTES: usize = 20 * 1024 * 1024;
const REPLY_TARGET_CAPACITY: usize = 4096;
const BASIC_CARD_SCHEMA_CONTENT_TYPE = "basic_card_schema";
const AI_CARD_CONTENT_TYPE = "ai_card";
const BASIC_CARD_SCHEMA_TITLE = "nullclaw";
const BASIC_CARD_SCHEMA_LOGO = "@lALPDfJ6V_FPDmvNAfTNAfQ";
const STREAMING_COMPONENT_TAG = "streamingComponent";

const AccessTokenResult = struct {
    token: []u8,
    expires_in: i64,
};

const StreamConnection = struct {
    endpoint: []u8,
    ticket: []u8,

    fn deinit(self: *StreamConnection, allocator: std.mem.Allocator) void {
        allocator.free(self.endpoint);
        allocator.free(self.ticket);
    }
};

const ParsedInboundMessage = struct {
    sender_id: []u8,
    reply_target: []u8,
    content: []u8,
    session_key: []u8,
    metadata_json: []u8,
    media: [][]u8,

    fn deinit(self: *ParsedInboundMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender_id);
        allocator.free(self.reply_target);
        allocator.free(self.content);
        allocator.free(self.session_key);
        allocator.free(self.metadata_json);
        for (self.media) |path| allocator.free(path);
        allocator.free(self.media);
    }
};

const SessionReplyTarget = struct {
    webhook_url: []u8,
    sender_staff_id: ?[]u8 = null,
    conversation_id: ?[]u8 = null,
    is_group: bool = false,
    expires_at_ms: i64 = 0,

    fn dupe(self: SessionReplyTarget, allocator: std.mem.Allocator) !SessionReplyTarget {
        return .{
            .webhook_url = try allocator.dupe(u8, self.webhook_url),
            .sender_staff_id = if (self.sender_staff_id) |staff_id|
                try allocator.dupe(u8, staff_id)
            else
                null,
            .conversation_id = if (self.conversation_id) |conversation_id|
                try allocator.dupe(u8, conversation_id)
            else
                null,
            .is_group = self.is_group,
            .expires_at_ms = self.expires_at_ms,
        };
    }

    fn deinit(self: *SessionReplyTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.webhook_url);
        if (self.sender_staff_id) |staff_id| allocator.free(staff_id);
        if (self.conversation_id) |conversation_id| allocator.free(conversation_id);
    }
};

const ProactiveTargetKind = enum {
    conversation,
    union_id,
};

const ProactiveTarget = struct {
    kind: ProactiveTargetKind,
    value: []const u8,
};

const StreamSession = struct {
    conversation_token: []u8,
    buffer: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *StreamSession, allocator: std.mem.Allocator) void {
        allocator.free(self.conversation_token);
        self.buffer.deinit(allocator);
    }
};

const ReplyTargetCache = struct {
    map: std.StringHashMapUnmanaged(SessionReplyTarget) = .empty,
    order: std.ArrayListUnmanaged([]u8) = .empty,
    mu: std.Thread.Mutex = .{},

    fn deinit(self: *ReplyTargetCache, allocator: std.mem.Allocator) void {
        self.mu.lock();
        defer self.mu.unlock();

        for (self.order.items) |key| {
            if (self.map.fetchRemove(key)) |entry| {
                var removed = entry.value;
                removed.deinit(allocator);
            }
            allocator.free(key);
        }
        self.order.deinit(allocator);
        self.map.deinit(allocator);
    }

    fn evictHalf(self: *ReplyTargetCache, allocator: std.mem.Allocator) void {
        if (self.order.items.len < REPLY_TARGET_CAPACITY) return;

        const remove_n = self.order.items.len / 2;
        var i: usize = 0;
        while (i < remove_n) : (i += 1) {
            const key = self.order.items[i];
            if (self.map.fetchRemove(key)) |entry| {
                var removed = entry.value;
                removed.deinit(allocator);
            }
            allocator.free(key);
        }

        const remaining = self.order.items.len - remove_n;
        std.mem.copyForwards([]u8, self.order.items[0..remaining], self.order.items[remove_n..]);
        self.order.items.len = remaining;
    }

    fn put(self: *ReplyTargetCache, allocator: std.mem.Allocator, key: []const u8, target: SessionReplyTarget) !void {
        self.mu.lock();
        defer self.mu.unlock();

        if (self.map.getPtr(key)) |existing| {
            existing.deinit(allocator);
            existing.* = try target.dupe(allocator);
            return;
        }

        self.evictHalf(allocator);

        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);
        const owned_target = try target.dupe(allocator);
        errdefer {
            var target_copy = owned_target;
            target_copy.deinit(allocator);
        }

        try self.map.put(allocator, owned_key, owned_target);
        errdefer _ = self.map.remove(owned_key);
        try self.order.append(allocator, owned_key);
    }

    fn getClone(self: *ReplyTargetCache, allocator: std.mem.Allocator, key: []const u8) !?SessionReplyTarget {
        self.mu.lock();
        defer self.mu.unlock();

        if (self.map.get(key)) |target| {
            return try target.dupe(allocator);
        }
        return null;
    }
};

fn component_as_slice(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |v| v,
        .percent_encoded => |v| v,
    };
}

fn status_code_is_success(code: u16) bool {
    return code >= 200 and code < 300;
}

fn json_string_from_obj(val: std.json.Value, key: []const u8) ?[]const u8 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return switch (field) {
        .string => |s| s,
        else => null,
    };
}

fn json_bool_from_obj(val: std.json.Value, key: []const u8) ?bool {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return switch (field) {
        .bool => |b| b,
        else => null,
    };
}

fn json_i64_from_obj(val: std.json.Value, key: []const u8) ?i64 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return switch (field) {
        .integer => |i| i,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn json_object_from_obj(val: std.json.Value, key: []const u8) ?std.json.Value {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return if (field == .object) field else null;
}

fn message_type_summary(msg_type: []const u8, file_name: ?[]const u8) []const u8 {
    if (std.mem.eql(u8, msg_type, "picture")) return "[picture]";
    if (std.mem.eql(u8, msg_type, "audio")) return "[audio]";
    if (std.mem.eql(u8, msg_type, "video")) return "[video]";
    if (std.mem.eql(u8, msg_type, "file")) {
        if (file_name) |name| {
            if (name.len > 0) return name;
        }
        return "[file]";
    }
    if (std.mem.eql(u8, msg_type, "unknownMsgType")) return "[unsupported dingtalk message]";
    return "[message]";
}

fn attachment_extension_from_type(msg_type: []const u8, file_name: ?[]const u8) []const u8 {
    if (file_name) |name| {
        if (std.fs.path.extension(name).len > 0) return std.fs.path.extension(name);
    }
    if (std.mem.eql(u8, msg_type, "picture")) return ".png";
    if (std.mem.eql(u8, msg_type, "audio")) return ".mp3";
    if (std.mem.eql(u8, msg_type, "video")) return ".mp4";
    if (std.mem.eql(u8, msg_type, "file")) return ".bin";
    return ".dat";
}

fn attachment_cache_dir_path(allocator: std.mem.Allocator) ![]u8 {
    const tmp_dir = try platform.getTempDir(allocator);
    defer allocator.free(tmp_dir);
    return std.fs.path.join(allocator, &.{ tmp_dir, ATTACHMENT_CACHE_SUBDIR });
}

fn ensure_attachment_cache_dir(cache_dir: []const u8) !void {
    std.fs.makeDirAbsolute(cache_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => try std.fs.cwd().makePath(cache_dir),
    };
}

fn append_query_escaped(writer: anytype, value: []const u8) !void {
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try writer.writeByte(ch);
        } else {
            try writer.print("%{X:0>2}", .{ch});
        }
    }
}

fn parse_endpoint_url(
    endpoint: []const u8,
    ticket: []const u8,
    host_buf: []u8,
    path_buf: []u8,
) !struct { host: []const u8, port: u16, path: []const u8 } {
    const uri = std.Uri.parse(endpoint) catch return error.DingTalkApiError;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "wss")) return error.DingTalkApiError;

    const host = uri.getHost(host_buf) catch return error.DingTalkApiError;
    const port = uri.port orelse 443;
    const raw_path = component_as_slice(uri.path);
    const raw_query = if (uri.query) |q| component_as_slice(q) else "";

    var fbs = std.io.fixedBufferStream(path_buf);
    const w = fbs.writer();
    if (raw_path.len == 0) {
        try w.writeByte('/');
    } else {
        if (raw_path[0] != '/') try w.writeByte('/');
        try w.writeAll(raw_path);
    }
    try w.writeByte('?');
    if (raw_query.len > 0) {
        try w.writeAll(raw_query);
        try w.writeByte('&');
    }
    try w.writeAll("ticket=");
    try append_query_escaped(w, ticket);

    return .{
        .host = host,
        .port = port,
        .path = fbs.getWritten(),
    };
}

fn build_open_connection_body(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    client_secret: []const u8,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"clientId\":");
    try root.json_util.appendJsonString(&body, allocator, client_id);
    try body.appendSlice(allocator, ",\"clientSecret\":");
    try root.json_util.appendJsonString(&body, allocator, client_secret);
    try body.appendSlice(allocator, ",\"subscriptions\":[{\"type\":\"CALLBACK\",\"topic\":\"");
    try body.appendSlice(allocator, CALLBACK_TOPIC);
    try body.appendSlice(allocator, "\"}],\"ua\":");
    try root.json_util.appendJsonString(&body, allocator, USER_AGENT);
    try body.appendSlice(allocator, "}");
    return body.toOwnedSlice(allocator);
}

fn parse_open_connection_response(allocator: std.mem.Allocator, resp_body: []const u8) !StreamConnection {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.DingTalkApiError;
    defer parsed.deinit();

    if (parsed.value != .object) return error.DingTalkApiError;
    const endpoint = json_string_from_obj(parsed.value, "endpoint") orelse return error.DingTalkApiError;
    const ticket = json_string_from_obj(parsed.value, "ticket") orelse return error.DingTalkApiError;
    if (endpoint.len == 0 or ticket.len == 0) return error.DingTalkApiError;

    return .{
        .endpoint = try allocator.dupe(u8, endpoint),
        .ticket = try allocator.dupe(u8, ticket),
    };
}

fn build_ack_json(
    allocator: std.mem.Allocator,
    code: u16,
    message_id: []const u8,
    message: []const u8,
    data_json: []const u8,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.writer(allocator).print("{{\"code\":{d},\"headers\":{{\"contentType\":\"application/json\",\"messageId\":", .{code});
    try root.json_util.appendJsonString(&body, allocator, message_id);
    try body.appendSlice(allocator, "},\"message\":");
    try root.json_util.appendJsonString(&body, allocator, message);
    try body.appendSlice(allocator, ",\"data\":");
    try root.json_util.appendJsonString(&body, allocator, data_json);
    try body.appendSlice(allocator, "}");
    return body.toOwnedSlice(allocator);
}

fn build_success_response_json(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);
    try body.appendSlice(allocator, "{\"response\":");
    try root.json_util.appendJsonString(&body, allocator, message);
    try body.appendSlice(allocator, "}");
    return body.toOwnedSlice(allocator);
}

fn build_response_null_json(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"response\":null}");
}

fn should_ack_system_topic(topic: []const u8) bool {
    // DingTalk disconnect notifications are advisory; the server closes the
    // socket after a short grace period and expects no ACK from the client.
    return !std.mem.eql(u8, topic, SYSTEM_TOPIC_DISCONNECT);
}

fn trim_prefix_ignore_case(text: []const u8, prefix: []const u8) ?[]const u8 {
    if (text.len < prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(text[0..prefix.len], prefix)) return null;
    return text[prefix.len..];
}

fn build_basic_card_schema_content(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");

    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"header\":{\"title\":{\"type\":\"text\",\"text\":");
    try root.json_util.appendJsonString(&body, allocator, BASIC_CARD_SCHEMA_TITLE);
    try body.appendSlice(allocator, "},\"logo\":");
    try root.json_util.appendJsonString(&body, allocator, BASIC_CARD_SCHEMA_LOGO);
    try body.appendSlice(allocator, "},\"contents\":[{\"type\":\"text\",\"text\":");
    try root.json_util.appendJsonString(&body, allocator, trimmed);
    try body.appendSlice(allocator, ",\"id\":\"content\"}]}");
    return body.toOwnedSlice(allocator);
}

fn build_ai_interaction_send_body(
    allocator: std.mem.Allocator,
    proactive_target: ProactiveTarget,
    text: []const u8,
) ![]u8 {
    const content = try build_basic_card_schema_content(allocator, text);
    defer allocator.free(content);

    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.append(allocator, '{');
    switch (proactive_target.kind) {
        .conversation => {
            try body.appendSlice(allocator, "\"openConversationId\":");
            try root.json_util.appendJsonString(&body, allocator, proactive_target.value);
        },
        .union_id => {
            try body.appendSlice(allocator, "\"unionId\":");
            try root.json_util.appendJsonString(&body, allocator, proactive_target.value);
        },
    }
    try body.appendSlice(allocator, ",\"contentType\":");
    try root.json_util.appendJsonString(&body, allocator, BASIC_CARD_SCHEMA_CONTENT_TYPE);
    try body.appendSlice(allocator, ",\"content\":");
    try root.json_util.appendJsonString(&body, allocator, content);
    try body.append(allocator, '}');
    return body.toOwnedSlice(allocator);
}

fn build_ai_card_prepare_content(allocator: std.mem.Allocator, template_id: []const u8) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"templateId\":");
    try root.json_util.appendJsonString(&body, allocator, template_id);
    try body.append(allocator, '}');
    return body.toOwnedSlice(allocator);
}

fn build_ai_card_streaming_content(
    allocator: std.mem.Allocator,
    template_id: []const u8,
    streaming_key: []const u8,
    text: []const u8,
    is_finalize: bool,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"templateId\":");
    try root.json_util.appendJsonString(&body, allocator, template_id);
    try body.appendSlice(allocator, ",\"cardData\":{\"key\":");
    try root.json_util.appendJsonString(&body, allocator, streaming_key);
    try body.appendSlice(allocator, ",\"value\":");
    try root.json_util.appendJsonString(&body, allocator, text);
    try body.appendSlice(allocator, ",\"isFinalize\":");
    try body.appendSlice(allocator, if (is_finalize) "true" else "false");
    try body.appendSlice(allocator, ",\"isFull\":true},\"options\":{\"componentTag\":");
    try root.json_util.appendJsonString(&body, allocator, STREAMING_COMPONENT_TAG);
    try body.appendSlice(allocator, "}}");
    return body.toOwnedSlice(allocator);
}

fn build_ai_interaction_prepare_body(
    allocator: std.mem.Allocator,
    proactive_target: ProactiveTarget,
    template_id: []const u8,
) ![]u8 {
    const content = try build_ai_card_prepare_content(allocator, template_id);
    defer allocator.free(content);

    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.append(allocator, '{');
    switch (proactive_target.kind) {
        .conversation => {
            try body.appendSlice(allocator, "\"openConversationId\":");
            try root.json_util.appendJsonString(&body, allocator, proactive_target.value);
        },
        .union_id => {
            try body.appendSlice(allocator, "\"unionId\":");
            try root.json_util.appendJsonString(&body, allocator, proactive_target.value);
        },
    }
    try body.appendSlice(allocator, ",\"contentType\":");
    try root.json_util.appendJsonString(&body, allocator, AI_CARD_CONTENT_TYPE);
    try body.appendSlice(allocator, ",\"content\":");
    try root.json_util.appendJsonString(&body, allocator, content);
    try body.append(allocator, '}');
    return body.toOwnedSlice(allocator);
}

fn build_ai_interaction_update_body(
    allocator: std.mem.Allocator,
    conversation_token: []const u8,
    content: []const u8,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"conversationToken\":");
    try root.json_util.appendJsonString(&body, allocator, conversation_token);
    try body.appendSlice(allocator, ",\"contentType\":");
    try root.json_util.appendJsonString(&body, allocator, AI_CARD_CONTENT_TYPE);
    try body.appendSlice(allocator, ",\"content\":");
    try root.json_util.appendJsonString(&body, allocator, content);
    try body.append(allocator, '}');
    return body.toOwnedSlice(allocator);
}

fn build_ai_interaction_finish_body(allocator: std.mem.Allocator, conversation_token: []const u8) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"conversationToken\":");
    try root.json_util.appendJsonString(&body, allocator, conversation_token);
    try body.append(allocator, '}');
    return body.toOwnedSlice(allocator);
}

fn parse_prepare_conversation_token(allocator: std.mem.Allocator, resp_body: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.DingTalkApiError;
    defer parsed.deinit();
    if (parsed.value != .object) return error.DingTalkApiError;

    if (json_object_from_obj(parsed.value, "result")) |result| {
        if (json_string_from_obj(result, "conversationToken")) |token| {
            return allocator.dupe(u8, token);
        }
    }
    if (json_string_from_obj(parsed.value, "conversationToken")) |token| {
        return allocator.dupe(u8, token);
    }
    return error.DingTalkApiError;
}

fn validate_ai_interaction_response(allocator: std.mem.Allocator, resp_body: []const u8) !void {
    if (resp_body.len == 0) return;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;

    const result = json_object_from_obj(parsed.value, "result") orelse return;
    if (json_bool_from_obj(result, "success")) |success| {
        if (!success) return error.DingTalkApiError;
    }
}

fn download_bytes_to_local(
    allocator: std.mem.Allocator,
    source_url: []const u8,
    msg_type: []const u8,
    file_name: ?[]const u8,
) !?[]u8 {
    if (comptime builtin.is_test) return null;
    if (!std.mem.startsWith(u8, source_url, "https://")) return null;

    const bytes = http_util.curlGetMaxBytes(allocator, source_url, &.{}, "30", ATTACHMENT_MAX_BYTES) catch return null;
    defer allocator.free(bytes);
    if (bytes.len == 0 or bytes.len > ATTACHMENT_MAX_BYTES) return null;

    const cache_dir = try attachment_cache_dir_path(allocator);
    defer allocator.free(cache_dir);
    ensure_attachment_cache_dir(cache_dir) catch return null;

    const ext = attachment_extension_from_type(msg_type, file_name);
    const ts: u64 = @intCast(@max(std.time.timestamp(), 0));
    const nonce = std.crypto.random.int(u64);

    var file_buf: [128]u8 = undefined;
    const file_name_part = std.fmt.bufPrint(&file_buf, "dingtalk_{d}_{x}{s}", .{ ts, nonce, ext }) catch return null;
    const local_path = try std.fs.path.join(allocator, &.{ cache_dir, file_name_part });

    const file = std.fs.createFileAbsolute(local_path, .{ .read = false, .truncate = true }) catch {
        allocator.free(local_path);
        return null;
    };
    defer file.close();
    file.writeAll(bytes) catch {
        allocator.free(local_path);
        return null;
    };

    return local_path;
}

/// DingTalk channel via Stream Mode WebSocket with session webhook replies.
pub const DingTalkChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    client_id: []const u8,
    client_secret: []const u8,
    allow_from: []const []const u8,
    ai_card_template_id: ?[]const u8 = null,
    ai_card_streaming_key: ?[]const u8 = null,
    event_bus: ?*bus.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ws_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    token_mu: std.Thread.Mutex = .{},
    access_token: ?[]u8 = null,
    token_expires_at: i64 = 0,
    reply_targets: ReplyTargetCache = .{},
    stream_sessions: std.StringHashMapUnmanaged(StreamSession) = .empty,
    stream_mu: std.Thread.Mutex = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        client_id: []const u8,
        client_secret: []const u8,
        allow_from: []const []const u8,
    ) DingTalkChannel {
        return .{
            .allocator = allocator,
            .client_id = client_id,
            .client_secret = client_secret,
            .allow_from = allow_from,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.DingTalkConfig) DingTalkChannel {
        var ch = init(allocator, cfg.client_id, cfg.client_secret, cfg.allow_from);
        ch.account_id = cfg.account_id;
        ch.ai_card_template_id = cfg.ai_card_template_id;
        ch.ai_card_streaming_key = cfg.ai_card_streaming_key;
        return ch;
    }

    pub fn channelName(_: *DingTalkChannel) []const u8 {
        return "dingtalk";
    }

    pub fn setBus(self: *DingTalkChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    fn stripAccountPrefix(self: *const DingTalkChannel, target: []const u8) ![]const u8 {
        const rest = trim_prefix_ignore_case(target, "dingtalk:") orelse return target;
        const sep = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidTarget;
        const account_id = std.mem.trim(u8, rest[0..sep], " \t\r\n");
        if (account_id.len == 0 or !std.mem.eql(u8, account_id, self.account_id)) {
            return error.InvalidTarget;
        }
        return std.mem.trim(u8, rest[sep + 1 ..], " \t\r\n");
    }

    fn parseProactiveTarget(self: *const DingTalkChannel, target: []const u8) !ProactiveTarget {
        var trimmed = std.mem.trim(u8, target, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidTarget;
        trimmed = try self.stripAccountPrefix(trimmed);
        if (trimmed.len == 0) return error.InvalidTarget;

        if (trim_prefix_ignore_case(trimmed, "conversation:")) |rest| {
            const value = std.mem.trim(u8, rest, " \t\r\n");
            if (value.len == 0) return error.InvalidTarget;
            return .{ .kind = .conversation, .value = value };
        }
        if (trim_prefix_ignore_case(trimmed, "group:")) |rest| {
            const value = std.mem.trim(u8, rest, " \t\r\n");
            if (value.len == 0) return error.InvalidTarget;
            return .{ .kind = .conversation, .value = value };
        }
        if (trim_prefix_ignore_case(trimmed, "union:")) |rest| {
            const value = std.mem.trim(u8, rest, " \t\r\n");
            if (value.len == 0) return error.InvalidTarget;
            return .{ .kind = .union_id, .value = value };
        }
        if (trim_prefix_ignore_case(trimmed, "user:")) |rest| {
            const value = std.mem.trim(u8, rest, " \t\r\n");
            if (value.len == 0) return error.InvalidTarget;
            return .{ .kind = .union_id, .value = value };
        }

        if (std.mem.indexOfScalar(u8, trimmed, ':') == null) {
            return .{ .kind = .conversation, .value = trimmed };
        }
        return error.InvalidTarget;
    }

    fn proactiveFallbackTarget(target: SessionReplyTarget) ?ProactiveTarget {
        if (!target.is_group) return null;
        if (target.conversation_id) |conversation_id| {
            return .{
                .kind = .conversation,
                .value = conversation_id,
            };
        }
        return null;
    }

    fn isSenderAllowed(self: *const DingTalkChannel, sender_id: []const u8, sender_staff_id: []const u8) bool {
        return root.isAllowedExactScoped("dingtalk channel", self.allow_from, sender_id) or
            (sender_staff_id.len > 0 and root.isAllowedExactScoped("dingtalk channel", self.allow_from, sender_staff_id));
    }

    pub fn healthCheck(self: *DingTalkChannel) bool {
        return self.running.load(.acquire) and self.connected.load(.acquire);
    }

    fn clearEphemeralState(self: *DingTalkChannel) void {
        self.token_mu.lock();
        if (self.access_token) |token| {
            self.allocator.free(token);
            self.access_token = null;
        }
        self.token_expires_at = 0;
        self.token_mu.unlock();

        self.stream_mu.lock();
        var stream_it = self.stream_sessions.iterator();
        while (stream_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.stream_sessions.deinit(self.allocator);
        self.stream_sessions = .empty;
        self.stream_mu.unlock();

        self.reply_targets.deinit(self.allocator);
        self.reply_targets = .{};
    }

    fn fetchAccessToken(self: *DingTalkChannel) !AccessTokenResult {
        if (comptime builtin.is_test) {
            return .{ .token = try self.allocator.dupe(u8, "test-access-token"), .expires_in = 7200 };
        }

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"appKey\":");
        try root.json_util.appendJsonString(&body, self.allocator, self.client_id);
        try body.appendSlice(self.allocator, ",\"appSecret\":");
        try root.json_util.appendJsonString(&body, self.allocator, self.client_secret);
        try body.appendSlice(self.allocator, "}");

        const resp = http_util.curlPostWithStatus(self.allocator, ACCESS_TOKEN_URL, body.items, &.{}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp.body, .{}) catch return error.DingTalkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.DingTalkApiError;

        const token = json_string_from_obj(parsed.value, "accessToken") orelse return error.DingTalkApiError;
        const expires_in = json_i64_from_obj(parsed.value, "expireIn") orelse 7200;
        if (token.len == 0) return error.DingTalkApiError;

        return .{
            .token = try self.allocator.dupe(u8, token),
            .expires_in = expires_in,
        };
    }

    fn ensureAccessToken(self: *DingTalkChannel) ![]u8 {
        self.token_mu.lock();
        defer self.token_mu.unlock();

        const now = std.time.timestamp();
        if (self.access_token) |token| {
            if (now < self.token_expires_at - TOKEN_REFRESH_MARGIN_SECS) {
                return self.allocator.dupe(u8, token);
            }
        }

        const result = try self.fetchAccessToken();
        if (self.access_token) |old| self.allocator.free(old);
        self.access_token = result.token;
        self.token_expires_at = now + result.expires_in;
        return self.allocator.dupe(u8, result.token);
    }

    fn openStreamConnection(self: *DingTalkChannel) !StreamConnection {
        const body = try build_open_connection_body(self.allocator, self.client_id, self.client_secret);
        defer self.allocator.free(body);

        const resp = http_util.curlPostWithStatus(self.allocator, OPEN_CONNECTION_URL, body, &.{}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;

        return parse_open_connection_response(self.allocator, resp.body);
    }

    fn resolveAttachmentUrl(
        self: *DingTalkChannel,
        robot_code: []const u8,
        download_code: []const u8,
    ) !?[]u8 {
        if (comptime builtin.is_test) return null;
        if (download_code.len == 0) return null;

        const token = try self.ensureAccessToken();
        defer self.allocator.free(token);

        var access_header_buf: [512]u8 = undefined;
        const access_header = std.fmt.bufPrint(
            &access_header_buf,
            "x-acs-dingtalk-access-token: {s}",
            .{token},
        ) catch return error.DingTalkApiError;

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"robotCode\":");
        try root.json_util.appendJsonString(&body, self.allocator, if (robot_code.len > 0) robot_code else self.client_id);
        try body.appendSlice(self.allocator, ",\"downloadCode\":");
        try root.json_util.appendJsonString(&body, self.allocator, download_code);
        try body.appendSlice(self.allocator, "}");

        const resp = http_util.curlPostWithStatus(self.allocator, DOWNLOAD_FILE_URL, body.items, &.{access_header}) catch return null;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return null;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp.body, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const download_url = json_string_from_obj(parsed.value, "downloadUrl") orelse return null;
        if (download_url.len == 0) return null;
        return @as(?[]u8, try self.allocator.dupe(u8, download_url));
    }

    fn maybeDownloadAttachment(
        self: *DingTalkChannel,
        msg_type: []const u8,
        robot_code: []const u8,
        content_obj: ?std.json.Value,
    ) !?[]u8 {
        if (content_obj == null) return null;
        const content = content_obj.?;

        const file_name = json_string_from_obj(content, "fileName");
        if (json_string_from_obj(content, "downloadUrl")) |direct_url| {
            return download_bytes_to_local(self.allocator, direct_url, msg_type, file_name);
        }
        if (json_string_from_obj(content, "downloadCode")) |download_code| {
            const download_url = try self.resolveAttachmentUrl(robot_code, download_code) orelse return null;
            defer self.allocator.free(download_url);
            return download_bytes_to_local(self.allocator, download_url, msg_type, file_name);
        }
        if (json_string_from_obj(content, "pictureDownloadCode")) |picture_download_code| {
            const download_url = try self.resolveAttachmentUrl(robot_code, picture_download_code) orelse return null;
            defer self.allocator.free(download_url);
            return download_bytes_to_local(self.allocator, download_url, msg_type, file_name);
        }
        return null;
    }

    fn appendTextPart(parts: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text: []const u8) !void {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len == 0) return;
        if (parts.items.len > 0) try parts.append(allocator, '\n');
        try parts.appendSlice(allocator, trimmed);
    }

    fn buildMetadataJson(
        self: *DingTalkChannel,
        allocator: std.mem.Allocator,
        sender_id: []const u8,
        sender_staff_id: []const u8,
        conversation_id: []const u8,
        conversation_type: []const u8,
        message_id: []const u8,
        robot_code: []const u8,
        session_webhook_expires_at: i64,
    ) ![]u8 {
        const peer_kind = if (std.mem.eql(u8, conversation_type, "2")) "group" else "direct";
        const direct_peer_id = if (sender_staff_id.len > 0) sender_staff_id else sender_id;
        const peer_id = if (std.mem.eql(u8, conversation_type, "2")) conversation_id else direct_peer_id;

        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"account_id\":");
        try root.json_util.appendJsonString(&body, allocator, self.account_id);
        try body.appendSlice(allocator, ",\"peer_kind\":");
        try root.json_util.appendJsonString(&body, allocator, peer_kind);
        try body.appendSlice(allocator, ",\"peer_id\":");
        try root.json_util.appendJsonString(&body, allocator, peer_id);
        try body.appendSlice(allocator, ",\"message_id\":");
        try root.json_util.appendJsonString(&body, allocator, message_id);
        try body.appendSlice(allocator, ",\"conversation_id\":");
        try root.json_util.appendJsonString(&body, allocator, conversation_id);
        try body.appendSlice(allocator, ",\"conversation_type\":");
        try root.json_util.appendJsonString(&body, allocator, conversation_type);
        try body.appendSlice(allocator, ",\"robot_code\":");
        try root.json_util.appendJsonString(&body, allocator, robot_code);
        try body.appendSlice(allocator, ",\"sender_id\":");
        try root.json_util.appendJsonString(&body, allocator, sender_id);
        try body.appendSlice(allocator, ",\"sender_staff_id\":");
        try root.json_util.appendJsonString(&body, allocator, sender_staff_id);
        try body.writer(allocator).print(",\"session_webhook_expires_at\":{d}}}", .{session_webhook_expires_at});
        return body.toOwnedSlice(allocator);
    }

    fn buildReplyBody(
        allocator: std.mem.Allocator,
        target: SessionReplyTarget,
        text: []const u8,
    ) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"msgtype\":\"text\",\"text\":{\"content\":");
        try root.json_util.appendJsonString(&body, allocator, text);
        try body.appendSlice(allocator, "}");
        if (target.is_group and target.sender_staff_id != null and target.sender_staff_id.?.len > 0) {
            try body.appendSlice(allocator, ",\"at\":{\"atUserIds\":[");
            try root.json_util.appendJsonString(&body, allocator, target.sender_staff_id.?);
            try body.appendSlice(allocator, "]}}");
        } else {
            try body.append(allocator, '}');
        }
        return body.toOwnedSlice(allocator);
    }

    fn sendViaSessionWebhook(self: *DingTalkChannel, target: SessionReplyTarget, text: []const u8) !void {
        const body = try buildReplyBody(self.allocator, target, text);
        defer self.allocator.free(body);

        if (comptime builtin.is_test) return;

        const resp = http_util.curlPostWithStatus(self.allocator, target.webhook_url, body, &.{}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;
    }

    fn sendViaAiInteraction(self: *DingTalkChannel, proactive_target: ProactiveTarget, text: []const u8) !void {
        const token = try self.ensureAccessToken();
        defer self.allocator.free(token);

        var access_header_buf: [512]u8 = undefined;
        const access_header = std.fmt.bufPrint(
            &access_header_buf,
            "x-acs-dingtalk-access-token: {s}",
            .{token},
        ) catch return error.DingTalkApiError;

        const body = try build_ai_interaction_send_body(self.allocator, proactive_target, text);
        defer self.allocator.free(body);

        if (comptime builtin.is_test) return;

        const resp = http_util.curlPostWithStatus(self.allocator, AI_INTERACTION_SEND_URL, body, &.{access_header}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;
        try validate_ai_interaction_response(self.allocator, resp.body);
    }

    fn prepareAiInteraction(self: *DingTalkChannel, proactive_target: ProactiveTarget) ![]u8 {
        const template_id = self.ai_card_template_id orelse return error.NotSupported;
        if (template_id.len == 0) return error.NotSupported;

        const token = try self.ensureAccessToken();
        defer self.allocator.free(token);

        var access_header_buf: [512]u8 = undefined;
        const access_header = std.fmt.bufPrint(
            &access_header_buf,
            "x-acs-dingtalk-access-token: {s}",
            .{token},
        ) catch return error.DingTalkApiError;

        const body = try build_ai_interaction_prepare_body(self.allocator, proactive_target, template_id);
        defer self.allocator.free(body);

        if (comptime builtin.is_test) {
            return self.allocator.dupe(u8, "test-conversation-token");
        }

        const resp = http_util.curlPostWithStatus(self.allocator, AI_INTERACTION_PREPARE_URL, body, &.{access_header}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;
        try validate_ai_interaction_response(self.allocator, resp.body);
        return parse_prepare_conversation_token(self.allocator, resp.body);
    }

    fn updateAiInteraction(self: *DingTalkChannel, conversation_token: []const u8, content: []const u8) !void {
        const token = try self.ensureAccessToken();
        defer self.allocator.free(token);

        var access_header_buf: [512]u8 = undefined;
        const access_header = std.fmt.bufPrint(
            &access_header_buf,
            "x-acs-dingtalk-access-token: {s}",
            .{token},
        ) catch return error.DingTalkApiError;

        const body = try build_ai_interaction_update_body(self.allocator, conversation_token, content);
        defer self.allocator.free(body);

        if (comptime builtin.is_test) return;

        const resp = http_util.curlPostWithStatus(self.allocator, AI_INTERACTION_UPDATE_URL, body, &.{access_header}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;
        try validate_ai_interaction_response(self.allocator, resp.body);
    }

    fn finishAiInteraction(self: *DingTalkChannel, conversation_token: []const u8) !void {
        const token = try self.ensureAccessToken();
        defer self.allocator.free(token);

        var access_header_buf: [512]u8 = undefined;
        const access_header = std.fmt.bufPrint(
            &access_header_buf,
            "x-acs-dingtalk-access-token: {s}",
            .{token},
        ) catch return error.DingTalkApiError;

        const body = try build_ai_interaction_finish_body(self.allocator, conversation_token);
        defer self.allocator.free(body);

        if (comptime builtin.is_test) return;

        const resp = http_util.curlPostWithStatus(self.allocator, AI_INTERACTION_FINISH_URL, body, &.{access_header}) catch return error.DingTalkApiError;
        defer self.allocator.free(resp.body);
        if (!status_code_is_success(resp.status_code)) return error.DingTalkApiError;
        try validate_ai_interaction_response(self.allocator, resp.body);
    }

    fn prepareAiInteractionForStreamingTarget(self: *DingTalkChannel, trimmed_target: []const u8) !?[]u8 {
        if (try self.reply_targets.getClone(self.allocator, trimmed_target)) |reply_target| {
            defer {
                var owned_reply_target = reply_target;
                owned_reply_target.deinit(self.allocator);
            }

            if (proactiveFallbackTarget(reply_target)) |proactive_target| {
                return try self.prepareAiInteraction(proactive_target);
            }
            return null;
        }

        if (std.mem.startsWith(u8, trimmed_target, "https://")) return null;

        const proactive_target = try self.parseProactiveTarget(trimmed_target);
        return try self.prepareAiInteraction(proactive_target);
    }

    fn sendEventMessage(
        self: *DingTalkChannel,
        target: []const u8,
        message: []const u8,
        media: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) !void {
        if (media.len > 0) {
            if (stage == .final) return self.sendMessage(target, message, media);
            return;
        }

        const trimmed_target = std.mem.trim(u8, target, " \t\r\n");
        if (trimmed_target.len == 0) return error.InvalidTarget;

        const template_id = self.ai_card_template_id orelse {
            if (stage == .final and message.len > 0) return self.sendMessage(trimmed_target, message, media);
            return;
        };
        const streaming_key = self.ai_card_streaming_key orelse {
            if (stage == .final and message.len > 0) return self.sendMessage(trimmed_target, message, media);
            return;
        };
        if (template_id.len == 0 or streaming_key.len == 0) {
            if (stage == .final and message.len > 0) return self.sendMessage(trimmed_target, message, media);
            return;
        }

        switch (stage) {
            .chunk => {
                if (message.len == 0) return;

                var conversation_token_copy: []u8 = undefined;
                var full_text_copy: []u8 = undefined;

                self.stream_mu.lock();
                if (self.stream_sessions.getPtr(trimmed_target)) |session| {
                    errdefer self.stream_mu.unlock();
                    try session.buffer.appendSlice(self.allocator, message);
                    conversation_token_copy = try self.allocator.dupe(u8, session.conversation_token);
                    errdefer self.allocator.free(conversation_token_copy);
                    full_text_copy = try self.allocator.dupe(u8, session.buffer.items);
                    self.stream_mu.unlock();
                } else {
                    self.stream_mu.unlock();

                    var pending_prepared_token: ?[]u8 = (try self.prepareAiInteractionForStreamingTarget(trimmed_target)) orelse return;
                    errdefer if (pending_prepared_token) |owned| self.allocator.free(owned);

                    self.stream_mu.lock();
                    errdefer self.stream_mu.unlock();

                    if (self.stream_sessions.getPtr(trimmed_target)) |session| {
                        self.allocator.free(pending_prepared_token.?);
                        pending_prepared_token = null;
                        try session.buffer.appendSlice(self.allocator, message);
                        conversation_token_copy = try self.allocator.dupe(u8, session.conversation_token);
                        errdefer self.allocator.free(conversation_token_copy);
                        full_text_copy = try self.allocator.dupe(u8, session.buffer.items);
                        self.stream_mu.unlock();
                    } else {
                        const owned_key = try self.allocator.dupe(u8, trimmed_target);
                        errdefer self.allocator.free(owned_key);
                        try self.stream_sessions.put(self.allocator, owned_key, .{
                            .conversation_token = pending_prepared_token.?,
                        });
                        errdefer {
                            if (self.stream_sessions.fetchRemove(trimmed_target)) |entry| {
                                self.allocator.free(entry.key);
                                var removed = entry.value;
                                removed.deinit(self.allocator);
                            }
                        }
                        pending_prepared_token = null;

                        const inserted = self.stream_sessions.getPtr(trimmed_target).?;
                        try inserted.buffer.appendSlice(self.allocator, message);
                        conversation_token_copy = try self.allocator.dupe(u8, inserted.conversation_token);
                        errdefer self.allocator.free(conversation_token_copy);
                        full_text_copy = try self.allocator.dupe(u8, inserted.buffer.items);
                        self.stream_mu.unlock();
                    }
                }

                errdefer self.allocator.free(conversation_token_copy);
                errdefer self.allocator.free(full_text_copy);
                const content = try build_ai_card_streaming_content(
                    self.allocator,
                    template_id,
                    streaming_key,
                    full_text_copy,
                    false,
                );
                defer self.allocator.free(content);
                defer self.allocator.free(conversation_token_copy);
                defer self.allocator.free(full_text_copy);
                try self.updateAiInteraction(conversation_token_copy, content);
            },
            .final => {
                self.stream_mu.lock();
                const removed = self.stream_sessions.fetchRemove(trimmed_target);
                self.stream_mu.unlock();

                if (removed) |entry| {
                    defer self.allocator.free(entry.key);
                    var session = entry.value;
                    defer session.deinit(self.allocator);

                    const final_text = if (message.len > 0) message else session.buffer.items;
                    if (final_text.len > 0) {
                        const content = try build_ai_card_streaming_content(
                            self.allocator,
                            template_id,
                            streaming_key,
                            final_text,
                            true,
                        );
                        defer self.allocator.free(content);
                        try self.updateAiInteraction(session.conversation_token, content);
                    }
                    try self.finishAiInteraction(session.conversation_token);
                    return;
                }

                if (message.len > 0) {
                    try self.sendMessage(trimmed_target, message, media);
                }
            },
        }
    }

    fn parseCallbackPayload(self: *DingTalkChannel, payload: []const u8) !?ParsedInboundMessage {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const sender_id = json_string_from_obj(parsed.value, "senderId") orelse return null;
        const sender_staff_id = json_string_from_obj(parsed.value, "senderStaffId") orelse "";
        if (!self.isSenderAllowed(sender_id, sender_staff_id)) return null;

        const conversation_id = json_string_from_obj(parsed.value, "conversationId") orelse return null;
        const conversation_type = json_string_from_obj(parsed.value, "conversationType") orelse "1";
        const session_webhook = json_string_from_obj(parsed.value, "sessionWebhook") orelse return null;
        const message_id = json_string_from_obj(parsed.value, "msgId") orelse return null;
        const robot_code = json_string_from_obj(parsed.value, "robotCode") orelse self.client_id;
        const message_type = json_string_from_obj(parsed.value, "msgtype") orelse return null;
        const session_webhook_expires_at = json_i64_from_obj(parsed.value, "sessionWebhookExpiredTime") orelse 0;
        const direct_peer_id = if (sender_staff_id.len > 0) sender_staff_id else sender_id;
        const is_group = std.mem.eql(u8, conversation_type, "2");

        if (is_group) {
            if (!(json_bool_from_obj(parsed.value, "isInAtList") orelse false)) {
                return null;
            }
        }

        var text_parts: std.ArrayListUnmanaged(u8) = .empty;
        defer text_parts.deinit(self.allocator);
        var media_paths: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (media_paths.items) |path| self.allocator.free(path);
            media_paths.deinit(self.allocator);
        }

        const text_obj = json_object_from_obj(parsed.value, "text");
        const content_obj = json_object_from_obj(parsed.value, "content");

        if (std.mem.eql(u8, message_type, "text")) {
            if (text_obj) |text_val| {
                if (json_string_from_obj(text_val, "content")) |content| {
                    try appendTextPart(&text_parts, self.allocator, content);
                }
            }
        } else if (std.mem.eql(u8, message_type, "richText")) {
            if (content_obj) |content_val| {
                if (content_val.object.get("richText")) |rich_text_val| {
                    if (rich_text_val == .array) {
                        for (rich_text_val.array.items) |item| {
                            if (item != .object) continue;
                            if (json_string_from_obj(item, "text")) |content| {
                                try appendTextPart(&text_parts, self.allocator, content);
                            }
                            const media_path = try self.maybeDownloadAttachment("picture", robot_code, item);
                            if (media_path) |path| {
                                try media_paths.append(self.allocator, path);
                            }
                        }
                    }
                }
            }
        } else if (std.mem.eql(u8, message_type, "unknownMsgType")) {
            if (content_obj) |content_val| {
                if (json_string_from_obj(content_val, "unknownMsgType")) |content| {
                    try appendTextPart(&text_parts, self.allocator, content);
                }
            }
        } else {
            const media_path = try self.maybeDownloadAttachment(message_type, robot_code, content_obj);
            if (media_path) |path| try media_paths.append(self.allocator, path);
            if (content_obj) |content_val| {
                if (json_string_from_obj(content_val, "text")) |content| {
                    try appendTextPart(&text_parts, self.allocator, content);
                } else if (json_string_from_obj(content_val, "fileName")) |file_name| {
                    try appendTextPart(&text_parts, self.allocator, file_name);
                }
            }
        }

        const summary_name = if (content_obj) |content_val| json_string_from_obj(content_val, "fileName") else null;
        const final_content = if (std.mem.trim(u8, text_parts.items, " \t\r\n").len > 0)
            try self.allocator.dupe(u8, std.mem.trim(u8, text_parts.items, " \t\r\n"))
        else
            try self.allocator.dupe(u8, message_type_summary(message_type, summary_name));
        errdefer self.allocator.free(final_content);

        const reply_target = try std.fmt.allocPrint(self.allocator, "dingtalk:{s}:reply:{s}", .{ self.account_id, message_id });
        errdefer self.allocator.free(reply_target);
        const session_key = if (is_group)
            try std.fmt.allocPrint(self.allocator, "dingtalk:{s}:group:{s}", .{ self.account_id, conversation_id })
        else
            try std.fmt.allocPrint(self.allocator, "dingtalk:{s}:direct:{s}", .{ self.account_id, conversation_id });
        errdefer self.allocator.free(session_key);

        const owned_sender_id = try self.allocator.dupe(u8, direct_peer_id);
        errdefer self.allocator.free(owned_sender_id);
        const metadata_json = try self.buildMetadataJson(
            self.allocator,
            sender_id,
            sender_staff_id,
            conversation_id,
            conversation_type,
            message_id,
            robot_code,
            session_webhook_expires_at,
        );
        errdefer self.allocator.free(metadata_json);
        const owned_media = try media_paths.toOwnedSlice(self.allocator);
        errdefer {
            for (owned_media) |path| self.allocator.free(path);
            self.allocator.free(owned_media);
        }

        var reply_state = SessionReplyTarget{
            .webhook_url = try self.allocator.dupe(u8, session_webhook),
            .sender_staff_id = if (sender_staff_id.len > 0) try self.allocator.dupe(u8, sender_staff_id) else null,
            .conversation_id = try self.allocator.dupe(u8, conversation_id),
            .is_group = is_group,
            .expires_at_ms = session_webhook_expires_at,
        };
        defer reply_state.deinit(self.allocator);
        try self.reply_targets.put(self.allocator, reply_target, reply_state);

        return .{
            .sender_id = owned_sender_id,
            .reply_target = reply_target,
            .content = final_content,
            .session_key = session_key,
            .metadata_json = metadata_json,
            .media = owned_media,
        };
    }

    fn publishInbound(self: *DingTalkChannel, msg: ParsedInboundMessage) !void {
        var owned = msg;
        defer owned.deinit(self.allocator);

        const inbound = try bus.makeInboundFull(
            self.allocator,
            "dingtalk",
            owned.sender_id,
            owned.reply_target,
            owned.content,
            owned.session_key,
            owned.media,
            owned.metadata_json,
        );
        errdefer inbound.deinit(self.allocator);

        if (self.event_bus) |eb| {
            try eb.publishInbound(inbound);
        } else {
            inbound.deinit(self.allocator);
        }
    }

    fn handleEnvelope(self: *DingTalkChannel, ws: *websocket.WsClient, payload: []const u8) !bool {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;

        const envelope_type = json_string_from_obj(parsed.value, "type") orelse return false;
        const headers = json_object_from_obj(parsed.value, "headers") orelse return false;
        const topic = json_string_from_obj(headers, "topic") orelse "";
        const message_id = json_string_from_obj(headers, "messageId") orelse "";
        const data_json = json_string_from_obj(parsed.value, "data") orelse "{}";

        if (std.mem.eql(u8, envelope_type, "SYSTEM")) {
            if (!should_ack_system_topic(topic)) return true;
            const ack = try build_ack_json(self.allocator, 200, message_id, "OK", data_json);
            defer self.allocator.free(ack);
            try ws.writeText(ack);
            return false;
        }

        if (std.mem.eql(u8, envelope_type, "CALLBACK")) {
            if (!std.mem.eql(u8, topic, CALLBACK_TOPIC)) {
                const not_supported = try build_response_null_json(self.allocator);
                defer self.allocator.free(not_supported);
                const ack = try build_ack_json(self.allocator, 404, message_id, "not_implemented", not_supported);
                defer self.allocator.free(ack);
                try ws.writeText(ack);
                return false;
            }

            const inbound = self.parseCallbackPayload(data_json) catch |err| {
                log.warn("dingtalk callback parse failed: {}", .{err});
                const failure = try build_response_null_json(self.allocator);
                defer self.allocator.free(failure);
                const ack = try build_ack_json(self.allocator, 500, message_id, "internal_error", failure);
                defer self.allocator.free(ack);
                try ws.writeText(ack);
                return false;
            };

            if (inbound) |msg| {
                self.publishInbound(msg) catch |err| {
                    log.warn("dingtalk publishInbound failed: {}", .{err});
                    const failure = try build_response_null_json(self.allocator);
                    defer self.allocator.free(failure);
                    const ack = try build_ack_json(self.allocator, 500, message_id, "internal_error", failure);
                    defer self.allocator.free(ack);
                    try ws.writeText(ack);
                    return false;
                };
            }

            const success = try build_response_null_json(self.allocator);
            defer self.allocator.free(success);
            const ack = try build_ack_json(self.allocator, 200, message_id, "OK", success);
            defer self.allocator.free(ack);
            try ws.writeText(ack);
            return false;
        }

        if (std.mem.eql(u8, envelope_type, "EVENT")) {
            const ignored = try build_success_response_json(self.allocator, "ignored");
            defer self.allocator.free(ignored);
            const ack = try build_ack_json(self.allocator, 404, message_id, "not_implemented", ignored);
            defer self.allocator.free(ack);
            try ws.writeText(ack);
        }

        return false;
    }

    fn runWebsocketOnce(self: *DingTalkChannel) !void {
        var connection = try self.openStreamConnection();
        defer connection.deinit(self.allocator);

        var host_buf: [256]u8 = undefined;
        var path_buf: [2048]u8 = undefined;
        const endpoint = try parse_endpoint_url(connection.endpoint, connection.ticket, &host_buf, &path_buf);

        var ws = try websocket.WsClient.connect(self.allocator, endpoint.host, endpoint.port, endpoint.path, &.{});
        self.ws_fd.store(ws.stream.handle, .release);
        self.connected.store(true, .release);
        defer {
            self.connected.store(false, .release);
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        while (self.running.load(.acquire)) {
            const maybe_message = ws.readMessage() catch |err| {
                log.warn("dingtalk websocket read failed: {}", .{err});
                break;
            };
            if (maybe_message == null) break;
            const message = maybe_message.?;
            defer self.allocator.free(message.payload);

            if (message.opcode != .text) continue;
            const should_disconnect = self.handleEnvelope(&ws, message.payload) catch |err| blk: {
                log.warn("dingtalk envelope handling failed: {}", .{err});
                break :blk false;
            };
            if (should_disconnect) {
                ws.writeClose();
                break;
            }
        }
    }

    fn websocketLoop(self: *DingTalkChannel) void {
        while (self.running.load(.acquire)) {
            self.runWebsocketOnce() catch |err| {
                if (self.running.load(.acquire)) {
                    log.warn("dingtalk websocket cycle failed: {}", .{err});
                }
            };
            if (!self.running.load(.acquire)) break;
            std.Thread.sleep(RECONNECT_DELAY_NS);
        }
    }

    /// Send a plain text reply through the session webhook URL or the AI interaction API.
    pub fn sendMessage(self: *DingTalkChannel, target: []const u8, text: []const u8, media: []const []const u8) !void {
        if (media.len > 0) return error.NotSupported;

        const trimmed_target = std.mem.trim(u8, target, " \t\r\n");
        if (trimmed_target.len == 0) return error.InvalidTarget;

        if (try self.reply_targets.getClone(self.allocator, trimmed_target)) |reply_target| {
            defer {
                var owned_reply_target = reply_target;
                owned_reply_target.deinit(self.allocator);
            }

            if (reply_target.expires_at_ms > 0 and std.time.timestamp() >= @divTrunc(reply_target.expires_at_ms, 1000)) {
                if (proactiveFallbackTarget(reply_target)) |proactive_target| {
                    return self.sendViaAiInteraction(proactive_target, text);
                }
                return error.TargetExpired;
            }

            return self.sendViaSessionWebhook(reply_target, text);
        }

        if (std.mem.startsWith(u8, trimmed_target, "https://")) return error.InvalidTarget;

        const proactive_target = try self.parseProactiveTarget(trimmed_target);
        try self.sendViaAiInteraction(proactive_target, text);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);
        self.connected.store(false, .release);
        self.ws_thread = std.Thread.spawn(
            .{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE },
            websocketLoop,
            .{self},
        ) catch |err| {
            self.running.store(false, .release);
            return err;
        };
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
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

        self.clearEphemeralState();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message, media);
    }

    fn vtableSendEvent(
        ptr: *anyopaque,
        target: []const u8,
        message: []const u8,
        media: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        try self.sendEventMessage(target, message, media, stage);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableSupportsStreamingOutbound(ptr: *anyopaque) bool {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        const template_id = self.ai_card_template_id orelse return false;
        const streaming_key = self.ai_card_streaming_key orelse return false;
        return template_id.len > 0 and streaming_key.len > 0;
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendEvent = &vtableSendEvent,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .supportsStreamingOutbound = &vtableSupportsStreamingOutbound,
    };

    pub fn channel(self: *DingTalkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "build_open_connection_body subscribes to bot callback topic" {
    const body = try build_open_connection_body(std.testing.allocator, "cid", "secret");
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"clientId\":\"cid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, CALLBACK_TOPIC) != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"type\":\"CALLBACK\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"type\":\"EVENT\"") == null);
}

test "parse_open_connection_response extracts endpoint and ticket" {
    var connection = try parse_open_connection_response(
        std.testing.allocator,
        "{\"endpoint\":\"wss://wss-open-connection.dingtalk.com:443/connect\",\"ticket\":\"abc-123\"}",
    );
    defer connection.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("wss://wss-open-connection.dingtalk.com:443/connect", connection.endpoint);
    try std.testing.expectEqualStrings("abc-123", connection.ticket);
}

test "parse_endpoint_url appends encoded ticket" {
    var host_buf: [128]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    const parsed = try parse_endpoint_url(
        "wss://wss-open-connection.dingtalk.com:443/connect?foo=bar",
        "ticket value",
        &host_buf,
        &path_buf,
    );

    try std.testing.expectEqualStrings("wss-open-connection.dingtalk.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
    try std.testing.expectEqualStrings("/connect?foo=bar&ticket=ticket%20value", parsed.path);
}

test "build_ack_json includes message id and escaped data" {
    const ack = try build_ack_json(
        std.testing.allocator,
        200,
        "mid-1",
        "success",
        "{\"response\":\"ok\"}",
    );
    defer std.testing.allocator.free(ack);

    try std.testing.expect(std.mem.indexOf(u8, ack, "\"messageId\":\"mid-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, ack, "\"code\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, ack, "\\\"response\\\":\\\"ok\\\"") != null);
}

test "should_ack_system_topic skips disconnect" {
    try std.testing.expect(should_ack_system_topic("ping"));
    try std.testing.expect(!should_ack_system_topic(SYSTEM_TOPIC_DISCONNECT));
}

test "build_basic_card_schema_content trims outer whitespace and embeds text content" {
    const content = try build_basic_card_schema_content(std.testing.allocator, "  oi\\nDingTalk  ");
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"header\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"logo\":\"" ++ BASIC_CARD_SCHEMA_LOGO ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"text\":\"oi\\\\nDingTalk\"") != null);
}

test "build_ai_interaction_send_body encodes conversation target" {
    const body = try build_ai_interaction_send_body(
        std.testing.allocator,
        .{ .kind = .conversation, .value = "cid-1" },
        "ola",
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"openConversationId\":\"cid-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"contentType\":\"basic_card_schema\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\\"text\\\":\\\"ola\\\"") != null);
}

test "build_ai_interaction_prepare_body encodes union target and template" {
    const body = try build_ai_interaction_prepare_body(
        std.testing.allocator,
        .{ .kind = .union_id, .value = "user-1" },
        "tmpl.schema",
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"unionId\":\"user-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"contentType\":\"ai_card\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\\"templateId\\\":\\\"tmpl.schema\\\"") != null);
}

test "build_ai_card_streaming_content encodes finalize flag and streaming component" {
    const content = try build_ai_card_streaming_content(
        std.testing.allocator,
        "tmpl.schema",
        "contentStreamingKey",
        "ola",
        true,
    );
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"templateId\":\"tmpl.schema\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"key\":\"contentStreamingKey\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"isFinalize\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"isFull\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"componentTag\":\"streamingComponent\"") != null);
}

test "parse_prepare_conversation_token extracts nested token" {
    const token = try parse_prepare_conversation_token(
        std.testing.allocator,
        "{\"result\":{\"conversationToken\":\"ct_123\"}}",
    );
    defer std.testing.allocator.free(token);

    try std.testing.expectEqualStrings("ct_123", token);
}

test "parseProactiveTarget accepts account-qualified conversation and union targets" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    const conversation = try channel.parseProactiveTarget("dingtalk:default:group:cid-1");
    try std.testing.expectEqual(ProactiveTargetKind.conversation, conversation.kind);
    try std.testing.expectEqualStrings("cid-1", conversation.value);

    const union_id = try channel.parseProactiveTarget("union:user-1");
    try std.testing.expectEqual(ProactiveTargetKind.union_id, union_id.kind);
    try std.testing.expectEqualStrings("user-1", union_id.value);
}

test "parseProactiveTarget rejects mismatched account prefix" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    try std.testing.expectError(
        error.InvalidTarget,
        channel.parseProactiveTarget("dingtalk:other:group:cid-1"),
    );
}

test "parseProactiveTarget rejects direct conversation ids" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    try std.testing.expectError(error.InvalidTarget, channel.parseProactiveTarget("direct:cid-1"));
    try std.testing.expectError(error.InvalidTarget, channel.parseProactiveTarget("dm:cid-1"));
}

test "parseCallbackPayload accepts sender_staff_id allowlist and rich text" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"staff-42"});
    defer channel.clearEphemeralState();

    const payload =
        \\{
        \\  "senderId":"$:sender",
        \\  "senderStaffId":"staff-42",
        \\  "conversationId":"cid-1",
        \\  "conversationType":"2",
        \\  "sessionWebhook":"https://oapi.dingtalk.com/robot/sendBySession?session=abc",
        \\  "sessionWebhookExpiredTime":1695290850075,
        \\  "msgId":"msg-1",
        \\  "robotCode":"dingbot",
        \\  "isInAtList":true,
        \\  "msgtype":"richText",
        \\  "content":{"richText":[{"text":"oi"},{"downloadCode":"img-1"},{"text":"mundo"}]}
        \\}
    ;

    var parsed = (try channel.parseCallbackPayload(payload)).?;
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("staff-42", parsed.sender_id);
    try std.testing.expectEqualStrings("dingtalk:default:reply:msg-1", parsed.reply_target);
    try std.testing.expectEqualStrings("oi\nmundo", parsed.content);
    try std.testing.expectEqualStrings("dingtalk:default:group:cid-1", parsed.session_key);
    try std.testing.expect(std.mem.indexOf(u8, parsed.metadata_json, "\"peer_kind\":\"group\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.metadata_json, "\"sender_staff_id\":\"staff-42\"") != null);
}

test "parseCallbackPayload drops unauthorized sender" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"allowed"});
    defer channel.clearEphemeralState();

    const payload =
        \\{
        \\  "senderId":"blocked",
        \\  "conversationId":"cid-1",
        \\  "conversationType":"1",
        \\  "sessionWebhook":"https://oapi.dingtalk.com/robot/sendBySession?session=abc",
        \\  "msgId":"msg-1",
        \\  "msgtype":"text",
        \\  "text":{"content":"hello"}
        \\}
    ;

    try std.testing.expect((try channel.parseCallbackPayload(payload)) == null);
}

test "parseCallbackPayload falls back to message summary for file" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    const payload =
        \\{
        \\  "senderId":"sender-1",
        \\  "conversationId":"cid-2",
        \\  "conversationType":"1",
        \\  "sessionWebhook":"https://oapi.dingtalk.com/robot/sendBySession?session=abc",
        \\  "msgId":"msg-2",
        \\  "msgtype":"file",
        \\  "content":{"fileName":"report.pdf","fileId":"fid-1"}
        \\}
    ;

    var parsed = (try channel.parseCallbackPayload(payload)).?;
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("report.pdf", parsed.content);
    try std.testing.expectEqualStrings("dingtalk:default:direct:cid-2", parsed.session_key);
    try std.testing.expect(std.mem.indexOf(u8, parsed.metadata_json, "\"peer_kind\":\"direct\"") != null);
}

test "parseCallbackPayload rolls back reply target cache on allocation failure" {
    const payload =
        \\{
        \\  "senderId":"sender-1",
        \\  "conversationId":"cid-2",
        \\  "conversationType":"1",
        \\  "sessionWebhook":"https://oapi.dingtalk.com/robot/sendBySession?session=abc",
        \\  "msgId":"msg-2",
        \\  "msgtype":"text",
        \\  "text":{"content":"hello"}
        \\}
    ;

    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var alloc_count: usize = 0;
    {
        var channel = DingTalkChannel.init(counting.allocator(), "cid", "secret", &.{"*"});
        defer channel.clearEphemeralState();

        var parsed = (try channel.parseCallbackPayload(payload)).?;
        defer parsed.deinit(counting.allocator());
        alloc_count = counting.alloc_index;
    }
    try std.testing.expect(alloc_count > 0);

    var found_late_oom = false;
    var fail_index = alloc_count;
    while (fail_index > 0) : (fail_index -= 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        failing.fail_index = fail_index;

        var channel = DingTalkChannel.init(failing.allocator(), "cid", "secret", &.{"*"});
        defer channel.clearEphemeralState();

        const maybe_parsed = channel.parseCallbackPayload(payload) catch |err| blk: {
            switch (err) {
                error.OutOfMemory => {
                    try std.testing.expectEqual(@as(usize, 0), channel.reply_targets.map.count());
                    found_late_oom = true;
                    break :blk null;
                },
                else => return err,
            }
        };
        if (found_late_oom) break;

        if (maybe_parsed) |parsed| {
            var owned = parsed;
            owned.deinit(failing.allocator());
        }
    }

    try std.testing.expect(found_late_oom);
}

test "sendMessage rejects expired cached reply target" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
        .sender_staff_id = try std.testing.allocator.dupe(u8, "staff-42"),
        .is_group = true,
        .expires_at_ms = 1,
    };
    defer target.deinit(std.testing.allocator);

    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);
    try std.testing.expectError(
        error.TargetExpired,
        channel.sendMessage("dingtalk:default:reply:msg-1", "oi", &.{}),
    );
}

test "sendMessage falls back to ai interaction when cached reply target expired with conversation id" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
        .conversation_id = try std.testing.allocator.dupe(u8, "cid-1"),
        .is_group = true,
        .expires_at_ms = 1,
    };
    defer target.deinit(std.testing.allocator);

    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);
    try channel.sendMessage("dingtalk:default:reply:msg-1", "oi", &.{});
}

test "sendMessage rejects arbitrary webhook target" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    try std.testing.expectError(
        error.InvalidTarget,
        channel.sendMessage("https://oapi.dingtalk.com/robot/sendBySession?session=abc", "oi", &.{}),
    );
}

test "sendMessage accepts proactive union id target" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    try channel.sendMessage("dingtalk:default:union:user-1", "oi", &.{});
}

test "sendMessage rejects media attachments" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
    };
    defer target.deinit(std.testing.allocator);
    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);

    try std.testing.expectError(
        error.NotSupported,
        channel.sendMessage("dingtalk:default:reply:msg-1", "oi", &.{"./file.png"}),
    );
}

test "sendEventMessage chunk accumulates streaming session for reply target" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    channel.ai_card_template_id = "tmpl.schema";
    channel.ai_card_streaming_key = "contentStreamingKey";
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
        .conversation_id = try std.testing.allocator.dupe(u8, "cid-1"),
        .is_group = true,
    };
    defer target.deinit(std.testing.allocator);

    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);
    try channel.channel().sendEvent("dingtalk:default:reply:msg-1", "ola", &.{}, .chunk);
    try channel.channel().sendEvent("dingtalk:default:reply:msg-1", " mundo", &.{}, .chunk);

    channel.stream_mu.lock();
    defer channel.stream_mu.unlock();
    try std.testing.expectEqual(@as(usize, 1), channel.stream_sessions.count());
    const session = channel.stream_sessions.get("dingtalk:default:reply:msg-1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ola mundo", session.buffer.items);
    try std.testing.expectEqualStrings("test-conversation-token", session.conversation_token);
}

test "sendEventMessage final clears streaming session" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    channel.ai_card_template_id = "tmpl.schema";
    channel.ai_card_streaming_key = "contentStreamingKey";
    defer channel.clearEphemeralState();

    try channel.channel().sendEvent("group:cid-1", "chunk", &.{}, .chunk);

    channel.stream_mu.lock();
    try std.testing.expect(channel.stream_sessions.get("group:cid-1") != null);
    channel.stream_mu.unlock();

    try channel.channel().sendEvent("group:cid-1", "chunk final", &.{}, .final);

    channel.stream_mu.lock();
    defer channel.stream_mu.unlock();
    try std.testing.expect(channel.stream_sessions.get("group:cid-1") == null);
}

test "sendEventMessage without streaming config ignores chunks and safely finalizes" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
    };
    defer target.deinit(std.testing.allocator);
    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);

    try channel.channel().sendEvent("dingtalk:default:reply:msg-1", "ola", &.{}, .chunk);
    try channel.channel().sendEvent("dingtalk:default:reply:msg-1", "ola final", &.{}, .final);

    channel.stream_mu.lock();
    defer channel.stream_mu.unlock();
    try std.testing.expectEqual(@as(usize, 0), channel.stream_sessions.count());
}

test "sendEventMessage final on nonexistent stream falls back safely" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    channel.ai_card_template_id = "tmpl.schema";
    channel.ai_card_streaming_key = "contentStreamingKey";
    defer channel.clearEphemeralState();

    try channel.channel().sendEvent("group:cid-1", "ola final", &.{}, .final);

    channel.stream_mu.lock();
    defer channel.stream_mu.unlock();
    try std.testing.expectEqual(@as(usize, 0), channel.stream_sessions.count());
}

test "sendEventMessage direct reply target cannot open streaming session" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    channel.ai_card_template_id = "tmpl.schema";
    channel.ai_card_streaming_key = "contentStreamingKey";
    defer channel.clearEphemeralState();

    var target = SessionReplyTarget{
        .webhook_url = try std.testing.allocator.dupe(u8, "https://oapi.dingtalk.com/robot/sendBySession?session=abc"),
        .sender_staff_id = try std.testing.allocator.dupe(u8, "staff-42"),
        .conversation_id = try std.testing.allocator.dupe(u8, "cid-direct-1"),
        .is_group = false,
    };
    defer target.deinit(std.testing.allocator);
    try channel.reply_targets.put(std.testing.allocator, "dingtalk:default:reply:msg-1", target);

    try channel.channel().sendEvent("dingtalk:default:reply:msg-1", "ola", &.{}, .chunk);

    channel.stream_mu.lock();
    defer channel.stream_mu.unlock();
    try std.testing.expectEqual(@as(usize, 0), channel.stream_sessions.count());
}

test "healthCheck requires running and connection" {
    var channel = DingTalkChannel.init(std.testing.allocator, "cid", "secret", &.{"*"});
    defer channel.clearEphemeralState();
    try std.testing.expect(!channel.healthCheck());

    channel.running.store(true, .release);
    try std.testing.expect(!channel.healthCheck());

    channel.connected.store(true, .release);
    try std.testing.expect(channel.healthCheck());
}
