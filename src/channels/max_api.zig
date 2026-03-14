//! HTTP client for the Max messenger Bot API (platform-api.max.ru).
//!
//! Provides typed wrappers for the Max Bot REST endpoints:
//!   GET /me, POST /messages, PUT /messages, DELETE /messages,
//!   POST /answers, GET /updates, POST /subscriptions, DELETE /subscriptions,
//!   POST /chats/{chatId}/actions, POST /uploads.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const url_percent = @import("../url_percent.zig");

const log = std.log.scoped(.max_api);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

pub const BASE_URL = "https://platform-api.max.ru";
pub const MAX_MESSAGE_LEN: usize = 4000;

// Update types requested via long-polling.
const UPDATE_TYPES = "message_created,message_callback,message_edited,message_removed,bot_added,bot_removed,bot_started,bot_stopped";

// ════════════════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════════════════

pub const BotInfo = struct {
    user_id: ?[]u8 = null,
    name: ?[]u8 = null,
    username: ?[]u8 = null,

    pub fn deinit(self: *const BotInfo, allocator: std.mem.Allocator) void {
        if (self.user_id) |v| allocator.free(v);
        if (self.name) |v| allocator.free(v);
        if (self.username) |v| allocator.free(v);
    }
};

pub const SentMessageMeta = struct {
    mid: ?[]u8 = null,

    pub fn deinit(self: *const SentMessageMeta, allocator: std.mem.Allocator) void {
        if (self.mid) |v| allocator.free(v);
    }
};

pub const UploadDescriptor = struct {
    url: ?[]u8 = null,
    token: ?[]u8 = null,

    pub fn deinit(self: *const UploadDescriptor, allocator: std.mem.Allocator) void {
        if (self.url) |v| allocator.free(v);
        if (self.token) |v| allocator.free(v);
    }
};

pub const InlineKeyboardButton = struct {
    text: []const u8,
    payload: []const u8,
};

// ════════════════════════════════════════════════════════════════════════════
// Client
// ════════════════════════════════════════════════════════════════════════════

pub const Client = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    proxy: ?[]const u8,

    // ── URL builder ─────────────────────────────────────────────────────

    /// Build a full API URL into `buf`. Returns a slice of `buf`.
    ///   buildUrl(buf, "/me", null)         → "https://platform-api.max.ru/me"
    ///   buildUrl(buf, "/messages", "chat_id=123") → ".../messages?chat_id=123"
    pub fn buildUrl(buf: []u8, path: []const u8, query: ?[]const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll(BASE_URL);
        try w.writeAll(path);
        if (query) |q| {
            try w.writeByte('?');
            try w.writeAll(q);
        }
        return fbs.getWritten();
    }

    // ── Auth header helper ──────────────────────────────────────────────

    fn authHeader(self: Client, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        try fbs.writer().print("Authorization: {s}", .{self.bot_token});
        return fbs.getWritten();
    }

    // ── Bot info ────────────────────────────────────────────────────────

    pub fn getMe(self: Client, allocator: std.mem.Allocator) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"user_id\":123,\"name\":\"TestBot\",\"username\":\"test_bot\"}");
        }
        var url_buf: [256]u8 = undefined;
        const url = try buildUrl(&url_buf, "/me", null);
        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        return root.http_util.curlGetWithProxy(allocator, url, &.{auth}, "10", self.proxy);
    }

    pub fn getMeOk(self: Client) bool {
        const resp = self.getMe(self.allocator) catch return false;
        defer self.allocator.free(resp);
        return std.mem.indexOf(u8, resp, "\"user_id\"") != null;
    }

    pub fn fetchBotInfo(self: Client, allocator: std.mem.Allocator) ?BotInfo {
        const resp = self.getMe(allocator) catch return null;
        defer allocator.free(resp);
        return parseBotInfo(allocator, resp);
    }

    pub fn parseBotInfo(allocator: std.mem.Allocator, json: []const u8) ?BotInfo {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const obj = parsed.value.object;

        // user_id can be integer or string
        const uid_str: ?[]u8 = blk: {
            const uid_val = obj.get("user_id") orelse break :blk null;
            switch (uid_val) {
                .string => |s| break :blk allocator.dupe(u8, s) catch null,
                .integer => |i| {
                    var id_buf: [32]u8 = undefined;
                    const s = std.fmt.bufPrint(&id_buf, "{d}", .{i}) catch break :blk null;
                    break :blk allocator.dupe(u8, s) catch null;
                },
                else => break :blk null,
            }
        };

        const name_str: ?[]u8 = blk: {
            const val = obj.get("name") orelse break :blk null;
            if (val != .string) break :blk null;
            break :blk allocator.dupe(u8, val.string) catch null;
        };

        const username_str: ?[]u8 = blk: {
            const val = obj.get("username") orelse break :blk null;
            if (val != .string) break :blk null;
            break :blk allocator.dupe(u8, val.string) catch null;
        };

        return .{
            .user_id = uid_str,
            .name = name_str,
            .username = username_str,
        };
    }

    // ── Messages ────────────────────────────────────────────────────────

    pub fn sendMessage(self: Client, allocator: std.mem.Allocator, chat_id: []const u8, body_json: []const u8) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"message\":{\"body\":{\"mid\":\"test-mid-123\"}}}");
        }
        var url_buf: [512]u8 = undefined;
        const encoded_chat_id = try url_percent.encode(allocator, chat_id);
        defer allocator.free(encoded_chat_id);
        var query_buf: [256]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("chat_id={s}", .{encoded_chat_id});
        const url = try buildUrl(&url_buf, "/messages", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        return root.http_util.curlPostWithProxy(allocator, url, body_json, &.{auth}, self.proxy, "30");
    }

    pub fn parseSentMessageMid(allocator: std.mem.Allocator, json: []const u8) ?SentMessageMeta {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const msg_obj = parsed.value.object.get("message") orelse return null;
        if (msg_obj != .object) return null;

        const body_obj = msg_obj.object.get("body") orelse return .{};
        if (body_obj != .object) return .{};

        const mid_val = body_obj.object.get("mid") orelse return .{};
        if (mid_val != .string) return .{};

        return .{
            .mid = allocator.dupe(u8, mid_val.string) catch null,
        };
    }

    pub fn editMessage(self: Client, allocator: std.mem.Allocator, message_id: []const u8, body_json: []const u8) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"success\":true}");
        }
        var url_buf: [512]u8 = undefined;
        const encoded_message_id = try url_percent.encode(allocator, message_id);
        defer allocator.free(encoded_message_id);
        var query_buf: [256]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("message_id={s}", .{encoded_message_id});
        const url = try buildUrl(&url_buf, "/messages", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        return root.http_util.curlPut(allocator, url, body_json, &.{auth});
    }

    pub fn deleteMessage(self: Client, allocator: std.mem.Allocator, message_id: []const u8) !void {
        if (comptime builtin.is_test) return;
        var url_buf: [512]u8 = undefined;
        const encoded_message_id = try url_percent.encode(allocator, message_id);
        defer allocator.free(encoded_message_id);
        var query_buf: [256]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("message_id={s}", .{encoded_message_id});
        const url = try buildUrl(&url_buf, "/messages", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        try curlDelete(allocator, url, auth, self.proxy);
    }

    // ── Callbacks ───────────────────────────────────────────────────────

    pub fn answerCallback(self: Client, allocator: std.mem.Allocator, callback_id: []const u8, notification: ?[]const u8) !void {
        return self.answerCallbackWithMessage(allocator, callback_id, notification, null);
    }

    pub fn answerCallbackWithMessage(
        self: Client,
        allocator: std.mem.Allocator,
        callback_id: []const u8,
        notification: ?[]const u8,
        message_body_json: ?[]const u8,
    ) !void {
        if (comptime builtin.is_test) return;
        var url_buf: [512]u8 = undefined;
        const encoded_callback_id = try url_percent.encode(allocator, callback_id);
        defer allocator.free(encoded_callback_id);
        var query_buf: [384]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("callback_id={s}", .{encoded_callback_id});
        const url = try buildUrl(&url_buf, "/answers", query_fbs.getWritten());

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);
        try body.appendSlice(allocator, "{");
        var needs_comma = false;
        if (notification) |text| {
            try body.appendSlice(allocator, "\"notification\":");
            try root.json_util.appendJsonString(&body, allocator, text);
            needs_comma = true;
        }
        if (message_body_json) |message_body| {
            if (needs_comma) try body.appendSlice(allocator, ",");
            try body.appendSlice(allocator, "\"message\":");
            try body.appendSlice(allocator, message_body);
        }
        try body.appendSlice(allocator, "}");

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        const resp = try root.http_util.curlPostWithProxy(allocator, url, body.items, &.{auth}, self.proxy, "10");
        allocator.free(resp);
    }

    // ── Updates (long-polling) ──────────────────────────────────────────

    pub fn getUpdates(self: Client, allocator: std.mem.Allocator, marker: ?[]const u8, timeout: []const u8) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"updates\":[]}");
        }
        var url_buf: [512]u8 = undefined;
        var query_buf: [1024]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        const qw = query_fbs.writer();
        try qw.print("timeout={s}&types={s}", .{ timeout, UPDATE_TYPES });
        if (marker) |m| {
            const encoded_marker = try url_percent.encode(allocator, m);
            defer allocator.free(encoded_marker);
            try qw.print("&marker={s}", .{encoded_marker});
        }
        const url = try buildUrl(&url_buf, "/updates", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);

        // Use a generous max-time for long-polling: timeout + 5s grace.
        var timeout_buf: [16]u8 = undefined;
        const timeout_val = std.fmt.parseInt(u32, timeout, 10) catch 30;
        const max_time = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_val + 5}) catch "35";

        return root.http_util.curlGetWithProxy(allocator, url, &.{auth}, max_time, self.proxy);
    }

    // ── Subscriptions (webhooks) ────────────────────────────────────────

    pub fn subscribe(self: Client, allocator: std.mem.Allocator, webhook_url: []const u8, secret: ?[]const u8) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"success\":true}");
        }
        var url_buf: [256]u8 = undefined;
        const url = try buildUrl(&url_buf, "/subscriptions", null);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);
        try body.appendSlice(allocator, "{\"url\":");
        try root.json_util.appendJsonString(&body, allocator, webhook_url);
        if (secret) |s| {
            try body.appendSlice(allocator, ",\"secret\":");
            try root.json_util.appendJsonString(&body, allocator, s);
        }
        try body.appendSlice(allocator, ",\"update_types\":[");
        // Emit update types as JSON string array
        var first = true;
        var it = std.mem.splitScalar(u8, UPDATE_TYPES, ',');
        while (it.next()) |t| {
            if (!first) try body.appendSlice(allocator, ",");
            try root.json_util.appendJsonString(&body, allocator, t);
            first = false;
        }
        try body.appendSlice(allocator, "]}");

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        return root.http_util.curlPostWithProxy(allocator, url, body.items, &.{auth}, self.proxy, "10");
    }

    pub fn unsubscribe(self: Client, allocator: std.mem.Allocator, webhook_url: []const u8) !void {
        if (comptime builtin.is_test) return;
        var url_buf: [512]u8 = undefined;
        const encoded_url = try url_percent.encode(allocator, webhook_url);
        defer allocator.free(encoded_url);
        var query_buf: [1024]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("url={s}", .{encoded_url});
        const url = try buildUrl(&url_buf, "/subscriptions", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        try curlDelete(allocator, url, auth, self.proxy);
    }

    // ── Typing indicator ────────────────────────────────────────────────

    pub fn sendTypingAction(self: Client, allocator: std.mem.Allocator, chat_id: []const u8) !void {
        if (comptime builtin.is_test) return;
        var url_buf: [512]u8 = undefined;
        const encoded_chat_id = try url_percent.encode(allocator, chat_id);
        defer allocator.free(encoded_chat_id);
        var path_buf: [512]u8 = undefined;
        var path_fbs = std.io.fixedBufferStream(&path_buf);
        try path_fbs.writer().print("/chats/{s}/actions", .{encoded_chat_id});
        const url = try buildUrl(&url_buf, path_fbs.getWritten(), null);

        const body = "{\"action\":\"typing_on\"}";
        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        const resp = try root.http_util.curlPostWithProxy(allocator, url, body, &.{auth}, self.proxy, "10");
        allocator.free(resp);
    }

    // ── File upload ─────────────────────────────────────────────────────

    pub fn uploadFile(self: Client, allocator: std.mem.Allocator, file_type: []const u8, file_path: []const u8) ![]u8 {
        if (comptime builtin.is_test) {
            return allocator.dupe(u8, "{\"token\":\"test-upload-token\"}");
        }
        var url_buf: [256]u8 = undefined;
        const encoded_file_type = try url_percent.encode(allocator, file_type);
        defer allocator.free(encoded_file_type);
        var query_buf: [128]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        try query_fbs.writer().print("type={s}", .{encoded_file_type});
        const url = try buildUrl(&url_buf, "/uploads", query_fbs.getWritten());

        var auth_buf: [512]u8 = undefined;
        const auth = try self.authHeader(&auth_buf);
        const upload_init_resp = try root.http_util.curlPostWithProxy(allocator, url, "", &.{auth}, self.proxy, "30");
        errdefer allocator.free(upload_init_resp);

        const upload_desc = parseUploadDescriptor(allocator, upload_init_resp) orelse return error.CurlFailed;
        defer upload_desc.deinit(allocator);

        const upload_url = upload_desc.url orelse return error.CurlFailed;
        const upload_resp = try curlMultipartUpload(allocator, upload_url, auth, self.proxy, file_path);

        if (upload_desc.token != null) {
            allocator.free(upload_resp);
            return upload_init_resp;
        }

        allocator.free(upload_init_resp);
        return upload_resp;
    }

    pub fn parseUploadToken(allocator: std.mem.Allocator, json: []const u8) ?[]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const token_val = parsed.value.object.get("token") orelse return null;
        if (token_val != .string) return null;
        return allocator.dupe(u8, token_val.string) catch null;
    }

    pub fn parseUploadDescriptor(allocator: std.mem.Allocator, json: []const u8) ?UploadDescriptor {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const url_val = if (parsed.value.object.get("url")) |value| blk: {
            if (value != .string) break :blk null;
            break :blk allocator.dupe(u8, value.string) catch return null;
        } else null;
        errdefer if (url_val) |v| allocator.free(v);

        const token_val = if (parsed.value.object.get("token")) |value| blk: {
            if (value != .string) break :blk null;
            break :blk allocator.dupe(u8, value.string) catch return null;
        } else null;

        return .{
            .url = url_val,
            .token = token_val,
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Internal: DELETE via curl subprocess
// ════════════════════════════════════════════════════════════════════════════

fn curlDelete(allocator: std.mem.Allocator, url: []const u8, auth_header: []const u8, proxy: ?[]const u8) !void {
    var argv_buf: [14][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "DELETE";
    argc += 1;
    argv_buf[argc] = "-m";
    argc += 1;
    argv_buf[argc] = "10";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = auth_header;
    argc += 1;

    if (proxy) |p| {
        argv_buf[argc] = "-x";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 256 * 1024) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return error.CurlReadError;
    };
    defer allocator.free(stdout);

    const term = child.wait() catch return error.CurlWaitError;
    switch (term) {
        .Exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }
}

fn curlMultipartUpload(
    allocator: std.mem.Allocator,
    url: []const u8,
    auth_header: []const u8,
    proxy: ?[]const u8,
    file_path: []const u8,
) ![]u8 {
    var file_arg_buf: [1024]u8 = undefined;
    var file_fbs = std.io.fixedBufferStream(&file_arg_buf);
    try file_fbs.writer().print("data=@{s}", .{file_path});
    const file_arg = file_fbs.getWritten();

    var argv_buf: [18][]const u8 = undefined;
    var argc: usize = 0;
    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "-m";
    argc += 1;
    argv_buf[argc] = "120";
    argc += 1;

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = auth_header;
    argc += 1;
    argv_buf[argc] = "-F";
    argc += 1;
    argv_buf[argc] = file_arg;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch return error.CurlReadError;
    const term = child.wait() catch {
        allocator.free(stdout);
        return error.CurlWaitError;
    };
    switch (term) {
        .Exited => |code| if (code != 0) {
            allocator.free(stdout);
            return error.CurlFailed;
        },
        else => {
            allocator.free(stdout);
            return error.CurlFailed;
        },
    }
    return stdout;
}

// ════════════════════════════════════════════════════════════════════════════
// JSON body builders (free functions)
// ════════════════════════════════════════════════════════════════════════════

/// Build a JSON body for a plain text message.
///   { "text": "...", "format": "..." }
/// `format` is optional (e.g. "markdown", "html"); omitted when null.
pub fn buildTextMessageBody(allocator: std.mem.Allocator, text: []const u8, format: ?[]const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"text\":");
    try root.appendJsonStringW(buf.writer(allocator), text);
    if (format) |fmt| {
        try buf.appendSlice(allocator, ",\"format\":");
        try root.appendJsonStringW(buf.writer(allocator), fmt);
    }
    try buf.appendSlice(allocator, "}");

    return allocator.dupe(u8, buf.items);
}

pub fn buildTextMessageBodyClearingAttachments(
    allocator: std.mem.Allocator,
    text: []const u8,
    format: ?[]const u8,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"text\":");
    try root.appendJsonStringW(buf.writer(allocator), text);
    if (format) |fmt| {
        try buf.appendSlice(allocator, ",\"format\":");
        try root.appendJsonStringW(buf.writer(allocator), fmt);
    }
    try buf.appendSlice(allocator, ",\"attachments\":[]}");

    return allocator.dupe(u8, buf.items);
}

/// Build a JSON body for a text message with an inline keyboard.
///   { "text": "...", "format": "...", "attachments": [{ "type": "inline_keyboard", "payload": { "buttons": [...] } }] }
pub fn buildTextWithKeyboardBody(allocator: std.mem.Allocator, text: []const u8, keyboard_json: []const u8, format: ?[]const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"text\":");
    try root.appendJsonStringW(buf.writer(allocator), text);
    if (format) |fmt| {
        try buf.appendSlice(allocator, ",\"format\":");
        try root.appendJsonStringW(buf.writer(allocator), fmt);
    }
    try buf.appendSlice(allocator, ",\"attachments\":[{\"type\":\"inline_keyboard\",\"payload\":");
    try buf.appendSlice(allocator, keyboard_json);
    try buf.appendSlice(allocator, "}]}");

    return allocator.dupe(u8, buf.items);
}

/// Build an inline keyboard JSON payload from a slice of choice labels.
///   { "buttons": [[{"type":"callback","text":"A","payload":"A"}], ...] }
/// Each choice becomes a single-button row.
pub fn buildInlineKeyboardJson(allocator: std.mem.Allocator, choices: []const []const u8) ![]u8 {
    const buttons = try allocator.alloc(InlineKeyboardButton, choices.len);
    defer allocator.free(buttons);
    for (choices, 0..) |choice, i| {
        buttons[i] = .{
            .text = choice,
            .payload = choice,
        };
    }
    return buildInlineKeyboardButtonsJson(allocator, buttons);
}

pub fn buildInlineKeyboardButtonsJson(
    allocator: std.mem.Allocator,
    buttons: []const InlineKeyboardButton,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"buttons\":[");
    for (buttons, 0..) |button, i| {
        if (i > 0) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "[{\"type\":\"callback\",\"text\":");
        try root.appendJsonStringW(buf.writer(allocator), button.text);
        try buf.appendSlice(allocator, ",\"payload\":");
        try root.appendJsonStringW(buf.writer(allocator), button.payload);
        try buf.appendSlice(allocator, ",\"intent\":\"default\"");
        try buf.appendSlice(allocator, "}]");
    }
    try buf.appendSlice(allocator, "]}");

    return allocator.dupe(u8, buf.items);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildUrl without query" {
    var buf: [256]u8 = undefined;
    const url = try Client.buildUrl(&buf, "/me", null);
    try std.testing.expectEqualStrings("https://platform-api.max.ru/me", url);
}

test "buildUrl with query params" {
    var buf: [256]u8 = undefined;
    const url = try Client.buildUrl(&buf, "/messages", "chat_id=123");
    try std.testing.expectEqualStrings("https://platform-api.max.ru/messages?chat_id=123", url);
}

test "buildUrl with compound query" {
    var buf: [512]u8 = undefined;
    const url = try Client.buildUrl(&buf, "/updates", "timeout=30&types=message_created&marker=abc");
    try std.testing.expectEqualStrings("https://platform-api.max.ru/updates?timeout=30&types=message_created&marker=abc", url);
}

test "authHeader uses raw token format required by Max" {
    const client = Client{
        .allocator = std.testing.allocator,
        .bot_token = "token-123",
        .proxy = null,
    };
    var buf: [128]u8 = undefined;
    const header = try client.authHeader(&buf);
    try std.testing.expectEqualStrings("Authorization: token-123", header);
}

test "parseBotInfo with integer user_id" {
    const allocator = std.testing.allocator;
    const json = "{\"user_id\":12345,\"name\":\"MyBot\",\"username\":\"my_bot\"}";
    const info = Client.parseBotInfo(allocator, json) orelse return error.TestExpectedEqual;
    defer info.deinit(allocator);

    try std.testing.expectEqualStrings("12345", info.user_id.?);
    try std.testing.expectEqualStrings("MyBot", info.name.?);
    try std.testing.expectEqualStrings("my_bot", info.username.?);
}

test "parseBotInfo with string user_id" {
    const allocator = std.testing.allocator;
    const json = "{\"user_id\":\"abc-def\",\"name\":\"Bot2\"}";
    const info = Client.parseBotInfo(allocator, json) orelse return error.TestExpectedEqual;
    defer info.deinit(allocator);

    try std.testing.expectEqualStrings("abc-def", info.user_id.?);
    try std.testing.expectEqualStrings("Bot2", info.name.?);
    try std.testing.expect(info.username == null);
}

test "parseBotInfo with invalid JSON returns null" {
    const allocator = std.testing.allocator;
    try std.testing.expect(Client.parseBotInfo(allocator, "not json") == null);
}

test "parseBotInfo with empty object" {
    const allocator = std.testing.allocator;
    const info = Client.parseBotInfo(allocator, "{}") orelse return error.TestExpectedEqual;
    defer info.deinit(allocator);
    try std.testing.expect(info.user_id == null);
    try std.testing.expect(info.name == null);
    try std.testing.expect(info.username == null);
}

test "parseSentMessageMid extracts mid" {
    const allocator = std.testing.allocator;
    const json = "{\"message\":{\"body\":{\"mid\":\"msg-42\",\"seq\":1}}}";
    const meta = Client.parseSentMessageMid(allocator, json) orelse return error.TestExpectedEqual;
    defer meta.deinit(allocator);
    try std.testing.expectEqualStrings("msg-42", meta.mid.?);
}

test "parseSentMessageMid returns empty meta on missing mid" {
    const allocator = std.testing.allocator;
    const json = "{\"message\":{\"body\":{}}}";
    const meta = Client.parseSentMessageMid(allocator, json) orelse return error.TestExpectedEqual;
    defer meta.deinit(allocator);
    try std.testing.expect(meta.mid == null);
}

test "parseSentMessageMid returns null on invalid JSON" {
    const allocator = std.testing.allocator;
    try std.testing.expect(Client.parseSentMessageMid(allocator, "garbage") == null);
}

test "parseUploadToken extracts token" {
    const allocator = std.testing.allocator;
    const json = "{\"token\":\"upload-tok-99\"}";
    const token = Client.parseUploadToken(allocator, json) orelse return error.TestExpectedEqual;
    defer allocator.free(token);
    try std.testing.expectEqualStrings("upload-tok-99", token);
}

test "parseUploadDescriptor extracts url and token" {
    const allocator = std.testing.allocator;
    const desc = Client.parseUploadDescriptor(allocator, "{\"url\":\"https://upload.example/max\",\"token\":\"tok-7\"}") orelse return error.TestExpectedEqual;
    defer desc.deinit(allocator);
    try std.testing.expectEqualStrings("https://upload.example/max", desc.url.?);
    try std.testing.expectEqualStrings("tok-7", desc.token.?);
}

test "parseUploadDescriptor allows upload url without token" {
    const allocator = std.testing.allocator;
    const desc = Client.parseUploadDescriptor(allocator, "{\"url\":\"https://upload.example/max\"}") orelse return error.TestExpectedEqual;
    defer desc.deinit(allocator);
    try std.testing.expectEqualStrings("https://upload.example/max", desc.url.?);
    try std.testing.expect(desc.token == null);
}

test "parseUploadToken returns null on missing token" {
    const allocator = std.testing.allocator;
    try std.testing.expect(Client.parseUploadToken(allocator, "{\"other\":1}") == null);
}

test "buildTextMessageBody without format" {
    const allocator = std.testing.allocator;
    const body = try buildTextMessageBody(allocator, "Hello, world!", null);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"text\":\"Hello, world!\"}", body);
}

test "buildTextMessageBody with format" {
    const allocator = std.testing.allocator;
    const body = try buildTextMessageBody(allocator, "**bold**", "markdown");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"text\":\"**bold**\",\"format\":\"markdown\"}", body);
}

test "buildTextMessageBody escapes special chars" {
    const allocator = std.testing.allocator;
    const body = try buildTextMessageBody(allocator, "line1\nline2", null);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"text\":\"line1\\nline2\"}", body);
}

test "buildTextMessageBodyClearingAttachments removes attachments" {
    const allocator = std.testing.allocator;
    const body = try buildTextMessageBodyClearingAttachments(allocator, "Pick one", "markdown");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"text\":\"Pick one\",\"format\":\"markdown\",\"attachments\":[]}", body);
}

test "buildInlineKeyboardJson with multiple choices" {
    const allocator = std.testing.allocator;
    const choices = [_][]const u8{ "Yes", "No" };
    const json = try buildInlineKeyboardJson(allocator, &choices);
    defer allocator.free(json);

    // Verify structure
    try std.testing.expect(std.mem.indexOf(u8, json, "\"buttons\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"text\":\"Yes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"text\":\"No\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"callback\"") != null);
}

test "buildInlineKeyboardButtonsJson preserves custom payloads" {
    const allocator = std.testing.allocator;
    const buttons = [_]InlineKeyboardButton{
        .{ .text = "Yes", .payload = "ncmax:1:0" },
        .{ .text = "No", .payload = "ncmax:1:1" },
    };
    const json = try buildInlineKeyboardButtonsJson(allocator, &buttons);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"payload\":\"ncmax:1:0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"payload\":\"ncmax:1:1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"intent\":\"default\"") != null);
}

test "getMe returns mock data in test mode" {
    const allocator = std.testing.allocator;
    const client = Client{
        .allocator = allocator,
        .bot_token = "test-token",
        .proxy = null,
    };
    const resp = try client.getMe(allocator);
    defer allocator.free(resp);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"user_id\"") != null);
}

test "sendMessage returns mock data in test mode" {
    const allocator = std.testing.allocator;
    const client = Client{
        .allocator = allocator,
        .bot_token = "test-token",
        .proxy = null,
    };
    const resp = try client.sendMessage(allocator, "123", "{\"text\":\"hi\"}");
    defer allocator.free(resp);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"mid\"") != null);
}

test "getMeOk returns true for valid mock response" {
    const client = Client{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .proxy = null,
    };
    try std.testing.expect(client.getMeOk());
}

test "MAX_MESSAGE_LEN is 4000" {
    try std.testing.expectEqual(@as(usize, 4000), MAX_MESSAGE_LEN);
}

test "BASE_URL is correct" {
    try std.testing.expectEqualStrings("https://platform-api.max.ru", BASE_URL);
}
