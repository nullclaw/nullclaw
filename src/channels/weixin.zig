const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const qr_mod = @import("../qr.zig");
const url_percent = @import("../url_percent.zig");

const ILINK_BASE_URL = "https://ilinkai.weixin.qq.com/";
const ILINK_APP_ID = "bot";
const ILINK_CLIENT_VERSION = "131329"; // 2.1.1 encoded as 0x00020101
const CHANNEL_VERSION = "2.1.1";
const WEIXIN_REPLY_TARGET_SEPARATOR: u8 = 0x1f;
const SEND_TIMEOUT_SECS = "15";
const GET_UPDATES_TIMEOUT_SECS = "35";
const GET_UPDATES_ITEM_TYPE_TEXT: u8 = 1;
const GET_UPDATES_ITEM_TYPE_VOICE: u8 = 3;
const MESSAGE_TYPE_BOT: u8 = 2;
const MESSAGE_STATE_FINISH: u8 = 2;
const QR_POLL_INTERVAL_NS: u64 = 2 * std.time.ns_per_s;
const LOGIN_TIMEOUT_NS: u64 = 300 * std.time.ns_per_s;
const log = std.log.scoped(.weixin);

const AuthHeaderSet = struct {
    authorization: []u8,
    wechat_uin: []u8,
    headers: [6][]const u8,

    fn init(allocator: std.mem.Allocator, token: []const u8) !AuthHeaderSet {
        const authorization = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
        errdefer allocator.free(authorization);

        const wechat_uin = try buildWechatUinHeader(allocator);
        errdefer allocator.free(wechat_uin);

        return .{
            .authorization = authorization,
            .wechat_uin = wechat_uin,
            .headers = .{
                "iLink-App-Id: " ++ ILINK_APP_ID,
                "iLink-App-ClientVersion: " ++ ILINK_CLIENT_VERSION,
                "AuthorizationType: ilink_bot_token",
                "Content-Type: application/json",
                authorization,
                wechat_uin,
            },
        };
    }

    fn deinit(self: *const AuthHeaderSet, allocator: std.mem.Allocator) void {
        allocator.free(self.authorization);
        allocator.free(self.wechat_uin);
    }
};

const SendTarget = struct {
    user_id: []const u8,
    context_token: ?[]const u8 = null,
};

const InboundTextItem = struct {
    text: ?[]const u8 = null,
};

const InboundVoiceItem = struct {
    text: ?[]const u8 = null,
};

const InboundItem = struct {
    type: ?u8 = null,
    text_item: ?InboundTextItem = null,
    voice_item: ?InboundVoiceItem = null,
};

const InboundMessage = struct {
    message_id: ?u64 = null,
    from_user_id: ?[]const u8 = null,
    create_time_ms: ?u64 = null,
    context_token: ?[]const u8 = null,
    item_list: ?[]const InboundItem = null,
};

const GetUpdatesResponse = struct {
    ret: ?i64 = null,
    errcode: ?i64 = null,
    errmsg: ?[]const u8 = null,
    msgs: ?[]const InboundMessage = null,
    get_updates_buf: ?[]const u8 = null,
    longpolling_timeout_ms: ?u64 = null,
};

const ParsedUpdates = struct {
    messages: []root.ChannelMessage,
    next_updates_buf: ?[]u8 = null,
    longpolling_timeout_ms: ?u64 = null,

    fn deinit(self: *ParsedUpdates, allocator: std.mem.Allocator) void {
        for (self.messages) |*message| {
            message.deinit(allocator);
        }
        if (self.messages.len > 0) allocator.free(self.messages);
        if (self.next_updates_buf) |next_updates_buf| allocator.free(next_updates_buf);
        self.* = .{
            .messages = &.{},
            .next_updates_buf = null,
            .longpolling_timeout_ms = null,
        };
    }

    fn takeMessages(self: *ParsedUpdates) []root.ChannelMessage {
        const messages = self.messages;
        self.messages = &.{};
        return messages;
    }
};

pub const WeixinChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.WeixinConfig,
    running: bool = false,
    updates_buf: []u8 = &.{},
    context_tokens: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, cfg: config_types.WeixinConfig) WeixinChannel {
        return .{ .allocator = allocator, .config = cfg };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WeixinConfig) WeixinChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *WeixinChannel) []const u8 {
        return "weixin";
    }

    pub fn healthCheck(self: *WeixinChannel) bool {
        return self.running or self.config.token.len > 0;
    }

    pub fn deinit(self: *WeixinChannel) void {
        if (self.updates_buf.len > 0) {
            self.allocator.free(self.updates_buf);
            self.updates_buf = &.{};
        }

        var it = self.context_tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.context_tokens.deinit(self.allocator);
        self.context_tokens = .empty;
    }

    pub fn sendMessage(self: *WeixinChannel, target: []const u8, text: []const u8) !void {
        if (target.len == 0) return error.InvalidTarget;
        if (builtin.is_test) return;

        const token = self.config.token;
        if (token.len == 0) return error.WeixinMissingToken;
        const parsed_target = parseReplyTarget(target);
        const context_token = self.lookupContextToken(parsed_target.user_id) orelse parsed_target.context_token;
        if (context_token == null) {
            log.warn("sending weixin message without context_token for user {s}", .{parsed_target.user_id});
        }

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try appendSendMessagePayload(self.allocator, &payload, parsed_target.user_id, text, context_token);

        const url = try buildUrl(self.allocator, self.config.base_url, "ilink/bot/sendmessage");
        defer self.allocator.free(url);

        var headers = try AuthHeaderSet.init(self.allocator, token);
        defer headers.deinit(self.allocator);

        const resp_body = root.http_util.curlPostWithProxy(
            self.allocator,
            url,
            payload.items,
            &headers.headers,
            self.config.proxy,
            SEND_TIMEOUT_SECS,
        ) catch return error.WeixinApiError;
        defer self.allocator.free(resp_body);

        try ensureApiResponseOk(self.allocator, resp_body);
    }

    pub fn pollMessages(self: *WeixinChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        if (builtin.is_test) return &.{};
        if (self.config.token.len == 0) return error.WeixinMissingToken;

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try appendGetUpdatesPayload(self.allocator, &payload, self.updates_buf);

        const url = try buildUrl(self.allocator, self.config.base_url, "ilink/bot/getupdates");
        defer self.allocator.free(url);

        var headers = try AuthHeaderSet.init(self.allocator, self.config.token);
        defer headers.deinit(self.allocator);

        const resp_body = root.http_util.curlPostWithProxy(
            self.allocator,
            url,
            payload.items,
            &headers.headers,
            self.config.proxy,
            GET_UPDATES_TIMEOUT_SECS,
        ) catch return error.WeixinApiError;
        defer self.allocator.free(resp_body);

        var parsed = try parseGetUpdatesResponse(allocator, resp_body, self.config.allow_from);
        errdefer parsed.deinit(allocator);

        if (parsed.next_updates_buf) |next_updates_buf| {
            try self.setUpdatesBuf(next_updates_buf);
            allocator.free(next_updates_buf);
            parsed.next_updates_buf = null;
        }

        for (parsed.messages) |message| {
            const reply_target = message.reply_target orelse continue;
            const parsed_target = parseReplyTarget(reply_target);
            const context_token = parsed_target.context_token orelse continue;
            try self.setContextToken(parsed_target.user_id, context_token);
        }

        return parsed.takeMessages();
    }

    fn setUpdatesBuf(self: *WeixinChannel, next_updates_buf: []const u8) !void {
        if (self.updates_buf.len > 0) {
            self.allocator.free(self.updates_buf);
            self.updates_buf = &.{};
        }

        if (next_updates_buf.len == 0) return;
        self.updates_buf = try self.allocator.dupe(u8, next_updates_buf);
    }

    fn setContextToken(self: *WeixinChannel, user_id: []const u8, context_token: []const u8) !void {
        if (user_id.len == 0 or context_token.len == 0) return;

        const owned_context_token = try self.allocator.dupe(u8, context_token);
        errdefer self.allocator.free(owned_context_token);
        if (self.context_tokens.getPtr(user_id)) |existing_value| {
            self.allocator.free(existing_value.*);
            existing_value.* = owned_context_token;
            return;
        }

        const owned_user_id = try self.allocator.dupe(u8, user_id);
        errdefer self.allocator.free(owned_user_id);
        try self.context_tokens.put(self.allocator, owned_user_id, owned_context_token);
    }

    fn lookupContextToken(self: *WeixinChannel, user_id: []const u8) ?[]const u8 {
        return self.context_tokens.get(user_id);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WeixinChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ── iLink API types ────────────────────────────────────────────────

pub const QrCodeResponse = struct {
    qrcode: []const u8 = "",
    qrcode_img_content: []const u8 = "",
};

pub const StatusResponse = struct {
    status: []const u8 = "",
    bot_token: []const u8 = "",
    ilink_bot_id: []const u8 = "",
    baseurl: []const u8 = "",
    ilink_user_id: []const u8 = "",
    redirect_host: []const u8 = "",
};

pub const LoginResult = struct {
    bot_token: []u8,
    user_id: []u8,
    account_id: []u8,
    base_url: []u8,

    pub fn deinit(self: *LoginResult, allocator: std.mem.Allocator) void {
        allocator.free(self.bot_token);
        allocator.free(self.user_id);
        allocator.free(self.account_id);
        allocator.free(self.base_url);
    }
};

pub const LoginOptions = struct {
    base_url: []const u8 = ILINK_BASE_URL,
    timeout_ns: u64 = LOGIN_TIMEOUT_NS,
    proxy: ?[]const u8 = null,
};

// ── QR Login Flow ──────────────────────────────────────────────────

pub fn performLogin(allocator: std.mem.Allocator, opts: LoginOptions) !LoginResult {
    if (builtin.is_test) {
        return LoginResult{
            .bot_token = try allocator.dupe(u8, "test-bot-token"),
            .user_id = try allocator.dupe(u8, "test-user-id"),
            .account_id = try allocator.dupe(u8, "test-account-id"),
            .base_url = try allocator.dupe(u8, "https://test.example.com/"),
        };
    }

    const qr_resp = try requestQrCode(allocator, opts.base_url, opts.proxy);
    defer allocator.free(qr_resp.qrcode);
    defer allocator.free(qr_resp.qrcode_img_content);

    // Display QR code in terminal
    try displayQrCode(qr_resp.qrcode_img_content);

    // Poll for scan status
    var poll_base_url: ?[]u8 = null;
    defer if (poll_base_url) |u| allocator.free(u);
    var scanned_printed = false;

    const deadline = std_compat.time.nanoTimestamp() + @as(i128, opts.timeout_ns);

    while (std_compat.time.nanoTimestamp() < deadline) {
        std_compat.thread.sleep(QR_POLL_INTERVAL_NS);

        const effective_base = if (poll_base_url) |u| u else opts.base_url;
        const status_resp = pollQrStatus(allocator, effective_base, qr_resp.qrcode, opts.proxy) catch continue;
        defer {
            allocator.free(status_resp.status);
            allocator.free(status_resp.bot_token);
            allocator.free(status_resp.ilink_bot_id);
            allocator.free(status_resp.baseurl);
            allocator.free(status_resp.ilink_user_id);
            allocator.free(status_resp.redirect_host);
        }

        if (std.mem.eql(u8, status_resp.status, "wait")) {
            continue;
        } else if (std.mem.eql(u8, status_resp.status, "scaned")) {
            if (!scanned_printed) {
                std.debug.print("QR Code scanned! Please confirm login on your WeChat app...\n", .{});
                scanned_printed = true;
            }
        } else if (std.mem.eql(u8, status_resp.status, "confirmed")) {
            if (status_resp.bot_token.len == 0 or status_resp.ilink_bot_id.len == 0) {
                return error.WeixinLoginMissingCredentials;
            }
            const result_base = if (status_resp.baseurl.len > 0)
                try allocator.dupe(u8, status_resp.baseurl)
            else
                try allocator.dupe(u8, opts.base_url);
            errdefer allocator.free(result_base);

            return LoginResult{
                .bot_token = try allocator.dupe(u8, status_resp.bot_token),
                .user_id = try allocator.dupe(u8, status_resp.ilink_user_id),
                .account_id = try allocator.dupe(u8, status_resp.ilink_bot_id),
                .base_url = result_base,
            };
        } else if (std.mem.eql(u8, status_resp.status, "scaned_but_redirect")) {
            if (status_resp.redirect_host.len > 0) {
                const new_url = try std.fmt.allocPrint(allocator, "https://{s}/", .{status_resp.redirect_host});
                if (poll_base_url) |old| allocator.free(old);
                poll_base_url = new_url;
                std.debug.print("Switched polling host to {s}\n", .{status_resp.redirect_host});
            }
        } else if (std.mem.eql(u8, status_resp.status, "expired")) {
            return error.WeixinQrCodeExpired;
        }
    }

    return error.WeixinLoginTimeout;
}

fn displayQrCode(url: []const u8) !void {
    std.debug.print("\n=======================================================\n", .{});
    std.debug.print("Please scan the following QR code with WeChat to login:\n", .{});
    std.debug.print("=======================================================\n\n", .{});

    const qr = qr_mod.encode(url) catch {
        std.debug.print("(Could not generate QR code in terminal)\n", .{});
        std.debug.print("QR Code Link: {s}\n\n", .{url});
        return;
    };

    var buf: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    qr_mod.renderTerminal(&qr, &writer) catch {
        std.debug.print("(Could not render QR code)\n", .{});
        std.debug.print("QR Code Link: {s}\n\n", .{url});
        return;
    };

    std.debug.print("{s}", .{writer.buffered()});
    std.debug.print("\nQR Code Link: {s}\n\n", .{url});
    std.debug.print("Waiting for scan...\n", .{});
}

// ── iLink API Client ───────────────────────────────────────────────

fn ilinkHeaders() [2][]const u8 {
    return .{
        "iLink-App-Id: " ++ ILINK_APP_ID,
        "iLink-App-ClientVersion: " ++ ILINK_CLIENT_VERSION,
    };
}

fn buildWechatUinHeader(allocator: std.mem.Allocator) ![]u8 {
    var random_bytes: [4]u8 = undefined;
    std_compat.crypto.random.bytes(&random_bytes);
    const value = std.mem.readInt(u32, &random_bytes, .big);

    var decimal_buf: [16]u8 = undefined;
    const decimal = try std.fmt.bufPrint(&decimal_buf, "{d}", .{value});

    var encoded_buf: [24]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(
        encoded_buf[0..std.base64.standard.Encoder.calcSize(decimal.len)],
        decimal,
    );

    return std.fmt.allocPrint(allocator, "X-WECHAT-UIN: {s}", .{encoded});
}

fn buildUrl(allocator: std.mem.Allocator, base_url: []const u8, endpoint: []const u8) ![]u8 {
    var base_end = base_url.len;
    while (base_end > 0 and base_url[base_end - 1] == '/') : (base_end -= 1) {}
    const base = base_url[0..base_end];
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, endpoint });
}

fn requestQrCode(allocator: std.mem.Allocator, base_url: []const u8, proxy: ?[]const u8) !struct { qrcode: []u8, qrcode_img_content: []u8 } {
    const url = try std.fmt.allocPrint(allocator, "{s}ilink/bot/get_bot_qrcode?bot_type=3", .{
        if (std.mem.endsWith(u8, base_url, "/")) base_url else blk: {
            // base_url always ends with / from default
            break :blk base_url;
        },
    });
    defer allocator.free(url);

    const headers = ilinkHeaders();
    const resp_body = root.http_util.curlGetWithProxy(allocator, url, &headers, SEND_TIMEOUT_SECS, proxy) catch return error.WeixinApiError;
    defer allocator.free(resp_body);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value != .object) return error.WeixinApiError;

    const qrcode_val = parsed.value.object.get("qrcode") orelse return error.WeixinApiError;
    const img_val = parsed.value.object.get("qrcode_img_content") orelse return error.WeixinApiError;

    if (qrcode_val != .string or img_val != .string) return error.WeixinApiError;
    if (qrcode_val.string.len == 0) return error.WeixinApiError;

    return .{
        .qrcode = try allocator.dupe(u8, qrcode_val.string),
        .qrcode_img_content = try allocator.dupe(u8, img_val.string),
    };
}

fn pollQrStatus(allocator: std.mem.Allocator, base_url: []const u8, qrcode: []const u8, proxy: ?[]const u8) !StatusResponse {
    const base = if (std.mem.endsWith(u8, base_url, "/")) base_url else base_url;
    const encoded_qrcode = try url_percent.encode(allocator, qrcode);
    defer allocator.free(encoded_qrcode);
    const url = try std.fmt.allocPrint(allocator, "{s}ilink/bot/get_qrcode_status?qrcode={s}", .{ base, encoded_qrcode });
    defer allocator.free(url);

    const headers = ilinkHeaders();
    const resp_body = root.http_util.curlGetWithProxy(allocator, url, &headers, GET_UPDATES_TIMEOUT_SECS, proxy) catch return error.WeixinApiError;
    defer allocator.free(resp_body);

    return parseStatusResponse(allocator, resp_body);
}

pub fn parseStatusResponse(allocator: std.mem.Allocator, json_body: []const u8) !StatusResponse {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value != .object) return error.WeixinApiError;
    const obj = parsed.value.object;

    const status = obj.get("status") orelse return error.WeixinApiError;
    if (status != .string) return error.WeixinApiError;

    return StatusResponse{
        .status = try allocator.dupe(u8, status.string),
        .bot_token = try dupeOptionalString(allocator, obj, "bot_token"),
        .ilink_bot_id = try dupeOptionalString(allocator, obj, "ilink_bot_id"),
        .baseurl = try dupeOptionalString(allocator, obj, "baseurl"),
        .ilink_user_id = try dupeOptionalString(allocator, obj, "ilink_user_id"),
        .redirect_host = try dupeOptionalString(allocator, obj, "redirect_host"),
    };
}

fn dupeOptionalString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]u8 {
    const val = obj.get(key) orelse return try allocator.dupe(u8, "");
    if (val != .string) return try allocator.dupe(u8, "");
    return try allocator.dupe(u8, val.string);
}

fn appendGeneratedClientId(writer: anytype) !void {
    var random_bytes: [8]u8 = undefined;
    std_compat.crypto.random.bytes(&random_bytes);
    const random_id = std.mem.readInt(u64, &random_bytes, .big);

    var client_id_buf: [48]u8 = undefined;
    const client_id = try std.fmt.bufPrint(&client_id_buf, "nullclaw-weixin-{x}", .{random_id});
    try root.appendJsonStringW(writer, client_id);
}

fn appendBaseInfo(writer: anytype) !void {
    try writer.writeAll("{\"channel_version\":");
    try root.appendJsonStringW(writer, CHANNEL_VERSION);
    try writer.writeAll("}");
}

fn appendGetUpdatesPayload(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), updates_buf: []const u8) !void {
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    const writer = &out_writer.writer;

    try writer.writeAll("{\"get_updates_buf\":");
    try root.appendJsonStringW(writer, updates_buf);
    try writer.writeAll(",\"base_info\":");
    try appendBaseInfo(writer);
    try writer.writeAll("}");

    out.* = out_writer.toArrayList();
}

fn appendSendMessagePayload(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    to_user: []const u8,
    text: []const u8,
    context_token: ?[]const u8,
) !void {
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    const writer = &out_writer.writer;

    try writer.writeAll("{\"msg\":{\"from_user_id\":\"\",\"to_user_id\":");
    try root.appendJsonStringW(writer, to_user);
    try writer.writeAll(",\"client_id\":");
    try appendGeneratedClientId(writer);
    try writer.print(",\"message_type\":{d},\"message_state\":{d}", .{ MESSAGE_TYPE_BOT, MESSAGE_STATE_FINISH });
    if (text.len > 0) {
        try writer.writeAll(",\"item_list\":[{\"type\":1,\"text_item\":{\"text\":");
        try root.appendJsonStringW(writer, text);
        try writer.writeAll("}}]");
    }
    if (context_token) |token| {
        try writer.writeAll(",\"context_token\":");
        try root.appendJsonStringW(writer, token);
    }
    try writer.writeAll("},\"base_info\":");
    try appendBaseInfo(writer);
    try writer.writeAll("}");

    out.* = out_writer.toArrayList();
}

fn parseReplyTarget(target: []const u8) SendTarget {
    if (std.mem.indexOfScalar(u8, target, WEIXIN_REPLY_TARGET_SEPARATOR)) |separator_index| {
        if (separator_index == 0) return .{ .user_id = target };
        const context_token = target[separator_index + 1 ..];
        return .{
            .user_id = target[0..separator_index],
            .context_token = if (context_token.len > 0) context_token else null,
        };
    }

    return .{ .user_id = target };
}

fn encodeReplyTarget(allocator: std.mem.Allocator, user_id: []const u8, context_token: ?[]const u8) ![]u8 {
    if (context_token) |token| {
        if (token.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ user_id, WEIXIN_REPLY_TARGET_SEPARATOR, token });
        }
    }
    return allocator.dupe(u8, user_id);
}

fn extractInboundText(item_list: ?[]const InboundItem) ?[]const u8 {
    const items = item_list orelse return null;
    for (items) |item| {
        if (item.type == null or item.type.? == GET_UPDATES_ITEM_TYPE_TEXT) {
            if (item.text_item) |text_item| {
                if (text_item.text) |text| {
                    const trimmed = std.mem.trim(u8, text, " \t\r\n");
                    if (trimmed.len > 0) return trimmed;
                }
            }
        }
        if (item.type == null or item.type.? == GET_UPDATES_ITEM_TYPE_VOICE) {
            if (item.voice_item) |voice_item| {
                if (voice_item.text) |text| {
                    const trimmed = std.mem.trim(u8, text, " \t\r\n");
                    if (trimmed.len > 0) return trimmed;
                }
            }
        }
    }
    return null;
}

fn buildInboundMessageId(allocator: std.mem.Allocator, message: InboundMessage, sender: []const u8) ![]u8 {
    if (message.message_id) |message_id| {
        return std.fmt.allocPrint(allocator, "{d}", .{message_id});
    }
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ sender, message.create_time_ms orelse 0 });
}

fn parseGetUpdatesResponse(
    allocator: std.mem.Allocator,
    json_body: []const u8,
    allow_from: []const []const u8,
) !ParsedUpdates {
    var parsed = std.json.parseFromSlice(GetUpdatesResponse, allocator, json_body, .{
        .ignore_unknown_fields = true,
    }) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value.ret) |ret| {
        if (ret != 0) return error.WeixinApiError;
    }
    if (parsed.value.errcode) |errcode| {
        if (errcode != 0) return error.WeixinApiError;
    }

    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    errdefer {
        for (messages.items) |*message| {
            message.deinit(allocator);
        }
        messages.deinit(allocator);
    }

    const inbound_messages = parsed.value.msgs orelse &.{};
    for (inbound_messages) |message| {
        const sender = message.from_user_id orelse continue;
        if (sender.len == 0) continue;
        if (allow_from.len > 0 and !root.isAllowedExactScoped("weixin channel", allow_from, sender)) {
            continue;
        }

        const text = extractInboundText(message.item_list) orelse continue;
        const reply_target = try encodeReplyTarget(allocator, sender, message.context_token);
        errdefer allocator.free(reply_target);

        try messages.append(allocator, .{
            .id = try buildInboundMessageId(allocator, message, sender),
            .sender = try allocator.dupe(u8, sender),
            .content = try allocator.dupe(u8, text),
            .channel = "weixin",
            .timestamp = message.create_time_ms orelse 0,
            .reply_target = reply_target,
            .message_id = if (message.message_id) |message_id| @intCast(message_id) else null,
            .is_group = false,
        });
    }

    return .{
        .messages = try messages.toOwnedSlice(allocator),
        .next_updates_buf = if (parsed.value.get_updates_buf) |next_updates_buf|
            try allocator.dupe(u8, next_updates_buf)
        else
            null,
        .longpolling_timeout_ms = parsed.value.longpolling_timeout_ms,
    };
}

fn ensureApiResponseOk(allocator: std.mem.Allocator, body: []const u8) !void {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "{}")) return;

    const Response = struct {
        ret: ?i64 = null,
        errcode: ?i64 = null,
    };

    var parsed = std.json.parseFromSlice(Response, allocator, trimmed, .{
        .ignore_unknown_fields = true,
    }) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value.ret) |ret| {
        if (ret != 0) return error.WeixinApiError;
    }
    if (parsed.value.errcode) |errcode| {
        if (errcode != 0) return error.WeixinApiError;
    }
}

// ── Tests ──────────────────────────────────────────────────────────

test "weixin channel vtable contract" {
    var ch = WeixinChannel.init(std.testing.allocator, .{});
    try std.testing.expectEqualStrings("weixin", ch.channel().name());
    try std.testing.expect(!ch.channel().healthCheck());

    try ch.channel().start();
    try std.testing.expect(ch.channel().healthCheck());

    ch.channel().stop();
    try std.testing.expect(!ch.channel().healthCheck());
}

test "parseStatusResponse parses wait status" {
    const json =
        \\{"status":"wait"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("wait", resp.status);
}

test "parseStatusResponse parses confirmed status with credentials" {
    const json =
        \\{"status":"confirmed","bot_token":"tk_abc123","ilink_bot_id":"bot_456","ilink_user_id":"user_789","baseurl":"https://region.example.com/"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("confirmed", resp.status);
    try std.testing.expectEqualStrings("tk_abc123", resp.bot_token);
    try std.testing.expectEqualStrings("bot_456", resp.ilink_bot_id);
    try std.testing.expectEqualStrings("user_789", resp.ilink_user_id);
    try std.testing.expectEqualStrings("https://region.example.com/", resp.baseurl);
}

test "parseStatusResponse parses scaned_but_redirect" {
    const json =
        \\{"status":"scaned_but_redirect","redirect_host":"region2.weixin.qq.com"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("scaned_but_redirect", resp.status);
    try std.testing.expectEqualStrings("region2.weixin.qq.com", resp.redirect_host);
}

test "parseStatusResponse rejects invalid JSON" {
    try std.testing.expectError(error.WeixinApiError, parseStatusResponse(std.testing.allocator, "not json"));
}

test "parseStatusResponse rejects missing status field" {
    try std.testing.expectError(error.WeixinApiError, parseStatusResponse(std.testing.allocator, "{}"));
}

test "appendSendMessagePayload builds correct JSON" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendSendMessagePayload(std.testing.allocator, &buf, "user123", "hello", "ctx-456");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"to_user_id\":\"user123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"text\":\"hello\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, CHANNEL_VERSION) != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"context_token\":\"ctx-456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"msg\"") != null);
}

test "parseReplyTarget round trips embedded context token" {
    const target = try encodeReplyTarget(std.testing.allocator, "user123", "ctx-456");
    defer std.testing.allocator.free(target);

    const parsed_target = parseReplyTarget(target);
    try std.testing.expectEqualStrings("user123", parsed_target.user_id);
    try std.testing.expectEqualStrings("ctx-456", parsed_target.context_token.?);
}

test "AuthHeaderSet includes bearer token" {
    var headers = try AuthHeaderSet.init(std.testing.allocator, "token-123");
    defer headers.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("AuthorizationType: ilink_bot_token", headers.headers[2]);
    try std.testing.expect(std.mem.indexOf(u8, headers.headers[4], "Authorization: Bearer token-123") != null);
    try std.testing.expect(std.mem.indexOf(u8, headers.headers[5], "X-WECHAT-UIN: ") != null);
}

test "parseGetUpdatesResponse extracts text message and context token" {
    const json =
        \\{"ret":0,"msgs":[{"message_id":42,"from_user_id":"user-123","create_time_ms":1712345678901,"context_token":"ctx-456","item_list":[{"type":1,"text_item":{"text":"hello from weixin"}}]}],"get_updates_buf":"next-buf"}
    ;

    var parsed = try parseGetUpdatesResponse(std.testing.allocator, json, &.{});
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.messages.len);
    try std.testing.expectEqualStrings("user-123", parsed.messages[0].sender);
    try std.testing.expectEqualStrings("hello from weixin", parsed.messages[0].content);
    try std.testing.expectEqualStrings("next-buf", parsed.next_updates_buf.?);

    const parsed_target = parseReplyTarget(parsed.messages[0].reply_target.?);
    try std.testing.expectEqualStrings("user-123", parsed_target.user_id);
    try std.testing.expectEqualStrings("ctx-456", parsed_target.context_token.?);
}

test "parseGetUpdatesResponse filters allow_from when configured" {
    const json =
        \\{"ret":0,"msgs":[{"from_user_id":"blocked","item_list":[{"type":1,"text_item":{"text":"nope"}}]},{"from_user_id":"allowed","item_list":[{"type":1,"text_item":{"text":"ok"}}]}]}
    ;

    var parsed = try parseGetUpdatesResponse(std.testing.allocator, json, &.{"allowed"});
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.messages.len);
    try std.testing.expectEqualStrings("allowed", parsed.messages[0].sender);
}

test "weixin channel stores latest context token per user" {
    var ch = WeixinChannel.init(std.testing.allocator, .{});
    defer ch.deinit();

    try ch.setContextToken("user-123", "ctx-old");
    try ch.setContextToken("user-123", "ctx-new");
    try std.testing.expectEqualStrings("ctx-new", ch.lookupContextToken("user-123").?);
}

test "buildUrl joins base and endpoint" {
    const url = try buildUrl(std.testing.allocator, "https://example.com/", "ilink/bot/test");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/ilink/bot/test", url);
}

test "buildUrl handles base without trailing slash" {
    const url = try buildUrl(std.testing.allocator, "https://example.com", "ilink/bot/test");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/ilink/bot/test", url);
}

test "performLogin returns test data in test mode" {
    var result = try performLogin(std.testing.allocator, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("test-bot-token", result.bot_token);
    try std.testing.expectEqualStrings("test-account-id", result.account_id);
}

test "sendMessage returns in test mode" {
    var ch = WeixinChannel.init(std.testing.allocator, .{ .token = "test-token" });
    try ch.sendMessage("target", "hello");
}

test "sendMessage rejects empty target" {
    var ch = WeixinChannel.init(std.testing.allocator, .{ .token = "test-token" });
    try std.testing.expectError(error.InvalidTarget, ch.sendMessage("", "hello"));
}
