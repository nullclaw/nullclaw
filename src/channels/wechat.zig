const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const tencent_crypto = @import("../security/tencent_crypto.zig");

const ACCESS_TOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token";
const CUSTOM_SEND_URL = "https://api.weixin.qq.com/cgi-bin/message/custom/send";

pub const WeChatChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.WeChatConfig,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: config_types.WeChatConfig) WeChatChannel {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WeChatConfig) WeChatChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *WeChatChannel) []const u8 {
        return "wechat";
    }

    pub fn healthCheck(self: *WeChatChannel) bool {
        return self.running;
    }

    pub fn sendMessage(self: *WeChatChannel, target: []const u8, text: []const u8) !void {
        return sendActiveTextMessage(self, target, text);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *WeChatChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *WeChatChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WeChatChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WeChatChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WeChatChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WeChatChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedWeChatMessage = struct {
    to_user: []const u8,
    from_user: []const u8,
    content: []const u8,
    msg_type: []const u8,
    event_type: ?[]const u8 = null,
    event_key: ?[]const u8 = null,

    pub fn deinit(self: *ParsedWeChatMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.to_user);
        allocator.free(self.from_user);
        allocator.free(self.content);
        allocator.free(self.msg_type);
        if (self.event_type) |v| allocator.free(v);
        if (self.event_key) |v| allocator.free(v);
    }
};

fn appendActiveTextPayload(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), to_user: []const u8, text: []const u8) !void {
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    defer out.* = out_writer.toArrayList();
    const w = &out_writer.writer;
    try w.writeAll("{\"touser\":");
    try root.appendJsonStringW(w, to_user);
    try w.writeAll(",\"msgtype\":\"text\",\"text\":{\"content\":");
    try root.appendJsonStringW(w, text);
    try w.writeAll("}}");
}

fn fetchAccessToken(allocator: std.mem.Allocator, app_id: []const u8, app_secret: []const u8) ![]u8 {
    if (app_id.len == 0 or app_secret.len == 0) return error.WeChatMissingCredentials;

    var url_buf: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "{s}?grant_type=client_credential&appid={s}&secret={s}",
        .{ ACCESS_TOKEN_URL, app_id, app_secret },
    );

    const resp = root.http_util.curlGet(allocator, url, &.{}, "15") catch return error.WeChatApiError;
    defer allocator.free(resp);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return error.WeChatApiError;
    defer parsed.deinit();
    if (parsed.value != .object) return error.WeChatApiError;

    if (parsed.value.object.get("errcode")) |errcode_val| {
        if (errcode_val == .integer and errcode_val.integer != 0) return error.WeChatApiError;
    }

    const token_val = parsed.value.object.get("access_token") orelse return error.WeChatApiError;
    if (token_val != .string or token_val.string.len == 0) return error.WeChatApiError;
    return allocator.dupe(u8, token_val.string);
}

pub fn sendActiveTextMessage(self: *WeChatChannel, to_user: []const u8, text: []const u8) !void {
    if (to_user.len == 0) return error.InvalidTarget;
    if (builtin.is_test) return;

    const app_id = self.config.app_id orelse return error.WeChatMissingCredentials;
    const app_secret = self.config.app_secret orelse return error.WeChatMissingCredentials;

    const access_token = try fetchAccessToken(self.allocator, app_id, app_secret);
    defer self.allocator.free(access_token);

    var payload: std.ArrayListUnmanaged(u8) = .empty;
    defer payload.deinit(self.allocator);
    try appendActiveTextPayload(self.allocator, &payload, to_user, text);

    var send_url_buf: [512]u8 = undefined;
    const send_url = try std.fmt.bufPrint(&send_url_buf, "{s}?access_token={s}", .{ CUSTOM_SEND_URL, access_token });

    const resp = root.http_util.curlPostWithStatus(self.allocator, send_url, payload.items, &.{}) catch return error.WeChatApiError;
    defer self.allocator.free(resp.body);
    if (resp.status_code < 200 or resp.status_code >= 300) return error.WeChatApiError;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp.body, .{}) catch return error.WeChatApiError;
    defer parsed.deinit();
    if (parsed.value != .object) return error.WeChatApiError;

    const errcode_val = parsed.value.object.get("errcode") orelse return error.WeChatApiError;
    if (errcode_val != .integer or errcode_val.integer != 0) return error.WeChatApiError;
}

pub fn verifySignature(token: []const u8, timestamp: []const u8, nonce: []const u8, signature: []const u8) bool {
    const expected_hex = tencent_crypto.wechatSha1Signature(token, timestamp, nonce);
    return std.ascii.eqlIgnoreCase(signature, expected_hex[0..]);
}

pub fn verifyMessageSignature(
    token: []const u8,
    timestamp: []const u8,
    nonce: []const u8,
    encrypted: []const u8,
    msg_signature: []const u8,
) bool {
    const expected_hex = tencent_crypto.wechatMessageSha1Signature(token, timestamp, nonce, encrypted);
    return std.ascii.eqlIgnoreCase(msg_signature, expected_hex[0..]);
}

pub fn extractEncryptedField(payload: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, payload, " \t\r\n");
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '<') return xmlTagValue(trimmed, "Encrypt");
    if (trimmed[0] == '{') {
        if (extractJsonStringField(trimmed, "Encrypt")) |v| return v;
        if (extractJsonStringField(trimmed, "encrypt")) |v| return v;
    }
    return null;
}

pub fn decryptSecurePayload(
    allocator: std.mem.Allocator,
    encoding_aes_key: []const u8,
    encrypted_b64: []const u8,
    expected_app_id: ?[]const u8,
) ![]u8 {
    const key = tencent_crypto.decodeEncodingAesKey(encoding_aes_key) catch {
        return error.InvalidWeChatEncodingAesKey;
    };

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encrypted_b64) catch return error.InvalidWeChatEncryptedPayload;
    const cipher = try allocator.alloc(u8, decoded_len);
    defer allocator.free(cipher);
    _ = std.base64.standard.Decoder.decode(cipher, encrypted_b64) catch return error.InvalidWeChatEncryptedPayload;

    const plain_with_pad = try allocator.dupe(u8, cipher);
    defer allocator.free(plain_with_pad);
    tencent_crypto.aes256CbcDecryptInPlace(plain_with_pad, key, key[0..16].*) catch {
        return error.InvalidWeChatEncryptedPayload;
    };

    const plain = tencent_crypto.pkcs7Unpad(
        plain_with_pad,
        tencent_crypto.WECHAT_PKCS7_BLOCK,
    ) catch return error.InvalidWeChatEncryptedPayload;
    if (plain.len < 20) return error.InvalidWeChatEncryptedPayload;

    const msg_len = (@as(u32, plain[16]) << 24) |
        (@as(u32, plain[17]) << 16) |
        (@as(u32, plain[18]) << 8) |
        @as(u32, plain[19]);

    const msg_start: usize = 20;
    const msg_end: usize = msg_start + msg_len;
    if (msg_end > plain.len) return error.InvalidWeChatEncryptedPayload;

    const app_id = plain[msg_end..];
    if (expected_app_id) |expected| {
        if (expected.len > 0 and !std.mem.eql(u8, app_id, expected)) {
            return error.InvalidWeChatAppId;
        }
    }

    return allocator.dupe(u8, plain[msg_start..msg_end]);
}

fn extractJsonStringField(json: []const u8, key: []const u8) ?[]const u8 {
    var key_buf: [96]u8 = undefined;
    const needle = std.fmt.bufPrint(&key_buf, "\"{s}\":\"", .{key}) catch return null;
    const start = std.mem.indexOf(u8, json, needle) orelse return null;
    const content_start = start + needle.len;
    const rest = json[content_start..];
    const end_rel = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..end_rel];
}

pub fn parseIncomingPayload(allocator: std.mem.Allocator, payload: []const u8) !?ParsedWeChatMessage {
    const trimmed = std.mem.trim(u8, payload, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '<') return null;

    const msg_type = xmlTagValue(trimmed, "MsgType") orelse return null;

    const to_user = xmlTagValue(trimmed, "ToUserName") orelse return null;
    const from_user = xmlTagValue(trimmed, "FromUserName") orelse return null;
    if (to_user.len == 0 or from_user.len == 0) return null;

    if (std.ascii.eqlIgnoreCase(msg_type, "text")) {
        const content = xmlTagValue(trimmed, "Content") orelse return null;
        if (content.len == 0) return null;
        return ParsedWeChatMessage{
            .to_user = try allocator.dupe(u8, to_user),
            .from_user = try allocator.dupe(u8, from_user),
            .content = try allocator.dupe(u8, content),
            .msg_type = try allocator.dupe(u8, "text"),
        };
    }

    if (std.ascii.eqlIgnoreCase(msg_type, "event")) {
        const event_type = xmlTagValue(trimmed, "Event") orelse return null;
        const event_key_raw = xmlTagValue(trimmed, "EventKey") orelse "";
        const content = if (event_key_raw.len > 0)
            try std.fmt.allocPrint(allocator, "event:{s}:{s}", .{ event_type, event_key_raw })
        else
            try std.fmt.allocPrint(allocator, "event:{s}", .{event_type});
        errdefer allocator.free(content);

        return ParsedWeChatMessage{
            .to_user = try allocator.dupe(u8, to_user),
            .from_user = try allocator.dupe(u8, from_user),
            .content = content,
            .msg_type = try allocator.dupe(u8, "event"),
            .event_type = try allocator.dupe(u8, event_type),
            .event_key = if (event_key_raw.len > 0) try allocator.dupe(u8, event_key_raw) else null,
        };
    }

    if (std.ascii.eqlIgnoreCase(msg_type, "image")) {
        const pic_url = xmlTagValue(trimmed, "PicUrl") orelse "";
        const media_id = xmlTagValue(trimmed, "MediaId") orelse "";
        const content = if (pic_url.len > 0)
            try std.fmt.allocPrint(allocator, "image:{s}", .{pic_url})
        else if (media_id.len > 0)
            try std.fmt.allocPrint(allocator, "image_media:{s}", .{media_id})
        else
            return null;
        errdefer allocator.free(content);

        return ParsedWeChatMessage{
            .to_user = try allocator.dupe(u8, to_user),
            .from_user = try allocator.dupe(u8, from_user),
            .content = content,
            .msg_type = try allocator.dupe(u8, "image"),
        };
    }

    return null;
}

pub fn buildPassiveTextReply(
    allocator: std.mem.Allocator,
    to_user: []const u8,
    from_user: []const u8,
    content: []const u8,
    create_time: i64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "<xml><ToUserName><![CDATA[{s}]]></ToUserName><FromUserName><![CDATA[{s}]]></FromUserName><CreateTime>{d}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{s}]]></Content></xml>",
        .{ to_user, from_user, create_time, content },
    );
}

fn xmlTagValue(payload: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open_cdata = std.fmt.bufPrint(&open_buf, "<{s}><![CDATA[", .{tag}) catch return null;
    const close_cdata = std.fmt.bufPrint(&close_buf, "]]></{s}>", .{tag}) catch return null;

    if (std.mem.indexOf(u8, payload, open_cdata)) |start| {
        const content_start = start + open_cdata.len;
        if (std.mem.indexOf(u8, payload[content_start..], close_cdata)) |rel_end| {
            return payload[content_start .. content_start + rel_end];
        }
    }

    const open_plain = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close_plain = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    if (std.mem.indexOf(u8, payload, open_plain)) |start_plain| {
        const content_start = start_plain + open_plain.len;
        if (std.mem.indexOf(u8, payload[content_start..], close_plain)) |rel_end| {
            return payload[content_start .. content_start + rel_end];
        }
    }

    return null;
}

test "verifySignature accepts generated digest and rejects wrong value" {
    const token = "testtoken";
    const timestamp = "1710000000";
    const nonce = "123456";

    var parts = [3][]const u8{ token, timestamp, nonce };
    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < parts.len) : (j += 1) {
            if (std.mem.lessThan(u8, parts[j], parts[i])) {
                const tmp = parts[i];
                parts[i] = parts[j];
                parts[j] = tmp;
            }
        }
    }

    var sha1 = std.crypto.hash.Sha1.init(.{});
    for (parts) |p| sha1.update(p);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    const sig = std.fmt.bytesToHex(digest, .lower);

    try std.testing.expect(verifySignature(token, timestamp, nonce, sig[0..]));
    try std.testing.expect(!verifySignature(token, timestamp, nonce, "deadbeef"));
}

test "verifyMessageSignature accepts generated digest and rejects wrong value" {
    const token = "testtoken";
    const timestamp = "1710000000";
    const nonce = "123456";
    const encrypted = "ENCRYPTED_PAYLOAD";

    var parts = [4][]const u8{ token, timestamp, nonce, encrypted };
    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < parts.len) : (j += 1) {
            if (std.mem.lessThan(u8, parts[j], parts[i])) {
                const tmp = parts[i];
                parts[i] = parts[j];
                parts[j] = tmp;
            }
        }
    }

    var sha1 = std.crypto.hash.Sha1.init(.{});
    for (parts) |p| sha1.update(p);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    const sig = std.fmt.bytesToHex(digest, .lower);

    try std.testing.expect(verifyMessageSignature(token, timestamp, nonce, encrypted, sig[0..]));
    try std.testing.expect(!verifyMessageSignature(token, timestamp, nonce, encrypted, "deadbeef"));
}

test "parseIncomingPayload parses wechat XML text message" {
    const payload =
        "<xml>" ++
        "<ToUserName><![CDATA[gh_abcdef]]></ToUserName>" ++
        "<FromUserName><![CDATA[o_user123]]></FromUserName>" ++
        "<CreateTime>1710000000</CreateTime>" ++
        "<MsgType><![CDATA[text]]></MsgType>" ++
        "<Content><![CDATA[hello wechat]]></Content>" ++
        "</xml>";

    const msg_opt = try parseIncomingPayload(std.testing.allocator, payload);
    try std.testing.expect(msg_opt != null);
    var msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("gh_abcdef", msg.to_user);
    try std.testing.expectEqualStrings("o_user123", msg.from_user);
    try std.testing.expectEqualStrings("hello wechat", msg.content);
    try std.testing.expectEqualStrings("text", msg.msg_type);
}

test "parseIncomingPayload parses wechat event subscribe" {
    const payload =
        "<xml>" ++
        "<ToUserName><![CDATA[gh_abcdef]]></ToUserName>" ++
        "<FromUserName><![CDATA[o_user123]]></FromUserName>" ++
        "<CreateTime>1710000000</CreateTime>" ++
        "<MsgType><![CDATA[event]]></MsgType>" ++
        "<Event><![CDATA[subscribe]]></Event>" ++
        "</xml>";

    const msg_opt = try parseIncomingPayload(std.testing.allocator, payload);
    try std.testing.expect(msg_opt != null);
    var msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("event", msg.msg_type);
    try std.testing.expectEqualStrings("event:subscribe", msg.content);
    try std.testing.expect(msg.event_type != null);
    try std.testing.expectEqualStrings("subscribe", msg.event_type.?);
}

test "parseIncomingPayload parses wechat image message" {
    const payload =
        "<xml>" ++
        "<ToUserName><![CDATA[gh_abcdef]]></ToUserName>" ++
        "<FromUserName><![CDATA[o_user123]]></FromUserName>" ++
        "<CreateTime>1710000000</CreateTime>" ++
        "<MsgType><![CDATA[image]]></MsgType>" ++
        "<PicUrl><![CDATA[https://example.com/a.jpg]]></PicUrl>" ++
        "</xml>";

    const msg_opt = try parseIncomingPayload(std.testing.allocator, payload);
    try std.testing.expect(msg_opt != null);
    var msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("image", msg.msg_type);
    try std.testing.expectEqualStrings("image:https://example.com/a.jpg", msg.content);
}

test "buildPassiveTextReply emits expected xml" {
    const xml = try buildPassiveTextReply(std.testing.allocator, "o_user", "gh_bot", "pong", 1710000012);
    defer std.testing.allocator.free(xml);

    try std.testing.expect(std.mem.containsAtLeast(u8, xml, 1, "<ToUserName><![CDATA[o_user]]></ToUserName>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, xml, 1, "<FromUserName><![CDATA[gh_bot]]></FromUserName>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, xml, 1, "<Content><![CDATA[pong]]></Content>"));
}

test "extractEncryptedField parses XML Encrypt" {
    const payload =
        "<xml>" ++
        "<ToUserName><![CDATA[gh_abc]]></ToUserName>" ++
        "<Encrypt><![CDATA[ENC_PAYLOAD]]></Encrypt>" ++
        "</xml>";
    const enc = extractEncryptedField(payload);
    try std.testing.expect(enc != null);
    try std.testing.expectEqualStrings("ENC_PAYLOAD", enc.?);
}

test "decryptSecurePayload rejects invalid encoding_aes_key length" {
    try std.testing.expectError(
        error.InvalidWeChatEncodingAesKey,
        decryptSecurePayload(
            std.testing.allocator,
            "short",
            "abcd",
            null,
        ),
    );
}

test "wechat smoke basic channel contract" {
    var ch = WeChatChannel.init(std.testing.allocator, .{
        .callback_token = "wechat-token",
    });
    try std.testing.expectEqualStrings("wechat", ch.channel().name());
    try std.testing.expect(!ch.channel().healthCheck());
}
