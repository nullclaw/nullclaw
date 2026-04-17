const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const tencent_crypto = @import("../security/tencent_crypto.zig");

const log = std.log.scoped(.wecom);

/// WeCom channel MVP (outbound via group webhook bot).
///
/// This MVP supports only outgoing text/markdown messages to a WeCom webhook URL.
/// Inbound callbacks and app-level access_token flow are out-of-scope for this phase.
pub const WeComChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.WeComConfig,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: config_types.WeComConfig) WeComChannel {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WeComConfig) WeComChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *WeComChannel) []const u8 {
        return "wecom";
    }

    pub fn healthCheck(self: *WeComChannel) bool {
        return self.running and isValidWebhookUrl(self.config.webhook_url);
    }

    pub fn sendMessage(self: *WeComChannel, webhook_url: []const u8, text: []const u8) !void {
        if (!isValidWebhookUrl(webhook_url)) return error.InvalidWeComWebhookUrl;

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try appendTextPayload(self.allocator, &payload, text);

        const resp = root.http_util.curlPost(self.allocator, webhook_url, payload.items, &.{}) catch |err| {
            log.err("wecom send failed: {}", .{err});
            return error.WeComApiError;
        };
        defer self.allocator.free(resp);

        // WeCom webhook success returns JSON with errcode == 0.
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch {
            return error.WeComApiError;
        };
        defer parsed.deinit();

        if (parsed.value != .object) return error.WeComApiError;
        const errcode_val = parsed.value.object.get("errcode") orelse return error.WeComApiError;
        if (errcode_val != .integer or errcode_val.integer != 0) return error.WeComApiError;
    }

    pub fn sendMarkdown(self: *WeComChannel, webhook_url: []const u8, markdown: []const u8) !void {
        if (!isValidWebhookUrl(webhook_url)) return error.InvalidWeComWebhookUrl;

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try appendMarkdownPayload(self.allocator, &payload, markdown);

        const resp = root.http_util.curlPost(self.allocator, webhook_url, payload.items, &.{}) catch |err| {
            log.err("wecom markdown send failed: {}", .{err});
            return error.WeComApiError;
        };
        defer self.allocator.free(resp);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch {
            return error.WeComApiError;
        };
        defer parsed.deinit();

        if (parsed.value != .object) return error.WeComApiError;
        const errcode_val = parsed.value.object.get("errcode") orelse return error.WeComApiError;
        if (errcode_val != .integer or errcode_val.integer != 0) return error.WeComApiError;
    }

    pub fn sendMessageAuto(self: *WeComChannel, target: []const u8, text: []const u8) !void {
        // target can override configured webhook URL for operational flexibility.
        const webhook_url = if (target.len > 0) target else self.config.webhook_url;

        // WeCom webhook text limit is 2048 bytes. If larger, fall back to markdown (4096 bytes).
        if (text.len <= 2048) {
            return self.sendMessage(webhook_url, text);
        }
        return self.sendMarkdown(webhook_url, text);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *WeComChannel = @ptrCast(@alignCast(ptr));
        if (!isValidWebhookUrl(self.config.webhook_url)) return error.InvalidWeComWebhookUrl;
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *WeComChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WeComChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessageAuto(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WeComChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WeComChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WeComChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedWeComMessage = struct {
    sender: []const u8,
    content: []const u8,
    msg_type: []const u8,
    agent_id: ?[]const u8 = null,

    pub fn deinit(self: *ParsedWeComMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
        allocator.free(self.msg_type);
        if (self.agent_id) |aid| allocator.free(aid);
    }
};

fn appendTextPayload(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), text: []const u8) !void {
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    defer out.* = out_writer.toArrayList();
    const w = &out_writer.writer;
    try w.writeAll("{\"msgtype\":\"text\",\"text\":{\"content\":");
    try root.appendJsonStringW(w, text);
    try w.writeAll("}}");
}

fn appendMarkdownPayload(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), markdown: []const u8) !void {
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    defer out.* = out_writer.toArrayList();
    const w = &out_writer.writer;
    try w.writeAll("{\"msgtype\":\"markdown\",\"markdown\":{\"content\":");
    try root.appendJsonStringW(w, markdown);
    try w.writeAll("}}");
}

fn isValidWebhookUrl(url: []const u8) bool {
    if (!std.mem.startsWith(u8, url, "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=")) {
        return false;
    }
    const key = url["https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=".len..];
    return key.len > 0;
}

pub fn hasSecureCallbackConfig(cfg: config_types.WeComConfig) bool {
    const token = cfg.callback_token orelse "";
    const aes = cfg.encoding_aes_key orelse "";
    return token.len > 0 and aes.len > 0;
}

pub fn extractEncryptedField(payload: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, payload, " \t\r\n");
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '<') {
        return xmlTagValue(trimmed, "Encrypt");
    }
    if (trimmed[0] == '{') {
        if (extractJsonStringField(trimmed, "Encrypt")) |v| return v;
        if (extractJsonStringField(trimmed, "encrypt")) |v| return v;
    }
    return null;
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

pub fn verifySignature(
    token: []const u8,
    timestamp: []const u8,
    nonce: []const u8,
    encrypted: []const u8,
    msg_signature: []const u8,
) bool {
    const expected_hex = tencent_crypto.wechatMessageSha1Signature(token, timestamp, nonce, encrypted);
    return std.ascii.eqlIgnoreCase(msg_signature, expected_hex[0..]);
}

pub fn decryptSecurePayload(
    allocator: std.mem.Allocator,
    encoding_aes_key: []const u8,
    encrypted_b64: []const u8,
    expected_receive_id: ?[]const u8,
) ![]u8 {
    const key = tencent_crypto.decodeEncodingAesKey(encoding_aes_key) catch {
        return error.InvalidWeComEncodingAesKey;
    };

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encrypted_b64) catch return error.InvalidWeComEncryptedPayload;
    const cipher = try allocator.alloc(u8, decoded_len);
    defer allocator.free(cipher);
    _ = std.base64.standard.Decoder.decode(cipher, encrypted_b64) catch return error.InvalidWeComEncryptedPayload;

    const plain_with_pad = try allocator.dupe(u8, cipher);
    defer allocator.free(plain_with_pad);
    tencent_crypto.aes256CbcDecryptInPlace(plain_with_pad, key, key[0..16].*) catch {
        return error.InvalidWeComEncryptedPayload;
    };

    const plain = tencent_crypto.pkcs7Unpad(
        plain_with_pad,
        tencent_crypto.WECHAT_PKCS7_BLOCK,
    ) catch return error.InvalidWeComEncryptedPayload;
    if (plain.len < 20) return error.InvalidWeComEncryptedPayload;

    const msg_len = (@as(u32, plain[16]) << 24) |
        (@as(u32, plain[17]) << 16) |
        (@as(u32, plain[18]) << 8) |
        @as(u32, plain[19]);

    const msg_start: usize = 20;
    const msg_end: usize = msg_start + msg_len;
    if (msg_end > plain.len) return error.InvalidWeComEncryptedPayload;

    const receive_id = plain[msg_end..];
    if (expected_receive_id) |expected| {
        if (expected.len > 0 and !std.mem.eql(u8, receive_id, expected)) {
            return error.InvalidWeComReceiveId;
        }
    }

    return allocator.dupe(u8, plain[msg_start..msg_end]);
}

pub fn parseIncomingPayload(allocator: std.mem.Allocator, payload: []const u8) !?ParsedWeComMessage {
    const trimmed = std.mem.trim(u8, payload, " \t\r\n");
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '<') {
        return parseXmlIncomingPayload(allocator, trimmed);
    }
    if (trimmed[0] == '{') {
        return parseJsonIncomingPayload(allocator, trimmed);
    }
    return null;
}

fn parseXmlIncomingPayload(allocator: std.mem.Allocator, payload: []const u8) !?ParsedWeComMessage {
    const msg_type_raw = xmlTagValue(payload, "MsgType") orelse return null;
    if (!std.ascii.eqlIgnoreCase(msg_type_raw, "text")) return null;

    const sender_raw = xmlTagValue(payload, "FromUserName") orelse return null;
    const content_raw = xmlTagValue(payload, "Content") orelse return null;
    if (sender_raw.len == 0 or content_raw.len == 0) return null;

    const out = ParsedWeComMessage{
        .sender = try allocator.dupe(u8, sender_raw),
        .content = try allocator.dupe(u8, content_raw),
        .msg_type = try allocator.dupe(u8, "text"),
        .agent_id = if (xmlTagValue(payload, "AgentID")) |agent| try allocator.dupe(u8, agent) else null,
    };
    return out;
}

fn parseJsonIncomingPayload(allocator: std.mem.Allocator, payload: []const u8) !?ParsedWeComMessage {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch {
        return null;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const msg_type_raw = blk: {
        if (obj.get("MsgType")) |v| {
            if (v == .string) break :blk v.string;
        }
        if (obj.get("msgtype")) |v| {
            if (v == .string) break :blk v.string;
        }
        break :blk "text";
    };
    if (!std.ascii.eqlIgnoreCase(msg_type_raw, "text")) return null;

    const sender_raw = blk: {
        if (obj.get("FromUserName")) |v| {
            if (v == .string) break :blk v.string;
        }
        if (obj.get("from")) |v| {
            if (v == .string) break :blk v.string;
        }
        break :blk "";
    };

    const content_raw = blk: {
        if (obj.get("Content")) |v| {
            if (v == .string) break :blk v.string;
        }
        if (obj.get("text")) |v| {
            if (v == .string) break :blk v.string;
        }
        break :blk "";
    };

    if (sender_raw.len == 0 or content_raw.len == 0) return null;

    return ParsedWeComMessage{
        .sender = try allocator.dupe(u8, sender_raw),
        .content = try allocator.dupe(u8, content_raw),
        .msg_type = try allocator.dupe(u8, "text"),
        .agent_id = if (obj.get("AgentID")) |aid| if (aid == .string) try allocator.dupe(u8, aid.string) else null else null,
    };
}

fn xmlTagValue(payload: []const u8, tag: []const u8) ?[]const u8 {
    // First try CDATA form: <Tag><![CDATA[value]]></Tag>
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open_cdata = std.fmt.bufPrint(&open_buf, "<{s}><![CDATA[", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "]]></{s}>", .{tag}) catch return null;

    if (std.mem.indexOf(u8, payload, open_cdata)) |start| {
        const content_start = start + open_cdata.len;
        if (std.mem.indexOf(u8, payload[content_start..], close)) |rel_end| {
            return payload[content_start .. content_start + rel_end];
        }
    }

    // Fallback plain form: <Tag>value</Tag>
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

test "isValidWebhookUrl accepts official wecom webhook URL" {
    try std.testing.expect(isValidWebhookUrl("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc123"));
}

test "isValidWebhookUrl rejects non-https and non-wecom URL" {
    try std.testing.expect(!isValidWebhookUrl("http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc123"));
    try std.testing.expect(!isValidWebhookUrl("https://example.com/cgi-bin/webhook/send?key=abc123"));
}

test "appendTextPayload emits expected JSON envelope" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try appendTextPayload(std.testing.allocator, &out, "hello\nwecom");
    try std.testing.expect(std.mem.containsAtLeast(u8, out.items, 1, "\"msgtype\":\"text\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, out.items, 1, "\"content\":\"hello\\nwecom\""));
}

test "parseIncomingPayload parses wecom XML text message" {
    const payload =
        "<xml>" ++
        "<ToUserName><![CDATA[ww_corp]]></ToUserName>" ++
        "<FromUserName><![CDATA[zhangsan]]></FromUserName>" ++
        "<CreateTime>1720000000</CreateTime>" ++
        "<MsgType><![CDATA[text]]></MsgType>" ++
        "<Content><![CDATA[hello wecom]]></Content>" ++
        "<AgentID>1000002</AgentID>" ++
        "</xml>";

    const msg_opt = try parseIncomingPayload(std.testing.allocator, payload);
    try std.testing.expect(msg_opt != null);
    var msg = msg_opt.?;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("zhangsan", msg.sender);
    try std.testing.expectEqualStrings("hello wecom", msg.content);
    try std.testing.expectEqualStrings("text", msg.msg_type);
    try std.testing.expectEqualStrings("1000002", msg.agent_id.?);
}

test "parseIncomingPayload ignores non-text XML messages" {
    const payload =
        "<xml>" ++
        "<FromUserName><![CDATA[zhangsan]]></FromUserName>" ++
        "<MsgType><![CDATA[image]]></MsgType>" ++
        "<PicUrl><![CDATA[https://example.com/a.png]]></PicUrl>" ++
        "</xml>";

    const msg_opt = try parseIncomingPayload(std.testing.allocator, payload);
    try std.testing.expect(msg_opt == null);
}

test "verifySignature accepts generated digest and rejects wrong value" {
    const token = "QDG6eK";
    const timestamp = "1409659589";
    const nonce = "263014780";
    const encrypted = "aoh6Lx_kXgA4EMfQ8j6lQ25x5hY=";

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

    try std.testing.expect(verifySignature(
        token,
        timestamp,
        nonce,
        encrypted,
        sig[0..],
    ));
    try std.testing.expect(!verifySignature(token, timestamp, nonce, encrypted, "deadbeef"));
}

test "hasSecureCallbackConfig requires token and aes key" {
    try std.testing.expect(!hasSecureCallbackConfig(.{
        .webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a",
    }));
    try std.testing.expect(!hasSecureCallbackConfig(.{
        .webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a",
        .callback_token = "tok",
    }));
    try std.testing.expect(hasSecureCallbackConfig(.{
        .webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a",
        .callback_token = "tok",
        .encoding_aes_key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    }));
}

test "wecom smoke basic channel contract" {
    var ch = WeComChannel.init(std.testing.allocator, .{
        .webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc",
    });
    try std.testing.expectEqualStrings("wecom", ch.channel().name());
    try std.testing.expect(!ch.channel().healthCheck());
}
