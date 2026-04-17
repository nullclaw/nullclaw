const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");
const fs_compat = @import("../fs_compat.zig");
const platform = @import("../platform.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");
const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.qq);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

pub const GATEWAY_URL = "wss://api.sgroup.qq.com/websocket";
pub const SANDBOX_GATEWAY_URL = "wss://sandbox.api.sgroup.qq.com/websocket";

pub const API_BASE = "https://api.sgroup.qq.com";
pub const SANDBOX_API_BASE = "https://sandbox.api.sgroup.qq.com";

/// QQ Gateway opcodes.
pub const Opcode = enum(u8) {
    dispatch = 0,
    heartbeat = 1,
    identify = 2,
    @"resume" = 6,
    reconnect = 7,
    invalid_session = 9,
    hello = 10,
    heartbeat_ack = 11,

    pub fn fromInt(val: i64) ?Opcode {
        return switch (val) {
            0 => .dispatch,
            1 => .heartbeat,
            2 => .identify,
            6 => .@"resume",
            7 => .reconnect,
            9 => .invalid_session,
            10 => .hello,
            11 => .heartbeat_ack,
            else => null,
        };
    }
};

/// Default intents bitmask for QQ Bot API (zeroclaw parity):
///   bit 25: GROUP_AND_C2C_EVENT   — group @msg + C2C (private chat) events
///   bit 30: PUBLIC_GUILD_MESSAGES — public guild @msg events
/// See: https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html
pub const DEFAULT_INTENTS: u32 = (1 << 25) | (1 << 30);

// ════════════════════════════════════════════════════════════════════════════
// CQ Code Parsing (QQ message format)
// ════════════════════════════════════════════════════════════════════════════

/// Strip CQ codes from message text, returning clean text.
/// [CQ:at,qq=123] -> stripped
/// [CQ:face,id=178] -> stripped
/// [CQ:image,...] -> stripped
/// Regular text is preserved.
pub fn stripCqCodes(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < raw.len) {
        const tag_start = std.mem.indexOfPos(u8, raw, cursor, "[CQ:") orelse {
            try result.appendSlice(allocator, raw[cursor..]);
            break;
        };

        // Append text before the tag
        try result.appendSlice(allocator, raw[cursor..tag_start]);

        // Find closing ]
        const tag_end = std.mem.indexOfPos(u8, raw, tag_start, "]") orelse {
            // Malformed tag — treat as plain text
            try result.appendSlice(allocator, raw[tag_start..]);
            break;
        };

        cursor = tag_end + 1;
    }

    return result.toOwnedSlice(allocator);
}

/// Extract the mentioned QQ number from a CQ-coded string.
/// Returns null if no [CQ:at,qq=...] tag is found.
pub fn extractMentionQQ(raw: []const u8) ?[]const u8 {
    const at_tag = "[CQ:at,qq=";
    const start = std.mem.indexOf(u8, raw, at_tag) orelse return null;
    const val_start = start + at_tag.len;
    const end = std.mem.indexOfPos(u8, raw, val_start, "]") orelse return null;
    return raw[val_start..end];
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

fn isImageFilename(filename: []const u8) bool {
    return endsWithIgnoreCase(filename, ".png") or
        endsWithIgnoreCase(filename, ".jpg") or
        endsWithIgnoreCase(filename, ".jpeg") or
        endsWithIgnoreCase(filename, ".gif") or
        endsWithIgnoreCase(filename, ".webp") or
        endsWithIgnoreCase(filename, ".bmp") or
        endsWithIgnoreCase(filename, ".heic") or
        endsWithIgnoreCase(filename, ".heif") or
        endsWithIgnoreCase(filename, ".svg");
}

fn isRemoteMediaUrl(url: []const u8) bool {
    const trimmed = std.mem.trim(u8, url, " \t\r\n");
    return std.mem.startsWith(u8, trimmed, "https://") or std.mem.startsWith(u8, trimmed, "http://");
}

const QQ_ATTACHMENT_CACHE_SUBDIR = "nullclaw_qq_media";
const QQ_ATTACHMENT_MAX_BYTES: usize = 20 * 1024 * 1024;

fn imageExtensionFromContentType(content_type: []const u8) []const u8 {
    if (content_type.len == 0) return ".img";
    if (std.ascii.eqlIgnoreCase(content_type, "image/png")) return ".png";
    if (std.ascii.eqlIgnoreCase(content_type, "image/jpeg")) return ".jpg";
    if (std.ascii.eqlIgnoreCase(content_type, "image/jpg")) return ".jpg";
    if (std.ascii.eqlIgnoreCase(content_type, "image/gif")) return ".gif";
    if (std.ascii.eqlIgnoreCase(content_type, "image/webp")) return ".webp";
    if (std.ascii.eqlIgnoreCase(content_type, "image/bmp")) return ".bmp";
    return ".img";
}

fn attachmentCacheDirPath(allocator: std.mem.Allocator) ![]u8 {
    const tmp_dir = try platform.getTempDir(allocator);
    defer allocator.free(tmp_dir);
    return std_compat.fs.path.join(allocator, &.{ tmp_dir, QQ_ATTACHMENT_CACHE_SUBDIR });
}

fn ensureAttachmentCacheDir(cache_dir: []const u8) !void {
    std_compat.fs.makeDirAbsolute(cache_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => try fs_compat.makePath(cache_dir),
    };
}

fn downloadImageAttachmentToLocal(
    allocator: std.mem.Allocator,
    image_url: []const u8,
    content_type: []const u8,
    auth_header_opt: ?[]const u8,
) !?[]u8 {
    if (!std.mem.startsWith(u8, image_url, "https://")) return null;

    var header_buf: [1][]const u8 = undefined;
    const headers: []const []const u8 = if (auth_header_opt) |auth_header| blk: {
        header_buf[0] = auth_header;
        break :blk header_buf[0..1];
    } else &.{};

    const image_bytes = root.http_util.curlGet(allocator, image_url, headers, "30") catch {
        return null;
    };
    defer allocator.free(image_bytes);

    if (image_bytes.len == 0 or image_bytes.len > QQ_ATTACHMENT_MAX_BYTES) return null;

    const cache_dir = try attachmentCacheDirPath(allocator);
    defer allocator.free(cache_dir);
    ensureAttachmentCacheDir(cache_dir) catch return null;

    const ext = imageExtensionFromContentType(content_type);
    const ts: u64 = @intCast(@max(std_compat.time.timestamp(), 0));
    const nonce = std_compat.crypto.random.int(u64);

    var filename_buf: [96]u8 = undefined;
    const filename = std.fmt.bufPrint(&filename_buf, "qq_{d}_{x}{s}", .{ ts, nonce, ext }) catch return null;
    const local_path = try std_compat.fs.path.join(allocator, &.{ cache_dir, filename });

    const file = std_compat.fs.createFileAbsolute(local_path, .{ .read = false, .truncate = true }) catch {
        allocator.free(local_path);
        return null;
    };
    defer file.close();
    file.writeAll(image_bytes) catch {
        allocator.free(local_path);
        return null;
    };

    return local_path;
}

fn parseImageMarkerLine(line: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    const prefix = "[IMAGE:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    if (trimmed.len < 8 or trimmed[trimmed.len - 1] != ']') return null;
    const marker = std.mem.trim(u8, trimmed[prefix.len .. trimmed.len - 1], " \t\r\n");
    if (marker.len == 0) return null;
    return marker;
}

const ParsedOutgoingContent = struct {
    text: []u8,
    image_urls: [][]u8,

    pub fn deinit(self: *ParsedOutgoingContent, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
        for (self.image_urls) |url| allocator.free(url);
        allocator.free(self.image_urls);
    }
};

/// Split outbound content into text and remote [IMAGE:URL] markers.
/// Non-remote markers stay in text; remote image URLs are extracted for media upload.
fn parseOutgoingContent(allocator: std.mem.Allocator, content: []const u8) !ParsedOutgoingContent {
    var passthrough: std.ArrayListUnmanaged(u8) = .empty;
    errdefer passthrough.deinit(allocator);
    var image_urls: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (image_urls.items) |url| allocator.free(url);
        image_urls.deinit(allocator);
    }

    var line_it = std.mem.splitScalar(u8, content, '\n');
    var first_line = true;
    while (line_it.next()) |line| {
        if (parseImageMarkerLine(line)) |marker_target| {
            if (isRemoteMediaUrl(marker_target)) {
                try image_urls.append(allocator, try allocator.dupe(u8, marker_target));
                continue;
            }
        }

        if (!first_line) try passthrough.append(allocator, '\n');
        first_line = false;
        try passthrough.appendSlice(allocator, line);
    }

    const trimmed_text = std.mem.trim(u8, passthrough.items, " \t\r\n");
    const text = try allocator.dupe(u8, trimmed_text);
    passthrough.deinit(allocator);

    return .{
        .text = text,
        .image_urls = try image_urls.toOwnedSlice(allocator),
    };
}

/// Extract image attachment markers as newline-joined "[IMAGE:<url>]".
/// Caller owns returned slice.
fn extractImageMarkers(allocator: std.mem.Allocator, payload: std.json.Value, auth_header_opt: ?[]const u8) ![]u8 {
    if (payload != .object) return allocator.dupe(u8, "");
    const attachments = payload.object.get("attachments") orelse return allocator.dupe(u8, "");
    if (attachments != .array) return allocator.dupe(u8, "");

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    var first = true;
    for (attachments.array.items) |item| {
        if (item != .object) continue;
        const raw_url = getJsonStringFromObj(item, "url") orelse continue;
        const url = std.mem.trim(u8, raw_url, " \t\r\n");
        if (url.len == 0) continue;

        const content_type = getJsonStringFromObj(item, "content_type") orelse "";
        const filename = getJsonStringFromObj(item, "filename") orelse "";
        const is_image = (content_type.len >= 6 and std.ascii.eqlIgnoreCase(content_type[0..6], "image/")) or isImageFilename(filename);
        if (!is_image) continue;

        const marker_target = blk: {
            if (!builtin.is_test) {
                if (try downloadImageAttachmentToLocal(allocator, url, content_type, auth_header_opt)) |local_path| {
                    break :blk local_path;
                }
            }
            break :blk try allocator.dupe(u8, url);
        };
        defer allocator.free(marker_target);

        if (!first) try out.append(allocator, '\n');
        first = false;
        try out.appendSlice(allocator, "[IMAGE:");
        try out.appendSlice(allocator, marker_target);
        try out.append(allocator, ']');
    }

    return out.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Message Deduplication
// ════════════════════════════════════════════════════════════════════════════

/// Runtime dedup capacity, aligned with zeroclaw (10k keys, evict half).
pub const DEDUP_CAPACITY: usize = 10_000;

pub const StringDedupSet = struct {
    seen: std.StringHashMapUnmanaged(void) = .empty,
    order: std.ArrayListUnmanaged([]u8) = .empty,
    mu: std_compat.sync.Mutex = .{},

    pub fn deinit(self: *StringDedupSet, allocator: std.mem.Allocator) void {
        self.mu.lock();
        defer self.mu.unlock();
        for (self.order.items) |key| allocator.free(key);
        self.order.deinit(allocator);
        self.seen.deinit(allocator);
    }

    pub fn isDuplicate(self: *StringDedupSet, allocator: std.mem.Allocator, message_id: []const u8) !bool {
        if (message_id.len == 0) return false;

        self.mu.lock();
        defer self.mu.unlock();

        if (self.seen.contains(message_id)) {
            return true;
        }

        if (self.order.items.len >= DEDUP_CAPACITY) {
            const remove_n = self.order.items.len / 2;
            var i: usize = 0;
            while (i < remove_n) : (i += 1) {
                const key = self.order.items[i];
                _ = self.seen.remove(key);
                allocator.free(key);
            }
            const remaining = self.order.items.len - remove_n;
            std.mem.copyForwards([]u8, self.order.items[0..remaining], self.order.items[remove_n..]);
            self.order.items.len = remaining;
        }

        const owned_key = try allocator.dupe(u8, message_id);
        errdefer allocator.free(owned_key);
        try self.seen.put(allocator, owned_key, {});
        errdefer _ = self.seen.remove(owned_key);
        try self.order.append(allocator, owned_key);
        return false;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Message Formatting
// ════════════════════════════════════════════════════════════════════════════

/// Build the IDENTIFY payload for QQ Gateway WebSocket.
/// Format: {"op":2,"d":{"token":"QQBot {access_token}","intents":N,"shard":[0,1]}}
pub fn buildIdentifyPayload(buf: []u8, access_token: []const u8, intents: u32) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{{\"op\":2,\"d\":{{\"token\":\"QQBot {s}\",\"intents\":{d},\"shard\":[0,1]}}}}", .{
        access_token,
        intents,
    });
    return w.buffered();
}

/// Build a heartbeat payload.
/// Format: {"op":1,"d":N} where N is the last sequence number (or null).
pub fn buildHeartbeatPayload(buf: []u8, sequence: ?i64) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (sequence) |seq| {
        try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
    } else {
        try w.writeAll("{\"op\":1,\"d\":null}");
    }
    return w.buffered();
}

/// Build the REST API URL for sending a message to a channel.
pub fn buildSendUrl(buf: []u8, base: []const u8, channel_id: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/channels/{s}/messages", .{ base, channel_id });
    return w.buffered();
}

/// Build the REST API URL for sending a DM (direct message).
pub fn buildDmUrl(buf: []u8, base: []const u8, guild_id: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/dms/{s}/messages", .{ base, guild_id });
    return w.buffered();
}

/// Build the REST API URL for sending a group message.
/// Format: {base}/v2/groups/{group_openid}/messages
pub fn buildGroupSendUrl(buf: []u8, base: []const u8, group_openid: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/v2/groups/{s}/messages", .{ base, group_openid });
    return w.buffered();
}

/// Build the REST API URL for sending a C2C (private) message.
/// Format: {base}/v2/users/{user_openid}/messages
pub fn buildC2cSendUrl(buf: []u8, base: []const u8, user_openid: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/v2/users/{s}/messages", .{ base, user_openid });
    return w.buffered();
}

/// Build the REST API URL for uploading a group media file descriptor.
/// Format: {base}/v2/groups/{group_openid}/files
pub fn buildGroupFilesUrl(buf: []u8, base: []const u8, group_openid: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/v2/groups/{s}/files", .{ base, group_openid });
    return w.buffered();
}

/// Build the REST API URL for uploading a C2C media file descriptor.
/// Format: {base}/v2/users/{user_openid}/files
pub fn buildC2cFilesUrl(buf: []u8, base: []const u8, user_openid: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/v2/users/{s}/files", .{ base, user_openid });
    return w.buffered();
}

/// Build the REST API URL for resolving gateway endpoint.
/// Format: {base}/gateway
pub fn buildGatewayResolveUrl(buf: []u8, base: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{s}/gateway", .{base});
    return w.buffered();
}

/// Build a message send body.
/// Format: {"content":"...", "msg_id":"..."}
pub fn buildSendBody(
    allocator: std.mem.Allocator,
    content: []const u8,
    msg_id: ?[]const u8,
    msg_type: ?u8,
    msg_seq: ?u32,
) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);

    try body_list.appendSlice(allocator, "{\"content\":");
    try root.json_util.appendJsonString(&body_list, allocator, content);
    if (msg_id) |mid| {
        try body_list.appendSlice(allocator, ",\"msg_id\":");
        try root.json_util.appendJsonString(&body_list, allocator, mid);
    }
    if (msg_type) |mt| {
        try body_list.print(allocator, ",\"msg_type\":{d}", .{mt});
    }
    if (msg_seq) |seq| {
        try body_list.print(allocator, ",\"msg_seq\":{d}", .{seq});
    }
    try body_list.appendSlice(allocator, "}");

    return body_list.toOwnedSlice(allocator);
}

fn targetWithoutMessageId(buf: []u8, target: []const u8) ?[]const u8 {
    const msg_type, const id_str, const msg_id = parseTarget(target);
    if (msg_id == null) return null;

    if (std.mem.eql(u8, msg_type, "c2c") or std.mem.eql(u8, msg_type, "group")) {
        return std.fmt.bufPrint(buf, "{s}:{s}", .{ msg_type, id_str }) catch null;
    }
    return null;
}

fn sendWithReplyFallback(
    target: []const u8,
    fallback_target: ?[]const u8,
    log_context: []const u8,
    sender: anytype,
) !void {
    sender.send(target) catch |err| {
        if (err == error.QQApiError and fallback_target != null) {
            log.warn("QQ {s} send failed; retrying without msg_id target={s}", .{ log_context, fallback_target.? });
            try sender.send(fallback_target.?);
        } else {
            return err;
        }
    };
}

/// Build a media upload body for QQ /files endpoint.
/// Format: {"file_type":1,"url":"https://...","srv_send_msg":false}
pub fn buildMediaUploadBody(allocator: std.mem.Allocator, media_url: []const u8) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);

    try body_list.appendSlice(allocator, "{\"file_type\":1,\"url\":");
    try root.json_util.appendJsonString(&body_list, allocator, media_url);
    try body_list.appendSlice(allocator, ",\"srv_send_msg\":false}");

    return body_list.toOwnedSlice(allocator);
}

/// Build a media send body after successful upload to /files.
/// Format: {"content":" ","msg_type":7,"media":{"file_info":"..."},"msg_id":"...","msg_seq":N}
pub fn buildMediaSendBody(
    allocator: std.mem.Allocator,
    file_info: []const u8,
    msg_id: ?[]const u8,
    msg_seq: ?u32,
) ![]u8 {
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_list.deinit(allocator);

    try body_list.appendSlice(allocator, "{\"content\":\" \",\"msg_type\":7,\"media\":{\"file_info\":");
    try root.json_util.appendJsonString(&body_list, allocator, file_info);
    try body_list.appendSlice(allocator, "}");
    if (msg_id) |mid| {
        try body_list.appendSlice(allocator, ",\"msg_id\":");
        try root.json_util.appendJsonString(&body_list, allocator, mid);
    }
    if (msg_seq) |seq| {
        try body_list.print(allocator, ",\"msg_seq\":{d}", .{seq});
    }
    try body_list.appendSlice(allocator, "}");

    return body_list.toOwnedSlice(allocator);
}

/// Build auth header value: "Authorization: QQBot {access_token}"
pub fn buildAuthHeader(buf: []u8, access_token: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("Authorization: QQBot {s}", .{access_token});
    return w.buffered();
}

/// Fetch the current gateway URL for this bot/environment.
/// Caller owns returned memory.
pub fn fetchGatewayUrl(allocator: std.mem.Allocator, access_token: []const u8, sandbox: bool) ![]u8 {
    if (comptime builtin.is_test) {
        // In tests, do not make real network calls
        return allocator.dupe(u8, gatewayUrl(sandbox));
    }

    var url_buf: [256]u8 = undefined;
    const resolve_url = try buildGatewayResolveUrl(&url_buf, apiBase(sandbox));

    var auth_buf: [512]u8 = undefined;
    const auth_header = try buildAuthHeader(&auth_buf, access_token);

    const resp_body = root.http_util.curlGet(allocator, resolve_url, &.{auth_header}, "15") catch |err| {
        log.err("QQ gateway resolve request failed: {}", .{err});
        return error.GatewayFetchFailed;
    };
    defer allocator.free(resp_body);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch {
        log.err("QQ gateway resolve: invalid JSON response", .{});
        return error.GatewayParseFailed;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return error.GatewayParseFailed;
    const url_str = blk: {
        const v = parsed.value.object.get("url") orelse return error.GatewayParseFailed;
        break :blk if (v == .string) v.string else return error.GatewayParseFailed;
    };
    if (url_str.len == 0) return error.GatewayParseFailed;

    return allocator.dupe(u8, url_str);
}

/// Best-effort QQ API response check.
/// If payload includes a non-zero "code", treat it as an API failure.
fn ensureQqApiSuccess(allocator: std.mem.Allocator, resp_body: []const u8) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.QQApiError;
    defer parsed.deinit();
    if (parsed.value != .object) return error.QQApiError;

    const code_val = parsed.value.object.get("code") orelse return;
    const code: i64 = switch (code_val) {
        .integer => code_val.integer,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch return error.QQApiError,
        else => return error.QQApiError,
    };
    if (code != 0) return error.QQApiError;
}

fn parseUploadedFileInfo(allocator: std.mem.Allocator, upload_response: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, upload_response, .{}) catch {
        return error.QQApiError;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.QQApiError;
    const file_info = getJsonStringFromObj(parsed.value, "file_info") orelse return error.QQApiError;
    if (file_info.len == 0) return error.QQApiError;
    return allocator.dupe(u8, file_info);
}

fn sanitizeUserOpenId(allocator: std.mem.Allocator, raw_id: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (raw_id) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '_') {
            try out.append(allocator, ch);
        }
    }
    if (out.items.len == 0) return error.InvalidTarget;
    return out.toOwnedSlice(allocator);
}

fn ensureHttpsMediaUrl(media_url: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, media_url, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "https://")) return error.InvalidMediaUrl;
    return trimmed;
}

fn qqSeedFromSecret(secret: []const u8) ?[32]u8 {
    if (secret.len == 0) return null;

    var seed: [32]u8 = undefined;
    var i: usize = 0;
    while (i < seed.len) : (i += 1) {
        seed[i] = secret[i % secret.len];
    }
    return seed;
}

fn qqWebhookValidationSignature(
    allocator: std.mem.Allocator,
    app_secret: []const u8,
    event_ts: []const u8,
    plain_token: []const u8,
) !?[]u8 {
    const seed = qqSeedFromSecret(app_secret) orelse return null;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return null;
    const payload = try std.fmt.allocPrint(allocator, "{s}{s}", .{ event_ts, plain_token });
    defer allocator.free(payload);

    const signature = key_pair.sign(payload, null) catch return null;
    const signature_bytes = signature.toBytes();
    const signature_hex = std.fmt.bytesToHex(signature_bytes, .lower);
    return @as(?[]u8, try allocator.dupe(u8, &signature_hex));
}

/// Check if a group ID is allowed by the given config.
pub fn isGroupAllowed(config: config_types.QQConfig, group_id: []const u8) bool {
    return switch (config.group_policy) {
        .allow => true,
        .allowlist => root.isAllowedExactScoped("qq channel", config.allowed_groups, group_id),
    };
}

/// Get the API base URL (sandbox or production).
pub fn apiBase(sandbox: bool) []const u8 {
    return if (sandbox) SANDBOX_API_BASE else API_BASE;
}

/// URL for obtaining an access token via the QQ Bot OAuth2 flow.
pub const TOKEN_URL = "https://bots.qq.com/app/getAppAccessToken";

/// Refresh the access token this many seconds before it actually expires.
pub const TOKEN_REFRESH_MARGIN_SECS: i64 = 120;

/// Result of a successful token fetch.
pub const AccessTokenResult = struct {
    token: []u8,
    expires_in: i64,
};

/// Fetch a new access_token from the QQ Bot API.
/// Caller owns the returned `token` slice.
pub fn fetchAccessToken(allocator: std.mem.Allocator, app_id: []const u8, app_secret: []const u8) !AccessTokenResult {
    if (comptime builtin.is_test) {
        // In tests, do not make real network calls
        return .{ .token = try allocator.dupe(u8, "test-access-token"), .expires_in = 7200 };
    }

    // Build request body with proper JSON escaping.
    var body_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer body_buf.deinit(allocator);
    try body_buf.appendSlice(allocator, "{\"appId\":");
    try root.json_util.appendJsonString(&body_buf, allocator, app_id);
    try body_buf.appendSlice(allocator, ",\"clientSecret\":");
    try root.json_util.appendJsonString(&body_buf, allocator, app_secret);
    try body_buf.appendSlice(allocator, "}");

    const resp_body = root.http_util.curlPost(allocator, TOKEN_URL, body_buf.items, &.{}) catch |err| {
        log.err("QQ getAppAccessToken request failed: {}", .{err});
        return error.TokenFetchFailed;
    };
    defer allocator.free(resp_body);

    // Parse response: {"access_token":"...","expires_in":"7200"}
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch {
        log.err("QQ getAppAccessToken: invalid JSON response", .{});
        return error.TokenParseFailed;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return error.TokenParseFailed;

    const token_str = blk: {
        const v = parsed.value.object.get("access_token") orelse return error.TokenParseFailed;
        break :blk if (v == .string) v.string else return error.TokenParseFailed;
    };

    if (token_str.len == 0) return error.TokenParseFailed;

    // expires_in can be a string ("7200") or an integer
    const expires_in: i64 = blk: {
        const v = parsed.value.object.get("expires_in") orelse break :blk 7200;
        switch (v) {
            .integer => break :blk v.integer,
            .string => |s| break :blk std.fmt.parseInt(i64, s, 10) catch 7200,
            else => break :blk 7200,
        }
    };

    log.info("Access_token obtained, expires_in={d}s", .{expires_in});

    return .{
        .token = try allocator.dupe(u8, token_str),
        .expires_in = expires_in,
    };
}

/// Get the Gateway URL (sandbox or production).
pub fn gatewayUrl(sandbox: bool) []const u8 {
    return if (sandbox) SANDBOX_GATEWAY_URL else GATEWAY_URL;
}

/// Parse host from wss:// URL.
/// "wss://api.sgroup.qq.com/websocket" -> "api.sgroup.qq.com"
/// "wss://api.sgroup.qq.com/websocket?x=1" -> "api.sgroup.qq.com"
pub fn parseGatewayHost(wss_url: []const u8) []const u8 {
    const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
        wss_url[6..]
    else if (std.mem.startsWith(u8, wss_url, "ws://"))
        wss_url[5..]
    else
        wss_url;

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
    const host_port = no_scheme[0..end];
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        if (colon > 0) {
            _ = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return host_port;
            return host_port[0..colon];
        }
    }
    return host_port;
}

/// Parse port from wss:// URL.
/// Defaults to 443 when port is absent or invalid.
pub fn parseGatewayPort(wss_url: []const u8) u16 {
    const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
        wss_url[6..]
    else if (std.mem.startsWith(u8, wss_url, "ws://"))
        wss_url[5..]
    else
        wss_url;

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
    const host_port = no_scheme[0..end];
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        if (colon > 0) {
            return std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch 443;
        }
    }
    return 443;
}

/// Parse path (and optional query) from wss:// URL.
/// Returns "/websocket" when no explicit path exists.
pub fn parseGatewayPath(wss_url: []const u8) []const u8 {
    const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
        wss_url[6..]
    else if (std.mem.startsWith(u8, wss_url, "ws://"))
        wss_url[5..]
    else
        wss_url;

    if (std.mem.indexOf(u8, no_scheme, "/")) |slash_pos| {
        return no_scheme[slash_pos..];
    }
    return "/websocket";
}

const invalid_socket: std.posix.socket_t = if (builtin.os.tag == .windows) std_compat.net.invalidHandle(std.posix.socket_t) else -1;
// ════════════════════════════════════════════════════════════════════════════
// QQChannel
// ════════════════════════════════════════════════════════════════════════════

/// QQ Bot API channel.
///
/// Connects to the QQ Gateway via WebSocket for real-time messages.
/// Handles opcodes: HELLO (10), DISPATCH (0), HEARTBEAT_ACK (11), RECONNECT (7).
/// Sends replies via REST API POST to /channels/{id}/messages or /dms/{id}/messages.
/// Message deduplication via 10k-key hash set with half-eviction.
/// Auto-reconnect with 5s backoff.
pub const QQChannel = struct {
    config: config_types.QQConfig,
    allocator: std.mem.Allocator,
    event_bus: ?*bus.Bus,
    dedup_set: StringDedupSet = .{},
    dedup_allocator: std.mem.Allocator,
    sequence: Atomic(i64) = Atomic(i64).init(0),
    has_sequence: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    heartbeat_interval_ms: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    session_id: ?[]const u8,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    reconnect_requested: bool = false,
    gateway_thread: ?std.Thread = null,
    heartbeat_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    force_heartbeat: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ws_fd: std.atomic.Value(std.posix.socket_t) = std.atomic.Value(std.posix.socket_t).init(invalid_socket),
    token_mu: std_compat.sync.Mutex = .{},

    // ── Access token state ──
    access_token: ?[]u8 = null,
    token_expires_at: i64 = 0, // epoch seconds

    pub const MAX_MESSAGE_LEN: usize = 4096;
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, config: config_types.QQConfig) QQChannel {
        return .{
            .config = config,
            .allocator = allocator,
            .event_bus = null,
            .dedup_allocator = if (builtin.is_test) std.heap.page_allocator else allocator,
            .session_id = null,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.QQConfig) QQChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *QQChannel) []const u8 {
        return "qq";
    }

    pub fn healthCheck(self: *QQChannel) bool {
        if (self.config.receive_mode == .websocket) {
            return self.running.load(.acquire) and self.ws_fd.load(.acquire) != invalid_socket;
        }
        const result = fetchAccessToken(self.allocator, self.config.app_id, self.config.app_secret) catch return false;
        self.allocator.free(result.token);
        return true;
    }

    /// Set the event bus for publishing inbound messages.
    pub fn setBus(self: *QQChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    /// Ensure a valid access_token is available, fetching or refreshing as needed.
    /// Returns a caller-owned copy of the token to avoid lifetime races with stop().
    fn ensureAccessToken(self: *QQChannel) ![]u8 {
        self.token_mu.lock();
        defer self.token_mu.unlock();

        const now = std_compat.time.timestamp();
        if (self.access_token) |tok| {
            if (now < self.token_expires_at - TOKEN_REFRESH_MARGIN_SECS) {
                return self.allocator.dupe(u8, tok);
            }
        }

        const result = try fetchAccessToken(self.allocator, self.config.app_id, self.config.app_secret);
        if (self.access_token) |old| self.allocator.free(old);
        self.access_token = result.token;
        self.token_expires_at = now + result.expires_in;
        log.info("Access token obtained (expires_in={d}s)", .{result.expires_in});
        return self.allocator.dupe(u8, result.token);
    }

    fn isDuplicateMessageId(self: *QQChannel, msg_id: []const u8) bool {
        if (msg_id.len == 0) return false;
        return self.dedup_set.isDuplicate(self.dedup_allocator, msg_id) catch false;
    }

    // ── Incoming event handling ──────────────────────────────────────

    /// Handle a parsed WebSocket event JSON from the QQ gateway.
    pub fn handleGatewayEvent(self: *QQChannel, raw_json: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, raw_json, .{}) catch {
            log.warn("failed to parse QQ gateway event JSON", .{});
            return;
        };
        defer parsed.deinit();
        const val = parsed.value;

        // Extract opcode
        if (val != .object) return;
        const op_val = val.object.get("op") orelse return;
        const op_int: i64 = switch (op_val) {
            .integer => op_val.integer,
            else => return,
        };
        const op = Opcode.fromInt(op_int) orelse return;

        // Update sequence number
        if (val.object.get("s")) |s_val| {
            if (s_val == .integer) {
                if (s_val.integer >= 0) {
                    self.sequence.store(s_val.integer, .release);
                    self.has_sequence.store(true, .release);
                } else {
                    // Invalid sequence range: clear sequence state so heartbeats send
                    // null instead of a stale positive value.
                    self.sequence.store(0, .release);
                    self.has_sequence.store(false, .release);
                }
            }
        }

        switch (op) {
            .hello => {
                // Extract heartbeat_interval from d.heartbeat_interval
                if (val.object.get("d")) |d_val| {
                    if (d_val == .object) {
                        if (d_val.object.get("heartbeat_interval")) |hb_val| {
                            if (hb_val == .integer and hb_val.integer > 0) {
                                self.heartbeat_interval_ms.store(@intCast(@min(hb_val.integer, std.math.maxInt(u32))), .release);
                            }
                        }
                    }
                }
                log.info("QQ Gateway HELLO: heartbeat_interval={d}ms", .{self.heartbeat_interval_ms.load(.acquire)});
            },
            .dispatch => {
                const event_type = getJsonString(val, "t") orelse {
                    log.info("handleGatewayEvent: dispatch op=0 but missing 't' field", .{});
                    return;
                };
                log.info("handleGatewayEvent: dispatch event_type='{s}'", .{event_type});
                if (std.mem.eql(u8, event_type, "READY")) {
                    // Extract session_id from d.session_id
                    if (val.object.get("d")) |d_val| {
                        if (getJsonStringFromObj(d_val, "session_id")) |sid| {
                            if (self.session_id) |old| self.allocator.free(old);
                            self.session_id = self.allocator.dupe(u8, sid) catch null;
                        }
                    }
                    self.running.store(true, .release);
                    log.info("QQ Gateway READY", .{});
                } else if (std.mem.eql(u8, event_type, "MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "AT_MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "DIRECT_MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "GROUP_AT_MESSAGE_CREATE") or
                    std.mem.eql(u8, event_type, "C2C_MESSAGE_CREATE"))
                {
                    try self.handleMessageCreate(val, event_type);
                } else {
                    log.debug("QQ dispatch event (unhandled): {s}", .{event_type});
                }
            },
            .heartbeat_ack => {
                // Heartbeat acknowledged — connection is healthy
            },
            .heartbeat => {
                // Server requests an immediate heartbeat.
                self.force_heartbeat.store(true, .release);
            },
            .reconnect => {
                log.info("QQ Gateway RECONNECT requested", .{});
                self.reconnect_requested = true;
            },
            .invalid_session => {
                log.warn("QQ Gateway INVALID_SESSION", .{});
                self.reconnect_requested = true;
            },
            else => {},
        }
    }

    pub fn buildWebhookValidationResponse(self: *QQChannel, allocator: std.mem.Allocator, raw_json: []const u8) !?[]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const op_val = parsed.value.object.get("op") orelse return null;
        const op_int: i64 = switch (op_val) {
            .integer => op_val.integer,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch return null,
            else => return null,
        };
        if (op_int != 13) return null;

        const payload = parsed.value.object.get("d") orelse return null;
        if (payload != .object) return null;
        const plain_token_raw = getJsonStringFromObj(payload, "plain_token") orelse return null;
        const event_ts_raw = getJsonStringFromObj(payload, "event_ts") orelse return null;
        const plain_token = std.mem.trim(u8, plain_token_raw, " \t\r\n");
        const event_ts = std.mem.trim(u8, event_ts_raw, " \t\r\n");
        if (plain_token.len == 0 or event_ts.len == 0) return null;

        const signature = (try qqWebhookValidationSignature(allocator, self.config.app_secret, event_ts, plain_token)) orelse return null;
        defer allocator.free(signature);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "{\"plain_token\":");
        try root.json_util.appendJsonString(&out, allocator, plain_token);
        try out.appendSlice(allocator, ",\"signature\":");
        try root.json_util.appendJsonString(&out, allocator, signature);
        try out.appendSlice(allocator, "}");
        return @as(?[]u8, try out.toOwnedSlice(allocator));
    }

    pub fn parseWebhookPayload(self: *QQChannel, allocator: std.mem.Allocator, raw_json: []const u8) !?bus.InboundMessage {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const op_val = parsed.value.object.get("op") orelse return null;
        const op_int: i64 = switch (op_val) {
            .integer => op_val.integer,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch return null,
            else => return null,
        };
        if (op_int != 0) return null;

        var temp_bus = bus.Bus.init();
        defer temp_bus.close();

        const prev_bus = self.event_bus;
        self.event_bus = &temp_bus;
        defer self.event_bus = prev_bus;

        try self.handleGatewayEvent(raw_json);
        if (temp_bus.inboundDepth() == 0) return null;
        return temp_bus.consumeInbound();
    }

    fn handleMessageCreate(self: *QQChannel, val: std.json.Value, event_type: []const u8) !void {
        log.info("handleMessageCreate: event_type='{s}'", .{event_type});

        const d = val.object.get("d") orelse {
            log.info("handleMessageCreate: DROPPED — missing 'd' field", .{});
            return;
        };
        if (d != .object) {
            log.info("handleMessageCreate: DROPPED — 'd' is not an object", .{});
            return;
        }

        // Extract message ID for dedup (some payloads use msg_id instead of id).
        const msg_id_str = getJsonStringFromObj(d, "id") orelse
            getJsonStringFromObj(d, "msg_id") orelse {
            log.info("handleMessageCreate: DROPPED — missing 'd.id'/'d.msg_id' field", .{});
            return;
        };
        log.info("handleMessageCreate: msg_id='{s}'", .{msg_id_str});
        if (self.isDuplicateMessageId(msg_id_str)) {
            log.info("handleMessageCreate: DROPPED — duplicate msg_id", .{});
            return;
        }

        // Determine event category
        const is_c2c = std.mem.eql(u8, event_type, "C2C_MESSAGE_CREATE");
        const is_group = std.mem.eql(u8, event_type, "GROUP_AT_MESSAGE_CREATE");
        const is_dm = std.mem.eql(u8, event_type, "DIRECT_MESSAGE_CREATE") or is_c2c;
        log.info("handleMessageCreate: is_c2c={} is_group={} is_dm={}", .{ is_c2c, is_group, is_dm });

        // Extract sender info — v2 API uses user_openid/member_openid, legacy uses author.id
        const author = d.object.get("author") orelse {
            log.info("handleMessageCreate: DROPPED — missing 'd.author' field", .{});
            return;
        };
        const author_id = getJsonStringFromObj(author, "id") orelse "";
        const author_user_openid = getJsonStringFromObj(author, "user_openid") orelse "";
        const author_member_openid = getJsonStringFromObj(author, "member_openid") orelse "";
        const sender_id = if (is_c2c)
            if (author_user_openid.len > 0) author_user_openid else if (author_id.len > 0) author_id else "unknown"
        else if (is_group)
            if (author_member_openid.len > 0) author_member_openid else if (author_id.len > 0) author_id else "unknown"
        else if (author_id.len > 0)
            author_id
        else if (author_user_openid.len > 0)
            author_user_openid
        else if (author_member_openid.len > 0)
            author_member_openid
        else
            "unknown";
        log.info("handleMessageCreate: sender_id='{s}'", .{sender_id});

        // Determine chat/reply identifiers depending on event type
        //   - Group events: use group_openid
        //   - C2C events:   use user_openid as chat id
        //   - Guild events: use channel_id / guild_id
        const channel_id = getJsonStringFromObj(d, "channel_id") orelse "";
        const group_openid = getJsonStringFromObj(d, "group_openid") orelse
            getJsonStringFromObj(d, "group_id") orelse
            "";
        const user_openid = if (author_user_openid.len > 0) author_user_openid else author_id;
        log.info("handleMessageCreate: channel_id='{s}' group_openid='{s}' user_openid='{s}'", .{ channel_id, group_openid, user_openid });
        if (is_c2c and user_openid.len == 0) {
            log.info("handleMessageCreate: DROPPED — C2C event missing user_openid", .{});
            return;
        }
        if (is_group and group_openid.len == 0) {
            log.info("handleMessageCreate: DROPPED — group event missing group_openid", .{});
            return;
        }
        if (!is_dm and !is_group and channel_id.len == 0) {
            log.info("handleMessageCreate: DROPPED — guild event missing channel_id", .{});
            return;
        }

        // Check group policy (for guild and group events)
        if (!is_dm and self.config.group_policy == .allowlist) {
            if (is_group) {
                if (!isGroupAllowed(self.config, group_openid)) {
                    log.info("handleMessageCreate: DROPPED — group '{s}' not in allowlist", .{group_openid});
                    return;
                }
            } else {
                const guild_id = getJsonStringFromObj(d, "guild_id") orelse "";
                if (!isGroupAllowed(self.config, guild_id) and !isGroupAllowed(self.config, channel_id)) {
                    log.info("handleMessageCreate: DROPPED — guild '{s}' / channel '{s}' not in allowlist", .{ guild_id, channel_id });
                    return;
                }
            }
        }

        // Allowlist check
        if (!root.isAllowedExactScoped("qq channel", self.config.allow_from, sender_id)) {
            log.info("handleMessageCreate: DROPPED — sender '{s}' not in allow_from", .{sender_id});
            return;
        }

        // Extract content and strip CQ codes
        const raw_content = getJsonStringFromObj(d, "content") orelse "";
        log.debug("handleMessageCreate: raw_content_len={d}", .{raw_content.len});
        const stripped_content = stripCqCodes(self.allocator, raw_content) catch |err| {
            log.info("handleMessageCreate: DROPPED — stripCqCodes failed: {}", .{err});
            return;
        };
        defer self.allocator.free(stripped_content);

        // Trim whitespace
        const trimmed = std.mem.trim(u8, stripped_content, " \t\n\r");
        var auth_buf: [512]u8 = undefined;
        const auth_header_opt: ?[]const u8 = blk: {
            if (builtin.is_test) break :blk null;
            const token = self.ensureAccessToken() catch break :blk null;
            defer self.allocator.free(token);
            break :blk buildAuthHeader(&auth_buf, token) catch null;
        };

        const image_markers = extractImageMarkers(self.allocator, d, auth_header_opt) catch |err| {
            log.info("handleMessageCreate: DROPPED — extractImageMarkers failed: {}", .{err});
            return;
        };
        defer self.allocator.free(image_markers);

        if (trimmed.len == 0 and image_markers.len == 0) {
            log.info("handleMessageCreate: DROPPED — content empty after trim", .{});
            return;
        }

        const final_content = if (image_markers.len == 0)
            self.allocator.dupe(u8, trimmed) catch return
        else if (trimmed.len == 0)
            self.allocator.dupe(u8, image_markers) catch return
        else
            std.fmt.allocPrint(self.allocator, "{s}\n\n{s}", .{ trimmed, image_markers }) catch return;
        defer self.allocator.free(final_content);

        // Determine the reply target and session key based on event type
        var session_buf: [128]u8 = undefined;
        var reply_buf: [256]u8 = undefined;
        const session_key: []const u8 = if (is_c2c)
            std.fmt.bufPrint(&session_buf, "qq:c2c:{s}", .{user_openid}) catch return
        else if (is_group)
            std.fmt.bufPrint(&session_buf, "qq:group:{s}", .{group_openid}) catch return
        else if (channel_id.len > 0)
            std.fmt.bufPrint(&session_buf, "qq:{s}", .{channel_id}) catch return
        else
            std.fmt.bufPrint(&session_buf, "qq:{s}", .{sender_id}) catch return;

        const reply_target: []const u8 = if (is_c2c)
            std.fmt.bufPrint(&reply_buf, "c2c:{s}:{s}", .{ user_openid, msg_id_str }) catch return
        else if (is_group)
            std.fmt.bufPrint(&reply_buf, "group:{s}:{s}", .{ group_openid, msg_id_str }) catch return
        else if (is_dm)
            std.fmt.bufPrint(&reply_buf, "dm:{s}", .{getJsonStringFromObj(d, "guild_id") orelse channel_id}) catch return
        else
            std.fmt.bufPrint(&reply_buf, "channel:{s}", .{channel_id}) catch return;

        // Build metadata JSON
        var meta_buf: [512]u8 = undefined;
        var mw: std.Io.Writer = .fixed(&meta_buf);
        mw.writeAll("{\"msg_id\":") catch return;
        root.appendJsonStringW(&mw, msg_id_str) catch return;
        mw.print(",\"is_dm\":{s},\"is_group\":{s}", .{
            if (is_dm) "true" else "false",
            if (is_group) "true" else "false",
        }) catch return;
        if (channel_id.len > 0) {
            mw.writeAll(",\"channel_id\":") catch return;
            root.appendJsonStringW(&mw, channel_id) catch return;
        }
        if (group_openid.len > 0) {
            mw.writeAll(",\"group_openid\":") catch return;
            root.appendJsonStringW(&mw, group_openid) catch return;
        }
        if (user_openid.len > 0) {
            mw.writeAll(",\"user_openid\":") catch return;
            root.appendJsonStringW(&mw, user_openid) catch return;
        }
        mw.writeAll(",\"account_id\":") catch return;
        root.appendJsonStringW(&mw, self.config.account_id) catch return;
        mw.writeByte('}') catch return;
        const metadata = mw.buffered();

        log.info("QQ inbound: type={s} sender={s} target={s}", .{ event_type, sender_id, reply_target });

        const msg = bus.makeInboundFull(
            self.allocator,
            "qq",
            sender_id,
            reply_target,
            final_content,
            session_key,
            &.{},
            metadata,
        ) catch |err| {
            log.err("failed to create InboundMessage: {}", .{err});
            return;
        };

        if (self.event_bus) |eb| {
            eb.publishInbound(msg) catch |err| {
                log.err("failed to publish inbound: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            msg.deinit(self.allocator);
        }
    }

    // ── Outbound send ────────────────────────────────────────────────

    /// Send a message to a QQ channel, DM, group, or C2C via REST API.
    /// Target format:
    ///   "channel:<channel_id>"  — guild channel message
    ///   "dm:<guild_id>"         — guild DM
    ///   "group:<group_openid>"  — group message
    ///   "c2c:<user_openid>"     — C2C private message
    ///   "user:<user_openid>"    — alias for c2c
    ///   "<user_openid>"         — defaults to c2c (zeroclaw parity)
    pub fn sendMessage(self: *QQChannel, target: []const u8, text: []const u8) !void {
        const ChunkSend = struct {
            channel: *QQChannel,
            chunk: []const u8,
            msg_seq: ?u32,

            fn send(ctx: *@This(), send_target: []const u8) !void {
                try ctx.channel.sendChunk(send_target, ctx.chunk, ctx.msg_seq);
            }
        };
        const MediaSend = struct {
            channel: *QQChannel,
            image_url: []const u8,
            msg_seq: ?u32,

            fn send(ctx: *@This(), send_target: []const u8) !void {
                try ctx.channel.sendMedia(send_target, ctx.image_url, ctx.msg_seq);
            }
        };

        const parsed_target = parseTarget(target);
        const msg_type = parsed_target[0];
        const msg_id = parsed_target[2];
        const supports_media_upload = std.mem.eql(u8, msg_type, "group") or std.mem.eql(u8, msg_type, "c2c");
        var fallback_target_buf: [256]u8 = undefined;
        const fallback_target = targetWithoutMessageId(&fallback_target_buf, target);

        var msg_seq: u32 = 1;
        if (supports_media_upload) {
            var parsed = try parseOutgoingContent(self.allocator, text);
            defer parsed.deinit(self.allocator);

            if (parsed.text.len > 0) {
                var text_it = root.splitMessage(parsed.text, MAX_MESSAGE_LEN);
                while (text_it.next()) |chunk| {
                    var chunk_send = ChunkSend{
                        .channel = self,
                        .chunk = chunk,
                        .msg_seq = if (msg_id != null) msg_seq else null,
                    };
                    try sendWithReplyFallback(target, fallback_target, "reply", &chunk_send);
                    if (msg_id != null and msg_seq < std.math.maxInt(u32)) {
                        msg_seq += 1;
                    }
                }
            }

            for (parsed.image_urls) |image_url| {
                var media_send = MediaSend{
                    .channel = self,
                    .image_url = image_url,
                    .msg_seq = if (msg_id != null) msg_seq else null,
                };
                try sendWithReplyFallback(target, fallback_target, "media reply", &media_send);
                if (msg_id != null and msg_seq < std.math.maxInt(u32)) {
                    msg_seq += 1;
                }
            }
            return;
        }

        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            var chunk_send = ChunkSend{
                .channel = self,
                .chunk = chunk,
                .msg_seq = if (msg_id != null) msg_seq else null,
            };
            try sendWithReplyFallback(target, fallback_target, "reply", &chunk_send);
            if (msg_id != null and msg_seq < std.math.maxInt(u32)) msg_seq += 1;
        }
    }

    fn sendChunk(self: *QQChannel, target: []const u8, text: []const u8, msg_seq: ?u32) !void {
        const msg_type, const id_str, const msg_id = parseTarget(target);

        const is_group = std.mem.eql(u8, msg_type, "group");
        const is_c2c = std.mem.eql(u8, msg_type, "c2c");
        const is_dm = std.mem.eql(u8, msg_type, "dm");
        const is_channel = std.mem.eql(u8, msg_type, "channel");
        if (!is_group and !is_c2c and !is_dm and !is_channel) {
            log.warn("sendChunk: unsupported target type '{s}'", .{msg_type});
            return error.InvalidTarget;
        }
        if (id_str.len == 0) {
            log.warn("sendChunk: empty target id for type '{s}'", .{msg_type});
            return error.InvalidTarget;
        }

        var sanitized_user_id: ?[]u8 = null;
        defer if (sanitized_user_id) |sid| self.allocator.free(sid);
        const target_id = blk: {
            if (is_c2c) {
                sanitized_user_id = sanitizeUserOpenId(self.allocator, id_str) catch |err| {
                    log.warn("sendChunk: invalid c2c user_openid: {}", .{err});
                    return error.InvalidTarget;
                };
                break :blk sanitized_user_id.?;
            }
            break :blk id_str;
        };

        log.info("sendChunk: target='{s}' msg_type='{s}' id='{s}' msg_id={s} text_len={d}", .{ target, msg_type, target_id, if (msg_id) |m| m else "(none)", text.len });

        const base = apiBase(self.config.sandbox);

        // Build URL based on target type
        var url_buf: [512]u8 = undefined;
        const url = if (is_group)
            buildGroupSendUrl(&url_buf, base, target_id) catch return
        else if (is_c2c)
            buildC2cSendUrl(&url_buf, base, target_id) catch return
        else if (is_dm)
            try buildDmUrl(&url_buf, base, target_id)
        else
            try buildSendUrl(&url_buf, base, target_id);

        log.info("sendChunk: URL={s}", .{url});

        const body = try buildSendBody(
            self.allocator,
            text,
            msg_id,
            if (is_group or is_c2c) @as(?u8, 0) else null,
            if (msg_id != null) msg_seq else null,
        );
        defer self.allocator.free(body);

        const token = self.ensureAccessToken() catch |err| {
            log.err("Access token fetch failed for sendChunk: {}", .{err});
            return error.QQApiError;
        };
        defer self.allocator.free(token);
        var auth_buf: [512]u8 = undefined;
        const auth_header = buildAuthHeader(&auth_buf, token) catch {
            return error.QQApiError;
        };

        log.info("sendChunk: POSTing to {s} ...", .{url});

        const resp = root.http_util.curlPostWithStatus(self.allocator, url, body, &.{auth_header}) catch |err| {
            log.err("QQ API POST failed: {}", .{err});
            return error.QQApiError;
        };
        defer self.allocator.free(resp.body);
        if (resp.status_code < 200 or resp.status_code >= 300) {
            log.err("QQ API send returned HTTP status {d}", .{resp.status_code});
            return error.QQApiError;
        }
        ensureQqApiSuccess(self.allocator, resp.body) catch {
            log.err("QQ API send returned non-zero code payload", .{});
            return error.QQApiError;
        };
        log.debug("sendChunk: API response_len={d}", .{resp.body.len});
    }

    fn sendMedia(self: *QQChannel, target: []const u8, image_url_raw: []const u8, msg_seq: ?u32) !void {
        const msg_type, const id_str, const msg_id = parseTarget(target);
        const is_group = std.mem.eql(u8, msg_type, "group");
        const is_c2c = std.mem.eql(u8, msg_type, "c2c");
        if (!is_group and !is_c2c) return error.InvalidTarget;
        if (id_str.len == 0) return error.InvalidTarget;

        const image_url = ensureHttpsMediaUrl(image_url_raw) catch |err| {
            log.warn("sendMedia: refusing non-https image url: {}", .{err});
            return err;
        };

        var sanitized_user_id: ?[]u8 = null;
        defer if (sanitized_user_id) |sid| self.allocator.free(sid);
        const target_id = blk: {
            if (is_c2c) {
                sanitized_user_id = sanitizeUserOpenId(self.allocator, id_str) catch |err| {
                    log.warn("sendMedia: invalid c2c user_openid: {}", .{err});
                    return error.InvalidTarget;
                };
                break :blk sanitized_user_id.?;
            }
            break :blk id_str;
        };

        const base = apiBase(self.config.sandbox);
        var message_url_buf: [512]u8 = undefined;
        const message_url = if (is_group)
            try buildGroupSendUrl(&message_url_buf, base, target_id)
        else
            try buildC2cSendUrl(&message_url_buf, base, target_id);
        var files_url_buf: [512]u8 = undefined;
        const files_url = if (is_group)
            try buildGroupFilesUrl(&files_url_buf, base, target_id)
        else
            try buildC2cFilesUrl(&files_url_buf, base, target_id);

        const token = self.ensureAccessToken() catch |err| {
            log.err("Access token fetch failed for sendMedia: {}", .{err});
            return error.QQApiError;
        };
        defer self.allocator.free(token);
        var auth_buf: [512]u8 = undefined;
        const auth_header = buildAuthHeader(&auth_buf, token) catch {
            return error.QQApiError;
        };

        const upload_body = try buildMediaUploadBody(self.allocator, image_url);
        defer self.allocator.free(upload_body);
        const upload_resp = root.http_util.curlPostWithStatus(self.allocator, files_url, upload_body, &.{auth_header}) catch |err| {
            log.err("QQ media upload failed: {}", .{err});
            return error.QQApiError;
        };
        defer self.allocator.free(upload_resp.body);
        if (upload_resp.status_code < 200 or upload_resp.status_code >= 300) {
            log.err("QQ media upload returned HTTP status {d}", .{upload_resp.status_code});
            return error.QQApiError;
        }
        ensureQqApiSuccess(self.allocator, upload_resp.body) catch {
            log.err("QQ media upload returned non-zero code payload", .{});
            return error.QQApiError;
        };

        const file_info = parseUploadedFileInfo(self.allocator, upload_resp.body) catch {
            log.err("QQ media upload response missing file_info", .{});
            return error.QQApiError;
        };
        defer self.allocator.free(file_info);

        const media_body = try buildMediaSendBody(
            self.allocator,
            file_info,
            msg_id,
            if (msg_id != null) msg_seq else null,
        );
        defer self.allocator.free(media_body);
        const send_resp = root.http_util.curlPostWithStatus(self.allocator, message_url, media_body, &.{auth_header}) catch |err| {
            log.err("QQ media send failed: {}", .{err});
            return error.QQApiError;
        };
        defer self.allocator.free(send_resp.body);
        if (send_resp.status_code < 200 or send_resp.status_code >= 300) {
            log.err("QQ media send returned HTTP status {d}", .{send_resp.status_code});
            return error.QQApiError;
        }
        ensureQqApiSuccess(self.allocator, send_resp.body) catch {
            log.err("QQ media send returned non-zero code payload", .{});
            return error.QQApiError;
        };
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        if (self.config.receive_mode == .webhook) {
            log.info("QQ channel in webhook receive_mode; websocket listener not started", .{});
            self.running.store(true, .release);
            return;
        }
        self.running.store(true, .release);
        self.heartbeat_stop.store(false, .release);
        log.info("QQ channel starting (sandbox={s}, app_id={s})", .{ if (self.config.sandbox) "true" else "false", self.config.app_id });
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.heartbeat_stop.store(true, .release);
        // Close socket to unblock blocking read
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            (std_compat.net.Stream{ .handle = fd }).close();
        }
        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }
        if (self.session_id) |sid| {
            self.allocator.free(sid);
            self.session_id = null;
        }
        self.token_mu.lock();
        defer self.token_mu.unlock();
        if (self.access_token) |tok| {
            self.allocator.free(tok);
            self.access_token = null;
        }
        self.dedup_set.deinit(self.dedup_allocator);
        self.dedup_set = .{};
        log.info("QQ channel stopped", .{});
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        log.info("vtableSend called: target='{s}' message_len={d}", .{ target, message.len });
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *QQChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *QQChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Gateway WebSocket loop ───────────────────────────────────────
    /// Main gateway loop: connect, run, reconnect on failure.
    fn gatewayLoop(self: *QQChannel) void {
        log.info("Gateway loop started", .{});
        const MAX_CONSECUTIVE_FAILURES: u32 = 10;
        var consecutive_failures: u32 = 0;
        while (self.running.load(.acquire)) {
            const backoff_ms: u64 = if (consecutive_failures < 3) 5000 else 15000;
            self.runGatewayOnce() catch |err| {
                log.warn("Gateway error: {}", .{err});
                consecutive_failures += 1;
                if (consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
                    log.err("Gateway: {d} consecutive failures, giving up", .{consecutive_failures});
                    self.running.store(false, .release);
                    break;
                }
            };
            if (!self.running.load(.acquire)) break;
            log.info("Reconnecting in {d}ms (attempt {d}/{d})...", .{ backoff_ms, consecutive_failures + 1, MAX_CONSECUTIVE_FAILURES });
            // Interruptible backoff
            var slept: u64 = 0;
            while (slept < backoff_ms and self.running.load(.acquire)) {
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                slept += 100;
            }
        }
        log.info("Gateway loop exited", .{});
    }

    /// Single connection attempt: connect WS, HELLO, IDENTIFY, read loop.
    fn runGatewayOnce(self: *QQChannel) !void {
        self.reconnect_requested = false;
        // Fresh IDENTIFY session: do not carry sequence from a previous connection.
        self.has_sequence.store(false, .release);
        self.sequence.store(0, .release);

        // Resolve gateway URL via REST API (v2 behavior).
        const token = self.ensureAccessToken() catch |err| {
            log.err("QQ access token fetch failed: {}", .{err});
            return error.TokenFetchFailed;
        };
        defer self.allocator.free(token);

        const gw_url = fetchGatewayUrl(self.allocator, token, self.config.sandbox) catch |err| {
            log.err("QQ gateway URL resolve failed: {}", .{err});
            return error.GatewayFetchFailed;
        };
        defer self.allocator.free(gw_url);
        if (!std.mem.startsWith(u8, gw_url, "wss://")) {
            log.err("QQ gateway URL must use wss://", .{});
            return error.InvalidGatewayUrl;
        }
        const host = parseGatewayHost(gw_url);
        const port = parseGatewayPort(gw_url);
        const path = parseGatewayPath(gw_url);
        log.info("Connecting to gateway: host={s} port={d} path={s}", .{ host, port, path });

        var ws = try websocket.WsClient.connect(self.allocator, host, port, path, &.{});

        // Store fd for interrupt-on-stop
        self.ws_fd.store(ws.stream.handle, .release);

        // Start heartbeat thread
        self.heartbeat_stop.store(false, .release);
        self.force_heartbeat.store(false, .release);
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

        log.info("WebSocket connected, waiting for HELLO...", .{});

        // Read HELLO (first message from server)
        const hello_text = try ws.readTextMessage() orelse return error.ConnectionClosed;
        defer self.allocator.free(hello_text);
        log.info("Received HELLO frame", .{});
        try self.handleGatewayEvent(hello_text);

        if (self.heartbeat_interval_ms.load(.acquire) == 0) {
            log.info("ERROR: No heartbeat_interval in HELLO", .{});
            return error.InvalidHello;
        }

        // Send IDENTIFY
        var identify_buf: [2048]u8 = undefined;
        const identify_payload = try buildIdentifyPayload(&identify_buf, token, DEFAULT_INTENTS);
        log.info("Sending IDENTIFY (app_id={s}, auth=QQBot)...", .{self.config.app_id});
        try ws.writeText(identify_payload);

        // Read READY (dispatch with t=READY)
        const ready_text = try ws.readTextMessage() orelse return error.ConnectionClosed;
        defer self.allocator.free(ready_text);
        log.info("Received READY frame", .{});
        try self.handleGatewayEvent(ready_text);

        // INVALID_SESSION after IDENTIFY means token/credentials are wrong
        if (self.reconnect_requested) {
            log.info("Session rejected after IDENTIFY — will reconnect", .{});
            return error.InvalidSession;
        }

        if (self.running.load(.acquire)) {
            log.info("Gateway READY — listening for messages (Ctrl+C to stop)", .{});
        }

        // Main read loop
        while (self.running.load(.acquire) and !self.reconnect_requested) {
            const maybe_text = ws.readTextMessage() catch |err| {
                log.info("Gateway read failed: {}", .{err});
                break;
            };
            const text = maybe_text orelse {
                log.info("Gateway connection closed by server", .{});
                break;
            };
            defer self.allocator.free(text);

            log.debug("Gateway event received: len={d}", .{text.len});

            self.handleGatewayEvent(text) catch |err| {
                log.err("Gateway event error: {}", .{err});
            };

            // Check if server requested reconnect
            if (self.reconnect_requested) break;
        }
    }

    /// Heartbeat thread: sends periodic heartbeat frames to keep the connection alive.
    fn sendHeartbeatNow(self: *QQChannel, ws: *websocket.WsClient) void {
        var hb_buf: [64]u8 = undefined;
        const seq: ?i64 = if (self.has_sequence.load(.acquire)) self.sequence.load(.acquire) else null;
        const hb_payload = buildHeartbeatPayload(&hb_buf, seq) catch return;
        ws.writeText(hb_payload) catch |err| {
            log.warn("Heartbeat failed: {}", .{err});
        };
    }

    /// Heartbeat thread: sends periodic heartbeat frames to keep the connection alive.
    fn heartbeatLoop(self: *QQChannel, ws: *websocket.WsClient) void {
        // Wait for heartbeat_interval to be set by HELLO handler
        while (!self.heartbeat_stop.load(.acquire) and self.heartbeat_interval_ms.load(.acquire) == 0) {
            if (self.force_heartbeat.swap(false, .acq_rel)) {
                self.sendHeartbeatNow(ws);
            }
            std_compat.thread.sleep(10 * std.time.ns_per_ms);
        }
        log.info("Heartbeat thread running (interval={d}ms)", .{self.heartbeat_interval_ms.load(.acquire)});
        while (!self.heartbeat_stop.load(.acquire)) {
            const interval_ms: u64 = self.heartbeat_interval_ms.load(.acquire);
            // Interruptible sleep
            var elapsed: u64 = 0;
            while (elapsed < interval_ms) {
                if (self.heartbeat_stop.load(.acquire)) return;
                if (self.force_heartbeat.swap(false, .acq_rel)) {
                    self.sendHeartbeatNow(ws);
                    elapsed = 0;
                    continue;
                }
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                elapsed += 100;
            }
            if (self.heartbeat_stop.load(.acquire)) return;
            self.sendHeartbeatNow(ws);
        }
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Parse target string into (type, id, msg_id).
/// "channel:12345"              -> ("channel", "12345", null)
/// "dm:12345"                   -> ("dm", "12345", null)
/// "group:<openid>:<msg_id>"    -> ("group", "<openid>", "<msg_id>")
/// "c2c:<openid>:<msg_id>"      -> ("c2c", "<openid>", "<msg_id>")
/// "12345"                      -> ("c2c", "12345", null)
fn parseTarget(target: []const u8) struct { []const u8, []const u8, ?[]const u8 } {
    if (std.mem.indexOf(u8, target, ":")) |first_colon| {
        const raw_msg_type = target[0..first_colon];
        const msg_type = if (std.mem.eql(u8, raw_msg_type, "user")) "c2c" else raw_msg_type;
        const rest = target[first_colon + 1 ..];
        // group/c2c reply targets may include a trailing msg_id after a second colon.
        if (std.mem.eql(u8, msg_type, "group") or std.mem.eql(u8, msg_type, "c2c")) {
            if (std.mem.indexOf(u8, rest, ":")) |second_colon| {
                return .{ msg_type, rest[0..second_colon], rest[second_colon + 1 ..] };
            }
        }
        return .{ msg_type, rest, null };
    }
    return .{ "c2c", target, null };
}

/// Get a string field from a JSON object value.
fn getJsonString(val: std.json.Value, key: []const u8) ?[]const u8 {
    if (val != .object) return null;
    const field = val.object.get(key) orelse return null;
    return if (field == .string) field.string else null;
}

/// Get a string field from a JSON object value (alias for nested access).
fn getJsonStringFromObj(val: std.json.Value, key: []const u8) ?[]const u8 {
    return getJsonString(val, key);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "qq config defaults" {
    const config = config_types.QQConfig{};
    try std.testing.expectEqualStrings("", config.app_id);
    try std.testing.expectEqualStrings("", config.app_secret);
    try std.testing.expectEqualStrings("", config.bot_token);
    try std.testing.expect(!config.sandbox);
    try std.testing.expect(config.receive_mode == .webhook);
    try std.testing.expect(config.group_policy == .allow);
    try std.testing.expectEqual(@as(usize, 0), config.allowed_groups.len);
}

test "qq config custom values" {
    const list = [_][]const u8{ "group1", "group2" };
    const config = config_types.QQConfig{
        .app_id = "12345",
        .app_secret = "secret",
        .bot_token = "token",
        .sandbox = true,
        .receive_mode = .websocket,
        .group_policy = .allowlist,
        .allowed_groups = &list,
    };
    try std.testing.expectEqualStrings("12345", config.app_id);
    try std.testing.expectEqualStrings("secret", config.app_secret);
    try std.testing.expect(config.sandbox);
    try std.testing.expect(config.receive_mode == .websocket);
    try std.testing.expect(config.group_policy == .allowlist);
    try std.testing.expectEqual(@as(usize, 2), config.allowed_groups.len);
}

test "qq opcode fromInt" {
    try std.testing.expect(Opcode.fromInt(0) == .dispatch);
    try std.testing.expect(Opcode.fromInt(1) == .heartbeat);
    try std.testing.expect(Opcode.fromInt(2) == .identify);
    try std.testing.expect(Opcode.fromInt(6) == .@"resume");
    try std.testing.expect(Opcode.fromInt(7) == .reconnect);
    try std.testing.expect(Opcode.fromInt(9) == .invalid_session);
    try std.testing.expect(Opcode.fromInt(10) == .hello);
    try std.testing.expect(Opcode.fromInt(11) == .heartbeat_ack);
    try std.testing.expect(Opcode.fromInt(99) == null);
    try std.testing.expect(Opcode.fromInt(-1) == null);
}

test "qq stripCqCodes plain text no tags" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "hello world");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "qq stripCqCodes removes at tag" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "[CQ:at,qq=123456] hello");
    defer alloc.free(result);
    try std.testing.expectEqualStrings(" hello", result);
}

test "qq stripCqCodes removes multiple tags" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "[CQ:at,qq=111] hi [CQ:image,file=pic.png]");
    defer alloc.free(result);
    try std.testing.expectEqualStrings(" hi ", result);
}

test "qq stripCqCodes empty string" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "qq stripCqCodes malformed tag preserved" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "broken [CQ:image,file=x");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("broken [CQ:image,file=x", result);
}

test "qq stripCqCodes face tag stripped" {
    const alloc = std.testing.allocator;
    const result = try stripCqCodes(alloc, "hi [CQ:face,id=178] there");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hi  there", result);
}

test "qq extractMentionQQ finds mention" {
    const qq = extractMentionQQ("[CQ:at,qq=123456] hello");
    try std.testing.expectEqualStrings("123456", qq.?);
}

test "qq extractMentionQQ returns null for no mention" {
    try std.testing.expect(extractMentionQQ("hello world") == null);
}

test "qq extractMentionQQ malformed returns null" {
    try std.testing.expect(extractMentionQQ("[CQ:at,qq=") == null);
}

test "qq string dedup set basic behavior" {
    const alloc = std.testing.allocator;
    var dedup = StringDedupSet{};
    defer dedup.deinit(alloc);

    try std.testing.expect(!(try dedup.isDuplicate(alloc, "msg-1")));
    try std.testing.expect(try dedup.isDuplicate(alloc, "msg-1"));
    try std.testing.expect(!(try dedup.isDuplicate(alloc, "msg-2")));
}

test "qq string dedup set evicts half at capacity" {
    const alloc = std.testing.allocator;
    var dedup = StringDedupSet{};
    defer dedup.deinit(alloc);

    var i: usize = 0;
    while (i < DEDUP_CAPACITY + 1) : (i += 1) {
        const key = try std.fmt.allocPrint(alloc, "msg-{d}", .{i});
        defer alloc.free(key);
        try std.testing.expect(!(try dedup.isDuplicate(alloc, key)));
    }

    try std.testing.expect(dedup.order.items.len <= DEDUP_CAPACITY);
}

test "qq buildIdentifyPayload" {
    var buf: [512]u8 = undefined;
    const payload = try buildIdentifyPayload(&buf, "my-access-token", DEFAULT_INTENTS);
    try std.testing.expect(std.mem.startsWith(u8, payload, "{\"op\":2,\"d\":{\"token\":\"QQBot my-access-token\""));
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"shard\":[0,1]") != null);
    // Must NOT contain the old "Bot" format
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"Bot ") == null);
}

test "qq buildHeartbeatPayload with sequence" {
    var buf: [64]u8 = undefined;
    const payload = try buildHeartbeatPayload(&buf, 42);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":42}", payload);
}

test "qq buildHeartbeatPayload null sequence" {
    var buf: [64]u8 = undefined;
    const payload = try buildHeartbeatPayload(&buf, null);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":null}", payload);
}

test "qq buildSendUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildSendUrl(&buf, API_BASE, "chan123");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/channels/chan123/messages", url);
}

test "qq buildDmUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildDmUrl(&buf, API_BASE, "guild456");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/dms/guild456/messages", url);
}

test "qq buildGatewayResolveUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildGatewayResolveUrl(&buf, API_BASE);
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/gateway", url);
}

test "qq buildSendBody" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "hello world", null, null, null);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"hello world\"}", body);
}

test "qq buildSendBody with msg_id" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "reply text", "msg_123", null, null);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"reply text\",\"msg_id\":\"msg_123\"}", body);
}

test "qq buildSendBody with msg_type" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "reply text", "msg_123", 0, null);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"reply text\",\"msg_id\":\"msg_123\",\"msg_type\":0}", body);
}

test "qq buildSendBody with msg_seq" {
    const alloc = std.testing.allocator;
    const body = try buildSendBody(alloc, "reply text", "msg_123", 0, 2);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\"reply text\",\"msg_id\":\"msg_123\",\"msg_type\":0,\"msg_seq\":2}", body);
}

test "qq buildMediaUploadBody" {
    const alloc = std.testing.allocator;
    const body = try buildMediaUploadBody(alloc, "https://cdn.example.com/a.png");
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"file_type\":1,\"url\":\"https://cdn.example.com/a.png\",\"srv_send_msg\":false}", body);
}

test "qq buildMediaSendBody with passive fields" {
    const alloc = std.testing.allocator;
    const body = try buildMediaSendBody(alloc, "file-info-abc", "msg_123", 3);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("{\"content\":\" \",\"msg_type\":7,\"media\":{\"file_info\":\"file-info-abc\"},\"msg_id\":\"msg_123\",\"msg_seq\":3}", body);
}

test "qq parseUploadedFileInfo extracts file_info" {
    const alloc = std.testing.allocator;
    const file_info = try parseUploadedFileInfo(alloc, "{\"file_info\":\"abc123\"}");
    defer alloc.free(file_info);
    try std.testing.expectEqualStrings("abc123", file_info);
}

test "qq ensureQqApiSuccess validates response payload" {
    const alloc = std.testing.allocator;
    try ensureQqApiSuccess(alloc, "{\"code\":0,\"message\":\"ok\"}");
    try ensureQqApiSuccess(alloc, "{\"file_info\":\"abc123\"}");
    try std.testing.expectError(error.QQApiError, ensureQqApiSuccess(alloc, "{\"code\":40001}"));
    try std.testing.expectError(error.QQApiError, ensureQqApiSuccess(alloc, "not-json"));
}

test "qq buildAuthHeader" {
    var buf: [256]u8 = undefined;
    const header = try buildAuthHeader(&buf, "my-access-token");
    try std.testing.expectEqualStrings("Authorization: QQBot my-access-token", header);
}

test "qq attachmentCacheDirPath uses system temp dir" {
    const alloc = std.testing.allocator;
    const tmp_dir = try platform.getTempDir(alloc);
    defer alloc.free(tmp_dir);

    const cache_dir = try attachmentCacheDirPath(alloc);
    defer alloc.free(cache_dir);

    try std.testing.expect(std.mem.startsWith(u8, cache_dir, tmp_dir));
    try std.testing.expect(std.mem.endsWith(u8, cache_dir, QQ_ATTACHMENT_CACHE_SUBDIR));
}

test "qq isGroupAllowed policy allow" {
    const config = config_types.QQConfig{ .group_policy = .allow };
    try std.testing.expect(isGroupAllowed(config, "anygroup"));
}

test "qq isGroupAllowed policy allowlist" {
    const list = [_][]const u8{ "group1", "group2" };
    const config = config_types.QQConfig{ .group_policy = .allowlist, .allowed_groups = &list };
    try std.testing.expect(isGroupAllowed(config, "group1"));
    try std.testing.expect(isGroupAllowed(config, "group2"));
    try std.testing.expect(!isGroupAllowed(config, "group3"));
}

test "qq isGroupAllowed empty allowlist denies all" {
    const config = config_types.QQConfig{ .group_policy = .allowlist, .allowed_groups = &.{} };
    try std.testing.expect(!isGroupAllowed(config, "anygroup"));
}

test "qq apiBase returns correct urls" {
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com", apiBase(false));
    try std.testing.expectEqualStrings("https://sandbox.api.sgroup.qq.com", apiBase(true));
}

test "qq gatewayUrl returns correct urls" {
    try std.testing.expectEqualStrings("wss://api.sgroup.qq.com/websocket", gatewayUrl(false));
    try std.testing.expectEqualStrings("wss://sandbox.api.sgroup.qq.com/websocket", gatewayUrl(true));
}

test "qq parseGatewayHost from wss url" {
    const host = parseGatewayHost("wss://api.sgroup.qq.com/websocket");
    try std.testing.expectEqualStrings("api.sgroup.qq.com", host);
}

test "qq parseGatewayHost strips explicit port" {
    const host = parseGatewayHost("wss://api.sgroup.qq.com:8443/websocket");
    try std.testing.expectEqualStrings("api.sgroup.qq.com", host);
}

test "qq parseGatewayPort from wss url" {
    try std.testing.expectEqual(@as(u16, 8443), parseGatewayPort("wss://api.sgroup.qq.com:8443/websocket"));
    try std.testing.expectEqual(@as(u16, 443), parseGatewayPort("wss://api.sgroup.qq.com/websocket"));
}

test "qq parseGatewayPath from wss url with query" {
    const path = parseGatewayPath("wss://api.sgroup.qq.com/websocket?v=1");
    try std.testing.expectEqualStrings("/websocket?v=1", path);
}

test "qq parseGatewayPath defaults when missing explicit path" {
    const path = parseGatewayPath("wss://api.sgroup.qq.com");
    try std.testing.expectEqualStrings("/websocket", path);
}

test "qq fetchGatewayUrl returns static gateway in test mode" {
    const alloc = std.testing.allocator;
    const url = try fetchGatewayUrl(alloc, "test-access-token", false);
    defer alloc.free(url);
    try std.testing.expectEqualStrings(gatewayUrl(false), url);
}

test "qq parseTarget channel prefix" {
    const msg_type, const id, const mid = parseTarget("channel:12345");
    try std.testing.expectEqualStrings("channel", msg_type);
    try std.testing.expectEqualStrings("12345", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget dm prefix" {
    const msg_type, const id, const mid = parseTarget("dm:67890");
    try std.testing.expectEqualStrings("dm", msg_type);
    try std.testing.expectEqualStrings("67890", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget no prefix defaults to c2c" {
    const msg_type, const id, const mid = parseTarget("12345");
    try std.testing.expectEqualStrings("c2c", msg_type);
    try std.testing.expectEqualStrings("12345", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget channel keeps extra colon in id" {
    const msg_type, const id, const mid = parseTarget("channel:abc:def");
    try std.testing.expectEqualStrings("channel", msg_type);
    try std.testing.expectEqualStrings("abc:def", id);
    try std.testing.expect(mid == null);
}

test "qq parseImageMarkerLine extracts marker target" {
    const marker = parseImageMarkerLine(" [IMAGE:https://cdn.example.com/a.png] ").?;
    try std.testing.expectEqualStrings("https://cdn.example.com/a.png", marker);
}

test "qq parseOutgoingContent extracts remote image markers" {
    const alloc = std.testing.allocator;
    var parsed = try parseOutgoingContent(alloc, "hello\n[IMAGE:https://cdn.example.com/a.png]\n[IMAGE:http://cdn.example.com/b.jpg]\nbye");
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("hello\nbye", parsed.text);
    try std.testing.expectEqual(@as(usize, 2), parsed.image_urls.len);
    try std.testing.expectEqualStrings("https://cdn.example.com/a.png", parsed.image_urls[0]);
    try std.testing.expectEqualStrings("http://cdn.example.com/b.jpg", parsed.image_urls[1]);
}

test "qq parseOutgoingContent keeps non-remote marker as text" {
    const alloc = std.testing.allocator;
    var parsed = try parseOutgoingContent(alloc, "[IMAGE:/tmp/a.png]\nhello");
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("[IMAGE:/tmp/a.png]\nhello", parsed.text);
    try std.testing.expectEqual(@as(usize, 0), parsed.image_urls.len);
}

test "qq ensureHttpsMediaUrl rejects http" {
    try std.testing.expectError(error.InvalidMediaUrl, ensureHttpsMediaUrl("http://cdn.example.com/a.png"));
    const ok = try ensureHttpsMediaUrl("  https://cdn.example.com/a.png  ");
    try std.testing.expectEqualStrings("https://cdn.example.com/a.png", ok);
}

test "qq QQChannel init stores config" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{
        .app_id = "myapp",
        .bot_token = "mytoken",
        .sandbox = true,
    });
    try std.testing.expectEqualStrings("myapp", ch.config.app_id);
    try std.testing.expectEqualStrings("mytoken", ch.config.bot_token);
    try std.testing.expect(ch.config.sandbox);
    try std.testing.expectEqualStrings("qq", ch.channelName());
    try std.testing.expect(ch.healthCheck());
    try std.testing.expect(!ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), ch.heartbeat_interval_ms.load(.acquire));
}

test "qq healthCheck websocket requires running socket" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .receive_mode = .websocket });
    try std.testing.expect(!ch.healthCheck());

    ch.running.store(true, .release);
    try std.testing.expect(!ch.healthCheck());

    const fake_socket: std.posix.socket_t = if (builtin.os.tag == .windows)
        @ptrFromInt(1)
    else
        42;
    ch.ws_fd.store(fake_socket, .release);
    try std.testing.expect(ch.healthCheck());
}

test "qq QQChannel vtable compiles" {
    const vtable_instance = QQChannel.vtable;
    try std.testing.expect(vtable_instance.start == &QQChannel.vtableStart);
    try std.testing.expect(vtable_instance.stop == &QQChannel.vtableStop);
    try std.testing.expect(vtable_instance.send == &QQChannel.vtableSend);
    try std.testing.expect(vtable_instance.name == &QQChannel.vtableName);
    try std.testing.expect(vtable_instance.healthCheck == &QQChannel.vtableHealthCheck);
}

test "qq QQChannel channel interface" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("qq", iface.name());
}

test "qq handleGatewayEvent HELLO" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const hello_json =
        \\{"op":10,"d":{"heartbeat_interval":41250}}
    ;
    try ch.handleGatewayEvent(hello_json);
    try std.testing.expectEqual(@as(u32, 41250), ch.heartbeat_interval_ms.load(.acquire));
}

test "qq handleGatewayEvent READY" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    defer {
        if (ch.session_id) |sid| alloc.free(sid);
    }
    const ready_json =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess_abc123","user":{"id":"bot1"}}}
    ;
    try ch.handleGatewayEvent(ready_json);
    try std.testing.expect(ch.running.load(.acquire));
    try std.testing.expectEqualStrings("sess_abc123", ch.session_id.?);
    try std.testing.expect(ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(i64, 1), ch.sequence.load(.acquire));
}

test "qq handleGatewayEvent accepts large 64-bit sequence" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const ready_json =
        \\{"op":0,"s":5000000000,"t":"READY","d":{"session_id":"sess_overflow"}}
    ;
    defer {
        if (ch.session_id) |sid| alloc.free(sid);
    }
    try ch.handleGatewayEvent(ready_json);
    try std.testing.expect(ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(i64, 5000000000), ch.sequence.load(.acquire));
}

test "qq handleGatewayEvent ignores negative sequence" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    const ready_json =
        \\{"op":0,"s":-3,"t":"READY","d":{"session_id":"sess_negative"}}
    ;
    defer {
        if (ch.session_id) |sid| alloc.free(sid);
    }
    try ch.handleGatewayEvent(ready_json);
    try std.testing.expect(!ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "qq handleGatewayEvent invalid sequence clears previous value" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    defer {
        if (ch.session_id) |sid| alloc.free(sid);
    }

    const ready_ok =
        \\{"op":0,"s":77,"t":"READY","d":{"session_id":"sess_ok"}}
    ;
    try ch.handleGatewayEvent(ready_ok);
    try std.testing.expect(ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(i64, 77), ch.sequence.load(.acquire));

    const ready_negative =
        \\{"op":0,"s":-8,"t":"READY","d":{"session_id":"sess_negative_after_ok"}}
    ;
    try ch.handleGatewayEvent(ready_negative);
    try std.testing.expect(!ch.has_sequence.load(.acquire));
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "qq handleGatewayEvent MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"id":"msg001","channel_id":"ch1","guild_id":"g1","content":"hello qq","author":{"id":"user1","username":"tester"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("user1", msg.sender_id);
    try std.testing.expectEqualStrings("channel:ch1", msg.chat_id);
    try std.testing.expectEqualStrings("hello qq", msg.content);
    try std.testing.expectEqualStrings("qq:ch1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    const meta_parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta_parsed.deinit();
    try std.testing.expect(meta_parsed.value == .object);
    try std.testing.expect(meta_parsed.value.object.get("account_id") != null);
    try std.testing.expect(meta_parsed.value.object.get("account_id").? == .string);
    try std.testing.expectEqualStrings("qq-main", meta_parsed.value.object.get("account_id").?.string);
}

test "qq handleGatewayEvent MESSAGE_CREATE accepts msg_id fallback" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"msg_id":"msg-fallback-1","channel_id":"ch1","guild_id":"g1","content":"hello qq","author":{"id":"user1"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("channel:ch1", msg.chat_id);
}

test "qq handleGatewayEvent metadata escapes dynamic strings" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"id":"msg\"001","channel_id":"ch\\1","guild_id":"g1","content":"hello","author":{"id":"user1"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expectEqualStrings("msg\"001", meta.value.object.get("msg_id").?.string);
    try std.testing.expectEqualStrings("ch\\1", meta.value.object.get("channel_id").?.string);
}

test "qq handleGatewayEvent DIRECT_MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":3,"t":"DIRECT_MESSAGE_CREATE","d":{"id":"dm001","channel_id":"dch1","guild_id":"dg1","content":"dm hello","author":{"id":"u2"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("u2", msg.sender_id);
    // For DMs, chat_id must include dm: prefix for sendMessage routing.
    try std.testing.expectEqualStrings("dm:dg1", msg.chat_id);
    try std.testing.expectEqualStrings("dm hello", msg.content);
}

test "qq handleGatewayEvent deduplication" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":4,"t":"MESSAGE_CREATE","d":{"id":"msg_dup","channel_id":"ch1","content":"test","author":{"id":"u1"}}}
    ;

    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    var msg = event_bus_inst.consumeInbound().?;
    msg.deinit(alloc);
}

test "qq handleGatewayEvent group allowlist filters" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    const list = [_][]const u8{"allowed_guild"};
    var ch = QQChannel.init(alloc, .{
        .group_policy = .allowlist,
        .allowed_groups = &list,
        .allow_from = &.{"*"},
    });
    ch.setBus(&event_bus_inst);

    // Message from non-allowed guild — should be filtered
    const blocked_json =
        \\{"op":0,"s":5,"t":"MESSAGE_CREATE","d":{"id":"msg_blocked","channel_id":"ch1","guild_id":"blocked_guild","content":"blocked","author":{"id":"u1"}}}
    ;
    try ch.handleGatewayEvent(blocked_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());

    // Message from allowed guild — should pass
    const allowed_json =
        \\{"op":0,"s":6,"t":"MESSAGE_CREATE","d":{"id":"msg_allowed","channel_id":"ch2","guild_id":"allowed_guild","content":"allowed","author":{"id":"u2"}}}
    ;
    try ch.handleGatewayEvent(allowed_json);
    try std.testing.expectEqual(@as(usize, 1), event_bus_inst.inboundDepth());

    var msg = event_bus_inst.consumeInbound().?;
    msg.deinit(alloc);
}

test "qq handleGatewayEvent drops sender when allow_from empty" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{});
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":15,"t":"C2C_MESSAGE_CREATE","d":{"id":"msg-denied","author":{"user_openid":"user-1"},"content":"hello"}}
    ;
    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "qq handleGatewayEvent RECONNECT sets running false" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    ch.running.store(true, .release);
    try ch.handleGatewayEvent("{\"op\":7}");
    // RECONNECT triggers a reconnect, not a full stop
    try std.testing.expect(ch.reconnect_requested);
    try std.testing.expect(ch.running.load(.acquire));
}

test "qq handleGatewayEvent INVALID_SESSION sets running false" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    ch.running.store(true, .release);
    // Suppress expected warning from INVALID_SESSION opcode
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    try ch.handleGatewayEvent("{\"op\":9}");
    // INVALID_SESSION triggers a reconnect, not a full stop
    try std.testing.expect(ch.reconnect_requested);
    try std.testing.expect(ch.running.load(.acquire));
}

test "qq handleGatewayEvent HEARTBEAT_ACK is silent" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    try ch.handleGatewayEvent("{\"op\":11}");
    // No crash, no state change
}

test "qq handleGatewayEvent HEARTBEAT requests immediate heartbeat" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    try ch.handleGatewayEvent("{\"op\":1}");
    try std.testing.expect(ch.force_heartbeat.load(.acquire));
}

test "qq handleGatewayEvent invalid JSON" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{});
    // Suppress expected warnings from invalid input
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    try ch.handleGatewayEvent("not json");
    try ch.handleGatewayEvent("{broken");
    try ch.handleGatewayEvent("");
}

test "qq handleGatewayEvent allow_from uses exact match" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"User-Exact"} });
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":15,"t":"C2C_MESSAGE_CREATE","d":{"id":"msg-case","author":{"user_openid":"user-exact"},"content":"hello"}}
    ;
    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "qq buildWebhookValidationResponse handles op13 challenge" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .app_secret = "super-secret" });

    const payload =
        \\{"op":13,"d":{"plain_token":"plain123","event_ts":"1725442341"}}
    ;
    const response = try ch.buildWebhookValidationResponse(alloc, payload);
    try std.testing.expect(response != null);
    defer alloc.free(response.?);

    try std.testing.expect(std.mem.indexOf(u8, response.?, "\"plain_token\":\"plain123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.?, "\"signature\":\"") != null);
}

test "qq parseWebhookPayload returns inbound message for dispatch event" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main", .allow_from = &.{"*"} });

    const payload =
        \\{"op":0,"s":42,"t":"C2C_MESSAGE_CREATE","d":{"id":"msg001","author":{"user_openid":"user_oid_1"},"content":"hello webhook"}}
    ;
    const maybe_msg = try ch.parseWebhookPayload(alloc, payload);
    try std.testing.expect(maybe_msg != null);

    var msg = maybe_msg.?;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("user_oid_1", msg.sender_id);
    try std.testing.expectEqualStrings("c2c:user_oid_1:msg001", msg.chat_id);
    try std.testing.expectEqualStrings("hello webhook", msg.content);
}

test "qq parseWebhookPayload deduplicates repeated message id" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .account_id = "qq-main", .allow_from = &.{"*"} });

    const payload =
        \\{"op":0,"s":42,"t":"C2C_MESSAGE_CREATE","d":{"id":"msg001","author":{"user_openid":"user_oid_1"},"content":"hello webhook"}}
    ;
    const first = try ch.parseWebhookPayload(alloc, payload);
    try std.testing.expect(first != null);
    if (first) |msg| msg.deinit(alloc);

    const second = try ch.parseWebhookPayload(alloc, payload);
    try std.testing.expect(second == null);
}

test "qq handleGatewayEvent empty message content ignored" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":7,"t":"MESSAGE_CREATE","d":{"id":"msg_empty","channel_id":"ch1","content":"   ","author":{"id":"u1"}}}
    ;
    try ch.handleGatewayEvent(msg_json);
    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}

test "qq handleGatewayEvent image-only attachment keeps marker content" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":16,"t":"C2C_MESSAGE_CREATE","d":{"id":"msg_img","author":{"user_openid":"u_img"},"content":"   ","attachments":[{"url":"https://cdn.example.com/a.png","content_type":"image/png"}]}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("[IMAGE:https://cdn.example.com/a.png]", msg.content);
}

test "qq handleGatewayEvent strips CQ codes from content" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);

    const msg_json =
        \\{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{"id":"msg_cq","channel_id":"ch1","content":"[CQ:at,qq=100] help me","author":{"id":"u3"}}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("help me", msg.content);
}

test "qq MAX_MESSAGE_LEN constant" {
    try std.testing.expectEqual(@as(usize, 4096), QQChannel.MAX_MESSAGE_LEN);
}

test "qq RECONNECT_DELAY_NS constant" {
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), QQChannel.RECONNECT_DELAY_NS);
}

test "qq DEFAULT_INTENTS has expected bits" {
    // GROUP_AND_C2C_EVENT (bit 25) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 25) != 0);
    // PUBLIC_GUILD_MESSAGES (bit 30) should be set
    try std.testing.expect(DEFAULT_INTENTS & (1 << 30) != 0);
    // Other bits should remain unset in the default mask.
    try std.testing.expect(DEFAULT_INTENTS & (1 << 0) == 0);
    try std.testing.expect(DEFAULT_INTENTS & (1 << 1) == 0);
    try std.testing.expect(DEFAULT_INTENTS & (1 << 12) == 0);
    try std.testing.expect(DEFAULT_INTENTS & (1 << 9) == 0);
}

test "qq fetchAccessToken returns test token in test mode" {
    const alloc = std.testing.allocator;
    const result = try fetchAccessToken(alloc, "test-app", "test-secret");
    defer alloc.free(result.token);
    try std.testing.expectEqualStrings("test-access-token", result.token);
    try std.testing.expectEqual(@as(i64, 7200), result.expires_in);
}

test "qq QQChannel ensureAccessToken caches token" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .app_id = "test-app", .app_secret = "test-secret" });
    defer {
        if (ch.access_token) |tok| alloc.free(tok);
    }

    const token1 = try ch.ensureAccessToken();
    defer alloc.free(token1);
    try std.testing.expectEqualStrings("test-access-token", token1);

    // Second call should still use cached channel token, but caller gets its own copy.
    const cached_ptr = ch.access_token.?.ptr;
    const token2 = try ch.ensureAccessToken();
    defer alloc.free(token2);
    try std.testing.expectEqualStrings("test-access-token", token2);
    try std.testing.expect(cached_ptr == ch.access_token.?.ptr);
    try std.testing.expect(token1.ptr != token2.ptr);
}

test "qq buildGroupSendUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildGroupSendUrl(&buf, API_BASE, "group_openid_123");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/v2/groups/group_openid_123/messages", url);
}

test "qq buildGroupFilesUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildGroupFilesUrl(&buf, API_BASE, "group_openid_123");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/v2/groups/group_openid_123/files", url);
}

test "qq buildC2cSendUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildC2cSendUrl(&buf, API_BASE, "user_openid_456");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/v2/users/user_openid_456/messages", url);
}

test "qq buildC2cFilesUrl" {
    var buf: [256]u8 = undefined;
    const url = try buildC2cFilesUrl(&buf, API_BASE, "user_openid_456");
    try std.testing.expectEqualStrings("https://api.sgroup.qq.com/v2/users/user_openid_456/files", url);
}

test "qq parseTarget group prefix" {
    const msg_type, const id, const mid = parseTarget("group:openid_abc");
    try std.testing.expectEqualStrings("group", msg_type);
    try std.testing.expectEqualStrings("openid_abc", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget c2c prefix" {
    const msg_type, const id, const mid = parseTarget("c2c:openid_xyz");
    try std.testing.expectEqualStrings("c2c", msg_type);
    try std.testing.expectEqualStrings("openid_xyz", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget user prefix aliases to c2c" {
    const msg_type, const id, const mid = parseTarget("user:openid_xyz");
    try std.testing.expectEqualStrings("c2c", msg_type);
    try std.testing.expectEqualStrings("openid_xyz", id);
    try std.testing.expect(mid == null);
}

test "qq parseTarget c2c with msg_id" {
    const msg_type, const id, const mid = parseTarget("c2c:openid_xyz:msg_abc123");
    try std.testing.expectEqualStrings("c2c", msg_type);
    try std.testing.expectEqualStrings("openid_xyz", id);
    try std.testing.expectEqualStrings("msg_abc123", mid.?);
}

test "qq parseTarget group with msg_id" {
    const msg_type, const id, const mid = parseTarget("group:openid_abc:msg_def456");
    try std.testing.expectEqualStrings("group", msg_type);
    try std.testing.expectEqualStrings("openid_abc", id);
    try std.testing.expectEqualStrings("msg_def456", mid.?);
}

// Regression: QQ delayed replies may need to fall back to a plain target without msg_id.
test "qq targetWithoutMessageId strips reply msg_id for c2c and group" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("c2c:openid_xyz", targetWithoutMessageId(&buf, "c2c:openid_xyz:msg_abc123").?);
    try std.testing.expectEqualStrings("group:openid_abc", targetWithoutMessageId(&buf, "group:openid_abc:msg_def456").?);
    try std.testing.expect(targetWithoutMessageId(&buf, "channel:abc:def") == null);
    try std.testing.expect(targetWithoutMessageId(&buf, "c2c:openid_xyz") == null);
}

// Regression: issue #722 must retry delayed QQ replies without msg_id after API failure.
test "qq sendWithReplyFallback retries QQApiError with plain target" {
    const Sender = struct {
        allocator: std.mem.Allocator,
        calls: std.ArrayListUnmanaged([]const u8) = .empty,
        fail_first: bool = true,

        fn deinit(self: *@This()) void {
            self.calls.deinit(self.allocator);
        }

        fn send(self: *@This(), send_target: []const u8) !void {
            try self.calls.append(self.allocator, send_target);
            if (self.fail_first) {
                self.fail_first = false;
                return error.QQApiError;
            }
        }
    };

    var sender = Sender{ .allocator = std.testing.allocator };
    defer sender.deinit();

    try sendWithReplyFallback("group:openid_abc:msg_def456", "group:openid_abc", "reply", &sender);
    try std.testing.expectEqual(@as(usize, 2), sender.calls.items.len);
    try std.testing.expectEqualStrings("group:openid_abc:msg_def456", sender.calls.items[0]);
    try std.testing.expectEqualStrings("group:openid_abc", sender.calls.items[1]);
}

test "qq sendWithReplyFallback does not retry without plain target" {
    const Sender = struct {
        calls: usize = 0,

        fn send(self: *@This(), _: []const u8) !void {
            self.calls += 1;
            return error.QQApiError;
        }
    };

    var sender = Sender{};
    try std.testing.expectError(error.QQApiError, sendWithReplyFallback("channel:abc", null, "reply", &sender));
    try std.testing.expectEqual(@as(usize, 1), sender.calls);
}

test "qq sendChunk rejects unsupported target type" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .app_id = "test-app", .app_secret = "test-secret" });
    try std.testing.expectError(error.InvalidTarget, ch.sendChunk("foo:openid_1", "hi", null));
}

test "qq sendChunk rejects empty target id" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .app_id = "test-app", .app_secret = "test-secret" });
    try std.testing.expectError(error.InvalidTarget, ch.sendChunk("dm:", "hi", null));
}

test "qq sanitizeUserOpenId strips unsafe chars" {
    const alloc = std.testing.allocator;
    const safe = try sanitizeUserOpenId(alloc, "../u$er_123");
    defer alloc.free(safe);
    try std.testing.expectEqualStrings("uer_123", safe);
}

test "qq sendChunk rejects c2c target with unsafe-only id" {
    const alloc = std.testing.allocator;
    var ch = QQChannel.init(alloc, .{ .app_id = "test-app", .app_secret = "test-secret" });
    try std.testing.expectError(error.InvalidTarget, ch.sendChunk("c2c:../", "hi", null));
}

test "qq handleGatewayEvent C2C_MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":10,"t":"C2C_MESSAGE_CREATE","d":{"id":"c2c001","author":{"user_openid":"user_oid_1"},"content":"hi from c2c","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("user_oid_1", msg.sender_id);
    try std.testing.expectEqualStrings("c2c:user_oid_1:c2c001", msg.chat_id);
    try std.testing.expectEqualStrings("hi from c2c", msg.content);
    try std.testing.expect(std.mem.startsWith(u8, msg.session_key, "qq:c2c:"));
}

test "qq handleGatewayEvent C2C_MESSAGE_CREATE prefers user_openid sender" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":10,"t":"C2C_MESSAGE_CREATE","d":{"id":"c2c002","author":{"id":"legacy-id","user_openid":"openid-id"},"content":"hi from c2c","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("openid-id", msg.sender_id);
    try std.testing.expectEqualStrings("c2c:openid-id:c2c002", msg.chat_id);
}

test "qq handleGatewayEvent C2C_MESSAGE_CREATE includes image attachment marker" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":10,"t":"C2C_MESSAGE_CREATE","d":{"id":"c2c-img","author":{"user_openid":"openid-id"},"content":"  ","attachments":[{"content_type":"image/png","url":"https://cdn.example.com/a.png"}],"timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("[IMAGE:https://cdn.example.com/a.png]", msg.content);
}

test "qq handleGatewayEvent GROUP_AT_MESSAGE_CREATE" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":11,"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"grp001","group_openid":"grp_oid_1","author":{"member_openid":"mem_oid_1"},"content":"@bot hello","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("qq", msg.channel);
    try std.testing.expectEqualStrings("mem_oid_1", msg.sender_id);
    try std.testing.expectEqualStrings("group:grp_oid_1:grp001", msg.chat_id);
    try std.testing.expect(std.mem.startsWith(u8, msg.session_key, "qq:group:"));
}

test "qq handleGatewayEvent GROUP_AT_MESSAGE_CREATE prefers member_openid sender" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":11,"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"grp002","group_openid":"grp_oid_2","author":{"id":"legacy-id","member_openid":"mem_oid_2"},"content":"@bot hello","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("mem_oid_2", msg.sender_id);
    try std.testing.expectEqualStrings("group:grp_oid_2:grp002", msg.chat_id);
}

test "qq handleGatewayEvent C2C_MESSAGE_CREATE falls back to author id" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":12,"t":"C2C_MESSAGE_CREATE","d":{"id":"c2c-missing-openid","author":{"id":"legacy-id"},"content":"hi","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("legacy-id", msg.sender_id);
    try std.testing.expectEqualStrings("c2c:legacy-id:c2c-missing-openid", msg.chat_id);
}

test "qq handleGatewayEvent GROUP_AT_MESSAGE_CREATE falls back to group_id" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":13,"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"grp-missing-openid","group_id":"grp_fallback_1","author":{"member_openid":"mem_oid_1"},"content":"@bot hello","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    var msg = event_bus_inst.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("group:grp_fallback_1:grp-missing-openid", msg.chat_id);
}

test "qq handleGatewayEvent GROUP_AT_MESSAGE_CREATE drops when group id missing" {
    const alloc = std.testing.allocator;
    var event_bus_inst = bus.Bus.init();
    defer event_bus_inst.close();

    var ch = QQChannel.init(alloc, .{ .account_id = "qq-test", .allow_from = &.{"*"} });
    ch.setBus(&event_bus_inst);
    ch.running.store(true, .release);

    const msg_json =
        \\{"op":0,"s":14,"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"grp-no-ids","author":{"member_openid":"mem_oid_1"},"content":"@bot hello","timestamp":"2025-01-01T00:00:00Z"}}
    ;
    try ch.handleGatewayEvent(msg_json);

    try std.testing.expectEqual(@as(usize, 0), event_bus_inst.inboundDepth());
}
