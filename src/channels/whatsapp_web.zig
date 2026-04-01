const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const outbound = @import("../outbound.zig");
const config_types = @import("../config_types.zig");

/// WhatsApp Web channel — uses Baileys sidecar for WhatsApp Web protocol.
/// Operates in webhook mode (push-based); sidecar forwards messages to gateway.
/// Sends outbound messages via HTTP POST to the sidecar's /send endpoint.
pub const WhatsAppWebChannel = struct {
    allocator: std.mem.Allocator,
    sidecar_url: []const u8,
    auth_token: []const u8,
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    group_policy: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        sidecar_url: []const u8,
        auth_token: []const u8,
        allow_from: []const []const u8,
        group_allow_from: []const []const u8,
        group_policy: []const u8,
    ) WhatsAppWebChannel {
        return .{
            .allocator = allocator,
            .sidecar_url = sidecar_url,
            .auth_token = auth_token,
            .allow_from = allow_from,
            .group_allow_from = group_allow_from,
            .group_policy = group_policy,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WhatsAppWebConfig) WhatsAppWebChannel {
        return init(
            allocator,
            cfg.sidecar_url,
            cfg.auth_token,
            cfg.allow_from,
            cfg.group_allow_from,
            cfg.group_policy,
        );
    }

    pub fn channelName(_: *WhatsAppWebChannel) []const u8 {
        return "whatsapp_web";
    }

    /// Check if a phone number is allowed.
    pub fn isNumberAllowed(self: *const WhatsAppWebChannel, phone: []const u8) bool {
        return root.isAllowed(self.allow_from, phone);
    }

    /// Normalize a phone number to E.164 (prepend + if missing).
    pub fn normalizePhone(buf: []u8, phone: []const u8) []const u8 {
        if (phone.len == 0) return phone;
        if (phone[0] == '+') return phone;
        if (phone.len + 1 > buf.len) return phone;
        buf[0] = '+';
        @memcpy(buf[1..][0..phone.len], phone);
        return buf[0 .. phone.len + 1];
    }

    /// Parse a webhook payload from the sidecar.
    /// The sidecar sends a simplified JSON: {"from":"+1234","text":"hi","timestamp":"123","is_group":false,"group_id":null,"reply_to":"..."}
    pub fn parseWebhookPayload(
        self: *const WhatsAppWebChannel,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) ![]ParsedMessage {
        var result: std.ArrayListUnmanaged(ParsedMessage) = .empty;
        errdefer {
            for (result.items) |*m| m.deinit(allocator);
            result.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return result.items;
        defer parsed.deinit();
        const val = parsed.value;

        if (val != .object) return result.items;

        const from_val = val.object.get("from") orelse return result.items;
        const from = if (from_val == .string) from_val.string else return result.items;

        // Normalize phone
        var phone_buf: [32]u8 = undefined;
        const normalized = normalizePhone(&phone_buf, from);

        // Check group policy
        const is_group = blk: {
            const ig = val.object.get("is_group") orelse break :blk false;
            break :blk if (ig == .bool) ig.bool else false;
        };

        if (!is_group) {
            if (self.allow_from.len > 0 and !self.isNumberAllowed(normalized)) return result.items;
        } else {
            if (std.mem.eql(u8, self.group_policy, "disabled")) return result.items;
            if (!std.mem.eql(u8, self.group_policy, "open")) {
                const effective_allow_from = if (self.group_allow_from.len > 0)
                    self.group_allow_from
                else
                    self.allow_from;
                if (effective_allow_from.len == 0) return result.items;
                if (!root.isAllowed(effective_allow_from, normalized)) return result.items;
            }
        }

        // Extract text
        const text_val = val.object.get("text") orelse return result.items;
        const text = if (text_val == .string) text_val.string else return result.items;
        if (text.len == 0) return result.items;

        // Extract timestamp
        const timestamp = blk: {
            const ts_val = val.object.get("timestamp") orelse break :blk root.nowEpochSecs();
            if (ts_val == .string) {
                break :blk std.fmt.parseInt(u64, ts_val.string, 10) catch root.nowEpochSecs();
            }
            break :blk root.nowEpochSecs();
        };

        // Extract reply_to (the JID to reply back to)
        const reply_to = blk: {
            const rt_val = val.object.get("reply_to") orelse break :blk null;
            break :blk if (rt_val == .string) rt_val.string else null;
        };

        try result.append(allocator, .{
            .sender = try allocator.dupe(u8, normalized),
            .content = try allocator.dupe(u8, text),
            .timestamp = timestamp,
            .reply_to = if (reply_to) |rt| try allocator.dupe(u8, rt) else null,
            .is_group = is_group,
            .group_id = blk: {
                const gid_val = val.object.get("group_id") orelse break :blk null;
                break :blk if (gid_val == .string) try allocator.dupe(u8, gid_val.string) else null;
            },
        });

        return result.toOwnedSlice(allocator);
    }

    /// Send a text message via the sidecar's /send endpoint.
    pub fn sendMessage(self: *WhatsAppWebChannel, recipient: []const u8, text: []const u8) !void {
        if (builtin.is_test) return;

        // Build URL
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/send", .{self.sidecar_url});
        const url = url_fbs.getWritten();

        // Build JSON body
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const w = body_list.writer(self.allocator);
        try w.writeAll("{\"to\":");
        try root.appendJsonStringW(w, recipient);
        try w.writeAll(",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}");
        const body = body_list.items;

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{self.auth_token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.WhatsAppWebSidecarError;

        if (result.status != .ok) {
            return error.WhatsAppWebSidecarError;
        }
    }

    /// Send a message with media attachments via the sidecar's /send endpoint.
    /// The sidecar accepts {to, text, media: ["/abs/path", ...]}.
    pub fn sendMessageWithMedia(self: *WhatsAppWebChannel, recipient: []const u8, text: []const u8, media_paths: []const []const u8) !void {
        if (builtin.is_test) return;

        // Build URL
        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        try url_fbs.writer().print("{s}/send", .{self.sidecar_url});
        const url = url_fbs.getWritten();

        // Build JSON body
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        const w = body_list.writer(self.allocator);
        try w.writeAll("{\"to\":");
        try root.appendJsonStringW(w, recipient);
        try w.writeAll(",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll(",\"media\":[");
        for (media_paths, 0..) |mp, idx| {
            if (idx > 0) try w.writeAll(",");
            try root.appendJsonStringW(w, mp);
        }
        try w.writeAll("]}");
        const body = body_list.items;

        // Build auth header
        var auth_buf: [512]u8 = undefined;
        var auth_fbs = std.io.fixedBufferStream(&auth_buf);
        try auth_fbs.writer().print("Bearer {s}", .{self.auth_token});
        const auth_value = auth_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Authorization", .value = auth_value },
            },
        }) catch return error.WhatsAppWebSidecarError;

        if (result.status != .ok) {
            return error.WhatsAppWebSidecarError;
        }
    }

    pub fn healthCheck(self: *WhatsAppWebChannel) bool {
        if (builtin.is_test) return true;

        var url_buf: [256]u8 = undefined;
        var url_fbs = std.io.fixedBufferStream(&url_buf);
        url_fbs.writer().print("{s}/health", .{self.sidecar_url}) catch return false;
        const url = url_fbs.getWritten();

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
        }) catch return false;

        return result.status == .ok;
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        _ = ptr;
        // Webhook-based; sidecar manages the WhatsApp Web connection.
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
    }

    const MAX_MESSAGE_LEN: usize = 4000;

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));

        // Parse attachment markers ([IMAGE:], [FILE:], [DOCUMENT:])
        if (outbound.has_legacy_attachment_markers(message)) {
            var parsed = parseAttachmentMarkers(self.allocator, message) catch {
                // Fallback: send as plain text
                return self.sendPlainChunked(target, message);
            };
            defer parsed.deinit(self.allocator);

            const clean_text = std.mem.trim(u8, parsed.text, " \t\n");
            if (parsed.media.len > 0) {
                const formatted = markdownToWhatsApp(self.allocator, clean_text) catch clean_text;
                defer if (formatted.ptr != clean_text.ptr) self.allocator.free(formatted);
                try self.sendMessageWithMedia(target, formatted, parsed.media);
            } else {
                return self.sendPlainChunked(target, message);
            }
            return;
        }

        return self.sendPlainChunked(target, message);
    }

    fn sendPlainChunked(self: *WhatsAppWebChannel, target: []const u8, message: []const u8) !void {
        var it = root.splitMessage(message, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            const formatted = markdownToWhatsApp(self.allocator, chunk) catch chunk;
            defer if (formatted.ptr != chunk.ptr) self.allocator.free(formatted);
            try self.sendMessage(target, formatted);
        }
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WhatsAppWebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

pub const ParsedMessage = struct {
    sender: []const u8,
    content: []const u8,
    timestamp: u64,
    reply_to: ?[]const u8 = null,
    is_group: bool = false,
    group_id: ?[]const u8 = null,

    pub fn deinit(self: *ParsedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.content);
        if (self.reply_to) |rt| allocator.free(rt);
        if (self.group_id) |gid| allocator.free(gid);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Attachment marker parsing
// ════════════════════════════════════════════════════════════════════════════

const marker_prefixes = [_][]const u8{
    "[IMAGE:",
    "[image:",
    "[PHOTO:",
    "[photo:",
    "[FILE:",
    "[file:",
    "[DOCUMENT:",
    "[document:",
    "[VIDEO:",
    "[video:",
    "[AUDIO:",
    "[audio:",
    "[VOICE:",
    "[voice:",
};

const ParsedAttachments = struct {
    text: []const u8,
    media: []const []const u8,

    fn deinit(self: *ParsedAttachments, allocator: std.mem.Allocator) void {
        if (self.media.len > 0) {
            for (self.media) |p| allocator.free(p);
            allocator.free(self.media);
        }
        if (self.text.len > 0) allocator.free(self.text);
    }
};

/// Parse [IMAGE:/path], [FILE:/path], etc. markers from message text.
/// Returns clean text (markers removed) and extracted file paths.
fn parseAttachmentMarkers(allocator: std.mem.Allocator, text: []const u8) !ParsedAttachments {
    var media_paths: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (media_paths.items) |p| allocator.free(p);
        media_paths.deinit(allocator);
    }
    var clean: std.ArrayListUnmanaged(u8) = .empty;
    errdefer clean.deinit(allocator);

    var pos: usize = 0;
    while (pos < text.len) {
        if (std.mem.indexOfScalar(u8, text[pos..], '[')) |bracket_offset| {
            const bracket_pos = pos + bracket_offset;
            var matched = false;
            for (marker_prefixes) |prefix| {
                if (bracket_pos + prefix.len <= text.len and
                    std.mem.eql(u8, text[bracket_pos .. bracket_pos + prefix.len], prefix))
                {
                    if (bracket_pos > pos) {
                        try clean.appendSlice(allocator, text[pos..bracket_pos]);
                    }
                    const path_start = bracket_pos + prefix.len;
                    if (std.mem.indexOfScalar(u8, text[path_start..], ']')) |close_offset| {
                        const path = std.mem.trim(u8, text[path_start .. path_start + close_offset], " \t");
                        if (path.len > 0) {
                            try media_paths.append(allocator, try allocator.dupe(u8, path));
                        }
                        pos = path_start + close_offset + 1;
                    } else {
                        try clean.appendSlice(allocator, text[bracket_pos .. bracket_pos + prefix.len]);
                        pos = bracket_pos + prefix.len;
                    }
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                if (bracket_pos > pos) {
                    try clean.appendSlice(allocator, text[pos..bracket_pos]);
                }
                try clean.append(allocator, '[');
                pos = bracket_pos + 1;
            }
        } else {
            try clean.appendSlice(allocator, text[pos..]);
            break;
        }
    }

    return .{
        .text = try clean.toOwnedSlice(allocator),
        .media = try media_paths.toOwnedSlice(allocator),
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Markdown → WhatsApp formatting
// ════════════════════════════════════════════════════════════════════════════

/// Convert standard Markdown to WhatsApp-native formatting.
///
/// WhatsApp uses: *bold*, _italic_, ~strikethrough~, ```monospace```.
/// Links [text](url) become "text (url)" since WhatsApp auto-links URLs.
pub fn markdownToWhatsApp(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    var line_start = true;

    while (i < input.len) {
        // ── Fenced code blocks (```) — preserve as-is ──
        if (i + 3 <= input.len and std.mem.eql(u8, input[i..][0..3], "```")) {
            // Skip optional language tag on opening fence
            const fence_start = i;
            i += 3;
            if (line_start or fence_start == 0 or (fence_start > 0 and input[fence_start - 1] == '\n')) {
                // Opening fence — skip language tag
                while (i < input.len and input[i] != '\n') : (i += 1) {}
            }
            try result.appendSlice(allocator, "```");
            // Copy everything until closing ```
            while (i < input.len) {
                if (i + 3 <= input.len and std.mem.eql(u8, input[i..][0..3], "```")) {
                    try result.appendSlice(allocator, "```");
                    i += 3;
                    break;
                }
                try result.append(allocator, input[i]);
                i += 1;
            }
            line_start = false;
            continue;
        }

        // ── Headers at start of line: "# text" → "*text*" ──
        if (line_start and i < input.len and input[i] == '#') {
            var hi = i;
            while (hi < input.len and input[hi] == '#') : (hi += 1) {}
            if (hi < input.len and input[hi] == ' ') {
                hi += 1;
                var end = hi;
                while (end < input.len and input[end] != '\n') : (end += 1) {}
                try result.append(allocator, '*');
                try result.appendSlice(allocator, input[hi..end]);
                try result.append(allocator, '*');
                i = end;
                line_start = false;
                continue;
            }
        }

        // ── Bullet points: "- " → "• " ──
        if (line_start and i + 1 < input.len and input[i] == '-' and input[i + 1] == ' ') {
            try result.appendSlice(allocator, "\xe2\x80\xa2 ");
            i += 2;
            line_start = false;
            continue;
        }

        // ── Bold: **text** → *text* ──
        if (i + 2 <= input.len and std.mem.eql(u8, input[i..][0..2], "**")) {
            const start = i + 2;
            if (std.mem.indexOf(u8, input[start..], "**")) |close_offset| {
                try result.append(allocator, '*');
                try result.appendSlice(allocator, input[start .. start + close_offset]);
                try result.append(allocator, '*');
                i = start + close_offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Strikethrough: ~~text~~ → ~text~ ──
        if (i + 2 <= input.len and std.mem.eql(u8, input[i..][0..2], "~~")) {
            const start = i + 2;
            if (std.mem.indexOf(u8, input[start..], "~~")) |close_offset| {
                try result.append(allocator, '~');
                try result.appendSlice(allocator, input[start .. start + close_offset]);
                try result.append(allocator, '~');
                i = start + close_offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Inline code: `code` — preserved as-is ──
        if (input[i] == '`') {
            try result.append(allocator, '`');
            i += 1;
            while (i < input.len and input[i] != '`') {
                try result.append(allocator, input[i]);
                i += 1;
            }
            if (i < input.len) {
                try result.append(allocator, '`');
                i += 1;
            }
            line_start = false;
            continue;
        }

        // ── Links: [text](url) → "text (url)" ──
        if (input[i] == '[') {
            const text_start = i + 1;
            if (std.mem.indexOfScalar(u8, input[text_start..], ']')) |close_bracket| {
                const text_end = text_start + close_bracket;
                const after = text_end + 1;
                if (after < input.len and input[after] == '(') {
                    const url_start = after + 1;
                    if (std.mem.indexOfScalar(u8, input[url_start..], ')')) |close_paren| {
                        const url_end = url_start + close_paren;
                        const link_text = input[text_start..text_end];
                        const link_url = input[url_start..url_end];
                        // If text equals URL, just show URL once
                        if (std.mem.eql(u8, link_text, link_url)) {
                            try result.appendSlice(allocator, link_url);
                        } else {
                            try result.appendSlice(allocator, link_text);
                            try result.appendSlice(allocator, " (");
                            try result.appendSlice(allocator, link_url);
                            try result.append(allocator, ')');
                        }
                        i = url_end + 1;
                        line_start = false;
                        continue;
                    }
                }
            }
        }

        // ── Newlines ──
        if (input[i] == '\n') {
            try result.append(allocator, '\n');
            i += 1;
            line_start = true;
            continue;
        }

        // ── Default: copy character ──
        try result.append(allocator, input[i]);
        i += 1;
        line_start = false;
    }

    return result.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "whatsapp_web channel name" {
    var ch = WhatsAppWebChannel.init(std.testing.allocator, "http://127.0.0.1:7100", "tok", &.{}, &.{}, "allowlist");
    try std.testing.expectEqualStrings("whatsapp_web", ch.channelName());
}

test "whatsapp_web normalize phone" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("+1234567890", WhatsAppWebChannel.normalizePhone(&buf, "1234567890"));
    try std.testing.expectEqualStrings("+1234567890", WhatsAppWebChannel.normalizePhone(&buf, "+1234567890"));
}

test "whatsapp_web normalize phone empty" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("", WhatsAppWebChannel.normalizePhone(&buf, ""));
}

test "whatsapp_web normalize phone buffer too small" {
    var buf: [2]u8 = undefined;
    try std.testing.expectEqualStrings("123", WhatsAppWebChannel.normalizePhone(&buf, "123"));
}

test "whatsapp_web parse empty payload" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");
    const msgs = try ch.parseWebhookPayload(allocator, "{}");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse valid message" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+1234567890","text":"Hello!","timestamp":"1699999999","is_group":false,"reply_to":"1234567890@s.whatsapp.net"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
    try std.testing.expectEqualStrings("Hello!", msgs[0].content);
    try std.testing.expectEqual(@as(u64, 1_699_999_999), msgs[0].timestamp);
    try std.testing.expectEqualStrings("1234567890@s.whatsapp.net", msgs[0].reply_to.?);
    try std.testing.expect(!msgs[0].is_group);
}

test "whatsapp_web parse unauthorized number filtered" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+9999999999","text":"Spam","timestamp":"1","is_group":false}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse group open allows all" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "open");

    const payload =
        \\{"from":"+9999999999","text":"Group hello","timestamp":"1","is_group":true,"group_id":"120363@g.us","reply_to":"120363@g.us"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("Group hello", msgs[0].content);
    try std.testing.expect(msgs[0].is_group);
    try std.testing.expectEqualStrings("120363@g.us", msgs[0].group_id.?);
}

test "whatsapp_web parse group disabled blocks" {
    const allocator = std.testing.allocator;
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &.{}, &.{}, "disabled");

    const payload =
        \\{"from":"+111","text":"Blocked","timestamp":"1","is_group":true,"group_id":"g1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse group allowlist fallback" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1111111111"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+1111111111","text":"Allowed in group","timestamp":"1","is_group":true,"group_id":"g1","reply_to":"g1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
}

test "whatsapp_web parse group allowlist empty blocks" {
    const allocator = std.testing.allocator;
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &.{}, &.{}, "allowlist");

    const payload =
        \\{"from":"+111","text":"Blocked","timestamp":"1","is_group":true,"group_id":"g1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse empty text skipped" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+111","text":"","timestamp":"1","is_group":false}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse missing text field" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+111","timestamp":"1","is_group":false}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse missing from field" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"text":"hello","timestamp":"1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse invalid json returns empty" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const msgs = try ch.parseWebhookPayload(allocator, "not json");
    defer allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "whatsapp_web parse missing timestamp uses current" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+111","text":"Hello"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].timestamp > 0);
}

test "whatsapp_web parse unicode preserved" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+111","text":"Hallo wereld \u00f0\u009f\u0091\u008b","timestamp":"1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
}

test "whatsapp_web parse wildcard allows all" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"*"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"+999","text":"Anyone","timestamp":"1","is_group":false}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
}

test "whatsapp_web parse normalizes phone without plus" {
    const allocator = std.testing.allocator;
    const nums = [_][]const u8{"+1234567890"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");

    const payload =
        \\{"from":"1234567890","text":"Hi","timestamp":"1"}
    ;

    const msgs = try ch.parseWebhookPayload(allocator, payload);
    defer {
        for (msgs) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("+1234567890", msgs[0].sender);
}

test "whatsapp_web number allowed multiple" {
    const nums = [_][]const u8{ "+111", "+222", "+333" };
    const ch = WhatsAppWebChannel.init(std.testing.allocator, "http://127.0.0.1:7100", "tok", &nums, &.{}, "allowlist");
    try std.testing.expect(ch.isNumberAllowed("+111"));
    try std.testing.expect(ch.isNumberAllowed("+222"));
    try std.testing.expect(ch.isNumberAllowed("+333"));
    try std.testing.expect(!ch.isNumberAllowed("+444"));
}

test "whatsapp_web vtable wiring" {
    var ch = WhatsAppWebChannel.init(std.testing.allocator, "http://127.0.0.1:7100", "tok", &.{}, &.{}, "allowlist");
    const iface = ch.channel();
    try std.testing.expectEqualStrings("whatsapp_web", iface.name());
    try std.testing.expect(iface.healthCheck());
}

test "whatsapp_web parse group with specific group_allow_from" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"+111"};
    const group_allow = [_][]const u8{"+222"};
    const ch = WhatsAppWebChannel.init(allocator, "http://127.0.0.1:7100", "tok", &allow, &group_allow, "allowlist");

    // +222 allowed in group (via group_allow_from)
    const payload1 =
        \\{"from":"+222","text":"OK","timestamp":"1","is_group":true,"group_id":"g1"}
    ;
    const msgs1 = try ch.parseWebhookPayload(allocator, payload1);
    defer {
        for (msgs1) |*m| {
            var mm = m.*;
            mm.deinit(allocator);
        }
        allocator.free(msgs1);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs1.len);

    // +111 NOT allowed in group (not in group_allow_from)
    const payload2 =
        \\{"from":"+111","text":"Nope","timestamp":"1","is_group":true,"group_id":"g1"}
    ;
    const msgs2 = try ch.parseWebhookPayload(allocator, payload2);
    defer allocator.free(msgs2);
    try std.testing.expectEqual(@as(usize, 0), msgs2.len);
}

// ── markdownToWhatsApp tests ────────────────────────────────────────────

test "markdownToWhatsApp bold converts double to single asterisk" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "This is **bold** text");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This is *bold* text", result);
}

test "markdownToWhatsApp strikethrough converts double to single tilde" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "This is ~~deleted~~ text");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This is ~deleted~ text", result);
}

test "markdownToWhatsApp headers become bold" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "# Title\n## Subtitle");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("*Title*\n*Subtitle*", result);
}

test "markdownToWhatsApp bullet points" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "- First\n- Second");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\xe2\x80\xa2 First\n\xe2\x80\xa2 Second", result);
}

test "markdownToWhatsApp links become text with url" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "Check [Google](https://google.com) out");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Check Google (https://google.com) out", result);
}

test "markdownToWhatsApp link text equals url shows once" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "[https://example.com](https://example.com)");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("https://example.com", result);
}

test "markdownToWhatsApp inline code preserved" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "Use `npm install` here");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Use `npm install` here", result);
}

test "markdownToWhatsApp fenced code block preserved" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "```\nconst x = 1;\n```");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("```\nconst x = 1;\n```", result);
}

test "markdownToWhatsApp fenced code block strips language tag" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "```javascript\nconst x = 1;\n```");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("```\nconst x = 1;\n```", result);
}

test "markdownToWhatsApp plain text unchanged" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "Hello, how are you?");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, how are you?", result);
}

test "markdownToWhatsApp combined formatting" {
    const allocator = std.testing.allocator;
    const result = try markdownToWhatsApp(allocator, "# Hoi\n\n**Donna** hier. Bekijk [dit](https://x.com):\n- Punt 1\n- Punt 2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("*Hoi*\n\n*Donna* hier. Bekijk dit (https://x.com):\n\xe2\x80\xa2 Punt 1\n\xe2\x80\xa2 Punt 2", result);
}

// ── parseAttachmentMarkers tests ────────────────────────────────────────

test "whatsapp_web parseAttachmentMarkers extracts IMAGE marker" {
    const allocator = std.testing.allocator;
    var parsed = try parseAttachmentMarkers(allocator, "Check [IMAGE:/tmp/photo.png] this");
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("Check  this", parsed.text);
    try std.testing.expectEqual(@as(usize, 1), parsed.media.len);
    try std.testing.expectEqualStrings("/tmp/photo.png", parsed.media[0]);
}

test "whatsapp_web parseAttachmentMarkers handles multiple markers" {
    const allocator = std.testing.allocator;
    var parsed = try parseAttachmentMarkers(allocator, "[IMAGE:a.png] text [DOCUMENT:b.pdf]");
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings(" text ", parsed.text);
    try std.testing.expectEqual(@as(usize, 2), parsed.media.len);
    try std.testing.expectEqualStrings("a.png", parsed.media[0]);
    try std.testing.expectEqualStrings("b.pdf", parsed.media[1]);
}

test "whatsapp_web parseAttachmentMarkers no markers returns full text" {
    const allocator = std.testing.allocator;
    var parsed = try parseAttachmentMarkers(allocator, "Just plain text");
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("Just plain text", parsed.text);
    try std.testing.expectEqual(@as(usize, 0), parsed.media.len);
}

test "whatsapp_web parseAttachmentMarkers case insensitive" {
    const allocator = std.testing.allocator;
    var parsed = try parseAttachmentMarkers(allocator, "See [image:/tmp/x.png]");
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed.media.len);
    try std.testing.expectEqualStrings("/tmp/x.png", parsed.media[0]);
}

test "whatsapp_web parseAttachmentMarkers preserves non-marker brackets" {
    const allocator = std.testing.allocator;
    var parsed = try parseAttachmentMarkers(allocator, "hello [world] there");
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("hello [world] there", parsed.text);
    try std.testing.expectEqual(@as(usize, 0), parsed.media.len);
}

test "whatsapp_web vtableSend with attachment marker uses test path" {
    var ch = WhatsAppWebChannel.init(std.testing.allocator, "http://127.0.0.1:7100", "tok", &.{}, &.{}, "allowlist");
    // In test mode sendMessage/sendMessageWithMedia return immediately
    try ch.sendPlainChunked("123", "Hello [IMAGE:/tmp/test.png] world");
}
