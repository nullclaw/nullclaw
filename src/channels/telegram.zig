const std = @import("std");
const root = @import("root.zig");
const voice = @import("../voice.zig");
const platform = @import("../platform.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.telegram);

// ════════════════════════════════════════════════════════════════════════════
// Attachment Types
// ════════════════════════════════════════════════════════════════════════════

pub const AttachmentKind = enum {
    image,
    document,
    video,
    audio,
    voice,

    /// Return the Telegram API method name for this attachment kind.
    pub fn apiMethod(self: AttachmentKind) []const u8 {
        return switch (self) {
            .image => "sendPhoto",
            .document => "sendDocument",
            .video => "sendVideo",
            .audio => "sendAudio",
            .voice => "sendVoice",
        };
    }

    /// Return the multipart form field name for this attachment kind.
    pub fn formField(self: AttachmentKind) []const u8 {
        return switch (self) {
            .image => "photo",
            .document => "document",
            .video => "video",
            .audio => "audio",
            .voice => "voice",
        };
    }
};

pub const Attachment = struct {
    kind: AttachmentKind,
    target: []const u8, // path or URL
    caption: ?[]const u8 = null,
};

pub const ParsedMessage = struct {
    attachments: []Attachment,
    remaining_text: []const u8,

    pub fn deinit(self: *const ParsedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.attachments);
        allocator.free(self.remaining_text);
    }
};

/// Infer attachment kind from file extension.
pub fn inferAttachmentKindFromExtension(path: []const u8) AttachmentKind {
    // Strip query string and fragment
    const without_query = if (std.mem.indexOf(u8, path, "?")) |i| path[0..i] else path;
    const without_fragment = if (std.mem.indexOf(u8, without_query, "#")) |i| without_query[0..i] else without_query;

    // Find last '.' for extension
    const dot_pos = std.mem.lastIndexOf(u8, without_fragment, ".") orelse return .document;
    const ext = without_fragment[dot_pos + 1 ..];

    // Compare lowercase
    if (eqlLower(ext, "png") or eqlLower(ext, "jpg") or eqlLower(ext, "jpeg") or
        eqlLower(ext, "gif") or eqlLower(ext, "webp") or eqlLower(ext, "bmp"))
        return .image;

    if (eqlLower(ext, "mp4") or eqlLower(ext, "mov") or eqlLower(ext, "avi") or
        eqlLower(ext, "mkv") or eqlLower(ext, "webm"))
        return .video;

    if (eqlLower(ext, "mp3") or eqlLower(ext, "m4a") or eqlLower(ext, "wav") or
        eqlLower(ext, "flac"))
        return .audio;

    if (eqlLower(ext, "ogg") or eqlLower(ext, "oga") or eqlLower(ext, "opus"))
        return .voice;

    if (eqlLower(ext, "pdf") or eqlLower(ext, "doc") or eqlLower(ext, "docx") or
        eqlLower(ext, "txt") or eqlLower(ext, "md") or eqlLower(ext, "csv") or
        eqlLower(ext, "json") or eqlLower(ext, "zip") or eqlLower(ext, "tar") or
        eqlLower(ext, "gz") or eqlLower(ext, "xls") or eqlLower(ext, "xlsx") or
        eqlLower(ext, "ppt") or eqlLower(ext, "pptx"))
        return .document;

    return .document;
}

fn eqlLower(a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != bc) return false;
    }
    return true;
}

/// Parse attachment markers from LLM response text.
/// Scans for [IMAGE:...], [DOCUMENT:...], [VIDEO:...], [AUDIO:...], [VOICE:...] markers.
/// Returns extracted attachments and the remaining text with markers removed.
pub fn parseAttachmentMarkers(allocator: std.mem.Allocator, text: []const u8) !ParsedMessage {
    var attachments: std.ArrayListUnmanaged(Attachment) = .empty;
    errdefer attachments.deinit(allocator);

    var remaining: std.ArrayListUnmanaged(u8) = .empty;
    errdefer remaining.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < text.len) {
        // Find next '['
        const open_pos = std.mem.indexOfPos(u8, text, cursor, "[") orelse {
            try remaining.appendSlice(allocator, text[cursor..]);
            break;
        };

        // Append text before the bracket
        try remaining.appendSlice(allocator, text[cursor..open_pos]);

        // Find matching ']'
        const close_pos = std.mem.indexOfPos(u8, text, open_pos, "]") orelse {
            try remaining.appendSlice(allocator, text[open_pos..]);
            break;
        };

        const marker = text[open_pos + 1 .. close_pos];

        // Try to parse as KIND:target
        if (std.mem.indexOf(u8, marker, ":")) |colon_pos| {
            const kind_str = marker[0..colon_pos];
            const target_raw = marker[colon_pos + 1 ..];
            const target = std.mem.trim(u8, target_raw, " ");

            if (target.len > 0) {
                if (parseMarkerKind(kind_str)) |kind| {
                    try attachments.append(allocator, .{
                        .kind = kind,
                        .target = target,
                    });
                    cursor = close_pos + 1;
                    continue;
                }
            }
        }

        // Not a valid marker — keep original text including brackets
        try remaining.appendSlice(allocator, text[open_pos .. close_pos + 1]);
        cursor = close_pos + 1;
    }

    // Trim whitespace from remaining text
    const trimmed = std.mem.trim(u8, remaining.items, " \t\n\r");
    const remaining_owned = try allocator.dupe(u8, trimmed);
    remaining.deinit(allocator);

    return .{
        .attachments = try attachments.toOwnedSlice(allocator),
        .remaining_text = remaining_owned,
    };
}

fn parseMarkerKind(kind_str: []const u8) ?AttachmentKind {
    if (eqlLower(kind_str, "image") or eqlLower(kind_str, "photo")) return .image;
    if (eqlLower(kind_str, "document") or eqlLower(kind_str, "file")) return .document;
    if (eqlLower(kind_str, "video")) return .video;
    if (eqlLower(kind_str, "audio")) return .audio;
    if (eqlLower(kind_str, "voice")) return .voice;
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Smart Message Splitting
// ════════════════════════════════════════════════════════════════════════════

/// Split a message into chunks respecting the max byte limit.
/// Prefers splitting at word boundaries (newline, then space) over mid-word.
pub fn smartSplitMessage(msg: []const u8, max_bytes: usize) SmartSplitIterator {
    return .{ .remaining = msg, .max = max_bytes };
}

pub const SmartSplitIterator = struct {
    remaining: []const u8,
    max: usize,

    pub fn next(self: *SmartSplitIterator) ?[]const u8 {
        if (self.remaining.len == 0) return null;
        if (self.remaining.len <= self.max) {
            const chunk = self.remaining;
            self.remaining = self.remaining[self.remaining.len..];
            return chunk;
        }

        const search_area = self.remaining[0..self.max];

        // Prefer splitting at newline in the second half
        const half = self.max / 2;
        var split_at: usize = self.max;

        // Search for last newline
        if (std.mem.lastIndexOf(u8, search_area, "\n")) |nl_pos| {
            if (nl_pos >= half) {
                split_at = nl_pos + 1;
            } else {
                // Newline too early; try space instead
                if (std.mem.lastIndexOf(u8, search_area, " ")) |sp_pos| {
                    split_at = sp_pos + 1;
                }
            }
        } else if (std.mem.lastIndexOf(u8, search_area, " ")) |sp_pos| {
            split_at = sp_pos + 1;
        }

        const chunk = self.remaining[0..split_at];
        self.remaining = self.remaining[split_at..];
        return chunk;
    }
};

/// Telegram channel — uses the Bot API with long-polling (getUpdates).
/// Splits messages at 4096 chars (Telegram limit).
pub const TelegramChannel = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    account_id: []const u8 = "default",
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    group_policy: []const u8,
    reply_in_private: bool = true,
    transcriber: ?voice.Transcriber = null,
    last_update_id: i64,
    proxy: ?[]const u8,

    pub const MAX_MESSAGE_LEN: usize = 4096;

    pub fn init(
        allocator: std.mem.Allocator,
        bot_token: []const u8,
        allow_from: []const []const u8,
        group_allow_from: []const []const u8,
        group_policy: []const u8,
    ) TelegramChannel {
        return .{
            .allocator = allocator,
            .bot_token = bot_token,
            .allow_from = allow_from,
            .group_allow_from = group_allow_from,
            .group_policy = group_policy,
            .last_update_id = 0,
            .proxy = null,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.TelegramConfig) TelegramChannel {
        var ch = init(
            allocator,
            cfg.bot_token,
            cfg.allow_from,
            cfg.group_allow_from,
            cfg.group_policy,
        );
        ch.account_id = cfg.account_id;
        ch.reply_in_private = cfg.reply_in_private;
        ch.proxy = cfg.proxy;
        return ch;
    }

    pub fn channelName(_: *TelegramChannel) []const u8 {
        return "telegram";
    }

    /// Build the Telegram API URL for a method.
    pub fn apiUrl(self: *const TelegramChannel, buf: []u8, method: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("https://api.telegram.org/bot{s}/{s}", .{ self.bot_token, method });
        return fbs.getWritten();
    }

    /// Build a sendMessage JSON body.
    pub fn buildSendBody(
        buf: []u8,
        chat_id: []const u8,
        text: []const u8,
    ) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.print("{{\"chat_id\":{s},\"text\":\"{s}\"}}", .{ chat_id, text });
        return fbs.getWritten();
    }

    pub fn isUserAllowed(self: *const TelegramChannel, sender: []const u8) bool {
        for (self.allow_from) |a| {
            if (std.mem.eql(u8, a, "*")) return true;
            // Strip leading "@" from allowlist entry (PicoClaw compat)
            const trimmed = if (a.len > 1 and a[0] == '@') a[1..] else a;
            // Case-insensitive: Telegram usernames are case-insensitive
            if (std.ascii.eqlIgnoreCase(trimmed, sender)) return true;
        }
        return false;
    }

    /// Check if any of the given identities (username, user_id) is allowed.
    pub fn isAnyIdentityAllowed(self: *const TelegramChannel, identities: []const []const u8) bool {
        for (identities) |id| {
            if (self.isUserAllowed(id)) return true;
        }
        return false;
    }

    pub fn isGroupUserAllowed(self: *const TelegramChannel, sender: []const u8) bool {
        for (self.group_allow_from) |a| {
            if (std.mem.eql(u8, a, "*")) return true;
            const trimmed = if (a.len > 1 and a[0] == '@') a[1..] else a;
            if (std.ascii.eqlIgnoreCase(trimmed, sender)) return true;
        }
        return false;
    }

    pub fn isAnyGroupIdentityAllowed(self: *const TelegramChannel, identities: []const []const u8) bool {
        for (identities) |id| {
            if (self.isGroupUserAllowed(id)) return true;
        }
        return false;
    }

    pub fn healthCheck(self: *TelegramChannel) bool {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "getMe") catch return false;
        const resp = root.http_util.curlPostWithProxy(self.allocator, url, "{}", &.{}, self.proxy, null) catch return false;
        defer self.allocator.free(resp);
        return std.mem.indexOf(u8, resp, "\"ok\":true") != null;
    }

    /// Register bot commands with Telegram so they appear in the "/" menu.
    pub fn setMyCommands(self: *TelegramChannel) void {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "setMyCommands") catch return;

        const body =
            \\{"commands":[
            \\{"command":"start","description":"Start a conversation"},
            \\{"command":"new","description":"Clear history, start fresh"},
            \\{"command":"help","description":"Show available commands"},
            \\{"command":"status","description":"Show model and stats"},
            \\{"command":"model","description":"Switch model"}
            \\]}
        ;

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, body, &.{}, self.proxy, null) catch |err| {
            log.warn("setMyCommands failed: {}", .{err});
            return;
        };
        self.allocator.free(resp);
    }

    /// Skip all pending updates accumulated while bot was offline.
    /// Fetches with offset=-1 to get only the latest update, then advances past it.
    pub fn dropPendingUpdates(self: *TelegramChannel) void {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "getUpdates") catch return;

        const body = "{\"offset\":-1,\"timeout\":0}";
        const resp_body = root.http_util.curlPostWithProxy(self.allocator, url, body, &.{}, self.proxy, null) catch return;
        defer self.allocator.free(resp_body);

        // Parse to extract the latest update_id and advance past it
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        const result_val = parsed.value.object.get("result") orelse return;
        if (result_val != .array) return;
        const result_array = result_val.array.items;
        for (result_array) |update| {
            if (update != .object) continue;
            if (update.object.get("update_id")) |uid| {
                if (uid == .integer) {
                    self.last_update_id = uid.integer + 1;
                }
            }
        }
    }

    // ── Typing indicator ────────────────────────────────────────────

    /// Send a "typing" chat action. Best-effort: errors are ignored.
    pub fn sendTypingIndicator(self: *TelegramChannel, chat_id: []const u8) void {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "sendChatAction") catch return;

        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        body_list.appendSlice(self.allocator, "{\"chat_id\":") catch return;
        body_list.appendSlice(self.allocator, chat_id) catch return;
        body_list.appendSlice(self.allocator, ",\"action\":\"typing\"}") catch return;

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, null) catch return;
        self.allocator.free(resp);
    }

    // ── HTML fallback ────────────────────────────────────────────────

    /// Send text with HTML parse_mode (converted from Markdown); on failure, retry as plain text.
    fn sendWithMarkdownFallback(self: *TelegramChannel, chat_id: []const u8, text: []const u8, reply_to: ?i64) !void {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "sendMessage");

        // Convert Markdown → Telegram HTML
        const html_text = markdownToTelegramHtml(self.allocator, text) catch {
            // Conversion failed — send as plain text
            try self.sendChunkPlain(chat_id, text, reply_to);
            return;
        };
        defer self.allocator.free(html_text);

        // Build HTML body
        var html_body: std.ArrayListUnmanaged(u8) = .empty;
        defer html_body.deinit(self.allocator);

        try html_body.appendSlice(self.allocator, "{\"chat_id\":");
        try html_body.appendSlice(self.allocator, chat_id);
        try html_body.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&html_body, self.allocator, html_text);
        try html_body.appendSlice(self.allocator, ",\"parse_mode\":\"HTML\"");
        if (reply_to) |rid| {
            var rid_buf: [32]u8 = undefined;
            const rid_str = std.fmt.bufPrint(&rid_buf, "{d}", .{rid}) catch unreachable;
            try html_body.appendSlice(self.allocator, ",\"reply_parameters\":{\"message_id\":");
            try html_body.appendSlice(self.allocator, rid_str);
            try html_body.appendSlice(self.allocator, "}");
        }
        try html_body.appendSlice(self.allocator, "}");

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, html_body.items, &.{}, self.proxy, null) catch {
            // Network error — fall through to plain send
            try self.sendChunkPlain(chat_id, text, reply_to);
            return;
        };
        defer self.allocator.free(resp);

        // Check if response indicates error (contains "error_code")
        if (std.mem.indexOf(u8, resp, "\"error_code\"") != null) {
            // HTML failed, retry as plain text
            try self.sendChunkPlain(chat_id, text, reply_to);
            return;
        }
    }

    fn sendChunkPlain(self: *TelegramChannel, chat_id: []const u8, text: []const u8, reply_to: ?i64) !void {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "sendMessage");

        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"chat_id\":");
        try body_list.appendSlice(self.allocator, chat_id);
        try body_list.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        if (reply_to) |rid| {
            var rid_buf: [32]u8 = undefined;
            const rid_str = std.fmt.bufPrint(&rid_buf, "{d}", .{rid}) catch unreachable;
            try body_list.appendSlice(self.allocator, ",\"reply_parameters\":{\"message_id\":");
            try body_list.appendSlice(self.allocator, rid_str);
            try body_list.appendSlice(self.allocator, "}");
        }
        try body_list.appendSlice(self.allocator, "}");

        const resp = try root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, null);
        self.allocator.free(resp);
    }

    // ── Media sending ───────────────────────────────────────────────

    /// Send a photo via curl multipart form POST.
    pub fn sendPhoto(self: *TelegramChannel, chat_id: []const u8, allocator: std.mem.Allocator, photo_path: []const u8, caption: ?[]const u8) !void {
        try self.sendMediaMultipart(chat_id, allocator, .image, photo_path, caption);
    }

    /// Send a document via curl multipart form POST.
    pub fn sendDocument(self: *TelegramChannel, chat_id: []const u8, allocator: std.mem.Allocator, doc_path: []const u8, caption: ?[]const u8) !void {
        try self.sendMediaMultipart(chat_id, allocator, .document, doc_path, caption);
    }

    /// Send any media type via curl multipart form POST.
    fn sendMediaMultipart(
        self: *TelegramChannel,
        chat_id: []const u8,
        allocator: std.mem.Allocator,
        kind: AttachmentKind,
        file_path: []const u8,
        caption: ?[]const u8,
    ) !void {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, kind.apiMethod());

        // Build file form field: field=@path (local files) or field=URL (remote URLs)
        var file_arg_buf: [1024]u8 = undefined;
        var file_fbs = std.io.fixedBufferStream(&file_arg_buf);
        if (std.mem.startsWith(u8, file_path, "http://") or
            std.mem.startsWith(u8, file_path, "https://"))
        {
            try file_fbs.writer().print("{s}={s}", .{ kind.formField(), file_path });
        } else {
            try file_fbs.writer().print("{s}=@{s}", .{ kind.formField(), file_path });
        }
        const file_arg = file_fbs.getWritten();

        // Build chat_id form field
        var chatid_arg_buf: [128]u8 = undefined;
        var chatid_fbs = std.io.fixedBufferStream(&chatid_arg_buf);
        try chatid_fbs.writer().print("chat_id={s}", .{chat_id});
        const chatid_arg = chatid_fbs.getWritten();

        // Build argv
        var argv_buf: [16][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-s";
        argc += 1;
        argv_buf[argc] = "-F";
        argc += 1;
        argv_buf[argc] = chatid_arg;
        argc += 1;
        argv_buf[argc] = "-F";
        argc += 1;
        argv_buf[argc] = file_arg;
        argc += 1;

        // Optional caption
        var caption_arg_buf: [1024]u8 = undefined;
        if (caption) |cap| {
            var cap_fbs = std.io.fixedBufferStream(&caption_arg_buf);
            try cap_fbs.writer().print("caption={s}", .{cap});
            argv_buf[argc] = "-F";
            argc += 1;
            argv_buf[argc] = cap_fbs.getWritten();
            argc += 1;
        }

        argv_buf[argc] = url;
        argc += 1;

        var child = std.process.Child.init(argv_buf[0..argc], allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        try child.spawn();

        _ = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch return error.CurlReadError;
        const term = child.wait() catch return error.CurlWaitError;
        switch (term) {
            .Exited => |code| if (code != 0) return error.CurlFailed,
            else => return error.CurlFailed,
        }
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Telegram chat via the Bot API.
    /// Parses attachment markers, sends typing indicator, uses smart splitting
    /// with Markdown fallback.
    pub fn sendMessage(self: *TelegramChannel, chat_id: []const u8, text: []const u8) !void {
        return self.sendMessageWithReply(chat_id, text, null);
    }

    /// Send a message with optional reply-to, continuation markers, and delay between chunks.
    pub fn sendMessageWithReply(self: *TelegramChannel, chat_id: []const u8, text: []const u8, reply_to: ?i64) !void {
        // Send typing indicator (best-effort)
        self.sendTypingIndicator(chat_id);

        // Parse attachment markers
        const parsed = try parseAttachmentMarkers(self.allocator, text);
        defer parsed.deinit(self.allocator);

        // Send remaining text (if any) with smart splitting
        if (parsed.remaining_text.len > 0) {
            // Use slightly smaller limit when text will split, to leave room for markers
            const needs_split = parsed.remaining_text.len > MAX_MESSAGE_LEN;
            const split_limit = if (needs_split) MAX_MESSAGE_LEN - 12 else MAX_MESSAGE_LEN;

            // Collect chunks
            var chunks: std.ArrayListUnmanaged([]const u8) = .empty;
            defer chunks.deinit(self.allocator);
            var it = smartSplitMessage(parsed.remaining_text, split_limit);
            while (it.next()) |chunk| {
                try chunks.append(self.allocator, chunk);
            }

            var current_reply_to = reply_to;
            for (chunks.items, 0..) |chunk, i| {
                if (chunks.items.len > 1 and i < chunks.items.len - 1) {
                    // Not the last chunk — append ⏬ to signal continuation
                    var annotated: std.ArrayListUnmanaged(u8) = .empty;
                    defer annotated.deinit(self.allocator);

                    try annotated.appendSlice(self.allocator, chunk);
                    try annotated.appendSlice(self.allocator, "\n\n\u{23EC}"); // ⏬

                    try self.sendWithMarkdownFallback(chat_id, annotated.items, current_reply_to);
                } else {
                    try self.sendWithMarkdownFallback(chat_id, chunk, current_reply_to);
                }

                // Only reply-to the first chunk
                current_reply_to = null;

                // 100ms delay between chunks to avoid rate-limit / ordering issues
                if (i < chunks.items.len - 1) {
                    std.Thread.sleep(100 * std.time.ns_per_ms);
                }
            }
        }

        // Send attachments
        for (parsed.attachments) |att| {
            self.sendMediaMultipart(chat_id, self.allocator, att.kind, att.target, att.caption) catch |err| {
                log.err("sendMediaMultipart failed: {}", .{err});
                continue;
            };
        }
    }

    fn sendChunk(self: *TelegramChannel, chat_id: []const u8, text: []const u8) !void {
        // Build URL
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "sendMessage");

        // Build JSON body with escaped text
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"chat_id\":");
        try body_list.appendSlice(self.allocator, chat_id);
        try body_list.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try body_list.appendSlice(self.allocator, "}");

        const resp = try root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, null);
        self.allocator.free(resp);
    }

    /// Poll for updates using long-polling (getUpdates) via curl.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    /// Voice and audio messages are automatically transcribed via Groq Whisper
    /// when a Groq API key is configured (config or GROQ_API_KEY env var).
    pub fn pollUpdates(self: *TelegramChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "getUpdates");

        // Build body with offset and timeout
        var body_buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        try fbs.writer().print("{{\"offset\":{d},\"timeout\":30,\"allowed_updates\":[\"message\"]}}", .{self.last_update_id});
        const body = fbs.getWritten();

        const resp_body = try root.http_util.curlPostWithProxy(allocator, url, body, &.{}, self.proxy, null);
        defer allocator.free(resp_body);

        // Parse JSON response to extract messages
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return &.{};
        defer parsed.deinit();
        if (parsed.value != .object) return &.{};

        const result_val = parsed.value.object.get("result") orelse return &.{};
        if (result_val != .array) return &.{};
        const result_array = result_val.array.items;

        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer messages.deinit(allocator);

        for (result_array) |update| {
            if (update != .object) continue;
            // Advance offset
            if (update.object.get("update_id")) |uid| {
                if (uid == .integer) {
                    self.last_update_id = uid.integer + 1;
                }
            }

            const message = update.object.get("message") orelse continue;
            if (message != .object) continue;

            // Get sender info — check both @username and numeric user_id
            const from_obj = message.object.get("from") orelse continue;
            if (from_obj != .object) continue;
            const username_val = from_obj.object.get("username");
            const username = if (username_val) |uv| (if (uv == .string) uv.string else "unknown") else "unknown";

            var user_id_buf: [32]u8 = undefined;
            const user_id: ?[]const u8 = blk_uid: {
                const id_val = from_obj.object.get("id") orelse break :blk_uid null;
                if (id_val != .integer) break :blk_uid null;
                break :blk_uid std.fmt.bufPrint(&user_id_buf, "{d}", .{id_val.integer}) catch null;
            };

            // Get chat_id and chat type
            const chat_obj = message.object.get("chat") orelse continue;
            if (chat_obj != .object) continue;
            const chat_id_val = chat_obj.object.get("id") orelse continue;
            var chat_id_buf: [32]u8 = undefined;
            const chat_id_str = blk: {
                if (chat_id_val == .integer) {
                    break :blk std.fmt.bufPrint(&chat_id_buf, "{d}", .{chat_id_val.integer}) catch continue;
                }
                continue;
            };
            const chat_type_val = chat_obj.object.get("type");
            const is_group = if (chat_type_val) |tv|
                (if (tv == .string) (!std.mem.eql(u8, tv.string, "private")) else false)
            else
                false;

            // Check allowlist against all known identities
            var ids_buf: [2][]const u8 = undefined;
            var ids_len: usize = 0;
            ids_buf[ids_len] = username;
            ids_len += 1;
            if (user_id) |uid| {
                ids_buf[ids_len] = uid;
                ids_len += 1;
            }

            const is_authorized = if (is_group) blk: {
                if (std.mem.eql(u8, self.group_policy, "open")) break :blk true;
                if (std.mem.eql(u8, self.group_policy, "disabled")) break :blk false;

                // Allowlist context: check group_allow_from for sender, fall back to allow_from
                if (self.group_allow_from.len > 0) {
                    break :blk self.isAnyGroupIdentityAllowed(ids_buf[0..ids_len]);
                } else {
                    break :blk self.isAnyIdentityAllowed(ids_buf[0..ids_len]);
                }
            } else self.isAnyIdentityAllowed(ids_buf[0..ids_len]);

            if (!is_authorized) {
                log.warn("ignoring message from unauthorized user: username={s}, user_id={s}", .{
                    username,
                    user_id orelse "unknown",
                });
                continue;
            }

            // Use username as sender identity, fall back to numeric id
            const sender_identity = if (!std.mem.eql(u8, username, "unknown"))
                username
            else
                (user_id orelse "unknown");

            // Extract first_name
            const first_name_val = from_obj.object.get("first_name");
            const first_name: ?[]const u8 = if (first_name_val) |fnv| (if (fnv == .string) fnv.string else null) else null;

            // Extract message_id
            const msg_id_val = message.object.get("message_id");
            const msg_id: ?i64 = if (msg_id_val) |mv| (if (mv == .integer) mv.integer else null) else null;

            // Check for voice/audio messages and attempt transcription
            const content = blk_content: {
                const voice_obj = message.object.get("voice") orelse message.object.get("audio");
                if (voice_obj) |vobj| {
                    if (vobj != .object) break :blk_content null;
                    const file_id_val = vobj.object.get("file_id") orelse break :blk_content null;
                    const file_id = if (file_id_val == .string) file_id_val.string else break :blk_content null;

                    if (voice.transcribeTelegramVoice(allocator, self.bot_token, file_id, self.transcriber)) |transcribed| {
                        // Prepend [Voice]: prefix
                        var result: std.ArrayListUnmanaged(u8) = .empty;
                        result.appendSlice(allocator, "[Voice]: ") catch break :blk_content null;
                        result.appendSlice(allocator, transcribed) catch {
                            result.deinit(allocator);
                            break :blk_content null;
                        };
                        allocator.free(transcribed);
                        break :blk_content result.toOwnedSlice(allocator) catch null;
                    }
                    break :blk_content null;
                }

                // Check for photo messages — download and wrap as [IMAGE:] marker
                if (message.object.get("photo")) |photo_val| {
                    if (photo_val == .array and photo_val.array.items.len > 0) {
                        // Pick last element (highest resolution)
                        const last_photo = photo_val.array.items[photo_val.array.items.len - 1];
                        if (last_photo == .object) {
                            const fid_val = last_photo.object.get("file_id") orelse break :blk_content null;
                            const fid = if (fid_val == .string) fid_val.string else break :blk_content null;
                            if (downloadTelegramPhoto(allocator, self.bot_token, fid, self.proxy)) |local_path| {
                                var result: std.ArrayListUnmanaged(u8) = .empty;
                                result.appendSlice(allocator, "[IMAGE:") catch {
                                    allocator.free(local_path);
                                    break :blk_content null;
                                };
                                result.appendSlice(allocator, local_path) catch {
                                    allocator.free(local_path);
                                    result.deinit(allocator);
                                    break :blk_content null;
                                };
                                result.appendSlice(allocator, "]") catch {
                                    allocator.free(local_path);
                                    result.deinit(allocator);
                                    break :blk_content null;
                                };
                                allocator.free(local_path);
                                // Append caption if present
                                if (message.object.get("caption")) |cap_val| {
                                    if (cap_val == .string) {
                                        result.appendSlice(allocator, " ") catch {};
                                        result.appendSlice(allocator, cap_val.string) catch {};
                                    }
                                }
                                break :blk_content result.toOwnedSlice(allocator) catch null;
                            }
                        }
                    }
                }

                break :blk_content null;
            };

            // Fall back to text content if no voice/photo content
            const final_content = content orelse blk_text: {
                const text_val = message.object.get("text") orelse continue;
                const text_str = if (text_val == .string) text_val.string else continue;
                break :blk_text try allocator.dupe(u8, text_str);
            };

            try messages.append(allocator, .{
                .id = try allocator.dupe(u8, sender_identity),
                .sender = try allocator.dupe(u8, chat_id_str),
                .content = final_content,
                .channel = "telegram",
                .timestamp = root.nowEpochSecs(),
                .message_id = msg_id,
                .first_name = if (first_name) |fn_| try allocator.dupe(u8, fn_) else null,
                .is_group = is_group,
            });
        }

        return messages.toOwnedSlice(allocator);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        // Verify bot token by calling getMe
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "getMe") catch return;

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        _ = client.fetch(.{
            .location = .{ .url = url },
        }) catch return;
        // If getMe fails, we still start — healthCheck will report issues
    }

    fn vtableStop(ptr: *anyopaque) void {
        _ = ptr;
        // Nothing to clean up for HTTP polling
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *TelegramChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Markdown → Telegram HTML Conversion
// ════════════════════════════════════════════════════════════════════════════

/// Convert Markdown to Telegram-compatible HTML.
/// Handles: code blocks, inline code, bold, italic, strikethrough,
/// links, headers, bullet lists. Escapes HTML entities.
pub fn markdownToTelegramHtml(allocator: std.mem.Allocator, md: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    var i: usize = 0;
    var line_start = true;

    while (i < md.len) {
        // ── Code blocks ``` ... ``` ──
        if (i + 2 < md.len and md[i] == '`' and md[i + 1] == '`' and md[i + 2] == '`') {
            // Find closing ```
            const content_start = if (i + 3 < md.len and md[i + 3] == '\n') i + 4 else i + 3;
            // Skip language tag on same line
            const lang_end = std.mem.indexOfScalarPos(u8, md, i + 3, '\n') orelse md.len;
            const actual_start = if (lang_end < md.len) lang_end + 1 else content_start;

            const close = findTripleBacktick(md, actual_start);
            if (close) |end| {
                try buf.appendSlice(allocator, "<pre>");
                try appendHtmlEscaped(&buf, allocator, md[actual_start..end]);
                try buf.appendSlice(allocator, "</pre>");
                // Skip past closing ```
                i = end + 3;
                if (i < md.len and md[i] == '\n') i += 1;
                line_start = true;
                continue;
            }
        }

        // ── Inline code `...` ──
        if (md[i] == '`') {
            const close = std.mem.indexOfScalarPos(u8, md, i + 1, '`');
            if (close) |end| {
                try buf.appendSlice(allocator, "<code>");
                try appendHtmlEscaped(&buf, allocator, md[i + 1 .. end]);
                try buf.appendSlice(allocator, "</code>");
                i = end + 1;
                line_start = false;
                continue;
            }
        }

        // ── Headers at line start ──
        if (line_start and md[i] == '#') {
            var level: usize = 0;
            while (i + level < md.len and md[i + level] == '#') level += 1;
            if (level <= 6 and i + level < md.len and md[i + level] == ' ') {
                i += level + 1; // skip "# "
                const end = std.mem.indexOfScalarPos(u8, md, i, '\n') orelse md.len;
                try buf.appendSlice(allocator, "<b>");
                try appendHtmlEscaped(&buf, allocator, md[i..end]);
                try buf.appendSlice(allocator, "</b>");
                i = end;
                if (i < md.len) {
                    try buf.append(allocator, '\n');
                    i += 1;
                }
                line_start = true;
                continue;
            }
        }

        // ── Bullet lists at line start ──
        if (line_start and md[i] == '-' and i + 1 < md.len and md[i + 1] == ' ') {
            try buf.appendSlice(allocator, "\u{2022} "); // • bullet
            i += 2;
            line_start = false;
            continue;
        }

        // ── Strikethrough ~~text~~ ──
        if (i + 1 < md.len and md[i] == '~' and md[i + 1] == '~') {
            const close = std.mem.indexOf(u8, md[i + 2 ..], "~~");
            if (close) |offset| {
                try buf.appendSlice(allocator, "<s>");
                try appendHtmlEscaped(&buf, allocator, md[i + 2 .. i + 2 + offset]);
                try buf.appendSlice(allocator, "</s>");
                i = i + 2 + offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Bold **text** ──
        if (i + 1 < md.len and md[i] == '*' and md[i + 1] == '*') {
            const close = std.mem.indexOf(u8, md[i + 2 ..], "**");
            if (close) |offset| {
                try buf.appendSlice(allocator, "<b>");
                try appendHtmlEscaped(&buf, allocator, md[i + 2 .. i + 2 + offset]);
                try buf.appendSlice(allocator, "</b>");
                i = i + 2 + offset + 2;
                line_start = false;
                continue;
            }
        }

        // ── Links [text](url) ──
        if (md[i] == '[') {
            const close_bracket = std.mem.indexOfScalarPos(u8, md, i + 1, ']');
            if (close_bracket) |cb| {
                if (cb + 1 < md.len and md[cb + 1] == '(') {
                    const close_paren = std.mem.indexOfScalarPos(u8, md, cb + 2, ')');
                    if (close_paren) |cp| {
                        const text = md[i + 1 .. cb];
                        const href = md[cb + 2 .. cp];
                        try buf.appendSlice(allocator, "<a href=\"");
                        try appendHtmlEscaped(&buf, allocator, href);
                        try buf.appendSlice(allocator, "\">");
                        try appendHtmlEscaped(&buf, allocator, text);
                        try buf.appendSlice(allocator, "</a>");
                        i = cp + 1;
                        line_start = false;
                        continue;
                    }
                }
            }
        }

        // ── Italic _text_ (not __text__) ──
        if (md[i] == '_' and !(i + 1 < md.len and md[i + 1] == '_')) {
            // Don't match inside words (check prev char)
            const prev_ok = (i == 0 or md[i - 1] == ' ' or md[i - 1] == '\n' or md[i - 1] == '(');
            if (prev_ok) {
                const close = std.mem.indexOfScalarPos(u8, md, i + 1, '_');
                if (close) |end| {
                    // Check next char after closing _
                    const next_ok = (end + 1 >= md.len or md[end + 1] == ' ' or md[end + 1] == '\n' or md[end + 1] == ',' or md[end + 1] == '.' or md[end + 1] == ')');
                    if (next_ok and end > i + 1) {
                        try buf.appendSlice(allocator, "<i>");
                        try appendHtmlEscaped(&buf, allocator, md[i + 1 .. end]);
                        try buf.appendSlice(allocator, "</i>");
                        i = end + 1;
                        line_start = false;
                        continue;
                    }
                }
            }
        }

        // ── Regular character ──
        if (md[i] == '\n') {
            try buf.append(allocator, '\n');
            line_start = true;
        } else {
            switch (md[i]) {
                '&' => try buf.appendSlice(allocator, "&amp;"),
                '<' => try buf.appendSlice(allocator, "&lt;"),
                '>' => try buf.appendSlice(allocator, "&gt;"),
                else => try buf.append(allocator, md[i]),
            }
            line_start = false;
        }
        i += 1;
    }

    return buf.toOwnedSlice(allocator);
}

fn findTripleBacktick(md: []const u8, from: usize) ?usize {
    var pos = from;
    while (pos + 2 < md.len) {
        if (md[pos] == '`' and md[pos + 1] == '`' and md[pos + 2] == '`') return pos;
        pos += 1;
    }
    return null;
}

/// Escape HTML entities for Telegram HTML parse_mode.
fn appendHtmlEscaped(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '&' => try buf.appendSlice(allocator, "&amp;"),
            '<' => try buf.appendSlice(allocator, "&lt;"),
            '>' => try buf.appendSlice(allocator, "&gt;"),
            '"' => try buf.appendSlice(allocator, "&quot;"),
            else => try buf.append(allocator, c),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Periodic Typing Indicator
// ════════════════════════════════════════════════════════════════════════════

/// Periodic typing indicator — sends "typing" action every 4 seconds
/// until stopped. Telegram typing status expires after 5 seconds.
pub const TypingIndicator = struct {
    channel: *TelegramChannel,
    chat_id: [64]u8 = undefined,
    chat_id_len: usize = 0,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    /// How often to send the typing indicator (nanoseconds).
    const INTERVAL_NS: u64 = 4 * std.time.ns_per_s;

    pub fn init(ch: *TelegramChannel) TypingIndicator {
        return .{ .channel = ch };
    }

    /// Start the periodic typing indicator for a chat.
    pub fn start(self: *TypingIndicator, chat_id: []const u8) void {
        if (self.running.load(.acquire)) return; // already running
        if (chat_id.len > self.chat_id.len) return;

        @memcpy(self.chat_id[0..chat_id.len], chat_id);
        self.chat_id_len = chat_id.len;
        self.running.store(true, .release);

        self.thread = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, typingLoop, .{self}) catch null;
    }

    /// Stop the periodic typing indicator.
    pub fn stop(self: *TypingIndicator) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn typingLoop(self: *TypingIndicator) void {
        while (self.running.load(.acquire)) {
            self.channel.sendTypingIndicator(self.chat_id[0..self.chat_id_len]);
            // Sleep in small increments to check running flag responsively
            var elapsed: u64 = 0;
            while (elapsed < INTERVAL_NS and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                elapsed += 100 * std.time.ns_per_ms;
            }
        }
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Telegram Photo Download
// ════════════════════════════════════════════════════════════════════════════

/// Download a photo from Telegram by file_id. Returns the local temp file path (caller-owned).
/// Calls getFile API, then downloads the binary, saves to temp dir.
/// Uses the provided proxy settings for all HTTP requests.
fn downloadTelegramPhoto(allocator: std.mem.Allocator, bot_token: []const u8, file_id: []const u8, proxy: ?[]const u8) ?[]u8 {
    // 1. Call getFile to get file_path
    var url_buf: [512]u8 = undefined;
    var url_fbs = std.io.fixedBufferStream(&url_buf);
    url_fbs.writer().print("https://api.telegram.org/bot{s}/getFile", .{bot_token}) catch return null;
    const api_url = url_fbs.getWritten();

    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    defer body_list.deinit(allocator);
    body_list.appendSlice(allocator, "{\"file_id\":") catch return null;
    root.json_util.appendJsonString(&body_list, allocator, file_id) catch return null;
    body_list.appendSlice(allocator, "}") catch return null;

    const resp = root.http_util.curlPostWithProxy(allocator, api_url, body_list.items, &.{}, proxy, null) catch |err| {
        log.warn("downloadTelegramPhoto: getFile API failed: {}", .{err});
        return null;
    };
    defer allocator.free(resp);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch |err| {
        log.warn("downloadTelegramPhoto: JSON parse failed: {}", .{err});
        return null;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const result_obj = parsed.value.object.get("result") orelse {
        log.warn("downloadTelegramPhoto: no 'result' in response", .{});
        return null;
    };
    if (result_obj != .object) return null;
    const fp_val = result_obj.object.get("file_path") orelse {
        log.warn("downloadTelegramPhoto: no 'file_path' in result", .{});
        return null;
    };
    const tg_file_path = if (fp_val == .string) fp_val.string else return null;

    // 2. Download the file
    var dl_url_buf: [1024]u8 = undefined;
    var dl_fbs = std.io.fixedBufferStream(&dl_url_buf);
    dl_fbs.writer().print("https://api.telegram.org/file/bot{s}/{s}", .{ bot_token, tg_file_path }) catch return null;
    const dl_url = dl_fbs.getWritten();

    const data = root.http_util.curlGetWithProxy(allocator, dl_url, &.{}, "30", proxy) catch |err| {
        log.warn("downloadTelegramPhoto: file download failed: {}", .{err});
        return null;
    };
    defer allocator.free(data);

    // 3. Determine file extension from the Telegram file_path
    const ext = if (std.mem.lastIndexOfScalar(u8, tg_file_path, '.')) |dot|
        tg_file_path[dot..]
    else
        ".jpg";

    // 4. Save to temp file — use sanitized file_id as filename (no hash collisions)
    const tmp_dir = platform.getTempDir(allocator) catch return null;
    defer allocator.free(tmp_dir);
    var path_buf: [512]u8 = undefined;
    var path_fbs = std.io.fixedBufferStream(&path_buf);
    // Sanitize file_id for filesystem safety (replace / and \ with _)
    var name_buf: [256]u8 = undefined;
    const safe_len = @min(file_id.len, 200);
    @memcpy(name_buf[0..safe_len], file_id[0..safe_len]);
    for (name_buf[0..safe_len]) |*c| {
        if (c.* == '/' or c.* == '\\') c.* = '_';
    }
    path_fbs.writer().print("{s}/nullclaw_photo_{s}{s}", .{ tmp_dir, name_buf[0..safe_len], ext }) catch return null;
    const local_path = path_fbs.getWritten();

    // Write file
    const file = std.fs.createFileAbsolute(local_path, .{}) catch |err| {
        log.warn("downloadTelegramPhoto: file create failed: {}", .{err});
        return null;
    };
    defer file.close();
    file.writeAll(data) catch return null;

    return allocator.dupe(u8, local_path) catch null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram api url" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "getUpdates");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/getUpdates", url);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Telegram Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "telegram api url sendDocument" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendDocument");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendDocument", url);
}

test "telegram api url sendPhoto" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendPhoto");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendPhoto", url);
}

test "telegram api url sendVideo" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendVideo");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendVideo", url);
}

test "telegram api url sendAudio" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendAudio");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendAudio", url);
}

test "telegram api url sendVoice" {
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC", &.{}, &.{}, "allowlist");
    var buf: [256]u8 = undefined;
    const url = try ch.apiUrl(&buf, "sendVoice");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendVoice", url);
}

test "telegram max message len constant" {
    try std.testing.expectEqual(@as(usize, 4096), TelegramChannel.MAX_MESSAGE_LEN);
}

test "telegram build send body" {
    var buf: [512]u8 = undefined;
    const body = try TelegramChannel.buildSendBody(&buf, "12345", "Hello!");
    try std.testing.expectEqualStrings("{\"chat_id\":12345,\"text\":\"Hello!\"}", body);
}

test "telegram init stores fields" {
    const users = [_][]const u8{ "alice", "bob" };
    const ch = TelegramChannel.init(std.testing.allocator, "123:ABC-DEF", &users, &.{}, "allowlist");
    try std.testing.expectEqualStrings("123:ABC-DEF", ch.bot_token);
    try std.testing.expectEqual(@as(i64, 0), ch.last_update_id);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
    try std.testing.expect(ch.transcriber == null);
}

test "telegram init has null transcriber" {
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    try std.testing.expect(ch.transcriber == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Attachment Marker Parsing Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram parseAttachmentMarkers extracts IMAGE marker" {
    const parsed = try parseAttachmentMarkers(std.testing.allocator, "Check this [IMAGE:/tmp/photo.png] out");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
    try std.testing.expectEqualStrings("/tmp/photo.png", parsed.attachments[0].target);
    try std.testing.expectEqualStrings("Check this  out", parsed.remaining_text);
}

test "telegram parseAttachmentMarkers extracts multiple markers" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "Here [IMAGE:/tmp/a.png] and [DOCUMENT:https://example.com/a.pdf]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
    try std.testing.expectEqualStrings("/tmp/a.png", parsed.attachments[0].target);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[1].kind);
    try std.testing.expectEqualStrings("https://example.com/a.pdf", parsed.attachments[1].target);
}

test "telegram parseAttachmentMarkers returns remaining text without markers" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "Before [VIDEO:/tmp/v.mp4] after",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Before  after", parsed.remaining_text);
    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
}

test "telegram parseAttachmentMarkers keeps invalid markers in text" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "Report [UNKNOWN:/tmp/a.bin]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Report [UNKNOWN:/tmp/a.bin]", parsed.remaining_text);
    try std.testing.expectEqual(@as(usize, 0), parsed.attachments.len);
}

test "telegram parseAttachmentMarkers no markers returns full text" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "Hello, no attachments here!",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Hello, no attachments here!", parsed.remaining_text);
    try std.testing.expectEqual(@as(usize, 0), parsed.attachments.len);
}

test "telegram parseAttachmentMarkers AUDIO and VOICE" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[AUDIO:/tmp/song.mp3] [VOICE:/tmp/msg.ogg]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.audio, parsed.attachments[0].kind);
    try std.testing.expectEqual(AttachmentKind.voice, parsed.attachments[1].kind);
}

test "telegram parseAttachmentMarkers case insensitive kind" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[image:/tmp/a.png] [Image:/tmp/b.png]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[1].kind);
}

test "telegram parseAttachmentMarkers empty text" {
    const parsed = try parseAttachmentMarkers(std.testing.allocator, "");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), parsed.attachments.len);
    try std.testing.expectEqualStrings("", parsed.remaining_text);
}

test "telegram parseAttachmentMarkers PHOTO alias" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[PHOTO:/tmp/snap.jpg]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
}

test "telegram parseAttachmentMarkers FILE alias" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[FILE:/tmp/report.pdf]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[0].kind);
}

// ════════════════════════════════════════════════════════════════════════════
// inferAttachmentKindFromExtension Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram inferAttachmentKindFromExtension png is image" {
    try std.testing.expectEqual(AttachmentKind.image, inferAttachmentKindFromExtension("/tmp/photo.png"));
}

test "telegram inferAttachmentKindFromExtension jpg is image" {
    try std.testing.expectEqual(AttachmentKind.image, inferAttachmentKindFromExtension("/tmp/photo.jpg"));
}

test "telegram inferAttachmentKindFromExtension pdf is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/report.pdf"));
}

test "telegram inferAttachmentKindFromExtension mp4 is video" {
    try std.testing.expectEqual(AttachmentKind.video, inferAttachmentKindFromExtension("/tmp/clip.mp4"));
}

test "telegram inferAttachmentKindFromExtension mp3 is audio" {
    try std.testing.expectEqual(AttachmentKind.audio, inferAttachmentKindFromExtension("/tmp/song.mp3"));
}

test "telegram inferAttachmentKindFromExtension ogg is voice" {
    try std.testing.expectEqual(AttachmentKind.voice, inferAttachmentKindFromExtension("/tmp/voice.ogg"));
}

test "telegram inferAttachmentKindFromExtension unknown is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/file.xyz"));
}

test "telegram inferAttachmentKindFromExtension no extension is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/noext"));
}

test "telegram inferAttachmentKindFromExtension strips query string" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("https://example.com/specs.pdf?download=1"));
}

test "telegram inferAttachmentKindFromExtension case insensitive" {
    try std.testing.expectEqual(AttachmentKind.image, inferAttachmentKindFromExtension("/tmp/photo.PNG"));
    try std.testing.expectEqual(AttachmentKind.image, inferAttachmentKindFromExtension("/tmp/photo.Jpg"));
}

// ════════════════════════════════════════════════════════════════════════════
// Smart Split Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram smartSplitMessage splits at word boundary not mid-word" {
    const msg = "Hello World! Goodbye Friend";
    var it = smartSplitMessage(msg, 20);
    const chunk1 = it.next().?;
    // Should split at a space, not in the middle of "Goodbye"
    try std.testing.expect(chunk1.len <= 20);
    try std.testing.expect(chunk1[chunk1.len - 1] == ' ' or chunk1.len == 20);

    const chunk2 = it.next().?;
    try std.testing.expect(chunk2.len > 0);
    try std.testing.expect(it.next() == null);

    // Verify all content preserved
    const total = chunk1.len + chunk2.len;
    try std.testing.expectEqual(msg.len, total);
}

test "telegram smartSplitMessage splits at newline if available" {
    const msg = "First line\nSecond line that is longer than needed";
    var it = smartSplitMessage(msg, 20);
    const chunk1 = it.next().?;
    // Should prefer newline at position 10 (which is >= half of 20)
    try std.testing.expectEqualStrings("First line\n", chunk1);
}

test "telegram smartSplitMessage short message no split" {
    var it = smartSplitMessage("short", 100);
    try std.testing.expectEqualStrings("short", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "telegram smartSplitMessage empty returns null" {
    var it = smartSplitMessage("", 100);
    try std.testing.expect(it.next() == null);
}

test "telegram smartSplitMessage no word boundary falls back to hard cut" {
    const msg = "abcdefghijklmnopqrstuvwxyz";
    var it = smartSplitMessage(msg, 10);
    const chunk1 = it.next().?;
    try std.testing.expectEqual(@as(usize, 10), chunk1.len);
}

test "telegram smartSplitMessage preserves total content" {
    const msg = "word " ** 100;
    var it = smartSplitMessage(msg, 50);
    var total: usize = 0;
    while (it.next()) |chunk| {
        try std.testing.expect(chunk.len <= 50);
        total += chunk.len;
    }
    try std.testing.expectEqual(msg.len, total);
}

// ════════════════════════════════════════════════════════════════════════════
// Typing Indicator Test
// ════════════════════════════════════════════════════════════════════════════

test "telegram sendTypingIndicator does not crash with invalid token" {
    var ch = TelegramChannel.init(std.testing.allocator, "invalid:token", &.{}, &.{}, "allowlist");
    ch.sendTypingIndicator("12345");
}

// ════════════════════════════════════════════════════════════════════════════
// Allowed Users Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram allow_from empty denies all" {
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    try std.testing.expect(!ch.isUserAllowed("anyone"));
    try std.testing.expect(!ch.isUserAllowed("admin"));
}

test "telegram allow_from non-empty filters correctly" {
    const users = [_][]const u8{ "alice", "bob" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(ch.isUserAllowed("bob"));
    try std.testing.expect(!ch.isUserAllowed("eve"));
    try std.testing.expect(!ch.isUserAllowed(""));
}

test "telegram allow_from wildcard allows all" {
    const users = [_][]const u8{"*"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    try std.testing.expect(ch.isUserAllowed("anyone"));
    try std.testing.expect(ch.isUserAllowed("admin"));
}

test "telegram allow_from case insensitive" {
    const users = [_][]const u8{"Alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    try std.testing.expect(ch.isUserAllowed("Alice"));
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(ch.isUserAllowed("ALICE"));
}

test "telegram allow_from strips @ prefix" {
    const users = [_][]const u8{"@alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(!ch.isUserAllowed("@alice"));
    try std.testing.expect(!ch.isUserAllowed("bob"));
}

test "telegram isAnyIdentityAllowed matches username" {
    const users = [_][]const u8{"alice"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    const ids = [_][]const u8{ "alice", "123456" };
    try std.testing.expect(ch.isAnyIdentityAllowed(&ids));
}

test "telegram isAnyIdentityAllowed matches numeric id" {
    const users = [_][]const u8{"123456"};
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    const ids = [_][]const u8{ "unknown", "123456" };
    try std.testing.expect(ch.isAnyIdentityAllowed(&ids));
}

test "telegram isAnyIdentityAllowed denies when none match" {
    const users = [_][]const u8{ "alice", "987654" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    const ids = [_][]const u8{ "unknown", "123456" };
    try std.testing.expect(!ch.isAnyIdentityAllowed(&ids));
}

test "telegram isAnyIdentityAllowed wildcard allows all" {
    const users = [_][]const u8{ "alice", "*" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    const ids = [_][]const u8{ "bob", "999" };
    try std.testing.expect(ch.isAnyIdentityAllowed(&ids));
}

// ════════════════════════════════════════════════════════════════════════════
// AttachmentKind Method Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram AttachmentKind apiMethod returns correct methods" {
    try std.testing.expectEqualStrings("sendPhoto", AttachmentKind.image.apiMethod());
    try std.testing.expectEqualStrings("sendDocument", AttachmentKind.document.apiMethod());
    try std.testing.expectEqualStrings("sendVideo", AttachmentKind.video.apiMethod());
    try std.testing.expectEqualStrings("sendAudio", AttachmentKind.audio.apiMethod());
    try std.testing.expectEqualStrings("sendVoice", AttachmentKind.voice.apiMethod());
}

test "telegram AttachmentKind formField returns correct fields" {
    try std.testing.expectEqualStrings("photo", AttachmentKind.image.formField());
    try std.testing.expectEqualStrings("document", AttachmentKind.document.formField());
    try std.testing.expectEqualStrings("video", AttachmentKind.video.formField());
    try std.testing.expectEqualStrings("audio", AttachmentKind.audio.formField());
    try std.testing.expectEqualStrings("voice", AttachmentKind.voice.formField());
}

// ════════════════════════════════════════════════════════════════════════════
// Markdown → HTML Conversion Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram markdownToTelegramHtml bold" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "This is **bold** text");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("This is <b>bold</b> text", html);
}

test "telegram markdownToTelegramHtml italic" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "This is _italic_ text");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("This is <i>italic</i> text", html);
}

test "telegram markdownToTelegramHtml inline code" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "Use `code` here");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("Use <code>code</code> here", html);
}

test "telegram markdownToTelegramHtml code block" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "```\nhello\n```");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("<pre>hello\n</pre>", html);
}

test "telegram markdownToTelegramHtml code block with language" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "```python\nprint('hi')\n```");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("<pre>print('hi')\n</pre>", html);
}

test "telegram markdownToTelegramHtml strikethrough" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "This is ~~deleted~~ text");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("This is <s>deleted</s> text", html);
}

test "telegram markdownToTelegramHtml link" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "Click [here](https://example.com)");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("Click <a href=\"https://example.com\">here</a>", html);
}

test "telegram markdownToTelegramHtml header" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "# Title\n## Subtitle");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("<b>Title</b>\n<b>Subtitle</b>", html);
}

test "telegram markdownToTelegramHtml bullet list" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "- Item 1\n- Item 2");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("\u{2022} Item 1\n\u{2022} Item 2", html);
}

test "telegram markdownToTelegramHtml escapes HTML entities" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "A < B & C > D");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("A &lt; B &amp; C &gt; D", html);
}

test "telegram markdownToTelegramHtml plain text passthrough" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "Just plain text.");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqualStrings("Just plain text.", html);
}

test "telegram markdownToTelegramHtml empty" {
    const html = try markdownToTelegramHtml(std.testing.allocator, "");
    defer std.testing.allocator.free(html);
    try std.testing.expectEqual(@as(usize, 0), html.len);
}

// ════════════════════════════════════════════════════════════════════════════
// Periodic Typing Indicator Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram TypingIndicator init" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    var ti = TypingIndicator.init(&ch);
    try std.testing.expect(!ti.running.load(.acquire));
    try std.testing.expect(ti.thread == null);
}

test "telegram TypingIndicator start and stop" {
    var ch = TelegramChannel.init(std.testing.allocator, "invalid:token", &.{}, &.{}, "allowlist");
    var ti = TypingIndicator.init(&ch);

    ti.start("12345");
    try std.testing.expect(ti.running.load(.acquire));

    // Let it run briefly
    std.Thread.sleep(50 * std.time.ns_per_ms);

    ti.stop();
    try std.testing.expect(!ti.running.load(.acquire));
    try std.testing.expect(ti.thread == null);
}

test "telegram TypingIndicator double start is safe" {
    var ch = TelegramChannel.init(std.testing.allocator, "invalid:token", &.{}, &.{}, "allowlist");
    var ti = TypingIndicator.init(&ch);

    ti.start("123");
    ti.start("456"); // should not spawn second thread
    std.Thread.sleep(20 * std.time.ns_per_ms);
    ti.stop();
}

test "telegram TypingIndicator stop without start is safe" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    var ti = TypingIndicator.init(&ch);
    ti.stop(); // no-op
}

// ════════════════════════════════════════════════════════════════════════════
// Multipart URL Detection Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram sendMediaMultipart URL detection for http" {
    // Verify URL detection logic (same logic used in sendMediaMultipart)
    const url = "https://example.com/photo.jpg";
    try std.testing.expect(std.mem.startsWith(u8, url, "http://") or
        std.mem.startsWith(u8, url, "https://") or
        std.mem.startsWith(u8, url, "data:"));
}

test "telegram sendMediaMultipart URL detection for local file" {
    const path = "/tmp/photo.png";
    try std.testing.expect(!(std.mem.startsWith(u8, path, "http://") or
        std.mem.startsWith(u8, path, "https://") or
        std.mem.startsWith(u8, path, "data:")));
}

test "telegram sendMediaMultipart data URI treated as local file" {
    // data: URIs are NOT treated as URLs in sendMediaMultipart (would overflow the
    // 1024-byte buffer and curl can't upload them). They are passed as local file @paths.
    const data_uri = "data:image/png;base64,iVBOR";
    try std.testing.expect(!(std.mem.startsWith(u8, data_uri, "http://") or
        std.mem.startsWith(u8, data_uri, "https://")));
}
