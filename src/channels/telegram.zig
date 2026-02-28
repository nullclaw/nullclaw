const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const voice = @import("../voice.zig");
const platform = @import("../platform.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.telegram);
const MEDIA_GROUP_FLUSH_SECS: u64 = 3;
const TEMP_MEDIA_SWEEP_INTERVAL_POLLS: u32 = 20;
const TEMP_MEDIA_TTL_SECS: i64 = 24 * 60 * 60;
const TELEGRAM_BOT_COMMANDS_JSON =
    \\{"commands":[
    \\{"command":"start","description":"Start a conversation"},
    \\{"command":"new","description":"Clear history, start fresh"},
    \\{"command":"reset","description":"Alias for /new"},
    \\{"command":"help","description":"Show available commands"},
    \\{"command":"commands","description":"Alias for /help"},
    \\{"command":"status","description":"Show model and stats"},
    \\{"command":"whoami","description":"Show current session id"},
    \\{"command":"model","description":"Switch model"},
    \\{"command":"models","description":"Alias for /model"},
    \\{"command":"think","description":"Set thinking level"},
    \\{"command":"verbose","description":"Set verbose level"},
    \\{"command":"reasoning","description":"Set reasoning output"},
    \\{"command":"exec","description":"Set exec policy"},
    \\{"command":"queue","description":"Set queue policy"},
    \\{"command":"usage","description":"Set usage footer mode"},
    \\{"command":"tts","description":"Set TTS mode"},
    \\{"command":"memory","description":"Memory tools and diagnostics"},
    \\{"command":"doctor","description":"Memory diagnostics quick check"},
    \\{"command":"stop","description":"Stop active background task"},
    \\{"command":"restart","description":"Restart current session"},
    \\{"command":"compact","description":"Compact context now"}
    \\]}
;

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

fn isWindowsForbiddenFilenameChar(c: u8) bool {
    return switch (c) {
        '<', '>', ':', '"', '/', '\\', '|', '?', '*' => true,
        else => c < 0x20,
    };
}

fn isWindowsReservedBaseName(name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, "CON")) return true;
    if (std.ascii.eqlIgnoreCase(name, "PRN")) return true;
    if (std.ascii.eqlIgnoreCase(name, "AUX")) return true;
    if (std.ascii.eqlIgnoreCase(name, "NUL")) return true;

    if (name.len == 4) {
        if (std.ascii.eqlIgnoreCase(name[0..3], "COM") and name[3] >= '1' and name[3] <= '9') return true;
        if (std.ascii.eqlIgnoreCase(name[0..3], "LPT") and name[3] >= '1' and name[3] <= '9') return true;
    }
    return false;
}

/// Sanitize a filename component for cross-platform safety (especially Windows).
/// Replaces forbidden characters with `_`, trims trailing dot/space, and avoids
/// reserved DOS device names such as `CON` and `LPT1`.
fn sanitizeFilenameComponent(out: []u8, input: []const u8, limit: usize) []const u8 {
    if (out.len == 0) return "";

    const n = @min(@min(input.len, limit), out.len);
    var w: usize = 0;
    for (input[0..n]) |c| {
        out[w] = if (isWindowsForbiddenFilenameChar(c)) '_' else c;
        w += 1;
    }

    while (w > 0 and (out[w - 1] == ' ' or out[w - 1] == '.')) : (w -= 1) {}
    if (w == 0) {
        out[0] = '_';
        w = 1;
    }

    const base = if (std.mem.indexOfScalar(u8, out[0..w], '.')) |dot|
        out[0..dot]
    else
        out[0..w];
    if (isWindowsReservedBaseName(base)) {
        if (w < out.len) {
            std.mem.copyBackwards(u8, out[1 .. w + 1], out[0..w]);
            out[0] = '_';
            w += 1;
        } else {
            out[0] = '_';
        }
    }

    return out[0..w];
}

fn trimTrailingPathSeparators(path: []const u8) []const u8 {
    if (path.len == 0) return path;
    var end = path.len;
    while (end > 1 and (path[end - 1] == '/' or path[end - 1] == '\\')) : (end -= 1) {}
    return path[0..end];
}

fn pathSeparator(base: []const u8) []const u8 {
    if (base.len == 0) return "";
    const last = base[base.len - 1];
    return if (last == '/' or last == '\\') "" else "/";
}

fn cloneChannelMessage(allocator: std.mem.Allocator, msg: root.ChannelMessage) !root.ChannelMessage {
    const id_dup = try allocator.dupe(u8, msg.id);
    errdefer allocator.free(id_dup);
    const sender_dup = try allocator.dupe(u8, msg.sender);
    errdefer allocator.free(sender_dup);
    const content_dup = try allocator.dupe(u8, msg.content);
    errdefer allocator.free(content_dup);

    const reply_target_dup: ?[]const u8 = if (msg.reply_target) |rt|
        (try allocator.dupe(u8, rt))
    else
        null;
    errdefer if (reply_target_dup) |rt| allocator.free(rt);

    const first_name_dup: ?[]const u8 = if (msg.first_name) |fn_|
        (try allocator.dupe(u8, fn_))
    else
        null;
    errdefer if (first_name_dup) |fn_| allocator.free(fn_);

    return .{
        .id = id_dup,
        .sender = sender_dup,
        .content = content_dup,
        .channel = msg.channel,
        .timestamp = msg.timestamp,
        .reply_target = reply_target_dup,
        .message_id = msg.message_id,
        .first_name = first_name_dup,
        .is_group = msg.is_group,
    };
}

fn mediaGroupLatestSeen(group_id: []const u8, group_ids: []const ?[]const u8, received_at: []const u64) ?u64 {
    const n = @min(group_ids.len, received_at.len);
    var seen = false;
    var latest: u64 = 0;
    for (0..n) |i| {
        const gid = group_ids[i] orelse continue;
        if (!std.mem.eql(u8, gid, group_id)) continue;
        if (!seen or received_at[i] > latest) latest = received_at[i];
        seen = true;
    }
    return if (seen) latest else null;
}

fn nextPendingMediaDeadline(group_ids: []const ?[]const u8, received_at: []const u64) ?u64 {
    const n = @min(group_ids.len, received_at.len);
    var seen = false;
    var next_deadline: u64 = 0;
    for (0..n) |i| {
        const gid = group_ids[i] orelse continue;
        const latest = mediaGroupLatestSeen(gid, group_ids, received_at) orelse continue;
        const deadline = latest + MEDIA_GROUP_FLUSH_SECS;
        if (!seen or deadline < next_deadline) next_deadline = deadline;
        seen = true;
    }
    return if (seen) next_deadline else null;
}

fn sweepTempMediaFilesInDir(dir_path: []const u8, now_secs: i64, ttl_secs: i64) void {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "nullclaw_doc_") and
            !std.mem.startsWith(u8, entry.name, "nullclaw_photo_"))
            continue;

        const stat = dir.statFile(entry.name) catch continue;
        const mtime_secs: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        if ((now_secs - mtime_secs) < ttl_secs) continue;

        dir.deleteFile(entry.name) catch continue;
    }
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
    errdefer allocator.free(remaining_owned);

    const final_attachments = try attachments.toOwnedSlice(allocator);
    remaining.deinit(allocator);

    return .{
        .attachments = final_attachments,
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

    // Pending media group messages (buffered across poll cycles until group is complete)
    pending_media_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty,
    pending_media_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty,
    pending_media_received_at: std.ArrayListUnmanaged(u64) = .empty,
    polls_since_temp_sweep: u32 = 0,

    typing_mu: std.Thread.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,

    pub const MAX_MESSAGE_LEN: usize = 4096;
    const TYPING_INTERVAL_NS: u64 = 4 * std.time.ns_per_s;
    const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;

    const TypingTask = struct {
        channel: *TelegramChannel,
        chat_id: []const u8,
        stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
    };

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
            // Strip leading "@" from allowlist entry.
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
        const resp = root.http_util.curlPostWithProxy(self.allocator, url, "{}", &.{}, self.proxy, "10") catch return false;
        defer self.allocator.free(resp);
        return std.mem.indexOf(u8, resp, "\"ok\":true") != null;
    }

    /// Register bot commands with Telegram so they appear in the "/" menu.
    pub fn setMyCommands(self: *TelegramChannel) void {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "setMyCommands") catch return;

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, TELEGRAM_BOT_COMMANDS_JSON, &.{}, self.proxy, "10") catch |err| {
            log.warn("setMyCommands failed: {}", .{err});
            return;
        };
        self.allocator.free(resp);
    }

    /// Disable webhook mode before polling, preserving queued updates.
    pub fn deleteWebhookKeepPending(self: *TelegramChannel) void {
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "deleteWebhook") catch return;

        const body = "{\"drop_pending_updates\":false}";
        const resp = root.http_util.curlPostWithProxy(self.allocator, url, body, &.{}, self.proxy, "10") catch |err| {
            log.warn("deleteWebhook failed: {}", .{err});
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
        const resp_body = root.http_util.curlPostWithProxy(self.allocator, url, body, &.{}, self.proxy, "10") catch return;
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

    /// Return an offset safe to persist across restarts.
    /// If media-group updates are still buffered in-memory, persisting a newer
    /// offset can skip those updates after restart, so return null until flushed.
    pub fn persistableUpdateOffset(self: *const TelegramChannel) ?i64 {
        if (self.pending_media_messages.items.len == 0) {
            return self.last_update_id;
        }
        return null;
    }

    // ── Typing indicator ────────────────────────────────────────────

    /// Send a "typing" chat action. Best-effort: errors are ignored.
    pub fn sendTypingIndicator(self: *TelegramChannel, chat_id: []const u8) void {
        if (builtin.is_test) return;
        if (chat_id.len == 0) return;

        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "sendChatAction") catch return;

        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        body_list.appendSlice(self.allocator, "{\"chat_id\":") catch return;
        body_list.appendSlice(self.allocator, chat_id) catch return;
        body_list.appendSlice(self.allocator, ",\"action\":\"typing\"}") catch return;

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, "10") catch return;
        self.allocator.free(resp);
    }

    pub fn startTyping(self: *TelegramChannel, chat_id: []const u8) !void {
        if (chat_id.len == 0) return;
        try self.stopTyping(chat_id);

        const key_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .chat_id = key_copy,
        };

        task.thread = try std.Thread.spawn(.{ .stack_size = 128 * 1024 }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *TelegramChannel, chat_id: []const u8) !void {
        var removed_key: ?[]u8 = null;
        var removed_task: ?*TypingTask = null;

        self.typing_mu.lock();
        if (self.typing_handles.fetchRemove(chat_id)) |entry| {
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

    fn stopAllTyping(self: *TelegramChannel) void {
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
            task.channel.sendTypingIndicator(task.chat_id);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std.Thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
        }
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

        const resp = root.http_util.curlPostWithProxy(self.allocator, url, html_body.items, &.{}, self.proxy, "30") catch {
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

        const resp = try root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, "30");
        self.allocator.free(resp);
    }

    // ── Media sending ───────────────────────────────────────────────

    const ResolvedAttachmentPath = struct {
        path: []const u8,
        owned: ?[]const u8 = null,

        fn deinit(self: *const ResolvedAttachmentPath, allocator: std.mem.Allocator) void {
            if (self.owned) |buf| allocator.free(buf);
        }
    };

    fn resolveAttachmentPath(allocator: std.mem.Allocator, file_path: []const u8) !ResolvedAttachmentPath {
        // Remote URL attachments are passed through as-is.
        if (std.mem.startsWith(u8, file_path, "http://") or
            std.mem.startsWith(u8, file_path, "https://"))
        {
            return .{ .path = file_path };
        }

        // Expand leading ~/ (or ~\ on Windows) so curl receives an absolute path.
        if (file_path.len >= 2 and file_path[0] == '~' and (file_path[1] == '/' or file_path[1] == '\\')) {
            const home = try platform.getHomeDir(allocator);
            defer allocator.free(home);

            const expanded = try std.fs.path.join(allocator, &.{ home, file_path[2..] });
            return .{
                .path = expanded,
                .owned = expanded,
            };
        }

        return .{ .path = file_path };
    }

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
        const resolved_file_path = try resolveAttachmentPath(allocator, file_path);
        defer resolved_file_path.deinit(allocator);
        const media_path = resolved_file_path.path;

        // Build file form field: field=@path (local files) or field=URL (remote URLs)
        var file_arg_buf: [1024]u8 = undefined;
        var file_fbs = std.io.fixedBufferStream(&file_arg_buf);
        if (std.mem.startsWith(u8, media_path, "http://") or
            std.mem.startsWith(u8, media_path, "https://"))
        {
            try file_fbs.writer().print("{s}={s}", .{ kind.formField(), media_path });
        } else {
            try file_fbs.writer().print("{s}=@{s}", .{ kind.formField(), media_path });
        }
        const file_arg = file_fbs.getWritten();

        // Build chat_id form field
        var chatid_arg_buf: [128]u8 = undefined;
        var chatid_fbs = std.io.fixedBufferStream(&chatid_arg_buf);
        try chatid_fbs.writer().print("chat_id={s}", .{chat_id});
        const chatid_arg = chatid_fbs.getWritten();

        // Build argv
        var argv_buf: [24][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-s";
        argc += 1;
        argv_buf[argc] = "-m";
        argc += 1;
        argv_buf[argc] = "120";
        argc += 1;

        if (self.proxy) |p| {
            argv_buf[argc] = "-x";
            argc += 1;
            argv_buf[argc] = p;
            argc += 1;
        }

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

        const resp = try root.http_util.curlPostWithProxy(self.allocator, url, body_list.items, &.{}, self.proxy, "30");
        self.allocator.free(resp);
    }

    fn resetPendingMediaBuffers(self: *TelegramChannel) void {
        for (self.pending_media_messages.items) |msg| {
            msg.deinit(self.allocator);
        }
        self.pending_media_messages.clearRetainingCapacity();

        for (self.pending_media_group_ids.items) |mg| {
            if (mg) |s| self.allocator.free(s);
        }
        self.pending_media_group_ids.clearRetainingCapacity();
        self.pending_media_received_at.clearRetainingCapacity();
    }

    fn maybeSweepTempMediaFiles(self: *TelegramChannel) void {
        self.polls_since_temp_sweep += 1;
        if (self.polls_since_temp_sweep < TEMP_MEDIA_SWEEP_INTERVAL_POLLS) return;
        self.polls_since_temp_sweep = 0;
        self.sweepTempMediaFiles();
    }

    fn sweepTempMediaFiles(self: *TelegramChannel) void {
        const tmp_dir = platform.getTempDir(self.allocator) catch return;
        defer self.allocator.free(tmp_dir);
        sweepTempMediaFilesInDir(tmp_dir, std.time.timestamp(), TEMP_MEDIA_TTL_SECS);
    }

    fn flushMaturedPendingMediaGroups(
        self: *TelegramChannel,
        poll_allocator: std.mem.Allocator,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
    ) void {
        if (self.pending_media_messages.items.len == 0) return;
        if (self.pending_media_messages.items.len != self.pending_media_group_ids.items.len or
            self.pending_media_messages.items.len != self.pending_media_received_at.items.len)
        {
            log.warn("telegram pending media buffers out of sync; resetting buffers", .{});
            self.resetPendingMediaBuffers();
            return;
        }

        const now = root.nowEpochSecs();

        // Own group ids in this scratch list: pending buffers can mutate/free ids
        // on allocation-failure paths while we're still scanning.
        var flush_groups: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (flush_groups.items) |gid| self.allocator.free(gid);
            flush_groups.deinit(self.allocator);
        }

        for (self.pending_media_group_ids.items) |mg_opt| {
            const mg = mg_opt orelse continue;
            const latest = mediaGroupLatestSeen(mg, self.pending_media_group_ids.items, self.pending_media_received_at.items) orelse continue;
            if (now < latest + MEDIA_GROUP_FLUSH_SECS) continue;

            var already_added = false;
            for (flush_groups.items) |existing| {
                if (std.mem.eql(u8, existing, mg)) {
                    already_added = true;
                    break;
                }
            }
            if (!already_added) {
                const gid_owned = self.allocator.dupe(u8, mg) catch continue;
                flush_groups.append(self.allocator, gid_owned) catch {
                    self.allocator.free(gid_owned);
                };
            }
        }

        if (flush_groups.items.len == 0) return;

        var moved_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        defer {
            for (moved_messages.items) |msg| msg.deinit(self.allocator);
            moved_messages.deinit(self.allocator);
        }

        var moved_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty;
        defer {
            for (moved_group_ids.items) |mg| if (mg) |s| self.allocator.free(s);
            moved_group_ids.deinit(self.allocator);
        }

        var i: usize = 0;
        while (i < self.pending_media_messages.items.len) {
            const mg = self.pending_media_group_ids.items[i] orelse {
                i += 1;
                continue;
            };

            var should_flush = false;
            for (flush_groups.items) |flush_gid| {
                if (std.mem.eql(u8, flush_gid, mg)) {
                    should_flush = true;
                    break;
                }
            }
            if (!should_flush) {
                i += 1;
                continue;
            }

            const msg = self.pending_media_messages.orderedRemove(i);
            const mgid = self.pending_media_group_ids.orderedRemove(i);
            _ = self.pending_media_received_at.orderedRemove(i);

            moved_messages.append(self.allocator, msg) catch {
                msg.deinit(self.allocator);
                if (mgid) |s| self.allocator.free(s);
                continue;
            };
            moved_group_ids.append(self.allocator, mgid) catch {
                const popped = moved_messages.pop().?;
                popped.deinit(self.allocator);
                if (mgid) |s| self.allocator.free(s);
                continue;
            };
        }

        mergeMediaGroups(self.allocator, &moved_messages, &moved_group_ids);

        for (moved_messages.items) |pending_msg| {
            const out_msg = cloneChannelMessage(poll_allocator, pending_msg) catch {
                pending_msg.deinit(self.allocator);
                continue;
            };

            messages.append(poll_allocator, out_msg) catch {
                var tmp = out_msg;
                tmp.deinit(poll_allocator);
                pending_msg.deinit(self.allocator);
                continue;
            };
            media_group_ids.append(poll_allocator, null) catch {
                const popped = messages.pop().?;
                var tmp = popped;
                tmp.deinit(poll_allocator);
                pending_msg.deinit(self.allocator);
                continue;
            };
            pending_msg.deinit(self.allocator);
        }

        moved_messages.clearRetainingCapacity();

        for (moved_group_ids.items) |mg| if (mg) |s| self.allocator.free(s);
        moved_group_ids.clearRetainingCapacity();
    }

    /// Poll for updates using long-polling (getUpdates) via curl.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    /// Voice and audio messages are automatically transcribed via Groq Whisper
    /// when a Groq API key is configured (config or GROQ_API_KEY env var).
    pub fn pollUpdates(self: *TelegramChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, "getUpdates");

        self.maybeSweepTempMediaFiles();

        // Build body with offset and dynamic timeout.
        // If pending media groups exist, cap timeout to the nearest group deadline.
        var poll_timeout: u64 = 30;
        {
            const t_now = root.nowEpochSecs();
            if (nextPendingMediaDeadline(self.pending_media_group_ids.items, self.pending_media_received_at.items)) |deadline| {
                if (t_now >= deadline) {
                    poll_timeout = 0; // Deadline already passed — return immediately
                } else {
                    poll_timeout = @min(30, deadline - t_now);
                }
            }
        }
        var body_buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        try fbs.writer().print("{{\"offset\":{d},\"timeout\":{d},\"allowed_updates\":[\"message\"]}}", .{ self.last_update_id, poll_timeout });
        const body = fbs.getWritten();

        var timeout_buf: [16]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{poll_timeout + 15}) catch "45";

        const resp_body = try root.http_util.curlPostWithProxy(allocator, url, body, &.{}, self.proxy, timeout_str);
        defer allocator.free(resp_body);

        // Parse JSON response to extract messages
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return &.{};
        defer parsed.deinit();
        if (parsed.value != .object) return &.{};

        const result_val = parsed.value.object.get("result") orelse return &.{};
        if (result_val != .array) return &.{};
        const result_array = result_val.array.items;

        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        // Track media_group_id per message for post-loop merging
        var media_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty;
        errdefer {
            for (messages.items) |msg| {
                var tmp = msg;
                tmp.deinit(allocator);
            }
            messages.deinit(allocator);
            for (media_group_ids.items) |mg| if (mg) |s| allocator.free(s);
            media_group_ids.deinit(allocator);
        }

        // Flush matured groups buffered across previous poll cycles.
        self.flushMaturedPendingMediaGroups(allocator, &messages, &media_group_ids);

        for (result_array) |update| {
            self.processUpdate(allocator, update, &messages, &media_group_ids);
        }

        // ── Route media group items to pending buffer ────────────────
        // Messages with a media_group_id are moved to the persistent pending
        // buffer instead of being returned immediately. This avoids blocking
        // and allows subsequent poll cycles to collect remaining group items.
        {
            var i: usize = 0;
            while (i < messages.items.len) {
                if (media_group_ids.items[i] != null) {
                    // Transfer ownership: remove from local arrays, clone into pending buffers
                    // owned by self.allocator, and free the poll-allocator copies.
                    const msg = messages.orderedRemove(i);
                    const mgid_opt = media_group_ids.orderedRemove(i);

                    const pending_msg = cloneChannelMessage(self.allocator, msg) catch {
                        var tmp = msg;
                        tmp.deinit(allocator);
                        if (mgid_opt) |m| allocator.free(m);
                        continue;
                    };
                    const pending_mgid: []const u8 = blk: {
                        const m = mgid_opt orelse {
                            var dropped = msg;
                            dropped.deinit(allocator);
                            var rollback = pending_msg;
                            rollback.deinit(self.allocator);
                            continue;
                        };
                        defer allocator.free(m);
                        break :blk self.allocator.dupe(u8, m) catch {
                            var dropped = msg;
                            dropped.deinit(allocator);
                            var rollback = pending_msg;
                            rollback.deinit(self.allocator);
                            continue;
                        };
                    };

                    var tmp = msg;
                    tmp.deinit(allocator);

                    self.pending_media_messages.append(self.allocator, pending_msg) catch {
                        var rollback = pending_msg;
                        rollback.deinit(self.allocator);
                        self.allocator.free(pending_mgid);
                        continue;
                    };
                    self.pending_media_group_ids.append(self.allocator, pending_mgid) catch {
                        const popped = self.pending_media_messages.pop().?;
                        var rollback = popped;
                        rollback.deinit(self.allocator);
                        self.allocator.free(pending_mgid);
                        continue;
                    };
                    self.pending_media_received_at.append(self.allocator, root.nowEpochSecs()) catch {
                        const popped_mgid = self.pending_media_group_ids.pop().?;
                        if (popped_mgid) |m| self.allocator.free(m);
                        const popped_msg = self.pending_media_messages.pop().?;
                        var rollback = popped_msg;
                        rollback.deinit(self.allocator);
                        continue;
                    };

                    // Don't increment i — orderedRemove shifted elements down.
                } else {
                    i += 1;
                }
            }
        }

        // Flush again to emit groups that became mature in this cycle.
        self.flushMaturedPendingMediaGroups(allocator, &messages, &media_group_ids);

        // Merge consecutive text messages to reconstruct long split texts
        // and debounce rapid-fire messages.
        mergeConsecutiveMessages(allocator, &messages);

        // toOwnedSlice MUST run before manual deinit to avoid double-free via errdefer
        const final_messages = try messages.toOwnedSlice(allocator);

        // Free remaining media_group_id tracking strings (all should be null at this point)
        for (media_group_ids.items) |mg| {
            if (mg) |s| allocator.free(s);
        }
        media_group_ids.deinit(allocator);

        return final_messages;
    }

    /// Process a single Telegram update: extract message content (voice, photo,
    /// document, or text), check authorization, and append to the messages list.
    /// Called from both the main poll loop and the follow-up media group re-poll.
    fn processUpdate(
        self: *TelegramChannel,
        allocator: std.mem.Allocator,
        update: std.json.Value,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
    ) void {
        if (update != .object) return;
        // Advance offset
        if (update.object.get("update_id")) |uid| {
            if (uid == .integer) {
                self.last_update_id = uid.integer + 1;
            }
        }

        const message = update.object.get("message") orelse return;
        if (message != .object) return;

        // Get sender info — check both @username and numeric user_id
        const from_obj = message.object.get("from") orelse return;
        if (from_obj != .object) return;
        const username_val = from_obj.object.get("username");
        const username = if (username_val) |uv| (if (uv == .string) uv.string else "unknown") else "unknown";

        var user_id_buf: [32]u8 = undefined;
        const user_id: ?[]const u8 = blk_uid: {
            const id_val = from_obj.object.get("id") orelse break :blk_uid null;
            if (id_val != .integer) break :blk_uid null;
            break :blk_uid std.fmt.bufPrint(&user_id_buf, "{d}", .{id_val.integer}) catch null;
        };

        // Get chat_id and chat type
        const chat_obj = message.object.get("chat") orelse return;
        if (chat_obj != .object) return;
        const chat_id_val = chat_obj.object.get("id") orelse return;
        var chat_id_buf: [32]u8 = undefined;
        const chat_id_str = if (chat_id_val == .integer)
            (std.fmt.bufPrint(&chat_id_buf, "{d}", .{chat_id_val.integer}) catch return)
        else
            return;
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
            return;
        }

        const sender_identity = if (!std.mem.eql(u8, username, "unknown"))
            username
        else
            (user_id orelse "unknown");

        const first_name_val = from_obj.object.get("first_name");
        const first_name: ?[]const u8 = if (first_name_val) |fnv| (if (fnv == .string) fnv.string else null) else null;

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
                    defer allocator.free(transcribed);
                    var result: std.ArrayListUnmanaged(u8) = .empty;
                    result.appendSlice(allocator, "[Voice]: ") catch break :blk_content null;
                    result.appendSlice(allocator, transcribed) catch {
                        result.deinit(allocator);
                        break :blk_content null;
                    };
                    break :blk_content result.toOwnedSlice(allocator) catch {
                        result.deinit(allocator);
                        break :blk_content null;
                    };
                }
                break :blk_content null;
            }

            // Check for photo messages
            if (message.object.get("photo")) |photo_val| {
                if (photo_val == .array and photo_val.array.items.len > 0) {
                    const last_photo = photo_val.array.items[photo_val.array.items.len - 1];
                    if (last_photo == .object) {
                        const photo_fid_val = last_photo.object.get("file_id") orelse break :blk_content null;
                        const photo_fid = if (photo_fid_val == .string) photo_fid_val.string else break :blk_content null;

                        if (downloadTelegramPhoto(allocator, self.bot_token, photo_fid, self.proxy)) |local_path| {
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
                            if (message.object.get("caption")) |cap_val| {
                                if (cap_val == .string) {
                                    result.appendSlice(allocator, " ") catch {};
                                    result.appendSlice(allocator, cap_val.string) catch {};
                                }
                            }
                            break :blk_content result.toOwnedSlice(allocator) catch {
                                result.deinit(allocator);
                                break :blk_content null;
                            };
                        }
                    }
                }
            }

            // Check for document messages
            if (message.object.get("document")) |doc_val| {
                if (doc_val == .object) {
                    const doc_fid_val = doc_val.object.get("file_id") orelse break :blk_content null;
                    const doc_fid = if (doc_fid_val == .string) doc_fid_val.string else break :blk_content null;
                    const doc_fname: ?[]const u8 = if (doc_val.object.get("file_name")) |fn_val|
                        (if (fn_val == .string) fn_val.string else null)
                    else
                        null;

                    if (downloadTelegramFile(allocator, self.bot_token, doc_fid, doc_fname, self.proxy)) |local_path| {
                        var result: std.ArrayListUnmanaged(u8) = .empty;
                        result.appendSlice(allocator, "[FILE:") catch {
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
                        if (message.object.get("caption")) |cap_val| {
                            if (cap_val == .string) {
                                result.appendSlice(allocator, " ") catch {};
                                result.appendSlice(allocator, cap_val.string) catch {};
                            }
                        }
                        break :blk_content result.toOwnedSlice(allocator) catch {
                            result.deinit(allocator);
                            break :blk_content null;
                        };
                    }
                }
            }

            break :blk_content null;
        };

        // Fall back to text content if no voice/photo/document content.
        // If text is absent (e.g. document/photo upload failure), use caption.
        const final_content = content orelse blk_text: {
            if (message.object.get("text")) |text_val| {
                if (text_val == .string) {
                    break :blk_text allocator.dupe(u8, text_val.string) catch return;
                }
            }
            if (message.object.get("caption")) |cap_val| {
                if (cap_val == .string) {
                    break :blk_text allocator.dupe(u8, cap_val.string) catch return;
                }
            }
            return;
        };

        // Extract media_group_id
        const media_group_id: ?[]const u8 = blk_mg: {
            const mg_val = message.object.get("media_group_id") orelse break :blk_mg null;
            break :blk_mg if (mg_val == .string) mg_val.string else null;
        };

        const id_dup = allocator.dupe(u8, sender_identity) catch {
            allocator.free(final_content);
            return;
        };
        const sender_dup = allocator.dupe(u8, chat_id_str) catch {
            allocator.free(final_content);
            allocator.free(id_dup);
            return;
        };
        const fn_dup: ?[]const u8 = if (first_name) |fn_|
            (allocator.dupe(u8, fn_) catch {
                allocator.free(final_content);
                allocator.free(id_dup);
                allocator.free(sender_dup);
                return;
            })
        else
            null;

        messages.append(allocator, .{
            .id = id_dup,
            .sender = sender_dup,
            .content = final_content,
            .channel = "telegram",
            .timestamp = root.nowEpochSecs(),
            .message_id = msg_id,
            .first_name = fn_dup,
            .is_group = is_group,
        }) catch {
            allocator.free(final_content);
            allocator.free(id_dup);
            allocator.free(sender_dup);
            if (fn_dup) |f| allocator.free(f);
            return;
        };

        // Track media_group_id for merging
        const mg_dup: ?[]const u8 = if (media_group_id) |mgid|
            (allocator.dupe(u8, mgid) catch null)
        else
            null;
        media_group_ids.append(allocator, mg_dup) catch {
            // Rollback to keep messages and media_group_ids synchronized
            const popped = messages.pop().?;
            var tmp = popped;
            tmp.deinit(allocator);
            if (mg_dup) |m| allocator.free(m);
            return;
        };
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        // Verify bot token by calling getMe
        var url_buf: [512]u8 = undefined;
        const url = self.apiUrl(&url_buf, "getMe") catch return;

        if (root.http_util.curlPostWithProxy(self.allocator, url, "{}", &.{}, self.proxy, "10")) |resp| {
            self.allocator.free(resp);
        } else |_| {}

        // Keep slash-command menu in sync when channel is started via manager/daemon.
        self.setMyCommands();
        // If getMe fails, we still start — healthCheck will report issues.
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        self.stopAllTyping();
        // Clean up buffered media group messages to prevent shutdown leaks.
        self.resetPendingMediaBuffers();
        self.pending_media_messages.deinit(self.allocator);
        self.pending_media_group_ids.deinit(self.allocator);
        self.pending_media_received_at.deinit(self.allocator);
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

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
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
// Telegram Photo Download
// ════════════════════════════════════════════════════════════════════════════

/// Merge consecutive text messages from the same sender in the same chat.
/// This acts as a debouncer for rapid-fire messages and automatically reassembles
/// long texts that were split by the Telegram client (which splits at 4096 chars).
/// Handles interleaving of messages from different chats.
fn isSlashCommandMessage(content: []const u8) bool {
    const trimmed = std.mem.trim(u8, content, " \t\r\n");
    return std.mem.startsWith(u8, trimmed, "/");
}

fn mergeConsecutiveMessages(
    allocator: std.mem.Allocator,
    messages: *std.ArrayListUnmanaged(root.ChannelMessage),
) void {
    if (messages.items.len <= 1) return;

    var i: usize = 0;
    while (i < messages.items.len) {
        const mid1 = messages.items[i].message_id orelse {
            i += 1;
            continue;
        };

        if (isSlashCommandMessage(messages.items[i].content)) {
            i += 1;
            continue;
        }

        var found_idx: ?usize = null;
        for (i + 1..messages.items.len) |j| {
            if (std.mem.eql(u8, messages.items[i].sender, messages.items[j].sender) and
                std.mem.eql(u8, messages.items[i].id, messages.items[j].id))
            {
                if (messages.items[j].message_id) |mid2| {
                    if (mid2 == mid1 + 1) {
                        if (!isSlashCommandMessage(messages.items[j].content)) {
                            found_idx = j;
                        }
                    }
                }
                break; // Found the next message from this user, consecutive or not.
            }
        }

        if (found_idx) |j| {
            var merged: std.ArrayListUnmanaged(u8) = .empty;
            defer merged.deinit(allocator);
            var merge_ok = true;
            merged.appendSlice(allocator, messages.items[i].content) catch {
                merge_ok = false;
            };
            if (merge_ok) {
                merged.appendSlice(allocator, "\n") catch {
                    merge_ok = false;
                };
                merged.appendSlice(allocator, messages.items[j].content) catch {
                    merge_ok = false;
                };
            }

            if (merge_ok and merged.items.len > 0) {
                const new_content = merged.toOwnedSlice(allocator) catch null;
                if (new_content) |nc| {
                    allocator.free(messages.items[i].content);
                    messages.items[i].content = nc;
                    messages.items[i].message_id = messages.items[j].message_id;

                    var extra = messages.orderedRemove(j);
                    extra.deinit(allocator);

                    continue; // Do not increment i, allow chain-merging
                }
            }
        }
        i += 1;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Media Group Merging
// ════════════════════════════════════════════════════════════════════════════

/// Merge messages that belong to the same `media_group_id` into a single message.
/// Handles interleaved groups (scans the full array, not just consecutive items)
/// and removes merged entries backward to avoid index-shifting bugs.
/// Memory-safe: only frees old content after new allocation succeeds.
fn mergeMediaGroups(
    allocator: std.mem.Allocator,
    messages: *std.ArrayListUnmanaged(root.ChannelMessage),
    media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
) void {
    if (messages.items.len <= 1) return;

    var i: usize = 0;
    while (i < messages.items.len) {
        const mg = media_group_ids.items[i] orelse {
            i += 1;
            continue;
        };

        // 1. Find all matching indices (supports interleaved messages)
        var match_indices: std.ArrayListUnmanaged(usize) = .empty;
        defer match_indices.deinit(allocator);

        var j = i + 1;
        while (j < messages.items.len) : (j += 1) {
            if (media_group_ids.items[j]) |other_mg| {
                if (std.mem.eql(u8, mg, other_mg)) {
                    match_indices.append(allocator, j) catch {};
                }
            }
        }

        if (match_indices.items.len > 0) {
            // 2. Build merged content
            var merged: std.ArrayListUnmanaged(u8) = .empty;
            var merge_ok = true;
            merged.appendSlice(allocator, messages.items[i].content) catch {
                merge_ok = false;
            };

            if (merge_ok) {
                for (match_indices.items) |idx| {
                    merged.appendSlice(allocator, "\n") catch {
                        merge_ok = false;
                        break;
                    };
                    merged.appendSlice(allocator, messages.items[idx].content) catch {
                        merge_ok = false;
                        break;
                    };
                }
            }

            const new_content = if (merge_ok) (merged.toOwnedSlice(allocator) catch null) else null;

            if (new_content) |nc| {
                // 3. Safely replace root content NOW that allocation succeeded
                allocator.free(messages.items[i].content);
                messages.items[i].content = nc;

                // 4. Remove backwards to prevent index shifting
                var k: usize = match_indices.items.len;
                while (k > 0) {
                    k -= 1;
                    const idx = match_indices.items[k];

                    const extra = messages.orderedRemove(idx);
                    allocator.free(extra.content);
                    allocator.free(extra.id);
                    allocator.free(extra.sender);
                    if (extra.first_name) |fn_| allocator.free(fn_);

                    if (media_group_ids.items[idx]) |s| allocator.free(s);
                    _ = media_group_ids.orderedRemove(idx);
                }
            } else {
                merged.deinit(allocator);
            }
        }
        i += 1;
    }
}

/// Download a photo from Telegram by file_id. Returns the local temp file path (caller-owned).
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

    const resp = root.http_util.curlPostWithProxy(allocator, api_url, body_list.items, &.{}, proxy, "15") catch |err| {
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
    var name_buf: [256]u8 = undefined;
    const safe_name = sanitizeFilenameComponent(&name_buf, file_id, 200);
    const tmp_base = trimTrailingPathSeparators(tmp_dir);
    path_fbs.writer().print("{s}{s}nullclaw_photo_{s}{s}", .{ tmp_base, pathSeparator(tmp_base), safe_name, ext }) catch return null;
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

/// Download any file from Telegram by file_id. Preserves the original filename when provided.
/// Returns the local temp file path (caller-owned).
fn downloadTelegramFile(allocator: std.mem.Allocator, bot_token: []const u8, file_id: []const u8, file_name: ?[]const u8, proxy: ?[]const u8) ?[]u8 {
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

    const resp = root.http_util.curlPostWithProxy(allocator, api_url, body_list.items, &.{}, proxy, "15") catch |err| {
        log.warn("downloadTelegramFile: getFile API failed: {}", .{err});
        return null;
    };
    defer allocator.free(resp);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch |err| {
        log.warn("downloadTelegramFile: JSON parse failed: {}", .{err});
        return null;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const result_obj = parsed.value.object.get("result") orelse {
        log.warn("downloadTelegramFile: no 'result' in response", .{});
        return null;
    };
    if (result_obj != .object) return null;
    const fp_val = result_obj.object.get("file_path") orelse {
        log.warn("downloadTelegramFile: no 'file_path' in result", .{});
        return null;
    };
    const tg_file_path = if (fp_val == .string) fp_val.string else return null;

    // 2. Download the file
    var dl_url_buf: [1024]u8 = undefined;
    var dl_fbs = std.io.fixedBufferStream(&dl_url_buf);
    dl_fbs.writer().print("https://api.telegram.org/file/bot{s}/{s}", .{ bot_token, tg_file_path }) catch return null;
    const dl_url = dl_fbs.getWritten();

    const data = root.http_util.curlGetWithProxy(allocator, dl_url, &.{}, "60", proxy) catch |err| {
        log.warn("downloadTelegramFile: file download failed: {}", .{err});
        return null;
    };
    defer allocator.free(data);

    // 3. Determine filename: prefer original file_name, fall back to file_id + extension
    const tmp_dir = platform.getTempDir(allocator) catch return null;
    defer allocator.free(tmp_dir);
    var path_buf: [512]u8 = undefined;
    var path_fbs = std.io.fixedBufferStream(&path_buf);

    if (file_name) |fname| {
        var name_buf: [256]u8 = undefined;
        const safe_name = sanitizeFilenameComponent(&name_buf, fname, 180);
        // Use first 12 chars of file_id as prefix to prevent collisions
        var safe_id: [12]u8 = undefined;
        const safe_id_part = sanitizeFilenameComponent(&safe_id, file_id, 12);
        const tmp_base = trimTrailingPathSeparators(tmp_dir);
        path_fbs.writer().print("{s}{s}nullclaw_doc_{s}_{s}", .{ tmp_base, pathSeparator(tmp_base), safe_id_part, safe_name }) catch return null;
    } else {
        // Fall back to file_id with extension from tg_file_path
        const ext = if (std.mem.lastIndexOfScalar(u8, tg_file_path, '.')) |dot|
            tg_file_path[dot..]
        else
            "";
        var name_buf: [256]u8 = undefined;
        const safe_name = sanitizeFilenameComponent(&name_buf, file_id, 200);
        const tmp_base = trimTrailingPathSeparators(tmp_dir);
        path_fbs.writer().print("{s}{s}nullclaw_doc_{s}{s}", .{ tmp_base, pathSeparator(tmp_base), safe_name, ext }) catch return null;
    }
    const local_path = path_fbs.getWritten();

    // Write file
    const file = std.fs.createFileAbsolute(local_path, .{}) catch |err| {
        log.warn("downloadTelegramFile: file create failed: {}", .{err});
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
// Additional Telegram tests.
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

test "telegram typing handles start empty" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    try std.testing.expect(ch.typing_handles.get("12345") == null);
}

test "telegram startTyping stores handle and stopTyping clears it" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.stopAllTyping();

    try ch.startTyping("12345");
    try std.testing.expect(ch.typing_handles.get("12345") != null);
    std.Thread.sleep(20 * std.time.ns_per_ms);
    try ch.stopTyping("12345");
    try std.testing.expect(ch.typing_handles.get("12345") == null);
}

test "telegram stopTyping is idempotent" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    try ch.stopTyping("12345");
    try ch.stopTyping("12345");
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

test "telegram sanitizeFilenameComponent replaces Windows-invalid chars" {
    var buf: [64]u8 = undefined;
    const sanitized = sanitizeFilenameComponent(&buf, "report:Q1*?.txt ", 64);
    try std.testing.expectEqualStrings("report_Q1__.txt", sanitized);
}

test "telegram sanitizeFilenameComponent avoids Windows reserved names" {
    var buf: [32]u8 = undefined;
    const con_name = sanitizeFilenameComponent(&buf, "CON", 32);
    try std.testing.expectEqualStrings("_CON", con_name);

    var buf2: [32]u8 = undefined;
    const lpt_name = sanitizeFilenameComponent(&buf2, "LPT1.txt", 32);
    try std.testing.expectEqualStrings("_LPT1.txt", lpt_name);
}

test "telegram trimTrailingPathSeparators removes trailing slash from tmpdir" {
    const trimmed = trimTrailingPathSeparators("/var/folders/a/b/T/");
    try std.testing.expectEqualStrings("/var/folders/a/b/T", trimmed);
}

test "telegram trimTrailingPathSeparators keeps root slash" {
    const trimmed = trimTrailingPathSeparators("/");
    try std.testing.expectEqualStrings("/", trimmed);
}

test "telegram pathSeparator avoids duplicate slash" {
    try std.testing.expectEqualStrings("/", pathSeparator("/var/folders/a/b/T"));
    try std.testing.expectEqualStrings("", pathSeparator("/var/folders/a/b/T/"));
}

// ════════════════════════════════════════════════════════════════════════════
// Document Handling Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram parseAttachmentMarkers FILE with caption" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[FILE:/tmp/nullclaw_doc_report.docx] Вот документ",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[0].kind);
    try std.testing.expectEqualStrings("/tmp/nullclaw_doc_report.docx", parsed.attachments[0].target);
}

test "telegram parseAttachmentMarkers multiple FILE markers" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[FILE:/tmp/a.docx]\n[FILE:/tmp/b.csv]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[0].kind);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[1].kind);
    try std.testing.expectEqualStrings("/tmp/a.docx", parsed.attachments[0].target);
    try std.testing.expectEqualStrings("/tmp/b.csv", parsed.attachments[1].target);
}

test "telegram parseAttachmentMarkers mixed FILE and IMAGE" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[IMAGE:/tmp/photo.jpg]\n[FILE:/tmp/doc.pdf] описание",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
    try std.testing.expectEqual(AttachmentKind.document, parsed.attachments[1].kind);
}

test "telegram inferAttachmentKindFromExtension docx is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/report.docx"));
}

test "telegram inferAttachmentKindFromExtension csv is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/data.csv"));
}

test "telegram inferAttachmentKindFromExtension xlsx is document" {
    try std.testing.expectEqual(AttachmentKind.document, inferAttachmentKindFromExtension("/tmp/sheet.xlsx"));
}

test "telegram media group content merging" {
    // Simulate media group merging: two FILE markers from same group
    // should be concatenated with newline separator.
    const alloc = std.testing.allocator;
    const content1 = try alloc.dupe(u8, "[FILE:/tmp/a.docx]");
    defer alloc.free(content1);
    const content2 = try alloc.dupe(u8, "[FILE:/tmp/b.csv] Вот файлы");
    defer alloc.free(content2);

    // Merged content should contain both markers
    var merged: std.ArrayListUnmanaged(u8) = .empty;
    defer merged.deinit(alloc);
    try merged.appendSlice(alloc, content1);
    try merged.appendSlice(alloc, "\n");
    try merged.appendSlice(alloc, content2);

    // Verify merged content parses correctly
    const parsed = try parseAttachmentMarkers(alloc, merged.items);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqualStrings("/tmp/a.docx", parsed.attachments[0].target);
    try std.testing.expectEqualStrings("/tmp/b.csv", parsed.attachments[1].target);
}

test "telegram media group content merging preserves caption" {
    const alloc = std.testing.allocator;
    // Simulate merged media group: images with caption on last one
    var merged: std.ArrayListUnmanaged(u8) = .empty;
    defer merged.deinit(alloc);
    try merged.appendSlice(alloc, "[IMAGE:/tmp/photo1.jpg]\n[IMAGE:/tmp/photo2.jpg] Опиши эти две картинки");

    const parsed = try parseAttachmentMarkers(alloc, merged.items);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[0].kind);
    try std.testing.expectEqual(AttachmentKind.image, parsed.attachments[1].kind);
}

test "telegram parseAttachmentMarkers FILE with cyrillic filename" {
    const parsed = try parseAttachmentMarkers(
        std.testing.allocator,
        "[FILE:/tmp/nullclaw_doc_Справка_в_школы.docx]",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expectEqualStrings("/tmp/nullclaw_doc_Справка_в_школы.docx", parsed.attachments[0].target);
}

// ════════════════════════════════════════════════════════════════════════════
// mergeMediaGroups Tests
// ════════════════════════════════════════════════════════════════════════════

test "telegram mergeMediaGroups consecutive items" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer messages.deinit(alloc);
    var mgids: std.ArrayListUnmanaged(?[]const u8) = .empty;
    defer {
        for (mgids.items) |mg| if (mg) |s| alloc.free(s);
        mgids.deinit(alloc);
    }

    // Add two messages with same media_group_id
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "123"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/a.docx]"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, try alloc.dupe(u8, "group_1"));

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "123"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/b.csv] caption"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, try alloc.dupe(u8, "group_1"));

    mergeMediaGroups(alloc, &messages, &mgids);

    // Should merge into 1 message
    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expect(std.mem.indexOf(u8, messages.items[0].content, "[FILE:/tmp/a.docx]") != null);
    try std.testing.expect(std.mem.indexOf(u8, messages.items[0].content, "[FILE:/tmp/b.csv] caption") != null);

    // Clean up remaining message
    alloc.free(messages.items[0].id);
    alloc.free(messages.items[0].sender);
    alloc.free(messages.items[0].content);
}

test "telegram mergeMediaGroups interleaved items" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer messages.deinit(alloc);
    var mgids: std.ArrayListUnmanaged(?[]const u8) = .empty;
    defer {
        for (mgids.items) |mg| if (mg) |s| alloc.free(s);
        mgids.deinit(alloc);
    }

    // msg0: group_A
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "123"),
        .content = try alloc.dupe(u8, "[IMAGE:/tmp/photo1.jpg]"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, try alloc.dupe(u8, "group_A"));

    // msg1: no group (standalone text)
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user2"),
        .sender = try alloc.dupe(u8, "456"),
        .content = try alloc.dupe(u8, "Hello!"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, null);

    // msg2: group_A (interleaved)
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "123"),
        .content = try alloc.dupe(u8, "[IMAGE:/tmp/photo2.jpg]"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, try alloc.dupe(u8, "group_A"));

    mergeMediaGroups(alloc, &messages, &mgids);

    // Should merge group_A into 1 message, keep standalone text
    try std.testing.expectEqual(@as(usize, 2), messages.items.len);

    // First message: merged group_A content
    try std.testing.expect(std.mem.indexOf(u8, messages.items[0].content, "[IMAGE:/tmp/photo1.jpg]") != null);
    try std.testing.expect(std.mem.indexOf(u8, messages.items[0].content, "[IMAGE:/tmp/photo2.jpg]") != null);

    // Second message: standalone text
    try std.testing.expectEqualStrings("Hello!", messages.items[1].content);

    // Clean up remaining messages
    for (messages.items) |msg| {
        alloc.free(msg.id);
        alloc.free(msg.sender);
        alloc.free(msg.content);
    }
}

test "telegram mergeConsecutiveMessages handles interleaved chats" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    // Chat 1, part 1
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "Part 1"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 10,
    });
    // Chat 2, isolated message
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user2"),
        .sender = try alloc.dupe(u8, "chat2"),
        .content = try alloc.dupe(u8, "Hello from chat 2"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 50,
    });
    // Chat 1, part 2
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "Part 2"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 11,
    });

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("Part 1\nPart 2", messages.items[0].content);
    try std.testing.expectEqual(@as(i64, 11), messages.items[0].message_id.?);
    try std.testing.expectEqualStrings("Hello from chat 2", messages.items[1].content);
}

test "telegram mergeConsecutiveMessages skips commands" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "/help"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 10,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "some text"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 11,
    });

    mergeConsecutiveMessages(alloc, &messages);

    // Command should NOT be merged
    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("/help", messages.items[0].content);
    try std.testing.expectEqualStrings("some text", messages.items[1].content);
}

test "telegram mergeConsecutiveMessages skips whitespace-padded commands" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, " \t/help"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 10,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "some text"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 11,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "\n/new"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 12,
    });

    mergeConsecutiveMessages(alloc, &messages);

    // Commands should stay isolated even with leading whitespace/newline.
    try std.testing.expectEqual(@as(usize, 3), messages.items.len);
    try std.testing.expectEqualStrings(" \t/help", messages.items[0].content);
    try std.testing.expectEqualStrings("some text", messages.items[1].content);
    try std.testing.expectEqualStrings("\n/new", messages.items[2].content);
}

test "telegram mergeConsecutiveMessages chain merges three parts" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "A"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 1,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "B"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 2,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "C"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 3,
    });

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("A\nB\nC", messages.items[0].content);
    try std.testing.expectEqual(@as(i64, 3), messages.items[0].message_id.?);
}

test "telegram mergeConsecutiveMessages single message no-op" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "Hello"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 42,
    });

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("Hello", messages.items[0].content);
}

test "telegram mergeConsecutiveMessages non-consecutive ids not merged" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "First"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 10,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "Second"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 15, // Gap — not consecutive
    });

    mergeConsecutiveMessages(alloc, &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("First", messages.items[0].content);
    try std.testing.expectEqualStrings("Second", messages.items[1].content);
}

test "telegram mergeConsecutiveMessages allocation failure does not leak" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }

    const large_len = 32 * 1024;
    const large_payload = try alloc.alloc(u8, large_len);
    @memset(large_payload, 'x');

    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = try alloc.dupe(u8, "A"),
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 1,
    });
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "chat1"),
        .content = large_payload,
        .channel = "telegram",
        .timestamp = 0,
        .message_id = 2,
    });

    var failing = std.testing.FailingAllocator.init(alloc, .{});
    // First temp append succeeds; second temp allocation fails.
    failing.fail_index = failing.alloc_index + 1;

    mergeConsecutiveMessages(failing.allocator(), &messages);

    try std.testing.expectEqual(@as(usize, 2), messages.items.len);
    try std.testing.expectEqualStrings("A", messages.items[0].content);
    try std.testing.expectEqual(@as(usize, large_len), messages.items[1].content.len);
    try std.testing.expectEqual(@as(u8, 'x'), messages.items[1].content[0]);
}

test "telegram mergeMediaGroups single item no merge" {
    const alloc = std.testing.allocator;
    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer messages.deinit(alloc);
    var mgids: std.ArrayListUnmanaged(?[]const u8) = .empty;
    defer {
        for (mgids.items) |mg| if (mg) |s| alloc.free(s);
        mgids.deinit(alloc);
    }

    // Single message with media_group_id (the group has only one item)
    try messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user1"),
        .sender = try alloc.dupe(u8, "123"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/doc.pdf]"),
        .channel = "telegram",
        .timestamp = 0,
    });
    try mgids.append(alloc, try alloc.dupe(u8, "group_solo"));

    mergeMediaGroups(alloc, &messages, &mgids);

    // Should not merge — still 1 message
    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("[FILE:/tmp/doc.pdf]", messages.items[0].content);

    // Clean up
    alloc.free(messages.items[0].id);
    alloc.free(messages.items[0].sender);
    alloc.free(messages.items[0].content);
}

test "telegram flushMaturedPendingMediaGroups flushes only mature groups" {
    const alloc = std.testing.allocator;
    var ch = TelegramChannel.init(alloc, "123:ABC", &.{"*"}, &.{}, "allowlist");

    const now = root.nowEpochSecs();

    try ch.pending_media_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-a"),
        .sender = try alloc.dupe(u8, "chat-a"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/a.pdf]"),
        .channel = "telegram",
        .timestamp = now - 10,
    });
    try ch.pending_media_group_ids.append(alloc, try alloc.dupe(u8, "group-a"));
    try ch.pending_media_received_at.append(alloc, now - 10);

    try ch.pending_media_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-b"),
        .sender = try alloc.dupe(u8, "chat-b"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/b.pdf]"),
        .channel = "telegram",
        .timestamp = now,
    });
    try ch.pending_media_group_ids.append(alloc, try alloc.dupe(u8, "group-b"));
    try ch.pending_media_received_at.append(alloc, now);

    var out_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (out_messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        out_messages.deinit(alloc);
    }
    var out_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty;
    defer {
        for (out_group_ids.items) |mg| if (mg) |s| alloc.free(s);
        out_group_ids.deinit(alloc);
    }

    ch.flushMaturedPendingMediaGroups(alloc, &out_messages, &out_group_ids);

    try std.testing.expectEqual(@as(usize, 1), out_messages.items.len);
    try std.testing.expect(std.mem.indexOf(u8, out_messages.items[0].content, "/tmp/a.pdf") != null);
    try std.testing.expectEqual(@as(usize, 1), ch.pending_media_messages.items.len);
    try std.testing.expectEqualStrings("group-b", ch.pending_media_group_ids.items[0].?);
    try std.testing.expectEqual(@as(u64, now), ch.pending_media_received_at.items[0]);

    ch.resetPendingMediaBuffers();
    ch.pending_media_messages.deinit(alloc);
    ch.pending_media_group_ids.deinit(alloc);
    ch.pending_media_received_at.deinit(alloc);
}

test "telegram persistableUpdateOffset waits until pending media flushes" {
    const alloc = std.testing.allocator;
    var ch = TelegramChannel.init(alloc, "123:ABC", &.{"*"}, &.{}, "allowlist");

    ch.last_update_id = 42;
    try std.testing.expectEqual(@as(?i64, 42), ch.persistableUpdateOffset());

    const now = root.nowEpochSecs();
    try ch.pending_media_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-a"),
        .sender = try alloc.dupe(u8, "chat-a"),
        .content = try alloc.dupe(u8, "[FILE:/tmp/a.pdf]"),
        .channel = "telegram",
        .timestamp = now,
    });
    try ch.pending_media_group_ids.append(alloc, try alloc.dupe(u8, "group-a"));
    try ch.pending_media_received_at.append(alloc, now);

    try std.testing.expect(ch.persistableUpdateOffset() == null);

    ch.resetPendingMediaBuffers();
    ch.pending_media_messages.deinit(alloc);
    ch.pending_media_group_ids.deinit(alloc);
    ch.pending_media_received_at.deinit(alloc);
}

test "telegram processUpdate falls back to caption when text is absent" {
    const alloc = std.testing.allocator;
    var ch = TelegramChannel.init(alloc, "123:ABC", &.{"*"}, &.{}, "allowlist");

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        \\{
        \\  "update_id": 1,
        \\  "message": {
        \\    "message_id": 42,
        \\    "from": {"id": 1001, "username": "tester", "first_name": "Test"},
        \\    "chat": {"id": 2002, "type": "private"},
        \\    "caption": "caption-only fallback"
        \\  }
        \\}
    ,
        .{},
    );
    defer parsed.deinit();

    var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
    defer {
        for (messages.items) |msg| {
            var tmp = msg;
            tmp.deinit(alloc);
        }
        messages.deinit(alloc);
    }
    var media_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty;
    defer {
        for (media_group_ids.items) |mg| if (mg) |s| alloc.free(s);
        media_group_ids.deinit(alloc);
    }

    ch.processUpdate(alloc, parsed.value, &messages, &media_group_ids);

    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings("caption-only fallback", messages.items[0].content);
}

test "telegram nextPendingMediaDeadline returns earliest group deadline" {
    const group_ids = [_]?[]const u8{
        "group-a",
        "group-a",
        "group-b",
        null,
        "group-b",
    };
    const received_at = [_]u64{
        10,
        12,
        5,
        100,
        7,
    };

    const deadline = nextPendingMediaDeadline(group_ids[0..], received_at[0..]);
    try std.testing.expect(deadline != null);
    try std.testing.expectEqual(@as(u64, 10), deadline.?); // group-b latest=7 => 7+3
}

test "telegram sweepTempMediaFilesInDir removes only stale nullclaw temp media files" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "nullclaw_doc_old.txt", .data = "doc" });
    try tmp_dir.dir.writeFile(.{ .sub_path = "nullclaw_photo_old.jpg", .data = "photo" });
    try tmp_dir.dir.writeFile(.{ .sub_path = "keep.txt", .data = "keep" });

    const abs_tmp = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs_tmp);

    // TTL < 0 forces matched temp files to be treated as stale for test determinism.
    sweepTempMediaFilesInDir(abs_tmp, std.time.timestamp(), -1);

    const keep_stat = try tmp_dir.dir.statFile("keep.txt");
    try std.testing.expect(keep_stat.size > 0);

    const doc_stat = tmp_dir.dir.statFile("nullclaw_doc_old.txt");
    try std.testing.expectError(error.FileNotFound, doc_stat);

    const photo_stat = tmp_dir.dir.statFile("nullclaw_photo_old.jpg");
    try std.testing.expectError(error.FileNotFound, photo_stat);
}

test "telegram resolveAttachmentPath expands tilde path" {
    const allocator = std.testing.allocator;
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);

    const input = if (comptime builtin.os.tag == .windows) "~\\docs\\report.txt" else "~/docs/report.txt";
    const suffix = if (comptime builtin.os.tag == .windows) "docs\\report.txt" else "docs/report.txt";
    const expected = try std.fs.path.join(allocator, &.{ home, suffix });
    defer allocator.free(expected);

    const resolved = try TelegramChannel.resolveAttachmentPath(allocator, input);
    defer resolved.deinit(allocator);

    try std.testing.expect(resolved.owned != null);
    try std.testing.expectEqualStrings(expected, resolved.path);
}

test "telegram resolveAttachmentPath keeps absolute local path unchanged" {
    const allocator = std.testing.allocator;
    const input = if (comptime builtin.os.tag == .windows) "C:\\tmp\\a.txt" else "/tmp/a.txt";

    const resolved = try TelegramChannel.resolveAttachmentPath(allocator, input);
    defer resolved.deinit(allocator);

    try std.testing.expect(resolved.owned == null);
    try std.testing.expectEqualStrings(input, resolved.path);
}

test "telegram bot command payload includes memory and doctor commands" {
    try std.testing.expect(std.mem.indexOf(u8, TELEGRAM_BOT_COMMANDS_JSON, "\"command\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, TELEGRAM_BOT_COMMANDS_JSON, "\"command\":\"doctor\"") != null);
}
