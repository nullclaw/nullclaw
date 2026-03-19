const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const voice = @import("../voice.zig");
const platform = @import("../platform.zig");
const config_types = @import("../config_types.zig");
const control_plane = @import("../control_plane.zig");
const interaction_choices = @import("../interactions/choices.zig");
const streaming = @import("../streaming.zig");
const telegram_api = @import("telegram_api.zig");
const telegram_draft_presenter = @import("telegram_draft_presenter.zig");
const telegram_ingress = @import("telegram_ingress.zig");
const telegram_update_ingress = @import("telegram_update_ingress.zig");
const thread_stacks = @import("../thread_stacks.zig");
const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.telegram);
const MEDIA_GROUP_FLUSH_SECS: u64 = 3;
const TEMP_MEDIA_SWEEP_INTERVAL_POLLS: u32 = 20;
const TEMP_MEDIA_TTL_SECS: i64 = 24 * 60 * 60;
const TOPIC_TARGET_SEPARATOR = "#topic:";

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

const OwnedOutboundPayload = struct {
    text: []u8,
    attachments: []root.Channel.OutboundAttachment,
    choices: []root.Channel.OutboundChoice,

    fn deinit(self: *OwnedOutboundPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
        for (self.attachments) |attachment| {
            allocator.free(attachment.target);
            if (attachment.caption) |caption| allocator.free(caption);
        }
        allocator.free(self.attachments);
        for (self.choices) |choice| {
            allocator.free(choice.id);
            allocator.free(choice.label);
            allocator.free(choice.submit_text);
        }
        allocator.free(self.choices);
    }

    fn payload(self: *const OwnedOutboundPayload) root.Channel.OutboundPayload {
        return .{
            .text = self.text,
            .attachments = self.attachments,
            .choices = self.choices,
        };
    }
};

const PendingInteractionOption = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    fn deinit(self: *const PendingInteractionOption, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

const PendingInteraction = struct {
    created_at: u64,
    expires_at: u64,
    chat_id: []const u8,
    owner_identity: ?[]const u8 = null,
    owner_only: bool = false,
    remove_on_click: bool = true,
    message_id: ?i64 = null,
    options: []PendingInteractionOption,

    fn deinit(self: *const PendingInteraction, allocator: std.mem.Allocator) void {
        allocator.free(self.chat_id);
        if (self.owner_identity) |owner| allocator.free(owner);
        for (self.options) |opt| opt.deinit(allocator);
        allocator.free(self.options);
    }
};

const DraftState = telegram_draft_presenter.DraftState;

const ParsedTelegramTarget = struct {
    chat_id: []const u8,
    message_thread_id: ?i64 = null,
};

pub const TaskReaction = enum {
    accepted,
    running,
    done,
    failed,
};

fn parseTelegramTarget(target: []const u8) ParsedTelegramTarget {
    const sep = std.mem.lastIndexOf(u8, target, TOPIC_TARGET_SEPARATOR) orelse return .{ .chat_id = target };
    const chat_id = target[0..sep];
    const thread_raw = target[sep + TOPIC_TARGET_SEPARATOR.len ..];
    if (chat_id.len == 0 or thread_raw.len == 0) return .{ .chat_id = target };
    const thread_id = std.fmt.parseInt(i64, thread_raw, 10) catch return .{ .chat_id = target };
    return .{
        .chat_id = chat_id,
        .message_thread_id = if (thread_id > 0) thread_id else null,
    };
}

pub fn targetChatId(target: []const u8) []const u8 {
    return parseTelegramTarget(target).chat_id;
}

pub fn targetThreadId(target: []const u8) ?i64 {
    return parseTelegramTarget(target).message_thread_id;
}

fn dupTelegramTarget(allocator: std.mem.Allocator, chat_id: []const u8, message_thread_id: ?i64) ![]u8 {
    if (message_thread_id) |thread_id| {
        return std.fmt.allocPrint(allocator, "{s}{s}{d}", .{ chat_id, TOPIC_TARGET_SEPARATOR, thread_id });
    }
    return allocator.dupe(u8, chat_id);
}

fn countUtf8Codepoints(text: []const u8) !usize {
    var i: usize = 0;
    var count: usize = 0;
    while (i < text.len) {
        const seq_len = try std.unicode.utf8ByteSequenceLength(text[i]);
        if (i + seq_len > text.len) return error.InvalidUtf8;
        _ = try std.unicode.utf8Decode(text[i .. i + seq_len]);
        i += seq_len;
        count += 1;
    }
    return count;
}

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

fn to_root_attachment_kind(kind: AttachmentKind) root.Channel.OutboundAttachmentKind {
    return switch (kind) {
        .image => .image,
        .document => .document,
        .video => .video,
        .audio => .audio,
        .voice => .voice,
    };
}

fn from_root_attachment_kind(kind: root.Channel.OutboundAttachmentKind) AttachmentKind {
    return switch (kind) {
        .image => .image,
        .document => .document,
        .video => .video,
        .audio => .audio,
        .voice => .voice,
    };
}

fn buildChoicesDirectiveFromPayload(
    allocator: std.mem.Allocator,
    choices: []const root.Channel.OutboundChoice,
) !interaction_choices.ChoicesDirective {
    if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) {
        return error.InvalidChoices;
    }

    var options = try allocator.alloc(interaction_choices.ChoiceOption, choices.len);
    var built: usize = 0;
    errdefer {
        for (options[0..built]) |opt| opt.deinit(allocator);
        allocator.free(options);
    }

    for (choices, 0..) |choice, i| {
        if (choice.id.len == 0 or choice.id.len > interaction_choices.MAX_ID_LEN) return error.InvalidChoices;
        if (choice.label.len == 0 or choice.label.len > interaction_choices.MAX_LABEL_LEN) return error.InvalidChoices;
        if (choice.submit_text.len == 0 or choice.submit_text.len > interaction_choices.MAX_SUBMIT_TEXT_LEN) return error.InvalidChoices;

        options[i] = .{
            .id = try allocator.dupe(u8, choice.id),
            .label = try allocator.dupe(u8, choice.label),
            .submit_text = try allocator.dupe(u8, choice.submit_text),
        };
        built += 1;
    }

    return .{
        .version = 1,
        .options = options,
    };
}

fn buildOwnedOutboundPayloadFromLegacy(
    allocator: std.mem.Allocator,
    text: []const u8,
    media: []const []const u8,
    allow_choices: bool,
) !OwnedOutboundPayload {
    var parsed_choices = try interaction_choices.parseAssistantChoices(allocator, text);
    defer parsed_choices.deinit(allocator);

    const parsed = try parseAttachmentMarkers(allocator, parsed_choices.visible_text);
    defer parsed.deinit(allocator);

    const choices_enabled = allow_choices and parsed_choices.choices != null and parsed.attachments.len == 0 and media.len == 0;
    const attachments_len = parsed.attachments.len + media.len;
    var attachments = try allocator.alloc(root.Channel.OutboundAttachment, attachments_len);
    var built_attachments: usize = 0;
    errdefer {
        for (attachments[0..built_attachments]) |attachment| {
            allocator.free(attachment.target);
            if (attachment.caption) |caption| allocator.free(caption);
        }
        allocator.free(attachments);
    }

    for (parsed.attachments, 0..) |attachment, i| {
        attachments[i] = .{
            .kind = to_root_attachment_kind(attachment.kind),
            .target = try allocator.dupe(u8, attachment.target),
            .caption = if (attachment.caption) |caption| try allocator.dupe(u8, caption) else null,
        };
        built_attachments += 1;
    }
    for (media, 0..) |item, i| {
        attachments[parsed.attachments.len + i] = .{
            .kind = to_root_attachment_kind(inferAttachmentKindFromExtension(item)),
            .target = try allocator.dupe(u8, item),
            .caption = null,
        };
        built_attachments += 1;
    }

    const choices = if (choices_enabled)
        try allocator.alloc(root.Channel.OutboundChoice, parsed_choices.choices.?.options.len)
    else
        try allocator.alloc(root.Channel.OutboundChoice, 0);
    var built_choices: usize = 0;
    errdefer {
        for (choices[0..built_choices]) |choice| {
            allocator.free(choice.id);
            allocator.free(choice.label);
            allocator.free(choice.submit_text);
        }
        allocator.free(choices);
    }

    if (choices_enabled) {
        for (parsed_choices.choices.?.options, 0..) |choice, i| {
            choices[i] = .{
                .id = try allocator.dupe(u8, choice.id),
                .label = try allocator.dupe(u8, choice.label),
                .submit_text = try allocator.dupe(u8, choice.submit_text),
            };
            built_choices += 1;
        }
    }

    return .{
        .text = try allocator.dupe(u8, parsed.remaining_text),
        .attachments = attachments,
        .choices = choices,
    };
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
    interactive: config_types.TelegramInteractiveConfig = .{},
    transcriber: ?voice.Transcriber = null,
    last_update_id: i64,
    proxy: ?[]const u8,

    bot_username: ?[]const u8 = null,
    bot_user_id: ?i64 = null,
    require_mention: bool = false,

    // Pending media group messages (buffered across poll cycles until group is complete)
    pending_media_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty,
    pending_media_group_ids: std.ArrayListUnmanaged(?[]const u8) = .empty,
    pending_media_received_at: std.ArrayListUnmanaged(u64) = .empty,
    pending_text_messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty,
    pending_text_received_at: std.ArrayListUnmanaged(u64) = .empty,
    polls_since_temp_sweep: u32 = 0,

    typing_mu: std.Thread.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,
    interaction_mu: std.Thread.Mutex = .{},
    pending_interactions: std.StringHashMapUnmanaged(PendingInteraction) = .empty,
    interaction_seq: Atomic(u64) = Atomic(u64).init(1),

    draft_mu: std.Thread.Mutex = .{},
    draft_send_mu: std.Thread.Mutex = .{},
    draft_buffers: std.StringHashMapUnmanaged(DraftState) = .empty,
    draft_target_suppress_until_ms: std.StringHashMapUnmanaged(i64) = .empty,
    draft_id_counter: Atomic(u64) = Atomic(u64).init(1),
    draft_global_suppress_until_ms: i64 = 0,
    streaming_enabled: bool = true,
    status_reactions_enabled: bool = false,
    reaction_emojis: config_types.TelegramReactionEmojisConfig = .{},
    binding_commands_enabled: bool = true,
    topic_commands_enabled: bool = true,
    topic_map_command_enabled: bool = true,
    commands_menu_mode: config_types.TelegramCommandsMenuMode = .flat,

    pub const MAX_MESSAGE_LEN: usize = 4096;
    const CONTINUATION_MARKER = "\n\n\u{23EC}";
    const MIN_ADAPTIVE_SPLIT_LIMIT: usize = 256;
    const TYPING_INTERVAL_NS: u64 = 4 * std.time.ns_per_s;
    const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;

    const OutgoingTextChunk = struct {
        body: []const u8,
        owned: ?[]u8 = null,

        fn deinit(self: *const OutgoingTextChunk, allocator: std.mem.Allocator) void {
            if (self.owned) |buf| allocator.free(buf);
        }
    };

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
        ch.interactive = cfg.interactive;
        ch.require_mention = cfg.require_mention;
        ch.streaming_enabled = cfg.streaming;
        ch.status_reactions_enabled = cfg.status_reactions;
        ch.reaction_emojis = cfg.reaction_emojis;
        ch.binding_commands_enabled = cfg.binding_commands_enabled;
        ch.topic_commands_enabled = cfg.topic_commands_enabled;
        ch.topic_map_command_enabled = cfg.topic_map_command_enabled;
        ch.commands_menu_mode = cfg.commands_menu_mode;
        return ch;
    }

    pub fn channelName(_: *TelegramChannel) []const u8 {
        return "telegram";
    }

    fn api(self: *const TelegramChannel) telegram_api.Client {
        return .{
            .allocator = self.allocator,
            .bot_token = self.bot_token,
            .proxy = self.proxy,
        };
    }

    /// Build the Telegram API URL for a method.
    pub fn apiUrl(self: *const TelegramChannel, buf: []u8, method: []const u8) ![]const u8 {
        return self.api().apiUrl(buf, method);
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
        var matched = false;
        var wildcard_seen = false;
        for (self.allow_from) |a| {
            if (std.mem.eql(u8, a, "*")) {
                wildcard_seen = true;
                continue;
            }
            // Strip leading "@" from allowlist entry.
            const trimmed = if (a.len > 1 and a[0] == '@') a[1..] else a;
            // Case-insensitive: Telegram usernames are case-insensitive
            if (std.ascii.eqlIgnoreCase(trimmed, sender)) matched = true;
        }
        if (wildcard_seen) {
            root.warnWildcardAllowAll("telegram channel");
            return true;
        }
        return matched;
    }

    /// Check if any of the given identities (username, user_id) is allowed.
    pub fn isAnyIdentityAllowed(self: *const TelegramChannel, identities: []const []const u8) bool {
        for (identities) |id| {
            if (self.isUserAllowed(id)) return true;
        }
        return false;
    }

    pub fn isGroupUserAllowed(self: *const TelegramChannel, sender: []const u8) bool {
        var matched = false;
        var wildcard_seen = false;
        for (self.group_allow_from) |a| {
            if (std.mem.eql(u8, a, "*")) {
                wildcard_seen = true;
                continue;
            }
            const trimmed = if (a.len > 1 and a[0] == '@') a[1..] else a;
            if (std.ascii.eqlIgnoreCase(trimmed, sender)) matched = true;
        }
        if (wildcard_seen) {
            root.warnWildcardAllowAll("telegram channel");
            return true;
        }
        return matched;
    }

    pub fn isAnyGroupIdentityAllowed(self: *const TelegramChannel, identities: []const []const u8) bool {
        for (identities) |id| {
            if (self.isGroupUserAllowed(id)) return true;
        }
        return false;
    }

    fn isAuthorizedIdentity(
        self: *const TelegramChannel,
        is_group: bool,
        username: []const u8,
        user_id: ?[]const u8,
    ) bool {
        var ids_buf: [2][]const u8 = undefined;
        var ids_len: usize = 0;
        ids_buf[ids_len] = username;
        ids_len += 1;
        if (user_id) |uid| {
            ids_buf[ids_len] = uid;
            ids_len += 1;
        }

        if (is_group) {
            if (std.mem.eql(u8, self.group_policy, "open")) return true;
            if (std.mem.eql(u8, self.group_policy, "disabled")) return false;

            if (self.group_allow_from.len > 0) {
                return self.isAnyGroupIdentityAllowed(ids_buf[0..ids_len]);
            }
            return self.isAnyIdentityAllowed(ids_buf[0..ids_len]);
        }

        return self.isAnyIdentityAllowed(ids_buf[0..ids_len]);
    }

    pub fn healthCheck(self: *TelegramChannel) bool {
        return self.api().getMeOk();
    }

    const Utf16ByteRange = struct {
        start: usize,
        end: usize,
    };

    fn utf16RangeToByteRange(text: []const u8, utf16_offset: usize, utf16_length: usize) ?Utf16ByteRange {
        const utf16_end = std.math.add(usize, utf16_offset, utf16_length) catch return null;
        var byte_index: usize = 0;
        var utf16_pos: usize = 0;
        var start_byte: ?usize = null;
        var end_byte: ?usize = null;

        while (byte_index < text.len) {
            if (start_byte == null and utf16_pos == utf16_offset) start_byte = byte_index;
            if (end_byte == null and utf16_pos == utf16_end) {
                end_byte = byte_index;
                break;
            }

            const cp_len = std.unicode.utf8ByteSequenceLength(text[byte_index]) catch return null;
            if (byte_index + cp_len > text.len) return null;
            const cp = std.unicode.utf8Decode(text[byte_index..][0..cp_len]) catch return null;
            utf16_pos += if (cp > 0xFFFF) 2 else 1;
            byte_index += cp_len;
        }

        if (start_byte == null and utf16_pos == utf16_offset) start_byte = byte_index;
        if (end_byte == null and utf16_pos == utf16_end) end_byte = byte_index;
        if (start_byte == null or end_byte == null) return null;
        if (end_byte.? < start_byte.?) return null;

        return .{
            .start = start_byte.?,
            .end = end_byte.?,
        };
    }

    fn containsMentionInEntitySet(
        message: std.json.Value,
        entities_key: []const u8,
        text_key: []const u8,
        bot_name: []const u8,
        bot_user_id: ?i64,
    ) bool {
        const entities_val = message.object.get(entities_key) orelse return false;
        if (entities_val != .array) return false;

        const text_val = message.object.get(text_key) orelse return false;
        const text = if (text_val == .string) text_val.string else return false;

        for (entities_val.array.items) |entity| {
            if (entity != .object) continue;

            const type_val = entity.object.get("type") orelse continue;
            const entity_type = if (type_val == .string) type_val.string else continue;

            if (std.mem.eql(u8, entity_type, "mention")) {
                const offset_val = entity.object.get("offset") orelse continue;
                const length_val = entity.object.get("length") orelse continue;
                if (offset_val != .integer or length_val != .integer) continue;
                if (offset_val.integer < 0 or length_val.integer <= 0) continue;

                const offset: usize = @intCast(offset_val.integer);
                const length: usize = @intCast(length_val.integer);
                const byte_range = utf16RangeToByteRange(text, offset, length) orelse continue;
                if (byte_range.end <= byte_range.start) continue;

                const mention_with_at = text[byte_range.start..byte_range.end];
                const mention = if (mention_with_at.len > 0 and mention_with_at[0] == '@')
                    mention_with_at[1..]
                else
                    mention_with_at;

                if (std.ascii.eqlIgnoreCase(mention, bot_name)) {
                    return true;
                }
            }

            if (std.mem.eql(u8, entity_type, "text_mention")) {
                const user_val = entity.object.get("user") orelse continue;
                if (user_val != .object) continue;
                if (user_val.object.get("username")) |username_val| {
                    if (username_val == .string and std.ascii.eqlIgnoreCase(username_val.string, bot_name)) {
                        return true;
                    }
                }
                if (bot_user_id) |bot_id| {
                    if (user_val.object.get("id")) |id_val| {
                        if (id_val == .integer and id_val.integer == bot_id) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /// Fetch and cache the bot's username from Telegram API.
    fn fetchBotUsername(self: *TelegramChannel) void {
        if (self.bot_username != null) return;
        if (builtin.is_test) return;
        const identity = self.api().fetchBotIdentity(self.allocator) orelse return;
        self.bot_user_id = identity.user_id;
        self.bot_username = identity.username;
    }

    /// Check if the bot should process this message based on mention requirements.
    /// In private chats, always returns true.
    /// In groups, returns true only if:
    ///   - require_mention is false, OR
    ///   - the bot is @mentioned in the message
    pub fn shouldProcessMessage(self: *TelegramChannel, message: std.json.Value) bool {
        const chat_val = message.object.get("chat") orelse return true;
        if (chat_val != .object) return true;
        const chat = chat_val.object;
        const chat_type_val = chat.get("type") orelse return true;
        const chat_type = if (chat_type_val == .string) chat_type_val.string else return true;

        // In private chats, always respond
        if (!std.mem.eql(u8, chat_type, "group") and !std.mem.eql(u8, chat_type, "supergroup")) {
            return true;
        }

        // If mention not required in groups, respond
        if (!self.require_mention) return true;

        // Ensure we have bot username cached
        self.fetchBotUsername();
        // Fail closed: if username is unavailable, do not bypass require_mention.
        const bot_name = self.bot_username orelse return false;

        return containsMentionInEntitySet(message, "entities", "text", bot_name, self.bot_user_id) or
            containsMentionInEntitySet(message, "caption_entities", "caption", bot_name, self.bot_user_id);
    }

    fn setMyCommandsForScope(
        self: *TelegramChannel,
        scope: control_plane.TelegramBotCommandScope,
        include_bind_command: bool,
        include_topic_command: bool,
        include_topics_command: bool,
    ) !void {
        const commands_json = try control_plane.buildTelegramBotCommandsJson(self.allocator, .{
            .scope = scope,
            .include_bind_command = include_bind_command,
            .include_topic_command = include_topic_command,
            .include_topics_command = include_topics_command,
        });
        defer self.allocator.free(commands_json);
        try self.api().setMyCommands(commands_json);
    }

    fn deleteMyCommandsForScope(self: *TelegramChannel, scope: control_plane.TelegramBotCommandScope) !void {
        const body_json = try control_plane.buildTelegramDeleteBotCommandsJson(self.allocator, scope);
        defer self.allocator.free(body_json);
        try self.api().deleteMyCommands(body_json);
    }

    /// Keep Telegram slash-command menus in sync with config.
    pub fn syncCommandsMenu(self: *TelegramChannel) void {
        switch (self.commands_menu_mode) {
            .off => {
                self.deleteMyCommandsForScope(.default) catch |err| {
                    log.warn("deleteMyCommands(default) failed: {}", .{err});
                };
                self.deleteMyCommandsForScope(.all_private_chats) catch |err| {
                    log.warn("deleteMyCommands(all_private_chats) failed: {}", .{err});
                };
                self.deleteMyCommandsForScope(.all_group_chats) catch |err| {
                    log.warn("deleteMyCommands(all_group_chats) failed: {}", .{err});
                };
            },
            .flat => {
                self.setMyCommandsForScope(.default, self.binding_commands_enabled, self.topic_commands_enabled, self.topic_map_command_enabled) catch |err| {
                    log.warn("setMyCommands(default) failed: {}", .{err});
                };
                self.deleteMyCommandsForScope(.all_private_chats) catch |err| {
                    log.warn("deleteMyCommands(all_private_chats) failed: {}", .{err});
                };
                self.deleteMyCommandsForScope(.all_group_chats) catch |err| {
                    log.warn("deleteMyCommands(all_group_chats) failed: {}", .{err});
                };
            },
            .scoped => {
                self.setMyCommandsForScope(.all_private_chats, self.binding_commands_enabled, false, false) catch |err| {
                    log.warn("setMyCommands(all_private_chats) failed: {}", .{err});
                };
                self.setMyCommandsForScope(.all_group_chats, self.binding_commands_enabled, self.topic_commands_enabled, self.topic_map_command_enabled) catch |err| {
                    log.warn("setMyCommands(all_group_chats) failed: {}", .{err});
                };
                self.deleteMyCommandsForScope(.default) catch |err| {
                    log.warn("deleteMyCommands(default) failed: {}", .{err});
                };
            },
        }
    }

    /// Disable webhook mode before polling, preserving queued updates.
    pub fn deleteWebhookKeepPending(self: *TelegramChannel) void {
        self.api().deleteWebhookKeepPending() catch |err| {
            log.warn("deleteWebhook failed: {}", .{err});
            return;
        };
    }

    /// Skip all pending updates accumulated while bot was offline.
    /// Fetches with offset=-1 to get only the latest update, then advances past it.
    pub fn dropPendingUpdates(self: *TelegramChannel) void {
        self.last_update_id = self.api().latestUpdateNextOffset(self.allocator) orelse return;
    }

    /// Return an offset safe to persist across restarts.
    /// If media-group updates are still buffered in-memory, persisting a newer
    /// offset can skip those updates after restart, so return null until flushed.
    pub fn persistableUpdateOffset(self: *const TelegramChannel) ?i64 {
        if (self.pending_media_messages.items.len == 0 and self.pending_text_messages.items.len == 0) {
            return self.last_update_id;
        }
        return null;
    }

    // ── Typing indicator ────────────────────────────────────────────

    /// Send a "typing" chat action. Best-effort: errors are ignored.
    pub fn sendTypingIndicator(self: *TelegramChannel, target: []const u8) void {
        if (builtin.is_test) return;
        if (target.len == 0) return;
        const parsed_target = parseTelegramTarget(target);
        self.api().sendTypingIndicator(parsed_target.chat_id, parsed_target.message_thread_id) catch return;
    }

    pub fn setTaskReaction(self: *TelegramChannel, target: []const u8, message_id: ?i64, reaction: TaskReaction) void {
        if (!self.status_reactions_enabled or target.len == 0) return;
        const msg_id = message_id orelse return;
        var message_id_buf: [32]u8 = undefined;
        const message_id_text = std.fmt.bufPrint(&message_id_buf, "{d}", .{msg_id}) catch return;
        self.channel().setReaction(.{
            .target = target,
            .message_id = message_id_text,
            .emoji = self.taskReactionEmoji(reaction),
        }) catch |err| {
            log.debug("telegram setMessageReaction failed: {}", .{err});
        };
    }

    fn taskReactionEmoji(self: *const TelegramChannel, reaction: TaskReaction) ?[]const u8 {
        const emoji = switch (reaction) {
            .accepted => self.reaction_emojis.accepted,
            .running => self.reaction_emojis.running,
            .done => self.reaction_emojis.done,
            .failed => self.reaction_emojis.failed,
        };
        return if (emoji.len == 0) null else emoji;
    }

    fn setReaction(self: *TelegramChannel, update: root.Channel.ReactionUpdate) !void {
        if (update.target.len == 0 or update.message_id.len == 0) return error.InvalidMessageRef;
        const msg_id = std.fmt.parseInt(i64, update.message_id, 10) catch return error.InvalidMessageRef;
        if (!self.status_reactions_enabled) return error.NotSupported;
        if (builtin.is_test) return;

        const parsed_target = parseTelegramTarget(update.target);
        try self.api().setMessageReaction(parsed_target.chat_id, msg_id, update.emoji);
    }

    pub fn createForumTopicFromTarget(self: *TelegramChannel, target: []const u8, name: []const u8) !i64 {
        const trimmed = std.mem.trim(u8, name, " \t\r\n");
        const name_len = try countUtf8Codepoints(trimmed);
        if (name_len == 0 or name_len > 128) return error.InvalidTopicName;

        const parsed_target = parseTelegramTarget(target);
        const topic = try self.api().createForumTopic(self.allocator, parsed_target.chat_id, trimmed);
        return topic.message_thread_id;
    }

    pub fn startTyping(self: *TelegramChannel, chat_id: []const u8) !void {
        _ = try self.startTypingTurn(chat_id);
    }

    pub fn startTypingTurn(self: *TelegramChannel, chat_id: []const u8) !u64 {
        if (chat_id.len == 0) return 0;
        try self.stopTyping(chat_id);

        const draft_id = try self.beginDraftTurn(chat_id);
        errdefer self.finishDraftTurn(chat_id, draft_id) catch {};

        const key_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .chat_id = key_copy,
        };

        task.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
        return draft_id;
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

    fn deinitPendingInteractions(self: *TelegramChannel) void {
        self.interaction_mu.lock();
        var interactions = self.pending_interactions;
        self.pending_interactions = .empty;
        self.interaction_mu.unlock();

        var it = interactions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        interactions.deinit(self.allocator);
    }

    fn typingLoop(task: *TypingTask) void {
        while (!task.stop_requested.load(.acquire)) {
            task.channel.sendTypingIndicator(task.chat_id);
            task.channel.sendDraftHeartbeat(task.chat_id);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std.Thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
        }
    }

    const SentMessageMeta = telegram_api.SentMessageMeta;

    const CallbackSelectionResult = union(enum) {
        ok: struct {
            submit_text: []u8,
            remove_on_click: bool,
            message_id: ?i64,
        },
        not_found,
        expired,
        owner_mismatch,
        chat_mismatch,
        invalid_option,
    };

    fn nextInteractionToken(self: *TelegramChannel) ![]u8 {
        const seq = self.interaction_seq.fetchAdd(1, .monotonic) + 1;
        var buf: [32]u8 = undefined;
        const token = try std.fmt.bufPrint(&buf, "{x}", .{seq});
        return self.allocator.dupe(u8, token);
    }

    fn buildInlineKeyboardJson(
        self: *TelegramChannel,
        directive: interaction_choices.ChoicesDirective,
        token: []const u8,
    ) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "{\"inline_keyboard\":[");
        for (directive.options, 0..) |opt, i| {
            if (i > 0) try out.appendSlice(self.allocator, ",");

            var callback_data_buf: [64]u8 = undefined;
            const callback_data = try interaction_choices.formatChoiceCallbackData(&callback_data_buf, token, opt.id, 64);

            try out.appendSlice(self.allocator, "[{\"text\":");
            try root.json_util.appendJsonString(&out, self.allocator, opt.label);
            try out.appendSlice(self.allocator, ",\"callback_data\":");
            try root.json_util.appendJsonString(&out, self.allocator, callback_data);
            try out.appendSlice(self.allocator, "}]");
        }
        try out.appendSlice(self.allocator, "]}");
        return try out.toOwnedSlice(self.allocator);
    }

    fn registerPendingInteraction(
        self: *TelegramChannel,
        token: []const u8,
        chat_id: []const u8,
        owner_identity: ?[]const u8,
        owner_only: bool,
        remove_on_click: bool,
        message_id: ?i64,
        directive: interaction_choices.ChoicesDirective,
    ) !void {
        var options = try self.allocator.alloc(PendingInteractionOption, directive.options.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }
        for (directive.options, 0..) |opt, i| {
            const id_copy = try self.allocator.dupe(u8, opt.id);
            errdefer self.allocator.free(id_copy);
            const label_copy = try self.allocator.dupe(u8, opt.label);
            errdefer self.allocator.free(label_copy);
            const submit_copy = try self.allocator.dupe(u8, opt.submit_text);
            errdefer self.allocator.free(submit_copy);

            options[i] = .{
                .id = id_copy,
                .label = label_copy,
                .submit_text = submit_copy,
            };
            built += 1;
        }

        const key = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(key);

        const chat_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(chat_copy);

        const owner_copy: ?[]const u8 = if (owner_identity) |owner|
            (try self.allocator.dupe(u8, owner))
        else
            null;
        errdefer if (owner_copy) |owner| self.allocator.free(owner);

        const now = root.nowEpochSecs();
        const ttl = if (self.interactive.ttl_secs == 0) @as(u64, 900) else self.interactive.ttl_secs;
        const pending = PendingInteraction{
            .created_at = now,
            .expires_at = now + ttl,
            .chat_id = chat_copy,
            .owner_identity = owner_copy,
            .owner_only = owner_only,
            .remove_on_click = remove_on_click,
            .message_id = message_id,
            .options = options,
        };

        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();
        try self.pending_interactions.put(self.allocator, key, pending);
    }

    fn cleanupExpiredInteractions(self: *TelegramChannel) void {
        var expired_keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (expired_keys.items) |k| self.allocator.free(k);
            expired_keys.deinit(self.allocator);
        }

        const now = root.nowEpochSecs();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        var it = self.pending_interactions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.expires_at <= now) {
                const key_copy = self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                expired_keys.append(self.allocator, key_copy) catch {
                    self.allocator.free(key_copy);
                };
            }
        }

        for (expired_keys.items) |key| {
            if (self.pending_interactions.fetchRemove(key)) |kv| {
                kv.value.deinit(self.allocator);
                self.allocator.free(kv.key);
            }
        }
    }

    fn consumeCallbackSelection(
        self: *TelegramChannel,
        allocator: std.mem.Allocator,
        token: []const u8,
        option_id: []const u8,
        clicker_identity: []const u8,
        chat_id: []const u8,
    ) !CallbackSelectionResult {
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        const now = root.nowEpochSecs();
        const pending_ptr = self.pending_interactions.getPtr(token) orelse return .not_found;

        if (pending_ptr.expires_at <= now) {
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                kv.value.deinit(self.allocator);
                self.allocator.free(kv.key);
            }
            return .expired;
        }

        if (!std.mem.eql(u8, pending_ptr.chat_id, chat_id)) {
            return .chat_mismatch;
        }

        if (pending_ptr.owner_only) {
            const owner = pending_ptr.owner_identity orelse return .owner_mismatch;
            if (!std.ascii.eqlIgnoreCase(owner, clicker_identity)) {
                return .owner_mismatch;
            }
        }

        for (pending_ptr.options) |opt| {
            if (!std.mem.eql(u8, opt.id, option_id)) continue;

            const submit = try allocator.dupe(u8, opt.submit_text);
            const remove_on_click = pending_ptr.remove_on_click;
            const message_id = pending_ptr.message_id;

            if (self.pending_interactions.fetchRemove(token)) |kv| {
                kv.value.deinit(self.allocator);
                self.allocator.free(kv.key);
            }

            return .{ .ok = .{
                .submit_text = submit,
                .remove_on_click = remove_on_click,
                .message_id = message_id,
            } };
        }

        return .invalid_option;
    }

    fn answerCallbackQuery(self: *TelegramChannel, callback_query_id: []const u8, text: ?[]const u8) void {
        self.api().answerCallbackQuery(callback_query_id, text) catch return;
    }

    fn editMessageReplyMarkupClear(self: *TelegramChannel, chat_id: []const u8, message_id: i64) void {
        self.api().clearReplyMarkup(chat_id, message_id) catch return;
    }

    // ── HTML fallback ────────────────────────────────────────────────

    /// Send text with HTML parse_mode (converted from Markdown); on failure, retry as plain text.
    fn sendWithMarkdownFallbackWithMarkup(
        self: *TelegramChannel,
        target: []const u8,
        text: []const u8,
        reply_to: ?i64,
        reply_markup_json: ?[]const u8,
    ) !SentMessageMeta {
        const parsed_target = parseTelegramTarget(target);

        // Convert Markdown → Telegram HTML
        const html_text = markdownToTelegramHtml(self.allocator, text) catch {
            // Conversion failed — send as plain text
            return try self.sendChunkPlainWithMarkup(target, text, reply_to, reply_markup_json);
        };
        defer self.allocator.free(html_text);

        // Build HTML body
        var html_body: std.ArrayListUnmanaged(u8) = .empty;
        defer html_body.deinit(self.allocator);

        try html_body.appendSlice(self.allocator, "{\"chat_id\":");
        try html_body.appendSlice(self.allocator, parsed_target.chat_id);
        try html_body.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&html_body, self.allocator, html_text);
        try html_body.appendSlice(self.allocator, ",\"parse_mode\":\"HTML\"");
        try telegram_api.appendMessageThreadId(&html_body, self.allocator, parsed_target.message_thread_id);
        try telegram_api.appendReplyTo(&html_body, self.allocator, reply_to);
        try telegram_api.appendRawReplyMarkup(&html_body, self.allocator, reply_markup_json);
        try html_body.appendSlice(self.allocator, "}");

        const resp = self.api().sendMessage(self.allocator, html_body.items, "30") catch {
            // Network error — fall through to plain send
            return try self.sendChunkPlainWithMarkup(target, text, reply_to, reply_markup_json);
        };
        defer self.allocator.free(resp);

        // Check if response indicates error (contains "error_code")
        if (telegram_api.responseHasTelegramError(resp)) {
            // HTML failed, retry as plain text
            return try self.sendChunkPlainWithMarkup(target, text, reply_to, reply_markup_json);
        }

        return telegram_api.parseSentMessageMeta(self.allocator, resp) orelse .{};
    }

    fn sendWithMarkdownFallback(self: *TelegramChannel, target: []const u8, text: []const u8, reply_to: ?i64) !void {
        _ = try self.sendWithMarkdownFallbackWithMarkup(target, text, reply_to, null);
    }

    fn outgoingChunkSplitLimit(text_len: usize, split_limit_override: ?usize) usize {
        if (split_limit_override) |split_limit| {
            const capped = @min(split_limit, MAX_MESSAGE_LEN - CONTINUATION_MARKER.len);
            return if (capped == 0) 1 else capped;
        }
        return if (text_len > MAX_MESSAGE_LEN) MAX_MESSAGE_LEN - CONTINUATION_MARKER.len else MAX_MESSAGE_LEN;
    }

    fn buildOutgoingTextChunksWithLimit(
        allocator: std.mem.Allocator,
        text: []const u8,
        split_limit_override: ?usize,
    ) ![]OutgoingTextChunk {
        if (text.len == 0) return allocator.alloc(OutgoingTextChunk, 0);

        const split_limit = outgoingChunkSplitLimit(text.len, split_limit_override);

        var raw_chunks: std.ArrayListUnmanaged([]const u8) = .empty;
        defer raw_chunks.deinit(allocator);

        var it = smartSplitMessage(text, split_limit);
        while (it.next()) |chunk| {
            try raw_chunks.append(allocator, chunk);
        }

        const out = try allocator.alloc(OutgoingTextChunk, raw_chunks.items.len);
        var built: usize = 0;
        errdefer {
            for (out[0..built]) |chunk| chunk.deinit(allocator);
            allocator.free(out);
        }

        for (raw_chunks.items, 0..) |chunk, i| {
            const is_last = i == raw_chunks.items.len - 1;
            if (is_last) {
                out[i] = .{ .body = chunk };
            } else {
                var body: std.ArrayListUnmanaged(u8) = .empty;
                errdefer body.deinit(allocator);
                try body.appendSlice(allocator, chunk);
                try body.appendSlice(allocator, CONTINUATION_MARKER);
                const owned = try body.toOwnedSlice(allocator);
                out[i] = .{
                    .body = owned,
                    .owned = owned,
                };
            }
            built += 1;
        }

        return out;
    }

    fn buildOutgoingTextChunks(
        allocator: std.mem.Allocator,
        text: []const u8,
    ) ![]OutgoingTextChunk {
        return buildOutgoingTextChunksWithLimit(allocator, text, null);
    }

    fn sendSplitTextWithMarkdownFallbackWithMarkup(
        self: *TelegramChannel,
        target: []const u8,
        text: []const u8,
        reply_to: ?i64,
        reply_markup_json: ?[]const u8,
    ) !SentMessageMeta {
        return self.sendSplitTextWithMarkdownFallbackWithMarkupAdaptive(
            target,
            text,
            reply_to,
            reply_markup_json,
            outgoingChunkSplitLimit(text.len, null),
        );
    }

    fn sendSplitTextWithMarkdownFallbackWithMarkupAdaptive(
        self: *TelegramChannel,
        target: []const u8,
        text: []const u8,
        reply_to: ?i64,
        reply_markup_json: ?[]const u8,
        split_limit_hint: usize,
    ) !SentMessageMeta {
        const chunks = try buildOutgoingTextChunksWithLimit(self.allocator, text, split_limit_hint);
        defer {
            for (chunks) |chunk| chunk.deinit(self.allocator);
            self.allocator.free(chunks);
        }

        const current_limit = outgoingChunkSplitLimit(text.len, split_limit_hint);
        var current_reply_to = reply_to;
        var last_meta: SentMessageMeta = .{};
        var sent_any = false;
        for (chunks, 0..) |chunk, i| {
            const is_last = i == chunks.len - 1;
            if (is_last) {
                last_meta = self.sendWithMarkdownFallbackWithMarkup(target, chunk.body, current_reply_to, reply_markup_json) catch |err| switch (err) {
                    error.TelegramMessageTooLong => blk: {
                        const next_limit = nextAdaptiveSplitLimit(current_limit, chunk.body.len);
                        if (next_limit == 0 or next_limit >= chunk.body.len) {
                            if (sent_any) return error.PartiallySent;
                            return err;
                        }
                        const meta = self.sendSplitTextWithMarkdownFallbackWithMarkupAdaptive(
                            target,
                            chunk.body,
                            current_reply_to,
                            reply_markup_json,
                            next_limit,
                        ) catch |split_err| {
                            if (sent_any) return error.PartiallySent;
                            return split_err;
                        };
                        break :blk meta;
                    },
                    else => {
                        if (sent_any) return error.PartiallySent;
                        return err;
                    },
                };
            } else {
                self.sendWithMarkdownFallback(target, chunk.body, current_reply_to) catch |err| switch (err) {
                    error.TelegramMessageTooLong => {
                        const next_limit = nextAdaptiveSplitLimit(current_limit, chunk.body.len);
                        if (next_limit == 0 or next_limit >= chunk.body.len) {
                            if (sent_any) return error.PartiallySent;
                            return err;
                        }
                        _ = self.sendSplitTextWithMarkdownFallbackWithMarkupAdaptive(
                            target,
                            chunk.body,
                            current_reply_to,
                            null,
                            next_limit,
                        ) catch |split_err| {
                            if (sent_any) return error.PartiallySent;
                            return split_err;
                        };
                    },
                    else => {
                        if (sent_any) return error.PartiallySent;
                        return err;
                    },
                };
            }

            sent_any = true;
            current_reply_to = null;
            if (!is_last) std.Thread.sleep(100 * std.time.ns_per_ms);
        }

        return last_meta;
    }

    fn sendChunkPlainWithMarkup(
        self: *TelegramChannel,
        target: []const u8,
        text: []const u8,
        reply_to: ?i64,
        reply_markup_json: ?[]const u8,
    ) !SentMessageMeta {
        const parsed_target = parseTelegramTarget(target);

        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"chat_id\":");
        try body_list.appendSlice(self.allocator, parsed_target.chat_id);
        try body_list.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try telegram_api.appendMessageThreadId(&body_list, self.allocator, parsed_target.message_thread_id);
        try telegram_api.appendReplyTo(&body_list, self.allocator, reply_to);
        try telegram_api.appendRawReplyMarkup(&body_list, self.allocator, reply_markup_json);
        try body_list.appendSlice(self.allocator, "}");

        const resp = try self.api().sendMessage(self.allocator, body_list.items, "30");
        defer self.allocator.free(resp);
        if (telegram_api.responseHasTelegramError(resp)) {
            if (telegram_api.responseIsMessageTooLong(resp)) return error.TelegramMessageTooLong;
            log.warn("telegram sendMessage API error: {s}", .{resp[0..@min(resp.len, 256)]});
            return error.TelegramApiError;
        }
        return telegram_api.parseSentMessageMeta(self.allocator, resp) orelse .{};
    }

    fn sendChunkPlain(self: *TelegramChannel, target: []const u8, text: []const u8, reply_to: ?i64) !void {
        _ = try self.sendChunkPlainWithMarkup(target, text, reply_to, null);
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
        target: []const u8,
        allocator: std.mem.Allocator,
        kind: AttachmentKind,
        file_path: []const u8,
        caption: ?[]const u8,
    ) !void {
        const parsed_target = parseTelegramTarget(target);
        const resolved_file_path = try resolveAttachmentPath(allocator, file_path);
        defer resolved_file_path.deinit(allocator);
        const media_path = resolved_file_path.path;
        try self.api().postMultipart(
            allocator,
            kind.apiMethod(),
            parsed_target.chat_id,
            parsed_target.message_thread_id,
            kind.formField(),
            media_path,
            caption,
        );
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Telegram chat via the Bot API.
    /// Parses attachment markers, sends typing indicator, uses smart splitting
    /// with Markdown fallback.
    pub fn sendMessage(self: *TelegramChannel, target: []const u8, text: []const u8) !void {
        return self.sendMessageWithReply(target, text, null);
    }

    pub fn sendAssistantMessageWithReply(
        self: *TelegramChannel,
        target: []const u8,
        owner_identity: []const u8,
        is_group: bool,
        text: []const u8,
        reply_to: ?i64,
    ) !void {
        var payload = try buildOwnedOutboundPayloadFromLegacy(self.allocator, text, &.{}, true);
        defer payload.deinit(self.allocator);
        try self.sendRichMessageWithReply(target, owner_identity, is_group, payload.payload(), reply_to);
    }

    fn nextAdaptiveSplitLimit(current_limit: usize, text_len: usize) usize {
        if (text_len <= 1) return 0;

        const limit_hint = if (current_limit == 0 or current_limit >= text_len)
            text_len
        else
            current_limit;

        const halved = if (limit_hint > 1) limit_hint / 2 else 1;
        return if (halved >= MIN_ADAPTIVE_SPLIT_LIMIT)
            halved
        else if (text_len > MIN_ADAPTIVE_SPLIT_LIMIT)
            MIN_ADAPTIVE_SPLIT_LIMIT
        else
            text_len - 1;
    }

    /// Send a message with optional reply-to, continuation markers, and delay between chunks.
    pub fn sendMessageWithReply(self: *TelegramChannel, target: []const u8, text: []const u8, reply_to: ?i64) !void {
        var payload = try buildOwnedOutboundPayloadFromLegacy(self.allocator, text, &.{}, false);
        defer payload.deinit(self.allocator);
        return self.sendRichMessageWithReply(target, "", false, payload.payload(), reply_to);
    }

    fn sendRichMessageWithReply(
        self: *TelegramChannel,
        target: []const u8,
        owner_identity: []const u8,
        is_group: bool,
        payload: root.Channel.OutboundPayload,
        reply_to: ?i64,
    ) !void {
        // Send typing indicator (best-effort)
        self.sendTypingIndicator(target);

        if (payload.choices.len > 0 and payload.attachments.len == 0 and self.interactive.enabled) {
            var directive = buildChoicesDirectiveFromPayload(self.allocator, payload.choices) catch |err| {
                log.warn("telegram buildChoicesDirectiveFromPayload failed, falling back to plain send: {}", .{err});
                return self.sendStructuredPayload(target, payload, reply_to);
            };
            defer directive.deinit(self.allocator);

            const token = self.nextInteractionToken() catch {
                return self.sendStructuredPayload(target, payload, reply_to);
            };
            defer self.allocator.free(token);

            const keyboard_json = self.buildInlineKeyboardJson(directive, token) catch |err| {
                if (err != error.CallbackDataTooLong) {
                    log.warn("telegram buildInlineKeyboardJson failed: {}", .{err});
                }
                return self.sendStructuredPayload(target, payload, reply_to);
            };
            defer self.allocator.free(keyboard_json);

            const sent = self.sendSplitTextWithMarkdownFallbackWithMarkup(target, payload.text, reply_to, keyboard_json) catch |err| {
                if (err == error.PartiallySent) {
                    log.warn("telegram interactive send partially succeeded; skipping full fallback to avoid duplicate chunks", .{});
                    return;
                }
                log.warn("telegram interactive send failed, falling back to plain send: {}", .{err});
                return self.sendStructuredPayload(target, payload, reply_to);
            };

            if (sent.message_id == null) {
                log.warn("telegram interactive send succeeded but response had no message_id; buttons will not be tracked", .{});
                return;
            }

            const enforce_owner = is_group and self.interactive.owner_only;
            self.registerPendingInteraction(
                token,
                target,
                if (enforce_owner) owner_identity else null,
                enforce_owner,
                self.interactive.remove_on_click,
                sent.message_id,
                directive,
            ) catch |err| {
                log.warn("telegram registerPendingInteraction failed: {}", .{err});
            };
            return;
        }

        return self.sendStructuredPayload(target, payload, reply_to);
    }

    fn sendStructuredPayload(
        self: *TelegramChannel,
        target: []const u8,
        payload: root.Channel.OutboundPayload,
        reply_to: ?i64,
    ) !void {
        if (payload.text.len > 0) {
            _ = try self.sendSplitTextWithMarkdownFallbackWithMarkup(target, payload.text, reply_to, null);
        }

        for (payload.attachments) |attachment| {
            self.sendMediaMultipart(target, self.allocator, from_root_attachment_kind(attachment.kind), attachment.target, attachment.caption) catch |err| {
                log.err("sendMediaMultipart failed: {}", .{err});
                continue;
            };
        }
    }

    fn sendChunk(self: *TelegramChannel, target: []const u8, text: []const u8) !void {
        const parsed_target = parseTelegramTarget(target);
        // Build JSON body with escaped text
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"chat_id\":");
        try body_list.appendSlice(self.allocator, parsed_target.chat_id);
        try body_list.appendSlice(self.allocator, ",\"text\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try telegram_api.appendMessageThreadId(&body_list, self.allocator, parsed_target.message_thread_id);
        try body_list.appendSlice(self.allocator, "}");

        const resp = try self.api().sendMessage(self.allocator, body_list.items, "30");
        self.allocator.free(resp);
    }

    fn advanceLastUpdateOffset(self: *TelegramChannel, update: std.json.Value) void {
        const update_id = telegram_update_ingress.updateId(update) orelse return;
        self.last_update_id = update_id + 1;
    }

    fn logUnauthorizedMessage(sender: telegram_update_ingress.UserIdentity) void {
        log.warn("ignoring message from unauthorized user: username={s}, user_id={s}", .{
            sender.username,
            sender.user_id orelse "unknown",
        });
    }

    fn logUnauthorizedCallback(sender: telegram_update_ingress.UserIdentity) void {
        log.warn("ignoring callback from unauthorized user: username={s}, user_id={s}", .{
            sender.username,
            sender.user_id orelse "unknown",
        });
    }

    fn buildVoiceContent(self: *TelegramChannel, allocator: std.mem.Allocator, file_id: []const u8) ?[]u8 {
        const transcribed = voice.transcribeTelegramVoice(allocator, self.bot_token, file_id, self.transcriber) orelse return null;
        defer allocator.free(transcribed);

        var result: std.ArrayListUnmanaged(u8) = .empty;
        result.appendSlice(allocator, "[Voice]: ") catch return null;
        result.appendSlice(allocator, transcribed) catch {
            result.deinit(allocator);
            return null;
        };
        return result.toOwnedSlice(allocator) catch {
            result.deinit(allocator);
            return null;
        };
    }

    fn appendOptionalCaption(result: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, message: std.json.Value) void {
        const caption = telegram_update_ingress.caption(message) orelse return;
        result.appendSlice(allocator, " ") catch return;
        result.appendSlice(allocator, caption) catch return;
    }

    fn buildAttachmentMetadataFallbackContent(
        allocator: std.mem.Allocator,
        kind: []const u8,
        file_name: ?[]const u8,
        mime_type: ?[]const u8,
        file_size: ?i64,
        duration_secs: ?i64,
        message: std.json.Value,
    ) ?[]u8 {
        var result: std.ArrayListUnmanaged(u8) = .empty;
        const writer = result.writer(allocator);

        writer.print("[ATTACHMENT:{s}", .{kind}) catch {
            result.deinit(allocator);
            return null;
        };
        if (file_name) |name| {
            writer.print(" file_name={s}", .{name}) catch {
                result.deinit(allocator);
                return null;
            };
        }
        if (mime_type) |mime| {
            writer.print(" mime_type={s}", .{mime}) catch {
                result.deinit(allocator);
                return null;
            };
        }
        if (file_size) |size| {
            writer.print(" file_size={d}", .{size}) catch {
                result.deinit(allocator);
                return null;
            };
        }
        if (duration_secs) |duration| {
            writer.print(" duration={d}", .{duration}) catch {
                result.deinit(allocator);
                return null;
            };
        }
        result.appendSlice(allocator, "]") catch {
            result.deinit(allocator);
            return null;
        };

        appendOptionalCaption(&result, allocator, message);
        return result.toOwnedSlice(allocator) catch {
            result.deinit(allocator);
            return null;
        };
    }

    fn buildTaggedAttachmentContent(
        allocator: std.mem.Allocator,
        prefix: []const u8,
        local_path: []const u8,
        message: std.json.Value,
    ) ?[]u8 {
        var result: std.ArrayListUnmanaged(u8) = .empty;
        result.appendSlice(allocator, prefix) catch return null;
        result.appendSlice(allocator, local_path) catch {
            result.deinit(allocator);
            return null;
        };
        result.appendSlice(allocator, "]") catch {
            result.deinit(allocator);
            return null;
        };
        appendOptionalCaption(&result, allocator, message);
        return result.toOwnedSlice(allocator) catch {
            result.deinit(allocator);
            return null;
        };
    }

    fn resolveVoiceOrAudioContent(self: *TelegramChannel, allocator: std.mem.Allocator, message: std.json.Value) ?[]u8 {
        const info = telegram_update_ingress.voiceOrAudioInfo(message) orelse return null;
        if (self.buildVoiceContent(allocator, info.file_id)) |transcribed| {
            return transcribed;
        }

        return buildAttachmentMetadataFallbackContent(
            allocator,
            switch (info.kind) {
                .voice => "voice",
                .audio => "audio",
            },
            info.file_name,
            info.mime_type,
            info.file_size,
            info.duration_secs,
            message,
        );
    }

    fn resolvePhotoContent(self: *TelegramChannel, allocator: std.mem.Allocator, message: std.json.Value) ?[]u8 {
        const photo_fid = telegram_update_ingress.photoFileId(message) orelse return null;
        const local_path = downloadTelegramPhoto(allocator, self.bot_token, photo_fid, self.proxy) orelse return null;
        defer allocator.free(local_path);
        return buildTaggedAttachmentContent(allocator, "[IMAGE:", local_path, message);
    }

    fn resolveDocumentContent(self: *TelegramChannel, allocator: std.mem.Allocator, message: std.json.Value) ?[]u8 {
        const doc = telegram_update_ingress.documentInfo(message) orelse return null;
        if (downloadTelegramFile(allocator, self.bot_token, doc.file_id, doc.file_name, self.proxy)) |local_path| {
            defer allocator.free(local_path);
            return buildTaggedAttachmentContent(allocator, "[FILE:", local_path, message);
        }

        return buildAttachmentMetadataFallbackContent(
            allocator,
            "document",
            doc.file_name,
            doc.mime_type,
            doc.file_size,
            null,
            message,
        );
    }

    fn resolveMessageContent(self: *TelegramChannel, allocator: std.mem.Allocator, message: std.json.Value) ?[]u8 {
        return self.resolveVoiceOrAudioContent(allocator, message) orelse
            self.resolvePhotoContent(allocator, message) orelse
            self.resolveDocumentContent(allocator, message) orelse
            telegram_update_ingress.textOrCaption(allocator, message);
    }

    fn appendIncomingMessage(
        allocator: std.mem.Allocator,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
        sender: telegram_update_ingress.UserIdentity,
        chat: telegram_update_ingress.ChatContext,
        final_content: []u8,
    ) void {
        const id_dup = allocator.dupe(u8, sender.preferred_identity) catch {
            allocator.free(final_content);
            return;
        };
        const sender_dup = dupTelegramTarget(allocator, chat.chat_id, chat.message_thread_id) catch {
            allocator.free(final_content);
            allocator.free(id_dup);
            return;
        };
        const fn_dup: ?[]const u8 = if (sender.first_name) |fn_|
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
            .message_id = chat.message_id,
            .first_name = fn_dup,
            .is_group = chat.is_group,
        }) catch {
            allocator.free(final_content);
            allocator.free(id_dup);
            allocator.free(sender_dup);
            if (fn_dup) |f| allocator.free(f);
            return;
        };

        const mg_dup: ?[]const u8 = if (chat.media_group_id) |mgid|
            (allocator.dupe(u8, mgid) catch null)
        else
            null;
        media_group_ids.append(allocator, mg_dup) catch {
            const popped = messages.pop().?;
            var tmp = popped;
            tmp.deinit(allocator);
            if (mg_dup) |m| allocator.free(m);
        };
    }

    fn processMessageUpdate(
        self: *TelegramChannel,
        allocator: std.mem.Allocator,
        message: std.json.Value,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
    ) void {
        var scratch: telegram_update_ingress.IdentityScratch = .{};
        const sender = telegram_update_ingress.messageSender(message, &scratch) orelse return;
        const chat = telegram_update_ingress.messageChatContext(message, &scratch) orelse return;

        if (!self.isAuthorizedIdentity(chat.is_group, sender.username, sender.user_id)) {
            logUnauthorizedMessage(sender);
            return;
        }

        if (!self.shouldProcessMessage(message)) {
            log.info("ignoring message: require_mention enabled but bot not mentioned", .{});
            return;
        }

        const final_content = self.resolveMessageContent(allocator, message) orelse return;
        appendIncomingMessage(allocator, messages, media_group_ids, sender, chat, final_content);
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

    fn resetPendingTextBuffers(self: *TelegramChannel) void {
        for (self.pending_text_messages.items) |msg| {
            msg.deinit(self.allocator);
        }
        self.pending_text_messages.clearRetainingCapacity();
        self.pending_text_received_at.clearRetainingCapacity();
    }

    fn cancelPendingTextChainForKey(self: *TelegramChannel, id: []const u8, sender: []const u8) void {
        if (self.pending_text_messages.items.len == 0) return;
        if (!telegram_ingress.pendingTextBuffersInSync(
            self.pending_text_messages.items,
            self.pending_text_received_at.items,
        )) {
            self.resetPendingTextBuffers();
            return;
        }
        telegram_ingress.cancelPendingTextChainForKey(
            self.allocator,
            &self.pending_text_messages,
            &self.pending_text_received_at,
            id,
            sender,
        );
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

    fn flushMaturedPendingTextMessages(
        self: *TelegramChannel,
        poll_allocator: std.mem.Allocator,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
    ) void {
        if (self.pending_text_messages.items.len == 0) return;
        if (!telegram_ingress.pendingTextBuffersInSync(
            self.pending_text_messages.items,
            self.pending_text_received_at.items,
        )) {
            log.warn("telegram pending text buffers out of sync; resetting buffers", .{});
            self.resetPendingTextBuffers();
            return;
        }

        const now = root.nowEpochSecs();

        var i: usize = 0;
        while (i < self.pending_text_messages.items.len) {
            if (!telegram_ingress.pendingTextChainMatureAtIndex(
                now,
                self.pending_text_messages.items,
                self.pending_text_received_at.items,
                i,
            )) {
                i += 1;
                continue;
            }

            const pending_msg = self.pending_text_messages.orderedRemove(i);
            _ = self.pending_text_received_at.orderedRemove(i);

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
    }

    fn buildGetUpdatesBody(buf: []u8, offset: i64, timeout_secs: u64) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        try fbs.writer().print(
            "{{\"offset\":{d},\"timeout\":{d},\"allowed_updates\":[\"message\",\"callback_query\"]}}",
            .{ offset, timeout_secs },
        );
        return fbs.getWritten();
    }

    /// Poll for updates using long-polling (getUpdates) via curl.
    /// Returns a slice of ChannelMessages allocated on the given allocator.
    /// Voice and audio messages are automatically transcribed via Groq Whisper
    /// when a Groq API key is configured (config or GROQ_API_KEY env var).
    pub fn pollUpdates(self: *TelegramChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        self.maybeSweepTempMediaFiles();
        self.cleanupExpiredInteractions();

        // Build body with offset and dynamic timeout.
        // If pending media/text debounced buffers exist, cap timeout to nearest deadline.
        var poll_timeout: u64 = 30;
        {
            const t_now = root.nowEpochSecs();
            var next_deadline: ?u64 = null;

            if (nextPendingMediaDeadline(self.pending_media_group_ids.items, self.pending_media_received_at.items)) |deadline| {
                next_deadline = deadline;
            }
            if (telegram_ingress.nextPendingTextDeadline(self.pending_text_messages.items, self.pending_text_received_at.items)) |deadline| {
                if (next_deadline == null or deadline < next_deadline.?) next_deadline = deadline;
            }

            if (next_deadline) |deadline| {
                if (t_now >= deadline) {
                    poll_timeout = 0;
                } else {
                    poll_timeout = @min(30, deadline - t_now);
                }
            }
        }
        var body_buf: [256]u8 = undefined;
        const body = try buildGetUpdatesBody(&body_buf, self.last_update_id, poll_timeout);

        var timeout_buf: [16]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{poll_timeout + 15}) catch "45";

        const resp_body = try self.api().getUpdates(allocator, body, timeout_str);
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

        // Buffer non-command text messages across poll cycles to debounce split
        // Telegram long messages that arrive in separate getUpdates responses.
        {
            var i: usize = 0;
            while (i < messages.items.len) {
                if (!telegram_ingress.shouldDebounceTextMessage(
                    root.nowEpochSecs(),
                    self.pending_text_messages.items,
                    self.pending_text_received_at.items,
                    messages.items[i],
                )) {
                    // Explicitly cancel stale chain fragments for this sender/chat
                    // so a fresh message is not blocked by old pending chunks.
                    self.cancelPendingTextChainForKey(messages.items[i].id, messages.items[i].sender);
                    i += 1;
                    continue;
                }

                const msg = messages.orderedRemove(i);
                const mgid = media_group_ids.orderedRemove(i);
                if (mgid) |m| allocator.free(m);

                const pending_msg = cloneChannelMessage(self.allocator, msg) catch {
                    var tmp = msg;
                    tmp.deinit(allocator);
                    continue;
                };
                var tmp = msg;
                tmp.deinit(allocator);

                self.pending_text_messages.append(self.allocator, pending_msg) catch {
                    var rollback = pending_msg;
                    rollback.deinit(self.allocator);
                    continue;
                };
                self.pending_text_received_at.append(self.allocator, root.nowEpochSecs()) catch {
                    const popped_msg = self.pending_text_messages.pop().?;
                    var rollback = popped_msg;
                    rollback.deinit(self.allocator);
                    continue;
                };
            }
        }

        // Flush text messages whose debounce window has fully elapsed.
        self.flushMaturedPendingTextMessages(allocator, &messages, &media_group_ids);

        // Merge consecutive text messages to reconstruct long split texts
        // and debounce rapid-fire messages.
        telegram_ingress.mergeConsecutiveMessages(allocator, &messages);

        // toOwnedSlice MUST run before manual deinit to avoid double-free via errdefer
        const final_messages = try messages.toOwnedSlice(allocator);

        // Free remaining media_group_id tracking strings (all should be null at this point)
        for (media_group_ids.items) |mg| {
            if (mg) |s| allocator.free(s);
        }
        media_group_ids.deinit(allocator);

        return final_messages;
    }

    fn processCallbackQueryUpdate(
        self: *TelegramChannel,
        allocator: std.mem.Allocator,
        callback_query: std.json.Value,
        messages: *std.ArrayListUnmanaged(root.ChannelMessage),
        media_group_ids: *std.ArrayListUnmanaged(?[]const u8),
    ) void {
        if (callback_query != .object) return;

        const cb_id_val = callback_query.object.get("id") orelse return;
        const cb_id = if (cb_id_val == .string) cb_id_val.string else return;

        const cb_data_val = callback_query.object.get("data") orelse return;
        const cb_data = if (cb_data_val == .string) cb_data_val.string else return;
        const parsed_cb = interaction_choices.parseChoiceCallbackData(cb_data) orelse {
            self.answerCallbackQuery(cb_id, "Unsupported button");
            return;
        };

        var sender_scratch: telegram_update_ingress.IdentityScratch = .{};
        const clicker = telegram_update_ingress.callbackSender(callback_query, &sender_scratch) orelse return;

        if (telegram_update_ingress.callbackMessage(callback_query) == null) {
            self.answerCallbackQuery(cb_id, "Button has no message context");
            return;
        }

        var chat_scratch: telegram_update_ingress.IdentityScratch = .{};
        const chat = telegram_update_ingress.callbackMessageContext(callback_query, &chat_scratch) orelse {
            self.answerCallbackQuery(cb_id, "Button has no message context");
            return;
        };

        if (!self.isAuthorizedIdentity(chat.is_group, clicker.username, clicker.user_id)) {
            logUnauthorizedCallback(clicker);
            self.answerCallbackQuery(cb_id, "You are not allowed to use this button");
            return;
        }

        const chat_target = dupTelegramTarget(allocator, chat.chat_id, chat.message_thread_id) catch {
            self.answerCallbackQuery(cb_id, "Failed to resolve topic context");
            return;
        };
        defer allocator.free(chat_target);

        const selection = self.consumeCallbackSelection(
            allocator,
            parsed_cb.token,
            parsed_cb.option_id,
            clicker.preferred_identity,
            chat_target,
        ) catch |err| {
            log.warn("telegram consumeCallbackSelection failed: {}", .{err});
            self.answerCallbackQuery(cb_id, "Failed to handle button");
            return;
        };

        switch (selection) {
            .ok => |ok| {
                self.answerCallbackQuery(cb_id, null);
                defer allocator.free(ok.submit_text);

                if (ok.remove_on_click) {
                    if (ok.message_id orelse chat.message_id) |bot_msg_id| {
                        self.editMessageReplyMarkupClear(chat.chat_id, bot_msg_id);
                    }
                }

                const id_dup = allocator.dupe(u8, clicker.preferred_identity) catch return;
                errdefer allocator.free(id_dup);
                const sender_dup = dupTelegramTarget(allocator, chat.chat_id, chat.message_thread_id) catch {
                    allocator.free(id_dup);
                    return;
                };
                errdefer allocator.free(sender_dup);
                const content_dup = allocator.dupe(u8, ok.submit_text) catch {
                    allocator.free(id_dup);
                    allocator.free(sender_dup);
                    return;
                };
                errdefer allocator.free(content_dup);
                const fn_dup: ?[]const u8 = if (clicker.first_name) |fn_|
                    (allocator.dupe(u8, fn_) catch {
                        allocator.free(id_dup);
                        allocator.free(sender_dup);
                        allocator.free(content_dup);
                        return;
                    })
                else
                    null;

                messages.append(allocator, .{
                    .id = id_dup,
                    .sender = sender_dup,
                    .content = content_dup,
                    .channel = "telegram",
                    .timestamp = root.nowEpochSecs(),
                    .message_id = chat.message_id,
                    .first_name = fn_dup,
                    .is_group = chat.is_group,
                }) catch {
                    allocator.free(id_dup);
                    allocator.free(sender_dup);
                    allocator.free(content_dup);
                    if (fn_dup) |f| allocator.free(f);
                    return;
                };

                media_group_ids.append(allocator, null) catch {
                    const popped = messages.pop().?;
                    var tmp = popped;
                    tmp.deinit(allocator);
                    return;
                };
            },
            .owner_mismatch => self.answerCallbackQuery(cb_id, "Only the original user can use this button"),
            .expired, .not_found => self.answerCallbackQuery(cb_id, "Button expired or already handled"),
            .chat_mismatch, .invalid_option => self.answerCallbackQuery(cb_id, "Invalid button"),
        }
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
        self.advanceLastUpdateOffset(update);

        if (telegram_update_ingress.callbackQuery(update)) |cbq| {
            self.processCallbackQueryUpdate(allocator, cbq, messages, media_group_ids);
            return;
        }

        const message = telegram_update_ingress.updateMessage(update) orelse return;
        self.processMessageUpdate(allocator, message, messages, media_group_ids);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        // Verify bot token by calling getMe
        if (self.api().getMe(self.allocator)) |resp| {
            self.allocator.free(resp);
        } else |_| {}

        // Keep slash-command menu in sync when channel is started via manager/daemon.
        self.syncCommandsMenu();
        // If getMe fails, we still start — healthCheck will report issues.
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        self.stopAllTyping();
        self.deinitPendingInteractions();
        self.deinitDraftBuffers();
        // Clean up buffered media group messages to prevent shutdown leaks.
        self.resetPendingMediaBuffers();
        self.resetPendingTextBuffers();
        self.pending_media_messages.deinit(self.allocator);
        self.pending_media_group_ids.deinit(self.allocator);
        self.pending_media_received_at.deinit(self.allocator);
        self.pending_text_messages.deinit(self.allocator);
        self.pending_text_received_at.deinit(self.allocator);
        if (self.bot_username) |name| {
            self.allocator.free(name);
            self.bot_username = null;
        }
        self.bot_user_id = null;
    }

    // ── Draft streaming (sendMessageDraft) ─────────────────────────

    fn deinitDraftBuffers(self: *TelegramChannel) void {
        telegram_draft_presenter.deinitDraftBuffers(self.allocator, &self.draft_buffers);
        var it = self.draft_target_suppress_until_ms.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.draft_target_suppress_until_ms.deinit(self.allocator);
        self.draft_target_suppress_until_ms = .empty;
    }

    fn targetDraftSuppressUntilLocked(self: *TelegramChannel, chat_id: []const u8, now_ms: i64) i64 {
        const suppress_until_ms = self.draft_target_suppress_until_ms.get(chat_id) orelse return 0;
        if (suppress_until_ms <= now_ms) {
            if (self.draft_target_suppress_until_ms.fetchRemove(chat_id)) |entry| {
                self.allocator.free(entry.key);
            }
            return 0;
        }
        return suppress_until_ms;
    }

    fn beginDraftStateLocked(self: *TelegramChannel, target: []const u8, now_ms: i64) !*DraftState {
        const gop = try self.draft_buffers.getOrPut(self.allocator, target);
        if (!gop.found_existing) {
            const key_copy = try self.allocator.dupe(u8, target);
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{
                .draft_id = 0,
            };
        } else {
            gop.value_ptr.buffer.clearRetainingCapacity();
        }

        gop.value_ptr.draft_id = self.draft_id_counter.fetchAdd(1, .monotonic);
        gop.value_ptr.last_flush_len = 0;
        gop.value_ptr.last_flush_time = now_ms;
        gop.value_ptr.started_at_ms = now_ms;
        if (self.draft_global_suppress_until_ms > gop.value_ptr.suppress_until_ms) {
            gop.value_ptr.suppress_until_ms = self.draft_global_suppress_until_ms;
        }
        const target_suppress_until_ms = self.targetDraftSuppressUntilLocked(target, now_ms);
        if (target_suppress_until_ms > gop.value_ptr.suppress_until_ms) {
            gop.value_ptr.suppress_until_ms = target_suppress_until_ms;
        }
        return gop.value_ptr;
    }

    fn ensureDraftStateLocked(self: *TelegramChannel, target: []const u8, now_ms: i64) !*DraftState {
        const target_suppress_until_ms = self.targetDraftSuppressUntilLocked(target, now_ms);
        const gop = try self.draft_buffers.getOrPut(self.allocator, target);
        if (!gop.found_existing) {
            const key_copy = try self.allocator.dupe(u8, target);
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{
                .draft_id = self.draft_id_counter.fetchAdd(1, .monotonic),
                .last_flush_time = now_ms,
                .started_at_ms = now_ms,
                .suppress_until_ms = @max(self.draft_global_suppress_until_ms, target_suppress_until_ms),
            };
        } else {
            if (gop.value_ptr.started_at_ms == 0) gop.value_ptr.started_at_ms = now_ms;
            if (self.draft_global_suppress_until_ms > now_ms) {
                telegram_draft_presenter.suppressDraftUntilMs(
                    gop.value_ptr,
                    self.draft_global_suppress_until_ms,
                );
            }
            if (target_suppress_until_ms > now_ms) {
                telegram_draft_presenter.suppressDraftUntilMs(
                    gop.value_ptr,
                    target_suppress_until_ms,
                );
            }
        }
        return gop.value_ptr;
    }

    pub fn beginDraftTurn(self: *TelegramChannel, target: []const u8) !u64 {
        if (!self.streaming_enabled or target.len == 0) return 0;

        const now_ms = std.time.milliTimestamp();
        self.draft_mu.lock();
        defer self.draft_mu.unlock();
        const state = try self.beginDraftStateLocked(target, now_ms);
        return state.draft_id;
    }

    pub fn finishDraftTurn(self: *TelegramChannel, target: []const u8, draft_id: u64) !void {
        if (draft_id == 0 or target.len == 0) return;

        self.draft_mu.lock();
        defer self.draft_mu.unlock();

        const state = self.draft_buffers.getPtr(target) orelse return;
        if (state.draft_id != draft_id) return;
        telegram_draft_presenter.clearDraftForTarget(self.allocator, &self.draft_buffers, target);
    }

    fn sendDraftChunkForTurn(self: *TelegramChannel, target: []const u8, draft_id: u64, message: []const u8) !void {
        if (!self.streaming_enabled or draft_id == 0 or message.len == 0) return;

        var pending_flush: ?telegram_draft_presenter.DraftFlush = null;
        defer if (pending_flush) |*flush| flush.deinit(self.allocator);
        const now_ms = std.time.milliTimestamp();

        {
            self.draft_mu.lock();
            defer self.draft_mu.unlock();

            const state = self.draft_buffers.getPtr(target) orelse return;
            if (state.draft_id != draft_id) return;
            pending_flush = try telegram_draft_presenter.appendDraftChunk(
                self.allocator,
                state,
                message,
                now_ms,
            );
        }

        if (pending_flush) |flush| {
            self.sendDraft(target, flush.draft_id, flush.text, flush.started_at_ms);
        }
    }

    fn suppressDraftSends(self: *TelegramChannel, chat_id: []const u8, retry_after_secs: u32) void {
        const now_ms = std.time.milliTimestamp();
        const retry_after_ms = @as(i64, @intCast(retry_after_secs)) * std.time.ms_per_s;
        const suppress_until_ms = now_ms + retry_after_ms;

        self.draft_mu.lock();
        defer self.draft_mu.unlock();

        if (suppress_until_ms > self.draft_global_suppress_until_ms) {
            self.draft_global_suppress_until_ms = suppress_until_ms;
        }
        if (self.draft_buffers.getPtr(chat_id)) |state| {
            telegram_draft_presenter.suppressDraftUntilMs(state, suppress_until_ms);
        }
    }

    fn suppressDraftSendsForTarget(self: *TelegramChannel, chat_id: []const u8, retry_after_secs: u32) void {
        const now_ms = std.time.milliTimestamp();
        const retry_after_ms = @as(i64, @intCast(retry_after_secs)) * std.time.ms_per_s;
        const suppress_until_ms = now_ms + retry_after_ms;

        self.draft_mu.lock();
        defer self.draft_mu.unlock();

        if (self.draft_target_suppress_until_ms.getPtr(chat_id)) |existing| {
            if (suppress_until_ms > existing.*) existing.* = suppress_until_ms;
        } else {
            const key_copy = self.allocator.dupe(u8, chat_id) catch return;
            errdefer self.allocator.free(key_copy);

            const gop = self.draft_target_suppress_until_ms.getOrPut(self.allocator, chat_id) catch return;
            if (gop.found_existing) {
                self.allocator.free(key_copy);
                if (suppress_until_ms > gop.value_ptr.*) gop.value_ptr.* = suppress_until_ms;
            } else {
                gop.key_ptr.* = key_copy;
                gop.value_ptr.* = suppress_until_ms;
            }
        }

        if (self.draft_buffers.getPtr(chat_id)) |state| {
            const target_suppress_until_ms = self.draft_target_suppress_until_ms.get(chat_id) orelse suppress_until_ms;
            telegram_draft_presenter.suppressDraftUntilMs(state, target_suppress_until_ms);
        }
    }

    fn shouldSkipDraftSend(self: *TelegramChannel, chat_id: []const u8, draft_id: u64, now_ms: i64) bool {
        self.draft_mu.lock();
        defer self.draft_mu.unlock();

        const state = self.draft_buffers.getPtr(chat_id) orelse return true;
        if (self.draft_global_suppress_until_ms > now_ms) {
            telegram_draft_presenter.suppressDraftUntilMs(state, self.draft_global_suppress_until_ms);
        }
        const target_suppress_until_ms = self.targetDraftSuppressUntilLocked(chat_id, now_ms);
        if (target_suppress_until_ms > now_ms) {
            telegram_draft_presenter.suppressDraftUntilMs(state, target_suppress_until_ms);
        }
        if (state.suppress_until_ms > now_ms) return true;
        return state.draft_id != draft_id;
    }

    fn sendDraftHeartbeat(self: *TelegramChannel, chat_id: []const u8) void {
        if (builtin.is_test or !self.streaming_enabled or chat_id.len == 0) return;

        const now_ms = std.time.milliTimestamp();
        var pending_flush: ?telegram_draft_presenter.DraftFlush = null;
        defer if (pending_flush) |*flush| flush.deinit(self.allocator);

        {
            self.draft_mu.lock();
            defer self.draft_mu.unlock();

            const state = self.ensureDraftStateLocked(chat_id, now_ms) catch return;
            pending_flush = telegram_draft_presenter.heartbeatDraft(
                self.allocator,
                state,
                now_ms,
            ) catch return;
        }

        if (pending_flush) |flush| {
            self.sendDraft(chat_id, flush.draft_id, flush.text, flush.started_at_ms);
        }
    }

    fn sendDraft(self: *TelegramChannel, chat_id: []const u8, draft_id: u64, text: []const u8, started_at_ms: i64) void {
        if (builtin.is_test) return;
        if (!telegram_draft_presenter.hasVisibleDraftText(text)) return;

        const now_ms = std.time.milliTimestamp();
        self.draft_send_mu.lock();
        defer self.draft_send_mu.unlock();

        if (self.shouldSkipDraftSend(chat_id, draft_id, now_ms)) return;

        const parsed_target = parseTelegramTarget(chat_id);

        const preview_text = telegram_draft_presenter.buildTransportText(
            self.allocator,
            text,
            started_at_ms,
            now_ms,
        ) catch return;
        defer self.allocator.free(preview_text);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        body.appendSlice(self.allocator, "{\"chat_id\":") catch return;
        body.appendSlice(self.allocator, parsed_target.chat_id) catch return;
        body.appendSlice(self.allocator, ",\"draft_id\":") catch return;
        var id_buf: [20]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{draft_id}) catch return;
        body.appendSlice(self.allocator, id_str) catch return;
        body.appendSlice(self.allocator, ",\"text\":") catch return;
        root.json_util.appendJsonString(&body, self.allocator, preview_text) catch return;
        telegram_api.appendMessageThreadId(&body, self.allocator, parsed_target.message_thread_id) catch return;
        body.appendSlice(self.allocator, "}") catch return;

        const resp = self.api().sendMessageDraft(self.allocator, body.items) catch |err| {
            log.warn("sendMessageDraft request failed: {}", .{err});
            return;
        };
        defer self.allocator.free(resp);

        if (telegram_api.responseHasTelegramError(resp)) {
            if (telegram_api.parseRetryAfterSecs(self.allocator, resp)) |retry_after_secs| {
                log.warn("sendMessageDraft rate-limited; suppressing drafts for {d}s", .{retry_after_secs});
                self.suppressDraftSends(chat_id, retry_after_secs);
                return;
            }
            if (telegram_api.responseIsMessageTooLong(resp)) {
                log.warn("sendMessageDraft exceeded Telegram message limit; suppressing drafts briefly", .{});
                self.suppressDraftSends(chat_id, 15);
                return;
            }
            if (telegram_api.responseIsDraftPeerInvalid(resp)) {
                log.warn("sendMessageDraft unsupported for peer; suppressing drafts for this target", .{});
                self.suppressDraftSendsForTarget(chat_id, 24 * 60 * 60);
                return;
            }
            log.warn("sendMessageDraft API error: {s}", .{resp[0..@min(resp.len, 256)]});
        }
    }

    /// Staged outbound event handler for draft streaming.
    ///
    /// - `.chunk`: Accumulates text in a per-chat draft buffer and periodically
    ///   flushes it to Telegram via `sendMessageDraft`, giving users a live
    ///   preview of the response as it is generated.
    /// - `.final`: Cleans up the draft buffer and delivers the complete message
    ///   through the normal `vtableSend` path (which handles attachment markers,
    ///   interactive buttons, and message splitting). Callers must pass the full
    ///   reply text as `message` for `.final`; an empty message skips delivery.
    fn vtableSendEvent(
        ptr: *anyopaque,
        target: []const u8,
        message: []const u8,
        _: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        if (!self.streaming_enabled) {
            if (stage == .final and message.len > 0) {
                return vtableSend(ptr, target, message, &.{});
            }
            return;
        }

        switch (stage) {
            .chunk => {
                if (message.len == 0) return;

                var pending_flush: ?telegram_draft_presenter.DraftFlush = null;
                defer if (pending_flush) |*flush| flush.deinit(self.allocator);
                const now_ms = std.time.milliTimestamp();

                {
                    self.draft_mu.lock();
                    defer self.draft_mu.unlock();

                    const state = try self.ensureDraftStateLocked(target, now_ms);
                    pending_flush = try telegram_draft_presenter.appendDraftChunk(
                        self.allocator,
                        state,
                        message,
                        now_ms,
                    );
                }

                if (pending_flush) |flush| {
                    self.sendDraft(target, flush.draft_id, flush.text, flush.started_at_ms);
                }
            },
            .final => {
                {
                    self.draft_mu.lock();
                    defer self.draft_mu.unlock();
                    telegram_draft_presenter.clearDraftForTarget(self.allocator, &self.draft_buffers, target);
                }
                // Forward the final message through the normal send path.
                // Once sendEvent is set in the vtable, the Channel wrapper no
                // longer falls through to send(), so we must deliver it here.
                if (message.len > 0) {
                    try vtableSend(ptr, target, message, &.{});
                }
            },
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        var payload = try buildOwnedOutboundPayloadFromLegacy(self.allocator, message, media, true);
        defer payload.deinit(self.allocator);
        try self.sendRichMessageWithReply(target, "", false, payload.payload(), null);
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichMessageWithReply(target, "", false, payload, null);
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

    fn vtableSetReaction(ptr: *anyopaque, update: root.Channel.ReactionUpdate) anyerror!void {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        try self.setReaction(update);
    }

    fn vtableSupportsStreamingOutbound(ptr: *anyopaque) bool {
        const self: *TelegramChannel = @ptrCast(@alignCast(ptr));
        return self.streaming_enabled;
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendEvent = &vtableSendEvent,
        .sendRich = &vtableSendRich,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
        .setReaction = &vtableSetReaction,
        .supportsStreamingOutbound = &vtableSupportsStreamingOutbound,
    };

    pub fn channel(self: *TelegramChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Streaming sink ─────────────────────────────────────────────

    pub const StreamCtx = struct {
        tg_ptr: *TelegramChannel,
        chat_id: []const u8,
        draft_id: u64 = 0,
        filter: streaming.TagFilter = undefined,
    };

    fn streamCallback(ctx_ptr: *anyopaque, event: streaming.Event) void {
        if (event.stage != .chunk or event.text.len == 0) return;
        const ctx: *StreamCtx = @ptrCast(@alignCast(ctx_ptr));
        ctx.tg_ptr.sendDraftChunkForTurn(ctx.chat_id, ctx.draft_id, event.text) catch {};
    }

    /// Build a streaming sink backed by the given context.
    /// Returns null if streaming is disabled. Caller owns the lifetime of `ctx`.
    /// Chunks are filtered through a TagFilter to strip tool_call markup.
    pub fn makeSink(self: *TelegramChannel, ctx: *StreamCtx) ?streaming.Sink {
        if (!self.streaming_enabled) return null;
        const raw = streaming.Sink{
            .callback = streamCallback,
            .ctx = @ptrCast(ctx),
        };
        ctx.filter = streaming.TagFilter.init(raw);
        return ctx.filter.sink();
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
    const api_client = telegram_api.Client{
        .allocator = allocator,
        .bot_token = bot_token,
        .proxy = proxy,
    };
    const tg_file_path = api_client.getFilePath(allocator, file_id) catch |err| {
        log.warn("downloadTelegramPhoto: getFile API failed: {}", .{err});
        return null;
    };
    defer allocator.free(tg_file_path);

    const data = api_client.downloadFile(allocator, tg_file_path, "30") catch |err| {
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
    const api_client = telegram_api.Client{
        .allocator = allocator,
        .bot_token = bot_token,
        .proxy = proxy,
    };
    const tg_file_path = api_client.getFilePath(allocator, file_id) catch |err| {
        log.warn("downloadTelegramFile: getFile API failed: {}", .{err});
        return null;
    };
    defer allocator.free(tg_file_path);

    const data = api_client.downloadFile(allocator, tg_file_path, "60") catch |err| {
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

test "telegram buildOwnedOutboundPayloadFromLegacy lifts choices into structured payload" {
    var payload = try buildOwnedOutboundPayloadFromLegacy(
        std.testing.allocator,
        "Question?\n<nc_choices>{\"v\":1,\"options\":[{\"id\":\"yes\",\"label\":\"Yes\",\"submit_text\":\"Yes\"},{\"id\":\"no\",\"label\":\"No\",\"submit_text\":\"No\"}]}</nc_choices>",
        &.{},
        true,
    );
    defer payload.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Question?", payload.text);
    try std.testing.expectEqual(@as(usize, 0), payload.attachments.len);
    try std.testing.expectEqual(@as(usize, 2), payload.choices.len);
    try std.testing.expectEqualStrings("yes", payload.choices[0].id);
    try std.testing.expectEqualStrings("No", payload.choices[1].label);
}

test "telegram buildOwnedOutboundPayloadFromLegacy suppresses choices when explicit media is present" {
    var payload = try buildOwnedOutboundPayloadFromLegacy(
        std.testing.allocator,
        "Question?\n<nc_choices>{\"v\":1,\"options\":[{\"id\":\"yes\",\"label\":\"Yes\",\"submit_text\":\"Yes\"},{\"id\":\"no\",\"label\":\"No\",\"submit_text\":\"No\"}]}</nc_choices>",
        &.{"/tmp/photo.png"},
        true,
    );
    defer payload.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Question?", payload.text);
    try std.testing.expectEqual(@as(usize, 1), payload.attachments.len);
    try std.testing.expectEqual(root.Channel.OutboundAttachmentKind.image, payload.attachments[0].kind);
    try std.testing.expectEqual(@as(usize, 0), payload.choices.len);
}

test "telegram buildOwnedOutboundPayloadFromLegacy keeps choices disabled for plain send path" {
    var payload = try buildOwnedOutboundPayloadFromLegacy(
        std.testing.allocator,
        "Question?\n<nc_choices>{\"v\":1,\"options\":[{\"id\":\"yes\",\"label\":\"Yes\",\"submit_text\":\"Yes\"},{\"id\":\"no\",\"label\":\"No\",\"submit_text\":\"No\"}]}</nc_choices>",
        &.{},
        false,
    );
    defer payload.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Question?", payload.text);
    try std.testing.expectEqual(@as(usize, 0), payload.attachments.len);
    try std.testing.expectEqual(@as(usize, 0), payload.choices.len);
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

test "telegram buildOutgoingTextChunks appends continuation only to non-last chunks" {
    const allocator = std.testing.allocator;
    const text = ("word " ** 900) ++ "tail";

    const chunks = try TelegramChannel.buildOutgoingTextChunks(allocator, text);
    defer {
        for (chunks) |chunk| chunk.deinit(allocator);
        allocator.free(chunks);
    }

    try std.testing.expect(chunks.len >= 2);
    for (chunks[0 .. chunks.len - 1]) |chunk| {
        try std.testing.expect(std.mem.endsWith(u8, chunk.body, TelegramChannel.CONTINUATION_MARKER));
        try std.testing.expect(chunk.body.len <= TelegramChannel.MAX_MESSAGE_LEN);
        try std.testing.expect(chunk.owned != null);
    }
    try std.testing.expect(!std.mem.endsWith(u8, chunks[chunks.len - 1].body, TelegramChannel.CONTINUATION_MARKER));
    try std.testing.expect(chunks[chunks.len - 1].body.len <= TelegramChannel.MAX_MESSAGE_LEN);
    try std.testing.expect(chunks[chunks.len - 1].owned == null);
}

test "telegram buildOutgoingTextChunks reuses source slice when split is unnecessary" {
    const allocator = std.testing.allocator;
    const text = "Short reply";

    const chunks = try TelegramChannel.buildOutgoingTextChunks(allocator, text);
    defer {
        for (chunks) |chunk| chunk.deinit(allocator);
        allocator.free(chunks);
    }

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqualStrings(text, chunks[0].body);
    try std.testing.expect(chunks[0].owned == null);
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

test "telegram exact dm match still triggers wildcard warning" {
    root.resetWildcardWarningForTest("telegram channel");
    defer root.resetWildcardWarningForTest("telegram channel");

    const users = [_][]const u8{ "alice", "*" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &users, &.{}, "allowlist");
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(root.wildcardWarningTriggeredForTest("telegram channel"));
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

test "telegram exact group match still triggers wildcard warning" {
    root.resetWildcardWarningForTest("telegram channel");
    defer root.resetWildcardWarningForTest("telegram channel");

    const groups = [_][]const u8{ "group_user", "*" };
    const ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &groups, "allowlist");
    try std.testing.expect(ch.isGroupUserAllowed("group_user"));
    try std.testing.expect(root.wildcardWarningTriggeredForTest("telegram channel"));
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
    defer ch.deinitDraftBuffers();

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

test "telegram channel setReaction rejects invalid message ids" {
    var ch = TelegramChannel.init(std.testing.allocator, "tok", &.{}, &.{}, "allowlist");
    ch.status_reactions_enabled = true;
    try std.testing.expectError(error.InvalidMessageRef, ch.channel().setReaction(.{
        .target = "12345",
        .message_id = "bad-id",
        .emoji = "✅",
    }));
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

test "telegram buildAttachmentMetadataFallbackContent includes available metadata" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        \\{"caption":"please summarize"}
    ,
        .{},
    );
    defer parsed.deinit();

    const content = TelegramChannel.buildAttachmentMetadataFallbackContent(
        alloc,
        "document",
        "report.pdf",
        "application/pdf",
        2048,
        null,
        parsed.value,
    ) orelse return error.TestExpectedEqual;
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "[ATTACHMENT:document") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "file_name=report.pdf") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "mime_type=application/pdf") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "file_size=2048") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "please summarize") != null);
}

test "telegram buildAttachmentMetadataFallbackContent omits optional fields" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        \\{}
    ,
        .{},
    );
    defer parsed.deinit();

    const content = TelegramChannel.buildAttachmentMetadataFallbackContent(
        alloc,
        "voice",
        null,
        null,
        null,
        6,
        parsed.value,
    ) orelse return error.TestExpectedEqual;
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "[ATTACHMENT:voice") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "duration=6") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "file_name=") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "mime_type=") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "file_size=") == null);
}

fn buildAttachmentMetadataFallbackContentAllocationTest(allocator: std.mem.Allocator) !void {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        \\{"caption":"please summarize"}
    ,
        .{},
    );
    defer parsed.deinit();

    const content = TelegramChannel.buildAttachmentMetadataFallbackContent(
        allocator,
        "document",
        "report.pdf",
        "application/pdf",
        2048,
        null,
        parsed.value,
    ) orelse return error.OutOfMemory;
    defer allocator.free(content);
}

test "telegram buildAttachmentMetadataFallbackContent frees partial allocations on out-of-memory" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildAttachmentMetadataFallbackContentAllocationTest,
        .{},
    );
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

test "telegram persistableUpdateOffset waits until pending text flushes" {
    const alloc = std.testing.allocator;
    var ch = TelegramChannel.init(alloc, "123:ABC", &.{"*"}, &.{}, "allowlist");

    ch.last_update_id = 42;
    try std.testing.expectEqual(@as(?i64, 42), ch.persistableUpdateOffset());

    const now = root.nowEpochSecs();
    try ch.pending_text_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-a"),
        .sender = try alloc.dupe(u8, "chat-a"),
        .content = try alloc.dupe(u8, "part one"),
        .channel = "telegram",
        .timestamp = now,
        .message_id = 1,
    });
    try ch.pending_text_received_at.append(alloc, now);

    try std.testing.expect(ch.persistableUpdateOffset() == null);

    ch.resetPendingTextBuffers();
    ch.pending_text_messages.deinit(alloc);
    ch.pending_text_received_at.deinit(alloc);
}

test "telegram flushMaturedPendingTextMessages waits for newest chain message" {
    const alloc = std.testing.allocator;
    var ch = TelegramChannel.init(alloc, "123:ABC", &.{"*"}, &.{}, "allowlist");

    const now = root.nowEpochSecs();

    try ch.pending_text_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-a"),
        .sender = try alloc.dupe(u8, "chat-a"),
        .content = try alloc.dupe(u8, "part-1"),
        .channel = "telegram",
        .timestamp = now - 10,
        .message_id = 1,
    });
    try ch.pending_text_received_at.append(alloc, now - 10);

    try ch.pending_text_messages.append(alloc, .{
        .id = try alloc.dupe(u8, "user-a"),
        .sender = try alloc.dupe(u8, "chat-a"),
        .content = try alloc.dupe(u8, "part-2"),
        .channel = "telegram",
        .timestamp = now,
        .message_id = 2,
    });
    try ch.pending_text_received_at.append(alloc, now);

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

    ch.flushMaturedPendingTextMessages(alloc, &out_messages, &out_group_ids);

    // Newest chain message is not mature yet, so both must remain pending.
    try std.testing.expectEqual(@as(usize, 0), out_messages.items.len);
    try std.testing.expectEqual(@as(usize, 2), ch.pending_text_messages.items.len);

    // Force chain maturity by moving the newest timestamp back.
    ch.pending_text_received_at.items[1] = now - (telegram_ingress.TEXT_MESSAGE_DEBOUNCE_SECS + 1);
    ch.flushMaturedPendingTextMessages(alloc, &out_messages, &out_group_ids);

    try std.testing.expectEqual(@as(usize, 2), out_messages.items.len);
    try std.testing.expectEqual(@as(usize, 0), ch.pending_text_messages.items.len);

    ch.resetPendingTextBuffers();
    ch.pending_text_messages.deinit(alloc);
    ch.pending_text_received_at.deinit(alloc);
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

fn makeTestChoicesDirective(allocator: std.mem.Allocator) !interaction_choices.ChoicesDirective {
    const opts = try allocator.alloc(interaction_choices.ChoiceOption, 2);
    errdefer allocator.free(opts);
    var built: usize = 0;
    errdefer {
        for (opts[0..built]) |opt| opt.deinit(allocator);
    }

    const yes_id = try allocator.dupe(u8, "yes");
    errdefer allocator.free(yes_id);
    const yes_label = try allocator.dupe(u8, "Yes");
    errdefer allocator.free(yes_label);
    const yes_submit = try allocator.dupe(u8, "Yes, done");
    errdefer allocator.free(yes_submit);
    opts[0] = .{
        .id = yes_id,
        .label = yes_label,
        .submit_text = yes_submit,
    };
    built = 1;

    const no_id = try allocator.dupe(u8, "no");
    errdefer allocator.free(no_id);
    const no_label = try allocator.dupe(u8, "No");
    errdefer allocator.free(no_label);
    const no_submit = try allocator.dupe(u8, "No, not yet");
    errdefer allocator.free(no_submit);
    opts[1] = .{
        .id = no_id,
        .label = no_label,
        .submit_text = no_submit,
    };
    built = 2;

    return .{
        .version = 1,
        .options = opts,
    };
}

test "telegram buildGetUpdatesBody includes callback_query" {
    var buf: [256]u8 = undefined;
    const body = try TelegramChannel.buildGetUpdatesBody(&buf, 10, 30);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"callback_query\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") != null);
}

test "telegram isAuthorizedIdentity enforces group allowlist and ids" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{ "alice", "42" }, &.{"group_user"}, "allowlist");
    defer ch.deinitPendingInteractions();

    try std.testing.expect(ch.isAuthorizedIdentity(false, "alice", null));
    try std.testing.expect(ch.isAuthorizedIdentity(false, "unknown", "42"));
    try std.testing.expect(!ch.isAuthorizedIdentity(false, "bob", "999"));

    try std.testing.expect(ch.isAuthorizedIdentity(true, "group_user", null));
    try std.testing.expect(!ch.isAuthorizedIdentity(true, "alice", null));

    ch.group_allow_from = &.{};
    try std.testing.expect(ch.isAuthorizedIdentity(true, "alice", null));
}

test "telegram shouldProcessMessage require_mention fails closed when username unavailable" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    ch.require_mention = true;

    const json =
        \\{"chat":{"type":"group"},"text":"hello everyone","entities":[]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(!ch.shouldProcessMessage(parsed.value));
}

test "telegram shouldProcessMessage accepts caption mention with utf16 offsets" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    ch.require_mention = true;
    ch.bot_username = try allocator.dupe(u8, "MyBot");
    defer if (ch.bot_username) |name| allocator.free(name);

    // "hi 😀 @MyBot" => mention starts at UTF-16 offset 6, length 6.
    const json =
        \\{"chat":{"type":"group"},"caption":"hi \ud83d\ude00 @MyBot","caption_entities":[{"type":"mention","offset":6,"length":6}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(ch.shouldProcessMessage(parsed.value));
}

test "telegram shouldProcessMessage accepts text_mention entity by username" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    ch.require_mention = true;
    ch.bot_username = try allocator.dupe(u8, "MyBot");
    defer if (ch.bot_username) |name| allocator.free(name);

    const json =
        \\{"chat":{"type":"group"},"text":"ping","entities":[{"type":"text_mention","offset":0,"length":4,"user":{"id":123,"is_bot":true,"first_name":"Bot","username":"MyBot"}}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(ch.shouldProcessMessage(parsed.value));
}

test "telegram shouldProcessMessage accepts text_mention entity by bot user id" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    ch.require_mention = true;
    ch.bot_username = try allocator.dupe(u8, "MyBot");
    ch.bot_user_id = 4242;
    defer if (ch.bot_username) |name| allocator.free(name);

    const json =
        \\{"chat":{"type":"group"},"text":"ping","entities":[{"type":"text_mention","offset":0,"length":4,"user":{"id":4242,"is_bot":true,"first_name":"Bot"}}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(ch.shouldProcessMessage(parsed.value));
}

test "telegram buildInlineKeyboardJson builds callback_data" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    var directive = try makeTestChoicesDirective(allocator);
    defer directive.deinit(allocator);

    const json = try ch.buildInlineKeyboardJson(directive, "t1");
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"inline_keyboard\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "nc1:t1:yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "nc1:t1:no") != null);
}

test "telegram consumeCallbackSelection valid click is one-shot" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    ch.interactive.enabled = true;
    var directive = try makeTestChoicesDirective(allocator);
    defer directive.deinit(allocator);

    try ch.registerPendingInteraction("tok1", "12345", "alice", true, true, 42, directive);

    const first = try ch.consumeCallbackSelection(allocator, "tok1", "yes", "alice", "12345");
    switch (first) {
        .ok => |ok| {
            defer allocator.free(ok.submit_text);
            try std.testing.expect(ok.remove_on_click);
            try std.testing.expectEqual(@as(?i64, 42), ok.message_id);
            try std.testing.expectEqualStrings("Yes, done", ok.submit_text);
        },
        else => return error.TestUnexpectedResult,
    }

    const second = try ch.consumeCallbackSelection(allocator, "tok1", "yes", "alice", "12345");
    switch (second) {
        .not_found, .expired => {},
        else => return error.TestUnexpectedResult,
    }
}

test "telegram consumeCallbackSelection rejects owner mismatch" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    var directive = try makeTestChoicesDirective(allocator);
    defer directive.deinit(allocator);

    try ch.registerPendingInteraction("tok2", "12345", "alice", true, true, 42, directive);
    const res = try ch.consumeCallbackSelection(allocator, "tok2", "yes", "bob", "12345");
    switch (res) {
        .owner_mismatch => {},
        else => return error.TestUnexpectedResult,
    }
}

test "telegram consumeCallbackSelection rejects expired interaction" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "tok", &.{}, &.{}, "allowlist");
    defer ch.deinitPendingInteractions();
    var directive = try makeTestChoicesDirective(allocator);
    defer directive.deinit(allocator);

    try ch.registerPendingInteraction("tok3", "12345", null, false, true, 42, directive);
    ch.interaction_mu.lock();
    if (ch.pending_interactions.getPtr("tok3")) |pending| {
        pending.*.expires_at = 0;
    }
    ch.interaction_mu.unlock();

    const res = try ch.consumeCallbackSelection(allocator, "tok3", "yes", "alice", "12345");
    switch (res) {
        .expired, .not_found => {},
        else => return error.TestUnexpectedResult,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Draft Streaming Tests
// ════════════════════════════════════════════════════════════════════════════

test "DraftState deinit frees buffer" {
    const allocator = std.testing.allocator;
    var draft = DraftState{
        .draft_id = 1,
    };
    try draft.buffer.appendSlice(allocator, "hello world");
    draft.deinit(allocator);
}

test "vtableSendEvent chunk accumulates in draft buffer" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello ", &.{}, .chunk);
    try ch.channel().sendEvent("12345", "world", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Hello world", draft.buffer.items);
}

test "vtableSendEvent first chunk does not flush immediately" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Hello", draft.buffer.items);
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
    try std.testing.expect(draft.last_flush_time > 0);
}

test "shouldSkipDraftSend allows active current draft" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello", &.{}, .chunk);

    ch.draft_mu.lock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    const draft_id = draft.draft_id;
    ch.draft_mu.unlock();

    try std.testing.expect(!ch.shouldSkipDraftSend("12345", draft_id, std.time.milliTimestamp()));
}

test "shouldSkipDraftSend skips missing or stale draft state" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello", &.{}, .chunk);

    ch.draft_mu.lock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    const draft_id = draft.draft_id;
    ch.draft_mu.unlock();

    try ch.channel().sendEvent("12345", "", &.{}, .final);

    try std.testing.expect(ch.shouldSkipDraftSend("12345", draft_id, std.time.milliTimestamp()));
}

test "shouldSkipDraftSend skips while global cooldown is active" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello", &.{}, .chunk);

    ch.draft_mu.lock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    const draft_id = draft.draft_id;
    ch.draft_mu.unlock();

    ch.suppressDraftSends("12345", 5);

    try std.testing.expect(ch.shouldSkipDraftSend("12345", draft_id, std.time.milliTimestamp()));
}

test "shouldSkipDraftSend skips while target cooldown is active" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello", &.{}, .chunk);

    ch.draft_mu.lock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    const draft_id = draft.draft_id;
    ch.draft_mu.unlock();

    ch.suppressDraftSendsForTarget("12345", 5);

    try std.testing.expect(ch.shouldSkipDraftSend("12345", draft_id, std.time.milliTimestamp()));
    try std.testing.expectEqual(@as(i64, 0), ch.draft_global_suppress_until_ms);
}

test "vtableSendEvent final cleans up draft state" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "chunk data", &.{}, .chunk);

    // Verify draft exists
    {
        ch.draft_mu.lock();
        defer ch.draft_mu.unlock();
        try std.testing.expect(ch.draft_buffers.get("12345") != null);
    }

    // Send final — should clean up
    try ch.channel().sendEvent("12345", "", &.{}, .final);

    {
        ch.draft_mu.lock();
        defer ch.draft_mu.unlock();
        try std.testing.expect(ch.draft_buffers.get("12345") == null);
    }
}

test "vtableSendEvent chunk assigns unique draft_id per chat" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("111", "a", &.{}, .chunk);
    try ch.channel().sendEvent("222", "b", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const d1 = ch.draft_buffers.get("111") orelse return error.TestUnexpectedResult;
    const d2 = ch.draft_buffers.get("222") orelse return error.TestUnexpectedResult;
    try std.testing.expect(d1.draft_id != d2.draft_id);
}

test "vtableSendEvent existing chat adopts global draft cooldown" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("111", "hello", &.{}, .chunk);
    try ch.channel().sendEvent("222", "world", &.{}, .chunk);

    const before = std.time.milliTimestamp();
    ch.suppressDraftSends("111", 5);
    try ch.channel().sendEvent("222", " again", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("222") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(ch.draft_global_suppress_until_ms, draft.suppress_until_ms);
    try std.testing.expect(draft.suppress_until_ms >= before + (4 * std.time.ms_per_s));
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
}

test "vtableSendEvent new chat inherits global draft cooldown" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    const before = std.time.milliTimestamp();
    ch.suppressDraftSends("111", 5);
    try ch.channel().sendEvent("222", "hello", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("222") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(ch.draft_global_suppress_until_ms, draft.suppress_until_ms);
    try std.testing.expect(draft.suppress_until_ms >= before + (4 * std.time.ms_per_s));
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
}

test "vtableSendEvent same chat inherits target draft cooldown across turns" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("111", "hello", &.{}, .chunk);

    ch.draft_mu.lock();
    const draft_id = ch.draft_buffers.get("111").?.draft_id;
    ch.draft_mu.unlock();

    const before = std.time.milliTimestamp();
    ch.suppressDraftSendsForTarget("111", 5);
    try ch.finishDraftTurn("111", draft_id);
    try ch.channel().sendEvent("111", "again", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("111") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i64, 0), ch.draft_global_suppress_until_ms);
    try std.testing.expect(draft.suppress_until_ms >= before + (4 * std.time.ms_per_s));
}

test "vtableSendEvent target draft cooldown does not affect other chats" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("111", "hello", &.{}, .chunk);
    try ch.channel().sendEvent("222", "world", &.{}, .chunk);

    ch.draft_mu.lock();
    const target_draft_id = ch.draft_buffers.get("111").?.draft_id;
    const other_draft_id = ch.draft_buffers.get("222").?.draft_id;
    ch.draft_mu.unlock();

    ch.suppressDraftSendsForTarget("111", 5);

    try std.testing.expect(ch.shouldSkipDraftSend("111", target_draft_id, std.time.milliTimestamp()));
    try std.testing.expect(!ch.shouldSkipDraftSend("222", other_draft_id, std.time.milliTimestamp()));
    try std.testing.expectEqual(@as(i64, 0), ch.draft_global_suppress_until_ms);
}

test "vtableSendEvent disabled streaming is noop" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    ch.streaming_enabled = false;
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "data", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expect(ch.draft_buffers.get("12345") == null);
}

test "vtableSendEvent empty chunk is ignored" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expect(ch.draft_buffers.get("12345") == null);
}

test "vtableSendEvent final on nonexistent chat is safe" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    // Should not panic or error
    try ch.channel().sendEvent("nonexistent", "", &.{}, .final);
}

test "ensureDraftStateLocked initializes started_at and flush timestamp" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const state = try ch.ensureDraftStateLocked("12345", 42_000);
    try std.testing.expect(state.draft_id > 0);
    try std.testing.expectEqual(@as(i64, 42_000), state.started_at_ms);
    try std.testing.expectEqual(@as(i64, 42_000), state.last_flush_time);
}

test "beginDraftStateLocked resets timer and rotates draft id" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();

    const first = try ch.beginDraftStateLocked("12345", 10_000);
    const first_id = first.draft_id;
    try first.buffer.appendSlice(allocator, "stale chunk");
    first.last_flush_len = first.buffer.items.len;

    const second = try ch.beginDraftStateLocked("12345", 20_000);
    try std.testing.expect(second.draft_id != first_id);
    try std.testing.expectEqualStrings("", second.buffer.items);
    try std.testing.expectEqual(@as(usize, 0), second.last_flush_len);
    try std.testing.expectEqual(@as(i64, 20_000), second.started_at_ms);
    try std.testing.expectEqual(@as(i64, 20_000), second.last_flush_time);
}

test "finishDraftTurn ignores stale draft id" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    ch.draft_mu.lock();
    const first = try ch.beginDraftStateLocked("12345", 10_000);
    const stale_id = first.draft_id;
    const current = try ch.beginDraftStateLocked("12345", 20_000);
    const current_id = current.draft_id;
    ch.draft_mu.unlock();

    try ch.finishDraftTurn("12345", stale_id);

    ch.draft_mu.lock();
    try std.testing.expect(ch.draft_buffers.get("12345") != null);
    try std.testing.expectEqual(current_id, ch.draft_buffers.get("12345").?.draft_id);
    ch.draft_mu.unlock();

    try ch.finishDraftTurn("12345", current_id);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expect(ch.draft_buffers.get("12345") == null);
}

test "sendDraftChunkForTurn ignores stale draft turn" {
    const allocator = std.testing.allocator;
    var ch = TelegramChannel.init(allocator, "test-token", &.{}, &.{}, "allowlist");
    defer ch.deinitDraftBuffers();

    ch.draft_mu.lock();
    const first = try ch.beginDraftStateLocked("12345", 10_000);
    const stale_id = first.draft_id;
    const current = try ch.beginDraftStateLocked("12345", 20_000);
    const current_id = current.draft_id;
    ch.draft_mu.unlock();

    try ch.sendDraftChunkForTurn("12345", stale_id, "stale");

    ch.draft_mu.lock();
    try std.testing.expectEqualStrings("", ch.draft_buffers.get("12345").?.buffer.items);
    ch.draft_mu.unlock();

    try ch.sendDraftChunkForTurn("12345", current_id, "fresh");

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expectEqualStrings("fresh", ch.draft_buffers.get("12345").?.buffer.items);
}

test "nextAdaptiveSplitLimit halves toward minimum threshold" {
    try std.testing.expectEqual(@as(usize, 512), TelegramChannel.nextAdaptiveSplitLimit(1024, 5000));
    try std.testing.expectEqual(@as(usize, 256), TelegramChannel.nextAdaptiveSplitLimit(400, 5000));
    try std.testing.expectEqual(@as(usize, 199), TelegramChannel.nextAdaptiveSplitLimit(400, 200));
    try std.testing.expectEqual(@as(usize, 0), TelegramChannel.nextAdaptiveSplitLimit(400, 1));
}

test "parseTelegramTarget extracts topic suffix" {
    const parsed = parseTelegramTarget("-100123#topic:77");
    try std.testing.expectEqualStrings("-100123", parsed.chat_id);
    try std.testing.expectEqual(@as(?i64, 77), parsed.message_thread_id);
}

test "createForumTopicFromTarget rejects empty name" {
    var ch = TelegramChannel.init(std.testing.allocator, "test-token", &.{}, &.{}, "allowlist");
    try std.testing.expectError(error.InvalidTopicName, ch.createForumTopicFromTarget("-100123#topic:77", "   "));
}
