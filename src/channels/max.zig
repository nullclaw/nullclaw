//! Max messenger channel — uses the Max Bot API with long-polling or webhooks.
//!
//! Implements the Channel vtable interface for the Max (VK Teams successor)
//! messaging platform. Supports inline keyboards, draft streaming via
//! message editing, typing indicators, and attachment forwarding.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const interaction_choices = @import("../interactions/choices.zig");
const max_api = @import("max_api.zig");
const max_ingress = @import("max_ingress.zig");
const thread_stacks = @import("../thread_stacks.zig");
const streaming = @import("../streaming.zig");
const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.max);

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

pub const MAX_MESSAGE_LEN: usize = 4000;
const CONTINUATION_MARKER = "\n\n\u{23EC}";
const CALLBACK_PAYLOAD_PREFIX = "ncmax:";
const TYPING_INTERVAL_NS: u64 = 4 * std.time.ns_per_s;
const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;
const DRAFT_MIN_EDIT_INTERVAL_MS: i64 = 500;
const DRAFT_MIN_DELTA_CHARS: usize = 100;

// ════════════════════════════════════════════════════════════════════════════
// Attachment parsing (legacy markers)
// ════════════════════════════════════════════════════════════════════════════

const AttachmentKind = enum {
    image,
    document,
    video,
    audio,

    fn apiFileType(self: AttachmentKind) []const u8 {
        return switch (self) {
            .image => "image",
            .document => "file",
            .video => "video",
            .audio => "audio",
        };
    }

    fn markerPrefix(self: AttachmentKind) []const u8 {
        return switch (self) {
            .image => "[IMAGE:",
            .document => "[DOCUMENT:",
            .video => "[VIDEO:",
            .audio => "[AUDIO:",
        };
    }
};

const ParsedAttachment = struct {
    kind: AttachmentKind,
    target: []const u8,
};

const ParsedMessage = struct {
    attachments: []ParsedAttachment,
    remaining_text: []const u8,
    remaining_owned: []u8,
    attachments_owned: []ParsedAttachment,

    fn deinit(self: *const ParsedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.remaining_owned);
        allocator.free(self.attachments_owned);
    }
};

fn parseMarkerKind(kind_str: []const u8) ?AttachmentKind {
    if (std.ascii.eqlIgnoreCase(kind_str, "image") or std.ascii.eqlIgnoreCase(kind_str, "photo"))
        return .image;
    if (std.ascii.eqlIgnoreCase(kind_str, "document") or std.ascii.eqlIgnoreCase(kind_str, "file"))
        return .document;
    if (std.ascii.eqlIgnoreCase(kind_str, "video"))
        return .video;
    if (std.ascii.eqlIgnoreCase(kind_str, "audio") or std.ascii.eqlIgnoreCase(kind_str, "voice"))
        return .audio;
    return null;
}

fn parseAttachmentMarkers(allocator: std.mem.Allocator, text: []const u8) !ParsedMessage {
    var attachments: std.ArrayListUnmanaged(ParsedAttachment) = .empty;
    errdefer attachments.deinit(allocator);

    var remaining: std.ArrayListUnmanaged(u8) = .empty;
    errdefer remaining.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < text.len) {
        const open_pos = std.mem.indexOfPos(u8, text, cursor, "[") orelse {
            try remaining.appendSlice(allocator, text[cursor..]);
            break;
        };

        try remaining.appendSlice(allocator, text[cursor..open_pos]);

        const close_pos = std.mem.indexOfPos(u8, text, open_pos, "]") orelse {
            try remaining.appendSlice(allocator, text[open_pos..]);
            break;
        };

        const marker = text[open_pos + 1 .. close_pos];

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

        try remaining.appendSlice(allocator, text[open_pos .. close_pos + 1]);
        cursor = close_pos + 1;
    }

    const trimmed = std.mem.trim(u8, remaining.items, " \t\n\r");
    const remaining_owned = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(remaining_owned);

    const final_attachments = try attachments.toOwnedSlice(allocator);
    remaining.deinit(allocator);

    return .{
        .attachments = final_attachments,
        .remaining_text = remaining_owned,
        .remaining_owned = remaining_owned,
        .attachments_owned = final_attachments,
    };
}

fn validateChoices(choices: []const root.Channel.OutboundChoice) bool {
    if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) {
        return false;
    }

    for (choices) |choice| {
        if (choice.id.len == 0 or choice.id.len > interaction_choices.MAX_ID_LEN) return false;
        if (choice.label.len == 0 or choice.label.len > interaction_choices.MAX_LABEL_LEN) return false;
        if (choice.submit_text.len == 0 or choice.submit_text.len > interaction_choices.MAX_SUBMIT_TEXT_LEN) return false;
    }

    return true;
}

fn buildOutgoingTextChunks(allocator: std.mem.Allocator, text: []const u8) ![]OutgoingTextChunk {
    if (text.len == 0) return allocator.alloc(OutgoingTextChunk, 0);

    var raw_chunks: std.ArrayListUnmanaged([]const u8) = .empty;
    defer raw_chunks.deinit(allocator);

    var it = root.splitMessage(text, MAX_MESSAGE_LEN - CONTINUATION_MARKER.len);
    while (it.next()) |chunk| {
        try raw_chunks.append(allocator, chunk);
    }

    const chunks = try allocator.alloc(OutgoingTextChunk, raw_chunks.items.len);
    var built: usize = 0;
    errdefer {
        for (chunks[0..built]) |chunk| chunk.deinit(allocator);
        allocator.free(chunks);
    }

    for (raw_chunks.items, 0..) |chunk, i| {
        const is_last = i == raw_chunks.items.len - 1;
        if (is_last) {
            chunks[i] = .{ .body = chunk };
        } else {
            var body: std.ArrayListUnmanaged(u8) = .empty;
            errdefer body.deinit(allocator);
            try body.appendSlice(allocator, chunk);
            try body.appendSlice(allocator, CONTINUATION_MARKER);
            const owned = try body.toOwnedSlice(allocator);
            chunks[i] = .{
                .body = owned,
                .owned = owned,
            };
        }
        built += 1;
    }

    return chunks;
}

fn buildDraftPreviewChunk(allocator: std.mem.Allocator, text: []const u8) !OutgoingTextChunk {
    if (text.len == 0) return .{ .body = "" };

    var it = root.splitMessage(text, MAX_MESSAGE_LEN - CONTINUATION_MARKER.len);
    const first_chunk = it.next() orelse return .{ .body = "" };
    if (it.remaining.len == 0) {
        return .{ .body = first_chunk };
    }

    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);
    try body.appendSlice(allocator, first_chunk);
    try body.appendSlice(allocator, CONTINUATION_MARKER);
    const owned = try body.toOwnedSlice(allocator);
    return .{
        .body = owned,
        .owned = owned,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Draft State (streaming via message editing)
// ════════════════════════════════════════════════════════════════════════════

const DraftState = struct {
    mid: ?[]u8 = null,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    last_edit_ms: i64 = 0,
    last_edit_len: usize = 0,

    fn deinit(self: *DraftState, allocator: std.mem.Allocator) void {
        if (self.mid) |m| allocator.free(m);
        self.buffer.deinit(allocator);
    }
};

const OutgoingTextChunk = struct {
    body: []const u8,
    owned: ?[]u8 = null,

    fn deinit(self: *const OutgoingTextChunk, allocator: std.mem.Allocator) void {
        if (self.owned) |buf| allocator.free(buf);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Pending Interaction (inline keyboard callbacks)
// ════════════════════════════════════════════════════════════════════════════

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
    allocator: std.mem.Allocator,
    created_at: u64,
    expires_at: u64,
    account_id: []const u8,
    chat_id: []const u8,
    owner_identity: ?[]const u8 = null,
    owner_only: bool = true,
    message_text: ?[]const u8 = null,
    options: []PendingInteractionOption,

    fn deinit(self: *const PendingInteraction) void {
        self.allocator.free(self.account_id);
        self.allocator.free(self.chat_id);
        if (self.owner_identity) |owner| self.allocator.free(owner);
        if (self.message_text) |text| self.allocator.free(text);
        for (self.options) |opt| opt.deinit(self.allocator);
        self.allocator.free(self.options);
    }
};

const CallbackSelection = union(enum) {
    ok: struct {
        submit_text: []u8,
        callback_notification: []u8,
        clear_message_text: ?[]u8 = null,
    },
    not_found,
    expired,
    owner_mismatch,
    chat_mismatch,
    invalid_option,
};

threadlocal var tls_interaction_owner_identity: ?[]const u8 = null;
var shared_interactions_mu: std.Thread.Mutex = .{};
var shared_interactions: std.StringHashMapUnmanaged(PendingInteraction) = .empty;
var shared_interaction_seq: Atomic(u64) = Atomic(u64).init(1);

fn sharedInteractionsAllocator() std.mem.Allocator {
    return if (builtin.is_test) std.testing.allocator else std.heap.page_allocator;
}

pub fn setInteractiveOwnerContext(owner_identity: ?[]const u8) void {
    tls_interaction_owner_identity = owner_identity;
}

// ════════════════════════════════════════════════════════════════════════════
// Typing Task
// ════════════════════════════════════════════════════════════════════════════

const TypingTask = struct {
    max_channel: *MaxChannel,
    chat_id: []const u8,
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
};

fn typingLoop(task: *TypingTask) void {
    while (!task.stop_requested.load(.acquire)) {
        task.max_channel.api().sendTypingAction(
            task.max_channel.allocator,
            task.chat_id,
        ) catch {};

        var elapsed: u64 = 0;
        while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
            std.Thread.sleep(TYPING_SLEEP_STEP_NS);
            elapsed += TYPING_SLEEP_STEP_NS;
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MaxChannel
// ════════════════════════════════════════════════════════════════════════════

pub const MaxChannel = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    account_id: []const u8 = "default",
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    group_policy: []const u8,
    proxy: ?[]const u8 = null,
    mode: config_types.MaxListenerMode = .polling,
    webhook_url: ?[]const u8 = null,
    webhook_secret: ?[]const u8 = null,
    interactive: config_types.MaxInteractiveConfig = .{},
    require_mention: bool = false,
    streaming_enabled: bool = true,

    bot_username: ?[]const u8 = null,
    bot_user_id: ?[]const u8 = null,
    marker: ?[]u8 = null,
    running: bool = false,

    typing_mu: std.Thread.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,

    draft_mu: std.Thread.Mutex = .{},
    draft_buffers: std.StringHashMapUnmanaged(DraftState) = .empty,

    // ── Construction ─────────────────────────────────────────────────

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.MaxConfig) MaxChannel {
        return .{
            .allocator = allocator,
            .bot_token = cfg.bot_token,
            .allow_from = cfg.allow_from,
            .group_allow_from = cfg.group_allow_from,
            .group_policy = cfg.group_policy,
            .account_id = cfg.account_id,
            .proxy = cfg.proxy,
            .mode = cfg.mode,
            .webhook_url = cfg.webhook_url,
            .webhook_secret = cfg.webhook_secret,
            .interactive = cfg.interactive,
            .require_mention = cfg.require_mention,
            .streaming_enabled = cfg.streaming,
        };
    }

    pub fn channelName(_: *const MaxChannel) []const u8 {
        return "max";
    }

    pub fn api(self: *const MaxChannel) max_api.Client {
        return .{
            .allocator = self.allocator,
            .bot_token = self.bot_token,
            .proxy = self.proxy,
        };
    }

    pub fn healthCheck(self: *MaxChannel) bool {
        if (comptime builtin.is_test) return true;
        return self.api().getMeOk();
    }

    // ── Authorization ────────────────────────────────────────────────

    pub fn isUserAllowed(self: *const MaxChannel, sender_id: []const u8) bool {
        return root.isAllowed(self.allow_from, sender_id);
    }

    pub fn isGroupUserAllowed(self: *const MaxChannel, sender_id: []const u8) bool {
        if (self.group_allow_from.len == 0) {
            return self.isUserAllowed(sender_id);
        }
        return root.isAllowed(self.group_allow_from, sender_id);
    }

    fn isAuthorized(self: *const MaxChannel, sender_id: []const u8, is_group: bool) bool {
        if (is_group) {
            if (std.mem.eql(u8, self.group_policy, "open")) return true;
            if (std.mem.eql(u8, self.group_policy, "disabled")) return false;
            return self.isGroupUserAllowed(sender_id);
        }
        return self.isUserAllowed(sender_id);
    }

    fn isAuthorizedSender(self: *const MaxChannel, sender: *const max_ingress.SenderInfo, is_group: bool) bool {
        const identity = sender.identity();
        const user_id = sender.user_id;

        if (is_group) {
            if (std.mem.eql(u8, self.group_policy, "open")) return true;
            if (std.mem.eql(u8, self.group_policy, "disabled")) return false;
            if (self.group_allow_from.len == 0) {
                return root.isAllowed(self.allow_from, identity) or
                    root.isAllowed(self.allow_from, user_id);
            }
            return root.isAllowed(self.group_allow_from, identity) or
                root.isAllowed(self.group_allow_from, user_id);
        }

        return root.isAllowed(self.allow_from, identity) or
            root.isAllowed(self.allow_from, user_id);
    }

    // ── Fetch bot identity ───────────────────────────────────────────

    fn fetchBotIdentity(self: *MaxChannel) void {
        if (self.bot_username != null and self.bot_user_id != null) return;
        if (comptime builtin.is_test) return;
        const info = self.api().fetchBotInfo(self.allocator) orelse return;
        defer info.deinit(self.allocator);
        if (info.username) |u| {
            self.bot_username = self.allocator.dupe(u8, u) catch null;
        }
        if (info.user_id) |uid| {
            self.bot_user_id = self.allocator.dupe(u8, uid) catch null;
        }
    }

    fn shouldProcessMessage(self: *MaxChannel, msg: max_ingress.InboundMessage) bool {
        if (!self.require_mention or !msg.chat.isGroup()) return true;
        const text = msg.text orelse return false;

        if (self.bot_username == null and self.bot_user_id == null and !builtin.is_test) {
            self.fetchBotIdentity();
        }

        return self.textMentionsBot(text);
    }

    fn textMentionsBot(self: *const MaxChannel, text: []const u8) bool {
        if (self.bot_username) |username| {
            var mention_buf: [256]u8 = undefined;
            const mention = std.fmt.bufPrint(&mention_buf, "@{s}", .{username}) catch username;
            if (asciiContainsIgnoreCase(text, mention)) return true;
        }

        if (self.bot_user_id) |user_id| {
            var deep_link_buf: [256]u8 = undefined;
            const deep_link = std.fmt.bufPrint(&deep_link_buf, "max://user/{s}", .{user_id}) catch user_id;
            if (asciiContainsIgnoreCase(text, deep_link)) return true;
        }

        return false;
    }

    fn stableSenderId(_: *const MaxChannel, sender: *const max_ingress.SenderInfo) []const u8 {
        return sender.user_id;
    }

    // ── Send (text + attachments) ────────────────────────────────────

    pub fn sendMessage(self: *MaxChannel, target: []const u8, text: []const u8) !void {
        const parsed = try parseAttachmentMarkers(self.allocator, text);
        defer parsed.deinit(self.allocator);

        try self.sendTextChunked(target, parsed.remaining_text);

        for (parsed.attachments) |att| {
            self.sendAttachment(target, att) catch |err| {
                log.warn("max sendAttachment failed: {}", .{err});
            };
        }
    }

    fn sendTextChunked(self: *MaxChannel, target: []const u8, text: []const u8) !void {
        if (text.len == 0) return;

        const chunks = try buildOutgoingTextChunks(self.allocator, text);
        defer {
            for (chunks) |chunk| chunk.deinit(self.allocator);
            self.allocator.free(chunks);
        }

        for (chunks) |chunk| {
            const body = try max_api.buildTextMessageBody(self.allocator, chunk.body, "markdown");
            defer self.allocator.free(body);

            const resp = try self.api().sendMessage(self.allocator, target, body);
            self.allocator.free(resp);
        }
    }

    fn sendAttachment(self: *MaxChannel, target: []const u8, att: ParsedAttachment) !void {
        if (comptime builtin.is_test) return;

        const upload_resp = try self.api().uploadFile(self.allocator, att.kind.apiFileType(), att.target);
        defer self.allocator.free(upload_resp);

        const token = max_api.Client.parseUploadToken(self.allocator, upload_resp) orelse return;
        defer self.allocator.free(token);

        // Build body with attachment token
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"text\":\"\",\"attachments\":[{\"type\":\"");
        try body.appendSlice(self.allocator, att.kind.apiFileType());
        try body.appendSlice(self.allocator, "\",\"payload\":{\"token\":");
        try root.json_util.appendJsonString(&body, self.allocator, token);
        try body.appendSlice(self.allocator, "}}]}");

        var attempt: u8 = 0;
        while (true) {
            const resp = try self.api().sendMessage(self.allocator, target, body.items);
            const ready = std.mem.indexOf(u8, resp, "attachment.not.ready") == null;
            self.allocator.free(resp);

            if (ready) break;
            if (attempt >= 4) return error.AttachmentNotReady;

            attempt += 1;
            if (!builtin.is_test) std.Thread.sleep(500 * std.time.ns_per_ms);
        }
    }

    // ── sendRich (inline keyboards) ──────────────────────────────────

    pub fn sendRichPayload(self: *MaxChannel, target: []const u8, payload: root.Channel.OutboundPayload) !void {
        if (payload.choices.len > 0 and self.interactive.enabled and validateChoices(payload.choices)) {
            const token = try self.nextInteractionToken();
            defer self.allocator.free(token);

            const buttons = try self.allocator.alloc(max_api.InlineKeyboardButton, payload.choices.len);
            defer self.allocator.free(buttons);

            var payload_bufs = try self.allocator.alloc([]u8, payload.choices.len);
            var built_payloads: usize = 0;
            defer {
                for (payload_bufs[0..built_payloads]) |value| self.allocator.free(value);
                self.allocator.free(payload_bufs);
            }

            for (payload.choices, 0..) |choice, i| {
                payload_bufs[i] = try std.fmt.allocPrint(self.allocator, "{s}{s}:{d}", .{
                    CALLBACK_PAYLOAD_PREFIX,
                    token,
                    i,
                });
                buttons[i] = .{
                    .text = choice.label,
                    .payload = payload_bufs[i],
                };
                built_payloads += 1;
            }

            const keyboard_json = try max_api.buildInlineKeyboardButtonsJson(self.allocator, buttons);
            defer self.allocator.free(keyboard_json);

            const body_json = try max_api.buildTextWithKeyboardBody(
                self.allocator,
                payload.text,
                keyboard_json,
                "markdown",
            );
            defer self.allocator.free(body_json);

            const resp = try self.api().sendMessage(self.allocator, target, body_json);
            defer self.allocator.free(resp);

            self.registerPendingInteraction(
                token,
                target,
                tls_interaction_owner_identity,
                payload.choices,
                payload.text,
            ) catch |err| log.warn("max registerPendingInteraction failed: {}", .{err});

            for (payload.attachments) |att| {
                const kind: AttachmentKind = switch (att.kind) {
                    .image => .image,
                    .document => .document,
                    .video => .video,
                    .audio, .voice => .audio,
                };
                self.sendAttachment(target, .{ .kind = kind, .target = att.target }) catch |err| {
                    log.warn("max sendAttachment failed: {}", .{err});
                };
            }
            return;
        }

        // Fall back to plain send
        const parsed = try parseAttachmentMarkers(self.allocator, payload.text);
        defer parsed.deinit(self.allocator);
        try self.sendTextChunked(target, parsed.remaining_text);

        for (parsed.attachments) |att| {
            self.sendAttachment(target, att) catch |err| {
                log.warn("max sendAttachment failed: {}", .{err});
            };
        }

        for (payload.attachments) |att| {
            const kind: AttachmentKind = switch (att.kind) {
                .image => .image,
                .document => .document,
                .video => .video,
                .audio, .voice => .audio,
            };
            self.sendAttachment(target, .{ .kind = kind, .target = att.target }) catch |err| {
                log.warn("max sendAttachment failed: {}", .{err});
            };
        }
    }

    // ── Pending interactions ──────────────────────────────────────────

    fn nextInteractionToken(self: *const MaxChannel) ![]u8 {
        var token_buf: [32]u8 = undefined;
        const seq = shared_interaction_seq.fetchAdd(1, .monotonic);
        const token = std.fmt.bufPrint(&token_buf, "{x}", .{seq}) catch unreachable;
        return self.allocator.dupe(u8, token);
    }

    fn registerPendingInteraction(
        self: *MaxChannel,
        token: []const u8,
        chat_id: []const u8,
        owner_identity: ?[]const u8,
        choices: []const root.Channel.OutboundChoice,
        message_text: []const u8,
    ) !void {
        const interaction_allocator = sharedInteractionsAllocator();
        const now = root.nowEpochSecs();
        const ttl = self.interactive.ttl_secs;

        var options = try interaction_allocator.alloc(PendingInteractionOption, choices.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(interaction_allocator);
            interaction_allocator.free(options);
        }

        for (choices, 0..) |choice, i| {
            options[i] = .{
                .id = try interaction_allocator.dupe(u8, choice.id),
                .label = try interaction_allocator.dupe(u8, choice.label),
                .submit_text = try interaction_allocator.dupe(u8, choice.submit_text),
            };
            built += 1;
        }

        const key = try interaction_allocator.dupe(u8, token);
        errdefer interaction_allocator.free(key);

        const chat_id_dup = try interaction_allocator.dupe(u8, chat_id);
        errdefer interaction_allocator.free(chat_id_dup);

        const account_id_dup = try interaction_allocator.dupe(u8, self.account_id);
        errdefer interaction_allocator.free(account_id_dup);

        const owner_dup = if (owner_identity) |owner|
            try interaction_allocator.dupe(u8, owner)
        else
            null;
        errdefer if (owner_dup) |owner| interaction_allocator.free(owner);

        const message_text_dup = if (message_text.len > 0)
            try interaction_allocator.dupe(u8, message_text)
        else
            null;
        errdefer if (message_text_dup) |text| interaction_allocator.free(text);

        shared_interactions_mu.lock();
        defer shared_interactions_mu.unlock();

        self.expireInteractionsLocked(now);

        try shared_interactions.put(interaction_allocator, key, .{
            .allocator = interaction_allocator,
            .created_at = now,
            .expires_at = now + ttl,
            .account_id = account_id_dup,
            .chat_id = chat_id_dup,
            .owner_identity = owner_dup,
            .owner_only = self.interactive.owner_only,
            .message_text = message_text_dup,
            .options = options,
        });
    }

    fn expireInteractionsLocked(self: *MaxChannel, now: u64) void {
        _ = self;
        while (true) {
            var expired_key: ?[]const u8 = null;
            var it = shared_interactions.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.expires_at < now) {
                    expired_key = entry.key_ptr.*;
                    break;
                }
            }

            const key = expired_key orelse break;
            if (shared_interactions.fetchRemove(key)) |removed| {
                removed.value.deinit();
                removed.value.allocator.free(@constCast(removed.key));
            }
        }

        if (shared_interactions.count() == 0) {
            shared_interactions.deinit(sharedInteractionsAllocator());
            shared_interactions = .empty;
        }
    }

    fn consumeInteractionSelection(
        self: *MaxChannel,
        token: []const u8,
        option_index: usize,
        sender_identity: []const u8,
        chat_id: []const u8,
    ) CallbackSelection {
        shared_interactions_mu.lock();
        defer shared_interactions_mu.unlock();

        const now = root.nowEpochSecs();
        self.expireInteractionsLocked(now);

        const interaction = shared_interactions.getPtr(token) orelse return .not_found;
        if (!std.ascii.eqlIgnoreCase(interaction.account_id, self.account_id)) return .not_found;
        if (!std.mem.eql(u8, interaction.chat_id, chat_id)) return .chat_mismatch;
        if (interaction.owner_only and interaction.owner_identity != null and
            !std.ascii.eqlIgnoreCase(interaction.owner_identity.?, sender_identity))
        {
            return .owner_mismatch;
        }
        if (option_index >= interaction.options.len) return .invalid_option;

        const submit_text = self.allocator.dupe(u8, interaction.options[option_index].submit_text) catch return .invalid_option;
        errdefer self.allocator.free(submit_text);

        const callback_notification = self.allocator.dupe(u8, interaction.options[option_index].label) catch return .invalid_option;
        errdefer self.allocator.free(callback_notification);
        const clear_message_text = if (interaction.message_text) |text|
            self.allocator.dupe(u8, text) catch return .invalid_option
        else
            null;
        errdefer if (clear_message_text) |text| self.allocator.free(text);

        if (shared_interactions.fetchRemove(token)) |removed| {
            removed.value.deinit();
            removed.value.allocator.free(@constCast(removed.key));
        }

        return .{ .ok = .{
            .submit_text = submit_text,
            .callback_notification = callback_notification,
            .clear_message_text = clear_message_text,
        } };
    }

    fn deinitPendingInteractions(self: *MaxChannel) void {
        shared_interactions_mu.lock();
        defer shared_interactions_mu.unlock();

        while (true) {
            var matching_key: ?[]const u8 = null;
            var it = shared_interactions.iterator();
            while (it.next()) |entry| {
                if (std.ascii.eqlIgnoreCase(entry.value_ptr.account_id, self.account_id)) {
                    matching_key = entry.key_ptr.*;
                    break;
                }
            }

            const key = matching_key orelse break;
            if (shared_interactions.fetchRemove(key)) |removed| {
                removed.value.deinit();
                removed.value.allocator.free(@constCast(removed.key));
            }
        }

        if (shared_interactions.count() == 0) {
            shared_interactions.deinit(sharedInteractionsAllocator());
            shared_interactions = .empty;
        }
    }

    // ── Draft streaming (sendEvent) ──────────────────────────────────

    fn ensureDraftStateLocked(self: *MaxChannel, target: []const u8, now_ms: i64) !*DraftState {
        const gop = try self.draft_buffers.getOrPut(self.allocator, target);
        if (!gop.found_existing) {
            const key_copy = try self.allocator.dupe(u8, target);
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{
                .last_edit_ms = now_ms,
            };
        }
        return gop.value_ptr;
    }

    fn clearDraftForTarget(self: *MaxChannel, target: []const u8) void {
        if (self.draft_buffers.fetchRemove(target)) |entry| {
            var state = entry.value;
            state.deinit(self.allocator);
            self.allocator.free(@constCast(entry.key));
        }
    }

    fn deinitDraftBuffers(self: *MaxChannel) void {
        self.draft_mu.lock();
        var buffers = self.draft_buffers;
        self.draft_buffers = .empty;
        self.draft_mu.unlock();

        var it = buffers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        buffers.deinit(self.allocator);
    }

    fn handleSendEventChunk(self: *MaxChannel, target: []const u8, message: []const u8) !void {
        if (message.len == 0) return;

        const now_ms = std.time.milliTimestamp();

        self.draft_mu.lock();
        defer self.draft_mu.unlock();

        const state = try self.ensureDraftStateLocked(target, now_ms);
        try state.buffer.appendSlice(self.allocator, message);

        // Rate-limit edits
        const elapsed = now_ms - state.last_edit_ms;
        const delta = state.buffer.items.len -| state.last_edit_len;

        if (elapsed < DRAFT_MIN_EDIT_INTERVAL_MS or delta < DRAFT_MIN_DELTA_CHARS) {
            return;
        }

        const preview = buildDraftPreviewChunk(self.allocator, state.buffer.items) catch return;
        defer preview.deinit(self.allocator);
        if (preview.body.len == 0) return;

        // Flush: send or edit
        if (state.mid == null) {
            // Send initial message
            const body = max_api.buildTextMessageBody(
                self.allocator,
                preview.body,
                "markdown",
            ) catch return;
            defer self.allocator.free(body);

            const resp = self.api().sendMessage(self.allocator, target, body) catch return;
            defer self.allocator.free(resp);

            if (max_api.Client.parseSentMessageMid(self.allocator, resp)) |meta| {
                if (meta.mid) |mid| {
                    state.mid = mid;
                } else {
                    meta.deinit(self.allocator);
                }
            }
        } else {
            // Edit existing message
            const body = max_api.buildTextMessageBody(
                self.allocator,
                preview.body,
                "markdown",
            ) catch return;
            defer self.allocator.free(body);

            const resp = self.api().editMessage(self.allocator, state.mid.?, body) catch return;
            self.allocator.free(resp);
        }

        state.last_edit_ms = now_ms;
        state.last_edit_len = state.buffer.items.len;
    }

    fn handleSendEventFinal(self: *MaxChannel, target: []const u8, message: []const u8) !void {
        var draft_mid: ?[]u8 = null;
        self.draft_mu.lock();
        if (self.draft_buffers.getPtr(target)) |state| {
            if (state.mid) |mid| {
                draft_mid = self.allocator.dupe(u8, mid) catch null;
            }
            self.clearDraftForTarget(target);
        }
        self.draft_mu.unlock();
        defer if (draft_mid) |mid| self.allocator.free(mid);

        if (message.len == 0) return;

        if (draft_mid) |mid| {
            const parsed = try parseAttachmentMarkers(self.allocator, message);
            defer parsed.deinit(self.allocator);
            const chunks = try buildOutgoingTextChunks(self.allocator, parsed.remaining_text);
            defer {
                for (chunks) |chunk| chunk.deinit(self.allocator);
                self.allocator.free(chunks);
            }

            if (chunks.len > 0) {
                const body = try max_api.buildTextMessageBody(self.allocator, chunks[0].body, "markdown");
                defer self.allocator.free(body);

                const resp = try self.api().editMessage(self.allocator, mid, body);
                self.allocator.free(resp);

                for (chunks[1..]) |chunk| {
                    const chunk_body = try max_api.buildTextMessageBody(self.allocator, chunk.body, "markdown");
                    defer self.allocator.free(chunk_body);

                    const chunk_resp = try self.api().sendMessage(self.allocator, target, chunk_body);
                    self.allocator.free(chunk_resp);
                }
            } else {
                self.api().deleteMessage(self.allocator, mid) catch {};
            }

            for (parsed.attachments) |att| {
                self.sendAttachment(target, att) catch |err| {
                    log.warn("max sendAttachment failed: {}", .{err});
                };
            }
            return;
        }

        try self.sendMessage(target, message);
    }

    // ── Typing indicator ─────────────────────────────────────────────

    pub fn startTyping(self: *MaxChannel, chat_id: []const u8) !void {
        if (chat_id.len == 0) return;
        try self.stopTyping(chat_id);

        const key_copy = try self.allocator.dupe(u8, chat_id);
        const task = try self.allocator.create(TypingTask);
        task.* = .{
            .max_channel = self,
            .chat_id = key_copy,
        };

        var spawned = false;
        errdefer {
            if (spawned) {
                task.stop_requested.store(true, .release);
                if (task.thread) |t| t.join();
            }
            self.allocator.destroy(task);
            self.allocator.free(key_copy);
        }

        if (comptime !builtin.is_test) {
            task.thread = try std.Thread.spawn(
                .{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE },
                typingLoop,
                .{task},
            );
            spawned = true;
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *MaxChannel, chat_id: []const u8) !void {
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

    fn stopAllTyping(self: *MaxChannel) void {
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

    // ── Process update ───────────────────────────────────────────────

    pub fn processUpdate(self: *MaxChannel, allocator: std.mem.Allocator, update_obj: std.json.Value) ?root.ChannelMessage {
        const parsed = max_ingress.parseUpdate(allocator, update_obj) orelse return null;

        switch (parsed) {
            .message => |msg| {
                defer msg.deinit(allocator);

                if (!self.isAuthorizedSender(&msg.sender, msg.chat.isGroup())) {
                    log.warn("ignoring message from unauthorized user: {s}", .{msg.sender.identity()});
                    return null;
                }

                if (!self.shouldProcessMessage(msg)) {
                    return null;
                }

                // Build content with attachment markers
                var content_buf: std.ArrayListUnmanaged(u8) = .empty;
                defer content_buf.deinit(allocator);

                if (msg.text) |text| {
                    content_buf.appendSlice(allocator, text) catch return null;
                }

                // Append attachment markers
                const min_len = @min(msg.attachment_urls.len, msg.attachment_types.len);
                for (0..min_len) |i| {
                    const prefix = max_ingress.attachmentMarkerPrefix(msg.attachment_types[i]) orelse continue;
                    if (content_buf.items.len > 0) {
                        content_buf.appendSlice(allocator, "\n") catch continue;
                    }
                    content_buf.appendSlice(allocator, prefix) catch continue;
                    content_buf.appendSlice(allocator, msg.attachment_urls[i]) catch continue;
                    content_buf.appendSlice(allocator, "]") catch continue;
                }

                if (content_buf.items.len == 0) return null;

                const id_owned = allocator.dupe(u8, msg.mid orelse "unknown") catch return null;
                errdefer allocator.free(id_owned);
                const sender_owned = allocator.dupe(u8, self.stableSenderId(&msg.sender)) catch {
                    allocator.free(id_owned);
                    return null;
                };
                errdefer allocator.free(sender_owned);
                const content_owned = allocator.dupe(u8, content_buf.items) catch {
                    allocator.free(id_owned);
                    allocator.free(sender_owned);
                    return null;
                };
                errdefer allocator.free(content_owned);
                const reply_target = allocator.dupe(u8, msg.chat.chat_id) catch {
                    allocator.free(id_owned);
                    allocator.free(sender_owned);
                    allocator.free(content_owned);
                    return null;
                };
                errdefer allocator.free(reply_target);
                const first_name: ?[]const u8 = if (msg.sender.name) |n|
                    (allocator.dupe(u8, n) catch null)
                else
                    null;

                return .{
                    .id = id_owned,
                    .sender = sender_owned,
                    .content = content_owned,
                    .channel = "max",
                    .timestamp = msg.timestamp,
                    .reply_target = reply_target,
                    .first_name = first_name,
                    .is_group = msg.chat.isGroup(),
                };
            },
            .callback => |cb| {
                defer cb.deinit(allocator);

                if (!self.isAuthorizedSender(&cb.sender, cb.is_group)) {
                    self.api().answerCallback(allocator, cb.callback_id, "You are not allowed to use this button") catch {};
                    return null;
                }

                const content_text = blk: {
                    if (parseCallbackPayload(cb.payload)) |parsed_payload| {
                        switch (self.consumeInteractionSelection(
                            parsed_payload.token,
                            parsed_payload.option_index,
                            self.stableSenderId(&cb.sender),
                            cb.chat_id,
                        )) {
                            .ok => |selection| {
                                const clear_message_body = if (selection.clear_message_text) |text|
                                    max_api.buildTextMessageBodyClearingAttachments(allocator, text, "markdown") catch null
                                else
                                    null;
                                defer if (clear_message_body) |body| allocator.free(body);
                                self.api().answerCallbackWithMessage(allocator, cb.callback_id, selection.callback_notification, clear_message_body) catch {};
                                allocator.free(selection.callback_notification);
                                if (selection.clear_message_text) |text| allocator.free(text);
                                break :blk selection.submit_text;
                            },
                            .owner_mismatch => {
                                self.api().answerCallback(allocator, cb.callback_id, "Only the original user can use this button") catch {};
                                return null;
                            },
                            .expired, .not_found => {
                                self.api().answerCallback(allocator, cb.callback_id, "Button expired or already handled") catch {};
                                return null;
                            },
                            .chat_mismatch, .invalid_option => {
                                self.api().answerCallback(allocator, cb.callback_id, "Invalid button") catch {};
                                return null;
                            },
                        }
                    }

                    self.api().answerCallback(allocator, cb.callback_id, null) catch {};
                    break :blk allocator.dupe(u8, cb.payload) catch return null;
                };

                const id_owned = allocator.dupe(u8, cb.callback_id) catch {
                    allocator.free(content_text);
                    return null;
                };
                errdefer allocator.free(id_owned);
                const sender_owned = allocator.dupe(u8, self.stableSenderId(&cb.sender)) catch {
                    allocator.free(id_owned);
                    allocator.free(content_text);
                    return null;
                };
                errdefer allocator.free(sender_owned);
                const reply_target = allocator.dupe(u8, cb.chat_id) catch {
                    allocator.free(id_owned);
                    allocator.free(sender_owned);
                    allocator.free(content_text);
                    return null;
                };

                return .{
                    .id = id_owned,
                    .sender = sender_owned,
                    .content = content_text,
                    .channel = "max",
                    .timestamp = if (cb.timestamp > 0) cb.timestamp else root.nowEpochSecs(),
                    .reply_target = reply_target,
                    .is_group = cb.is_group,
                };
            },
            .bot_started => |bs| {
                defer bs.deinit(allocator);

                if (!self.isAuthorizedSender(&bs.sender, false)) {
                    log.warn("ignoring max bot_started from unauthorized user: {s}", .{bs.sender.identity()});
                    return null;
                }

                // Build /start content
                var start_content: std.ArrayListUnmanaged(u8) = .empty;
                defer start_content.deinit(allocator);
                start_content.appendSlice(allocator, "/start") catch return null;
                if (bs.payload) |payload| {
                    start_content.appendSlice(allocator, " ") catch return null;
                    start_content.appendSlice(allocator, payload) catch return null;
                }

                const id_owned = if (bs.timestamp > 0)
                    std.fmt.allocPrint(allocator, "bot_started:{s}:{d}", .{ bs.chat_id, bs.timestamp }) catch return null
                else
                    std.fmt.allocPrint(allocator, "bot_started:{s}", .{bs.chat_id}) catch return null;
                errdefer allocator.free(id_owned);
                const sender_owned = allocator.dupe(u8, self.stableSenderId(&bs.sender)) catch {
                    allocator.free(id_owned);
                    return null;
                };
                errdefer allocator.free(sender_owned);
                const content_owned = allocator.dupe(u8, start_content.items) catch {
                    allocator.free(id_owned);
                    allocator.free(sender_owned);
                    return null;
                };
                errdefer allocator.free(content_owned);
                const reply_target = allocator.dupe(u8, bs.chat_id) catch {
                    allocator.free(id_owned);
                    allocator.free(sender_owned);
                    allocator.free(content_owned);
                    return null;
                };
                errdefer allocator.free(reply_target);

                const first_name: ?[]const u8 = if (bs.sender.name) |n|
                    (allocator.dupe(u8, n) catch null)
                else
                    null;

                return .{
                    .id = id_owned,
                    .sender = sender_owned,
                    .content = content_owned,
                    .channel = "max",
                    .timestamp = if (bs.timestamp > 0) bs.timestamp else root.nowEpochSecs(),
                    .reply_target = reply_target,
                    .first_name = first_name,
                };
            },
            .ignored => return null,
        }
    }

    // ── Poll updates ─────────────────────────────────────────────────

    pub fn pollUpdates(self: *MaxChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        const resp = try self.api().getUpdates(
            allocator,
            if (self.marker) |m| m else null,
            "30",
        );
        defer allocator.free(resp);

        var next_marker = max_ingress.parseUpdatesMarker(allocator, resp);
        errdefer if (next_marker) |marker| allocator.free(marker);

        // Parse updates array
        var parsed_resp = max_ingress.parseUpdatesArray(resp, allocator) orelse return &.{};
        defer parsed_resp.deinit();

        if (parsed_resp.value != .object) return &.{};
        const updates_val = parsed_resp.value.object.get("updates") orelse return &.{};
        if (updates_val != .array) return &.{};

        var messages: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer {
            for (messages.items) |*msg| msg.deinit(allocator);
            messages.deinit(allocator);
        }

        for (updates_val.array.items) |update_obj| {
            if (self.processUpdate(allocator, update_obj)) |msg| {
                try messages.append(allocator, msg);
            }
        }

        if (next_marker) |new_marker| {
            if (self.marker) |old| self.allocator.free(old);
            self.marker = new_marker;
            next_marker = null;
        }

        return try messages.toOwnedSlice(allocator);
    }

    // ── VTable wrappers ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        if (self.mode == .polling) {
            if (self.webhook_url) |webhook_url| {
                if (webhook_url.len > 0 and !builtin.is_test) {
                    self.api().unsubscribe(self.allocator, webhook_url) catch {};
                }
            }
        }

        if (self.mode == .webhook) {
            const webhook_url = self.webhook_url orelse return error.MissingWebhookUrl;
            const trimmed_url = std.mem.trim(u8, webhook_url, " \t\r\n");
            if (trimmed_url.len == 0) return error.MissingWebhookUrl;
            if (!std.mem.startsWith(u8, trimmed_url, "https://")) return error.InvalidWebhookUrl;

            if (!builtin.is_test) {
                const resp = try self.api().subscribe(self.allocator, trimmed_url, self.webhook_secret);
                self.allocator.free(resp);
            }
        }

        self.running = true;
        self.fetchBotIdentity();
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
        if (self.mode == .webhook and !builtin.is_test) {
            if (self.webhook_url) |webhook_url| {
                const trimmed_url = std.mem.trim(u8, webhook_url, " \t\r\n");
                if (trimmed_url.len > 0) {
                    self.api().unsubscribe(self.allocator, trimmed_url) catch |err| {
                        log.warn("max unsubscribe failed: {}", .{err});
                    };
                }
            }
        }
        self.stopAllTyping();
        self.deinitPendingInteractions();
        self.deinitDraftBuffers();
        if (self.marker) |m| {
            self.allocator.free(m);
            self.marker = null;
        }
        if (self.bot_username) |name| {
            self.allocator.free(name);
            self.bot_username = null;
        }
        if (self.bot_user_id) |uid| {
            self.allocator.free(uid);
            self.bot_user_id = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableSendEvent(
        ptr: *anyopaque,
        target: []const u8,
        message: []const u8,
        _: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        if (!self.streaming_enabled) {
            if (stage == .final and message.len > 0) {
                return vtableSend(ptr, target, message, &.{});
            }
            return;
        }

        switch (stage) {
            .chunk => try self.handleSendEventChunk(target, message),
            .final => try self.handleSendEventFinal(target, message),
        }
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichPayload(target, payload);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *MaxChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    // ── Streaming sink (for processMessageStreaming) ──────────────

    pub const StreamCtx = struct {
        max_ptr: *MaxChannel,
        chat_id: []const u8,
        filter: streaming.TagFilter = undefined,
    };

    fn streamCallback(ctx_ptr: *anyopaque, event: streaming.Event) void {
        if (event.stage != .chunk or event.text.len == 0) return;
        const ctx: *StreamCtx = @ptrCast(@alignCast(ctx_ptr));
        ctx.max_ptr.handleSendEventChunk(ctx.chat_id, event.text) catch {};
    }

    /// Build a streaming sink backed by the given context.
    /// Returns null if streaming is disabled. Caller owns the lifetime of `ctx`.
    /// Chunks are filtered through a TagFilter to strip tool_call markup.
    pub fn makeSink(self: *MaxChannel, ctx: *StreamCtx) ?streaming.Sink {
        if (!self.streaming_enabled) return null;
        const raw = streaming.Sink{
            .callback = streamCallback,
            .ctx = @ptrCast(ctx),
        };
        ctx.filter = streaming.TagFilter.init(raw);
        return ctx.filter.sink();
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
    };

    pub fn channel(self: *MaxChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Bus (unused, required by channel manager) ────────────────────

    pub fn setBus(_: *MaxChannel, _: anytype) void {}
};

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;

    var start: usize = 0;
    while (start + needle.len <= haystack.len) : (start += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) {
            return true;
        }
    }
    return false;
}

fn parseCallbackPayload(payload: []const u8) ?struct {
    token: []const u8,
    option_index: usize,
} {
    if (!std.mem.startsWith(u8, payload, CALLBACK_PAYLOAD_PREFIX)) return null;

    const remainder = payload[CALLBACK_PAYLOAD_PREFIX.len..];
    const sep = std.mem.lastIndexOfScalar(u8, remainder, ':') orelse return null;
    if (sep == 0 or sep + 1 >= remainder.len) return null;

    const token = remainder[0..sep];
    const option_index = std.fmt.parseUnsigned(usize, remainder[sep + 1 ..], 10) catch return null;

    return .{
        .token = token,
        .option_index = option_index,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

fn testChannel() MaxChannel {
    return .{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &.{},
        .group_allow_from = &.{},
        .group_policy = "allowlist",
    };
}

fn testChannelWithAllowFrom(allow: []const []const u8) MaxChannel {
    return .{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = allow,
        .group_allow_from = &.{},
        .group_policy = "allowlist",
    };
}

fn parseTestJson(allocator: std.mem.Allocator, json: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, json, .{});
}

test "channelName returns max" {
    var ch = testChannel();
    try std.testing.expectEqualStrings("max", ch.channelName());
}

test "vtable channel returns valid interface" {
    var ch = testChannel();
    const iface = ch.channel();
    try std.testing.expectEqualStrings("max", iface.name());
}

test "healthCheck returns true in test mode" {
    var ch = testChannel();
    try std.testing.expect(ch.healthCheck());
}

test "isUserAllowed wildcard" {
    const list = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&list);
    try std.testing.expect(ch.isUserAllowed("anyone"));
}

test "isUserAllowed exact match" {
    const list = [_][]const u8{ "alice", "bob" };
    var ch = testChannelWithAllowFrom(&list);
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(ch.isUserAllowed("bob"));
    try std.testing.expect(!ch.isUserAllowed("eve"));
}

test "isUserAllowed case insensitive" {
    const list = [_][]const u8{"Alice"};
    var ch = testChannelWithAllowFrom(&list);
    try std.testing.expect(ch.isUserAllowed("alice"));
    try std.testing.expect(ch.isUserAllowed("ALICE"));
    try std.testing.expect(ch.isUserAllowed("Alice"));
}

test "isUserAllowed empty list denies" {
    var ch = testChannel();
    try std.testing.expect(!ch.isUserAllowed("anyone"));
}

test "isGroupUserAllowed falls back to allow_from when group list empty" {
    const list = [_][]const u8{ "alice", "bob" };
    var ch = testChannelWithAllowFrom(&list);
    try std.testing.expect(ch.isGroupUserAllowed("alice"));
    try std.testing.expect(!ch.isGroupUserAllowed("eve"));
}

test "isGroupUserAllowed uses group_allow_from when non-empty" {
    const allow = [_][]const u8{"alice"};
    const group_allow = [_][]const u8{"bob"};
    var ch = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &group_allow,
        .group_policy = "allowlist",
    };
    try std.testing.expect(!ch.isGroupUserAllowed("alice"));
    try std.testing.expect(ch.isGroupUserAllowed("bob"));
}

test "isGroupUserAllowed wildcard" {
    const group_allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &.{},
        .group_allow_from = &group_allow,
        .group_policy = "allowlist",
    };
    try std.testing.expect(ch.isGroupUserAllowed("anyone"));
}

test "processUpdate matches allowlist by numeric user_id when username is present" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"42"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-1","text":"Hello"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("42", msg.sender);
}

test "processUpdate require_mention drops unmentioned group message" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &allow,
        .group_policy = "allowlist",
        .require_mention = true,
    };
    ch.bot_username = try allocator.dupe(u8, "maxbot");
    defer if (ch.bot_username) |username| allocator.free(username);

    const json =
        \\{"update_type":"message_created","timestamp":1710000001,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"200","chat_type":"chat"},
        \\"body":{"mid":"msg-2","text":"hello everyone"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(ch.processUpdate(allocator, parsed.value) == null);
}

test "processUpdate require_mention accepts explicit bot mention" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &allow,
        .group_policy = "allowlist",
        .require_mention = true,
    };
    ch.bot_username = try allocator.dupe(u8, "maxbot");
    defer if (ch.bot_username) |username| allocator.free(username);

    const json =
        \\{"update_type":"message_created","timestamp":1710000002,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"200","chat_type":"chat"},
        \\"body":{"mid":"msg-3","text":"@MaxBot please help"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("@MaxBot please help", msg.content);
}

test "processUpdate message_created produces ChannelMessage" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-1","text":"Hello"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expectEqualStrings("msg-1", msg.id);
    try std.testing.expectEqualStrings("42", msg.sender);
    try std.testing.expectEqualStrings("Hello", msg.content);
    try std.testing.expectEqualStrings("max", msg.channel);
    try std.testing.expectEqualStrings("100", msg.reply_target.?);
    try std.testing.expectEqualStrings("Alice", msg.first_name.?);
    try std.testing.expect(!msg.is_group);
    try std.testing.expectEqual(@as(u64, 1710000000), msg.timestamp);
}

test "processUpdate message_created group chat" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &allow,
        .group_policy = "allowlist",
    };
    const json =
        \\{"update_type":"message_created","timestamp":1710000001,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"200","chat_type":"chat"},
        \\"body":{"mid":"msg-2","text":"Group msg"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expectEqualStrings("200", msg.reply_target.?);
    try std.testing.expect(msg.is_group);
}

test "processUpdate unauthorized user returns null" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"bob"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-1","text":"Hello"}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(ch.processUpdate(allocator, parsed.value) == null);
}

test "processUpdate message_callback maps to ChannelMessage" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"message_callback","callback_id":"cb-1",
        \\"callback":{"payload":"opt1","user":{"user_id":"42","name":"Alice"},
        \\"message":{"recipient":{"chat_id":"100"}}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expectEqualStrings("cb-1", msg.id);
    try std.testing.expectEqualStrings("42", msg.sender);
    try std.testing.expectEqualStrings("opt1", msg.content);
    try std.testing.expectEqualStrings("max", msg.channel);
    try std.testing.expectEqualStrings("100", msg.reply_target.?);
}

test "processUpdate callback consumes registered interaction token once" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    defer ch.deinitPendingInteractions();

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "Confirm action" },
    };
    try ch.registerPendingInteraction("tok1", "100", "42", &choices, "Choose");

    const json =
        \\{"update_type":"message_callback","callback_id":"cb-2",
        \\"callback":{"payload":"ncmax:tok1:0","user":{"user_id":"42","name":"Alice","username":"alice"},
        \\"message":{"recipient":{"chat_id":"100"}}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const first = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("Confirm action", first.content);

    try std.testing.expect(ch.processUpdate(allocator, parsed.value) == null);
}

test "processUpdate callback enforces owner_only" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    defer ch.deinitPendingInteractions();

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "Confirm action" },
    };
    try ch.registerPendingInteraction("tok2", "100", "42", &choices, "Choose");

    const json =
        \\{"update_type":"message_callback","callback_id":"cb-3",
        \\"callback":{"payload":"ncmax:tok2:0","user":{"user_id":"7","name":"Bob","username":"bob"},
        \\"message":{"recipient":{"chat_id":"100"}}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(ch.processUpdate(allocator, parsed.value) == null);
}

test "processUpdate callback preserves group routing" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &allow,
        .group_policy = "allowlist",
    };

    const json =
        \\{"update_type":"message_callback","callback_id":"cb-4",
        \\"callback":{"payload":"plain","user":{"user_id":"42","name":"Alice","username":"alice"},
        \\"message":{"recipient":{"chat_id":"200","chat_type":"chat"}}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);
    try std.testing.expect(msg.is_group);
}

test "processUpdate bot_started with payload" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"bot_started","chat_id":"100",
        \\"user":{"user_id":"42","name":"Alice"},"payload":"deep-link-data"}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expectEqualStrings("/start deep-link-data", msg.content);
    try std.testing.expectEqualStrings("max", msg.channel);
    try std.testing.expectEqualStrings("100", msg.reply_target.?);
    try std.testing.expectEqualStrings("Alice", msg.first_name.?);
}

test "processUpdate bot_started without payload" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"bot_started","chat_id":"200",
        \\"user":{"user_id":"99","name":"Bob"}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expectEqualStrings("/start", msg.content);
}

test "processUpdate ignored type returns null" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"bot_stopped","chat_id":"100",
        \\"user":{"user_id":"42","name":"Alice"}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(ch.processUpdate(allocator, parsed.value) == null);
}

test "processUpdate with attachments includes markers" {
    const allocator = std.testing.allocator;
    const allow = [_][]const u8{"*"};
    var ch = testChannelWithAllowFrom(&allow);
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":"42","name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-3","text":"Check this",
        \\"attachments":[{"type":"image","payload":{"url":"https://example.com/photo.jpg"}}]}}}
    ;
    var parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const msg = ch.processUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer msg.deinit(allocator);

    try std.testing.expect(std.mem.indexOf(u8, msg.content, "[IMAGE:") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.content, "https://example.com/photo.jpg") != null);
}

test "sendTextChunked sends short message in single call" {
    var ch = testChannel();
    // In test mode, sendMessage is mocked so this should not error
    try ch.sendTextChunked("100", "Hello world");
}

test "text splitting at MAX_MESSAGE_LEN boundary" {
    const effective_max = MAX_MESSAGE_LEN - CONTINUATION_MARKER.len;
    var it = root.splitMessage("a" ** 5000, effective_max);
    const chunk1 = it.next().?;
    try std.testing.expect(chunk1.len <= effective_max);
    try std.testing.expect(it.next() != null);
}

test "buildOutgoingTextChunks keeps chunks within Max limit" {
    const allocator = std.testing.allocator;
    const chunks = try buildOutgoingTextChunks(allocator, "a" ** 5000);
    defer {
        for (chunks) |chunk| chunk.deinit(allocator);
        allocator.free(chunks);
    }

    try std.testing.expect(chunks.len >= 2);
    for (chunks) |chunk| {
        try std.testing.expect(chunk.body.len <= MAX_MESSAGE_LEN);
    }
}

test "buildDraftPreviewChunk caps preview length with continuation marker" {
    const allocator = std.testing.allocator;
    const preview = try buildDraftPreviewChunk(allocator, "a" ** 5000);
    defer preview.deinit(allocator);

    try std.testing.expect(preview.body.len <= MAX_MESSAGE_LEN);
    try std.testing.expect(std.mem.endsWith(u8, preview.body, CONTINUATION_MARKER));
}

test "CONTINUATION_MARKER is correct" {
    try std.testing.expect(CONTINUATION_MARKER.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, CONTINUATION_MARKER, "\u{23EC}") != null);
}

test "vtableSendEvent chunk accumulates in draft buffer" {
    var ch = testChannel();
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "Hello ", &.{}, .chunk);
    try ch.channel().sendEvent("12345", "world", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const draft = ch.draft_buffers.get("12345") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Hello world", draft.buffer.items);
}

test "vtableSendEvent final cleans up draft state" {
    var ch = testChannel();
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "chunk data", &.{}, .chunk);

    {
        ch.draft_mu.lock();
        defer ch.draft_mu.unlock();
        try std.testing.expect(ch.draft_buffers.get("12345") != null);
    }

    try ch.channel().sendEvent("12345", "", &.{}, .final);

    {
        ch.draft_mu.lock();
        defer ch.draft_mu.unlock();
        try std.testing.expect(ch.draft_buffers.get("12345") == null);
    }
}

test "vtableSendEvent chunk assigns unique entry per chat" {
    var ch = testChannel();
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("111", "a", &.{}, .chunk);
    try ch.channel().sendEvent("222", "b", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    const d1 = ch.draft_buffers.get("111") orelse return error.TestUnexpectedResult;
    const d2 = ch.draft_buffers.get("222") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("a", d1.buffer.items);
    try std.testing.expectEqualStrings("b", d2.buffer.items);
}

test "vtableSendEvent disabled streaming is noop" {
    var ch = testChannel();
    ch.streaming_enabled = false;
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "data", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expect(ch.draft_buffers.get("12345") == null);
}

test "vtableSendEvent empty chunk is ignored" {
    var ch = testChannel();
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("12345", "", &.{}, .chunk);

    ch.draft_mu.lock();
    defer ch.draft_mu.unlock();
    try std.testing.expect(ch.draft_buffers.get("12345") == null);
}

test "vtableSendEvent final on nonexistent chat is safe" {
    var ch = testChannel();
    defer ch.deinitDraftBuffers();

    try ch.channel().sendEvent("nonexistent", "", &.{}, .final);
}

test "parseAttachmentMarkers extracts image marker" {
    const allocator = std.testing.allocator;
    const parsed = try parseAttachmentMarkers(allocator, "Check [IMAGE:/tmp/photo.png] this");
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.attachments.len);
    try std.testing.expect(parsed.attachments[0].kind == .image);
    try std.testing.expectEqualStrings("/tmp/photo.png", parsed.attachments[0].target);
    try std.testing.expectEqualStrings("Check  this", parsed.remaining_text);
}

test "parseAttachmentMarkers handles multiple markers" {
    const allocator = std.testing.allocator;
    const parsed = try parseAttachmentMarkers(allocator, "[IMAGE:a.png] text [DOCUMENT:b.pdf]");
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expect(parsed.attachments[0].kind == .image);
    try std.testing.expect(parsed.attachments[1].kind == .document);
    try std.testing.expectEqualStrings("text", parsed.remaining_text);
}

test "parseAttachmentMarkers preserves non-marker brackets" {
    const allocator = std.testing.allocator;
    const parsed = try parseAttachmentMarkers(allocator, "hello [world] there");
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), parsed.attachments.len);
    try std.testing.expectEqualStrings("hello [world] there", parsed.remaining_text);
}

test "parseAttachmentMarkers video and audio" {
    const allocator = std.testing.allocator;
    const parsed = try parseAttachmentMarkers(allocator, "[VIDEO:v.mp4][AUDIO:a.mp3]");
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.attachments.len);
    try std.testing.expect(parsed.attachments[0].kind == .video);
    try std.testing.expect(parsed.attachments[1].kind == .audio);
}

test "MAX_MESSAGE_LEN is 4000" {
    try std.testing.expectEqual(@as(usize, 4000), MAX_MESSAGE_LEN);
}

test "vtable constant has all required methods" {
    const v = MaxChannel.vtable;
    try std.testing.expect(v.start == &MaxChannel.vtableStart);
    try std.testing.expect(v.stop == &MaxChannel.vtableStop);
    try std.testing.expect(v.send == &MaxChannel.vtableSend);
    try std.testing.expect(v.name == &MaxChannel.vtableName);
    try std.testing.expect(v.healthCheck == &MaxChannel.vtableHealthCheck);
    try std.testing.expect(v.sendEvent != null);
    try std.testing.expect(v.sendRich != null);
}

test "channel interface healthCheck dispatches correctly" {
    var ch = testChannel();
    const iface = ch.channel();
    try std.testing.expect(iface.healthCheck());
}

test "initFromConfig sets all fields" {
    const cfg = config_types.MaxConfig{
        .bot_token = "my-token",
        .account_id = "prod",
        .proxy = "http://proxy:8080",
        .streaming = false,
        .require_mention = true,
    };
    const ch = MaxChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("my-token", ch.bot_token);
    try std.testing.expectEqualStrings("prod", ch.account_id);
    try std.testing.expectEqualStrings("http://proxy:8080", ch.proxy.?);
    try std.testing.expect(!ch.streaming_enabled);
    try std.testing.expect(ch.require_mention);
}

test "vtableStart webhook mode requires https webhook URL" {
    var missing = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &.{},
        .group_allow_from = &.{},
        .group_policy = "allowlist",
        .mode = .webhook,
    };
    try std.testing.expectError(error.MissingWebhookUrl, MaxChannel.vtableStart(@ptrCast(&missing)));

    var insecure = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &.{},
        .group_allow_from = &.{},
        .group_policy = "allowlist",
        .mode = .webhook,
        .webhook_url = "http://example.com/max",
    };
    try std.testing.expectError(error.InvalidWebhookUrl, MaxChannel.vtableStart(@ptrCast(&insecure)));

    var secure = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &.{},
        .group_allow_from = &.{},
        .group_policy = "allowlist",
        .mode = .webhook,
        .webhook_url = "https://example.com/max",
    };
    try MaxChannel.vtableStart(@ptrCast(&secure));
    try std.testing.expect(secure.running);
    MaxChannel.vtableStop(@ptrCast(&secure));
}

test "send invokes sendMessage without error" {
    var ch = testChannel();
    // Test mode: API calls are mocked, so this should succeed
    try ch.sendMessage("100", "Hello, world!");
}

test "sendRichPayload without choices falls back to send" {
    var ch = testChannel();
    try ch.sendRichPayload("100", .{ .text = "just text" });
}

test "isAuthorized open group policy allows everyone" {
    const allow = [_][]const u8{"bob"};
    var ch = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &.{},
        .group_policy = "open",
    };
    try std.testing.expect(ch.isAuthorized("eve", true));
    // But DM still restricted
    try std.testing.expect(!ch.isAuthorized("eve", false));
    try std.testing.expect(ch.isAuthorized("bob", false));
}

test "isAuthorized disabled group policy denies everyone" {
    const allow = [_][]const u8{"*"};
    var ch = MaxChannel{
        .allocator = std.testing.allocator,
        .bot_token = "test-token",
        .allow_from = &allow,
        .group_allow_from = &.{},
        .group_policy = "disabled",
    };
    try std.testing.expect(!ch.isAuthorized("alice", true));
    // DM still allowed
    try std.testing.expect(ch.isAuthorized("alice", false));
}

test "DraftState accumulation" {
    const allocator = std.testing.allocator;
    var state = DraftState{};
    defer state.deinit(allocator);

    try state.buffer.appendSlice(allocator, "Hello ");
    try state.buffer.appendSlice(allocator, "world");
    try std.testing.expectEqualStrings("Hello world", state.buffer.items);
}

test "vtableStop cleans up all resources" {
    var ch = testChannel();
    MaxChannel.vtableStart(@ptrCast(&ch)) catch {};
    MaxChannel.vtableStop(@ptrCast(&ch));

    // After stop, all state should be cleaned
    try std.testing.expect(ch.marker == null);
    try std.testing.expect(!ch.running);
}

test "AttachmentKind apiFileType mapping" {
    try std.testing.expectEqualStrings("image", AttachmentKind.image.apiFileType());
    try std.testing.expectEqualStrings("file", AttachmentKind.document.apiFileType());
    try std.testing.expectEqualStrings("video", AttachmentKind.video.apiFileType());
    try std.testing.expectEqualStrings("audio", AttachmentKind.audio.apiFileType());
}

test "pollUpdates returns empty in test mode" {
    const allocator = std.testing.allocator;
    var ch = testChannel();
    const messages = try ch.pollUpdates(allocator);
    defer {
        for (messages) |*msg| {
            var m = msg.*;
            m.deinit(allocator);
        }
        if (messages.len > 0) allocator.free(messages);
    }
    try std.testing.expectEqual(@as(usize, 0), messages.len);
}

test "parseCallbackPayload parses token and option index" {
    const parsed = parseCallbackPayload("ncmax:abc123:7") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("abc123", parsed.token);
    try std.testing.expectEqual(@as(usize, 7), parsed.option_index);
    try std.testing.expect(parseCallbackPayload("plain") == null);
}

test {
    @import("std").testing.refAllDecls(@This());
}
