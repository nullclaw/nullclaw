//! Update parser for the Max messenger Bot API.
//!
//! Converts raw JSON updates from the Max Bot API into typed Zig structs
//! for the MaxChannel to process. Handles message_created, message_callback,
//! bot_started, and other update types.

const std = @import("std");

// ════════════════════════════════════════════════════════════════════════════
// Update Types
// ════════════════════════════════════════════════════════════════════════════

pub const UpdateType = enum {
    message_created,
    message_callback,
    message_edited,
    message_removed,
    bot_started,
    bot_stopped,
    bot_added,
    bot_removed,
    user_added,
    user_removed,
    chat_title_changed,
    unknown,

    pub fn fromString(s: []const u8) UpdateType {
        const map = .{
            .{ "message_created", .message_created },
            .{ "message_callback", .message_callback },
            .{ "message_edited", .message_edited },
            .{ "message_removed", .message_removed },
            .{ "bot_started", .bot_started },
            .{ "bot_stopped", .bot_stopped },
            .{ "bot_added", .bot_added },
            .{ "bot_removed", .bot_removed },
            .{ "user_added", .user_added },
            .{ "user_removed", .user_removed },
            .{ "chat_title_changed", .chat_title_changed },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, s, entry[0])) return entry[1];
        }
        return .unknown;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Parsed Update Structures
// ════════════════════════════════════════════════════════════════════════════

pub const ChatType = enum { dialog, chat, channel };

pub const SenderInfo = struct {
    user_id: []u8,
    name: ?[]u8 = null,
    username: ?[]u8 = null,

    pub fn deinit(self: *const SenderInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.user_id);
        if (self.name) |v| allocator.free(v);
        if (self.username) |v| allocator.free(v);
    }

    /// Returns username if available, otherwise user_id.
    pub fn identity(self: *const SenderInfo) []const u8 {
        return self.username orelse self.user_id;
    }
};

pub const ChatInfo = struct {
    chat_id: []u8,
    chat_type: ChatType = .dialog,

    pub fn deinit(self: *const ChatInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.chat_id);
    }

    pub fn isGroup(self: *const ChatInfo) bool {
        return self.chat_type != .dialog;
    }
};

pub const InboundMessage = struct {
    sender: SenderInfo,
    chat: ChatInfo,
    text: ?[]u8 = null,
    mid: ?[]u8 = null,
    timestamp: u64 = 0,
    attachment_urls: [][]u8 = &.{},
    attachment_types: [][]u8 = &.{},

    pub fn deinit(self: *const InboundMessage, allocator: std.mem.Allocator) void {
        self.sender.deinit(allocator);
        self.chat.deinit(allocator);
        if (self.text) |v| allocator.free(v);
        if (self.mid) |v| allocator.free(v);
        for (self.attachment_urls) |url| allocator.free(url);
        if (self.attachment_urls.len > 0) allocator.free(self.attachment_urls);
        for (self.attachment_types) |t| allocator.free(t);
        if (self.attachment_types.len > 0) allocator.free(self.attachment_types);
    }
};

pub const InboundCallback = struct {
    callback_id: []u8,
    payload: []u8,
    sender: SenderInfo,
    chat_id: []u8,
    is_group: bool = false,
    timestamp: u64 = 0,

    pub fn deinit(self: *const InboundCallback, allocator: std.mem.Allocator) void {
        allocator.free(self.callback_id);
        allocator.free(self.payload);
        self.sender.deinit(allocator);
        allocator.free(self.chat_id);
    }
};

pub const BotStartedInfo = struct {
    sender: SenderInfo,
    chat_id: []u8,
    payload: ?[]u8 = null,
    timestamp: u64 = 0,

    pub fn deinit(self: *const BotStartedInfo, allocator: std.mem.Allocator) void {
        self.sender.deinit(allocator);
        allocator.free(self.chat_id);
        if (self.payload) |v| allocator.free(v);
    }
};

pub const ParsedUpdate = union(enum) {
    message: InboundMessage,
    callback: InboundCallback,
    bot_started: BotStartedInfo,
    ignored,

    pub fn deinit(self: *const ParsedUpdate, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .message => |m| m.deinit(allocator),
            .callback => |c| c.deinit(allocator),
            .bot_started => |b| b.deinit(allocator),
            .ignored => {},
        }
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Main Parsing Function
// ════════════════════════════════════════════════════════════════════════════

/// Parse a single Max Bot API update JSON object into a typed ParsedUpdate.
pub fn parseUpdate(allocator: std.mem.Allocator, update_obj: std.json.Value) ?ParsedUpdate {
    if (update_obj != .object) return null;

    const update_type_str = getStr(update_obj, "update_type") orelse return null;
    const update_type = UpdateType.fromString(update_type_str);

    switch (update_type) {
        .message_created => return parseMessageCreated(allocator, update_obj),
        .message_callback => return parseMessageCallback(allocator, update_obj),
        .bot_started => return parseBotStarted(allocator, update_obj),
        else => return .ignored,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Specific Update Parsers
// ════════════════════════════════════════════════════════════════════════════

fn parseMessageCreated(allocator: std.mem.Allocator, update_obj: std.json.Value) ?ParsedUpdate {
    const message_val = update_obj.object.get("message") orelse return null;

    var sender = parseSender(allocator, message_val) orelse return null;
    errdefer sender.deinit(allocator);

    var chat = parseChat(allocator, message_val) orelse {
        sender.deinit(allocator);
        return null;
    };
    errdefer chat.deinit(allocator);

    // Extract body fields
    const body_obj = getObject(message_val, "body");

    var text_val: ?[]u8 = null;
    errdefer if (text_val) |v| allocator.free(v);
    var mid_val: ?[]u8 = null;
    errdefer if (mid_val) |v| allocator.free(v);

    var att_urls: std.ArrayListUnmanaged([]u8) = .empty;
    defer att_urls.deinit(allocator);
    var att_types: std.ArrayListUnmanaged([]u8) = .empty;
    defer att_types.deinit(allocator);

    if (body_obj) |body| {
        // Extract text
        if (body.get("text")) |text_json| {
            if (text_json == .string) {
                text_val = allocator.dupe(u8, text_json.string) catch return null;
            }
        }

        // Extract mid
        if (body.get("mid")) |mid_json| {
            if (mid_json == .string) {
                mid_val = allocator.dupe(u8, mid_json.string) catch return null;
            }
        }

        // Extract attachments
        if (body.get("attachments")) |atts_json| {
            if (atts_json == .array) {
                for (atts_json.array.items) |att_item| {
                    if (att_item != .object) continue;
                    const att_type_str = getStr(att_item, "type") orelse continue;

                    // Get URL from payload
                    if (att_item.object.get("payload")) |payload_val| {
                        if (payload_val == .object) {
                            if (payload_val.object.get("url")) |url_val| {
                                if (url_val == .string) {
                                    const url_dup = allocator.dupe(u8, url_val.string) catch continue;
                                    att_urls.append(allocator, url_dup) catch {
                                        allocator.free(url_dup);
                                        continue;
                                    };
                                    const type_dup = allocator.dupe(u8, att_type_str) catch {
                                        // Roll back the URL we just pushed
                                        allocator.free(att_urls.pop().?);
                                        continue;
                                    };
                                    att_types.append(allocator, type_dup) catch {
                                        allocator.free(type_dup);
                                        allocator.free(att_urls.pop().?);
                                        continue;
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract timestamp from the update level
    var timestamp: u64 = 0;
    if (update_obj.object.get("timestamp")) |ts_val| {
        timestamp = normalizeUnixTimestamp(ts_val);
    }

    const owned_urls = att_urls.toOwnedSlice(allocator) catch {
        // Free any accumulated items on failure
        for (att_urls.items) |u| allocator.free(u);
        for (att_types.items) |t| allocator.free(t);
        sender.deinit(allocator);
        chat.deinit(allocator);
        if (text_val) |v| allocator.free(v);
        if (mid_val) |v| allocator.free(v);
        return null;
    };
    errdefer {
        for (owned_urls) |u| allocator.free(u);
        allocator.free(owned_urls);
    }

    const owned_types = att_types.toOwnedSlice(allocator) catch {
        for (owned_urls) |u| allocator.free(u);
        allocator.free(owned_urls);
        for (att_types.items) |t| allocator.free(t);
        sender.deinit(allocator);
        chat.deinit(allocator);
        if (text_val) |v| allocator.free(v);
        if (mid_val) |v| allocator.free(v);
        return null;
    };

    return .{ .message = .{
        .sender = sender,
        .chat = chat,
        .text = text_val,
        .mid = mid_val,
        .timestamp = timestamp,
        .attachment_urls = owned_urls,
        .attachment_types = owned_types,
    } };
}

fn parseMessageCallback(allocator: std.mem.Allocator, update_obj: std.json.Value) ?ParsedUpdate {
    // callback object
    const callback_val = update_obj.object.get("callback") orelse return null;
    if (callback_val != .object) return null;

    const callback_id = dupStringLikeValue(
        allocator,
        callback_val.object.get("callback_id") orelse update_obj.object.get("callback_id") orelse return null,
    ) orelse return null;
    errdefer allocator.free(callback_id);

    // payload from callback
    const payload_str = getStr(callback_val, "payload") orelse "";
    const payload = allocator.dupe(u8, payload_str) catch {
        allocator.free(callback_id);
        return null;
    };
    errdefer allocator.free(payload);

    // sender from callback.user
    var sender = parseSenderFromUser(allocator, callback_val) orelse {
        allocator.free(callback_id);
        allocator.free(payload);
        return null;
    };
    errdefer sender.deinit(allocator);

    // chat_id from callback.message.recipient.chat_id
    const callback_message = callback_val.object.get("message") orelse {
        allocator.free(callback_id);
        allocator.free(payload);
        sender.deinit(allocator);
        return null;
    };
    if (callback_message != .object) {
        allocator.free(callback_id);
        allocator.free(payload);
        sender.deinit(allocator);
        return null;
    }

    const chat_id = blk: {
        const recipient = callback_message.object.get("recipient") orelse break :blk null;
        if (recipient != .object) break :blk null;
        break :blk dupStringLikeField(allocator, recipient, "chat_id");
    } orelse {
        allocator.free(callback_id);
        allocator.free(payload);
        sender.deinit(allocator);
        return null;
    };

    const is_group = blk: {
        const recipient = callback_message.object.get("recipient") orelse break :blk false;
        if (recipient != .object) break :blk false;
        const chat_type = getStr(recipient, "chat_type") orelse break :blk false;
        break :blk std.mem.eql(u8, chat_type, "chat") or std.mem.eql(u8, chat_type, "channel");
    };

    const timestamp = if (update_obj.object.get("timestamp")) |ts_val|
        normalizeUnixTimestamp(ts_val)
    else
        0;

    return .{ .callback = .{
        .callback_id = callback_id,
        .payload = payload,
        .sender = sender,
        .chat_id = chat_id,
        .is_group = is_group,
        .timestamp = timestamp,
    } };
}

fn parseBotStarted(allocator: std.mem.Allocator, update_obj: std.json.Value) ?ParsedUpdate {
    // sender from user at update level
    var sender = parseSenderFromUser(allocator, update_obj) orelse return null;
    errdefer sender.deinit(allocator);

    // chat_id at update level
    const chat_id = dupStringLikeField(allocator, update_obj, "chat_id") orelse {
        sender.deinit(allocator);
        return null;
    };
    errdefer allocator.free(chat_id);

    // optional payload
    var payload_val: ?[]u8 = null;
    if (getStr(update_obj, "payload")) |p| {
        payload_val = allocator.dupe(u8, p) catch null;
    }

    return .{ .bot_started = .{
        .sender = sender,
        .chat_id = chat_id,
        .payload = payload_val,
        .timestamp = if (update_obj.object.get("timestamp")) |ts_val|
            normalizeUnixTimestamp(ts_val)
        else
            0,
    } };
}

// ════════════════════════════════════════════════════════════════════════════
// JSON Helpers (private)
// ════════════════════════════════════════════════════════════════════════════

fn getStr(obj: std.json.Value, key: []const u8) ?[]const u8 {
    if (obj != .object) return null;
    const val = obj.object.get(key) orelse return null;
    return if (val == .string) val.string else null;
}

fn dupStringLikeField(allocator: std.mem.Allocator, obj: std.json.Value, key: []const u8) ?[]u8 {
    if (obj != .object) return null;
    const val = obj.object.get(key) orelse return null;
    return dupStringLikeValue(allocator, val);
}

fn dupStringLikeValue(allocator: std.mem.Allocator, val: std.json.Value) ?[]u8 {
    return switch (val) {
        .string => |s| allocator.dupe(u8, s) catch null,
        .number_string => |s| allocator.dupe(u8, s) catch null,
        .integer => |i| std.fmt.allocPrint(allocator, "{d}", .{i}) catch null,
        else => null,
    };
}

fn getObject(obj: std.json.Value, key: []const u8) ?std.json.ObjectMap {
    if (obj != .object) return null;
    const val = obj.object.get(key) orelse return null;
    return if (val == .object) val.object else null;
}

/// Parse sender from message.sender sub-object.
fn parseSender(allocator: std.mem.Allocator, message_val: std.json.Value) ?SenderInfo {
    if (message_val != .object) return null;
    const sender_val = message_val.object.get("sender") orelse return null;
    if (sender_val != .object) return null;
    return parseSenderFields(allocator, sender_val);
}

/// Parse sender from a "user" sub-object (used by callbacks and bot_started).
fn parseSenderFromUser(allocator: std.mem.Allocator, parent_val: std.json.Value) ?SenderInfo {
    if (parent_val != .object) return null;
    const user_val = parent_val.object.get("user") orelse return null;
    if (user_val != .object) return null;
    return parseSenderFields(allocator, user_val);
}

/// Common sender field extraction — user_id can be string or integer.
fn parseSenderFields(allocator: std.mem.Allocator, user_obj: std.json.Value) ?SenderInfo {
    if (user_obj != .object) return null;

    // user_id: string or integer
    const user_id: []u8 = blk: {
        const uid_val = user_obj.object.get("user_id") orelse return null;
        switch (uid_val) {
            .string => |s| break :blk allocator.dupe(u8, s) catch return null,
            .integer => |i| {
                var id_buf: [32]u8 = undefined;
                const s = std.fmt.bufPrint(&id_buf, "{d}", .{i}) catch return null;
                break :blk allocator.dupe(u8, s) catch return null;
            },
            else => return null,
        }
    };
    errdefer allocator.free(user_id);

    var name_val: ?[]u8 = null;
    if (getStr(user_obj, "first_name")) |n| {
        name_val = allocator.dupe(u8, n) catch null;
    } else if (getStr(user_obj, "name")) |n| {
        name_val = allocator.dupe(u8, n) catch null;
    }
    errdefer if (name_val) |v| allocator.free(v);

    var username_val: ?[]u8 = null;
    if (getStr(user_obj, "username")) |u| {
        username_val = allocator.dupe(u8, u) catch null;
    }

    return .{
        .user_id = user_id,
        .name = name_val,
        .username = username_val,
    };
}

/// Parse chat info from message.recipient sub-object.
fn parseChat(allocator: std.mem.Allocator, message_val: std.json.Value) ?ChatInfo {
    if (message_val != .object) return null;
    const recipient_val = message_val.object.get("recipient") orelse return null;
    if (recipient_val != .object) return null;

    const chat_id = dupStringLikeField(allocator, recipient_val, "chat_id") orelse return null;

    const chat_type: ChatType = blk: {
        const ct_str = getStr(recipient_val, "chat_type") orelse break :blk .dialog;
        if (std.mem.eql(u8, ct_str, "chat")) break :blk .chat;
        if (std.mem.eql(u8, ct_str, "channel")) break :blk .channel;
        break :blk .dialog;
    };

    return .{
        .chat_id = chat_id,
        .chat_type = chat_type,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ════════════════════════════════════════════════════════════════════════════

/// Map attachment type string to a human-readable marker prefix.
pub fn attachmentMarkerPrefix(att_type: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, att_type, "image")) return "[IMAGE:";
    if (std.mem.eql(u8, att_type, "video")) return "[VIDEO:";
    if (std.mem.eql(u8, att_type, "audio")) return "[AUDIO:";
    if (std.mem.eql(u8, att_type, "file")) return "[DOCUMENT:";
    if (std.mem.eql(u8, att_type, "sticker")) return "[IMAGE:";
    return null;
}

/// Extract the `marker` field from a getUpdates API response.
pub fn parseUpdatesMarker(allocator: std.mem.Allocator, json_resp: []const u8) ?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_resp, .{}) catch return null;
    defer parsed.deinit();

    if (parsed.value != .object) return null;
    const marker_val = parsed.value.object.get("marker") orelse return null;
    return switch (marker_val) {
        .string => |s| allocator.dupe(u8, s) catch null,
        .number_string => |s| allocator.dupe(u8, s) catch null,
        .integer => |i| std.fmt.allocPrint(allocator, "{d}", .{i}) catch null,
        else => null,
    };
}

fn normalizeUnixTimestamp(value: std.json.Value) u64 {
    const raw: u64 = switch (value) {
        .integer => |i| @intCast(@max(0, i)),
        .float => |f| @intFromFloat(@max(0.0, f)),
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch 0,
        .string => |s| std.fmt.parseInt(u64, s, 10) catch 0,
        else => 0,
    };

    return if (raw >= 1_000_000_000_000) raw / 1000 else raw;
}

/// Parse the full getUpdates response JSON for iteration over the `updates` array.
pub fn parseUpdatesArray(json_resp: []const u8, allocator: std.mem.Allocator) ?std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, json_resp, .{}) catch null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

fn parseTestJson(allocator: std.mem.Allocator, json: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, json, .{});
}

test "UpdateType.fromString known types" {
    try std.testing.expectEqual(UpdateType.message_created, UpdateType.fromString("message_created"));
    try std.testing.expectEqual(UpdateType.message_callback, UpdateType.fromString("message_callback"));
    try std.testing.expectEqual(UpdateType.message_edited, UpdateType.fromString("message_edited"));
    try std.testing.expectEqual(UpdateType.message_removed, UpdateType.fromString("message_removed"));
    try std.testing.expectEqual(UpdateType.bot_started, UpdateType.fromString("bot_started"));
    try std.testing.expectEqual(UpdateType.bot_stopped, UpdateType.fromString("bot_stopped"));
    try std.testing.expectEqual(UpdateType.bot_added, UpdateType.fromString("bot_added"));
    try std.testing.expectEqual(UpdateType.bot_removed, UpdateType.fromString("bot_removed"));
    try std.testing.expectEqual(UpdateType.user_added, UpdateType.fromString("user_added"));
    try std.testing.expectEqual(UpdateType.user_removed, UpdateType.fromString("user_removed"));
    try std.testing.expectEqual(UpdateType.chat_title_changed, UpdateType.fromString("chat_title_changed"));
}

test "UpdateType.fromString unknown type" {
    try std.testing.expectEqual(UpdateType.unknown, UpdateType.fromString("something_else"));
    try std.testing.expectEqual(UpdateType.unknown, UpdateType.fromString(""));
}

test "parseUpdate message_created text only" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_created","timestamp":1710000000123,
        \\"message":{"sender":{"user_id":"42","first_name":"Alice","username":"alice"},
        \\"recipient":{"chat_id":100,"chat_type":"dialog"},
        \\"body":{"mid":"msg-1","text":"Hello"}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .message);
    const msg = update.message;
    try std.testing.expectEqualStrings("42", msg.sender.user_id);
    try std.testing.expectEqualStrings("Alice", msg.sender.name.?);
    try std.testing.expectEqualStrings("alice", msg.sender.username.?);
    try std.testing.expectEqualStrings("100", msg.chat.chat_id);
    try std.testing.expect(!msg.chat.isGroup());
    try std.testing.expectEqualStrings("Hello", msg.text.?);
    try std.testing.expectEqualStrings("msg-1", msg.mid.?);
    try std.testing.expectEqual(@as(u64, 1710000000), msg.timestamp);
    try std.testing.expectEqual(@as(usize, 0), msg.attachment_urls.len);
}

test "parseUpdate message_created group chat" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_created","timestamp":1710000001,
        \\"message":{"sender":{"user_id":"42","name":"Alice"},
        \\"recipient":{"chat_id":"200","chat_type":"chat"},
        \\"body":{"mid":"msg-2","text":"Group msg"}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .message);
    const msg = update.message;
    try std.testing.expectEqualStrings("200", msg.chat.chat_id);
    try std.testing.expect(msg.chat.isGroup());
    try std.testing.expectEqual(ChatType.chat, msg.chat.chat_type);
    try std.testing.expectEqualStrings("Group msg", msg.text.?);
}

test "parseUpdate message_created with image attachment" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_created","timestamp":1710000002,
        \\"message":{"sender":{"user_id":"42","name":"Alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-3","text":"Check this out",
        \\"attachments":[{"type":"image","payload":{"url":"https://example.com/photo.jpg"}}]}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .message);
    const msg = update.message;
    try std.testing.expectEqual(@as(usize, 1), msg.attachment_urls.len);
    try std.testing.expectEqualStrings("https://example.com/photo.jpg", msg.attachment_urls[0]);
    try std.testing.expectEqual(@as(usize, 1), msg.attachment_types.len);
    try std.testing.expectEqualStrings("image", msg.attachment_types[0]);
}

test "parseUpdate message_callback" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_callback","timestamp":1710000000456,
        \\"callback":{"callback_id":"cb-1","payload":"opt1","user":{"user_id":"42","first_name":"Alice"},
        \\"message":{"recipient":{"chat_id":100}}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .callback);
    const cb = update.callback;
    try std.testing.expectEqualStrings("cb-1", cb.callback_id);
    try std.testing.expectEqualStrings("opt1", cb.payload);
    try std.testing.expectEqualStrings("42", cb.sender.user_id);
    try std.testing.expectEqualStrings("Alice", cb.sender.name.?);
    try std.testing.expectEqualStrings("100", cb.chat_id);
    try std.testing.expect(!cb.is_group);
    try std.testing.expectEqual(@as(u64, 1710000000), cb.timestamp);
}

test "parseUpdate message_callback preserves group recipient type" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_callback","callback_id":"cb-2",
        \\"callback":{"payload":"opt2","user":{"user_id":"42","name":"Alice"},
        \\"message":{"recipient":{"chat_id":"200","chat_type":"chat"}}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .callback);
    try std.testing.expect(update.callback.is_group);
}

test "parseUpdate bot_started with payload" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"bot_started","timestamp":1710000000789,"chat_id":100,
        \\"user":{"user_id":"42","first_name":"Alice"},"payload":"deep-link-data"}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .bot_started);
    const bs = update.bot_started;
    try std.testing.expectEqualStrings("42", bs.sender.user_id);
    try std.testing.expectEqualStrings("Alice", bs.sender.name.?);
    try std.testing.expectEqualStrings("100", bs.chat_id);
    try std.testing.expectEqualStrings("deep-link-data", bs.payload.?);
    try std.testing.expectEqual(@as(u64, 1710000000), bs.timestamp);
}

test "parseUpdate bot_started without payload" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"bot_started","chat_id":"200",
        \\"user":{"user_id":"99","name":"Bob"}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .bot_started);
    const bs = update.bot_started;
    try std.testing.expectEqualStrings("99", bs.sender.user_id);
    try std.testing.expectEqualStrings("200", bs.chat_id);
    try std.testing.expect(bs.payload == null);
}

test "parseUpdate bot_stopped returns ignored" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"bot_stopped","chat_id":"100",
        \\"user":{"user_id":"42","name":"Alice"}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .ignored);
}

test "parseUpdate unknown type returns ignored" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"some_future_type","data":"whatever"}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .ignored);
}

test "parseUpdate missing update_type returns null" {
    const allocator = std.testing.allocator;
    const json =
        \\{"data":"no update_type field"}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    try std.testing.expect(parseUpdate(allocator, parsed.value) == null);
}

test "SenderInfo.identity prefers username over user_id" {
    const allocator = std.testing.allocator;
    const uid = try allocator.dupe(u8, "42");
    errdefer allocator.free(uid);
    const uname = try allocator.dupe(u8, "alice");

    const sender = SenderInfo{
        .user_id = uid,
        .username = uname,
    };
    defer sender.deinit(allocator);

    try std.testing.expectEqualStrings("alice", sender.identity());
}

test "SenderInfo.identity falls back to user_id" {
    const allocator = std.testing.allocator;
    const uid = try allocator.dupe(u8, "42");

    const sender = SenderInfo{
        .user_id = uid,
    };
    defer sender.deinit(allocator);

    try std.testing.expectEqualStrings("42", sender.identity());
}

test "ChatInfo.isGroup distinguishes dialog from group" {
    const allocator = std.testing.allocator;
    const cid1 = try allocator.dupe(u8, "100");
    const dialog = ChatInfo{ .chat_id = cid1, .chat_type = .dialog };
    defer dialog.deinit(allocator);
    try std.testing.expect(!dialog.isGroup());

    const cid2 = try allocator.dupe(u8, "200");
    const group = ChatInfo{ .chat_id = cid2, .chat_type = .chat };
    defer group.deinit(allocator);
    try std.testing.expect(group.isGroup());

    const cid3 = try allocator.dupe(u8, "300");
    const chan = ChatInfo{ .chat_id = cid3, .chat_type = .channel };
    defer chan.deinit(allocator);
    try std.testing.expect(chan.isGroup());
}

test "attachmentMarkerPrefix for all known types" {
    try std.testing.expectEqualStrings("[IMAGE:", attachmentMarkerPrefix("image").?);
    try std.testing.expectEqualStrings("[VIDEO:", attachmentMarkerPrefix("video").?);
    try std.testing.expectEqualStrings("[AUDIO:", attachmentMarkerPrefix("audio").?);
    try std.testing.expectEqualStrings("[DOCUMENT:", attachmentMarkerPrefix("file").?);
    try std.testing.expectEqualStrings("[IMAGE:", attachmentMarkerPrefix("sticker").?);
}

test "attachmentMarkerPrefix for unknown type" {
    try std.testing.expect(attachmentMarkerPrefix("contact") == null);
    try std.testing.expect(attachmentMarkerPrefix("location") == null);
    try std.testing.expect(attachmentMarkerPrefix("") == null);
}

test "parseUpdatesMarker extracts marker" {
    const allocator = std.testing.allocator;
    const json =
        \\{"updates":[],"marker":"abc-123"}
    ;
    const marker = parseUpdatesMarker(allocator, json) orelse return error.TestUnexpectedResult;
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("abc-123", marker);
}

test "parseUpdatesMarker accepts integer marker" {
    const allocator = std.testing.allocator;
    const marker = parseUpdatesMarker(allocator, "{\"updates\":[],\"marker\":123456}") orelse return error.TestUnexpectedResult;
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("123456", marker);
}

test "parseUpdatesMarker returns null on missing marker" {
    const allocator = std.testing.allocator;
    try std.testing.expect(parseUpdatesMarker(allocator, "{\"updates\":[]}") == null);
    try std.testing.expect(parseUpdatesMarker(allocator, "invalid json") == null);
}

test "parseUpdatesArray parses valid response" {
    const allocator = std.testing.allocator;
    const json =
        \\{"updates":[{"update_type":"bot_started"}],"marker":"m1"}
    ;
    var result = parseUpdatesArray(json, allocator) orelse return error.TestUnexpectedResult;
    defer result.deinit();

    try std.testing.expect(result.value == .object);
    const updates_val = result.value.object.get("updates") orelse return error.TestUnexpectedResult;
    try std.testing.expect(updates_val == .array);
    try std.testing.expectEqual(@as(usize, 1), updates_val.array.items.len);
}

test "parseUpdatesArray returns null for invalid JSON" {
    const allocator = std.testing.allocator;
    try std.testing.expect(parseUpdatesArray("not json at all", allocator) == null);
}

test "parseUpdate message_created with integer user_id" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":12345,"name":"NumericUser"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"},
        \\"body":{"mid":"msg-num","text":"Hi"}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .message);
    try std.testing.expectEqualStrings("12345", update.message.sender.user_id);
    try std.testing.expectEqualStrings("NumericUser", update.message.sender.name.?);
}

test "parseUpdate message_created no body" {
    const allocator = std.testing.allocator;
    const json =
        \\{"update_type":"message_created","timestamp":1710000000,
        \\"message":{"sender":{"user_id":"42","name":"Alice"},
        \\"recipient":{"chat_id":"100","chat_type":"dialog"}}}
    ;
    const parsed = try parseTestJson(allocator, json);
    defer parsed.deinit();

    const update = parseUpdate(allocator, parsed.value) orelse return error.TestUnexpectedResult;
    defer update.deinit(allocator);

    try std.testing.expect(update == .message);
    try std.testing.expect(update.message.text == null);
    try std.testing.expect(update.message.mid == null);
    try std.testing.expectEqual(@as(usize, 0), update.message.attachment_urls.len);
}
