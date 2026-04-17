const std = @import("std");

pub const IdentityScratch = struct {
    user_id_buf: [32]u8 = undefined,
    chat_id_buf: [32]u8 = undefined,
};

pub const UserIdentity = struct {
    username: []const u8,
    user_id: ?[]const u8,
    first_name: ?[]const u8,
    preferred_identity: []const u8,
};

pub const ChatContext = struct {
    chat_id: []const u8,
    is_group: bool,
    message_id: ?i64,
    message_thread_id: ?i64 = null,
    media_group_id: ?[]const u8,
};

pub const DocumentInfo = struct {
    file_id: []const u8,
    file_name: ?[]const u8,
    mime_type: ?[]const u8,
    file_size: ?i64,
};

pub const VoiceOrAudioKind = enum {
    voice,
    audio,
};

pub const VoiceOrAudioInfo = struct {
    kind: VoiceOrAudioKind,
    file_id: []const u8,
    file_name: ?[]const u8,
    mime_type: ?[]const u8,
    file_size: ?i64,
    duration_secs: ?i64,
};

pub fn updateId(update: std.json.Value) ?i64 {
    const uid = objectField(update, "update_id") orelse return null;
    return if (uid == .integer) uid.integer else null;
}

pub fn callbackQuery(update: std.json.Value) ?std.json.Value {
    const cbq = objectField(update, "callback_query") orelse return null;
    return if (cbq == .object) cbq else null;
}

pub fn updateMessage(update: std.json.Value) ?std.json.Value {
    const message = objectField(update, "message") orelse return null;
    return if (message == .object) message else null;
}

pub fn callbackMessage(callback_query: std.json.Value) ?std.json.Value {
    const message = objectField(callback_query, "message") orelse return null;
    return if (message == .object) message else null;
}

pub fn messageSender(message: std.json.Value, scratch: *IdentityScratch) ?UserIdentity {
    const from_obj = objectField(message, "from") orelse return null;
    return userIdentity(from_obj, scratch);
}

pub fn callbackSender(callback_query: std.json.Value, scratch: *IdentityScratch) ?UserIdentity {
    const from_obj = objectField(callback_query, "from") orelse return null;
    return userIdentity(from_obj, scratch);
}

pub fn messageChatContext(message: std.json.Value, scratch: *IdentityScratch) ?ChatContext {
    const chat_obj = objectField(message, "chat") orelse return null;
    const chat_id_val = objectField(chat_obj, "id") orelse return null;
    if (chat_id_val != .integer) return null;

    const chat_id = std.fmt.bufPrint(&scratch.chat_id_buf, "{d}", .{chat_id_val.integer}) catch return null;
    const chat_type = stringField(chat_obj, "type");
    return .{
        .chat_id = chat_id,
        .is_group = if (chat_type) |value|
            !std.mem.eql(u8, value, "private")
        else
            false,
        .message_id = integerField(message, "message_id"),
        .message_thread_id = messageThreadId(message),
        .media_group_id = stringField(message, "media_group_id"),
    };
}

pub fn callbackMessageContext(callback_query: std.json.Value, scratch: *IdentityScratch) ?ChatContext {
    const message = callbackMessage(callback_query) orelse return null;
    return messageChatContext(message, scratch);
}

pub fn voiceOrAudioFileId(message: std.json.Value) ?[]const u8 {
    const info = voiceOrAudioInfo(message) orelse return null;
    return info.file_id;
}

pub fn voiceOrAudioInfo(message: std.json.Value) ?VoiceOrAudioInfo {
    if (mediaInfo(message, "voice")) |media| {
        return .{
            .kind = .voice,
            .file_id = media.file_id,
            .file_name = null,
            .mime_type = media.mime_type,
            .file_size = media.file_size,
            .duration_secs = media.duration_secs,
        };
    }

    if (mediaInfo(message, "audio")) |media| {
        return .{
            .kind = .audio,
            .file_id = media.file_id,
            .file_name = media.file_name,
            .mime_type = media.mime_type,
            .file_size = media.file_size,
            .duration_secs = media.duration_secs,
        };
    }

    return null;
}

pub fn photoFileId(message: std.json.Value) ?[]const u8 {
    const photo_val = objectField(message, "photo") orelse return null;
    if (photo_val != .array or photo_val.array.items.len == 0) return null;

    const last_photo = photo_val.array.items[photo_val.array.items.len - 1];
    if (last_photo != .object) return null;
    return stringField(last_photo, "file_id");
}

pub fn documentInfo(message: std.json.Value) ?DocumentInfo {
    const doc_val = objectField(message, "document") orelse return null;
    return .{
        .file_id = stringField(doc_val, "file_id") orelse return null,
        .file_name = stringField(doc_val, "file_name"),
        .mime_type = stringField(doc_val, "mime_type"),
        .file_size = integerField(doc_val, "file_size"),
    };
}

pub fn text(message: std.json.Value) ?[]const u8 {
    return stringField(message, "text");
}

pub fn caption(message: std.json.Value) ?[]const u8 {
    return stringField(message, "caption");
}

pub fn textOrCaption(allocator: std.mem.Allocator, message: std.json.Value) ?[]u8 {
    if (text(message)) |value| {
        return allocator.dupe(u8, value) catch null;
    }
    if (caption(message)) |value| {
        return allocator.dupe(u8, value) catch null;
    }
    return null;
}

fn mediaFileId(message: std.json.Value, key: []const u8) ?[]const u8 {
    const media = objectField(message, key) orelse return null;
    return stringField(media, "file_id");
}

const MediaInfo = struct {
    file_id: []const u8,
    file_name: ?[]const u8,
    mime_type: ?[]const u8,
    file_size: ?i64,
    duration_secs: ?i64,
};

fn mediaInfo(message: std.json.Value, key: []const u8) ?MediaInfo {
    const media = objectField(message, key) orelse return null;
    return .{
        .file_id = stringField(media, "file_id") orelse return null,
        .file_name = stringField(media, "file_name"),
        .mime_type = stringField(media, "mime_type"),
        .file_size = integerField(media, "file_size"),
        .duration_secs = integerField(media, "duration"),
    };
}

fn userIdentity(from_obj: std.json.Value, scratch: *IdentityScratch) ?UserIdentity {
    const username = stringField(from_obj, "username") orelse "unknown";
    const user_id = parseUserId(from_obj, scratch);
    return .{
        .username = username,
        .user_id = user_id,
        .first_name = stringField(from_obj, "first_name"),
        .preferred_identity = preferredIdentity(username, user_id),
    };
}

fn parseUserId(from_obj: std.json.Value, scratch: *IdentityScratch) ?[]const u8 {
    const id_val = objectField(from_obj, "id") orelse return null;
    if (id_val != .integer) return null;
    return std.fmt.bufPrint(&scratch.user_id_buf, "{d}", .{id_val.integer}) catch null;
}

fn preferredIdentity(username: []const u8, user_id: ?[]const u8) []const u8 {
    if (!std.mem.eql(u8, username, "unknown")) return username;
    return user_id orelse "unknown";
}

fn objectField(value: std.json.Value, key: []const u8) ?std.json.Value {
    if (value != .object) return null;
    return value.object.get(key);
}

fn stringField(value: std.json.Value, key: []const u8) ?[]const u8 {
    const field = objectField(value, key) orelse return null;
    return if (field == .string) field.string else null;
}

fn integerField(value: std.json.Value, key: []const u8) ?i64 {
    const field = objectField(value, key) orelse return null;
    return if (field == .integer) field.integer else null;
}

fn messageThreadId(message: std.json.Value) ?i64 {
    if (integerField(message, "message_thread_id")) |thread_id| {
        if (thread_id > 0) return thread_id;
    }

    const is_topic_message = blk: {
        const field = objectField(message, "is_topic_message") orelse break :blk false;
        break :blk field == .bool and field.bool;
    };
    if (!is_topic_message) return null;

    const reply_to_message = objectField(message, "reply_to_message") orelse return null;
    const reply_message_id = integerField(reply_to_message, "message_id") orelse return null;
    return if (reply_message_id > 0) reply_message_id else null;
}

test "telegram update ingress parses user identity" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"from":{"id":1001,"username":"tester","first_name":"Test"}}
    ,
        .{},
    );
    defer parsed.deinit();

    var scratch: IdentityScratch = .{};
    const sender = messageSender(parsed.value, &scratch) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("tester", sender.username);
    try std.testing.expectEqualStrings("1001", sender.user_id.?);
    try std.testing.expectEqualStrings("Test", sender.first_name.?);
    try std.testing.expectEqualStrings("tester", sender.preferred_identity);
}

test "telegram update ingress parses chat context" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"chat":{"id":2002,"type":"group"},"message_id":42,"message_thread_id":77,"media_group_id":"mg-1"}
    ,
        .{},
    );
    defer parsed.deinit();

    var scratch: IdentityScratch = .{};
    const chat = messageChatContext(parsed.value, &scratch) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("2002", chat.chat_id);
    try std.testing.expect(chat.is_group);
    try std.testing.expectEqual(@as(?i64, 42), chat.message_id);
    try std.testing.expectEqual(@as(?i64, 77), chat.message_thread_id);
    try std.testing.expectEqualStrings("mg-1", chat.media_group_id.?);
}

test "telegram update ingress infers thread id from topic reply root" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"chat":{"id":2002,"type":"supergroup"},"message_id":43,"is_topic_message":true,"reply_to_message":{"message_id":77}}
    ,
        .{},
    );
    defer parsed.deinit();

    var scratch: IdentityScratch = .{};
    const chat = messageChatContext(parsed.value, &scratch) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("2002", chat.chat_id);
    try std.testing.expect(chat.is_group);
    try std.testing.expectEqual(@as(?i64, 43), chat.message_id);
    try std.testing.expectEqual(@as(?i64, 77), chat.message_thread_id);
}

test "telegram update ingress falls back from text to caption" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        \\{"caption":"caption-only fallback"}
    ,
        .{},
    );
    defer parsed.deinit();

    const content = textOrCaption(allocator, parsed.value) orelse return error.TestExpectedEqual;
    defer allocator.free(content);
    try std.testing.expectEqualStrings("caption-only fallback", content);
}

test "telegram update ingress parses document metadata" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"document":{"file_id":"doc-1","file_name":"invoice.pdf","mime_type":"application/pdf","file_size":12345}}
    ,
        .{},
    );
    defer parsed.deinit();

    const doc = documentInfo(parsed.value) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("doc-1", doc.file_id);
    try std.testing.expectEqualStrings("invoice.pdf", doc.file_name.?);
    try std.testing.expectEqualStrings("application/pdf", doc.mime_type.?);
    try std.testing.expectEqual(@as(?i64, 12345), doc.file_size);
}

test "telegram update ingress parses voice and audio metadata" {
    const voice_parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"voice":{"file_id":"voice-1","mime_type":"audio/ogg","file_size":321,"duration":7}}
    ,
        .{},
    );
    defer voice_parsed.deinit();

    const voice_info = voiceOrAudioInfo(voice_parsed.value) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(VoiceOrAudioKind.voice, voice_info.kind);
    try std.testing.expectEqualStrings("voice-1", voice_info.file_id);
    try std.testing.expectEqualStrings("audio/ogg", voice_info.mime_type.?);
    try std.testing.expectEqual(@as(?i64, 321), voice_info.file_size);
    try std.testing.expectEqual(@as(?i64, 7), voice_info.duration_secs);

    const audio_parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"audio":{"file_id":"audio-1","file_name":"note.ogg","mime_type":"audio/ogg","file_size":654,"duration":12}}
    ,
        .{},
    );
    defer audio_parsed.deinit();

    const audio_info = voiceOrAudioInfo(audio_parsed.value) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(VoiceOrAudioKind.audio, audio_info.kind);
    try std.testing.expectEqualStrings("audio-1", audio_info.file_id);
    try std.testing.expectEqualStrings("note.ogg", audio_info.file_name.?);
    try std.testing.expectEqualStrings("audio/ogg", audio_info.mime_type.?);
    try std.testing.expectEqual(@as(?i64, 654), audio_info.file_size);
    try std.testing.expectEqual(@as(?i64, 12), audio_info.duration_secs);
}
