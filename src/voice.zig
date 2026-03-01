//! Voice transcription via Groq Whisper API (OpenAI-compatible).
//!
//! Reads an audio file, builds a multipart/form-data POST request,
//! and sends it to the Groq transcription endpoint. Returns the
//! transcribed text as an owned slice.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const json_util = @import("json_util.zig");
const http_util = @import("http_util.zig");

const log = std.log.scoped(.voice);

fn getPid() i32 {
    if (builtin.os.tag == .linux) return @intCast(std.os.linux.getpid());
    if (builtin.os.tag == .macos) return std.c.getpid();
    return 0;
}

pub const TranscribeOptions = struct {
    model: []const u8 = "whisper-large-v3",
    language: ?[]const u8 = null,
};

pub const TranscribeError = error{
    FileReadFailed,
    BoundaryGenerationFailed,
    ApiRequestFailed,
    InvalidResponse,
} || std.mem.Allocator.Error;

// ════════════════════════════════════════════════════════════════════════════
// Transcriber vtable interface
// ════════════════════════════════════════════════════════════════════════════

pub const Transcriber = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        transcribe: *const fn (*anyopaque, std.mem.Allocator, []const u8) TranscribeError!?[]const u8,
    };

    pub fn transcribe(self: Transcriber, alloc: std.mem.Allocator, path: []const u8) TranscribeError!?[]const u8 {
        return self.vtable.transcribe(self.ptr, alloc, path);
    }
};

pub const WhisperTranscriber = struct {
    endpoint: []const u8,
    api_key: []const u8,
    model: []const u8,
    language: ?[]const u8,

    fn vtableTranscribe(ptr: *anyopaque, alloc: std.mem.Allocator, path: []const u8) TranscribeError!?[]const u8 {
        const self: *WhisperTranscriber = @ptrCast(@alignCast(ptr));
        const result = try transcribeFile(alloc, self.api_key, self.endpoint, path, .{
            .model = self.model,
            .language = self.language,
        });
        return result;
    }

    pub const vtable = Transcriber.VTable{
        .transcribe = &vtableTranscribe,
    };

    pub fn transcriber(self: *WhisperTranscriber) Transcriber {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

/// Resolve transcription endpoint for a given provider name.
pub fn resolveTranscriptionEndpoint(provider: []const u8, explicit_endpoint: ?[]const u8) []const u8 {
    if (explicit_endpoint) |ep| return ep;
    if (std.mem.eql(u8, provider, "openai")) return "https://api.openai.com/v1/audio/transcriptions";
    if (std.mem.eql(u8, provider, "groq")) return "https://api.groq.com/openai/v1/audio/transcriptions";
    if (std.mem.eql(u8, provider, "telnyx")) return "https://api.telnyx.com/v2/ai/audio/transcriptions";
    // For unknown providers, try OpenAI-compatible endpoint
    return "https://api.groq.com/openai/v1/audio/transcriptions";
}

/// Transcribe an audio file using the Groq Whisper API.
///
/// Reads the file at `file_path`, builds a multipart/form-data request,
/// POSTs to the Groq transcription endpoint, and returns the transcribed text.
/// Caller owns the returned slice.
pub fn transcribeFile(
    allocator: std.mem.Allocator,
    api_key: []const u8,
    endpoint: []const u8,
    file_path: []const u8,
    opts: TranscribeOptions,
) TranscribeError![]const u8 {
    // Generate random boundary (16 hex chars)
    const boundary = generateBoundary() catch return error.BoundaryGenerationFailed;

    // Build temp file path (platform-aware temp dir)
    const tmp_dir = platform.getTempDir(allocator) catch return error.FileReadFailed;
    defer allocator.free(tmp_dir);
    var tmp_path_buf: [256]u8 = undefined;
    var tmp_fbs = std.io.fixedBufferStream(&tmp_path_buf);
    tmp_fbs.writer().print("{s}/nullclaw_voice_{d}.bin", .{ tmp_dir, getPid() }) catch
        return error.FileReadFailed;
    const tmp_path_len = tmp_fbs.pos;
    tmp_path_buf[tmp_path_len] = 0;
    const tmp_path: [:0]const u8 = tmp_path_buf[0..tmp_path_len :0];

    // Write multipart body directly to temp file (avoids holding file_data + body in memory)
    writeMultipartToTempFile(tmp_path, file_path, &boundary, opts) catch
        return error.FileReadFailed;
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    // Build headers
    var content_type_buf: [128]u8 = undefined;
    var ct_fbs = std.io.fixedBufferStream(&content_type_buf);
    ct_fbs.writer().print("Content-Type: multipart/form-data; boundary={s}", .{&boundary}) catch
        return error.BoundaryGenerationFailed;
    const content_type_hdr = ct_fbs.getWritten();

    var auth_buf: [256]u8 = undefined;
    var auth_fbs = std.io.fixedBufferStream(&auth_buf);
    auth_fbs.writer().print("Authorization: Bearer {s}", .{api_key}) catch
        return error.ApiRequestFailed;
    const auth_hdr = auth_fbs.getWritten();

    // POST via curl using --data-binary @tempfile
    const resp = curlPostFromFile(
        allocator,
        endpoint,
        tmp_path,
        &.{ auth_hdr, content_type_hdr },
    ) catch return error.ApiRequestFailed;
    defer allocator.free(resp);

    // Parse {"text":"..."} from response
    return parseTranscriptionText(allocator, resp) catch return error.InvalidResponse;
}

/// Generate a random 32-character hex boundary string.
fn generateBoundary() ![32]u8 {
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var boundary: [32]u8 = undefined;
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |b, i| {
        boundary[i * 2] = hex[b >> 4];
        boundary[i * 2 + 1] = hex[b & 0x0f];
    }
    return boundary;
}

/// Build the multipart/form-data body.
fn buildMultipartBody(
    allocator: std.mem.Allocator,
    boundary: []const u8,
    file_data: []const u8,
    opts: TranscribeOptions,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    // Part: file
    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.ogg\"\r\nContent-Type: audio/ogg\r\n\r\n");
    try body.appendSlice(allocator, file_data);
    try body.appendSlice(allocator, "\r\n");

    // Part: model
    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n");
    try body.appendSlice(allocator, opts.model);
    try body.appendSlice(allocator, "\r\n");

    // Part: language (optional)
    if (opts.language) |lang| {
        try body.appendSlice(allocator, "--");
        try body.appendSlice(allocator, boundary);
        try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n");
        try body.appendSlice(allocator, lang);
        try body.appendSlice(allocator, "\r\n");
    }

    // Closing boundary
    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "--\r\n");

    return body.toOwnedSlice(allocator);
}

/// Write multipart/form-data directly to a temp file, streaming the audio file
/// through without building the full body in memory.
/// This avoids holding both file_data and multipart body in RAM simultaneously.
fn writeMultipartToTempFile(
    tmp_path: [:0]const u8,
    audio_path: []const u8,
    boundary: []const u8,
    opts: TranscribeOptions,
) !void {
    const tmp_file = try std.fs.createFileAbsolute(tmp_path, .{});
    defer tmp_file.close();

    // Write file part header
    try tmp_file.writeAll("--");
    try tmp_file.writeAll(boundary);
    try tmp_file.writeAll("\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.ogg\"\r\nContent-Type: audio/ogg\r\n\r\n");

    // Stream audio file directly (no intermediate buffer)
    {
        const audio_file = try std.fs.openFileAbsolute(audio_path, .{});
        defer audio_file.close();
        var buf: [32768]u8 = undefined;
        while (true) {
            const n = try audio_file.read(&buf);
            if (n == 0) break;
            try tmp_file.writeAll(buf[0..n]);
        }
    }
    try tmp_file.writeAll("\r\n");

    // Write model part
    try tmp_file.writeAll("--");
    try tmp_file.writeAll(boundary);
    try tmp_file.writeAll("\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n");
    try tmp_file.writeAll(opts.model);
    try tmp_file.writeAll("\r\n");

    // Write language part (optional)
    if (opts.language) |lang| {
        try tmp_file.writeAll("--");
        try tmp_file.writeAll(boundary);
        try tmp_file.writeAll("\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n");
        try tmp_file.writeAll(lang);
        try tmp_file.writeAll("\r\n");
    }

    // Closing boundary
    try tmp_file.writeAll("--");
    try tmp_file.writeAll(boundary);
    try tmp_file.writeAll("--\r\n");
}

/// Parse the "text" field from a JSON response like {"text":"transcribed text here"}.
fn parseTranscriptionText(allocator: std.mem.Allocator, json_resp: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_resp, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();

    const text_val = parsed.value.object.get("text") orelse return error.InvalidResponse;
    if (text_val != .string) return error.InvalidResponse;
    return try allocator.dupe(u8, text_val.string);
}

/// HTTP POST via curl subprocess, reading body from a file on disk.
/// Used for multipart/form-data where body has already been written to a temp file.
fn curlPostFromFile(
    allocator: std.mem.Allocator,
    url: []const u8,
    file_path: [:0]const u8,
    headers: []const []const u8,
) ![]u8 {
    // Build data-binary arg: @/path/to/file
    var data_arg_buf: [300]u8 = undefined;
    var data_fbs = std.io.fixedBufferStream(&data_arg_buf);
    try data_fbs.writer().print("@{s}", .{file_path});
    const data_arg = data_fbs.getWritten();

    var argv_buf: [32][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = data_arg;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return error.CurlReadError;

    const term = child.wait() catch return error.CurlWaitError;
    switch (term) {
        .Exited => |code| if (code != 0) {
            allocator.free(stdout);
            return error.CurlFailed;
        },
        else => {
            allocator.free(stdout);
            return error.CurlFailed;
        },
    }

    return stdout;
}

// ════════════════════════════════════════════════════════════════════════════
// Telegram Voice Integration
// ════════════════════════════════════════════════════════════════════════════

/// Download a Telegram voice/audio file and transcribe it.
/// Returns the transcribed text, or null if transcription is unavailable
/// (no Transcriber configured or file download fails).
pub fn transcribeTelegramVoice(
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    file_id: []const u8,
    t: ?Transcriber,
) ?[]const u8 {
    const transcr = t orelse return null;

    // 1. Call getFile to get file_path
    const tg_file_path = getFilePath(allocator, bot_token, file_id) catch |err| {
        log.err("getFile failed: {}", .{err});
        return null;
    };
    defer allocator.free(tg_file_path);

    // 2. Download file via Telegram API
    const local_path = downloadTelegramFile(allocator, bot_token, tg_file_path) catch |err| {
        log.err("download failed: {}", .{err});
        return null;
    };
    defer {
        // Clean up temp file
        std.fs.deleteFileAbsolute(local_path) catch {};
        allocator.free(local_path);
    }

    // 3. Transcribe via vtable
    const text = transcr.transcribe(allocator, local_path) catch |err| {
        log.err("transcription failed: {}", .{err});
        return null;
    };

    return text;
}

/// Call Telegram getFile API and extract the file_path from the response.
fn getFilePath(allocator: std.mem.Allocator, bot_token: []const u8, file_id: []const u8) ![]u8 {
    var url_buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&url_buf);
    try fbs.writer().print("https://api.telegram.org/bot{s}/getFile", .{bot_token});
    const url = fbs.getWritten();

    // Build request body
    var body_list: std.ArrayListUnmanaged(u8) = .empty;
    defer body_list.deinit(allocator);
    try body_list.appendSlice(allocator, "{\"file_id\":");
    try json_util.appendJsonString(&body_list, allocator, file_id);
    try body_list.appendSlice(allocator, "}");

    const resp = try http_util.curlPost(allocator, url, body_list.items, &.{});
    defer allocator.free(resp);

    // Parse response
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch
        return error.InvalidResponse;
    defer parsed.deinit();

    const result = parsed.value.object.get("result") orelse return error.InvalidResponse;
    const fp_val = result.object.get("file_path") orelse return error.InvalidResponse;
    if (fp_val != .string) return error.InvalidResponse;
    return try allocator.dupe(u8, fp_val.string);
}

/// Download a file from Telegram and save to temp dir. Returns the local path (owned).
fn downloadTelegramFile(allocator: std.mem.Allocator, bot_token: []const u8, tg_file_path: []const u8) ![]u8 {
    var url_buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&url_buf);
    try fbs.writer().print("https://api.telegram.org/file/bot{s}/{s}", .{ bot_token, tg_file_path });
    const url = fbs.getWritten();

    const data = try http_util.curlGet(allocator, url, &.{}, "30");
    defer allocator.free(data);

    // Save to temp file (platform-aware temp dir)
    const tmp_dir = platform.getTempDir(allocator) catch return error.OutOfMemory;
    defer allocator.free(tmp_dir);
    const pid = getPid();
    var path_buf: [256]u8 = undefined;
    var path_fbs = std.io.fixedBufferStream(&path_buf);
    try path_fbs.writer().print("{s}/nullclaw_tg_voice_{d}.ogg", .{ tmp_dir, pid });
    const local_path = path_fbs.getWritten();

    var z_buf: [256]u8 = undefined;
    @memcpy(z_buf[0..local_path.len], local_path);
    z_buf[local_path.len] = 0;
    const local_path_z: [:0]const u8 = z_buf[0..local_path.len :0];

    {
        const f = try std.fs.createFileAbsolute(local_path_z, .{});
        defer f.close();
        try f.writeAll(data);
    }

    return try allocator.dupe(u8, local_path);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "voice TranscribeOptions defaults" {
    const opts = TranscribeOptions{};
    try std.testing.expectEqualStrings("whisper-large-v3", opts.model);
    try std.testing.expect(opts.language == null);
}

test "voice TranscribeOptions custom" {
    const opts = TranscribeOptions{
        .model = "whisper-large-v3-turbo",
        .language = "ru",
    };
    try std.testing.expectEqualStrings("whisper-large-v3-turbo", opts.model);
    try std.testing.expectEqualStrings("ru", opts.language.?);
}

test "voice generateBoundary produces 32 hex chars" {
    const boundary = try generateBoundary();
    try std.testing.expectEqual(@as(usize, 32), boundary.len);
    for (&boundary) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "voice generateBoundary produces different values" {
    const b1 = try generateBoundary();
    const b2 = try generateBoundary();
    // Extremely unlikely to be equal
    try std.testing.expect(!std.mem.eql(u8, &b1, &b2));
}

test "voice buildMultipartBody structure" {
    const allocator = std.testing.allocator;
    const boundary = "abcdef0123456789abcdef0123456789";
    const file_data = "fake audio data";

    const body = try buildMultipartBody(allocator, boundary, file_data, .{});
    defer allocator.free(body);

    // Check that boundary markers appear
    try std.testing.expect(std.mem.indexOf(u8, body, "--abcdef0123456789abcdef0123456789") != null);
    // Check file part
    try std.testing.expect(std.mem.indexOf(u8, body, "name=\"file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "filename=\"audio.ogg\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Content-Type: audio/ogg") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "fake audio data") != null);
    // Check model part
    try std.testing.expect(std.mem.indexOf(u8, body, "name=\"model\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "whisper-large-v3") != null);
    // Check closing boundary
    try std.testing.expect(std.mem.indexOf(u8, body, "--abcdef0123456789abcdef0123456789--") != null);
}

test "voice buildMultipartBody with language" {
    const allocator = std.testing.allocator;
    const boundary = "abcdef0123456789abcdef0123456789";

    const body = try buildMultipartBody(allocator, boundary, "data", .{ .language = "en" });
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "name=\"language\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "en") != null);
}

test "voice buildMultipartBody without language" {
    const allocator = std.testing.allocator;
    const boundary = "abcdef0123456789abcdef0123456789";

    const body = try buildMultipartBody(allocator, boundary, "data", .{});
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "name=\"language\"") == null);
}

test "voice parseTranscriptionText valid" {
    const allocator = std.testing.allocator;
    const json = "{\"text\":\"Hello, world!\"}";
    const text = try parseTranscriptionText(allocator, json);
    defer allocator.free(text);
    try std.testing.expectEqualStrings("Hello, world!", text);
}

test "voice parseTranscriptionText unicode" {
    const allocator = std.testing.allocator;
    const json = "{\"text\":\"Héllo wörld\"}";
    const text = try parseTranscriptionText(allocator, json);
    defer allocator.free(text);
    try std.testing.expectEqualStrings("Héllo wörld", text);
}

test "voice parseTranscriptionText missing field" {
    const allocator = std.testing.allocator;
    const result = parseTranscriptionText(allocator, "{\"status\":\"ok\"}");
    try std.testing.expectError(error.InvalidResponse, result);
}

test "voice parseTranscriptionText invalid json" {
    const allocator = std.testing.allocator;
    const result = parseTranscriptionText(allocator, "not json");
    try std.testing.expectError(error.InvalidResponse, result);
}

test "voice parseTranscriptionText non-string text" {
    const allocator = std.testing.allocator;
    const result = parseTranscriptionText(allocator, "{\"text\":42}");
    try std.testing.expectError(error.InvalidResponse, result);
}

test "voice parseTranscriptionText empty text" {
    const allocator = std.testing.allocator;
    const text = try parseTranscriptionText(allocator, "{\"text\":\"\"}");
    defer allocator.free(text);
    try std.testing.expectEqualStrings("", text);
}

test "voice transcribeFile returns error for nonexistent file" {
    const allocator = std.testing.allocator;
    const result = transcribeFile(allocator, "fake_key", "https://api.groq.com/openai/v1/audio/transcriptions", "/nonexistent/path/audio.ogg", .{});
    try std.testing.expectError(error.FileReadFailed, result);
}

test "voice transcribeTelegramVoice returns null without transcriber" {
    // No transcriber configured, so should return null
    const result = transcribeTelegramVoice(std.testing.allocator, "fake:token", "fake_file_id", null);
    try std.testing.expect(result == null);
}

test "voice WhisperTranscriber stores fields" {
    var wt = WhisperTranscriber{
        .endpoint = "https://api.groq.com/openai/v1/audio/transcriptions",
        .api_key = "gsk_test",
        .model = "whisper-large-v3",
        .language = "ru",
    };
    try std.testing.expectEqualStrings("gsk_test", wt.api_key);
    try std.testing.expectEqualStrings("ru", wt.language.?);
    // Vtable dispatches
    const t = wt.transcriber();
    try std.testing.expect(t.vtable == &WhisperTranscriber.vtable);
}

test "voice resolveTranscriptionEndpoint groq" {
    try std.testing.expectEqualStrings(
        "https://api.groq.com/openai/v1/audio/transcriptions",
        resolveTranscriptionEndpoint("groq", null),
    );
}

test "voice resolveTranscriptionEndpoint openai" {
    try std.testing.expectEqualStrings(
        "https://api.openai.com/v1/audio/transcriptions",
        resolveTranscriptionEndpoint("openai", null),
    );
}

test "voice resolveTranscriptionEndpoint explicit" {
    try std.testing.expectEqualStrings(
        "http://localhost:9090/v1/transcribe",
        resolveTranscriptionEndpoint("groq", "http://localhost:9090/v1/transcribe"),
    );
}

test "voice resolveTranscriptionEndpoint unknown falls back to groq" {
    // Unknown providers fall back to the Groq-compatible endpoint
    try std.testing.expectEqualStrings(
        "https://api.groq.com/openai/v1/audio/transcriptions",
        resolveTranscriptionEndpoint("some-unknown-provider", null),
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Telnyx Transcriber (OpenAI-compatible Whisper STT)
// ════════════════════════════════════════════════════════════════════════════

pub const TelnyxTranscriber = struct {
    endpoint: []const u8,
    api_key: []const u8,
    model: []const u8,
    language: ?[]const u8,

    fn vtableTranscribe(ptr: *anyopaque, alloc: std.mem.Allocator, path: []const u8) TranscribeError!?[]const u8 {
        const self: *TelnyxTranscriber = @ptrCast(@alignCast(ptr));
        const result = try transcribeFile(alloc, self.api_key, self.endpoint, path, .{
            .model = self.model,
            .language = self.language,
        });
        return result;
    }

    pub const vtable = Transcriber.VTable{
        .transcribe = &vtableTranscribe,
    };

    pub fn transcriber(self: *TelnyxTranscriber) Transcriber {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

test "voice TelnyxTranscriber stores fields" {
    var tt = TelnyxTranscriber{
        .endpoint = "https://api.telnyx.com/v2/ai/audio/transcriptions",
        .api_key = "test-telnyx-key",
        .model = "whisper-1",
        .language = "en",
    };
    try std.testing.expectEqualStrings("test-telnyx-key", tt.api_key);
    try std.testing.expectEqualStrings("en", tt.language.?);
    // Vtable dispatches
    const t = tt.transcriber();
    try std.testing.expect(t.vtable == &TelnyxTranscriber.vtable);
}

test "voice resolveTranscriptionEndpoint telnyx" {
    try std.testing.expectEqualStrings(
        "https://api.telnyx.com/v2/ai/audio/transcriptions",
        resolveTranscriptionEndpoint("telnyx", null),
    );
}
