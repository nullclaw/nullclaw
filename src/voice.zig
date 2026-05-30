//! Voice transcription via OpenAI-compatible STT APIs (Groq/OpenAI/Telnyx).
//!
//! Reads an audio file, builds a multipart/form-data POST request,
//! and sends it to the configured transcription endpoint. Returns the
//! transcribed text as an owned slice.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const json_util = @import("json_util.zig");
const http_util = @import("http_util.zig");
const net_security = @import("net_security.zig");

const log = std.log.scoped(.voice);

fn getPid() i32 {
    if (builtin.os.tag == .linux) return @intCast(std.os.linux.getpid());
    if (builtin.os.tag == .macos) return std.c.getpid();
    return 0;
}

pub const TranscribeOptions = struct {
    model: []const u8 = "whisper-large-v3",
    language: ?[]const u8 = null,
    mime_type: []const u8 = "audio/ogg",
    filename: []const u8 = "audio.ogg",
};

pub const TranscribeError = error{
    FileReadFailed,
    BoundaryGenerationFailed,
    ApiRequestFailed,
    InvalidResponse,
} || std.mem.Allocator.Error;

const TEMP_PATH_ATTEMPTS: usize = 16;
const TRANSCRIBE_CURL_MAX_TIME_SECS = "120";
const TRANSCRIBE_CURL_CONNECT_TIMEOUT_SECS = "30";

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
    if (std.ascii.eqlIgnoreCase(provider, "openai")) return "https://api.openai.com/v1/audio/transcriptions";
    if (std.ascii.eqlIgnoreCase(provider, "groq")) return "https://api.groq.com/openai/v1/audio/transcriptions";
    if (std.ascii.eqlIgnoreCase(provider, "telnyx")) return "https://api.telnyx.com/v2/ai/audio/transcriptions";
    // For unknown providers, try OpenAI-compatible endpoint
    return "https://api.groq.com/openai/v1/audio/transcriptions";
}

fn trimTrailingSlash(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and s[end - 1] == '/') end -= 1;
    return s[0..end];
}

/// Derive an OpenAI-compatible transcription endpoint from a provider base URL.
/// Explicit `tools.media.audio.models[0].base_url` values remain exact endpoints;
/// this helper is for `models.providers.<name>.base_url` and `custom:<base>`.
pub fn transcriptionEndpointFromBaseUrl(allocator: std.mem.Allocator, base_url: []const u8) ![]u8 {
    const trimmed = trimTrailingSlash(base_url);
    if (std.mem.endsWith(u8, trimmed, "/audio/transcriptions")) {
        return try allocator.dupe(u8, trimmed);
    }
    if (std.mem.endsWith(u8, trimmed, "/chat/completions")) {
        const prefix = trimmed[0 .. trimmed.len - "/chat/completions".len];
        return std.fmt.allocPrint(allocator, "{s}/audio/transcriptions", .{prefix});
    }
    if (hasExplicitApiPath(trimmed)) {
        return std.fmt.allocPrint(allocator, "{s}/audio/transcriptions", .{trimmed});
    }
    return std.fmt.allocPrint(allocator, "{s}/v1/audio/transcriptions", .{trimmed});
}

fn hasExplicitApiPath(url: []const u8) bool {
    const after_scheme = if (std.mem.indexOf(u8, url, "://")) |idx| url[idx + 3 ..] else return false;
    const path_start = std.mem.indexOf(u8, after_scheme, "/") orelse return false;
    const path = trimTrailingSlash(after_scheme[path_start..]);
    return path.len > 0 and !std.mem.eql(u8, path, "/");
}

fn isSafeTranscriptionEndpointUrl(url: []const u8) bool {
    const trimmed = std.mem.trim(u8, url, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len != url.len) return false;
    if (std.mem.indexOfAny(u8, trimmed, " \t\r\n?#") != null) return false;

    const uri = std.Uri.parse(trimmed) catch return false;
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
    if (!is_https and !is_http) return false;

    const host = net_security.extractHost(trimmed) orelse return false;
    if (is_http and !net_security.isLocalHost(host)) return false;
    return true;
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
    if (!isSafeTranscriptionEndpointUrl(endpoint)) return error.ApiRequestFailed;

    // Generate random boundary (16 hex chars)
    const boundary = generateBoundary() catch return error.BoundaryGenerationFailed;

    // Build temp file path (platform-aware temp dir)
    const tmp_dir = platform.getTempDir(allocator) catch return error.FileReadFailed;
    defer allocator.free(tmp_dir);

    // Write multipart body directly to temp file (avoids holding file_data + body in memory)
    const tmp_path = writeMultipartToUniqueTempFile(allocator, tmp_dir, file_path, &boundary, opts) catch
        return error.FileReadFailed;
    defer {
        std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
        allocator.free(tmp_path);
    }

    // Build headers
    const content_type_hdr = std.fmt.allocPrint(
        allocator,
        "Content-Type: multipart/form-data; boundary={s}",
        .{&boundary},
    ) catch return error.BoundaryGenerationFailed;
    defer allocator.free(content_type_hdr);

    const auth_hdr = std.fmt.allocPrint(
        allocator,
        "Authorization: Bearer {s}",
        .{api_key},
    ) catch return error.ApiRequestFailed;
    defer allocator.free(auth_hdr);

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

fn tempMultipartPath(allocator: std.mem.Allocator, tmp_dir: []const u8) ![:0]u8 {
    const raw = try std.fmt.allocPrint(
        allocator,
        "{s}{c}nullclaw_voice_{d}_{x}.bin",
        .{ tmp_dir, std.fs.path.sep, getPid(), std_compat.crypto.random.int(u64) },
    );
    defer allocator.free(raw);
    const path = try allocator.allocSentinel(u8, raw.len, 0);
    @memcpy(path[0..raw.len], raw);
    return path;
}

fn writeMultipartToUniqueTempFile(
    allocator: std.mem.Allocator,
    tmp_dir: []const u8,
    file_path: []const u8,
    boundary: []const u8,
    opts: TranscribeOptions,
) ![:0]u8 {
    var attempts: usize = 0;
    while (attempts < TEMP_PATH_ATTEMPTS) : (attempts += 1) {
        const tmp_path = try tempMultipartPath(allocator, tmp_dir);
        errdefer allocator.free(tmp_path);
        writeMultipartToTempFile(tmp_path, file_path, boundary, opts) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(tmp_path);
                continue;
            },
            else => return err,
        };
        return tmp_path;
    }
    return error.TempFileUnavailable;
}

/// Generate a random 32-character hex boundary string.
fn generateBoundary() ![32]u8 {
    var random_bytes: [16]u8 = undefined;
    std_compat.crypto.random.bytes(&random_bytes);
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
    try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
    try body.appendSlice(allocator, opts.filename);
    try body.appendSlice(allocator, "\"\r\nContent-Type: ");
    try body.appendSlice(allocator, opts.mime_type);
    try body.appendSlice(allocator, "\r\n\r\n");
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
    tmp_path: []const u8,
    audio_path: []const u8,
    boundary: []const u8,
    opts: TranscribeOptions,
) !void {
    const tmp_file = try std_compat.fs.createFileAbsolute(tmp_path, .{
        .read = false,
        .truncate = false,
        .exclusive = true,
    });
    errdefer std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
    defer tmp_file.close();

    // Write file part header
    try tmp_file.writeAll("--");
    try tmp_file.writeAll(boundary);
    try tmp_file.writeAll("\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
    try tmp_file.writeAll(opts.filename);
    try tmp_file.writeAll("\"\r\nContent-Type: ");
    try tmp_file.writeAll(opts.mime_type);
    try tmp_file.writeAll("\r\n\r\n");

    // Stream audio file directly (no intermediate buffer)
    {
        const audio_file = try std_compat.fs.openFileAbsolute(audio_path, .{});
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

    if (parsed.value != .object) return error.InvalidResponse;
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
    const data_arg = try std.fmt.allocPrint(allocator, "@{s}", .{file_path});
    defer allocator.free(data_arg);

    var argv_buf: [32][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--max-time";
    argc += 1;
    argv_buf[argc] = TRANSCRIBE_CURL_MAX_TIME_SECS;
    argc += 1;
    argv_buf[argc] = "--connect-timeout";
    argc += 1;
    argv_buf[argc] = TRANSCRIBE_CURL_CONNECT_TIMEOUT_SECS;
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;

    var prepared_headers = try http_util.prepareCurlHeaderArg(allocator, headers);
    defer prepared_headers.deinit(allocator);
    if (prepared_headers.arg) |headers_arg| {
        if (argc + 2 > argv_buf.len) return error.CurlFailed;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = headers_arg;
        argc += 1;
    }

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = data_arg;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return error.CurlReadError;

    const term = child.wait() catch return error.CurlWaitError;
    switch (term) {
        .exited => |code| if (code != 0) {
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
        std_compat.fs.deleteFileAbsolute(local_path) catch {};
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
    var writer: std.Io.Writer = .fixed(&url_buf);
    try writer.print("https://api.telegram.org/bot{s}/getFile", .{bot_token});
    const url = writer.buffered();

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
    var url_writer: std.Io.Writer = .fixed(&url_buf);
    try url_writer.print("https://api.telegram.org/file/bot{s}/{s}", .{ bot_token, tg_file_path });
    const url = url_writer.buffered();

    const data = try http_util.curlGet(allocator, url, &.{}, "30");
    defer allocator.free(data);

    // Save to temp file (platform-aware temp dir)
    const tmp_dir = platform.getTempDir(allocator) catch return error.OutOfMemory;
    defer allocator.free(tmp_dir);
    const pid = getPid();
    var path_buf: [256]u8 = undefined;
    var path_writer: std.Io.Writer = .fixed(&path_buf);
    try path_writer.print("{s}/nullclaw_tg_voice_{d}.ogg", .{ tmp_dir, pid });
    const local_path = path_writer.buffered();

    var z_buf: [256]u8 = undefined;
    @memcpy(z_buf[0..local_path.len], local_path);
    z_buf[local_path.len] = 0;
    const local_path_z: [:0]const u8 = z_buf[0..local_path.len :0];

    {
        const f = try std_compat.fs.createFileAbsolute(local_path_z, .{});
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
    try std.testing.expectEqualStrings("audio/ogg", opts.mime_type);
    try std.testing.expectEqualStrings("audio.ogg", opts.filename);
}

test "voice TranscribeOptions custom" {
    const opts = TranscribeOptions{
        .model = "whisper-large-v3-turbo",
        .language = "ru",
        .mime_type = "audio/wav",
        .filename = "capture.wav",
    };
    try std.testing.expectEqualStrings("whisper-large-v3-turbo", opts.model);
    try std.testing.expectEqualStrings("ru", opts.language.?);
    try std.testing.expectEqualStrings("audio/wav", opts.mime_type);
    try std.testing.expectEqualStrings("capture.wav", opts.filename);
}

test "voice resolveTranscriptionEndpoint is provider case insensitive" {
    try std.testing.expectEqualStrings(
        "https://api.openai.com/v1/audio/transcriptions",
        resolveTranscriptionEndpoint("OpenAI", null),
    );
    try std.testing.expectEqualStrings(
        "https://api.groq.com/openai/v1/audio/transcriptions",
        resolveTranscriptionEndpoint("GROQ", null),
    );
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

test "voice buildMultipartBody uses requested audio mime and filename" {
    const allocator = std.testing.allocator;
    const boundary = "abcdef0123456789abcdef0123456789";
    const body = try buildMultipartBody(allocator, boundary, "data", .{
        .mime_type = "audio/wav",
        .filename = "capture.wav",
    });
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "filename=\"capture.wav\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Content-Type: audio/wav") != null);
}

test "voice writeMultipartToTempFile refuses to overwrite existing file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const audio_path = try std.fmt.allocPrint(allocator, "{s}/audio.ogg", .{base});
    defer allocator.free(audio_path);
    const target_path = try std.fmt.allocPrint(allocator, "{s}/multipart.bin", .{base});
    defer allocator.free(target_path);

    {
        const audio_file = try std_compat.fs.createFileAbsolute(audio_path, .{});
        defer audio_file.close();
        try audio_file.writeAll("audio");
    }
    {
        const target_file = try std_compat.fs.createFileAbsolute(target_path, .{});
        defer target_file.close();
        try target_file.writeAll("existing");
    }

    try std.testing.expectError(
        error.PathAlreadyExists,
        writeMultipartToTempFile(target_path, audio_path, "abcdef0123456789abcdef0123456789", .{}),
    );

    const target_file = try std_compat.fs.openFileAbsolute(target_path, .{});
    defer target_file.close();
    const content = try target_file.readToEndAlloc(allocator, 64);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("existing", content);
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

test "voice parseTranscriptionText rejects non-object response" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidResponse, parseTranscriptionText(allocator, "[]"));
    try std.testing.expectError(error.InvalidResponse, parseTranscriptionText(allocator, "\"text\""));
}

test "voice parseTranscriptionText empty text" {
    const allocator = std.testing.allocator;
    const text = try parseTranscriptionText(allocator, "{\"text\":\"\"}");
    defer allocator.free(text);
    try std.testing.expectEqualStrings("", text);
}

test "voice transcriptionEndpointFromBaseUrl derives OpenAI-compatible paths" {
    const allocator = std.testing.allocator;

    {
        const endpoint = try transcriptionEndpointFromBaseUrl(allocator, "https://api.example.com");
        defer allocator.free(endpoint);
        try std.testing.expectEqualStrings("https://api.example.com/v1/audio/transcriptions", endpoint);
    }
    {
        const endpoint = try transcriptionEndpointFromBaseUrl(allocator, "https://api.example.com/v1");
        defer allocator.free(endpoint);
        try std.testing.expectEqualStrings("https://api.example.com/v1/audio/transcriptions", endpoint);
    }
    {
        const endpoint = try transcriptionEndpointFromBaseUrl(allocator, "https://api.example.com/v1/chat/completions");
        defer allocator.free(endpoint);
        try std.testing.expectEqualStrings("https://api.example.com/v1/audio/transcriptions", endpoint);
    }
    {
        const endpoint = try transcriptionEndpointFromBaseUrl(allocator, "https://api.example.com/v1/audio/transcriptions/");
        defer allocator.free(endpoint);
        try std.testing.expectEqualStrings("https://api.example.com/v1/audio/transcriptions", endpoint);
    }
}

test "voice transcription endpoint URL validation" {
    try std.testing.expect(isSafeTranscriptionEndpointUrl("https://api.example.com/v1/audio/transcriptions"));
    try std.testing.expect(isSafeTranscriptionEndpointUrl("http://localhost:9090/v1/audio/transcriptions"));
    try std.testing.expect(!isSafeTranscriptionEndpointUrl("http://api.example.com/v1/audio/transcriptions"));
    try std.testing.expect(!isSafeTranscriptionEndpointUrl("https://api.example.com/v1/audio/transcriptions?access_token=test"));
    try std.testing.expect(!isSafeTranscriptionEndpointUrl("https://api.example.com/v1/audio/transcriptions#frag"));
}

test "voice transcribeFile returns error for nonexistent file" {
    const allocator = std.testing.allocator;
    const result = transcribeFile(allocator, "fake_key", "https://api.groq.com/openai/v1/audio/transcriptions", "/nonexistent/path/audio.ogg", .{});
    try std.testing.expectError(error.FileReadFailed, result);
}

test "voice transcribeFile rejects remote plaintext endpoint before request" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const audio_path = try std.fmt.allocPrint(allocator, "{s}/audio.ogg", .{base});
    defer allocator.free(audio_path);
    {
        const file = try std_compat.fs.createFileAbsolute(audio_path, .{});
        defer file.close();
        try file.writeAll("audio");
    }

    const result = transcribeFile(allocator, "fake_key", "http://api.example.com/v1/audio/transcriptions", audio_path, .{});
    try std.testing.expectError(error.ApiRequestFailed, result);
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

test "voice resolveTranscriptionEndpoint telnyx" {
    try std.testing.expectEqualStrings(
        "https://api.telnyx.com/v2/ai/audio/transcriptions",
        resolveTranscriptionEndpoint("telnyx", null),
    );
}
