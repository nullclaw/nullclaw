//! Multimodal image processing — [IMAGE:] marker parsing, MIME detection,
//! base64 encoding, and ephemeral content_parts preparation for providers.
//!
//! Ported from ZeroClaw's `src/multimodal.rs`.
//! Images travel as `[IMAGE:path]` markers in content strings through the
//! entire pipeline. Conversion to `content_parts` happens ephemerally at
//! send time (arena-allocated), with no changes to session/agent signatures
//! or message history storage.

const std = @import("std");
const providers = @import("providers/root.zig");
const ChatMessage = providers.ChatMessage;
const ContentPart = providers.ContentPart;
const path_security = @import("tools/path_security.zig");

const log = std.log.scoped(.multimodal);

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════

pub const MultimodalConfig = struct {
    max_images: u32 = 4,
    max_image_size_bytes: u64 = 5_242_880, // 5 MB
    /// Allow passing remote image URLs (`https://...`) through to providers.
    /// Disabled by default for secure-by-default behavior.
    allow_remote_fetch: bool = false,
    /// Directories from which local image reads are allowed.
    /// If empty, all local file reads are rejected (only URLs pass through).
    allowed_dirs: []const []const u8 = &.{},
};

pub const default_config = MultimodalConfig{};

// ════════════════════════════════════════════════════════════════════════════
// Image Marker Parsing
// ════════════════════════════════════════════════════════════════════════════

pub const ParseResult = struct {
    cleaned_text: []const u8,
    refs: []const []const u8,
};

/// Scan content for `[IMAGE:...]` markers. Returns the cleaned text (markers
/// removed) and an array of image references (file paths or URLs).
/// Refs are sub-slices of the original content parameter, not independently allocated.
pub fn parseImageMarkers(allocator: std.mem.Allocator, content: []const u8) !ParseResult {
    var refs: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer refs.deinit(allocator);

    var remaining: std.ArrayListUnmanaged(u8) = .empty;
    errdefer remaining.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < content.len) {
        const open_pos = std.mem.indexOfPos(u8, content, cursor, "[") orelse {
            try remaining.appendSlice(allocator, content[cursor..]);
            break;
        };

        try remaining.appendSlice(allocator, content[cursor..open_pos]);

        const close_pos = std.mem.indexOfPos(u8, content, open_pos, "]") orelse {
            try remaining.appendSlice(allocator, content[open_pos..]);
            break;
        };

        const marker = content[open_pos + 1 .. close_pos];

        if (std.mem.indexOf(u8, marker, ":")) |colon_pos| {
            const kind_str = marker[0..colon_pos];
            const target_raw = marker[colon_pos + 1 ..];
            const target = std.mem.trim(u8, target_raw, " ");

            if (target.len > 0 and isImageKind(kind_str)) {
                try refs.append(allocator, target);
                cursor = close_pos + 1;
                continue;
            }
        }

        // Not a valid [IMAGE:] marker — keep original text
        try remaining.appendSlice(allocator, content[open_pos .. close_pos + 1]);
        cursor = close_pos + 1;
    }

    const trimmed = std.mem.trim(u8, remaining.items, " \t\n\r");
    const cleaned = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(cleaned);
    remaining.deinit(allocator);

    return .{
        .cleaned_text = cleaned,
        .refs = try refs.toOwnedSlice(allocator),
    };
}

fn isImageKind(kind_str: []const u8) bool {
    return eqlLower(kind_str, "image") or eqlLower(kind_str, "photo") or eqlLower(kind_str, "img");
}

fn eqlLower(a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != bc) return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// MIME Type Detection
// ════════════════════════════════════════════════════════════════════════════

/// Detect MIME type from the first bytes of a file (magic byte sniffing).
pub fn detectMimeType(header: []const u8) ?[]const u8 {
    if (header.len < 4) return null;

    // PNG: 89 50 4E 47
    if (header[0] == 0x89 and header[1] == 'P' and header[2] == 'N' and header[3] == 'G')
        return "image/png";

    // JPEG: FF D8 FF
    if (header[0] == 0xFF and header[1] == 0xD8 and header[2] == 0xFF)
        return "image/jpeg";

    // GIF: GIF8
    if (header[0] == 'G' and header[1] == 'I' and header[2] == 'F' and header[3] == '8')
        return "image/gif";

    // BMP: BM
    if (header[0] == 'B' and header[1] == 'M')
        return "image/bmp";

    // WebP: RIFF....WEBP
    if (header.len >= 12 and
        header[0] == 'R' and header[1] == 'I' and header[2] == 'F' and header[3] == 'F' and
        header[8] == 'W' and header[9] == 'E' and header[10] == 'B' and header[11] == 'P')
        return "image/webp";

    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Local Image Reading
// ════════════════════════════════════════════════════════════════════════════

pub const ImageData = struct {
    data: []const u8,
    mime_type: []const u8,
};

pub const DataUriImage = struct {
    data: []const u8,
    mime_type: []const u8,
};

/// Read a local image file, validate its size, and detect MIME type.
/// Returns raw bytes and MIME type. Caller owns the returned `data` slice.
/// Path is validated against `allowed_dirs` to prevent arbitrary file reads.
pub fn readLocalImage(allocator: std.mem.Allocator, path: []const u8, config: MultimodalConfig) !ImageData {
    // Resolve to absolute path (realpathAlloc resolves ".." and symlinks)
    const resolved = if (std.fs.path.isAbsolute(path))
        std.fs.realpathAlloc(allocator, path) catch return error.PathNotFound
    else blk: {
        break :blk std.fs.cwd().realpathAlloc(allocator, path) catch return error.PathNotFound;
    };
    defer allocator.free(resolved);

    // Verify the resolved path is within an allowed directory
    if (config.allowed_dirs.len == 0) return error.LocalReadNotAllowed;
    const allowed = blk: {
        for (config.allowed_dirs) |dir| {
            const trimmed = std.mem.trimRight(u8, dir, "/\\");
            if (trimmed.len == 0) continue;
            if (path_security.pathStartsWith(resolved, trimmed)) break :blk true;

            // Compare against canonicalized allowed dir too (/var -> /private/var on macOS).
            const canonical = std.fs.realpathAlloc(allocator, trimmed) catch continue;
            defer allocator.free(canonical);
            if (path_security.pathStartsWith(resolved, canonical)) break :blk true;
        }
        break :blk false;
    };
    if (!allowed) return error.PathNotAllowed;

    const file = std.fs.openFileAbsolute(resolved, .{}) catch return error.PathNotFound;
    return readFromFile(allocator, file, config.max_image_size_bytes);
}

fn readFromFile(allocator: std.mem.Allocator, file: std.fs.File, max_size: u64) !ImageData {
    defer file.close();

    const stat = try file.stat();
    if (stat.size > max_size)
        return error.ImageTooLarge;

    const data = try file.readToEndAlloc(allocator, max_size);
    errdefer allocator.free(data);

    const mime = detectMimeType(data) orelse return error.UnknownImageFormat;

    return .{ .data = data, .mime_type = mime };
}

// ════════════════════════════════════════════════════════════════════════════
// Base64 Encoding
// ════════════════════════════════════════════════════════════════════════════

/// Base64-encode raw bytes. Caller owns the returned slice.
pub fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(buf, data);
    return buf;
}

fn isAllowedMimeType(mime: []const u8) bool {
    return std.ascii.eqlIgnoreCase(mime, "image/png") or
        std.ascii.eqlIgnoreCase(mime, "image/jpeg") or
        std.ascii.eqlIgnoreCase(mime, "image/webp") or
        std.ascii.eqlIgnoreCase(mime, "image/gif") or
        std.ascii.eqlIgnoreCase(mime, "image/bmp");
}

/// Parse and validate a data URI image marker.
/// Returns the base64 payload and MIME type as borrowed slices of `source`.
fn parseDataUriImage(source: []const u8, max_size_bytes: u64) !DataUriImage {
    if (!std.mem.startsWith(u8, source, "data:")) return error.InvalidDataUri;
    const comma = std.mem.indexOfScalar(u8, source, ',') orelse return error.InvalidDataUri;

    const meta = source["data:".len..comma];
    const payload = std.mem.trim(u8, source[comma + 1 ..], " \t\r\n");
    if (payload.len == 0) return error.InvalidDataUri;

    var meta_it = std.mem.splitScalar(u8, meta, ';');
    const mime = std.mem.trim(u8, meta_it.next() orelse "", " \t");
    if (mime.len == 0 or !isAllowedMimeType(mime)) return error.UnknownImageFormat;

    var has_base64 = false;
    while (meta_it.next()) |token| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "base64")) {
            has_base64 = true;
            break;
        }
    }
    if (!has_base64) return error.InvalidDataUri;

    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(payload) catch return error.InvalidDataUri;
    if (decoded_size > max_size_bytes) return error.ImageTooLarge;

    return .{
        .data = payload,
        .mime_type = mime,
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Message Preparation for Providers
// ════════════════════════════════════════════════════════════════════════════

/// Process messages for multimodal content: scan user messages for [IMAGE:]
/// markers, read local files, base64-encode, and build content_parts.
///
/// All allocations happen on the arena (freed after the provider call).
/// Messages without markers pass through unchanged.
pub fn prepareMessagesForProvider(
    arena: std.mem.Allocator,
    messages: []ChatMessage,
    config: MultimodalConfig,
) ![]ChatMessage {
    const result = try arena.alloc(ChatMessage, messages.len);

    // Only process the last user message — earlier images are already consumed
    // and their temp files may be gone. This avoids re-encoding on every iteration.
    var last_user_idx: ?usize = null;
    for (0..messages.len) |j| {
        const idx = messages.len - 1 - j;
        if (messages[idx].role == .user) {
            last_user_idx = idx;
            break;
        }
    }

    for (messages, 0..) |msg, i| {
        if (msg.role != .user or msg.content.len == 0 or i != (last_user_idx orelse messages.len)) {
            result[i] = msg;
            continue;
        }

        // Quick check: scan for '[' followed by case-insensitive image keyword and ':'
        const has_marker = blk: {
            var pos: usize = 0;
            while (pos < msg.content.len) : (pos += 1) {
                if (msg.content[pos] == '[') {
                    const rest = msg.content[pos + 1 ..];
                    if (rest.len >= 6 and rest[5] == ':' and eqlLower(rest[0..5], "image")) break :blk true;
                    if (rest.len >= 6 and rest[5] == ':' and eqlLower(rest[0..5], "photo")) break :blk true;
                    if (rest.len >= 4 and rest[3] == ':' and eqlLower(rest[0..3], "img")) break :blk true;
                }
            }
            break :blk false;
        };
        if (!has_marker) {
            result[i] = msg;
            continue;
        }

        const parsed = try parseImageMarkers(arena, msg.content);

        if (parsed.refs.len == 0) {
            result[i] = msg;
            continue;
        }

        // Build content_parts: text part + image parts
        var parts: std.ArrayListUnmanaged(ContentPart) = .empty;

        if (parsed.cleaned_text.len > 0) {
            try parts.append(arena, .{ .text = parsed.cleaned_text });
        }

        const max_images = @min(parsed.refs.len, config.max_images);
        if (parsed.refs.len > max_images) {
            const dropped = parsed.refs.len - max_images;
            const note = try std.fmt.allocPrint(
                arena,
                "[Only {d} image(s) were processed (max_images={d}); {d} additional image(s) ignored]",
                .{ max_images, config.max_images, dropped },
            );
            try parts.append(arena, .{ .text = note });
        }

        for (parsed.refs[0..max_images]) |ref| {
            // Truncated ref for error messages (avoid leaking huge data URIs)
            const display_ref = if (ref.len > 80) ref[0..80] else ref;

            if (isDataUrl(ref)) {
                const data_uri = parseDataUriImage(ref, config.max_image_size_bytes) catch |err| {
                    log.warn("failed to parse data URI image: {}", .{err});
                    const note = try std.fmt.allocPrint(arena, "[Failed to load image: {s}...]", .{display_ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                };
                try parts.append(arena, .{ .image_base64 = .{
                    .data = data_uri.data,
                    .media_type = data_uri.mime_type,
                } });
            } else if (isHttpUrl(ref) or isHttpsUrl(ref)) {
                if (!config.allow_remote_fetch) {
                    const note = try std.fmt.allocPrint(arena, "[Remote image URLs are disabled: {s}]", .{display_ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                }
                if (!isHttpsUrl(ref)) {
                    const note = try std.fmt.allocPrint(arena, "[Remote image URL must use HTTPS: {s}]", .{display_ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                }
                try parts.append(arena, .{ .image_url = .{ .url = ref } });
            } else {
                // Local file — read + base64 encode
                const img = readLocalImage(arena, ref, config) catch |err| {
                    log.warn("failed to read image '{s}': {}", .{ ref, err });
                    const note = try std.fmt.allocPrint(arena, "[Failed to load image: {s}]", .{display_ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                };
                const b64 = encodeBase64(arena, img.data) catch {
                    const note = try std.fmt.allocPrint(arena, "[Failed to encode image: {s}]", .{display_ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                };
                try parts.append(arena, .{ .image_base64 = .{
                    .data = b64,
                    .media_type = img.mime_type,
                } });
            }
        }

        result[i] = .{
            .role = msg.role,
            .content = if (parsed.cleaned_text.len > 0) parsed.cleaned_text else msg.content,
            .name = msg.name,
            .tool_call_id = msg.tool_call_id,
            .content_parts = try parts.toOwnedSlice(arena),
        };
    }

    return result;
}

/// Count image markers across user messages.
pub fn countImageMarkers(messages: []const ChatMessage) usize {
    var total: usize = 0;
    for (messages) |msg| {
        if (msg.role != .user or msg.content.len == 0) continue;
        total += countImageMarkersInText(msg.content);
    }
    return total;
}

/// Count image markers in the most recent user message only.
pub fn countImageMarkersInLastUser(messages: []const ChatMessage) usize {
    var i = messages.len;
    while (i > 0) : (i -= 1) {
        const idx = i - 1;
        const msg = messages[idx];
        if (msg.role != .user or msg.content.len == 0) continue;
        return countImageMarkersInText(msg.content);
    }
    return 0;
}

fn countImageMarkersInText(content: []const u8) usize {
    var count: usize = 0;
    var cursor: usize = 0;
    while (cursor < content.len) {
        const open_pos = std.mem.indexOfPos(u8, content, cursor, "[") orelse break;
        const close_pos = std.mem.indexOfPos(u8, content, open_pos, "]") orelse break;
        const marker = content[open_pos + 1 .. close_pos];
        if (std.mem.indexOf(u8, marker, ":")) |colon_pos| {
            const kind_str = marker[0..colon_pos];
            const target = std.mem.trim(u8, marker[colon_pos + 1 ..], " ");
            if (target.len > 0 and isImageKind(kind_str)) {
                count += 1;
            }
        }
        cursor = close_pos + 1;
    }
    return count;
}

/// Returns true if the string looks like a URL.
pub fn isUrl(s: []const u8) bool {
    return isHttpUrl(s) or isHttpsUrl(s) or isDataUrl(s);
}

fn isHttpUrl(s: []const u8) bool {
    if (s.len < 7) return false;
    return std.ascii.eqlIgnoreCase(s[0..7], "http://");
}

fn isHttpsUrl(s: []const u8) bool {
    if (s.len < 8) return false;
    return std.ascii.eqlIgnoreCase(s[0..8], "https://");
}

fn isDataUrl(s: []const u8) bool {
    if (s.len < 5) return false;
    return std.ascii.eqlIgnoreCase(s[0..5], "data:");
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseImageMarkers single marker" {
    const parsed = try parseImageMarkers(std.testing.allocator, "Look at this [IMAGE:/tmp/photo.png] please");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
    try std.testing.expectEqualStrings("/tmp/photo.png", parsed.refs[0]);
    try std.testing.expectEqualStrings("Look at this  please", parsed.cleaned_text);
}

test "parseImageMarkers multiple markers" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:/a.png] text [IMAGE:/b.jpg]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 2), parsed.refs.len);
    try std.testing.expectEqualStrings("/a.png", parsed.refs[0]);
    try std.testing.expectEqualStrings("/b.jpg", parsed.refs[1]);
    try std.testing.expectEqualStrings("text", parsed.cleaned_text);
}

test "parseImageMarkers no markers" {
    const parsed = try parseImageMarkers(std.testing.allocator, "No images here!");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("No images here!", parsed.cleaned_text);
}

test "parseImageMarkers empty text" {
    const parsed = try parseImageMarkers(std.testing.allocator, "");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("", parsed.cleaned_text);
}

test "parseImageMarkers case insensitive" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[image:/a.png] [Image:/b.png] [PHOTO:/c.png]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 3), parsed.refs.len);
}

test "parseImageMarkers invalid marker kept" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[UNKNOWN:/a.bin]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("[UNKNOWN:/a.bin]", parsed.cleaned_text);
}

test "parseImageMarkers empty target ignored" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("[IMAGE:]", parsed.cleaned_text);
}

test "parseImageMarkers unclosed bracket" {
    const parsed = try parseImageMarkers(std.testing.allocator, "text [IMAGE:/a.png");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("text [IMAGE:/a.png", parsed.cleaned_text);
}

test "parseImageMarkers URL target" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:https://example.com/cat.jpg]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", parsed.refs[0]);
}

test "parseImageMarkers IMG alias" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMG:/tmp/a.png]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
}

test "detectMimeType PNG" {
    const header = [_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    try std.testing.expectEqualStrings("image/png", detectMimeType(&header).?);
}

test "detectMimeType JPEG" {
    const header = [_]u8{ 0xFF, 0xD8, 0xFF, 0xE0 };
    try std.testing.expectEqualStrings("image/jpeg", detectMimeType(&header).?);
}

test "detectMimeType GIF" {
    const header = [_]u8{ 'G', 'I', 'F', '8', '9', 'a' };
    try std.testing.expectEqualStrings("image/gif", detectMimeType(&header).?);
}

test "detectMimeType BMP" {
    const header = [_]u8{ 'B', 'M', 0x00, 0x00 };
    try std.testing.expectEqualStrings("image/bmp", detectMimeType(&header).?);
}

test "detectMimeType WebP" {
    const header = [_]u8{ 'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P' };
    try std.testing.expectEqualStrings("image/webp", detectMimeType(&header).?);
}

test "detectMimeType unknown" {
    const header = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expect(detectMimeType(&header) == null);
}

test "detectMimeType too short" {
    const header = [_]u8{ 0x89, 'P' };
    try std.testing.expect(detectMimeType(&header) == null);
}

test "encodeBase64 simple" {
    const encoded = try encodeBase64(std.testing.allocator, "Hello");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("SGVsbG8=", encoded);
}

test "encodeBase64 empty" {
    const encoded = try encodeBase64(std.testing.allocator, "");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("", encoded);
}

test "encodeBase64 binary data" {
    const data = [_]u8{ 0x89, 0x50, 0x4E, 0x47 };
    const encoded = try encodeBase64(std.testing.allocator, &data);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("iVBORw==", encoded);
}

test "isUrl http" {
    try std.testing.expect(isUrl("http://example.com/a.png"));
}

test "isUrl https" {
    try std.testing.expect(isUrl("https://example.com/a.png"));
}

test "isUrl data" {
    try std.testing.expect(isUrl("data:image/png;base64,iVBOR"));
}

test "isUrl local path" {
    try std.testing.expect(!isUrl("/tmp/photo.png"));
}

test "isUrl relative path" {
    try std.testing.expect(!isUrl("photos/cat.jpg"));
}

test "MultimodalConfig defaults" {
    const cfg = MultimodalConfig{};
    try std.testing.expectEqual(@as(u32, 4), cfg.max_images);
    try std.testing.expectEqual(@as(u64, 5_242_880), cfg.max_image_size_bytes);
}

test "prepareMessagesForProvider no markers passes through" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.user("Hello, no images"),
        ChatMessage.assistant("Hi there"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    try std.testing.expectEqual(@as(usize, 3), result.len);
    // All should pass through unchanged
    try std.testing.expect(result[0].content_parts == null);
    try std.testing.expect(result[1].content_parts == null);
    try std.testing.expect(result[2].content_parts == null);
}

test "prepareMessagesForProvider with URL marker creates content_parts" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Check this [IMAGE:https://example.com/cat.jpg] out"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expect(result[0].content_parts != null);
    const parts = result[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 2), parts.len);
    // First part: text
    try std.testing.expect(parts[0] == .text);
    try std.testing.expectEqualStrings("Check this  out", parts[0].text);
    // Second part: explicit policy note (remote URLs disabled by default)
    try std.testing.expect(parts[1] == .text);
    try std.testing.expect(std.mem.indexOf(u8, parts[1].text, "Remote image URLs are disabled") != null);
}

test "prepareMessagesForProvider with URL marker allowed by config" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Check this [IMAGE:https://example.com/cat.jpg] out"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{ .allow_remote_fetch = true });
    const parts = result[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 2), parts.len);
    try std.testing.expect(parts[1] == .image_url);
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", parts[1].image_url.url);
}

test "prepareMessagesForProvider adds note when markers exceed max_images" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Compare [IMAGE:https://example.com/a.jpg] [IMAGE:https://example.com/b.jpg]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{
        .allow_remote_fetch = true,
        .max_images = 1,
    });
    const parts = result[0].content_parts.?;

    var saw_limit_note = false;
    var saw_image = false;
    for (parts) |part| {
        switch (part) {
            .text => |text| {
                if (std.mem.indexOf(u8, text, "additional image(s) ignored") != null) {
                    saw_limit_note = true;
                }
            },
            .image_url => saw_image = true,
            else => {},
        }
    }
    try std.testing.expect(saw_image);
    try std.testing.expect(saw_limit_note);
}

test "prepareMessagesForProvider with data URI marker creates base64 image part" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Analyze [IMAGE:data:image/png;base64,iVBORw0KGgo=]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    const parts = result[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 2), parts.len);
    try std.testing.expect(parts[1] == .image_base64);
    try std.testing.expectEqualStrings("image/png", parts[1].image_base64.media_type);
    try std.testing.expectEqualStrings("iVBORw0KGgo=", parts[1].image_base64.data);
}

test "prepareMessagesForProvider skips assistant messages" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.assistant("Here is [IMAGE:/tmp/a.png]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    try std.testing.expect(result[0].content_parts == null);
}

test "readLocalImage rejects path traversal via allowed_dirs" {
    // On Unix: realpathAlloc resolves ".." -> path doesn't match empty allowed_dirs -> LocalReadNotAllowed
    // On Windows: /tmp doesn't exist -> realpathAlloc fails -> PathNotFound
    if (readLocalImage(std.testing.allocator, "/tmp/../etc/passwd", .{})) |_| {
        @panic("expected readLocalImage to fail for traversal path");
    } else |err| {
        try std.testing.expect(err == error.LocalReadNotAllowed or err == error.PathNotFound);
    }
}

test "readLocalImage rejects when no allowed_dirs" {
    // Create a real temp file so realpath succeeds, then verify allowed_dirs rejection
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.png", .data = "\x89PNG\x0d\x0a\x1a\x0a" });
    const dir_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const file_path = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "test.png" });
    defer std.testing.allocator.free(file_path);

    const err = readLocalImage(std.testing.allocator, file_path, .{});
    try std.testing.expectError(error.LocalReadNotAllowed, err);
}

test "prepareMessagesForProvider does not delete nullclaw temp image files" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{
        .sub_path = "nullclaw_photo_123.png",
        .data = "\x89PNG\x0d\x0a\x1a\x0a",
    });

    const dir_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const file_path = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "nullclaw_photo_123.png" });
    defer std.testing.allocator.free(file_path);

    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user(try std.fmt.allocPrint(std.testing.allocator, "[IMAGE:{s}]", .{file_path})),
    };
    defer std.testing.allocator.free(msgs[0].content);

    _ = try prepareMessagesForProvider(arena, &msgs, .{
        .allowed_dirs = &.{dir_path},
    });

    try std.fs.accessAbsolute(file_path, .{});
}

test "parseImageMarkers mixed case markers" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[ImAgE:/a.png] [pHoTo:/b.jpg] [iMg:/c.gif]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 3), parsed.refs.len);
    try std.testing.expectEqualStrings("/a.png", parsed.refs[0]);
    try std.testing.expectEqualStrings("/b.jpg", parsed.refs[1]);
    try std.testing.expectEqualStrings("/c.gif", parsed.refs[2]);
}

test "prepareMessagesForProvider only processes last user message" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Look [IMAGE:https://example.com/old.jpg]"),
        ChatMessage.assistant("I see the old image"),
        ChatMessage.user("Now see [IMAGE:https://example.com/new.jpg]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    try std.testing.expectEqual(@as(usize, 3), result.len);
    // First user message should NOT be processed (not the last)
    try std.testing.expect(result[0].content_parts == null);
    // Assistant passes through
    try std.testing.expect(result[1].content_parts == null);
    // Last user message should be processed
    try std.testing.expect(result[2].content_parts != null);
}

test "quick-check handles mixed case IMAGE markers" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("[ImAgE:https://example.com/cat.jpg]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs, .{});
    try std.testing.expect(result[0].content_parts != null);
}

test "MultimodalConfig allowed_dirs defaults empty" {
    const cfg = MultimodalConfig{};
    try std.testing.expectEqual(@as(usize, 0), cfg.allowed_dirs.len);
}

test "countImageMarkers counts user image markers only" {
    const msgs = [_]ChatMessage{
        ChatMessage.user("One [IMAGE:/tmp/a.png]"),
        ChatMessage.assistant("[IMAGE:/tmp/ignored.png]"),
        ChatMessage.user("Two [PHOTO:/tmp/b.png] [IMG:/tmp/c.png]"),
    };
    try std.testing.expectEqual(@as(usize, 3), countImageMarkers(&msgs));
}

test "countImageMarkersInLastUser only counts latest user message" {
    const msgs = [_]ChatMessage{
        ChatMessage.user("Old [IMAGE:/tmp/old.png]"),
        ChatMessage.assistant("ack"),
        ChatMessage.user("No image here"),
    };
    try std.testing.expectEqual(@as(usize, 0), countImageMarkersInLastUser(&msgs));
}
