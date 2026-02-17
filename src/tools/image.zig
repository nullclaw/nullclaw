const std = @import("std");
const builtin = @import("builtin");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Maximum image file size (5MB).
const MAX_IMAGE_BYTES: u64 = 5_242_880;

/// Tool to read image metadata (format, dimensions, size).
pub const ImageInfoTool = struct {
    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ImageInfoTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ImageInfoTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "image_info";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Read image file metadata (format, dimensions, size).";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"path":{"type":"string","description":"Path to the image file"},"include_base64":{"type":"boolean","description":"Include base64-encoded data (default: false)"}},"required":["path"]}
        ;
    }

    fn execute(_: *ImageInfoTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const path = parseStringField(args_json, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        // Open and read file
        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
            // Try as relative path
            const f = std.fs.cwd().openFile(path, .{}) catch {
                const msg = try std.fmt.allocPrint(allocator, "File not found: {s} ({s})", .{ path, @errorName(err) });
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            return executeWithFile(f, allocator, path);
        };
        return executeWithFile(file, allocator, path);
    }

    fn executeWithFile(file: std.fs.File, allocator: std.mem.Allocator, path: []const u8) !ToolResult {
        defer file.close();

        const stat = try file.stat();
        if (stat.size > MAX_IMAGE_BYTES) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Image too large: {d} bytes (max {d} bytes)",
                .{ stat.size, MAX_IMAGE_BYTES },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        // Read enough for format detection and dimensions
        var header: [128]u8 = undefined;
        const bytes_read = try file.read(&header);
        const bytes = header[0..bytes_read];

        const format = detectFormat(bytes);
        const dimensions = extractDimensions(bytes, format);

        var buf: [512]u8 = undefined;
        var len: usize = 0;
        const prefix = std.fmt.bufPrint(buf[0..], "File: {s}\nFormat: {s}\nSize: {d} bytes", .{ path, format, stat.size }) catch return error.OutOfMemory;
        len = prefix.len;

        if (dimensions) |dims| {
            const dim_str = std.fmt.bufPrint(buf[len..], "\nDimensions: {d}x{d}", .{ dims[0], dims[1] }) catch return error.OutOfMemory;
            len += dim_str.len;
        }

        const output = try allocator.dupe(u8, buf[0..len]);
        return ToolResult{ .success = true, .output = output };
    }
};

/// Detect image format from magic bytes.
pub fn detectFormat(bytes: []const u8) []const u8 {
    if (bytes.len < 4) return "unknown";
    if (bytes[0] == 0x89 and bytes[1] == 'P' and bytes[2] == 'N' and bytes[3] == 'G') return "png";
    if (bytes[0] == 0xFF and bytes[1] == 0xD8 and bytes[2] == 0xFF) return "jpeg";
    if (bytes[0] == 'G' and bytes[1] == 'I' and bytes[2] == 'F' and bytes[3] == '8') return "gif";
    if (bytes[0] == 'R' and bytes[1] == 'I' and bytes[2] == 'F' and bytes[3] == 'F') {
        if (bytes.len >= 12 and bytes[8] == 'W' and bytes[9] == 'E' and bytes[10] == 'B' and bytes[11] == 'P') return "webp";
    }
    if (bytes[0] == 'B' and bytes[1] == 'M') return "bmp";
    return "unknown";
}

/// Extract image dimensions from header bytes.
pub fn extractDimensions(bytes: []const u8, format: []const u8) ?[2]u32 {
    if (std.mem.eql(u8, format, "png")) {
        if (bytes.len >= 24) {
            const w = std.mem.readInt(u32, bytes[16..20], .big);
            const h = std.mem.readInt(u32, bytes[20..24], .big);
            return .{ w, h };
        }
    }
    if (std.mem.eql(u8, format, "gif")) {
        if (bytes.len >= 10) {
            const w: u32 = std.mem.readInt(u16, bytes[6..8], .little);
            const h: u32 = std.mem.readInt(u16, bytes[8..10], .little);
            return .{ w, h };
        }
    }
    if (std.mem.eql(u8, format, "bmp")) {
        if (bytes.len >= 26) {
            const w = std.mem.readInt(u32, bytes[18..22], .little);
            const h_raw = std.mem.readInt(i32, bytes[22..26], .little);
            const h: u32 = @intCast(if (h_raw < 0) -h_raw else h_raw);
            return .{ w, h };
        }
    }
    if (std.mem.eql(u8, format, "jpeg")) {
        return jpegDimensions(bytes);
    }
    return null;
}

/// Parse JPEG SOF markers to extract dimensions.
fn jpegDimensions(bytes: []const u8) ?[2]u32 {
    var i: usize = 2; // skip SOI marker
    while (i + 1 < bytes.len) {
        if (bytes[i] != 0xFF) return null;
        const marker = bytes[i + 1];
        i += 2;

        // SOF0..SOF3
        if (marker >= 0xC0 and marker <= 0xC3) {
            if (i + 7 <= bytes.len) {
                const h: u32 = std.mem.readInt(u16, bytes[i + 3 ..][0..2], .big);
                const w: u32 = std.mem.readInt(u16, bytes[i + 5 ..][0..2], .big);
                return .{ w, h };
            }
            return null;
        }

        // Skip segment
        if (i + 1 < bytes.len) {
            const seg_len: usize = std.mem.readInt(u16, bytes[i..][0..2], .big);
            if (seg_len < 2) return null; // malformed
            i += seg_len;
        } else {
            return null;
        }
    }
    return null;
}

/// Screenshot tool — captures screenshots using platform-native commands.
pub const ScreenshotTool = struct {
    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ScreenshotTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ScreenshotTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "screenshot";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Capture a screenshot of the current screen.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"filename":{"type":"string","description":"Optional filename"},"region":{"type":"string","description":"Region: 'selection' or 'window' (macOS only)"}}}
        ;
    }

    fn execute(_: *ScreenshotTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        _ = args_json;
        const output_path = "/tmp/nullclaw_screenshot.png";

        const argv: []const []const u8 = switch (comptime builtin.os.tag) {
            .macos => &.{ "screencapture", "-x", output_path },
            .linux => &.{ "import", "-window", "root", output_path },
            else => return ToolResult.fail("Screenshot not supported on this platform"),
        };

        var child = std.process.Child.init(argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            return ToolResult.fail("Failed to spawn screenshot command");
        };

        const stderr = child.stderr.?.readToEndAlloc(allocator, 1_048_576) catch "";
        defer if (stderr.len > 0) allocator.free(stderr);

        const term = child.wait() catch {
            return ToolResult.fail("Failed to wait for screenshot command");
        };

        if (term.Exited == 0) {
            const msg = try std.fmt.allocPrint(allocator, "Screenshot saved to: {s}", .{output_path});
            return ToolResult{ .success = true, .output = msg };
        } else {
            const err_msg = try std.fmt.allocPrint(allocator, "Screenshot command failed: {s}", .{if (stderr.len > 0) stderr else "unknown error"});
            return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "image_info tool name" {
    var it = ImageInfoTool{};
    const t = it.tool();
    try std.testing.expectEqualStrings("image_info", t.name());
}

test "image_info description not empty" {
    var it = ImageInfoTool{};
    const t = it.tool();
    try std.testing.expect(t.description().len > 0);
}

test "image_info schema has path" {
    var it = ImageInfoTool{};
    const t = it.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "path") != null);
}

test "screenshot tool name" {
    var st = ScreenshotTool{};
    const t = st.tool();
    try std.testing.expectEqualStrings("screenshot", t.name());
}

test "screenshot description not empty" {
    var st = ScreenshotTool{};
    const t = st.tool();
    try std.testing.expect(t.description().len > 0);
}

// ── Format detection tests ──────────────────────────────────────────

test "detect PNG" {
    const bytes = &[_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    try std.testing.expectEqualStrings("png", detectFormat(bytes));
}

test "detect JPEG" {
    const bytes = &[_]u8{ 0xFF, 0xD8, 0xFF, 0xE0 };
    try std.testing.expectEqualStrings("jpeg", detectFormat(bytes));
}

test "detect GIF" {
    const bytes = "GIF89a";
    try std.testing.expectEqualStrings("gif", detectFormat(bytes));
}

test "detect BMP" {
    const bytes = &[_]u8{ 'B', 'M', 0x00, 0x00 };
    try std.testing.expectEqualStrings("bmp", detectFormat(bytes));
}

test "detect WEBP" {
    const bytes = &[_]u8{ 'R', 'I', 'F', 'F', 0x00, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P' };
    try std.testing.expectEqualStrings("webp", detectFormat(bytes));
}

test "detect unknown short" {
    try std.testing.expectEqualStrings("unknown", detectFormat(&[_]u8{ 0x00, 0x01 }));
}

test "detect unknown garbage" {
    try std.testing.expectEqualStrings("unknown", detectFormat("this is not an image"));
}

// ── Dimension extraction tests ──────────────────────────────────────

test "PNG dimensions" {
    var bytes = [_]u8{
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
        0x00, 0x00, 0x00, 0x0D, // IHDR length
        0x49, 0x48, 0x44, 0x52, // "IHDR"
        0x00, 0x00, 0x03, 0x20, // width: 800
        0x00, 0x00, 0x02, 0x58, // height: 600
    } ++ [_]u8{0} ** 10;
    const dims = extractDimensions(&bytes, "png");
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u32, 800), dims.?[0]);
    try std.testing.expectEqual(@as(u32, 600), dims.?[1]);
}

test "GIF dimensions" {
    const bytes = [_]u8{
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
        0x40, 0x01, // width: 320 (LE)
        0xF0, 0x00, // height: 240 (LE)
    };
    const dims = extractDimensions(&bytes, "gif");
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u32, 320), dims.?[0]);
    try std.testing.expectEqual(@as(u32, 240), dims.?[1]);
}

test "BMP dimensions" {
    var bytes = [_]u8{0} ** 26;
    bytes[0] = 'B';
    bytes[1] = 'M';
    bytes[18] = 0x00;
    bytes[19] = 0x04; // width: 1024 (LE)
    bytes[20] = 0x00;
    bytes[21] = 0x00;
    bytes[22] = 0x00;
    bytes[23] = 0x03; // height: 768 (LE)
    bytes[24] = 0x00;
    bytes[25] = 0x00;
    const dims = extractDimensions(&bytes, "bmp");
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u32, 1024), dims.?[0]);
    try std.testing.expectEqual(@as(u32, 768), dims.?[1]);
}

test "JPEG dimensions" {
    var bytes = [_]u8{
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, // APP0 marker
        0x00, 0x10, // APP0 length = 16
    } ++ [_]u8{0} ** 14 ++ [_]u8{
        0xFF, 0xC0, // SOF0 marker
        0x00, 0x11, // SOF0 length
        0x08, // precision
        0x01, 0xE0, // height: 480
        0x02, 0x80, // width: 640
    };
    const dims = extractDimensions(&bytes, "jpeg");
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u32, 640), dims.?[0]);
    try std.testing.expectEqual(@as(u32, 480), dims.?[1]);
}

test "JPEG malformed zero-length segment" {
    const bytes = [_]u8{
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, // APP0 marker
        0x00, 0x00, // length = 0 (malformed)
    };
    const dims = extractDimensions(&bytes, "jpeg");
    try std.testing.expect(dims == null);
}

test "unknown format no dimensions" {
    try std.testing.expect(extractDimensions("random data here", "unknown") == null);
}

// ── Additional format detection tests ───────────────────────────

test "detect empty bytes" {
    try std.testing.expectEqualStrings("unknown", detectFormat(&[_]u8{}));
}

test "detect single byte" {
    try std.testing.expectEqualStrings("unknown", detectFormat(&[_]u8{0x89}));
}

test "detect three bytes" {
    try std.testing.expectEqualStrings("unknown", detectFormat(&[_]u8{ 0x89, 'P', 'N' }));
}

test "detect RIFF without WEBP" {
    const bytes = &[_]u8{ 'R', 'I', 'F', 'F', 0x00, 0x00, 0x00, 0x00, 'A', 'V', 'I', ' ' };
    try std.testing.expectEqualStrings("unknown", detectFormat(bytes));
}

test "detect JPEG with different APP marker" {
    // JPEG with APP1 (EXIF) marker instead of APP0
    const bytes = &[_]u8{ 0xFF, 0xD8, 0xFF, 0xE1 };
    try std.testing.expectEqualStrings("jpeg", detectFormat(bytes));
}

test "detect GIF87a variant" {
    const bytes = "GIF87a";
    try std.testing.expectEqualStrings("gif", detectFormat(bytes));
}

test "detect TIFF not supported returns unknown" {
    // TIFF little-endian
    const bytes = &[_]u8{ 'I', 'I', 0x2A, 0x00 };
    try std.testing.expectEqualStrings("unknown", detectFormat(bytes));
}

// ── Additional dimension extraction tests ───────────────────────

test "PNG dimensions insufficient bytes" {
    const bytes = [_]u8{
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    }; // Only 16 bytes, need 24
    try std.testing.expect(extractDimensions(&bytes, "png") == null);
}

test "GIF dimensions insufficient bytes" {
    const bytes = [_]u8{ 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 }; // Only header, no dims
    try std.testing.expect(extractDimensions(&bytes, "gif") == null);
}

test "BMP dimensions insufficient bytes" {
    var bytes = [_]u8{0} ** 20;
    bytes[0] = 'B';
    bytes[1] = 'M';
    try std.testing.expect(extractDimensions(&bytes, "bmp") == null);
}

test "BMP negative height" {
    // BMP with negative height (top-down bitmap)
    var bytes = [_]u8{0} ** 26;
    bytes[0] = 'B';
    bytes[1] = 'M';
    bytes[18] = 0x20; // width: 32 (LE)
    bytes[19] = 0x00;
    bytes[20] = 0x00;
    bytes[21] = 0x00;
    // height: -16 in i32 LE = 0xFFFFFFF0
    bytes[22] = 0xF0;
    bytes[23] = 0xFF;
    bytes[24] = 0xFF;
    bytes[25] = 0xFF;
    const dims = extractDimensions(&bytes, "bmp");
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u32, 32), dims.?[0]);
    try std.testing.expectEqual(@as(u32, 16), dims.?[1]);
}

test "WEBP no dimensions" {
    // WEBP format detection works but dimension extraction not implemented
    const bytes = &[_]u8{ 'R', 'I', 'F', 'F', 0x00, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P' };
    try std.testing.expect(extractDimensions(bytes, "webp") == null);
}

test "JPEG no SOF marker returns null" {
    // JPEG with only APP0 segment and no SOF marker
    const bytes = [_]u8{
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, // APP0 marker
        0x00, 0x04, // APP0 length = 4
        0x00, 0x00, // padding
    };
    const dims = extractDimensions(&bytes, "jpeg");
    try std.testing.expect(dims == null);
}

test "JPEG non-FF byte returns null" {
    // After SOI, encounter non-marker byte
    const bytes = [_]u8{
        0xFF, 0xD8, // SOI
        0x00, 0xE0, // Invalid: should start with 0xFF
    };
    const dims = extractDimensions(&bytes, "jpeg");
    try std.testing.expect(dims == null);
}

test "image_info schema has include_base64" {
    var it = ImageInfoTool{};
    const t = it.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "include_base64") != null);
}

test "image_info description mentions metadata" {
    var it = ImageInfoTool{};
    const t = it.tool();
    const desc = t.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "metadata") != null or std.mem.indexOf(u8, desc, "format") != null);
}
