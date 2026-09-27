//! Compress verbose tool output before it is appended to conversation history.

const std = @import("std");
const util = @import("../util.zig");

pub const DEFAULT_MAX_RESULT_CHARS: u32 = 8192;
pub const DEFAULT_MAX_RESULT_TAIL_LINES: u32 = 12;
pub const LOCAL_LOOP_MAX_RESULT_CHARS: u32 = 400;

pub const CompressOptions = struct {
    max_chars: u32 = DEFAULT_MAX_RESULT_CHARS,
    max_tail_lines: u32 = DEFAULT_MAX_RESULT_TAIL_LINES,
    is_error: bool = false,
};

const ERROR_MARKERS = [_][]const u8{
    "error:",
    "failed:",
    "traceback (most recent call last)",
    "assertionerror",
    "exception:",
};

/// Shrink tool output for history injection. Returns an owned slice.
pub fn compressToolOutput(allocator: std.mem.Allocator, raw: []const u8, opts: CompressOptions) ![]const u8 {
    const normalized = std.mem.trim(u8, raw, " \t\r\n");
    if (normalized.len == 0) return try allocator.dupe(u8, "");

    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer parts.deinit(allocator);

    if (opts.is_error) {
        if (extractErrorSignature(normalized)) |sig| {
            try parts.append(allocator, sig);
        }
    }

    const tail = try extractTail(allocator, normalized, opts.max_tail_lines);
    defer allocator.free(tail);
    if (tail.len > 0) {
        try parts.append(allocator, tail);
    }

    const joined = try std.mem.join(allocator, "\n", parts.items);
    defer allocator.free(joined);

    if (joined.len <= opts.max_chars) {
        return try allocator.dupe(u8, joined);
    }

    const clipped = util.truncateUtf8(joined, opts.max_chars);
    const suffix = "\n… [truncated]";
    if (clipped.len + suffix.len <= opts.max_chars) {
        return try std.fmt.allocPrint(allocator, "{s}{s}", .{ clipped, suffix });
    }
    const body_len = opts.max_chars -| suffix.len;
    const body = util.truncateUtf8(clipped, body_len);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ body, suffix });
}

fn extractTail(allocator: std.mem.Allocator, text: []const u8, max_lines: u32) ![]const u8 {
    var lines: std.ArrayListUnmanaged([]const u8) = .empty;
    defer lines.deinit(allocator);

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        try lines.append(allocator, trimmed);
    }

    if (lines.items.len <= max_lines) {
        return try std.mem.join(allocator, "\n", lines.items);
    }

    const omitted = lines.items.len - max_lines;
    const slice = lines.items[lines.items.len - max_lines ..];
    const joined = try std.mem.join(allocator, "\n", slice);
    defer allocator.free(joined);
    return try std.fmt.allocPrint(allocator, "… [omitted {d} lines]\n{s}", .{ omitted, joined });
}

fn extractErrorSignature(text: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const lower_buf = stackLowerAscii(trimmed);
        for (ERROR_MARKERS) |marker| {
            if (std.mem.indexOf(u8, lower_buf, marker) != null) {
                const cap = @min(trimmed.len, 180);
                return trimmed[0..cap];
            }
        }
    }
    return null;
}

fn stackLowerAscii(input: []const u8) []const u8 {
    const cap = @min(input.len, 256);
    var buf: [256]u8 = undefined;
    for (input[0..cap], 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..cap];
}

test "compressToolOutput empty input returns empty string" {
    const out = try compressToolOutput(std.testing.allocator, "", .{});
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "compressToolOutput keeps short output unchanged" {
    const out = try compressToolOutput(std.testing.allocator, "line one\nline two", .{});
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("line one\nline two", out);
}

test "compressToolOutput keeps last tail lines and omits earlier lines" {
    const raw =
        \\line 0
        \\line 1
        \\line 2
        \\line 3
        \\line 4
        \\line 5
        \\line 6
        \\line 7
        \\line 8
        \\line 9
        \\line 10
        \\line 11
        \\line 12
        \\line 13
        \\line 14
        \\line 15
        \\line 16
        \\line 17
        \\line 18
        \\line 19
    ;
    const out = try compressToolOutput(std.testing.allocator, raw, .{
        .max_tail_lines = 3,
        .max_chars = 8192,
    });
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "… [omitted") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "line 19") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "line 0") == null);
}

test "compressToolOutput prepends error signature for failed tools" {
    const raw =
        \\ignored header
        \\Traceback (most recent call last):
        \\  File "x.py", line 1
        \\AssertionError: boom
    ;
    const out = try compressToolOutput(std.testing.allocator, raw, .{
        .is_error = true,
        .max_tail_lines = 2,
        .max_chars = 8192,
    });
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "Traceback") != null);
}

test "compressToolOutput hard caps at max_chars with truncated marker" {
    const raw = "x" ** 10_000;
    const out = try compressToolOutput(std.testing.allocator, raw, .{
        .max_chars = 400,
        .max_tail_lines = 12,
    });
    defer std.testing.allocator.free(out);
    try std.testing.expect(out.len <= 400);
    try std.testing.expect(std.mem.indexOf(u8, out, "… [truncated]") != null);
    try std.testing.expect(std.unicode.utf8ValidateSlice(out));
}
