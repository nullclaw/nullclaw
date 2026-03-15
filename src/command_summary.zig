const std = @import("std");

pub const Summary = struct {
    head: []const u8,
    byte_len: usize,
    assignment_count: usize,
};

pub fn summarizeBlockedCommand(command: []const u8) Summary {
    const trimmed = normalizeCommand(command);
    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t\r\n");
    var assignment_count: usize = 0;

    while (tokens.next()) |token| {
        if (isEnvAssignmentToken(token)) {
            assignment_count += 1;
            continue;
        }

        return .{
            .head = displayToken(token),
            .byte_len = trimmed.len,
            .assignment_count = assignment_count,
        };
    }

    return .{
        .head = if (assignment_count > 0) "<env-only>" else "<empty>",
        .byte_len = trimmed.len,
        .assignment_count = assignment_count,
    };
}

fn normalizeCommand(command: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (unwrapMarkdownFence(trimmed)) |unfenced| {
        return std.mem.trim(u8, unfenced, " \t\r\n");
    }
    return trimmed;
}

fn unwrapMarkdownFence(command: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, command, "```")) return null;
    const after_open = command[3..];
    const close_idx = std.mem.lastIndexOf(u8, after_open, "```") orelse return null;
    const trailing = std.mem.trim(u8, after_open[close_idx + 3 ..], " \t\r\n");
    if (trailing.len != 0) return null;

    const fenced_body = after_open[0..close_idx];
    const content = if (std.mem.indexOfScalar(u8, fenced_body, '\n')) |first_newline|
        fenced_body[first_newline + 1 ..]
    else
        fenced_body;
    const trimmed_content = std.mem.trim(u8, content, " \t\r\n");
    if (trimmed_content.len == 0) return null;
    return trimmed_content;
}

fn isEnvAssignmentToken(token: []const u8) bool {
    const eq_idx = std.mem.indexOfScalar(u8, token, '=') orelse return false;
    const name = token[0..eq_idx];
    if (name.len == 0) return false;
    if (!(std.ascii.isAlphabetic(name[0]) or name[0] == '_')) return false;

    for (name[1..]) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return false;
    }
    return true;
}

fn basenameToken(token: []const u8) []const u8 {
    var start: usize = 0;
    if (std.mem.lastIndexOfScalar(u8, token, '/')) |idx| {
        start = idx + 1;
    }
    if (std.mem.lastIndexOfScalar(u8, token, '\\')) |idx| {
        start = @max(start, idx + 1);
    }
    return token[start..];
}

fn safeDisplayLen(token: []const u8) usize {
    const MAX_LEN = 48;
    var i: usize = 0;
    while (i < token.len and i < MAX_LEN) : (i += 1) {
        const ch = token[i];
        if (!(std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '_' or ch == '-' or ch == '+')) break;
    }
    return i;
}

fn displayToken(token: []const u8) []const u8 {
    const base = std.mem.trim(u8, basenameToken(token), "\"'`");
    if (base.len == 0) return "<special>";

    const safe_len = safeDisplayLen(base);
    if (safe_len == 0) return "<special>";
    return base[0..safe_len];
}

test "summarizeBlockedCommand skips env assignment values" {
    const summary = summarizeBlockedCommand("OPENAI_API_KEY=sk-secret-123 curl https://example.com");
    try std.testing.expectEqualStrings("curl", summary.head);
    try std.testing.expectEqual(@as(usize, 1), summary.assignment_count);
    try std.testing.expect(summary.byte_len > "curl".len);
}

test "summarizeBlockedCommand unwraps fenced command" {
    const summary = summarizeBlockedCommand(
        \\```bash
        \\curl https://example.com
        \\```
    );
    try std.testing.expectEqualStrings("curl", summary.head);
}

test "summarizeBlockedCommand uses executable basename" {
    const summary = summarizeBlockedCommand("/usr/local/bin/python3 script.py");
    try std.testing.expectEqualStrings("python3", summary.head);
    try std.testing.expectEqual(@as(usize, 0), summary.assignment_count);
}

test "summarizeBlockedCommand reports env-only command safely" {
    const summary = summarizeBlockedCommand("FOO=bar BAR=baz");
    try std.testing.expectEqualStrings("<env-only>", summary.head);
    try std.testing.expectEqual(@as(usize, 2), summary.assignment_count);
}
