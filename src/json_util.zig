//! Shared JSON string utilities (RFC 8259).
//!
//! Replaces 10+ local `appendJsonString` duplicates across the codebase.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Append a JSON-escaped string (with enclosing quotes) to the buffer.
/// Handles: `"`, `\`, `\n`, `\r`, `\t`, control chars < 0x20 → `\u00XX`.
pub fn appendJsonString(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, s: []const u8) !void {
    try buf.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var escape_buf: [6]u8 = undefined;
                    const escape = std.fmt.bufPrint(&escape_buf, "\\u{x:0>4}", .{c}) catch unreachable;
                    try buf.appendSlice(allocator, escape);
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
    try buf.append(allocator, '"');
}

/// Append `"key":` (JSON-escaped key with colon) to the buffer.
pub fn appendJsonKey(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, key: []const u8) !void {
    try appendJsonString(buf, allocator, key);
    try buf.append(allocator, ':');
}

/// Append `"key":"value"` (both JSON-escaped) to the buffer.
pub fn appendJsonKeyValue(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, key: []const u8, value: []const u8) !void {
    try appendJsonKey(buf, allocator, key);
    try appendJsonString(buf, allocator, value);
}

/// Append `"key":123` (JSON-escaped key, integer value) to the buffer.
pub fn appendJsonInt(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, key: []const u8, value: i64) !void {
    try appendJsonKey(buf, allocator, key);
    var int_buf: [24]u8 = undefined;
    const int_str = std.fmt.bufPrint(&int_buf, "{d}", .{value}) catch unreachable;
    try buf.appendSlice(allocator, int_str);
}

/// Attempt to repair common JSON issues from LLM output.
/// Handles: trailing commas, unbalanced braces/brackets, unbalanced quotes.
///
/// Shared by the agent's tool-call parser (`dispatcher.parseToolCallJson`) and
/// the streaming/batch tool-markup predicates (`providers.helpers`), so a text
/// tool call the agent would execute is recognised by the very same repair.
pub fn repairJson(allocator: Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Step 1: Copy input, fixing trailing commas and control chars in strings
    var in_string = false;
    var escaped = false;
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (escaped) {
            try buf.append(allocator, c);
            escaped = false;
            continue;
        }
        if (in_string) {
            if (c == '\\') {
                escaped = true;
                try buf.append(allocator, c);
            } else if (c == '"') {
                in_string = false;
                try buf.append(allocator, c);
            } else if (c == '\n') {
                try buf.appendSlice(allocator, "\\n");
            } else if (c == '\r') {
                try buf.appendSlice(allocator, "\\r");
            } else if (c == '\t') {
                try buf.appendSlice(allocator, "\\t");
            } else {
                try buf.append(allocator, c);
            }
        } else {
            if (c == '"') {
                in_string = true;
                try buf.append(allocator, c);
            } else if (c == ',') {
                // Check if next non-whitespace is } or ] (trailing comma)
                var j = i + 1;
                while (j < input.len and (input[j] == ' ' or input[j] == '\n' or input[j] == '\r' or input[j] == '\t')) j += 1;
                if (j < input.len and (input[j] == '}' or input[j] == ']')) {
                    // Skip trailing comma
                } else {
                    try buf.append(allocator, c);
                }
            } else {
                try buf.append(allocator, c);
            }
        }
    }

    // Step 2: Balance quotes (if odd number of unescaped quotes, add closing quote)
    var quote_count: usize = 0;
    var esc2 = false;
    for (buf.items) |c| {
        if (esc2) {
            esc2 = false;
            continue;
        }
        if (c == '\\') {
            esc2 = true;
            continue;
        }
        if (c == '"') quote_count += 1;
    }
    if (quote_count % 2 != 0) {
        try buf.append(allocator, '"');
    }

    // Step 3: Balance braces and brackets
    var brace_depth: i32 = 0;
    var bracket_depth: i32 = 0;
    var in_str = false;
    var esc3 = false;
    for (buf.items) |c| {
        if (esc3) {
            esc3 = false;
            continue;
        }
        if (c == '\\' and in_str) {
            esc3 = true;
            continue;
        }
        if (c == '"') in_str = !in_str;
        if (!in_str) {
            if (c == '{') brace_depth += 1;
            if (c == '}') brace_depth -= 1;
            if (c == '[') bracket_depth += 1;
            if (c == ']') bracket_depth -= 1;
        }
    }
    while (bracket_depth > 0) : (bracket_depth -= 1) {
        try buf.append(allocator, ']');
    }
    while (brace_depth > 0) : (brace_depth -= 1) {
        try buf.append(allocator, '}');
    }

    return try buf.toOwnedSlice(allocator);
}

/// Find the first JSON object `{...}` (or array `[...]`) in a string,
/// handling nesting and string escapes. Shared by the agent's tool-call parser
/// (`dispatcher.parseInnerToolCall`) and the display's fallback-close predicate
/// (`providers.helpers`), so a text tool call the agent would execute is found
/// by exactly the same scan.
pub fn extractJsonObject(input: []const u8) ?[]const u8 {
    // Strip markdown fences if present
    var trimmed = input;
    if (std.mem.indexOf(u8, trimmed, "```")) |fence_start| {
        // Skip to end of first line (after ```json or ```)
        const after_fence = trimmed[fence_start + 3 ..];
        if (std.mem.indexOfScalar(u8, after_fence, '\n')) |nl| {
            trimmed = after_fence[nl + 1 ..];
        }
        // Strip closing fence
        if (std.mem.lastIndexOf(u8, trimmed, "```")) |close| {
            trimmed = trimmed[0..close];
        }
    }

    // Find first '{' or '[' — support both objects and arrays
    const obj_pos = std.mem.indexOfScalar(u8, trimmed, '{');
    const arr_pos = std.mem.indexOfScalar(u8, trimmed, '[');

    const start_info: struct { pos: usize, open: u8, close: u8 } = blk: {
        if (obj_pos) |op| {
            if (arr_pos) |ap| {
                // Both found — pick whichever comes first
                if (ap < op) break :blk .{ .pos = ap, .open = '[', .close = ']' };
                break :blk .{ .pos = op, .open = '{', .close = '}' };
            }
            break :blk .{ .pos = op, .open = '{', .close = '}' };
        }
        if (arr_pos) |ap| break :blk .{ .pos = ap, .open = '[', .close = ']' };
        return null;
    };

    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    var i: usize = start_info.pos;
    while (i < trimmed.len) : (i += 1) {
        const c = trimmed[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escaped = true;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        if (!in_string) {
            if (c == start_info.open) depth += 1;
            if (c == start_info.close) {
                if (depth > 0) depth -= 1;
                if (depth == 0) return trimmed[start_info.pos .. i + 1];
            }
        }
    }

    return null;
}

// ── Tests ───────────────────────────────────────────────────────────

test "repairJson removes trailing commas" {
    const result = try repairJson(std.testing.allocator, "{\"key\": \"value\",}");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("{\"key\": \"value\"}", result);
}

test "repairJson balances unclosed braces and quotes" {
    const result = try repairJson(std.testing.allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls}");
    defer std.testing.allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
}

test "appendJsonString empty string" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "");
    try std.testing.expectEqualStrings("\"\"", buf.items);
}

test "appendJsonString plain ASCII" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "hello world");
    try std.testing.expectEqualStrings("\"hello world\"", buf.items);
}

test "appendJsonString escapes quotes" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "say \"hi\"");
    try std.testing.expectEqualStrings("\"say \\\"hi\\\"\"", buf.items);
}

test "appendJsonString escapes backslash" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "a\\b");
    try std.testing.expectEqualStrings("\"a\\\\b\"", buf.items);
}

test "appendJsonString escapes tabs and newlines" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "a\tb\nc\r");
    try std.testing.expectEqualStrings("\"a\\tb\\nc\\r\"", buf.items);
}

test "appendJsonString escapes control chars" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, &[_]u8{0x01});
    try std.testing.expectEqualStrings("\"\\u0001\"", buf.items);
}

test "appendJsonString preserves Unicode" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonString(&buf, std.testing.allocator, "Héllo 🌍");
    try std.testing.expectEqualStrings("\"Héllo 🌍\"", buf.items);
}

test "appendJsonKeyValue" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonKeyValue(&buf, std.testing.allocator, "name", "Alice \"A\"");
    try std.testing.expectEqualStrings("\"name\":\"Alice \\\"A\\\"\"", buf.items);
}

test "appendJsonInt" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonInt(&buf, std.testing.allocator, "count", 42);
    try std.testing.expectEqualStrings("\"count\":42", buf.items);
}

test "appendJsonInt negative" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonInt(&buf, std.testing.allocator, "delta", -7);
    try std.testing.expectEqualStrings("\"delta\":-7", buf.items);
}
