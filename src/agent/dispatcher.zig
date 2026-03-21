const std = @import("std");
const providers = @import("../providers/root.zig");

// ═══════════════════════════════════════════════════════════════════════════
// Dispatcher — tool call parsing and result formatting
// ═══════════════════════════════════════════════════════════════════════════

/// A parsed tool call extracted from an LLM response.
pub const ParsedToolCall = struct {
    name: []const u8,
    /// Raw JSON arguments string.
    arguments_json: []const u8,
    /// Optional tool_call_id for native tool-calling APIs.
    tool_call_id: ?[]const u8 = null,
};

/// Result of parsing tool calls from an LLM response: text content and extracted calls.
pub const ParseResult = struct {
    text: []const u8,
    calls: []ParsedToolCall,
};

fn stripDelimitedBlocks(
    allocator: std.mem.Allocator,
    input: []const u8,
    open_prefix: []const u8,
    close_tag: []const u8,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var remaining = input;
    while (std.mem.indexOf(u8, remaining, open_prefix)) |open_idx| {
        try out.appendSlice(allocator, remaining[0..open_idx]);
        const after_open = remaining[open_idx..];
        const open_end_rel = std.mem.indexOfScalar(u8, after_open, '>') orelse {
            remaining = remaining[0..open_idx];
            break;
        };
        const content_start = open_idx + open_end_rel + 1;
        const after_content = remaining[content_start..];
        const close_rel = std.mem.indexOf(u8, after_content, close_tag) orelse {
            remaining = remaining[0..open_idx];
            break;
        };
        remaining = after_content[close_rel + close_tag.len ..];
    }

    try out.appendSlice(allocator, remaining);
    return try out.toOwnedSlice(allocator);
}

pub fn stripToolResultMarkup(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const xml_stripped = try stripDelimitedBlocks(allocator, input, "<tool_result", "</tool_result>");
    defer allocator.free(xml_stripped);

    const bracket_stripped = try stripDelimitedBlocks(allocator, xml_stripped, "[tool_result", "[/tool_result]");
    return bracket_stripped;
}

/// Result of executing a single tool.
pub const ToolExecutionResult = struct {
    name: []const u8,
    output: []const u8,
    success: bool,
    tool_call_id: ?[]const u8 = null,
};

/// Parse tool calls from an LLM response.
///
/// Two parsing paths (matching ZeroClaw's Rust implementation):
/// 1. First, try parsing as OpenAI native JSON format `{"tool_calls": [...]}`
/// 2. Fall back to XML `<tool_call>` tag parsing
///
/// Returns text portions (joined by newline) and extracted tool calls.
pub fn parseToolCalls(
    allocator: std.mem.Allocator,
    response: []const u8,
) !ParseResult {
    // First: try OpenAI native JSON format {"tool_calls": [...]}
    if (isNativeJsonFormat(response)) {
        const native = parseNativeToolCalls(allocator, response) catch null;
        if (native) |result| {
            if (result.calls.len > 0) return result;
            // No calls found in native format — free and fall through to XML
            allocator.free(result.text);
            allocator.free(result.calls);
        }
    }
    // Second: fall back to XML <tool_call> tag parsing
    return parseXmlToolCalls(allocator, response);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Detect whether the response contains explicit tool-call markup tags.
/// Used by the agent loop to avoid leaking raw tool XML-like payloads to users
/// when parsing fails on malformed inner content.
pub fn containsToolCallMarkup(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "<tool_call>") != null or
        std.mem.indexOf(u8, text, "</tool_call>") != null or
        std.mem.indexOf(u8, text, "[TOOL_CALL]") != null or
        std.mem.indexOf(u8, text, "[tool_call]") != null or
        std.mem.indexOf(u8, text, "[/TOOL_CALL]") != null or
        std.mem.indexOf(u8, text, "[/tool_call]") != null;
}

/// Parse tool calls from an LLM response using XML-style `<tool_call>` tags.
///
/// Expected format:
/// ```
/// Some text
/// <tool_call>
/// {"name": "shell", "arguments": {"command": "ls"}}
/// </tool_call>
/// More text
/// ```
///
/// Returns text portions (joined by newline) and extracted tool calls.
///
/// SECURITY: This function only extracts JSON from within explicit `<tool_call>` tags.
/// It does NOT parse raw JSON from the response body, which prevents prompt injection
/// where malicious content could include JSON mimicking a tool call.
pub fn parseXmlToolCalls(
    allocator: std.mem.Allocator,
    response: []const u8,
) !ParseResult {
    var text_parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer text_parts.deinit(allocator);

    var calls: std.ArrayListUnmanaged(ParsedToolCall) = .empty;
    errdefer {
        for (calls.items) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        calls.deinit(allocator);
    }

    var remaining = response;

    while (true) {
        // Find next tool call marker: either <tool_call> or [TOOL_CALL] or [tool_call]
        const marker_info: ?struct { start: usize, end: usize, open_char: u8, close_char: u8 } = blk: {
            const xml_start = std.mem.indexOf(u8, remaining, "<tool_call>");
            const br_start_upper = std.mem.indexOf(u8, remaining, "[TOOL_CALL]");
            const br_start_lower = std.mem.indexOf(u8, remaining, "[tool_call]");

            var best_start: ?usize = null;
            var open_c: u8 = '<';
            var close_c: u8 = '>';
            const marker_len: usize = 11;

            if (xml_start) |s| {
                best_start = s;
            }
            if (br_start_upper) |s| {
                if (best_start == null or s < best_start.?) {
                    best_start = s;
                    open_c = '[';
                    close_c = ']';
                }
            }
            if (br_start_lower) |s| {
                if (best_start == null or s < best_start.?) {
                    best_start = s;
                    open_c = '[';
                    close_c = ']';
                }
            }

            if (best_start) |s| {
                break :blk .{ .start = s, .end = s + marker_len, .open_char = open_c, .close_char = close_c };
            }
            break :blk null;
        };

        if (marker_info == null) break;
        const info = marker_info.?;
        const start = info.start;

        const after_open = remaining[info.end..];
        // Flexible closing tag:
        // 1) Prefer tags whose name contains "tool_call"
        // 2) Fallback to the first closing tag (handles malformed outputs like </arg_value>)
        var strict_end: ?usize = null;
        var strict_end_tag_len: usize = 0;
        var fallback_first_end: ?usize = null;
        var fallback_first_end_tag_len: usize = 0;
        var fallback_last_end: ?usize = null;
        var fallback_last_end_tag_len: usize = 0;
        var search_idx: usize = 0;
        while (search_idx < after_open.len) {
            const next_open = std.mem.indexOfScalar(u8, after_open[search_idx..], info.open_char) orelse break;
            const abs_open = search_idx + next_open;
            if (abs_open + 1 < after_open.len and after_open[abs_open + 1] == '/') {
                if (std.mem.indexOfScalar(u8, after_open[abs_open..], info.close_char)) |rel_close| {
                    const abs_close = abs_open + rel_close;
                    const tag_content = after_open[abs_open + 2 .. abs_close];
                    if (fallback_first_end == null) {
                        fallback_first_end = abs_open;
                        fallback_first_end_tag_len = rel_close + 1;
                    }
                    fallback_last_end = abs_open;
                    fallback_last_end_tag_len = rel_close + 1;
                    if (containsIgnoreCase(tag_content, "tool_call")) {
                        strict_end = abs_open;
                        strict_end_tag_len = rel_close + 1;
                        break;
                    }
                    search_idx = abs_close + 1;
                } else {
                    break;
                }
            } else {
                search_idx = abs_open + 1;
            }
        }

        const found_end = strict_end orelse fallback_first_end;
        var end_tag_len = if (strict_end != null) strict_end_tag_len else fallback_first_end_tag_len;

        if (found_end) |end| {
            // Text before the tag
            const before = std.mem.trim(u8, remaining[0..start], " \t\r\n");
            if (before.len > 0) {
                try text_parts.append(allocator, before);
            }

            var selected_end = end;
            var parsed_call: ?ParsedToolCall = null;

            // If we only have malformed close-tags (no strict </tool_call>),
            // prefer the last close-tag first. This avoids truncating when JSON
            // arguments contain an early `</...>` string (e.g. HTML content).
            if (strict_end == null) {
                if (fallback_last_end) |last_end| {
                    if (last_end != selected_end) {
                        const last_inner = std.mem.trim(u8, after_open[0..last_end], " \t\r\n");
                        parsed_call = try parseInnerToolCall(allocator, last_inner);
                        if (parsed_call != null) {
                            selected_end = last_end;
                            end_tag_len = fallback_last_end_tag_len;
                        }
                    }
                }
            }

            if (parsed_call == null) {
                const inner = std.mem.trim(u8, after_open[0..selected_end], " \t\r\n");
                parsed_call = try parseInnerToolCall(allocator, inner);
            }

            if (parsed_call) |call| {
                try calls.append(allocator, call);
            }

            remaining = after_open[selected_end + end_tag_len ..];
        } else {
            // Unclosed tag — attempt conservative recovery for compact calls emitted at
            // end-of-message (e.g. <tool_call>memory_list{"limit":10}).
            const inner_unclosed = std.mem.trim(u8, after_open, " \t\r\n");
            var recovered = false;

            if (inner_unclosed.len > 0) {
                if (inner_unclosed[0] == '{' and inner_unclosed[inner_unclosed.len - 1] == '}') {
                    if (parseToolCallJson(allocator, inner_unclosed)) |call| {
                        const before = std.mem.trim(u8, remaining[0..start], " \t\r\n");
                        if (before.len > 0) try text_parts.append(allocator, before);
                        try calls.append(allocator, call);
                        recovered = true;
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {},
                    }
                }

                if (!recovered) {
                    if (parseNamePrefixedJsonCall(allocator, inner_unclosed)) |call| {
                        const before = std.mem.trim(u8, remaining[0..start], " \t\r\n");
                        if (before.len > 0) try text_parts.append(allocator, before);
                        try calls.append(allocator, call);
                        recovered = true;
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {},
                    }
                }
            }

            if (!recovered) {
                const unresolved = std.mem.trim(u8, remaining, " \t\r\n");
                if (unresolved.len > 0) {
                    try text_parts.append(allocator, unresolved);
                }
            }

            remaining = "";
            break;
        }
    }

    // Remaining text after last tool call
    const trailing = std.mem.trim(u8, remaining, " \t\r\n");
    if (trailing.len > 0) {
        try text_parts.append(allocator, trailing);
    }

    // Join text parts
    var text = if (text_parts.items.len == 0)
        try allocator.dupe(u8, "")
    else
        try std.mem.join(allocator, "\n", text_parts.items);
    errdefer allocator.free(text);

    if (calls.items.len > 0) {
        const sanitized_text = try stripToolResultMarkup(allocator, text);
        allocator.free(text);
        text = sanitized_text;
    }

    return .{
        .text = text,
        .calls = try calls.toOwnedSlice(allocator),
    };
}

/// Format tool execution results as XML for the next LLM turn.
pub fn formatToolResults(allocator: std.mem.Allocator, results: []const ToolExecutionResult) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[Tool results]\n");
    for (results) |result| {
        const status_str = if (result.success) "ok" else "error";
        try std.fmt.format(buf.writer(allocator), "<tool_result name=\"{s}\" status=\"{s}\">\n{s}\n</tool_result>\n", .{
            result.name,
            status_str,
            result.output,
        });
    }

    return try buf.toOwnedSlice(allocator);
}

// ═══════════════════════════════════════════════════════════════════════════
// Structured Tool Call Conversion
// ═══════════════════════════════════════════════════════════════════════════

const ToolCall = providers.ToolCall;

/// Convert structured tool calls from a ChatResponse (provider-native format)
/// into ParsedToolCall slices for the agent loop.
///
/// This bridges the provider's `ToolCall` type (id, name, arguments) to the
/// dispatcher's `ParsedToolCall` type used for tool execution.
pub fn parseStructuredToolCalls(
    allocator: std.mem.Allocator,
    tool_calls: []const ToolCall,
) ![]ParsedToolCall {
    var calls: std.ArrayListUnmanaged(ParsedToolCall) = .empty;
    errdefer {
        for (calls.items) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        calls.deinit(allocator);
    }

    for (tool_calls) |tc| {
        if (tc.name.len == 0) continue;

        try calls.append(allocator, .{
            .name = try allocator.dupe(u8, tc.name),
            .arguments_json = try allocator.dupe(u8, tc.arguments),
            .tool_call_id = if (tc.id.len > 0) try allocator.dupe(u8, tc.id) else null,
        });
    }

    return try calls.toOwnedSlice(allocator);
}

// ═══════════════════════════════════════════════════════════════════════════
// Native Tool Dispatcher — OpenAI-format tool_calls support
// ═══════════════════════════════════════════════════════════════════════════

/// Dispatcher format kind.
pub const DispatcherKind = enum {
    xml,
    native,
};

/// Quick check whether a response string looks like OpenAI native JSON format.
/// Returns true if the text starts with `{` (after trimming whitespace) and contains `"tool_calls"`.
/// This is a lightweight heuristic — full JSON parsing happens in parseNativeToolCalls.
pub fn isNativeJsonFormat(text: []const u8) bool {
    const trimmed = std.mem.trimLeft(u8, text, " \n\r\t");
    if (trimmed.len == 0 or trimmed[0] != '{') return false;
    return std.mem.indexOf(u8, trimmed, "\"tool_calls\"") != null;
}

/// Detect whether a response string is in OpenAI native tool-call format.
/// Looks for the `"tool_calls"` key inside a top-level JSON object.
pub fn isNativeFormat(allocator: std.mem.Allocator, response: []const u8) bool {
    // Quick heuristic: must contain "tool_calls" substring
    if (std.mem.indexOf(u8, response, "\"tool_calls\"") == null) return false;

    // Validate it's inside a parseable JSON object
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch return false;
    defer parsed.deinit();

    return switch (parsed.value) {
        .object => |obj| obj.get("tool_calls") != null,
        else => false,
    };
}

/// A single tool call in the OpenAI native format (within the `tool_calls` array).
const NativeToolCall = struct {
    id: []const u8,
    type: []const u8,
    function: struct {
        name: []const u8,
        arguments: []const u8,
    },
};

/// Parse tool calls from an OpenAI-format JSON response.
///
/// Expected input format (the full response JSON, or just the message object):
/// ```json
/// {
///   "content": "Some text",
///   "tool_calls": [
///     {
///       "id": "call_abc123",
///       "type": "function",
///       "function": {
///         "name": "shell",
///         "arguments": "{\"command\": \"ls -la\"}"
///       }
///     }
///   ]
/// }
/// ```
///
/// Returns text content and extracted tool calls (same shape as XML parser).
pub fn parseNativeToolCalls(
    allocator: std.mem.Allocator,
    response: []const u8,
) !ParseResult {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidNativeFormat,
    };

    // Extract text content
    const text = if (obj.get("content")) |content_val| switch (content_val) {
        .string => |s| try allocator.dupe(u8, s),
        .null => try allocator.dupe(u8, ""),
        else => try allocator.dupe(u8, ""),
    } else try allocator.dupe(u8, "");

    // Extract tool_calls array
    const tool_calls_val = obj.get("tool_calls") orelse return .{
        .text = text,
        .calls = try allocator.alloc(ParsedToolCall, 0),
    };

    const tool_calls_arr = switch (tool_calls_val) {
        .array => |a| a,
        else => return .{
            .text = text,
            .calls = try allocator.alloc(ParsedToolCall, 0),
        },
    };

    var calls: std.ArrayListUnmanaged(ParsedToolCall) = .empty;
    errdefer {
        for (calls.items) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        calls.deinit(allocator);
    }

    for (tool_calls_arr.items) |tc_val| {
        const tc_obj = switch (tc_val) {
            .object => |o| o,
            else => continue,
        };

        // Extract the function object
        const func_val = tc_obj.get("function") orelse continue;
        const func_obj = switch (func_val) {
            .object => |o| o,
            else => continue,
        };

        // Extract function name
        const name_val = func_obj.get("name") orelse continue;
        const name_str = switch (name_val) {
            .string => |s| s,
            else => continue,
        };
        if (name_str.len == 0) continue;

        // Extract arguments (string)
        const args_str = if (func_obj.get("arguments")) |args_val| switch (args_val) {
            .string => |s| s,
            else => "{}",
        } else "{}";

        // Extract tool call id
        const tc_id = if (tc_obj.get("id")) |id_val| switch (id_val) {
            .string => |s| s,
            else => null,
        } else null;

        try calls.append(allocator, .{
            .name = try allocator.dupe(u8, name_str),
            .arguments_json = try allocator.dupe(u8, args_str),
            .tool_call_id = if (tc_id) |id| try allocator.dupe(u8, id) else null,
        });
    }

    return .{
        .text = text,
        .calls = try calls.toOwnedSlice(allocator),
    };
}

/// Format tool execution results as OpenAI-format JSON for the next API call.
///
/// Produces an array of tool result messages:
/// ```json
/// [
///   {"role": "tool", "tool_call_id": "call_abc123", "content": "output here"}
/// ]
/// ```
pub fn formatNativeToolResults(allocator: std.mem.Allocator, results: []const ToolExecutionResult) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("[");
    for (results, 0..) |result, i| {
        if (i > 0) try w.writeAll(",");
        const tc_id = result.tool_call_id orelse "unknown";

        // Serialize content as a JSON string value
        try std.fmt.format(w, "{{\"role\":\"tool\",\"tool_call_id\":{f},\"content\":{f}}}", .{
            std.json.fmt(tc_id, .{}),
            std.json.fmt(result.output, .{}),
        });
    }
    try w.writeAll("]");

    return try buf.toOwnedSlice(allocator);
}

// ═══════════════════════════════════════════════════════════════════════════
// Assistant History Builder
// ═══════════════════════════════════════════════════════════════════════════

/// Build an assistant history entry that includes serialized tool calls as XML.
///
/// When the provider returns structured tool_calls, we serialize them as
/// `<tool_call>` XML tags so the conversation history stays in a canonical
/// format regardless of whether tools came from native API or XML parsing.
///
/// Mirrors ZeroClaw's `build_assistant_history_with_tool_calls`.
pub fn buildAssistantHistoryWithToolCalls(
    allocator: std.mem.Allocator,
    response_text: []const u8,
    parsed_calls: []const ParsedToolCall,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    if (response_text.len > 0) {
        try w.writeAll(response_text);
        try w.writeByte('\n');
    }

    for (parsed_calls) |call| {
        try w.writeAll("<tool_call>\n");
        const name_json = try std.json.Stringify.valueAlloc(allocator, call.name, .{});
        defer allocator.free(name_json);
        try w.writeAll("{\"name\": ");
        try w.writeAll(name_json);
        try w.writeAll(", \"arguments\": ");
        try w.writeAll(call.arguments_json);
        try w.writeByte('}');
        try w.writeAll("\n</tool_call>\n");
    }

    return buf.toOwnedSlice(allocator);
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Strip trailing XML tags (e.g. </arg_value>, </tool_call>) from a string.
fn stripTrailingXml(input: []const u8) []const u8 {
    const trimmed_right = std.mem.trimRight(u8, input, " \t\r\n");
    if (trimmed_right.len == 0 or trimmed_right[trimmed_right.len - 1] != '>') return input;

    const end_tag = trimmed_right.len - 1;
    const start_tag = std.mem.lastIndexOfScalar(u8, trimmed_right[0..end_tag], '<') orelse return input;
    if (start_tag + 1 >= trimmed_right.len) return input;

    const tag_head = trimmed_right[start_tag + 1];
    const looks_like_tag = (tag_head == '/') or
        (tag_head >= 'a' and tag_head <= 'z') or
        (tag_head >= 'A' and tag_head <= 'Z');
    if (!looks_like_tag) return input;

    const tag_body = trimmed_right[start_tag + 1 .. end_tag];
    if (std.mem.indexOfScalar(u8, tag_body, '"') != null or std.mem.indexOfScalar(u8, tag_body, '\'') != null) {
        return input;
    }

    // Found what looks like a trailing tag <...> at end-of-string.
    return std.mem.trimRight(u8, trimmed_right[0..start_tag], " \t\r\n");
}

fn isToolNameChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => true,
        else => false,
    };
}

fn isPlausibleToolName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (!isToolNameChar(c)) return false;
    }
    return true;
}

fn hasMalformedQuotedColonToolName(raw_json: []const u8) bool {
    const name_key = "\"name\"";
    const name_idx = std.mem.indexOf(u8, raw_json, name_key) orelse return false;

    var remaining = std.mem.trimLeft(u8, raw_json[name_idx + name_key.len ..], " \t\r\n");
    if (remaining.len == 0 or remaining[0] != ':') return false;

    remaining = std.mem.trimLeft(u8, remaining[1..], " \t\r\n");
    if (remaining.len < 2 or remaining[0] != '"') return false;

    remaining = remaining[1..];
    if (remaining.len == 0 or remaining[0] != ':') return false;

    remaining = std.mem.trimLeft(u8, remaining[1..], " \t\r\n");
    return remaining.len > 0 and remaining[0] == '"';
}

fn recoverToolNameFromRawJson(raw_json: []const u8) ?[]const u8 {
    const name_key = "\"name\"";
    const arguments_key = "\"arguments\"";

    const name_idx = std.mem.indexOf(u8, raw_json, name_key) orelse return null;
    const after_name = raw_json[name_idx + name_key.len ..];
    const colon_idx = std.mem.indexOfScalar(u8, after_name, ':') orelse return null;
    const after_colon = after_name[colon_idx + 1 ..];

    const window = if (std.mem.indexOf(u8, after_colon, arguments_key)) |args_idx|
        after_colon[0..args_idx]
    else
        after_colon;

    var i: usize = 0;
    while (i < window.len) : (i += 1) {
        if (!isToolNameChar(window[i])) continue;

        const start = i;
        var end = i + 1;
        while (end < window.len and isToolNameChar(window[end])) : (end += 1) {}

        const candidate = window[start..end];
        if (!std.mem.eql(u8, candidate, "name") and !std.mem.eql(u8, candidate, "arguments")) {
            return candidate;
        }

        i = end;
    }

    return null;
}

fn extractRawArgumentsJson(raw_json: []const u8) ?[]const u8 {
    const arguments_key = "\"arguments\"";
    const args_idx = std.mem.indexOf(u8, raw_json, arguments_key) orelse return null;
    const after_args = raw_json[args_idx + arguments_key.len ..];
    const colon_idx = std.mem.indexOfScalar(u8, after_args, ':') orelse return null;
    return extractJsonObject(after_args[colon_idx + 1 ..]);
}

fn normalizeSalvagedArgumentsJson(allocator: std.mem.Allocator, raw_json: []const u8) ![]u8 {
    const args_src = extractRawArgumentsJson(raw_json) orelse return allocator.dupe(u8, "{}");
    var parsed_args = std.json.parseFromSlice(std.json.Value, allocator, args_src, .{}) catch blk: {
        const repaired = repairJson(allocator, args_src) catch return allocator.dupe(u8, "{}");
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch return allocator.dupe(u8, "{}");
    };
    defer parsed_args.deinit();

    return try std.json.Stringify.valueAlloc(allocator, parsed_args.value, .{});
}

fn salvageMalformedToolCallJson(allocator: std.mem.Allocator, raw_json: []const u8) !?ParsedToolCall {
    if (!hasMalformedQuotedColonToolName(raw_json)) return null;

    const recovered_name = recoverToolNameFromRawJson(raw_json) orelse return null;
    if (!isPlausibleToolName(recovered_name)) return null;

    const args_json = try normalizeSalvagedArgumentsJson(allocator, raw_json);
    errdefer allocator.free(args_json);

    return .{
        .name = try allocator.dupe(u8, recovered_name),
        .arguments_json = args_json,
    };
}

fn repairMalformedParsedToolName(
    allocator: std.mem.Allocator,
    raw_json: []const u8,
    call: *ParsedToolCall,
) !void {
    if (!hasMalformedQuotedColonToolName(raw_json)) return;
    if (isPlausibleToolName(call.name)) return;

    const recovered_name = recoverToolNameFromRawJson(raw_json) orelse return;
    if (!isPlausibleToolName(recovered_name)) return;

    allocator.free(call.name);
    call.name = try allocator.dupe(u8, recovered_name);
}

fn parseInnerToolCall(allocator: std.mem.Allocator, inner: []const u8) !?ParsedToolCall {
    const malformed_quoted_colon_name = hasMalformedQuotedColonToolName(inner);
    if (malformed_quoted_colon_name) {
        if (try salvageMalformedToolCallJson(allocator, inner)) |recovered| {
            return recovered;
        }
    }
    if (extractJsonObject(inner)) |json_slice| {
        if (parseToolCallJson(allocator, json_slice)) |call| {
            if (malformed_quoted_colon_name and !isPlausibleToolName(call.name)) {
                if (try salvageMalformedToolCallJson(allocator, inner)) |recovered| {
                    allocator.free(call.name);
                    allocator.free(call.arguments_json);
                    return recovered;
                }
            }
            return call;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    }
    if (parseFunctionTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseInvokeTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseHybridTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseNamePrefixedJsonCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }

    return null;
}

/// Find the first JSON object `{...}` in a string, handling nesting.
fn extractJsonObject(input: []const u8) ?[]const u8 {
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

/// Attempt to repair common JSON issues from LLM output.
/// Handles: trailing commas, unbalanced braces/brackets, unbalanced quotes.
pub fn repairJson(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
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

/// Parse a JSON tool call object: {"name": "...", "arguments": {...}}
/// Tries to parse as-is first, then applies JSON repair as fallback.
fn parseToolCallJson(allocator: std.mem.Allocator, json_str: []const u8) !ParsedToolCall {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch blk: {
        // JSON parse failed — try repair
        const repaired = repairJson(allocator, json_str) catch return error.InvalidToolCallFormat;
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch {
            if (try salvageMalformedToolCallJson(allocator, json_str)) |call| return call;
            return error.InvalidToolCallFormat;
        };
    };
    var call = try parseToolCallJsonInner(allocator, parsed);
    errdefer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try repairMalformedParsedToolName(allocator, json_str, &call);

    // Fail closed on implausible names (e.g. ":") and make one last
    // attempt to recover from malformed quoted-colon payloads.
    if (!isPlausibleToolName(call.name)) {
        if (try salvageMalformedToolCallJson(allocator, json_str)) |recovered| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            call = recovered;
        }
    }

    if (!isPlausibleToolName(call.name)) {
        return error.InvalidToolName;
    }

    return call;
}

fn parseToolCallJsonInner(allocator: std.mem.Allocator, parsed: std.json.Parsed(std.json.Value)) !ParsedToolCall {
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidToolCallFormat,
    };

    // Extract name
    const name_val = obj.get("name") orelse return error.MissingToolName;
    const name_str = switch (name_val) {
        .string => |s| s,
        else => return error.InvalidToolName,
    };

    // Robustness: strip trailing XML tags and handle JSON-in-JSON hallucinations.
    const resolved_name_src = stripTrailingXml(std.mem.trim(u8, name_str, " \t\r\n"));
    var resolved_name_owned: ?[]u8 = null;

    if (std.mem.startsWith(u8, resolved_name_src, "{")) {
        const inner_parsed = std.json.parseFromSlice(std.json.Value, allocator, resolved_name_src, .{}) catch null;
        if (inner_parsed) |p| {
            defer p.deinit();
            if (p.value == .object) {
                if (p.value.object.get("name")) |n| {
                    if (n == .string) {
                        resolved_name_owned = try allocator.dupe(u8, std.mem.trim(u8, n.string, " \t\r\n"));
                    }
                }
            }
        }
    }

    const resolved_name = resolved_name_owned orelse try allocator.dupe(u8, resolved_name_src);
    errdefer allocator.free(resolved_name);

    if (resolved_name.len == 0) return error.EmptyToolName;

    // Extract arguments — re-serialize to JSON string
    const args_json = if (obj.get("arguments")) |args_val| blk: {
        switch (args_val) {
            .string => |s| {
                // Arguments is a string (possibly a JSON string) — use as-is
                break :blk try allocator.dupe(u8, s);
            },
            else => {
                // Arguments is an object/value — serialize it
                break :blk try std.json.Stringify.valueAlloc(allocator, args_val, .{});
            },
        }
    } else try allocator.dupe(u8, "{}");
    errdefer allocator.free(args_json);

    return .{
        .name = resolved_name,
        .arguments_json = args_json,
    };
}

/// Parse `<function=NAME><parameter=KEY>VALUE</parameter>...</function>` format.
///
/// Some open-source LLMs (Llama, Qwen, etc.) emit this XML-based format
/// instead of JSON inside `<tool_call>` tags. Extracts function name and
/// parameter key-value pairs, returning a `ParsedToolCall` with serialized
/// JSON arguments.
fn parseFunctionTagCall(allocator: std.mem.Allocator, inner: []const u8) !ParsedToolCall {
    // Expect: <function=NAME> ... </function>
    const func_prefix = "<function=";
    const func_start = std.mem.indexOf(u8, inner, func_prefix) orelse return error.NoFunctionTag;
    const after_prefix = inner[func_start + func_prefix.len ..];
    const name_end = std.mem.indexOfScalar(u8, after_prefix, '>') orelse return error.NoFunctionTag;
    const func_name = std.mem.trim(u8, after_prefix[0..name_end], " \t\r\n");
    if (func_name.len == 0) return error.EmptyFunctionName;

    // Validate function name: only alphanumeric, underscore, dash, dot allowed
    for (func_name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidFunctionName,
        }
    }

    // Collect <parameter=KEY>VALUE</parameter> pairs — bounded by </function>
    const full_body = after_prefix[name_end + 1 ..];
    const body = if (std.mem.indexOf(u8, full_body, "</function>")) |fc|
        full_body[0..fc]
    else
        full_body;

    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    const w = args_buf.writer(allocator);
    try w.writeByte('{');

    var remaining = body;
    var first = true;
    const param_prefix = "<parameter=";
    const param_close = "</parameter>";

    while (std.mem.indexOf(u8, remaining, param_prefix)) |ps| {
        const after_param = remaining[ps + param_prefix.len ..];
        const key_end = std.mem.indexOfScalar(u8, after_param, '>') orelse break;
        const key = std.mem.trim(u8, after_param[0..key_end], " \t\r\n");
        if (key.len == 0) break;

        const value_start = after_param[key_end + 1 ..];
        const value_end_pos = std.mem.indexOf(u8, value_start, param_close) orelse break;
        const value = std.mem.trim(u8, value_start[0..value_end_pos], " \t\r\n");

        if (!first) try w.writeByte(',');
        first = false;

        // Write "key": "value" with JSON string escaping via Stringify.valueAlloc
        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(key_json);
        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(val_json);
        try w.writeAll(key_json);
        try w.writeByte(':');
        try w.writeAll(val_json);

        remaining = value_start[value_end_pos + param_close.len ..];
    }

    try w.writeByte('}');

    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, func_name),
        .arguments_json = args_json,
    };
}

/// Parse `<invoke name=NAME><parameter name=KEY>VALUE</parameter>...</invoke>` format.
///
/// This is the tool-calling format typically used by MiniMax models.
fn parseInvokeTagCall(allocator: std.mem.Allocator, inner: []const u8) !ParsedToolCall {
    // Expect: <invoke name="NAME"> ... </invoke>
    const invoke_prefix = "<invoke name=";
    const invoke_start = std.mem.indexOf(u8, inner, invoke_prefix) orelse return error.NoInvokeTag;
    const after_prefix = inner[invoke_start + invoke_prefix.len ..];

    // Tool name is usually in quotes: "name"
    const name_quote = if (after_prefix.len > 0) after_prefix[0] else ' ';
    if (name_quote != '"' and name_quote != '\'') return error.InvalidInvokeFormat;

    const name_end = std.mem.indexOfScalar(u8, after_prefix[1..], name_quote) orelse return error.InvalidInvokeFormat;
    const tool_name = std.mem.trim(u8, after_prefix[1 .. name_end + 1], " \t\r\n");
    if (tool_name.len == 0) return error.EmptyToolName;
    if (!isPlausibleToolName(tool_name)) return error.InvalidToolName;

    const invoke_close_tag = "</invoke>";
    // Look for the '>' that closes the <invoke ...> tag.
    // It might not be immediately after the name (e.g. models sometimes insert a comma or space).
    // Robustness: if we find "<parameter" before ">", then the ">" was missing entirely.
    const invoke_tag_end_pos = blk: {
        const next_gt = std.mem.indexOfScalar(u8, after_prefix[name_end + 1 ..], '>');
        const next_param = std.mem.indexOf(u8, after_prefix[name_end + 1 ..], "<parameter");
        if (next_gt) |gt_pos| {
            if (next_param) |p_pos| {
                if (p_pos < gt_pos) break :blk name_end; // missing '>', started param
            }
            break :blk name_end + 1 + gt_pos;
        }
        break :blk name_end;
    };

    const full_invoke_content = after_prefix[invoke_tag_end_pos + 1 ..];
    const invoke_body = if (std.mem.indexOf(u8, full_invoke_content, invoke_close_tag)) |ic|
        full_invoke_content[0..ic]
    else
        full_invoke_content;

    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    const w = args_buf.writer(allocator);
    try w.writeByte('{');

    var remaining = invoke_body;
    var first = true;
    const param_close = "</parameter>";

    while (remaining.len > 0) {
        const ps = std.mem.indexOf(u8, remaining, "parameter name=") orelse break;
        // Find the '<' before 'parameter'
        var tag_start = ps;
        while (tag_start > 0 and remaining[tag_start] != '<') tag_start -= 1;
        if (remaining[tag_start] != '<') {
            remaining = if (ps + 15 < remaining.len) remaining[ps + 15 ..] else "";
            continue;
        }

        const after_param = remaining[ps + 15 ..];
        const p_name_quote = if (after_param.len > 0) after_param[0] else ' ';
        if (p_name_quote != '"' and p_name_quote != '\'') break;

        const p_name_end = std.mem.indexOfScalar(u8, after_param[1..], p_name_quote) orelse break;
        const key = std.mem.trim(u8, after_param[1 .. p_name_end + 1], " \t\r\n");
        if (key.len == 0) break;

        const p_tag_end = std.mem.indexOfScalar(u8, after_param[p_name_end + 1 ..], '>') orelse break;
        const value_start = after_param[p_name_end + 1 + p_tag_end + 1 ..];
        const value_end_pos = std.mem.indexOf(u8, value_start, param_close) orelse break;
        const value = std.mem.trim(u8, value_start[0..value_end_pos], " \t\r\n");

        if (!first) try w.writeByte(',');
        first = false;

        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(key_json);
        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(val_json);
        try w.writeAll(key_json);
        try w.writeByte(':');
        try w.writeAll(val_json);

        remaining = value_start[value_end_pos + param_close.len ..];
    }

    try w.writeByte('}');

    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, tool_name),
        .arguments_json = args_json,
    };
}

/// Parse mixed/hybrid formats like: {"name": "shell", <parameter name="command">ls</parameter>}
/// This is a "greedy" fallback parser for highly malformed or mixed LLM output.
fn parseHybridTagCall(allocator: std.mem.Allocator, inner: []const u8) !ParsedToolCall {
    // 1. Greedy Name Extraction
    const tool_name: []const u8 = blk: {
        // Try JSON-style name
        if (std.mem.indexOf(u8, inner, "\"name\":")) |idx| {
            const after = inner[idx + 7 ..];
            if (std.mem.indexOfScalar(u8, after, '"')) |q1| {
                if (std.mem.indexOfScalar(u8, after[q1 + 1 ..], '"')) |q2| {
                    break :blk std.mem.trim(u8, after[q1 + 1 .. q1 + 1 + q2], " \t\r\n");
                }
            }
        }
        // Try Invoke-style name
        if (std.mem.indexOf(u8, inner, "<invoke name=")) |idx| {
            const after = inner[idx + 13 ..];
            if (after.len > 0) {
                const quote = after[0];
                if (quote == '"' or quote == '\'') {
                    if (std.mem.indexOfScalar(u8, after[1..], quote)) |q_end| {
                        break :blk std.mem.trim(u8, after[1 .. q_end + 1], " \t\r\n");
                    }
                }
            }
        }
        // Try Function-style name
        if (std.mem.indexOf(u8, inner, "<function=")) |idx| {
            const after = inner[idx + 10 ..];
            if (std.mem.indexOfScalar(u8, after, '>')) |end| {
                break :blk std.mem.trim(u8, after[0..end], " \t\r\n");
            }
        }
        // Try <tool name="..."> style
        if (std.mem.indexOf(u8, inner, "<tool name=")) |idx| {
            const after = inner[idx + 11 ..];
            if (after.len > 0) {
                const quote = after[0];
                if (quote == '"' or quote == '\'') {
                    if (std.mem.indexOfScalar(u8, after[1..], quote)) |q_end| {
                        break :blk std.mem.trim(u8, after[1 .. q_end + 1], " \t\r\n");
                    }
                }
            }
        }
        return error.NoToolNameFound;
    };

    if (tool_name.len == 0) return error.EmptyToolName;
    if (!isPlausibleToolName(tool_name)) return error.InvalidToolName;

    // 2. Greedy Parameter Collection
    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    const w = args_buf.writer(allocator);
    try w.writeByte('{');

    var first = true;
    var remaining = inner;

    // Track keys we've already found to avoid duplicates
    var found_keys = std.StringHashMap(void).init(allocator);
    defer found_keys.deinit();

    // Look for XML parameters
    const p_close = "</parameter>";
    var search_idx: usize = 0;
    while (search_idx < remaining.len) {
        const ps = std.mem.indexOf(u8, remaining[search_idx..], "parameter name=") orelse break;
        const absolute_ps = search_idx + ps;
        // Find the '<' before 'parameter'
        var tag_start = absolute_ps;
        while (tag_start > 0 and remaining[tag_start] != '<') tag_start -= 1;
        if (remaining[tag_start] != '<') {
            search_idx = absolute_ps + 15;
            continue;
        }

        const after_param = remaining[absolute_ps + 15 ..];
        if (after_param.len == 0) {
            search_idx = absolute_ps + 15;
            continue;
        }
        const quote = after_param[0];
        if (quote != '"' and quote != '\'') {
            search_idx = absolute_ps + 15;
            continue;
        }
        if (std.mem.indexOfScalar(u8, after_param[1..], quote)) |q_end| {
            const key = std.mem.trim(u8, after_param[1 .. q_end + 1], " \t\r\n");
            if (std.mem.indexOfScalar(u8, after_param[q_end + 1 ..], '>')) |tag_end| {
                const val_start = after_param[q_end + 1 + tag_end + 1 ..];
                if (std.mem.indexOf(u8, val_start, p_close)) |val_end| {
                    const value = std.mem.trim(u8, val_start[0..val_end], " \t\r\n");

                    if (!found_keys.contains(key)) {
                        if (!first) try w.writeByte(',');
                        first = false;
                        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
                        defer allocator.free(key_json);
                        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
                        defer allocator.free(val_json);
                        try w.writeAll(key_json);
                        try w.writeByte(':');
                        try w.writeAll(val_json);
                        try found_keys.put(key, {});
                    }
                    search_idx = absolute_ps + 15 + q_end + 1 + tag_end + 1 + val_end + p_close.len;
                    continue;
                }
            }
        }
        search_idx = absolute_ps + 15;
    }

    // Look for JSON-style simple key-value pairs (only strings for now as greedy fallback)
    // Pattern: "key": "value"
    search_idx = 0;
    while (std.mem.indexOfScalar(u8, remaining[search_idx..], '"')) |q1| {
        const absolute_q1 = search_idx + q1;
        const after_q1 = remaining[absolute_q1 + 1 ..];
        if (std.mem.indexOfScalar(u8, after_q1, '"')) |q2| {
            const key = after_q1[0..q2];
            const after_key = after_q1[q2 + 1 ..];
            // Look for ':' and then another string
            var i: usize = 0;
            while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':')) i += 1;
            if (i < after_key.len and after_key[i] == '"') {
                const val_start = after_key[i + 1 ..];
                if (std.mem.indexOfScalar(u8, val_start, '"')) |val_q_end| {
                    const value = val_start[0..val_q_end];
                    if (!found_keys.contains(key) and !std.mem.eql(u8, key, "name") and !std.mem.eql(u8, key, "arguments")) {
                        if (!first) try w.writeByte(',');
                        first = false;
                        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
                        defer allocator.free(key_json);
                        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
                        defer allocator.free(val_json);
                        try w.writeAll(key_json);
                        try w.writeByte(':');
                        try w.writeAll(val_json);
                        try found_keys.put(key, {});
                    }
                    search_idx = absolute_q1 + 1 + q2 + 1 + i + 1 + val_q_end + 1;
                    continue;
                }
            }
        }
        search_idx = absolute_q1 + 1;
    }

    try w.writeByte('}');

    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, tool_name),
        .arguments_json = args_json,
    };
}

/// Parse compact tool-call format: `tool_name{...json arguments...}`.
///
/// Some compatible providers occasionally emit this form inside `<tool_call>`
/// when they fail to produce the strict JSON envelope.
fn parseNamePrefixedJsonCall(allocator: std.mem.Allocator, inner: []const u8) !ParsedToolCall {
    const cleaned = std.mem.trim(u8, stripTrailingXml(inner), " \t\r\n");
    const obj_start = std.mem.indexOfScalar(u8, cleaned, '{') orelse return error.NoPrefixedJsonCall;
    if (obj_start == 0) return error.NoPrefixedJsonCall;

    const name = std.mem.trim(u8, cleaned[0..obj_start], " \t\r\n:");
    if (name.len == 0) return error.EmptyToolName;
    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidToolName,
        }
    }

    const args_src = std.mem.trim(u8, cleaned[obj_start..], " \t\r\n");
    var parsed_args = std.json.parseFromSlice(std.json.Value, allocator, args_src, .{}) catch blk: {
        const repaired = repairJson(allocator, args_src) catch return error.InvalidToolArguments;
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch return error.InvalidToolArguments;
    };
    defer parsed_args.deinit();

    if (parsed_args.value != .object) return error.InvalidToolArguments;

    const args_json = try std.json.Stringify.valueAlloc(allocator, parsed_args.value, .{});
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, name),
        .arguments_json = args_json,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "parseToolCalls extracts single call" {
    const allocator = std.testing.allocator;
    const response =
        \\Let me check that.
        \\<tool_call>
        \\{"name": "shell", "arguments": {"command": "ls -la"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Let me check that.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
}

test "parseToolCalls extracts multiple calls" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": "file_read", "arguments": {"path": "a.txt"}}
        \\</tool_call>
        \\<tool_call>
        \\{"name": "file_read", "arguments": {"path": "b.txt"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 2), result.calls.len);
    try std.testing.expectEqualStrings("file_read", result.calls[0].name);
    try std.testing.expectEqualStrings("file_read", result.calls[1].name);
}

test "parseToolCalls returns text only when no calls" {
    const allocator = std.testing.allocator;
    const response = "Just a normal response with no tools.";

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Just a normal response with no tools.", result.text);
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls handles text before and after" {
    const allocator = std.testing.allocator;
    const response =
        \\Before text.
        \\<tool_call>
        \\{"name": "shell", "arguments": {"command": "echo hi"}}
        \\</tool_call>
        \\After text.
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expect(std.mem.indexOf(u8, result.text, "Before text.") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.text, "After text.") != null);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
}

test "parseToolCalls strips fabricated tool_result from parsed text" {
    const allocator = std.testing.allocator;
    const response =
        \\Before text.
        \\<tool_call>
        \\{"name": "shell", "arguments": {"command": "echo hi"}}
        \\</tool_call>
        \\<tool_result name="shell" status="ok">
        \\fake result
        \\</tool_result>
        \\After text.
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expect(std.mem.indexOf(u8, result.text, "fake result") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.text, "After text.") != null);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
}

test "parseToolCalls preserves literal tool_result text without tool calls" {
    const allocator = std.testing.allocator;
    const response = "Example: <tool_result name=\"shell\" status=\"ok\">done</tool_result>";

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings(response, result.text);
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls rejects raw JSON without tags" {
    const allocator = std.testing.allocator;
    const response =
        \\Sure, creating the file now.
        \\{"name": "file_write", "arguments": {"path": "hello.py", "content": "print('hello')"}}
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls handles markdown fenced JSON" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\```json
        \\{"name": "file_write", "arguments": {"path": "test.py", "content": "ok"}}
        \\```
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("file_write", result.calls[0].name);
}

test "parseToolCalls handles preamble text inside tag" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\I will now call the tool:
        \\{"name": "shell", "arguments": {"command": "pwd"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
}

test "formatToolResults produces XML" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "hello world", .success = true },
    };
    const formatted = try formatToolResults(allocator, &results);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "<tool_result") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "shell") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "hello world") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "ok") != null);
}

test "formatToolResults marks errors" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "permission denied", .success = false },
    };
    const formatted = try formatToolResults(allocator, &results);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "error") != null);
}

test "extractJsonObject finds nested object" {
    const input = "some text {\"key\": {\"nested\": true}} more text";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("{\"key\": {\"nested\": true}}", result);
}

test "extractJsonObject returns null for no object" {
    try std.testing.expect(extractJsonObject("no json here") == null);
}

// ── Additional dispatcher tests ─────────────────────────────────

test "parseToolCalls empty string" {
    const allocator = std.testing.allocator;
    const result = try parseToolCalls(allocator, "");
    defer {
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
    try std.testing.expectEqual(@as(usize, 0), result.text.len);
}

test "parseToolCalls unclosed tag" {
    const allocator = std.testing.allocator;
    const response = "Some text <tool_call>{\"name\":\"shell\",\"arguments\":{}} and more";
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        allocator.free(result.calls);
    }
    // Unclosed tag should not duplicate prefix text.
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
    try std.testing.expectEqualStrings(response, result.text);
}

test "parseToolCalls compact call with malformed closing tag" {
    const allocator = std.testing.allocator;
    const response =
        \\Vou dar uma olhada no que tem na memória agora.
        \\<tool_call>memory_list{"limit": 10, "include_content": true}</arg_value>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Vou dar uma olhada no que tem na memória agora.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("memory_list", result.calls[0].name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.calls[0].arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqual(@as(i64, 10), parsed_args.value.object.get("limit").?.integer);
    try std.testing.expect(parsed_args.value.object.get("include_content").?.bool);
}

test "parseToolCalls compact malformed close with xml-like argument content" {
    const allocator = std.testing.allocator;
    const response =
        \\Generating HTML file.
        \\<tool_call>file_write{"path":"index.html","content":"</html>"}</arg_value>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Generating HTML file.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("file_write", result.calls[0].name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.calls[0].arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("index.html", parsed_args.value.object.get("path").?.string);
    try std.testing.expectEqualStrings("</html>", parsed_args.value.object.get("content").?.string);
}

test "parseToolCalls compact call with no closing tag" {
    const allocator = std.testing.allocator;
    const response = "<tool_call>file_read{\"path\": \"/home/micelio/.nullclaw/void.md\"}";

    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("file_read", result.calls[0].name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.calls[0].arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("/home/micelio/.nullclaw/void.md", parsed_args.value.object.get("path").?.string);
}

test "parseToolCalls malformed JSON inside tag" {
    const allocator = std.testing.allocator;
    const response = "<tool_call>this is not json</tool_call>";
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        allocator.free(result.calls);
    }
    // Malformed JSON is skipped
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls recovers malformed quoted-colon tool name" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name":": "memory_recall", "arguments": {"query": "Traumforschung"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("memory_recall", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "Traumforschung") != null);
}

test "parseToolCalls rejects literal colon tool name" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": ":", "arguments": {"query": "x"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls malformed xml-like arg_key payload is skipped" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>web_search<arg_key>query</arg_key><arg_value>manelsen amelie github lattes</arg_value><arg_key>count</arg_key><arg_value>5</arg_value></tool_call>
    ;
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        allocator.free(result.calls);
    }
    try std.testing.expectEqualStrings("", result.text);
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseToolCalls empty arguments defaults to empty object" {
    const allocator = std.testing.allocator;
    const response = "<tool_call>{\"name\": \"shell\"}</tool_call>";
    const result = try parseToolCalls(allocator, response);
    defer {
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expectEqualStrings("{}", result.calls[0].arguments_json);
}

test "parseToolCalls whitespace-only inside tag" {
    const allocator = std.testing.allocator;
    const response = "<tool_call>   \n   </tool_call>";
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "formatToolResults empty results" {
    const allocator = std.testing.allocator;
    const formatted = try formatToolResults(allocator, &.{});
    defer allocator.free(formatted);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Tool results") != null);
}

test "formatToolResults multiple results" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "file1.txt", .success = true },
        .{ .name = "file_read", .output = "content here", .success = true },
        .{ .name = "search", .output = "not found", .success = false },
    };
    const formatted = try formatToolResults(allocator, &results);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "shell") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "file_read") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "search") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "file1.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "not found") != null);
}

// Bug 3 regression: unmatched close brace/bracket must not underflow depth (usize).
// Before fix, `depth -= 1` when depth==0 caused a panic (usize underflow).
test "extractJsonObject unmatched close brace does not panic" {
    // Input starts with '}' — no matching open, depth would underflow before fix.
    const result = extractJsonObject("} not an object {\"key\":\"ok\"}");
    // The second valid object should still be found (or null — both are acceptable).
    // The important thing is no panic.
    if (result) |r| {
        try std.testing.expect(r.len > 0);
    }
}

test "extractJsonObject unmatched close bracket does not panic" {
    // Input starts with ']' — no matching open.
    const result = extractJsonObject("] some text [1,2,3]");
    if (result) |r| {
        try std.testing.expect(r.len > 0);
    }
}

test "extractJsonObject with leading text" {
    const input = "Here is the result: {\"key\": \"value\"}";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("{\"key\": \"value\"}", result);
}

test "extractJsonObject deeply nested" {
    const input = "{\"a\":{\"b\":{\"c\":true}}}";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings(input, result);
}

test "extractJsonObject with string containing braces" {
    const input = "{\"key\": \"value with { and } inside\"}";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings(input, result);
}

test "extractJsonObject empty string" {
    try std.testing.expect(extractJsonObject("") == null);
}

test "extractJsonObject unmatched brace" {
    try std.testing.expect(extractJsonObject("{unclosed") == null);
}

test "parseToolCalls three consecutive calls" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": "a", "arguments": {}}
        \\</tool_call>
        \\<tool_call>
        \\{"name": "b", "arguments": {}}
        \\</tool_call>
        \\<tool_call>
        \\{"name": "c", "arguments": {}}
        \\</tool_call>
    ;
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 3), result.calls.len);
    try std.testing.expectEqualStrings("a", result.calls[0].name);
    try std.testing.expectEqualStrings("b", result.calls[1].name);
    try std.testing.expectEqualStrings("c", result.calls[2].name);
}

test "formatToolResults with tool_call_id" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "ok", .success = true, .tool_call_id = "tc-123" },
    };
    const formatted = try formatToolResults(allocator, &results);
    defer allocator.free(formatted);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "shell") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "ok") != null);
}

test "ParsedToolCall default tool_call_id is null" {
    const call = ParsedToolCall{
        .name = "test",
        .arguments_json = "{}",
    };
    try std.testing.expect(call.tool_call_id == null);
}

test "ToolExecutionResult default tool_call_id is null" {
    const result = ToolExecutionResult{
        .name = "test",
        .output = "output",
        .success = true,
    };
    try std.testing.expect(result.tool_call_id == null);
}

// ── Function-tag format tests (<function=name><parameter=key>value</parameter></function>) ──

test "parseFunctionTagCall single parameter" {
    const allocator = std.testing.allocator;
    const inner = "<function=shell><parameter=command>ps aux | grep nullclaw</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "ps aux | grep nullclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "command") != null);
}

test "parseFunctionTagCall multiple parameters" {
    const allocator = std.testing.allocator;
    const inner = "<function=file_write><parameter=path>/tmp/test.txt</parameter><parameter=content>hello world</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("file_write", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "path") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "/tmp/test.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "content") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "hello world") != null);
}

test "parseFunctionTagCall with whitespace and newlines" {
    const allocator = std.testing.allocator;
    const inner =
        \\<function=shell>
        \\<parameter=command>
        \\ls -la
        \\</parameter>
        \\</function>
    ;
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "ls -la") != null);
}

test "parseFunctionTagCall no function tag returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NoFunctionTag, parseFunctionTagCall(allocator, "just plain text"));
}

test "parseToolCalls handles function-tag format inside tool_call" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\<function=shell>
        \\<parameter=command>ps aux | grep nullclaw | grep -v grep</parameter>
        \\</function>
        \\</tool_call>
    ;
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ps aux") != null);
}

test "parseToolCalls function-tag with surrounding text" {
    const allocator = std.testing.allocator;
    const response =
        \\Let me check that.
        \\<tool_call>
        \\<function=shell>
        \\<parameter=command>echo hi</parameter>
        \\</function>
        \\</tool_call>
        \\Done.
    ;
    const result = try parseToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.text, "Let me check that.") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.text, "Done.") != null);
}

test "parseFunctionTagCall value with quotes is JSON-escaped" {
    const allocator = std.testing.allocator;
    const inner = "<function=shell><parameter=command>echo \"hello world\"</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    // Verify the JSON is valid by parsing it
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, call.arguments_json, .{});
    defer parsed.deinit();
    const cmd = parsed.value.object.get("command").?.string;
    try std.testing.expectEqualStrings("echo \"hello world\"", cmd);
}

// ── Native tool dispatcher tests ────────────────────────────────

test "isNativeFormat detects OpenAI tool_calls" {
    const native_response =
        \\{"content":"ok","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls\"}"}}]}
    ;
    try std.testing.expect(isNativeFormat(std.testing.allocator, native_response));
}

test "isNativeFormat rejects XML format" {
    const xml_response = "Let me check.\n<tool_call>\n{\"name\":\"shell\",\"arguments\":{}}\n</tool_call>";
    try std.testing.expect(!isNativeFormat(std.testing.allocator, xml_response));
}

test "isNativeFormat rejects plain text" {
    try std.testing.expect(!isNativeFormat(std.testing.allocator, "Just a normal response."));
}

test "isNativeFormat rejects tool_calls in non-JSON context" {
    // Contains the substring but is not valid JSON
    try std.testing.expect(!isNativeFormat(std.testing.allocator, "The API returns \"tool_calls\" in the response."));
}

test "parseNativeToolCalls single call" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"I will list files.","tool_calls":[{"id":"call_abc","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls -la\"}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("I will list files.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expectEqualStrings("call_abc", result.calls[0].tool_call_id.?);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
}

test "parseNativeToolCalls multiple calls" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"Reading files.","tool_calls":[{"id":"tc1","type":"function","function":{"name":"file_read","arguments":"{\"path\":\"a.txt\"}"}},{"id":"tc2","type":"function","function":{"name":"file_read","arguments":"{\"path\":\"b.txt\"}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 2), result.calls.len);
    try std.testing.expectEqualStrings("file_read", result.calls[0].name);
    try std.testing.expectEqualStrings("tc1", result.calls[0].tool_call_id.?);
    try std.testing.expectEqualStrings("file_read", result.calls[1].name);
    try std.testing.expectEqualStrings("tc2", result.calls[1].tool_call_id.?);
}

test "parseNativeToolCalls null content" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":null,"tool_calls":[{"id":"tc1","type":"function","function":{"name":"shell","arguments":"{}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
}

test "parseNativeToolCalls no tool_calls key" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"Just text, no tools."}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Just text, no tools.", result.text);
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseNativeToolCalls empty tool_calls array" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"Done.","tool_calls":[]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Done.", result.text);
    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseNativeToolCalls skips entries without function field" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"","tool_calls":[{"id":"tc1","type":"function"},{"id":"tc2","type":"function","function":{"name":"shell","arguments":"{}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
}

test "parseNativeToolCalls skips entries with empty function name" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"","tool_calls":[{"id":"tc1","type":"function","function":{"name":"","arguments":"{}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseNativeToolCalls preserves tool_call_id" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"","tool_calls":[{"id":"call_xyz789","type":"function","function":{"name":"search","arguments":"{\"query\":\"test\"}"}}]}
    ;

    const result = try parseNativeToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("call_xyz789", result.calls[0].tool_call_id.?);
}

test "formatNativeToolResults single result" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "hello world", .success = true, .tool_call_id = "call_1" },
    };
    const formatted = try formatNativeToolResults(allocator, &results);
    defer allocator.free(formatted);

    // Should be valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, formatted, .{});
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.ExpectedArray,
    };

    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    const item = arr.items[0].object;
    try std.testing.expectEqualStrings("tool", item.get("role").?.string);
    try std.testing.expectEqualStrings("call_1", item.get("tool_call_id").?.string);
    try std.testing.expectEqualStrings("hello world", item.get("content").?.string);
}

test "formatNativeToolResults multiple results" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "ok", .success = true, .tool_call_id = "tc1" },
        .{ .name = "file_read", .output = "content", .success = true, .tool_call_id = "tc2" },
    };
    const formatted = try formatNativeToolResults(allocator, &results);
    defer allocator.free(formatted);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, formatted, .{});
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.ExpectedArray,
    };

    try std.testing.expectEqual(@as(usize, 2), arr.items.len);
    try std.testing.expectEqualStrings("tc1", arr.items[0].object.get("tool_call_id").?.string);
    try std.testing.expectEqualStrings("tc2", arr.items[1].object.get("tool_call_id").?.string);
}

test "formatNativeToolResults missing tool_call_id defaults to unknown" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "ok", .success = true },
    };
    const formatted = try formatNativeToolResults(allocator, &results);
    defer allocator.free(formatted);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, formatted, .{});
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.ExpectedArray,
    };

    try std.testing.expectEqualStrings("unknown", arr.items[0].object.get("tool_call_id").?.string);
}

test "formatNativeToolResults empty results" {
    const allocator = std.testing.allocator;
    const formatted = try formatNativeToolResults(allocator, &.{});
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("[]", formatted);
}

test "formatNativeToolResults escapes special characters in output" {
    const allocator = std.testing.allocator;
    const results = [_]ToolExecutionResult{
        .{ .name = "shell", .output = "line1\nline2\t\"quoted\"", .success = true, .tool_call_id = "tc1" },
    };
    const formatted = try formatNativeToolResults(allocator, &results);
    defer allocator.free(formatted);

    // Verify it's valid JSON (will fail if escaping is broken)
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, formatted, .{});
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.ExpectedArray,
    };
    try std.testing.expectEqualStrings("line1\nline2\t\"quoted\"", arr.items[0].object.get("content").?.string);
}

test "DispatcherKind enum values" {
    try std.testing.expect(@intFromEnum(DispatcherKind.xml) != @intFromEnum(DispatcherKind.native));
}

// ── parseToolCalls with OpenAI JSON format ──────────────────────

test "parseToolCalls routes OpenAI JSON to native parser" {
    const allocator = std.testing.allocator;
    const response =
        \\{"content":"Listing files.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls\"}"}}]}
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Listing files.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expectEqualStrings("call_1", result.calls[0].tool_call_id.?);
}

test "parseToolCalls falls back to XML when JSON has no tool_calls" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": "shell", "arguments": {"command": "pwd"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
}

// ── isNativeJsonFormat ──────────────────────────────────────────

test "isNativeJsonFormat true for valid native JSON" {
    try std.testing.expect(isNativeJsonFormat(
        \\{"content":"ok","tool_calls":[]}
    ));
}

test "isNativeJsonFormat true with leading whitespace" {
    try std.testing.expect(isNativeJsonFormat(
        \\  {"tool_calls":[{"id":"1","type":"function","function":{"name":"x","arguments":"{}"}}]}
    ));
}

test "containsToolCallMarkup detects xml and bracket variants" {
    try std.testing.expect(containsToolCallMarkup("<tool_call>{}</tool_call>"));
    try std.testing.expect(containsToolCallMarkup("[TOOL_CALL]{\"name\":\"shell\"}[/TOOL_CALL]"));
    try std.testing.expect(containsToolCallMarkup("[tool_call]{\"name\":\"shell\"}[/tool_call]"));
    try std.testing.expect(!containsToolCallMarkup("plain reply text"));
}

test "containsToolCallMarkup detects orphan closing tag" {
    // Model sometimes emits </tool_call> without an opener; must be suppressed.
    try std.testing.expect(containsToolCallMarkup("Here are the results:\n</tool_call>\nSome reply"));
    try std.testing.expect(containsToolCallMarkup("</tool_call>"));
    try std.testing.expect(containsToolCallMarkup("Here are the results:\n[/TOOL_CALL]\nSome reply"));
    try std.testing.expect(containsToolCallMarkup("[/tool_call]"));
}

test "isNativeJsonFormat false for XML response" {
    try std.testing.expect(!isNativeJsonFormat("<tool_call>{\"name\":\"shell\"}</tool_call>"));
}

test "isNativeJsonFormat false for plain text" {
    try std.testing.expect(!isNativeJsonFormat("Just a normal response."));
}

test "isNativeJsonFormat false for empty string" {
    try std.testing.expect(!isNativeJsonFormat(""));
}

test "isNativeJsonFormat false for array" {
    try std.testing.expect(!isNativeJsonFormat("[1,2,3]"));
}

// ── parseStructuredToolCalls ────────────────────────────────────

test "parseStructuredToolCalls converts ToolCall slice" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "call_1", .name = "shell", .arguments = "{\"command\":\"ls\"}" },
        .{ .id = "call_2", .name = "file_read", .arguments = "{\"path\":\"a.txt\"}" },
    };

    const result = try parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name);
    try std.testing.expectEqualStrings("{\"command\":\"ls\"}", result[0].arguments_json);
    try std.testing.expectEqualStrings("call_1", result[0].tool_call_id.?);
    try std.testing.expectEqualStrings("file_read", result[1].name);
    try std.testing.expectEqualStrings("call_2", result[1].tool_call_id.?);
}

test "parseStructuredToolCalls skips empty name" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "call_1", .name = "", .arguments = "{}" },
        .{ .id = "call_2", .name = "shell", .arguments = "{}" },
    };

    const result = try parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name);
}

test "parseStructuredToolCalls empty input" {
    const allocator = std.testing.allocator;
    const empty: []const providers.ToolCall = &.{};

    const result = try parseStructuredToolCalls(allocator, empty);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "parseStructuredToolCalls empty id becomes null" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "", .name = "shell", .arguments = "{}" },
    };

    const result = try parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expect(result[0].tool_call_id == null);
}

// ── extractJsonObject with arrays ───────────────────────────────

test "extractJsonObject finds array" {
    const input = "some text [1, 2, 3] more text";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("[1, 2, 3]", result);
}

test "extractJsonObject finds nested array" {
    const input = "[[1, 2], [3, 4]]";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("[[1, 2], [3, 4]]", result);
}

test "extractJsonObject prefers earlier bracket over brace" {
    const input = "[{\"key\": \"value\"}]";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("[{\"key\": \"value\"}]", result);
}

test "extractJsonObject prefers earlier brace over bracket" {
    const input = "{\"arr\": [1, 2]}";
    const result = extractJsonObject(input).?;
    try std.testing.expectEqualStrings("{\"arr\": [1, 2]}", result);
}

// ── JSON Repair Tests ───────────────────────────────────────────

test "repairJson removes trailing commas" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "{\"key\": \"value\",}");
    defer allocator.free(result);
    // Should be valid JSON after repair
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("value", parsed.value.object.get("key").?.string);
}

test "repairJson removes trailing comma in array" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "[1, 2, 3,]");
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.value.array.items.len);
}

test "repairJson balances unclosed braces" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"");
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("shell", parsed.value.object.get("name").?.string);
}

test "repairJson balances unclosed brackets" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "[1, 2, 3");
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.value.array.items.len);
}

test "repairJson balances unclosed quote" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "{\"name\": \"shell}");
    defer allocator.free(result);
    // After repair, should have balanced quotes and closing brace
    try std.testing.expect(std.mem.indexOf(u8, result, "shell") != null);
}

test "repairJson escapes newlines in strings" {
    const allocator = std.testing.allocator;
    const result = try repairJson(allocator, "{\"content\": \"line1\nline2\"}");
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("line1\nline2", parsed.value.object.get("content").?.string);
}

test "repairJson passes through valid JSON unchanged" {
    const allocator = std.testing.allocator;
    const valid = "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}";
    const result = try repairJson(allocator, valid);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(valid, result);
}

test "repairJson handles combined issues" {
    const allocator = std.testing.allocator;
    // Trailing comma + unclosed brace
    const result = try repairJson(allocator, "{\"name\": \"test\", \"args\": {\"a\": 1,}");
    defer allocator.free(result);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("test", parsed.value.object.get("name").?.string);
}

test "parseToolCallJson with trailing comma repair" {
    const allocator = std.testing.allocator;
    const result = try parseToolCallJson(allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"},}");
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", result.name);
}

test "parseToolCallJson with unclosed brace repair" {
    const allocator = std.testing.allocator;
    const result = try parseToolCallJson(allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}");
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", result.name);
}

test "parseToolCallJson robustness" {
    const allocator = std.testing.allocator;

    // Case 1: JSON-in-JSON (name field is a whole JSON object)
    const json1 = "{\"name\": \"{\\\"name\\\": \\\"shell\\\", \\\"arguments\\\": {}}\", \"arguments\": {}}";
    const res1 = try parseToolCallJson(allocator, json1);
    defer {
        allocator.free(res1.name);
        allocator.free(res1.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", res1.name);

    // Case 2: Trailing XML tag in name (from logs)
    const json2 = "{\"name\": \"shell</arg_value>\", \"arguments\": {\"command\": \"ls\"}}";
    const res2 = try parseToolCallJson(allocator, json2);
    defer {
        allocator.free(res2.name);
        allocator.free(res2.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", res2.name);

    // Case 3: JSON-like name without nested "name" is rejected as invalid tool name.
    const json3 = "{\"name\": \"{\\\"tool\\\":\\\"shell\\\"}\", \"arguments\": {}}";
    try std.testing.expectError(error.InvalidToolName, parseToolCallJson(allocator, json3));
}

test "parseToolCallJson salvages malformed quoted colon tool name" {
    const allocator = std.testing.allocator;
    const raw = "{\"name\":\": \"memory_recall\", \"arguments\": {\"query\": \"Traumforschung kulturwissenschaftlich\"}}";

    const result = try parseToolCallJson(allocator, raw);
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }

    try std.testing.expectEqualStrings("memory_recall", result.name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("Traumforschung kulturwissenschaftlich", parsed_args.value.object.get("query").?.string);
}

test "parseToolCallJson salvages malformed quoted colon tool name with repaired arguments" {
    const allocator = std.testing.allocator;
    const raw = "{\"name\" : \": \"memory_recall\", \"arguments\" : {\"query\": \"hello\",}}";

    const result = try parseToolCallJson(allocator, raw);
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }

    try std.testing.expectEqualStrings("memory_recall", result.name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("hello", parsed_args.value.object.get("query").?.string);
}

test "parseToolCalls salvages malformed quoted colon tool name" {
    const allocator = std.testing.allocator;
    const response =
        \\Ich suche erst im Langzeitgedaechtnis.
        \\<tool_call>
        \\{"name":": "memory_recall", "arguments": {"query": "Traumforschung kulturwissenschaftlich"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Ich suche erst im Langzeitgedaechtnis.", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("memory_recall", result.calls[0].name);
}

test "parseToolCalls rejects unrelated invalid tool name" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": "shell tool", "arguments": {"command": "echo hi"}}
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseXmlToolCalls minimax format" {
    const allocator = std.testing.allocator;
    const response =
        \\Directory already exists. Let me see what's inside:
        \\<tool_call>
        \\<invoke name="shell">
        \\<parameter name="command">ls -la /home/micelio/.nullclaw/workspace/amelie</parameter>
        \\</invoke>
        \\</minimax:tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Directory already exists. Let me see what's inside:", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
}

test "parseXmlToolCalls minimax format robustness" {
    const allocator = std.testing.allocator;
    const response =
        \\Cloning...
        \\<tool_call>
        \\<invoke name="shell",<parameter name="command">ls -la /home/micelio/.nullclaw/workspace/amelie</parameter>
        \\</invoke>
        \\</minimax:tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqualStrings("Cloning...", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
}

test "parseXmlToolCalls rejects invalid minimax tool name" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\<invoke name=":">
        \\<parameter name="command">ls</parameter>
        \\</invoke>
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 0), result.calls.len);
}

test "parseXmlToolCalls hybrid format" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\{"name": "shell", <parameter name="command">ls -la /home/micelio/.nullclaw/workspace/amelie</parameter>
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "command") != null);
}

test "parseXmlToolCalls tool-tag hybrid format" {
    const allocator = std.testing.allocator;
    const response =
        \\<tool_call>
        \\<tool name="shell">
        \\<parameter name="command">ls</parameter>
        \\</tool>
        \\</tool_call>
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls") != null);
}

test "parseXmlToolCalls square bracket format" {
    const allocator = std.testing.allocator;
    const response =
        \\[TOOL_CALL]
        \\<invoke name="shell">
        \\<parameter name="command">ls -la /home/micelio/.nullclaw/</parameter>
        \\</invoke>
        \\[/TOOL_CALL]
    ;

    const result = try parseToolCalls(allocator, response);
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }

    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "ls -la") != null);
}

// ── Hardening tests (issue #16 audit) ───────────────────────────

test "parseFunctionTagCall parameters bounded by </function>" {
    const allocator = std.testing.allocator;
    // Two function blocks concatenated — second block's params must NOT leak into first
    const inner = "<function=shell><parameter=command>echo hi</parameter></function><function=file_read><parameter=path>/etc/passwd</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    // Only "command" parameter should be present, not "path"
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "echo hi") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "/etc/passwd") == null);
}

test "parseFunctionTagCall rejects invalid function name with special chars" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=shell\"><parameter=x>y</parameter></function>"),
    );
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=she<ll><parameter=x>y</parameter></function>"),
    );
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=she ll><parameter=x>y</parameter></function>"),
    );
}

test "parseFunctionTagCall accepts valid names with dots dashes underscores" {
    const allocator = std.testing.allocator;
    const call = try parseFunctionTagCall(allocator, "<function=my-tool_v2.0><parameter=key>val</parameter></function>");
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("my-tool_v2.0", call.name);
}

test "parseXmlToolCalls function-tag fallback when JSON has braces in value" {
    const allocator = std.testing.allocator;
    // The parameter value contains {hello} which extractJsonObject will pick up,
    // but parseToolCallJson will fail — function-tag should still be tried as fallback
    const response =
        \\<tool_call>
        \\<function=shell><parameter=command>echo {hello}</parameter></function>
        \\</tool_call>
    ;
    const result = try parseXmlToolCalls(allocator, response);
    defer {
        if (result.text.len > 0) allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
    }
    try std.testing.expectEqual(@as(usize, 1), result.calls.len);
    try std.testing.expectEqualStrings("shell", result.calls[0].name);
    try std.testing.expect(std.mem.indexOf(u8, result.calls[0].arguments_json, "echo {hello}") != null);
}

// ── buildAssistantHistoryWithToolCalls tests ─────────────────────

test "buildAssistantHistoryWithToolCalls with text and calls" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "shell", .arguments_json = "{\"command\":\"ls\"}" },
        .{ .name = "file_read", .arguments_json = "{\"path\":\"a.txt\"}" },
    };
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "Let me check that.",
        &calls,
    );
    defer allocator.free(result);

    // Should contain the response text
    try std.testing.expect(std.mem.indexOf(u8, result, "Let me check that.") != null);
    // Should contain tool_call XML tags
    try std.testing.expect(std.mem.indexOf(u8, result, "<tool_call>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "</tool_call>") != null);
    // Should contain tool names
    try std.testing.expect(std.mem.indexOf(u8, result, "\"shell\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"file_read\"") != null);
    // Should contain two tool_call tags
    var count: usize = 0;
    var search = result;
    while (std.mem.indexOf(u8, search, "<tool_call>")) |idx| {
        count += 1;
        search = search[idx + 11 ..];
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "buildAssistantHistoryWithToolCalls empty text" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "shell", .arguments_json = "{}" },
    };
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &calls,
    );
    defer allocator.free(result);

    // Should NOT start with a newline (no empty text prefix)
    try std.testing.expect(result[0] == '<');
    try std.testing.expect(std.mem.indexOf(u8, result, "<tool_call>") != null);
}

test "buildAssistantHistoryWithToolCalls no calls" {
    const allocator = std.testing.allocator;
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "Just text, no tools.",
        &.{},
    );
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Just text, no tools.\n", result);
}

test "buildAssistantHistoryWithToolCalls empty text and no calls" {
    const allocator = std.testing.allocator;
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &.{},
    );
    defer allocator.free(result);

    try std.testing.expectEqualStrings("", result);
}

test "buildAssistantHistoryWithToolCalls preserves arguments JSON" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "file_write", .arguments_json = "{\"path\":\"test.py\",\"content\":\"print('hello')\"}" },
    };
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &calls,
    );
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"file_write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "print('hello')") != null);
}

test "buildAssistantHistoryWithToolCalls escapes special chars in name" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "shell\"injection", .arguments_json = "{}" },
    };
    const result = try buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &calls,
    );
    defer allocator.free(result);

    // The name should be properly JSON-escaped, so the output must be valid JSON inside <tool_call>
    // Find the JSON between <tool_call> tags
    const tc_start = std.mem.indexOf(u8, result, "<tool_call>\n").?;
    const json_start = tc_start + "<tool_call>\n".len;
    const tc_end = std.mem.indexOf(u8, result[json_start..], "\n</tool_call>").?;
    const json_str = result[json_start .. json_start + tc_end];

    // Must be valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();
    const name = parsed.value.object.get("name").?.string;
    try std.testing.expectEqualStrings("shell\"injection", name);
}
