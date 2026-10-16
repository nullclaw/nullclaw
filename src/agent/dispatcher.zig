const std = @import("std");
const std_compat = @import("compat");
const json_util = @import("../json_util.zig");
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

/// Detect whether the response contains explicit tool-call markup tags.
/// Used by the agent loop to avoid leaking raw tool XML-like payloads to users
/// when parsing fails on malformed inner content.
pub fn containsToolCallMarkup(allocator: std.mem.Allocator, text: []const u8) bool {
    // Only the dispatcher's own unparsed markers are checked here. A legitimate
    // answer may discuss or quote XML `<function>`/`<parameter>` markup, or show
    // it in a code block, without containing a tool call; a false positive makes
    // `selectDisplayText` drop the whole reply. The one XML-`function` shape that
    // is never prose is a *run* of dangling closers — the runaway loop — and
    // even that is skipped inside a code sample.
    return std.mem.indexOf(u8, text, "<tool_call>") != null or
        std.mem.indexOf(u8, text, "</tool_call>") != null or
        std.mem.indexOf(u8, text, "[TOOL_CALL]") != null or
        std.mem.indexOf(u8, text, "[tool_call]") != null or
        std.mem.indexOf(u8, text, "[/TOOL_CALL]") != null or
        std.mem.indexOf(u8, text, "[/tool_call]") != null or
        providers.helpers.hasRepetitiveToolCloseRun(allocator, text);
}

fn freeParsedToolCall(allocator: std.mem.Allocator, call: ParsedToolCall) void {
    allocator.free(call.name);
    allocator.free(call.arguments_json);
    if (call.tool_call_id) |id| allocator.free(id);
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
/// Parse tool calls from an LLM response using XML-style `<tool_call>` tags.
///
/// The block scan and the inner-call parsers live in `providers.helpers`
/// (`parseDispatcherXmlToolCalls`), so the display paths (`streaming.TagFilter`,
/// `stripToolCallMarkup`) and the dispatcher decide "is this a text tool call"
/// with the *same* code. This wrapper only maps the shared result onto the
/// dispatcher's `ParsedToolCall` and strips trailing `<tool_result>` markup from
/// the visible text, exactly as the old in-file parser did.
pub fn parseXmlToolCalls(
    allocator: std.mem.Allocator,
    response: []const u8,
) !ParseResult {
    const shared = try providers.helpers.parseDispatcherXmlToolCalls(allocator, response);
    allocator.free(shared.blocks);

    // Map the shared calls onto the dispatcher's `ParsedToolCall` (the XML path
    // never carries a `tool_call_id`). Every step frees what the shared parse
    // handed over on failure, so no allocation-failure path leaks.
    const calls = allocator.alloc(ParsedToolCall, shared.calls.len) catch |err| {
        freeDispatcherCalls(allocator, shared.calls);
        allocator.free(shared.text);
        return err;
    };
    for (shared.calls, 0..) |call, idx| {
        calls[idx] = .{ .name = call.name, .arguments_json = call.arguments_json };
    }
    allocator.free(shared.calls);

    if (calls.len == 0) return .{ .text = shared.text, .calls = calls };

    const sanitized = stripToolResultMarkup(allocator, shared.text) catch |err| {
        for (calls) |call| freeParsedToolCall(allocator, call);
        allocator.free(calls);
        allocator.free(shared.text);
        return err;
    };
    allocator.free(shared.text);
    return .{ .text = sanitized, .calls = calls };
}

/// Free a slice of shared-parse calls: their owned strings and the slice itself.
fn freeDispatcherCalls(allocator: std.mem.Allocator, calls: []providers.DispatcherCall) void {
    for (calls) |call| {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    allocator.free(calls);
}

/// Format tool execution results as XML for the next LLM turn.
pub fn formatToolResults(allocator: std.mem.Allocator, results: []const ToolExecutionResult) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[Tool results]\n");
    for (results) |result| {
        const status_str = if (result.success) "ok" else "error";
        try buf.print(allocator, "<tool_result name=\"{s}\" status=\"{s}\">\n{s}\n</tool_result>\n", .{
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

        const name = try allocator.dupe(u8, tc.name);
        errdefer allocator.free(name);
        const arguments_json = try allocator.dupe(u8, tc.arguments);
        errdefer allocator.free(arguments_json);
        const tool_call_id = if (tc.id.len > 0) try allocator.dupe(u8, tc.id) else null;
        errdefer if (tool_call_id) |id| allocator.free(id);
        try calls.append(allocator, .{
            .name = name,
            .arguments_json = arguments_json,
            .tool_call_id = tool_call_id,
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
    const trimmed = std.mem.trimStart(u8, text, " \n\r\t");
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
    errdefer allocator.free(text);

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

        const name = try allocator.dupe(u8, name_str);
        errdefer allocator.free(name);
        const arguments_json = try allocator.dupe(u8, args_str);
        errdefer allocator.free(arguments_json);
        const tool_call_id = if (tc_id) |id| try allocator.dupe(u8, id) else null;
        errdefer if (tool_call_id) |id| allocator.free(id);
        try calls.append(allocator, .{
            .name = name,
            .arguments_json = arguments_json,
            .tool_call_id = tool_call_id,
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
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
    const w = &buf_writer.writer;

    try w.writeAll("[");
    for (results, 0..) |result, i| {
        if (i > 0) try w.writeAll(",");
        const tc_id = result.tool_call_id orelse "unknown";

        // Serialize content as a JSON string value
        try w.print("{{\"role\":\"tool\",\"tool_call_id\":{f},\"content\":{f}}}", .{
            std.json.fmt(tc_id, .{}),
            std.json.fmt(result.output, .{}),
        });
    }
    try w.writeAll("]");

    buf = buf_writer.toArrayList();
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
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
    const w = &buf_writer.writer;

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

    buf = buf_writer.toArrayList();
    return buf.toOwnedSlice(allocator);
}

/// Find the first JSON object `{...}` in a string, handling nesting. Shared
/// with the display paths via `json_util`, so the agent and the display locate
/// the same tool-call object.
pub const extractJsonObject = json_util.extractJsonObject;

/// JSON repair for LLM output (trailing commas, unbalanced braces/brackets,
/// unbalanced quotes). Shared with the display paths via `json_util`, so a text
/// tool call the agent executes is recognised by exactly the same repair.
pub const repairJson = json_util.repairJson;

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

fn parseXmlToolCallsForAllocationTest(allocator: std.mem.Allocator, response: []const u8) !void {
    const result = try parseXmlToolCalls(allocator, response);
    allocator.free(result.text);
    for (result.calls) |call| {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
        if (call.tool_call_id) |id| allocator.free(id);
    }
    allocator.free(result.calls);
}

test "parseXmlToolCalls frees parsed calls when an allocation fails" {
    const response =
        \\Let me check the disk layout first.
        \\<tool_call>
        \\{"name":"shell","arguments":{"command":"df -h"}}
        \\</tool_call>
        \\Then I will summarise.
    ;
    // Regression: a call that parsed successfully leaked its name and arguments
    // when a later allocation in the same parse failed (appending to the call
    // list, or assembling the remaining text), because only already-appended
    // calls were freed on the error path.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseXmlToolCallsForAllocationTest, .{response});
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
    const a = std.testing.allocator;
    try std.testing.expect(containsToolCallMarkup(a, "<tool_call>{}</tool_call>"));
    try std.testing.expect(containsToolCallMarkup(a, "[TOOL_CALL]{\"name\":\"shell\"}[/TOOL_CALL]"));
    try std.testing.expect(containsToolCallMarkup(a, "[tool_call]{\"name\":\"shell\"}[/tool_call]"));
    try std.testing.expect(!containsToolCallMarkup(a, "plain reply text"));
}

test "containsToolCallMarkup detects orphan closing tag" {
    const a = std.testing.allocator;
    // Model sometimes emits </tool_call> without an opener; must be suppressed.
    try std.testing.expect(containsToolCallMarkup(a, "Here are the results:\n</tool_call>\nSome reply"));
    try std.testing.expect(containsToolCallMarkup(a, "</tool_call>"));
    try std.testing.expect(containsToolCallMarkup(a, "Here are the results:\n[/TOOL_CALL]\nSome reply"));
    try std.testing.expect(containsToolCallMarkup(a, "[/tool_call]"));
    // A degenerate loop of XML `function` closers is tool markup too.
    try std.testing.expect(containsToolCallMarkup(a, "</function></function></function>"));
    try std.testing.expect(containsToolCallMarkup(a, "</function>\n</function>\n</function>"));
    // `</function_calls>` shares a prefix with `</function`; a run of it is
    // the same runaway and must be detected too.
    try std.testing.expect(containsToolCallMarkup(a, "</function_calls></function_calls></function_calls>"));
    try std.testing.expect(!containsToolCallMarkup(a, "a plain answer"));
    // Prose or a documented sample that merely names the XML `function`
    // dialect must not be mistaken for an unparsed call: dropping the reply for
    // it used to abort the turn with error.NoResponseContent.
    try std.testing.expect(!containsToolCallMarkup(a, "Use the `<function>` and `<parameter>` tags like this."));
    try std.testing.expect(!containsToolCallMarkup(a, "<function_calls><invoke name=\"shell\"></invoke></function_calls>"));
    try std.testing.expect(!containsToolCallMarkup(a, "a single </function> closer"));
    // Regression: a fenced sample with three closers blanked the whole reply
    // (containsToolCallMarkup returned true, so selectDisplayText returned ""),
    // which then aborted the turn with error.NoResponseContent.
    try std.testing.expect(!containsToolCallMarkup(a, "```xml\n</function></function></function>\n```"));
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

fn parseNativeToolCallsForAllocationTest(allocator: std.mem.Allocator) !void {
    const result = try parseNativeToolCalls(allocator, "{\"content\":\"text\",\"tool_calls\":[{\"id\":\"call_1\",\"function\":{\"name\":\"shell\",\"arguments\":\"{}\"}}]}");
    defer allocator.free(result.text);
    defer allocator.free(result.calls);
    for (result.calls) |call| freeParsedToolCall(allocator, call);
}
fn parseStructuredToolCallsForAllocationTest(allocator: std.mem.Allocator) !void {
    const calls = try parseStructuredToolCalls(allocator, &.{.{ .id = "call_1", .name = "shell", .arguments = "{}" }});
    defer allocator.free(calls);
    for (calls) |call| freeParsedToolCall(allocator, call);
}
test "dispatcher native parsing frees all allocations on failure" {
    // Regression: PR #1011's ownership fix also applies to native calls.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseNativeToolCallsForAllocationTest, .{});
}
test "dispatcher structured parsing frees all allocations on failure" {
    // Regression: PR #1011's ownership fix also applies to structured calls.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseStructuredToolCallsForAllocationTest, .{});
}
test "dispatcher unclosed XML recovery frees all allocations on failure" {
    // Regression: exercise both additional ownership-transfer sites in #1011.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseXmlToolCallsForAllocationTest, .{"before <tool_call>{\"name\":\"shell\",\"arguments\":{}}"});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseXmlToolCallsForAllocationTest, .{"before <tool_call>shell{}"});
}
