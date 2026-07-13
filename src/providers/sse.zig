const std = @import("std");
const std_compat = @import("compat");
const root = @import("root.zig");
const http_util = @import("../http_util.zig");
const error_classify = @import("error_classify.zig");
const verbose = @import("../verbose.zig");
const log = std.log.scoped(.provider_sse);

var curl_fail_fast_arg_mutex: std_compat.sync.Mutex = .{};
var curl_fail_with_body_supported_cache: ?bool = null;
const stream_stall_detection_args = [_][]const u8{
    "--speed-limit",
    "1",
    "--speed-time",
    "60",
};

fn finalizeStreamResult(
    allocator: std.mem.Allocator,
    accumulated: []const u8,
    stream_usage: ?root.TokenUsage,
    tool_call_accumulators: ?*const ToolCallAccumulators,
) !root.StreamChatResult {
    var result = root.StreamChatResult{};
    errdefer result.deinit(allocator);

    if (accumulated.len > 0) {
        const split = try root.splitThinkContent(allocator, accumulated);
        result.content = split.visible;
        result.reasoning_content = split.reasoning;
    }
    if (tool_call_accumulators) |accumulators| {
        result.tool_calls = try accumulators.toOwnedToolCalls(allocator);
    }

    var usage = stream_usage orelse root.TokenUsage{};
    if (usage.completion_tokens == 0) {
        const tool_bytes = if (tool_call_accumulators) |accumulators|
            accumulators.estimatedOutputBytes()
        else
            0;
        usage.completion_tokens = @intCast((accumulated.len +| tool_bytes +| 3) / 4);
    }
    if (usage.total_tokens == 0 and (usage.prompt_tokens > 0 or usage.completion_tokens > 0)) {
        usage.total_tokens = usage.prompt_tokens +| usage.completion_tokens;
    }
    result.usage = usage;
    return result;
}

fn parseCurlVersionComponent(component: []const u8) ?u32 {
    var end: usize = 0;
    while (end < component.len and std.ascii.isDigit(component[end])) : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(u32, component[0..end], 10) catch null;
}

fn parseCurlVersionTriplet(version_line: []const u8) ?[3]u32 {
    const prefix = "curl ";
    if (!std.mem.startsWith(u8, version_line, prefix)) return null;

    const version_tail = version_line[prefix.len..];
    const version_end = std.mem.indexOfScalar(u8, version_tail, ' ') orelse version_tail.len;
    const version_token = version_tail[0..version_end];

    var parts = std.mem.splitScalar(u8, version_token, '.');
    const major = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    const minor = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    const patch = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    return .{ major, minor, patch };
}

fn curlVersionSupportsFailWithBody(version_line: []const u8) bool {
    const version = parseCurlVersionTriplet(version_line) orelse return false;
    if (version[0] != 7) return version[0] > 7;
    if (version[1] != 76) return version[1] > 76;
    return version[2] >= 0;
}

fn detectCurlFailWithBodySupport(allocator: std.mem.Allocator) bool {
    const result = std_compat.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "curl", "--version" },
        .max_output_bytes = 1024,
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return false,
        else => return false,
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \n\r\t");
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    return curlVersionSupportsFailWithBody(line_it.first());
}

/// Prefer `--fail-with-body` so JSON API errors remain classifiable, but fall
/// back to `-f` on curl releases older than 7.76.0 where the newer flag fails.
pub fn curlFailFastArg(allocator: std.mem.Allocator) []const u8 {
    curl_fail_fast_arg_mutex.lock();
    defer curl_fail_fast_arg_mutex.unlock();

    if (curl_fail_with_body_supported_cache == null) {
        curl_fail_with_body_supported_cache = detectCurlFailWithBodySupport(allocator);
    }

    return if (curl_fail_with_body_supported_cache.?) "--fail-with-body" else "-f";
}

pub fn appendCurlStallDetectionArgs(argv_buf: [][]const u8, argc: *usize) void {
    for (stream_stall_detection_args) |arg| {
        argv_buf[argc.*] = arg;
        argc.* += 1;
    }
}

fn appendCurlTimeoutArgs(
    argv_buf: [][]const u8,
    argc: *usize,
    timeout_buf: []u8,
    timeout_secs: u64,
) void {
    if (timeout_secs == 0) return;
    const timeout_str = std.fmt.bufPrint(timeout_buf, "{d}", .{timeout_secs}) catch unreachable;
    argv_buf[argc.*] = "--max-time";
    argc.* += 1;
    argv_buf[argc.*] = timeout_str;
    argc.* += 1;
}

/// Content delta from an SSE chunk.
pub const DeltaContent = union(enum) {
    text: []const u8,
    reasoning: []const u8,

    pub fn deinit(self: DeltaContent, allocator: std.mem.Allocator) void {
        switch (self) {
            .text => |t| allocator.free(t),
            .reasoning => |r| allocator.free(r),
        }
    }
};

const MAX_STREAM_TOOL_CALLS: usize = 128;

/// One fragmented OpenAI-compatible tool-call update from an SSE chunk.
const ToolCallDelta = struct {
    index: usize,
    id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    arguments: ?[]const u8 = null,

    fn deinit(self: ToolCallDelta, allocator: std.mem.Allocator) void {
        if (self.id) |id| allocator.free(id);
        if (self.name) |name| allocator.free(name);
        if (self.arguments) |arguments| allocator.free(arguments);
    }
};

fn deinitToolCallDeltas(allocator: std.mem.Allocator, deltas: []const ToolCallDelta) void {
    for (deltas) |delta| delta.deinit(allocator);
    if (deltas.len > 0) allocator.free(deltas);
}

const ToolCallAccumulator = struct {
    index: usize,
    id: std.ArrayListUnmanaged(u8) = .empty,
    name: std.ArrayListUnmanaged(u8) = .empty,
    arguments: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *ToolCallAccumulator, allocator: std.mem.Allocator) void {
        self.id.deinit(allocator);
        self.name.deinit(allocator);
        self.arguments.deinit(allocator);
    }
};

const ToolCallAccumulators = struct {
    entries: std.ArrayListUnmanaged(ToolCallAccumulator) = .empty,

    fn deinit(self: *ToolCallAccumulators, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*entry| entry.deinit(allocator);
        self.entries.deinit(allocator);
    }

    fn getOrCreate(
        self: *ToolCallAccumulators,
        allocator: std.mem.Allocator,
        index: usize,
    ) !*ToolCallAccumulator {
        var insert_at: usize = 0;
        while (insert_at < self.entries.items.len and self.entries.items[insert_at].index < index) : (insert_at += 1) {}
        if (insert_at < self.entries.items.len and self.entries.items[insert_at].index == index) {
            return &self.entries.items[insert_at];
        }
        if (self.entries.items.len >= MAX_STREAM_TOOL_CALLS) return error.TooManyStreamToolCalls;
        try self.entries.insert(allocator, insert_at, .{ .index = index });
        return &self.entries.items[insert_at];
    }

    fn appendDelta(
        self: *ToolCallAccumulators,
        allocator: std.mem.Allocator,
        delta: ToolCallDelta,
    ) !void {
        const entry = try self.getOrCreate(allocator, delta.index);
        if (delta.id) |id| try entry.id.appendSlice(allocator, id);
        if (delta.name) |name| try entry.name.appendSlice(allocator, name);
        if (delta.arguments) |arguments| try entry.arguments.appendSlice(allocator, arguments);
    }

    fn estimatedOutputBytes(self: *const ToolCallAccumulators) usize {
        var total: usize = 0;
        for (self.entries.items) |entry| {
            total +|= entry.id.items.len;
            total +|= entry.name.items.len;
            total +|= entry.arguments.items.len;
        }
        return total;
    }

    fn toOwnedToolCalls(
        self: *const ToolCallAccumulators,
        allocator: std.mem.Allocator,
    ) ![]const root.ToolCall {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.name.items.len > 0) count += 1;
        }
        if (count == 0) return &.{};

        const tool_calls = try allocator.alloc(root.ToolCall, count);
        var initialized: usize = 0;
        errdefer {
            for (tool_calls[0..initialized]) |tool_call| {
                if (tool_call.id.len > 0) allocator.free(tool_call.id);
                allocator.free(tool_call.name);
                allocator.free(tool_call.arguments);
            }
            allocator.free(tool_calls);
        }

        for (self.entries.items) |entry| {
            if (entry.name.items.len == 0) continue;
            const id: []const u8 = if (entry.id.items.len > 0)
                try allocator.dupe(u8, entry.id.items)
            else
                "";
            errdefer if (id.len > 0) allocator.free(id);
            const name = try allocator.dupe(u8, entry.name.items);
            errdefer allocator.free(name);
            const arguments = try allocator.dupe(
                u8,
                if (entry.arguments.items.len > 0) entry.arguments.items else "{}",
            );
            tool_calls[initialized] = .{
                .id = id,
                .name = name,
                .arguments = arguments,
            };
            initialized += 1;
        }
        return tool_calls;
    }
};

fn toolCallStreamIsConfirmed(
    finish_reason: OpenAiFinishReason,
    has_tool_call_fragments: bool,
    had_invalid_data: bool,
) bool {
    // A truncated native call is executable data, not display-only partial
    // text. `[DONE]` alone is insufficient because it is also emitted after
    // finish_reason=length; require the explicit tool_calls finish reason.
    return !has_tool_call_fragments or (!had_invalid_data and finish_reason == .tool_calls);
}

fn shouldRecoverPartialStreamSafely(
    accumulated_len: usize,
    saw_done: bool,
    finish_reason: OpenAiFinishReason,
    has_tool_call_fragments: bool,
    had_invalid_data: bool,
    saw_stream_error: bool,
) bool {
    if (saw_stream_error) return false;
    if (has_tool_call_fragments) return !had_invalid_data and finish_reason == .tool_calls;
    return root.shouldRecoverPartialStream(accumulated_len, saw_done);
}

const OpenAiFinishReason = enum {
    none,
    tool_calls,
    length,
    other,
};

const OpenAiSseEvent = struct {
    content: ?DeltaContent = null,
    tool_call_deltas: []const ToolCallDelta = &.{},
    usage: ?root.TokenUsage = null,
    finish_reason: OpenAiFinishReason = .none,
    api_error: bool = false,

    fn deinit(self: *OpenAiSseEvent, allocator: std.mem.Allocator) void {
        if (self.content) |content| content.deinit(allocator);
        deinitToolCallDeltas(allocator, self.tool_call_deltas);
        self.* = .{};
    }

    fn hasPayload(self: OpenAiSseEvent) bool {
        return self.content != null or
            self.tool_call_deltas.len > 0 or
            self.usage != null or
            self.finish_reason != .none or
            self.api_error;
    }
};

/// Result of parsing a single SSE line.
pub const SseLineResult = union(enum) {
    /// Text or reasoning delta content (owned, caller frees).
    delta: DeltaContent,
    /// Stream is complete ([DONE] sentinel).
    done: void,
    /// Token usage from a stream chunk.
    usage: root.TokenUsage,
    /// Line should be skipped (empty, comment, or no content).
    skip: void,
};

const OpenAiSseLineResult = union(enum) {
    event: OpenAiSseEvent,
    done: void,
    skip: void,
};

const THINK_OPEN_TAG = "<think>";
const THINK_CLOSE_TAG = "</think>";

fn closeReasoningBlock(
    allocator: std.mem.Allocator,
    accumulated: *std.ArrayListUnmanaged(u8),
    in_reasoning: *bool,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !void {
    if (!in_reasoning.*) return;
    in_reasoning.* = false;
    try accumulated.appendSlice(allocator, THINK_CLOSE_TAG);
    callback(ctx, root.StreamChunk.textDelta(THINK_CLOSE_TAG));
}

fn appendDeltaContent(
    allocator: std.mem.Allocator,
    accumulated: *std.ArrayListUnmanaged(u8),
    in_reasoning: *bool,
    callback: root.StreamCallback,
    ctx: *anyopaque,
    content: DeltaContent,
) !void {
    switch (content) {
        .text => |text| {
            try closeReasoningBlock(allocator, accumulated, in_reasoning, callback, ctx);
            try accumulated.appendSlice(allocator, text);
            callback(ctx, root.StreamChunk.textDelta(text));
        },
        .reasoning => |reasoning| {
            if (!in_reasoning.*) {
                in_reasoning.* = true;
                try accumulated.appendSlice(allocator, THINK_OPEN_TAG);
                callback(ctx, root.StreamChunk.textDelta(THINK_OPEN_TAG));
            }
            try accumulated.appendSlice(allocator, reasoning);
            callback(ctx, root.StreamChunk.textDelta(reasoning));
        },
    }
}

fn applyOpenAiStreamEvent(
    allocator: std.mem.Allocator,
    event_value: OpenAiSseEvent,
    accumulated: *std.ArrayListUnmanaged(u8),
    in_reasoning: *bool,
    tool_call_accumulators: *ToolCallAccumulators,
    stream_usage: *?root.TokenUsage,
    finish_reason: *OpenAiFinishReason,
    saw_stream_error: *bool,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !void {
    var event = event_value;
    defer event.deinit(allocator);

    if (event.content) |content| {
        try appendDeltaContent(allocator, accumulated, in_reasoning, callback, ctx, content);
    }
    for (event.tool_call_deltas) |delta| {
        try tool_call_accumulators.appendDelta(allocator, delta);
    }
    if (event.usage) |usage| stream_usage.* = usage;
    if (event.finish_reason != .none) finish_reason.* = event.finish_reason;
    if (event.api_error) saw_stream_error.* = true;
}

/// Parse a single SSE line in OpenAI streaming format.
///
/// Handles:
/// - `data: [DONE]` → `.done`
/// - `data: {JSON}` → extracts text/reasoning and fragmented native tool calls
/// - Empty lines, comments (`:`) → `.skip`
fn parseOpenAiSseLine(allocator: std.mem.Allocator, line: []const u8) !OpenAiSseLineResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // SSE uses "data:" with an optional single leading space before the value.
    const prefix = "data:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return .skip;

    const data = if (trimmed.len > prefix.len and trimmed[prefix.len] == ' ')
        trimmed[prefix.len + 1 ..]
    else
        trimmed[prefix.len..];

    if (data.len == 0) return .skip;

    if (std.mem.eql(u8, data, "[DONE]")) return .done;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    var event = OpenAiSseEvent{};
    errdefer event.deinit(allocator);
    event.content = try extractDeltaContentFromValue(allocator, parsed.value);
    event.tool_call_deltas = try extractToolCallDeltasFromValue(allocator, parsed.value);
    event.usage = extractStreamUsageFromValue(parsed.value);
    event.finish_reason = extractOpenAiFinishReason(parsed.value);
    if (parsed.value == .object) {
        if (parsed.value.object.get("error")) |error_value| {
            // OpenAI-compatible APIs sometimes include `"error": null` in a
            // successful envelope. Only a concrete error payload terminates
            // the stream.
            event.api_error = error_value != .null;
        }
    }
    if (!event.hasPayload()) return .skip;
    return .{ .event = event };
}

/// Parse one OpenAI-compatible SSE line using the legacy public result shape.
/// Rich tool-call and terminal metadata is consumed by curlStream internally.
pub fn parseSseLine(allocator: std.mem.Allocator, line: []const u8) !SseLineResult {
    const parsed = try parseOpenAiSseLine(allocator, line);
    return switch (parsed) {
        .event => |event_value| blk: {
            var event = event_value;
            if (event.content) |content| {
                event.content = null;
                event.deinit(allocator);
                break :blk .{ .delta = content };
            }
            if (event.usage) |usage| {
                event.deinit(allocator);
                break :blk .{ .usage = usage };
            }
            event.deinit(allocator);
            break :blk .skip;
        },
        .done => .done,
        .skip => .skip,
    };
}

fn parseToolCallDelta(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    fallback_index: usize,
) !?ToolCallDelta {
    if (value != .object) return null;
    const obj = value.object;

    const index = if (obj.get("index")) |index_value| switch (index_value) {
        .integer => |raw| if (raw >= 0) std.math.cast(usize, raw) orelse return null else return null,
        else => return null,
    } else fallback_index;

    const id_source: ?[]const u8 = if (obj.get("id")) |id_value|
        if (id_value == .string and id_value.string.len > 0) id_value.string else null
    else
        null;

    var name_source: ?[]const u8 = null;
    var arguments_source: ?[]const u8 = null;
    if (obj.get("function")) |function_value| {
        if (function_value == .object) {
            if (function_value.object.get("name")) |name_value| {
                if (name_value == .string and name_value.string.len > 0) name_source = name_value.string;
            }
            if (function_value.object.get("arguments")) |arguments_value| {
                if (arguments_value == .string and arguments_value.string.len > 0) arguments_source = arguments_value.string;
            }
        }
    }

    if (id_source == null and name_source == null and arguments_source == null) return null;

    var result = ToolCallDelta{ .index = index };
    errdefer result.deinit(allocator);
    if (id_source) |id| result.id = try allocator.dupe(u8, id);
    if (name_source) |name| result.name = try allocator.dupe(u8, name);
    if (arguments_source) |arguments| result.arguments = try allocator.dupe(u8, arguments);
    return result;
}

/// Extract OpenAI-compatible `choices[0].delta.tool_calls` fragments.
fn extractToolCallDeltas(
    allocator: std.mem.Allocator,
    json_str: []const u8,
) ![]const ToolCallDelta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    return extractToolCallDeltasFromValue(allocator, parsed.value);
}

fn extractToolCallDeltasFromValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) ![]const ToolCallDelta {
    if (value != .object) return &.{};
    const choices = value.object.get("choices") orelse return &.{};
    if (choices != .array or choices.array.items.len == 0) return &.{};
    const first = choices.array.items[0];
    if (first != .object) return &.{};
    const delta = first.object.get("delta") orelse return &.{};
    if (delta != .object) return &.{};
    const tool_calls = delta.object.get("tool_calls") orelse return &.{};
    if (tool_calls != .array or tool_calls.array.items.len == 0) return &.{};

    var result: std.ArrayListUnmanaged(ToolCallDelta) = .empty;
    errdefer {
        for (result.items) |item| item.deinit(allocator);
        result.deinit(allocator);
    }
    for (tool_calls.array.items, 0..) |item, fallback_index| {
        const parsed_delta = try parseToolCallDelta(allocator, item, fallback_index) orelse continue;
        result.append(allocator, parsed_delta) catch |err| {
            parsed_delta.deinit(allocator);
            return err;
        };
    }
    if (result.items.len == 0) {
        result.deinit(allocator);
        return &.{};
    }
    return try result.toOwnedSlice(allocator);
}

fn extractOpenAiFinishReason(value: std.json.Value) OpenAiFinishReason {
    if (value != .object) return .none;
    const choices = value.object.get("choices") orelse return .none;
    if (choices != .array or choices.array.items.len == 0) return .none;
    const first = choices.array.items[0];
    if (first != .object) return .none;
    const finish_reason = first.object.get("finish_reason") orelse return .none;
    if (finish_reason == .null) return .none;
    if (finish_reason != .string) return .other;
    if (std.mem.eql(u8, finish_reason.string, "tool_calls")) return .tool_calls;
    if (std.mem.eql(u8, finish_reason.string, "length")) return .length;
    return .other;
}

/// Extract `usage` object from an OpenAI-compatible streaming chunk.
/// The final chunk typically has `choices:[]` and a top-level `usage` object.
/// OpenAI usage chunks may contain nested objects (prompt_tokens_details,
/// completion_tokens_details) so we use a generous 32 KB stack buffer.
fn tokenCountFromJsonValue(value: std.json.Value) ?u32 {
    return switch (value) {
        .integer => |raw| if (raw <= 0)
            0
        else
            std.math.cast(u32, raw) orelse std.math.maxInt(u32),
        .float => |raw| if (std.math.isNan(raw) or raw <= 0)
            0
        else if (!std.math.isFinite(raw) or raw >= @as(f64, @floatFromInt(std.math.maxInt(u32))))
            std.math.maxInt(u32)
        else
            @intFromFloat(raw),
        else => null,
    };
}

fn extractStreamUsage(json_str: []const u8) ?root.TokenUsage {
    // 32 KB is sufficient for OpenAI's nested usage objects.
    var buf: [32 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, json_str, .{}) catch
        return null;
    defer parsed.deinit();

    return extractStreamUsageFromValue(parsed.value);
}

fn extractStreamUsageFromValue(value: std.json.Value) ?root.TokenUsage {
    if (value != .object) return null;
    const obj = value.object;
    const usage_val = obj.get("usage") orelse return null;
    if (usage_val != .object) return null;

    var usage = root.TokenUsage{};
    // Handle prompt_tokens (OpenAI) or input_tokens (Anthropic/some compatible)
    const prompt_val = usage_val.object.get("prompt_tokens") orelse
        usage_val.object.get("input_tokens");
    if (prompt_val) |v| {
        usage.prompt_tokens = tokenCountFromJsonValue(v) orelse 0;
    }

    const completion_val = usage_val.object.get("completion_tokens") orelse
        usage_val.object.get("output_tokens");
    if (completion_val) |v| {
        usage.completion_tokens = tokenCountFromJsonValue(v) orelse 0;
    }

    if (usage_val.object.get("total_tokens")) |v| {
        usage.total_tokens = tokenCountFromJsonValue(v) orelse 0;
    } else {
        usage.total_tokens = usage.prompt_tokens +| usage.completion_tokens;
    }

    // Require at least one non-zero field to treat this as a valid usage chunk.
    // This guards against "usage":null being coerced into a zero struct.
    if (usage.prompt_tokens == 0 and usage.completion_tokens == 0 and usage.total_tokens == 0) {
        return null;
    }

    return usage;
}

/// Extract visible streaming text or reasoning from an SSE JSON payload.
/// Returns owned DeltaContent or null if no content found.
pub fn extractDeltaContent(allocator: std.mem.Allocator, json_str: []const u8) !?DeltaContent {
    if (verbose.isVerbose()) {
        // NOTE: No unit test for this log path; it depends on global verbose
        // logging state. Keep payload bytes out of logs because SSE chunks can
        // contain user prompts, tool results, or model output.
        log.debug("SSE JSON payload received: len={d}", .{json_str.len});
    }

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (verbose.isVerbose()) log.err("Failed to parse SSE JSON payload: len={d} error={s}", .{ json_str.len, @errorName(err) });
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    return extractDeltaContentFromValue(allocator, parsed.value);
}

fn extractDeltaContentFromValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?DeltaContent {
    if (value != .object) return null;
    const obj = value.object;
    const choices = obj.get("choices") orelse return null;
    if (choices != .array or choices.array.items.len == 0) return null;

    const first = choices.array.items[0];
    if (first != .object) return null;

    const delta = first.object.get("delta") orelse return null;
    if (delta != .object) return null;

    // Check content first, but only if not empty
    if (delta.object.get("content")) |content| {
        if (content == .string and content.string.len > 0) {
            return .{ .text = try allocator.dupe(u8, content.string) };
        }
    }

    // Fallback to various reasoning fields
    const reasoning_keys = [_][]const u8{ "reasoning", "reasoning_content", "reasoning_details" };
    for (reasoning_keys) |key| {
        if (delta.object.get(key)) |val| {
            if (val == .string and val.string.len > 0) {
                return .{ .reasoning = try allocator.dupe(u8, val.string) };
            }
            if (std.mem.eql(u8, key, "reasoning_details") and val == .array) {
                if (try root.extractReasoningTextFromDetails(allocator, val)) |text| {
                    return .{ .reasoning = text };
                }
            }
        }
    }

    return null;
}

/// Run curl in SSE streaming mode and parse output line by line.
///
/// Spawns `curl -s --no-buffer` with the strongest supported fail-fast flag:
/// `--fail-with-body` on curl >= 7.76.0, otherwise `-f`.
/// For each SSE delta, calls `callback(ctx, chunk)`.
/// Returns accumulated result after stream completes.
pub fn curlStream(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_header: ?[]const u8,
    extra_headers: []const []const u8,
    timeout_secs: u64,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    // Check verbose mode once at function start
    const log_enabled = verbose.isVerbose();
    const debug_log = std.log.scoped(.sse);

    // Build argv on stack (max 40 args)
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--no-buffer";
    argc += 1;
    argv_buf[argc] = curlFailFastArg(allocator);
    argc += 1;

    var timeout_buf: [32]u8 = undefined;
    appendCurlTimeoutArgs(argv_buf[0..], &argc, &timeout_buf, timeout_secs);

    // Kill the curl process if transfer rate drops below 1 byte/second for 60 seconds.
    // This catches providers that open the SSE connection but stall mid-stream without
    // hitting the --max-time wall (e.g. glm-5 on infini-ai hanging on large contexts).
    appendCurlStallDetectionArgs(argv_buf[0..], &argc);

    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;

    // Add proxy from environment if set
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);
    http_util.appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    var header_buf: [16][]const u8 = undefined;
    var header_count: usize = 0;
    header_buf[header_count] = "Content-Type: application/json";
    header_count += 1;
    if (auth_header) |auth| {
        if (header_count >= header_buf.len) return error.TooManyHeaders;
        header_buf[header_count] = auth;
        header_count += 1;
    }

    for (extra_headers) |hdr| {
        if (header_count >= header_buf.len) return error.TooManyHeaders;
        header_buf[header_count] = hdr;
        header_count += 1;
    }

    var prepared_headers = try http_util.prepareCurlHeaderArg(allocator, header_buf[0..header_count]);
    defer prepared_headers.deinit(allocator);
    if (prepared_headers.arg) |headers_arg| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = headers_arg;
        argc += 1;
    }

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = "@-";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    if (log_enabled) {
        debug_log.info("curl argc={d}, body_len={d}, header_file={}", .{ argc, body.len, prepared_headers.uses_temp_file });
    }

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    if (log_enabled) {
        debug_log.info("spawning curl process...", .{});
    }
    try child.spawn();
    var child_reaped = false;
    errdefer if (!child_reaped) {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    };
    if (log_enabled) {
        const pid: i64 = if (@import("builtin").os.tag == .windows) @intCast(@intFromPtr(child.id)) else child.id;
        debug_log.info("curl process spawned, pid={d}", .{pid});
    }

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(body) catch {
            stdin_file.close();
            child.stdin = null;
            return error.CurlWriteError;
        };
        stdin_file.close();
        child.stdin = null;
    } else {
        return error.CurlWriteError;
    }

    // Read stdout line by line, parse SSE events
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var tool_call_accumulators = ToolCallAccumulators{};
    defer tool_call_accumulators.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    const stdout_file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var saw_done = false;
    var total_stdout: usize = 0;
    var stream_usage: ?root.TokenUsage = null;
    var finish_reason: OpenAiFinishReason = .none;
    var had_invalid_data = false;
    var saw_stream_error = false;
    var in_reasoning = false;

    outer: while (true) {
        const n = stdout_file.read(&read_buf) catch |err| {
            if (log_enabled) {
                debug_log.info("stdout read error: {}", .{err});
            }
            break;
        };
        if (n == 0) {
            if (log_enabled) {
                debug_log.info("stdout read returned 0 bytes (EOF)", .{});
            }
            break;
        }
        total_stdout += n;

        if (log_enabled) {
            debug_log.info("stdout read {d} bytes", .{n});
        }

        // Check if this is JSON (starts with '{')
        if (total_stdout == n and read_buf[0] == '{') {
            if (log_enabled) {
                debug_log.info("Detected JSON response, not SSE", .{});
            }
            // This is a JSON error, not SSE
            const json_response = try allocator.dupe(u8, read_buf[0..n]);
            defer allocator.free(json_response);

            // Try to classify the error
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_response, .{}) catch null;
            if (parsed) |p| {
                defer p.deinit();
                if (error_classify.classifyKnownApiError(p.value.object)) |kind| {
                    _ = child.wait() catch {};
                    child_reaped = true;
                    return error_classify.kindToError(kind);
                }
            }

            // Return a meaningful error
            _ = child.wait() catch {};
            child_reaped = true;
            debug_log.err("Server returned JSON error payload: len={d}", .{json_response.len});
            return error.ServerError;
        }

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                if (log_enabled) {
                    debug_log.info("parsing SSE line: len={d}", .{line_buf.items.len});
                }
                const result = parseOpenAiSseLine(allocator, line_buf.items) catch |err| {
                    line_buf.clearRetainingCapacity();
                    if (err == error.OutOfMemory) return err;
                    had_invalid_data = true;
                    continue;
                };
                line_buf.clearRetainingCapacity();
                switch (result) {
                    .event => |event| try applyOpenAiStreamEvent(
                        allocator,
                        event,
                        &accumulated,
                        &in_reasoning,
                        &tool_call_accumulators,
                        &stream_usage,
                        &finish_reason,
                        &saw_stream_error,
                        callback,
                        ctx,
                    ),
                    .done => {
                        if (log_enabled) {
                            debug_log.info("SSE stream done", .{});
                        }
                        saw_done = true;
                        break :outer;
                    },
                    .skip => {},
                }
            } else {
                try line_buf.append(allocator, byte);
            }
        }
    }

    if (log_enabled) {
        debug_log.info("stdout stream ended, saw_done={}, accumulated_len={d}, total_stdout={d}", .{ saw_done, accumulated.items.len, total_stdout });
    }

    // Parse a trailing line when the stream ends without a final '\n'.
    if (!saw_done and line_buf.items.len > 0) {
        const trailing = parseOpenAiSseLine(allocator, line_buf.items) catch |err| blk: {
            if (err == error.OutOfMemory) return err;
            had_invalid_data = true;
            break :blk null;
        };
        line_buf.clearRetainingCapacity();
        if (trailing) |result| {
            switch (result) {
                .event => |event| try applyOpenAiStreamEvent(
                    allocator,
                    event,
                    &accumulated,
                    &in_reasoning,
                    &tool_call_accumulators,
                    &stream_usage,
                    &finish_reason,
                    &saw_stream_error,
                    callback,
                    ctx,
                ),
                .done => saw_done = true,
                .skip => {},
            }
        }
    }

    // Drain remaining stdout to prevent deadlock on wait()
    while (true) {
        const n = stdout_file.read(&read_buf) catch break;
        if (n == 0) break;
        if (log_enabled) {
            debug_log.info("drained {d} more stdout bytes", .{n});
        }
    }

    if (log_enabled) {
        debug_log.info("waiting for curl process to exit...", .{});
    }
    const term = child.wait() catch |err| {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        child_reaped = true;
        log.err("curlStream child.wait failed: {}", .{err});
        if (shouldRecoverPartialStreamSafely(accumulated.items.len, saw_done, finish_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
            log.warn("curlStream proceeding despite wait failure after partial stream output", .{});
            try closeReasoningBlock(allocator, &accumulated, &in_reasoning, callback, ctx);
            callback(ctx, root.StreamChunk.finalChunk());
            return finalizeStreamResult(allocator, accumulated.items, stream_usage, &tool_call_accumulators);
        }
        return error.CurlWaitError;
    };
    child_reaped = true;
    if (log_enabled) {
        debug_log.info("curl process terminated: {}", .{term});
    }
    switch (term) {
        .exited => |code| if (code != 0) {
            if (shouldRecoverPartialStreamSafely(accumulated.items.len, saw_done, finish_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
                log.warn("curlStream exit code {d} after partial stream output; returning accumulated output", .{code});
                try closeReasoningBlock(allocator, &accumulated, &in_reasoning, callback, ctx);
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, stream_usage, &tool_call_accumulators);
            }
            return error.CurlFailed;
        },
        else => {
            if (shouldRecoverPartialStreamSafely(accumulated.items.len, saw_done, finish_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
                log.warn("curlStream abnormal termination after partial stream output; returning accumulated output", .{});
                try closeReasoningBlock(allocator, &accumulated, &in_reasoning, callback, ctx);
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, stream_usage, &tool_call_accumulators);
            }
            return error.CurlFailed;
        },
    }

    if (saw_stream_error or !toolCallStreamIsConfirmed(finish_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data)) {
        return error.CurlFailed;
    }

    // Signal stream completion only after curl exits successfully.
    try closeReasoningBlock(allocator, &accumulated, &in_reasoning, callback, ctx);
    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, stream_usage, &tool_call_accumulators);
}

// ════════════════════════════════════════════════════════════════════════════
// Anthropic SSE Parsing
// ════════════════════════════════════════════════════════════════════════════

const AnthropicStopReason = enum {
    none,
    tool_use,
    max_tokens,
    other,
};

const AnthropicMessageDelta = struct {
    usage: ?u32 = null,
    stop_reason: AnthropicStopReason = .none,
};

fn anthropicToolCallStreamIsConfirmed(
    stop_reason: AnthropicStopReason,
    has_tool_call_fragments: bool,
    had_invalid_data: bool,
) bool {
    return !has_tool_call_fragments or (!had_invalid_data and stop_reason == .tool_use);
}

fn shouldRecoverAnthropicPartialStreamSafely(
    accumulated_len: usize,
    saw_done: bool,
    stop_reason: AnthropicStopReason,
    has_tool_call_fragments: bool,
    had_invalid_data: bool,
    saw_stream_error: bool,
) bool {
    if (saw_stream_error) return false;
    if (has_tool_call_fragments) return !had_invalid_data and stop_reason == .tool_use;
    return root.shouldRecoverPartialStream(accumulated_len, saw_done);
}

/// Result of parsing a single Anthropic SSE line.
pub const AnthropicSseResult = union(enum) {
    /// Remember this event type (caller tracks state).
    event: []const u8,
    /// Text delta content (owned, caller frees).
    delta: []const u8,
    /// Output token count from message_delta usage.
    usage: u32,
    /// Stream is complete (message_stop).
    done: void,
    /// Line should be skipped (empty, comment, or uninteresting event).
    skip: void,
};

const AnthropicStreamResult = union(enum) {
    event: []const u8,
    delta: []const u8,
    tool_call_start: ToolCallDelta,
    tool_call_delta: ToolCallDelta,
    message_delta: AnthropicMessageDelta,
    done: void,
    stream_error: void,
    skip: void,
};

/// Parse a single SSE line in Anthropic streaming format.
///
/// Anthropic SSE is stateful: `event:` lines set the context for subsequent `data:` lines.
/// The caller must track `current_event` across calls.
///
/// - `event: X` → `.event` (caller remembers X)
/// - `data: {JSON}` + current_event=="content_block_delta" → extracts `delta.text` → `.delta`
/// - `content_block_start`/`input_json_delta` → native tool-call fragments
/// - `data: {JSON}` + current_event=="message_delta" → extracts `usage.output_tokens` → `.usage`
/// - `data: {JSON}` + current_event=="message_stop" → `.done`
/// - Everything else → `.skip`
fn parseAnthropicStreamLine(allocator: std.mem.Allocator, line: []const u8, current_event: []const u8) !AnthropicStreamResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // Handle "event: TYPE" lines
    const event_prefix = "event: ";
    if (std.mem.startsWith(u8, trimmed, event_prefix)) {
        return .{ .event = trimmed[event_prefix.len..] };
    }

    // Handle "data: {JSON}" lines
    const data_prefix = "data: ";
    if (!std.mem.startsWith(u8, trimmed, data_prefix)) return .skip;

    const data = trimmed[data_prefix.len..];

    if (std.mem.eql(u8, current_event, "message_stop")) return .done;
    if (std.mem.eql(u8, current_event, "error")) return .stream_error;

    if (std.mem.eql(u8, current_event, "content_block_start")) {
        const start = try extractAnthropicToolCallStart(allocator, data) orelse return .skip;
        return .{ .tool_call_start = start };
    }

    if (std.mem.eql(u8, current_event, "content_block_delta")) {
        return extractAnthropicContentBlockDelta(allocator, data);
    }

    if (std.mem.eql(u8, current_event, "message_delta")) {
        const message_delta = try extractAnthropicMessageDelta(allocator, data);
        if (message_delta.usage == null and message_delta.stop_reason == .none) return .skip;
        return .{ .message_delta = message_delta };
    }

    return .skip;
}

/// Parse an Anthropic SSE line using the original public result variants.
/// Structured tool-call and terminal metadata remains internal to the curl
/// streaming implementation.
pub fn parseAnthropicSseLine(allocator: std.mem.Allocator, line: []const u8, current_event: []const u8) !AnthropicSseResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");
    if (trimmed.len == 0 or trimmed[0] == ':') return .skip;

    const event_prefix = "event: ";
    if (std.mem.startsWith(u8, trimmed, event_prefix)) {
        return .{ .event = trimmed[event_prefix.len..] };
    }

    const data_prefix = "data: ";
    if (!std.mem.startsWith(u8, trimmed, data_prefix)) return .skip;
    const data = trimmed[data_prefix.len..];

    if (std.mem.eql(u8, current_event, "message_stop")) return .done;
    if (std.mem.eql(u8, current_event, "content_block_delta")) {
        const text = try extractAnthropicDelta(allocator, data) orelse return .skip;
        return .{ .delta = text };
    }
    if (std.mem.eql(u8, current_event, "message_delta")) {
        const usage = try extractAnthropicUsage(data) orelse return .skip;
        return .{ .usage = usage };
    }
    return .skip;
}

fn extractNonNegativeIndex(obj: std.json.ObjectMap) ?usize {
    const index_value = obj.get("index") orelse return null;
    if (index_value != .integer or index_value.integer < 0) return null;
    return std.math.cast(usize, index_value.integer);
}

/// Parse an Anthropic `content_block_start` event for a client tool call.
fn extractAnthropicToolCallStart(
    allocator: std.mem.Allocator,
    json_str: []const u8,
) !?ToolCallDelta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const index = extractNonNegativeIndex(parsed.value.object) orelse return null;
    const content_block = parsed.value.object.get("content_block") orelse return null;
    if (content_block != .object) return null;
    const block_type = content_block.object.get("type") orelse return null;
    if (block_type != .string or !std.mem.eql(u8, block_type.string, "tool_use")) return null;
    const id_value = content_block.object.get("id") orelse return null;
    const name_value = content_block.object.get("name") orelse return null;
    if (id_value != .string or name_value != .string or name_value.string.len == 0) return null;

    var result = ToolCallDelta{ .index = index };
    errdefer result.deinit(allocator);
    if (id_value.string.len > 0) result.id = try allocator.dupe(u8, id_value.string);
    result.name = try allocator.dupe(u8, name_value.string);
    return result;
}

/// Parse an Anthropic `input_json_delta` fragment.
fn extractAnthropicToolCallDelta(
    allocator: std.mem.Allocator,
    json_str: []const u8,
) !?ToolCallDelta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    return extractAnthropicToolCallDeltaFromValue(allocator, parsed.value);
}

fn extractAnthropicToolCallDeltaFromValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?ToolCallDelta {
    if (value != .object) return null;
    const index = extractNonNegativeIndex(value.object) orelse return null;
    const delta = value.object.get("delta") orelse return null;
    if (delta != .object) return null;
    const delta_type = delta.object.get("type") orelse return null;
    if (delta_type != .string or !std.mem.eql(u8, delta_type.string, "input_json_delta")) return null;
    const partial_json = delta.object.get("partial_json") orelse return null;
    if (partial_json != .string or partial_json.string.len == 0) return null;

    return .{
        .index = index,
        .arguments = try allocator.dupe(u8, partial_json.string),
    };
}

/// Extract `delta.text` from an Anthropic content_block_delta JSON payload.
/// Returns owned slice or null if not a text_delta.
pub fn extractAnthropicDelta(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    return extractAnthropicDeltaFromValue(allocator, parsed.value);
}

fn extractAnthropicDeltaFromValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !?[]const u8 {
    if (value != .object) return null;
    const obj = value.object;
    const delta = obj.get("delta") orelse return null;
    if (delta != .object) return null;

    const dtype = delta.object.get("type") orelse return null;
    if (dtype != .string or !std.mem.eql(u8, dtype.string, "text_delta")) return null;

    const text = delta.object.get("text") orelse return null;
    if (text != .string) return null;
    if (text.string.len == 0) return null;

    return try allocator.dupe(u8, text.string);
}

fn extractAnthropicContentBlockDelta(
    allocator: std.mem.Allocator,
    json_str: []const u8,
) !AnthropicStreamResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();

    if (try extractAnthropicDeltaFromValue(allocator, parsed.value)) |text| {
        return .{ .delta = text };
    }
    const delta = try extractAnthropicToolCallDeltaFromValue(allocator, parsed.value) orelse return .skip;
    return .{ .tool_call_delta = delta };
}

fn extractAnthropicMessageDelta(
    allocator: std.mem.Allocator,
    json_str: []const u8,
) !AnthropicMessageDelta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidSseJson;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return .{};

    const obj = parsed.value.object;
    var result = AnthropicMessageDelta{};
    if (obj.get("usage")) |usage| {
        if (usage == .object) {
            if (usage.object.get("output_tokens")) |output_tokens| {
                if (output_tokens == .integer) {
                    result.usage = std.math.cast(u32, output_tokens.integer);
                }
            }
        }
    }
    if (obj.get("delta")) |delta| {
        if (delta == .object) {
            if (delta.object.get("stop_reason")) |stop_reason| {
                if (stop_reason == .string) {
                    result.stop_reason = if (std.mem.eql(u8, stop_reason.string, "tool_use"))
                        .tool_use
                    else if (std.mem.eql(u8, stop_reason.string, "max_tokens"))
                        .max_tokens
                    else
                        .other;
                }
            }
        }
    }
    return result;
}

/// Extract `usage.output_tokens` from an Anthropic message_delta JSON payload.
/// Returns token count or null if not present.
pub fn extractAnthropicUsage(json_str: []const u8) !?u32 {
    // Use a stack buffer for parsing to avoid needing an allocator
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    if (parsed.value != .object) return null;
    const obj = parsed.value.object;
    const usage = obj.get("usage") orelse return null;
    if (usage != .object) return null;

    const output_tokens = usage.object.get("output_tokens") orelse return null;
    if (output_tokens != .integer) return null;

    return std.math.cast(u32, output_tokens.integer);
}

/// Run curl in SSE streaming mode for Anthropic and parse output line by line.
///
/// Similar to `curlStream()` but uses stateful Anthropic SSE parsing.
/// `headers` is a slice of pre-formatted header strings (e.g. "x-api-key: sk-...").
pub fn curlStreamAnthropicTimed(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    timeout_secs: u64,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    // Build argv on stack (max 40 args)
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--no-buffer";
    argc += 1;
    argv_buf[argc] = curlFailFastArg(allocator);
    argc += 1;

    var timeout_buf: [32]u8 = undefined;
    appendCurlTimeoutArgs(argv_buf[0..], &argc, &timeout_buf, timeout_secs);
    appendCurlStallDetectionArgs(argv_buf[0..], &argc);

    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;

    // Add proxy from environment if set
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);
    http_util.appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    var header_buf: [16][]const u8 = undefined;
    var header_count: usize = 0;
    header_buf[header_count] = "Content-Type: application/json";
    header_count += 1;
    for (headers) |hdr| {
        if (header_count >= header_buf.len) return error.TooManyHeaders;
        header_buf[header_count] = hdr;
        header_count += 1;
    }

    var prepared_headers = try http_util.prepareCurlHeaderArg(allocator, header_buf[0..header_count]);
    defer prepared_headers.deinit(allocator);
    if (prepared_headers.arg) |headers_arg| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = headers_arg;
        argc += 1;
    }

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = "@-";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    var child_reaped = false;
    errdefer if (!child_reaped) {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    };

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(body) catch {
            stdin_file.close();
            child.stdin = null;
            return error.CurlWriteError;
        };
        stdin_file.close();
        child.stdin = null;
    } else {
        return error.CurlWriteError;
    }

    // Read stdout line by line, parse Anthropic SSE events
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var tool_call_accumulators = ToolCallAccumulators{};
    defer tool_call_accumulators.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    var current_event: []const u8 = "";
    defer if (current_event.len > 0) allocator.free(@constCast(current_event));
    var anthropic_usage: root.TokenUsage = .{};
    var saw_done = false;
    var stop_reason: AnthropicStopReason = .none;
    var had_invalid_data = false;
    var saw_stream_error = false;

    const file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;

    outer: while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                const result = parseAnthropicStreamLine(allocator, line_buf.items, current_event) catch |err| {
                    line_buf.clearRetainingCapacity();
                    if (err == error.OutOfMemory) return err;
                    had_invalid_data = true;
                    continue;
                };
                switch (result) {
                    .event => |ev| {
                        // Dupe event name — it points into line_buf which we're about to clear
                        if (current_event.len > 0) {
                            allocator.free(@constCast(current_event));
                            current_event = "";
                        }
                        current_event = try allocator.dupe(u8, ev);
                    },
                    .delta => |text| {
                        defer allocator.free(text);
                        try accumulated.appendSlice(allocator, text);
                        callback(ctx, root.StreamChunk.textDelta(text));
                    },
                    .tool_call_start, .tool_call_delta => |delta| {
                        defer delta.deinit(allocator);
                        try tool_call_accumulators.appendDelta(allocator, delta);
                    },
                    .message_delta => |message_delta| {
                        if (message_delta.usage) |tokens| anthropic_usage.completion_tokens = tokens;
                        if (message_delta.stop_reason != .none) stop_reason = message_delta.stop_reason;
                    },
                    .done => {
                        saw_done = true;
                        line_buf.clearRetainingCapacity();
                        break :outer;
                    },
                    .stream_error => saw_stream_error = true,
                    .skip => {},
                }
                line_buf.clearRetainingCapacity();
            } else {
                try line_buf.append(allocator, byte);
            }
        }
    }

    // Parse a trailing line when the stream ends without a final newline.
    if (!saw_done and line_buf.items.len > 0) {
        const trailing = parseAnthropicStreamLine(allocator, line_buf.items, current_event) catch |err| blk: {
            if (err == error.OutOfMemory) return err;
            had_invalid_data = true;
            break :blk null;
        };
        line_buf.clearRetainingCapacity();
        if (trailing) |result| switch (result) {
            .event => {},
            .delta => |text| {
                defer allocator.free(text);
                try accumulated.appendSlice(allocator, text);
                callback(ctx, root.StreamChunk.textDelta(text));
            },
            .tool_call_start, .tool_call_delta => |delta| {
                defer delta.deinit(allocator);
                try tool_call_accumulators.appendDelta(allocator, delta);
            },
            .message_delta => |message_delta| {
                if (message_delta.usage) |tokens| anthropic_usage.completion_tokens = tokens;
                if (message_delta.stop_reason != .none) stop_reason = message_delta.stop_reason;
            },
            .done => saw_done = true,
            .stream_error => saw_stream_error = true,
            .skip => {},
        };
    }

    // Drain remaining stdout to prevent deadlock on wait()
    while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;
    }

    const term = child.wait() catch |err| {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        child_reaped = true;
        log.err("curlStreamAnthropic child.wait failed: {}", .{err});
        if (shouldRecoverAnthropicPartialStreamSafely(accumulated.items.len, saw_done, stop_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
            log.warn("curlStreamAnthropic proceeding despite wait failure after partial stream output", .{});
            callback(ctx, root.StreamChunk.finalChunk());
            return finalizeStreamResult(allocator, accumulated.items, anthropic_usage, &tool_call_accumulators);
        }
        return error.CurlWaitError;
    };
    child_reaped = true;
    switch (term) {
        .exited => |code| if (code != 0) {
            if (shouldRecoverAnthropicPartialStreamSafely(accumulated.items.len, saw_done, stop_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
                log.warn("curlStreamAnthropic exit code {d} after partial stream output; returning accumulated output", .{code});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, anthropic_usage, &tool_call_accumulators);
            }
            return error.CurlFailed;
        },
        else => {
            if (shouldRecoverAnthropicPartialStreamSafely(accumulated.items.len, saw_done, stop_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data, saw_stream_error)) {
                log.warn("curlStreamAnthropic abnormal termination after partial stream output; returning accumulated output", .{});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, anthropic_usage, &tool_call_accumulators);
            }
            return error.CurlFailed;
        },
    }

    if (saw_stream_error or !anthropicToolCallStreamIsConfirmed(stop_reason, tool_call_accumulators.entries.items.len > 0, had_invalid_data)) {
        return error.CurlFailed;
    }

    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, anthropic_usage, &tool_call_accumulators);
}

/// Backward-compatible Anthropic streaming entry point without an explicit
/// timeout. New callers should use curlStreamAnthropicTimed.
pub fn curlStreamAnthropic(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    return curlStreamAnthropicTimed(allocator, url, body, headers, 0, callback, ctx);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseSseLine valid delta" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |delta| {
            defer delta.deinit(allocator);
            try std.testing.expectEqualStrings("Hello", delta.text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine valid delta without optional space" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data:{\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |delta| {
            defer delta.deinit(allocator);
            try std.testing.expectEqualStrings("Hello", delta.text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine returns text and native tool fields from one chunk" {
    // Regression: providers may emit visible content and the first tool-call
    // fragment together; neither side of the chunk may be discarded.
    const allocator = std.testing.allocator;
    const line = "data: {\"choices\":[{\"delta\":{\"content\":\"Calling tool\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"weather\",\"arguments\":\"{}\"}}]}}]}";
    const result = try parseOpenAiSseLine(allocator, line);
    switch (result) {
        .event => |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            try std.testing.expectEqualStrings("Calling tool", event.content.?.text);
            try std.testing.expectEqual(@as(usize, 1), event.tool_call_deltas.len);
            try std.testing.expectEqualStrings("call_1", event.tool_call_deltas[0].id.?);
            try std.testing.expectEqualStrings("weather", event.tool_call_deltas[0].name.?);
            try std.testing.expectEqualStrings("{}", event.tool_call_deltas[0].arguments.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine exposes terminal tool reason and streamed API errors" {
    const allocator = std.testing.allocator;
    const finished = try parseOpenAiSseLine(
        allocator,
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}",
    );
    switch (finished) {
        .event => |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            try std.testing.expect(event.finish_reason == .tool_calls);
        },
        else => return error.TestUnexpectedResult,
    }

    const api_error = try parseOpenAiSseLine(
        allocator,
        "data: {\"error\":{\"message\":\"stream failed\"}}",
    );
    switch (api_error) {
        .event => |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            try std.testing.expect(event.api_error);
        },
        else => return error.TestUnexpectedResult,
    }

    // Regression: compatible APIs may include an explicit null error field in
    // otherwise successful streaming envelopes.
    const null_error = try parseOpenAiSseLine(
        allocator,
        "data: {\"error\":null,\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}",
    );
    switch (null_error) {
        .event => |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            try std.testing.expect(!event.api_error);
            try std.testing.expectEqualStrings("ok", event.content.?.text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "OpenAI streaming tool call fragments accumulate by index" {
    // Regression: Chat Completions and vLLM split function arguments across
    // multiple delta.tool_calls chunks.
    const allocator = std.testing.allocator;
    const lines = [_][]const u8{
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"weather\",\"arguments\":\"\"}}]}}]}",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\"}}]}}]}",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Paris\\\"}\"}}]}}]}",
    };

    var accumulators = ToolCallAccumulators{};
    defer accumulators.deinit(allocator);
    for (lines) |line| {
        const parsed = try parseOpenAiSseLine(allocator, line);
        switch (parsed) {
            .event => |event_value| {
                var event = event_value;
                defer event.deinit(allocator);
                for (event.tool_call_deltas) |delta| try accumulators.appendDelta(allocator, delta);
            },
            else => return error.TestUnexpectedResult,
        }
    }

    var result = try finalizeStreamResult(allocator, "", null, &accumulators);
    defer result.deinit(allocator);
    try std.testing.expect(result.content == null);
    try std.testing.expectEqual(@as(usize, 1), result.tool_calls.len);
    try std.testing.expectEqualStrings("call_1", result.tool_calls[0].id);
    try std.testing.expectEqualStrings("weather", result.tool_calls[0].name);
    try std.testing.expectEqualStrings("{\"city\":\"Paris\"}", result.tool_calls[0].arguments);
    try std.testing.expect(result.usage.completion_tokens > 0);
}

test "partial stream recovery rejects unconfirmed native tool calls" {
    // Regression: a premature EOF must never turn a truncated function name
    // or argument fragment into an executable call.
    try std.testing.expect(!shouldRecoverPartialStreamSafely(0, false, .none, true, false, false));
    try std.testing.expect(!shouldRecoverPartialStreamSafely(12, true, .length, true, false, false));
    try std.testing.expect(shouldRecoverPartialStreamSafely(0, false, .tool_calls, true, false, false));
    try std.testing.expect(!shouldRecoverPartialStreamSafely(0, true, .tool_calls, true, true, false));
    try std.testing.expect(shouldRecoverPartialStreamSafely(12, false, .none, false, true, false));
    try std.testing.expect(!toolCallStreamIsConfirmed(.length, true, false));
    try std.testing.expect(!toolCallStreamIsConfirmed(.tool_calls, true, true));
    try std.testing.expect(toolCallStreamIsConfirmed(.tool_calls, true, false));
}

fn streamingToolCallAllocationTest(allocator: std.mem.Allocator) !void {
    var accumulators = ToolCallAccumulators{};
    defer accumulators.deinit(allocator);
    const line = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"weather\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}]}}]}";
    const parsed = try parseOpenAiSseLine(allocator, line);
    switch (parsed) {
        .event => |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            for (event.tool_call_deltas) |delta| try accumulators.appendDelta(allocator, delta);
        },
        else => return error.TestUnexpectedResult,
    }
    var result = try finalizeStreamResult(allocator, "", null, &accumulators);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), result.tool_calls.len);
}

test "streaming tool call allocation failures do not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, streamingToolCallAllocationTest, .{});
}

test "appendCurlStallDetectionArgs appends curl speed flags in order" {
    // Regression: stalled SSE streams must trip curl's speed-limit instead of
    // hanging until --max-time expires with an idle-but-open connection.
    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;
    appendCurlStallDetectionArgs(argv_buf[0..], &argc);

    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("--speed-limit", argv_buf[0]);
    try std.testing.expectEqualStrings("1", argv_buf[1]);
    try std.testing.expectEqualStrings("--speed-time", argv_buf[2]);
    try std.testing.expectEqualStrings("60", argv_buf[3]);
}

test "appendCurlTimeoutArgs preserves configured stream timeout" {
    var argv_buf: [4][]const u8 = undefined;
    var timeout_buf: [32]u8 = undefined;
    var argc: usize = 0;
    appendCurlTimeoutArgs(argv_buf[0..], &argc, &timeout_buf, 42);
    try std.testing.expectEqual(@as(usize, 2), argc);
    try std.testing.expectEqualStrings("--max-time", argv_buf[0]);
    try std.testing.expectEqualStrings("42", argv_buf[1]);

    argc = 0;
    appendCurlTimeoutArgs(argv_buf[0..], &argc, &timeout_buf, 0);
    try std.testing.expectEqual(@as(usize, 0), argc);
}

test "parseSseLine DONE sentinel" {
    const result = try parseSseLine(std.testing.allocator, "data: [DONE]");
    try std.testing.expect(result == .done);
}

test "parseSseLine DONE sentinel without optional space" {
    const result = try parseSseLine(std.testing.allocator, "data:[DONE]");
    try std.testing.expect(result == .done);
}

test "curlVersionSupportsFailWithBody rejects curl older than 7.76.0" {
    try std.testing.expect(!curlVersionSupportsFailWithBody("curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0"));
}

test "curlVersionSupportsFailWithBody accepts curl 7.76.0 and newer" {
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 7.76.0 (x86_64-pc-linux-gnu) libcurl/7.76.0"));
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 8.17.0 (x86_64-alpine-linux-musl) libcurl/8.17.0"));
}

test "curlVersionSupportsFailWithBody tolerates suffixes in version token" {
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 8.17.0-DEV (x86_64) libcurl/8.17.0"));
}

test "parseSseLine empty line" {
    const result = try parseSseLine(std.testing.allocator, "");
    try std.testing.expect(result == .skip);
}

test "parseSseLine comment" {
    const result = try parseSseLine(std.testing.allocator, ":keep-alive");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty data field" {
    const result = try parseSseLine(std.testing.allocator, "data:");
    try std.testing.expect(result == .skip);
}

test "parseSseLine delta without content" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[{\"delta\":{}}]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty choices" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine invalid JSON" {
    try std.testing.expectError(error.InvalidSseJson, parseSseLine(std.testing.allocator, "data: not-json{{{"));
}

test "extractDeltaContent with content" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"world\"}}]}")).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("world", d.text);
}

test "extractDeltaContent without content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent ignores non-object JSON" {
    // Regression: provider-controlled JSON must not reach `.object` on a
    // non-object value and panic the streaming process.
    try std.testing.expect((try extractDeltaContent(std.testing.allocator, "[]")) == null);
}

test "extractDeltaContent empty content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent falls back to reasoning_content when content empty" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"\",\"reasoning_content\":\"step by step\"}}]}")).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("step by step", d.reasoning);
}

// Regression: OpenRouter's documented chat stream uses delta.reasoning.
test "extractDeltaContent falls back to reasoning when content missing" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning\":\"step by step\"}}]}")).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("step by step", d.reasoning);
}

test "extractDeltaContent falls back to reasoning_content when content missing" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"step by step\"}}]}")).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("step by step", d.reasoning);
}

// Regression: OpenRouter's current normalized streaming shape uses reasoning_details.
test "extractDeltaContent falls back to reasoning_details when content missing" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(
        allocator,
        "{\"choices\":[{\"delta\":{\"reasoning_details\":[{\"type\":\"reasoning.summary\",\"summary\":\"plan\"},{\"type\":\"reasoning.text\",\"text\":\"step by step\"}]}}]}",
    )).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("plan\nstep by step", d.reasoning);
}

test "extractDeltaContent prefers visible content over reasoning_content" {
    const allocator = std.testing.allocator;
    const d = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"final answer\",\"reasoning_content\":\"private\"}}]}")).?;
    defer d.deinit(allocator);
    try std.testing.expectEqualStrings("final answer", d.text);
}

test "appendDeltaContent closes reasoning before final" {
    const Collector = struct {
        buf: std.ArrayListUnmanaged(u8) = .empty,
        saw_final: bool = false,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.saw_final = true;
                return;
            }
            self.buf.appendSlice(std.testing.allocator, chunk.delta) catch unreachable;
        }
    };

    const allocator = std.testing.allocator;
    var collector = Collector{};
    defer collector.buf.deinit(allocator);
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var in_reasoning = false;
    const content = DeltaContent{ .reasoning = try allocator.dupe(u8, "private") };
    defer content.deinit(allocator);

    try appendDeltaContent(allocator, &accumulated, &in_reasoning, Collector.callback, @ptrCast(&collector), content);
    try closeReasoningBlock(allocator, &accumulated, &in_reasoning, Collector.callback, @ptrCast(&collector));
    Collector.callback(@ptrCast(&collector), root.StreamChunk.finalChunk());

    try std.testing.expect(collector.saw_final);
    try std.testing.expect(!in_reasoning);
    try std.testing.expectEqualStrings("<think>private</think>", accumulated.items);
    try std.testing.expectEqualStrings("<think>private</think>", collector.buf.items);
}

test "extractDeltaContent empty reasoning_content returns null" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "StreamChunk textDelta token estimate" {
    const chunk = root.StreamChunk.textDelta("12345678");
    try std.testing.expect(chunk.token_count == 2);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqualStrings("12345678", chunk.delta);
}

test "StreamChunk finalChunk" {
    const chunk = root.StreamChunk.finalChunk();
    try std.testing.expect(chunk.is_final);
    try std.testing.expectEqualStrings("", chunk.delta);
    try std.testing.expect(chunk.token_count == 0);
}

// ── Anthropic SSE Tests ─────────────────────────────────────────

test "parseAnthropicSseLine event line returns event" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "event: content_block_delta", "");
    switch (result) {
        .event => |ev| try std.testing.expectEqualStrings("content_block_delta", ev),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with content_block_delta returns delta" {
    const allocator = std.testing.allocator;
    const json = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}";
    const result = try parseAnthropicSseLine(allocator, json, "content_block_delta");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Anthropic streaming tool_use fragments become a native tool call" {
    // Regression: tool_use metadata arrives in content_block_start while its
    // arguments arrive later as fragmented input_json_delta events.
    const allocator = std.testing.allocator;
    const start_line = "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"weather\",\"input\":{}}}";
    const delta_lines = [_][]const u8{
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"Paris\\\"}\"}}",
    };

    var accumulators = ToolCallAccumulators{};
    defer accumulators.deinit(allocator);

    const start = try parseAnthropicStreamLine(allocator, start_line, "content_block_start");
    switch (start) {
        .tool_call_start => |delta| {
            defer delta.deinit(allocator);
            try accumulators.appendDelta(allocator, delta);
        },
        else => return error.TestUnexpectedResult,
    }
    for (delta_lines) |line| {
        const parsed = try parseAnthropicStreamLine(allocator, line, "content_block_delta");
        switch (parsed) {
            .tool_call_delta => |delta| {
                defer delta.deinit(allocator);
                try accumulators.appendDelta(allocator, delta);
            },
            else => return error.TestUnexpectedResult,
        }
    }

    var result = try finalizeStreamResult(allocator, "", null, &accumulators);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), result.tool_calls.len);
    try std.testing.expectEqualStrings("toolu_1", result.tool_calls[0].id);
    try std.testing.expectEqualStrings("weather", result.tool_calls[0].name);
    try std.testing.expectEqualStrings("{\"city\":\"Paris\"}", result.tool_calls[0].arguments);
}

test "Anthropic empty tool input defaults to empty JSON object" {
    const allocator = std.testing.allocator;
    const line = "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_empty\",\"name\":\"ping\",\"input\":{}}}";
    const parsed = try parseAnthropicStreamLine(allocator, line, "content_block_start");
    var accumulators = ToolCallAccumulators{};
    defer accumulators.deinit(allocator);
    switch (parsed) {
        .tool_call_start => |delta| {
            defer delta.deinit(allocator);
            try accumulators.appendDelta(allocator, delta);
        },
        else => return error.TestUnexpectedResult,
    }

    var result = try finalizeStreamResult(allocator, "", null, &accumulators);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("{}", result.tool_calls[0].arguments);
}

test "parseAnthropicSseLine data with message_delta returns usage" {
    const json = "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":42}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_delta");
    switch (result) {
        .usage => |usage| try std.testing.expect(usage == 42),
        else => return error.TestUnexpectedResult,
    }
}

test "Anthropic tool stream rejects max_tokens termination" {
    // Regression: message_stop also follows max_tokens, where partial_json may
    // be truncated and must never become an executable tool call.
    try std.testing.expect(!anthropicToolCallStreamIsConfirmed(.max_tokens, true, false));
    try std.testing.expect(!anthropicToolCallStreamIsConfirmed(.tool_use, true, true));
    try std.testing.expect(anthropicToolCallStreamIsConfirmed(.tool_use, true, false));

    const json = "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":42}}";
    const result = try parseAnthropicStreamLine(std.testing.allocator, json, "message_delta");
    switch (result) {
        .message_delta => |message_delta| try std.testing.expect(message_delta.stop_reason == .max_tokens),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with message_stop returns done" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "data: {\"type\":\"message_stop\"}", "message_stop");
    try std.testing.expect(result == .done);
}

test "parseAnthropicSseLine surfaces HTTP-200 stream errors" {
    const result = try parseAnthropicStreamLine(
        std.testing.allocator,
        "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}",
        "error",
    );
    try std.testing.expect(result == .stream_error);
}

test "parseAnthropicSseLine empty line returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine comment returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, ":keep-alive", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine data with unknown event returns skip" {
    const json = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\"}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_start");
    try std.testing.expect(result == .skip);
}

test "extractAnthropicDelta correct JSON returns text" {
    const allocator = std.testing.allocator;
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}";
    const result = (try extractAnthropicDelta(allocator, json)).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("world", result);
}

test "extractAnthropicDelta without text returns null" {
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}";
    const result = try extractAnthropicDelta(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "extractAnthropicDelta ignores non-object JSON" {
    try std.testing.expect((try extractAnthropicDelta(std.testing.allocator, "[]")) == null);
}

test "extractAnthropicUsage correct JSON returns token count" {
    const json = "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":57}}";
    const result = (try extractAnthropicUsage(json)).?;
    try std.testing.expect(result == 57);
}

test "extractAnthropicUsage rejects out-of-range token counts" {
    try std.testing.expect((try extractAnthropicUsage("{\"usage\":{\"output_tokens\":-1}}")) == null);
    try std.testing.expect((try extractAnthropicUsage("{\"usage\":{\"output_tokens\":4294967296}}")) == null);
}

test "extractAnthropicUsage ignores non-object JSON" {
    // Regression: provider-controlled usage events must not select `.object`
    // on a different JSON union tag.
    try std.testing.expect((try extractAnthropicUsage("[]")) == null);
    try std.testing.expect((try extractAnthropicUsage("null")) == null);
}

// ── Stream Usage Extraction Tests ───────────────────────────────

test "extractStreamUsage returns full usage from final chunk" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":263,\"total_tokens\":363}}";
    const usage = extractStreamUsage(json).?;
    try std.testing.expectEqual(@as(u32, 100), usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 263), usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 363), usage.total_tokens);
}

test "extractStreamUsage returns null for chunk without usage" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}";
    try std.testing.expect(extractStreamUsage(json) == null);
}

test "extractStreamUsage returns null for invalid JSON" {
    try std.testing.expect(extractStreamUsage("not-json{{{") == null);
}

test "extractStreamUsage clamps provider-controlled token counts" {
    const json = "{\"usage\":{\"prompt_tokens\":9223372036854775807,\"completion_tokens\":1e40}}";
    const usage = extractStreamUsage(json).?;
    try std.testing.expectEqual(std.math.maxInt(u32), usage.prompt_tokens);
    try std.testing.expectEqual(std.math.maxInt(u32), usage.completion_tokens);
    try std.testing.expectEqual(std.math.maxInt(u32), usage.total_tokens);
}

test "finalizeStreamResult separates think blocks into reasoning content" {
    var result = try finalizeStreamResult(
        std.testing.allocator,
        "<think>private trace</think>Visible answer",
        .{ .completion_tokens = 4, .total_tokens = 4 },
        null,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expectEqualStrings("private trace", result.reasoning_content.?);
}

test "parseSseLine extracts usage from final chunk" {
    const allocator = std.testing.allocator;
    const line = "data: {\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":20,\"total_tokens\":70}}";
    const result = try parseSseLine(allocator, line);
    switch (result) {
        .usage => |u| {
            try std.testing.expectEqual(@as(u32, 50), u.prompt_tokens);
            try std.testing.expectEqual(@as(u32, 20), u.completion_tokens);
            try std.testing.expectEqual(@as(u32, 70), u.total_tokens);
        },
        else => return error.TestUnexpectedResult,
    }
}

// Regression: OpenAI usage chunks contain nested objects (prompt_tokens_details,
// completion_tokens_details) that exceeded the old 4096-byte FixedBufferAllocator,
// silently returning null from extractStreamUsage and causing prompt_tokens=0.
test "parseSseLine extracts usage from OpenAI nested usage chunk" {
    const allocator = std.testing.allocator;
    const line = "data: {\"id\":\"chatcmpl-De08d\",\"object\":\"chat.completion.chunk\"," ++
        "\"created\":1778426023,\"model\":\"gpt-4o-2024-08-06\"," ++
        "\"service_tier\":\"default\",\"system_fingerprint\":\"fp_5acb5510d6\"," ++
        "\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":9,\"total_tokens\":18," ++
        "\"prompt_tokens_details\":{\"cached_tokens\":0,\"audio_tokens\":0}," ++
        "\"completion_tokens_details\":{\"reasoning_tokens\":0,\"audio_tokens\":0," ++
        "\"accepted_prediction_tokens\":0,\"rejected_prediction_tokens\":0}}}";
    const result = try parseSseLine(allocator, line);
    switch (result) {
        .usage => |u| {
            try std.testing.expectEqual(@as(u32, 9), u.prompt_tokens);
            try std.testing.expectEqual(@as(u32, 9), u.completion_tokens);
            try std.testing.expectEqual(@as(u32, 18), u.total_tokens);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "extractStreamUsage returns null for null usage field" {
    // Intermediate OpenAI chunks have "usage":null — must not produce a zero struct.
    const json =
        \\{"id":"chatcmpl-abc","choices":[{"delta":{"content":"Hi"}}],"usage":null}
    ;
    try std.testing.expect(extractStreamUsage(json) == null);
}
