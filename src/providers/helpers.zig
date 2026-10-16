const std = @import("std");
const std_compat = @import("compat");
const json_util = @import("../json_util.zig");
const http_util = @import("../http_util.zig");
const root = @import("root.zig");
const ToolSpec = root.ToolSpec;

// ── Think-block parsing ───────────────────────────────────────────────────

const think_open_tag = "<think>";
const think_close_tag = "</think>";

/// Result of splitting a response text at <think>…</think> blocks.
pub const SplitThinkContent = struct {
    /// Text outside think blocks (the user-visible answer).
    visible: []const u8,
    /// Concatenated content of all think blocks, or null if none were present.
    reasoning: ?[]const u8,
};

fn scanThinkContent(
    allocator: std.mem.Allocator,
    text: []const u8,
    visible_out: *std.ArrayListUnmanaged(u8),
    reasoning_out: ?*std.ArrayListUnmanaged(u8),
) !void {
    var i: usize = 0;
    var depth: usize = 0;
    while (i < text.len) {
        if (std.mem.startsWith(u8, text[i..], think_open_tag)) {
            depth += 1;
            i += think_open_tag.len;
            continue;
        }
        if (std.mem.startsWith(u8, text[i..], think_close_tag)) {
            if (depth > 0) depth -= 1;
            i += think_close_tag.len;
            continue;
        }
        if (depth == 0) {
            try visible_out.append(allocator, text[i]);
        } else if (reasoning_out) |reasoning_buf| {
            try reasoning_buf.append(allocator, text[i]);
        }
        i += 1;
    }
}

/// Split `text` into visible content and reasoning extracted from <think>…</think> blocks.
/// Both returned slices are caller-owned (allocated with `allocator`).
pub fn splitThinkContent(allocator: std.mem.Allocator, text: []const u8) !SplitThinkContent {
    if (std.mem.indexOf(u8, text, think_open_tag) == null and std.mem.indexOf(u8, text, think_close_tag) == null) {
        return .{
            .visible = try allocator.dupe(u8, text),
            .reasoning = null,
        };
    }

    var visible_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer visible_buf.deinit(allocator);
    var reasoning_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer reasoning_buf.deinit(allocator);

    try scanThinkContent(allocator, text, &visible_buf, &reasoning_buf);

    const visible_trimmed = std.mem.trim(u8, visible_buf.items, " \t\r\n");
    const visible = try allocator.dupe(u8, visible_trimmed);
    errdefer allocator.free(visible);

    const reasoning_trimmed = std.mem.trim(u8, reasoning_buf.items, " \t\r\n");
    const reasoning = if (reasoning_trimmed.len > 0) try allocator.dupe(u8, reasoning_trimmed) else null;

    return .{ .visible = visible, .reasoning = reasoning };
}

/// Strip all <think>…</think> blocks from `text`. Returns caller-owned slice.
pub fn stripThinkBlocks(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (std.mem.indexOf(u8, text, think_open_tag) == null and std.mem.indexOf(u8, text, think_close_tag) == null) {
        return allocator.dupe(u8, text);
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try scanThinkContent(allocator, text, &out, null);

    const cleaned = try out.toOwnedSlice(allocator);
    const trimmed = std.mem.trim(u8, cleaned, " \t\r\n");
    if (trimmed.ptr == cleaned.ptr and trimmed.len == cleaned.len) return cleaned;
    defer allocator.free(cleaned);
    return allocator.dupe(u8, trimmed);
}

fn appendReasoningDetailText(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    detail: std.json.Value,
) !void {
    if (detail != .object) return;
    const obj = detail.object;

    if (obj.get("type")) |type_val| {
        if (type_val == .string and std.mem.eql(u8, type_val.string, "reasoning.encrypted")) return;
    }

    const text = blk: {
        if (obj.get("text")) |value| {
            if (value == .string and value.string.len > 0) break :blk value.string;
        }
        if (obj.get("summary")) |value| {
            if (value == .string and value.string.len > 0) break :blk value.string;
        }
        break :blk null;
    } orelse return;

    if (out.items.len > 0) try out.append(allocator, '\n');
    try out.appendSlice(allocator, text);
}

/// Extract plain-text reasoning from OpenRouter/OpenAI-style `reasoning_details`.
/// Encrypted detail variants are intentionally ignored.
pub fn extractReasoningTextFromDetails(allocator: std.mem.Allocator, details: std.json.Value) !?[]const u8 {
    if (details != .array) return null;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    for (details.array.items) |detail| {
        try appendReasoningDetailText(&out, allocator, detail);
    }

    const trimmed = std.mem.trim(u8, out.items, " \t\r\n");
    if (trimmed.len == 0) return null;
    const owned = try allocator.dupe(u8, trimmed);
    return owned;
}

/// Append OpenAI-compatible request extras:
/// - `user` sourced from the upstream session_id
/// - arbitrary top-level JSON fields from `extra_body_params`
///
/// `extra_body_params` is expected to be a compact JSON object string such as
/// `{"seed":123,"metadata":{"tier":"pro"}}`. Parsing happens at config-load
/// time; request builders only splice the already-validated object body.
pub fn appendOpenAiBodyExtraParams(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    session_id: ?[]const u8,
    extra_body_params: ?[]const u8,
) !void {
    if (session_id) |sid| {
        try buf.appendSlice(allocator, ",\"user\":");
        try json_util.appendJsonString(buf, allocator, sid);
    }

    if (extra_body_params) |extra| {
        const trimmed = std.mem.trim(u8, extra, " \t\r\n");
        if (trimmed.len < 2 or trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') return;

        const inner = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t\r\n");
        if (inner.len == 0) return;

        try buf.append(allocator, ',');
        try buf.appendSlice(allocator, inner);
    }
}

/// Check if a model name indicates an OpenAI reasoning model
/// (o1, o3, o4-mini, gpt-5*, codex-mini).
pub fn isReasoningModel(model: []const u8) bool {
    return std.mem.startsWith(u8, model, "gpt-5") or
        std.mem.startsWith(u8, model, "o1") or
        std.mem.startsWith(u8, model, "o3") or
        std.mem.startsWith(u8, model, "o4-mini") or
        std.mem.startsWith(u8, model, "codex-mini");
}

/// Append model-specific generation controls to a JSON request body buffer:
/// - non-reasoning: `temperature` + optional `max_tokens`
/// - reasoning + reasoning_effort=="none": `temperature` + `max_completion_tokens`
/// - reasoning (otherwise): `max_completion_tokens` only (no temperature)
/// Always emits normalized `reasoning_effort` when set on a reasoning model.
/// OpenAI-compatible reasoning values are normalized as:
/// - `minimal` -> `low`
/// - `xhigh` -> `high`
pub fn appendGenerationFields(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    temperature: f64,
    max_tokens: ?u32,
    reasoning_effort: ?[]const u8,
) !void {
    if (!isReasoningModel(model)) {
        // Non-reasoning model: temperature + max_tokens
        try buf.appendSlice(allocator, ",\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.FormatError;
        try buf.appendSlice(allocator, temp_str);

        if (max_tokens) |max_tok| {
            try buf.appendSlice(allocator, ",\"max_tokens\":");
            var max_buf: [16]u8 = undefined;
            const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tok}) catch return error.FormatError;
            try buf.appendSlice(allocator, max_str);
        }
        return;
    }

    const normalized_effort = normalizeOpenAiReasoningEffort(reasoning_effort);

    // Reasoning model: temperature only if reasoning_effort == "none"
    const effort_is_none = if (normalized_effort) |re| std.mem.eql(u8, re, "none") else false;
    if (effort_is_none) {
        try buf.appendSlice(allocator, ",\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.FormatError;
        try buf.appendSlice(allocator, temp_str);
    }

    // Reasoning model: always use max_completion_tokens instead of max_tokens
    if (max_tokens) |max_tok| {
        try buf.appendSlice(allocator, ",\"max_completion_tokens\":");
        var max_buf: [16]u8 = undefined;
        const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tok}) catch return error.FormatError;
        try buf.appendSlice(allocator, max_str);
    }

    // Emit reasoning_effort when set (JSON-escaped for safety)
    if (normalized_effort) |re| {
        try buf.appendSlice(allocator, ",\"reasoning_effort\":");
        try json_util.appendJsonString(buf, allocator, re);
    }
}

pub fn normalizeOpenAiReasoningEffort(reasoning_effort: ?[]const u8) ?[]const u8 {
    const raw = reasoning_effort orelse return null;
    if (std.ascii.eqlIgnoreCase(raw, "none")) return "none";
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(raw, "high") or std.ascii.eqlIgnoreCase(raw, "xhigh")) return "high";
    return raw;
}

const GeminiReasoningEffort = enum {
    none,
    minimal,
    low,
    medium,
    high,
    xhigh,
};

const GeminiThinkingProfile = union(enum) {
    level: []const u8,
    budget: u32,
};

const GeminiThinkingTarget = enum {
    gemini_api,
    vertex_ai,
};

fn parseGeminiReasoningEffort(reasoning_effort: ?[]const u8) ?GeminiReasoningEffort {
    const raw = reasoning_effort orelse return null;
    if (std.ascii.eqlIgnoreCase(raw, "off") or std.ascii.eqlIgnoreCase(raw, "none")) return .none;
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return .minimal;
    if (std.ascii.eqlIgnoreCase(raw, "low")) return .low;
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return .medium;
    if (std.ascii.eqlIgnoreCase(raw, "high")) return .high;
    if (std.ascii.eqlIgnoreCase(raw, "xhigh")) return .xhigh;
    return null;
}

fn geminiThinkingProfile(model: []const u8, reasoning_effort: ?[]const u8) ?GeminiThinkingProfile {
    const effort = parseGeminiReasoningEffort(reasoning_effort) orelse return null;

    var lower_buf: [160]u8 = undefined;
    const lower_len = @min(model.len, lower_buf.len);
    for (model[0..lower_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..lower_len];

    const is_gemini_3 = std.mem.indexOf(u8, lower, "gemini-3") != null;
    const is_gemini_25 = std.mem.indexOf(u8, lower, "gemini-2.5") != null;
    const is_flash = std.mem.indexOf(u8, lower, "flash") != null;
    const is_pro = std.mem.indexOf(u8, lower, "pro") != null;

    // Gemini 3 family: use thinking levels.
    // Gemini 3 Pro supports only low/high, while Flash supports minimal/low/medium/high.
    if (is_gemini_3) {
        if (is_flash) {
            return .{
                .level = switch (effort) {
                    .none => "minimal",
                    .minimal => "minimal",
                    .low => "low",
                    .medium => "medium",
                    .high, .xhigh => "high",
                },
            };
        }
        return .{
            .level = switch (effort) {
                .high, .xhigh => "high",
                .none, .minimal, .low, .medium => "low",
            },
        };
    }

    // Gemini 2.5 family: use thinking budget.
    if (is_gemini_25) {
        return switch (effort) {
            .none => if (is_pro) null else .{ .budget = 0 },
            .minimal, .low => .{ .budget = 1024 },
            .medium => .{ .budget = 8192 },
            .high, .xhigh => .{ .budget = 24576 },
        };
    }

    return null;
}

/// Append Gemini/Vertex thinking controls under generationConfig when reasoning effort is set.
/// Mapping:
/// - Gemini 3 models => `thinkingConfig.thinkingLevel`
/// - Gemini 2.5 models => `thinkingConfig.thinkingBudget`
pub fn appendGeminiThinkingConfig(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
) !void {
    return appendThinkingConfigForTarget(buf, allocator, model, reasoning_effort, .gemini_api);
}

/// Append Vertex thinking controls under generationConfig when reasoning effort is set.
/// Vertex expects enum-style uppercase values for `thinkingLevel`.
pub fn appendVertexThinkingConfig(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
) !void {
    return appendThinkingConfigForTarget(buf, allocator, model, reasoning_effort, .vertex_ai);
}

fn normalizeVertexThinkingLevel(level: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(level, "minimal")) return "MINIMAL";
    if (std.ascii.eqlIgnoreCase(level, "low")) return "LOW";
    if (std.ascii.eqlIgnoreCase(level, "medium")) return "MEDIUM";
    return "HIGH";
}

fn appendThinkingConfigForTarget(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
    target: GeminiThinkingTarget,
) !void {
    const profile = geminiThinkingProfile(model, reasoning_effort) orelse return;

    try buf.appendSlice(allocator, ",\"thinkingConfig\":{\"includeThoughts\":true,");
    switch (profile) {
        .level => |level| {
            try buf.appendSlice(allocator, "\"thinkingLevel\":");
            const out_level = switch (target) {
                .gemini_api => level,
                .vertex_ai => normalizeVertexThinkingLevel(level),
            };
            try json_util.appendJsonString(buf, allocator, out_level);
        },
        .budget => |budget| {
            try buf.appendSlice(allocator, "\"thinkingBudget\":");
            var budget_buf: [16]u8 = undefined;
            const budget_str = std.fmt.bufPrint(&budget_buf, "{d}", .{budget}) catch return error.FormatError;
            try buf.appendSlice(allocator, budget_str);
        },
    }
    try buf.append(allocator, '}');
}

/// Serialize a single message's content field (plain string or multimodal content parts array).
/// OpenAI format: text → {"type":"text","text":"..."}, image_url → {"type":"image_url","image_url":{"url":"...","detail":"..."}},
/// image_base64 → {"type":"image_url","image_url":{"url":"data:mime;base64,..."}}.
/// Used by OpenAI, OpenRouter, and Compatible providers.
/// Serialize a single content part (text, image_url, or image_base64) to a JSON string.
pub fn serializeContentPart(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, part: root.ContentPart) !void {
    switch (part) {
        .text => |text| {
            try buf.appendSlice(allocator, "{\"type\":\"text\",\"text\":");
            try json_util.appendJsonString(buf, allocator, text);
            try buf.append(allocator, '}');
        },
        .image_url => |img| {
            try buf.appendSlice(allocator, "{\"type\":\"image_url\",\"image_url\":{\"url\":");
            try json_util.appendJsonString(buf, allocator, img.url);
            try buf.appendSlice(allocator, ",\"detail\":\"");
            try buf.appendSlice(allocator, img.detail.toSlice());
            try buf.appendSlice(allocator, "\"}}");
        },
        .image_base64 => |img| {
            // OpenAI accepts base64 images as data URIs in image_url
            // Build data URI with escaped media_type
            try buf.appendSlice(allocator, "{\"type\":\"image_url\",\"image_url\":{\"url\":\"data:");
            // media_type is from detectMimeType (e.g. "image/png") — safe,
            // but escape for defense-in-depth
            for (img.media_type) |c| {
                switch (c) {
                    '"' => try buf.appendSlice(allocator, "\\\""),
                    '\\' => try buf.appendSlice(allocator, "\\\\"),
                    else => try buf.append(allocator, c),
                }
            }
            try buf.appendSlice(allocator, ";base64,");
            try buf.appendSlice(allocator, img.data);
            try buf.appendSlice(allocator, "\"}}");
        },
    }
}

pub fn serializeMessageContent(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, msg: root.ChatMessage) !void {
    if (msg.content_parts) |parts| {
        try buf.append(allocator, '[');
        for (parts, 0..) |part, j| {
            if (j > 0) try buf.append(allocator, ',');
            try serializeContentPart(buf, allocator, part);
        }
        try buf.append(allocator, ']');
    } else {
        try json_util.appendJsonString(buf, allocator, msg.content);
    }
}

/// Serialize tool definitions into an OpenAI-format JSON array, appending directly into `buf`.
/// Format: [{"type":"function","function":{"name":"...","description":"...","parameters":{...}}}]
pub fn convertToolsOpenAI(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"type\":\"function\",\"function\":{\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"parameters\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.appendSlice(allocator, "}}");
    }
    try buf.append(allocator, ']');
}

/// Serialize tool definitions into an Anthropic-format JSON array, appending directly into `buf`.
/// Format: [{"name":"...","description":"...","input_schema":{...}}]
pub fn convertToolsAnthropic(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"input_schema\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');
}

/// Serialize tool definitions into a Responses-API-format JSON array, appending directly into `buf`.
/// Format: [{"type":"function","name":"...","description":"...","parameters":{...}}]
/// Note: flat format — no nested "function" wrapper (unlike OpenAI format).
pub fn convertToolsResponses(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"type\":\"function\",\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"parameters\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');
}

/// HTTP POST with optional LLM timeout (seconds). 0 = no limit.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
fn curlTimeoutArg(buf: *[32]u8, timeout_secs: u64) ?[]const u8 {
    if (timeout_secs == 0) return null;
    return std.fmt.bufPrint(buf, "{d}", .{timeout_secs}) catch unreachable;
}

fn curlPostTypedTimed(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    content_type: []const u8,
    timeout_secs: u64,
) ![]u8 {
    const resolve_entry = http_util.buildSafeResolveEntryForRemoteUrl(allocator, url) catch |err| switch (err) {
        error.InvalidUrl, error.HostResolutionFailed, error.LocalAddressBlocked => return err,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer if (resolve_entry) |entry| allocator.free(entry);

    var timeout_buf: [32]u8 = undefined;
    const response = try http_util.curlRequestWithStatusAndHeaders(allocator, .{
        .method = .POST,
        .url = url,
        .body = body,
        .headers = headers,
        .content_type = content_type,
        .max_time = curlTimeoutArg(&timeout_buf, timeout_secs),
        .resolve_entry = resolve_entry,
        .accept_compression = true,
        .std_http_defaults = true,
    });
    allocator.free(response.headers);
    errdefer allocator.free(response.body);
    if (response.status_code < 200 or response.status_code >= 300) return error.HttpStatusError;
    return response.body;
}

pub fn curlPostTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, headers: []const []const u8, timeout_secs: u64) ![]u8 {
    return curlPostTypedTimed(allocator, url, body, headers, "application/json", timeout_secs);
}

/// HTTP POST (application/x-www-form-urlencoded) with optional timeout.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
pub fn curlPostFormTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, timeout_secs: u64) ![]u8 {
    return curlPostTypedTimed(allocator, url, body, &.{}, "application/x-www-form-urlencoded", timeout_secs);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "provider curl timeout argument preserves zero and finite values" {
    var buf: [32]u8 = undefined;
    try std.testing.expect(curlTimeoutArg(&buf, 0) == null);
    try std.testing.expectEqualStrings("300", curlTimeoutArg(&buf, 300).?);
}

test "convertToolsOpenAI produces valid JSON" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a \"shell\" command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
        .{
            .name = "file_read",
            .description = "Read a file",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsOpenAI(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 2), arr.items.len);

    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("function", t0.get("type").?.string);
    const f0 = t0.get("function").?.object;
    try std.testing.expectEqualStrings("shell", f0.get("name").?.string);
    // Description with quotes should be properly escaped
    try std.testing.expect(std.mem.indexOf(u8, f0.get("description").?.string, "\"shell\"") != null);
    try std.testing.expect(f0.get("parameters").? == .object);

    const f1 = arr.items[1].object.get("function").?.object;
    try std.testing.expectEqualStrings("file_read", f1.get("name").?.string);
}

test "convertToolsOpenAI empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsOpenAI(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "convertToolsAnthropic produces valid JSON" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsAnthropic(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);

    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("shell", t0.get("name").?.string);
    try std.testing.expectEqualStrings("Run a command", t0.get("description").?.string);
    try std.testing.expect(t0.get("input_schema").? == .object);
}

test "convertToolsAnthropic empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsAnthropic(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "convertToolsResponses produces flat format" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a shell command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
        .{
            .name = "file_read",
            .description = "Read a file",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsResponses(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 2), arr.items.len);

    // Verify flat format: "name" at top level, no nested "function" key
    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("function", t0.get("type").?.string);
    try std.testing.expect(t0.get("function") == null); // Must NOT have nested "function"
    try std.testing.expectEqualStrings("shell", t0.get("name").?.string);
    try std.testing.expectEqualStrings("Run a shell command", t0.get("description").?.string);
    try std.testing.expect(t0.get("parameters").? == .object);

    const t1 = arr.items[1].object;
    try std.testing.expectEqualStrings("file_read", t1.get("name").?.string);
}

test "convertToolsResponses empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsResponses(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "serializeMessageContent plain text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const msg = root.ChatMessage.user("Hello world");
    try serializeMessageContent(&buf, alloc, msg);
    try std.testing.expectEqualStrings("\"Hello world\"", buf.items);
}

test "serializeMessageContent with content_parts text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .text = "Describe this" },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "Describe this",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    // Should produce an array with a text part
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    try std.testing.expectEqualStrings("text", arr.items[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("Describe this", arr.items[0].object.get("text").?.string);
}

test "serializeMessageContent with image_base64 part" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .text = "What is this?" },
        .{ .image_base64 = .{ .data = "iVBOR", .media_type = "image/png" } },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "What is this?",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    // Verify it produces valid JSON with data URI
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "data:image/png;base64,iVBOR") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"type\":\"image_url\"") != null);
}

test "serializeMessageContent with image_url part" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .image_url = .{ .url = "https://example.com/cat.jpg" } },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    const img_obj = arr.items[0].object.get("image_url").?.object;
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", img_obj.get("url").?.string);
    try std.testing.expectEqualStrings("auto", img_obj.get("detail").?.string);
}

test "appendGenerationFields normalizes minimal reasoning effort for gpt-5" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"model\":\"gpt-5\"");
    try appendGenerationFields(&buf, alloc, "gpt-5", 0.2, 4096, "minimal");
    try buf.append(alloc, '}');

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("low", obj.get("reasoning_effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expectEqual(@as(i64, 4096), obj.get("max_completion_tokens").?.integer);
}

test "appendGenerationFields normalizes xhigh reasoning effort for gpt-5" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"model\":\"gpt-5\"");
    try appendGenerationFields(&buf, alloc, "gpt-5", 0.2, 2048, "xhigh");
    try buf.append(alloc, '}');

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("high", obj.get("reasoning_effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expectEqual(@as(i64, 2048), obj.get("max_completion_tokens").?.integer);
}

test "appendGeminiThinkingConfig uses thinkingLevel for gemini-3 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-3.1-flash", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("medium", thinking.get("thinkingLevel").?.string);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

test "appendGeminiThinkingConfig maps unsupported gemini-3 pro medium to low level" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-3.1-pro-preview", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("low", thinking.get("thinkingLevel").?.string);
}

test "appendGeminiThinkingConfig uses thinkingBudget for gemini-2.5 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-2.5-flash", "high");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqual(@as(i64, 24576), thinking.get("thinkingBudget").?.integer);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

test "appendGeminiThinkingConfig omits none budget for gemini-2.5 pro" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-2.5-pro", "none");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    try std.testing.expect(cfg.get("thinkingConfig") == null);
}

test "appendVertexThinkingConfig uses uppercase thinkingLevel for gemini-3 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendVertexThinkingConfig(&buf, alloc, "gemini-3.1-flash", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("MEDIUM", thinking.get("thinkingLevel").?.string);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

// ════════════════════════════════════════════════════════════════════════════
// Garbled text tool-call markup
// ════════════════════════════════════════════════════════════════════════════
//
// A model that falls back to a text tool-call dialect can end a reply with a
// garbled call the parser cannot turn into an executable one: announcing more
// work and then emitting a lone `</function>` closer, or a bare
// `<function=name>` opener that never closes. `hasOrphanToolCallClose` is the
// structural, language-independent signal the turn loop keys its bounded retry
// on; `stripToolCallMarkup` removes the markup so the delivered reply never
// carries it. Both skip Markdown code fences and inline spans, so a documented
// sample is preserved.

/// Byte range of a Markdown code fence or inline code span.
pub const CodeRegion = struct { start: usize, end: usize };

/// True when `pos` is inside one of the sorted, non-overlapping `regions`.
pub fn isInsideCode(regions: []const CodeRegion, pos: usize) bool {
    var lo: usize = 0;
    var hi: usize = regions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const region = regions[mid];
        if (pos < region.start) {
            hi = mid;
        } else if (pos >= region.end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn codeRunLen(text: []const u8, start: usize) usize {
    const ch = text[start];
    var i = start;
    while (i < text.len and text[i] == ch) i += 1;
    return i - start;
}

/// Byte ranges of Markdown code in `text`: fenced blocks (``` / ~~~, opened by
/// a run of three or more at the start of a line) and inline code spans (a
/// backtick run closed by an equal run). Caller frees the returned slice.
pub fn findCodeRegions(allocator: std.mem.Allocator, text: []const u8) ![]CodeRegion {
    return findCodeRegionsInternal(allocator, text, true);
}

/// Like `findCodeRegions` but does not treat a trailing *unterminated* fence as
/// code, so a garbled closer after an unclosed fence is still scanned as
/// visible text. The tool-call-markup scanners use this.
pub fn findCodeRegionsForToolMarkup(allocator: std.mem.Allocator, text: []const u8) ![]CodeRegion {
    return findCodeRegionsInternal(allocator, text, false);
}

fn findCodeRegionsInternal(
    allocator: std.mem.Allocator,
    text: []const u8,
    unterminated_fence_is_code: bool,
) ![]CodeRegion {
    var regions: std.ArrayListUnmanaged(CodeRegion) = .empty;
    errdefer regions.deinit(allocator);

    var i: usize = 0;
    var at_line_start = true;
    var fence_ch: u8 = 0;
    var fence_len: usize = 0;
    var fence_start: usize = 0;
    var span_len: usize = 0;
    var span_start: usize = 0;
    while (i < text.len) {
        if (at_line_start) {
            at_line_start = false;
            var j = i;
            var indent: usize = 0;
            while (j < text.len and text[j] == ' ' and indent < 4) : (indent += 1) j += 1;
            if (indent <= 3 and j < text.len and (text[j] == '`' or text[j] == '~')) {
                const run = codeRunLen(text, j);
                if (fence_ch == 0 and run >= 3) {
                    fence_ch = text[j];
                    fence_len = run;
                    fence_start = i;
                    i = j + run;
                    continue;
                }
                if (fence_ch == text[j] and run >= fence_len) {
                    try regions.append(allocator, .{ .start = fence_start, .end = j + run });
                    fence_ch = 0;
                    i = j + run;
                    continue;
                }
            }
            if (fence_ch != 0) {
                // Inside a fence every byte is code until the next line start,
                // where a closing fence can appear.
                while (i < text.len and text[i] != '\n') i += 1;
                if (i < text.len) {
                    i += 1;
                    at_line_start = true;
                }
                continue;
            }
        }
        const b = text[i];
        if (b == '\n') {
            at_line_start = true;
            i += 1;
            continue;
        }
        if (b == '`') {
            const run = codeRunLen(text, i);
            if (span_len == 0) {
                span_len = run;
                span_start = i;
            } else if (run == span_len) {
                try regions.append(allocator, .{ .start = span_start, .end = i + run });
                span_len = 0;
            }
            i += run;
            continue;
        }
        i += 1;
    }
    // An unterminated fence runs to the end of the text (mid-stream). Callers
    // that scan for tool-call markup opt out (see `findCodeRegionsForToolMarkup`)
    // so an unclosed fence cannot hide a trailing garbled closer.
    if (fence_ch != 0 and unterminated_fence_is_code) {
        try regions.append(allocator, .{ .start = fence_start, .end = text.len });
    }
    // Regions are appended in the order they CLOSE, so a nested inline span that
    // wraps a fenced block can precede the fence it contains. isInsideCode's
    // binary search needs a sorted, non-overlapping list, so sort by start and
    // merge overlaps in place (the wrapped fence and span become one region).
    std.mem.sort(CodeRegion, regions.items, {}, struct {
        fn lessThan(_: void, a: CodeRegion, b: CodeRegion) bool {
            return a.start < b.start;
        }
    }.lessThan);
    var write: usize = 0;
    for (regions.items) |region| {
        if (write > 0 and region.start <= regions.items[write - 1].end) {
            if (region.end > regions.items[write - 1].end)
                regions.items[write - 1].end = region.end;
        } else {
            regions.items[write] = region;
            write += 1;
        }
    }
    regions.shrinkRetainingCapacity(write);
    return regions.toOwnedSlice(allocator);
}

// Tool-call markup tag *names*. A model that falls back to one of these text
// dialects can degenerate into a garbled call; the names mirror the dispatcher's
// `<tool_call>` grammar plus the Anthropic `function`/`invoke` dialects and the
// `antml:`/`mm:` namespaced variants a gateway can leak for a non-OpenAI model.
const tool_call_open_tags = [_][]const u8{
    "<tool_call",
    "<tool_result",
    "<tool_call_begin",
    "<tool_result_begin",
    "<|tool_call_begin|",
    "<|tool_result_begin|",
    "<function",
    "<function_calls",
    "<function_call",
    "<function_response",
    "<tool_calls",
    "<invoke",
    "<parameter",
    "<antml:invoke",
    "<antml:parameter",
    "<antml:function_calls",
    "<mm:tool_call",
    "<mm:function_calls",
    "<mm:invoke",
    "<mm:parameter",
};
// Close tag *names*, without the trailing delimiter: a close is matched with
// either a `>` or a whitespace delimiter, so a model that drops the `>`
// (`</tool_call >`) still ends the block.
const tool_call_close_names = [_][]const u8{
    "</tool_call",
    "</tool_result",
    "<tool_call_end",
    "<tool_result_end",
    "<|tool_call_end|",
    "<|tool_result_end|",
    "</function",
    "</function_calls",
    "</function_call",
    "</function_response",
    "</tool_calls",
    "</invoke",
    "</parameter",
    "</antml:invoke",
    "</antml:parameter",
    "</antml:function_calls",
    "</mm:tool_call",
    "</mm:function_calls",
    "</mm:invoke",
    "</mm:parameter",
};
const tool_call_standalone_names = [_][]const u8{
    "<tool_calls_section_begin",
    "<tool_calls_section_end",
    "<tool_calls_section_end|",
    "<|tool_calls_section_begin|",
    "<|tool_calls_section_end|",
    "<tool_call_argument_begin",
    "<|tool_call_argument_begin|",
};
// The dispatcher's bracket grammar (`[tool_call]` / `[TOOL_CALL]`), matched as
// exact literals.
const bracket_tool_call_markers = [_][]const u8{
    "[tool_call]",
    "[TOOL_CALL]",
    "[/tool_call]",
    "[/TOOL_CALL]",
};

/// True when `text` contains any text tool-call markup tag.
pub fn hasToolCallMarkup(text: []const u8) bool {
    for (tool_call_open_tags) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (tool_call_close_names) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (tool_call_standalone_names) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (bracket_tool_call_markers) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    return false;
}

/// True when `name` is one of the two OpenAI XML `function`-dialect tag names,
/// which bind their argument with `=` (`<function=read>`, `<parameter=path>`)
/// instead of the `>`/whitespace delimiter of the other dialects.
fn isFunctionDialectName(name: []const u8) bool {
    return std.mem.eql(u8, name, "<function") or std.mem.eql(u8, name, "<parameter");
}

/// True when the byte after a tool-call tag *name* may delimit it: `>` or any
/// whitespace, or `=` for OpenAI's `<function=NAME>` / `<parameter=NAME>` form.
pub fn toolTagDelimiterOk(name: []const u8, b: u8) bool {
    if (b == '>' or std.ascii.isWhitespace(b)) return true;
    return b == '=' and isFunctionDialectName(name);
}

/// True when an OpenAI `=`-dialect tag (`<function=NAME>` / `<parameter=NAME>`)
/// starts at `start`.
pub fn isFunctionDialectOpenAt(text: []const u8, start: usize) bool {
    return std.mem.startsWith(u8, text[start..], "<function=") or
        std.mem.startsWith(u8, text[start..], "<parameter=");
}

/// Offset just past the `>` that ends a tag token whose name already matched at
/// `from`, or the offset of a `<` seen first (an unterminated token the caller
/// drops and reprocesses from that `<`). A token with no `>` runs to end-of-text.
fn scanTagTokenEnd(text: []const u8, from: usize) usize {
    var i = from;
    while (i < text.len) : (i += 1) {
        if (text[i] == '>') return i + 1;
        if (text[i] == '<') return i;
    }
    return text.len;
}

/// Byte offset just past a tool-call open tag starting at `start`, or null when
/// the bytes there are not one. The longest name wins, and the tag must end on
/// `>` or a whitespace delimiter (or `=` for the `function`/`parameter` dialect).
pub fn matchToolCallOpenTag(text: []const u8, start: usize) ?usize {
    var open_len: usize = 0;
    for (tool_call_open_tags) |open| {
        if (open.len <= open_len) continue;
        if (!std.mem.startsWith(u8, text[start..], open)) continue;
        const after = start + open.len;
        if (after >= text.len) continue;
        if (!toolTagDelimiterOk(open, text[after])) continue;
        open_len = open.len;
    }
    if (open_len == 0) return null;
    const after = start + open_len;
    return if (text[after] == '>') after + 1 else scanTagTokenEnd(text, after);
}

/// Byte offset just past the close tag starting at `start`, or null. The name
/// may be delimited by `>` or any whitespace; `eof_drops` selects the
/// end-of-text behaviour: a delimiter-less close name at the very end is an
/// unterminated token the top level drops (`text.len`), while a tool body
/// simply stays open (null).
fn matchToolCallClose(text: []const u8, start: usize, eof_drops: bool) ?usize {
    for (tool_call_close_names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        if (after >= text.len) return if (eof_drops) text.len else null;
        if (text[after] != '>' and !std.ascii.isWhitespace(text[after])) continue;
        return scanTagTokenEnd(text, after);
    }
    return null;
}

fn nameFollowedByLt(text: []const u8, start: usize, names: []const []const u8) ?usize {
    for (names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        if (after < text.len and text[after] == '<') return name.len;
    }
    return null;
}

/// Length of a complete tag *name* at `start` immediately followed by `<` (the
/// model dropped the tag's `>`), or null. Mirrors the streaming filter's `.lt`
/// fallback: the unterminated name is dropped and the `<` is reprocessed.
fn unterminatedTagNameLen(text: []const u8, start: usize) ?usize {
    return nameFollowedByLt(text, start, &tool_call_open_tags) orelse
        nameFollowedByLt(text, start, &tool_call_close_names) orelse
        nameFollowedByLt(text, start, &tool_call_standalone_names);
}

/// Byte offset just past a tool-call block opened at `start`, or null when no
/// block open tag starts there or the block never closes (the caller then
/// releases a plain opener as prose). The open tag may carry attributes, or the
/// model may omit the `>` so the body starts right after the tag name.
fn skipToolCallBlock(text: []const u8, start: usize) ?usize {
    // Longest matching open tag wins, so `<function_calls` beats `<function`.
    var open_len: usize = 0;
    for (tool_call_open_tags) |open| {
        if (open.len <= open_len) continue;
        if (!std.mem.startsWith(u8, text[start..], open)) continue;
        const after = start + open.len;
        // A delimiter-less open name at the end of the text is an unterminated
        // token: the remainder is dropped, exactly like the streaming filter.
        if (after >= text.len) return text.len;
        if (!toolTagDelimiterOk(open, text[after])) continue;
        open_len = open.len;
    }
    if (open_len == 0) return null;
    const tag_end = matchToolCallOpenTag(text, start) orelse return null;
    var j = tag_end;
    while (j < text.len) : (j += 1) {
        if (text[j] != '<') continue;
        if (matchToolCallClose(text, j, false)) |end| return end;
    }
    return null;
}

fn skipToolCallStandalone(text: []const u8, start: usize) ?usize {
    for (tool_call_standalone_names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        if (after >= text.len) return text.len;
        if (text[after] != '>' and !std.ascii.isWhitespace(text[after])) continue;
        return scanTagTokenEnd(text, after);
    }
    return null;
}

/// Byte offset just past a `[tool_call]` / `[TOOL_CALL]` block starting at
/// `start`, or null. A stray close marker is dropped on its own.
fn skipBracketToolCall(text: []const u8, start: usize) ?usize {
    const rest = text[start..];
    const open: []const u8 = if (std.mem.startsWith(u8, rest, "[tool_call]"))
        "[tool_call]"
    else if (std.mem.startsWith(u8, rest, "[TOOL_CALL]"))
        "[TOOL_CALL]"
    else if (std.mem.startsWith(u8, rest, "[/tool_call]"))
        "[/tool_call]"
    else if (std.mem.startsWith(u8, rest, "[/TOOL_CALL]"))
        "[/TOOL_CALL]"
    else
        return null;

    if (open[1] == '/') return start + open.len; // stray close marker

    const payload_start = start + open.len;
    var close_end: ?usize = null;
    for ([_][]const u8{ "[/tool_call]", "[/TOOL_CALL]" }) |close| {
        if (std.mem.indexOf(u8, text[payload_start..], close)) |rel| {
            const abs = payload_start + rel + close.len;
            if (close_end == null or abs < close_end.?) close_end = abs;
        }
    }
    return close_end;
}

/// Byte length of a `[tool_call]` / `[TOOL_CALL]` opener at `start`, or null.
fn bracketOpenLen(text: []const u8, start: usize) ?usize {
    if (std.mem.startsWith(u8, text[start..], "[tool_call]")) return "[tool_call]".len;
    if (std.mem.startsWith(u8, text[start..], "[TOOL_CALL]")) return "[TOOL_CALL]".len;
    return null;
}

/// Byte length of a `[/tool_call]` / `[/TOOL_CALL]` closer at `start`, or null.
fn bracketCloseLen(text: []const u8, start: usize) ?usize {
    if (std.mem.startsWith(u8, text[start..], "[/tool_call]")) return "[/tool_call]".len;
    if (std.mem.startsWith(u8, text[start..], "[/TOOL_CALL]")) return "[/TOOL_CALL]".len;
    return null;
}

/// True when `text` holds unbalanced angle-bracket tool-call markup outside any
/// code fence or inline span: a `</…` close tag with no matching opener, or an
/// OpenAI `=`-dialect opener (`<function=NAME>` / `<parameter=NAME>`) that never
/// closes. That is the shape a model degenerates into when it announces more
/// work and then emits a garbled text tool call (prod: a reply ending in a lone
/// `</function>`; the `=` dialect: a reply ending in a bare `<function=web_search>`).
/// It is a structural, language-independent signal, so the turn loop keys its
/// bounded retry on it instead of on assistant prose. A balanced pair
/// (`<function>…</function>`) is prose and does not qualify, and neither does
/// markup inside a code sample. A stray bracket closer (`[/tool_call]`, the
/// dispatcher's grammar) qualifies on the same terms. This detector is narrower
/// than `stripToolCallMarkup`, which also drops a balanced pair from the
/// delivered reply.
pub fn hasOrphanToolCallClose(allocator: std.mem.Allocator, text: []const u8) !bool {
    if (!hasToolCallMarkup(text)) return false;
    const code = try findCodeRegionsForToolMarkup(allocator, text);
    defer allocator.free(code);
    var depth: usize = 0;
    // Whether the outermost open tag is the `=` dialect, whose unclosed form is
    // tool markup rather than a prose mention of a marker name.
    var function_open = false;
    // The dispatcher's bracket grammar is a separate dialect with its own depth.
    var bracket_depth: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        if (isInsideCode(code, i)) {
            i += 1;
            continue;
        }
        if (text[i] == '[') {
            // A stray `[/tool_call]` closer with no matching opener is the same
            // garbled shape as an orphan angle-bracket closer, so the bounded
            // retry fires for it too; a balanced bracket pair is a complete
            // block (prose), and an unclosed `[tool_call]` opener is released as
            // prose, exactly like the angle-bracket dialects.
            if (bracketCloseLen(text, i)) |len| {
                if (bracket_depth == 0) return true;
                bracket_depth -= 1;
                i += len;
                continue;
            }
            if (bracketOpenLen(text, i)) |len| {
                bracket_depth += 1;
                i += len;
                continue;
            }
            i += 1;
            continue;
        }
        if (text[i] != '<') {
            i += 1;
            continue;
        }
        if (matchToolCallOpenTag(text, i)) |end| {
            if (depth == 0 and isFunctionDialectOpenAt(text, i)) function_open = true;
            depth += 1;
            i = end;
            continue;
        }
        if (matchToolCallClose(text, i, true)) |end| {
            if (depth == 0) return true;
            depth -= 1;
            // Only the outermost *still-unclosed* opener decides the verdict: a
            // balanced pair that closes back to depth 0 is prose, so clear the
            // `=`-dialect flag rather than let it leak into a later plain opener.
            if (depth == 0) function_open = false;
            i = end;
            continue;
        }
        i += 1;
    }
    return depth > 0 and function_open;
}

/// Remove text tool-call markup from `text`, preserving Markdown code fences and
/// inline spans (a documented sample is not markup). A closed block, a stray
/// close tag, and a standalone marker are dropped whole; an unterminated
/// `=`-dialect opener drops only the tag token, so trailing prose survives.
///
/// This is deliberately broader than `hasOrphanToolCallClose`: it also drops a
/// balanced block (`<function>...</function>`), because the delivered reply must
/// not carry markup even though the detector treats a balanced pair as prose and
/// leaves it alone. The detector stays narrow so a prose mention of the markup
/// does not trigger a retry; the stripper removes any markup it sees.
pub fn stripToolCallMarkup(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (!hasToolCallMarkup(text)) return allocator.dupe(u8, text);
    const code = try findCodeRegionsForToolMarkup(allocator, text);
    defer allocator.free(code);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < text.len) {
        if (isInsideCode(code, i)) {
            try out.append(allocator, text[i]);
            i += 1;
            continue;
        }
        if (text[i] == '<') {
            // An unterminated tag name (`<tool_call<`, ...): drop the name.
            if (unterminatedTagNameLen(text, i)) |len| {
                i += len;
                continue;
            }
            // A closed tool-call block is markup: drop tags and body.
            if (skipToolCallBlock(text, i)) |end| {
                i = end;
                continue;
            }
            // A `=`-dialect opener that never closes is a garbled text tool
            // call, not prose, so drop the tag token only. A mid-sentence
            // mention leaves trailing prose that is a real answer.
            if (isFunctionDialectOpenAt(text, i)) {
                i = matchToolCallOpenTag(text, i) orelse text.len;
                continue;
            }
            if (skipToolCallStandalone(text, i)) |end| {
                i = end;
                continue;
            }
            // A stray close tag with no opener is still tool markup.
            if (matchToolCallClose(text, i, true)) |end| {
                i = end;
                continue;
            }
        } else if (text[i] == '[') {
            if (skipBracketToolCall(text, i)) |end| {
                i = end;
                continue;
            }
        }
        try out.append(allocator, text[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

test "stripToolCallMarkup drops a single stray function close tag" {
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "核心数据到手了。\n</function>");
    defer a.free(out);
    try std.testing.expectEqualStrings("核心数据到手了。\n", out);
}

test "stripToolCallMarkup drops the OpenAI function= dialect block" {
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "prose\n<function=web_search>query</function>\nend");
    defer a.free(out);
    try std.testing.expectEqualStrings("prose\n\nend", out);
}

test "stripToolCallMarkup drops a truncated function= opener" {
    // Prod-adjacent shape: the model announces a tool call and emits only a bare
    // `<function=NAME>` with no close. The opener is tool markup, not prose.
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "prose\n<function=web_search>");
    defer a.free(out);
    try std.testing.expectEqualStrings("prose\n", out);
}

test "stripToolCallMarkup drops an orphan tool_call closer" {
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "answer\n</tool_call>");
    defer a.free(out);
    try std.testing.expectEqualStrings("answer\n", out);
}

test "stripToolCallMarkup keeps a function= sample inside a code fence" {
    const a = std.testing.allocator;
    const doc = "Example:\n```xml\n<function=read><parameter=path>p</parameter></function>\n```\ndone";
    const out = try stripToolCallMarkup(a, doc);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<function=read>") != null);
}

test "hasOrphanToolCallClose flags the function= dialect shapes" {
    const a = std.testing.allocator;
    try std.testing.expect(try hasOrphanToolCallClose(a, "prose\n<function=web_search>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n</tool_call>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "核心数据到手了。\n</function>"));
    // A balanced pair is prose, not a garbled call.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "Use <function name=\"read\">body</function> in the docs."));
    // An unclosed plain marker is released as prose, so it is not flagged.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "the <tool_call> marker"));
}

test "stripToolCallMarkup drops the function_call/function_response and namespaced closers" {
    const a = std.testing.allocator;
    const cases = [_][]const u8{
        "answer\n</function_call>",
        "answer\n</function_response>",
        "answer\n</antml:invoke>",
        "answer\n</mm:parameter>",
    };
    for (cases) |c| {
        const out = try stripToolCallMarkup(a, c);
        defer a.free(out);
        try std.testing.expectEqualStrings("answer\n", out);
    }
    // A closed `function_call` block is tool markup too.
    const block = try stripToolCallMarkup(a, "A<function_call>x</function_call>B");
    defer a.free(block);
    try std.testing.expectEqualStrings("AB", block);
}

test "hasOrphanToolCallClose flags a lone namespaced or function_call closer" {
    const a = std.testing.allocator;
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n</function_call>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n</function_response>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n</antml:invoke>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n</mm:parameter>"));
}

test "hasOrphanToolCallClose ignores a balanced pair before a plain unclosed opener" {
    const a = std.testing.allocator;
    // A balanced `=` pair that closes back to depth 0 must not leave the `=`
    // flag set for a later, plain opener the code releases as prose.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "<function=x>ok</function> and the <tool_call> marker"));
}

test "stripToolCallMarkup keeps the prose after an unclosed = opener" {
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "The model emits <function=read> tags. Then the real answer here.");
    defer a.free(out);
    try std.testing.expectEqualStrings("The model emits  tags. Then the real answer here.", out);
}

test "stripToolCallMarkup drops a lone closer after an unclosed fence" {
    // The prod reply promised a comparison table, opened a ``` fence and then
    // degenerated into a lone `</function>`. An unterminated fence must not hide
    // the trailing garbled closer from the strip.
    const a = std.testing.allocator;
    const cases = [_][]const u8{ "answer\n```\n</function>", "answer\n~~~\n</function>" };
    for (cases) |input| {
        const out = try stripToolCallMarkup(a, input);
        defer a.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "</function") == null);
    }
}

test "hasOrphanToolCallClose flags a lone closer after an unclosed fence" {
    const a = std.testing.allocator;
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n```\n</function>"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n~~~\n</function>"));
    // A closed fence still preserves a documented sample.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "```\n</function>\n```"));
}

test "findCodeRegions returns a sorted, non-overlapping list when a span wraps a fence" {
    // Regression: pre-fix regions were appended in the order they close, so an
    // inline span opened before a fenced block that closes first produced an
    // unsorted, overlapping list and broke isInsideCode's binary-search
    // precondition.
    const a = std.testing.allocator;
    const regions = try findCodeRegions(a, "x`y\n```\nz\n```\nw`v");
    defer a.free(regions);
    var prev_end: usize = 0;
    for (regions) |r| {
        try std.testing.expect(r.start >= prev_end);
        try std.testing.expect(r.end > r.start);
        prev_end = r.end;
    }
    // The wrapped span is one code region: the span opener and a byte inside the
    // fence both read as code.
    try std.testing.expect(isInsideCode(regions, 1));
    try std.testing.expect(isInsideCode(regions, 8));
}

test "hasOrphanToolCallClose flags a stray bracket closer" {
    // Regression: pre-fix the detector scanned only '<', so a stray
    // `[/tool_call]` was stripped by stripToolCallMarkup but never triggered the
    // bounded retry.
    const a = std.testing.allocator;
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n[/tool_call]"));
    try std.testing.expect(try hasOrphanToolCallClose(a, "answer\n[/TOOL_CALL]"));
    // A balanced bracket pair is a complete block, not an orphan closer.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "[tool_call]x[/tool_call]"));
    // A stray bracket closer inside a code fence is a documented sample.
    try std.testing.expect(!try hasOrphanToolCallClose(a, "```\n[/tool_call]\n```"));
}
