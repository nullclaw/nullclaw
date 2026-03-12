const std = @import("std");
const json_util = @import("../json_util.zig");
const http_util = @import("../http_util.zig");
const config_types = @import("../config_types.zig");
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

/// Extract api_key from a config-like struct (supports both Config.defaultProviderKey() and plain .api_key field).
fn resolveApiKeyFromCfg(cfg: anytype) ?[]const u8 {
    const T = @TypeOf(cfg);
    const Struct = switch (@typeInfo(T)) {
        .pointer => |p| p.child,
        else => T,
    };
    if (@hasField(Struct, "api_key")) return cfg.api_key;
    if (@hasDecl(Struct, "defaultProviderKey")) return cfg.defaultProviderKey();
    return null;
}

/// High-level complete function that routes to the right provider via HTTP.
/// Used by agent.zig for backward compatibility.
pub fn complete(allocator: std.mem.Allocator, cfg: anytype, prompt: []const u8) ![]const u8 {
    const api_key = resolveApiKeyFromCfg(cfg) orelse return error.NoApiKey;
    const url = providerUrl(cfg.default_provider);
    const model = cfg.default_model orelse return error.NoDefaultModel;
    const body_str = try buildRequestBody(allocator, model, prompt, cfg.temperature, cfg.max_tokens orelse config_types.DEFAULT_MODEL_MAX_TOKENS);
    defer allocator.free(body_str);

    var auth_buf: [512]u8 = undefined;
    const auth_val = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{api_key}) catch return error.NoApiKey;

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body_str,
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth_val },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .response_writer = &aw.writer,
    });

    if (result.status != .ok) return error.ProviderError;

    const response_body = aw.writer.buffer[0..aw.writer.end];
    return try extractContent(allocator, response_body);
}

/// Like complete() but prepends a system prompt. OpenAI-compatible format.
pub fn completeWithSystem(allocator: std.mem.Allocator, cfg: anytype, system_prompt: []const u8, prompt: []const u8) ![]const u8 {
    const api_key = resolveApiKeyFromCfg(cfg) orelse return error.NoApiKey;
    const url = providerUrl(cfg.default_provider);
    const model = cfg.default_model orelse return error.NoDefaultModel;
    const max_tok: u32 = if (cfg.max_tokens) |mt| @intCast(@min(mt, std.math.maxInt(u32))) else config_types.DEFAULT_MODEL_MAX_TOKENS;
    const body_str = try buildRequestBodyWithSystem(allocator, model, system_prompt, prompt, cfg.temperature, max_tok);
    defer allocator.free(body_str);

    var auth_buf: [512]u8 = undefined;
    const auth_val = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{api_key}) catch return error.NoApiKey;

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body_str,
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth_val },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .response_writer = &aw.writer,
    });

    if (result.status != .ok) return error.ProviderError;

    const response_body = aw.writer.buffer[0..aw.writer.end];
    return try extractContent(allocator, response_body);
}

/// Provider URL mapping for the legacy complete() function.
pub fn providerUrl(provider_name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "anthropic", "https://api.anthropic.com/v1/messages" },
        .{ "openai", "https://api.openai.com/v1/chat/completions" },
        .{ "ollama", "http://localhost:11434/api/chat" },
        .{ "gemini", "https://generativelanguage.googleapis.com/v1beta" },
        .{ "google", "https://generativelanguage.googleapis.com/v1beta" },
        .{ "vertex", "https://aiplatform.googleapis.com/v1" },
    });
    return map.get(provider_name) orelse "https://openrouter.ai/api/v1/chat/completions";
}

/// Build a JSON request body for the legacy complete() function.
pub fn buildRequestBody(allocator: std.mem.Allocator, model: []const u8, prompt: []const u8, temperature: f64, max_tokens: u32) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.writeAll("{\"model\":");
    try json_util.appendJsonString(&buf, allocator, model);
    try w.writeAll(",\"messages\":[{\"role\":\"user\",\"content\":");
    try json_util.appendJsonString(&buf, allocator, prompt);
    try std.fmt.format(w, "}}],\"temperature\":{d:.1},\"max_tokens\":{d}}}", .{ temperature, max_tokens });
    return try buf.toOwnedSlice(allocator);
}

/// Build a JSON request body with a system prompt (OpenAI-compatible format).
pub fn buildRequestBodyWithSystem(allocator: std.mem.Allocator, model: []const u8, system: []const u8, prompt: []const u8, temperature: f64, max_tokens: u32) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.writeAll("{\"model\":\"");
    try w.writeAll(model);
    try w.writeAll("\",\"messages\":[{\"role\":\"system\",\"content\":");
    try json_util.appendJsonString(&buf, allocator, system);
    try w.writeAll("},{\"role\":\"user\",\"content\":");
    try json_util.appendJsonString(&buf, allocator, prompt);
    try std.fmt.format(w, "}}],\"temperature\":{d:.1},\"max_tokens\":{d}}}", .{ temperature, max_tokens });
    return try buf.toOwnedSlice(allocator);
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

/// HTTP POST with optional LLM timeout (seconds). 0 = no limit.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
pub fn curlPostTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, headers: []const []const u8, timeout_secs: u64) ![]u8 {
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (timeout_secs > 0) {
        var timeout_buf: [32]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch
            return http_util.curlPostWithProxy(allocator, url, body, headers, proxy, null);
        return http_util.curlPostWithProxy(allocator, url, body, headers, proxy, timeout_str);
    }
    return http_util.curlPostWithProxy(allocator, url, body, headers, proxy, null);
}

/// HTTP POST (application/x-www-form-urlencoded) with optional timeout.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
pub fn curlPostFormTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, timeout_secs: u64) ![]u8 {
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (timeout_secs > 0) {
        var timeout_buf: [32]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch
            return http_util.curlPostFormWithProxy(allocator, url, body, proxy, null);
        return http_util.curlPostFormWithProxy(allocator, url, body, proxy, timeout_str);
    }
    return http_util.curlPostFormWithProxy(allocator, url, body, proxy, null);
}

/// Extract text content from a provider JSON response.
pub fn extractContent(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const root_obj = parsed.value.object;

    // OpenAI/OpenRouter format: choices[0].message.content
    if (root_obj.get("choices")) |choices| {
        if (choices.array.items.len > 0) {
            if (choices.array.items[0].object.get("message")) |msg| {
                if (msg.object.get("content")) |content| {
                    if (content == .string) return try allocator.dupe(u8, content.string);
                }
            }
        }
    }

    // Anthropic format: content[0].text
    if (root_obj.get("content")) |content| {
        if (content.array.items.len > 0) {
            if (content.array.items[0].object.get("text")) |text| {
                if (text == .string) return try allocator.dupe(u8, text.string);
            }
        }
    }

    return error.UnexpectedResponse;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

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

test "providerUrl returns correct URLs" {
    try std.testing.expectEqualStrings(
        "https://api.anthropic.com/v1/messages",
        providerUrl("anthropic"),
    );
    try std.testing.expectEqualStrings(
        "https://api.openai.com/v1/chat/completions",
        providerUrl("openai"),
    );
    try std.testing.expectEqualStrings(
        "https://openrouter.ai/api/v1/chat/completions",
        providerUrl("openrouter"),
    );
    try std.testing.expectEqualStrings(
        "http://localhost:11434/api/chat",
        providerUrl("ollama"),
    );
}

test "extractContent parses OpenAI format" {
    const allocator = std.testing.allocator;
    const body =
        \\{"choices":[{"message":{"content":"Hello there!"}}]}
    ;
    const result = try extractContent(allocator, body);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello there!", result);
}

test "extractContent parses Anthropic format" {
    const allocator = std.testing.allocator;
    const body =
        \\{"content":[{"type":"text","text":"Hello from Claude"}]}
    ;
    const result = try extractContent(allocator, body);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Claude", result);
}

test "buildRequestBody escapes double quotes in prompt" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBody(allocator, "gpt-4o", "say \"hello\"", 0.7, 100);
    defer allocator.free(body);
    // Raw quote would break JSON; escaped form must be present
    try std.testing.expect(std.mem.indexOf(u8, body, "\\\"hello\\\"") != null);
    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    parsed.deinit();
}

test "buildRequestBody escapes newlines in prompt" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBody(allocator, "gpt-4o", "line1\nline2", 0.7, 100);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\n") != null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    parsed.deinit();
}

test "buildRequestBody escapes backslash in prompt" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBody(allocator, "gpt-4o", "path\\to\\file", 0.7, 100);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\\\") != null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    parsed.deinit();
}

test "buildRequestBodyWithSystem escapes special chars in both fields" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBodyWithSystem(allocator, "gpt-4o", "sys \"role\"", "user\nprompt", 0.7, 100);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\\"role\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\\n") != null);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    parsed.deinit();
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
