const std = @import("std");
const json_util = @import("../json_util.zig");
const http_util = @import("../http_util.zig");
const root = @import("root.zig");
const ToolSpec = root.ToolSpec;

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
    const model = cfg.default_model orelse "anthropic/claude-sonnet-4-5-20250929";
    const body_str = try buildRequestBody(allocator, model, prompt, cfg.temperature, cfg.max_tokens orelse 4096);
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
    const model = cfg.default_model orelse "anthropic/claude-sonnet-4-5-20250929";
    const max_tok: u32 = if (cfg.max_tokens) |mt| @intCast(@min(mt, std.math.maxInt(u32))) else 4096;
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
/// Always emits `reasoning_effort` when set on a reasoning model.
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

    // Reasoning model: temperature only if reasoning_effort == "none"
    const effort_is_none = if (reasoning_effort) |re| std.mem.eql(u8, re, "none") else false;
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
    if (reasoning_effort) |re| {
        try buf.appendSlice(allocator, ",\"reasoning_effort\":");
        try json_util.appendJsonString(buf, allocator, re);
    }
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
pub fn curlPostTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, headers: []const []const u8, timeout_secs: u64) ![]u8 {
    if (timeout_secs > 0) {
        var timeout_buf: [16]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch
            return http_util.curlPost(allocator, url, body, headers);
        return http_util.curlPostWithProxy(allocator, url, body, headers, null, timeout_str);
    }
    return http_util.curlPost(allocator, url, body, headers);
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
