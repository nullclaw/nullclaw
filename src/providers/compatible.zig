const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const sse = @import("sse.zig");
const error_classify = @import("error_classify.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ContentPart = root.ContentPart;
const ToolCall = root.ToolCall;
const TokenUsage = root.TokenUsage;

const log = std.log.scoped(.compatible);
/// Legacy default kept as a named constant for tests only.
/// Runtime code uses OpenAiCompatibleProvider.max_streaming_prompt_bytes (null = no limit).
const DEFAULT_MAX_STREAMING_PROMPT_BYTES: usize = 32 * 1024;
const STREAMING_FALLBACK_TIMEOUT_SECS: u64 = 90;

fn logCompatibleApiError(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    err: anyerror,
    url: []const u8,
    resp_body: []const u8,
) void {
    const sanitized = root.sanitizeApiError(allocator, resp_body) catch null;
    defer if (sanitized) |body| allocator.free(body);

    const preview = sanitized orelse "<api error body unavailable>";
    log.err("{s} {s}: {s} {s}", .{ provider_name, @errorName(err), url, preview });
}

fn returnLoggedCompatibleApiError(
    comptime T: type,
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    err: anyerror,
    url: []const u8,
    resp_body: []const u8,
) anyerror!T {
    // Tests assert error propagation on this path; skip log side effects there
    // because Zig's test runner treats unexpected stderr logs as failures.
    if (!builtin.is_test) {
        logCompatibleApiError(allocator, provider_name, err, url, resp_body);
    }
    return err;
}

fn parseStatusCodeValue(value: std.json.Value) ?u16 {
    return switch (value) {
        .integer => |i| blk: {
            if (i < 0 or i > std.math.maxInt(u16)) break :blk null;
            break :blk @intCast(i);
        },
        .string => |s| std.fmt.parseInt(u16, std.mem.trim(u8, s, " \t\r\n"), 10) catch null,
        else => null,
    };
}

fn sliceEqlAsciiFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn containsAsciiFold(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (sliceEqlAsciiFold(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn lookupFallbackStatusCode(root_obj: std.json.ObjectMap) ?u16 {
    if (root_obj.get("error")) |err_value| {
        if (err_value == .object) {
            const err_obj = err_value.object;
            if (err_obj.get("status")) |status| {
                if (parseStatusCodeValue(status)) |code| return code;
            }
            if (err_obj.get("code")) |code_value| {
                if (parseStatusCodeValue(code_value)) |code| return code;
            }
        }
    }

    if (root_obj.get("status")) |status| {
        if (parseStatusCodeValue(status)) |code| return code;
    }
    if (root_obj.get("code")) |code_value| {
        if (parseStatusCodeValue(code_value)) |code| return code;
    }

    return null;
}

fn lookupErrorMessageField(obj: std.json.ObjectMap) ?[]const u8 {
    if (obj.get("message")) |message| {
        if (message == .string) return message.string;
    }
    if (obj.get("msg")) |message| {
        if (message == .string) return message.string;
    }
    return null;
}

fn lookupFallbackMessage(root_obj: std.json.ObjectMap) ?[]const u8 {
    if (root_obj.get("error")) |err_value| {
        if (err_value == .object) {
            if (lookupErrorMessageField(err_value.object)) |message| return message;
        }
    }

    return lookupErrorMessageField(root_obj);
}

fn isResponsesFallbackMessage(message: []const u8) bool {
    const trimmed = std.mem.trim(u8, message, " \t\r\n");
    if (trimmed.len == 0) return false;

    return sliceEqlAsciiFold(trimmed, "not found") or
        sliceEqlAsciiFold(trimmed, "404 not found") or
        containsAsciiFold(trimmed, "unknown endpoint") or
        containsAsciiFold(trimmed, "endpoint not found") or
        containsAsciiFold(trimmed, "/chat/completions");
}

fn isPlainTextResponsesFallbackMessage(body: []const u8) bool {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0) return false;

    // Some compatible gateways return a plain-text 404 instead of a JSON error
    // envelope when /chat/completions is missing.
    return containsAsciiFold(trimmed, "/chat/completions") and
        (containsAsciiFold(trimmed, "404") or
            containsAsciiFold(trimmed, "not found") or
            containsAsciiFold(trimmed, "unknown endpoint") or
            containsAsciiFold(trimmed, "endpoint not found"));
}

fn shouldFallbackToResponses(allocator: std.mem.Allocator, body: []const u8) bool {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0) return false;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return isPlainTextResponsesFallbackMessage(trimmed);
    };
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    if (error_classify.classifyKnownApiError(parsed.value.object)) |kind| {
        if (kind != .other) return false;
    }

    const status = lookupFallbackStatusCode(parsed.value.object) orelse return false;
    if (status != 404) return false;

    const message = lookupFallbackMessage(parsed.value.object) orelse return false;
    return isResponsesFallbackMessage(message);
}

/// How the provider expects the API key to be sent.
pub const AuthStyle = enum {
    /// `Authorization: Bearer <key>`
    bearer,
    /// `x-api-key: <key>`
    x_api_key,
    /// Custom header name (set via `custom_header` field on the provider)
    custom,

    pub fn headerName(self: AuthStyle) []const u8 {
        return switch (self) {
            .bearer => "authorization",
            .x_api_key => "x-api-key",
            .custom => "authorization", // fallback; actual name comes from custom_header field
        };
    }
};

pub const CompatibleApiMode = enum {
    chat_completions,
    responses,
};

/// A provider that speaks the OpenAI-compatible chat completions API.
///
/// Used by: Venice, Vercel, Cloudflare, Moonshot, Synthetic, OpenCode,
/// Z.AI, GLM, MiniMax, Bedrock, Qianfan, Groq, Mistral, xAI, DeepSeek,
/// Together, Fireworks, Perplexity, Cohere, Copilot, and custom endpoints.
pub const OpenAiCompatibleProvider = struct {
    name: []const u8,
    base_url: []const u8,
    /// Optional owned copy of base_url when the caller had to normalize/build it.
    owned_base_url: ?[]u8 = null,
    api_key: ?[]const u8,
    auth_style: AuthStyle,
    /// Custom header name when auth_style is .custom (e.g. "X-Custom-Key").
    custom_header: ?[]const u8 = null,
    /// When false, do not fall back to /v1/responses on chat completions 404.
    /// GLM/Zhipu does not support the responses API.
    supports_responses_fallback: bool = true,
    /// When true, collect system message content and prepend it to the first
    /// user message as "[System: …]\n\n…", then skip system-role messages.
    /// Required by providers like MiniMax that reject the system role.
    merge_system_into_user: bool = false,
    /// Whether this provider supports native OpenAI-style tool_calls.
    /// When false, the agent uses XML tool format via system prompt.
    native_tools: bool = true,
    /// When true, disable streaming (force non-streaming requests).
    /// Required for providers where native tool_calls only work in non-streaming mode.
    disable_streaming: bool = false,
    /// When set, cap max_tokens in non-streaming requests to this value.
    /// Some providers (e.g. Fireworks) reject large max_tokens without streaming.
    max_tokens_non_streaming: ?u32 = null,
    /// When true, include `"thinking":{"type":"enabled|disabled"}` in request
    /// bodies so Z.AI/GLM models do not fall back to server-side defaults.
    thinking_param: bool = false,
    /// When true, include `"enable_thinking":true` in request bodies
    /// when reasoning_effort is set. Required by Qwen (DashScope compatible mode).
    enable_thinking_param: bool = false,
    /// When true, include `"reasoning_split":true` in request bodies
    /// when reasoning_effort is set. Used by MiniMax to separate reasoning output.
    reasoning_split_param: bool = false,
    /// When true, include `chat_template_kwargs.enable_thinking` in request
    /// bodies so custom vLLM/Qwen endpoints can opt into reasoning.
    chat_template_enable_thinking_param: bool = false,
    /// Optional User-Agent header for HTTP requests.
    /// When set, requests will include "User-Agent: {value}" header.
    user_agent: ?[]const u8 = null,
    /// Primary OpenAI-compatible protocol to use for this provider.
    api_mode: CompatibleApiMode = .chat_completions,
    /// Maximum estimated request text bytes before streaming is skipped.
    /// null means no limit — streaming is always attempted.
    /// Set via per-provider config field `max_streaming_prompt_bytes`.
    max_streaming_prompt_bytes: ?usize = null,
    /// Optional compact JSON string of additional key-value pairs to merge into request bodies.
    extra_body_params: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    const think_open_tag = "<think>";
    const think_close_tag = "</think>";
    const splitThinkContent = root.splitThinkContent;
    const stripThinkBlocks = root.stripThinkBlocks;

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        base_url: []const u8,
        api_key: ?[]const u8,
        auth_style: AuthStyle,
        user_agent: ?[]const u8,
    ) OpenAiCompatibleProvider {
        return .{
            .name = name,
            .base_url = trimTrailingSlash(base_url),
            .api_key = api_key,
            .auth_style = auth_style,
            .user_agent = user_agent,
            .allocator = allocator,
        };
    }

    fn validateUserAgent(user_agent: []const u8) bool {
        // Disallow header injection and malformed values.
        return std.mem.indexOfAny(u8, user_agent, "\r\n") == null;
    }

    fn trimTrailingSlash(s: []const u8) []const u8 {
        if (s.len > 0 and s[s.len - 1] == '/') {
            return s[0 .. s.len - 1];
        }
        return s;
    }

    /// Build the full URL for chat completions.
    /// Detects if base_url already ends with /chat/completions.
    pub fn chatCompletionsUrl(self: OpenAiCompatibleProvider, allocator: std.mem.Allocator) ![]const u8 {
        const trimmed = trimTrailingSlash(self.base_url);
        if (std.mem.endsWith(u8, trimmed, "/chat/completions")) {
            return try allocator.dupe(u8, trimmed);
        }
        return std.fmt.allocPrint(allocator, "{s}/chat/completions", .{trimmed});
    }

    /// Build the full URL for the responses API.
    /// Derives from base_url: strips /chat/completions suffix if present,
    /// otherwise appends /v1/responses or /responses depending on path.
    pub fn responsesUrl(self: OpenAiCompatibleProvider, allocator: std.mem.Allocator) ![]const u8 {
        const trimmed = trimTrailingSlash(self.base_url);

        // If already ends with /responses, use as-is
        if (std.mem.endsWith(u8, trimmed, "/responses")) {
            return try allocator.dupe(u8, trimmed);
        }

        // If chat endpoint is explicitly configured, derive sibling responses endpoint
        if (std.mem.endsWith(u8, trimmed, "/chat/completions")) {
            const prefix = trimmed[0 .. trimmed.len - "/chat/completions".len];
            return std.fmt.allocPrint(allocator, "{s}/responses", .{prefix});
        }

        // If an explicit API path exists (anything beyond just scheme://host),
        // append /responses directly to avoid duplicate /v1 segments
        if (hasExplicitApiPath(trimmed)) {
            return std.fmt.allocPrint(allocator, "{s}/responses", .{trimmed});
        }

        return std.fmt.allocPrint(allocator, "{s}/v1/responses", .{trimmed});
    }

    fn hasExplicitApiPath(url: []const u8) bool {
        // Find the path portion after scheme://host
        const after_scheme = if (std.mem.indexOf(u8, url, "://")) |idx| url[idx + 3 ..] else return false;
        const path_start = std.mem.indexOf(u8, after_scheme, "/") orelse return false;
        const path = after_scheme[path_start..];
        const trimmed_path = trimTrailingSlash(path);
        return trimmed_path.len > 0 and !std.mem.eql(u8, trimmed_path, "/");
    }

    /// Backward-compatible model aliases for provider-specific API model ids.
    fn normalizeProviderModel(self: OpenAiCompatibleProvider, model: []const u8) []const u8 {
        if (std.mem.eql(u8, self.name, "deepseek")) {
            if (std.mem.eql(u8, model, "deepseek-v3.2") or
                std.mem.eql(u8, model, "deepseek/deepseek-v3.2"))
            {
                return "deepseek-chat";
            }
        }
        return model;
    }

    fn capNonStreamingMaxTokens(self: OpenAiCompatibleProvider, request: ChatRequest) ChatRequest {
        var capped_request = request;
        if (self.max_tokens_non_streaming) |cap| {
            if (capped_request.max_tokens) |mt| {
                if (mt > cap) capped_request.max_tokens = cap;
            }
        }
        return capped_request;
    }

    fn estimateRequestTextBytes(request: ChatRequest) usize {
        var total: usize = 0;
        for (request.messages) |msg| {
            total += msg.content.len;
            if (msg.content_parts) |parts| {
                for (parts) |part| {
                    switch (part) {
                        .text => |t| total += t.len,
                        else => {},
                    }
                }
            }
        }
        return total;
    }

    /// Returns true when the streaming path should be skipped in favour of the
    /// non-streaming fallback.  When `limit` is null (the default) this always
    /// returns false — i.e. always attempt streaming regardless of payload size.
    pub fn shouldSkipStreaming(limit: ?usize, request: ChatRequest) bool {
        const l = limit orelse return false;
        return estimateRequestTextBytes(request) >= l;
    }

    fn streamingFallbackTimeoutSecs(request_timeout_secs: u64) u64 {
        if (request_timeout_secs > 0 and request_timeout_secs < STREAMING_FALLBACK_TIMEOUT_SECS) {
            return request_timeout_secs;
        }
        return STREAMING_FALLBACK_TIMEOUT_SECS;
    }

    fn appendResponsesMessageText(
        buf: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        msg: ChatMessage,
    ) !bool {
        if (msg.content_parts) |parts| {
            var wrote = false;
            for (parts) |part| {
                switch (part) {
                    .text => |text| {
                        const trimmed = std.mem.trim(u8, text, " \t\n\r");
                        if (trimmed.len == 0) continue;
                        if (wrote) try buf.appendSlice(allocator, "\n");
                        try buf.appendSlice(allocator, trimmed);
                        wrote = true;
                    },
                    else => {},
                }
            }
            return wrote;
        }

        const trimmed = std.mem.trim(u8, msg.content, " \t\n\r");
        if (trimmed.len == 0) return false;
        try buf.appendSlice(allocator, trimmed);
        return true;
    }

    fn collectResponsesInstructions(allocator: std.mem.Allocator, messages: []const ChatMessage) !?[]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        for (messages) |msg| {
            if (msg.role != .system) continue;
            const before = buf.items.len;
            if (before > 0) try buf.appendSlice(allocator, "\n\n");
            const wrote = try appendResponsesMessageText(&buf, allocator, msg);
            if (!wrote) buf.items.len = before;
        }

        if (buf.items.len == 0) {
            buf.deinit(allocator);
            return null;
        }
        return try buf.toOwnedSlice(allocator);
    }

    fn appendResponsesContentPart(
        buf: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        part: ContentPart,
    ) !void {
        switch (part) {
            .text => |text| {
                try buf.appendSlice(allocator, "{\"type\":\"input_text\",\"text\":");
                try root.appendJsonString(buf, allocator, text);
                try buf.append(allocator, '}');
            },
            .image_url => |img| {
                try buf.appendSlice(allocator, "{\"type\":\"input_image\",\"image_url\":");
                try root.appendJsonString(buf, allocator, img.url);
                try buf.appendSlice(allocator, ",\"detail\":");
                try root.appendJsonString(buf, allocator, img.detail.toSlice());
                try buf.append(allocator, '}');
            },
            .image_base64 => |img| {
                try buf.appendSlice(allocator, "{\"type\":\"input_image\",\"image_url\":\"data:");
                try buf.appendSlice(allocator, img.media_type);
                try buf.appendSlice(allocator, ";base64,");
                try buf.appendSlice(allocator, img.data);
                try buf.appendSlice(allocator, "\"}");
            },
        }
    }

    fn appendResponsesMessageContent(
        buf: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        msg: ChatMessage,
    ) !void {
        if (msg.content_parts) |parts| {
            try buf.append(allocator, '[');
            var first = true;
            for (parts) |part| {
                if (!first) try buf.append(allocator, ',');
                first = false;
                try appendResponsesContentPart(buf, allocator, part);
            }
            try buf.append(allocator, ']');
            return;
        }
        try root.appendJsonString(buf, allocator, msg.content);
    }

    fn serializeResponsesInputInto(
        buf: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        messages: []const ChatMessage,
    ) !void {
        var first = true;
        for (messages) |msg| {
            if (msg.role == .system) continue;
            if (!first) try buf.append(allocator, ',');
            first = false;

            switch (msg.role) {
                .user, .assistant => {
                    try buf.appendSlice(allocator, "{\"type\":\"message\",\"role\":\"");
                    try buf.appendSlice(allocator, msg.role.toSlice());
                    try buf.appendSlice(allocator, "\",\"content\":");
                    try appendResponsesMessageContent(buf, allocator, msg);
                    try buf.append(allocator, '}');
                },
                .tool => {
                    try buf.appendSlice(allocator, "{\"type\":\"function_call_output\",\"call_id\":");
                    try root.appendJsonString(buf, allocator, msg.tool_call_id orelse "unknown");
                    try buf.appendSlice(allocator, ",\"output\":");
                    try root.appendJsonString(buf, allocator, msg.content);
                    try buf.append(allocator, '}');
                },
                .system => unreachable,
            }
        }
    }

    fn appendResponsesGenerationFields(
        buf: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        model: []const u8,
        temperature: f64,
        max_tokens: ?u32,
        reasoning_effort: ?[]const u8,
    ) !void {
        const normalized_effort = root.normalizeOpenAiReasoningEffort(reasoning_effort);
        const effort_is_none = if (normalized_effort) |re| std.mem.eql(u8, re, "none") else false;

        if (!root.isReasoningModel(model) or effort_is_none) {
            try buf.appendSlice(allocator, ",\"temperature\":");
            var temp_buf: [16]u8 = undefined;
            const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.FormatError;
            try buf.appendSlice(allocator, temp_str);
        }

        if (max_tokens) |max_tok| {
            try buf.appendSlice(allocator, ",\"max_output_tokens\":");
            var max_buf: [16]u8 = undefined;
            const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tok}) catch return error.FormatError;
            try buf.appendSlice(allocator, max_str);
        }

        if (normalized_effort) |re| {
            if (!std.mem.eql(u8, re, "none")) {
                try buf.appendSlice(allocator, ",\"reasoning\":{\"effort\":");
                try root.appendJsonString(buf, allocator, re);
                try buf.append(allocator, '}');
            }
        }
    }

    /// Build a Responses API request JSON body from a full ChatRequest.
    pub fn buildResponsesRequestBody(
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        extra_body_params: ?[]const u8,
    ) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        const instructions = try collectResponsesInstructions(allocator, request.messages);
        defer if (instructions) |text| allocator.free(text);

        try buf.appendSlice(allocator, "{\"model\":");
        try root.appendJsonString(&buf, allocator, model);
        try buf.appendSlice(allocator, ",\"input\":[");
        try serializeResponsesInputInto(&buf, allocator, request.messages);
        try buf.append(allocator, ']');

        if (instructions) |text| {
            try buf.appendSlice(allocator, ",\"instructions\":");
            try root.appendJsonString(&buf, allocator, text);
        }

        try appendResponsesGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);

        if (request.tools) |tools| {
            if (tools.len > 0) {
                try buf.appendSlice(allocator, ",\"tools\":");
                try root.convertToolsResponses(&buf, allocator, tools);
                try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
            }
        }

        try root.appendOpenAiBodyExtraParams(&buf, allocator, request.session_id, extra_body_params);
        try buf.appendSlice(allocator, ",\"stream\":false}");
        return try buf.toOwnedSlice(allocator);
    }

    fn extractResponsesOutputText(
        allocator: std.mem.Allocator,
        root_obj: std.json.ObjectMap,
    ) !?[]const u8 {
        var text_buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer text_buf.deinit(allocator);

        if (root_obj.get("output_text")) |ot| {
            if (ot == .string) {
                const trimmed = std.mem.trim(u8, ot.string, " \t\n\r");
                if (trimmed.len > 0) try text_buf.appendSlice(allocator, trimmed);
            }
        }

        if (root_obj.get("output")) |output_arr| {
            if (output_arr == .array) {
                for (output_arr.array.items) |item| {
                    if (item != .object) continue;
                    const item_obj = item.object;
                    if (item_obj.get("role")) |role_val| {
                        if (role_val != .string or !std.mem.eql(u8, role_val.string, "assistant")) continue;
                    }
                    if (item_obj.get("content")) |content_arr| {
                        if (content_arr != .array) continue;
                        for (content_arr.array.items) |content| {
                            if (content != .object) continue;
                            const text_val = content.object.get("text") orelse continue;
                            if (text_val != .string) continue;
                            const trimmed = std.mem.trim(u8, text_val.string, " \t\n\r");
                            if (trimmed.len == 0) continue;
                            if (text_buf.items.len > 0) try text_buf.appendSlice(allocator, "\n\n");
                            try text_buf.appendSlice(allocator, trimmed);
                        }
                    }
                }
            }
        }

        if (text_buf.items.len == 0) {
            text_buf.deinit(allocator);
            return null;
        }

        const raw = try text_buf.toOwnedSlice(allocator);
        errdefer allocator.free(raw);
        const cleaned = try stripThinkBlocks(allocator, raw);
        allocator.free(raw);
        if (cleaned.len == 0) {
            allocator.free(cleaned);
            return null;
        }
        return cleaned;
    }

    fn extractResponsesToolCalls(
        allocator: std.mem.Allocator,
        root_obj: std.json.ObjectMap,
    ) ![]const ToolCall {
        const output_arr = root_obj.get("output") orelse return try allocator.alloc(ToolCall, 0);
        if (output_arr != .array) return try allocator.alloc(ToolCall, 0);

        var tool_calls: std.ArrayListUnmanaged(ToolCall) = .empty;
        errdefer {
            for (tool_calls.items) |tc| {
                allocator.free(tc.id);
                allocator.free(tc.name);
                allocator.free(tc.arguments);
            }
            tool_calls.deinit(allocator);
        }

        for (output_arr.array.items) |item| {
            if (item != .object) continue;
            const item_obj = item.object;
            const type_val = item_obj.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "function_call")) continue;

            const id = if (item_obj.get("call_id")) |call_id|
                if (call_id == .string) try allocator.dupe(u8, call_id.string) else try allocator.dupe(u8, "unknown")
            else
                try allocator.dupe(u8, "unknown");
            errdefer allocator.free(id);

            const name = if (item_obj.get("name")) |name_val|
                if (name_val == .string) try allocator.dupe(u8, name_val.string) else try allocator.dupe(u8, "")
            else
                try allocator.dupe(u8, "");
            errdefer allocator.free(name);

            const arguments = if (item_obj.get("arguments")) |args_val|
                if (args_val == .string) try allocator.dupe(u8, args_val.string) else try allocator.dupe(u8, "{}")
            else
                try allocator.dupe(u8, "{}");
            errdefer allocator.free(arguments);

            try tool_calls.append(allocator, .{
                .id = id,
                .name = name,
                .arguments = arguments,
            });
        }

        return try tool_calls.toOwnedSlice(allocator);
    }

    fn extractResponsesReasoning(
        allocator: std.mem.Allocator,
        root_obj: std.json.ObjectMap,
    ) !?[]u8 {
        const output_arr = root_obj.get("output") orelse return null;
        if (output_arr != .array) return null;

        for (output_arr.array.items) |item| {
            if (item != .object) continue;
            const item_obj = item.object;
            const type_val = item_obj.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "reasoning")) continue;

            if (item_obj.get("summary")) |summary_val| {
                switch (summary_val) {
                    .string => |summary| {
                        if (summary.len > 0) return try allocator.dupe(u8, summary);
                    },
                    .array => |summary_arr| {
                        for (summary_arr.items) |summary_item| {
                            if (summary_item != .object) continue;
                            const text_val = summary_item.object.get("text") orelse continue;
                            if (text_val == .string and text_val.string.len > 0) {
                                return try allocator.dupe(u8, text_val.string);
                            }
                        }
                    },
                    else => {},
                }
            }

            if (item_obj.get("content")) |content| {
                if (content == .string and content.string.len > 0) return try allocator.dupe(u8, content.string);
            }
        }
        return null;
    }

    fn extractResponsesUsage(root_obj: std.json.ObjectMap) TokenUsage {
        var usage = TokenUsage{};
        const usage_obj = root_obj.get("usage") orelse return usage;
        if (usage_obj != .object) return usage;

        if (usage_obj.object.get("input_tokens")) |v| {
            if (v == .integer) usage.prompt_tokens = @intCast(v.integer);
        }
        if (usage_obj.object.get("output_tokens")) |v| {
            if (v == .integer) usage.completion_tokens = @intCast(v.integer);
        }
        if (usage_obj.object.get("total_tokens")) |v| {
            if (v == .integer) usage.total_tokens = @intCast(v.integer);
        }
        return usage;
    }

    pub fn parseResponsesResponse(allocator: std.mem.Allocator, body: []const u8) !ChatResponse {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.NoResponseContent;

        const root_obj = parsed.value.object;

        if (error_classify.classifyKnownApiError(root_obj)) |kind| {
            const mapped_err = error_classify.kindToError(kind);
            var summary_buf: [1024]u8 = undefined;
            const summary = error_classify.summarizeKnownApiError(root_obj, &summary_buf) orelse @errorName(mapped_err);
            const sanitized = root.sanitizeApiError(allocator, summary) catch null;
            defer if (sanitized) |s| allocator.free(s);
            root.setLastApiErrorDetail("compatible", sanitized orelse summary);
            return mapped_err;
        }

        const content = try extractResponsesOutputText(allocator, root_obj);
        errdefer if (content) |text| allocator.free(text);

        const tool_calls = try extractResponsesToolCalls(allocator, root_obj);
        errdefer {
            for (tool_calls) |tc| {
                allocator.free(tc.id);
                allocator.free(tc.name);
                allocator.free(tc.arguments);
            }
            allocator.free(tool_calls);
        }

        const reasoning = try extractResponsesReasoning(allocator, root_obj);
        errdefer if (reasoning) |text| allocator.free(text);

        if (content == null and tool_calls.len == 0 and reasoning == null) {
            return error.NoResponseContent;
        }

        const model_str = if (root_obj.get("model")) |m|
            if (m == .string and m.string.len > 0) try allocator.dupe(u8, m.string) else ""
        else
            "";

        return .{
            .content = content,
            .tool_calls = tool_calls,
            .usage = extractResponsesUsage(root_obj),
            .model = model_str,
            .reasoning_content = reasoning,
        };
    }

    /// Extract plain text from a Responses response.
    pub fn extractResponsesText(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        var response = try parseResponsesResponse(allocator, body);
        errdefer {
            if (response.content) |text| allocator.free(text);
            for (response.tool_calls) |tc| {
                allocator.free(tc.id);
                allocator.free(tc.name);
                allocator.free(tc.arguments);
            }
            allocator.free(response.tool_calls);
            if (response.model.len > 0) allocator.free(response.model);
            if (response.reasoning_content) |text| allocator.free(text);
        }
        if (response.content) |text| {
            const result = text;
            response.content = null;
            for (response.tool_calls) |tc| {
                allocator.free(tc.id);
                allocator.free(tc.name);
                allocator.free(tc.arguments);
            }
            allocator.free(response.tool_calls);
            if (response.model.len > 0) allocator.free(response.model);
            if (response.reasoning_content) |reasoning| allocator.free(reasoning);
            return result;
        }
        return error.NoResponseContent;
    }

    /// Chat via the Responses API endpoint using a full ChatRequest.
    pub fn chatViaResponses(
        self: OpenAiCompatibleProvider,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        timeout_secs: u64,
    ) !ChatResponse {
        const url = try self.responsesUrl(allocator);
        defer allocator.free(url);

        const body = try buildResponsesRequestBody(allocator, request, model, temperature, self.extra_body_params);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], timeout_secs) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseResponsesResponse(allocator, resp_body) catch |err| {
            logCompatibleApiError(allocator, self.name, err, url, resp_body);
            return err;
        };
    }

    /// Build a chat request JSON body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
        extra_body_params: ?[]const u8,
    ) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "{\"model\":\"");
        try buf.appendSlice(allocator, model);
        try buf.appendSlice(allocator, "\",\"messages\":[");

        if (system_prompt) |sys| {
            try buf.appendSlice(allocator, "{\"role\":\"system\",\"content\":");
            try root.appendJsonString(&buf, allocator, sys);
            try buf.appendSlice(allocator, "},{\"role\":\"user\",\"content\":");
            try root.appendJsonString(&buf, allocator, message);
            try buf.append(allocator, '}');
        } else {
            try buf.appendSlice(allocator, "{\"role\":\"user\",\"content\":");
            try root.appendJsonString(&buf, allocator, message);
            try buf.append(allocator, '}');
        }

        try buf.append(allocator, ']');
        try root.appendGenerationFields(&buf, allocator, model, temperature, null, null);
        try root.appendOpenAiBodyExtraParams(&buf, allocator, null, extra_body_params);
        try buf.appendSlice(allocator, ",\"stream\":false}");

        return try buf.toOwnedSlice(allocator);
    }

    /// Build the authorization header value.
    pub fn authHeaderValue(self: OpenAiCompatibleProvider, allocator: std.mem.Allocator) !?AuthHeaderResult {
        const key = self.api_key orelse return null;
        return switch (self.auth_style) {
            .bearer => .{
                .name = "authorization",
                .value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{key}),
                .needs_free = true,
            },
            .x_api_key => .{
                .name = "x-api-key",
                .value = key,
                .needs_free = false,
            },
            .custom => .{
                .name = self.custom_header orelse "authorization",
                .value = key,
                .needs_free = false,
            },
        };
    }

    pub const AuthHeaderResult = struct {
        name: []const u8,
        value: []const u8,
        needs_free: bool,
    };

    const ThinkStripStreamCtx = struct {
        downstream: root.StreamCallback,
        downstream_ctx: *anyopaque,
        state: ThinkStripStreamState = .{},
    };

    const ThinkStripStreamState = struct {
        depth: usize = 0,
        pending: [think_close_tag.len]u8 = undefined,
        pending_len: usize = 0,

        fn feed(self: *ThinkStripStreamState, delta: []const u8, downstream: root.StreamCallback, downstream_ctx: *anyopaque) void {
            var out_buf: [256]u8 = undefined;
            var out_len: usize = 0;

            for (delta) |byte| {
                if (self.pending_len == self.pending.len) {
                    self.processPending(false, &out_buf, &out_len, downstream, downstream_ctx);
                }
                self.pending[self.pending_len] = byte;
                self.pending_len += 1;
                self.processPending(false, &out_buf, &out_len, downstream, downstream_ctx);
            }

            if (out_len > 0) {
                downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len]));
            }
        }

        fn finish(self: *ThinkStripStreamState, downstream: root.StreamCallback, downstream_ctx: *anyopaque) void {
            var out_buf: [256]u8 = undefined;
            var out_len: usize = 0;
            self.processPending(true, &out_buf, &out_len, downstream, downstream_ctx);
            if (out_len > 0) {
                downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len]));
            }
        }

        fn processPending(
            self: *ThinkStripStreamState,
            final: bool,
            out_buf: *[256]u8,
            out_len: *usize,
            downstream: root.StreamCallback,
            downstream_ctx: *anyopaque,
        ) void {
            while (self.pending_len > 0) {
                const pending = self.pending[0..self.pending_len];

                if (pending.len >= think_open_tag.len and std.mem.eql(u8, pending[0..think_open_tag.len], think_open_tag)) {
                    self.consumePrefix(think_open_tag.len);
                    self.depth += 1;
                    continue;
                }

                if (pending.len >= think_close_tag.len and std.mem.eql(u8, pending[0..think_close_tag.len], think_close_tag)) {
                    self.consumePrefix(think_close_tag.len);
                    if (self.depth > 0) self.depth -= 1;
                    continue;
                }

                const maybe_tag_prefix = std.mem.startsWith(u8, think_open_tag, pending) or std.mem.startsWith(u8, think_close_tag, pending);
                if (!final and maybe_tag_prefix and pending.len < think_close_tag.len) {
                    break;
                }

                if (self.depth == 0) {
                    out_buf[out_len.*] = pending[0];
                    out_len.* += 1;
                    if (out_len.* == out_buf.len) {
                        downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len.*]));
                        out_len.* = 0;
                    }
                }
                self.consumePrefix(1);
            }
        }

        fn consumePrefix(self: *ThinkStripStreamState, n: usize) void {
            std.debug.assert(n <= self.pending_len);
            if (n == self.pending_len) {
                self.pending_len = 0;
                return;
            }
            const remaining = self.pending_len - n;
            std.mem.copyForwards(u8, self.pending[0..remaining], self.pending[n..self.pending_len]);
            self.pending_len = remaining;
        }
    };

    fn streamThinkSanitizeCallback(ctx_ptr: *anyopaque, chunk: root.StreamChunk) void {
        const ctx: *ThinkStripStreamCtx = @ptrCast(@alignCast(ctx_ptr));
        if (chunk.is_final) {
            ctx.state.finish(ctx.downstream, ctx.downstream_ctx);
            ctx.downstream(ctx.downstream_ctx, root.StreamChunk.finalChunk());
            return;
        }
        ctx.state.feed(chunk.delta, ctx.downstream, ctx.downstream_ctx);
    }

    fn extractMessageText(allocator: std.mem.Allocator, msg_obj: std.json.ObjectMap) !?[]const u8 {
        const content = msg_obj.get("content") orelse return null;

        switch (content) {
            .string => {
                const trimmed = std.mem.trim(u8, content.string, " \t\n\r");
                if (trimmed.len == 0) return null;
                return try allocator.dupe(u8, trimmed);
            },
            .array => {
                var text_parts: std.ArrayListUnmanaged(u8) = .empty;
                defer text_parts.deinit(allocator);

                for (content.array.items) |part| {
                    var candidate: ?[]const u8 = null;
                    switch (part) {
                        .string => candidate = part.string,
                        .object => {
                            if (part.object.get("text")) |text| {
                                if (text == .string) candidate = text.string;
                            }
                        },
                        else => {},
                    }

                    if (candidate) |text_value| {
                        try text_parts.appendSlice(allocator, text_value);
                    }
                }

                const trimmed = std.mem.trim(u8, text_parts.items, " \t\n\r");
                if (trimmed.len == 0) return null;
                return try allocator.dupe(u8, trimmed);
            },
            else => return null,
        }
    }

    /// Parse text content from an OpenAI-compatible response.
    pub fn parseTextResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        if (error_classify.classifyKnownApiError(root_obj)) |kind| {
            const mapped_err = error_classify.kindToError(kind);
            var summary_buf: [1024]u8 = undefined;
            const summary = error_classify.summarizeKnownApiError(root_obj, &summary_buf) orelse @errorName(mapped_err);
            const sanitized = root.sanitizeApiError(allocator, summary) catch null;
            defer if (sanitized) |s| allocator.free(s);
            root.setLastApiErrorDetail("compatible", sanitized orelse summary);
            return mapped_err;
        }

        if (root_obj.get("choices")) |choices| {
            if (choices == .array and choices.array.items.len > 0) {
                if (choices.array.items[0].object.get("message")) |msg| {
                    const msg_obj = msg.object;

                    if (try extractMessageText(allocator, msg_obj)) |text| {
                        defer allocator.free(text);
                        return stripThinkBlocks(allocator, text);
                    }
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Parse a native tool-calling response into ChatResponse (OpenAI-compatible format).
    pub fn parseNativeResponse(allocator: std.mem.Allocator, body: []const u8) !ChatResponse {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        if (error_classify.classifyKnownApiError(root_obj)) |kind| {
            const mapped_err = error_classify.kindToError(kind);
            var summary_buf: [1024]u8 = undefined;
            const summary = error_classify.summarizeKnownApiError(root_obj, &summary_buf) orelse @errorName(mapped_err);
            const sanitized = root.sanitizeApiError(allocator, summary) catch null;
            defer if (sanitized) |s| allocator.free(s);
            root.setLastApiErrorDetail("compatible", sanitized orelse summary);
            return mapped_err;
        }

        if (root_obj.get("choices")) |choices| {
            if (choices == .array and choices.array.items.len > 0) {
                const msg = choices.array.items[0].object.get("message") orelse return error.NoResponseContent;
                const msg_obj = msg.object;

                var content: ?[]const u8 = null;
                errdefer if (content) |c| if (c.len > 0) allocator.free(c);
                var reasoning_content: ?[]const u8 = null;
                errdefer if (reasoning_content) |rc| if (rc.len > 0) allocator.free(rc);
                if (try extractMessageText(allocator, msg_obj)) |message_text| {
                    defer allocator.free(message_text);
                    const split = try splitThinkContent(allocator, message_text);
                    content = split.visible;
                    reasoning_content = split.reasoning;
                }
                // Fallback: some providers return reasoning in native fields.
                // - Z.AI/GLM: `reasoning_content`
                // - Groq/Cerebras parsed format: `reasoning`
                if (reasoning_content == null) {
                    if (msg_obj.get("reasoning_content")) |rc| {
                        if (rc == .string and rc.string.len > 0)
                            reasoning_content = try allocator.dupe(u8, rc.string);
                    }
                }
                if (reasoning_content == null) {
                    if (msg_obj.get("reasoning")) |rc| {
                        if (rc == .string and rc.string.len > 0)
                            reasoning_content = try allocator.dupe(u8, rc.string);
                    }
                }
                if (reasoning_content == null) {
                    if (msg_obj.get("reasoning_details")) |details| {
                        reasoning_content = try root.extractReasoningTextFromDetails(allocator, details);
                    }
                }

                var tool_calls_list: std.ArrayListUnmanaged(ToolCall) = .empty;
                errdefer {
                    for (tool_calls_list.items) |tc| {
                        if (tc.id.len > 0) allocator.free(tc.id);
                        if (tc.name.len > 0) allocator.free(tc.name);
                        if (tc.arguments.len > 0) allocator.free(tc.arguments);
                    }
                    tool_calls_list.deinit(allocator);
                }

                // Regression: GLM-5 (and some other providers) return `"tool_calls": null`
                // instead of omitting the key or returning an empty array.  Accessing
                // `.array` on a `.null` Value panics in Debug and segfaults in ReleaseSmall.
                if (msg_obj.get("tool_calls")) |tc_arr| if (tc_arr == .array) {
                    for (tc_arr.array.items) |tc| {
                        const tc_obj = tc.object;
                        const id = if (tc_obj.get("id")) |i| (if (i == .string) try allocator.dupe(u8, i.string) else try allocator.dupe(u8, "unknown")) else try allocator.dupe(u8, "unknown");

                        if (tc_obj.get("function")) |func| {
                            const func_obj = func.object;
                            const name = if (func_obj.get("name")) |n| (if (n == .string) try allocator.dupe(u8, n.string) else try allocator.dupe(u8, "")) else try allocator.dupe(u8, "");
                            const arguments = if (func_obj.get("arguments")) |a| (if (a == .string) try allocator.dupe(u8, a.string) else try allocator.dupe(u8, "{}")) else try allocator.dupe(u8, "{}");

                            try tool_calls_list.append(allocator, .{
                                .id = id,
                                .name = name,
                                .arguments = arguments,
                            });
                        }
                    }
                };

                // Treat a response with no content, no tool calls, and no reasoning as empty.
                // This happens when the model hits its context limit and returns finish_reason=length
                // with a null or empty content field. Returning NoResponseContent here lets the
                // agent's empty-response retry and model-fallback logic engage rather than
                // silently succeeding with nothing to show.
                const has_content = content != null and content.?.len > 0;
                const has_tools = tool_calls_list.items.len > 0;
                const has_reasoning = reasoning_content != null and reasoning_content.?.len > 0;
                if (!has_content and !has_tools and !has_reasoning) {
                    log.warn("parseNativeResponse: response has no content, tool calls, or reasoning; treating as NoResponseContent", .{});
                    return error.NoResponseContent;
                }

                var usage = TokenUsage{};
                if (root_obj.get("usage")) |usage_obj| {
                    if (usage_obj == .object) {
                        if (usage_obj.object.get("prompt_tokens")) |v| {
                            if (v == .integer) usage.prompt_tokens = @intCast(v.integer);
                        }
                        if (usage_obj.object.get("completion_tokens")) |v| {
                            if (v == .integer) usage.completion_tokens = @intCast(v.integer);
                        }
                        if (usage_obj.object.get("total_tokens")) |v| {
                            if (v == .integer) usage.total_tokens = @intCast(v.integer);
                        }
                    }
                }

                const owned_tool_calls = try tool_calls_list.toOwnedSlice(allocator);
                errdefer {
                    for (owned_tool_calls) |tc| {
                        if (tc.id.len > 0) allocator.free(tc.id);
                        if (tc.name.len > 0) allocator.free(tc.name);
                        if (tc.arguments.len > 0) allocator.free(tc.arguments);
                    }
                    if (owned_tool_calls.len > 0) allocator.free(owned_tool_calls);
                }

                const model_str = if (root_obj.get("model")) |m| (if (m == .string) try allocator.dupe(u8, m.string) else try allocator.dupe(u8, "")) else try allocator.dupe(u8, "");
                errdefer if (model_str.len > 0) allocator.free(model_str);

                return .{
                    .content = content,
                    .tool_calls = owned_tool_calls,
                    .usage = usage,
                    .model = model_str,
                    .reasoning_content = reasoning_content,
                };
            }
        }

        return error.NoResponseContent;
    }

    /// Create a Provider interface from this OpenAiCompatibleProvider.
    pub fn provider(self: *OpenAiCompatibleProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .supports_vision = supportsVisionImpl,
        .supports_vision_for_model = supportsVisionForModelImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .stream_chat = streamChatImpl,
        .supports_streaming = supportsStreamingImpl,
    };

    fn buildSingleTurnMessages(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        merge_system_into_user: bool,
    ) ![]ChatMessage {
        if (merge_system_into_user) {
            if (system_prompt) |sp| {
                const merged = try std.fmt.allocPrint(allocator, "[System: {s}]\n\n{s}", .{ sp, message });
                errdefer allocator.free(merged);
                const messages = try allocator.alloc(ChatMessage, 1);
                messages[0] = .{ .role = .user, .content = merged, .name = "__merged_system__" };
                return messages;
            }
        }

        const messages = try allocator.alloc(ChatMessage, if (system_prompt != null) 2 else 1);
        if (system_prompt) |sp| {
            messages[0] = ChatMessage.system(sp);
            messages[1] = ChatMessage.user(message);
        } else {
            messages[0] = ChatMessage.user(message);
        }
        return messages;
    }

    fn freeSingleTurnMessages(allocator: std.mem.Allocator, messages: []ChatMessage) void {
        for (messages) |msg| {
            if (msg.role == .user and msg.name != null and std.mem.eql(u8, msg.name.?, "__merged_system__")) {
                allocator.free(msg.content);
            }
        }
        allocator.free(messages);
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: root.ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!root.StreamChatResult {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        const effective_model = self.normalizeProviderModel(model);

        if (self.api_mode == .responses) {
            var fallback = try chatImpl(ptr, allocator, request, effective_model, temperature);
            return root.emitChatResponseAsStream(allocator, &fallback, callback, callback_ctx);
        }

        if (shouldSkipStreaming(self.max_streaming_prompt_bytes, request)) {
            const request_text_bytes = estimateRequestTextBytes(request);
            log.warn(
                "{s} streaming skipped for large request ({d} bytes >= {d}); using non-streaming",
                .{ self.name, request_text_bytes, self.max_streaming_prompt_bytes.? },
            );
            var fallback = try chatImpl(ptr, allocator, request, model, temperature);
            return root.emitChatResponseAsStream(allocator, &fallback, callback, callback_ctx);
        }

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildStreamingChatRequestBody(
            allocator,
            request,
            effective_model,
            temperature,
            self.merge_system_into_user,
            self.thinking_param,
            self.enable_thinking_param,
            self.reasoning_split_param,
            self.chat_template_enable_thinking_param,
            request.session_id,
            self.extra_body_params,
        );
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr: ?[]const u8 = if (auth) |a|
            std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError
        else
            null;

        // Build extra headers (User-Agent if configured)
        var extra_headers: [1][]const u8 = undefined;
        var extra_header_count: usize = 0;
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            extra_headers[extra_header_count] = user_agent_hdr.?;
            extra_header_count += 1;
        }

        var sanitize_ctx = ThinkStripStreamCtx{
            .downstream = callback,
            .downstream_ctx = callback_ctx,
        };

        var result = sse.curlStream(
            allocator,
            url,
            body,
            auth_hdr,
            extra_headers[0..extra_header_count],
            request.timeout_secs,
            streamThinkSanitizeCallback,
            @ptrCast(&sanitize_ctx),
        ) catch |err| {
            if (err == error.CurlWaitError or err == error.CurlFailed) {
                log.warn("{s} streaming failed with {}; falling back to non-streaming response", .{ self.name, err });
                // Cap the fallback timeout to 90 s — if streaming stalled (e.g. speed-limit
                // triggered after 60 s of zero throughput) the non-streaming endpoint is
                // likely slow too; avoid blocking for the full message_timeout_secs.
                var fallback_request = request;
                fallback_request.timeout_secs = streamingFallbackTimeoutSecs(request.timeout_secs);
                var fallback = try chatImpl(ptr, allocator, fallback_request, model, temperature);
                return root.emitChatResponseAsStream(allocator, &fallback, callback, callback_ctx);
            }
            return err;
        };

        if (result.content) |raw| {
            const cleaned = try stripThinkBlocks(allocator, raw);
            allocator.free(raw);
            if (cleaned.len == 0) {
                result.content = null;
                result.usage.completion_tokens = 0;
            } else {
                result.content = cleaned;
                result.usage.completion_tokens = @intCast((cleaned.len + 3) / 4);
            }
        }

        return result;
    }

    fn supportsStreamingImpl(ptr: *anyopaque) bool {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return !self.disable_streaming and self.api_mode != .responses;
    }

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        const effective_model = self.normalizeProviderModel(model);

        if (self.api_mode == .responses) {
            const messages = try buildSingleTurnMessages(allocator, system_prompt, message, self.merge_system_into_user);
            defer freeSingleTurnMessages(allocator, messages);

            const request = ChatRequest{
                .messages = messages,
                .model = effective_model,
                .temperature = temperature,
                .timeout_secs = 0,
            };

            const response = try self.chatViaResponses(allocator, request, effective_model, temperature, 0);
            defer {
                if (response.content) |text| allocator.free(text);
                for (response.tool_calls) |tc| {
                    allocator.free(tc.id);
                    allocator.free(tc.name);
                    allocator.free(tc.arguments);
                }
                allocator.free(response.tool_calls);
                if (response.model.len > 0) allocator.free(response.model);
                if (response.reasoning_content) |text| allocator.free(text);
            }

            if (response.content) |text| return try allocator.dupe(u8, text);
            return error.NoResponseContent;
        }

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        // When merge_system_into_user is set, fold the system prompt into
        // the user message so providers that reject the system role still work.
        var eff_system = system_prompt;
        var merged_msg: ?[]const u8 = null;
        defer if (merged_msg) |m| allocator.free(m);
        if (self.merge_system_into_user) {
            if (system_prompt) |sp| {
                merged_msg = try std.fmt.allocPrint(allocator, "[System: {s}]\n\n{s}", .{ sp, message });
                eff_system = null;
            }
        }

        const body = try buildRequestBody(
            allocator,
            eff_system,
            merged_msg orelse message,
            effective_model,
            temperature,
            self.extra_body_params,
        );
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], 0) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseTextResponse(allocator, resp_body) catch |err| {
            // Only switch protocols when chat-completions explicitly reports endpoint absence.
            if (self.supports_responses_fallback and shouldFallbackToResponses(allocator, resp_body)) {
                const fallback_messages = try buildSingleTurnMessages(allocator, eff_system, merged_msg orelse message, false);
                defer freeSingleTurnMessages(allocator, fallback_messages);
                const fallback_request = ChatRequest{
                    .messages = fallback_messages,
                    .model = effective_model,
                    .temperature = temperature,
                    .timeout_secs = 0,
                };
                const fallback_resp = self.chatViaResponses(allocator, fallback_request, effective_model, temperature, 0) catch |fallback_err| {
                    return returnLoggedCompatibleApiError([]const u8, allocator, self.name, fallback_err, url, resp_body);
                };
                defer {
                    if (fallback_resp.content) |text| allocator.free(text);
                    for (fallback_resp.tool_calls) |tc| {
                        allocator.free(tc.id);
                        allocator.free(tc.name);
                        allocator.free(tc.arguments);
                    }
                    allocator.free(fallback_resp.tool_calls);
                    if (fallback_resp.model.len > 0) allocator.free(fallback_resp.model);
                    if (fallback_resp.reasoning_content) |text| allocator.free(text);
                }
                if (fallback_resp.content) |text| return try allocator.dupe(u8, text);
                return error.NoResponseContent;
            }
            logCompatibleApiError(allocator, self.name, err, url, resp_body);
            return err;
        };
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        const effective_model = self.normalizeProviderModel(model);
        const capped_request = self.capNonStreamingMaxTokens(request);

        if (self.api_mode == .responses) {
            return self.chatViaResponses(allocator, capped_request, effective_model, temperature, capped_request.timeout_secs);
        }

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildChatRequestBody(
            allocator,
            capped_request,
            effective_model,
            temperature,
            self.merge_system_into_user,
            self.thinking_param,
            self.enable_thinking_param,
            self.reasoning_split_param,
            self.chat_template_enable_thinking_param,
            capped_request.session_id,
            self.extra_body_params,
        );
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], request.timeout_secs) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body) catch |err| {
            if (self.supports_responses_fallback and shouldFallbackToResponses(allocator, resp_body)) {
                return self.chatViaResponses(
                    allocator,
                    capped_request,
                    effective_model,
                    temperature,
                    capped_request.timeout_secs,
                ) catch |fallback_err| {
                    return returnLoggedCompatibleApiError(ChatResponse, allocator, self.name, fallback_err, url, resp_body);
                };
            }
            logCompatibleApiError(allocator, self.name, err, url, resp_body);
            return err;
        };
    }

    fn supportsNativeToolsImpl(ptr: *anyopaque) bool {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.native_tools;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn supportsVisionForModelImpl(_: *anyopaque, _: []const u8) bool {
        // Vision capability is managed by Agent's vision_disabled_models.
        // Provider assumes all models support vision by default.
        return true;
    }

    fn getNameImpl(ptr: *anyopaque) []const u8 {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.name;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        if (self.owned_base_url) |owned| {
            self.allocator.free(owned);
            self.owned_base_url = null;
        }
    }
};

/// Serialize a single message's content field — delegates to shared helper in providers/helpers.zig.
const serializeMessageContent = root.serializeMessageContent;

/// Serialize messages into a JSON array, optionally merging system messages
/// into the first user message (for providers that reject the system role).
fn serializeMessagesInto(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    messages: []const ChatMessage,
    merge_system: bool,
) !void {
    if (!merge_system) {
        // Standard path: serialize all messages as-is.
        for (messages, 0..) |msg, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "{\"role\":\"");
            try buf.appendSlice(allocator, msg.role.toSlice());
            try buf.appendSlice(allocator, "\",\"content\":");
            try serializeMessageContent(buf, allocator, msg);
            if (msg.tool_call_id) |tc_id| {
                try buf.appendSlice(allocator, ",\"tool_call_id\":");
                try root.appendJsonString(buf, allocator, tc_id);
            }
            try buf.append(allocator, '}');
        }
        return;
    }

    // Merge path: collect system content, prepend to first user message.
    var sys_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer sys_buf.deinit(allocator);
    for (messages) |msg| {
        if (msg.role == .system) {
            if (sys_buf.items.len > 0) try sys_buf.appendSlice(allocator, "\n");
            try sys_buf.appendSlice(allocator, msg.content);
        }
    }

    var first_msg = true;
    var first_user_done = false;
    for (messages) |msg| {
        if (msg.role == .system) continue;

        if (!first_msg) try buf.append(allocator, ',');
        first_msg = false;

        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, msg.role.toSlice());
        try buf.appendSlice(allocator, "\",\"content\":");

        if (!first_user_done and msg.role == .user and sys_buf.items.len > 0) {
            first_user_done = true;
            if (msg.content_parts) |parts| {
                // Prepend system text as a text part, then serialize original parts
                try buf.append(allocator, '[');
                try buf.appendSlice(allocator, "{\"type\":\"text\",\"text\":");
                const sys_prefix = try std.fmt.allocPrint(allocator, "[System: {s}]", .{sys_buf.items});
                defer allocator.free(sys_prefix);
                try root.appendJsonString(buf, allocator, sys_prefix);
                try buf.append(allocator, '}');
                for (parts) |part| {
                    try buf.append(allocator, ',');
                    try root.serializeContentPart(buf, allocator, part);
                }
                try buf.append(allocator, ']');
            } else {
                const merged = try std.fmt.allocPrint(allocator, "[System: {s}]\n\n{s}", .{ sys_buf.items, msg.content });
                defer allocator.free(merged);
                try root.appendJsonString(buf, allocator, merged);
            }
        } else {
            try serializeMessageContent(buf, allocator, msg);
        }

        if (msg.tool_call_id) |tc_id| {
            try buf.appendSlice(allocator, ",\"tool_call_id\":");
            try root.appendJsonString(buf, allocator, tc_id);
        }
        try buf.append(allocator, '}');
    }
}

/// Build a full chat request JSON body from a ChatRequest (OpenAI-compatible format).
fn buildChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
    merge_system: bool,
    thinking_param: bool,
    enable_thinking_param: bool,
    reasoning_split_param: bool,
    chat_template_enable_thinking_param: bool,
    session_id: ?[]const u8,
    extra_body_params: ?[]const u8,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const reasoning_enabled = hasCompatReasoningEnabled(request.reasoning_effort);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (thinking_param) {
        if (reasoning_enabled) {
            try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"enabled\"}");
        } else {
            try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"disabled\"}");
        }
    }
    if (enable_thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"enable_thinking\":true");
    }
    if (reasoning_split_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"reasoning_split\":true");
    }
    if (chat_template_enable_thinking_param) {
        if (reasoning_enabled) {
            try buf.appendSlice(allocator, ",\"chat_template_kwargs\":{\"enable_thinking\":true}");
        } else {
            try buf.appendSlice(allocator, ",\"chat_template_kwargs\":{\"enable_thinking\":false}");
        }
    }
    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsOpenAI(&buf, allocator, tools);
            try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
        }
    }

    try root.appendOpenAiBodyExtraParams(&buf, allocator, session_id, extra_body_params);
    try buf.appendSlice(allocator, ",\"stream\":false}");

    return try buf.toOwnedSlice(allocator);
}

/// Build a streaming chat request JSON body (identical to buildChatRequestBody but with "stream":true).
fn buildStreamingChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
    merge_system: bool,
    thinking_param: bool,
    enable_thinking_param: bool,
    reasoning_split_param: bool,
    chat_template_enable_thinking_param: bool,
    session_id: ?[]const u8,
    extra_body_params: ?[]const u8,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const reasoning_enabled = hasCompatReasoningEnabled(request.reasoning_effort);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (thinking_param) {
        if (reasoning_enabled) {
            try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"enabled\"}");
        } else {
            try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"disabled\"}");
        }
    }
    if (enable_thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"enable_thinking\":true");
    }
    if (reasoning_split_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"reasoning_split\":true");
    }
    if (chat_template_enable_thinking_param) {
        if (reasoning_enabled) {
            try buf.appendSlice(allocator, ",\"chat_template_kwargs\":{\"enable_thinking\":true}");
        } else {
            try buf.appendSlice(allocator, ",\"chat_template_kwargs\":{\"enable_thinking\":false}");
        }
    }
    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsOpenAI(&buf, allocator, tools);
            try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
        }
    }

    try root.appendOpenAiBodyExtraParams(&buf, allocator, session_id, extra_body_params);
    try buf.appendSlice(allocator, ",\"stream\":true,\"stream_options\":{\"include_usage\":true}}");

    return try buf.toOwnedSlice(allocator);
}

fn hasCompatReasoningEnabled(reasoning_effort: ?[]const u8) bool {
    const effort = root.normalizeOpenAiReasoningEffort(reasoning_effort) orelse return false;
    return !std.mem.eql(u8, effort, "none");
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "strips trailing slash" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com/", null, .bearer, null);
    try std.testing.expectEqualStrings("https://example.com", p.base_url);
}

test "chatCompletionsUrl standard" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.openai.com/v1", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.openai.com/v1/chat/completions", url);
}

test "chatCompletionsUrl custom full endpoint" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "volcengine",
        "https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions",
        null,
        .bearer,
        null,
    );
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions", url);
}

test "buildRequestBody with system" {
    const body = try OpenAiCompatibleProvider.buildRequestBody(
        std.testing.allocator,
        "You are helpful",
        "hello",
        "llama-3.3-70b",
        0.4,
        null,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "llama-3.3-70b") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "user") != null);
}

test "buildRequestBody appends extra_body_params" {
    // Regression: chatWithSystem used this builder and previously dropped
    // extra_body_params on the chat-completions path.
    const body = try OpenAiCompatibleProvider.buildRequestBody(
        std.testing.allocator,
        "You are helpful",
        "hello",
        "llama-3.3-70b",
        0.4,
        "{\"seed\":123,\"metadata\":{\"tier\":\"team\"}}",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"seed\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"metadata\":{\"tier\":\"team\"}") != null);
}

test "parseTextResponse extracts content" {
    const body =
        \\{"choices":[{"message":{"content":"Hello from Venice!"}}]}
    ;
    const result = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Venice!", result);
}

test "parseTextResponse strips think blocks" {
    const body =
        \\{"choices":[{"message":{"content":"<think>private reasoning</think>\nVisible answer"}}]}
    ;
    const result = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Visible answer", result);
}

test "parseNativeResponse splits think blocks into content and reasoning_content" {
    const body =
        \\{"choices":[{"message":{"content":"<think>private chain of thought</think>\nVisible answer"}}],"model":"minimax-m2.5"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |content| {
            if (content.len > 0) std.testing.allocator.free(content);
        }
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |reasoning| {
            if (reasoning.len > 0) std.testing.allocator.free(reasoning);
        }
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("private chain of thought", result.reasoning_content.?);
}

test "parseNativeResponse reads native reasoning_content field (Z.AI/GLM style)" {
    const body =
        \\{"choices":[{"message":{"content":"Final answer","reasoning_content":"chain of thought"}}],"model":"glm-4.7-thinking"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Final answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("chain of thought", result.reasoning_content.?);
}

test "parseNativeResponse reads native reasoning field (Groq/Cerebras parsed format)" {
    const body =
        \\{"choices":[{"message":{"content":"Final answer","reasoning":"parsed reasoning trace"}}],"model":"qwen/qwen3-32b"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Final answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("parsed reasoning trace", result.reasoning_content.?);
}

test "parseNativeResponse reads reasoning_details field" {
    const body =
        \\{"choices":[{"message":{"content":"Visible answer","reasoning_details":[{"type":"reasoning.summary","summary":"plan"},{"type":"reasoning.text","text":"step by step"}]}}],"model":"openrouter/auto"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expectEqualStrings("plan\nstep by step", result.reasoning_content.?);
}

test "parseNativeResponse supports content array text parts" {
    const body =
        \\{"choices":[{"message":{"content":[{"type":"text","text":"Hello "},{"type":"text","text":"from kimi-k2.5"}]}}],"model":"kimi-k2.5"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Hello from kimi-k2.5", result.content.?);
    try std.testing.expect(result.reasoning_content == null);
}

test "parseNativeResponse null content with no tools or reasoning returns NoResponseContent" {
    // Simulates GLM-5 hitting its context limit: finish_reason=length, content=null.
    // All three payloads (content, tool_calls, reasoning_content) are absent/empty.
    // parseNativeResponse must return NoResponseContent so the agent's retry/fallback chain engages.
    const body =
        \\{"choices":[{"message":{"content":null},"finish_reason":"length"}],"model":"glm-5"}
    ;
    try std.testing.expectError(
        error.NoResponseContent,
        OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body),
    );
}

test "parseNativeResponse empty string content with no tools or reasoning returns NoResponseContent" {
    const body =
        \\{"choices":[{"message":{"content":""},"finish_reason":"length"}],"model":"glm-5"}
    ;
    try std.testing.expectError(
        error.NoResponseContent,
        OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body),
    );
}

test "parseNativeResponse null content with reasoning_content succeeds" {
    // Reasoning-only response (thinking model that produced a CoT but no final text) is valid.
    const body =
        \\{"choices":[{"message":{"content":null,"reasoning_content":"step-by-step reasoning here"}}],"model":"glm-z1"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content == null);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("step-by-step reasoning here", result.reasoning_content.?);
}

test "parseNativeResponse null content with native tool calls succeeds" {
    // Models that emit tool_calls with no text content are valid — the agent should
    // execute the tool, not treat the response as empty.
    const body =
        \\{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call-1","function":{"name":"list_dir","arguments":"{\"path\":\"/tmp\"}"}}]}}],"model":"glm-5"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content == null);
    try std.testing.expect(result.tool_calls.len == 1);
    try std.testing.expectEqualStrings("list_dir", result.tool_calls[0].name);
    try std.testing.expectEqualStrings("call-1", result.tool_calls[0].id);
}

test "parseNativeResponse tool_calls null does not crash" {
    // Regression: GLM-5 on infini-ai returns "tool_calls": null in the message.
    // Both parseTextResponse and parseNativeResponse must not panic on this shape.
    const body =
        \\{"choices":[{"finish_reason":"stop","message":{"content":"pong","reasoning_content":"thinking","role":"assistant","tool_calls":null}}],"model":"glm-5","usage":{"prompt_tokens":12,"completion_tokens":16,"total_tokens":28}}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
    }
    try std.testing.expect(result.tool_calls.len == 0);
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("pong", result.content.?);
}

test "parseTextResponse tool_calls null does not crash" {
    // Regression: same shape, non-native parse path.
    const body =
        \\{"choices":[{"message":{"content":"pong","tool_calls":null}}]}
    ;
    const text = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("pong", text);
}

test "buildChatRequestBody emits thinking param for GLM when reasoning_effort set" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "glm-4.7-thinking",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "glm-4.7-thinking", 0.7, false, true, false, false, false, null, null);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\":{\"type\":\"enabled\"}") != null);
}

test "buildChatRequestBody omits thinking param when thinking_param false" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "some-model",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "some-model", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\"") == null);
}

test "buildChatRequestBody emits enable_thinking when configured" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "qwen3-thinking",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "qwen3-thinking", 0.7, false, false, true, false, false, null, null);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") != null);
}

test "buildChatRequestBody emits reasoning_split when configured" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "minimax-m2",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "minimax-m2", 0.7, false, false, false, true, false, null, null);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") != null);
}

test "buildChatRequestBody emits chat_template enable_thinking when configured" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "qwen3.5-27b",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "qwen3.5-27b", 0.7, false, false, false, false, true, null, null);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"chat_template_kwargs\":{\"enable_thinking\":true}") != null);
}

test "buildChatRequestBody sends thinking disabled when reasoning_effort unset" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "glm-4.7-thinking",
    };
    const body = try buildChatRequestBody(allocator, req, "glm-4.7-thinking", 0.7, false, true, true, true, false, null, null);
    defer allocator.free(body);
    // Regression: GLM defaults deep thinking to enabled unless we explicitly send disabled.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\":{\"type\":\"disabled\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") == null);
}

test "buildChatRequestBody appends session_id and extra_body_params" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-4o",
        .session_id = "session-123",
    };
    const body = try buildChatRequestBody(
        allocator,
        req,
        "gpt-4o",
        0.7,
        false,
        false,
        false,
        false,
        false,
        req.session_id,
        "{\"seed\":321,\"metadata\":{\"tier\":\"team\"}}",
    );
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"user\":\"session-123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"seed\":321") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"metadata\":{\"tier\":\"team\"}") != null);
}

test "streamThinkSanitizeCallback strips think blocks across chunk boundaries" {
    const Collector = struct {
        allocator: std.mem.Allocator,
        buf: std.ArrayListUnmanaged(u8) = .empty,
        saw_final: bool = false,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.saw_final = true;
                return;
            }
            self.buf.appendSlice(self.allocator, chunk.delta) catch unreachable;
        }

        fn deinit(self: *@This()) void {
            self.buf.deinit(self.allocator);
        }
    };

    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();

    var sanitize_ctx = OpenAiCompatibleProvider.ThinkStripStreamCtx{
        .downstream = Collector.callback,
        .downstream_ctx = @ptrCast(&collector),
    };

    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("<thi"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("nk>private reasoning"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("</think>\nVisible answer"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.finalChunk());

    try std.testing.expect(collector.saw_final);
    try std.testing.expectEqualStrings("\nVisible answer", collector.buf.items);
}

test "streamThinkSanitizeCallback preserves incomplete think tag literals" {
    const Collector = struct {
        allocator: std.mem.Allocator,
        buf: std.ArrayListUnmanaged(u8) = .empty,
        saw_final: bool = false,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.saw_final = true;
                return;
            }
            self.buf.appendSlice(self.allocator, chunk.delta) catch unreachable;
        }

        fn deinit(self: *@This()) void {
            self.buf.deinit(self.allocator);
        }
    };

    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();

    var sanitize_ctx = OpenAiCompatibleProvider.ThinkStripStreamCtx{
        .downstream = Collector.callback,
        .downstream_ctx = @ptrCast(&collector),
    };

    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("literal <thi"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.finalChunk());

    try std.testing.expect(collector.saw_final);
    try std.testing.expectEqualStrings("literal <thi", collector.buf.items);
}

test "parseTextResponse empty choices" {
    const body =
        \\{"choices":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse classifies rate-limit errors" {
    const body =
        \\{"error":{"message":"Too many requests","type":"rate_limit_error","status":429}}
    ;
    try std.testing.expectError(error.RateLimited, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
}

test "authHeaderValue bearer style" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .bearer, null);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("authorization", auth.name);
    try std.testing.expectEqualStrings("Bearer my-key", auth.value);
}

test "authHeaderValue x-api-key style" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .x_api_key, null);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("x-api-key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
}

test "authHeaderValue no key" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer, null);
    try std.testing.expect(try p.authHeaderValue(std.testing.allocator) == null);
}

test "chatCompletionsUrl trailing slash stripped" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1/", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/chat/completions", url);
}

test "chatCompletionsUrl without v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/chat/completions", url);
}

test "chatCompletionsUrl with v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/chat/completions", url);
}

test "buildRequestBody without system" {
    const body = try OpenAiCompatibleProvider.buildRequestBody(
        std.testing.allocator,
        null,
        "hello",
        "model",
        0.7,
        null,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":false") != null);
}

test "normalizeProviderModel maps DeepSeek v3.2 aliases to deepseek-chat" {
    const deepseek = OpenAiCompatibleProvider.init(std.testing.allocator, "deepseek", "https://api.deepseek.com", null, .bearer, null);
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek/deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-reasoner", deepseek.normalizeProviderModel("deepseek-reasoner"));
}

test "normalizeProviderModel leaves other providers unchanged" {
    const openrouter = OpenAiCompatibleProvider.init(std.testing.allocator, "openrouter", "https://openrouter.ai/api/v1", null, .bearer, null);
    try std.testing.expectEqualStrings("deepseek-v3.2", openrouter.normalizeProviderModel("deepseek-v3.2"));
}

test "parseTextResponse with null content fails" {
    const body =
        \\{"choices":[{"message":{"content":null}}]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse does not surface reasoning_content as visible content" {
    const body =
        \\{"choices":[{"message":{"content":null,"reasoning_content":"private chain of thought"}}]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse supports content array text parts" {
    const body =
        \\{"choices":[{"message":{"content":[{"type":"text","text":"Hello "},{"type":"text","text":"from kimi-k2.5"}]}}]}
    ;
    const result = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from kimi-k2.5", result);
}

test "AuthStyle headerName" {
    try std.testing.expectEqualStrings("authorization", AuthStyle.bearer.headerName());
    try std.testing.expectEqualStrings("x-api-key", AuthStyle.x_api_key.headerName());
}

test "provider getName returns custom name" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "Venice", "https://api.venice.ai", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expectEqualStrings("Venice", prov.getName());
}

test "chatCompletionsUrl requires exact suffix match" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/v2/llm/chat/completions-proxy",
        null,
        .bearer,
        null,
    );
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/v2/llm/chat/completions-proxy/chat/completions", url);
}

test "supportsNativeTools returns true for compatible" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

test "capNonStreamingMaxTokens caps request max_tokens above provider limit" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 8000 };
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "fireworks", "https://api.fireworks.ai/inference/v1", "key", .bearer, null);
    p.max_tokens_non_streaming = 4096;

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 4096), capped.max_tokens);
    try std.testing.expectEqual(@as(?u32, 8000), req.max_tokens);
}

test "capNonStreamingMaxTokens keeps request max_tokens when already below limit" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 1024 };
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "fireworks", "https://api.fireworks.ai/inference/v1", "key", .bearer, null);
    p.max_tokens_non_streaming = 4096;

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 1024), capped.max_tokens);
}

test "capNonStreamingMaxTokens leaves request unchanged when limit is unset" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 8000 };
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "generic", "https://example.com/v1", "key", .bearer, null);

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 8000), capped.max_tokens);
}

test "streamingFallbackTimeoutSecs caps stalled-stream fallback timeout" {
    // Regression: a provider that stalls on both streaming and non-streaming
    // paths must not consume the full message_timeout_secs twice.
    try std.testing.expectEqual(@as(u64, STREAMING_FALLBACK_TIMEOUT_SECS), OpenAiCompatibleProvider.streamingFallbackTimeoutSecs(0));
    try std.testing.expectEqual(@as(u64, 45), OpenAiCompatibleProvider.streamingFallbackTimeoutSecs(45));
    try std.testing.expectEqual(@as(u64, STREAMING_FALLBACK_TIMEOUT_SECS), OpenAiCompatibleProvider.streamingFallbackTimeoutSecs(300));
}

// ════════════════════════════════════════════════════════════════════════════
// Responses API tests
// ════════════════════════════════════════════════════════════════════════════

test "responsesUrl standard base" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer, null);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/responses", url);
}

test "responsesUrl with v1 no duplicate" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer, null);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/responses", url);
}

test "responsesUrl derives from chat endpoint" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/api/v2/chat/completions",
        null,
        .bearer,
        null,
    );
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/responses", url);
}

test "responsesUrl custom full endpoint preserved" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/api/v2/responses",
        null,
        .bearer,
        null,
    );
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/responses", url);
}

test "responsesUrl non-v1 api path uses raw suffix" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/api/coding/v3", null, .bearer, null);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/api/coding/v3/responses", url);
}

test "shouldFallbackToResponses only for explicit 404 payloads" {
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"Not found\",\"code\":404}}"));
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"status\":404,\"message\":\"unknown endpoint\"}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"No endpoints found that support image input\",\"code\":404}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"model not found\",\"code\":404}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"temporary overload\",\"code\":503}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"choices\":[{\"message\":{\"content\":\"ok\"}}]}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "not json at all"));
}

test "shouldFallbackToResponses accepts msg fallback fields" {
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"msg\":\"Not found\",\"code\":404}}"));
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"status\":404,\"msg\":\"unknown endpoint\"}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"msg\":\"No endpoints found that support image input\",\"code\":404}}"));
}

test "structured chat endpoint 404 payloads surface as ApiError" {
    // Regression: #766 follow-up — structured endpoint 404s are still generic
    // API errors, so the fallback must key off the body instead of parser errors.
    const body = "{\"error\":{\"message\":\"https://integrate.api.nvidia.com/v1/chat/completions 404 page not found\",\"code\":404}}";

    try std.testing.expectError(error.ApiError, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
    try std.testing.expectError(error.ApiError, OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body));
}

test "shouldFallbackToResponses accepts plain text chat endpoint 404" {
    // Regression: #766 — some gateways return the missing endpoint as plain
    // text instead of a JSON error envelope.
    try std.testing.expect(shouldFallbackToResponses(
        std.testing.allocator,
        "https://integrate.api.nvidia.com/v1/chat/completions 404 page not found",
    ));
    try std.testing.expect(!shouldFallbackToResponses(
        std.testing.allocator,
        "https://integrate.api.nvidia.com/v1/responses 404 page not found",
    ));
    try std.testing.expect(!shouldFallbackToResponses(
        std.testing.allocator,
        "temporary overload",
    ));
}

test "returnLoggedCompatibleApiError preserves fallback error" {
    // Regression: when chat-completions 404 falls back to Responses, a failure
    // on the second request must surface the Responses error, not the original one.
    try std.testing.expectError(
        error.RateLimited,
        returnLoggedCompatibleApiError(
            void,
            std.testing.allocator,
            "test",
            error.RateLimited,
            "https://example.com/v1/chat/completions",
            "{\"error\":{\"message\":\"Too many requests\",\"status\":429}}",
        ),
    );
}

test "responsesUrl requires exact suffix match" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/api/v2/responses-proxy",
        null,
        .bearer,
        null,
    );
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/responses-proxy/responses", url);
}

test "extractResponsesText top-level output_text" {
    const body =
        \\{"output_text":"Hello from top-level","output":[]}
    ;
    const result = try OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from top-level", result);
}

test "extractResponsesText strips think blocks" {
    const body =
        \\{"output_text":"<think>private reasoning</think>\nVisible answer","output":[]}
    ;
    const result = try OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Visible answer", result);
}

test "extractResponsesText nested output_text type" {
    const body =
        \\{"output":[{"content":[{"type":"output_text","text":"Hello from nested"}]}]}
    ;
    const result = try OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from nested", result);
}

test "extractResponsesText fallback any text" {
    const body =
        \\{"output":[{"content":[{"type":"message","text":"Fallback text"}]}]}
    ;
    const result = try OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Fallback text", result);
}

test "extractResponsesText empty returns error" {
    const body =
        \\{"output":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body));
}

test "buildResponsesRequestBody with system" {
    const messages = [_]root.ChatMessage{
        root.ChatMessage.system("You are helpful"),
        root.ChatMessage.user("hello"),
    };
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-4o",
            .temperature = 0.7,
            .timeout_secs = 0,
        },
        "gpt-4o",
        0.7,
        null,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "gpt-4o") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "instructions") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "You are helpful") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
}

test "buildResponsesRequestBody preserves short system prompt" {
    const messages = [_]root.ChatMessage{
        root.ChatMessage.system("hi"),
        root.ChatMessage.user("hello"),
    };
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-4o",
            .temperature = 0.7,
            .timeout_secs = 0,
        },
        "gpt-4o",
        0.7,
        null,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"instructions\":\"hi\"") != null);
}

test "buildResponsesRequestBody without system" {
    const messages = [_]root.ChatMessage{
        root.ChatMessage.user("hello"),
    };
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-4o",
            .temperature = 0.7,
            .timeout_secs = 0,
        },
        "gpt-4o",
        0.7,
        null,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "gpt-4o") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "instructions") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
}

test "buildResponsesRequestBody includes tools and tool results" {
    const messages = [_]root.ChatMessage{
        root.ChatMessage.user("list files"),
        root.ChatMessage.toolMsg("done", "call_123"),
    };
    const tools = [_]root.ToolSpec{.{
        .name = "bash",
        .description = "Run shell command",
        .parameters_json = "{\"type\":\"object\"}",
    }};
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-5.4",
            .temperature = 0.2,
            .max_tokens = 512,
            .tools = &tools,
            .timeout_secs = 30,
            .reasoning_effort = "medium",
        },
        "gpt-5.4",
        0.2,
        null,
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"function_call_output\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "call_123") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"tools\"") != null);
    // Verify flat tool schema: "name" at top level, no nested "function" wrapper
    try std.testing.expect(std.mem.indexOf(u8, body, "\"type\":\"function\",\"name\":\"bash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"function\":{\"name\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"tool_choice\":\"auto\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_output_tokens\":512") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning\":{\"effort\":\"medium\"}") != null);
}

test "buildResponsesRequestBody includes image parts with responses schema" {
    const parts = [_]root.ContentPart{
        root.makeTextPart("describe this"),
        root.makeImageUrlPart("https://example.com/cat.png"),
        root.makeBase64ImagePart("Zm9v", "image/png"),
    };
    const messages = [_]root.ChatMessage{.{
        .role = .user,
        .content = "describe this",
        .content_parts = &parts,
    }};
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-4.1",
            .temperature = 0.7,
            .timeout_secs = 0,
        },
        "gpt-4.1",
        0.7,
        null,
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"input_text\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"input_image\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"image_url\":\"https://example.com/cat.png\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"detail\":\"auto\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"image_url\":\"data:image/png;base64,Zm9v\"") != null);
}

test "buildResponsesRequestBody appends session_id and extra_body_params" {
    const messages = [_]root.ChatMessage{
        root.ChatMessage.user("hello"),
    };
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        .{
            .messages = &messages,
            .model = "gpt-4.1",
            .temperature = 0.7,
            .timeout_secs = 0,
            .session_id = "session-456",
        },
        "gpt-4.1",
        0.7,
        "{\"seed\":99,\"metadata\":{\"tier\":\"pro\"}}",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"user\":\"session-456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"seed\":99") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"metadata\":{\"tier\":\"pro\"}") != null);
}

test "parseResponsesResponse extracts function call text and reasoning summary" {
    const body =
        \\{"model":"gpt-5.4","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15},"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Need tool"}]},{"type":"reasoning","summary":[{"type":"summary_text","text":"thinking summary"}]},{"type":"function_call","call_id":"call_1","name":"bash","arguments":"{\"command\":\"ls\"}"}]}
    ;
    const result = try OpenAiCompatibleProvider.parseResponsesResponse(std.testing.allocator, body);
    defer {
        if (result.content) |text| std.testing.allocator.free(text);
        for (result.tool_calls) |tc| {
            std.testing.allocator.free(tc.id);
            std.testing.allocator.free(tc.name);
            std.testing.allocator.free(tc.arguments);
        }
        std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |text| std.testing.allocator.free(text);
    }

    try std.testing.expectEqualStrings("Need tool", result.content.?);
    try std.testing.expectEqual(@as(usize, 1), result.tool_calls.len);
    try std.testing.expectEqualStrings("call_1", result.tool_calls[0].id);
    try std.testing.expectEqualStrings("bash", result.tool_calls[0].name);
    try std.testing.expectEqualStrings("{\"command\":\"ls\"}", result.tool_calls[0].arguments);
    try std.testing.expectEqual(@as(u32, 10), result.usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 5), result.usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 15), result.usage.total_tokens);
    try std.testing.expectEqualStrings("gpt-5.4", result.model);
    try std.testing.expectEqualStrings("thinking summary", result.reasoning_content.?);
}

test "parseResponsesResponse maps generic error envelope" {
    const body =
        \\{"error":{"message":"An error occurred while processing your request."}}
    ;
    try std.testing.expectError(error.ApiError, OpenAiCompatibleProvider.parseResponsesResponse(std.testing.allocator, body));
}

test "parseResponsesResponse handles error:null without returning error" {
    const body =
        \\{"error":null,"output":[{"role":"assistant","content":[{"text":"Hello"}]}]}
    ;
    const result = try OpenAiCompatibleProvider.parseResponsesResponse(std.testing.allocator, body);
    defer {
        if (result.content) |t| std.testing.allocator.free(t);
        for (result.tool_calls) |tc| {
            std.testing.allocator.free(tc.id);
            std.testing.allocator.free(tc.name);
            std.testing.allocator.free(tc.arguments);
        }
        std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |t| std.testing.allocator.free(t);
    }
    try std.testing.expectEqualStrings("Hello", result.content.?);
}

test "AuthStyle custom headerName fallback" {
    try std.testing.expectEqualStrings("authorization", AuthStyle.custom.headerName());
}

test "authHeaderValue custom style" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom, null);
    p.custom_header = "X-Custom-Key";
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("X-Custom-Key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
    try std.testing.expect(!auth.needs_free);
}

test "authHeaderValue custom style without custom_header falls back" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom, null);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("authorization", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
}

// ════════════════════════════════════════════════════════════════════════════
// Streaming tests
// ════════════════════════════════════════════════════════════════════════════

test "buildStreamingChatRequestBody contains stream true" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model" };

    const body = try buildStreamingChatRequestBody(allocator, req, "test-model", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"include_usage\":true") != null);
}

test "buildStreamingChatRequestBody sends thinking disabled when reasoning_effort unset" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "test-model",
    };
    const body = try buildStreamingChatRequestBody(allocator, req, "test-model", 0.7, false, true, true, true, false, null, null);
    defer allocator.free(body);
    // Regression: GLM defaults deep thinking to enabled unless we explicitly send disabled.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\":{\"type\":\"disabled\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") == null);
}

test "buildStreamingChatRequestBody appends session_id and extra_body_params" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-4o",
        .session_id = "session-789",
    };
    const body = try buildStreamingChatRequestBody(
        allocator,
        req,
        "gpt-4o",
        0.7,
        false,
        false,
        false,
        false,
        false,
        req.session_id,
        "{\"seed\":654}",
    );
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"user\":\"session-789\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"seed\":654") != null);
}

test "supportsStreaming returns true for compatible by default" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsStreaming());
}

test "supportsStreaming returns false when disable_streaming enabled" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "glm", "https://api.z.ai/api/paas/v4", "key", .bearer, null);
    p.disable_streaming = true;
    const prov = p.provider();
    try std.testing.expect(!prov.supportsStreaming());
}

test "validateUserAgent rejects CRLF injection" {
    try std.testing.expect(OpenAiCompatibleProvider.validateUserAgent("nullclaw/1.0"));
    try std.testing.expect(!OpenAiCompatibleProvider.validateUserAgent("bad\r\nX-Test: 1"));
}

test "vtable has stream_chat not null" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.vtable.stream_chat != null);
}

test "streaming body has same messages as non-streaming" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test message")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const non_stream = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(non_stream);

    const stream = try buildStreamingChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(stream);

    // Both should contain the message
    try std.testing.expect(std.mem.indexOf(u8, non_stream, "test message") != null);
    try std.testing.expect(std.mem.indexOf(u8, stream, "test message") != null);

    // Different stream values
    try std.testing.expect(std.mem.indexOf(u8, non_stream, "\"stream\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, stream, "\"stream\":true") != null);
}

test "streaming body has model field" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "custom-model" };

    const body = try buildStreamingChatRequestBody(allocator, req, "custom-model", 0.5, false, false, false, false, false, null, null);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "custom-model") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// Multimodal serialization tests
// ════════════════════════════════════════════════════════════════════════════

test "buildChatRequestBody without content_parts serializes plain string" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("plain text")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    // Content should be a plain string, not an array
    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?;
    try std.testing.expect(content == .string);
    try std.testing.expectEqualStrings("plain text", content.string);
}

test "buildChatRequestBody with image_url content_parts serializes OpenAI array" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        root.makeTextPart("What is in this image?"),
        root.makeImageUrlPart("https://example.com/cat.jpg"),
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    // Content should be an array
    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?;
    try std.testing.expect(content == .array);
    try std.testing.expect(content.array.items.len == 2);

    // First part: text
    const text_part = content.array.items[0].object;
    try std.testing.expectEqualStrings("text", text_part.get("type").?.string);
    try std.testing.expectEqualStrings("What is in this image?", text_part.get("text").?.string);

    // Second part: image_url
    const img_part = content.array.items[1].object;
    try std.testing.expectEqualStrings("image_url", img_part.get("type").?.string);
    const img_url_obj = img_part.get("image_url").?.object;
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", img_url_obj.get("url").?.string);
    try std.testing.expectEqualStrings("auto", img_url_obj.get("detail").?.string);
}

test "buildChatRequestBody with base64 image serializes as data URI" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        root.makeBase64ImagePart("AQID", "image/jpeg"),
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    // Should contain the data URI
    try std.testing.expect(std.mem.indexOf(u8, body, "data:image/jpeg;base64,AQID") != null);
}

test "buildChatRequestBody with high detail image_url" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        .{ .image_url = .{ .url = "https://example.com/photo.png", .detail = .high } },
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?.array;
    const img_url_obj = content.items[0].object.get("image_url").?.object;
    try std.testing.expectEqualStrings("high", img_url_obj.get("detail").?.string);
}

test "buildRequestBody reasoning model omits temperature" {
    const body = try OpenAiCompatibleProvider.buildRequestBody(std.testing.allocator, null, "hello", "gpt-5", 0.5, null);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":false") != null);
}

test "buildChatRequestBody o1 omits temperature" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "o1",
        .temperature = 0.7,
        .max_tokens = 100,
    };

    const body = try buildChatRequestBody(allocator, req, "o1", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    // Reasoning model: no temperature, uses max_completion_tokens
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
}

test "buildStreamingChatRequestBody reasoning model omits temperature" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-5.2",
        .temperature = 0.5,
        .max_tokens = 200,
    };

    const body = try buildStreamingChatRequestBody(allocator, req, "gpt-5.2", 0.5, false, false, false, false, false, null, null);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// merge_system_into_user tests
// ════════════════════════════════════════════════════════════════════════════

test "merge_system_into_user merges system into first user message" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Be helpful"),
        root.ChatMessage.user("hello"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    // System message should be gone, only user message remains
    try std.testing.expect(messages.items.len == 1);
    const content = messages.items[0].object.get("content").?.string;
    try std.testing.expect(std.mem.indexOf(u8, content, "[System: Be helpful]") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "hello") != null);
    try std.testing.expectEqualStrings("user", messages.items[0].object.get("role").?.string);
}

test "merge_system_into_user with no system messages passes through" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.user("hello"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 1);
    try std.testing.expectEqualStrings("hello", messages.items[0].object.get("content").?.string);
}

test "merge_system_into_user false keeps system messages" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Be helpful"),
        root.ChatMessage.user("hello"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, false, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 2);
    try std.testing.expectEqualStrings("system", messages.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("user", messages.items[1].object.get("role").?.string);
}

test "merge_system_into_user field defaults to false" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer, null);
    try std.testing.expect(!p.merge_system_into_user);
}

test "merge_system_into_user with multiple system messages concatenates" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Rule 1"),
        root.ChatMessage.system("Rule 2"),
        root.ChatMessage.user("hello"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 1);
    const content = messages.items[0].object.get("content").?.string;
    // Both system messages should be joined with \n
    try std.testing.expect(std.mem.indexOf(u8, content, "Rule 1\nRule 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "hello") != null);
}

test "merge_system_into_user preserves assistant messages" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Be helpful"),
        root.ChatMessage.user("hello"),
        root.ChatMessage.assistant("Hi!"),
        root.ChatMessage.user("bye"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    // system removed, 3 messages remain: merged user, assistant, user
    try std.testing.expect(messages.items.len == 3);
    try std.testing.expectEqualStrings("user", messages.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("assistant", messages.items[1].object.get("role").?.string);
    try std.testing.expectEqualStrings("user", messages.items[2].object.get("role").?.string);
    // Only first user message has the merge prefix
    const first_content = messages.items[0].object.get("content").?.string;
    try std.testing.expect(std.mem.indexOf(u8, first_content, "[System:") != null);
    const last_content = messages.items[2].object.get("content").?.string;
    try std.testing.expectEqualStrings("bye", last_content);
}

test "merge_system_into_user streaming body also merges" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Be concise"),
        root.ChatMessage.user("summarize"),
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "test" };

    const body = try buildStreamingChatRequestBody(allocator, req, "test", 0.7, true, false, false, false, false, null, null);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 1);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    const content = messages.items[0].object.get("content").?.string;
    try std.testing.expect(std.mem.indexOf(u8, content, "[System: Be concise]") != null);
}

test "max_streaming_prompt_bytes null means no limit" {
    // A provider with no limit set should never skip to non-streaming regardless of payload size.
    const prov = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "test",
        "https://api.example.com/v1",
        "key",
        .bearer,
        null,
    );
    // null = no limit
    try std.testing.expectEqual(@as(?usize, null), prov.max_streaming_prompt_bytes);
}

test "max_streaming_prompt_bytes set applies threshold" {
    // A provider with a limit set should reflect it.
    var prov = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "test",
        "https://api.example.com/v1",
        "key",
        .bearer,
        null,
    );
    prov.max_streaming_prompt_bytes = 65536;
    try std.testing.expectEqual(@as(?usize, 65536), prov.max_streaming_prompt_bytes);

    // A small message should be under the limit; a large one should exceed it.
    const small_msgs = [_]root.ChatMessage{root.ChatMessage.user("hi")};
    const small_req = root.ChatRequest{ .messages = &small_msgs, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.estimateRequestTextBytes(small_req) < 65536);

    const big_content = "x" ** 70000;
    const big_msgs = [_]root.ChatMessage{root.ChatMessage.user(big_content)};
    const big_req = root.ChatRequest{ .messages = &big_msgs, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.estimateRequestTextBytes(big_req) >= 65536);
}

test "DEFAULT_MAX_STREAMING_PROMPT_BYTES legacy value is 32 KiB" {
    try std.testing.expectEqual(@as(usize, 32 * 1024), DEFAULT_MAX_STREAMING_PROMPT_BYTES);
}

// ════════════════════════════════════════════════════════════════════════════
// shouldSkipStreaming — behavioural branch tests
// ════════════════════════════════════════════════════════════════════════════

test "shouldSkipStreaming: null limit never skips streaming" {
    // Even a payload larger than the old 32 KiB hardcoded limit must NOT skip
    // when max_streaming_prompt_bytes is null (the new default).
    const big_content = "x" ** 70000; // 70 KiB > old 32 KiB limit
    const msgs = [_]root.ChatMessage{root.ChatMessage.user(big_content)};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(null, req));
}

test "shouldSkipStreaming: below limit does not skip" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };
    // limit = 1 MiB, 5 bytes << 1 MiB
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(1024 * 1024, req));
}

test "shouldSkipStreaming: at limit skips" {
    // Content of exactly `limit` bytes should trigger the fallback.
    const content = "a" ** 100;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user(content)};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.shouldSkipStreaming(100, req));
}

test "shouldSkipStreaming: above limit skips" {
    const content = "a" ** 101;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user(content)};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.shouldSkipStreaming(100, req));
}

test "shouldSkipStreaming: old 32KiB limit would have skipped typical session with 50 MCP tools" {
    // Regression: with the old hardcoded 32 KiB threshold a session loaded with
    // 50 Vikunja tools (~46-48 KiB of text) always fell back to non-streaming.
    // The new default (null) must never skip it.
    const content = "x" ** 48000; // representative of typical session text estimate
    const msgs = [_]root.ChatMessage{root.ChatMessage.user(content)};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };

    // Old hardcoded limit would have skipped.
    try std.testing.expect(OpenAiCompatibleProvider.shouldSkipStreaming(DEFAULT_MAX_STREAMING_PROMPT_BYTES, req));
    // New default (null) must not skip.
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(null, req));
}

// ════════════════════════════════════════════════════════════════════════════
// estimateRequestTextBytes — edge cases (GAP-6, GAP-7, GAP-8)
// ════════════════════════════════════════════════════════════════════════════

test "estimateRequestTextBytes: empty messages slice returns zero" {
    // GAP-6: Must not crash on an empty slice and must return 0.
    const req = root.ChatRequest{ .messages = &.{}, .model = "m" };
    try std.testing.expectEqual(@as(usize, 0), OpenAiCompatibleProvider.estimateRequestTextBytes(req));
}

test "estimateRequestTextBytes: counts content_parts text and ignores non-text" {
    // GAP-7: Only text parts inside content_parts should be counted; image
    // parts must not contribute to the byte total.
    const text_part = root.ContentPart{ .text = "hello world" }; // 11 bytes
    const image_part = root.ContentPart{ .image_url = .{ .url = "https://x.com/img.jpg", .detail = .auto } };
    var parts = [_]root.ContentPart{ text_part, image_part };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    };
    const req = root.ChatRequest{ .messages = &[_]root.ChatMessage{msg}, .model = "m" };
    // Only "hello world" (11 bytes) — not the image URL — is counted.
    try std.testing.expectEqual(@as(usize, 11), OpenAiCompatibleProvider.estimateRequestTextBytes(req));
}

test "estimateRequestTextBytes: accumulates across multiple messages" {
    // GAP-8: Total must be the sum across all messages, not just the last.
    const m1 = root.ChatMessage.user("aaa"); // 3 bytes
    const m2 = root.ChatMessage.user("bbbb"); // 4 bytes
    const m3 = root.ChatMessage.user("ccccc"); // 5 bytes
    const req = root.ChatRequest{ .messages = &[_]root.ChatMessage{ m1, m2, m3 }, .model = "m" };
    try std.testing.expectEqual(@as(usize, 12), OpenAiCompatibleProvider.estimateRequestTextBytes(req));
}

// ════════════════════════════════════════════════════════════════════════════
// shouldSkipStreaming — additional edge cases (GAP-9, GAP-10, GAP-11)
// ════════════════════════════════════════════════════════════════════════════

test "shouldSkipStreaming: zero limit skips any non-empty request" {
    // GAP-9: A limit of 0 means every message (≥1 byte) should fall back.
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("x")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.shouldSkipStreaming(0, req));
}

test "shouldSkipStreaming: empty request never skips regardless of limit" {
    // GAP-10: Zero-byte payload is always below any limit (including 0 is
    // 0 >= 0 = true — but an empty messages slice returns 0 bytes, and 0 >= 0
    // means a zero limit would still skip an empty request; document actual behaviour).
    const req = root.ChatRequest{ .messages = &.{}, .model = "m" };
    // With a non-zero limit: 0 bytes < limit → no skip.
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(1, req));
    // With null: always no skip.
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(null, req));
}

test "shouldSkipStreaming: multi-message total triggers skip when sum exceeds limit" {
    // GAP-11: Threshold must apply to the accumulated total, not per-message.
    // Three messages of 10 bytes each = 30 bytes total; limit = 25.
    const m1 = root.ChatMessage.user("aaaaaaaaaa"); // 10
    const m2 = root.ChatMessage.user("bbbbbbbbbb"); // 10
    const m3 = root.ChatMessage.user("cccccccccc"); // 10 → total 30
    const req = root.ChatRequest{ .messages = &[_]root.ChatMessage{ m1, m2, m3 }, .model = "m" };
    try std.testing.expect(OpenAiCompatibleProvider.shouldSkipStreaming(25, req));
    // Individual messages are each under the limit; verify the sum is what matters.
    const single = root.ChatRequest{ .messages = &[_]root.ChatMessage{m1}, .model = "m" };
    try std.testing.expect(!OpenAiCompatibleProvider.shouldSkipStreaming(25, single));
}
