const std = @import("std");
const log = std.log.scoped(.anthropic);
const root = @import("root.zig");
const sse = @import("sse.zig");
const error_classify = @import("error_classify.zig");
const config_types = @import("../config_types.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ContentPart = root.ContentPart;
const ToolCall = root.ToolCall;
const ToolSpec = root.ToolSpec;
const TokenUsage = root.TokenUsage;

/// Anthropic Claude API provider.
///
/// Supports:
/// - x-api-key authentication (standard API keys)
/// - Bearer token authentication (setup/OAuth tokens starting with sk-ant-oat01-)
/// - Custom base URLs for Anthropic-compatible proxies and gateways
pub const AnthropicProvider = struct {
    credential: ?[]const u8,
    base_url: []const u8,
    allocator: std.mem.Allocator,

    const DEFAULT_BASE_URL = "https://api.anthropic.com";
    const API_VERSION = "2023-06-01";
    const DEFAULT_MAX_TOKENS: u32 = config_types.DEFAULT_MODEL_MAX_TOKENS;
    const OAUTH_BETA_HEADER = "anthropic-beta: oauth-2025-04-20";
    const OAUTH_USER_AGENT_HEADER = "User-Agent: claude-cli/2.1.2 (external, cli)";

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8, base_url: ?[]const u8) AnthropicProvider {
        const url = if (base_url) |u| trimTrailingSlash(u) else DEFAULT_BASE_URL;

        var credential: ?[]const u8 = null;
        if (api_key) |key| {
            const trimmed = std.mem.trim(u8, key, " \t\r\n");
            if (trimmed.len > 0) {
                credential = trimmed;
            }
        }

        return .{
            .credential = credential,
            .base_url = url,
            .allocator = allocator,
        };
    }

    fn trimTrailingSlash(s: []const u8) []const u8 {
        if (s.len > 0 and s[s.len - 1] == '/') {
            return s[0 .. s.len - 1];
        }
        return s;
    }

    /// Check if the credential is a setup/OAuth token (Bearer auth).
    pub fn isSetupToken(token: []const u8) bool {
        return std.mem.startsWith(u8, token, "sk-ant-oat01-");
    }

    /// Build the messages endpoint URL.
    pub fn messagesUrl(self: AnthropicProvider, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/v1/messages", .{self.base_url});
    }

    fn formatMessagesUrl(self: AnthropicProvider, buffer: []u8, is_oauth: bool) ![]const u8 {
        const path: []const u8 = if (is_oauth) "/v1/messages?beta=true" else "/v1/messages";
        return std.fmt.bufPrint(buffer, "{s}{s}", .{ self.base_url, path });
    }

    fn appendOAuthHeaders(headers_buf: *[4][]const u8, hdr_count: *usize, is_oauth: bool) void {
        if (!is_oauth) return;
        headers_buf[hdr_count.*] = OAUTH_BETA_HEADER;
        hdr_count.* += 1;
        headers_buf[hdr_count.*] = OAUTH_USER_AGENT_HEADER;
        hdr_count.* += 1;
    }

    /// Build a simple chat request JSON body.
    pub fn buildSimpleRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","max_tokens":{d},"system":"{s}","messages":[{{"role":"user","content":"{s}"}}],"temperature":{d:.2}}}
            , .{ model, DEFAULT_MAX_TOKENS, sys, message, temperature });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","max_tokens":{d},"messages":[{{"role":"user","content":"{s}"}}],"temperature":{d:.2}}}
            , .{ model, DEFAULT_MAX_TOKENS, message, temperature });
        }
    }

    /// Build the authorization header value based on credential type.
    pub fn authHeaderValue(allocator: std.mem.Allocator, credential: []const u8) !AuthHeader {
        if (isSetupToken(credential)) {
            return .{
                .header_name = "authorization",
                .header_value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{credential}),
                .needs_free = true,
            };
        } else {
            return .{
                .header_name = "x-api-key",
                .header_value = credential,
                .needs_free = false,
            };
        }
    }

    /// Parse text content from an Anthropic response body.
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
            root.setLastApiErrorDetail("anthropic", sanitized orelse summary);
            return mapped_err;
        }

        if (root_obj.get("content")) |content_arr| {
            if (content_arr == .array) {
                for (content_arr.array.items) |block| {
                    const obj = block.object;
                    if (obj.get("type")) |kind| {
                        if (kind == .string and std.mem.eql(u8, kind.string, "text")) {
                            if (obj.get("text")) |text| {
                                if (text == .string) {
                                    return try allocator.dupe(u8, text.string);
                                }
                            }
                        }
                    }
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Parse a native tool-calling response into ChatResponse.
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
            root.setLastApiErrorDetail("anthropic", sanitized orelse summary);
            return mapped_err;
        }

        var text_parts: std.ArrayListUnmanaged(u8) = .empty;
        defer text_parts.deinit(allocator);

        var thinking_parts: std.ArrayListUnmanaged(u8) = .empty;
        defer thinking_parts.deinit(allocator);

        var tool_calls_list: std.ArrayListUnmanaged(ToolCall) = .empty;

        if (root_obj.get("content")) |content_arr| {
            if (content_arr == .array) {
                for (content_arr.array.items) |block| {
                    const obj = block.object;
                    const kind = if (obj.get("type")) |t| (if (t == .string) t.string else "") else "";

                    if (std.mem.eql(u8, kind, "thinking")) {
                        if (obj.get("thinking")) |thinking| {
                            if (thinking == .string and thinking.string.len > 0) {
                                if (thinking_parts.items.len > 0) {
                                    try thinking_parts.append(allocator, '\n');
                                }
                                try thinking_parts.appendSlice(allocator, thinking.string);
                            }
                        }
                    } else if (std.mem.eql(u8, kind, "text")) {
                        if (obj.get("text")) |text| {
                            if (text == .string) {
                                const trimmed = std.mem.trim(u8, text.string, " \t\r\n");
                                if (trimmed.len > 0) {
                                    if (text_parts.items.len > 0) {
                                        try text_parts.append(allocator, '\n');
                                    }
                                    try text_parts.appendSlice(allocator, trimmed);
                                }
                            }
                        }
                    } else if (std.mem.eql(u8, kind, "tool_use")) {
                        const name = if (obj.get("name")) |n| (if (n == .string) n.string else "") else "";
                        if (name.len == 0) continue;

                        const id = if (obj.get("id")) |i| (if (i == .string) i.string else "unknown") else "unknown";

                        var arguments: []const u8 = "{}";
                        if (obj.get("input")) |input| {
                            arguments = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(input, .{})});
                        }

                        try tool_calls_list.append(allocator, .{
                            .id = try allocator.dupe(u8, id),
                            .name = try allocator.dupe(u8, name),
                            .arguments = arguments,
                        });
                    }
                }
            }
        }

        // Parse usage if present
        var usage = TokenUsage{};
        if (root_obj.get("usage")) |usage_obj| {
            if (usage_obj == .object) {
                if (usage_obj.object.get("input_tokens")) |v| {
                    if (v == .integer) usage.prompt_tokens = @intCast(v.integer);
                }
                if (usage_obj.object.get("output_tokens")) |v| {
                    if (v == .integer) usage.completion_tokens = @intCast(v.integer);
                }
                usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
            }
        }

        const model_str = if (root_obj.get("model")) |m| (if (m == .string) m.string else "") else "";

        return .{
            .content = if (text_parts.items.len > 0) try text_parts.toOwnedSlice(allocator) else null,
            .reasoning_content = if (thinking_parts.items.len > 0) try thinking_parts.toOwnedSlice(allocator) else null,
            .tool_calls = try tool_calls_list.toOwnedSlice(allocator),
            .usage = usage,
            .model = try allocator.dupe(u8, model_str),
        };
    }

    /// Create a Provider interface from this AnthropicProvider.
    pub fn provider(self: *AnthropicProvider) Provider {
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
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .stream_chat = streamChatImpl,
        .supports_streaming = supportsStreamingImpl,
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *AnthropicProvider = @ptrCast(@alignCast(ptr));
        const credential = self.credential orelse return error.CredentialsNotSet;
        const is_oauth = isSetupToken(credential);

        // URL: stack-allocated (base_url + path is bounded)
        var url_buf: [2048]u8 = undefined;
        const url = self.formatMessagesUrl(&url_buf, is_oauth) catch return error.AnthropicApiError;

        const body = try buildSimpleRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        // Build auth header directly on stack (avoids intermediate heap alloc)
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = if (is_oauth)
            std.fmt.bufPrint(&auth_hdr_buf, "authorization: Bearer {s}", .{credential}) catch return error.AnthropicApiError
        else
            std.fmt.bufPrint(&auth_hdr_buf, "x-api-key: {s}", .{credential}) catch return error.AnthropicApiError;

        var version_hdr_buf: [64]u8 = undefined;
        const version_hdr = std.fmt.bufPrint(&version_hdr_buf, "anthropic-version: {s}", .{API_VERSION}) catch return error.AnthropicApiError;

        var headers_buf: [4][]const u8 = undefined;
        var hdr_count: usize = 0;
        headers_buf[hdr_count] = auth_hdr;
        hdr_count += 1;
        headers_buf[hdr_count] = version_hdr;
        hdr_count += 1;
        appendOAuthHeaders(&headers_buf, &hdr_count, is_oauth);

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..hdr_count], 0) catch |err| return root.preserveCurlTransportError(err, error.AnthropicApiError);
        defer allocator.free(resp_body);

        return parseTextResponse(allocator, resp_body);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *AnthropicProvider = @ptrCast(@alignCast(ptr));
        const credential = self.credential orelse return error.CredentialsNotSet;
        const is_oauth = isSetupToken(credential);

        // URL: stack-allocated (base_url + path is bounded)
        var url_buf: [2048]u8 = undefined;
        const url = self.formatMessagesUrl(&url_buf, is_oauth) catch return error.AnthropicApiError;

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        // Build auth header directly on stack (avoids intermediate heap alloc)
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = if (is_oauth)
            std.fmt.bufPrint(&auth_hdr_buf, "authorization: Bearer {s}", .{credential}) catch return error.AnthropicApiError
        else
            std.fmt.bufPrint(&auth_hdr_buf, "x-api-key: {s}", .{credential}) catch return error.AnthropicApiError;

        var version_hdr_buf: [64]u8 = undefined;
        const version_hdr = std.fmt.bufPrint(&version_hdr_buf, "anthropic-version: {s}", .{API_VERSION}) catch return error.AnthropicApiError;

        var headers_buf: [4][]const u8 = undefined;
        var hdr_count: usize = 0;
        headers_buf[hdr_count] = auth_hdr;
        hdr_count += 1;
        headers_buf[hdr_count] = version_hdr;
        hdr_count += 1;
        appendOAuthHeaders(&headers_buf, &hdr_count, is_oauth);

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..hdr_count], request.timeout_secs) catch |err| return root.preserveCurlTransportError(err, error.AnthropicApiError);
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return true;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Anthropic";
    }

    fn deinitImpl(_: *anyopaque) void {}

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!root.StreamChatResult {
        const self: *AnthropicProvider = @ptrCast(@alignCast(ptr));
        const credential = self.credential orelse return error.CredentialsNotSet;
        const is_oauth = isSetupToken(credential);

        var url_buf: [2048]u8 = undefined;
        const url = self.formatMessagesUrl(&url_buf, is_oauth) catch return error.AnthropicApiError;

        const body = try buildStreamingChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        // Build auth header directly on stack
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = if (is_oauth)
            std.fmt.bufPrint(&auth_hdr_buf, "authorization: Bearer {s}", .{credential}) catch return error.AnthropicApiError
        else
            std.fmt.bufPrint(&auth_hdr_buf, "x-api-key: {s}", .{credential}) catch return error.AnthropicApiError;

        var version_hdr_buf: [64]u8 = undefined;
        const version_hdr = std.fmt.bufPrint(&version_hdr_buf, "anthropic-version: {s}", .{API_VERSION}) catch return error.AnthropicApiError;

        // Build headers array (up to 4: auth, version, optional beta, optional user-agent)
        var headers_buf: [4][]const u8 = undefined;
        var hdr_count: usize = 0;
        headers_buf[hdr_count] = auth_hdr;
        hdr_count += 1;
        headers_buf[hdr_count] = version_hdr;
        hdr_count += 1;
        appendOAuthHeaders(&headers_buf, &hdr_count, is_oauth);

        return sse.curlStreamAnthropic(allocator, url, body, headers_buf[0..hdr_count], callback, callback_ctx) catch |err| {
            if (err == error.CurlWaitError or err == error.CurlFailed) {
                log.warn("Anthropic streaming failed with {}; falling back to non-streaming response", .{err});
                var fallback = try chatImpl(ptr, allocator, request, model, temperature);
                return root.emitChatResponseAsStream(allocator, &fallback, callback, callback_ctx);
            }
            return err;
        };
    }
};

/// Serialize a single message's content field in Anthropic format.
/// Plain text → JSON string, multimodal → content array with type:text / type:image blocks.
fn serializeAnthropicContent(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, msg: ChatMessage) !void {
    if (msg.content_parts) |parts| {
        try buf.append(allocator, '[');
        for (parts, 0..) |part, j| {
            if (j > 0) try buf.append(allocator, ',');
            switch (part) {
                .text => |text| {
                    try buf.appendSlice(allocator, "{\"type\":\"text\",\"text\":");
                    try root.appendJsonString(buf, allocator, text);
                    try buf.append(allocator, '}');
                },
                .image_url => |img| {
                    try buf.appendSlice(allocator, "{\"type\":\"image\",\"source\":{\"type\":\"url\",\"url\":");
                    try root.appendJsonString(buf, allocator, img.url);
                    try buf.appendSlice(allocator, "}}");
                },
                .image_base64 => |img| {
                    try buf.appendSlice(allocator, "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":");
                    try root.appendJsonString(buf, allocator, img.media_type);
                    try buf.appendSlice(allocator, ",\"data\":");
                    try root.appendJsonString(buf, allocator, img.data);
                    try buf.appendSlice(allocator, "}}");
                },
            }
        }
        try buf.append(allocator, ']');
    } else {
        try root.appendJsonString(buf, allocator, msg.content);
    }
}

/// Build a full chat request JSON body from a ChatRequest (Anthropic messages format).
/// System messages are extracted and placed in the top-level "system" field.
/// User/assistant/tool messages go in the "messages" array.
fn buildChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Extract system prompt (Anthropic puts it top-level, not in messages array)
    var system_prompt: ?[]const u8 = null;
    for (request.messages) |msg| {
        if (msg.role == .system) {
            system_prompt = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"max_tokens\":");
    const max_tokens = request.max_tokens orelse AnthropicProvider.DEFAULT_MAX_TOKENS;
    var max_buf: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tokens}) catch return error.AnthropicApiError;
    try buf.appendSlice(allocator, max_str);

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system\":");
        try root.appendJsonString(&buf, allocator, sys);
    }

    try buf.appendSlice(allocator, ",\"messages\":[");
    var count: usize = 0;
    for (request.messages) |msg| {
        if (msg.role == .system) continue;
        if (count > 0) try buf.append(allocator, ',');
        count += 1;
        // Anthropic only supports "user" and "assistant" roles in messages
        const role_str: []const u8 = switch (msg.role) {
            .user, .tool => "user",
            .assistant => "assistant",
            .system => unreachable,
        };
        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, role_str);
        try buf.appendSlice(allocator, "\",\"content\":");
        try serializeAnthropicContent(&buf, allocator, msg);
        try buf.append(allocator, '}');
    }

    try buf.append(allocator, ']');

    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsAnthropic(&buf, allocator, tools);
        }
    }
    try appendAnthropicGenerationConfig(&buf, allocator, model, max_tokens, temperature, request.reasoning_effort);

    try buf.append(allocator, '}');
    return try buf.toOwnedSlice(allocator);
}

/// Build a streaming chat request JSON body (same as buildChatRequestBody but with "stream":true).
fn buildStreamingChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Extract system prompt (Anthropic puts it top-level, not in messages array)
    var system_prompt: ?[]const u8 = null;
    for (request.messages) |msg| {
        if (msg.role == .system) {
            system_prompt = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"max_tokens\":");
    const max_tokens = request.max_tokens orelse AnthropicProvider.DEFAULT_MAX_TOKENS;
    var max_buf2: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf2, "{d}", .{max_tokens}) catch return error.AnthropicApiError;
    try buf.appendSlice(allocator, max_str);

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system\":");
        try root.appendJsonString(&buf, allocator, sys);
    }

    try buf.appendSlice(allocator, ",\"messages\":[");
    var count: usize = 0;
    for (request.messages) |msg| {
        if (msg.role == .system) continue;
        if (count > 0) try buf.append(allocator, ',');
        count += 1;
        const role_str: []const u8 = switch (msg.role) {
            .user, .tool => "user",
            .assistant => "assistant",
            .system => unreachable,
        };
        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, role_str);
        try buf.appendSlice(allocator, "\",\"content\":");
        try serializeAnthropicContent(&buf, allocator, msg);
        try buf.append(allocator, '}');
    }

    try buf.append(allocator, ']');

    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsAnthropic(&buf, allocator, tools);
        }
    }
    try appendAnthropicGenerationConfig(&buf, allocator, model, max_tokens, temperature, request.reasoning_effort);

    try buf.appendSlice(allocator, ",\"stream\":true}");
    return try buf.toOwnedSlice(allocator);
}

fn appendAnthropicGenerationConfig(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    max_tokens: u32,
    temperature: f64,
    reasoning_effort: ?[]const u8,
) !void {
    const effort = root.normalizeOpenAiReasoningEffort(reasoning_effort);
    if (effort == null or std.ascii.eqlIgnoreCase(effort.?, "none")) {
        try buf.appendSlice(allocator, ",\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.AnthropicApiError;
        try buf.appendSlice(allocator, temp_str);
        return;
    }

    const normalized_effort: []const u8 = if (std.ascii.eqlIgnoreCase(effort.?, "low"))
        "low"
    else if (std.ascii.eqlIgnoreCase(effort.?, "medium"))
        "medium"
    else
        "high";

    if (std.mem.eql(u8, model, "claude-opus-4-6") or std.mem.eql(u8, model, "claude-sonnet-4-6")) {
        try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"adaptive\"},\"output_config\":{\"effort\":\"");
        try buf.appendSlice(allocator, normalized_effort);
        try buf.appendSlice(allocator, "\"}");
        return;
    }

    const MIN_THINKING_BUDGET: u32 = 1024;
    if (max_tokens <= MIN_THINKING_BUDGET) return error.AnthropicThinkingBudgetTooSmall;

    // Manual extended thinking requires at least 1,024 tokens and a budget
    // strictly smaller than max_tokens.
    const requested_budget: u32 = if (std.mem.eql(u8, normalized_effort, "low"))
        MIN_THINKING_BUDGET
    else if (std.mem.eql(u8, normalized_effort, "medium"))
        4096
    else
        8192;
    const budget = @min(requested_budget, max_tokens - 1);

    try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"enabled\",\"budget_tokens\":");
    var budget_buf: [16]u8 = undefined;
    const budget_str = std.fmt.bufPrint(&budget_buf, "{d}", .{budget}) catch return error.AnthropicApiError;
    try buf.appendSlice(allocator, budget_str);
    try buf.append(allocator, '}');
}

pub const AuthHeader = struct {
    header_name: []const u8,
    header_value: []const u8,
    needs_free: bool,
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "creates with empty key" {
    const p = AnthropicProvider.init(std.testing.allocator, "", null);
    try std.testing.expect(p.credential == null);
}

test "creates with whitespace key" {
    const p = AnthropicProvider.init(std.testing.allocator, "  sk-ant-test123  ", null);
    try std.testing.expectEqualStrings("sk-ant-test123", p.credential.?);
}

test "creates with custom base url" {
    const p = AnthropicProvider.init(std.testing.allocator, "sk-ant-test", "https://api.example.com");
    try std.testing.expectEqualStrings("https://api.example.com", p.base_url);
    try std.testing.expectEqualStrings("sk-ant-test", p.credential.?);
}

test "custom base url trims trailing slash" {
    const p = AnthropicProvider.init(std.testing.allocator, null, "https://api.example.com/");
    try std.testing.expectEqualStrings("https://api.example.com", p.base_url);
}

test "default base url when none provided" {
    const p = AnthropicProvider.init(std.testing.allocator, null, null);
    try std.testing.expectEqualStrings("https://api.anthropic.com", p.base_url);
}

test "setup token detection works" {
    try std.testing.expect(AnthropicProvider.isSetupToken("sk-ant-oat01-abcdef"));
    try std.testing.expect(!AnthropicProvider.isSetupToken("sk-ant-api-key"));
}

test "messages url is correct" {
    const p = AnthropicProvider.init(std.testing.allocator, null, null);
    const url = try p.messagesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.anthropic.com/v1/messages", url);
}

test "messages url with custom base" {
    const p = AnthropicProvider.init(std.testing.allocator, null, "https://proxy.example.com");
    const url = try p.messagesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://proxy.example.com/v1/messages", url);
}

test "OAuth request metadata matches blocking and streaming paths" {
    // Regression: setup-token streaming must use the same beta URL and headers
    // as blocking requests, otherwise authentication can fail as an empty stream.
    const p = AnthropicProvider.init(std.testing.allocator, null, null);
    var url_buf: [256]u8 = undefined;
    const oauth_url = try p.formatMessagesUrl(&url_buf, true);
    try std.testing.expectEqualStrings("https://api.anthropic.com/v1/messages?beta=true", oauth_url);

    var headers: [4][]const u8 = undefined;
    headers[0] = "authorization: Bearer token";
    headers[1] = "anthropic-version: 2023-06-01";
    var header_count: usize = 2;
    AnthropicProvider.appendOAuthHeaders(&headers, &header_count, true);
    try std.testing.expectEqual(@as(usize, 4), header_count);
    try std.testing.expectEqualStrings(AnthropicProvider.OAUTH_BETA_HEADER, headers[2]);
    try std.testing.expectEqualStrings(AnthropicProvider.OAUTH_USER_AGENT_HEADER, headers[3]);

    const api_key_url = try p.formatMessagesUrl(&url_buf, false);
    try std.testing.expectEqualStrings("https://api.anthropic.com/v1/messages", api_key_url);
    header_count = 2;
    AnthropicProvider.appendOAuthHeaders(&headers, &header_count, false);
    try std.testing.expectEqual(@as(usize, 2), header_count);
}

test "auth header for regular key" {
    const auth = try AnthropicProvider.authHeaderValue(std.testing.allocator, "sk-ant-regular-key");
    defer if (auth.needs_free) std.testing.allocator.free(auth.header_value);
    try std.testing.expectEqualStrings("x-api-key", auth.header_name);
    try std.testing.expectEqualStrings("sk-ant-regular-key", auth.header_value);
    try std.testing.expect(!auth.needs_free);
}

test "auth header for setup token" {
    const auth = try AnthropicProvider.authHeaderValue(std.testing.allocator, "sk-ant-oat01-mytoken");
    defer if (auth.needs_free) std.testing.allocator.free(auth.header_value);
    try std.testing.expectEqualStrings("authorization", auth.header_name);
    try std.testing.expectEqualStrings("Bearer sk-ant-oat01-mytoken", auth.header_value);
    try std.testing.expect(auth.needs_free);
}

test "buildSimpleRequestBody without system prompt" {
    const body = try AnthropicProvider.buildSimpleRequestBody(
        std.testing.allocator,
        null,
        "hello",
        "claude-3-opus",
        0.7,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "claude-3-opus") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") == null);
}

test "buildSimpleRequestBody with system prompt" {
    const body = try AnthropicProvider.buildSimpleRequestBody(
        std.testing.allocator,
        "You are helpful",
        "hello",
        "claude-3-opus",
        0.7,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "You are helpful") != null);
}

test "parseTextResponse extracts text" {
    const body =
        \\{"content":[{"type":"text","text":"Hello there!"}]}
    ;
    const result = try AnthropicProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello there!", result);
}

test "parseTextResponse empty content fails" {
    const body =
        \\{"content":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, AnthropicProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse null content fails" {
    // Regression: provider response parsing must tolerate `"content": null`.
    const body =
        \\{"content":null}
    ;
    try std.testing.expectError(error.NoResponseContent, AnthropicProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse classifies rate-limit errors" {
    const body =
        \\{"error":{"type":"rate_limit_error","message":"Too many requests","status":429}}
    ;
    try std.testing.expectError(error.RateLimited, AnthropicProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseNativeResponse with text and tool_use" {
    const body =
        \\{"content":[{"type":"text","text":"Let me check"},{"type":"tool_use","id":"call_1","name":"shell","input":{"cmd":"ls"}}],"usage":{"input_tokens":10,"output_tokens":20},"model":"claude-3-opus"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c| std.testing.allocator.free(c);
        for (response.tool_calls) |tc| {
            std.testing.allocator.free(tc.id);
            std.testing.allocator.free(tc.name);
            std.testing.allocator.free(tc.arguments);
        }
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("Let me check", response.content.?);
    try std.testing.expect(response.tool_calls.len == 1);
    try std.testing.expectEqualStrings("shell", response.tool_calls[0].name);
    try std.testing.expect(response.usage.prompt_tokens == 10);
    try std.testing.expect(response.usage.completion_tokens == 20);
    try std.testing.expect(response.usage.total_tokens == 30);
}

test "supportsNativeTools returns true" {
    var p = AnthropicProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

test "parseTextResponse multiple blocks returns first text" {
    const body =
        \\{"content":[{"type":"text","text":"First"},{"type":"text","text":"Second"}]}
    ;
    const result = try AnthropicProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("First", result);
}

test "parseNativeResponse text only no tool calls" {
    const body =
        \\{"content":[{"type":"text","text":"Just text"}],"model":"claude-3-opus"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("Just text", response.content.?);
    try std.testing.expect(response.tool_calls.len == 0);
}

test "parseNativeResponse tool_use only no text" {
    const body =
        \\{"content":[{"type":"tool_use","id":"call_2","name":"read_file","input":{"path":"a.txt"}}],"model":"claude-3-opus"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        for (response.tool_calls) |tc| {
            std.testing.allocator.free(tc.id);
            std.testing.allocator.free(tc.name);
            std.testing.allocator.free(tc.arguments);
        }
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.content == null);
    try std.testing.expect(response.tool_calls.len == 1);
    try std.testing.expectEqualStrings("read_file", response.tool_calls[0].name);
    try std.testing.expectEqualStrings("call_2", response.tool_calls[0].id);
}

test "parseNativeResponse empty content array" {
    const body =
        \\{"content":[],"model":"claude-3"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.content == null);
    try std.testing.expect(response.tool_calls.len == 0);
}

test "parseNativeResponse null content does not crash" {
    // Regression: provider response parsing must tolerate `"content": null`.
    const body =
        \\{"content":null,"model":"claude-3"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.content == null);
    try std.testing.expectEqual(@as(usize, 0), response.tool_calls.len);
    try std.testing.expectEqualStrings("claude-3", response.model);
}

test "parseNativeResponse skips tool_use with empty name" {
    const body =
        \\{"content":[{"type":"tool_use","id":"call_x","name":"","input":{}}],"model":"claude-3"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.tool_calls.len == 0);
}

test "parseNativeResponse multiple tool calls" {
    const body =
        \\{"content":[{"type":"tool_use","id":"c1","name":"shell","input":{"cmd":"ls"}},{"type":"tool_use","id":"c2","name":"read","input":{"path":"x"}}],"model":"claude-3"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        for (response.tool_calls) |tc| {
            std.testing.allocator.free(tc.id);
            std.testing.allocator.free(tc.name);
            std.testing.allocator.free(tc.arguments);
        }
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.tool_calls.len == 2);
    try std.testing.expectEqualStrings("shell", response.tool_calls[0].name);
    try std.testing.expectEqualStrings("read", response.tool_calls[1].name);
}

test "parseNativeResponse model field extracted" {
    const body =
        \\{"content":[{"type":"text","text":"Hi"}],"model":"claude-sonnet-4-6"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("claude-sonnet-4-6", response.model);
}

test "parseNativeResponse trims whitespace text" {
    const body =
        \\{"content":[{"type":"text","text":"  trimmed  "}],"model":"m"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("trimmed", response.content.?);
}

test "parseNativeResponse skips whitespace-only text blocks" {
    const body =
        \\{"content":[{"type":"text","text":"   "}],"model":"m"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.content == null);
}

test "provider getName returns Anthropic" {
    var p = AnthropicProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expectEqualStrings("Anthropic", prov.getName());
}

test "parseNativeResponse thinking block populates reasoning_content" {
    const body =
        \\{"content":[{"type":"thinking","thinking":"I should reason carefully"},{"type":"text","text":"Here is my answer"}],"model":"claude-opus-4-5-20250514"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        if (response.reasoning_content) |rc| std.testing.allocator.free(rc);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("Here is my answer", response.content.?);
    try std.testing.expectEqualStrings("I should reason carefully", response.reasoning_content.?);
}

test "parseNativeResponse thinking block only no visible text" {
    const body =
        \\{"content":[{"type":"thinking","thinking":"silent reasoning"}],"model":"m"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        if (response.reasoning_content) |rc| std.testing.allocator.free(rc);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.content == null);
    try std.testing.expectEqualStrings("silent reasoning", response.reasoning_content.?);
}

test "parseNativeResponse usage missing defaults to zero" {
    const body =
        \\{"content":[{"type":"text","text":"Hi"}],"model":"m"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expect(response.usage.prompt_tokens == 0);
    try std.testing.expect(response.usage.completion_tokens == 0);
    try std.testing.expect(response.usage.total_tokens == 0);
}

// ── Streaming Tests ─────────────────────────────────────────────

test "buildStreamingChatRequestBody contains stream true" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildStreamingChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
}

test "buildChatRequestBody defaults max_tokens to runtime fallback" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const max_tokens = parsed.value.object.get("max_tokens").?;
    try std.testing.expect(max_tokens == .integer);
    try std.testing.expectEqual(@as(i64, config_types.DEFAULT_MODEL_MAX_TOKENS), max_tokens.integer);
}

test "buildChatRequestBody uses adaptive thinking for Claude 4.6" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .reasoning_effort = "high",
    };

    const body = try buildChatRequestBody(allocator, req, "claude-sonnet-4-6", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("adaptive", obj.get("thinking").?.object.get("type").?.string);
    try std.testing.expectEqualStrings("high", obj.get("output_config").?.object.get("effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expect(obj.get("thinking").?.object.get("budget_tokens") == null);
}

test "buildChatRequestBody omits thinking config when reasoning_effort is none" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .reasoning_effort = "none",
    };

    const body = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("thinking") == null);
    try std.testing.expectEqual(@as(f64, 0.7), parsed.value.object.get("temperature").?.float);
}

test "buildChatRequestBody keeps manual thinking budget below max tokens" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{.{ .role = .user, .content = "hello" }};
    const req = ChatRequest{
        .messages = &msgs,
        .max_tokens = 8192,
        .reasoning_effort = "high",
    };

    const body = try buildChatRequestBody(allocator, req, "claude-haiku-4-5", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("enabled", obj.get("thinking").?.object.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 8191), obj.get("thinking").?.object.get("budget_tokens").?.integer);
    try std.testing.expect(obj.get("temperature") == null);
}

test "buildChatRequestBody uses minimum valid manual thinking budget" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{.{ .role = .user, .content = "hello" }};
    const req = ChatRequest{
        .messages = &msgs,
        .max_tokens = 1025,
        .reasoning_effort = "low",
    };

    const body = try buildChatRequestBody(allocator, req, "claude-haiku-4-5", 0.7);
    defer allocator.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1024), parsed.value.object.get("thinking").?.object.get("budget_tokens").?.integer);
}

test "buildChatRequestBody rejects max tokens too small for manual thinking" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{.{ .role = .user, .content = "hello" }};
    const req = ChatRequest{
        .messages = &msgs,
        .max_tokens = 1024,
        .reasoning_effort = "low",
    };

    try std.testing.expectError(
        error.AnthropicThinkingBudgetTooSmall,
        buildChatRequestBody(allocator, req, "claude-haiku-4-5", 0.7),
    );
}

test "buildStreamingChatRequestBody uses adaptive thinking without temperature" {
    const allocator = std.testing.allocator;
    const msgs = [_]ChatMessage{.{ .role = .user, .content = "hello" }};
    const req = ChatRequest{
        .messages = &msgs,
        .reasoning_effort = "medium",
    };

    const body = try buildStreamingChatRequestBody(allocator, req, "claude-opus-4-6", 0.7);
    defer allocator.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("adaptive", obj.get("thinking").?.object.get("type").?.string);
    try std.testing.expectEqualStrings("medium", obj.get("output_config").?.object.get("effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expect(obj.get("stream").?.bool);
}

test "buildStreamingChatRequestBody contains same messages as non-streaming" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{
        root.ChatMessage.system("Be helpful"),
        root.ChatMessage.user("hello"),
    };
    const req = root.ChatRequest{ .messages = &msgs };
    const streaming = try buildStreamingChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(streaming);
    const blocking = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(blocking);
    // Both should contain the model and message content
    try std.testing.expect(std.mem.indexOf(u8, streaming, "claude-3-opus") != null);
    try std.testing.expect(std.mem.indexOf(u8, streaming, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, streaming, "Be helpful") != null);
    // Non-streaming should NOT have stream:true
    try std.testing.expect(std.mem.indexOf(u8, blocking, "\"stream\":true") == null);
}

test "supportsStreamingImpl returns true" {
    var p = AnthropicProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsStreaming());
}

test "vtable stream_chat is not null" {
    try std.testing.expect(AnthropicProvider.vtable.stream_chat != null);
}

test "vtable supports_streaming is not null" {
    try std.testing.expect(AnthropicProvider.vtable.supports_streaming != null);
}

// ── Multimodal Serialization Tests ──────────────────────────────

test "buildChatRequestBody without content_parts serializes plain string" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("plain text")};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?;
    try std.testing.expect(content == .string);
    try std.testing.expectEqualStrings("plain text", content.string);
}

test "buildChatRequestBody with base64 image serializes Anthropic format" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        root.makeTextPart("What is this?"),
        root.makeBase64ImagePart("iVBORw0KGgo=", "image/png"),
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?;
    try std.testing.expect(content == .array);
    try std.testing.expect(content.array.items.len == 2);

    // First part: text
    const text_part = content.array.items[0].object;
    try std.testing.expectEqualStrings("text", text_part.get("type").?.string);
    try std.testing.expectEqualStrings("What is this?", text_part.get("text").?.string);

    // Second part: image with base64 source
    const img_part = content.array.items[1].object;
    try std.testing.expectEqualStrings("image", img_part.get("type").?.string);
    const source = img_part.get("source").?.object;
    try std.testing.expectEqualStrings("base64", source.get("type").?.string);
    try std.testing.expectEqualStrings("image/png", source.get("media_type").?.string);
    try std.testing.expectEqualStrings("iVBORw0KGgo=", source.get("data").?.string);
}

test "buildChatRequestBody with image URL serializes Anthropic URL source" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        root.makeImageUrlPart("https://example.com/photo.jpg"),
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?.array;
    const img_part = content.items[0].object;
    try std.testing.expectEqualStrings("image", img_part.get("type").?.string);
    const source = img_part.get("source").?.object;
    try std.testing.expectEqualStrings("url", source.get("type").?.string);
    try std.testing.expectEqualStrings("https://example.com/photo.jpg", source.get("url").?.string);
}

test "buildStreamingChatRequestBody with content_parts serializes correctly" {
    const allocator = std.testing.allocator;
    const parts = [_]root.ContentPart{
        root.makeTextPart("Describe"),
        root.makeBase64ImagePart("AAAA", "image/jpeg"),
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const req = root.ChatRequest{ .messages = &msgs };
    const body = try buildStreamingChatRequestBody(allocator, req, "claude-3-opus", 0.7);
    defer allocator.free(body);

    // Should have stream:true and the image data
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"type\":\"image\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "AAAA") != null);
}
