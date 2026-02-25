const std = @import("std");
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

/// A provider that speaks the OpenAI-compatible chat completions API.
///
/// Used by: Venice, Vercel, Cloudflare, Moonshot, Synthetic, OpenCode,
/// Z.AI, GLM, MiniMax, Bedrock, Qianfan, Groq, Mistral, xAI, DeepSeek,
/// Together, Fireworks, Perplexity, Cohere, Copilot, and custom endpoints.
pub const OpenAiCompatibleProvider = struct {
    name: []const u8,
    base_url: []const u8,
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
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        base_url: []const u8,
        api_key: ?[]const u8,
        auth_style: AuthStyle,
    ) OpenAiCompatibleProvider {
        return .{
            .name = name,
            .base_url = trimTrailingSlash(base_url),
            .api_key = api_key,
            .auth_style = auth_style,
            .allocator = allocator,
        };
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

    /// Build a Responses API request JSON body.
    pub fn buildResponsesRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","input":[{{"role":"user","content":"{s}"}}],"instructions":"{s}","stream":false}}
            , .{ model, message, sys });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","input":[{{"role":"user","content":"{s}"}}],"stream":false}}
            , .{ model, message });
        }
    }

    /// Extract text from a Responses API JSON response.
    /// Checks output_text first, then output[*].content[*] with type "output_text",
    /// then any text in output[*].content[*].
    pub fn extractResponsesText(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        // Check top-level output_text first
        if (root_obj.get("output_text")) |ot| {
            if (ot == .string) {
                const trimmed = std.mem.trim(u8, ot.string, " \t\n\r");
                if (trimmed.len > 0) {
                    return try allocator.dupe(u8, trimmed);
                }
            }
        }

        // Walk output[*].content[*] looking for type "output_text"
        if (root_obj.get("output")) |output_arr| {
            for (output_arr.array.items) |item| {
                if (item.object.get("content")) |content_arr| {
                    for (content_arr.array.items) |content| {
                        const cobj = content.object;
                        if (cobj.get("type")) |t| {
                            if (t == .string and std.mem.eql(u8, t.string, "output_text")) {
                                if (cobj.get("text")) |text| {
                                    if (text == .string) {
                                        const trimmed = std.mem.trim(u8, text.string, " \t\n\r");
                                        if (trimmed.len > 0) {
                                            return try allocator.dupe(u8, trimmed);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: any text in output[*].content[*]
        if (root_obj.get("output")) |output_arr| {
            for (output_arr.array.items) |item| {
                if (item.object.get("content")) |content_arr| {
                    for (content_arr.array.items) |content| {
                        if (content.object.get("text")) |text| {
                            if (text == .string) {
                                const trimmed = std.mem.trim(u8, text.string, " \t\n\r");
                                if (trimmed.len > 0) {
                                    return try allocator.dupe(u8, trimmed);
                                }
                            }
                        }
                    }
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Chat via the Responses API endpoint (fallback when chat completions returns 404).
    pub fn chatViaResponses(
        self: OpenAiCompatibleProvider,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
    ) ![]const u8 {
        const url = try self.responsesUrl(allocator);
        defer allocator.free(url);

        const body = try buildResponsesRequestBody(allocator, system_prompt, message, model);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        const resp_body = if (auth) |a| blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            break :blk root.curlPost(allocator, url, body, &.{auth_hdr}) catch return error.CompatibleApiError;
        } else root.curlPost(allocator, url, body, &.{}) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return extractResponsesText(allocator, resp_body);
    }

    /// Build a chat request JSON body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
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

    /// Parse text content from an OpenAI-compatible response.
    pub fn parseTextResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        if (error_classify.classifyKnownApiError(root_obj)) |kind| {
            return error_classify.kindToError(kind);
        }

        if (root_obj.get("choices")) |choices| {
            if (choices.array.items.len > 0) {
                if (choices.array.items[0].object.get("message")) |msg| {
                    if (msg.object.get("content")) |content| {
                        if (content == .string) {
                            return try allocator.dupe(u8, content.string);
                        }
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
            return error_classify.kindToError(kind);
        }

        if (root_obj.get("choices")) |choices| {
            if (choices.array.items.len > 0) {
                const msg = choices.array.items[0].object.get("message") orelse return error.NoResponseContent;
                const msg_obj = msg.object;

                var content: ?[]const u8 = null;
                if (msg_obj.get("content")) |c| {
                    if (c == .string) {
                        content = try allocator.dupe(u8, c.string);
                    }
                }

                var tool_calls_list: std.ArrayListUnmanaged(ToolCall) = .empty;

                if (msg_obj.get("tool_calls")) |tc_arr| {
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

                const model_str = if (root_obj.get("model")) |m| (if (m == .string) try allocator.dupe(u8, m.string) else try allocator.dupe(u8, "")) else try allocator.dupe(u8, "");

                return .{
                    .content = content,
                    .tool_calls = try tool_calls_list.toOwnedSlice(allocator),
                    .usage = usage,
                    .model = model_str,
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
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .stream_chat = streamChatImpl,
        .supports_streaming = supportsStreamingImpl,
    };

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

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildStreamingChatRequestBody(allocator, request, effective_model, temperature, self.merge_system_into_user);
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

        return sse.curlStream(allocator, url, body, auth_hdr, &.{}, callback, callback_ctx);
    }

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
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

        const body = try buildRequestBody(allocator, eff_system, merged_msg orelse message, effective_model, temperature);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        const resp_body = if (auth) |a| blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            break :blk root.curlPost(allocator, url, body, &.{auth_hdr}) catch return error.CompatibleApiError;
        } else root.curlPost(allocator, url, body, &.{}) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseTextResponse(allocator, resp_body) catch |err| {
            // If chat completions failed and responses fallback is enabled, try the responses API
            if (self.supports_responses_fallback) {
                return self.chatViaResponses(allocator, eff_system, merged_msg orelse message, effective_model) catch {
                    return err;
                };
            }
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

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, effective_model, temperature, self.merge_system_into_user);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        const resp_body = if (auth) |a| blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            break :blk root.curlPostTimed(allocator, url, body, &.{auth_hdr}, request.timeout_secs) catch return error.CompatibleApiError;
        } else root.curlPostTimed(allocator, url, body, &.{}, request.timeout_secs) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(ptr: *anyopaque) bool {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.native_tools;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(ptr: *anyopaque) []const u8 {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.name;
    }

    fn deinitImpl(_: *anyopaque) void {}
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
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsOpenAI(&buf, allocator, tools);
            try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
        }
    }

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
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (request.tools) |tools| {
        if (tools.len > 0) {
            try buf.appendSlice(allocator, ",\"tools\":");
            try root.convertToolsOpenAI(&buf, allocator, tools);
            try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
        }
    }

    try buf.appendSlice(allocator, ",\"stream\":true}");

    return try buf.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "strips trailing slash" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com/", null, .bearer);
    try std.testing.expectEqualStrings("https://example.com", p.base_url);
}

test "chatCompletionsUrl standard" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.openai.com/v1", null, .bearer);
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
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "llama-3.3-70b") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "user") != null);
}

test "parseTextResponse extracts content" {
    const body =
        \\{"choices":[{"message":{"content":"Hello from Venice!"}}]}
    ;
    const result = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Venice!", result);
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
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .bearer);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("authorization", auth.name);
    try std.testing.expectEqualStrings("Bearer my-key", auth.value);
}

test "authHeaderValue x-api-key style" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .x_api_key);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("x-api-key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
}

test "authHeaderValue no key" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer);
    try std.testing.expect(try p.authHeaderValue(std.testing.allocator) == null);
}

test "chatCompletionsUrl trailing slash stripped" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1/", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/chat/completions", url);
}

test "chatCompletionsUrl without v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/chat/completions", url);
}

test "chatCompletionsUrl with v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer);
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
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":false") != null);
}

test "normalizeProviderModel maps DeepSeek v3.2 aliases to deepseek-chat" {
    const deepseek = OpenAiCompatibleProvider.init(std.testing.allocator, "deepseek", "https://api.deepseek.com", null, .bearer);
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek/deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-reasoner", deepseek.normalizeProviderModel("deepseek-reasoner"));
}

test "normalizeProviderModel leaves other providers unchanged" {
    const openrouter = OpenAiCompatibleProvider.init(std.testing.allocator, "openrouter", "https://openrouter.ai/api/v1", null, .bearer);
    try std.testing.expectEqualStrings("deepseek-v3.2", openrouter.normalizeProviderModel("deepseek-v3.2"));
}

test "parseTextResponse with null content fails" {
    const body =
        \\{"choices":[{"message":{"content":null}}]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body));
}

test "AuthStyle headerName" {
    try std.testing.expectEqualStrings("authorization", AuthStyle.bearer.headerName());
    try std.testing.expectEqualStrings("x-api-key", AuthStyle.x_api_key.headerName());
}

test "provider getName returns custom name" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "Venice", "https://api.venice.ai", "key", .bearer);
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
    );
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/v2/llm/chat/completions-proxy/chat/completions", url);
}

test "supportsNativeTools returns true for compatible" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer);
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

// ════════════════════════════════════════════════════════════════════════════
// Responses API tests
// ════════════════════════════════════════════════════════════════════════════

test "responsesUrl standard base" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/responses", url);
}

test "responsesUrl with v1 no duplicate" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer);
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
    );
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/responses", url);
}

test "responsesUrl non-v1 api path uses raw suffix" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/api/coding/v3", null, .bearer);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/api/coding/v3/responses", url);
}

test "responsesUrl requires exact suffix match" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/api/v2/responses-proxy",
        null,
        .bearer,
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
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        "You are helpful",
        "hello",
        "gpt-4o",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "gpt-4o") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "instructions") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "You are helpful") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
}

test "buildResponsesRequestBody without system" {
    const body = try OpenAiCompatibleProvider.buildResponsesRequestBody(
        std.testing.allocator,
        null,
        "hello",
        "gpt-4o",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "gpt-4o") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "instructions") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
}

test "AuthStyle custom headerName fallback" {
    try std.testing.expectEqualStrings("authorization", AuthStyle.custom.headerName());
}

test "authHeaderValue custom style" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom);
    p.custom_header = "X-Custom-Key";
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("X-Custom-Key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
    try std.testing.expect(!auth.needs_free);
}

test "authHeaderValue custom style without custom_header falls back" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "test-model", 0.7, false);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
}

test "supportsStreaming returns true for compatible" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer);
    const prov = p.provider();
    try std.testing.expect(prov.supportsStreaming());
}

test "vtable has stream_chat not null" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer);
    const prov = p.provider();
    try std.testing.expect(prov.vtable.stream_chat != null);
}

test "streaming body has same messages as non-streaming" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test message")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const non_stream = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
    defer allocator.free(non_stream);

    const stream = try buildStreamingChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "custom-model", 0.5, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    const content = messages.items[0].object.get("content").?.array;
    const img_url_obj = content.items[0].object.get("image_url").?.object;
    try std.testing.expectEqualStrings("high", img_url_obj.get("detail").?.string);
}

test "buildRequestBody reasoning model omits temperature" {
    const body = try OpenAiCompatibleProvider.buildRequestBody(std.testing.allocator, null, "hello", "gpt-5", 0.5);
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

    const body = try buildChatRequestBody(allocator, req, "o1", 0.7, false);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "gpt-5.2", 0.5, false);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, false);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 2);
    try std.testing.expectEqualStrings("system", messages.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("user", messages.items[1].object.get("role").?.string);
}

test "merge_system_into_user field defaults to false" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "test", 0.7, true);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 1);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    const content = messages.items[0].object.get("content").?.string;
    try std.testing.expect(std.mem.indexOf(u8, content, "[System: Be concise]") != null);
}
