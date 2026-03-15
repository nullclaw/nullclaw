const std = @import("std");
const root = @import("root.zig");
const sse = @import("sse.zig");
const error_classify = @import("error_classify.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ToolCall = root.ToolCall;
const ToolSpec = root.ToolSpec;
const TokenUsage = root.TokenUsage;

/// OpenRouter provider — AI model aggregator.
///
/// Endpoints:
/// - POST https://openrouter.ai/api/v1/chat/completions
/// - Authorization: Bearer <key>
/// - Extra headers: HTTP-Referer, X-Title
pub const OpenRouterProvider = struct {
    api_key: ?[]const u8,
    allocator: std.mem.Allocator,

    const BASE_URL = "https://openrouter.ai/api/v1/chat/completions";
    const WARMUP_URL = "https://openrouter.ai/api/v1/auth/key";
    const REFERER = "https://github.com/nullclaw/nullclaw";
    const TITLE = "nullclaw";

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) OpenRouterProvider {
        return .{
            .api_key = api_key,
            .allocator = allocator,
        };
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
        try buf.append(allocator, '}');

        return try buf.toOwnedSlice(allocator);
    }

    /// Parse text content from an OpenRouter response (OpenAI-compatible format).
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
            root.setLastApiErrorDetail("openrouter", sanitized orelse summary);
            return mapped_err;
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
            root.setLastApiErrorDetail("openrouter", sanitized orelse summary);
            return mapped_err;
        }

        if (root_obj.get("choices")) |choices| {
            if (choices.array.items.len > 0) {
                const msg = choices.array.items[0].object.get("message") orelse return error.NoResponseContent;
                const msg_obj = msg.object;

                var content: ?[]const u8 = null;
                var reasoning_content: ?[]const u8 = null;
                if (msg_obj.get("content")) |c| {
                    if (c == .string) {
                        const split = try root.splitThinkContent(allocator, c.string);
                        content = split.visible;
                        reasoning_content = split.reasoning;
                    }
                }

                // OpenRouter also exposes reasoning in dedicated fields.
                // reasoning_content: Kimi K2.5, DeepSeek-R1 native field.
                // reasoning: OpenRouter unified alias (same content, different key).
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
                    .reasoning_content = reasoning_content,
                    .tool_calls = try tool_calls_list.toOwnedSlice(allocator),
                    .usage = usage,
                    .model = model_str,
                };
            }
        }

        return error.NoResponseContent;
    }

    /// Pre-warm TLS connection by hitting auth endpoint. Best-effort, ignores errors.
    pub fn warmup(self: *OpenRouterProvider) void {
        const api_key = self.api_key orelse return;
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return;
        const resp = curlGet(self.allocator, WARMUP_URL, auth_hdr) catch return;
        self.allocator.free(resp);
    }

    /// Convert ChatMessages to a JSON array string for the API.
    pub fn convertMessages(allocator: std.mem.Allocator, messages: []const ChatMessage, system: ?[]const u8) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.append(allocator, '[');

        var count: usize = 0;

        // Prepend system message if provided
        if (system) |sys| {
            try buf.appendSlice(allocator, "{\"role\":\"system\",\"content\":");
            try root.appendJsonString(&buf, allocator, sys);
            try buf.append(allocator, '}');
            count += 1;
        }

        for (messages) |msg| {
            if (count > 0) try buf.append(allocator, ',');
            count += 1;

            try buf.appendSlice(allocator, "{\"role\":\"");
            try buf.appendSlice(allocator, msg.role.toSlice());
            try buf.appendSlice(allocator, "\",\"content\":");
            try root.serializeMessageContent(&buf, allocator, msg);

            if (msg.tool_call_id) |tc_id| {
                try buf.appendSlice(allocator, ",\"tool_call_id\":\"");
                try buf.appendSlice(allocator, tc_id);
                try buf.append(allocator, '"');
            }

            try buf.append(allocator, '}');
        }

        try buf.append(allocator, ']');
        return try buf.toOwnedSlice(allocator);
    }

    /// Convert ToolSpecs to a JSON array string for native function calling.
    pub fn convertTools(allocator: std.mem.Allocator, tools: []const ToolSpec) ![]const u8 {
        if (tools.len == 0) return try allocator.dupe(u8, "[]");

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.append(allocator, '[');

        for (tools, 0..) |tool, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "{\"type\":\"function\",\"function\":{\"name\":\"");
            try buf.appendSlice(allocator, tool.name);
            try buf.appendSlice(allocator, "\",\"description\":\"");
            try buf.appendSlice(allocator, tool.description);
            try buf.appendSlice(allocator, "\",\"parameters\":");
            try buf.appendSlice(allocator, tool.parameters_json);
            try buf.appendSlice(allocator, "}}");
        }

        try buf.append(allocator, ']');
        return try buf.toOwnedSlice(allocator);
    }

    /// Multi-turn chat with history. Sends all messages to the API.
    pub fn chatWithHistory(
        self: *OpenRouterProvider,
        allocator: std.mem.Allocator,
        messages: []const ChatMessage,
        system: ?[]const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const msgs_json = try convertMessages(allocator, messages, system);
        defer allocator.free(msgs_json);

        const body = try std.fmt.allocPrint(allocator,
            \\{{"model":"{s}","messages":{s},"temperature":{d:.2}}}
        , .{ model, msgs_json, temperature });
        defer allocator.free(body);

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenRouterApiError;

        var referer_hdr_buf: [256]u8 = undefined;
        const referer_hdr = std.fmt.bufPrint(&referer_hdr_buf, "HTTP-Referer: {s}", .{REFERER}) catch return error.OpenRouterApiError;

        var title_hdr_buf: [128]u8 = undefined;
        const title_hdr = std.fmt.bufPrint(&title_hdr_buf, "X-Title: {s}", .{TITLE}) catch return error.OpenRouterApiError;

        const resp_body = root.curlPostTimed(allocator, BASE_URL, body, &.{ auth_hdr, referer_hdr, title_hdr }, 0) catch return error.OpenRouterApiError;
        defer allocator.free(resp_body);

        return parseTextResponse(allocator, resp_body);
    }

    /// Create a Provider interface from this OpenRouterProvider.
    pub fn provider(self: *OpenRouterProvider) Provider {
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
        .warmup = warmupImpl,
        .stream_chat = streamChatImpl,
        .supports_streaming = supportsStreamingImpl,
    };

    fn warmupImpl(ptr: *anyopaque) void {
        const self: *OpenRouterProvider = @ptrCast(@alignCast(ptr));
        self.warmup();
    }

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *OpenRouterProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenRouterApiError;

        var referer_hdr_buf: [256]u8 = undefined;
        const referer_hdr = std.fmt.bufPrint(&referer_hdr_buf, "HTTP-Referer: {s}", .{REFERER}) catch return error.OpenRouterApiError;

        var title_hdr_buf: [128]u8 = undefined;
        const title_hdr = std.fmt.bufPrint(&title_hdr_buf, "X-Title: {s}", .{TITLE}) catch return error.OpenRouterApiError;

        const resp_body = root.curlPostTimed(allocator, BASE_URL, body, &.{ auth_hdr, referer_hdr, title_hdr }, 0) catch return error.OpenRouterApiError;
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
        const self: *OpenRouterProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenRouterApiError;

        var referer_hdr_buf: [256]u8 = undefined;
        const referer_hdr = std.fmt.bufPrint(&referer_hdr_buf, "HTTP-Referer: {s}", .{REFERER}) catch return error.OpenRouterApiError;

        var title_hdr_buf: [128]u8 = undefined;
        const title_hdr = std.fmt.bufPrint(&title_hdr_buf, "X-Title: {s}", .{TITLE}) catch return error.OpenRouterApiError;

        const resp_body = root.curlPostTimed(allocator, BASE_URL, body, &.{ auth_hdr, referer_hdr, title_hdr }, request.timeout_secs) catch return error.OpenRouterApiError;
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
        return "OpenRouter";
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
        const self: *OpenRouterProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildStreamingChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenRouterApiError;

        var referer_hdr_buf: [256]u8 = undefined;
        const referer_hdr = std.fmt.bufPrint(&referer_hdr_buf, "HTTP-Referer: {s}", .{REFERER}) catch return error.OpenRouterApiError;

        var title_hdr_buf: [128]u8 = undefined;
        const title_hdr = std.fmt.bufPrint(&title_hdr_buf, "X-Title: {s}", .{TITLE}) catch return error.OpenRouterApiError;

        return sse.curlStream(allocator, BASE_URL, body, auth_hdr, &.{ referer_hdr, title_hdr }, request.timeout_secs, callback, callback_ctx);
    }

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
    }

    fn deinitImpl(_: *anyopaque) void {}

    /// Build a full chat request JSON body from a ChatRequest.
    fn buildChatRequestBody(
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "{\"model\":\"");
        try buf.appendSlice(allocator, model);
        try buf.appendSlice(allocator, "\",\"messages\":[");

        for (request.messages, 0..) |msg, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "{\"role\":\"");
            try buf.appendSlice(allocator, msg.role.toSlice());
            try buf.appendSlice(allocator, "\",\"content\":");
            try root.serializeMessageContent(&buf, allocator, msg);
            if (msg.tool_call_id) |tc_id| {
                try buf.appendSlice(allocator, ",\"tool_call_id\":");
                try root.appendJsonString(&buf, allocator, tc_id);
            }
            try buf.append(allocator, '}');
        }

        try buf.append(allocator, ']');
        try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
        try appendOpenRouterReasoning(&buf, allocator, request.reasoning_effort);

        if (request.tools) |tools| {
            if (tools.len > 0) {
                try buf.appendSlice(allocator, ",\"tools\":");
                try root.convertToolsOpenAI(&buf, allocator, tools);
                try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
            }
        }

        try buf.append(allocator, '}');
        return try buf.toOwnedSlice(allocator);
    }

    /// Build a streaming chat request JSON body from a ChatRequest.
    fn buildStreamingChatRequestBody(
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "{\"model\":\"");
        try buf.appendSlice(allocator, model);
        try buf.appendSlice(allocator, "\",\"messages\":[");

        for (request.messages, 0..) |msg, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "{\"role\":\"");
            try buf.appendSlice(allocator, msg.role.toSlice());
            try buf.appendSlice(allocator, "\",\"content\":");
            try root.serializeMessageContent(&buf, allocator, msg);
            if (msg.tool_call_id) |tc_id| {
                try buf.appendSlice(allocator, ",\"tool_call_id\":");
                try root.appendJsonString(&buf, allocator, tc_id);
            }
            try buf.append(allocator, '}');
        }

        try buf.append(allocator, ']');
        try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
        try appendOpenRouterReasoning(&buf, allocator, request.reasoning_effort);

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
};

/// Append OpenRouter's unified reasoning parameter when reasoning_effort is set.
/// OpenRouter models like Kimi K2.5 use {"reasoning":{"effort":"high"}} to include
/// the reasoning trace in the response, regardless of whether they recognize
/// the top-level reasoning_effort field that appendGenerationFields emits for o-series models.
fn appendOpenRouterReasoning(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    reasoning_effort: ?[]const u8,
) !void {
    const effort = root.normalizeOpenAiReasoningEffort(reasoning_effort) orelse return;
    if (std.mem.eql(u8, effort, "none")) return;
    try buf.appendSlice(allocator, ",\"reasoning\":{\"effort\":");
    try root.appendJsonString(buf, allocator, effort);
    try buf.append(allocator, '}');
}

/// HTTP GET via curl subprocess with auth header.
fn curlGet(allocator: std.mem.Allocator, url: []const u8, auth_hdr: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s", "-H", auth_hdr, url,
    }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch return error.CurlReadError;

    const term = child.wait() catch return error.CurlWaitError;
    switch (term) {
        .Exited => |code| if (code != 0) {
            allocator.free(stdout);
            return error.CurlFailed;
        },
        else => {
            allocator.free(stdout);
            return error.CurlFailed;
        },
    }

    return stdout;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildRequestBody with system and user" {
    const body = try OpenRouterProvider.buildRequestBody(
        std.testing.allocator,
        "You are helpful",
        "Summarize this",
        "anthropic/claude-sonnet-4",
        0.5,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "anthropic/claude-sonnet-4") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"system\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"user\"") != null);
}

test "parseTextResponse single choice" {
    const body =
        \\{"choices":[{"message":{"content":"Hi from OpenRouter"}}]}
    ;
    const result = try OpenRouterProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hi from OpenRouter", result);
}

test "parseTextResponse empty choices" {
    const body =
        \\{"choices":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenRouterProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse classifies context errors" {
    const body =
        \\{"error":{"message":"maximum context length exceeded","type":"invalid_request_error"}}
    ;
    try std.testing.expectError(error.ContextLengthExceeded, OpenRouterProvider.parseTextResponse(std.testing.allocator, body));
}

test "supportsNativeTools returns true" {
    var p = OpenRouterProvider.init(std.testing.allocator, "key");
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

test "convertMessages produces valid JSON with system, user, assistant" {
    const alloc = std.testing.allocator;
    const messages = &[_]ChatMessage{
        ChatMessage.user("Hello"),
        ChatMessage.assistant("Hi there"),
        ChatMessage.user("Follow up"),
    };
    const result = try OpenRouterProvider.convertMessages(alloc, messages, "Be concise");
    defer alloc.free(result);

    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;

    // system + 3 messages = 4
    try std.testing.expectEqual(@as(usize, 4), arr.items.len);
    try std.testing.expectEqualStrings("system", arr.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("Be concise", arr.items[0].object.get("content").?.string);
    try std.testing.expectEqualStrings("user", arr.items[1].object.get("role").?.string);
    try std.testing.expectEqualStrings("assistant", arr.items[2].object.get("role").?.string);
    try std.testing.expectEqualStrings("user", arr.items[3].object.get("role").?.string);
}

test "convertMessages with tool role includes tool_call_id" {
    const alloc = std.testing.allocator;
    const messages = &[_]ChatMessage{
        ChatMessage.toolMsg("done", "call_xyz"),
    };
    const result = try OpenRouterProvider.convertMessages(alloc, messages, null);
    defer alloc.free(result);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;

    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    try std.testing.expectEqualStrings("tool", arr.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("call_xyz", arr.items[0].object.get("tool_call_id").?.string);
    try std.testing.expectEqualStrings("done", arr.items[0].object.get("content").?.string);
}

test "convertMessages without system prompt" {
    const alloc = std.testing.allocator;
    const messages = &[_]ChatMessage{
        ChatMessage.user("Hello"),
    };
    const result = try OpenRouterProvider.convertMessages(alloc, messages, null);
    defer alloc.free(result);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;

    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    try std.testing.expectEqualStrings("user", arr.items[0].object.get("role").?.string);
}

test "convertMessages escapes special characters" {
    const alloc = std.testing.allocator;
    const messages = &[_]ChatMessage{
        ChatMessage.user("line1\nline2\ttab\"quote"),
    };
    const result = try OpenRouterProvider.convertMessages(alloc, messages, null);
    defer alloc.free(result);

    // Must parse as valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;

    try std.testing.expectEqualStrings("line1\nline2\ttab\"quote", arr.items[0].object.get("content").?.string);
}

test "convertTools produces valid JSON schema" {
    const alloc = std.testing.allocator;
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
    const result = try OpenRouterProvider.convertTools(alloc, tools);
    defer alloc.free(result);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;

    try std.testing.expectEqual(@as(usize, 2), arr.items.len);

    // First tool
    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("function", t0.get("type").?.string);
    const f0 = t0.get("function").?.object;
    try std.testing.expectEqualStrings("shell", f0.get("name").?.string);
    try std.testing.expectEqualStrings("Run a shell command", f0.get("description").?.string);
    try std.testing.expect(f0.get("parameters").? == .object);

    // Second tool
    const t1 = arr.items[1].object;
    const f1 = t1.get("function").?.object;
    try std.testing.expectEqualStrings("file_read", f1.get("name").?.string);
}

test "convertTools with empty tools returns empty array" {
    const alloc = std.testing.allocator;
    const result = try OpenRouterProvider.convertTools(alloc, &.{});
    defer alloc.free(result);
    try std.testing.expectEqualStrings("[]", result);
}

test "warmup does not crash without key" {
    var p = OpenRouterProvider.init(std.testing.allocator, null);
    p.warmup(); // Should return immediately, no crash
}

test "buildRequestBody reasoning model omits temperature" {
    const body = try OpenRouterProvider.buildRequestBody(std.testing.allocator, null, "hello", "o3-mini", 0.5);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "buildChatRequestBody o3 uses max_completion_tokens" {
    const msgs = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .model = "o3",
        .temperature = 0.7,
        .max_tokens = 100,
    };
    const body = try OpenRouterProvider.buildChatRequestBody(std.testing.allocator, req, "o3", 0.7);
    defer std.testing.allocator.free(body);
    // Reasoning model: no temperature, uses max_completion_tokens
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
}

test "buildChatRequestBody escapes OpenRouter reasoning effort value" {
    const msgs = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .model = "openrouter/custom",
        .reasoning_effort = "high\"},\"pwned\":true,\"x\":\"",
    };
    const body = try OpenRouterProvider.buildChatRequestBody(std.testing.allocator, req, "openrouter/custom", 0.7);
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    const reasoning = parsed.value.object.get("reasoning").?.object;
    try std.testing.expectEqualStrings("high\"},\"pwned\":true,\"x\":\"", reasoning.get("effort").?.string);
    try std.testing.expect(parsed.value.object.get("pwned") == null);
}

test "chatWithHistory fails without key" {
    var p = OpenRouterProvider.init(std.testing.allocator, null);
    const messages = &[_]ChatMessage{
        ChatMessage.user("hello"),
    };
    const result = p.chatWithHistory(std.testing.allocator, messages, null, "openai/gpt-4o", 0.7);
    try std.testing.expectError(error.CredentialsNotSet, result);
}

test "vtable stream_chat is not null" {
    try std.testing.expect(OpenRouterProvider.vtable.stream_chat != null);
}

test "vtable supports_streaming is not null" {
    try std.testing.expect(OpenRouterProvider.vtable.supports_streaming != null);
}

test "buildStreamingChatRequestBody with stream flag" {
    const msgs = [_]ChatMessage{
        .{ .role = .user, .content = "test message" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .model = "test-model",
        .temperature = 0.7,
    };
    const body = try OpenRouterProvider.buildStreamingChatRequestBody(std.testing.allocator, req, "test-model", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
}

test "buildStreamingChatRequestBody escapes tool_call_id" {
    const msgs = [_]ChatMessage{
        .{ .role = .tool, .content = "done", .tool_call_id = "call_\"x\\y" },
    };
    const req = ChatRequest{
        .messages = &msgs,
        .model = "test-model",
    };
    const body = try OpenRouterProvider.buildStreamingChatRequestBody(std.testing.allocator, req, "test-model", 0.7);
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    const msg = parsed.value.object.get("messages").?.array.items[0].object;
    try std.testing.expectEqualStrings("call_\"x\\y", msg.get("tool_call_id").?.string);
}

test "streamChatImpl fails without key" {
    var p = OpenRouterProvider.init(std.testing.allocator, null);
    const provider = p.provider();

    const messages = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = ChatRequest{
        .messages = &messages,
        .model = "test-model",
    };

    var ctx: u8 = 0;
    const result = provider.streamChat(
        std.testing.allocator,
        req,
        "test-model",
        0.7,
        testCallback,
        @ptrCast(&ctx),
    );
    try std.testing.expectError(error.CredentialsNotSet, result);
}

fn testCallback(_: *anyopaque, _: root.StreamChunk) void {}

test "parseNativeResponse extracts think tags into reasoning_content" {
    const body =
        \\{"choices":[{"message":{"content":"<think>step by step</think>Final answer"}}],"model":"kimi-k2","usage":{"prompt_tokens":5,"completion_tokens":10,"total_tokens":15}}
    ;
    const alloc = std.testing.allocator;
    const response = try OpenRouterProvider.parseNativeResponse(alloc, body);
    defer {
        if (response.content) |c| alloc.free(c);
        if (response.reasoning_content) |rc| alloc.free(rc);
        alloc.free(response.tool_calls);
        alloc.free(response.model);
    }
    try std.testing.expectEqualStrings("Final answer", response.content.?);
    try std.testing.expectEqualStrings("step by step", response.reasoning_content.?);
}

test "parseNativeResponse reads native reasoning_content field" {
    const body =
        \\{"choices":[{"message":{"content":"The answer is 42","reasoning_content":"I computed this"}}],"model":"deepseek-r1","usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}
    ;
    const alloc = std.testing.allocator;
    const response = try OpenRouterProvider.parseNativeResponse(alloc, body);
    defer {
        if (response.content) |c| alloc.free(c);
        if (response.reasoning_content) |rc| alloc.free(rc);
        alloc.free(response.tool_calls);
        alloc.free(response.model);
    }
    try std.testing.expectEqualStrings("The answer is 42", response.content.?);
    try std.testing.expectEqualStrings("I computed this", response.reasoning_content.?);
}

test "parseNativeResponse no think tags leaves reasoning_content null" {
    const body =
        \\{"choices":[{"message":{"content":"Plain response"}}],"model":"gpt-4o","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
    ;
    const alloc = std.testing.allocator;
    const response = try OpenRouterProvider.parseNativeResponse(alloc, body);
    defer {
        if (response.content) |c| alloc.free(c);
        if (response.reasoning_content) |rc| alloc.free(rc);
        alloc.free(response.tool_calls);
        alloc.free(response.model);
    }
    try std.testing.expectEqualStrings("Plain response", response.content.?);
    try std.testing.expect(response.reasoning_content == null);
}
