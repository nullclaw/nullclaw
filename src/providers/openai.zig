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

/// OpenAI API provider.
///
/// Endpoints:
/// - POST https://api.openai.com/v1/chat/completions
/// - Authorization: Bearer <key>
pub const OpenAiProvider = struct {
    api_key: ?[]const u8,
    allocator: std.mem.Allocator,
    /// Optional User-Agent header for HTTP requests.
    user_agent: ?[]const u8 = null,

    const BASE_URL = "https://api.openai.com/v1/chat/completions";

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8, user_agent: ?[]const u8) OpenAiProvider {
        return .{
            .api_key = api_key,
            .allocator = allocator,
            .user_agent = user_agent,
        };
    }

    fn validateUserAgent(user_agent: []const u8) bool {
        // Disallow header injection and malformed values.
        return std.mem.indexOfAny(u8, user_agent, "\r\n") == null;
    }

    /// Build a simple chat request JSON body.
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

    /// Parse text content from an OpenAI chat completions response.
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
            root.setLastApiErrorDetail("openai", sanitized orelse summary);
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
            root.setLastApiErrorDetail("openai", sanitized orelse summary);
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

                // Parse usage
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

    /// Create a Provider interface from this OpenAiProvider.
    pub fn provider(self: *OpenAiProvider) Provider {
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
        const self: *OpenAiProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildStreamingChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenAiApiError;

        // Build extra headers (User-Agent if configured)
        var extra_headers: [1][]const u8 = undefined;
        var extra_header_count: usize = 0;
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.OpenAiApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.OpenAiApiError;
            extra_headers[extra_header_count] = user_agent_hdr.?;
            extra_header_count += 1;
        }

        return sse.curlStream(allocator, BASE_URL, body, auth_hdr, extra_headers[0..extra_header_count], request.timeout_secs, callback, callback_ctx);
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
        const self: *OpenAiProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenAiApiError;
        headers_buf[header_count] = auth_hdr;
        header_count += 1;
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.OpenAiApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.OpenAiApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, BASE_URL, body, headers_buf[0..header_count], 0) catch return error.OpenAiApiError;
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
        const self: *OpenAiProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{api_key}) catch return error.OpenAiApiError;
        headers_buf[header_count] = auth_hdr;
        header_count += 1;
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.OpenAiApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.OpenAiApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, BASE_URL, body, headers_buf[0..header_count], request.timeout_secs) catch return error.OpenAiApiError;
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
        return "OpenAI";
    }

    fn deinitImpl(_: *anyopaque) void {}

    /// Build a streaming chat request JSON body (same as buildChatRequestBody but with "stream":true).
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

        if (request.tools) |tools| {
            if (tools.len > 0) {
                try buf.appendSlice(allocator, ",\"tools\":");
                try root.convertToolsOpenAI(&buf, allocator, tools);
                try buf.appendSlice(allocator, ",\"tool_choice\":\"auto\"");
            }
        }

        try buf.appendSlice(allocator, ",\"stream\":true,\"stream_options\":{\"include_usage\":true}}");
        return try buf.toOwnedSlice(allocator);
    }

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
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildRequestBody without system" {
    const body = try OpenAiProvider.buildRequestBody(std.testing.allocator, null, "hello", "gpt-4o", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "gpt-4o") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") == null);
}

test "buildRequestBody with system" {
    const body = try OpenAiProvider.buildRequestBody(std.testing.allocator, "You are helpful", "hello", "gpt-4o", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"system\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "You are helpful") != null);
}

test "buildRequestBody reasoning model omits temperature" {
    const body = try OpenAiProvider.buildRequestBody(std.testing.allocator, null, "hello", "gpt-5.2", 0.1);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "parseTextResponse single choice" {
    const body =
        \\{"choices":[{"message":{"content":"Hi!"}}]}
    ;
    const result = try OpenAiProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hi!", result);
}

test "parseTextResponse empty choices" {
    const body =
        \\{"choices":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseTextResponse classifies rate-limit errors" {
    const body =
        \\{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","code":429}}
    ;
    try std.testing.expectError(error.RateLimited, OpenAiProvider.parseTextResponse(std.testing.allocator, body));
}

test "parseNativeResponse with tool calls" {
    const body =
        \\{"choices":[{"message":{"content":"Let me help","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"cmd\":\"ls\"}"}}]}}],"model":"gpt-4o","usage":{"prompt_tokens":5,"completion_tokens":10,"total_tokens":15}}
    ;
    const response = try OpenAiProvider.parseNativeResponse(std.testing.allocator, body);
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
    try std.testing.expectEqualStrings("Let me help", response.content.?);
    try std.testing.expect(response.tool_calls.len == 1);
    try std.testing.expectEqualStrings("shell", response.tool_calls[0].name);
    try std.testing.expectEqualStrings("call_1", response.tool_calls[0].id);
    try std.testing.expect(response.usage.prompt_tokens == 5);
    try std.testing.expect(response.usage.total_tokens == 15);
}

test "supportsNativeTools returns true" {
    var p = OpenAiProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

test "parseTextResponse multiple choices returns first" {
    const body =
        \\{"choices":[{"message":{"content":"A"}},{"message":{"content":"B"}}]}
    ;
    const result = try OpenAiProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("A", result);
}

test "parseNativeResponse text only no tool calls" {
    const body =
        \\{"choices":[{"message":{"content":"Just text"}}],"model":"gpt-4o","usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}
    ;
    const response = try OpenAiProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("Just text", response.content.?);
    try std.testing.expect(response.tool_calls.len == 0);
    try std.testing.expect(response.usage.prompt_tokens == 3);
    try std.testing.expect(response.usage.total_tokens == 8);
}

test "parseNativeResponse empty choices fails" {
    const body =
        \\{"choices":[],"model":"gpt-4o"}
    ;
    try std.testing.expectError(error.NoResponseContent, OpenAiProvider.parseNativeResponse(std.testing.allocator, body));
}

test "parseNativeResponse multiple tool calls" {
    const body =
        \\{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"shell","arguments":"{}"}},{"id":"c2","type":"function","function":{"name":"read","arguments":"{}"}}]}}],"model":"gpt-4o"}
    ;
    const response = try OpenAiProvider.parseNativeResponse(std.testing.allocator, body);
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
    try std.testing.expect(response.tool_calls.len == 2);
    try std.testing.expectEqualStrings("shell", response.tool_calls[0].name);
    try std.testing.expectEqualStrings("read", response.tool_calls[1].name);
}

test "parseNativeResponse model field extracted" {
    const body =
        \\{"choices":[{"message":{"content":"Hi"}}],"model":"gpt-4o-2024-05-13"}
    ;
    const response = try OpenAiProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("gpt-4o-2024-05-13", response.model);
}

test "buildRequestBody includes temperature zero" {
    const body = try OpenAiProvider.buildRequestBody(std.testing.allocator, null, "hello", "gpt-4o", 0.0);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "0.00") != null);
}

test "buildChatRequestBody reasoning model uses max_completion_tokens" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-5.2",
        .temperature = 0.2,
        .max_tokens = 42,
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "gpt-5.2", 0.2);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "buildStreamingChatRequestBody reasoning model uses max_completion_tokens" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-5.2",
        .temperature = 0.2,
        .max_tokens = 64,
    };
    const body = try OpenAiProvider.buildStreamingChatRequestBody(std.testing.allocator, req, "gpt-5.2", 0.2);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":64") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"include_usage\":true") != null);
}

test "provider getName returns OpenAI" {
    var p = OpenAiProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expectEqualStrings("OpenAI", prov.getName());
}

test "validateUserAgent rejects CRLF injection" {
    try std.testing.expect(OpenAiProvider.validateUserAgent("nullclaw/1.0"));
    try std.testing.expect(!OpenAiProvider.validateUserAgent("bad\r\nX-Test: 1"));
}

test "isReasoningModel detects all reasoning prefixes" {
    try std.testing.expect(root.isReasoningModel("gpt-5"));
    try std.testing.expect(root.isReasoningModel("gpt-5.1"));
    try std.testing.expect(root.isReasoningModel("gpt-5.2-turbo"));
    try std.testing.expect(root.isReasoningModel("o1"));
    try std.testing.expect(root.isReasoningModel("o1-mini"));
    try std.testing.expect(root.isReasoningModel("o1-preview"));
    try std.testing.expect(root.isReasoningModel("o3"));
    try std.testing.expect(root.isReasoningModel("o3-mini"));
    try std.testing.expect(root.isReasoningModel("o4-mini"));
    try std.testing.expect(root.isReasoningModel("o4-mini-2025"));
    try std.testing.expect(root.isReasoningModel("codex-mini"));
    try std.testing.expect(root.isReasoningModel("codex-mini-latest"));
    // Non-reasoning models
    try std.testing.expect(!root.isReasoningModel("gpt-4o"));
    try std.testing.expect(!root.isReasoningModel("gpt-4-turbo"));
    try std.testing.expect(!root.isReasoningModel("gpt-4o-mini"));
    try std.testing.expect(!root.isReasoningModel("claude-sonnet-4"));
}

test "o3-mini omits temperature" {
    const body = try OpenAiProvider.buildRequestBody(std.testing.allocator, null, "hello", "o3-mini", 0.5);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "buildChatRequestBody without max_tokens omits it" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hi" },
    };
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o", .temperature = 0.7 };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "gpt-4o", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") != null);
}

test "o1 uses max_completion_tokens" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "o1",
        .temperature = 0.7,
        .max_tokens = 100,
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "o1", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "reasoning model with reasoning_effort=none includes temperature" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-5.1",
        .temperature = 0.3,
        .max_tokens = 200,
        .reasoning_effort = "none",
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "gpt-5.1", 0.3);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":0.30") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_effort\":\"none\"") != null);
}

test "reasoning_effort emitted in request body" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "o3-mini",
        .temperature = 0.7,
        .max_tokens = 50,
        .reasoning_effort = "high",
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "o3-mini", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_effort\":\"high\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":50") != null);
}

test "o4-mini omits temperature in streaming request" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "o4-mini",
        .temperature = 0.7,
        .max_tokens = 80,
    };
    const body = try OpenAiProvider.buildStreamingChatRequestBody(std.testing.allocator, req, "o4-mini", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":80") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
}

test "codex-mini uses max_completion_tokens" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "codex-mini-latest",
        .temperature = 0.5,
        .max_tokens = 60,
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "codex-mini-latest", 0.5);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":60") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_tokens\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
}

test "reasoning_effort on non-reasoning model is not emitted" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "gpt-4o",
        .temperature = 0.7,
        .max_tokens = 100,
        .reasoning_effort = "high",
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "gpt-4o", 0.7);
    defer std.testing.allocator.free(body);
    // Non-reasoning model: reasoning_effort should NOT appear
    try std.testing.expect(std.mem.indexOf(u8, body, "reasoning_effort") == null);
    // Should still have temperature
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") != null);
}

test "reasoning_effort medium omits temperature" {
    const msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "hello" },
    };
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "o3-mini",
        .temperature = 0.5,
        .max_tokens = 50,
        .reasoning_effort = "medium",
    };
    const body = try OpenAiProvider.buildChatRequestBody(std.testing.allocator, req, "o3-mini", 0.5);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_effort\":\"medium\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"temperature\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"max_completion_tokens\":50") != null);
}
