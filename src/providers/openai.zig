const std = @import("std");
const root = @import("root.zig");

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

    const BASE_URL = "https://api.openai.com/v1/chat/completions";

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) OpenAiProvider {
        return .{
            .api_key = api_key,
            .allocator = allocator,
        };
    }

    /// Build a simple chat request JSON body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"system","content":"{s}"}},{{"role":"user","content":"{s}"}}],"temperature":{d:.2}}}
            , .{ model, sys, message, temperature });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"user","content":"{s}"}}],"temperature":{d:.2}}}
            , .{ model, message, temperature });
        }
    }

    /// Parse text content from an OpenAI chat completions response.
    pub fn parseTextResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

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
        .getName = getNameImpl,
        .deinit = deinitImpl,
    };

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

        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
        defer allocator.free(auth_hdr);

        const resp_body = curlPost(allocator, BASE_URL, body, auth_hdr) catch return error.OpenAiApiError;
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

        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
        defer allocator.free(auth_hdr);

        const resp_body = curlPost(allocator, BASE_URL, body, auth_hdr) catch return error.OpenAiApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "OpenAI";
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
            try buf.appendSlice(allocator, "\",\"content\":\"");
            try buf.appendSlice(allocator, msg.content);
            try buf.append(allocator, '"');
            if (msg.tool_call_id) |tc_id| {
                try buf.appendSlice(allocator, ",\"tool_call_id\":\"");
                try buf.appendSlice(allocator, tc_id);
                try buf.append(allocator, '"');
            }
            try buf.append(allocator, '}');
        }

        try buf.appendSlice(allocator, "],\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.OpenAiApiError;
        try buf.appendSlice(allocator, temp_str);

        try buf.appendSlice(allocator, ",\"max_tokens\":");
        var max_buf: [16]u8 = undefined;
        const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{request.max_tokens}) catch return error.OpenAiApiError;
        try buf.appendSlice(allocator, max_str);

        try buf.append(allocator, '}');
        return try buf.toOwnedSlice(allocator);
    }
};

/// HTTP POST via curl subprocess.
fn curlPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8, auth_hdr: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s",                             "-X", "POST",
        "-H",   "Content-Type: application/json", "-H", auth_hdr,
        "-d",   body,                             url,
    }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch return error.CurlReadError;

    const term = child.wait() catch return error.CurlWaitError;
    if (term != .Exited or term.Exited != 0) return error.CurlFailed;

    return stdout;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "creates with key" {
    const p = OpenAiProvider.init(std.testing.allocator, "sk-proj-abc123");
    try std.testing.expectEqualStrings("sk-proj-abc123", p.api_key.?);
}

test "creates without key" {
    const p = OpenAiProvider.init(std.testing.allocator, null);
    try std.testing.expect(p.api_key == null);
}

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
    var p = OpenAiProvider.init(std.testing.allocator, "key");
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

test "parseTextResponse with unicode" {
    const body =
        \\{"choices":[{"message":{"content":"こんにちは 🦀"}}]}
    ;
    const result = try OpenAiProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("こんにちは 🦀", result);
}

test "parseTextResponse with long content" {
    const body =
        \\{"choices":[{"message":{"content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}
    ;
    const result = try OpenAiProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expect(result.len == 64);
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

test "provider getName returns OpenAI" {
    var p = OpenAiProvider.init(std.testing.allocator, "key");
    const prov = p.provider();
    try std.testing.expectEqualStrings("OpenAI", prov.getName());
}
