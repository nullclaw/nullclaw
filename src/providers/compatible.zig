const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ToolCall = root.ToolCall;
const TokenUsage = root.TokenUsage;

/// How the provider expects the API key to be sent.
pub const AuthStyle = enum {
    /// `Authorization: Bearer <key>`
    bearer,
    /// `x-api-key: <key>`
    x_api_key,

    pub fn headerName(self: AuthStyle) []const u8 {
        return switch (self) {
            .bearer => "authorization",
            .x_api_key => "x-api-key",
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

    /// Build a chat request JSON body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"system","content":"{s}"}},{{"role":"user","content":"{s}"}}],"temperature":{d:.2},"stream":false}}
            , .{ model, sys, message, temperature });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"user","content":"{s}"}}],"temperature":{d:.2},"stream":false}}
            , .{ model, message, temperature });
        }
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
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        const resp_body = if (auth) |a| blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            break :blk curlPost(allocator, url, body, auth_hdr) catch return error.CompatibleApiError;
        } else curlPostNoAuth(allocator, url, body) catch return error.CompatibleApiError;
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
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));

        // Extract system prompt and last user message from ChatRequest
        var system_prompt: ?[]const u8 = null;
        var user_message: []const u8 = "";
        for (request.messages) |msg| {
            if (msg.role == .system) system_prompt = msg.content;
            if (msg.role == .user) user_message = msg.content;
        }

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, user_message, model, temperature);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        const resp_body = if (auth) |a| blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            break :blk curlPost(allocator, url, body, auth_hdr) catch return error.CompatibleApiError;
        } else curlPostNoAuth(allocator, url, body) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(ptr: *anyopaque) []const u8 {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.name;
    }

    fn deinitImpl(_: *anyopaque) void {}
};

/// HTTP POST via curl subprocess with auth header.
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

/// HTTP POST via curl subprocess without auth (for keyless providers like Ollama).
fn curlPostNoAuth(allocator: std.mem.Allocator, url: []const u8, body: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s",                             "-X", "POST",
        "-H",   "Content-Type: application/json", "-d", body,
        url,
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
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "Venice", "https://api.venice.ai", "vn-key", .bearer);
    try std.testing.expectEqualStrings("Venice", p.name);
    try std.testing.expectEqualStrings("https://api.venice.ai", p.base_url);
    try std.testing.expectEqualStrings("vn-key", p.api_key.?);
}

test "creates without key" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer);
    try std.testing.expect(p.api_key == null);
}

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

test "chatCompletionsUrl groq" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "Groq", "https://api.groq.com/openai", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.groq.com/openai/chat/completions", url);
}

test "chatCompletionsUrl minimax" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "MiniMax", "https://api.minimaxi.com/v1", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.minimaxi.com/v1/chat/completions", url);
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

test "chatCompletionsUrl glm endpoint" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "glm", "https://open.bigmodel.cn/api/paas/v4", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://open.bigmodel.cn/api/paas/v4/chat/completions", url);
}

test "chatCompletionsUrl zai endpoint" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "zai", "https://api.z.ai/api/paas/v4", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.z.ai/api/paas/v4/chat/completions", url);
}

test "chatCompletionsUrl opencode endpoint" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "opencode", "https://opencode.ai/zen/v1", null, .bearer);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://opencode.ai/zen/v1/chat/completions", url);
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

test "chatCompletionsUrl volcengine custom path preserved" {
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
