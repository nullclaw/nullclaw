const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ToolCall = root.ToolCall;
const ToolSpec = root.ToolSpec;
const TokenUsage = root.TokenUsage;

/// Anthropic Claude API provider.
///
/// Supports:
/// - x-api-key authentication (standard API keys)
/// - Bearer token authentication (setup/OAuth tokens starting with sk-ant-oat01-)
/// - Custom base URLs for proxies/self-hosted endpoints
pub const AnthropicProvider = struct {
    credential: ?[]const u8,
    base_url: []const u8,
    allocator: std.mem.Allocator,

    const DEFAULT_BASE_URL = "https://api.anthropic.com";
    const API_VERSION = "2023-06-01";
    const DEFAULT_MAX_TOKENS: u32 = 4096;

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

        if (root_obj.get("content")) |content_arr| {
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

        return error.NoResponseContent;
    }

    /// Parse a native tool-calling response into ChatResponse.
    pub fn parseNativeResponse(allocator: std.mem.Allocator, body: []const u8) !ChatResponse {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        var text_parts: std.ArrayListUnmanaged(u8) = .empty;
        defer text_parts.deinit(allocator);

        var tool_calls_list: std.ArrayListUnmanaged(ToolCall) = .empty;

        if (root_obj.get("content")) |content_arr| {
            for (content_arr.array.items) |block| {
                const obj = block.object;
                const kind = if (obj.get("type")) |t| (if (t == .string) t.string else "") else "";

                if (std.mem.eql(u8, kind, "text")) {
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
        const self: *AnthropicProvider = @ptrCast(@alignCast(ptr));
        const credential = self.credential orelse return error.CredentialsNotSet;
        const is_oauth = isSetupToken(credential);

        // URL: append ?beta=true for OAuth tokens
        const url = if (is_oauth)
            try std.fmt.allocPrint(allocator, "{s}/v1/messages?beta=true", .{self.base_url})
        else
            try self.messagesUrl(allocator);
        defer allocator.free(url);

        const body = try buildSimpleRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        const auth = try authHeaderValue(allocator, credential);
        defer if (auth.needs_free) allocator.free(auth.header_value);

        // Build header strings for curl
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ auth.header_name, auth.header_value }) catch return error.AnthropicApiError;

        var version_hdr_buf: [64]u8 = undefined;
        const version_hdr = std.fmt.bufPrint(&version_hdr_buf, "anthropic-version: {s}", .{API_VERSION}) catch return error.AnthropicApiError;

        // OAuth tokens require extra beta and user-agent headers
        const resp_body = if (is_oauth)
            curlPostOAuth(allocator, url, body, auth_hdr, version_hdr) catch return error.AnthropicApiError
        else
            curlPost(allocator, url, body, auth_hdr, version_hdr) catch return error.AnthropicApiError;
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

        // Extract system prompt and last user message from ChatRequest
        var system_prompt: ?[]const u8 = null;
        var user_message: []const u8 = "";
        for (request.messages) |msg| {
            if (msg.role == .system) system_prompt = msg.content;
            if (msg.role == .user) user_message = msg.content;
        }

        // URL: append ?beta=true for OAuth tokens
        const url = if (is_oauth)
            try std.fmt.allocPrint(allocator, "{s}/v1/messages?beta=true", .{self.base_url})
        else
            try self.messagesUrl(allocator);
        defer allocator.free(url);

        const body = try buildSimpleRequestBody(allocator, system_prompt, user_message, model, temperature);
        defer allocator.free(body);

        const auth = try authHeaderValue(allocator, credential);
        defer if (auth.needs_free) allocator.free(auth.header_value);

        // Build header strings for curl
        var auth_hdr_buf: [512]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ auth.header_name, auth.header_value }) catch return error.AnthropicApiError;

        var version_hdr_buf: [64]u8 = undefined;
        const version_hdr = std.fmt.bufPrint(&version_hdr_buf, "anthropic-version: {s}", .{API_VERSION}) catch return error.AnthropicApiError;

        const resp_body = if (is_oauth)
            curlPostOAuth(allocator, url, body, auth_hdr, version_hdr) catch return error.AnthropicApiError
        else
            curlPost(allocator, url, body, auth_hdr, version_hdr) catch return error.AnthropicApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Anthropic";
    }

    fn deinitImpl(_: *anyopaque) void {}
};

/// HTTP POST via curl subprocess (avoids Zig 0.15 std.http.Client segfaults).
fn curlPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8, auth_hdr: []const u8, extra_hdr: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s",                             "-X", "POST",
        "-H",   "Content-Type: application/json", "-H", auth_hdr,
        "-H",   extra_hdr,                        "-d", body,
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

/// HTTP POST with OAuth-specific headers (anthropic-beta, user-agent).
fn curlPostOAuth(allocator: std.mem.Allocator, url: []const u8, body: []const u8, auth_hdr: []const u8, version_hdr: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s",                               "-X", "POST",
        "-H",   "Content-Type: application/json",   "-H", auth_hdr,
        "-H",   version_hdr,                        "-H", "anthropic-beta: oauth-2025-04-20",
        "-A",   "claude-cli/2.1.2 (external, cli)", "-d", body,
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

pub const AuthHeader = struct {
    header_name: []const u8,
    header_value: []const u8,
    needs_free: bool,
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "creates with key" {
    const p = AnthropicProvider.init(std.testing.allocator, "sk-ant-test123", null);
    try std.testing.expectEqualStrings("sk-ant-test123", p.credential.?);
    try std.testing.expectEqualStrings("https://api.anthropic.com", p.base_url);
}

test "creates without key" {
    const p = AnthropicProvider.init(std.testing.allocator, null, null);
    try std.testing.expect(p.credential == null);
    try std.testing.expectEqualStrings("https://api.anthropic.com", p.base_url);
}

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
        \\{"content":[{"type":"text","text":"Hi"}],"model":"claude-sonnet-4-20250514"}
    ;
    const response = try AnthropicProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (response.content) |c_val| std.testing.allocator.free(c_val);
        std.testing.allocator.free(response.tool_calls);
        std.testing.allocator.free(response.model);
    }
    try std.testing.expectEqualStrings("claude-sonnet-4-20250514", response.model);
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

test "buildSimpleRequestBody includes temperature" {
    const body = try AnthropicProvider.buildSimpleRequestBody(
        std.testing.allocator,
        null,
        "test",
        "claude-3",
        0.50,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "0.50") != null);
}

test "buildSimpleRequestBody includes max_tokens" {
    const body = try AnthropicProvider.buildSimpleRequestBody(
        std.testing.allocator,
        null,
        "test",
        "claude-3",
        0.7,
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "4096") != null);
}

test "provider getName returns Anthropic" {
    var p = AnthropicProvider.init(std.testing.allocator, "key", null);
    const prov = p.provider();
    try std.testing.expectEqualStrings("Anthropic", prov.getName());
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
