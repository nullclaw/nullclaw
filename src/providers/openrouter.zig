const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ToolCall = root.ToolCall;
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
    const REFERER = "https://github.com/theonlyhennygod/nullclaw";
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

    /// Parse text content from an OpenRouter response (OpenAI-compatible format).
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
        const self: *OpenRouterProvider = @ptrCast(@alignCast(ptr));
        const api_key = self.api_key orelse return error.CredentialsNotSet;

        const body = try buildRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
        defer allocator.free(auth_hdr);

        const referer_hdr = try std.fmt.allocPrint(allocator, "HTTP-Referer: {s}", .{REFERER});
        defer allocator.free(referer_hdr);

        const title_hdr = try std.fmt.allocPrint(allocator, "X-Title: {s}", .{TITLE});
        defer allocator.free(title_hdr);

        const resp_body = curlPost(allocator, BASE_URL, body, auth_hdr, referer_hdr, title_hdr) catch return error.OpenRouterApiError;
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

        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
        defer allocator.free(auth_hdr);

        const referer_hdr = try std.fmt.allocPrint(allocator, "HTTP-Referer: {s}", .{REFERER});
        defer allocator.free(referer_hdr);

        const title_hdr = try std.fmt.allocPrint(allocator, "X-Title: {s}", .{TITLE});
        defer allocator.free(title_hdr);

        const resp_body = curlPost(allocator, BASE_URL, body, auth_hdr, referer_hdr, title_hdr) catch return error.OpenRouterApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "OpenRouter";
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
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.OpenRouterApiError;
        try buf.appendSlice(allocator, temp_str);

        try buf.appendSlice(allocator, ",\"max_tokens\":");
        var max_buf: [16]u8 = undefined;
        const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{request.max_tokens}) catch return error.OpenRouterApiError;
        try buf.appendSlice(allocator, max_str);

        try buf.append(allocator, '}');
        return try buf.toOwnedSlice(allocator);
    }
};

/// HTTP POST via curl subprocess with extra OpenRouter headers.
fn curlPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8, auth_hdr: []const u8, referer_hdr: []const u8, title_hdr: []const u8) ![]u8 {
    var child = std.process.Child.init(&.{
        "curl", "-s",                             "-X", "POST",
        "-H",   "Content-Type: application/json", "-H", auth_hdr,
        "-H",   referer_hdr,                      "-H", title_hdr,
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
    const p = OpenRouterProvider.init(std.testing.allocator, "sk-or-123");
    try std.testing.expectEqualStrings("sk-or-123", p.api_key.?);
}

test "creates without key" {
    const p = OpenRouterProvider.init(std.testing.allocator, null);
    try std.testing.expect(p.api_key == null);
}

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

test "supportsNativeTools returns true" {
    var p = OpenRouterProvider.init(std.testing.allocator, "key");
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}
