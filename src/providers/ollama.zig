const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

/// Ollama local LLM provider.
///
/// Endpoints:
/// - POST {base_url}/api/chat
/// - No authentication required (local service)
pub const OllamaProvider = struct {
    base_url: []const u8,
    allocator: std.mem.Allocator,

    const DEFAULT_BASE_URL = "http://localhost:11434";

    pub fn init(allocator: std.mem.Allocator, base_url: ?[]const u8) OllamaProvider {
        const url = if (base_url) |u| trimTrailingSlash(u) else DEFAULT_BASE_URL;
        return .{
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

    /// Build the chat endpoint URL.
    pub fn chatUrl(self: OllamaProvider, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/api/chat", .{self.base_url});
    }

    /// Build an Ollama chat request JSON body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"system","content":"{s}"}},{{"role":"user","content":"{s}"}}],"stream":false,"options":{{"temperature":{d:.2}}}}}
            , .{ model, sys, message, temperature });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"model":"{s}","messages":[{{"role":"user","content":"{s}"}}],"stream":false,"options":{{"temperature":{d:.2}}}}}
            , .{ model, message, temperature });
        }
    }

    /// Parse text content from an Ollama response.
    pub fn parseResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        if (root_obj.get("message")) |msg| {
            if (msg.object.get("content")) |content| {
                if (content == .string) {
                    return try allocator.dupe(u8, content.string);
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Create a Provider interface from this OllamaProvider.
    pub fn provider(self: *OllamaProvider) Provider {
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
        const self: *OllamaProvider = @ptrCast(@alignCast(ptr));

        const url = try self.chatUrl(allocator);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, message, model, temperature);
        defer allocator.free(body);

        const resp_body = curlPost(allocator, url, body) catch return error.OllamaApiError;
        defer allocator.free(resp_body);

        return parseResponse(allocator, resp_body);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *OllamaProvider = @ptrCast(@alignCast(ptr));

        // Extract system prompt and last user message from the request
        var system_prompt: ?[]const u8 = null;
        var user_message: []const u8 = "";
        for (request.messages) |msg| {
            if (msg.role == .system) system_prompt = msg.content;
            if (msg.role == .user) user_message = msg.content;
        }

        const url = try self.chatUrl(allocator);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, user_message, model, temperature);
        defer allocator.free(body);

        const resp_body = curlPost(allocator, url, body) catch return error.OllamaApiError;
        defer allocator.free(resp_body);

        const text = try parseResponse(allocator, resp_body);
        return ChatResponse{ .content = text };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Ollama";
    }

    fn deinitImpl(_: *anyopaque) void {}
};

/// HTTP POST via curl subprocess (no auth needed for local Ollama).
fn curlPost(allocator: std.mem.Allocator, url: []const u8, body: []const u8) ![]u8 {
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

test "default url" {
    const p = OllamaProvider.init(std.testing.allocator, null);
    try std.testing.expectEqualStrings("http://localhost:11434", p.base_url);
}

test "custom url trailing slash" {
    const p = OllamaProvider.init(std.testing.allocator, "http://192.168.1.100:11434/");
    try std.testing.expectEqualStrings("http://192.168.1.100:11434", p.base_url);
}

test "custom url no trailing slash" {
    const p = OllamaProvider.init(std.testing.allocator, "http://myserver:11434");
    try std.testing.expectEqualStrings("http://myserver:11434", p.base_url);
}

test "chat url is correct" {
    const p = OllamaProvider.init(std.testing.allocator, null);
    const url = try p.chatUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("http://localhost:11434/api/chat", url);
}

test "buildRequestBody with system" {
    const body = try OllamaProvider.buildRequestBody(std.testing.allocator, "You are helpful", "hello", "llama3", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "llama3") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "temperature") != null);
}

test "buildRequestBody without system" {
    const body = try OllamaProvider.buildRequestBody(std.testing.allocator, null, "test", "mistral", 0.0);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"system\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "mistral") != null);
}

test "parseResponse extracts content" {
    const body =
        \\{"message":{"role":"assistant","content":"Hello from Ollama!"}}
    ;
    const result = try OllamaProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Ollama!", result);
}

test "parseResponse empty content" {
    const body =
        \\{"message":{"role":"assistant","content":""}}
    ;
    const result = try OllamaProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "supportsNativeTools returns false" {
    var p = OllamaProvider.init(std.testing.allocator, null);
    const prov = p.provider();
    try std.testing.expect(!prov.supportsNativeTools());
}
