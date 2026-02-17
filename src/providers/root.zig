const std = @import("std");

// Re-export all provider sub-modules
pub const anthropic = @import("anthropic.zig");
pub const openai = @import("openai.zig");
pub const ollama = @import("ollama.zig");
pub const gemini = @import("gemini.zig");
pub const openrouter = @import("openrouter.zig");
pub const compatible = @import("compatible.zig");
pub const reliable = @import("reliable.zig");
pub const router = @import("router.zig");

// ════════════════════════════════════════════════════════════════════════════
// Core Types
// ════════════════════════════════════════════════════════════════════════════

/// Roles a message can have in a conversation.
pub const Role = enum {
    system,
    user,
    assistant,
    tool,

    pub fn toSlice(self: Role) []const u8 {
        return switch (self) {
            .system => "system",
            .user => "user",
            .assistant => "assistant",
            .tool => "tool",
        };
    }

    pub fn fromSlice(s: []const u8) ?Role {
        if (std.mem.eql(u8, s, "system")) return .system;
        if (std.mem.eql(u8, s, "user")) return .user;
        if (std.mem.eql(u8, s, "assistant")) return .assistant;
        if (std.mem.eql(u8, s, "tool")) return .tool;
        return null;
    }
};

/// A single message in a conversation.
pub const ChatMessage = struct {
    role: Role,
    content: []const u8,
    /// Optional name (for tool results).
    name: ?[]const u8 = null,
    /// Tool call ID this message responds to.
    tool_call_id: ?[]const u8 = null,

    pub fn system(content: []const u8) ChatMessage {
        return .{ .role = .system, .content = content };
    }

    pub fn user(content: []const u8) ChatMessage {
        return .{ .role = .user, .content = content };
    }

    pub fn assistant(content: []const u8) ChatMessage {
        return .{ .role = .assistant, .content = content };
    }

    pub fn toolMsg(content: []const u8, tool_call_id: []const u8) ChatMessage {
        return .{ .role = .tool, .content = content, .tool_call_id = tool_call_id };
    }
};

/// A tool call requested by the LLM.
pub const ToolCall = struct {
    id: []const u8,
    name: []const u8,
    arguments: []const u8,
};

/// Token usage stats from a provider response.
pub const TokenUsage = struct {
    prompt_tokens: u32 = 0,
    completion_tokens: u32 = 0,
    total_tokens: u32 = 0,
};

/// An LLM response that may contain text, tool calls, or both.
pub const ChatResponse = struct {
    content: ?[]const u8 = null,
    tool_calls: []const ToolCall = &.{},
    usage: TokenUsage = .{},
    model: []const u8 = "",

    /// True when the LLM wants to invoke at least one tool.
    pub fn hasToolCalls(self: ChatResponse) bool {
        return self.tool_calls.len > 0;
    }

    /// Convenience: return text content or empty string.
    pub fn contentOrEmpty(self: ChatResponse) []const u8 {
        return self.content orelse "";
    }
};

/// Tool specification for function-calling APIs.
pub const ToolSpec = struct {
    name: []const u8,
    description: []const u8,
    /// JSON schema for the tool's parameters.
    parameters_json: []const u8 = "{}",
};

/// Request payload for provider chat calls.
pub const ChatRequest = struct {
    messages: []const ChatMessage,
    model: []const u8 = "",
    temperature: f64 = 0.7,
    max_tokens: u32 = 4096,
    tools: ?[]const ToolSpec = null,
};

// ════════════════════════════════════════════════════════════════════════════
// Provider Interface (vtable-based polymorphism)
// ════════════════════════════════════════════════════════════════════════════

/// Provider interface. Zig equivalent of ZeroClaw's `trait Provider`.
/// Uses vtable-based polymorphism for runtime dispatch.
pub const Provider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Simple one-shot chat: system prompt + user message.
        chatWithSystem: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            system_prompt: ?[]const u8,
            message: []const u8,
            model: []const u8,
            temperature: f64,
        ) anyerror![]const u8,

        /// Structured chat returning ChatResponse (supports tool calls).
        chat: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: ChatRequest,
            model: []const u8,
            temperature: f64,
        ) anyerror!ChatResponse,

        /// Whether this provider supports native tool calls.
        supportsNativeTools: *const fn (ptr: *anyopaque) bool,

        /// Provider name for diagnostics.
        getName: *const fn (ptr: *anyopaque) []const u8,

        /// Clean up resources.
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn chatWithSystem(
        self: Provider,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) ![]const u8 {
        return self.vtable.chatWithSystem(self.ptr, allocator, system_prompt, message, model, temperature);
    }

    pub fn chat(
        self: Provider,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) !ChatResponse {
        return self.vtable.chat(self.ptr, allocator, request, model, temperature);
    }

    pub fn supportsNativeTools(self: Provider) bool {
        return self.vtable.supportsNativeTools(self.ptr);
    }

    pub fn getName(self: Provider) []const u8 {
        return self.vtable.getName(self.ptr);
    }

    pub fn deinit(self: Provider) void {
        return self.vtable.deinit(self.ptr);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Secret Scrubbing
// ════════════════════════════════════════════════════════════════════════════

const MAX_API_ERROR_CHARS: usize = 200;

fn isSecretChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == ':';
}

fn tokenEnd(input: []const u8, from: usize) usize {
    var end = from;
    for (input[from..]) |c| {
        if (isSecretChar(c)) {
            end += 1;
        } else {
            break;
        }
    }
    return end;
}

/// Scrub known secret-like token prefixes from provider error strings.
/// Redacts tokens with prefixes like `sk-`, `xoxb-`, and `xoxp-`.
pub fn scrubSecretPatterns(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const prefixes = [_][]const u8{ "sk-", "xoxb-", "xoxp-" };
    const redacted = "[REDACTED]";

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        var matched = false;
        for (prefixes) |prefix| {
            if (i + prefix.len <= input.len and std.mem.eql(u8, input[i..][0..prefix.len], prefix)) {
                const content_start = i + prefix.len;
                const end = tokenEnd(input, content_start);
                if (end > content_start) {
                    // Real token found — redact
                    try result.appendSlice(allocator, redacted);
                    i = end;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Sanitize API error text by scrubbing secrets and truncating length.
pub fn sanitizeApiError(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const scrubbed = try scrubSecretPatterns(allocator, input);

    if (scrubbed.len <= MAX_API_ERROR_CHARS) {
        return scrubbed;
    }

    // Truncate
    var truncated = try allocator.alloc(u8, MAX_API_ERROR_CHARS + 3);
    @memcpy(truncated[0..MAX_API_ERROR_CHARS], scrubbed[0..MAX_API_ERROR_CHARS]);
    @memcpy(truncated[MAX_API_ERROR_CHARS..][0..3], "...");
    allocator.free(scrubbed);
    return truncated;
}

// ════════════════════════════════════════════════════════════════════════════
// API Key Resolution
// ════════════════════════════════════════════════════════════════════════════

/// Resolve API key for a provider from config and environment variables.
///
/// Resolution order:
/// 1. Explicitly provided `api_key` parameter (trimmed, filtered if empty)
/// 2. Provider-specific environment variable
/// 3. Generic fallback variables (`NULLCLAW_API_KEY`, `API_KEY`)
pub fn resolveApiKey(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
) !?[]u8 {
    // 1. Explicit key
    if (api_key) |key| {
        const trimmed = std.mem.trim(u8, key, " \t\r\n");
        if (trimmed.len > 0) {
            return try allocator.dupe(u8, trimmed);
        }
    }

    // 2. Provider-specific env vars
    const env_candidates = providerEnvCandidates(provider_name);
    for (env_candidates) |env_var| {
        if (env_var.len == 0) break;
        if (std.process.getEnvVarOwned(allocator, env_var)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                if (trimmed.ptr != value.ptr or trimmed.len != value.len) {
                    const duped = try allocator.dupe(u8, trimmed);
                    allocator.free(value);
                    return duped;
                }
                return value;
            }
            allocator.free(value);
        } else |_| {}
    }

    // 3. Generic fallbacks
    const fallbacks = [_][]const u8{ "NULLCLAW_API_KEY", "API_KEY" };
    for (fallbacks) |env_var| {
        if (std.process.getEnvVarOwned(allocator, env_var)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                if (trimmed.ptr != value.ptr or trimmed.len != value.len) {
                    const duped = try allocator.dupe(u8, trimmed);
                    allocator.free(value);
                    return duped;
                }
                return value;
            }
            allocator.free(value);
        } else |_| {}
    }

    return null;
}

fn providerEnvCandidates(name: []const u8) [3][]const u8 {
    if (std.mem.eql(u8, name, "anthropic")) return .{ "ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "" };
    if (std.mem.eql(u8, name, "openrouter")) return .{ "OPENROUTER_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "openai")) return .{ "OPENAI_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "gemini") or std.mem.eql(u8, name, "google") or std.mem.eql(u8, name, "google-gemini")) return .{ "GEMINI_API_KEY", "GOOGLE_API_KEY", "" };
    if (std.mem.eql(u8, name, "groq")) return .{ "GROQ_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "mistral")) return .{ "MISTRAL_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "deepseek")) return .{ "DEEPSEEK_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "xai") or std.mem.eql(u8, name, "grok")) return .{ "XAI_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "together") or std.mem.eql(u8, name, "together-ai")) return .{ "TOGETHER_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "fireworks") or std.mem.eql(u8, name, "fireworks-ai")) return .{ "FIREWORKS_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "perplexity")) return .{ "PERPLEXITY_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "cohere")) return .{ "COHERE_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "venice")) return .{ "VENICE_API_KEY", "", "" };
    if (std.mem.eql(u8, name, "moonshot") or std.mem.eql(u8, name, "kimi")) return .{ "MOONSHOT_API_KEY", "", "" };
    return .{ "", "", "" };
}

// ════════════════════════════════════════════════════════════════════════════
// Provider Factory
// ════════════════════════════════════════════════════════════════════════════

pub const ProviderKind = enum {
    anthropic_provider,
    openai_provider,
    openrouter_provider,
    ollama_provider,
    gemini_provider,
    compatible_provider,
    unknown,
};

/// Determine which provider to create from a name string.
pub fn classifyProvider(name: []const u8) ProviderKind {
    if (std.mem.eql(u8, name, "anthropic")) return .anthropic_provider;
    if (std.mem.eql(u8, name, "openai")) return .openai_provider;
    if (std.mem.eql(u8, name, "openrouter")) return .openrouter_provider;
    if (std.mem.eql(u8, name, "ollama")) return .ollama_provider;
    if (std.mem.eql(u8, name, "gemini") or std.mem.eql(u8, name, "google") or std.mem.eql(u8, name, "google-gemini")) return .gemini_provider;

    // OpenAI-compatible providers
    const compat_names = [_][]const u8{
        "venice",        "vercel",         "vercel-ai",      "cloudflare",
        "cloudflare-ai", "moonshot",       "kimi",           "synthetic",
        "opencode",      "opencode-zen",   "zai",            "z.ai",
        "glm",           "zhipu",          "minimax",        "bedrock",
        "aws-bedrock",   "qianfan",        "baidu",          "qwen",
        "dashscope",     "qwen-intl",      "dashscope-intl", "qwen-us",
        "dashscope-us",  "groq",           "mistral",        "xai",
        "grok",          "deepseek",       "together",       "together-ai",
        "fireworks",     "fireworks-ai",   "perplexity",     "cohere",
        "copilot",       "github-copilot",
    };

    for (compat_names) |cn| {
        if (std.mem.eql(u8, name, cn)) return .compatible_provider;
    }

    // custom: prefix
    if (std.mem.startsWith(u8, name, "custom:")) return .compatible_provider;

    return .unknown;
}

/// Get the base URL for an OpenAI-compatible provider by name.
pub fn compatibleProviderUrl(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "venice")) return "https://api.venice.ai";
    if (std.mem.eql(u8, name, "vercel") or std.mem.eql(u8, name, "vercel-ai")) return "https://api.vercel.ai";
    if (std.mem.eql(u8, name, "cloudflare") or std.mem.eql(u8, name, "cloudflare-ai")) return "https://gateway.ai.cloudflare.com/v1";
    if (std.mem.eql(u8, name, "moonshot") or std.mem.eql(u8, name, "kimi")) return "https://api.moonshot.cn";
    if (std.mem.eql(u8, name, "synthetic")) return "https://api.synthetic.com";
    if (std.mem.eql(u8, name, "opencode") or std.mem.eql(u8, name, "opencode-zen")) return "https://api.opencode.ai";
    if (std.mem.eql(u8, name, "zai") or std.mem.eql(u8, name, "z.ai")) return "https://api.z.ai/api/coding/paas/v4";
    if (std.mem.eql(u8, name, "glm") or std.mem.eql(u8, name, "zhipu")) return "https://api.z.ai/api/paas/v4";
    if (std.mem.eql(u8, name, "minimax")) return "https://api.minimaxi.com/v1";
    if (std.mem.eql(u8, name, "bedrock") or std.mem.eql(u8, name, "aws-bedrock")) return "https://bedrock-runtime.us-east-1.amazonaws.com";
    if (std.mem.eql(u8, name, "qianfan") or std.mem.eql(u8, name, "baidu")) return "https://aip.baidubce.com";
    if (std.mem.eql(u8, name, "qwen") or std.mem.eql(u8, name, "dashscope")) return "https://dashscope.aliyuncs.com/compatible-mode/v1";
    if (std.mem.eql(u8, name, "qwen-intl") or std.mem.eql(u8, name, "dashscope-intl")) return "https://dashscope-intl.aliyuncs.com/compatible-mode/v1";
    if (std.mem.eql(u8, name, "qwen-us") or std.mem.eql(u8, name, "dashscope-us")) return "https://dashscope-us.aliyuncs.com/compatible-mode/v1";
    if (std.mem.eql(u8, name, "groq")) return "https://api.groq.com/openai";
    if (std.mem.eql(u8, name, "mistral")) return "https://api.mistral.ai";
    if (std.mem.eql(u8, name, "xai") or std.mem.eql(u8, name, "grok")) return "https://api.x.ai";
    if (std.mem.eql(u8, name, "deepseek")) return "https://api.deepseek.com";
    if (std.mem.eql(u8, name, "together") or std.mem.eql(u8, name, "together-ai")) return "https://api.together.xyz";
    if (std.mem.eql(u8, name, "fireworks") or std.mem.eql(u8, name, "fireworks-ai")) return "https://api.fireworks.ai/inference/v1";
    if (std.mem.eql(u8, name, "perplexity")) return "https://api.perplexity.ai";
    if (std.mem.eql(u8, name, "cohere")) return "https://api.cohere.com/compatibility";
    if (std.mem.eql(u8, name, "copilot") or std.mem.eql(u8, name, "github-copilot")) return "https://api.githubcopilot.com";
    return null;
}

/// Get the display name for an OpenAI-compatible provider.
pub fn compatibleProviderDisplayName(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "venice")) return "Venice";
    if (std.mem.eql(u8, name, "vercel") or std.mem.eql(u8, name, "vercel-ai")) return "Vercel AI Gateway";
    if (std.mem.eql(u8, name, "cloudflare") or std.mem.eql(u8, name, "cloudflare-ai")) return "Cloudflare AI Gateway";
    if (std.mem.eql(u8, name, "moonshot") or std.mem.eql(u8, name, "kimi")) return "Moonshot";
    if (std.mem.eql(u8, name, "synthetic")) return "Synthetic";
    if (std.mem.eql(u8, name, "opencode") or std.mem.eql(u8, name, "opencode-zen")) return "OpenCode Zen";
    if (std.mem.eql(u8, name, "zai") or std.mem.eql(u8, name, "z.ai")) return "Z.AI";
    if (std.mem.eql(u8, name, "glm") or std.mem.eql(u8, name, "zhipu")) return "GLM";
    if (std.mem.eql(u8, name, "minimax")) return "MiniMax";
    if (std.mem.eql(u8, name, "bedrock") or std.mem.eql(u8, name, "aws-bedrock")) return "Amazon Bedrock";
    if (std.mem.eql(u8, name, "qianfan") or std.mem.eql(u8, name, "baidu")) return "Qianfan";
    if (std.mem.eql(u8, name, "qwen") or std.mem.eql(u8, name, "dashscope") or
        std.mem.eql(u8, name, "qwen-intl") or std.mem.eql(u8, name, "dashscope-intl") or
        std.mem.eql(u8, name, "qwen-us") or std.mem.eql(u8, name, "dashscope-us")) return "Qwen";
    if (std.mem.eql(u8, name, "groq")) return "Groq";
    if (std.mem.eql(u8, name, "mistral")) return "Mistral";
    if (std.mem.eql(u8, name, "xai") or std.mem.eql(u8, name, "grok")) return "xAI";
    if (std.mem.eql(u8, name, "deepseek")) return "DeepSeek";
    if (std.mem.eql(u8, name, "together") or std.mem.eql(u8, name, "together-ai")) return "Together AI";
    if (std.mem.eql(u8, name, "fireworks") or std.mem.eql(u8, name, "fireworks-ai")) return "Fireworks AI";
    if (std.mem.eql(u8, name, "perplexity")) return "Perplexity";
    if (std.mem.eql(u8, name, "cohere")) return "Cohere";
    if (std.mem.eql(u8, name, "copilot") or std.mem.eql(u8, name, "github-copilot")) return "GitHub Copilot";
    return "Custom";
}

// ════════════════════════════════════════════════════════════════════════════
// High-level complete function (legacy compatibility)
// ════════════════════════════════════════════════════════════════════════════

/// High-level complete function that routes to the right provider via HTTP.
/// Used by agent.zig for backward compatibility.
pub fn complete(allocator: std.mem.Allocator, cfg: anytype, prompt: []const u8) ![]const u8 {
    const api_key = cfg.api_key orelse return error.NoApiKey;
    const url = providerUrl(cfg.default_provider);
    const model = cfg.default_model orelse "anthropic/claude-sonnet-4-5-20250929";
    const body_str = try buildRequestBody(allocator, model, prompt, cfg.temperature, cfg.max_tokens);
    defer allocator.free(body_str);

    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
    defer allocator.free(auth_header);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    var req = try client.request(.POST, uri, .{
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = .{ .override = auth_header },
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();

    const body_buf = try allocator.dupe(u8, body_str);
    defer allocator.free(body_buf);
    try req.sendBodyComplete(body_buf);

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok) {
        return error.ProviderError;
    }

    var transfer_buf: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    const response_body = try reader.readAlloc(allocator, 1024 * 1024);
    defer allocator.free(response_body);

    return try extractContent(allocator, response_body);
}

/// Provider URL mapping for the legacy complete() function.
pub fn providerUrl(provider_name: []const u8) []const u8 {
    if (std.mem.eql(u8, provider_name, "anthropic")) {
        return "https://api.anthropic.com/v1/messages";
    } else if (std.mem.eql(u8, provider_name, "openai")) {
        return "https://api.openai.com/v1/chat/completions";
    } else if (std.mem.eql(u8, provider_name, "ollama")) {
        return "http://localhost:11434/api/chat";
    } else if (std.mem.eql(u8, provider_name, "gemini") or std.mem.eql(u8, provider_name, "google")) {
        return "https://generativelanguage.googleapis.com/v1beta";
    } else {
        return "https://openrouter.ai/api/v1/chat/completions";
    }
}

/// Build a JSON request body for the legacy complete() function.
pub fn buildRequestBody(allocator: std.mem.Allocator, model: []const u8, prompt: []const u8, temperature: f64, max_tokens: u32) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"model":"{s}","messages":[{{"role":"user","content":"{s}"}}],"temperature":{d:.1},"max_tokens":{d}}}
    , .{ model, prompt, temperature, max_tokens });
}

/// Extract text content from a provider JSON response.
pub fn extractContent(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const root_obj = parsed.value.object;

    // OpenAI/OpenRouter format: choices[0].message.content
    if (root_obj.get("choices")) |choices| {
        if (choices.array.items.len > 0) {
            if (choices.array.items[0].object.get("message")) |msg| {
                if (msg.object.get("content")) |content| {
                    if (content == .string) return try allocator.dupe(u8, content.string);
                }
            }
        }
    }

    // Anthropic format: content[0].text
    if (root_obj.get("content")) |content| {
        if (content.array.items.len > 0) {
            if (content.array.items[0].object.get("text")) |text| {
                if (text == .string) return try allocator.dupe(u8, text.string);
            }
        }
    }

    return error.UnexpectedResponse;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "Role.toSlice returns correct strings" {
    try std.testing.expectEqualStrings("system", Role.system.toSlice());
    try std.testing.expectEqualStrings("user", Role.user.toSlice());
    try std.testing.expectEqualStrings("assistant", Role.assistant.toSlice());
    try std.testing.expectEqualStrings("tool", Role.tool.toSlice());
}

test "Role.fromSlice parses correctly" {
    try std.testing.expect(Role.fromSlice("system").? == .system);
    try std.testing.expect(Role.fromSlice("user").? == .user);
    try std.testing.expect(Role.fromSlice("assistant").? == .assistant);
    try std.testing.expect(Role.fromSlice("tool").? == .tool);
    try std.testing.expect(Role.fromSlice("unknown") == null);
}

test "ChatMessage constructors" {
    const sys = ChatMessage.system("Be helpful");
    try std.testing.expect(sys.role == .system);
    try std.testing.expectEqualStrings("Be helpful", sys.content);

    const usr = ChatMessage.user("Hello");
    try std.testing.expect(usr.role == .user);

    const asst = ChatMessage.assistant("Hi there");
    try std.testing.expect(asst.role == .assistant);

    const tool_msg = ChatMessage.toolMsg("{}", "call_123");
    try std.testing.expect(tool_msg.role == .tool);
    try std.testing.expectEqualStrings("call_123", tool_msg.tool_call_id.?);
}

test "ChatResponse helpers" {
    const empty = ChatResponse{};
    try std.testing.expect(!empty.hasToolCalls());
    try std.testing.expectEqualStrings("", empty.contentOrEmpty());

    const calls = [_]ToolCall{.{ .id = "1", .name = "shell", .arguments = "{}" }};
    const with_tools = ChatResponse{
        .content = "Let me check",
        .tool_calls = &calls,
    };
    try std.testing.expect(with_tools.hasToolCalls());
    try std.testing.expectEqualStrings("Let me check", with_tools.contentOrEmpty());
}

test "providerUrl returns correct URLs" {
    try std.testing.expectEqualStrings(
        "https://api.anthropic.com/v1/messages",
        providerUrl("anthropic"),
    );
    try std.testing.expectEqualStrings(
        "https://api.openai.com/v1/chat/completions",
        providerUrl("openai"),
    );
    try std.testing.expectEqualStrings(
        "https://openrouter.ai/api/v1/chat/completions",
        providerUrl("openrouter"),
    );
    try std.testing.expectEqualStrings(
        "http://localhost:11434/api/chat",
        providerUrl("ollama"),
    );
}

test "classifyProvider identifies known providers" {
    try std.testing.expect(classifyProvider("anthropic") == .anthropic_provider);
    try std.testing.expect(classifyProvider("openai") == .openai_provider);
    try std.testing.expect(classifyProvider("openrouter") == .openrouter_provider);
    try std.testing.expect(classifyProvider("ollama") == .ollama_provider);
    try std.testing.expect(classifyProvider("gemini") == .gemini_provider);
    try std.testing.expect(classifyProvider("google") == .gemini_provider);
    try std.testing.expect(classifyProvider("groq") == .compatible_provider);
    try std.testing.expect(classifyProvider("mistral") == .compatible_provider);
    try std.testing.expect(classifyProvider("deepseek") == .compatible_provider);
    try std.testing.expect(classifyProvider("venice") == .compatible_provider);
    try std.testing.expect(classifyProvider("custom:https://example.com") == .compatible_provider);
    try std.testing.expect(classifyProvider("nonexistent") == .unknown);
}

test "compatibleProviderUrl returns correct URLs" {
    try std.testing.expectEqualStrings("https://api.venice.ai", compatibleProviderUrl("venice").?);
    try std.testing.expectEqualStrings("https://api.groq.com/openai", compatibleProviderUrl("groq").?);
    try std.testing.expectEqualStrings("https://api.deepseek.com", compatibleProviderUrl("deepseek").?);
    try std.testing.expect(compatibleProviderUrl("nonexistent") == null);
}

test "scrubSecretPatterns redacts sk- tokens" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "request failed: sk-1234567890abcdef");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-1234567890abcdef") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns handles multiple prefixes" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "keys sk-abcdef xoxb-12345 xoxp-67890");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-abcdef") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xoxb-12345") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xoxp-67890") == null);
}

test "scrubSecretPatterns keeps bare prefix" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "only prefix sk- present");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-") != null);
}

test "sanitizeApiError truncates long errors" {
    const allocator = std.testing.allocator;
    const long = try allocator.alloc(u8, 400);
    defer allocator.free(long);
    @memset(long, 'a');
    const result = try sanitizeApiError(allocator, long);
    defer allocator.free(result);
    try std.testing.expect(result.len <= MAX_API_ERROR_CHARS + 3);
    try std.testing.expect(std.mem.endsWith(u8, result, "..."));
}

test "sanitizeApiError no secret no change" {
    const allocator = std.testing.allocator;
    const result = try sanitizeApiError(allocator, "simple upstream timeout");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("simple upstream timeout", result);
}

test "extractContent parses OpenAI format" {
    const allocator = std.testing.allocator;
    const body =
        \\{"choices":[{"message":{"content":"Hello there!"}}]}
    ;
    const result = try extractContent(allocator, body);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello there!", result);
}

test "extractContent parses Anthropic format" {
    const allocator = std.testing.allocator;
    const body =
        \\{"content":[{"type":"text","text":"Hello from Claude"}]}
    ;
    const result = try extractContent(allocator, body);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Claude", result);
}

test {
    // Run tests from all sub-modules
    std.testing.refAllDecls(@This());
}
