const std = @import("std");
const json_util = @import("../json_util.zig");
const http_util = @import("../http_util.zig");

// Re-export all provider sub-modules
pub const anthropic = @import("anthropic.zig");
pub const openai = @import("openai.zig");
pub const ollama = @import("ollama.zig");
pub const gemini = @import("gemini.zig");
pub const openrouter = @import("openrouter.zig");
pub const compatible = @import("compatible.zig");
pub const reliable = @import("reliable.zig");
pub const router = @import("router.zig");
pub const sse = @import("sse.zig");
pub const claude_cli = @import("claude_cli.zig");
pub const codex_cli = @import("codex_cli.zig");
pub const openai_codex = @import("openai_codex.zig");

// Extracted sub-modules
pub const scrub = @import("scrub.zig");
pub const api_key = @import("api_key.zig");
pub const factory = @import("factory.zig");
pub const helpers = @import("helpers.zig");

// Re-exports from scrub.zig
pub const scrubSecretPatterns = scrub.scrubSecretPatterns;
pub const scrubToolOutput = scrub.scrubToolOutput;
pub const sanitizeApiError = scrub.sanitizeApiError;

// Re-exports from api_key.zig
pub const resolveApiKey = api_key.resolveApiKey;
pub const resolveApiKeyFromConfig = api_key.resolveApiKeyFromConfig;

// Re-exports from factory.zig
pub const ProviderKind = factory.ProviderKind;
pub const classifyProvider = factory.classifyProvider;
pub const detectProviderByApiKey = factory.detectProviderByApiKey;
pub const compatibleProviderUrl = factory.compatibleProviderUrl;
pub const compatibleProviderDisplayName = factory.compatibleProviderDisplayName;
pub const ProviderHolder = factory.ProviderHolder;

// Re-exports from helpers.zig
pub const complete = helpers.complete;
pub const completeWithSystem = helpers.completeWithSystem;
pub const providerUrl = helpers.providerUrl;
pub const buildRequestBody = helpers.buildRequestBody;
pub const buildRequestBodyWithSystem = helpers.buildRequestBodyWithSystem;
pub const isReasoningModel = helpers.isReasoningModel;
pub const appendGenerationFields = helpers.appendGenerationFields;
pub const convertToolsOpenAI = helpers.convertToolsOpenAI;
pub const serializeMessageContent = helpers.serializeMessageContent;
pub const convertToolsAnthropic = helpers.convertToolsAnthropic;
pub const curlPostTimed = helpers.curlPostTimed;
pub const extractContent = helpers.extractContent;

// Direct re-exports from utility modules
pub const appendJsonString = json_util.appendJsonString;
pub const curlPost = http_util.curlPost;

// ════════════════════════════════════════════════════════════════════════════
// Core Types
// ════════════════════════════════════════════════════════════════════════════

/// Level of detail for image processing.
pub const ImageDetail = enum {
    auto,
    low,
    high,

    pub fn toSlice(self: ImageDetail) []const u8 {
        return switch (self) {
            .auto => "auto",
            .low => "low",
            .high => "high",
        };
    }
};

/// A single content part in a multimodal message.
pub const ContentPart = union(enum) {
    text: []const u8,
    image_url: ImageUrl,
    image_base64: ImageBase64,

    pub const ImageUrl = struct {
        url: []const u8,
        detail: ImageDetail = .auto,
    };

    pub const ImageBase64 = struct {
        data: []const u8,
        media_type: []const u8,
    };
};

/// Create a text content part.
pub fn makeTextPart(text: []const u8) ContentPart {
    return .{ .text = text };
}

/// Create an image URL content part.
pub fn makeImageUrlPart(url: []const u8) ContentPart {
    return .{ .image_url = .{ .url = url } };
}

/// Create a base64-encoded image content part.
pub fn makeBase64ImagePart(data: []const u8, media_type: []const u8) ContentPart {
    return .{ .image_base64 = .{ .data = data, .media_type = media_type } };
}

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
        const map = std.StaticStringMap(Role).initComptime(.{
            .{ "system", .system },
            .{ "user", .user },
            .{ "assistant", .assistant },
            .{ "tool", .tool },
        });
        return map.get(s);
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
    /// Optional multimodal content parts (images, etc.). When set, providers
    /// serialize these instead of the plain `content` field.
    content_parts: ?[]const ContentPart = null,

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
    /// Optional reasoning/thinking content from models that support it (e.g. Claude extended thinking).
    reasoning_content: ?[]const u8 = null,

    /// True when the LLM wants to invoke at least one tool.
    pub fn hasToolCalls(self: ChatResponse) bool {
        return self.tool_calls.len > 0;
    }

    /// Convenience: return text content or empty string.
    pub fn contentOrEmpty(self: ChatResponse) []const u8 {
        return self.content orelse "";
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Streaming Types
// ════════════════════════════════════════════════════════════════════════════

/// A single chunk of streamed output.
pub const StreamChunk = struct {
    delta: []const u8,
    is_final: bool,
    token_count: u32,

    /// Create a text delta chunk with estimated token count.
    pub fn textDelta(text: []const u8) StreamChunk {
        return .{
            .delta = text,
            .is_final = false,
            .token_count = @intCast((text.len + 3) / 4),
        };
    }

    /// Create a final (end-of-stream) chunk.
    pub fn finalChunk() StreamChunk {
        return .{
            .delta = "",
            .is_final = true,
            .token_count = 0,
        };
    }
};

/// Callback invoked for each streaming chunk.
pub const StreamCallback = *const fn (ctx: *anyopaque, chunk: StreamChunk) void;

/// Result of a streaming chat call (accumulated after stream completes).
pub const StreamChatResult = struct {
    content: ?[]const u8 = null,
    usage: TokenUsage = .{},
    model: []const u8 = "",
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
    max_tokens: ?u32 = null,
    tools: ?[]const ToolSpec = null,
    /// Max seconds to wait for the HTTP response (curl --max-time). 0 = no limit.
    timeout_secs: u64 = 0,
    /// Reasoning effort for reasoning models (o1, o3, gpt-5*). null = don't send.
    reasoning_effort: ?[]const u8 = null,
};

/// A single tool result message in a conversation.
pub const ToolResultMessage = struct {
    tool_call_id: []const u8,
    content: []const u8,
};

/// Kind discriminator for ConversationMessage.
pub const ConversationMessageKind = enum { chat, assistant_tool_calls, tool_results };

/// A conversation message that can be a plain chat, assistant tool calls, or tool results.
pub const ConversationMessage = union(ConversationMessageKind) {
    chat: ChatMessage,
    assistant_tool_calls: struct {
        text: []const u8,
        tool_calls: []const ToolCall,
    },
    tool_results: []const ToolResultMessage,
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

        /// Optional: pre-warm connection. Default: no-op.
        warmup: ?*const fn (ptr: *anyopaque) void = null,
        /// Optional: native function calling. Default: delegates to chat().
        chat_with_tools: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator, req: ChatRequest) anyerror!ChatResponse = null,
        /// Optional: returns true if provider supports streaming. Default: false.
        supports_streaming: ?*const fn (ptr: *anyopaque) bool = null,
        /// Optional: returns true if provider supports vision/image input. Default: false.
        supports_vision: ?*const fn (ptr: *anyopaque) bool = null,
        /// Optional: returns true if provider supports vision for a specific model.
        /// Default: falls back to supports_vision.
        supports_vision_for_model: ?*const fn (ptr: *anyopaque, model: []const u8) bool = null,
        /// Optional: streaming chat. Default: null (falls back to chat() with single chunk).
        stream_chat: ?*const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: ChatRequest,
            model: []const u8,
            temperature: f64,
            callback: StreamCallback,
            callback_ctx: *anyopaque,
        ) anyerror!StreamChatResult = null,
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

    /// Warm up the provider connection. No-op if not implemented.
    pub fn warmup(self: Provider) void {
        if (self.vtable.warmup) |f| f(self.ptr);
    }

    /// Returns true if provider supports streaming.
    pub fn supportsStreaming(self: Provider) bool {
        if (self.vtable.supports_streaming) |f| return f(self.ptr);
        return false;
    }

    /// Returns true if provider supports vision/image input.
    pub fn supportsVision(self: Provider) bool {
        if (self.vtable.supports_vision) |f| return f(self.ptr);
        return false;
    }

    /// Returns true if provider supports vision/image input for a specific model.
    pub fn supportsVisionForModel(self: Provider, model: []const u8) bool {
        if (self.vtable.supports_vision_for_model) |f| return f(self.ptr, model);
        return self.supportsVision();
    }

    /// Chat with native tool support. Falls back to regular chat() if not implemented.
    pub fn chatWithTools(self: Provider, allocator: std.mem.Allocator, req: ChatRequest) !ChatResponse {
        if (self.vtable.chat_with_tools) |f| return f(self.ptr, allocator, req);
        return self.chat(allocator, req, req.model, req.temperature);
    }

    /// Streaming chat. If vtable slot is null, falls back to chat() and emits a single chunk + final.
    pub fn streamChat(
        self: Provider,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: StreamCallback,
        callback_ctx: *anyopaque,
    ) !StreamChatResult {
        if (self.vtable.stream_chat) |f| {
            return f(self.ptr, allocator, request, model, temperature, callback, callback_ctx);
        }
        // Fallback: blocking chat() → single chunk + final
        const response = try self.chat(allocator, request, model, temperature);
        if (response.content) |content| {
            if (content.len > 0) {
                callback(callback_ctx, StreamChunk.textDelta(content));
            }
        }
        callback(callback_ctx, StreamChunk.finalChunk());
        return .{
            .content = response.content,
            .usage = response.usage,
            .model = response.model,
        };
    }
};

/// Comptime check that a type correctly implements the Provider interface.
pub fn assertProviderInterface(comptime T: type) void {
    if (!@hasDecl(T, "provider")) @compileError(@typeName(T) ++ " missing provider() method");
    if (!@hasDecl(T, "vtable")) @compileError(@typeName(T) ++ " missing vtable constant");
    const vt = T.vtable;
    _ = vt.chatWithSystem;
    _ = vt.chat;
    _ = vt.supportsNativeTools;
    _ = vt.supports_vision;
    _ = vt.getName;
    _ = vt.deinit;
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

test "ConversationMessage union variants" {
    const chat_msg: ConversationMessage = .{ .chat = ChatMessage.user("hi") };
    try std.testing.expect(chat_msg == .chat);
    try std.testing.expect(chat_msg.chat.role == .user);

    const calls = [_]ToolCall{.{ .id = "1", .name = "shell", .arguments = "{}" }};
    const tc_msg: ConversationMessage = .{ .assistant_tool_calls = .{
        .text = "calling shell",
        .tool_calls = &calls,
    } };
    try std.testing.expect(tc_msg == .assistant_tool_calls);
    try std.testing.expectEqualStrings("calling shell", tc_msg.assistant_tool_calls.text);

    const results = [_]ToolResultMessage{.{ .tool_call_id = "1", .content = "ok" }};
    const tr_msg: ConversationMessage = .{ .tool_results = &results };
    try std.testing.expect(tr_msg == .tool_results);
    try std.testing.expect(tr_msg.tool_results.len == 1);
}

test "provider warmup no-op when vtable warmup is null" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
        // warmup, chat_with_tools, supports_streaming all default to null
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    // Should not crash
    provider.warmup();
}

test "provider supportsStreaming returns false when vtable is null" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    try std.testing.expect(!provider.supportsStreaming());
}

test "provider supportsVision returns false when vtable supports_vision is null" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    try std.testing.expect(!provider.supportsVision());
}

test "provider supportsVision delegates when supports_vision is set" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn supVision(_: *anyopaque) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .supports_vision = DummyProvider.supVision,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    try std.testing.expect(provider.supportsVision());
}

test "provider supportsVisionForModel falls back to supportsVision" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn supVision(_: *anyopaque) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .supports_vision = DummyProvider.supVision,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    try std.testing.expect(provider.supportsVisionForModel("any-model"));
}

test "provider supportsVisionForModel delegates when model hook is set" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{};
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn supVision(_: *anyopaque) bool {
            return true;
        }
        fn supVisionForModel(_: *anyopaque, model: []const u8) bool {
            return std.mem.eql(u8, model, "vision-model");
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .supports_vision = DummyProvider.supVision,
        .supports_vision_for_model = DummyProvider.supVisionForModel,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    try std.testing.expect(provider.supportsVisionForModel("vision-model"));
    try std.testing.expect(!provider.supportsVisionForModel("text-model"));
}

test "provider chatWithTools falls back to chat when vtable is null" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{ .content = "fallback response", .model = "test-model" };
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    const msgs = [_]ChatMessage{ChatMessage.user("test")};
    const req = ChatRequest{ .messages = &msgs, .model = "test-model" };
    const resp = try provider.chatWithTools(std.testing.allocator, req);
    try std.testing.expectEqualStrings("fallback response", resp.content.?);
    try std.testing.expectEqualStrings("test-model", resp.model);
}

test "ChatResponse reasoning_content defaults to null" {
    const resp = ChatResponse{};
    try std.testing.expect(resp.reasoning_content == null);
}

test "ChatResponse reasoning_content can be set" {
    const resp = ChatResponse{ .reasoning_content = "Let me think..." };
    try std.testing.expectEqualStrings("Let me think...", resp.reasoning_content.?);
}

test "StreamChatResult defaults" {
    const result = StreamChatResult{};
    try std.testing.expect(result.content == null);
    try std.testing.expect(result.usage.prompt_tokens == 0);
    try std.testing.expect(result.usage.completion_tokens == 0);
    try std.testing.expectEqualStrings("", result.model);
}

test "Provider.streamChat fallback emits single chunk and final" {
    const TestCtx = struct {
        chunks_count: usize = 0,
        got_content: bool = false,
        got_final: bool = false,

        fn onChunk(ctx_ptr: *anyopaque, chunk: StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            self.chunks_count += 1;
            if (!chunk.is_final and chunk.delta.len > 0) self.got_content = true;
            if (chunk.is_final) self.got_final = true;
        }
    };

    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, _: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return "";
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            return .{ .content = "hello from fallback", .model = "test" };
        }
        fn supNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    var dummy: u8 = 0;
    const vtable_val = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const prov = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable_val };

    var ctx = TestCtx{};
    const msgs = [_]ChatMessage{ChatMessage.user("test")};
    const req = ChatRequest{ .messages = &msgs, .model = "test" };
    const result = try prov.streamChat(std.testing.allocator, req, "test", 0.7, TestCtx.onChunk, @ptrCast(&ctx));

    try std.testing.expect(ctx.got_content);
    try std.testing.expect(ctx.got_final);
    try std.testing.expect(ctx.chunks_count == 2);
    try std.testing.expectEqualStrings("hello from fallback", result.content.?);
}

test "appendJsonString encodes control chars as \\uXXXX" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    // BEL character (0x07) should be encoded as \u0007
    try json_util.appendJsonString(&buf, allocator, "\x07");
    try std.testing.expectEqualStrings("\"\\u0007\"", buf.items);
}

test "makeTextPart creates text content part" {
    const part = makeTextPart("Hello world");
    try std.testing.expect(part == .text);
    try std.testing.expectEqualStrings("Hello world", part.text);
}

test "makeImageUrlPart creates image_url content part with auto detail" {
    const part = makeImageUrlPart("https://example.com/image.png");
    try std.testing.expect(part == .image_url);
    try std.testing.expectEqualStrings("https://example.com/image.png", part.image_url.url);
    try std.testing.expect(part.image_url.detail == .auto);
}

test "makeBase64ImagePart creates image_base64 content part" {
    const part = makeBase64ImagePart("iVBORw0KGgo=", "image/png");
    try std.testing.expect(part == .image_base64);
    try std.testing.expectEqualStrings("iVBORw0KGgo=", part.image_base64.data);
    try std.testing.expectEqualStrings("image/png", part.image_base64.media_type);
}

test "ImageDetail.toSlice returns correct strings" {
    try std.testing.expectEqualStrings("auto", ImageDetail.auto.toSlice());
    try std.testing.expectEqualStrings("low", ImageDetail.low.toSlice());
    try std.testing.expectEqualStrings("high", ImageDetail.high.toSlice());
}

test "ChatMessage content_parts defaults to null" {
    const msg = ChatMessage.user("hello");
    try std.testing.expect(msg.content_parts == null);
}

test "ChatMessage with content_parts set" {
    const parts = [_]ContentPart{
        makeTextPart("Describe this image"),
        makeImageUrlPart("https://example.com/cat.jpg"),
    };
    const msg = ChatMessage{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    };
    try std.testing.expect(msg.content_parts != null);
    try std.testing.expect(msg.content_parts.?.len == 2);
    try std.testing.expect(msg.content_parts.?[0] == .text);
    try std.testing.expect(msg.content_parts.?[1] == .image_url);
}

test {
    // Run tests from all sub-modules
    std.testing.refAllDecls(@This());
}
