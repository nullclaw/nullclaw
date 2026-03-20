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

const log = std.log.scoped(.compatible);
const MAX_STREAMING_PROMPT_BYTES: usize = 32 * 1024;

fn logCompatibleApiError(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    err: anyerror,
    url: []const u8,
    resp_body: []const u8,
) void {
    const sanitized = root.sanitizeApiError(allocator, resp_body) catch null;
    defer if (sanitized) |body| allocator.free(body);

    const preview = sanitized orelse "<api error body unavailable>";
    log.err("{s} {s}: {s} {s}", .{ provider_name, @errorName(err), url, preview });
}

fn parseStatusCodeValue(value: std.json.Value) ?u16 {
    return switch (value) {
        .integer => |i| blk: {
            if (i < 0 or i > std.math.maxInt(u16)) break :blk null;
            break :blk @intCast(i);
        },
        .string => |s| std.fmt.parseInt(u16, std.mem.trim(u8, s, " \t\r\n"), 10) catch null,
        else => null,
    };
}

fn sliceEqlAsciiFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn containsAsciiFold(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (sliceEqlAsciiFold(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn lookupFallbackStatusCode(root_obj: std.json.ObjectMap) ?u16 {
    if (root_obj.get("error")) |err_value| {
        if (err_value == .object) {
            const err_obj = err_value.object;
            if (err_obj.get("status")) |status| {
                if (parseStatusCodeValue(status)) |code| return code;
            }
            if (err_obj.get("code")) |code_value| {
                if (parseStatusCodeValue(code_value)) |code| return code;
            }
        }
    }

    if (root_obj.get("status")) |status| {
        if (parseStatusCodeValue(status)) |code| return code;
    }
    if (root_obj.get("code")) |code_value| {
        if (parseStatusCodeValue(code_value)) |code| return code;
    }

    return null;
}

fn lookupFallbackMessage(root_obj: std.json.ObjectMap) ?[]const u8 {
    if (root_obj.get("error")) |err_value| {
        if (err_value == .object) {
            const err_obj = err_value.object;
            if (err_obj.get("message")) |message| {
                if (message == .string) return message.string;
            }
        }
    }

    if (root_obj.get("message")) |message| {
        if (message == .string) return message.string;
    }

    return null;
}

fn isResponsesFallbackMessage(message: []const u8) bool {
    const trimmed = std.mem.trim(u8, message, " \t\r\n");
    if (trimmed.len == 0) return false;

    return sliceEqlAsciiFold(trimmed, "not found") or
        sliceEqlAsciiFold(trimmed, "404 not found") or
        containsAsciiFold(trimmed, "unknown endpoint") or
        containsAsciiFold(trimmed, "endpoint not found") or
        containsAsciiFold(trimmed, "/chat/completions");
}

fn shouldFallbackToResponses(allocator: std.mem.Allocator, body: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    if (error_classify.classifyKnownApiError(parsed.value.object)) |kind| {
        if (kind != .other) return false;
    }

    const status = lookupFallbackStatusCode(parsed.value.object) orelse return false;
    if (status != 404) return false;

    const message = lookupFallbackMessage(parsed.value.object) orelse return false;
    return isResponsesFallbackMessage(message);
}

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
    /// Optional owned copy of base_url when the caller had to normalize/build it.
    owned_base_url: ?[]u8 = null,
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
    /// When set, cap max_tokens in non-streaming requests to this value.
    /// Some providers (e.g. Fireworks) reject large max_tokens without streaming.
    max_tokens_non_streaming: ?u32 = null,
    /// When true, include `"thinking":{"type":"enabled"}` in request bodies
    /// when reasoning_effort is set. Required by Z.AI/GLM thinking models.
    thinking_param: bool = false,
    /// When true, include `"enable_thinking":true` in request bodies
    /// when reasoning_effort is set. Required by Qwen (DashScope compatible mode).
    enable_thinking_param: bool = false,
    /// When true, include `"reasoning_split":true` in request bodies
    /// when reasoning_effort is set. Used by MiniMax to separate reasoning output.
    reasoning_split_param: bool = false,
    /// Optional User-Agent header for HTTP requests.
    /// When set, requests will include "User-Agent: {value}" header.
    user_agent: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    const think_open_tag = "<think>";
    const think_close_tag = "</think>";
    const splitThinkContent = root.splitThinkContent;
    const stripThinkBlocks = root.stripThinkBlocks;

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        base_url: []const u8,
        api_key: ?[]const u8,
        auth_style: AuthStyle,
        user_agent: ?[]const u8,
    ) OpenAiCompatibleProvider {
        return .{
            .name = name,
            .base_url = trimTrailingSlash(base_url),
            .api_key = api_key,
            .auth_style = auth_style,
            .user_agent = user_agent,
            .allocator = allocator,
        };
    }

    fn validateUserAgent(user_agent: []const u8) bool {
        // Disallow header injection and malformed values.
        return std.mem.indexOfAny(u8, user_agent, "\r\n") == null;
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

    fn capNonStreamingMaxTokens(self: OpenAiCompatibleProvider, request: ChatRequest) ChatRequest {
        var capped_request = request;
        if (self.max_tokens_non_streaming) |cap| {
            if (capped_request.max_tokens) |mt| {
                if (mt > cap) capped_request.max_tokens = cap;
            }
        }
        return capped_request;
    }

    fn estimateRequestTextBytes(request: ChatRequest) usize {
        var total: usize = 0;
        for (request.messages) |msg| {
            total += msg.content.len;
            if (msg.content_parts) |parts| {
                for (parts) |part| {
                    switch (part) {
                        .text => |t| total += t.len,
                        else => {},
                    }
                }
            }
        }
        return total;
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
                    return stripThinkBlocks(allocator, trimmed);
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
                                            return stripThinkBlocks(allocator, trimmed);
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
                                    return stripThinkBlocks(allocator, trimmed);
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
        timeout_secs: u64,
    ) ![]const u8 {
        const url = try self.responsesUrl(allocator);
        defer allocator.free(url);

        const body = try buildResponsesRequestBody(allocator, system_prompt, message, model);
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], timeout_secs) catch return error.CompatibleApiError;
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

    const ThinkStripStreamCtx = struct {
        downstream: root.StreamCallback,
        downstream_ctx: *anyopaque,
        state: ThinkStripStreamState = .{},
    };

    const ThinkStripStreamState = struct {
        depth: usize = 0,
        pending: [think_close_tag.len]u8 = undefined,
        pending_len: usize = 0,

        fn feed(self: *ThinkStripStreamState, delta: []const u8, downstream: root.StreamCallback, downstream_ctx: *anyopaque) void {
            var out_buf: [256]u8 = undefined;
            var out_len: usize = 0;

            for (delta) |byte| {
                if (self.pending_len == self.pending.len) {
                    self.processPending(false, &out_buf, &out_len, downstream, downstream_ctx);
                }
                self.pending[self.pending_len] = byte;
                self.pending_len += 1;
                self.processPending(false, &out_buf, &out_len, downstream, downstream_ctx);
            }

            if (out_len > 0) {
                downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len]));
            }
        }

        fn finish(self: *ThinkStripStreamState, downstream: root.StreamCallback, downstream_ctx: *anyopaque) void {
            var out_buf: [256]u8 = undefined;
            var out_len: usize = 0;
            self.processPending(true, &out_buf, &out_len, downstream, downstream_ctx);
            if (out_len > 0) {
                downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len]));
            }
        }

        fn processPending(
            self: *ThinkStripStreamState,
            final: bool,
            out_buf: *[256]u8,
            out_len: *usize,
            downstream: root.StreamCallback,
            downstream_ctx: *anyopaque,
        ) void {
            while (self.pending_len > 0) {
                const pending = self.pending[0..self.pending_len];

                if (pending.len >= think_open_tag.len and std.mem.eql(u8, pending[0..think_open_tag.len], think_open_tag)) {
                    self.consumePrefix(think_open_tag.len);
                    self.depth += 1;
                    continue;
                }

                if (pending.len >= think_close_tag.len and std.mem.eql(u8, pending[0..think_close_tag.len], think_close_tag)) {
                    self.consumePrefix(think_close_tag.len);
                    if (self.depth > 0) self.depth -= 1;
                    continue;
                }

                const maybe_tag_prefix = std.mem.startsWith(u8, think_open_tag, pending) or std.mem.startsWith(u8, think_close_tag, pending);
                if (!final and maybe_tag_prefix and pending.len < think_close_tag.len) {
                    break;
                }

                if (self.depth == 0) {
                    out_buf[out_len.*] = pending[0];
                    out_len.* += 1;
                    if (out_len.* == out_buf.len) {
                        downstream(downstream_ctx, root.StreamChunk.textDelta(out_buf[0..out_len.*]));
                        out_len.* = 0;
                    }
                }
                self.consumePrefix(1);
            }
        }

        fn consumePrefix(self: *ThinkStripStreamState, n: usize) void {
            std.debug.assert(n <= self.pending_len);
            if (n == self.pending_len) {
                self.pending_len = 0;
                return;
            }
            const remaining = self.pending_len - n;
            std.mem.copyForwards(u8, self.pending[0..remaining], self.pending[n..self.pending_len]);
            self.pending_len = remaining;
        }
    };

    fn streamThinkSanitizeCallback(ctx_ptr: *anyopaque, chunk: root.StreamChunk) void {
        const ctx: *ThinkStripStreamCtx = @ptrCast(@alignCast(ctx_ptr));
        if (chunk.is_final) {
            ctx.state.finish(ctx.downstream, ctx.downstream_ctx);
            ctx.downstream(ctx.downstream_ctx, root.StreamChunk.finalChunk());
            return;
        }
        ctx.state.feed(chunk.delta, ctx.downstream, ctx.downstream_ctx);
    }

    /// Parse text content from an OpenAI-compatible response.
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
            root.setLastApiErrorDetail("compatible", sanitized orelse summary);
            return mapped_err;
        }

        if (root_obj.get("choices")) |choices| {
            if (choices.array.items.len > 0) {
                if (choices.array.items[0].object.get("message")) |msg| {
                    if (msg.object.get("content")) |content| {
                        if (content == .string) {
                            return stripThinkBlocks(allocator, content.string);
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
            const mapped_err = error_classify.kindToError(kind);
            var summary_buf: [1024]u8 = undefined;
            const summary = error_classify.summarizeKnownApiError(root_obj, &summary_buf) orelse @errorName(mapped_err);
            const sanitized = root.sanitizeApiError(allocator, summary) catch null;
            defer if (sanitized) |s| allocator.free(s);
            root.setLastApiErrorDetail("compatible", sanitized orelse summary);
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
                        const split = try splitThinkContent(allocator, c.string);
                        content = split.visible;
                        reasoning_content = split.reasoning;
                    }
                }
                // Fallback: some providers return reasoning in native fields.
                // - Z.AI/GLM: `reasoning_content`
                // - Groq/Cerebras parsed format: `reasoning`
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
                    .tool_calls = try tool_calls_list.toOwnedSlice(allocator),
                    .usage = usage,
                    .model = model_str,
                    .reasoning_content = reasoning_content,
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
        .supports_vision_for_model = supportsVisionForModelImpl,
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
        const request_text_bytes = estimateRequestTextBytes(request);

        if (request_text_bytes >= MAX_STREAMING_PROMPT_BYTES) {
            log.warn(
                "{s} streaming skipped for large request ({d} bytes >= {d}); using non-streaming",
                .{ self.name, request_text_bytes, MAX_STREAMING_PROMPT_BYTES },
            );
            const fallback = try chatImpl(ptr, allocator, request, model, temperature);
            if (fallback.content) |text| {
                callback(callback_ctx, root.StreamChunk.textDelta(text));
            }
            callback(callback_ctx, root.StreamChunk.finalChunk());
            return .{
                .content = fallback.content,
                .usage = fallback.usage,
                .model = fallback.model,
            };
        }

        const url = try self.chatCompletionsUrl(allocator);
        defer allocator.free(url);

        const body = try buildStreamingChatRequestBody(
            allocator,
            request,
            effective_model,
            temperature,
            self.merge_system_into_user,
            self.thinking_param,
            self.enable_thinking_param,
            self.reasoning_split_param,
        );
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

        // Build extra headers (User-Agent if configured)
        var extra_headers: [1][]const u8 = undefined;
        var extra_header_count: usize = 0;
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            extra_headers[extra_header_count] = user_agent_hdr.?;
            extra_header_count += 1;
        }

        var sanitize_ctx = ThinkStripStreamCtx{
            .downstream = callback,
            .downstream_ctx = callback_ctx,
        };

        var result = sse.curlStream(
            allocator,
            url,
            body,
            auth_hdr,
            extra_headers[0..extra_header_count],
            request.timeout_secs,
            streamThinkSanitizeCallback,
            @ptrCast(&sanitize_ctx),
        ) catch |err| {
            if (err == error.CurlWaitError or err == error.CurlFailed) {
                log.warn("{s} streaming failed with {}; falling back to non-streaming response", .{ self.name, err });
                var fallback = try chatImpl(ptr, allocator, request, model, temperature);
                return root.emitChatResponseAsStream(allocator, &fallback, callback, callback_ctx);
            }
            return err;
        };

        if (result.content) |raw| {
            const cleaned = try stripThinkBlocks(allocator, raw);
            allocator.free(raw);
            if (cleaned.len == 0) {
                result.content = null;
                result.usage.completion_tokens = 0;
            } else {
                result.content = cleaned;
                result.usage.completion_tokens = @intCast((cleaned.len + 3) / 4);
            }
        }

        return result;
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

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], 0) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseTextResponse(allocator, resp_body) catch |err| {
            // Only switch protocols when chat-completions explicitly reports endpoint absence.
            if (self.supports_responses_fallback and shouldFallbackToResponses(allocator, resp_body)) {
                return self.chatViaResponses(allocator, eff_system, merged_msg orelse message, effective_model, 0) catch {
                    logCompatibleApiError(allocator, self.name, err, url, resp_body);
                    return err;
                };
            }
            logCompatibleApiError(allocator, self.name, err, url, resp_body);
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

        const capped_request = self.capNonStreamingMaxTokens(request);
        const body = try buildChatRequestBody(
            allocator,
            capped_request,
            effective_model,
            temperature,
            self.merge_system_into_user,
            self.thinking_param,
            self.enable_thinking_param,
            self.reasoning_split_param,
        );
        defer allocator.free(body);

        const auth = try self.authHeaderValue(allocator);
        defer if (auth) |a| {
            if (a.needs_free) allocator.free(a.value);
        };

        // Build headers (auth + optional User-Agent)
        var headers_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;
        if (auth) |a| {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "{s}: {s}", .{ a.name, a.value }) catch return error.CompatibleApiError;
            headers_buf[header_count] = auth_hdr;
            header_count += 1;
        }
        var user_agent_hdr: ?[]u8 = null;
        defer if (user_agent_hdr) |h| allocator.free(h);
        if (self.user_agent) |ua| {
            if (!validateUserAgent(ua)) return error.CompatibleApiError;
            user_agent_hdr = std.fmt.allocPrint(allocator, "User-Agent: {s}", .{ua}) catch return error.CompatibleApiError;
            headers_buf[header_count] = user_agent_hdr.?;
            header_count += 1;
        }

        const resp_body = root.curlPostTimed(allocator, url, body, headers_buf[0..header_count], request.timeout_secs) catch return error.CompatibleApiError;
        defer allocator.free(resp_body);

        return parseNativeResponse(allocator, resp_body) catch |err| {
            logCompatibleApiError(allocator, self.name, err, url, resp_body);
            return err;
        };
    }

    fn supportsNativeToolsImpl(ptr: *anyopaque) bool {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.native_tools;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn supportsVisionForModelImpl(_: *anyopaque, _: []const u8) bool {
        // Vision capability is managed by Agent's vision_disabled_models.
        // Provider assumes all models support vision by default.
        return true;
    }

    fn getNameImpl(ptr: *anyopaque) []const u8 {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        return self.name;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *OpenAiCompatibleProvider = @ptrCast(@alignCast(ptr));
        if (self.owned_base_url) |owned| {
            self.allocator.free(owned);
            self.owned_base_url = null;
        }
    }
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
    thinking_param: bool,
    enable_thinking_param: bool,
    reasoning_split_param: bool,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const reasoning_enabled = hasCompatReasoningEnabled(request.reasoning_effort);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"enabled\"}");
    }
    if (enable_thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"enable_thinking\":true");
    }
    if (reasoning_split_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"reasoning_split\":true");
    }
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
    thinking_param: bool,
    enable_thinking_param: bool,
    reasoning_split_param: bool,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const reasoning_enabled = hasCompatReasoningEnabled(request.reasoning_effort);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\",\"messages\":[");

    try serializeMessagesInto(&buf, allocator, request.messages, merge_system);

    try buf.append(allocator, ']');
    try root.appendGenerationFields(&buf, allocator, model, temperature, request.max_tokens, request.reasoning_effort);
    if (thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"thinking\":{\"type\":\"enabled\"}");
    }
    if (enable_thinking_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"enable_thinking\":true");
    }
    if (reasoning_split_param and reasoning_enabled) {
        try buf.appendSlice(allocator, ",\"reasoning_split\":true");
    }
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

fn hasCompatReasoningEnabled(reasoning_effort: ?[]const u8) bool {
    const effort = root.normalizeOpenAiReasoningEffort(reasoning_effort) orelse return false;
    return !std.mem.eql(u8, effort, "none");
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "strips trailing slash" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com/", null, .bearer, null);
    try std.testing.expectEqualStrings("https://example.com", p.base_url);
}

test "chatCompletionsUrl standard" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.openai.com/v1", null, .bearer, null);
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
        null,
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

test "parseTextResponse strips think blocks" {
    const body =
        \\{"choices":[{"message":{"content":"<think>private reasoning</think>\nVisible answer"}}]}
    ;
    const result = try OpenAiCompatibleProvider.parseTextResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Visible answer", result);
}

test "parseNativeResponse splits think blocks into content and reasoning_content" {
    const body =
        \\{"choices":[{"message":{"content":"<think>private chain of thought</think>\nVisible answer"}}],"model":"minimax-m2.5"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |content| {
            if (content.len > 0) std.testing.allocator.free(content);
        }
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |reasoning| {
            if (reasoning.len > 0) std.testing.allocator.free(reasoning);
        }
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("private chain of thought", result.reasoning_content.?);
}

test "parseNativeResponse reads native reasoning_content field (Z.AI/GLM style)" {
    const body =
        \\{"choices":[{"message":{"content":"Final answer","reasoning_content":"chain of thought"}}],"model":"glm-4.7-thinking"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Final answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("chain of thought", result.reasoning_content.?);
}

test "parseNativeResponse reads native reasoning field (Groq/Cerebras parsed format)" {
    const body =
        \\{"choices":[{"message":{"content":"Final answer","reasoning":"parsed reasoning trace"}}],"model":"qwen/qwen3-32b"}
    ;
    const result = try OpenAiCompatibleProvider.parseNativeResponse(std.testing.allocator, body);
    defer {
        if (result.content) |c| if (c.len > 0) std.testing.allocator.free(c);
        for (result.tool_calls) |tc| {
            if (tc.id.len > 0) std.testing.allocator.free(tc.id);
            if (tc.name.len > 0) std.testing.allocator.free(tc.name);
            if (tc.arguments.len > 0) std.testing.allocator.free(tc.arguments);
        }
        if (result.tool_calls.len > 0) std.testing.allocator.free(result.tool_calls);
        if (result.model.len > 0) std.testing.allocator.free(result.model);
        if (result.reasoning_content) |rc| if (rc.len > 0) std.testing.allocator.free(rc);
    }
    try std.testing.expect(result.content != null);
    try std.testing.expectEqualStrings("Final answer", result.content.?);
    try std.testing.expect(result.reasoning_content != null);
    try std.testing.expectEqualStrings("parsed reasoning trace", result.reasoning_content.?);
}

test "buildChatRequestBody emits thinking param for GLM when reasoning_effort set" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "glm-4.7-thinking",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "glm-4.7-thinking", 0.7, false, true, false, false);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\":{\"type\":\"enabled\"}") != null);
}

test "buildChatRequestBody omits thinking param when thinking_param false" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "some-model",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "some-model", 0.7, false, false, false, false);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\"") == null);
}

test "buildChatRequestBody emits enable_thinking when configured" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "qwen3-thinking",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "qwen3-thinking", 0.7, false, false, true, false);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") != null);
}

test "buildChatRequestBody emits reasoning_split when configured" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "minimax-m2",
        .reasoning_effort = "high",
    };
    const body = try buildChatRequestBody(allocator, req, "minimax-m2", 0.7, false, false, false, true);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") != null);
}

test "buildChatRequestBody omits provider thinking params when reasoning_effort none" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "glm-4.7-thinking",
        .reasoning_effort = "none",
    };
    const body = try buildChatRequestBody(allocator, req, "glm-4.7-thinking", 0.7, false, true, true, true);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") == null);
}

test "streamThinkSanitizeCallback strips think blocks across chunk boundaries" {
    const Collector = struct {
        allocator: std.mem.Allocator,
        buf: std.ArrayListUnmanaged(u8) = .empty,
        saw_final: bool = false,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.saw_final = true;
                return;
            }
            self.buf.appendSlice(self.allocator, chunk.delta) catch unreachable;
        }

        fn deinit(self: *@This()) void {
            self.buf.deinit(self.allocator);
        }
    };

    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();

    var sanitize_ctx = OpenAiCompatibleProvider.ThinkStripStreamCtx{
        .downstream = Collector.callback,
        .downstream_ctx = @ptrCast(&collector),
    };

    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("<thi"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("nk>private reasoning"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("</think>\nVisible answer"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.finalChunk());

    try std.testing.expect(collector.saw_final);
    try std.testing.expectEqualStrings("\nVisible answer", collector.buf.items);
}

test "streamThinkSanitizeCallback preserves incomplete think tag literals" {
    const Collector = struct {
        allocator: std.mem.Allocator,
        buf: std.ArrayListUnmanaged(u8) = .empty,
        saw_final: bool = false,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.saw_final = true;
                return;
            }
            self.buf.appendSlice(self.allocator, chunk.delta) catch unreachable;
        }

        fn deinit(self: *@This()) void {
            self.buf.deinit(self.allocator);
        }
    };

    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();

    var sanitize_ctx = OpenAiCompatibleProvider.ThinkStripStreamCtx{
        .downstream = Collector.callback,
        .downstream_ctx = @ptrCast(&collector),
    };

    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.textDelta("literal <thi"));
    OpenAiCompatibleProvider.streamThinkSanitizeCallback(@ptrCast(&sanitize_ctx), root.StreamChunk.finalChunk());

    try std.testing.expect(collector.saw_final);
    try std.testing.expectEqualStrings("literal <thi", collector.buf.items);
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
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .bearer, null);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("authorization", auth.name);
    try std.testing.expectEqualStrings("Bearer my-key", auth.value);
}

test "authHeaderValue x-api-key style" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "my-key", .x_api_key, null);
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("x-api-key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
}

test "authHeaderValue no key" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer, null);
    try std.testing.expect(try p.authHeaderValue(std.testing.allocator) == null);
}

test "chatCompletionsUrl trailing slash stripped" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1/", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/chat/completions", url);
}

test "chatCompletionsUrl without v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer, null);
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/chat/completions", url);
}

test "chatCompletionsUrl with v1" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer, null);
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
    const deepseek = OpenAiCompatibleProvider.init(std.testing.allocator, "deepseek", "https://api.deepseek.com", null, .bearer, null);
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-chat", deepseek.normalizeProviderModel("deepseek/deepseek-v3.2"));
    try std.testing.expectEqualStrings("deepseek-reasoner", deepseek.normalizeProviderModel("deepseek-reasoner"));
}

test "normalizeProviderModel leaves other providers unchanged" {
    const openrouter = OpenAiCompatibleProvider.init(std.testing.allocator, "openrouter", "https://openrouter.ai/api/v1", null, .bearer, null);
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
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "Venice", "https://api.venice.ai", "key", .bearer, null);
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
        null,
    );
    const url = try p.chatCompletionsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/v2/llm/chat/completions-proxy/chat/completions", url);
}

test "supportsNativeTools returns true for compatible" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsNativeTools());
}

test "capNonStreamingMaxTokens caps request max_tokens above provider limit" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 8000 };
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "fireworks", "https://api.fireworks.ai/inference/v1", "key", .bearer, null);
    p.max_tokens_non_streaming = 4096;

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 4096), capped.max_tokens);
    try std.testing.expectEqual(@as(?u32, 8000), req.max_tokens);
}

test "capNonStreamingMaxTokens keeps request max_tokens when already below limit" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 1024 };
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "fireworks", "https://api.fireworks.ai/inference/v1", "key", .bearer, null);
    p.max_tokens_non_streaming = 4096;

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 1024), capped.max_tokens);
}

test "capNonStreamingMaxTokens leaves request unchanged when limit is unset" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "test-model", .max_tokens = 8000 };
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "generic", "https://example.com/v1", "key", .bearer, null);

    const capped = p.capNonStreamingMaxTokens(req);
    try std.testing.expectEqual(@as(?u32, 8000), capped.max_tokens);
}

// ════════════════════════════════════════════════════════════════════════════
// Responses API tests
// ════════════════════════════════════════════════════════════════════════════

test "responsesUrl standard base" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com", null, .bearer, null);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/responses", url);
}

test "responsesUrl with v1 no duplicate" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/v1", null, .bearer, null);
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
        null,
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
        null,
    );
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/responses", url);
}

test "responsesUrl non-v1 api path uses raw suffix" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://api.example.com/api/coding/v3", null, .bearer, null);
    const url = try p.responsesUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/api/coding/v3/responses", url);
}

test "shouldFallbackToResponses only for explicit 404 payloads" {
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"Not found\",\"code\":404}}"));
    try std.testing.expect(shouldFallbackToResponses(std.testing.allocator, "{\"status\":404,\"message\":\"unknown endpoint\"}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"No endpoints found that support image input\",\"code\":404}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"model not found\",\"code\":404}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"error\":{\"message\":\"temporary overload\",\"code\":503}}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "{\"choices\":[{\"message\":{\"content\":\"ok\"}}]}"));
    try std.testing.expect(!shouldFallbackToResponses(std.testing.allocator, "not json at all"));
}

test "responsesUrl requires exact suffix match" {
    const p = OpenAiCompatibleProvider.init(
        std.testing.allocator,
        "custom",
        "https://my-api.example.com/api/v2/responses-proxy",
        null,
        .bearer,
        null,
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

test "extractResponsesText strips think blocks" {
    const body =
        \\{"output_text":"<think>private reasoning</think>\nVisible answer","output":[]}
    ;
    const result = try OpenAiCompatibleProvider.extractResponsesText(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Visible answer", result);
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
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom, null);
    p.custom_header = "X-Custom-Key";
    const auth = (try p.authHeaderValue(std.testing.allocator)).?;
    defer if (auth.needs_free) std.testing.allocator.free(auth.value);
    try std.testing.expectEqualStrings("X-Custom-Key", auth.name);
    try std.testing.expectEqualStrings("my-key", auth.value);
    try std.testing.expect(!auth.needs_free);
}

test "authHeaderValue custom style without custom_header falls back" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "custom", "https://api.example.com", "my-key", .custom, null);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "test-model", 0.7, false, false, false, false);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"include_usage\":true") != null);
}

test "buildStreamingChatRequestBody omits provider thinking params when reasoning_effort none" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const req = root.ChatRequest{
        .messages = &msgs,
        .model = "test-model",
        .reasoning_effort = "none",
    };
    const body = try buildStreamingChatRequestBody(allocator, req, "test-model", 0.7, false, true, true, true);
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"thinking\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enable_thinking\":true") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning_split\":true") == null);
}

test "supportsStreaming returns true for compatible" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.supportsStreaming());
}

test "validateUserAgent rejects CRLF injection" {
    try std.testing.expect(OpenAiCompatibleProvider.validateUserAgent("nullclaw/1.0"));
    try std.testing.expect(!OpenAiCompatibleProvider.validateUserAgent("bad\r\nX-Test: 1"));
}

test "vtable has stream_chat not null" {
    var p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", "key", .bearer, null);
    const prov = p.provider();
    try std.testing.expect(prov.vtable.stream_chat != null);
}

test "streaming body has same messages as non-streaming" {
    const allocator = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test message")};
    const req = root.ChatRequest{ .messages = &msgs, .model = "gpt-4o" };

    const non_stream = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
    defer allocator.free(non_stream);

    const stream = try buildStreamingChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "custom-model", 0.5, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "gpt-4o", 0.7, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "o1", 0.7, false, false, false, false);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "gpt-5.2", 0.5, false, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, false, false, false, false);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 2);
    try std.testing.expectEqualStrings("system", messages.items[0].object.get("role").?.string);
    try std.testing.expectEqualStrings("user", messages.items[1].object.get("role").?.string);
}

test "merge_system_into_user field defaults to false" {
    const p = OpenAiCompatibleProvider.init(std.testing.allocator, "test", "https://example.com", null, .bearer, null);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false);
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

    const body = try buildChatRequestBody(allocator, req, "test", 0.7, true, false, false, false);
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

    const body = try buildStreamingChatRequestBody(allocator, req, "test", 0.7, true, false, false, false);
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const messages = parsed.value.object.get("messages").?.array;
    try std.testing.expect(messages.items.len == 1);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    const content = messages.items[0].object.get("content").?.string;
    try std.testing.expect(std.mem.indexOf(u8, content, "[System: Be concise]") != null);
}
