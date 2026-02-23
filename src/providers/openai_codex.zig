//! OpenAI Codex provider — connects to ChatGPT subscription API via OAuth tokens.
//!
//! Uses the Codex Responses API at chatgpt.com/backend-api/codex/responses,
//! authenticated via OAuth device code flow (RFC 8628). Users with ChatGPT
//! Plus/Pro subscriptions can use this without separate API tokens.

const std = @import("std");
const root = @import("root.zig");
const sse = @import("sse.zig");
const platform = @import("../platform.zig");
const auth = @import("../auth.zig");

const Provider = root.Provider;
const ChatMessage = root.ChatMessage;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const StreamChatResult = root.StreamChatResult;

// ── Constants ────────────────────────────────────────────────────────────

pub const CODEX_API_URL = "https://chatgpt.com/backend-api/codex/responses";
pub const OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OAUTH_DEVICE_URL = "https://auth.openai.com/oauth/device/code";
pub const OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token";
pub const OAUTH_SCOPE = "openid profile email offline_access";
pub const CREDENTIAL_KEY = "openai-codex";

// ── Provider ─────────────────────────────────────────────────────────────

pub const OpenAiCodexProvider = struct {
    allocator: std.mem.Allocator,
    access_token: ?[]const u8,
    refresh_token: ?[]const u8,
    account_id: ?[]const u8,
    expires_at: i64,

    pub fn init(allocator: std.mem.Allocator, _: ?[]const u8) OpenAiCodexProvider {
        var self = OpenAiCodexProvider{
            .allocator = allocator,
            .access_token = null,
            .refresh_token = null,
            .account_id = null,
            .expires_at = 0,
        };

        // Try to load stored credential
        if (auth.loadCredential(allocator, CREDENTIAL_KEY) catch null) |token| {
            self.access_token = token.access_token;
            self.refresh_token = token.refresh_token;
            self.expires_at = token.expires_at;
            // token_type is not stored — free it
            allocator.free(token.token_type);

            // Extract account ID from JWT
            if (self.access_token) |at| {
                self.account_id = extractAccountIdFromJwt(allocator, at) catch null;
            }
        }

        // Fallback: try Codex CLI token (~/.codex/auth.json) if no stored credential
        if (self.access_token == null) {
            if (tryLoadCodexCliToken(allocator)) |token| {
                self.access_token = token.access_token;
                self.refresh_token = token.refresh_token;
                self.expires_at = token.expires_at;
                allocator.free(token.token_type);

                if (self.access_token) |at| {
                    self.account_id = extractAccountIdFromJwt(allocator, at) catch null;
                }
            }
        }

        return self;
    }

    pub fn provider(self: *OpenAiCodexProvider) Provider {
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

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *OpenAiCodexProvider = @ptrCast(@alignCast(ptr));
        if (self.access_token) |at| self.allocator.free(at);
        if (self.refresh_token) |rt| self.allocator.free(rt);
        if (self.account_id) |id| self.allocator.free(id);
    }

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *OpenAiCodexProvider = @ptrCast(@alignCast(ptr));
        const token = try self.getValidToken();

        const body = try buildSimpleCodexBody(allocator, system_prompt, message, normalizeModel(model));
        defer allocator.free(body);

        var auth_hdr_buf: [2048]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{token}) catch return error.CodexApiError;

        return codexRequest(allocator, CODEX_API_URL, body, auth_hdr, &.{});
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *OpenAiCodexProvider = @ptrCast(@alignCast(ptr));
        const token = try self.getValidToken();

        const body = try buildCodexBody(allocator, null, request.messages, normalizeModel(model), request.reasoning_effort);
        defer allocator.free(body);

        var auth_hdr_buf: [2048]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{token}) catch return error.CodexApiError;

        const content = try codexRequest(allocator, CODEX_API_URL, body, auth_hdr, &.{});

        return .{
            .content = content,
            .model = try allocator.dupe(u8, normalizeModel(model)),
        };
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!StreamChatResult {
        const self: *OpenAiCodexProvider = @ptrCast(@alignCast(ptr));
        const token = try self.getValidToken();

        const body = try buildCodexBody(allocator, null, request.messages, normalizeModel(model), request.reasoning_effort);
        defer allocator.free(body);

        var auth_hdr_buf: [2048]u8 = undefined;
        const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{token}) catch return error.CodexApiError;

        return codexStreamRequest(allocator, CODEX_API_URL, body, auth_hdr, &.{}, callback, callback_ctx);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "openai-codex";
    }

    /// Ensure the token is valid, refreshing if needed.
    fn getValidToken(self: *OpenAiCodexProvider) ![]const u8 {
        const token = self.access_token orelse return error.CredentialsNotSet;

        // Check if token needs refresh
        if (self.expires_at != 0 and std.time.timestamp() + 300 >= self.expires_at) {
            const rt = self.refresh_token orelse return error.TokenExpired;
            const new_token = try auth.refreshAccessToken(
                self.allocator,
                OAUTH_TOKEN_URL,
                OAUTH_CLIENT_ID,
                rt,
            );

            // Free old tokens
            self.allocator.free(token);
            if (self.refresh_token) |old_rt| {
                // Don't double-free if refresh_token was preserved (same pointer)
                if (new_token.refresh_token) |new_rt| {
                    if (old_rt.ptr != new_rt.ptr) self.allocator.free(old_rt);
                } else {
                    self.allocator.free(old_rt);
                }
            }
            if (self.account_id) |id| self.allocator.free(id);

            self.access_token = new_token.access_token;
            self.refresh_token = new_token.refresh_token;
            self.expires_at = new_token.expires_at;
            self.allocator.free(new_token.token_type);

            // Re-extract account ID
            self.account_id = extractAccountIdFromJwt(self.allocator, new_token.access_token) catch null;

            // Persist updated token
            auth.saveCredential(self.allocator, CREDENTIAL_KEY, .{
                .access_token = new_token.access_token,
                .refresh_token = new_token.refresh_token,
                .expires_at = new_token.expires_at,
            }) catch {};

            return self.access_token.?;
        }

        return token;
    }
};

// ── Body Builders ────────────────────────────────────────────────────────

/// Build a Codex request body from system prompt and messages.
/// Maps: system → instructions, user → "user" item with input_text, assistant → "assistant" item.
fn buildCodexBody(
    allocator: std.mem.Allocator,
    system: ?[]const u8,
    messages: []const ChatMessage,
    model: []const u8,
    reasoning_effort: ?[]const u8,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\"");

    // Extract system/instructions from messages
    var instructions: ?[]const u8 = system;
    for (messages) |msg| {
        if (msg.role == .system) {
            instructions = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, ",\"instructions\":");
    if (instructions) |inst| {
        try root.appendJsonString(&buf, allocator, inst);
    } else {
        try buf.appendSlice(allocator, "\"You are a helpful assistant.\"");
    }

    // Build input items array — last user message becomes input, rest are context
    try buf.appendSlice(allocator, ",\"input\":[");
    var first = true;
    for (messages) |msg| {
        if (msg.role == .system) continue;
        if (!first) try buf.append(allocator, ',');
        first = false;

        if (msg.role == .user) {
            try buf.appendSlice(allocator, "{\"type\":\"message\",\"role\":\"user\",\"content\":");
            try root.appendJsonString(&buf, allocator, msg.content);
            try buf.append(allocator, '}');
        } else if (msg.role == .assistant) {
            try buf.appendSlice(allocator, "{\"type\":\"message\",\"role\":\"assistant\",\"content\":");
            try root.appendJsonString(&buf, allocator, msg.content);
            try buf.append(allocator, '}');
        }
    }
    try buf.append(allocator, ']');

    // Fixed fields
    try buf.appendSlice(allocator, ",\"store\":false,\"stream\":true");

    // Reasoning
    const effort = reasoning_effort orelse "medium";
    try buf.appendSlice(allocator, ",\"reasoning\":{\"effort\":\"");
    try buf.appendSlice(allocator, effort);
    try buf.appendSlice(allocator, "\",\"summary\":\"auto\"}");

    try buf.append(allocator, '}');
    return try buf.toOwnedSlice(allocator);
}

/// Build a simple Codex request body for chatWithSystem shortcut.
fn buildSimpleCodexBody(
    allocator: std.mem.Allocator,
    system: ?[]const u8,
    message: []const u8,
    model: []const u8,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"model\":\"");
    try buf.appendSlice(allocator, model);
    try buf.appendSlice(allocator, "\"");

    try buf.appendSlice(allocator, ",\"instructions\":");
    if (system) |sys| {
        try root.appendJsonString(&buf, allocator, sys);
    } else {
        try buf.appendSlice(allocator, "\"You are a helpful assistant.\"");
    }

    try buf.appendSlice(allocator, ",\"input\":[{\"type\":\"message\",\"role\":\"user\",\"content\":");
    try root.appendJsonString(&buf, allocator, message);
    try buf.appendSlice(allocator, "}],\"store\":false,\"stream\":true");
    try buf.appendSlice(allocator, ",\"reasoning\":{\"effort\":\"medium\",\"summary\":\"auto\"}}");

    return try buf.toOwnedSlice(allocator);
}

// ── SSE / HTTP ───────────────────────────────────────────────────────────

/// Non-streaming Codex request — spawns curl with SSE, accumulates text deltas, returns final text.
fn codexRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_header: []const u8,
    extra_headers: []const []const u8,
) ![]const u8 {
    // Use the streaming path internally and just accumulate
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    const NoopCtx = struct {
        list: *std.ArrayListUnmanaged(u8),
        alloc: std.mem.Allocator,

        fn callback(ctx: *anyopaque, chunk: root.StreamChunk) void {
            if (chunk.is_final) return;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.list.appendSlice(self.alloc, chunk.delta) catch {};
        }
    };

    var ctx = NoopCtx{ .list = &accumulated, .alloc = allocator };
    _ = codexStreamRequest(allocator, url, body, auth_header, extra_headers, NoopCtx.callback, @ptrCast(&ctx)) catch |err| {
        return err;
    };

    if (accumulated.items.len == 0) return error.NoResponseContent;
    return try allocator.dupe(u8, accumulated.items);
}

/// Streaming Codex request — spawns curl, parses Codex SSE events, invokes callback per delta.
fn codexStreamRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_header: []const u8,
    extra_headers: []const []const u8,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !StreamChatResult {
    // Build argv on stack
    var argv_buf: [32][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--no-buffer";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = auth_header;
    argc += 1;

    for (extra_headers) |hdr| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = "-d";
    argc += 1;
    argv_buf[argc] = body;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    // Read stdout line by line, parse Codex SSE events
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    const file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var saw_text_delta = false;
    var emitted_text_fallback = false;
    var emitted_tool_payload = false;

    outer: while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                const result = parseCodexSseEvent(allocator, line_buf.items) catch {
                    line_buf.clearRetainingCapacity();
                    continue;
                };
                line_buf.clearRetainingCapacity();
                switch (result) {
                    .delta => |delta_evt| {
                        defer allocator.free(delta_evt.text);
                        const is_tool_payload = std.mem.indexOf(u8, delta_evt.text, "<tool_call>") != null;
                        switch (delta_evt.source) {
                            .output_text_delta, .refusal_delta => {
                                saw_text_delta = true;
                                try accumulated.appendSlice(allocator, delta_evt.text);
                                callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                            },
                            .output_text_done, .content_part_done => {
                                // Fallback text only when canonical deltas were absent.
                                if (saw_text_delta or emitted_text_fallback) continue;
                                emitted_text_fallback = true;
                                try accumulated.appendSlice(allocator, delta_evt.text);
                                callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                            },
                            .output_item_done => {
                                if (is_tool_payload) {
                                    emitted_tool_payload = true;
                                    try accumulated.appendSlice(allocator, delta_evt.text);
                                    callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                                } else {
                                    // Message snapshot text, fallback-only.
                                    if (saw_text_delta or emitted_text_fallback) continue;
                                    emitted_text_fallback = true;
                                    try accumulated.appendSlice(allocator, delta_evt.text);
                                    callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                                }
                            },
                            .response_completed, .response_done => {
                                if (is_tool_payload) {
                                    // Completed may repeat tool payloads already emitted from output_item.done.
                                    if (emitted_tool_payload) continue;
                                    emitted_tool_payload = true;
                                    try accumulated.appendSlice(allocator, delta_evt.text);
                                    callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                                } else {
                                    // Completed text is fallback-only when no deltas were seen.
                                    if (saw_text_delta or emitted_text_fallback) continue;
                                    emitted_text_fallback = true;
                                    try accumulated.appendSlice(allocator, delta_evt.text);
                                    callback(ctx, root.StreamChunk.textDelta(delta_evt.text));
                                }
                            },
                        }
                    },
                    .done => break :outer,
                    .error_msg => break :outer,
                    .skip => {},
                }
            } else {
                try line_buf.append(allocator, byte);
            }
        }
    }

    // Send final chunk
    callback(ctx, root.StreamChunk.finalChunk());

    // Drain remaining stdout
    while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;
    }

    const term = child.wait() catch return error.CurlWaitError;
    switch (term) {
        .Exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }

    const content = if (accumulated.items.len > 0)
        try allocator.dupe(u8, accumulated.items)
    else
        null;

    return .{
        .content = content,
        .usage = .{ .completion_tokens = @intCast((accumulated.items.len + 3) / 4) },
        .model = "",
    };
}

// ── SSE Event Parsing ────────────────────────────────────────────────────

/// Result of parsing a single Codex SSE line.
pub const CodexDeltaSource = enum {
    output_text_delta,
    refusal_delta,
    output_text_done,
    content_part_done,
    output_item_done,
    response_completed,
    response_done,
};

pub const CodexSseResult = union(enum) {
    delta: struct {
        text: []const u8,
        source: CodexDeltaSource,
    },
    done: void,
    error_msg: void,
    skip: void,
};

fn appendSingleContentPartText(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    part_obj: std.json.ObjectMap,
) !void {
    const type_val = part_obj.get("type") orelse return;
    if (type_val != .string) return;
    if (!std.mem.eql(u8, type_val.string, "output_text") and
        !std.mem.eql(u8, type_val.string, "text"))
    {
        return;
    }
    const text_val = part_obj.get("text") orelse return;
    if (text_val != .string or text_val.string.len == 0) return;
    try out.appendSlice(allocator, text_val.string);
}

fn appendResponseContentText(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, content_val: std.json.Value) !void {
    if (content_val != .array) return;
    for (content_val.array.items) |part| {
        if (part != .object) continue;
        try appendSingleContentPartText(out, allocator, part.object);
    }
}

fn firstTextFromContent(content_val: std.json.Value) ?[]const u8 {
    if (content_val != .array) return null;

    // Prefer explicit output_text blocks first.
    for (content_val.array.items) |part| {
        if (part != .object) continue;
        const part_obj = part.object;
        const type_val = part_obj.get("type") orelse continue;
        if (type_val != .string) continue;
        if (!std.mem.eql(u8, type_val.string, "output_text")) continue;
        const text_val = part_obj.get("text") orelse continue;
        if (text_val == .string and text_val.string.len > 0) return text_val.string;
    }

    // Fallback to any non-empty text-like block.
    for (content_val.array.items) |part| {
        if (part != .object) continue;
        const part_obj = part.object;
        const text_val = part_obj.get("text") orelse continue;
        if (text_val == .string and text_val.string.len > 0) return text_val.string;
    }

    return null;
}

fn appendToolCallXml(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    name: []const u8,
    arguments_json: []const u8,
) !void {
    try out.appendSlice(allocator, "<tool_call>\n{\"name\":");
    try root.appendJsonString(out, allocator, name);
    try out.appendSlice(allocator, ",\"arguments\":");

    const trimmed_args = std.mem.trim(u8, arguments_json, " \t\r\n");
    if (trimmed_args.len == 0) {
        try out.appendSlice(allocator, "{}");
    } else if (trimmed_args[0] == '{' or trimmed_args[0] == '[') {
        try out.appendSlice(allocator, trimmed_args);
    } else {
        // Keep shape valid if backend returns non-JSON arguments.
        try root.appendJsonString(out, allocator, trimmed_args);
    }

    try out.appendSlice(allocator, "}\n</tool_call>\n");
}

fn extractOutputItemText(item_obj: std.json.ObjectMap) ?[]const u8 {
    const item_type = item_obj.get("type") orelse return null;
    if (item_type != .string) return null;

    if (!std.mem.eql(u8, item_type.string, "message")) return null;

    const content_val = item_obj.get("content") orelse return null;
    return firstTextFromContent(content_val);
}

fn extractOutputItemToolCallXml(allocator: std.mem.Allocator, item_obj: std.json.ObjectMap) !?[]u8 {
    const item_type = item_obj.get("type") orelse return null;
    if (item_type != .string) return null;

    if (!std.mem.eql(u8, item_type.string, "function_call")) return null;

    const name_val = item_obj.get("name") orelse return null;
    if (name_val != .string or name_val.string.len == 0) return null;

    var args: []const u8 = "{}";
    if (item_obj.get("arguments")) |args_val| {
        if (args_val == .string and args_val.string.len > 0) {
            args = args_val.string;
        }
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendToolCallXml(&out, allocator, name_val.string, args);
    return try out.toOwnedSlice(allocator);
}

fn extractCompletedText(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !?[]u8 {
    if (root_obj.get("output_text")) |ot| {
        if (ot == .string and ot.string.len > 0) {
            return try allocator.dupe(u8, ot.string);
        }
    }

    const response_val = root_obj.get("response");
    if (response_val) |resp| {
        if (resp == .object) {
            if (resp.object.get("output_text")) |ot| {
                if (ot == .string and ot.string.len > 0) {
                    return try allocator.dupe(u8, ot.string);
                }
            }
        }
    }

    const output_val: ?std.json.Value = if (response_val) |resp| blk: {
        if (resp != .object) break :blk null;
        break :blk resp.object.get("output");
    } else root_obj.get("output");

    if (output_val) |ov| {
        if (ov == .array) {
            for (ov.array.items) |item| {
                if (item != .object) continue;
                if (extractOutputItemText(item.object)) |text| {
                    return try allocator.dupe(u8, text);
                }
            }
        }
    }

    return null;
}

fn extractCompletedToolCalls(allocator: std.mem.Allocator, root_obj: std.json.ObjectMap) !?[]u8 {
    const response_val = root_obj.get("response");
    const output_val: ?std.json.Value = if (response_val) |resp| blk: {
        if (resp != .object) break :blk null;
        break :blk resp.object.get("output");
    } else root_obj.get("output");

    if (output_val == null or output_val.? != .array) return null;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    for (output_val.?.array.items) |item| {
        if (item != .object) continue;
        const maybe_xml = try extractOutputItemToolCallXml(allocator, item.object);
        if (maybe_xml) |xml| {
            defer allocator.free(xml);
            try out.appendSlice(allocator, xml);
        }
    }

    if (out.items.len == 0) return null;
    return try out.toOwnedSlice(allocator);
}

/// Parse a single Codex SSE event line.
///
/// Codex SSE format: `event: <type>\ndata: {JSON}`
/// Event types:
/// - "response.output_text.delta" → extract "delta" field
/// - "response.output_text.done" → optional final text chunk
/// - "response.output_item.done" / "response.content_part.done" → message/tool-call payload
/// - "response.completed" / "response.done" → done
/// - "error" / "response.failed" → error
pub fn parseCodexSseEvent(allocator: std.mem.Allocator, line: []const u8) !CodexSseResult {
    const trimmed = std.mem.trimRight(u8, line, "\r");
    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // Handle event: lines — skip them (we parse data: lines which contain type field)
    if (std.mem.startsWith(u8, trimmed, "event:")) return .skip;

    const prefix = "data:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return .skip;
    const data = std.mem.trimLeft(u8, trimmed[prefix.len..], " ");
    if (std.mem.eql(u8, data, "[DONE]")) return .done;

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch return .skip;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return .skip,
    };

    // Check "type" field
    const type_val = obj.get("type") orelse return .skip;
    const type_str = switch (type_val) {
        .string => |s| s,
        else => return .skip,
    };

    if (std.mem.eql(u8, type_str, "response.output_text.delta")) {
        // Extract "delta" field
        const delta_val = obj.get("delta") orelse return .skip;
        const delta_str = switch (delta_val) {
            .string => |s| s,
            else => return .skip,
        };
        if (delta_str.len == 0) return .skip;
        return .{ .delta = .{
            .text = try allocator.dupe(u8, delta_str),
            .source = .output_text_delta,
        } };
    }

    if (std.mem.eql(u8, type_str, "response.refusal.delta")) {
        const delta_val = obj.get("delta") orelse return .skip;
        const delta_str = switch (delta_val) {
            .string => |s| s,
            else => return .skip,
        };
        if (delta_str.len == 0) return .skip;
        return .{ .delta = .{
            .text = try allocator.dupe(u8, delta_str),
            .source = .refusal_delta,
        } };
    }

    if (std.mem.eql(u8, type_str, "response.output_text.done")) {
        if (obj.get("text")) |text_val| {
            if (text_val == .string and text_val.string.len > 0) {
                return .{ .delta = .{
                    .text = try allocator.dupe(u8, text_val.string),
                    .source = .output_text_done,
                } };
            }
        }
        // This marks one text part complete, not the full response.
        return .skip;
    }

    if (std.mem.eql(u8, type_str, "response.content_part.done")) {
        if (obj.get("part")) |part_val| {
            if (part_val == .object) {
                var out: std.ArrayListUnmanaged(u8) = .empty;
                defer out.deinit(allocator);
                try appendSingleContentPartText(&out, allocator, part_val.object);
                if (out.items.len > 0) {
                    return .{ .delta = .{
                        .text = try allocator.dupe(u8, out.items),
                        .source = .content_part_done,
                    } };
                }
            }
        }
        return .skip;
    }

    if (std.mem.eql(u8, type_str, "response.output_item.done")) {
        if (obj.get("item")) |item_val| {
            if (item_val == .object) {
                if (try extractOutputItemToolCallXml(allocator, item_val.object)) |xml| {
                    return .{ .delta = .{
                        .text = xml,
                        .source = .output_item_done,
                    } };
                }
                if (extractOutputItemText(item_val.object)) |text| {
                    if (text.len > 0) {
                        return .{ .delta = .{
                            .text = try allocator.dupe(u8, text),
                            .source = .output_item_done,
                        } };
                    }
                }
            }
        }
        return .skip;
    }

    if (std.mem.eql(u8, type_str, "response.completed")) {
        if (try extractCompletedToolCalls(allocator, obj)) |xml| {
            return .{ .delta = .{
                .text = xml,
                .source = .response_completed,
            } };
        }
        if (try extractCompletedText(allocator, obj)) |text| {
            return .{ .delta = .{
                .text = text,
                .source = .response_completed,
            } };
        }
        return .done;
    }

    if (std.mem.eql(u8, type_str, "response.done")) {
        if (try extractCompletedToolCalls(allocator, obj)) |xml| {
            return .{ .delta = .{
                .text = xml,
                .source = .response_done,
            } };
        }
        if (try extractCompletedText(allocator, obj)) |text| {
            return .{ .delta = .{
                .text = text,
                .source = .response_done,
            } };
        }
        return .done;
    }

    if (std.mem.eql(u8, type_str, "error") or
        std.mem.eql(u8, type_str, "response.failed"))
    {
        return .error_msg;
    }

    return .skip;
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Normalize model name — strip "openai-codex/" prefix if present.
pub fn normalizeModel(model: []const u8) []const u8 {
    const prefix = "openai-codex/";
    if (std.mem.startsWith(u8, model, prefix)) return model[prefix.len..];
    return model;
}

/// Extract account_id from a JWT access token.
/// Splits on '.', base64url-decodes segment[1], parses JSON.
/// Checks keys: account_id, accountId, acct, sub, https://api.openai.com/account_id.
pub fn extractAccountIdFromJwt(allocator: std.mem.Allocator, token: []const u8) !?[]const u8 {
    // Find the payload segment (between first and second '.')
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return null;
    const payload_b64 = rest[0..second_dot];

    if (payload_b64.len == 0) return null;

    // Base64url decode (add padding if needed)
    const Decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(payload_b64) catch return null;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    Decoder.decode(decoded, payload_b64) catch return null;

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    // Try multiple claim names
    const claim_keys = [_][]const u8{
        "account_id",
        "accountId",
        "acct",
        "sub",
        "https://api.openai.com/account_id",
    };

    for (&claim_keys) |key| {
        if (obj.get(key)) |val| {
            switch (val) {
                .string => |s| if (s.len > 0) return try allocator.dupe(u8, s),
                else => {},
            }
        }
    }

    return null;
}

// ── Codex CLI Token Import ────────────────────────────────────────────────

/// Try to load OAuth tokens from Codex CLI at ~/.codex/auth.json.
/// Returns an OAuthToken with access_token, refresh_token, and decoded JWT exp.
/// Returns null on any error (file not found, parse failure, etc.).
pub fn tryLoadCodexCliToken(allocator: std.mem.Allocator) ?auth.OAuthToken {
    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);
    const path = std.fs.path.join(allocator, &.{ home, ".codex", "auth.json" }) catch return null;
    defer allocator.free(path);

    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    // Codex CLI format: { "tokens": { "access_token": "...", "refresh_token": "..." }, ... }
    const tokens_val = root_obj.get("tokens") orelse return null;
    const tokens_obj = switch (tokens_val) {
        .object => |o| o,
        else => return null,
    };

    const access_token_str = switch (tokens_obj.get("access_token") orelse return null) {
        .string => |s| s,
        else => return null,
    };
    if (access_token_str.len == 0) return null;

    const access_token = allocator.dupe(u8, access_token_str) catch return null;
    errdefer allocator.free(access_token);

    const refresh_token: ?[]const u8 = if (tokens_obj.get("refresh_token")) |rt_val| blk: {
        switch (rt_val) {
            .string => |s| break :blk if (s.len > 0) allocator.dupe(u8, s) catch null else null,
            else => break :blk null,
        }
    } else null;

    // Decode JWT exp
    const expires_at = decodeJwtExp(allocator, access_token);

    // Check expiration — skip if already expired (past the 300s buffer)
    if (expires_at != 0 and std.time.timestamp() + 300 >= expires_at) {
        allocator.free(access_token);
        if (refresh_token) |rt| allocator.free(rt);
        return null;
    }

    const token_type = allocator.dupe(u8, "Bearer") catch {
        allocator.free(access_token);
        if (refresh_token) |rt| allocator.free(rt);
        return null;
    };

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
        .token_type = token_type,
    };
}

/// Decode the "exp" claim from a JWT, returning the Unix timestamp or 0 if not decodable.
fn decodeJwtExp(allocator: std.mem.Allocator, token: []const u8) i64 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return 0;
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return 0;
    const payload_b64 = rest[0..second_dot];
    if (payload_b64.len == 0) return 0;

    const Decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(payload_b64) catch return 0;
    const decoded = allocator.alloc(u8, decoded_len) catch return 0;
    defer allocator.free(decoded);
    Decoder.decode(decoded, payload_b64) catch return 0;

    const json_parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded, .{}) catch return 0;
    defer json_parsed.deinit();

    const obj = switch (json_parsed.value) {
        .object => |o| o,
        else => return 0,
    };

    if (obj.get("exp")) |exp_val| {
        switch (exp_val) {
            .integer => |i| return i,
            .float => |f| return @intFromFloat(f),
            else => {},
        }
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildCodexBody with system and user messages" {
    const messages = [_]ChatMessage{
        .{ .role = .system, .content = "You are helpful" },
        .{ .role = .user, .content = "Hello" },
        .{ .role = .assistant, .content = "Hi there" },
        .{ .role = .user, .content = "How are you?" },
    };
    const body = try buildCodexBody(std.testing.allocator, null, &messages, "o4-mini", null);
    defer std.testing.allocator.free(body);

    // Should contain model
    try std.testing.expect(std.mem.indexOf(u8, body, "\"model\":\"o4-mini\"") != null);
    // Should contain instructions from system message
    try std.testing.expect(std.mem.indexOf(u8, body, "\"instructions\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "You are helpful") != null);
    // Should contain user message
    try std.testing.expect(std.mem.indexOf(u8, body, "Hello") != null);
    // Should contain assistant message
    try std.testing.expect(std.mem.indexOf(u8, body, "Hi there") != null);
    // Should contain store=false
    try std.testing.expect(std.mem.indexOf(u8, body, "\"store\":false") != null);
    // Should contain stream=true
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    // Should contain reasoning
    try std.testing.expect(std.mem.indexOf(u8, body, "\"reasoning\":{") != null);
}

test "buildSimpleCodexBody correct JSON" {
    const body = try buildSimpleCodexBody(std.testing.allocator, "Be brief", "What is 2+2?", "o4-mini");
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"model\":\"o4-mini\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"instructions\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Be brief") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "What is 2+2?") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"store\":false") != null);
}

test "buildSimpleCodexBody without system prompt" {
    const body = try buildSimpleCodexBody(std.testing.allocator, null, "Hello", "o4-mini");
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"instructions\":\"You are a helpful assistant.\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Hello") != null);
}

test "normalizeModel strips openai-codex/ prefix" {
    try std.testing.expectEqualStrings("o4-mini", normalizeModel("openai-codex/o4-mini"));
    try std.testing.expectEqualStrings("gpt-4o", normalizeModel("openai-codex/gpt-4o"));
}

test "normalizeModel preserves model without prefix" {
    try std.testing.expectEqualStrings("o4-mini", normalizeModel("o4-mini"));
    try std.testing.expectEqualStrings("gpt-4o", normalizeModel("gpt-4o"));
}

test "extractAccountIdFromJwt with valid JWT" {
    // Build a fake JWT: header.payload.signature
    // Payload: {"sub":"user-12345","account_id":"acct-abc"}
    const payload = "{\"sub\":\"user-12345\",\"account_id\":\"acct-abc\"}";
    const Encoder = std.base64.url_safe_no_pad.Encoder;

    var header_buf: [64]u8 = undefined;
    const header_encoded = Encoder.encode(&header_buf, "{}");

    var payload_buf: [128]u8 = undefined;
    const payload_encoded = Encoder.encode(&payload_buf, payload);

    const jwt = try std.fmt.allocPrint(std.testing.allocator, "{s}.{s}.sig", .{ header_encoded, payload_encoded });
    defer std.testing.allocator.free(jwt);

    const account_id = try extractAccountIdFromJwt(std.testing.allocator, jwt);
    defer if (account_id) |id| std.testing.allocator.free(id);

    try std.testing.expect(account_id != null);
    try std.testing.expectEqualStrings("acct-abc", account_id.?);
}

test "extractAccountIdFromJwt falls back to sub claim" {
    const payload = "{\"sub\":\"user-99\"}";
    const Encoder = std.base64.url_safe_no_pad.Encoder;

    var header_buf: [64]u8 = undefined;
    const header_encoded = Encoder.encode(&header_buf, "{}");

    var payload_buf: [128]u8 = undefined;
    const payload_encoded = Encoder.encode(&payload_buf, payload);

    const jwt = try std.fmt.allocPrint(std.testing.allocator, "{s}.{s}.sig", .{ header_encoded, payload_encoded });
    defer std.testing.allocator.free(jwt);

    const account_id = try extractAccountIdFromJwt(std.testing.allocator, jwt);
    defer if (account_id) |id| std.testing.allocator.free(id);

    try std.testing.expect(account_id != null);
    try std.testing.expectEqualStrings("user-99", account_id.?);
}

test "extractAccountIdFromJwt returns null for missing claims" {
    const payload = "{\"email\":\"test@test.com\"}";
    const Encoder = std.base64.url_safe_no_pad.Encoder;

    var header_buf: [64]u8 = undefined;
    const header_encoded = Encoder.encode(&header_buf, "{}");

    var payload_buf: [128]u8 = undefined;
    const payload_encoded = Encoder.encode(&payload_buf, payload);

    const jwt = try std.fmt.allocPrint(std.testing.allocator, "{s}.{s}.sig", .{ header_encoded, payload_encoded });
    defer std.testing.allocator.free(jwt);

    const account_id = try extractAccountIdFromJwt(std.testing.allocator, jwt);
    try std.testing.expect(account_id == null);
}

test "extractAccountIdFromJwt returns null for malformed token" {
    const result1 = try extractAccountIdFromJwt(std.testing.allocator, "not-a-jwt");
    try std.testing.expect(result1 == null);

    const result2 = try extractAccountIdFromJwt(std.testing.allocator, "a.b");
    try std.testing.expect(result2 == null);

    const result3 = try extractAccountIdFromJwt(std.testing.allocator, "");
    try std.testing.expect(result3 == null);
}

test "parseCodexSseEvent delta event" {
    const line = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("Hello", delta_evt.text);
            try std.testing.expect(delta_evt.source == .output_text_delta);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent accepts data prefix without space" {
    const line = "data:{\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("Hello", delta_evt.text);
            try std.testing.expect(delta_evt.source == .output_text_delta);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent done event" {
    const line = "data: {\"type\":\"response.completed\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    try std.testing.expect(result == .done);
}

test "parseCodexSseEvent output_text.done with text emits delta" {
    const line = "data: {\"type\":\"response.output_text.done\",\"text\":\"Final answer\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("Final answer", delta_evt.text);
            try std.testing.expect(delta_evt.source == .output_text_done);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent output_text.done without text does not finish stream" {
    const line = "data: {\"type\":\"response.output_text.done\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    try std.testing.expect(result == .skip);
}

test "parseCodexSseEvent content_part.done emits text delta" {
    const line =
        \\data: {"type":"response.content_part.done","part":{"type":"output_text","text":"part text"}}
    ;
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("part text", delta_evt.text);
            try std.testing.expect(delta_evt.source == .content_part_done);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent output_item.done message emits text delta" {
    const line =
        \\data: {"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"item text"}]}}
    ;
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("item text", delta_evt.text);
            try std.testing.expect(delta_evt.source == .output_item_done);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent output_item.done function_call emits xml tool call" {
    const line =
        \\data: {"type":"response.output_item.done","item":{"type":"function_call","name":"screenshot","arguments":"{\"filename\":\"screenshot.png\"}"}}
    ;
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "<tool_call>") != null);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "\"name\":\"screenshot\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "\"filename\":\"screenshot.png\"") != null);
            try std.testing.expect(delta_evt.source == .output_item_done);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent response.completed extracts text from response output" {
    const line =
        \\data: {"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello from completed"}]}]}}
    ;
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("Hello from completed", delta_evt.text);
            try std.testing.expect(delta_evt.source == .response_completed);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent response.completed extracts function_call from response output" {
    const line =
        \\data: {"type":"response.completed","response":{"output":[{"type":"function_call","name":"screenshot","arguments":"{\"filename\":\"a.png\"}"}]}}
    ;
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "<tool_call>") != null);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "\"name\":\"screenshot\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, delta_evt.text, "\"filename\":\"a.png\"") != null);
            try std.testing.expect(delta_evt.source == .response_completed);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent response.refusal.delta emits delta" {
    const line = "data: {\"type\":\"response.refusal.delta\",\"delta\":\"Cannot do that\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    switch (result) {
        .delta => |delta_evt| {
            defer std.testing.allocator.free(delta_evt.text);
            try std.testing.expectEqualStrings("Cannot do that", delta_evt.text);
            try std.testing.expect(delta_evt.source == .refusal_delta);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseCodexSseEvent error event" {
    const line = "data: {\"type\":\"error\",\"message\":\"rate limited\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    try std.testing.expect(result == .error_msg);
}

test "parseCodexSseEvent skips event: lines" {
    const result = try parseCodexSseEvent(std.testing.allocator, "event: response.output_text.delta");
    try std.testing.expect(result == .skip);
}

test "parseCodexSseEvent skips empty lines" {
    const result = try parseCodexSseEvent(std.testing.allocator, "");
    try std.testing.expect(result == .skip);
}

test "parseCodexSseEvent DONE sentinel" {
    const result = try parseCodexSseEvent(std.testing.allocator, "data: [DONE]");
    try std.testing.expect(result == .done);
}

test "parseCodexSseEvent response.done event" {
    const line = "data: {\"type\":\"response.done\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    try std.testing.expect(result == .done);
}

test "parseCodexSseEvent response.failed event" {
    const line = "data: {\"type\":\"response.failed\"}";
    const result = try parseCodexSseEvent(std.testing.allocator, line);
    try std.testing.expect(result == .error_msg);
}

test "buildCodexBody with explicit reasoning effort" {
    const messages = [_]ChatMessage{
        .{ .role = .user, .content = "Think hard" },
    };
    const body = try buildCodexBody(std.testing.allocator, null, &messages, "o4-mini", "high");
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"effort\":\"high\"") != null);
}
