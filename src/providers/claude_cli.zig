const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ChatMessage = root.ChatMessage;

/// Provider that delegates to the `claude` CLI (Claude Code).
///
/// Fresh sessions seed Claude with the full NullClaw transcript, while resumed
/// sessions send only the new message delta since the last successful turn.
pub const ClaudeCliProvider = struct {
    allocator: std.mem.Allocator,
    model: []const u8,
    mutex: std.Thread.Mutex = .{},
    sessions: std.StringHashMapUnmanaged(SessionState) = .empty,

    const DEFAULT_MODEL = "claude-opus-4-6";
    const CLI_NAME = "claude";
    const IDLE_TIMEOUT_NS: i128 = 30 * 60 * std.time.ns_per_s;
    const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

    const ClaudeCommandResult = struct {
        result: []u8,
        session_id: ?[]u8 = null,
    };

    const ClaudeCommandOptions = struct {
        prompt: []const u8,
        model: []const u8,
        system_prompt: ?[]const u8 = null,
        resume_session_id: ?[]const u8 = null,
    };

    const SessionState = struct {
        cli_session_id: ?[]u8 = null,
        last_active_ns: i128 = 0,
        transcript_hashes: std.ArrayListUnmanaged(u64) = .empty,

        fn deinit(self: *SessionState, allocator: std.mem.Allocator) void {
            if (self.cli_session_id) |sid| allocator.free(sid);
            self.transcript_hashes.deinit(allocator);
        }

        fn reset(self: *SessionState, allocator: std.mem.Allocator) void {
            if (self.cli_session_id) |sid| allocator.free(sid);
            self.cli_session_id = null;
            self.last_active_ns = 0;
            self.transcript_hashes.clearRetainingCapacity();
        }

        fn replaceSessionId(self: *SessionState, allocator: std.mem.Allocator, session_id: ?[]const u8) !void {
            const sid = session_id orelse return;
            const copy = try allocator.dupe(u8, sid);
            errdefer allocator.free(copy);
            if (self.cli_session_id) |old| allocator.free(old);
            self.cli_session_id = copy;
        }

        fn updateTranscript(
            self: *SessionState,
            allocator: std.mem.Allocator,
            current_hashes: []const u64,
            response_content: []const u8,
            session_id: ?[]const u8,
            now_ns: i128,
        ) !void {
            if (session_id != null) {
                try self.replaceSessionId(allocator, session_id);
            }
            self.last_active_ns = now_ns;
            self.transcript_hashes.clearRetainingCapacity();
            try self.transcript_hashes.appendSlice(allocator, current_hashes);
            try self.transcript_hashes.append(allocator, hashAssistantResponse(response_content));
        }
    };

    const SessionPlan = struct {
        use_resume: bool,
        delta_start: usize,
        reset_state: bool,
    };

    pub fn init(allocator: std.mem.Allocator, model: ?[]const u8) !ClaudeCliProvider {
        try checkCliAvailable(allocator, CLI_NAME);
        return .{
            .allocator = allocator,
            .model = model orelse DEFAULT_MODEL,
        };
    }

    pub fn provider(self: *ClaudeCliProvider) Provider {
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
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *ClaudeCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;

        const result = try runClaudeCommand(allocator, .{
            .prompt = message,
            .model = effective_model,
            .system_prompt = system_prompt,
        });
        if (result.session_id) |sid| allocator.free(sid);
        return result.result;
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *ClaudeCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;
        const system_prompt = extractSystemPrompt(request.messages);

        const content = if (request.session_id) |session_key|
            try self.runSessionChat(allocator, session_key, request.messages, system_prompt, effective_model)
        else blk: {
            const prompt = try renderPromptMessages(allocator, request.messages, 0);
            defer allocator.free(prompt);

            const result = try runClaudeCommand(allocator, .{
                .prompt = prompt,
                .model = effective_model,
                .system_prompt = system_prompt,
            });
            if (result.session_id) |sid| allocator.free(sid);
            break :blk result.result;
        };

        return .{
            .content = content,
            .model = try allocator.dupe(u8, effective_model),
        };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "claude-cli";
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *ClaudeCliProvider = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.sessions.deinit(self.allocator);
    }

    fn runSessionChat(
        self: *ClaudeCliProvider,
        allocator: std.mem.Allocator,
        session_key: []const u8,
        messages: []const ChatMessage,
        system_prompt: ?[]const u8,
        model: []const u8,
    ) ![]u8 {
        const current_hashes = try collectMessageHashes(allocator, messages);
        defer allocator.free(current_hashes);

        const now_ns = std.time.nanoTimestamp();
        var plan = ClaudeCliProvider.SessionPlan{
            .use_resume = false,
            .delta_start = 0,
            .reset_state = false,
        };
        var resume_session_id: ?[]u8 = null;
        defer if (resume_session_id) |sid| allocator.free(sid);

        self.mutex.lock();
        {
            defer self.mutex.unlock();
            const state = try self.getOrCreateSessionStateLocked(session_key);
            plan = buildSessionPlan(state, messages, current_hashes, now_ns);
            if (plan.reset_state) {
                self.deleteSessionStateLocked(session_key);
            } else if (plan.use_resume) {
                resume_session_id = try allocator.dupe(u8, state.cli_session_id.?);
            }
        }

        if (resume_session_id) |sid| {
            const resume_prompt = renderPromptMessages(allocator, messages, plan.delta_start) catch |err| switch (err) {
                error.NoUserMessage => {
                    self.deleteSessionState(session_key);
                    return try self.runFreshSessionChat(allocator, session_key, messages, current_hashes, system_prompt, model, now_ns);
                },
                else => return err,
            };
            defer allocator.free(resume_prompt);

            const resume_result = runClaudeCommand(allocator, .{
                .prompt = resume_prompt,
                .model = model,
                .resume_session_id = sid,
            }) catch |err| switch (err) {
                error.CliProcessFailed, error.NoResultInOutput => {
                    self.deleteSessionState(session_key);
                    return try self.runFreshSessionChat(allocator, session_key, messages, current_hashes, system_prompt, model, now_ns);
                },
                else => return err,
            };
            errdefer allocator.free(resume_result.result);
            defer if (resume_result.session_id) |new_sid| allocator.free(new_sid);

            try self.recordSuccessfulTurn(session_key, current_hashes, resume_result.result, resume_result.session_id, now_ns);
            return resume_result.result;
        }

        return try self.runFreshSessionChat(allocator, session_key, messages, current_hashes, system_prompt, model, now_ns);
    }

    fn runFreshSessionChat(
        self: *ClaudeCliProvider,
        allocator: std.mem.Allocator,
        session_key: []const u8,
        messages: []const ChatMessage,
        current_hashes: []const u64,
        system_prompt: ?[]const u8,
        model: []const u8,
        now_ns: i128,
    ) ![]u8 {
        const prompt = try renderPromptMessages(allocator, messages, 0);
        defer allocator.free(prompt);

        const result = try runClaudeCommand(allocator, .{
            .prompt = prompt,
            .model = model,
            .system_prompt = system_prompt,
        });
        errdefer allocator.free(result.result);
        defer if (result.session_id) |sid| allocator.free(sid);

        try self.recordSuccessfulTurn(session_key, current_hashes, result.result, result.session_id, now_ns);
        return result.result;
    }

    fn recordSuccessfulTurn(
        self: *ClaudeCliProvider,
        session_key: []const u8,
        current_hashes: []const u64,
        response_content: []const u8,
        session_id: ?[]const u8,
        now_ns: i128,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const state = try self.getOrCreateSessionStateLocked(session_key);
        try state.updateTranscript(self.allocator, current_hashes, response_content, session_id, now_ns);
    }

    fn deleteSessionState(self: *ClaudeCliProvider, session_key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.deleteSessionStateLocked(session_key);
    }

    fn deleteSessionStateLocked(self: *ClaudeCliProvider, session_key: []const u8) void {
        if (self.sessions.fetchRemove(session_key)) |entry| {
            self.allocator.free(entry.key);
            var state = entry.value;
            state.deinit(self.allocator);
        }
    }

    fn getOrCreateSessionStateLocked(self: *ClaudeCliProvider, session_key: []const u8) !*SessionState {
        if (self.sessions.getPtr(session_key)) |state| return state;

        const key_copy = try self.allocator.dupe(u8, session_key);
        errdefer self.allocator.free(key_copy);

        try self.sessions.put(self.allocator, key_copy, .{});
        return self.sessions.getPtr(session_key).?;
    }

    fn healthCheck(allocator: std.mem.Allocator) !void {
        try checkCliVersion(allocator, CLI_NAME);
    }
};

fn buildSessionPlan(
    state: *const ClaudeCliProvider.SessionState,
    messages: []const ChatMessage,
    current_hashes: []const u64,
    now_ns: i128,
) ClaudeCliProvider.SessionPlan {
    if (state.cli_session_id == null) {
        return .{ .use_resume = false, .delta_start = 0, .reset_state = true };
    }
    if (state.last_active_ns != 0 and now_ns - state.last_active_ns > ClaudeCliProvider.IDLE_TIMEOUT_NS) {
        return .{ .use_resume = false, .delta_start = 0, .reset_state = true };
    }

    const delta_start = transcriptResumeDeltaStart(state.transcript_hashes.items, messages, current_hashes) orelse {
        return .{ .use_resume = false, .delta_start = 0, .reset_state = true };
    };
    return .{
        .use_resume = true,
        .delta_start = delta_start,
        .reset_state = false,
    };
}

fn transcriptResumeDeltaStart(existing: []const u64, messages: []const ChatMessage, current: []const u64) ?usize {
    if (existing.len > current.len) return null;
    if (std.mem.eql(u64, existing, current[0..existing.len])) return existing.len;
    if (existing.len == 0 or existing.len > messages.len) return null;
    if (messages[existing.len - 1].role != .assistant) return null;
    if (existing.len > 1 and !std.mem.eql(u64, existing[0 .. existing.len - 1], current[0 .. existing.len - 1])) {
        return null;
    }
    return existing.len;
}

fn extractSystemPrompt(messages: []const ChatMessage) ?[]const u8 {
    for (messages) |msg| {
        if (msg.role == .system) return msg.content;
    }
    return null;
}

fn hashChatMessage(msg: ChatMessage) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(msg.role.toSlice());
    hasher.update("\x1f");
    hasher.update(msg.content);
    if (msg.name) |name| {
        hasher.update("\x1e");
        hasher.update(name);
    }
    if (msg.tool_call_id) |tool_call_id| {
        hasher.update("\x1d");
        hasher.update(tool_call_id);
    }
    return hasher.final();
}

fn hashAssistantResponse(content: []const u8) u64 {
    return hashChatMessage(ChatMessage.assistant(content));
}

fn collectMessageHashes(allocator: std.mem.Allocator, messages: []const ChatMessage) ![]u64 {
    const hashes = try allocator.alloc(u64, messages.len);
    for (messages, 0..) |msg, i| {
        hashes[i] = hashChatMessage(msg);
    }
    return hashes;
}

fn renderPromptMessages(allocator: std.mem.Allocator, messages: []const ChatMessage, start_index: usize) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    var wrote_any = false;
    for (messages[start_index..]) |msg| {
        if (msg.role == .system) continue;

        if (wrote_any) try buf.appendSlice(allocator, "\n\n");
        wrote_any = true;

        switch (msg.role) {
            .user => try buf.appendSlice(allocator, "User:\n"),
            .assistant => try buf.appendSlice(allocator, "Assistant:\n"),
            .tool => try buf.appendSlice(allocator, "Tool result:\n"),
            .system => unreachable,
        }
        try buf.appendSlice(allocator, msg.content);
    }

    if (!wrote_any) return error.NoUserMessage;
    return try buf.toOwnedSlice(allocator);
}

fn runClaudeCommand(allocator: std.mem.Allocator, opts: ClaudeCliProvider.ClaudeCommandOptions) !ClaudeCliProvider.ClaudeCommandResult {
    var argv: [14][]const u8 = undefined;
    var argc: usize = 0;

    argv[argc] = ClaudeCliProvider.CLI_NAME;
    argc += 1;
    argv[argc] = "-p";
    argc += 1;
    argv[argc] = opts.prompt;
    argc += 1;
    argv[argc] = "--output-format";
    argc += 1;
    argv[argc] = "stream-json";
    argc += 1;
    argv[argc] = "--model";
    argc += 1;
    argv[argc] = opts.model;
    argc += 1;
    if (opts.system_prompt) |system_prompt| {
        argv[argc] = "--system-prompt";
        argc += 1;
        argv[argc] = system_prompt;
        argc += 1;
    }
    if (opts.resume_session_id) |session_id| {
        argv[argc] = "--resume";
        argc += 1;
        argv[argc] = session_id;
        argc += 1;
    }
    argv[argc] = "--verbose";
    argc += 1;

    var child = std.process.Child.init(argv[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const stdout_result = child.stdout.?.readToEndAlloc(allocator, ClaudeCliProvider.MAX_OUTPUT_BYTES) catch |err| {
        _ = child.wait() catch {};
        return err;
    };
    defer allocator.free(stdout_result);

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CliProcessFailed;
        },
        else => return error.CliProcessFailed,
    }

    return parseStreamJson(allocator, stdout_result);
}

fn parseStreamJson(allocator: std.mem.Allocator, output: []const u8) !ClaudeCliProvider.ClaudeCommandResult {
    var lines = std.mem.splitScalar(u8, output, '\n');
    var session_id: ?[]u8 = null;
    errdefer if (session_id) |sid| allocator.free(sid);

    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
        defer parsed.deinit();

        if (parsed.value != .object) continue;
        const obj = parsed.value.object;

        const type_val = obj.get("type") orelse continue;
        if (type_val != .string) continue;

        if (std.mem.eql(u8, type_val.string, "system") or std.mem.eql(u8, type_val.string, "start")) {
            if (obj.get("session_id")) |session_val| {
                if (session_val == .string) {
                    const copy = try allocator.dupe(u8, session_val.string);
                    errdefer allocator.free(copy);
                    if (session_id) |old| allocator.free(old);
                    session_id = copy;
                }
            }
            continue;
        }

        if (!std.mem.eql(u8, type_val.string, "result")) continue;
        if (obj.get("result")) |result_val| {
            if (result_val == .string) {
                return .{
                    .result = try allocator.dupe(u8, result_val.string),
                    .session_id = session_id,
                };
            }
        }
    }

    return error.NoResultInOutput;
}

fn checkCliAvailable(allocator: std.mem.Allocator, cli_name: []const u8) !void {
    const argv = [_][]const u8{ "which", cli_name };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CliNotFound;
        },
        else => return error.CliNotFound,
    }
}

fn checkCliVersion(allocator: std.mem.Allocator, cli_name: []const u8) !void {
    const argv = [_][]const u8{ cli_name, "--version" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CliNotFound;
        },
        else => return error.CliNotFound,
    }
}

test "ClaudeCliProvider.getNameImpl returns claude-cli" {
    const vtable = ClaudeCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("claude-cli", vtable.getName(@ptrCast(&dummy)));
}

test "extractSystemPrompt returns first system message" {
    const msgs = [_]ChatMessage{
        ChatMessage.user("hello"),
        ChatMessage.system("Be concise"),
        ChatMessage.system("ignored"),
    };
    try std.testing.expectEqualStrings("Be concise", extractSystemPrompt(&msgs).?);
}

test "extractSystemPrompt returns null when absent" {
    const msgs = [_]ChatMessage{
        ChatMessage.user("hello"),
        ChatMessage.assistant("hi"),
    };
    try std.testing.expect(extractSystemPrompt(&msgs) == null);
}

test "renderPromptMessages renders transcript without system" {
    const msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.user("first"),
        ChatMessage.assistant("second"),
        ChatMessage.toolMsg("tool output", "tc1"),
    };

    const rendered = try renderPromptMessages(std.testing.allocator, &msgs, 0);
    defer std.testing.allocator.free(rendered);

    try std.testing.expectEqualStrings(
        "User:\nfirst\n\nAssistant:\nsecond\n\nTool result:\ntool output",
        rendered,
    );
}

test "renderPromptMessages respects delta start" {
    const msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.user("first"),
        ChatMessage.assistant("second"),
        ChatMessage.user("third"),
    };

    const rendered = try renderPromptMessages(std.testing.allocator, &msgs, 2);
    defer std.testing.allocator.free(rendered);

    try std.testing.expectEqualStrings("Assistant:\nsecond\n\nUser:\nthird", rendered);
}

test "renderPromptMessages rejects all-system delta" {
    const msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
    };
    try std.testing.expectError(error.NoUserMessage, renderPromptMessages(std.testing.allocator, &msgs, 0));
}

test "buildSessionPlan resumes only when transcript is still a prefix" {
    var state = ClaudeCliProvider.SessionState{};
    defer state.deinit(std.testing.allocator);
    const msgs = [_]ChatMessage{
        ChatMessage.user("first"),
        ChatMessage.assistant("second"),
        ChatMessage.user("third"),
    };

    try state.replaceSessionId(std.testing.allocator, "sess-1");
    try state.transcript_hashes.appendSlice(std.testing.allocator, &.{ 1, 2, 3 });
    state.last_active_ns = std.time.nanoTimestamp();

    const plan = buildSessionPlan(&state, &msgs, &.{ 1, 2, 3, 4 }, std.time.nanoTimestamp());
    try std.testing.expect(plan.use_resume);
    try std.testing.expectEqual(@as(usize, 3), plan.delta_start);
    try std.testing.expect(!plan.reset_state);
}

test "buildSessionPlan resets on diverged history" {
    var state = ClaudeCliProvider.SessionState{};
    defer state.deinit(std.testing.allocator);
    const msgs = [_]ChatMessage{
        ChatMessage.user("first"),
        ChatMessage.assistant("second"),
        ChatMessage.user("third"),
    };

    try state.replaceSessionId(std.testing.allocator, "sess-1");
    try state.transcript_hashes.appendSlice(std.testing.allocator, &.{ 9, 2 });
    state.last_active_ns = std.time.nanoTimestamp();

    const plan = buildSessionPlan(&state, &msgs, &.{ 1, 2, 3 }, std.time.nanoTimestamp());
    try std.testing.expect(!plan.use_resume);
    try std.testing.expect(plan.reset_state);
}

test "buildSessionPlan resets on idle timeout" {
    var state = ClaudeCliProvider.SessionState{};
    defer state.deinit(std.testing.allocator);
    const msgs = [_]ChatMessage{
        ChatMessage.user("first"),
        ChatMessage.assistant("second"),
    };

    try state.replaceSessionId(std.testing.allocator, "sess-1");
    try state.transcript_hashes.appendSlice(std.testing.allocator, &.{1});
    state.last_active_ns = std.time.nanoTimestamp() - ClaudeCliProvider.IDLE_TIMEOUT_NS - std.time.ns_per_s;

    const plan = buildSessionPlan(&state, &msgs, &.{ 1, 2 }, std.time.nanoTimestamp());
    try std.testing.expect(!plan.use_resume);
    try std.testing.expect(plan.reset_state);
}

test "buildSessionPlan tolerates normalized assistant history mismatch" {
    var state = ClaudeCliProvider.SessionState{};
    defer state.deinit(std.testing.allocator);
    const msgs = [_]ChatMessage{
        ChatMessage.user("first"),
        ChatMessage.assistant("normalized"),
        ChatMessage.user("third"),
    };

    try state.replaceSessionId(std.testing.allocator, "sess-1");
    try state.transcript_hashes.appendSlice(std.testing.allocator, &.{ 1, 99 });
    state.last_active_ns = std.time.nanoTimestamp();

    const plan = buildSessionPlan(&state, &msgs, &.{ 1, 2, 3 }, std.time.nanoTimestamp());
    try std.testing.expect(plan.use_resume);
    try std.testing.expectEqual(@as(usize, 2), plan.delta_start);
    try std.testing.expect(!plan.reset_state);
}

test "deleteSessionStateLocked removes stored session state" {
    var provider = ClaudeCliProvider{
        .allocator = std.testing.allocator,
        .model = "test-model",
    };
    defer provider.provider().deinit();

    provider.mutex.lock();
    defer provider.mutex.unlock();

    _ = try provider.getOrCreateSessionStateLocked("chat-1");
    try std.testing.expect(provider.sessions.count() == 1);

    provider.deleteSessionStateLocked("chat-1");
    try std.testing.expect(provider.sessions.count() == 0);
}

test "SessionState updateTranscript appends assistant response hash" {
    var state = ClaudeCliProvider.SessionState{};
    defer state.deinit(std.testing.allocator);

    try state.updateTranscript(std.testing.allocator, &.{ 11, 22 }, "assistant reply", "sess-2", 123);
    try std.testing.expectEqual(@as(usize, 3), state.transcript_hashes.items.len);
    try std.testing.expectEqual(@as(i128, 123), state.last_active_ns);
    try std.testing.expectEqualStrings("sess-2", state.cli_session_id.?);
    try std.testing.expectEqual(hashAssistantResponse("assistant reply"), state.transcript_hashes.items[2]);
}

test "parseStreamJson extracts result and session id from start event" {
    const input =
        \\{"type":"start","session_id":"abc123"}
        \\{"type":"result","result":"Hello from Claude CLI!"}
    ;
    const result = try parseStreamJson(std.testing.allocator, input);
    defer {
        std.testing.allocator.free(result.result);
        if (result.session_id) |sid| std.testing.allocator.free(sid);
    }
    try std.testing.expectEqualStrings("Hello from Claude CLI!", result.result);
    try std.testing.expectEqualStrings("abc123", result.session_id.?);
}

test "parseStreamJson extracts session id from system event" {
    const input =
        \\{"type":"system","session_id":"sys-456"}
        \\{"type":"result","result":"ok"}
    ;
    const result = try parseStreamJson(std.testing.allocator, input);
    defer {
        std.testing.allocator.free(result.result);
        if (result.session_id) |sid| std.testing.allocator.free(sid);
    }
    try std.testing.expectEqualStrings("sys-456", result.session_id.?);
}

test "parseStreamJson no result returns error" {
    const input =
        \\{"type":"start","session_id":"abc123"}
        \\{"type":"content","content":"partial"}
    ;
    try std.testing.expectError(error.NoResultInOutput, parseStreamJson(std.testing.allocator, input));
}

test "parseStreamJson handles invalid json lines gracefully" {
    const input =
        \\not json at all
        \\{"type":"result","result":"found it"}
    ;
    const result = try parseStreamJson(std.testing.allocator, input);
    defer std.testing.allocator.free(result.result);
    try std.testing.expectEqualStrings("found it", result.result);
    try std.testing.expect(result.session_id == null);
}

test "ClaudeCliProvider vtable has correct function pointers" {
    const vtable = ClaudeCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("claude-cli", vtable.getName(@ptrCast(&dummy)));
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
    try std.testing.expect(vtable.supports_vision != null);
    try std.testing.expect(!vtable.supports_vision.?(@ptrCast(&dummy)));
}

test "ClaudeCliProvider.init returns CliNotFound for missing binary" {
    const result = checkCliAvailable(std.testing.allocator, "nonexistent_binary_xyzzy_12345");
    try std.testing.expectError(error.CliNotFound, result);
}

test "ClaudeCliProvider default model is claude-opus-4-6" {
    try std.testing.expectEqualStrings("claude-opus-4-6", ClaudeCliProvider.DEFAULT_MODEL);
}
