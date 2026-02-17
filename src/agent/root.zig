//! Agent core — main loop, tool execution, conversation management.
//!
//! Mirrors ZeroClaw's agent module: Agent struct, tool call loop,
//! system prompt construction, history management, single and interactive modes.

const std = @import("std");
const Config = @import("../config.zig").Config;
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const ChatMessage = providers.ChatMessage;
const ChatRequest = providers.ChatRequest;
const ChatResponse = providers.ChatResponse;
const ToolSpec = providers.ToolSpec;
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;
const ToolResult = tools_mod.ToolResult;
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const MemoryCategory = memory_mod.MemoryCategory;
const observability = @import("../observability.zig");
const Observer = observability.Observer;
const ObserverEvent = observability.ObserverEvent;

pub const dispatcher = @import("dispatcher.zig");
pub const prompt = @import("prompt.zig");
pub const memory_loader = @import("memory_loader.zig");

const ParsedToolCall = dispatcher.ParsedToolCall;
const ToolExecutionResult = dispatcher.ToolExecutionResult;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum agentic tool-use iterations per user message.
const DEFAULT_MAX_TOOL_ITERATIONS: u32 = 10;

/// Maximum non-system messages before trimming.
const DEFAULT_MAX_HISTORY: u32 = 50;

/// Keep this many most-recent non-system messages after compaction.
const COMPACTION_KEEP_RECENT: u32 = 20;

/// Max characters retained in stored compaction summary.
const COMPACTION_MAX_SUMMARY_CHARS: usize = 2_000;

/// Max characters in source transcript passed to the summarizer.
const COMPACTION_MAX_SOURCE_CHARS: usize = 12_000;

// ═══════════════════════════════════════════════════════════════════════════
// Agent
// ═══════════════════════════════════════════════════════════════════════════

pub const Agent = struct {
    allocator: std.mem.Allocator,
    provider: Provider,
    tools: []const Tool,
    tool_specs: []const ToolSpec,
    mem: ?Memory,
    observer: Observer,
    model_name: []const u8,
    temperature: f64,
    workspace_dir: []const u8,
    max_tool_iterations: u32,
    max_history_messages: u32,
    auto_save: bool,

    /// Conversation history — owned, growable list.
    history: std.ArrayListUnmanaged(OwnedMessage),

    /// Total tokens used across all turns.
    total_tokens: u64,

    /// Whether the system prompt has been injected.
    has_system_prompt: bool,

    /// An owned copy of a ChatMessage, where content is heap-allocated.
    const OwnedMessage = struct {
        role: providers.Role,
        content: []const u8,

        fn deinit(self: *const OwnedMessage, allocator: std.mem.Allocator) void {
            allocator.free(self.content);
        }

        fn toChatMessage(self: *const OwnedMessage) ChatMessage {
            return .{ .role = self.role, .content = self.content };
        }
    };

    /// Initialize agent from a loaded Config.
    pub fn fromConfig(
        allocator: std.mem.Allocator,
        cfg: *const Config,
        provider_i: Provider,
        tools: []const Tool,
        mem: ?Memory,
        observer_i: Observer,
    ) !Agent {
        // Build tool specs for function-calling APIs
        const specs = try allocator.alloc(ToolSpec, tools.len);
        for (tools, 0..) |t, i| {
            specs[i] = t.spec();
        }

        return .{
            .allocator = allocator,
            .provider = provider_i,
            .tools = tools,
            .tool_specs = specs,
            .mem = mem,
            .observer = observer_i,
            .model_name = cfg.default_model orelse "anthropic/claude-sonnet-4",
            .temperature = cfg.default_temperature,
            .workspace_dir = cfg.workspace_dir,
            .max_tool_iterations = cfg.agent.max_tool_iterations,
            .max_history_messages = cfg.agent.max_history_messages,
            .auto_save = cfg.memory.auto_save,
            .history = .empty,
            .total_tokens = 0,
            .has_system_prompt = false,
        };
    }

    pub fn deinit(self: *Agent) void {
        for (self.history.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.history.deinit(self.allocator);
        self.allocator.free(self.tool_specs);
    }

    /// Build a compaction transcript from a slice of history messages.
    fn buildCompactionTranscript(self: *Agent, start: usize, end: usize) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);

        for (self.history.items[start..end]) |*msg| {
            const role_str: []const u8 = switch (msg.role) {
                .system => "SYSTEM",
                .user => "USER",
                .assistant => "ASSISTANT",
                .tool => "TOOL",
            };
            try buf.appendSlice(self.allocator, role_str);
            try buf.appendSlice(self.allocator, ": ");
            // Truncate very long messages in transcript
            const content = if (msg.content.len > 500) msg.content[0..500] else msg.content;
            try buf.appendSlice(self.allocator, content);
            try buf.append(self.allocator, '\n');

            // Safety cap
            if (buf.items.len > COMPACTION_MAX_SOURCE_CHARS) break;
        }

        if (buf.items.len > COMPACTION_MAX_SOURCE_CHARS) {
            buf.items.len = COMPACTION_MAX_SOURCE_CHARS;
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// Auto-compact history when it exceeds max_history_messages.
    /// Uses the LLM provider to summarize older messages, replacing them
    /// with a single summary system message. Keeps system prompt + summary + recent N messages.
    /// Returns true if compaction was performed.
    pub fn autoCompactHistory(self: *Agent) !bool {
        const has_system = self.history.items.len > 0 and self.history.items[0].role == .system;
        const start: usize = if (has_system) 1 else 0;
        const non_system_count = self.history.items.len - start;

        if (non_system_count <= self.max_history_messages) return false;

        const keep_recent = @min(COMPACTION_KEEP_RECENT, @as(u32, @intCast(non_system_count)));
        const compact_count = non_system_count - keep_recent;
        if (compact_count == 0) return false;

        const compact_end = start + compact_count;

        // Build transcript of messages to compact
        const transcript = try self.buildCompactionTranscript(start, compact_end);
        defer self.allocator.free(transcript);

        // Try to summarize using the LLM
        const summary = blk: {
            // Build a summarization request
            const summarizer_system = "You are a conversation compaction engine. Summarize older chat history into concise context for future turns. Preserve: user preferences, commitments, decisions, unresolved tasks, key facts. Omit: filler, repeated chit-chat, verbose tool logs. Output plain text bullet points only.";
            const summarizer_user = try std.fmt.allocPrint(self.allocator, "Summarize the following conversation history for context preservation. Keep it short (max 12 bullet points).\n\n{s}", .{transcript});
            defer self.allocator.free(summarizer_user);

            var summary_messages: [2]ChatMessage = .{
                .{ .role = .system, .content = summarizer_system },
                .{ .role = .user, .content = summarizer_user },
            };

            const messages_slice = summary_messages[0..2];

            const summary_resp = self.provider.chat(
                self.allocator,
                .{
                    .messages = messages_slice,
                    .model = self.model_name,
                    .temperature = 0.2,
                    .tools = null,
                },
                self.model_name,
                0.2,
            ) catch {
                // Fallback: use a local truncation of the transcript
                const max_len = @min(transcript.len, COMPACTION_MAX_SUMMARY_CHARS);
                break :blk try self.allocator.dupe(u8, transcript[0..max_len]);
            };

            const raw_summary = summary_resp.contentOrEmpty();
            const max_len = @min(raw_summary.len, COMPACTION_MAX_SUMMARY_CHARS);
            break :blk try self.allocator.dupe(u8, raw_summary[0..max_len]);
        };
        defer self.allocator.free(summary);

        // Create the compaction summary message
        const summary_content = try std.fmt.allocPrint(self.allocator, "[Compaction summary]\n{s}", .{summary});

        // Free old messages being compacted
        for (self.history.items[start..compact_end]) |*msg| {
            msg.deinit(self.allocator);
        }

        // Replace compacted messages with summary
        self.history.items[start] = .{
            .role = .assistant,
            .content = summary_content,
        };

        // Shift remaining messages
        if (compact_end > start + 1) {
            const src = self.history.items[compact_end..];
            std.mem.copyForwards(OwnedMessage, self.history.items[start + 1 ..], src);
            self.history.items.len -= (compact_end - start - 1);
        }

        return true;
    }

    /// Execute a single conversation turn: send messages to LLM, parse tool calls,
    /// execute tools, and loop until a final text response is produced.
    pub fn turn(self: *Agent, user_message: []const u8) ![]const u8 {
        // Inject system prompt on first turn
        if (!self.has_system_prompt) {
            const system_prompt = try prompt.buildSystemPrompt(self.allocator, .{
                .workspace_dir = self.workspace_dir,
                .model_name = self.model_name,
                .tools = self.tools,
            });
            defer self.allocator.free(system_prompt);

            // Append tool instructions
            const tool_instructions = try dispatcher.buildToolInstructions(self.allocator, self.tools);
            defer self.allocator.free(tool_instructions);

            const full_system = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ system_prompt, tool_instructions });

            try self.history.append(self.allocator, .{
                .role = .system,
                .content = full_system,
            });
            self.has_system_prompt = true;
        }

        // Auto-save user message to memory
        if (self.auto_save) {
            if (self.mem) |mem| {
                mem.store("user_msg", user_message, .conversation) catch {};
            }
        }

        // Enrich message with memory context
        const enriched = if (self.mem) |mem|
            try memory_loader.enrichMessage(self.allocator, mem, user_message)
        else
            try self.allocator.dupe(u8, user_message);
        defer self.allocator.free(enriched);

        try self.history.append(self.allocator, .{
            .role = .user,
            .content = try self.allocator.dupe(u8, enriched),
        });

        // Record agent event
        const start_event = ObserverEvent{ .llm_request = .{
            .provider = self.provider.getName(),
            .model = self.model_name,
            .messages_count = self.history.items.len,
        } };
        self.observer.recordEvent(&start_event);

        // Tool call loop
        var iteration: u32 = 0;
        while (iteration < self.max_tool_iterations) : (iteration += 1) {
            // Build messages slice for provider
            const messages = try self.buildMessageSlice();
            defer self.allocator.free(messages);

            const timer_start = std.time.milliTimestamp();

            // Call provider with error recovery (retry once on failure)
            const response = self.provider.chat(
                self.allocator,
                .{
                    .messages = messages,
                    .model = self.model_name,
                    .temperature = self.temperature,
                    .tools = if (self.provider.supportsNativeTools()) self.tool_specs else null,
                },
                self.model_name,
                self.temperature,
            ) catch |err| retry_blk: {
                // Record the failed attempt
                const fail_duration: u64 = @intCast(std.time.milliTimestamp() - timer_start);
                const fail_event = ObserverEvent{ .llm_response = .{
                    .provider = self.provider.getName(),
                    .model = self.model_name,
                    .duration_ms = fail_duration,
                    .success = false,
                    .error_message = @errorName(err),
                } };
                self.observer.recordEvent(&fail_event);

                // Retry once
                std.time.sleep(500 * std.time.ns_per_ms);
                break :retry_blk self.provider.chat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .model = self.model_name,
                        .temperature = self.temperature,
                        .tools = if (self.provider.supportsNativeTools()) self.tool_specs else null,
                    },
                    self.model_name,
                    self.temperature,
                ) catch |retry_err| {
                    return retry_err;
                };
            };

            const duration_ms: u64 = @intCast(std.time.milliTimestamp() - timer_start);
            const resp_event = ObserverEvent{ .llm_response = .{
                .provider = self.provider.getName(),
                .model = self.model_name,
                .duration_ms = duration_ms,
                .success = true,
                .error_message = null,
            } };
            self.observer.recordEvent(&resp_event);

            // Track tokens
            self.total_tokens += response.usage.total_tokens;

            // Parse tool calls from response
            const response_text = response.contentOrEmpty();

            const parsed = try dispatcher.parseToolCalls(self.allocator, response_text);
            defer {
                if (parsed.text.len > 0) self.allocator.free(parsed.text);
                for (parsed.calls) |call| {
                    self.allocator.free(call.name);
                    self.allocator.free(call.arguments_json);
                }
                self.allocator.free(parsed.calls);
            }

            if (parsed.calls.len == 0) {
                // No tool calls — final response
                const final_text = if (parsed.text.len > 0)
                    try self.allocator.dupe(u8, parsed.text)
                else
                    try self.allocator.dupe(u8, response_text);

                try self.history.append(self.allocator, .{
                    .role = .assistant,
                    .content = try self.allocator.dupe(u8, final_text),
                });

                // Auto-compaction before hard trimming to preserve context
                _ = self.autoCompactHistory() catch false;
                self.trimHistory();

                // Auto-save assistant response
                if (self.auto_save) {
                    if (self.mem) |mem| {
                        const summary = if (final_text.len > 100) final_text[0..100] else final_text;
                        mem.store("assistant_resp", summary, .daily) catch {};
                    }
                }

                const complete_event = ObserverEvent{ .turn_complete = {} };
                self.observer.recordEvent(&complete_event);

                return final_text;
            }

            // There are tool calls — add assistant's response to history
            if (parsed.text.len > 0) {
                // Print intermediary text to stdout
                var out_buf: [4096]u8 = undefined;
                var bw = std.fs.File.stdout().writer(&out_buf);
                const w = &bw.interface;
                w.print("{s}", .{parsed.text}) catch {};
                w.flush() catch {};
            }

            // Record assistant message with tool calls in history
            try self.history.append(self.allocator, .{
                .role = .assistant,
                .content = try self.allocator.dupe(u8, response_text),
            });

            // Execute each tool call
            var results_buf: std.ArrayListUnmanaged(ToolExecutionResult) = .empty;
            defer results_buf.deinit(self.allocator);

            for (parsed.calls) |call| {
                const tool_start_event = ObserverEvent{ .tool_call_start = .{ .tool = call.name } };
                self.observer.recordEvent(&tool_start_event);

                const tool_timer = std.time.milliTimestamp();
                const result = self.executeTool(call);
                const tool_duration: u64 = @intCast(std.time.milliTimestamp() - tool_timer);

                const tool_event = ObserverEvent{ .tool_call = .{
                    .tool = call.name,
                    .duration_ms = tool_duration,
                    .success = result.success,
                } };
                self.observer.recordEvent(&tool_event);

                try results_buf.append(self.allocator, result);
            }

            // Format tool results and add to history
            const formatted_results = try dispatcher.formatToolResults(self.allocator, results_buf.items);
            try self.history.append(self.allocator, .{
                .role = .user,
                .content = formatted_results,
            });

            self.trimHistory();
        }

        return error.MaxToolIterationsExceeded;
    }

    /// Execute a tool by name lookup.
    fn executeTool(self: *Agent, call: ParsedToolCall) ToolExecutionResult {
        for (self.tools) |t| {
            if (std.mem.eql(u8, t.name(), call.name)) {
                const result = t.execute(self.allocator, call.arguments_json) catch |err| {
                    return .{
                        .name = call.name,
                        .output = @errorName(err),
                        .success = false,
                        .tool_call_id = call.tool_call_id,
                    };
                };
                return .{
                    .name = call.name,
                    .output = if (result.success) result.output else (result.error_msg orelse result.output),
                    .success = result.success,
                    .tool_call_id = call.tool_call_id,
                };
            }
        }

        return .{
            .name = call.name,
            .output = "Unknown tool",
            .success = false,
            .tool_call_id = call.tool_call_id,
        };
    }

    /// Build a flat ChatMessage slice from owned history.
    fn buildMessageSlice(self: *Agent) ![]ChatMessage {
        const messages = try self.allocator.alloc(ChatMessage, self.history.items.len);
        for (self.history.items, 0..) |*msg, i| {
            messages[i] = msg.toChatMessage();
        }
        return messages;
    }

    /// Trim history to prevent unbounded growth.
    /// Preserves the system prompt (first message) and the most recent messages.
    fn trimHistory(self: *Agent) void {
        const max = self.max_history_messages;
        if (self.history.items.len <= max + 1) return; // +1 for system prompt

        const has_system = self.history.items.len > 0 and self.history.items[0].role == .system;
        const start: usize = if (has_system) 1 else 0;
        const non_system_count = self.history.items.len - start;

        if (non_system_count <= max) return;

        const to_remove = non_system_count - max;
        // Free the messages being removed
        for (self.history.items[start .. start + to_remove]) |*msg| {
            msg.deinit(self.allocator);
        }

        // Shift remaining elements
        const src = self.history.items[start + to_remove ..];
        std.mem.copyForwards(OwnedMessage, self.history.items[start..], src);
        self.history.items.len -= to_remove;
    }

    /// Run a single message through the agent and return the response.
    pub fn runSingle(self: *Agent, message: []const u8) ![]const u8 {
        return self.turn(message);
    }

    /// Clear conversation history (for starting a new session).
    pub fn clearHistory(self: *Agent) void {
        for (self.history.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.history.items.len = 0;
        self.has_system_prompt = false;
    }

    /// Get total tokens used.
    pub fn tokensUsed(self: *const Agent) u64 {
        return self.total_tokens;
    }

    /// Get current history length.
    pub fn historyLen(self: *const Agent) usize {
        return self.history.items.len;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Top-level run() — entry point for CLI
// ═══════════════════════════════════════════════════════════════════════════

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    const cfg = Config.load(allocator) catch {
        std.debug.print("No config found. Run `nullclaw onboard` first.\n", .{});
        return;
    };

    var out_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&out_buf);
    const w = &bw.interface;

    // Create a noop observer
    var noop = observability.NoopObserver{};
    const obs = noop.observer();

    // Record agent start
    const start_event = ObserverEvent{ .agent_start = .{
        .provider = cfg.default_provider,
        .model = cfg.default_model orelse "(default)",
    } };
    obs.recordEvent(&start_event);

    // Create tools
    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .browser_enabled = cfg.browser.enabled,
    });
    defer allocator.free(tools);

    // Create memory (optional — don't fail if it can't init)
    var mem_opt: ?Memory = null;
    const db_path = try std.fs.path.joinZ(allocator, &.{ cfg.workspace_dir, "memory.db" });
    defer allocator.free(db_path);
    if (memory_mod.createMemory(allocator, cfg.memory.backend, db_path)) |mem| {
        mem_opt = mem;
    } else |_| {}

    // Create provider — use the legacy complete() for now since the full vtable
    // provider factory requires HTTP client initialization that's still in progress.
    // For the agent module, we need the Provider vtable interface.
    // Fall back to printing an error if provider creation fails.

    // Single message mode: nullclaw agent -m "hello"
    if (args.len >= 2 and (std.mem.eql(u8, args[0], "-m") or std.mem.eql(u8, args[0], "--message"))) {
        const message = args[1];
        try w.print("Sending to {s}...\n", .{cfg.default_provider});
        try w.flush();

        // Use legacy provider path for single messages
        const response = try providers.complete(allocator, &cfg, message);
        defer allocator.free(response);
        try w.print("{s}\n", .{response});
        try w.flush();
        return;
    }

    // Interactive REPL mode
    try w.print("nullclaw Agent -- Interactive Mode\n", .{});
    try w.print("Provider: {s} | Model: {s}\n", .{
        cfg.default_provider,
        cfg.default_model orelse "(default)",
    });
    try w.print("Type your message (Ctrl+D to exit):\n\n", .{});
    try w.flush();

    const stdin = std.fs.File.stdin();
    var line_buf: [4096]u8 = undefined;

    while (true) {
        try w.print("> ", .{});
        try w.flush();

        // Read a line from stdin byte-by-byte
        var pos: usize = 0;
        while (pos < line_buf.len) {
            const n = stdin.read(line_buf[pos .. pos + 1]) catch return;
            if (n == 0) return; // EOF
            if (line_buf[pos] == '\n') break;
            pos += 1;
        }
        const line = line_buf[0..pos];

        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "exit") or std.mem.eql(u8, line, "quit")) return;

        // Use legacy provider path for REPL
        const response = providers.complete(allocator, &cfg, line) catch |err| {
            try w.print("Error: {}\n", .{err});
            try w.flush();
            continue;
        };
        defer allocator.free(response);
        try w.print("\n{s}\n\n", .{response});
        try w.flush();
    }
}

/// Process a single message through the full agent pipeline (for channel use).
/// Returns the agent's response. Caller owns the returned string.
pub fn processMessage(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    provider_i: Provider,
    tools: []const Tool,
    mem: ?Memory,
    observer_i: Observer,
    message: []const u8,
) ![]const u8 {
    var agent = try Agent.fromConfig(allocator, cfg, provider_i, tools, mem, observer_i);
    defer agent.deinit();

    return agent.turn(message);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "Agent.OwnedMessage toChatMessage" {
    const msg = Agent.OwnedMessage{
        .role = .user,
        .content = "hello",
    };
    const chat = msg.toChatMessage();
    try std.testing.expect(chat.role == .user);
    try std.testing.expectEqualStrings("hello", chat.content);
}

test "Agent trim history preserves system prompt" {
    const allocator = std.testing.allocator;

    // Create a minimal agent config
    const cfg = Config{
        .workspace_dir = "/tmp/yc_test",
        .config_path = "/tmp/yc_test/config.json",
        .allocator = allocator,
    };

    var noop = observability.NoopObserver{};

    // We can't create a real provider in tests, but we can test trimHistory
    // by creating an Agent with minimal fields
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = cfg.default_model orelse "test",
        .temperature = 0.7,
        .workspace_dir = cfg.workspace_dir,
        .max_tool_iterations = 10,
        .max_history_messages = 5,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    // Add system prompt
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "system prompt"),
    });

    // Add more messages than max
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try agent.history.append(allocator, .{
            .role = .user,
            .content = try std.fmt.allocPrint(allocator, "msg {d}", .{i}),
        });
    }

    try std.testing.expect(agent.history.items.len == 11); // 1 system + 10 user

    agent.trimHistory();

    // System prompt should be preserved
    try std.testing.expect(agent.history.items[0].role == .system);
    try std.testing.expectEqualStrings("system prompt", agent.history.items[0].content);

    // Should be trimmed to max + 1 (system)
    try std.testing.expect(agent.history.items.len <= 6); // 1 system + 5 messages

    // Most recent message should be the last one added
    const last = agent.history.items[agent.history.items.len - 1];
    try std.testing.expectEqualStrings("msg 9", last.content);
}

test "Agent clear history" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = true,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());

    agent.clearHistory();

    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expect(!agent.has_system_prompt);
}

test "dispatcher module reexport" {
    // Verify dispatcher types are accessible
    _ = dispatcher.ParsedToolCall;
    _ = dispatcher.ToolExecutionResult;
    _ = dispatcher.parseToolCalls;
    _ = dispatcher.formatToolResults;
    _ = dispatcher.buildToolInstructions;
}

test "prompt module reexport" {
    _ = prompt.buildSystemPrompt;
    _ = prompt.PromptContext;
}

test "memory_loader module reexport" {
    _ = memory_loader.loadContext;
    _ = memory_loader.enrichMessage;
}

test {
    _ = dispatcher;
    _ = prompt;
    _ = memory_loader;
}

// ── Additional agent tests ──────────────────────────────────────

test "Agent.OwnedMessage system role" {
    const msg = Agent.OwnedMessage{
        .role = .system,
        .content = "system prompt",
    };
    const chat = msg.toChatMessage();
    try std.testing.expect(chat.role == .system);
    try std.testing.expectEqualStrings("system prompt", chat.content);
}

test "Agent.OwnedMessage assistant role" {
    const msg = Agent.OwnedMessage{
        .role = .assistant,
        .content = "I can help with that.",
    };
    const chat = msg.toChatMessage();
    try std.testing.expect(chat.role == .assistant);
    try std.testing.expectEqualStrings("I can help with that.", chat.content);
}

test "Agent initial state" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.5,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expectEqual(@as(u64, 0), agent.tokensUsed());
    try std.testing.expect(!agent.has_system_prompt);
}

test "Agent tokens tracking" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    agent.total_tokens = 100;
    try std.testing.expectEqual(@as(u64, 100), agent.tokensUsed());
    agent.total_tokens += 50;
    try std.testing.expectEqual(@as(u64, 150), agent.tokensUsed());
}

test "Agent trimHistory no-op when under limit" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    agent.trimHistory();
    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());
}

test "Agent trimHistory without system prompt" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 3,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    // Add 6 user messages (no system prompt)
    for (0..6) |i| {
        try agent.history.append(allocator, .{
            .role = .user,
            .content = try std.fmt.allocPrint(allocator, "msg {d}", .{i}),
        });
    }

    agent.trimHistory();
    // Should trim to max_history_messages (3) + 1 for system = 4, but no system
    try std.testing.expect(agent.history.items.len <= 4);
}

test "Agent clearHistory resets all state" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = true,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "system"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });
    try agent.history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "hi"),
    });

    try std.testing.expectEqual(@as(usize, 3), agent.historyLen());
    try std.testing.expect(agent.has_system_prompt);

    agent.clearHistory();

    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expect(!agent.has_system_prompt);
}

test "Agent buildMessageSlice" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    const messages = try agent.buildMessageSlice();
    defer allocator.free(messages);

    try std.testing.expectEqual(@as(usize, 2), messages.len);
    try std.testing.expect(messages[0].role == .system);
    try std.testing.expect(messages[1].role == .user);
    try std.testing.expectEqualStrings("sys", messages[0].content);
    try std.testing.expectEqualStrings("hello", messages[1].content);
}

test "Agent max_tool_iterations default" {
    try std.testing.expectEqual(@as(u32, 10), DEFAULT_MAX_TOOL_ITERATIONS);
}

test "Agent max_history default" {
    try std.testing.expectEqual(@as(u32, 50), DEFAULT_MAX_HISTORY);
}

test "Agent trimHistory keeps most recent messages" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 3,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    // Add system + 5 messages
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "system"),
    });
    for (0..5) |i| {
        try agent.history.append(allocator, .{
            .role = .user,
            .content = try std.fmt.allocPrint(allocator, "msg-{d}", .{i}),
        });
    }

    agent.trimHistory();

    // Should keep system + last 3 messages
    try std.testing.expectEqual(@as(usize, 4), agent.historyLen());
    try std.testing.expect(agent.history.items[0].role == .system);
    // Last message should be msg-4
    try std.testing.expectEqualStrings("msg-4", agent.history.items[3].content);
}

test "Agent clearHistory then add messages" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = true,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "old"),
    });
    agent.clearHistory();

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "new"),
    });
    try std.testing.expectEqual(@as(usize, 1), agent.historyLen());
    try std.testing.expectEqualStrings("new", agent.history.items[0].content);
}
