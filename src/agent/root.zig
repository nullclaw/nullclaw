//! Agent core — main loop, tool execution, conversation management.
//!
//! Mirrors ZeroClaw's agent module: Agent struct, tool call loop,
//! system prompt construction, history management, single and interactive modes.

const std = @import("std");
const log = std.log.scoped(.agent);
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
const cli_mod = @import("../channels/cli.zig");

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

/// Default token limit for context window (used by token-based compaction trigger).
pub const DEFAULT_TOKEN_LIMIT: u64 = 128_000;

/// Minimum history length before context exhaustion recovery is attempted.
const CONTEXT_RECOVERY_MIN_HISTORY: usize = 6;

/// Number of recent messages to keep during force compression.
const CONTEXT_RECOVERY_KEEP: usize = 4;

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
    model_name_owned: bool = false,
    temperature: f64,
    workspace_dir: []const u8,
    max_tool_iterations: u32,
    max_history_messages: u32,
    auto_save: bool,
    token_limit: u64 = 0,

    /// Optional streaming callback. When set, turn() uses streamChat() for streaming providers.
    stream_callback: ?providers.StreamCallback = null,
    /// Context pointer passed to stream_callback.
    stream_ctx: ?*anyopaque = null,

    /// Conversation history — owned, growable list.
    history: std.ArrayListUnmanaged(OwnedMessage) = .empty,

    /// Total tokens used across all turns.
    total_tokens: u64 = 0,

    /// Whether the system prompt has been injected.
    has_system_prompt: bool = false,

    /// Whether compaction was performed during the last turn.
    last_turn_compacted: bool = false,

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
            specs[i] = .{
                .name = t.name(),
                .description = t.description(),
                .parameters_json = t.parametersJson(),
            };
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
            .token_limit = cfg.agent.token_limit,
            .history = .empty,
            .total_tokens = 0,
            .has_system_prompt = false,
            .last_turn_compacted = false,
        };
    }

    pub fn deinit(self: *Agent) void {
        if (self.model_name_owned) self.allocator.free(self.model_name);
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

    /// Estimate total tokens in conversation history using heuristic: (total_chars + 3) / 4.
    pub fn tokenEstimate(self: *const Agent) u64 {
        var total_chars: u64 = 0;
        for (self.history.items) |*msg| {
            total_chars += msg.content.len;
        }
        return (total_chars + 3) / 4;
    }

    /// Summarize a slice of history messages via the LLM provider.
    /// Returns an owned summary string. Falls back to transcript truncation on error.
    fn summarizeSlice(self: *Agent, start: usize, end: usize) ![]u8 {
        const transcript = try self.buildCompactionTranscript(start, end);
        defer self.allocator.free(transcript);

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
            return try self.allocator.dupe(u8, transcript[0..max_len]);
        };
        // Free response's heap-allocated fields after extracting what we need
        defer {
            if (summary_resp.content) |c| {
                if (c.len > 0) self.allocator.free(c);
            }
            if (summary_resp.model.len > 0) self.allocator.free(summary_resp.model);
            if (summary_resp.reasoning_content) |rc| {
                if (rc.len > 0) self.allocator.free(rc);
            }
        }

        const raw_summary = summary_resp.contentOrEmpty();
        const max_len = @min(raw_summary.len, COMPACTION_MAX_SUMMARY_CHARS);
        return try self.allocator.dupe(u8, raw_summary[0..max_len]);
    }

    /// Auto-compact history when it exceeds max_history_messages or when
    /// estimated token usage exceeds 75% of the configured token limit.
    /// For large histories (>10 messages to summarize), uses multi-part strategy:
    /// splits into halves, summarizes each independently, then merges.
    /// Returns true if compaction was performed.
    pub fn autoCompactHistory(self: *Agent) !bool {
        const has_system = self.history.items.len > 0 and self.history.items[0].role == .system;
        const start: usize = if (has_system) 1 else 0;
        const non_system_count = self.history.items.len - start;

        // Trigger on message count exceeding threshold
        const count_trigger = non_system_count > self.max_history_messages;

        // Trigger on token estimate exceeding 75% of token limit
        const token_threshold = (self.token_limit * 3) / 4;
        const token_trigger = self.token_limit > 0 and self.tokenEstimate() > token_threshold;

        if (!count_trigger and !token_trigger) return false;

        const keep_recent = @min(COMPACTION_KEEP_RECENT, @as(u32, @intCast(non_system_count)));
        const compact_count = non_system_count - keep_recent;
        if (compact_count == 0) return false;

        const compact_end = start + compact_count;

        // Multi-part strategy: if >10 messages to summarize, split into halves
        const summary = if (compact_count > 10) blk: {
            const mid = start + compact_count / 2;

            // Summarize first half
            const summary_a = try self.summarizeSlice(start, mid);
            defer self.allocator.free(summary_a);

            // Summarize second half
            const summary_b = try self.summarizeSlice(mid, compact_end);
            defer self.allocator.free(summary_b);

            // Merge the two summaries
            const merged = try std.fmt.allocPrint(
                self.allocator,
                "Earlier context:\n{s}\n\nMore recent context:\n{s}",
                .{ summary_a, summary_b },
            );

            // Truncate if too long
            if (merged.len > COMPACTION_MAX_SUMMARY_CHARS) {
                const truncated = try self.allocator.dupe(u8, merged[0..COMPACTION_MAX_SUMMARY_CHARS]);
                self.allocator.free(merged);
                break :blk truncated;
            }

            break :blk merged;
        } else try self.summarizeSlice(start, compact_end);
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

    /// Force-compress history for context exhaustion recovery.
    /// Keeps system prompt (if any) + last CONTEXT_RECOVERY_KEEP messages.
    /// Everything in between is dropped without LLM summarization (we can't call
    /// the LLM since the context is exhausted). Returns true if compression was performed.
    pub fn forceCompressHistory(self: *Agent) bool {
        const has_system = self.history.items.len > 0 and self.history.items[0].role == .system;
        const start: usize = if (has_system) 1 else 0;
        const non_system_count = self.history.items.len - start;

        if (non_system_count <= CONTEXT_RECOVERY_KEEP) return false;

        const keep_start = self.history.items.len - CONTEXT_RECOVERY_KEEP;
        const to_remove = keep_start - start;

        // Free messages being removed
        for (self.history.items[start..keep_start]) |*msg| {
            msg.deinit(self.allocator);
        }

        // Shift remaining elements
        const src = self.history.items[keep_start..];
        std.mem.copyForwards(OwnedMessage, self.history.items[start..], src);
        self.history.items.len -= to_remove;

        return true;
    }

    /// Handle slash commands that don't require LLM.
    /// Returns an owned response string, or null if not a slash command.
    pub fn handleSlashCommand(self: *Agent, message: []const u8) !?[]const u8 {
        const trimmed = std.mem.trim(u8, message, " \t\r\n");

        if (std.mem.eql(u8, trimmed, "/new")) {
            self.clearHistory();
            return try self.allocator.dupe(u8, "Session cleared.");
        }

        if (std.mem.eql(u8, trimmed, "/help")) {
            return try self.allocator.dupe(u8,
                \\Available commands:
                \\  /new     — Clear conversation history and start fresh
                \\  /help    — Show this help message
                \\  /status  — Show current model, provider and session stats
                \\  /model <name> — Switch to a different model
                \\  exit, quit — Exit interactive mode
            );
        }

        if (std.mem.eql(u8, trimmed, "/status")) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Model: {s}\nHistory: {d} messages\nTokens used: {d}\nTools: {d} available",
                .{
                    self.model_name,
                    self.history.items.len,
                    self.total_tokens,
                    self.tools.len,
                },
            );
        }

        if (std.mem.eql(u8, trimmed, "/model") or std.mem.startsWith(u8, trimmed, "/model ")) {
            const arg = if (trimmed.len > "/model".len)
                std.mem.trim(u8, trimmed["/model".len..], " \t")
            else
                "";
            if (arg.len == 0) {
                return try std.fmt.allocPrint(self.allocator, "Current model: {s}", .{self.model_name});
            }
            if (self.model_name_owned) self.allocator.free(self.model_name);
            self.model_name = try self.allocator.dupe(u8, arg);
            self.model_name_owned = true;
            return try std.fmt.allocPrint(self.allocator, "Switched to model: {s}", .{arg});
        }

        return null;
    }

    /// Execute a single conversation turn: send messages to LLM, parse tool calls,
    /// execute tools, and loop until a final text response is produced.
    pub fn turn(self: *Agent, user_message: []const u8) ![]const u8 {
        // Handle slash commands before sending to LLM (saves tokens)
        if (try self.handleSlashCommand(user_message)) |response| {
            return response;
        }

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

            const full_system = try self.allocator.alloc(u8, system_prompt.len + tool_instructions.len);
            @memcpy(full_system[0..system_prompt.len], system_prompt);
            @memcpy(full_system[system_prompt.len..], tool_instructions);

            try self.history.append(self.allocator, .{
                .role = .system,
                .content = full_system,
            });
            self.has_system_prompt = true;
        }

        // Auto-save user message to memory (timestamp-based key to avoid overwriting)
        if (self.auto_save) {
            if (self.mem) |mem| {
                const ts = @as(u64, @intCast(std.time.timestamp()));
                const save_key = std.fmt.allocPrint(self.allocator, "autosave_user_{d}", .{ts}) catch null;
                if (save_key) |key| {
                    defer self.allocator.free(key);
                    mem.store(key, user_message, .conversation, null) catch {};
                }
            }
        }

        // Enrich message with memory context (always returns owned slice; ownership → history)
        const enriched = if (self.mem) |mem|
            try memory_loader.enrichMessage(self.allocator, mem, user_message)
        else
            try self.allocator.dupe(u8, user_message);
        errdefer self.allocator.free(enriched);

        try self.history.append(self.allocator, .{
            .role = .user,
            .content = enriched,
        });

        // Record agent event
        const start_event = ObserverEvent{ .llm_request = .{
            .provider = self.provider.getName(),
            .model = self.model_name,
            .messages_count = self.history.items.len,
        } };
        self.observer.recordEvent(&start_event);

        // Tool call loop — reuse a single arena across iterations (retains pages)
        var iter_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer iter_arena.deinit();

        var iteration: u32 = 0;
        while (iteration < self.max_tool_iterations) : (iteration += 1) {
            _ = iter_arena.reset(.retain_capacity);
            const arena = iter_arena.allocator();

            // Build messages slice for provider (arena-owned; freed at end of iteration)
            const messages = blk: {
                const m = try arena.alloc(ChatMessage, self.history.items.len);
                for (self.history.items, 0..) |*msg, i| {
                    m[i] = msg.toChatMessage();
                }
                break :blk m;
            };

            const timer_start = std.time.milliTimestamp();
            const is_streaming = self.stream_callback != null and self.provider.supportsStreaming();

            // Call provider: streaming (no retries, no native tools) or blocking with retry
            var response: ChatResponse = undefined;
            if (is_streaming) {
                const stream_result = self.provider.streamChat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .model = self.model_name,
                        .temperature = self.temperature,
                        .tools = null,
                    },
                    self.model_name,
                    self.temperature,
                    self.stream_callback.?,
                    self.stream_ctx.?,
                ) catch |err| {
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
                    const fail_event = ObserverEvent{ .llm_response = .{
                        .provider = self.provider.getName(),
                        .model = self.model_name,
                        .duration_ms = fail_duration,
                        .success = false,
                        .error_message = @errorName(err),
                    } };
                    self.observer.recordEvent(&fail_event);
                    return err;
                };
                response = ChatResponse{
                    .content = stream_result.content,
                    .tool_calls = &.{},
                    .usage = stream_result.usage,
                    .model = stream_result.model,
                };
            } else {
                response = self.provider.chat(
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
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
                    const fail_event = ObserverEvent{ .llm_response = .{
                        .provider = self.provider.getName(),
                        .model = self.model_name,
                        .duration_ms = fail_duration,
                        .success = false,
                        .error_message = @errorName(err),
                    } };
                    self.observer.recordEvent(&fail_event);

                    // Retry once
                    std.Thread.sleep(500 * std.time.ns_per_ms);
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
                        // Context exhaustion recovery: if we have enough history,
                        // force-compress and retry once more
                        if (self.history.items.len > CONTEXT_RECOVERY_MIN_HISTORY and self.forceCompressHistory()) {
                            const recovery_msgs = self.buildMessageSlice() catch return retry_err;
                            defer self.allocator.free(recovery_msgs);
                            break :retry_blk self.provider.chat(
                                self.allocator,
                                .{
                                    .messages = recovery_msgs,
                                    .model = self.model_name,
                                    .temperature = self.temperature,
                                    .tools = if (self.provider.supportsNativeTools()) self.tool_specs else null,
                                },
                                self.model_name,
                                self.temperature,
                            ) catch return retry_err;
                        }
                        return retry_err;
                    };
                };
            }

            const duration_ms: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
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

            const response_text = response.contentOrEmpty();
            const use_native = response.hasToolCalls();

            // Determine tool calls: structured (native) first, then XML fallback.
            // Mirrors ZeroClaw's run_tool_call_loop logic.
            var parsed_calls: []ParsedToolCall = &.{};
            var parsed_text: []const u8 = "";
            var assistant_history_content: []const u8 = "";

            // Track what we need to free
            var free_parsed_calls = false;
            var free_parsed_text = false;
            var free_assistant_history = false;

            defer {
                if (free_parsed_calls) {
                    for (parsed_calls) |call| {
                        self.allocator.free(call.name);
                        self.allocator.free(call.arguments_json);
                        if (call.tool_call_id) |id| self.allocator.free(id);
                    }
                    self.allocator.free(parsed_calls);
                }
                if (free_parsed_text and parsed_text.len > 0) self.allocator.free(parsed_text);
                if (free_assistant_history and assistant_history_content.len > 0) self.allocator.free(assistant_history_content);
            }

            if (use_native) {
                // Provider returned structured tool_calls — convert them
                parsed_calls = try dispatcher.parseStructuredToolCalls(self.allocator, response.tool_calls);
                free_parsed_calls = true;

                if (parsed_calls.len == 0) {
                    // Structured calls were empty (e.g. all had empty names) — try XML fallback
                    self.allocator.free(parsed_calls);
                    free_parsed_calls = false;

                    const xml_parsed = try dispatcher.parseToolCalls(self.allocator, response_text);
                    parsed_calls = xml_parsed.calls;
                    free_parsed_calls = true;
                    parsed_text = xml_parsed.text;
                    free_parsed_text = true;
                }

                // Build history content with serialized tool calls
                assistant_history_content = try buildAssistantHistoryWithToolCalls(
                    self.allocator,
                    response_text,
                    parsed_calls,
                );
                free_assistant_history = true;
            } else {
                // No native tool calls — parse response text for XML tool calls
                const xml_parsed = try dispatcher.parseToolCalls(self.allocator, response_text);
                parsed_calls = xml_parsed.calls;
                free_parsed_calls = true;
                parsed_text = xml_parsed.text;
                free_parsed_text = true;
                // For XML path, store the raw response text as history
                assistant_history_content = response_text;
            }

            // Determine display text
            const display_text = if (parsed_text.len > 0) parsed_text else response_text;

            if (parsed_calls.len == 0) {
                // No tool calls — final response
                const final_text = try self.allocator.dupe(u8, display_text);

                // Dupe from display_text directly (not from final_text) to avoid double-dupe
                try self.history.append(self.allocator, .{
                    .role = .assistant,
                    .content = try self.allocator.dupe(u8, display_text),
                });

                // Auto-compaction before hard trimming to preserve context
                self.last_turn_compacted = self.autoCompactHistory() catch false;
                self.trimHistory();

                // Auto-save assistant response
                if (self.auto_save) {
                    if (self.mem) |mem| {
                        const summary = if (final_text.len > 100) final_text[0..100] else final_text;
                        const ts = @as(u64, @intCast(std.time.timestamp()));
                        const save_key = try std.fmt.allocPrint(self.allocator, "autosave_assistant_{d}", .{ts});
                        defer self.allocator.free(save_key);
                        mem.store(save_key, summary, .daily, null) catch {};
                    }
                }

                const complete_event = ObserverEvent{ .turn_complete = {} };
                self.observer.recordEvent(&complete_event);

                // Free provider response fields (content, tool_calls, model)
                // All borrows have been duped into final_text and history at this point.
                self.freeResponseFields(&response);

                return final_text;
            }

            // There are tool calls — print intermediary text
            if (display_text.len > 0 and parsed_calls.len > 0 and !is_streaming) {
                var out_buf: [4096]u8 = undefined;
                var bw = std.fs.File.stdout().writer(&out_buf);
                const w = &bw.interface;
                w.print("{s}", .{display_text}) catch {};
                w.flush() catch {};
            }

            // Record assistant message with tool calls in history.
            // Native path (free_assistant_history=true): transfer ownership directly to avoid
            // a redundant allocation; clear the flag so the outer defer does not double-free.
            // XML path (free_assistant_history=false): response_text is not owned, must dupe.
            const assistant_content: []const u8 = if (free_assistant_history) blk: {
                free_assistant_history = false;
                break :blk assistant_history_content;
            } else try self.allocator.dupe(u8, assistant_history_content);
            errdefer self.allocator.free(assistant_content);

            try self.history.append(self.allocator, .{
                .role = .assistant,
                .content = assistant_content,
            });

            // Execute each tool call
            var results_buf: std.ArrayListUnmanaged(ToolExecutionResult) = .empty;
            defer results_buf.deinit(self.allocator);
            try results_buf.ensureTotalCapacity(self.allocator, parsed_calls.len);

            for (parsed_calls) |call| {
                const tool_start_event = ObserverEvent{ .tool_call_start = .{ .tool = call.name } };
                self.observer.recordEvent(&tool_start_event);

                const tool_timer = std.time.milliTimestamp();
                const result = self.executeTool(call);
                const tool_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - tool_timer)));

                const tool_event = ObserverEvent{ .tool_call = .{
                    .tool = call.name,
                    .duration_ms = tool_duration,
                    .success = result.success,
                } };
                self.observer.recordEvent(&tool_event);

                try results_buf.append(self.allocator, result);
            }

            // Format tool results, scrub credentials, add reflection prompt, and add to history
            const formatted_results = try dispatcher.formatToolResults(arena, results_buf.items);
            const scrubbed_results = try providers.scrubToolOutput(arena, formatted_results);
            const with_reflection = try std.fmt.allocPrint(
                arena,
                "{s}\n\nReflect on the tool results above and decide your next steps.",
                .{scrubbed_results},
            );
            try self.history.append(self.allocator, .{
                .role = .user,
                .content = try self.allocator.dupe(u8, with_reflection),
            });

            self.trimHistory();

            // Free provider response fields now that all borrows are consumed.
            self.freeResponseFields(&response);
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

    /// Build an assistant history entry that includes serialized tool calls as XML.
    ///
    /// When the provider returns structured tool_calls, we serialize them as
    /// `<tool_call>` XML tags so the conversation history stays in a canonical
    /// format regardless of whether tools came from native API or XML parsing.
    ///
    /// Mirrors ZeroClaw's `build_assistant_history_with_tool_calls`.
    pub fn buildAssistantHistoryWithToolCalls(
        allocator: std.mem.Allocator,
        response_text: []const u8,
        parsed_calls: []const ParsedToolCall,
    ) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        if (response_text.len > 0) {
            try w.writeAll(response_text);
            try w.writeByte('\n');
        }

        for (parsed_calls) |call| {
            try w.writeAll("<tool_call>\n");
            try std.fmt.format(w, "{{\"name\": \"{s}\", \"arguments\": {s}}}", .{
                call.name,
                call.arguments_json,
            });
            try w.writeAll("\n</tool_call>\n");
        }

        return buf.toOwnedSlice(allocator);
    }

    /// Build a flat ChatMessage slice from owned history.
    fn buildMessageSlice(self: *Agent) ![]ChatMessage {
        const messages = try self.allocator.alloc(ChatMessage, self.history.items.len);
        for (self.history.items, 0..) |*msg, i| {
            messages[i] = msg.toChatMessage();
        }
        return messages;
    }

    /// Free heap-allocated fields of a ChatResponse.
    /// Providers allocate content, tool_calls, and model on the heap.
    /// After extracting/duping what we need, call this to prevent leaks.
    fn freeResponseFields(self: *Agent, resp: *ChatResponse) void {
        if (resp.content) |c| {
            if (c.len > 0) self.allocator.free(c);
        }
        for (resp.tool_calls) |tc| {
            if (tc.id.len > 0) self.allocator.free(tc.id);
            if (tc.name.len > 0) self.allocator.free(tc.name);
            if (tc.arguments.len > 0) self.allocator.free(tc.arguments);
        }
        if (resp.tool_calls.len > 0) self.allocator.free(resp.tool_calls);
        if (resp.model.len > 0) self.allocator.free(resp.model);
        if (resp.reasoning_content) |rc| {
            if (rc.len > 0) self.allocator.free(rc);
        }
        // Mark as consumed to prevent double-free
        resp.content = null;
        resp.tool_calls = &.{};
        resp.model = "";
        resp.reasoning_content = null;
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

        // Shrink backing array if capacity is much larger than needed
        if (self.history.capacity > self.history.items.len * 2 + 8) {
            self.history.shrinkAndFree(self.allocator, self.history.items.len);
        }
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

/// Streaming callback that writes chunks directly to stdout.
fn cliStreamCallback(_: *anyopaque, chunk: providers.StreamChunk) void {
    if (chunk.delta.len == 0) return;
    var buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const wr = &bw.interface;
    wr.print("{s}", .{chunk.delta}) catch {};
    wr.flush() catch {};
}

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    const cfg = Config.load(allocator) catch {
        log.err("No config found. Run `nullclaw onboard` first.", .{});
        return;
    };

    var out_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&out_buf);
    const w = &bw.interface;

    // Parse agent-specific flags
    var message_arg: ?[]const u8 = null;
    var session_id: ?[]const u8 = null;
    {
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg: []const u8 = args[i];
            if ((std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--message")) and i + 1 < args.len) {
                i += 1;
                message_arg = args[i];
            } else if ((std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--session")) and i + 1 < args.len) {
                i += 1;
                session_id = args[i];
            }
        }
    }

    // Create a noop observer
    var noop = observability.NoopObserver{};
    const obs = noop.observer();

    // Record agent start
    const start_event = ObserverEvent{ .agent_start = .{
        .provider = cfg.default_provider,
        .model = cfg.default_model orelse "(default)",
    } };
    obs.recordEvent(&start_event);

    // Initialize MCP tools from config
    const mcp_mod = @import("../mcp.zig");
    const mcp_tools: ?[]const tools_mod.Tool = if (cfg.mcp_servers.len > 0)
        mcp_mod.initMcpTools(allocator, cfg.mcp_servers) catch |err| blk: {
            log.warn("MCP: init failed: {}", .{err});
            break :blk null;
        }
    else
        null;

    // Create tools (with agents config for delegate depth enforcement)
    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .browser_enabled = cfg.browser.enabled,
        .mcp_tools = mcp_tools,
        .agents = cfg.agents,
        .fallback_api_key = cfg.api_key,
    });
    defer allocator.free(tools);

    // Create memory (optional — don't fail if it can't init)
    var mem_opt: ?Memory = null;
    const db_path = try std.fs.path.joinZ(allocator, &.{ cfg.workspace_dir, "memory.db" });
    defer allocator.free(db_path);
    if (memory_mod.createMemory(allocator, cfg.memory.backend, db_path)) |mem| {
        mem_opt = mem;
    } else |_| {}

    // Create provider via ProviderHolder (concrete struct lives on the stack)
    const ProviderHolder = union(enum) {
        openrouter: providers.openrouter.OpenRouterProvider,
        anthropic: providers.anthropic.AnthropicProvider,
        openai: providers.openai.OpenAiProvider,
        gemini: providers.gemini.GeminiProvider,
        ollama: providers.ollama.OllamaProvider,
        compatible: providers.compatible.OpenAiCompatibleProvider,
        claude_cli: providers.claude_cli.ClaudeCliProvider,
        codex_cli: providers.codex_cli.CodexCliProvider,
    };

    const kind = providers.classifyProvider(cfg.default_provider);
    var holder: ProviderHolder = switch (kind) {
        .anthropic_provider => .{ .anthropic = providers.anthropic.AnthropicProvider.init(
            allocator,
            cfg.api_key,
            if (std.mem.startsWith(u8, cfg.default_provider, "anthropic-custom:"))
                cfg.default_provider["anthropic-custom:".len..]
            else
                null,
        ) },
        .openai_provider => .{ .openai = providers.openai.OpenAiProvider.init(allocator, cfg.api_key) },
        .gemini_provider => .{ .gemini = providers.gemini.GeminiProvider.init(allocator, cfg.api_key) },
        .ollama_provider => .{ .ollama = providers.ollama.OllamaProvider.init(allocator, null) },
        .openrouter_provider => .{ .openrouter = providers.openrouter.OpenRouterProvider.init(allocator, cfg.api_key) },
        .compatible_provider => .{ .compatible = providers.compatible.OpenAiCompatibleProvider.init(
            allocator,
            cfg.default_provider,
            if (std.mem.startsWith(u8, cfg.default_provider, "custom:"))
                cfg.default_provider["custom:".len..]
            else
                providers.compatibleProviderUrl(cfg.default_provider) orelse "https://openrouter.ai/api/v1",
            cfg.api_key,
            .bearer,
        ) },
        .claude_cli_provider => if (providers.claude_cli.ClaudeCliProvider.init(allocator, null)) |p|
            .{ .claude_cli = p }
        else |_|
            .{ .openrouter = providers.openrouter.OpenRouterProvider.init(allocator, cfg.api_key) },
        .codex_cli_provider => if (providers.codex_cli.CodexCliProvider.init(allocator, null)) |p|
            .{ .codex_cli = p }
        else |_|
            .{ .openrouter = providers.openrouter.OpenRouterProvider.init(allocator, cfg.api_key) },
        .unknown => .{ .openrouter = providers.openrouter.OpenRouterProvider.init(allocator, cfg.api_key) },
    };

    const provider_i: Provider = switch (holder) {
        .openrouter => |*p| p.provider(),
        .anthropic => |*p| p.provider(),
        .openai => |*p| p.provider(),
        .gemini => |*p| p.provider(),
        .ollama => |*p| p.provider(),
        .compatible => |*p| p.provider(),
        .claude_cli => |*p| p.provider(),
        .codex_cli => |*p| p.provider(),
    };

    const supports_streaming = provider_i.supportsStreaming();

    // Single message mode: nullclaw agent -m "hello"
    if (message_arg) |message| {
        try w.print("Sending to {s}...\n", .{cfg.default_provider});
        if (session_id) |sid| {
            try w.print("Session: {s}\n", .{sid});
        }
        try w.flush();

        var agent = try Agent.fromConfig(allocator, &cfg, provider_i, tools, mem_opt, obs);
        defer agent.deinit();

        // Enable streaming if provider supports it
        var stream_ctx: u8 = 0;
        if (supports_streaming) {
            agent.stream_callback = cliStreamCallback;
            agent.stream_ctx = @ptrCast(&stream_ctx);
        }

        const response = try agent.turn(message);
        defer allocator.free(response);

        if (supports_streaming) {
            try w.print("\n", .{});
        } else {
            try w.print("{s}\n", .{response});
        }
        try w.flush();
        return;
    }

    // Interactive REPL mode
    try w.print("nullclaw Agent -- Interactive Mode\n", .{});
    try w.print("Provider: {s} | Model: {s}\n", .{
        cfg.default_provider,
        cfg.default_model orelse "(default)",
    });
    if (session_id) |sid| {
        try w.print("Session: {s}\n", .{sid});
    }
    if (supports_streaming) {
        try w.print("Streaming: enabled\n", .{});
    }
    try w.print("Type your message (Ctrl+D or 'exit' to quit):\n\n", .{});
    try w.flush();

    // Load command history
    const history_path = cli_mod.defaultHistoryPath(allocator) catch null;
    defer if (history_path) |hp| allocator.free(hp);

    var repl_history: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        // Save history on exit
        if (history_path) |hp| {
            cli_mod.saveHistory(repl_history.items, hp) catch {};
        }
        for (repl_history.items) |entry| allocator.free(entry);
        repl_history.deinit(allocator);
    }

    // Seed history from file
    if (history_path) |hp| {
        const loaded = cli_mod.loadHistory(allocator, hp) catch null;
        if (loaded) |entries| {
            defer allocator.free(entries);
            for (entries) |entry| {
                repl_history.append(allocator, entry) catch {
                    allocator.free(entry);
                };
            }
        }
    }

    if (repl_history.items.len > 0) {
        try w.print("[History: {d} entries loaded]\n", .{repl_history.items.len});
        try w.flush();
    }

    var agent = try Agent.fromConfig(allocator, &cfg, provider_i, tools, mem_opt, obs);
    defer agent.deinit();

    // Enable streaming if provider supports it
    var stream_ctx: u8 = 0;
    if (supports_streaming) {
        agent.stream_callback = cliStreamCallback;
        agent.stream_ctx = @ptrCast(&stream_ctx);
    }

    const stdin = std.fs.File.stdin();
    var line_buf: [4096]u8 = undefined;

    while (true) {
        try w.print("> ", .{});
        try w.flush();

        // Read a line from stdin byte-by-byte
        var pos: usize = 0;
        while (pos < line_buf.len) {
            const n = stdin.read(line_buf[pos .. pos + 1]) catch return;
            if (n == 0) return; // EOF (Ctrl+D)
            if (line_buf[pos] == '\n') break;
            pos += 1;
        }
        const line = line_buf[0..pos];

        if (line.len == 0) continue;
        if (cli_mod.CliChannel.isQuitCommand(line)) return;

        // Append to history
        repl_history.append(allocator, allocator.dupe(u8, line) catch continue) catch {};

        const response = agent.turn(line) catch |err| {
            try w.print("Error: {}\n", .{err});
            try w.flush();
            continue;
        };
        defer allocator.free(response);

        if (supports_streaming) {
            try w.print("\n\n", .{});
        } else {
            try w.print("\n{s}\n\n", .{response});
        }
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

// ── buildAssistantHistoryWithToolCalls tests ─────────────────────

test "buildAssistantHistoryWithToolCalls with text and calls" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "shell", .arguments_json = "{\"command\":\"ls\"}" },
        .{ .name = "file_read", .arguments_json = "{\"path\":\"a.txt\"}" },
    };
    const result = try Agent.buildAssistantHistoryWithToolCalls(
        allocator,
        "Let me check that.",
        &calls,
    );
    defer allocator.free(result);

    // Should contain the response text
    try std.testing.expect(std.mem.indexOf(u8, result, "Let me check that.") != null);
    // Should contain tool_call XML tags
    try std.testing.expect(std.mem.indexOf(u8, result, "<tool_call>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "</tool_call>") != null);
    // Should contain tool names
    try std.testing.expect(std.mem.indexOf(u8, result, "\"shell\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"file_read\"") != null);
    // Should contain two tool_call tags
    var count: usize = 0;
    var search = result;
    while (std.mem.indexOf(u8, search, "<tool_call>")) |idx| {
        count += 1;
        search = search[idx + 11 ..];
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "buildAssistantHistoryWithToolCalls empty text" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "shell", .arguments_json = "{}" },
    };
    const result = try Agent.buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &calls,
    );
    defer allocator.free(result);

    // Should NOT start with a newline (no empty text prefix)
    try std.testing.expect(result[0] == '<');
    try std.testing.expect(std.mem.indexOf(u8, result, "<tool_call>") != null);
}

test "buildAssistantHistoryWithToolCalls no calls" {
    const allocator = std.testing.allocator;
    const result = try Agent.buildAssistantHistoryWithToolCalls(
        allocator,
        "Just text, no tools.",
        &.{},
    );
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Just text, no tools.\n", result);
}

test "buildAssistantHistoryWithToolCalls empty text and no calls" {
    const allocator = std.testing.allocator;
    const result = try Agent.buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &.{},
    );
    defer allocator.free(result);

    try std.testing.expectEqualStrings("", result);
}

test "buildAssistantHistoryWithToolCalls preserves arguments JSON" {
    const allocator = std.testing.allocator;
    const calls = [_]ParsedToolCall{
        .{ .name = "file_write", .arguments_json = "{\"path\":\"test.py\",\"content\":\"print('hello')\"}" },
    };
    const result = try Agent.buildAssistantHistoryWithToolCalls(
        allocator,
        "",
        &calls,
    );
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"file_write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "print('hello')") != null);
}

// ── parseStructuredToolCalls tests ──────────────────────────────

test "parseStructuredToolCalls converts ToolCalls to ParsedToolCalls" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "call_1", .name = "shell", .arguments = "{\"command\":\"ls\"}" },
        .{ .id = "call_2", .name = "file_read", .arguments = "{\"path\":\"a.txt\"}" },
    };

    const result = try dispatcher.parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name);
    try std.testing.expectEqualStrings("{\"command\":\"ls\"}", result[0].arguments_json);
    try std.testing.expectEqualStrings("call_1", result[0].tool_call_id.?);
    try std.testing.expectEqualStrings("file_read", result[1].name);
    try std.testing.expectEqualStrings("call_2", result[1].tool_call_id.?);
}

test "parseStructuredToolCalls skips empty names" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "tc1", .name = "", .arguments = "{}" },
        .{ .id = "tc2", .name = "shell", .arguments = "{}" },
    };

    const result = try dispatcher.parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name);
}

test "parseStructuredToolCalls empty input" {
    const allocator = std.testing.allocator;
    const result = try dispatcher.parseStructuredToolCalls(allocator, &.{});
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "parseStructuredToolCalls empty id yields null tool_call_id" {
    const allocator = std.testing.allocator;
    const tool_calls = [_]providers.ToolCall{
        .{ .id = "", .name = "shell", .arguments = "{}" },
    };

    const result = try dispatcher.parseStructuredToolCalls(allocator, &tool_calls);
    defer {
        for (result) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            if (call.tool_call_id) |id| allocator.free(id);
        }
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expect(result[0].tool_call_id == null);
}

// ── Slash Command Tests ──────────────────────────────────────────

fn makeTestAgent(allocator: std.mem.Allocator) !Agent {
    var noop = observability.NoopObserver{};
    return Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
}

test "slash /new clears history" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Add some history
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });
    agent.has_system_prompt = true;

    const response = (try agent.handleSlashCommand("/new")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Session cleared.", response);
    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expect(!agent.has_system_prompt);
}

test "slash /help returns help text" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/help")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "/new") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/help") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/status") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/model") != null);
}

test "slash /status returns agent info" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    agent.total_tokens = 42;
    const response = (try agent.handleSlashCommand("/status")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "42") != null);
}

test "slash /model switches model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/model gpt-4o")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4o") != null);
    try std.testing.expectEqualStrings("gpt-4o", agent.model_name);
}

test "slash /model without name shows current" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/model ")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "test-model") != null);
}

test "non-slash message returns null" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = try agent.handleSlashCommand("hello world");
    try std.testing.expect(response == null);
}

test "slash command with whitespace" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("  /help  ")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "/new") != null);
}

// ── Session Consolidation Enhancement Tests ─────────────────────

test "tokenEstimate empty history" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Empty history: (0 + 3) / 4 = 0
    try std.testing.expectEqual(@as(u64, 0), agent.tokenEstimate());
}

test "tokenEstimate with messages" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Add messages with known content lengths
    // "hello" = 5 chars, "world" = 5 chars => total 10 chars => (10 + 3) / 4 = 3
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });
    try agent.history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "world"),
    });

    try std.testing.expectEqual(@as(u64, 3), agent.tokenEstimate());
}

test "tokenEstimate heuristic accuracy" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // 400 chars should estimate ~100 tokens
    const content = try allocator.alloc(u8, 400);
    defer allocator.free(content);
    @memset(content, 'a');

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, content),
    });

    // (400 + 3) / 4 = 100
    try std.testing.expectEqual(@as(u64, 100), agent.tokenEstimate());
}

test "autoCompactHistory no-op below count and token thresholds" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    agent.token_limit = DEFAULT_TOKEN_LIMIT;

    // Add a few small messages — well below both thresholds
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "system"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    const compacted = try agent.autoCompactHistory();
    try std.testing.expect(!compacted);
    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());
}

test "DEFAULT_TOKEN_LIMIT constant" {
    try std.testing.expectEqual(@as(u64, 128_000), DEFAULT_TOKEN_LIMIT);
}

// ── Context Exhaustion Recovery Tests ────────────────────────────

test "forceCompressHistory keeps system + last 4 messages" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Add system prompt + 8 messages
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "system prompt"),
    });
    for (0..8) |i| {
        try agent.history.append(allocator, .{
            .role = .user,
            .content = try std.fmt.allocPrint(allocator, "msg-{d}", .{i}),
        });
    }
    try std.testing.expectEqual(@as(usize, 9), agent.historyLen());

    const compressed = agent.forceCompressHistory();
    try std.testing.expect(compressed);

    // Should keep system + last 4
    try std.testing.expectEqual(@as(usize, 5), agent.historyLen());
    try std.testing.expect(agent.history.items[0].role == .system);
    try std.testing.expectEqualStrings("system prompt", agent.history.items[0].content);
    try std.testing.expectEqualStrings("msg-4", agent.history.items[1].content);
    try std.testing.expectEqualStrings("msg-7", agent.history.items[4].content);
}

test "forceCompressHistory without system prompt" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Add 8 messages (no system prompt)
    for (0..8) |i| {
        try agent.history.append(allocator, .{
            .role = .user,
            .content = try std.fmt.allocPrint(allocator, "msg-{d}", .{i}),
        });
    }

    const compressed = agent.forceCompressHistory();
    try std.testing.expect(compressed);

    // Should keep last 4
    try std.testing.expectEqual(@as(usize, 4), agent.historyLen());
    try std.testing.expectEqualStrings("msg-4", agent.history.items[0].content);
    try std.testing.expectEqualStrings("msg-7", agent.history.items[3].content);
}

test "forceCompressHistory no-op when history is small" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    const compressed = agent.forceCompressHistory();
    try std.testing.expect(!compressed);
    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());
}

test "CONTEXT_RECOVERY constants" {
    try std.testing.expectEqual(@as(usize, 6), CONTEXT_RECOVERY_MIN_HISTORY);
    try std.testing.expectEqual(@as(usize, 4), CONTEXT_RECOVERY_KEEP);
}

test "Agent streaming fields default to null" {
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
    };
    defer agent.deinit();

    try std.testing.expect(agent.stream_callback == null);
    try std.testing.expect(agent.stream_ctx == null);
}

test "cliStreamCallback handles empty delta" {
    const chunk = providers.StreamChunk.finalChunk();
    cliStreamCallback(undefined, chunk);
}

test "cliStreamCallback text delta chunk" {
    const chunk = providers.StreamChunk.textDelta("hello");
    try std.testing.expectEqualStrings("hello", chunk.delta);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqual(@as(u32, 2), chunk.token_count);
}

// ── Bug regression tests ─────────────────────────────────────────

// Bug 1: /model command should dupe the arg to avoid use-after-free.
// model_name must survive past the stack buffer that held the original message.
test "slash /model dupe prevents use-after-free" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    // Build message in a buffer that we then invalidate (simulate stack lifetime end)
    var msg_buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, "/model new-model-xyz", .{}) catch unreachable;
    const response = (try agent.handleSlashCommand(msg)).?;
    defer allocator.free(response);

    // Overwrite the source buffer to verify model_name is an independent copy
    @memset(&msg_buf, 0);
    try std.testing.expectEqualStrings("new-model-xyz", agent.model_name);
}

// Bug 2: @intCast on negative i64 duration should not panic.
// Simulate by verifying the @max(0, ...) clamping logic.
test "milliTimestamp negative difference clamps to zero" {
    // Simulate: timer_start is in the future relative to "now" (negative diff)
    const timer_start = std.time.milliTimestamp() + 10_000;
    const diff = std.time.milliTimestamp() - timer_start;
    // diff < 0 here; @max(0, diff) must clamp to 0 without panic
    const clamped = @max(0, diff);
    const duration: u64 = @as(u64, @intCast(clamped));
    try std.testing.expectEqual(@as(u64, 0), duration);
}

test "Agent streaming fields can be set" {
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
    };
    defer agent.deinit();

    var ctx: u8 = 42;
    agent.stream_callback = cliStreamCallback;
    agent.stream_ctx = @ptrCast(&ctx);

    try std.testing.expect(agent.stream_callback != null);
    try std.testing.expect(agent.stream_ctx != null);
}
