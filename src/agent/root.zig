//! Agent core — struct definition, turn loop, tool execution.
//!
//! Sub-modules: dispatcher.zig (tool call parsing), compaction.zig (history
//! compaction/trimming), cli.zig (CLI entry point + REPL), prompt.zig
//! (system prompt), memory_loader.zig (memory enrichment).

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.agent);
const Config = @import("../config.zig").Config;
const config_types = @import("../config_types.zig");
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const ChatMessage = providers.ChatMessage;
const ChatResponse = providers.ChatResponse;
const ToolSpec = providers.ToolSpec;
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const capabilities_mod = @import("../capabilities.zig");
const multimodal = @import("../multimodal.zig");
const platform = @import("../platform.zig");
const observability = @import("../observability.zig");
const Observer = observability.Observer;
const ObserverEvent = observability.ObserverEvent;
const SecurityPolicy = @import("../security/policy.zig").SecurityPolicy;

const cache = memory_mod.cache;
pub const dispatcher = @import("dispatcher.zig");
pub const compaction = @import("compaction.zig");
pub const context_tokens = @import("context_tokens.zig");
pub const max_tokens_resolver = @import("max_tokens.zig");
pub const prompt = @import("prompt.zig");
pub const memory_loader = @import("memory_loader.zig");
pub const commands = @import("commands.zig");
const ParsedToolCall = dispatcher.ParsedToolCall;
const ToolExecutionResult = dispatcher.ToolExecutionResult;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum agentic tool-use iterations per user message.
const DEFAULT_MAX_TOOL_ITERATIONS: u32 = 25;

/// Maximum non-system messages before trimming.
const DEFAULT_MAX_HISTORY: u32 = 50;

// ═══════════════════════════════════════════════════════════════════════════
// Agent
// ═══════════════════════════════════════════════════════════════════════════

pub const Agent = struct {
    const VerboseLevel = enum {
        off,
        on,
        full,

        pub fn toSlice(self: VerboseLevel) []const u8 {
            return switch (self) {
                .off => "off",
                .on => "on",
                .full => "full",
            };
        }
    };

    const ReasoningMode = enum {
        off,
        on,
        stream,

        pub fn toSlice(self: ReasoningMode) []const u8 {
            return switch (self) {
                .off => "off",
                .on => "on",
                .stream => "stream",
            };
        }
    };

    const UsageMode = enum {
        off,
        tokens,
        full,
        cost,

        pub fn toSlice(self: UsageMode) []const u8 {
            return switch (self) {
                .off => "off",
                .tokens => "tokens",
                .full => "full",
                .cost => "cost",
            };
        }
    };

    const ExecHost = enum {
        sandbox,
        gateway,
        node,

        pub fn toSlice(self: ExecHost) []const u8 {
            return switch (self) {
                .sandbox => "sandbox",
                .gateway => "gateway",
                .node => "node",
            };
        }
    };

    const ExecSecurity = enum {
        deny,
        allowlist,
        full,

        pub fn toSlice(self: ExecSecurity) []const u8 {
            return switch (self) {
                .deny => "deny",
                .allowlist => "allowlist",
                .full => "full",
            };
        }
    };

    const ExecAsk = enum {
        off,
        on_miss,
        always,

        pub fn toSlice(self: ExecAsk) []const u8 {
            return switch (self) {
                .off => "off",
                .on_miss => "on-miss",
                .always => "always",
            };
        }
    };

    const QueueMode = enum {
        off,
        serial,
        latest,
        debounce,

        pub fn toSlice(self: QueueMode) []const u8 {
            return switch (self) {
                .off => "off",
                .serial => "serial",
                .latest => "latest",
                .debounce => "debounce",
            };
        }
    };

    const QueueDrop = enum {
        summarize,
        oldest,
        newest,

        pub fn toSlice(self: QueueDrop) []const u8 {
            return switch (self) {
                .summarize => "summarize",
                .oldest => "oldest",
                .newest => "newest",
            };
        }
    };

    const TtsMode = enum {
        off,
        always,
        inbound,
        tagged,

        pub fn toSlice(self: TtsMode) []const u8 {
            return switch (self) {
                .off => "off",
                .always => "always",
                .inbound => "inbound",
                .tagged => "tagged",
            };
        }
    };

    const ActivationMode = enum {
        mention,
        always,

        pub fn toSlice(self: ActivationMode) []const u8 {
            return switch (self) {
                .mention => "mention",
                .always => "always",
            };
        }
    };

    const SendMode = enum {
        on,
        off,
        inherit,

        pub fn toSlice(self: SendMode) []const u8 {
            return switch (self) {
                .on => "on",
                .off => "off",
                .inherit => "inherit",
            };
        }
    };

    allocator: std.mem.Allocator,
    provider: Provider,
    tools: []const Tool,
    tool_specs: []const ToolSpec,
    mem: ?Memory,
    session_store: ?memory_mod.SessionStore = null,
    response_cache: ?*cache.ResponseCache = null,
    /// Optional MemoryRuntime pointer for diagnostics (e.g. /doctor command).
    mem_rt: ?*memory_mod.MemoryRuntime = null,
    /// Optional session scope for memory read/write operations.
    memory_session_id: ?[]const u8 = null,
    observer: Observer,
    model_name: []const u8,
    model_name_owned: bool = false,
    default_provider: []const u8 = "openrouter",
    default_provider_owned: bool = false,
    default_model: []const u8 = "anthropic/claude-sonnet-4",
    configured_providers: []const config_types.ProviderEntry = &.{},
    fallback_providers: []const []const u8 = &.{},
    model_fallbacks: []const config_types.ModelFallbackEntry = &.{},
    temperature: f64,
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_tool_iterations: u32,
    max_history_messages: u32,
    auto_save: bool,
    token_limit: u64 = 0,
    token_limit_override: ?u64 = null,
    max_tokens: u32 = max_tokens_resolver.DEFAULT_MODEL_MAX_TOKENS,
    max_tokens_override: ?u32 = null,
    reasoning_effort: ?[]const u8 = null,
    verbose_level: VerboseLevel = .off,
    reasoning_mode: ReasoningMode = .off,
    usage_mode: UsageMode = .off,
    exec_host: ExecHost = .gateway,
    exec_security: ExecSecurity = .allowlist,
    exec_ask: ExecAsk = .on_miss,
    exec_node_id: ?[]const u8 = null,
    exec_node_id_owned: bool = false,
    queue_mode: QueueMode = .off,
    queue_debounce_ms: u32 = 0,
    queue_cap: u32 = 0,
    queue_drop: QueueDrop = .summarize,
    tts_mode: TtsMode = .off,
    tts_provider: ?[]const u8 = null,
    tts_provider_owned: bool = false,
    tts_limit_chars: u32 = 0,
    tts_summary: bool = false,
    tts_audio: bool = false,
    pending_exec_command: ?[]const u8 = null,
    pending_exec_command_owned: bool = false,
    pending_exec_id: u64 = 0,
    session_ttl_secs: ?u64 = null,
    focus_target: ?[]const u8 = null,
    focus_target_owned: bool = false,
    dock_target: ?[]const u8 = null,
    dock_target_owned: bool = false,
    activation_mode: ActivationMode = .mention,
    send_mode: SendMode = .inherit,
    last_turn_usage: providers.TokenUsage = .{},
    message_timeout_secs: u64 = 0,
    log_tool_calls: bool = false,
    log_llm_io: bool = false,
    compaction_keep_recent: u32 = compaction.DEFAULT_COMPACTION_KEEP_RECENT,
    compaction_max_summary_chars: u32 = compaction.DEFAULT_COMPACTION_MAX_SUMMARY_CHARS,
    compaction_max_source_chars: u32 = compaction.DEFAULT_COMPACTION_MAX_SOURCE_CHARS,

    /// Optional security policy for autonomy checks and rate limiting.
    policy: ?*const SecurityPolicy = null,

    /// Optional streaming callback. When set, turn() uses streamChat() for streaming providers.
    stream_callback: ?providers.StreamCallback = null,
    /// Context pointer passed to stream_callback.
    stream_ctx: ?*anyopaque = null,
    /// Conversation context for the current turn (Signal-specific for now).
    conversation_context: ?prompt.ConversationContext = null,

    /// Conversation history — owned, growable list.
    history: std.ArrayListUnmanaged(OwnedMessage) = .empty,

    /// Total tokens used across all turns.
    total_tokens: u64 = 0,

    /// Whether the system prompt has been injected.
    has_system_prompt: bool = false,
    /// Whether the currently injected system prompt contains conversation context.
    system_prompt_has_conversation_context: bool = false,
    /// Fingerprint of workspace prompt files for the currently injected system prompt.
    workspace_prompt_fingerprint: ?u64 = null,

    /// Whether compaction was performed during the last turn.
    last_turn_compacted: bool = false,

    /// Whether context was force-compacted due to exhaustion during the current turn.
    context_was_compacted: bool = false,

    /// An owned copy of a ChatMessage, where content is heap-allocated.
    pub const OwnedMessage = struct {
        role: providers.Role,
        content: []const u8,

        pub fn deinit(self: *const OwnedMessage, allocator: std.mem.Allocator) void {
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
        const default_model = cfg.default_model orelse return error.NoDefaultModel;
        const token_limit_override = if (cfg.agent.token_limit_explicit) cfg.agent.token_limit else null;
        const resolved_token_limit = context_tokens.resolveContextTokens(token_limit_override, default_model);
        const resolved_max_tokens_raw = max_tokens_resolver.resolveMaxTokens(cfg.max_tokens, default_model);
        const token_limit_cap: u32 = @intCast(@min(resolved_token_limit, @as(u64, std.math.maxInt(u32))));
        const resolved_max_tokens = @min(resolved_max_tokens_raw, token_limit_cap);

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
            .model_name = default_model,
            .default_provider = cfg.default_provider,
            .default_model = default_model,
            .configured_providers = cfg.providers,
            .fallback_providers = cfg.reliability.fallback_providers,
            .model_fallbacks = cfg.reliability.model_fallbacks,
            .temperature = cfg.default_temperature,
            .workspace_dir = cfg.workspace_dir,
            .allowed_paths = cfg.autonomy.allowed_paths,
            .max_tool_iterations = cfg.agent.max_tool_iterations,
            .max_history_messages = cfg.agent.max_history_messages,
            .auto_save = cfg.memory.auto_save,
            .token_limit = resolved_token_limit,
            .token_limit_override = token_limit_override,
            .max_tokens = resolved_max_tokens,
            .max_tokens_override = cfg.max_tokens,
            .reasoning_effort = cfg.reasoning_effort,
            .message_timeout_secs = cfg.agent.message_timeout_secs,
            .log_tool_calls = cfg.diagnostics.log_tool_calls,
            .log_llm_io = cfg.diagnostics.log_llm_io,
            .compaction_keep_recent = cfg.agent.compaction_keep_recent,
            .compaction_max_summary_chars = cfg.agent.compaction_max_summary_chars,
            .compaction_max_source_chars = cfg.agent.compaction_max_source_chars,
            .history = .empty,
            .total_tokens = 0,
            .has_system_prompt = false,
            .last_turn_compacted = false,
        };
    }

    pub fn deinit(self: *Agent) void {
        if (self.model_name_owned) self.allocator.free(self.model_name);
        if (self.default_provider_owned) self.allocator.free(self.default_provider);
        if (self.exec_node_id_owned and self.exec_node_id != null) self.allocator.free(self.exec_node_id.?);
        if (self.tts_provider_owned and self.tts_provider != null) self.allocator.free(self.tts_provider.?);
        if (self.pending_exec_command_owned and self.pending_exec_command != null) self.allocator.free(self.pending_exec_command.?);
        if (self.focus_target_owned and self.focus_target != null) self.allocator.free(self.focus_target.?);
        if (self.dock_target_owned and self.dock_target != null) self.allocator.free(self.dock_target.?);
        for (self.history.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.history.deinit(self.allocator);
        self.allocator.free(self.tool_specs);
    }

    /// Estimate total tokens in conversation history.
    pub fn tokenEstimate(self: *const Agent) u64 {
        return compaction.tokenEstimate(self.history.items);
    }

    /// Auto-compact history when it exceeds thresholds.
    pub fn autoCompactHistory(self: *Agent) !bool {
        return compaction.autoCompactHistory(self.allocator, &self.history, self.provider, self.model_name, .{
            .keep_recent = self.compaction_keep_recent,
            .max_summary_chars = self.compaction_max_summary_chars,
            .max_source_chars = self.compaction_max_source_chars,
            .token_limit = self.token_limit,
            .max_history_messages = self.max_history_messages,
            .workspace_dir = self.workspace_dir,
        });
    }

    /// Force-compress history for context exhaustion recovery.
    pub fn forceCompressHistory(self: *Agent) bool {
        return compaction.forceCompressHistory(self.allocator, &self.history);
    }

    fn appendUniqueString(
        list: *std.ArrayListUnmanaged([]const u8),
        allocator: std.mem.Allocator,
        value: []const u8,
    ) !void {
        if (value.len == 0) return;
        for (list.items) |existing| {
            if (std.mem.eql(u8, existing, value)) return;
        }
        try list.append(allocator, value);
    }

    fn providerIsFallback(self: *const Agent, provider_name: []const u8) bool {
        for (self.fallback_providers) |fallback_name| {
            if (std.mem.eql(u8, fallback_name, provider_name)) return true;
        }
        return false;
    }

    fn providerAuthStatus(self: *const Agent, provider_name: []const u8) []const u8 {
        if (providers.classifyProvider(provider_name) == .openai_codex_provider) {
            return "oauth";
        }

        const resolved_key = providers.resolveApiKeyFromConfig(
            self.allocator,
            provider_name,
            self.configured_providers,
        ) catch null;
        defer if (resolved_key) |key| self.allocator.free(key);

        if (resolved_key) |key| {
            if (std.mem.trim(u8, key, " \t\r\n").len > 0) return "configured";
        }
        return "missing";
    }

    fn currentModelFallbacks(self: *const Agent) ?[]const []const u8 {
        for (self.model_fallbacks) |entry| {
            if (std.mem.eql(u8, entry.model, self.model_name)) return entry.fallbacks;
        }
        return null;
    }

    fn composeFinalReply(self: *const Agent, base_text: []const u8, reasoning_content: ?[]const u8, usage: providers.TokenUsage) ![]const u8 {
        return commands.composeFinalReply(self, base_text, reasoning_content, usage);
    }

    fn shouldForceActionFollowThrough(text: []const u8) bool {
        const ascii_patterns = [_][]const u8{
            "i'll try",
            "i will try",
            "let me try",
            "i'll check",
            "i will check",
            "let me check",
            "i'll retry",
            "i will retry",
            "let me retry",
            "i'll attempt",
            "i will attempt",
            "i'll do that now",
            "i will do that now",
            "doing that now",
        };
        inline for (ascii_patterns) |pattern| {
            if (containsAsciiIgnoreCase(text, pattern)) return true;
        }

        const exact_patterns = [_][]const u8{
            "сейчас попробую",
            "Сейчас попробую",
            "попробую снова",
            "Попробую снова",
            "сейчас проверю",
            "Сейчас проверю",
            "сейчас сделаю",
            "Сейчас сделаю",
            "попробую переснять",
            "Попробую переснять",
            "сейчас перепроверю",
            "Сейчас перепроверю",
            "попробую ещё раз",
            "Попробую ещё раз",
        };
        inline for (exact_patterns) |pattern| {
            if (std.mem.indexOf(u8, text, pattern) != null) return true;
        }
        return false;
    }

    fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
        if (needle.len == 0 or haystack.len < needle.len) return false;
        var i: usize = 0;
        while (i + needle.len <= haystack.len) : (i += 1) {
            var matched = true;
            var j: usize = 0;
            while (j < needle.len) : (j += 1) {
                if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
        return false;
    }

    fn isExecToolName(tool_name: []const u8) bool {
        return commands.isExecToolName(tool_name);
    }

    fn execBlockMessage(self: *Agent, args: std.json.ObjectMap) ?[]const u8 {
        return commands.execBlockMessage(self, args);
    }

    pub fn formatModelStatus(self: *const Agent) ![]const u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);

        try w.print("Current model: {s}\n", .{self.model_name});
        try w.print("Default model: {s}\n", .{self.default_model});
        try w.print("Default provider: {s}\n", .{self.default_provider});

        var provider_names: std.ArrayListUnmanaged([]const u8) = .empty;
        defer provider_names.deinit(self.allocator);
        try appendUniqueString(&provider_names, self.allocator, self.default_provider);
        for (self.configured_providers) |entry| {
            try appendUniqueString(&provider_names, self.allocator, entry.name);
        }
        for (self.fallback_providers) |fallback_name| {
            try appendUniqueString(&provider_names, self.allocator, fallback_name);
        }

        if (provider_names.items.len > 0) {
            try w.writeAll("\nProviders:\n");
            for (provider_names.items) |provider_name| {
                const is_default = std.mem.eql(u8, provider_name, self.default_provider);
                const is_fallback = self.providerIsFallback(provider_name);
                const role_label = if (is_default and is_fallback)
                    " [default,fallback]"
                else if (is_default)
                    " [default]"
                else if (is_fallback)
                    " [fallback]"
                else
                    "";
                try w.print("  - {s}{s} (auth: {s})\n", .{
                    provider_name,
                    role_label,
                    self.providerAuthStatus(provider_name),
                });
            }
        }

        var model_names: std.ArrayListUnmanaged([]const u8) = .empty;
        defer model_names.deinit(self.allocator);
        try appendUniqueString(&model_names, self.allocator, self.model_name);
        try appendUniqueString(&model_names, self.allocator, self.default_model);
        for (self.model_fallbacks) |entry| {
            try appendUniqueString(&model_names, self.allocator, entry.model);
            for (entry.fallbacks) |fallback_model| {
                try appendUniqueString(&model_names, self.allocator, fallback_model);
            }
        }

        if (model_names.items.len > 0) {
            try w.writeAll("\nModels:\n");
            for (model_names.items) |model_name| {
                const is_current = std.mem.eql(u8, model_name, self.model_name);
                const is_default = std.mem.eql(u8, model_name, self.default_model);
                const role_label = if (is_current and is_default)
                    " [current,default]"
                else if (is_current)
                    " [current]"
                else if (is_default)
                    " [default]"
                else
                    "";
                try w.print("  - {s}{s}\n", .{ model_name, role_label });
            }
        }

        try w.writeAll("\nProvider chain: ");
        try w.writeAll(self.default_provider);
        if (self.fallback_providers.len == 0) {
            try w.writeAll(" (no fallback providers)");
        } else {
            for (self.fallback_providers) |fallback_provider| {
                try w.print(" -> {s}", .{fallback_provider});
            }
        }

        try w.writeAll("\nModel chain: ");
        try w.writeAll(self.model_name);
        if (self.currentModelFallbacks()) |fallbacks| {
            for (fallbacks) |fallback_model| {
                try w.print(" -> {s}", .{fallback_model});
            }
        } else {
            try w.writeAll(" (no configured fallbacks)");
        }

        try w.writeAll("\nSwitch: /model <name>");
        return try out.toOwnedSlice(self.allocator);
    }

    /// Handle slash commands that don't require LLM.
    /// Returns an owned response string, or null if not a slash command.
    pub fn handleSlashCommand(self: *Agent, message: []const u8) !?[]const u8 {
        return commands.handleSlashCommand(self, message);
    }

    /// Execute a single conversation turn: send messages to LLM, parse tool calls,
    /// execute tools, and loop until a final text response is produced.
    pub fn turn(self: *Agent, user_message: []const u8) ![]const u8 {
        self.context_was_compacted = false;
        commands.refreshSubagentToolContext(self);

        const effective_user_message = blk: {
            if (commands.bareSessionResetPrompt(user_message)) |fresh_prompt| {
                // Preserve slash side-effects (/new|/reset session clear), but route bare command
                // through a fresh-session prompt instead of returning command text.
                if (try self.handleSlashCommand(user_message)) |slash_response| {
                    self.allocator.free(slash_response);
                }
                break :blk fresh_prompt;
            }

            // Handle regular slash commands before sending to LLM (saves tokens).
            if (try self.handleSlashCommand(user_message)) |response| {
                return response;
            }
            break :blk user_message;
        };

        // Inject system prompt on first turn (or when tracked workspace files changed).
        const workspace_fp: ?u64 = prompt.workspacePromptFingerprint(self.allocator, self.workspace_dir) catch null;
        if (self.has_system_prompt and workspace_fp != null and self.workspace_prompt_fingerprint != workspace_fp) {
            self.has_system_prompt = false;
        }

        const turn_has_conversation_context = self.conversation_context != null;
        const conversation_context_changed = self.has_system_prompt and
            self.system_prompt_has_conversation_context != turn_has_conversation_context;

        if (!self.has_system_prompt or conversation_context_changed) {
            var cfg_for_caps_opt: ?Config = Config.load(self.allocator) catch null;
            defer if (cfg_for_caps_opt) |*cfg_loaded| cfg_loaded.deinit();
            const cfg_for_caps_ptr: ?*const Config = if (cfg_for_caps_opt) |*cfg_loaded| cfg_loaded else null;

            const capabilities_section = capabilities_mod.buildPromptSection(
                self.allocator,
                cfg_for_caps_ptr,
                self.tools,
            ) catch null;
            defer if (capabilities_section) |section| self.allocator.free(section);

            const system_prompt = try prompt.buildSystemPrompt(self.allocator, .{
                .workspace_dir = self.workspace_dir,
                .model_name = self.model_name,
                .tools = self.tools,
                .capabilities_section = capabilities_section,
                .conversation_context = self.conversation_context,
            });
            defer self.allocator.free(system_prompt);

            // Append tool instructions
            const tool_instructions = try dispatcher.buildToolInstructions(self.allocator, self.tools);
            defer self.allocator.free(tool_instructions);

            const full_system = try self.allocator.alloc(u8, system_prompt.len + tool_instructions.len);
            @memcpy(full_system[0..system_prompt.len], system_prompt);
            @memcpy(full_system[system_prompt.len..], tool_instructions);

            // Keep exactly one canonical system prompt at history[0].
            // This allows /model to invalidate and refresh the prompt in place.
            if (self.history.items.len > 0 and self.history.items[0].role == .system) {
                self.history.items[0].deinit(self.allocator);
                self.history.items[0] = .{
                    .role = .system,
                    .content = full_system,
                };
            } else if (self.history.items.len > 0) {
                try self.history.insert(self.allocator, 0, .{
                    .role = .system,
                    .content = full_system,
                });
            } else {
                try self.history.append(self.allocator, .{
                    .role = .system,
                    .content = full_system,
                });
            }
            self.has_system_prompt = true;
            self.system_prompt_has_conversation_context = turn_has_conversation_context;
            self.workspace_prompt_fingerprint = workspace_fp;
        }

        // Auto-save user message to memory (nanoTimestamp key to avoid collisions within the same second)
        if (self.auto_save) {
            if (self.mem) |mem| {
                const ts: u128 = @bitCast(std.time.nanoTimestamp());
                const save_key = std.fmt.allocPrint(self.allocator, "autosave_user_{d}", .{ts}) catch null;
                if (save_key) |key| {
                    defer self.allocator.free(key);
                    if (mem.store(key, effective_user_message, .conversation, self.memory_session_id)) |_| {
                        // Vector sync after auto-save
                        if (self.mem_rt) |rt| {
                            rt.syncVectorAfterStore(self.allocator, key, effective_user_message);
                        }
                    } else |_| {}
                }
            }
        }

        // Enrich message with memory context (always returns owned slice; ownership → history)
        // Uses retrieval pipeline (hybrid search, RRF, temporal decay, MMR) when MemoryRuntime is available.
        const enriched = if (self.mem) |mem|
            try memory_loader.enrichMessageWithRuntime(self.allocator, mem, self.mem_rt, effective_user_message, self.memory_session_id)
        else
            try self.allocator.dupe(u8, effective_user_message);
        errdefer self.allocator.free(enriched);

        try self.history.append(self.allocator, .{
            .role = .user,
            .content = enriched,
        });

        // ── Response cache check ──
        if (self.response_cache) |rc| {
            var key_buf: [16]u8 = undefined;
            const system_prompt = if (self.history.items.len > 0 and self.history.items[0].role == .system)
                self.history.items[0].content
            else
                null;
            const key_hex = cache.ResponseCache.cacheKeyHex(&key_buf, self.model_name, system_prompt, effective_user_message);
            if (rc.get(self.allocator, key_hex) catch null) |cached_response| {
                errdefer self.allocator.free(cached_response);
                const history_copy = try self.allocator.dupe(u8, cached_response);
                errdefer self.allocator.free(history_copy);
                try self.history.append(self.allocator, .{
                    .role = .assistant,
                    .content = history_copy,
                });
                return cached_response;
            }
        }

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
        var forced_follow_through_count: u32 = 0;
        while (iteration < self.max_tool_iterations) : (iteration += 1) {
            _ = iter_arena.reset(.retain_capacity);
            const arena = iter_arena.allocator();

            // Build messages slice for provider (arena-owned; freed at end of iteration)
            const messages = try self.buildProviderMessages(arena);

            const timer_start = std.time.milliTimestamp();
            const is_streaming = self.stream_callback != null and self.provider.supportsStreaming();
            const native_tools_enabled = !is_streaming and self.provider.supportsNativeTools();

            // Call provider: streaming (no retries, no native tools) or blocking with retry
            var response: ChatResponse = undefined;
            var response_attempt: u32 = 1;
            if (is_streaming) {
                self.logLlmRequest(iteration + 1, 1, messages, native_tools_enabled, true);
                const stream_result = self.provider.streamChat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .model = self.model_name,
                        .temperature = self.temperature,
                        .max_tokens = self.max_tokens,
                        .tools = null,
                        .timeout_secs = self.message_timeout_secs,
                        .reasoning_effort = self.reasoning_effort,
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
                self.logLlmRequest(iteration + 1, 1, messages, native_tools_enabled, false);
                response = self.provider.chat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .model = self.model_name,
                        .temperature = self.temperature,
                        .max_tokens = self.max_tokens,
                        .tools = if (native_tools_enabled) self.tool_specs else null,
                        .timeout_secs = self.message_timeout_secs,
                        .reasoning_effort = self.reasoning_effort,
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

                    // Context exhaustion: compact immediately before first retry
                    const err_name = @errorName(err);
                    if (providers.reliable.isContextExhausted(err_name) and
                        self.history.items.len > compaction.CONTEXT_RECOVERY_MIN_HISTORY and
                        self.forceCompressHistory())
                    {
                        self.context_was_compacted = true;
                        const recovery_msgs = self.buildProviderMessages(arena) catch |prep_err| return prep_err;
                        response_attempt = 2;
                        self.logLlmRequest(iteration + 1, 2, recovery_msgs, native_tools_enabled, false);
                        break :retry_blk self.provider.chat(
                            self.allocator,
                            .{
                                .messages = recovery_msgs,
                                .model = self.model_name,
                                .temperature = self.temperature,
                                .max_tokens = self.max_tokens,
                                .tools = if (native_tools_enabled) self.tool_specs else null,
                                .timeout_secs = self.message_timeout_secs,
                                .reasoning_effort = self.reasoning_effort,
                            },
                            self.model_name,
                            self.temperature,
                        ) catch return err;
                    }

                    // Retry once
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                    response_attempt = 2;
                    self.logLlmRequest(iteration + 1, 2, messages, native_tools_enabled, false);
                    break :retry_blk self.provider.chat(
                        self.allocator,
                        .{
                            .messages = messages,
                            .model = self.model_name,
                            .temperature = self.temperature,
                            .max_tokens = self.max_tokens,
                            .tools = if (native_tools_enabled) self.tool_specs else null,
                            .timeout_secs = self.message_timeout_secs,
                            .reasoning_effort = self.reasoning_effort,
                        },
                        self.model_name,
                        self.temperature,
                    ) catch |retry_err| {
                        // Context exhaustion recovery: if we have enough history,
                        // force-compress and retry once more
                        if (self.history.items.len > compaction.CONTEXT_RECOVERY_MIN_HISTORY and self.forceCompressHistory()) {
                            self.context_was_compacted = true;
                            const recovery_msgs = self.buildProviderMessages(arena) catch |prep_err| return prep_err;
                            response_attempt = 3;
                            self.logLlmRequest(iteration + 1, 3, recovery_msgs, native_tools_enabled, false);
                            break :retry_blk self.provider.chat(
                                self.allocator,
                                .{
                                    .messages = recovery_msgs,
                                    .model = self.model_name,
                                    .temperature = self.temperature,
                                    .max_tokens = self.max_tokens,
                                    .tools = if (native_tools_enabled) self.tool_specs else null,
                                    .timeout_secs = self.message_timeout_secs,
                                    .reasoning_effort = self.reasoning_effort,
                                },
                                self.model_name,
                                self.temperature,
                            ) catch return retry_err;
                        }
                        return retry_err;
                    };
                };
            }
            self.logLlmResponse(iteration + 1, response_attempt, &response);

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
            self.last_turn_usage = response.usage;

            const response_text = response.contentOrEmpty();
            const use_native = response.hasToolCalls();

            // Determine tool calls: structured (native) first, then XML fallback.
            // Keep the same loop semantics used by the reference runtime.
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
                assistant_history_content = try dispatcher.buildAssistantHistoryWithToolCalls(
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
                // Guardrail: if the model promises "I'll try/check now" but emits no
                // tool call, force one follow-up completion to either act now or
                // explicitly state the limitation without deferred promises.
                if (!is_streaming and
                    forced_follow_through_count < 2 and
                    iteration + 1 < self.max_tool_iterations and
                    shouldForceActionFollowThrough(display_text))
                {
                    try self.history.append(self.allocator, .{
                        .role = .assistant,
                        .content = try self.allocator.dupe(u8, display_text),
                    });
                    try self.history.append(self.allocator, .{
                        .role = .user,
                        .content = try self.allocator.dupe(u8, "SYSTEM: You just promised to take action now (for example: \"I'll try/check now\"). " ++
                            "Do it in this turn by issuing the appropriate tool call(s). " ++
                            "If no tool can perform it, respond with a clear limitation now and do not promise another future attempt."),
                    });
                    self.trimHistory();
                    self.freeResponseFields(&response);
                    forced_follow_through_count += 1;
                    continue;
                }

                // No tool calls — final response
                const base_text = if (self.context_was_compacted) blk: {
                    self.context_was_compacted = false;
                    break :blk try std.fmt.allocPrint(self.allocator, "[Context compacted]\n\n{s}", .{display_text});
                } else try self.allocator.dupe(u8, display_text);
                errdefer self.allocator.free(base_text);

                const final_text = try self.composeFinalReply(base_text, response.reasoning_content, response.usage);
                errdefer self.allocator.free(final_text);

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
                        // Truncate to ~100 bytes on a valid UTF-8 boundary
                        const summary = if (base_text.len > 100) blk: {
                            var end: usize = 100;
                            while (end > 0 and base_text[end] & 0xC0 == 0x80) end -= 1;
                            break :blk base_text[0..end];
                        } else base_text;
                        const ts: u128 = @bitCast(std.time.nanoTimestamp());
                        const save_key = std.fmt.allocPrint(self.allocator, "autosave_assistant_{d}", .{ts}) catch null;
                        if (save_key) |key| {
                            defer self.allocator.free(key);
                            if (mem.store(key, summary, .conversation, self.memory_session_id)) |_| {
                                // Vector sync after auto-save
                                if (self.mem_rt) |rt| {
                                    rt.syncVectorAfterStore(self.allocator, key, summary);
                                }
                            } else |_| {}
                        }
                    }
                }

                // Drain durable outbox after turn completion (best-effort)
                if (self.mem_rt) |rt| {
                    _ = rt.drainOutbox(self.allocator);
                }

                const complete_event = ObserverEvent{ .turn_complete = {} };
                self.observer.recordEvent(&complete_event);

                // Free provider response fields (content, tool_calls, model)
                // All borrows have been duped into final_text and history at this point.
                self.freeResponseFields(&response);
                self.allocator.free(base_text);

                // ── Cache store (only for direct responses, no tool calls) ──
                if (self.response_cache) |rc| {
                    var store_key_buf: [16]u8 = undefined;
                    const sys_prompt = if (self.history.items.len > 0 and self.history.items[0].role == .system)
                        self.history.items[0].content
                    else
                        null;
                    const store_key_hex = cache.ResponseCache.cacheKeyHex(&store_key_buf, self.model_name, sys_prompt, effective_user_message);
                    const token_count: u32 = @intCast(@min(self.last_turn_usage.total_tokens, std.math.maxInt(u32)));
                    rc.put(self.allocator, store_key_hex, self.model_name, final_text, token_count) catch {};
                }

                return final_text;
            }

            // There are tool calls — print intermediary text.
            // In tests, stdout is used by Zig's test runner protocol (`--listen`),
            // so avoid writing arbitrary text that can corrupt the control channel.
            if (!builtin.is_test and display_text.len > 0 and parsed_calls.len > 0 and !is_streaming) {
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
            const batch_updates_tools_md = tool_call_batch_updates_tools_md(arena, parsed_calls);

            const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
            if (self.log_tool_calls) {
                log.info("tool-call batch session=0x{x} count={d}", .{ session_hash, parsed_calls.len });
            }

            for (parsed_calls, 0..) |call, idx| {
                if (self.log_tool_calls) {
                    log.info(
                        "tool-call start session=0x{x} index={d} name={s} id={s}",
                        .{ session_hash, idx + 1, call.name, call.tool_call_id orelse "-" },
                    );
                }

                const tool_start_event = ObserverEvent{ .tool_call_start = .{ .tool = call.name } };
                self.observer.recordEvent(&tool_start_event);

                const tool_timer = std.time.milliTimestamp();
                const result = if (should_skip_tools_memory_store_duplicate(arena, batch_updates_tools_md, call))
                    ToolExecutionResult{
                        .name = call.name,
                        .output = "Skipped duplicate memory_store: TOOLS.md was updated in the same tool batch",
                        .success = true,
                        .tool_call_id = call.tool_call_id,
                    }
                else
                    self.executeTool(arena, call);
                const tool_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - tool_timer)));

                if (self.log_tool_calls) {
                    log.info(
                        "tool-call done session=0x{x} index={d} name={s} success={} duration_ms={d}",
                        .{ session_hash, idx + 1, call.name, result.success, tool_duration },
                    );
                }

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
                "{s}\n\nReflect on the tool results above and decide your next steps. " ++
                    "If a tool failed due to policy/permissions, do not repeat the same blocked call; explain the limitation and choose a different available tool or ask the user for permission/config change. " ++
                    "If a tool failed due to a transient issue (timeout/network/rate-limit), proactively retry up to 2 times with adjusted parameters before giving up.",
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

        // ── Graceful degradation: tool iterations exhausted ──────────
        // Instead of returning an error, ask the LLM to summarize what it
        // has accomplished so far and return that as the final response.
        const exhausted_event = ObserverEvent{ .tool_iterations_exhausted = .{ .iterations = self.max_tool_iterations } };
        self.observer.recordEvent(&exhausted_event);
        log.warn("Tool iterations exhausted ({d}/{d}), requesting summary", .{ self.max_tool_iterations, self.max_tool_iterations });

        // Append a pseudo-user message forcing a text-only summary
        try self.history.append(self.allocator, .{
            .role = .user,
            .content = try self.allocator.dupe(u8, "SYSTEM: You have reached the maximum number of tool iterations. " ++
                "You MUST NOT call any more tools. Summarize what you have accomplished " ++
                "so far and what remains to be done. Respond in the same language the user used."),
        });

        // Build messages for the summary call
        const summary_messages = self.buildMessageSlice() catch {
            const fallback = try std.fmt.allocPrint(self.allocator, "[Tool iteration limit: {d}/{d}] Could not produce a summary. Try /new and repeat your request.", .{ self.max_tool_iterations, self.max_tool_iterations });
            const complete_event = ObserverEvent{ .turn_complete = {} };
            self.observer.recordEvent(&complete_event);
            return fallback;
        };
        defer self.allocator.free(summary_messages);

        self.logLlmRequest(self.max_tool_iterations + 1, 1, summary_messages, false, false);
        var summary_response = self.provider.chat(
            self.allocator,
            .{
                .messages = summary_messages,
                .model = self.model_name,
                .temperature = self.temperature,
                .max_tokens = self.max_tokens,
                .tools = null, // force text-only
                .timeout_secs = self.message_timeout_secs,
                .reasoning_effort = self.reasoning_effort,
            },
            self.model_name,
            self.temperature,
        ) catch {
            const fallback = try std.fmt.allocPrint(self.allocator, "[Tool iteration limit: {d}/{d}] Could not produce a summary. Try /new and repeat your request.", .{ self.max_tool_iterations, self.max_tool_iterations });
            const complete_event = ObserverEvent{ .turn_complete = {} };
            self.observer.recordEvent(&complete_event);
            return fallback;
        };
        self.logLlmResponse(self.max_tool_iterations + 1, 1, &summary_response);
        defer self.freeResponseFields(&summary_response);

        const summary_text = summary_response.contentOrEmpty();
        const prefixed = try std.fmt.allocPrint(self.allocator, "[Tool iteration limit: {d}/{d}]\n\n{s}", .{ self.max_tool_iterations, self.max_tool_iterations, summary_text });
        errdefer self.allocator.free(prefixed);

        // Store in history (dupe the raw summary, not the prefixed version)
        try self.history.append(self.allocator, .{
            .role = .assistant,
            .content = try self.allocator.dupe(u8, summary_text),
        });

        // Compact/trim history so the next turn doesn't start with bloated context
        self.last_turn_compacted = self.autoCompactHistory() catch false;
        self.trimHistory();

        const complete_event = ObserverEvent{ .turn_complete = {} };
        self.observer.recordEvent(&complete_event);

        return prefixed;
    }

    /// Execute a tool by name lookup.
    /// Parses arguments_json once into a std.json.ObjectMap and passes it to the tool.
    fn tool_call_batch_updates_tools_md(allocator: std.mem.Allocator, calls: []const ParsedToolCall) bool {
        for (calls) |call| {
            if (tool_call_updates_tools_md(allocator, call)) return true;
        }
        return false;
    }

    fn tool_call_updates_tools_md(allocator: std.mem.Allocator, call: ParsedToolCall) bool {
        if (!std.mem.eql(u8, call.name, "file_write") and !std.mem.eql(u8, call.name, "file_edit")) return false;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, call.arguments_json, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;

        const path_value = parsed.value.object.get("path") orelse return false;
        const path = switch (path_value) {
            .string => |s| s,
            else => return false,
        };
        return is_tools_markdown_path(path);
    }

    fn should_skip_tools_memory_store_duplicate(
        allocator: std.mem.Allocator,
        batch_updates_tools_md: bool,
        call: ParsedToolCall,
    ) bool {
        if (!batch_updates_tools_md) return false;
        if (!std.mem.eql(u8, call.name, "memory_store")) return false;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, call.arguments_json, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;

        if (parsed.value.object.get("key")) |key_value| {
            const key = switch (key_value) {
                .string => |s| s,
                else => "",
            };
            if (is_tools_memory_key(key)) return true;
        }

        if (parsed.value.object.get("content")) |content_value| {
            const content = switch (content_value) {
                .string => |s| s,
                else => "",
            };
            if (std.ascii.indexOfIgnoreCase(content, "tools.md") != null) return true;
        }

        return false;
    }

    fn is_tools_markdown_path(path: []const u8) bool {
        const basename = path_basename_any_separator(path);
        if (basename.len == 0) return false;
        return std.ascii.eqlIgnoreCase(basename, "TOOLS.md");
    }

    fn path_basename_any_separator(path: []const u8) []const u8 {
        const slash_idx = std.mem.lastIndexOfScalar(u8, path, '/');
        const backslash_idx = std.mem.lastIndexOfScalar(u8, path, '\\');
        const sep_idx = switch (slash_idx != null and backslash_idx != null) {
            true => if (slash_idx.? > backslash_idx.?) slash_idx.? else backslash_idx.?,
            false => slash_idx orelse backslash_idx orelse return path,
        };
        if (sep_idx + 1 >= path.len) return "";
        return path[sep_idx + 1 ..];
    }

    fn starts_with_ascii_ignore_case(value: []const u8, prefix: []const u8) bool {
        if (value.len < prefix.len) return false;
        return std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
    }

    fn is_tools_memory_key(key: []const u8) bool {
        return starts_with_ascii_ignore_case(key, "pref.tools.") or
            starts_with_ascii_ignore_case(key, "preference.tools.") or
            std.ascii.eqlIgnoreCase(key, "__bootstrap.prompt.TOOLS.md");
    }

    fn executeTool(self: *Agent, tool_allocator: std.mem.Allocator, call: ParsedToolCall) ToolExecutionResult {
        // Policy gate: check autonomy and rate limit
        if (self.policy) |pol| {
            if (!pol.canAct()) {
                return .{
                    .name = call.name,
                    .output = "Action blocked: agent is in read-only mode",
                    .success = false,
                    .tool_call_id = call.tool_call_id,
                };
            }
            const allowed = pol.recordAction() catch true;
            if (!allowed) {
                return .{
                    .name = call.name,
                    .output = "Rate limit exceeded",
                    .success = false,
                    .tool_call_id = call.tool_call_id,
                };
            }
        }

        for (self.tools) |t| {
            if (std.mem.eql(u8, t.name(), call.name)) {
                // Parse arguments JSON to ObjectMap ONCE
                const parsed = std.json.parseFromSlice(
                    std.json.Value,
                    tool_allocator,
                    call.arguments_json,
                    .{},
                ) catch {
                    return .{
                        .name = call.name,
                        .output = "Invalid arguments JSON",
                        .success = false,
                        .tool_call_id = call.tool_call_id,
                    };
                };
                defer parsed.deinit();

                const args: std.json.ObjectMap = switch (parsed.value) {
                    .object => |o| o,
                    else => {
                        return .{
                            .name = call.name,
                            .output = "Arguments must be a JSON object",
                            .success = false,
                            .tool_call_id = call.tool_call_id,
                        };
                    },
                };

                if (isExecToolName(call.name)) {
                    if (self.execBlockMessage(args)) |msg| {
                        return .{
                            .name = call.name,
                            .output = msg,
                            .success = false,
                            .tool_call_id = call.tool_call_id,
                        };
                    }
                }

                const result = t.execute(tool_allocator, args) catch |err| {
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

    const LLM_LOG_MAX_BYTES: usize = 8192;

    fn llmLogPreview(text: []const u8) struct { slice: []const u8, truncated: bool } {
        if (text.len <= LLM_LOG_MAX_BYTES) {
            return .{ .slice = text, .truncated = false };
        }
        return .{ .slice = text[0..LLM_LOG_MAX_BYTES], .truncated = true };
    }

    fn logLlmRequest(self: *Agent, iteration: u32, attempt: u32, messages: []const ChatMessage, native_tools_enabled: bool, is_streaming: bool) void {
        if (!self.log_llm_io) return;
        const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
        log.info(
            "llm request session=0x{x} iter={d} attempt={d} provider={s} model={s} messages={d} native_tools={} streaming={}",
            .{
                session_hash,
                iteration,
                attempt,
                self.provider.getName(),
                self.model_name,
                messages.len,
                native_tools_enabled,
                is_streaming,
            },
        );
        for (messages, 0..) |msg, idx| {
            const preview = llmLogPreview(msg.content);
            const parts_count: usize = if (msg.content_parts) |parts| parts.len else 0;
            log.info(
                "llm request msg session=0x{x} iter={d} attempt={d} index={d} role={s} bytes={d} parts={d} content={f}{s}",
                .{
                    session_hash,
                    iteration,
                    attempt,
                    idx + 1,
                    msg.role.toSlice(),
                    msg.content.len,
                    parts_count,
                    std.json.fmt(preview.slice, .{}),
                    if (preview.truncated) " [truncated]" else "",
                },
            );
        }
    }

    fn logLlmResponse(self: *Agent, iteration: u32, attempt: u32, response: *const ChatResponse) void {
        if (!self.log_llm_io) return;
        const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
        const content = response.contentOrEmpty();
        const preview = llmLogPreview(content);
        log.info(
            "llm response session=0x{x} iter={d} attempt={d} model={s} bytes={d} tool_calls={d} usage={f} content={f}{s}",
            .{
                session_hash,
                iteration,
                attempt,
                if (response.model.len > 0) response.model else self.model_name,
                content.len,
                response.tool_calls.len,
                std.json.fmt(response.usage, .{}),
                std.json.fmt(preview.slice, .{}),
                if (preview.truncated) " [truncated]" else "",
            },
        );

        if (response.reasoning_content) |reasoning| {
            const r_preview = llmLogPreview(reasoning);
            log.info(
                "llm response reasoning session=0x{x} iter={d} attempt={d} bytes={d} content={f}{s}",
                .{
                    session_hash,
                    iteration,
                    attempt,
                    reasoning.len,
                    std.json.fmt(r_preview.slice, .{}),
                    if (r_preview.truncated) " [truncated]" else "",
                },
            );
        }

        for (response.tool_calls, 0..) |tc, idx| {
            const args_preview = llmLogPreview(tc.arguments);
            log.info(
                "llm response tool-call session=0x{x} iter={d} attempt={d} index={d} id={s} name={s} args={f}{s}",
                .{
                    session_hash,
                    iteration,
                    attempt,
                    idx + 1,
                    if (tc.id.len > 0) tc.id else "-",
                    tc.name,
                    std.json.fmt(args_preview.slice, .{}),
                    if (args_preview.truncated) " [truncated]" else "",
                },
            );
        }
    }

    /// Build provider-ready ChatMessage slice from owned history.
    /// Applies multimodal preprocessing and vision capability checks.
    fn buildProviderMessages(self: *Agent, arena: std.mem.Allocator) ![]ChatMessage {
        const m = try arena.alloc(ChatMessage, self.history.items.len);
        for (self.history.items, 0..) |*msg, i| {
            m[i] = msg.toChatMessage();
        }

        const image_marker_count = multimodal.countImageMarkersInLastUser(m);
        if (image_marker_count > 0 and !self.provider.supportsVisionForModel(self.model_name)) {
            return error.ProviderDoesNotSupportVision;
        }

        // Allow local multimodal reads from:
        // - workspace (e.g. screenshot tool output),
        // - autonomy.allowed_paths,
        // - platform temp dir (e.g. Telegram downloaded files).
        var allowed_dirs_list: std.ArrayListUnmanaged([]const u8) = .empty;
        try appendMultimodalAllowedDir(arena, &allowed_dirs_list, self.workspace_dir);
        for (self.allowed_paths) |dir| {
            try appendMultimodalAllowedDir(arena, &allowed_dirs_list, dir);
        }
        if (platform.getTempDir(arena) catch null) |tmp_dir| {
            try appendMultimodalAllowedDir(arena, &allowed_dirs_list, tmp_dir);
        }
        const allowed = try allowed_dirs_list.toOwnedSlice(arena);

        return multimodal.prepareMessagesForProvider(arena, m, .{
            .allowed_dirs = allowed,
        });
    }

    fn appendMultimodalAllowedDir(
        arena: std.mem.Allocator,
        dirs: *std.ArrayListUnmanaged([]const u8),
        raw_dir: []const u8,
    ) !void {
        const trimmed = std.mem.trimRight(u8, raw_dir, "/\\");
        if (trimmed.len == 0) return;

        if (!containsMultimodalDir(dirs.items, trimmed)) {
            try dirs.append(arena, trimmed);
        }

        // Add canonical path variant too (/var <-> /private/var on macOS).
        const canonical = std.fs.realpathAlloc(arena, trimmed) catch return;
        if (!containsMultimodalDir(dirs.items, canonical)) {
            try dirs.append(arena, canonical);
        }
    }

    fn containsMultimodalDir(dirs: []const []const u8, target: []const u8) bool {
        for (dirs) |dir| {
            if (std.mem.eql(u8, dir, target)) return true;
        }
        return false;
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
    fn trimHistory(self: *Agent) void {
        compaction.trimHistory(self.allocator, &self.history, self.max_history_messages);
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
        self.system_prompt_has_conversation_context = false;
        self.workspace_prompt_fingerprint = null;
    }

    /// Get total tokens used.
    pub fn tokensUsed(self: *const Agent) u64 {
        return self.total_tokens;
    }

    /// Get current history length.
    pub fn historyLen(self: *const Agent) usize {
        return self.history.items.len;
    }

    /// Load persisted messages into history (for session restore).
    /// Each entry has .role ("user"/"assistant") and .content.
    /// The agent takes ownership of the content strings.
    pub fn loadHistory(self: *Agent, entries: anytype) !void {
        for (entries) |entry| {
            const role: providers.Role = if (std.mem.eql(u8, entry.role, "assistant"))
                .assistant
            else if (std.mem.eql(u8, entry.role, "system"))
                .system
            else
                .user;
            try self.history.append(self.allocator, .{
                .role = role,
                .content = try self.allocator.dupe(u8, entry.content),
            });
        }
    }

    /// Get history entries as role-string + content pairs (for persistence).
    /// Caller owns the returned slice but NOT the inner strings (borrows from history).
    pub fn getHistory(self: *const Agent, allocator: std.mem.Allocator) ![]struct { role: []const u8, content: []const u8 } {
        const Pair = struct { role: []const u8, content: []const u8 };
        const result = try allocator.alloc(Pair, self.history.items.len);
        for (self.history.items, 0..) |*msg, i| {
            result[i] = .{
                .role = switch (msg.role) {
                    .system => "system",
                    .user => "user",
                    .assistant => "assistant",
                    .tool => "tool",
                },
                .content = msg.content,
            };
        }
        return result;
    }
};

pub const cli = @import("cli.zig");

/// CLI entry point — re-exported for backward compatibility.
pub const run = cli.run;

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
        .workspace_prompt_fingerprint = 1234,
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
    try std.testing.expect(agent.workspace_prompt_fingerprint == null);
}

test "dispatcher module reexport" {
    _ = dispatcher.ParsedToolCall;
    _ = dispatcher.ToolExecutionResult;
    _ = dispatcher.parseToolCalls;
    _ = dispatcher.formatToolResults;
    _ = dispatcher.buildToolInstructions;
    _ = dispatcher.buildAssistantHistoryWithToolCalls;
}

test "compaction module reexport" {
    _ = compaction.tokenEstimate;
    _ = compaction.autoCompactHistory;
    _ = compaction.forceCompressHistory;
    _ = compaction.trimHistory;
    _ = compaction.CompactionConfig;
}

test "cli module reexport" {
    _ = cli.run;
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
    _ = compaction;
    _ = cli;
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

test "Agent buildProviderMessages uses model-aware vision capability" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{};
        }
        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn supportsVision(_: *anyopaque) bool {
            return true;
        }
        fn supportsVisionForModel(_: *anyopaque, model: []const u8) bool {
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
        .supportsNativeTools = DummyProvider.supportsNativeTools,
        .supports_vision = DummyProvider.supportsVision,
        .supports_vision_for_model = DummyProvider.supportsVisionForModel,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const prov = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };

    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = prov,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "text-model",
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
        .role = .user,
        .content = try allocator.dupe(u8, "Check [IMAGE:https://example.com/a.jpg]"),
    });

    var arena_impl = std.heap.ArenaAllocator.init(allocator);
    defer arena_impl.deinit();
    const arena = arena_impl.allocator();

    try std.testing.expectError(error.ProviderDoesNotSupportVision, agent.buildProviderMessages(arena));

    agent.model_name = "vision-model";
    const messages = try agent.buildProviderMessages(arena);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expect(messages[0].content_parts != null);
}

test "Agent buildProviderMessages allows workspace image paths" {
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }
        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{};
        }
        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }
        fn supportsVision(_: *anyopaque) bool {
            return true;
        }
        fn supportsVisionForModel(_: *anyopaque, _: []const u8) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{
        .sub_path = "screen.png",
        .data = "\x89PNG\x0d\x0a\x1a\x0a",
    });

    const allocator = std.testing.allocator;
    const workspace_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace_path);
    const image_path = try std.fs.path.join(allocator, &.{ workspace_path, "screen.png" });
    defer allocator.free(image_path);

    var dummy: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supportsNativeTools,
        .supports_vision = DummyProvider.supportsVision,
        .supports_vision_for_model = DummyProvider.supportsVisionForModel,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const prov = Provider{ .ptr = @ptrCast(&dummy), .vtable = &vtable };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = prov,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "vision-model",
        .temperature = 0.7,
        .workspace_dir = workspace_path,
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try std.fmt.allocPrint(allocator, "Inspect [IMAGE:{s}]", .{image_path}),
    });

    var arena_impl = std.heap.ArenaAllocator.init(allocator);
    defer arena_impl.deinit();
    const arena = arena_impl.allocator();
    const messages = try agent.buildProviderMessages(arena);

    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expect(messages[0].content_parts != null);
    const parts = messages[0].content_parts.?;
    var has_image_part = false;
    for (parts) |part| {
        if (part == .image_base64) {
            has_image_part = true;
            break;
        }
    }
    try std.testing.expect(has_image_part);
}

test "Agent max_tool_iterations default" {
    try std.testing.expectEqual(@as(u32, 25), DEFAULT_MAX_TOOL_ITERATIONS);
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

fn find_tool_by_name(tools: []const Tool, name: []const u8) ?Tool {
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), name)) return t;
    }
    return null;
}

test "Agent.fromConfig resolves token limit from model lookup when unset" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.token_limit = config_types.DEFAULT_AGENT_TOKEN_LIMIT;
    cfg.agent.token_limit_explicit = false;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u64, 128_000), agent.token_limit);
    try std.testing.expect(agent.token_limit_override == null);
    try std.testing.expectEqual(@as(u32, max_tokens_resolver.DEFAULT_MODEL_MAX_TOKENS), agent.max_tokens);
    try std.testing.expect(agent.max_tokens_override == null);
}

test "Agent.fromConfig keeps explicit token_limit override" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.token_limit = 64_000;
    cfg.agent.token_limit_explicit = true;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u64, 64_000), agent.token_limit);
    try std.testing.expectEqual(@as(?u64, 64_000), agent.token_limit_override);
}

test "Agent.fromConfig resolves max_tokens from provider lookup when unset" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "qianfan/custom-model",
        .allocator = allocator,
    };
    cfg.max_tokens = null;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u32, 32_768), agent.max_tokens);
    try std.testing.expect(agent.max_tokens_override == null);
}

test "Agent.fromConfig keeps explicit max_tokens override" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "qianfan/custom-model",
        .allocator = allocator,
    };
    cfg.max_tokens = 1536;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u32, 1536), agent.max_tokens);
    try std.testing.expectEqual(@as(?u32, 1536), agent.max_tokens_override);
}

test "Agent.fromConfig clamps max_tokens to token_limit" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.token_limit = 4096;
    cfg.agent.token_limit_explicit = true;
    cfg.max_tokens = 8192;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u64, 4096), agent.token_limit);
    try std.testing.expectEqual(@as(u32, 4096), agent.max_tokens);
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

test "slash /reset clears history and switches model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "hello"),
    });

    const response = (try agent.handleSlashCommand("/reset gpt-4o-mini")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Session cleared.") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4o-mini") != null);
    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expectEqualStrings("gpt-4o-mini", agent.model_name);
}

test "turn bare /new routes through fresh-session prompt" {
    const EchoProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, req: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            var last_user: []const u8 = "";
            for (req.messages) |msg| {
                if (msg.role == .user) last_user = msg.content;
            }

            return .{
                .content = try allocator.dupe(u8, last_user),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "echo-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = EchoProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = EchoProvider.chatWithSystem,
        .chat = EchoProvider.chat,
        .supportsNativeTools = EchoProvider.supportsNativeTools,
        .getName = EchoProvider.getName,
        .deinit = EchoProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = true,
    };
    defer agent.deinit();

    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "old-before-reset"),
    });

    const response = try agent.turn("/new");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Execute your Session Startup sequence now") != null);
    try std.testing.expectEqual(@as(usize, 1), provider_state.call_count);

    for (agent.history.items) |msg| {
        try std.testing.expect(std.mem.indexOf(u8, msg.content, "old-before-reset") == null);
    }
}

test "turn /reset with argument stays slash-only command" {
    const NoCallProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return error.UnexpectedProviderCall;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "nocall-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state: u8 = 0;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = NoCallProvider.chatWithSystem,
        .chat = NoCallProvider.chat,
        .supportsNativeTools = NoCallProvider.supportsNativeTools,
        .getName = NoCallProvider.getName,
        .deinit = NoCallProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("/reset gpt-4o-mini");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Session cleared.") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4o-mini") != null);
    try std.testing.expectEqualStrings("gpt-4o-mini", agent.model_name);
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

test "slash /commands aliases to help" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/commands")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "/new") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/commands") != null);
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

test "slash /whoami returns current session id" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.memory_session_id = "telegram:chat123";

    const response = (try agent.handleSlashCommand("/whoami")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "telegram:chat123") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "test-model") != null);
}

test "slash /model switches model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.max_tokens = 111;
    agent.has_system_prompt = true;

    const response = (try agent.handleSlashCommand("/model gpt-4o")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4o") != null);
    try std.testing.expectEqualStrings("gpt-4o", agent.model_name);
    try std.testing.expectEqualStrings("gpt-4o", agent.default_model);
    try std.testing.expectEqual(@as(u64, 128_000), agent.token_limit);
    try std.testing.expectEqual(@as(u32, 8192), agent.max_tokens);
    try std.testing.expect(!agent.has_system_prompt);
}

test "slash /model with colon switches model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.max_tokens = 111;

    const response = (try agent.handleSlashCommand("/model: gpt-4.1-mini")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4.1-mini") != null);
    try std.testing.expectEqualStrings("gpt-4.1-mini", agent.model_name);
    try std.testing.expectEqual(@as(u64, 128_000), agent.token_limit);
    try std.testing.expectEqual(@as(u32, 8192), agent.max_tokens);
}

test "slash /model with telegram bot mention switches model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.max_tokens = 111;

    const response = (try agent.handleSlashCommand("/model@nullclaw_bot qianfan/custom-model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "qianfan/custom-model") != null);
    try std.testing.expectEqualStrings("qianfan/custom-model", agent.model_name);
    try std.testing.expectEqualStrings("qianfan/custom-model", agent.default_model);
    try std.testing.expectEqual(@as(u32, 32_768), agent.max_tokens);
}

test "slash /model resolves provider max_tokens fallback" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.max_tokens = 111;

    const response = (try agent.handleSlashCommand("/model qianfan/custom-model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "qianfan/custom-model") != null);
    try std.testing.expectEqualStrings("qianfan/custom-model", agent.model_name);
    try std.testing.expectEqual(@as(u32, 32_768), agent.max_tokens);
}

test "slash /model keeps explicit token_limit override" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.token_limit_override = 64_000;
    agent.token_limit = 64_000;
    agent.max_tokens_override = 1024;
    agent.max_tokens = 1024;

    const response = (try agent.handleSlashCommand("/model claude-opus-4-6")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "claude-opus-4-6") != null);
    try std.testing.expectEqual(@as(u64, 64_000), agent.token_limit);
    try std.testing.expectEqual(@as(u32, 1024), agent.max_tokens);
}

test "slash /model without name shows current" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/model ")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "test-model") != null);
}

test "slash /models aliases to /model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/models list")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Current model: test-model") != null);
}

test "slash /model list aliases to model status" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/model list")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Current model: test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Switch: /model <name>") != null);
}

test "slash /memory list hides internal autosave and hygiene entries by default" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "hello", .conversation, null);
    try mem.store("last_hygiene_at", "1772051598", .core, null);
    try mem.store("MEMORY:99", "**last_hygiene_at**: 1772051691", .core, null);
    try mem.store("user_language", "ru", .core, null);

    const resolved = memory_mod.ResolvedConfig{
        .primary_backend = "test",
        .retrieval_mode = "keyword",
        .vector_mode = "none",
        .embedding_provider = "none",
        .rollout_mode = "off",
        .vector_sync_mode = "best_effort",
        .hygiene_enabled = false,
        .snapshot_enabled = false,
        .cache_enabled = false,
        .semantic_cache_enabled = false,
        .summarizer_enabled = false,
        .source_count = 0,
        .fallback_policy = "degrade",
    };
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };
    agent.mem_rt = &rt;

    const response = (try agent.handleSlashCommand("/memory list --limit 10")).?;
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "user_language") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "autosave_user_") == null);
    try std.testing.expect(std.mem.indexOf(u8, response, "last_hygiene_at") == null);
}

test "slash /memory list includes internal entries when requested" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "hello", .conversation, null);
    try mem.store("last_hygiene_at", "1772051598", .core, null);

    const resolved = memory_mod.ResolvedConfig{
        .primary_backend = "test",
        .retrieval_mode = "keyword",
        .vector_mode = "none",
        .embedding_provider = "none",
        .rollout_mode = "off",
        .vector_sync_mode = "best_effort",
        .hygiene_enabled = false,
        .snapshot_enabled = false,
        .cache_enabled = false,
        .semantic_cache_enabled = false,
        .summarizer_enabled = false,
        .source_count = 0,
        .fallback_policy = "degrade",
    };
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };
    agent.mem_rt = &rt;

    const response = (try agent.handleSlashCommand("/memory list --limit 10 --include-internal")).?;
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "autosave_user_1") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "last_hygiene_at") != null);
}

test "slash /model shows provider and model fallback chains" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const configured_providers = [_]config_types.ProviderEntry{
        .{ .name = "openai-codex" },
        .{ .name = "openrouter", .api_key = "sk-or-test" },
    };
    const model_fallbacks = [_]config_types.ModelFallbackEntry{
        .{
            .model = "gpt-5.3-codex",
            .fallbacks = &.{"openrouter/anthropic/claude-sonnet-4"},
        },
    };

    agent.model_name = "gpt-5.3-codex";
    agent.default_model = "gpt-5.3-codex";
    agent.default_provider = "openai-codex";
    agent.configured_providers = &configured_providers;
    agent.fallback_providers = &.{"openrouter"};
    agent.model_fallbacks = &model_fallbacks;

    const response = (try agent.handleSlashCommand("/model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Provider chain: openai-codex -> openrouter") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response,
        "Model chain: gpt-5.3-codex -> openrouter/anthropic/claude-sonnet-4",
    ) != null);
}

test "slash /compact with short history is a no-op" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/compact")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Nothing to compact.", response);
}

test "slash /think updates reasoning effort" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const set_resp = (try agent.handleSlashCommand("/think high")).?;
    defer allocator.free(set_resp);
    try std.testing.expect(std.mem.indexOf(u8, set_resp, "high") != null);
    try std.testing.expectEqualStrings("high", agent.reasoning_effort.?);

    const off_resp = (try agent.handleSlashCommand("/think off")).?;
    defer allocator.free(off_resp);
    try std.testing.expect(agent.reasoning_effort == null);
}

test "slash /verbose updates verbose level" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/verbose full")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.verbose_level == .full);
}

test "slash /reasoning updates reasoning mode" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/reasoning stream")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.reasoning_mode == .stream);
}

test "slash /exec updates runtime exec settings" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/exec host=sandbox security=full ask=off node=node-1")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.exec_host == .sandbox);
    try std.testing.expect(agent.exec_security == .full);
    try std.testing.expect(agent.exec_ask == .off);
    try std.testing.expect(agent.exec_node_id != null);
    try std.testing.expectEqualStrings("node-1", agent.exec_node_id.?);
}

test "slash /queue updates queue settings" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/queue debounce debounce:2s cap:25 drop:newest")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.queue_mode == .debounce);
    try std.testing.expectEqual(@as(u32, 2000), agent.queue_debounce_ms);
    try std.testing.expectEqual(@as(u32, 25), agent.queue_cap);
    try std.testing.expect(agent.queue_drop == .newest);
}

test "slash /usage updates usage mode" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/usage full")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.usage_mode == .full);
}

test "slash /tts updates tts settings" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/tts always provider openai limit 1200 summary on audio off")).?;
    defer allocator.free(response);

    try std.testing.expect(agent.tts_mode == .always);
    try std.testing.expect(agent.tts_provider != null);
    try std.testing.expectEqualStrings("openai", agent.tts_provider.?);
    try std.testing.expectEqual(@as(u32, 1200), agent.tts_limit_chars);
    try std.testing.expect(agent.tts_summary);
    try std.testing.expect(!agent.tts_audio);
}

test "slash /stop handled explicitly" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/stop")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "No active background task") != null);
}

test "slash /approve executes pending bash command" {
    const allocator = std.testing.allocator;

    const shell_impl = try allocator.create(tools_mod.shell.ShellTool);
    shell_impl.* = .{ .workspace_dir = "." };
    const shell_tool = shell_impl.tool();
    defer shell_tool.deinit(allocator);

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{shell_tool},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const exec_resp = (try agent.handleSlashCommand("/exec ask=always")).?;
    defer allocator.free(exec_resp);

    const pending_resp = (try agent.handleSlashCommand("/bash echo hello-approve")).?;
    defer allocator.free(pending_resp);
    try std.testing.expect(std.mem.indexOf(u8, pending_resp, "Exec approval required") != null);
    try std.testing.expect(agent.pending_exec_command != null);

    const approve_resp = (try agent.handleSlashCommand("/approve allow-once")).?;
    defer allocator.free(approve_resp);
    try std.testing.expect(std.mem.indexOf(u8, approve_resp, "Approved exec") != null);
    try std.testing.expect(std.mem.indexOf(u8, approve_resp, "hello-approve") != null);
    try std.testing.expect(agent.pending_exec_command == null);
}

test "slash /restart clears runtime command settings" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const think_resp = (try agent.handleSlashCommand("/think high")).?;
    defer allocator.free(think_resp);
    const verbose_resp = (try agent.handleSlashCommand("/verbose full")).?;
    defer allocator.free(verbose_resp);
    const usage_resp = (try agent.handleSlashCommand("/usage full")).?;
    defer allocator.free(usage_resp);
    const tts_resp = (try agent.handleSlashCommand("/tts always provider test-provider")).?;
    defer allocator.free(tts_resp);

    const response = (try agent.handleSlashCommand("/restart")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Session restarted.", response);
    try std.testing.expect(agent.reasoning_effort == null);
    try std.testing.expect(agent.verbose_level == .off);
    try std.testing.expect(agent.usage_mode == .off);
    try std.testing.expect(agent.tts_mode == .off);
    try std.testing.expect(agent.tts_provider == null);
}

test "turn includes reasoning and usage footer when enabled" {
    const ProviderState = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "final answer"),
                .tool_calls = &.{},
                .usage = .{ .prompt_tokens = 4, .completion_tokens = 6, .total_tokens = 10 },
                .model = try allocator.dupe(u8, "test-model"),
                .reasoning_content = try allocator.dupe(u8, "thinking trace"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "test";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    var state: u8 = 0;
    const vtable = Provider.VTable{
        .chatWithSystem = ProviderState.chatWithSystem,
        .chat = ProviderState.chat,
        .supportsNativeTools = ProviderState.supportsNativeTools,
        .getName = ProviderState.getName,
        .deinit = ProviderState.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &vtable };

    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const reasoning_cmd = (try agent.handleSlashCommand("/reasoning on")).?;
    defer allocator.free(reasoning_cmd);
    const usage_cmd = (try agent.handleSlashCommand("/usage tokens")).?;
    defer allocator.free(usage_cmd);

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Reasoning:\nthinking trace") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "[usage] total_tokens=10") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "final answer") != null);
}

test "turn refreshes system prompt after workspace markdown change" {
    const ReloadProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("SOUL.md", .{});
        defer f.close();
        try f.writeAll("SOUL-V1");
    }

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    var provider_state: u8 = 0;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ReloadProvider.chatWithSystem,
        .chat = ReloadProvider.chat,
        .supportsNativeTools = ReloadProvider.supportsNativeTools,
        .getName = ReloadProvider.getName,
        .deinit = ReloadProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = workspace,
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const first = try agent.turn("first");
    defer allocator.free(first);
    try std.testing.expect(agent.history.items.len > 0);
    try std.testing.expectEqual(providers.Role.system, agent.history.items[0].role);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "SOUL-V1") != null);

    {
        const f = try tmp.dir.createFile("SOUL.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("SOUL-V2-UPDATED");
    }

    const second = try agent.turn("second");
    defer allocator.free(second);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "SOUL-V2-UPDATED") != null);
}

test "turn refreshes system prompt after TOOLS.md change" {
    const ReloadProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("TOOLS.md", .{});
        defer f.close();
        try f.writeAll("TOOLS-V1");
    }

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    var provider_state: u8 = 0;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ReloadProvider.chatWithSystem,
        .chat = ReloadProvider.chat,
        .supportsNativeTools = ReloadProvider.supportsNativeTools,
        .getName = ReloadProvider.getName,
        .deinit = ReloadProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = workspace,
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const first = try agent.turn("first");
    defer allocator.free(first);
    try std.testing.expect(agent.history.items.len > 0);
    try std.testing.expectEqual(providers.Role.system, agent.history.items[0].role);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "TOOLS-V1") != null);

    {
        const f = try tmp.dir.createFile("TOOLS.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("TOOLS-V2-UPDATED");
    }

    const second = try agent.turn("second");
    defer allocator.free(second);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "TOOLS-V2-UPDATED") != null);
}

test "turn refreshes system prompt after USER.md change" {
    const ReloadProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** USER-V1");
    }

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    var provider_state: u8 = 0;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ReloadProvider.chatWithSystem,
        .chat = ReloadProvider.chat,
        .supportsNativeTools = ReloadProvider.supportsNativeTools,
        .getName = ReloadProvider.getName,
        .deinit = ReloadProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = workspace,
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const first = try agent.turn("first");
    defer allocator.free(first);
    try std.testing.expect(agent.history.items.len > 0);
    try std.testing.expectEqual(providers.Role.system, agent.history.items[0].role);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "USER-V1") != null);

    {
        const f = try tmp.dir.createFile("USER.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("- **Name:** USER-V2-UPDATED");
    }

    const second = try agent.turn("second");
    defer allocator.free(second);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "USER-V2-UPDATED") != null);
}

test "exec security deny blocks shell tool execution" {
    const allocator = std.testing.allocator;
    const shell_impl = try allocator.create(tools_mod.shell.ShellTool);
    shell_impl.* = .{ .workspace_dir = "." };
    const shell_tool = shell_impl.tool();
    defer shell_tool.deinit(allocator);

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{shell_tool},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const cmd_resp = (try agent.handleSlashCommand("/exec security=deny")).?;
    defer allocator.free(cmd_resp);

    const call = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"echo hello\"}",
        .tool_call_id = null,
    };
    const result = agent.executeTool(allocator, call);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "security=deny") != null);
}

test "exec ask always registers pending approval from tool path" {
    const allocator = std.testing.allocator;
    const shell_impl = try allocator.create(tools_mod.shell.ShellTool);
    shell_impl.* = .{ .workspace_dir = "." };
    const shell_tool = shell_impl.tool();
    defer shell_tool.deinit(allocator);

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{shell_tool},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 20,
        .auto_save = false,
        .history = .empty,
    };
    defer agent.deinit();

    const cmd_resp = (try agent.handleSlashCommand("/exec ask=always")).?;
    defer allocator.free(cmd_resp);

    const call = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"echo hello\"}",
        .tool_call_id = null,
    };
    const result = agent.executeTool(allocator, call);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "approval required") != null);
    try std.testing.expect(agent.pending_exec_command != null);
    try std.testing.expectEqualStrings("echo hello", agent.pending_exec_command.?);
}

test "slash additional commands are handled" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const cmd_list = [_][]const u8{
        "/allowlist",
        "/elevated full",
        "/dock-telegram",
        "/bash echo hi",
        "/approve",
        "/poll",
        "/subagents",
        "/config get model",
        "/skill list",
    };

    for (cmd_list) |cmd| {
        const response_opt = try agent.handleSlashCommand(cmd);
        try std.testing.expect(response_opt != null);
        const response = response_opt.?;
        try std.testing.expect(response.len > 0);
        allocator.free(response);
    }
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

test "tool_call_batch_updates_tools_md detects writes to TOOLS.md" {
    const allocator = std.testing.allocator;

    const calls_match = [_]ParsedToolCall{
        .{ .name = "file_write", .arguments_json = "{\"path\":\"TOOLS.md\",\"content\":\"x\"}" },
        .{ .name = "file_edit", .arguments_json = "{\"path\":\"notes/TOOLS.md\",\"old_text\":\"a\",\"new_text\":\"b\"}" },
    };
    try std.testing.expect(Agent.tool_call_batch_updates_tools_md(allocator, &calls_match));

    const calls_no_match = [_]ParsedToolCall{
        .{ .name = "file_write", .arguments_json = "{\"path\":\"README.md\",\"content\":\"x\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"pref.tools.file_read_over_cat\",\"content\":\"rule\"}" },
    };
    try std.testing.expect(!Agent.tool_call_batch_updates_tools_md(allocator, &calls_no_match));
}

test "should_skip_tools_memory_store_duplicate skips only tools-related memory_store entries" {
    const allocator = std.testing.allocator;

    const calls = [_]ParsedToolCall{
        .{ .name = "file_edit", .arguments_json = "{\"path\":\"./config/TOOLS.md\",\"old_text\":\"old\",\"new_text\":\"new\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"pref.tools.file_read_over_cat\",\"content\":\"Always use file_read\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"user.nickname\",\"content\":\"DonPrus\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"session.note\",\"content\":\"Rule is documented in TOOLS.md\"}" },
    };

    const batch_updates_tools_md = Agent.tool_call_batch_updates_tools_md(allocator, &calls);
    try std.testing.expect(batch_updates_tools_md);
    try std.testing.expect(Agent.should_skip_tools_memory_store_duplicate(allocator, batch_updates_tools_md, calls[1]));
    try std.testing.expect(!Agent.should_skip_tools_memory_store_duplicate(allocator, batch_updates_tools_md, calls[2]));
    try std.testing.expect(Agent.should_skip_tools_memory_store_duplicate(allocator, batch_updates_tools_md, calls[3]));
    try std.testing.expect(!Agent.should_skip_tools_memory_store_duplicate(allocator, false, calls[1]));
}

test "Agent turn skips duplicate memory_store when TOOLS.md is updated in same batch" {
    const FileWriteProbeTool = struct {
        const Self = @This();
        count: *usize,
        pub const tool_name = "file_write";
        pub const tool_description = "probe";
        pub const tool_params =
            \\{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}
        ;
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, _: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.count.* += 1;
            return .{ .success = true, .output = "file_write probe ok" };
        }
    };

    const MemoryStoreProbeTool = struct {
        const Self = @This();
        count: *usize,
        pub const tool_name = "memory_store";
        pub const tool_description = "probe";
        pub const tool_params =
            \\{"type":"object","properties":{"key":{"type":"string"},"content":{"type":"string"}},"required":["key","content"]}
        ;
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, _: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.count.* += 1;
            return .{ .success = true, .output = "memory_store probe ok" };
        }
    };

    const StepProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 2);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-file"),
                    .name = try allocator.dupe(u8, "file_write"),
                    .arguments = try allocator.dupe(u8, "{\"path\":\"TOOLS.md\",\"content\":\"Use file_read\"}"),
                };
                tool_calls[1] = .{
                    .id = try allocator.dupe(u8, "call-memory"),
                    .name = try allocator.dupe(u8, "memory_store"),
                    .arguments = try allocator.dupe(u8, "{\"key\":\"pref.tools.file_read_over_cat\",\"content\":\"Use file_read\"}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "applying"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            return .{
                .content = try allocator.dupe(u8, "done"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "step-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = StepProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = StepProvider.chatWithSystem,
        .chat = StepProvider.chat,
        .supportsNativeTools = StepProvider.supportsNativeTools,
        .getName = StepProvider.getName,
        .deinit = StepProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var file_write_count: usize = 0;
    var memory_store_count: usize = 0;
    var file_write_tool_impl = FileWriteProbeTool{ .count = &file_write_count };
    var memory_store_tool_impl = MemoryStoreProbeTool{ .count = &memory_store_count };
    const tool_list = [_]Tool{ file_write_tool_impl.tool(), memory_store_tool_impl.tool() };

    var specs = try allocator.alloc(ToolSpec, tool_list.len);
    for (tool_list, 0..) |t, i| {
        specs[i] = .{
            .name = t.name(),
            .description = t.description(),
            .parameters_json = t.parametersJson(),
        };
    }

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tool_list,
        .tool_specs = specs,
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("update tools guidance");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("done", response);
    try std.testing.expectEqual(@as(usize, 1), file_write_count);
    try std.testing.expectEqual(@as(usize, 0), memory_store_count);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
}

test "bindMemoryTools wires memory tools to sqlite backend" {
    const allocator = std.testing.allocator;

    var cfg = Config{
        .workspace_dir = "/tmp/yc_test",
        .config_path = "/tmp/yc_test/config.json",
        .default_model = "test/mock-model",
        .allocator = allocator,
    };

    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{});
    defer tools_mod.deinitTools(allocator, tools);

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    var mem = sqlite_mem.memory();
    tools_mod.bindMemoryTools(tools, mem);

    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator_: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator_.dupe(u8, "");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{};
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    var dummy_state: u8 = 0;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supportsNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };
    const provider_i = Provider{
        .ptr = @ptrCast(&dummy_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(
        allocator,
        &cfg,
        provider_i,
        tools,
        mem,
        noop.observer(),
    );
    defer agent.deinit();

    const store_tool = find_tool_by_name(tools, "memory_store").?;
    const store_args = try tools_mod.parseTestArgs("{\"key\":\"preference.test\",\"content\":\"123\"}");
    defer store_args.deinit();

    const store_result = try store_tool.execute(allocator, store_args.value.object);
    defer if (store_result.output.len > 0) allocator.free(store_result.output);
    try std.testing.expect(store_result.success);
    try std.testing.expect(std.mem.indexOf(u8, store_result.output, "Stored memory") != null);

    const entry = try mem.get(allocator, "preference.test");
    try std.testing.expect(entry != null);
    if (entry) |e| {
        defer e.deinit(allocator);
        try std.testing.expectEqualStrings("123", e.content);
    }

    const recall_tool = find_tool_by_name(tools, "memory_recall").?;
    const recall_args = try tools_mod.parseTestArgs("{\"query\":\"preference.test\"}");
    defer recall_args.deinit();

    const recall_result = try recall_tool.execute(allocator, recall_args.value.object);
    defer if (recall_result.output.len > 0) allocator.free(recall_result.output);
    try std.testing.expect(recall_result.success);
    try std.testing.expect(std.mem.indexOf(u8, recall_result.output, "preference.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, recall_result.output, "123") != null);
}

test "Agent tool loop frees dynamic tool outputs" {
    const DynamicOutputTool = struct {
        const Self = @This();
        pub const tool_name = "leak_probe";
        pub const tool_description = "Returns dynamically allocated tool output";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{
                .success = true,
                .output = try allocator.dupe(u8, "dynamic-tool-output"),
            };
        }
    };

    const StepProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-1"),
                    .name = try allocator.dupe(u8, "leak_probe"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };

                return .{
                    .content = try allocator.dupe(u8, "Running tool"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            return .{
                .content = try allocator.dupe(u8, "done"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "step-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = StepProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = StepProvider.chatWithSystem,
        .chat = StepProvider.chat,
        .supportsNativeTools = StepProvider.supportsNativeTools,
        .getName = StepProvider.getName,
        .deinit = StepProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var tool_impl = DynamicOutputTool{};
    const tool_list = [_]Tool{tool_impl.tool()};

    var specs = try allocator.alloc(ToolSpec, tool_list.len);
    for (tool_list, 0..) |t, i| {
        specs[i] = .{
            .name = t.name(),
            .description = t.description(),
            .parameters_json = t.parametersJson(),
        };
    }

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tool_list,
        .tool_specs = specs,
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("run tool");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("done", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
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
    const test_cb: providers.StreamCallback = struct {
        fn cb(_: *anyopaque, _: providers.StreamChunk) void {}
    }.cb;
    agent.stream_callback = test_cb;
    agent.stream_ctx = @ptrCast(&ctx);

    try std.testing.expect(agent.stream_callback != null);
    try std.testing.expect(agent.stream_ctx != null);
}

test "Agent shouldForceActionFollowThrough detects english deferred promise" {
    try std.testing.expect(Agent.shouldForceActionFollowThrough("I'll try again with a different filename now."));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("let me check that and get back in a moment"));
}

test "Agent shouldForceActionFollowThrough detects russian deferred promise" {
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Сейчас попробую переснять и отправить файл."));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("сейчас проверю и вернусь с результатом"));
}

test "Agent shouldForceActionFollowThrough ignores normal final answer" {
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Вот результат: файл успешно отправлен."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I cannot do that in this environment."));
}
