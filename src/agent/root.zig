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
const bootstrap_mod = @import("../bootstrap/root.zig");
const capabilities_mod = @import("../capabilities.zig");
const multimodal = @import("../multimodal.zig");
const platform = @import("../platform.zig");
const observability = @import("../observability.zig");
const Observer = observability.Observer;
const ObserverEvent = observability.ObserverEvent;
const SecurityPolicy = @import("../security/policy.zig").SecurityPolicy;
const verbose_mod = @import("../verbose.zig");

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

pub fn estimate_text_tokens(text: []const u8) u32 {
    return @intCast((text.len + 3) / 4);
}

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

    pub const UsageRecord = struct {
        ts: i64,
        provider: []const u8,
        model: []const u8,
        usage: providers.TokenUsage,
        success: bool,
    };

    pub const UsageRecordCallback = *const fn (ctx: *anyopaque, record: UsageRecord) void;

    allocator: std.mem.Allocator,
    provider: Provider,
    tools: []const Tool,
    tool_specs: []const ToolSpec,
    mem: ?Memory,
    bootstrap: ?bootstrap_mod.BootstrapProvider = null,
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
    profile_name: ?[]const u8 = null,
    profile_system_prompt: ?[]const u8 = null,
    model_routes: []const config_types.ModelRouteConfig = &.{},
    model_pinned_by_user: bool = false,
    last_route_trace: ?[]u8 = null,
    degraded_routes: std.ArrayListUnmanaged(DegradedRoute) = .empty,
    configured_providers: []const config_types.ProviderEntry = &.{},
    fallback_providers: []const []const u8 = &.{},
    model_fallbacks: []const config_types.ModelFallbackEntry = &.{},
    temperature: f64,
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    multimodal_unrestricted: bool = false,
    /// List of models that do not support image/vision input.
    /// When image markers are detected and the model is in this list,
    /// the agent will skip processing images instead of returning an error.
    vision_disabled_models: []const []const u8 = &.{},
    /// When true, automatically adds the current model to vision_disabled_models
    /// upon receiving a "model does not support vision" error.
    auto_disable_vision_on_error: bool = true,
    /// Models auto-detected as not supporting vision (built at runtime).
    detected_vision_disabled: std.ArrayListUnmanaged([]const u8) = .empty,
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
    default_exec_security: ExecSecurity = .allowlist,
    exec_security: ExecSecurity = .allowlist,
    default_exec_ask: ExecAsk = .on_miss,
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
    status_show_emojis: bool = true,
    message_timeout_secs: u64 = 0,
    log_tool_calls: bool = false,
    log_llm_io: bool = false,
    compaction_keep_recent: u32 = compaction.DEFAULT_COMPACTION_KEEP_RECENT,
    compaction_max_summary_chars: u32 = compaction.DEFAULT_COMPACTION_MAX_SUMMARY_CHARS,
    compaction_max_source_chars: u32 = compaction.DEFAULT_COMPACTION_MAX_SOURCE_CHARS,

    /// Per-turn MCP tool filter groups (slice into config-owned memory; not freed by Agent).
    /// Empty = no filtering; all tool specs are sent as-is.
    tool_filter_groups: []const config_types.ToolFilterGroup = &.{},

    /// Optional security policy for autonomy checks and rate limiting.
    policy: ?*const SecurityPolicy = null,

    /// Optional streaming callback. When set, turn() uses streamChat() for streaming providers.
    stream_callback: ?providers.StreamCallback = null,
    /// Context pointer passed to stream_callback.
    stream_ctx: ?*anyopaque = null,
    /// Optional callback invoked for each LLM response usage record.
    usage_record_callback: ?UsageRecordCallback = null,
    /// Context pointer passed to usage_record_callback.
    usage_record_ctx: ?*anyopaque = null,
    /// Cross-thread interrupt flag used to stop in-flight tool loops.
    interrupt_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Tracks currently running tool and effective interruptions for user-facing reporting.
    tool_state_mu: std.Thread.Mutex = .{},
    active_tool_name: ?[]u8 = null,
    interrupted_tools: std.ArrayListUnmanaged([]u8) = .empty,
    /// Conversation context for the current turn.
    conversation_context: ?prompt.ConversationContext = null,

    /// Conversation history — owned, growable list.
    history: std.ArrayListUnmanaged(OwnedMessage) = .empty,

    /// Total tokens used across all turns.
    total_tokens: u64 = 0,

    /// Whether the system prompt has been injected.
    has_system_prompt: bool = false,
    /// Whether the currently injected system prompt contains conversation context.
    system_prompt_has_conversation_context: bool = false,
    /// Fingerprint of the conversation context used for the cached system prompt.
    system_prompt_conversation_context_fingerprint: ?u64 = null,
    /// Fingerprint of workspace prompt files for the currently injected system prompt.
    workspace_prompt_fingerprint: ?u64 = null,
    /// Model name used when building the currently cached system prompt.
    system_prompt_model_name: ?[]u8 = null,

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

    /// Append a history message that owns its content.
    /// On append failure, the message is deinitialized to avoid leaks.
    fn appendOwnedHistoryMessage(self: *Agent, msg: OwnedMessage) !void {
        self.history.append(self.allocator, msg) catch |err| {
            msg.deinit(self.allocator);
            return err;
        };
    }

    /// Initialize agent from a loaded Config.
    pub fn fromConfig(
        allocator: std.mem.Allocator,
        cfg: *const Config,
        provider_i: Provider,
        tools: []const Tool,
        mem: ?Memory,
        observer_i: Observer,
    ) !Agent {
        return fromConfigWithProfile(allocator, cfg, provider_i, tools, mem, observer_i, null);
    }

    pub fn fromConfigWithProfile(
        allocator: std.mem.Allocator,
        cfg: *const Config,
        provider_i: Provider,
        tools: []const Tool,
        mem: ?Memory,
        observer_i: Observer,
        profile: ?config_types.NamedAgentConfig,
    ) !Agent {
        const default_model = if (profile) |agent_profile|
            agent_profile.model
        else
            cfg.default_model orelse return error.NoDefaultModel;
        const default_provider = if (profile) |agent_profile|
            agent_profile.provider
        else
            cfg.default_provider;
        const token_limit_override = if (cfg.agent.token_limit_explicit) cfg.agent.token_limit else null;
        const resolved_token_limit = context_tokens.resolveContextTokens(token_limit_override, default_model);
        const resolved_max_tokens_raw = max_tokens_resolver.resolveMaxTokens(cfg.max_tokens, default_model);
        const token_limit_cap: u32 = @intCast(@min(resolved_token_limit, @as(u64, std.math.maxInt(u32))));
        const resolved_max_tokens = @min(resolved_max_tokens_raw, token_limit_cap);
        const resolved_exec_security: ExecSecurity = switch (cfg.autonomy.level) {
            .full, .yolo => .full,
            .read_only => .deny,
            .supervised => .allowlist,
        };
        const resolved_exec_ask: ExecAsk = switch (cfg.autonomy.level) {
            .full, .read_only, .yolo => .off,
            .supervised => .on_miss,
        };

        // Build tool specs for function-calling APIs
        const specs = try allocator.alloc(ToolSpec, tools.len);
        for (tools, 0..) |t, i| {
            specs[i] = .{
                .name = t.name(),
                .description = t.description(),
                .parameters_json = t.parametersJson(),
            };
        }

        const bootstrap_provider: ?bootstrap_mod.BootstrapProvider = bootstrap_mod.createProvider(
            allocator,
            cfg.memory.backend,
            mem,
            cfg.workspace_dir,
        ) catch null;

        return .{
            .allocator = allocator,
            .provider = provider_i,
            .tools = tools,
            .tool_specs = specs,
            .mem = mem,
            .bootstrap = bootstrap_provider,
            .observer = observer_i,
            .model_name = default_model,
            .default_provider = default_provider,
            .default_model = default_model,
            .profile_name = if (profile) |agent_profile| agent_profile.name else null,
            .profile_system_prompt = if (profile) |agent_profile| agent_profile.system_prompt else null,
            .model_routes = if (profile != null) &.{} else cfg.model_routes,
            .configured_providers = cfg.providers,
            .fallback_providers = cfg.reliability.fallback_providers,
            .model_fallbacks = cfg.reliability.model_fallbacks,
            .temperature = if (profile) |agent_profile| agent_profile.temperature orelse cfg.default_temperature else cfg.default_temperature,
            .workspace_dir = cfg.workspace_dir,
            .allowed_paths = cfg.autonomy.allowed_paths,
            .multimodal_unrestricted = cfg.autonomy.level == .yolo,
            .vision_disabled_models = cfg.agent.vision_disabled_models,
            .auto_disable_vision_on_error = cfg.agent.auto_disable_vision_on_error,
            .max_tool_iterations = cfg.agent.max_tool_iterations,
            .max_history_messages = cfg.agent.max_history_messages,
            .auto_save = cfg.memory.auto_save,
            .token_limit = resolved_token_limit,
            .token_limit_override = token_limit_override,
            .max_tokens = resolved_max_tokens,
            .max_tokens_override = cfg.max_tokens,
            .reasoning_effort = cfg.reasoning_effort,
            .status_show_emojis = cfg.agent.status_show_emojis,
            .message_timeout_secs = cfg.agent.message_timeout_secs,
            .log_tool_calls = cfg.diagnostics.log_tool_calls,
            .log_llm_io = cfg.diagnostics.log_llm_io,
            .compaction_keep_recent = cfg.agent.compaction_keep_recent,
            .compaction_max_summary_chars = cfg.agent.compaction_max_summary_chars,
            .compaction_max_source_chars = cfg.agent.compaction_max_source_chars,
            .tool_filter_groups = cfg.agent.tool_filter_groups,
            .default_exec_security = resolved_exec_security,
            .exec_security = resolved_exec_security,
            .default_exec_ask = resolved_exec_ask,
            .exec_ask = resolved_exec_ask,
            .history = .empty,
            .total_tokens = 0,
            .has_system_prompt = false,
            .last_turn_compacted = false,
        };
    }

    pub fn deinit(self: *Agent) void {
        if (self.bootstrap) |bp| bp.deinit();
        if (self.model_name_owned) self.allocator.free(self.model_name);
        if (self.default_provider_owned) self.allocator.free(self.default_provider);
        if (self.system_prompt_model_name) |model| self.allocator.free(model);
        if (self.last_route_trace) |trace| self.allocator.free(trace);
        if (self.exec_node_id_owned and self.exec_node_id != null) self.allocator.free(self.exec_node_id.?);
        if (self.tts_provider_owned and self.tts_provider != null) self.allocator.free(self.tts_provider.?);
        if (self.pending_exec_command_owned and self.pending_exec_command != null) self.allocator.free(self.pending_exec_command.?);
        if (self.focus_target_owned and self.focus_target != null) self.allocator.free(self.focus_target.?);
        if (self.dock_target_owned and self.dock_target != null) self.allocator.free(self.dock_target.?);
        self.tool_state_mu.lock();
        if (self.active_tool_name) |name| self.allocator.free(name);
        self.active_tool_name = null;
        for (self.interrupted_tools.items) |name| self.allocator.free(name);
        self.interrupted_tools.deinit(self.allocator);
        self.tool_state_mu.unlock();
        for (self.history.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.history.deinit(self.allocator);
        for (self.detected_vision_disabled.items) |model| {
            self.allocator.free(model);
        }
        self.detected_vision_disabled.deinit(self.allocator);
        for (self.degraded_routes.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.degraded_routes.deinit(self.allocator);
        self.allocator.free(self.tool_specs);
    }

    pub fn requestInterrupt(self: *Agent) void {
        self.interrupt_requested.store(true, .release);
    }

    pub fn clearInterruptRequest(self: *Agent) void {
        self.interrupt_requested.store(false, .release);
    }

    fn isInterruptRequested(self: *const Agent) bool {
        return self.interrupt_requested.load(.acquire);
    }

    fn setActiveToolName(self: *Agent, name: []const u8) !void {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        if (self.active_tool_name) |old| self.allocator.free(old);
        self.active_tool_name = try self.allocator.dupe(u8, name);
    }

    fn clearActiveToolName(self: *Agent) void {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        if (self.active_tool_name) |old| self.allocator.free(old);
        self.active_tool_name = null;
    }

    fn noteInterruptedTool(self: *Agent, name: []const u8) !void {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        for (self.interrupted_tools.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing, name)) return;
        }
        try self.interrupted_tools.append(self.allocator, try self.allocator.dupe(u8, name));
    }

    fn takeInterruptedToolsSummary(self: *Agent) !?[]u8 {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        if (self.interrupted_tools.items.len == 0) return null;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        for (self.interrupted_tools.items, 0..) |name, i| {
            if (i > 0) try out.appendSlice(self.allocator, ", ");
            try out.appendSlice(self.allocator, name);
        }

        for (self.interrupted_tools.items) |name| self.allocator.free(name);
        self.interrupted_tools.clearRetainingCapacity();

        return try out.toOwnedSlice(self.allocator);
    }

    pub fn snapshotActiveToolName(self: *Agent, allocator: std.mem.Allocator) !?[]u8 {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        if (self.active_tool_name) |name| {
            return try allocator.dupe(u8, name);
        }
        return null;
    }

    fn interruptedReply(self: *Agent) ![]const u8 {
        self.clearInterruptRequest();
        const summary = try self.takeInterruptedToolsSummary();
        defer if (summary) |s| self.allocator.free(s);
        const msg = if (summary) |tools|
            try std.fmt.allocPrint(self.allocator, "Interrupted by /stop. Interrupted tools: {s}.", .{tools})
        else
            try self.allocator.dupe(u8, "Interrupted by /stop. Halting tool execution for this turn.");
        errdefer self.allocator.free(msg);
        try self.history.append(self.allocator, .{
            .role = .assistant,
            .content = try self.allocator.dupe(u8, msg),
        });
        const complete_event = ObserverEvent{ .turn_complete = {} };
        self.observer.recordEvent(&complete_event);
        return msg;
    }

    /// Estimate total tokens in conversation history.
    pub fn tokenEstimate(self: *const Agent) u64 {
        return compaction.tokenEstimate(self.history.items);
    }

    /// Rough token estimate for provider-ready messages.
    /// Uses a char-based heuristic (1 token ~= 4 chars) plus structural overhead.
    fn estimatePromptTokens(messages: []const ChatMessage) u64 {
        var total_chars: u64 = 0;
        for (messages) |msg| {
            if (msg.name) |name| total_chars +|= name.len;
            if (msg.tool_call_id) |tool_call_id| total_chars +|= tool_call_id.len;
            if (msg.content_parts) |parts| {
                // content_parts are the provider-facing payload; avoid double counting
                // mirrored plain `content` unless parts are unexpectedly empty.
                if (parts.len == 0) total_chars +|= msg.content.len;
                for (parts) |part| switch (part) {
                    .text => |text| total_chars +|= text.len,
                    .image_url => |img| total_chars +|= img.url.len + 32,
                    .image_base64 => |img| total_chars +|= img.data.len + img.media_type.len + 32,
                };
            } else {
                total_chars +|= msg.content.len;
            }
        }

        const structural_chars: u64 = @as(u64, @intCast(messages.len)) * 32;
        return (total_chars + structural_chars + 3) / 4;
    }

    fn estimateToolSpecsTokens(tool_specs: []const ToolSpec) u64 {
        var total_chars: u64 = 0;
        for (tool_specs) |spec| {
            total_chars +|= spec.name.len;
            total_chars +|= spec.description.len;
            total_chars +|= spec.parameters_json.len;
        }

        const structural_chars: u64 = @as(u64, @intCast(tool_specs.len)) * 48;
        return (total_chars + structural_chars + 3) / 4;
    }

    /// Clamp completion tokens to fit within the configured context budget.
    /// Keeps a safety headroom to reduce ContextLengthExceeded errors on strict providers.
    fn effectiveMaxTokensForMessages(
        self: *const Agent,
        messages: []const ChatMessage,
        include_tool_specs: bool,
    ) u32 {
        return self.effectiveMaxTokensForMessagesWithToolSpecs(
            messages,
            if (include_tool_specs) self.tool_specs else null,
        );
    }

    /// Variant of effectiveMaxTokensForMessages that accepts the exact tool schema set
    /// used for this request. This avoids overestimating prompt size when MCP schemas
    /// are filtered per turn.
    fn effectiveMaxTokensForMessagesWithToolSpecs(
        self: *const Agent,
        messages: []const ChatMessage,
        tool_specs_for_estimate: ?[]const ToolSpec,
    ) u32 {
        return self.effectiveMaxTokensForTurn(messages, tool_specs_for_estimate, self.token_limit, self.max_tokens);
    }

    fn effectiveMaxTokensForTurn(
        self: *const Agent,
        messages: []const ChatMessage,
        tool_specs_for_estimate: ?[]const ToolSpec,
        token_limit: u64,
        max_tokens: u32,
    ) u32 {
        _ = self;
        if (token_limit == 0) return max_tokens;

        var prompt_estimate = estimatePromptTokens(messages);
        if (tool_specs_for_estimate) |tool_specs| {
            prompt_estimate +|= estimateToolSpecsTokens(tool_specs);
        }

        if (prompt_estimate >= token_limit) return 1;

        const available = token_limit - prompt_estimate;
        const reserve = @min(@as(u64, 256), available / 4);
        if (available <= reserve) return 1;

        const completion_budget = available - reserve;
        const completion_budget_u32: u32 = @intCast(@min(completion_budget, @as(u64, std.math.maxInt(u32))));
        if (completion_budget_u32 == 0) return 1;
        return @max(@as(u32, 1), @min(max_tokens, completion_budget_u32));
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
            .bootstrap_provider = self.bootstrap,
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

    fn selectDisplayText(response_text: []const u8, parsed_text: []const u8, parsed_calls_len: usize) []const u8 {
        if (parsed_calls_len > 0) return parsed_text;
        if (parsed_text.len > 0) {
            // Some malformed/unclosed tool-call payloads can survive into parsed_text
            // via parser recovery fallbacks. Suppress them from user-visible output.
            if (dispatcher.containsToolCallMarkup(parsed_text)) return "";
            return parsed_text;
        }
        // If tool-call markup exists but parsing produced no valid calls/text,
        // never show the raw payload to the user.
        if (dispatcher.containsToolCallMarkup(response_text)) return "";
        return response_text;
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

    fn hasModelRouteHint(self: *const Agent, hint: []const u8) bool {
        for (self.model_routes) |route| {
            if (std.mem.eql(u8, route.hint, hint)) return true;
        }
        return false;
    }

    fn findModelRouteByHint(self: *const Agent, hint: []const u8) ?config_types.ModelRouteConfig {
        for (self.model_routes) |route| {
            if (std.mem.eql(u8, route.hint, hint)) return route;
        }
        return null;
    }

    fn degradedRouteMatches(entry: *const DegradedRoute, route: config_types.ModelRouteConfig) bool {
        return std.mem.eql(u8, entry.hint, route.hint) and
            std.mem.eql(u8, entry.provider, route.provider) and
            std.mem.eql(u8, entry.model, route.model);
    }

    fn pruneExpiredDegradedRoutes(self: *Agent, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.degraded_routes.items.len) {
            if (self.degraded_routes.items[i].until_ms <= now_ms) {
                var expired = self.degraded_routes.orderedRemove(i);
                expired.deinit(self.allocator);
                continue;
            }
            i += 1;
        }
    }

    fn findActiveDegradedRoute(self: *Agent, route: config_types.ModelRouteConfig, now_ms: i64) ?*DegradedRoute {
        self.pruneExpiredDegradedRoutes(now_ms);
        for (self.degraded_routes.items) |*entry| {
            if (entry.until_ms > now_ms and degradedRouteMatches(entry, route)) return entry;
        }
        return null;
    }

    fn hasDegradedRouteHint(self: *const Agent, hint: []const u8, now_ms: i64) bool {
        for (self.model_routes) |route| {
            if (!std.mem.eql(u8, route.hint, hint)) continue;
            for (self.degraded_routes.items) |entry| {
                if (entry.until_ms > now_ms and degradedRouteMatches(&entry, route)) return true;
            }
        }
        return false;
    }

    fn findUsableModelRouteByHint(self: *Agent, hint: []const u8, now_ms: i64) ?config_types.ModelRouteConfig {
        self.pruneExpiredDegradedRoutes(now_ms);
        for (self.model_routes) |route| {
            if (!std.mem.eql(u8, route.hint, hint)) continue;
            if (self.findActiveDegradedRoute(route, now_ms) == null) return route;
        }
        return null;
    }

    fn hasUsableModelRouteHint(self: *Agent, hint: []const u8, now_ms: i64) bool {
        return self.findUsableModelRouteByHint(hint, now_ms) != null;
    }

    fn routeCostClassLabel(route: config_types.ModelRouteConfig) []const u8 {
        return @tagName(route.cost_class);
    }

    fn routeQuotaClassLabel(route: config_types.ModelRouteConfig) []const u8 {
        return @tagName(route.quota_class);
    }

    fn routeMetadataScoreNudge(route: config_types.ModelRouteConfig) i32 {
        const cost_nudge: i32 = switch (route.cost_class) {
            .free => 8,
            .cheap => 4,
            .standard => 0,
            .premium => -4,
        };
        const quota_nudge: i32 = switch (route.quota_class) {
            .unlimited => 6,
            .normal => 0,
            .constrained => -6,
        };
        return cost_nudge + quota_nudge;
    }

    fn routeTiePriority(hint: []const u8) u8 {
        if (std.mem.eql(u8, hint, "balanced")) return 0;
        if (std.mem.eql(u8, hint, "fast")) return 1;
        if (std.mem.eql(u8, hint, "deep")) return 2;
        if (std.mem.eql(u8, hint, "reasoning")) return 3;
        if (std.mem.eql(u8, hint, "vision")) return 4;
        return 255;
    }

    fn maybePromoteRoute(best: *?RouteSelection, candidate: RouteSelection) void {
        if (best.*) |current| {
            if (candidate.score < current.score) return;
            if (candidate.score == current.score and routeTiePriority(candidate.hint) >= routeTiePriority(current.hint)) {
                return;
            }
        }
        best.* = candidate;
    }

    fn firstMatchingKeyword(haystack: []const u8, keywords: []const []const u8) ?[]const u8 {
        for (keywords) |keyword| {
            if (containsAsciiIgnoreCase(haystack, keyword)) return keyword;
        }
        return null;
    }

    fn isAmbiguousPrompt(user_message: []const u8) bool {
        const ambiguous_keywords = [_][]const u8{
            "what should",
            "should we",
            "should i",
            "what do you think",
            "thoughts",
            "advice",
            "not sure",
            "unclear",
        };
        inline for (ambiguous_keywords) |keyword| {
            if (containsAsciiIgnoreCase(user_message, keyword)) return true;
        }
        return user_message.len <= 220 and std.mem.indexOfScalar(u8, user_message, '?') != null;
    }

    fn activeDegradedRouteForStatus(
        self: *const Agent,
        route: config_types.ModelRouteConfig,
        now_ms: i64,
    ) ?*const DegradedRoute {
        for (self.degraded_routes.items) |*entry| {
            if (entry.until_ms > now_ms and degradedRouteMatches(entry, route)) return entry;
        }
        return null;
    }

    const RouteSelection = struct {
        hint: []const u8,
        route: config_types.ModelRouteConfig,
        reason: []const u8,
        matched_keyword: ?[]const u8 = null,
        score: i32 = 0,
    };

    const DegradedRoute = struct {
        hint: []const u8,
        provider: []const u8,
        model: []const u8,
        reason: []u8,
        until_ms: i64,

        fn deinit(self: *DegradedRoute, allocator: std.mem.Allocator) void {
            allocator.free(self.reason);
        }
    };

    const auto_route_degrade_cooldown_ms: i64 = 5 * 60 * 1000;

    fn routeSelectionForHint(
        self: *Agent,
        hint: []const u8,
        reason: []const u8,
        matched_keyword: ?[]const u8,
        score: i32,
        now_ms: i64,
    ) ?RouteSelection {
        const route = self.findUsableModelRouteByHint(hint, now_ms) orelse return null;
        return .{
            .hint = hint,
            .route = route,
            .reason = reason,
            .matched_keyword = matched_keyword,
            .score = score,
        };
    }

    fn apiErrorSuggestsQuotaExhaustion(self: *Agent) bool {
        const detail = providers.snapshotLastApiErrorDetail(self.allocator) catch return false;
        defer if (detail) |owned| self.allocator.free(owned);
        const snapshot = detail orelse return false;
        return providers.reliable.isRateLimited(snapshot) or
            containsAsciiIgnoreCase(snapshot, "quota") or
            containsAsciiIgnoreCase(snapshot, "credit") or
            containsAsciiIgnoreCase(snapshot, "billing") or
            containsAsciiIgnoreCase(snapshot, "insufficient_quota") or
            containsAsciiIgnoreCase(snapshot, "out of credits");
    }

    fn routeShouldBeDegraded(self: *Agent, err: anyerror) bool {
        if (err == error.RateLimited) return true;
        const err_name = @errorName(err);
        if (providers.reliable.isRateLimited(err_name)) return true;
        return self.apiErrorSuggestsQuotaExhaustion();
    }

    fn routeDegradeReason(self: *Agent, err: anyerror) ![]u8 {
        if (try providers.snapshotLastApiErrorDetail(self.allocator)) |detail| {
            return detail;
        }
        return try self.allocator.dupe(u8, @errorName(err));
    }

    fn markRouteDegraded(self: *Agent, selection: RouteSelection, err: anyerror) !void {
        if (!self.routeShouldBeDegraded(err)) return;
        const now_ms = std.time.milliTimestamp();
        const reason = try self.routeDegradeReason(err);
        errdefer self.allocator.free(reason);

        if (self.findActiveDegradedRoute(selection.route, now_ms)) |entry| {
            entry.deinit(self.allocator);
            entry.reason = reason;
            entry.until_ms = now_ms + auto_route_degrade_cooldown_ms;
            return;
        }

        try self.degraded_routes.append(self.allocator, .{
            .hint = selection.route.hint,
            .provider = selection.route.provider,
            .model = selection.route.model,
            .reason = reason,
            .until_ms = now_ms + auto_route_degrade_cooldown_ms,
        });
    }

    pub fn clearLastRouteTrace(self: *Agent) void {
        if (self.last_route_trace) |trace| self.allocator.free(trace);
        self.last_route_trace = null;
    }

    fn setLastRouteTrace(self: *Agent, selection: RouteSelection) !void {
        self.clearLastRouteTrace();
        const route_ref = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ selection.route.provider, selection.route.model },
        );
        defer self.allocator.free(route_ref);

        if (selection.matched_keyword) |keyword| {
            self.last_route_trace = try std.fmt.allocPrint(
                self.allocator,
                "{s} -> {s} ({s}: \"{s}\"; score {d})",
                .{ selection.hint, route_ref, selection.reason, keyword, selection.score },
            );
            return;
        }

        self.last_route_trace = try std.fmt.allocPrint(
            self.allocator,
            "{s} -> {s} ({s}; score {d})",
            .{ selection.hint, route_ref, selection.reason, selection.score },
        );
    }

    fn selectRouteHintForTurn(self: *Agent, user_message: []const u8) ?[]const u8 {
        const selection = self.routeSelectionForTurn(user_message) orelse return null;
        return selection.hint;
    }

    fn routeSelectionForTurn(self: *Agent, user_message: []const u8) ?RouteSelection {
        if (self.model_pinned_by_user or self.model_routes.len == 0) return null;
        const now_ms = std.time.milliTimestamp();

        if (std.mem.indexOf(u8, user_message, "[IMAGE:") != null and self.hasUsableModelRouteHint("vision", now_ms)) {
            return self.routeSelectionForHint(
                "vision",
                "image input with configured vision route",
                null,
                100,
                now_ms,
            );
        }

        const deep_keywords = [_][]const u8{
            "root cause",
            "investigate",
            "compare",
            "tradeoff",
            "architecture",
            "architectural",
            "refactor",
            "migration",
            "migrate",
            "design",
            "plan",
            "debug deeply",
            "why does",
            "why is",
        };
        const fast_keywords = [_][]const u8{
            "status",
            "list",
            "show",
            "current",
            "version",
            "pwd",
            "ls",
            "whoami",
            "doctor",
            "health",
            "check",
        };
        const structured_fast_keywords = [_][]const u8{
            "extract",
            "count",
            "classify",
            "label",
            "normalize",
            "convert",
            "format",
            "return only",
            "respond with",
            "yes or no",
            "true or false",
        };

        const deep_keyword = firstMatchingKeyword(user_message, &deep_keywords);
        const fast_keyword = if (user_message.len <= 120) firstMatchingKeyword(user_message, &fast_keywords) else null;
        const structured_fast_keyword = if (user_message.len <= 220)
            firstMatchingKeyword(user_message, &structured_fast_keywords)
        else
            null;
        const long_context = user_message.len > 600 or self.history.items.len >= 24;
        const ambiguous_prompt = isAmbiguousPrompt(user_message);

        var best: ?RouteSelection = null;

        if (self.findUsableModelRouteByHint("fast", now_ms)) |route| {
            var fast_score: i32 = 12 + routeMetadataScoreNudge(route);
            var fast_reason: []const u8 = "fallback fast route";
            var fast_matched_keyword: ?[]const u8 = null;
            if (fast_keyword) |keyword| {
                fast_score += 45;
                fast_reason = "high-confidence short operational prompt";
                fast_matched_keyword = keyword;
            }
            if (structured_fast_keyword) |keyword| {
                fast_score += 55;
                fast_reason = "high-confidence structured prompt";
                fast_matched_keyword = keyword;
            }
            if (long_context) fast_score -= 15;
            maybePromoteRoute(&best, .{
                .hint = "fast",
                .route = route,
                .reason = fast_reason,
                .matched_keyword = fast_matched_keyword,
                .score = fast_score,
            });
        }

        if (self.findUsableModelRouteByHint("balanced", now_ms)) |route| {
            var balanced_score: i32 = 30 + routeMetadataScoreNudge(route);
            var balanced_reason: []const u8 = "default balanced route";
            if (ambiguous_prompt) {
                balanced_score += 12;
                balanced_reason = "ambiguous prompt kept on balanced route";
            }
            if (deep_keyword != null) balanced_score -= 10;
            if (structured_fast_keyword != null or fast_keyword != null) balanced_score -= 8;
            maybePromoteRoute(&best, .{
                .hint = "balanced",
                .route = route,
                .reason = balanced_reason,
                .score = balanced_score,
            });
        }

        if (self.findUsableModelRouteByHint("deep", now_ms)) |route| {
            var deep_score: i32 = 10 + routeMetadataScoreNudge(route);
            var deep_reason: []const u8 = "fallback deep route";
            var deep_matched_keyword: ?[]const u8 = null;
            if (deep_keyword) |keyword| {
                deep_score += 50;
                deep_reason = "matched deep-task keyword";
                deep_matched_keyword = keyword;
            }
            if (long_context) {
                deep_score += 35;
                if (deep_matched_keyword == null) deep_reason = "long prompt or deep conversation context";
            }
            if (user_message.len <= 120 and deep_keyword == null) deep_score -= 4;
            maybePromoteRoute(&best, .{
                .hint = "deep",
                .route = route,
                .reason = deep_reason,
                .matched_keyword = deep_matched_keyword,
                .score = deep_score,
            });
        }

        if (self.findUsableModelRouteByHint("reasoning", now_ms)) |route| {
            var reasoning_score: i32 = 8 + routeMetadataScoreNudge(route);
            var reasoning_reason: []const u8 = "fallback reasoning route";
            var reasoning_matched_keyword: ?[]const u8 = null;
            if (deep_keyword) |keyword| {
                reasoning_score += 45;
                reasoning_reason = "matched deep-task keyword";
                reasoning_matched_keyword = keyword;
            }
            if (long_context) {
                reasoning_score += 30;
                if (reasoning_matched_keyword == null) reasoning_reason = "long prompt or deep conversation context";
            }
            if (user_message.len <= 120 and deep_keyword == null) reasoning_score -= 4;
            maybePromoteRoute(&best, .{
                .hint = "reasoning",
                .route = route,
                .reason = reasoning_reason,
                .matched_keyword = reasoning_matched_keyword,
                .score = reasoning_score,
            });
        }

        return best;
    }

    fn routeModelNameForTurn(self: *Agent, allocator: std.mem.Allocator, user_message: []const u8) !?[]u8 {
        const selection = self.routeSelectionForTurn(user_message) orelse return null;
        try self.setLastRouteTrace(selection);
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ selection.route.provider, selection.route.model });
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

        try w.writeAll("\nAuto-routing: ");
        if (self.model_routes.len == 0) {
            try w.writeAll("not configured");
        } else {
            try w.writeAll("configured");
            if (self.model_pinned_by_user) {
                try w.writeAll(" (currently pinned off for this session)");
            }
            if (self.last_route_trace) |trace| {
                try w.print("\nLast auto-route: {s}", .{trace});
            } else if (self.model_pinned_by_user) {
                try w.writeAll("\nLast auto-route: inactive while the model is pinned");
            } else {
                try w.writeAll("\nLast auto-route: no decision recorded yet");
            }
        }

        const now_ms = std.time.milliTimestamp();
        if (self.model_routes.len > 0) {
            try w.writeAll("\nAuto routes:");
            for (self.model_routes) |route| {
                try w.print(
                    "\n  - {s} -> {s}/{s} (cost={s}, quota={s})",
                    .{
                        route.hint,
                        route.provider,
                        route.model,
                        routeCostClassLabel(route),
                        routeQuotaClassLabel(route),
                    },
                );
                if (self.activeDegradedRouteForStatus(route, now_ms)) |entry| {
                    const remaining_ms = @max(@as(i64, 0), entry.until_ms - now_ms);
                    const remaining_secs: u64 = @intCast(@divFloor(remaining_ms + 999, 1000));
                    try w.print(" [degraded: {s}; {d}s remaining]", .{ entry.reason, remaining_secs });
                }
            }
        }

        var wrote_degraded_routes = false;
        for (self.degraded_routes.items) |entry| {
            if (entry.until_ms <= now_ms) continue;
            if (!wrote_degraded_routes) {
                try w.writeAll("\nDegraded routes:");
                wrote_degraded_routes = true;
            }
            const remaining_ms = @max(@as(i64, 0), entry.until_ms - now_ms);
            const remaining_secs: u64 = @intCast(@divFloor(remaining_ms + 999, 1000));
            try w.print(
                "\n  - {s} -> {s}/{s} ({s}; {d}s cooldown remaining)",
                .{ entry.hint, entry.provider, entry.model, entry.reason, remaining_secs },
            );
        }

        try w.writeAll("\nSwitch: /model <name>");
        return try out.toOwnedSlice(self.allocator);
    }

    /// Handle slash commands that don't require LLM.
    /// Returns an owned response string, or null if not a slash command.
    pub fn handleSlashCommand(self: *Agent, message: []const u8) !?[]const u8 {
        return commands.handleSlashCommand(self, message);
    }

    /// Returns true if `name` matches `pattern` using simple `*` glob.
    /// `*` matches any sequence of characters (including none).
    fn globMatch(pattern: []const u8, name: []const u8) bool {
        // Fast paths
        if (std.mem.eql(u8, pattern, "*")) return true;
        const star = std.mem.indexOfScalar(u8, pattern, '*') orelse {
            return std.mem.eql(u8, pattern, name);
        };
        const prefix = pattern[0..star];
        const suffix = pattern[star + 1 ..];
        if (!std.mem.startsWith(u8, name, prefix)) return false;
        if (suffix.len == 0) return true;
        // suffix must appear at end (handles single-`*` patterns only)
        if (name.len < prefix.len + suffix.len) return false;
        return std.mem.endsWith(u8, name, suffix);
    }

    /// Filter `self.tool_specs` for the current turn based on `tool_filter_groups`.
    ///
    /// Returns a slice allocated from `arena` containing only the specs that should
    /// be included for this turn.  The returned slice borrows pointers from
    /// `self.tool_specs` — it must NOT outlive `self.tool_specs`.
    ///
    /// Rules:
    ///   - If no filter groups are configured, returns `self.tool_specs` directly (no copy).
    ///   - A tool whose name does NOT start with "mcp_" is always included.
    ///   - `always` groups unconditionally include matching MCP tools.
    ///   - `dynamic` groups include matching MCP tools when the user message contains
    ///     at least one of the group's keywords (case-insensitive substring match).
    fn filterToolSpecsForTurn(
        self: *const Agent,
        arena: std.mem.Allocator,
        user_message: []const u8,
    ) ![]const ToolSpec {
        if (self.tool_filter_groups.len == 0) return self.tool_specs;

        var result: std.ArrayListUnmanaged(ToolSpec) = .empty;

        for (self.tool_specs) |spec| {
            // Non-MCP tools are always included.
            if (!std.mem.startsWith(u8, spec.name, "mcp_")) {
                try result.append(arena, spec);
                continue;
            }

            var include = false;
            for (self.tool_filter_groups) |group| {
                // Check if any pattern in this group matches the tool name.
                var pattern_matched = false;
                for (group.tools) |pattern| {
                    if (globMatch(pattern, spec.name)) {
                        pattern_matched = true;
                        break;
                    }
                }
                if (!pattern_matched) continue;

                switch (group.mode) {
                    .always => {
                        include = true;
                        break;
                    },
                    .dynamic => {
                        // Case-insensitive ASCII substring match for configured keywords.
                        for (group.keywords) |kw| {
                            if (containsAsciiIgnoreCase(user_message, kw)) {
                                include = true;
                                break;
                            }
                            if (include) break;
                        }
                        if (include) break;
                    },
                }
            }

            if (include) try result.append(arena, spec);
        }

        return result.toOwnedSlice(arena);
    }

    /// Execute a single conversation turn: send messages to LLM, parse tool calls,
    /// execute tools, and loop until a final text response is produced.
    pub fn turn(self: *Agent, user_message: []const u8) ![]const u8 {
        self.context_was_compacted = false;
        commands.refreshSubagentToolContext(self);

        const turn_input = commands.planTurnInput(user_message);
        const effective_user_message = blk: {
            if (turn_input.invoke_local_handler) {
                const slash_response = (try self.handleSlashCommand(user_message)) orelse return error.SlashCommandDispatchMismatch;
                if (turn_input.llm_user_message) |llm_user_message| {
                    // Bare /new and /reset clear session state first, then continue as a fresh LLM turn.
                    self.allocator.free(slash_response);
                    break :blk llm_user_message;
                }
                return slash_response;
            }
            break :blk turn_input.llm_user_message orelse user_message;
        };

        const turn_route_selection = self.routeSelectionForTurn(effective_user_message);
        if (turn_route_selection) |selection| {
            try self.setLastRouteTrace(selection);
        }
        const turn_model_name = if (turn_route_selection) |selection|
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ selection.route.provider, selection.route.model })
        else
            self.model_name;
        const turn_model_name_owned = !std.mem.eql(u8, turn_model_name, self.model_name);
        defer if (turn_model_name_owned) self.allocator.free(turn_model_name);

        // Inject system prompt on first turn (or when tracked workspace files changed).
        const workspace_fp: ?u64 = prompt.workspacePromptFingerprint(self.allocator, self.workspace_dir, self.bootstrap) catch null;
        if (self.has_system_prompt and workspace_fp != null and self.workspace_prompt_fingerprint != workspace_fp) {
            self.has_system_prompt = false;
        }
        if (self.has_system_prompt) {
            if (self.system_prompt_model_name) |cached_model| {
                if (!std.mem.eql(u8, cached_model, turn_model_name)) {
                    self.has_system_prompt = false;
                }
            }
        }

        const turn_has_conversation_context = self.conversation_context != null;
        const turn_conversation_context_fingerprint = if (self.conversation_context) |ctx|
            ctx.senderFingerprint()
        else
            null;
        const conversation_context_changed = self.has_system_prompt and
            (self.system_prompt_has_conversation_context != turn_has_conversation_context or
                self.system_prompt_conversation_context_fingerprint != turn_conversation_context_fingerprint);

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

            const full_system = try prompt.buildSystemPrompt(self.allocator, .{
                .workspace_dir = self.workspace_dir,
                .model_name = turn_model_name,
                .tools = self.tools,
                .capabilities_section = capabilities_section,
                .conversation_context = self.conversation_context,
                .bootstrap_provider = self.bootstrap,
            });
            const final_system = if (self.profile_system_prompt) |profile_prompt|
                if (profile_prompt.len > 0) blk: {
                    defer self.allocator.free(full_system);
                    break :blk try std.fmt.allocPrint(
                        self.allocator,
                        "## Agent Profile\n\nProfile: {s}\n\n{s}\n\n{s}",
                        .{
                            self.profile_name orelse "custom",
                            profile_prompt,
                            full_system,
                        },
                    );
                } else full_system
            else
                full_system;

            // Keep exactly one canonical system prompt at history[0].
            // This allows /model to invalidate and refresh the prompt in place.
            if (self.history.items.len > 0 and self.history.items[0].role == .system) {
                self.history.items[0].deinit(self.allocator);
                self.history.items[0] = .{
                    .role = .system,
                    .content = final_system,
                };
            } else if (self.history.items.len > 0) {
                try self.history.insert(self.allocator, 0, .{
                    .role = .system,
                    .content = final_system,
                });
            } else {
                try self.history.append(self.allocator, .{
                    .role = .system,
                    .content = final_system,
                });
            }
            self.has_system_prompt = true;
            self.system_prompt_has_conversation_context = turn_has_conversation_context;
            self.system_prompt_conversation_context_fingerprint = turn_conversation_context_fingerprint;
            self.workspace_prompt_fingerprint = workspace_fp;
            if (self.system_prompt_model_name) |cached_model| self.allocator.free(cached_model);
            self.system_prompt_model_name = try self.allocator.dupe(u8, turn_model_name);
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

        // Keep the user message retained even if provider/tool steps fail.
        try self.appendOwnedHistoryMessage(.{ .role = .user, .content = enriched });

        // ── Response cache check ──
        if (self.response_cache) |rc| {
            var key_buf: [16]u8 = undefined;
            const system_prompt = if (self.history.items.len > 0 and self.history.items[0].role == .system)
                self.history.items[0].content
            else
                null;
            const key_hex = cache.ResponseCache.cacheKeyHex(&key_buf, turn_model_name, system_prompt, effective_user_message);
            if (rc.get(self.allocator, key_hex) catch null) |cached_response| {
                errdefer self.allocator.free(cached_response);
                const history_copy = try self.allocator.dupe(u8, cached_response);
                errdefer self.allocator.free(history_copy);
                try self.history.append(self.allocator, .{
                    .role = .assistant,
                    .content = history_copy,
                });
                self.last_turn_usage = .{};
                return cached_response;
            }
        }

        // Record agent event
        const start_event = ObserverEvent{ .llm_request = .{
            .provider = self.provider.getName(),
            .model = turn_model_name,
            .messages_count = self.history.items.len,
        } };
        self.observer.recordEvent(&start_event);

        const turn_token_limit = context_tokens.resolveContextTokens(self.token_limit_override, turn_model_name);
        const turn_max_tokens_raw = max_tokens_resolver.resolveMaxTokens(self.max_tokens_override, turn_model_name);
        const turn_token_limit_cap: u32 = @intCast(@min(turn_token_limit, @as(u64, std.math.maxInt(u32))));
        const turn_max_tokens = @min(turn_max_tokens_raw, turn_token_limit_cap);

        // Tool call loop — reuse a single arena across iterations (retains pages)
        var iter_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer iter_arena.deinit();

        var iteration: u32 = 0;
        var forced_follow_through_count: u32 = 0;
        var empty_response_retry_count: u32 = 0;
        while (iteration < self.max_tool_iterations) : (iteration += 1) {
            if (self.isInterruptRequested()) {
                return self.interruptedReply();
            }

            _ = iter_arena.reset(.retain_capacity);
            const arena = iter_arena.allocator();

            // Build messages slice for provider (arena-owned; freed at end of iteration)
            const messages = try self.buildProviderMessages(arena, turn_model_name);

            const timer_start = std.time.milliTimestamp();
            const is_streaming = self.stream_callback != null and self.stream_ctx != null and self.provider.supportsStreaming();
            const native_tools_enabled = !is_streaming and self.provider.supportsNativeTools();

            // Filter tool specs for this turn (arena-owned; may be self.tool_specs directly if no groups).
            const turn_tool_specs = try self.filterToolSpecsForTurn(arena, effective_user_message);
            const request_max_tokens = self.effectiveMaxTokensForTurn(
                messages,
                if (native_tools_enabled) turn_tool_specs else null,
                turn_token_limit,
                turn_max_tokens,
            );

            // Call provider: streaming (no retries, no native tools) or blocking with retry
            var response: ChatResponse = undefined;
            var response_attempt: u32 = 1;
            providers.clearLastApiErrorDetail();
            if (is_streaming) {
                self.logLlmRequest(iteration + 1, 1, turn_model_name, messages, native_tools_enabled, true);
                const stream_result = self.provider.streamChat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .session_id = self.memory_session_id,
                        .model = turn_model_name,
                        .temperature = self.temperature,
                        .max_tokens = request_max_tokens,
                        .tools = null,
                        .timeout_secs = self.message_timeout_secs,
                        .reasoning_effort = self.reasoning_effort,
                    },
                    turn_model_name,
                    self.temperature,
                    self.stream_callback.?,
                    self.stream_ctx.?,
                ) catch |err| retry_stream: {
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
                    const fail_event = ObserverEvent{ .llm_response = .{
                        .provider = self.provider.getName(),
                        .model = turn_model_name,
                        .duration_ms = fail_duration,
                        .success = false,
                        .error_message = @errorName(err),
                    } };
                    self.observer.recordEvent(&fail_event);

                    // Auto-disable vision on first "model does not support vision" error
                    if (self.auto_disable_vision_on_error and err == error.ProviderDoesNotSupportVision) {
                        if (self.verbose_level == .on or self.verbose_level == .full) {
                            log.info("Auto-disabling vision for model {s}", .{turn_model_name});
                        }
                        try self.markVisionDisabled(turn_model_name);
                        const retry_msgs = try self.buildProviderMessages(arena, turn_model_name);
                        const retry_max_tokens = self.effectiveMaxTokensForTurn(
                            retry_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.logLlmRequest(iteration + 1, 2, turn_model_name, retry_msgs, native_tools_enabled, true);
                        break :retry_stream self.provider.streamChat(
                            self.allocator,
                            .{
                                .messages = retry_msgs,
                                .session_id = self.memory_session_id,
                                .model = turn_model_name,
                                .temperature = self.temperature,
                                .max_tokens = retry_max_tokens,
                                .tools = null,
                                .timeout_secs = self.message_timeout_secs,
                                .reasoning_effort = self.reasoning_effort,
                            },
                            turn_model_name,
                            self.temperature,
                            self.stream_callback.?,
                            self.stream_ctx.?,
                        ) catch |retry_err| {
                            if (turn_route_selection) |selection| try self.markRouteDegraded(selection, retry_err);
                            self.emitUsageFailure(turn_model_name);
                            return retry_err;
                        };
                    }

                    if (turn_route_selection) |selection| try self.markRouteDegraded(selection, err);
                    self.emitUsageFailure(turn_model_name);
                    return err;
                };
                response = ChatResponse{
                    .content = stream_result.content,
                    .tool_calls = &.{},
                    .usage = stream_result.usage,
                    .model = stream_result.model,
                };
            } else {
                self.logLlmRequest(iteration + 1, 1, turn_model_name, messages, native_tools_enabled, false);
                response = self.provider.chat(
                    self.allocator,
                    .{
                        .messages = messages,
                        .session_id = self.memory_session_id,
                        .model = turn_model_name,
                        .temperature = self.temperature,
                        .max_tokens = request_max_tokens,
                        .tools = if (native_tools_enabled) turn_tool_specs else null,
                        .timeout_secs = self.message_timeout_secs,
                        .reasoning_effort = self.reasoning_effort,
                    },
                    turn_model_name,
                    self.temperature,
                ) catch |err| retry_blk: {
                    // Record the failed attempt
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
                    const fail_event = ObserverEvent{ .llm_response = .{
                        .provider = self.provider.getName(),
                        .model = turn_model_name,
                        .duration_ms = fail_duration,
                        .success = false,
                        .error_message = @errorName(err),
                    } };
                    self.observer.recordEvent(&fail_event);

                    // Auto-disable vision on first "model does not support vision" error
                    if (self.auto_disable_vision_on_error and err == error.ProviderDoesNotSupportVision) {
                        if (self.verbose_level == .on or self.verbose_level == .full) {
                            log.info("Auto-disabling vision for model {s}", .{turn_model_name});
                        }
                        try self.markVisionDisabled(turn_model_name);
                        const retry_msgs = try self.buildProviderMessages(arena, turn_model_name);
                        const retry_max_tokens = self.effectiveMaxTokensForTurn(
                            retry_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.logLlmRequest(iteration + 1, 2, turn_model_name, retry_msgs, native_tools_enabled, false);
                        break :retry_blk self.provider.chat(
                            self.allocator,
                            .{
                                .messages = retry_msgs,
                                .session_id = self.memory_session_id,
                                .model = turn_model_name,
                                .temperature = self.temperature,
                                .max_tokens = retry_max_tokens,
                                .tools = if (native_tools_enabled) turn_tool_specs else null,
                                .timeout_secs = self.message_timeout_secs,
                                .reasoning_effort = self.reasoning_effort,
                            },
                            turn_model_name,
                            self.temperature,
                        ) catch |retry_err| {
                            if (turn_route_selection) |selection| try self.markRouteDegraded(selection, retry_err);
                            self.emitUsageFailure(turn_model_name);
                            return retry_err;
                        };
                    }

                    // Context exhaustion: compact immediately before first retry
                    const err_name = @errorName(err);
                    if (providers.reliable.isContextExhausted(err_name) and
                        self.history.items.len > compaction.CONTEXT_RECOVERY_MIN_HISTORY and
                        self.forceCompressHistory())
                    {
                        self.context_was_compacted = true;
                        const recovery_msgs = self.buildProviderMessages(arena, turn_model_name) catch |prep_err| return prep_err;
                        const recovery_max_tokens = self.effectiveMaxTokensForTurn(
                            recovery_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.logLlmRequest(iteration + 1, 2, turn_model_name, recovery_msgs, native_tools_enabled, false);
                        break :retry_blk self.provider.chat(
                            self.allocator,
                            .{
                                .messages = recovery_msgs,
                                .session_id = self.memory_session_id,
                                .model = turn_model_name,
                                .temperature = self.temperature,
                                .max_tokens = recovery_max_tokens,
                                .tools = if (native_tools_enabled) turn_tool_specs else null,
                                .timeout_secs = self.message_timeout_secs,
                                .reasoning_effort = self.reasoning_effort,
                            },
                            turn_model_name,
                            self.temperature,
                        ) catch |retry_after_compact_err| {
                            if (turn_route_selection) |selection| try self.markRouteDegraded(selection, retry_after_compact_err);
                            self.emitUsageFailure(turn_model_name);
                            return retry_after_compact_err;
                        };
                    }

                    if (self.routeShouldBeDegraded(err)) {
                        if (turn_route_selection) |selection| try self.markRouteDegraded(selection, err);
                        self.emitUsageFailure(turn_model_name);
                        return err;
                    }

                    // Retry once
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                    response_attempt = 2;
                    self.logLlmRequest(iteration + 1, 2, turn_model_name, messages, native_tools_enabled, false);
                    break :retry_blk self.provider.chat(
                        self.allocator,
                        .{
                            .messages = messages,
                            .session_id = self.memory_session_id,
                            .model = turn_model_name,
                            .temperature = self.temperature,
                            .max_tokens = request_max_tokens,
                            .tools = if (native_tools_enabled) turn_tool_specs else null,
                            .timeout_secs = self.message_timeout_secs,
                            .reasoning_effort = self.reasoning_effort,
                        },
                        turn_model_name,
                        self.temperature,
                    ) catch |retry_err| {
                        // Context exhaustion recovery: if we have enough history,
                        // force-compress and retry once more
                        if (self.history.items.len > compaction.CONTEXT_RECOVERY_MIN_HISTORY and self.forceCompressHistory()) {
                            self.context_was_compacted = true;
                            const recovery_msgs = self.buildProviderMessages(arena, turn_model_name) catch |prep_err| return prep_err;
                            const recovery_max_tokens = self.effectiveMaxTokensForTurn(
                                recovery_msgs,
                                if (native_tools_enabled) turn_tool_specs else null,
                                turn_token_limit,
                                turn_max_tokens,
                            );
                            response_attempt = 3;
                            self.logLlmRequest(iteration + 1, 3, turn_model_name, recovery_msgs, native_tools_enabled, false);
                            break :retry_blk self.provider.chat(
                                self.allocator,
                                .{
                                    .messages = recovery_msgs,
                                    .session_id = self.memory_session_id,
                                    .model = turn_model_name,
                                    .temperature = self.temperature,
                                    .max_tokens = recovery_max_tokens,
                                    .tools = if (native_tools_enabled) turn_tool_specs else null,
                                    .timeout_secs = self.message_timeout_secs,
                                    .reasoning_effort = self.reasoning_effort,
                                },
                                turn_model_name,
                                self.temperature,
                            ) catch |retry_after_compact_err| {
                                if (turn_route_selection) |selection| try self.markRouteDegraded(selection, retry_after_compact_err);
                                self.emitUsageFailure(turn_model_name);
                                return retry_after_compact_err;
                            };
                        }
                        if (turn_route_selection) |selection| try self.markRouteDegraded(selection, retry_err);
                        self.emitUsageFailure(turn_model_name);
                        return retry_err;
                    };
                };
            }
            self.logLlmResponse(iteration + 1, response_attempt, &response);

            const duration_ms: u64 = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - timer_start)));
            const resp_event = ObserverEvent{ .llm_response = .{
                .provider = self.provider.getName(),
                .model = turn_model_name,
                .duration_ms = duration_ms,
                .success = true,
                .error_message = null,
            } };
            self.observer.recordEvent(&resp_event);

            const response_text = response.contentOrEmpty();

            // Track tokens with provider-agnostic fallback when total is omitted.
            var normalized_usage = response.usage;
            if (normalized_usage.total_tokens == 0 and
                (normalized_usage.prompt_tokens > 0 or normalized_usage.completion_tokens > 0))
            {
                normalized_usage.total_tokens = normalized_usage.prompt_tokens +| normalized_usage.completion_tokens;
            }
            // Some providers/channels omit usage entirely; keep status counters useful.
            if (normalized_usage.total_tokens == 0 and normalized_usage.prompt_tokens == 0 and normalized_usage.completion_tokens == 0 and response_text.len > 0) {
                normalized_usage.completion_tokens = estimate_text_tokens(response_text);
                normalized_usage.total_tokens = normalized_usage.completion_tokens;
            }
            response.usage = normalized_usage;

            self.total_tokens += normalized_usage.total_tokens;
            self.last_turn_usage = normalized_usage;
            self.emitUsageRecord(&response, true);
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
                // For XML path, never preserve model-fabricated <tool_result> markup in history.
                assistant_history_content = try dispatcher.stripToolResultMarkup(self.allocator, response_text);
                free_assistant_history = true;
            }

            // Determine display text.
            // When tool calls are present, only show parsed plain text (if any).
            // Never fall back to raw response_text here, otherwise markup like
            // <tool_call>...</tool_call> can leak to users.
            const display_text = selectDisplayText(response_text, parsed_text, parsed_calls.len);

            if (parsed_calls.len == 0) {
                const trimmed_display_text = std.mem.trim(u8, display_text, " \t\r\n");

                if (trimmed_display_text.len == 0) {
                    self.freeResponseFields(&response);
                    if (!is_streaming and
                        empty_response_retry_count < 1 and
                        iteration + 1 < self.max_tool_iterations)
                    {
                        try self.appendOwnedHistoryMessage(.{ .role = .user, .content = try self.allocator.dupe(u8, "SYSTEM: Your previous reply was empty. Respond with a direct user-visible answer or emit the necessary tool call(s). Do not return an empty response.") });
                        self.trimHistory();
                        empty_response_retry_count += 1;
                        continue;
                    }
                    return error.NoResponseContent;
                }

                // Guardrail: if the model promises "I'll try/check now" but emits no
                // tool call, force one follow-up completion to either act now or
                // explicitly state the limitation without deferred promises.
                if (!is_streaming and
                    forced_follow_through_count < 2 and
                    iteration + 1 < self.max_tool_iterations and
                    shouldForceActionFollowThrough(display_text))
                {
                    try self.appendOwnedHistoryMessage(.{ .role = .assistant, .content = try self.allocator.dupe(u8, display_text) });
                    try self.appendOwnedHistoryMessage(.{ .role = .user, .content = try self.allocator.dupe(u8, "SYSTEM: You just promised to take action now (for example: \"I'll try/check now\"). " ++
                        "Do it in this turn by issuing the appropriate tool call(s). " ++
                        "If no tool can perform it, respond with a clear limitation now and do not promise another future attempt.") });
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
                    const store_key_hex = cache.ResponseCache.cacheKeyHex(&store_key_buf, turn_model_name, sys_prompt, effective_user_message);
                    const token_count: u32 = @intCast(@min(self.last_turn_usage.total_tokens, std.math.maxInt(u32)));
                    rc.put(self.allocator, store_key_hex, turn_model_name, final_text, token_count) catch {};
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

            // Once appended, history owns the buffer.
            try self.appendOwnedHistoryMessage(.{ .role = .assistant, .content = assistant_content });

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
                if (self.isInterruptRequested()) {
                    self.freeResponseFields(&response);
                    return self.interruptedReply();
                }

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
                    .detail = if (result.success) null else result.output,
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
        const summary_max_tokens = self.effectiveMaxTokensForMessages(summary_messages, false);

        self.logLlmRequest(self.max_tool_iterations + 1, 1, self.model_name, summary_messages, false, false);
        var summary_response = self.provider.chat(
            self.allocator,
            .{
                .messages = summary_messages,
                .session_id = self.memory_session_id,
                .model = self.model_name,
                .temperature = self.temperature,
                .max_tokens = summary_max_tokens,
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
        if (!std.mem.eql(u8, call.name, "file_write") and
            !std.mem.eql(u8, call.name, "file_edit") and
            !std.mem.eql(u8, call.name, "file_edit_hashed")) return false;

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
        if (self.isInterruptRequested()) {
            return .{
                .name = call.name,
                .output = "Interrupted by /stop",
                .success = false,
                .tool_call_id = call.tool_call_id,
            };
        }

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

        const trimmed_call_name = std.mem.trim(u8, call.name, " \t\r\n");

        for (self.tools) |t| {
            if (std.ascii.eqlIgnoreCase(t.name(), trimmed_call_name)) {
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

                self.setActiveToolName(trimmed_call_name) catch {};
                defer self.clearActiveToolName();
                tools_mod.process_util.setThreadInterruptFlag(&self.interrupt_requested);
                defer tools_mod.process_util.setThreadInterruptFlag(null);
                @import("../http_util.zig").setThreadInterruptFlag(&self.interrupt_requested);
                defer @import("../http_util.zig").setThreadInterruptFlag(null);
                const result = t.execute(tool_allocator, args) catch |err| {
                    if (verbose_mod.isVerbose()) {
                        log.info("tool result: name={s} error={s}", .{ call.name, @errorName(err) });
                    }
                    return .{
                        .name = call.name,
                        .output = @errorName(err),
                        .success = false,
                        .tool_call_id = call.tool_call_id,
                    };
                };
                const was_interrupted = !result.success and
                    ((result.error_msg != null and std.mem.indexOf(u8, result.error_msg.?, "Interrupted by /stop") != null) or
                        std.mem.indexOf(u8, result.output, "Interrupted by /stop") != null);
                if (was_interrupted) {
                    self.noteInterruptedTool(trimmed_call_name) catch {};
                }
                if (verbose_mod.isVerbose()) {
                    const output_preview = if (result.output.len > 256) result.output[0..256] else result.output;
                    log.info("tool result: name={s} success={} output_len={d} output={s}...", .{ call.name, result.success, result.output.len, output_preview });
                }
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

    fn logLlmRequest(
        self: *Agent,
        iteration: u32,
        attempt: u32,
        model_name: []const u8,
        messages: []const ChatMessage,
        native_tools_enabled: bool,
        is_streaming: bool,
    ) void {
        if (!self.log_llm_io) return;
        const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
        log.info(
            "llm request session=0x{x} iter={d} attempt={d} provider={s} model={s} messages={d} native_tools={} streaming={}",
            .{
                session_hash,
                iteration,
                attempt,
                self.provider.getName(),
                model_name,
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
                    if (preview.truncated) " [log preview truncated]" else "",
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
            "llm response session=0x{x} iter={d} attempt={d} provider={s} model={s} bytes={d} tool_calls={d} usage={f} content={f}{s}",
            .{
                session_hash,
                iteration,
                attempt,
                self.effectiveProvider(response),
                self.effectiveModel(response),
                content.len,
                response.tool_calls.len,
                std.json.fmt(response.usage, .{}),
                std.json.fmt(preview.slice, .{}),
                if (preview.truncated) " [log preview truncated]" else "",
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
                    if (r_preview.truncated) " [log preview truncated]" else "",
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
                    if (args_preview.truncated) " [log preview truncated]" else "",
                },
            );
        }
    }

    fn effectiveProvider(self: *const Agent, response: *const ChatResponse) []const u8 {
        if (response.provider.len > 0) return response.provider;
        return self.provider.getName();
    }

    fn effectiveModel(self: *const Agent, response: *const ChatResponse) []const u8 {
        if (response.model.len > 0) return response.model;
        return self.model_name;
    }

    fn emitUsageRecord(self: *Agent, response: *const ChatResponse, success: bool) void {
        const cb = self.usage_record_callback orelse return;
        const ctx = self.usage_record_ctx orelse return;
        cb(ctx, .{
            .ts = std.time.timestamp(),
            .provider = self.effectiveProvider(response),
            .model = self.effectiveModel(response),
            .usage = response.usage,
            .success = success,
        });
    }

    fn emitUsageFailure(self: *Agent, model_name: []const u8) void {
        const failed = ChatResponse{
            .model = model_name,
            .usage = .{},
        };
        self.emitUsageRecord(&failed, false);
    }

    /// Check if vision is disabled for current model (either configured or auto-detected).
    fn isVisionDisabled(self: *const Agent, model_name: []const u8) bool {
        for (self.vision_disabled_models) |model| {
            if (std.mem.eql(u8, model, model_name)) return true;
        }
        for (self.detected_vision_disabled.items) |model| {
            if (std.mem.eql(u8, model, model_name)) return true;
        }
        return false;
    }

    /// Add model to detected vision disabled list if not already present.
    fn markVisionDisabled(self: *Agent, model_name: []const u8) !void {
        const already_disabled = for (self.detected_vision_disabled.items) |model| {
            if (std.mem.eql(u8, model, model_name)) break true;
        } else false;
        if (!already_disabled) {
            try self.detected_vision_disabled.append(self.allocator, try self.allocator.dupe(u8, model_name));
        }
    }

    /// Build provider-ready ChatMessage slice from owned history.
    /// Applies multimodal preprocessing and vision capability checks.
    fn buildProviderMessages(self: *Agent, arena: std.mem.Allocator, model_name: []const u8) ![]ChatMessage {
        const m = try arena.alloc(ChatMessage, self.history.items.len);
        for (self.history.items, 0..) |*msg, i| {
            m[i] = msg.toChatMessage();
        }

        const image_marker_count = multimodal.countImageMarkersInLastUser(m);
        if (image_marker_count == 0) {
            return m;
        }

        // Check if vision is disabled (configured or auto-detected)
        if (self.isVisionDisabled(model_name)) {
            if (self.verbose_level == .on or self.verbose_level == .full) {
                log.info("Vision disabled for model {s}, stripping image markers", .{model_name});
            }
            return multimodal.stripImageMarkers(arena, m);
        }

        // Check if provider supports vision for this model
        if (!self.provider.supportsVisionForModel(model_name)) {
            if (self.verbose_level == .on or self.verbose_level == .full) {
                log.info("Model {s} does not support vision, stripping image markers", .{model_name});
            }
            // Auto-disable vision if configured
            if (self.auto_disable_vision_on_error) {
                try self.markVisionDisabled(model_name);
            }
            return multimodal.stripImageMarkers(arena, m);
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
            .skip_dir_check = self.multimodal_unrestricted,
            .allow_remote_fetch = self.multimodal_unrestricted,
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
        if (resp.provider.len > 0) self.allocator.free(resp.provider);
        if (resp.model.len > 0) self.allocator.free(resp.model);
        if (resp.reasoning_content) |rc| {
            if (rc.len > 0) self.allocator.free(rc);
        }
        // Mark as consumed to prevent double-free
        resp.content = null;
        resp.tool_calls = &.{};
        resp.provider = "";
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
        self.system_prompt_conversation_context_fingerprint = null;
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

    const text_model_messages = try agent.buildProviderMessages(arena, agent.model_name);
    try std.testing.expectEqual(@as(usize, 1), text_model_messages.len);
    try std.testing.expect(text_model_messages[0].content_parts == null);
    try std.testing.expect(std.mem.indexOf(u8, text_model_messages[0].content, "[IMAGE:") == null);
    try std.testing.expect(std.mem.indexOf(u8, text_model_messages[0].content, "omitted because the current model does not support vision") != null);

    agent.model_name = "vision-model";
    const messages = try agent.buildProviderMessages(arena, agent.model_name);
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
    const messages = try agent.buildProviderMessages(arena, agent.model_name);

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
    const DummyProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator_: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator_.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator_: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator_.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator_.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "dummy-test-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const dummy_vtable = Provider.VTable{
        .chatWithSystem = DummyProvider.chatWithSystem,
        .chat = DummyProvider.chat,
        .supportsNativeTools = DummyProvider.supportsNativeTools,
        .getName = DummyProvider.getName,
        .deinit = DummyProvider.deinitFn,
    };

    var noop = observability.NoopObserver{};
    return Agent{
        .allocator = allocator,
        .provider = .{ .ptr = @ptrFromInt(1), .vtable = &dummy_vtable },
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

test "Agent.fromConfigWithProfile applies named profile defaults" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_provider = "openrouter",
        .default_model = "openrouter/default-model",
        .allocator = allocator,
        .model_routes = &.{
            .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b" },
        },
    };

    const profile = config_types.NamedAgentConfig{
        .name = "coder",
        .provider = "ollama",
        .model = "qwen2.5-coder:14b",
        .system_prompt = "You are a coding specialist.",
        .temperature = 0.2,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, undefined, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    try std.testing.expectEqualStrings("qwen2.5-coder:14b", agent.model_name);
    try std.testing.expectEqualStrings("ollama", agent.default_provider);
    try std.testing.expectEqualStrings("qwen2.5-coder:14b", agent.default_model);
    try std.testing.expectEqualStrings("coder", agent.profile_name.?);
    try std.testing.expectEqualStrings("You are a coding specialist.", agent.profile_system_prompt.?);
    try std.testing.expectApproxEqAbs(@as(f64, 0.2), agent.temperature, 0.000001);
    try std.testing.expectEqual(@as(usize, 0), agent.model_routes.len);
}

test "turn prepends profile system prompt when profile is active" {
    const CaptureProvider = struct {
        captured_system: ?[]const u8 = null,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (request.messages.len > 0 and request.messages[0].role == .system) {
                self.captured_system = request.messages[0].content;
            }
            return .{
                .content = try allocator.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "capture-profile-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = CaptureProvider.chatWithSystem,
        .chat = CaptureProvider.chat,
        .supportsNativeTools = CaptureProvider.supportsNativeTools,
        .getName = CaptureProvider.getName,
        .deinit = CaptureProvider.deinitFn,
    };
    var provider_state = CaptureProvider{};
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_provider = "openrouter",
        .default_model = "openrouter/default-model",
        .allocator = allocator,
    };
    const profile = config_types.NamedAgentConfig{
        .name = "coder",
        .provider = "openrouter",
        .model = "openrouter/coder-model",
        .system_prompt = "You are a coding specialist.",
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("ok", response);
    try std.testing.expect(provider_state.captured_system != null);
    try std.testing.expect(std.mem.indexOf(u8, provider_state.captured_system.?, "You are a coding specialist.") != null);
    try std.testing.expect(std.mem.indexOf(u8, provider_state.captured_system.?, "Profile: coder") != null);
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

test "Agent.fromConfig resolves conservative limits for legacy gpt-4" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4",
        .allocator = allocator,
    };
    cfg.max_tokens = null;
    cfg.agent.token_limit = config_types.DEFAULT_AGENT_TOKEN_LIMIT;
    cfg.agent.token_limit_explicit = false;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(@as(u64, 8_192), agent.token_limit);
    try std.testing.expectEqual(@as(u32, 4_096), agent.max_tokens);
}

test "Agent effective max_tokens reserves prompt headroom" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "openai/gpt-4",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .token_limit = 8_192,
        .max_tokens = 4_096,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const large_system = try allocator.alloc(u8, 28_000);
    defer allocator.free(large_system);
    @memset(large_system, 'a');

    const messages = [_]ChatMessage{
        .{ .role = .system, .content = large_system },
        .{ .role = .user, .content = "how are you?" },
    };
    const capped = agent.effectiveMaxTokensForMessages(&messages, false);
    try std.testing.expect(capped < agent.max_tokens);
    try std.testing.expect(capped > 0);
}

test "Agent effective max_tokens does not double count plain content with content_parts" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "openai/gpt-4",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .token_limit = 1_000,
        .max_tokens = 512,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const long_text = try allocator.alloc(u8, 2_000);
    defer allocator.free(long_text);
    @memset(long_text, 'a');

    const parts = [_]providers.ContentPart{
        .{ .text = long_text },
    };
    const messages = [_]ChatMessage{
        .{
            .role = .user,
            .content = long_text,
            .content_parts = &parts,
        },
    };

    const capped = agent.effectiveMaxTokensForMessages(&messages, false);
    try std.testing.expect(capped > 1);
}

test "Agent effective max_tokens scales with image_base64 size" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "openai/gpt-4",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .token_limit = 4_000,
        .max_tokens = 2_000,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const small_base64 = try allocator.alloc(u8, 120);
    defer allocator.free(small_base64);
    @memset(small_base64, 'a');

    const large_base64 = try allocator.alloc(u8, 12_000);
    defer allocator.free(large_base64);
    @memset(large_base64, 'b');

    const small_parts = [_]providers.ContentPart{
        .{ .text = "describe this image" },
        .{ .image_base64 = .{ .data = small_base64, .media_type = "image/png" } },
    };
    const large_parts = [_]providers.ContentPart{
        .{ .text = "describe this image" },
        .{ .image_base64 = .{ .data = large_base64, .media_type = "image/png" } },
    };

    const small_messages = [_]ChatMessage{
        .{
            .role = .user,
            .content = "describe this image",
            .content_parts = &small_parts,
        },
    };
    const large_messages = [_]ChatMessage{
        .{
            .role = .user,
            .content = "describe this image",
            .content_parts = &large_parts,
        },
    };

    const capped_small = agent.effectiveMaxTokensForMessages(&small_messages, false);
    const capped_large = agent.effectiveMaxTokensForMessages(&large_messages, false);
    try std.testing.expect(capped_large < capped_small);
}

test "Agent effective max_tokens accounts for native tool schema overhead" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    const tool_specs = try allocator.alloc(ToolSpec, 2);

    var params_a: [2_000]u8 = undefined;
    @memset(params_a[0..], 'a');
    var params_b: [2_000]u8 = undefined;
    @memset(params_b[0..], 'b');

    tool_specs[0] = .{
        .name = "file_write",
        .description = "Write file content",
        .parameters_json = params_a[0..],
    };
    tool_specs[1] = .{
        .name = "file_edit",
        .description = "Edit file content",
        .parameters_json = params_b[0..],
    };

    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = tool_specs,
        .mem = null,
        .observer = noop.observer(),
        .model_name = "openai/gpt-4",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .token_limit = 2_000,
        .max_tokens = 1_000,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const messages = [_]ChatMessage{
        .{ .role = .user, .content = "hello" },
    };

    const without_tools = agent.effectiveMaxTokensForMessages(&messages, false);
    const with_tools = agent.effectiveMaxTokensForMessages(&messages, true);
    try std.testing.expect(with_tools < without_tools);
}

test "Agent effective max_tokens can estimate using filtered tool schemas" {
    const allocator = std.testing.allocator;

    var noop = observability.NoopObserver{};
    const tool_specs = try allocator.alloc(ToolSpec, 2);

    var params_a: [3_000]u8 = undefined;
    @memset(params_a[0..], 'a');
    var params_b: [3_000]u8 = undefined;
    @memset(params_b[0..], 'b');

    tool_specs[0] = .{
        .name = "mcp_vikunja_list_tasks",
        .description = "List tasks",
        .parameters_json = params_a[0..],
    };
    tool_specs[1] = .{
        .name = "mcp_browser_open",
        .description = "Open browser",
        .parameters_json = params_b[0..],
    };

    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = tool_specs,
        .mem = null,
        .observer = noop.observer(),
        .model_name = "openai/gpt-4",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .token_limit = 2_200,
        .max_tokens = 1_000,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const messages = [_]ChatMessage{
        .{ .role = .user, .content = "show my tasks" },
    };

    const with_all_tools = agent.effectiveMaxTokensForMessagesWithToolSpecs(&messages, tool_specs);
    const with_filtered_tools = agent.effectiveMaxTokensForMessagesWithToolSpecs(&messages, tool_specs[0..1]);
    try std.testing.expect(with_filtered_tools > with_all_tools);
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

test "Agent.fromConfig applies status_show_emojis flag" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.status_show_emojis = false;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(!agent.status_show_emojis);
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
    agent.total_tokens = 42;
    agent.last_turn_usage = .{ .prompt_tokens = 10, .completion_tokens = 5, .total_tokens = 15 };

    const response = (try agent.handleSlashCommand("/new")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Session cleared.", response);
    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
    try std.testing.expect(!agent.has_system_prompt);
    try std.testing.expectEqual(@as(u64, 0), agent.total_tokens);
    try std.testing.expectEqual(@as(u32, 0), agent.last_turn_usage.total_tokens);
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

test "turn retains user message on provider error" {
    const FailProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return error.ProviderFailed;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "fail-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    const provider_vtable = Provider.VTable{
        .chatWithSystem = FailProvider.chatWithSystem,
        .chat = FailProvider.chat,
        .supportsNativeTools = FailProvider.supportsNativeTools,
        .getName = FailProvider.getName,
        .deinit = FailProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrFromInt(1), .vtable = &provider_vtable };

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
        .has_system_prompt = true,
    };
    defer agent.deinit();

    // Seed a system prompt so turn() does not rebuild it (which can load
    // user config and introduce non-deterministic side effects in tests).
    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });

    try std.testing.expectError(error.ProviderFailed, agent.turn("hello"));
    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());
    try std.testing.expectEqualStrings("hello", agent.history.items[1].content);

    // Should not double-free when clearing history after a failed turn.
    agent.clearHistory();
    try std.testing.expectEqual(@as(usize, 0), agent.historyLen());
}

test "turn does not retry immediately on rate limit" {
    const RateLimitedProvider = struct {
        const State = struct {
            calls: u32 = 0,
        };

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const state: *State = @ptrCast(@alignCast(ptr));
            state.calls += 1;
            return error.RateLimited;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "rate-limited-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    const provider_vtable = Provider.VTable{
        .chatWithSystem = RateLimitedProvider.chatWithSystem,
        .chat = RateLimitedProvider.chat,
        .supportsNativeTools = RateLimitedProvider.supportsNativeTools,
        .getName = RateLimitedProvider.getName,
        .deinit = RateLimitedProvider.deinitFn,
    };
    var state = RateLimitedProvider.State{};
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &provider_vtable };

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
        .has_system_prompt = true,
    };
    defer agent.deinit();

    providers.clearLastApiErrorDetail();
    defer providers.clearLastApiErrorDetail();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });

    try std.testing.expectError(error.RateLimited, agent.turn("hello"));
    try std.testing.expectEqual(@as(u32, 1), state.calls);
}

test "turn still retries non-rate-limited provider failures once" {
    const RetryProvider = struct {
        const State = struct {
            calls: u32 = 0,
        };

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const state: *State = @ptrCast(@alignCast(ptr));
            state.calls += 1;
            return error.ProviderFailed;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "retry-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    const provider_vtable = Provider.VTable{
        .chatWithSystem = RetryProvider.chatWithSystem,
        .chat = RetryProvider.chat,
        .supportsNativeTools = RetryProvider.supportsNativeTools,
        .getName = RetryProvider.getName,
        .deinit = RetryProvider.deinitFn,
    };
    var state = RetryProvider.State{};
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &provider_vtable };

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
        .has_system_prompt = true,
    };
    defer agent.deinit();

    providers.clearLastApiErrorDetail();
    providers.setLastApiErrorDetail("compatible", "status=429 message=Rate limit exceeded");
    defer providers.clearLastApiErrorDetail();

    try agent.history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "sys"),
    });

    try std.testing.expectError(error.ProviderFailed, agent.turn("hello"));
    try std.testing.expectEqual(@as(u32, 2), state.calls);
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
    try std.testing.expect(std.mem.indexOf(u8, response, "/tasks") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/poll") != null);
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

    try std.testing.expect(std.mem.indexOf(u8, response, "🌊 NullClaw ") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "42") != null);
}

test "slash /status can render without emojis" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.status_show_emojis = false;

    const response = (try agent.handleSlashCommand("/status")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "🌊") == null);
    try std.testing.expect(std.mem.indexOf(u8, response, "NullClaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Model:") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "🧠") == null);
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

test "auto route selects provider-prefixed model ref for fast prompt" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };

    const routed = (try agent.routeModelNameForTurn(allocator, "show current status")).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("groq/llama-3.3-70b", routed);
}

test "auto route selects fast model for short structured prompt" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b", .cost_class = .free, .quota_class = .unlimited },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4", .cost_class = .standard, .quota_class = .normal },
        .{ .hint = "deep", .provider = "openrouter", .model = "anthropic/claude-opus-4", .cost_class = .premium, .quota_class = .constrained },
    };

    const routed = (try agent.routeModelNameForTurn(
        allocator,
        "Extract the version from 'release-1.2.3' and return only the semver.",
    )).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("groq/llama-3.3-8b", routed);
}

test "auto route keeps ambiguous short prompt on balanced model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b", .cost_class = .free, .quota_class = .unlimited },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4", .cost_class = .premium, .quota_class = .constrained },
        .{ .hint = "deep", .provider = "openrouter", .model = "anthropic/claude-opus-4", .cost_class = .premium, .quota_class = .constrained },
    };

    const routed = (try agent.routeModelNameForTurn(allocator, "What should we do here?")).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("openrouter/anthropic/claude-sonnet-4", routed);
}

test "auto route selects deep model for investigation prompt" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b", .cost_class = .free, .quota_class = .unlimited },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4", .cost_class = .standard, .quota_class = .normal },
        .{ .hint = "deep", .provider = "openrouter", .model = "anthropic/claude-opus-4", .cost_class = .premium, .quota_class = .constrained },
    };

    const routed = (try agent.routeModelNameForTurn(
        allocator,
        "Investigate the root cause of this regression and compare the tradeoffs of the possible fixes.",
    )).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("openrouter/anthropic/claude-opus-4", routed);
}

test "auto route records last route trace for short structured prompt" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{
            .hint = "fast",
            .provider = "groq",
            .model = "llama-3.3-8b",
            .cost_class = .free,
            .quota_class = .unlimited,
        },
        .{
            .hint = "balanced",
            .provider = "openrouter",
            .model = "anthropic/claude-sonnet-4",
            .cost_class = .standard,
            .quota_class = .normal,
        },
    };

    const routed = (try agent.routeModelNameForTurn(
        allocator,
        "Extract the version from 'release-1.2.3' and return only the semver.",
    )).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("groq/llama-3.3-8b", routed);
    try std.testing.expect(agent.last_route_trace != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.last_route_trace.?, "fast -> groq/llama-3.3-8b") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, agent.last_route_trace.?, "high-confidence") != null or
            std.mem.indexOf(u8, agent.last_route_trace.?, "structured prompt") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, agent.last_route_trace.?, "score ") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, agent.last_route_trace.?, "\"version\"") != null or
            std.mem.indexOf(u8, agent.last_route_trace.?, "\"extract\"") != null or
            std.mem.indexOf(u8, agent.last_route_trace.?, "\"return only\"") != null,
    );
}

test "model status reports last auto-route trace" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{
            .hint = "fast",
            .provider = "groq",
            .model = "llama-3.3-8b",
            .cost_class = .free,
            .quota_class = .unlimited,
        },
        .{
            .hint = "balanced",
            .provider = "openrouter",
            .model = "anthropic/claude-sonnet-4",
            .cost_class = .standard,
            .quota_class = .normal,
        },
    };

    const routed = (try agent.routeModelNameForTurn(
        allocator,
        "Extract the version from 'release-1.2.3' and return only the semver.",
    )).?;
    defer allocator.free(routed);

    const status = try agent.formatModelStatus();
    defer allocator.free(status);

    try std.testing.expect(std.mem.indexOf(u8, status, "Auto-routing: configured") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "Last auto-route: fast -> groq/llama-3.3-8b") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "Auto routes:") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "cost=free, quota=unlimited") != null);
}

test "auto route skips degraded fast route after rate limit" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };

    const selection = agent.routeSelectionForTurn("show current status").?;
    try agent.markRouteDegraded(selection, error.RateLimited);

    const routed = (try agent.routeModelNameForTurn(allocator, "show current status")).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("openrouter/anthropic/claude-sonnet-4", routed);

    const status = try agent.formatModelStatus();
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "Degraded routes:") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "fast -> groq/llama-3.3-8b") != null);
}

test "auto route degrades route on out-of-credits provider detail" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-8b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };

    providers.clearLastApiErrorDetail();
    defer providers.clearLastApiErrorDetail();
    providers.setLastApiErrorDetail("groq", "out of credits");

    const selection = agent.routeSelectionForTurn("show current status").?;
    try agent.markRouteDegraded(selection, error.AllProvidersFailed);

    const routed = (try agent.routeModelNameForTurn(allocator, "show current status")).?;
    defer allocator.free(routed);

    try std.testing.expectEqualStrings("openrouter/anthropic/claude-sonnet-4", routed);
}

test "auto route is disabled when model is pinned" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };
    agent.model_pinned_by_user = true;

    try std.testing.expect((try agent.routeModelNameForTurn(allocator, "show current status")) == null);
}

test "auto route selection benchmark stays below visible overhead" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
        .{ .hint = "deep", .provider = "openrouter", .model = "anthropic/claude-opus-4" },
        .{ .hint = "vision", .provider = "openrouter", .model = "openai/gpt-4.1" },
    };

    const iterations: usize = 50_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const hint = agent.selectRouteHintForTurn("show current status");
        try std.testing.expect(hint != null);
        try std.testing.expectEqualStrings("fast", hint.?);
    }
    const elapsed_ns = timer.read();
    const avg_ns = elapsed_ns / iterations;

    // Heuristic routing should stay far below human-visible latency.
    try std.testing.expect(avg_ns < 200_000);
}

test "slash /model auto clears pin and invalidates cached prompt model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };
    agent.model_name = "gpt-4o";
    agent.model_name_owned = false;
    agent.model_pinned_by_user = true;
    agent.has_system_prompt = true;
    agent.system_prompt_has_conversation_context = true;
    agent.system_prompt_model_name = try allocator.dupe(u8, "groq/llama-3.3-70b");

    const response = (try agent.handleSlashCommand("/model auto")).?;
    defer allocator.free(response);

    const expected = try std.fmt.allocPrint(
        allocator,
        "Automatic model routing enabled. Reverted to the configured default model: {s}",
        .{agent.default_model},
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, response);
    try std.testing.expect(!agent.model_pinned_by_user);
    try std.testing.expectEqualStrings(agent.default_model, agent.model_name);
    try std.testing.expect(!agent.has_system_prompt);
    try std.testing.expect(!agent.system_prompt_has_conversation_context);
    try std.testing.expect(agent.system_prompt_model_name == null);
}

test "slash /model auto without routes restores default model and explains routing is not configured" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_name = "gpt-4o";
    agent.model_name_owned = false;
    agent.model_pinned_by_user = true;

    const response = (try agent.handleSlashCommand("/model auto")).?;
    defer allocator.free(response);

    const expected = try std.fmt.allocPrint(
        allocator,
        "Automatic model routing is not configured. Reverted to the configured default model: {s}",
        .{agent.default_model},
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, response);
    try std.testing.expect(!agent.model_pinned_by_user);
    try std.testing.expectEqualStrings(agent.default_model, agent.model_name);
}

test "slash /model pins explicit selection" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.model_routes = &.{
        .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };

    const response = (try agent.handleSlashCommand("/model gpt-4o")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "gpt-4o") != null);
    try std.testing.expect(agent.model_pinned_by_user);
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

    const alias_resp = (try agent.handleSlashCommand("/think on")).?;
    defer allocator.free(alias_resp);
    try std.testing.expect(std.mem.indexOf(u8, alias_resp, "medium") != null);
    try std.testing.expectEqualStrings("medium", agent.reasoning_effort.?);

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

test "slash /abort aliases /stop" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/abort")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "No active background task") != null);
}

test "turn returns interruption reply when interrupt requested" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    agent.requestInterrupt();
    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Interrupted by /stop") != null);
}

test "interruption reply lists effectively interrupted tools" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    try agent.noteInterruptedTool("shell");
    try agent.noteInterruptedTool("web_fetch");
    agent.requestInterrupt();

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Interrupted tools: shell, web_fetch") != null);
}

test "hard stop mock interruption lists exactly interrupted tool" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const ProbeTool = struct {
        const Self = @This();
        started: *std.atomic.Value(bool),

        pub const tool_name = "hard_stop_probe";
        pub const tool_description = "Mock long-running tool for hard-stop tests";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.started.store(true, .release);
            const proc = tools_mod.process_util;
            const result = try proc.run(allocator, &.{ "sh", "-c", "sleep 5; echo done" }, .{});
            defer result.deinit(allocator);
            if (result.interrupted) {
                return .{ .success = false, .output = "", .error_msg = "Interrupted by /stop" };
            }
            return .{ .success = true, .output = try allocator.dupe(u8, "probe-finished") };
        }
    };

    const OneShotToolProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            const tool_calls = try allocator.alloc(providers.ToolCall, 1);
            tool_calls[0] = .{
                .id = try allocator.dupe(u8, "call-hard-stop"),
                .name = try allocator.dupe(u8, "hard_stop_probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            return .{
                .content = try allocator.dupe(u8, "running"),
                .tool_calls = tool_calls,
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "one-shot-tool-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const InterruptCtx = struct {
        agent: *Agent,
        started: *std.atomic.Value(bool),
    };
    const InterruptWorker = struct {
        fn run(ctx: *InterruptCtx) void {
            while (!ctx.started.load(.acquire)) {
                std.Thread.sleep(10 * std.time.ns_per_ms);
            }
            std.Thread.sleep(80 * std.time.ns_per_ms);
            ctx.agent.requestInterrupt();
        }
    };

    const allocator = std.testing.allocator;
    var started = std.atomic.Value(bool).init(false);
    var tool_impl = ProbeTool{ .started = &started };
    const tools = [_]Tool{tool_impl.tool()};

    var specs = try allocator.alloc(ToolSpec, tools.len);
    for (tools, 0..) |t, i| {
        specs[i] = .{
            .name = t.name(),
            .description = t.description(),
            .parameters_json = t.parametersJson(),
        };
    }

    var provider_state = OneShotToolProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = OneShotToolProvider.chatWithSystem,
        .chat = OneShotToolProvider.chat,
        .supportsNativeTools = OneShotToolProvider.supportsNativeTools,
        .getName = OneShotToolProvider.getName,
        .deinit = OneShotToolProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tools,
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

    var interrupt_ctx = InterruptCtx{ .agent = &agent, .started = &started };
    const interrupt_thread = try std.Thread.spawn(.{}, InterruptWorker.run, .{&interrupt_ctx});
    defer interrupt_thread.join();

    const response = try agent.turn("run hard stop mock");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Interrupted by /stop") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "hard_stop_probe") != null);
    try std.testing.expectEqual(@as(usize, 1), provider_state.call_count);
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
    agent.total_tokens = 42;
    agent.last_turn_usage = .{ .prompt_tokens = 7, .completion_tokens = 5, .total_tokens = 12 };

    const response = (try agent.handleSlashCommand("/restart")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Session restarted.", response);
    try std.testing.expect(agent.reasoning_effort == null);
    try std.testing.expect(agent.verbose_level == .off);
    try std.testing.expect(agent.usage_mode == .off);
    try std.testing.expect(agent.tts_mode == .off);
    try std.testing.expect(agent.tts_provider == null);
    try std.testing.expectEqual(@as(u64, 0), agent.total_tokens);
    try std.testing.expectEqual(@as(u32, 0), agent.last_turn_usage.total_tokens);
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

test "turn estimates token usage when provider omits usage" {
    const ProviderState = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "final answer"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
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

    const response = try agent.turn("hello");
    defer allocator.free(response);

    const expected_tokens = estimate_text_tokens("final answer");
    try std.testing.expectEqual(@as(u64, expected_tokens), agent.tokensUsed());

    const status = (try agent.handleSlashCommand("/status")).?;
    defer allocator.free(status);
    var expected_line_buf: [64]u8 = undefined;
    const expected_line = try std.fmt.bufPrint(&expected_line_buf, "Tokens used: {d}", .{expected_tokens});
    try std.testing.expect(std.mem.indexOf(u8, status, expected_line) != null);
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

test "turn refreshes system prompt when conversation sender changes" {
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

    agent.conversation_context = .{
        .channel = "discord",
        .sender_id = "user-1",
        .sender_username = "alpha",
        .sender_display_name = "Alpha",
        .group_id = "guild-1",
        .is_group = true,
    };
    const first = try agent.turn("first");
    defer allocator.free(first);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Sender Discord ID: user-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Sender username: alpha") != null);

    agent.conversation_context = .{
        .channel = "discord",
        .sender_id = "user-2",
        .sender_username = "beta",
        .sender_display_name = "Beta",
        .group_id = "guild-1",
        .is_group = true,
    };
    const second = try agent.turn("second");
    defer allocator.free(second);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Sender Discord ID: user-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Sender username: beta") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Sender Discord ID: user-1") == null);
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

test "direct slash skill command resolves hyphenated skill name" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/news-digest");
    {
        const f = try tmp.dir.createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Build a digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news-digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "news-digest") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "latest ai news") != null);
}

test "direct slash skill command resolves two-word alias to hyphenated skill" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/news-digest");
    {
        const f = try tmp.dir.createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Build a digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "news-digest") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "latest ai news") != null);
}

test "direct slash skill command does not collapse token boundaries" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/news-digest");
    {
        const f = try tmp.dir.createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Build a digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = try agent.handleSlashCommand("/newsdigest latest ai news");
    try std.testing.expect(response == null);
}

test "direct slash skill command reports ambiguous normalized alias" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/news-digest");
    try tmp.dir.makePath("skills/news_ digest");
    {
        const f = try tmp.dir.createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Build a digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }
    {
        const f = try tmp.dir.createFile("skills/news_ digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news_digest",
            \\  "description": "Build another digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news_ digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect other news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Ambiguous skill name") != null);
}

test "direct slash skill command does not shadow built in doctor" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/doctor");
    {
        const f = try tmp.dir.createFile("skills/doctor/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "doctor",
            \\  "description": "Pretend doctor skill",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/doctor/SKILL.md", .{});
        defer f.close();
        try f.writeAll("This should not shadow /doctor.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/doctor")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Memory runtime not available") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Pretend doctor skill") == null);
}

test "direct slash skill command reports ambiguity between exact and composite matches" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/news");
    try tmp.dir.makePath("skills/news-digest");
    {
        const f = try tmp.dir.createFile("skills/news/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news",
            \\  "description": "General news skill",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news/SKILL.md", .{});
        defer f.close();
        try f.writeAll("General news skill body.");
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Digest skill",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp.dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Digest skill body.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Ambiguous skill name") != null);
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

test "turn passes auto-routed model to provider" {
    const CaptureProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, model),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "capture-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    const provider_vtable = Provider.VTable{
        .chatWithSystem = CaptureProvider.chatWithSystem,
        .chat = CaptureProvider.chat,
        .supportsNativeTools = CaptureProvider.supportsNativeTools,
        .getName = CaptureProvider.getName,
        .deinit = CaptureProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrFromInt(1),
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
        .model_routes = &.{
            .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
            .{ .hint = "balanced", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
        },
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

    const response = try agent.turn("show current status");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("groq/llama-3.3-70b", response);
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
        .{ .name = "file_edit_hashed", .arguments_json = "{\"path\":\"notes/TOOLS.md\",\"target\":\"L1:abc\",\"new_text\":\"b\"}" },
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
        .{ .name = "file_edit_hashed", .arguments_json = "{\"path\":\"./config/TOOLS.md\",\"target\":\"L4:def\",\"new_text\":\"new\"}" },
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

test "Agent tool-limit summary preserves provider session_id" {
    const NoopTool = struct {
        const Self = @This();
        pub const tool_name = "noop";
        pub const tool_description = "noop";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{
                .success = true,
                .output = try allocator.dupe(u8, "noop ok"),
            };
        }
    };

    const SessionCaptureProvider = struct {
        const Self = @This();
        call_count: usize = 0,
        summary_session_id: ?[]const u8 = null,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-noop"),
                    .name = try allocator.dupe(u8, "noop"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "running tool"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            self.summary_session_id = request.session_id;
            return .{
                .content = try allocator.dupe(u8, "summary"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "session-capture-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = SessionCaptureProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = SessionCaptureProvider.chatWithSystem,
        .chat = SessionCaptureProvider.chat,
        .supportsNativeTools = SessionCaptureProvider.supportsNativeTools,
        .getName = SessionCaptureProvider.getName,
        .deinit = SessionCaptureProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop_tool = NoopTool{};
    const tool_list = [_]Tool{noop_tool.tool()};
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
        .max_tool_iterations = 1,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
        .memory_session_id = "telegram:chat123",
    };
    defer agent.deinit();

    const response = try agent.turn("trigger summary");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("[Tool iteration limit: 1/1]\n\nsummary", response);
    try std.testing.expectEqualStrings("telegram:chat123", provider_state.summary_session_id.?);
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

test "Agent shell failure with normalized output does not poison next turn" {
    const ShellFailureProvider = struct {
        const Self = @This();

        call_count: usize = 0,
        saw_tool_results: bool = false,
        saw_error_tool_result: bool = false,
        saw_valid_utf8_tool_results: bool = false,
        saw_non_empty_error_tool_result: bool = false,

        fn failingShellCommand() []const u8 {
            return if (comptime builtin.os.tag == .windows)
                "powershell.exe -NoProfile -Command \"[Console]::OpenStandardError().Write([byte[]](0xD6,0xD0,0xCE,0xC4),0,4)\" & exit /b 1"
            else
                "printf '\\200' >&2; exit 1";
        }

        fn captureToolResultMessage(self: *Self, messages: []const ChatMessage) void {
            const start_marker = "<tool_result name=\"shell\" status=\"error\">";
            const end_marker = "</tool_result>";

            for (messages) |msg| {
                if (msg.role != .user) continue;
                if (std.mem.indexOf(u8, msg.content, "[Tool results]") == null) continue;

                self.saw_tool_results = true;
                self.saw_error_tool_result = std.mem.indexOf(u8, msg.content, "<tool_result name=\"shell\" status=\"error\">") != null;
                self.saw_valid_utf8_tool_results = std.unicode.utf8ValidateSlice(msg.content);
                if (std.mem.indexOf(u8, msg.content, start_marker)) |start_idx| {
                    const body_start = start_idx + start_marker.len;
                    if (std.mem.indexOf(u8, msg.content[body_start..], end_marker)) |end_rel| {
                        const body = std.mem.trim(u8, msg.content[body_start .. body_start + end_rel], " \t\r\n");
                        self.saw_non_empty_error_tool_result = body.len > 0;
                    }
                }
                break;
            }
        }

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-shell-1"),
                    .name = try allocator.dupe(u8, "shell"),
                    .arguments = try std.fmt.allocPrint(allocator, "{{\"command\":{f}}}", .{
                        std.json.fmt(failingShellCommand(), .{}),
                    }),
                };

                return .{
                    .content = try allocator.dupe(u8, "Run shell"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            self.captureToolResultMessage(request.messages);
            return .{
                .content = try allocator.dupe(u8, "recovered"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "shell-failure-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = ShellFailureProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ShellFailureProvider.chatWithSystem,
        .chat = ShellFailureProvider.chat,
        .supportsNativeTools = ShellFailureProvider.supportsNativeTools,
        .getName = ShellFailureProvider.getName,
        .deinit = ShellFailureProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var shell_tool_impl = tools_mod.shell.ShellTool{ .workspace_dir = "." };
    const tool_list = [_]Tool{shell_tool_impl.tool()};

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
        .workspace_dir = ".",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("run failing shell");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("recovered", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(provider_state.saw_tool_results);
    try std.testing.expect(provider_state.saw_error_tool_result);
    try std.testing.expect(provider_state.saw_valid_utf8_tool_results);
    try std.testing.expect(provider_state.saw_non_empty_error_tool_result);

    for (agent.history.items) |msg| {
        try std.testing.expect(std.unicode.utf8ValidateSlice(msg.content));
    }
}

test "Agent strips fabricated tool_result blocks from XML assistant history" {
    const XmlFabricationProvider = struct {
        saw_fake_tool_result_in_history: bool = false,
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                return .{
                    .content = try allocator.dupe(
                        u8,
                        "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"printf hi\"}}</tool_call><tool_result name=\"shell\" status=\"ok\">fabricated</tool_result>",
                    ),
                    .tool_calls = &.{},
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            for (request.messages) |msg| {
                if (msg.role != .assistant) continue;
                if (std.mem.indexOf(u8, msg.content, "fabricated") != null) {
                    self.saw_fake_tool_result_in_history = true;
                }
            }

            return .{
                .content = try allocator.dupe(u8, "done"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "xml-fabrication-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = XmlFabricationProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = XmlFabricationProvider.chatWithSystem,
        .chat = XmlFabricationProvider.chat,
        .supportsNativeTools = XmlFabricationProvider.supportsNativeTools,
        .getName = XmlFabricationProvider.getName,
        .deinit = XmlFabricationProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var shell_tool_impl = tools_mod.shell.ShellTool{ .workspace_dir = "." };
    const tool_list = [_]Tool{shell_tool_impl.tool()};

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
        .workspace_dir = ".",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("run shell");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("done", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(!provider_state.saw_fake_tool_result_in_history);
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

test "Agent falls back to blocking chat when stream ctx is missing" {
    const allocator = std.testing.allocator;

    const StreamGuardProvider = struct {
        chat_calls: usize = 0,
        stream_calls: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator_: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator_.dupe(u8, "ok");
        }

        fn chat(ptr: *anyopaque, allocator_: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.chat_calls += 1;
            return .{
                .content = try allocator_.dupe(u8, "ok"),
                .tool_calls = &.{},
                .usage = .{},
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn supportsStreaming(_: *anyopaque) bool {
            return true;
        }

        fn streamChat(
            ptr: *anyopaque,
            _: std.mem.Allocator,
            _: providers.ChatRequest,
            _: []const u8,
            _: f64,
            _: providers.StreamCallback,
            _: *anyopaque,
        ) anyerror!providers.StreamChatResult {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.stream_calls += 1;
            return error.ShouldNotStream;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "stream-guard";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    var provider_state = StreamGuardProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = StreamGuardProvider.chatWithSystem,
        .chat = StreamGuardProvider.chat,
        .supportsNativeTools = StreamGuardProvider.supportsNativeTools,
        .getName = StreamGuardProvider.getName,
        .deinit = StreamGuardProvider.deinitFn,
        .supports_streaming = StreamGuardProvider.supportsStreaming,
        .stream_chat = StreamGuardProvider.streamChat,
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
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const test_cb: providers.StreamCallback = struct {
        fn cb(_: *anyopaque, _: providers.StreamChunk) void {}
    }.cb;
    agent.stream_callback = test_cb;
    agent.stream_ctx = null;

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("ok", response);
    try std.testing.expectEqual(@as(usize, 1), provider_state.chat_calls);
    try std.testing.expectEqual(@as(usize, 0), provider_state.stream_calls);
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

test "Agent selectDisplayText hides malformed tool markup payload" {
    const raw = "<tool_call>web_search<arg_key>query</arg_key><arg_value>x</arg_value></tool_call>";
    const selected = Agent.selectDisplayText(raw, "", 0);
    try std.testing.expectEqualStrings("", selected);
}

test "Agent selectDisplayText keeps plain text when no markup exists" {
    const raw = "All good.";
    const selected = Agent.selectDisplayText(raw, "", 0);
    try std.testing.expectEqualStrings("All good.", selected);
}

test "Agent selectDisplayText prefers parsed text when present" {
    const selected = Agent.selectDisplayText("<tool_call>{}</tool_call>", "let me check", 1);
    try std.testing.expectEqualStrings("let me check", selected);
}

test "Agent selectDisplayText hides malformed tool markup present in parsed text" {
    const parsed_with_markup = "Some text <tool_call>{\"name\":\"shell\"";
    const selected = Agent.selectDisplayText(parsed_with_markup, parsed_with_markup, 0);
    try std.testing.expectEqualStrings("", selected);
}

test "Agent retries empty final response once before succeeding" {
    const EmptyThenRecoveredProvider = struct {
        call_count: usize = 0,
        saw_empty_retry_prompt: bool = false,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 1) {
                return .{
                    .content = try allocator.dupe(u8, ""),
                    .tool_calls = &.{},
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            for (request.messages) |msg| {
                if (msg.role == .user and std.mem.indexOf(u8, msg.content, "previous reply was empty") != null) {
                    self.saw_empty_retry_prompt = true;
                }
            }

            return .{
                .content = try allocator.dupe(u8, "recovered"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "empty-then-recovered-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = EmptyThenRecoveredProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = EmptyThenRecoveredProvider.chatWithSystem,
        .chat = EmptyThenRecoveredProvider.chat,
        .supportsNativeTools = EmptyThenRecoveredProvider.supportsNativeTools,
        .getName = EmptyThenRecoveredProvider.getName,
        .deinit = EmptyThenRecoveredProvider.deinitFn,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = .{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable },
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = ".",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("recovered", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(provider_state.saw_empty_retry_prompt);
}

test "Agent returns NoResponseContent after repeated empty final responses" {
    const AlwaysEmptyProvider = struct {
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            return .{
                .content = try allocator.dupe(u8, ""),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "always-empty-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = AlwaysEmptyProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = AlwaysEmptyProvider.chatWithSystem,
        .chat = AlwaysEmptyProvider.chat,
        .supportsNativeTools = AlwaysEmptyProvider.supportsNativeTools,
        .getName = AlwaysEmptyProvider.getName,
        .deinit = AlwaysEmptyProvider.deinitFn,
    };

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = .{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable },
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = noop.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = ".",
        .max_tool_iterations = 4,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    try std.testing.expectError(error.NoResponseContent, agent.turn("hello"));
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
}

test "Agent.fromConfig sets exec_security=full for full autonomy" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .full;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(agent.exec_security == .full);
    try std.testing.expect(agent.exec_ask == .off);
}

test "Agent.fromConfig sets exec_security=deny for read_only autonomy" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .read_only;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(agent.exec_security == .deny);
    try std.testing.expect(agent.exec_ask == .off);
}

test "Agent.fromConfig sets exec_security=allowlist for supervised autonomy" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .supervised;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(agent.exec_security == .allowlist);
    try std.testing.expect(agent.exec_ask == .on_miss);
}

test "Agent.fromConfig sets multimodal_unrestricted for yolo" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .yolo;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(agent.multimodal_unrestricted == true);
    try std.testing.expect(agent.exec_security == .full);
    try std.testing.expect(agent.exec_ask == .off);
    try std.testing.expect(agent.default_exec_security == .full);
    try std.testing.expect(agent.default_exec_ask == .off);
}

test "slash /restart restores config-derived exec policy for yolo" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .yolo;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    agent.exec_security = .allowlist;
    agent.exec_ask = .on_miss;

    const response = (try agent.handleSlashCommand("/restart")).?;
    defer allocator.free(response);

    try std.testing.expectEqualStrings("Session restarted.", response);
    try std.testing.expect(agent.exec_security == .full);
    try std.testing.expect(agent.exec_ask == .off);
}

test "Agent.fromConfig does not set multimodal_unrestricted for full" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.autonomy.level = .full;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(agent.multimodal_unrestricted == false);
}

test "execBlockMessage allows all commands when exec_security=full" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.exec_security = .full;
    agent.exec_ask = .off;

    // Even high-risk commands should not be blocked by execBlockMessage
    var args1 = std.json.ObjectMap.init(allocator);
    defer args1.deinit();
    try args1.put("command", .{ .string = "rm -rf /tmp/test" });
    try std.testing.expect(agent.execBlockMessage(args1) == null);

    var args2 = std.json.ObjectMap.init(allocator);
    defer args2.deinit();
    try args2.put("command", .{ .string = "curl https://example.com" });
    try std.testing.expect(agent.execBlockMessage(args2) == null);

    var args3 = std.json.ObjectMap.init(allocator);
    defer args3.deinit();
    try args3.put("command", .{ .string = "ls -la" });
    try std.testing.expect(agent.execBlockMessage(args3) == null);
}

test "execBlockMessage checks allowlist when exec_security=allowlist" {
    const allocator = std.testing.allocator;
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(allocator, 100);
    defer tracker.deinit();

    const allowed = [_][]const u8{ "ls", "cat" };
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .tracker = &tracker,
        .allowed_commands = &allowed,
    };

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.exec_security = .allowlist;
    agent.exec_ask = .on_miss;
    agent.policy = &policy;

    // Allowed command passes
    var args1 = std.json.ObjectMap.init(allocator);
    defer args1.deinit();
    try args1.put("command", .{ .string = "ls -la" });
    try std.testing.expect(agent.execBlockMessage(args1) == null);

    // Disallowed command is blocked
    var args2 = std.json.ObjectMap.init(allocator);
    defer args2.deinit();
    try args2.put("command", .{ .string = "curl https://example.com" });
    try std.testing.expect(agent.execBlockMessage(args2) != null);
}

test "execBlockMessage allowlist mode honors wildcard allowed_commands" {
    const allocator = std.testing.allocator;
    const policy_mod = @import("../security/policy.zig");
    var tracker_open = policy_mod.RateTracker.init(allocator, 10000);
    defer tracker_open.deinit();

    var open_policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker_open,
    };

    var tracker_restricted = policy_mod.RateTracker.init(allocator, 10000);
    defer tracker_restricted.deinit();
    const restricted_allowed = [_][]const u8{"ls"};
    var restricted_policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .allowed_commands = &restricted_allowed,
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker_restricted,
    };

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.exec_security = .allowlist;
    agent.exec_ask = .on_miss;

    // Command outside default allowlist should pass with wildcard policy.
    agent.policy = &open_policy;
    var args = std.json.ObjectMap.init(allocator);
    defer args.deinit();
    try args.put("command", .{ .string = "python3 script.py" });
    try std.testing.expect(agent.execBlockMessage(args) == null);

    // Same command should be blocked under restrictive allowlist.
    agent.policy = &restricted_policy;
    try std.testing.expect(agent.execBlockMessage(args) != null);
}

// ── filterToolSpecsForTurn tests ─────────────────────────────────

test "filterToolSpecsForTurn no groups returns all specs unchanged" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    var noop = observability.NoopObserver{};
    const specs: []const ToolSpec = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "mcp_vikunja_list_tasks", .description = "list tasks", .parameters_json = "{}" },
    };
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();
    // Override tool_specs to our test set (not heap-alloc'd via fromConfig)
    allocator.free(agent.tool_specs);
    agent.tool_specs = specs;
    agent.tool_filter_groups = &.{}; // explicitly empty

    const result = try agent.filterToolSpecsForTurn(arena, "show me tasks");
    // Should be same pointer — no copy made
    try std.testing.expectEqual(specs.ptr, result.ptr);
    try std.testing.expectEqual(@as(usize, 2), result.len);
    // Prevent double-free: clear the pointer so deinit doesn't free it
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "filterToolSpecsForTurn always group always includes matching MCP tool" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    var noop = observability.NoopObserver{};
    const specs: []const ToolSpec = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "mcp_vikunja_list_tasks", .description = "list tasks", .parameters_json = "{}" },
        .{ .name = "mcp_browser_open", .description = "open browser", .parameters_json = "{}" },
    };
    const patterns: []const []const u8 = &.{"mcp_vikunja_*"};
    const groups: []const config_types.ToolFilterGroup = &.{
        .{ .mode = .always, .tools = patterns, .keywords = &.{} },
    };

    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = specs;
    agent.tool_filter_groups = groups;

    const result = try agent.filterToolSpecsForTurn(arena, "hello world");
    // shell (non-MCP) + mcp_vikunja_list_tasks (always matched); mcp_browser_open excluded
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name);
    try std.testing.expectEqualStrings("mcp_vikunja_list_tasks", result[1].name);
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "filterToolSpecsForTurn dynamic group includes tool on keyword match" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    var noop = observability.NoopObserver{};
    const specs: []const ToolSpec = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "mcp_vikunja_list_tasks", .description = "list tasks", .parameters_json = "{}" },
    };
    const patterns: []const []const u8 = &.{"mcp_vikunja_*"};
    const keywords: []const []const u8 = &.{ "task", "vikunja", "todo" };
    const groups: []const config_types.ToolFilterGroup = &.{
        .{ .mode = .dynamic, .tools = patterns, .keywords = keywords },
    };

    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = specs;
    agent.tool_filter_groups = groups;

    // Keyword present — tool should be included
    const with_kw = try agent.filterToolSpecsForTurn(arena, "show me my tasks for today");
    try std.testing.expectEqual(@as(usize, 2), with_kw.len);
    try std.testing.expectEqualStrings("mcp_vikunja_list_tasks", with_kw[1].name);

    // No keyword — MCP tool should be excluded
    const without_kw = try agent.filterToolSpecsForTurn(arena, "what is the weather?");
    try std.testing.expectEqual(@as(usize, 1), without_kw.len);
    try std.testing.expectEqualStrings("shell", without_kw[0].name);

    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "filterToolSpecsForTurn dynamic group keyword match is case-insensitive" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    var noop = observability.NoopObserver{};
    const specs: []const ToolSpec = &.{
        .{ .name = "mcp_vikunja_create_task", .description = "create task", .parameters_json = "{}" },
    };
    const patterns: []const []const u8 = &.{"mcp_vikunja_*"};
    const keywords: []const []const u8 = &.{"task"};
    const groups: []const config_types.ToolFilterGroup = &.{
        .{ .mode = .dynamic, .tools = patterns, .keywords = keywords },
    };

    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = specs;
    agent.tool_filter_groups = groups;

    const result = try agent.filterToolSpecsForTurn(arena, "Create a TASK for me");
    try std.testing.expectEqual(@as(usize, 1), result.len);
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "globMatch handles prefix wildcard" {
    try std.testing.expect(Agent.globMatch("mcp_vikunja_*", "mcp_vikunja_list_tasks"));
    try std.testing.expect(Agent.globMatch("mcp_vikunja_*", "mcp_vikunja_create_task"));
    try std.testing.expect(!Agent.globMatch("mcp_vikunja_*", "mcp_browser_open"));
    try std.testing.expect(Agent.globMatch("*", "anything"));
    try std.testing.expect(Agent.globMatch("shell", "shell"));
    try std.testing.expect(!Agent.globMatch("shell", "shell_extra"));
}
