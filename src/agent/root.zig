//! Agent core — struct definition, turn loop, tool execution.
//!
//! Sub-modules: dispatcher.zig (tool call parsing), compaction.zig (history
//! compaction/trimming), cli.zig (CLI entry point + REPL), prompt.zig
//! (system prompt), memory_loader.zig (memory enrichment).

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const log = std.log.scoped(.agent);
const Config = @import("../config.zig").Config;
const config_types = @import("../config_types.zig");
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const ChatMessage = providers.ChatMessage;
const ChatResponse = providers.ChatResponse;
const ContentPart = providers.ContentPart;
const ToolSpec = providers.ToolSpec;
const redaction = @import("../redaction.zig");
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
const CommandRiskLevel = @import("../security/root.zig").CommandRiskLevel;
const util = @import("../util.zig");
const verbose_mod = @import("../verbose.zig");
const cost_mod = @import("../cost.zig");

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
const MAX_MID_TURN_INJECTION_FOLLOWUPS: u32 = 8;

/// Maximum non-system messages before trimming.
const DEFAULT_MAX_HISTORY: u32 = 50;

pub fn estimate_text_tokens(text: []const u8) u32 {
    return @intCast((text.len + 3) / 4);
}

// ─── Progress hints ──────────────────────────────────────────────────────────

/// Progress hint emitted during a turn. For tool-call starts, text is the tool name.
pub const ProgressHint = struct {
    text: []const u8,
};

/// Callback invoked for each progress hint. Same lifetime rules as StreamCallback.
pub const ProgressCallback = *const fn (ctx: *anyopaque, hint: ProgressHint) void;

/// Sink wrapping a ProgressCallback + context pointer.
pub const ProgressSink = struct {
    callback: ProgressCallback,
    ctx: *anyopaque,

    pub fn emit(self: ProgressSink, hint: ProgressHint) void {
        self.callback(self.ctx, hint);
    }
};

/// Structured approval request emitted by the agent runtime.
/// All slices are borrowed and valid only for the callback invocation.
pub const ApprovalRequest = struct {
    request_id: []const u8,
    action: []const u8,
    reason: []const u8,
};

/// Returns true only when the request was accepted by an interactive channel.
pub const ApprovalCallback = *const fn (ctx: *anyopaque, request: ApprovalRequest) bool;

pub const ApprovalSink = struct {
    callback: ApprovalCallback,
    ctx: *anyopaque,

    pub fn emit(self: ApprovalSink, request: ApprovalRequest) bool {
        return self.callback(self.ctx, request);
    }
};

/// Callback invoked at each tool-loop boundary to drain a pending mid-turn injection.
/// Returns an owned slice allocated with the provided allocator, or null if empty.
pub const DrainCallback = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!?[]u8;

/// Called once before the first tool batch in a turn can dispatch. Session
/// runtimes use this as a durable write-ahead barrier; returning an error must
/// abort the batch before any external side effect starts.
pub const BeforeToolDispatchCallback = *const fn (ctx: *anyopaque) anyerror!void;

// ── Structured approval (approval_request / approval_response) ────────────

const APPROVAL_REQUEST_TTL_SECS: i64 = 300;
const APPROVAL_REQUEST_ENTROPY_BYTES: usize = 16;
pub const APPROVAL_REQUEST_ID_LEN: usize = APPROVAL_REQUEST_ENTROPY_BYTES * 2;
const APPROVAL_DENIED_PERSISTENCE_RESULT =
    "The approval-gated tool was denied and was not executed. Do not retry it automatically.";

const CachedToolCallResult = struct {
    success: bool,
    output: []const u8,
    output_owned: bool,
};

const ToolCallResultCache = std.AutoHashMapUnmanaged(u64, CachedToolCallResult);

fn deinitToolCallResultCache(
    allocator: std.mem.Allocator,
    result_cache: *ToolCallResultCache,
) void {
    var it = result_cache.valueIterator();
    while (it.next()) |cached_result| {
        if (cached_result.output_owned and cached_result.output.len > 0) allocator.free(cached_result.output);
    }
    result_cache.deinit(allocator);
    result_cache.* = .empty;
}

fn dupeOptionalApprovalOriginField(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) !?[]const u8 {
    return if (value) |field| try allocator.dupe(u8, field) else null;
}

fn optionalApprovalOriginFieldEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |a_value| {
        const b_value = b orelse return false;
        return std.mem.eql(u8, a_value, b_value);
    }
    return b == null;
}

/// Immutable authenticated route that requested an approval. Session routing
/// may intentionally collapse multiple DMs into one Agent, so the one-shot ID
/// alone is not enough to decide which channel principal may consume it.
const ApprovalOrigin = struct {
    channel: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
    delivery_chat_id: ?[]const u8 = null,
    sender_id: ?[]const u8 = null,
    peer_id: ?[]const u8 = null,
    group_id: ?[]const u8 = null,
    is_group: ?bool = null,

    fn init(
        allocator: std.mem.Allocator,
        conversation_context: ?prompt.ConversationContext,
    ) !ApprovalOrigin {
        const ctx = conversation_context orelse return .{};
        const channel = try dupeOptionalApprovalOriginField(allocator, ctx.channel);
        errdefer if (channel) |value| allocator.free(value);
        const account_id = try dupeOptionalApprovalOriginField(allocator, ctx.account_id);
        errdefer if (account_id) |value| allocator.free(value);
        const delivery_chat_id = try dupeOptionalApprovalOriginField(allocator, ctx.delivery_chat_id);
        errdefer if (delivery_chat_id) |value| allocator.free(value);
        const sender_id = try dupeOptionalApprovalOriginField(allocator, ctx.sender_id);
        errdefer if (sender_id) |value| allocator.free(value);
        const peer_id = try dupeOptionalApprovalOriginField(allocator, ctx.peer_id);
        errdefer if (peer_id) |value| allocator.free(value);
        const group_id = try dupeOptionalApprovalOriginField(allocator, ctx.group_id);
        errdefer if (group_id) |value| allocator.free(value);

        return .{
            .channel = channel,
            .account_id = account_id,
            .delivery_chat_id = delivery_chat_id,
            .sender_id = sender_id,
            .peer_id = peer_id,
            .group_id = group_id,
            .is_group = ctx.is_group,
        };
    }

    fn deinit(self: *ApprovalOrigin, allocator: std.mem.Allocator) void {
        if (self.channel) |value| allocator.free(value);
        if (self.account_id) |value| allocator.free(value);
        if (self.delivery_chat_id) |value| allocator.free(value);
        if (self.sender_id) |value| allocator.free(value);
        if (self.peer_id) |value| allocator.free(value);
        if (self.group_id) |value| allocator.free(value);
        self.* = .{};
    }

    fn matches(self: ApprovalOrigin, conversation_context: ?prompt.ConversationContext) bool {
        const ctx = conversation_context orelse return self.channel == null and
            self.account_id == null and
            self.delivery_chat_id == null and
            self.sender_id == null and
            self.peer_id == null and
            self.group_id == null and
            self.is_group == null;
        return optionalApprovalOriginFieldEql(self.channel, ctx.channel) and
            optionalApprovalOriginFieldEql(self.account_id, ctx.account_id) and
            optionalApprovalOriginFieldEql(self.delivery_chat_id, ctx.delivery_chat_id) and
            optionalApprovalOriginFieldEql(self.sender_id, ctx.sender_id) and
            optionalApprovalOriginFieldEql(self.peer_id, ctx.peer_id) and
            optionalApprovalOriginFieldEql(self.group_id, ctx.group_id) and
            self.is_group == ctx.is_group;
    }
};

/// Pending tool-execution approval, set when a tool raises ApprovalRequired.
/// Stored across turns; resolved only through an authenticated approval_response control event.
pub const PendingApproval = struct {
    request_id: [APPROVAL_REQUEST_ID_LEN]u8,
    tool_name: []const u8,
    tool_call_id: ?[]const u8,
    action: []const u8,
    risk_level: CommandRiskLevel,
    args_json: []const u8,
    timestamp: i64,
    origin: ApprovalOrigin = .{},
    continuation_user_message: ?[]const u8 = null,
    continuation_model_name: ?[]const u8 = null,
    persistence_user_message: ?[]const u8 = null,
    /// Assistant entry for the provider batch that opened this request.
    history_rollback_index: ?usize = null,
    /// Same assistant response with the pending call and unexecuted tail
    /// removed. Cancellation swaps this in while preserving completed calls
    /// and their results from earlier in the batch.
    cancel_assistant_content: ?[]const u8 = null,
    /// Dedup results from calls completed before the approval boundary. This is
    /// moved into the continuation so one logical tool loop stays exactly-once.
    replay_results: ToolCallResultCache = .empty,

    fn init(
        allocator: std.mem.Allocator,
        request_id: [APPROVAL_REQUEST_ID_LEN]u8,
        tool_name: []const u8,
        tool_call_id: ?[]const u8,
        action: []const u8,
        risk_level: CommandRiskLevel,
        args_json: []const u8,
        conversation_context: ?prompt.ConversationContext,
        continuation_user_message: ?[]const u8,
        continuation_model_name: ?[]const u8,
        persistence_user_message: ?[]const u8,
    ) !PendingApproval {
        const owned_name = try allocator.dupe(u8, tool_name);
        errdefer allocator.free(owned_name);
        const owned_id = if (tool_call_id) |id| try allocator.dupe(u8, id) else null;
        errdefer if (owned_id) |id| allocator.free(id);
        const owned_action = try allocator.dupe(u8, action);
        errdefer allocator.free(owned_action);
        const owned_args = try allocator.dupe(u8, args_json);
        errdefer allocator.free(owned_args);
        const origin = try ApprovalOrigin.init(allocator, conversation_context);
        errdefer {
            var owned_origin = origin;
            owned_origin.deinit(allocator);
        }
        const owned_continuation_user_message = try dupeOptionalApprovalOriginField(allocator, continuation_user_message);
        errdefer if (owned_continuation_user_message) |value| allocator.free(value);
        const owned_continuation_model_name = try dupeOptionalApprovalOriginField(allocator, continuation_model_name);
        errdefer if (owned_continuation_model_name) |value| allocator.free(value);
        const owned_persistence_user_message = try dupeOptionalApprovalOriginField(allocator, persistence_user_message);
        errdefer if (owned_persistence_user_message) |value| allocator.free(value);

        return .{
            .request_id = request_id,
            .tool_name = owned_name,
            .tool_call_id = owned_id,
            .action = owned_action,
            .risk_level = risk_level,
            .args_json = owned_args,
            .timestamp = std_compat.time.timestamp(),
            .origin = origin,
            .continuation_user_message = owned_continuation_user_message,
            .continuation_model_name = owned_continuation_model_name,
            .persistence_user_message = owned_persistence_user_message,
        };
    }

    pub fn deinit(self: *PendingApproval, allocator: std.mem.Allocator) void {
        allocator.free(self.tool_name);
        if (self.tool_call_id) |id| allocator.free(id);
        allocator.free(self.action);
        allocator.free(self.args_json);
        self.origin.deinit(allocator);
        if (self.continuation_user_message) |value| allocator.free(value);
        if (self.continuation_model_name) |value| allocator.free(value);
        if (self.persistence_user_message) |value| allocator.free(value);
        if (self.cancel_assistant_content) |value| allocator.free(value);
        deinitToolCallResultCache(allocator, &self.replay_results);
    }
};

pub const ApprovalContinuation = struct {
    tool_result_message: []u8,
    /// Safe borrowed projection for immediate durable persistence. It points
    /// either into Agent history or at a static denial marker and must not be
    /// freed by ApprovalContinuation.
    persistence_tool_result_message: []const u8,
    user_message: ?[]const u8,
    model_name: ?[]const u8,
    persistence_user_message: ?[]const u8,
    replay_results: ToolCallResultCache = .empty,

    fn deinit(self: *ApprovalContinuation, allocator: std.mem.Allocator) void {
        allocator.free(self.tool_result_message);
        if (self.user_message) |value| allocator.free(value);
        if (self.model_name) |value| allocator.free(value);
        if (self.persistence_user_message) |value| allocator.free(value);
        deinitToolCallResultCache(allocator, &self.replay_results);
    }
};

pub const ApprovalResolution = union(enum) {
    no_pending,
    request_mismatch,
    expired,
    resolved: ApprovalContinuation,

    pub fn deinit(self: *ApprovalResolution, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .resolved => |*continuation| continuation.deinit(allocator),
            else => {},
        }
        self.* = .no_pending;
    }
};

const PreparedApprovalBoundary = struct {
    assistant_content: ?[]const u8,
    cancel_assistant_content: ?[]const u8,
    completed_results: ?[]const u8,
    failure_results: ?[]const u8,

    fn deinit(self: *PreparedApprovalBoundary, allocator: std.mem.Allocator) void {
        if (self.assistant_content) |content| allocator.free(content);
        if (self.cancel_assistant_content) |content| allocator.free(content);
        if (self.completed_results) |content| allocator.free(content);
        if (self.failure_results) |content| allocator.free(content);
        self.* = .{
            .assistant_content = null,
            .cancel_assistant_content = null,
            .completed_results = null,
            .failure_results = null,
        };
    }
};

const PreparedInterruptedPrefix = struct {
    assistant_content: ?[]const u8,
    completed_results: ?[]const u8,

    fn deinit(self: *PreparedInterruptedPrefix, allocator: std.mem.Allocator) void {
        if (self.assistant_content) |content| allocator.free(content);
        if (self.completed_results) |content| allocator.free(content);
        self.* = .{
            .assistant_content = null,
            .completed_results = null,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Agent
// ═══════════════════════════════════════════════════════════════════════════

pub const Agent = struct {
    const TextPreview = struct {
        slice: []const u8,
        truncated: bool,
    };

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

    pub const QueueMode = config_types.QueueMode;

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
    /// Optional per-conversation Redactor for PII scrubbing before outbound
    /// provider calls. Heap-allocated when `enable_pii_redaction` is true on
    /// the active agent profile (default true). State (counters, maps) lives
    /// on `self.allocator`; redacted slices for each turn are allocated on the
    /// per-turn arena.
    redactor: ?*redaction.Redactor = null,
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
    profile_system_prompt_owned: bool = false,
    model_routes: []const config_types.ModelRouteConfig = &.{},
    model_pinned_by_user: bool = false,
    last_route_trace: ?[]u8 = null,
    degraded_routes: std.ArrayListUnmanaged(DegradedRoute) = .empty,
    configured_providers: []const config_types.ProviderEntry = &.{},
    fallback_providers: []const []const u8 = &.{},
    model_fallbacks: []const config_types.ModelFallbackEntry = &.{},
    temperature: f64,
    workspace_dir: []const u8,
    workspace_dir_owned: bool = false,
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
    compact_context: bool = true,
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
    default_queue_mode: QueueMode = .off,
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
    pending_exec_origin: ApprovalOrigin = .{},
    session_ttl_secs: ?u64 = null,
    focus_target: ?[]const u8 = null,
    focus_target_owned: bool = false,
    dock_target: ?[]const u8 = null,
    dock_target_owned: bool = false,
    activation_mode: ActivationMode = .mention,
    send_mode: SendMode = .inherit,
    last_turn_usage: providers.TokenUsage = .{},
    last_system_prompt_bytes: usize = 0,
    last_history_bytes: usize = 0,
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

    /// Tool customization config (system_prompt overrides, triggers, enabled flags).
    tools_config: config_types.ToolsConfig = .{},

    /// Optional security policy for autonomy checks and rate limiting.
    policy: ?*const SecurityPolicy = null,

    /// Pending tool-execution approval. Set when a tool raises ApprovalRequired.
    /// Stored across turns; resolved only through a typed control path.
    pending_approval: ?PendingApproval = null,

    /// Optional first-class approval request callback. It is wired only for
    /// channels that can deliver authenticated structured approval events.
    approval_callback: ?ApprovalCallback = null,
    approval_ctx: ?*anyopaque = null,
    /// Borrowed only while a turn is executing. PendingApproval duplicates
    /// these values so an authenticated continuation can preserve routing and
    /// dynamic tool selection after the original stack unwinds.
    approval_turn_user_message: ?[]const u8 = null,
    approval_turn_model_name: ?[]const u8 = null,
    approval_turn_persistence_message: ?[]const u8 = null,

    /// Optional streaming callback. When set, turn() uses streamChat() for streaming providers.
    stream_callback: ?providers.StreamCallback = null,
    /// Context pointer passed to stream_callback.
    stream_ctx: ?*anyopaque = null,
    /// Optional progress hint callback. When set, called on tool_call_start events.
    progress_callback: ?ProgressCallback = null,
    /// Context pointer passed to progress_callback.
    progress_ctx: ?*anyopaque = null,
    /// Optional mid-turn injection drain. When set, called at each tool-loop boundary
    /// to pull a pending user message and fold it into the active turn.
    /// Returns an owned slice (allocated with the agent allocator) or null if empty.
    drain_injection_cb: ?DrainCallback = null,
    /// Context pointer passed to drain_injection_cb.
    drain_injection_ctx: ?*anyopaque = null,
    /// Optional durable barrier invoked before this turn's first tool batch.
    before_tool_dispatch_cb: ?BeforeToolDispatchCallback = null,
    /// Context pointer passed to before_tool_dispatch_cb.
    before_tool_dispatch_ctx: ?*anyopaque = null,
    /// Optional callback invoked for each LLM response usage record.
    usage_record_callback: ?UsageRecordCallback = null,
    /// Context pointer passed to usage_record_callback.
    usage_record_ctx: ?*anyopaque = null,
    /// Cross-thread interrupt flag used to stop in-flight tool loops.
    interrupt_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Tracks currently running tool and effective interruptions for user-facing reporting.
    tool_state_mu: std_compat.sync.Mutex = .{},
    active_tool_name: ?[]u8 = null,
    interrupted_tools: std.ArrayListUnmanaged([]u8) = .empty,
    /// Conversation context for the current turn.
    conversation_context: ?prompt.ConversationContext = null,
    /// Session-scoped active skill applied to subsequent user messages until cleared.
    active_skill_name: ?[]const u8 = null,
    active_skill_name_owned: bool = false,
    active_skill_description: ?[]const u8 = null,
    active_skill_description_owned: bool = false,
    active_skill_instructions: ?[]const u8 = null,
    active_skill_instructions_owned: bool = false,
    active_skill_path: ?[]const u8 = null,
    active_skill_path_owned: bool = false,
    active_skill_interactive: bool = false,

    /// Conversation history — owned, growable list.
    history: std.ArrayListUnmanaged(OwnedMessage) = .empty,

    /// Total tokens used across all turns.
    total_tokens: u64 = 0,

    /// Total cost in USD across all turns.
    total_cost_usd: f64 = 0,

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

    fn redactOwnedForHistory(self: *Agent, owned: []const u8) ![]const u8 {
        const r = self.redactor orelse return owned;
        const redacted = r.redact(self.allocator, owned) catch |err| {
            self.allocator.free(owned);
            return err;
        };
        self.allocator.free(owned);
        return redacted;
    }

    fn dupeForHistory(self: *Agent, content: []const u8) ![]const u8 {
        if (self.redactor) |r| return r.redact(self.allocator, content);
        return self.allocator.dupe(u8, content);
    }

    fn containsRedactionPlaceholder(text: []const u8) bool {
        const markers = [_][]const u8{ "[EMAIL_", "[PHONE_", "[CARD_", "[ID_", "[TOKEN_" };
        for (markers) |marker| {
            if (std.mem.indexOf(u8, text, marker) != null) return true;
        }
        return false;
    }

    fn historyContainsRedactionPlaceholder(self: *const Agent) bool {
        for (self.history.items) |msg| {
            if (containsRedactionPlaceholder(msg.content)) return true;
        }
        return false;
    }

    /// Response cache keys are built from provider-safe text, not raw PII.
    /// Once governance placeholders are present, different originals can collapse
    /// to the same prompt shape after a reset, so cache reuse is not semantics-safe.
    fn responseCacheSafeForTurn(self: *const Agent, safe_user_message: []const u8) bool {
        if (self.redactor == null) return true;
        if (containsRedactionPlaceholder(safe_user_message)) return false;
        return !self.historyContainsRedactionPlaceholder();
    }

    fn drainPendingInjection(self: *Agent) !?[]u8 {
        // A tool can create either approval kind after the session-level turn
        // routing decision. Keep queued user text intact until that approval
        // is resolved instead of absorbing it into the paused tool turn.
        if (self.pending_approval != null or self.pending_exec_command != null) return null;
        if (self.drain_injection_cb) |drain_cb| {
            if (self.drain_injection_ctx) |drain_ctx| {
                return try drain_cb(drain_ctx, self.allocator);
            }
        }
        return null;
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
        // Ownership transfers to Agent only after all initialization succeeds.
        errdefer allocator.free(specs);
        for (tools, 0..) |t, i| {
            specs[i] = .{
                .name = t.name(),
                .description = t.description(),
                .parameters_json = t.parametersJson(),
            };
        }

        var effective_workspace_dir = cfg.workspace_dir;
        var workspace_dir_owned = false;
        // Free a resolved workspace override on any later initialization error.
        errdefer if (workspace_dir_owned) allocator.free(effective_workspace_dir);
        if (profile) |agent_profile| {
            if (agent_profile.workspace_path) |workspace_path| {
                effective_workspace_dir = try cfg.resolveAgentWorkspacePath(allocator, workspace_path);
                workspace_dir_owned = true;
                Config.scaffoldAgentWorkspace(allocator, effective_workspace_dir) catch {};
            }
        }

        const bootstrap_provider: ?bootstrap_mod.BootstrapProvider = bootstrap_mod.createProvider(
            allocator,
            cfg.memory.backend,
            mem,
            effective_workspace_dir,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
        errdefer if (bootstrap_provider) |bp| bp.deinit();

        // Per-conversation PII redactor (default-on, can be disabled per agent profile).
        const redactor_ptr: ?*redaction.Redactor = blk: {
            const enabled = if (profile) |p| p.enable_pii_redaction else cfg.agent.enable_pii_redaction;
            if (!enabled) break :blk null;
            const r = try allocator.create(redaction.Redactor);
            errdefer allocator.destroy(r);
            // record_originals=true lets user-facing display paths restore
            // placeholders while provider/tool/log/persistence boundaries stay redacted.
            r.* = redaction.Redactor.init(allocator, .{ .record_originals = true });
            break :blk r;
        };
        errdefer if (redactor_ptr) |r| {
            r.deinit();
            allocator.destroy(r);
        };

        return .{
            .allocator = allocator,
            .provider = provider_i,
            .tools = tools,
            .tool_specs = specs,
            .mem = mem,
            .bootstrap = bootstrap_provider,
            .redactor = redactor_ptr,
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
            .workspace_dir = effective_workspace_dir,
            .workspace_dir_owned = workspace_dir_owned,
            .allowed_paths = cfg.autonomy.allowed_paths,
            .multimodal_unrestricted = cfg.autonomy.level == .yolo,
            .vision_disabled_models = cfg.agent.vision_disabled_models,
            .auto_disable_vision_on_error = cfg.agent.auto_disable_vision_on_error,
            .max_tool_iterations = cfg.agent.max_tool_iterations,
            .max_history_messages = cfg.agent.max_history_messages,
            .auto_save = cfg.memory.auto_save,
            .compact_context = cfg.agent.compact_context,
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
            .default_queue_mode = cfg.agent.default_queue_mode,
            .queue_mode = cfg.agent.default_queue_mode,
            .tools_config = cfg.tools,
            .tool_filter_groups = cfg.agent.tool_filter_groups,
            .default_exec_security = resolved_exec_security,
            .exec_security = resolved_exec_security,
            .default_exec_ask = resolved_exec_ask,
            .exec_ask = resolved_exec_ask,
            .history = .empty,
            .usage_mode = if (cfg.cost.enabled) .full else .off,
            .total_tokens = 0,
            .has_system_prompt = false,
            .last_turn_compacted = false,
        };
    }

    pub fn deinit(self: *Agent) void {
        if (self.bootstrap) |bp| bp.deinit();
        if (self.redactor) |r| {
            r.deinit();
            self.allocator.destroy(r);
        }
        if (self.model_name_owned) self.allocator.free(self.model_name);
        if (self.default_provider_owned) self.allocator.free(self.default_provider);
        if (self.profile_system_prompt_owned and self.profile_system_prompt != null) self.allocator.free(self.profile_system_prompt.?);
        if (self.workspace_dir_owned) self.allocator.free(self.workspace_dir);
        if (self.system_prompt_model_name) |model| self.allocator.free(model);
        if (self.last_route_trace) |trace| self.allocator.free(trace);
        if (self.exec_node_id_owned and self.exec_node_id != null) self.allocator.free(self.exec_node_id.?);
        if (self.tts_provider_owned and self.tts_provider != null) self.allocator.free(self.tts_provider.?);
        if (self.pending_exec_command_owned and self.pending_exec_command != null) self.allocator.free(self.pending_exec_command.?);
        self.pending_exec_origin.deinit(self.allocator);
        if (self.focus_target_owned and self.focus_target != null) self.allocator.free(self.focus_target.?);
        if (self.dock_target_owned and self.dock_target != null) self.allocator.free(self.dock_target.?);
        if (self.active_skill_name_owned and self.active_skill_name != null) self.allocator.free(self.active_skill_name.?);
        if (self.active_skill_description_owned and self.active_skill_description != null) self.allocator.free(self.active_skill_description.?);
        if (self.active_skill_instructions_owned and self.active_skill_instructions != null) self.allocator.free(self.active_skill_instructions.?);
        if (self.active_skill_path_owned and self.active_skill_path != null) self.allocator.free(self.active_skill_path.?);
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
        if (self.pending_approval) |*pa| pa.deinit(self.allocator);
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
        const owned = try self.allocator.dupe(u8, name);
        if (self.active_tool_name) |old| self.allocator.free(old);
        self.active_tool_name = owned;
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
        try self.interrupted_tools.ensureUnusedCapacity(self.allocator, 1);
        const owned = try self.allocator.dupe(u8, name);
        self.interrupted_tools.appendAssumeCapacity(owned);
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

    fn discardInterruptedTools(self: *Agent) void {
        self.tool_state_mu.lock();
        defer self.tool_state_mu.unlock();
        for (self.interrupted_tools.items) |name| self.allocator.free(name);
        self.interrupted_tools.clearRetainingCapacity();
    }

    fn generateApprovalRequestId() [APPROVAL_REQUEST_ID_LEN]u8 {
        var entropy: [APPROVAL_REQUEST_ENTROPY_BYTES]u8 = undefined;
        std_compat.crypto.random.bytes(&entropy);
        return std.fmt.bytesToHex(entropy, .lower);
    }

    fn approvalExpired(pending: PendingApproval, now: i64) bool {
        // Wall-clock rollback must fail closed rather than extending a bearer
        // approval beyond its advertised lifetime.
        if (now < pending.timestamp) return true;
        return now - pending.timestamp >= APPROVAL_REQUEST_TTL_SECS;
    }

    fn truncateHistoryFrom(self: *Agent, index: usize) void {
        if (index >= self.history.items.len) return;
        for (self.history.items[index..]) |*message| message.deinit(self.allocator);
        self.history.shrinkRetainingCapacity(index);
    }

    fn discardPendingApproval(self: *Agent) void {
        if (self.pending_approval) |*pending| pending.deinit(self.allocator);
        self.pending_approval = null;
    }

    pub fn clearPendingApproval(self: *Agent) void {
        var pending = self.pending_approval orelse return;
        self.pending_approval = null;
        if (pending.history_rollback_index) |index| {
            if (index < self.history.items.len) {
                if (pending.cancel_assistant_content) |content| {
                    self.history.items[index].deinit(self.allocator);
                    self.history.items[index] = .{ .role = .assistant, .content = content };
                    pending.cancel_assistant_content = null;
                } else {
                    self.truncateHistoryFrom(index);
                }
            }
        }
        pending.deinit(self.allocator);
    }

    pub fn pendingApprovalOriginMatchesCurrent(self: *const Agent) bool {
        const pending = self.pending_approval orelse return false;
        return pending.origin.matches(self.conversation_context);
    }

    /// Read-only preflight used by SessionManager before writing a durable
    /// execution-intent receipt. resolveApproval repeats every check at the
    /// actual one-shot commit point.
    pub fn pendingApprovalResponseMatchesCurrent(
        self: *const Agent,
        request_id: []const u8,
    ) bool {
        const pending = self.pending_approval orelse return false;
        if (approvalExpired(pending, std_compat.time.timestamp())) return false;
        if (!pending.origin.matches(self.conversation_context)) return false;
        if (request_id.len != APPROVAL_REQUEST_ID_LEN) return false;
        const supplied: [APPROVAL_REQUEST_ID_LEN]u8 = request_id[0..APPROVAL_REQUEST_ID_LEN].*;
        return std.crypto.timing_safe.eql(
            [APPROVAL_REQUEST_ID_LEN]u8,
            pending.request_id,
            supplied,
        );
    }

    /// Drop an expired approval before ordinary message routing applies the
    /// pending-turn gate. Without this eager check, a stale request could keep
    /// the session blocked forever because only approval responses reached the
    /// TTL validation path.
    pub fn clearExpiredPendingApproval(self: *Agent) bool {
        const pending = self.pending_approval orelse return false;
        if (!approvalExpired(pending, std_compat.time.timestamp())) return false;
        self.clearPendingApproval();
        return true;
    }

    pub fn capturePendingExecOrigin(self: *Agent) !void {
        const origin = try ApprovalOrigin.init(self.allocator, self.conversation_context);
        self.pending_exec_origin.deinit(self.allocator);
        self.pending_exec_origin = origin;
    }

    pub fn clearPendingExecOrigin(self: *Agent) void {
        self.pending_exec_origin.deinit(self.allocator);
    }

    pub fn pendingExecOriginMatchesCurrent(self: *const Agent) bool {
        return self.pending_exec_origin.matches(self.conversation_context);
    }

    fn emitApprovalRequest(self: *Agent, pending: *const PendingApproval) bool {
        const callback = self.approval_callback orelse return false;
        const ctx = self.approval_ctx orelse return false;

        var reason_buf: [128]u8 = undefined;
        const reason = std.fmt.bufPrint(
            &reason_buf,
            "Policy requires approval for this {s}-risk tool execution.",
            .{pending.risk_level.toString()},
        ) catch "Policy requires approval for this tool execution.";

        return callback(ctx, .{
            .request_id = &pending.request_id,
            .action = pending.action,
            .reason = reason,
        });
    }

    fn setPendingToolApproval(
        self: *Agent,
        tool_name: []const u8,
        tool_call_id: ?[]const u8,
        action: []const u8,
        risk_level: CommandRiskLevel,
        args_json: []const u8,
    ) !void {
        if (self.pending_approval) |pending| {
            if (!approvalExpired(pending, std_compat.time.timestamp())) {
                return error.ApprovalAlreadyPending;
            }
            self.clearPendingApproval();
        }
        if (self.approval_callback == null or self.approval_ctx == null) {
            return error.ApprovalUnavailable;
        }

        self.pending_approval = try PendingApproval.init(
            self.allocator,
            generateApprovalRequestId(),
            tool_name,
            tool_call_id,
            action,
            risk_level,
            args_json,
            self.conversation_context,
            self.approval_turn_user_message,
            self.approval_turn_model_name,
            self.approval_turn_persistence_message,
        );

        // Delivery is deliberately deferred until the outer tool loop has
        // committed a canonical, tail-truncated history state. This prevents a
        // usable request id from escaping before every fallible allocation is
        // complete.
    }

    /// Resolve a typed, authenticated approval response. This is intentionally
    /// not reachable from ordinary user-message text; SessionManager calls it
    /// through the dedicated control path.
    pub fn resolveApproval(
        self: *Agent,
        request_id: []const u8,
        approved: bool,
        reason: ?[]const u8,
    ) !ApprovalResolution {
        const pending = self.pending_approval orelse return .no_pending;
        if (approvalExpired(pending, std_compat.time.timestamp())) {
            self.clearPendingApproval();
            return .expired;
        }
        const origin_matches = pending.origin.matches(self.conversation_context);
        if (request_id.len != pending.request_id.len) return .request_mismatch;
        const supplied_request_id: [APPROVAL_REQUEST_ID_LEN]u8 = request_id[0..APPROVAL_REQUEST_ID_LEN].*;
        const request_matches = std.crypto.timing_safe.eql(
            [APPROVAL_REQUEST_ID_LEN]u8,
            pending.request_id,
            supplied_request_id,
        );
        if (!request_matches or !origin_matches) {
            return .request_mismatch;
        }
        const approval_history_index = pending.history_rollback_index orelse return error.InvalidApprovalState;
        if (approval_history_index >= self.history.items.len or
            self.history.items[approval_history_index].role != .assistant)
        {
            return error.InvalidApprovalState;
        }

        if (!approved) {
            const message = if (reason) |why|
                try std.fmt.allocPrint(
                    self.allocator,
                    "Tool execution '{s}' was explicitly denied by the user. Reason: {s}. Do not retry it unless the user asks again. Any later calls from the paused batch were not executed and must be reconsidered.",
                    .{ pending.action, why },
                )
            else
                try std.fmt.allocPrint(
                    self.allocator,
                    "Tool execution '{s}' was explicitly denied by the user. Do not retry it unless the user asks again. Any later calls from the paused batch were not executed and must be reconsidered.",
                    .{pending.action},
                );
            errdefer self.allocator.free(message);
            var history_message: ?[]const u8 = if (self.redactor) |redactor|
                try redactor.redact(self.allocator, message)
            else
                try self.allocator.dupe(u8, message);
            errdefer if (history_message) |content| self.allocator.free(content);
            const denied_call = ParsedToolCall{
                .name = pending.tool_name,
                .arguments_json = pending.args_json,
                .tool_call_id = pending.tool_call_id,
            };
            // Finish every fallible allocation before consuming the one-shot
            // request. If this fails, the caller can safely retry the same
            // denial and the paused history remains gated.
            try self.history.ensureUnusedCapacity(self.allocator, 1);
            try rememberApprovalToolCallResultExact(self.allocator, &self.pending_approval.?.replay_results, denied_call, .{
                .name = pending.tool_name,
                .output = message,
                .success = false,
                .tool_call_id = pending.tool_call_id,
            });
            // The replay insertion above is the commit point. Everything from
            // here through ownership transfer is allocation-free.
            self.history.appendAssumeCapacity(.{ .role = .user, .content = history_message.? });
            history_message = null;
            var owned = self.pending_approval.?;
            self.pending_approval = null;
            defer owned.deinit(self.allocator);
            const continuation_user_message = owned.continuation_user_message;
            owned.continuation_user_message = null;
            const continuation_model_name = owned.continuation_model_name;
            owned.continuation_model_name = null;
            const persistence_user_message = owned.persistence_user_message;
            owned.persistence_user_message = null;
            const replay_results = owned.replay_results;
            owned.replay_results = .empty;
            return .{ .resolved = .{
                .tool_result_message = message,
                .persistence_tool_result_message = APPROVAL_DENIED_PERSISTENCE_RESULT,
                .user_message = continuation_user_message,
                .model_name = continuation_model_name,
                .persistence_user_message = persistence_user_message,
                .replay_results = replay_results,
            } };
        }

        const approved_call = ParsedToolCall{
            .name = pending.tool_name,
            .arguments_json = pending.args_json,
            .tool_call_id = pending.tool_call_id,
        };
        const fallback_message = try self.allocator.dupe(
            u8,
            "The approved tool invocation was attempted, but its result could not be fully recorded because of an internal allocation failure. Treat this approval as consumed and do not repeat the action automatically. Any later calls from the paused batch were not executed and must be reconsidered.",
        );
        errdefer self.allocator.free(fallback_message);
        var fallback_history: ?[]u8 = try self.allocator.dupe(
            u8,
            "The approved tool invocation was attempted, but its result could not be fully recorded because of an internal allocation failure. Treat this approval as consumed and do not repeat the action automatically.",
        );
        errdefer if (fallback_history) |content| self.allocator.free(content);
        try self.history.ensureUnusedCapacity(self.allocator, 1);
        // Reserve an exact-once replay entry before executing the side effect.
        // Post-execution formatting can then degrade to this owned fallback
        // without either retrying the action or leaving a dangling tool call.
        try rememberApprovalToolCallResultExact(
            self.allocator,
            &self.pending_approval.?.replay_results,
            approved_call,
            .{
                .name = pending.tool_name,
                .output = fallback_message,
                .success = false,
                .tool_call_id = pending.tool_call_id,
            },
        );
        const message = self.runApprovedTool(&self.pending_approval.?, fallback_message);
        // No propagated errors are allowed after the approved side effect. A
        // rich history copy is best effort; the separately owned safe fallback
        // closes the assistant tool call under OOM.
        const rich_history = self.allocator.dupe(u8, message) catch null;
        const history_content = rich_history orelse fallback_history.?;
        if (rich_history != null) self.allocator.free(fallback_history.?);
        fallback_history = null;
        self.history.appendAssumeCapacity(.{ .role = .user, .content = history_content });
        var owned = self.pending_approval.?;
        self.pending_approval = null;
        defer owned.deinit(self.allocator);
        const continuation_user_message = owned.continuation_user_message;
        owned.continuation_user_message = null;
        const continuation_model_name = owned.continuation_model_name;
        owned.continuation_model_name = null;
        const persistence_user_message = owned.persistence_user_message;
        owned.persistence_user_message = null;
        const replay_results = owned.replay_results;
        owned.replay_results = .empty;
        return .{ .resolved = .{
            .tool_result_message = message,
            .persistence_tool_result_message = history_content,
            .user_message = continuation_user_message,
            .model_name = continuation_model_name,
            .persistence_user_message = persistence_user_message,
            .replay_results = replay_results,
        } };
    }

    /// Re-execute an approved invocation through the same dispatcher and
    /// redaction path as a normal tool call. The approval grant removes only
    /// the matching policy approval gate.
    fn runApprovedTool(self: *Agent, pending: *PendingApproval, fallback_message: []u8) []u8 {
        var arena_impl = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_impl.deinit();
        const arena = arena_impl.allocator();

        const call = ParsedToolCall{
            .name = pending.tool_name,
            .arguments_json = pending.args_json,
            .tool_call_id = pending.tool_call_id,
        };
        const start_event = ObserverEvent{ .tool_call_start = .{ .tool = pending.tool_name } };
        self.observer.recordEvent(&start_event);
        if (self.progress_callback) |cb| {
            if (self.progress_ctx) |ctx| cb(ctx, .{ .text = pending.tool_name });
        }
        const started_at = std_compat.time.milliTimestamp();
        const result = self.executeToolWithOptions(arena, call, .{
            .approved = true,
            .record_action = false,
        });
        updateApprovalToolCallResult(self.allocator, &pending.replay_results, call, result);
        const duration_ms: u64 = @intCast(@max(0, std_compat.time.milliTimestamp() - started_at));

        const event = ObserverEvent{ .tool_call = .{
            .tool = pending.tool_name,
            .duration_ms = duration_ms,
            .success = result.success,
            .args = null,
            .detail = null,
        } };
        self.observer.recordEvent(&event);

        const formatted = dispatcher.formatToolResults(arena, &.{result}) catch return fallback_message;
        const scrubbed = providers.scrubToolOutput(arena, formatted) catch return fallback_message;
        const safe_output = if (self.redactor) |redactor|
            redactor.redact(arena, scrubbed) catch return fallback_message
        else
            scrubbed;

        const message = std.fmt.allocPrint(
            self.allocator,
            "The user approved tool '{s}'. The approved execution {s}:\n{s}\n\nReflect on this tool result and continue the original task. Do not repeat the approved action unless needed. Any later calls from the paused batch were not executed and must be reconsidered.",
            .{
                pending.tool_name,
                if (result.success) "succeeded" else "failed",
                safe_output,
            },
        ) catch return fallback_message;
        self.allocator.free(fallback_message);
        return message;
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
        const history_content = try self.dupeForHistory(msg);
        errdefer self.allocator.free(history_content);
        try self.history.ensureUnusedCapacity(self.allocator, 1);
        self.history.appendAssumeCapacity(.{
            .role = .assistant,
            .content = history_content,
        });
        const complete_event = ObserverEvent{ .turn_complete = {} };
        self.observer.recordEvent(&complete_event);
        return msg;
    }

    /// Finish an interrupt observed after a tool side effect without making
    /// another allocation. The caller must reserve history capacity and own
    /// two independent fallback buffers before execution starts.
    fn interruptedToolBatchReply(
        self: *Agent,
        response_fallback: *?[]u8,
        history_fallback: *?[]const u8,
    ) []const u8 {
        self.clearInterruptRequest();
        self.discardInterruptedTools();

        const response = response_fallback.*.?;
        response_fallback.* = null;
        // Inner batch exits reserve this slot. The outer iteration gate can be
        // reached after unrelated history growth, so degrade to returning the
        // owned response while preserving the already-closed tool prefix.
        if (self.history.items.len < self.history.capacity) {
            const history_content = history_fallback.*.?;
            history_fallback.* = null;
            self.history.appendAssumeCapacity(.{
                .role = .assistant,
                .content = history_content,
            });
        }
        const complete_event = ObserverEvent{ .turn_complete = {} };
        self.observer.recordEvent(&complete_event);
        return response;
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

    /// Proactively auto-compact history, honoring `agent.compact_context`.
    /// When the flag is disabled the LLM summarization pass is skipped. Hard
    /// history trimming and emergency `forceCompressHistory` remain separate
    /// safeguards and are intentionally not gated by this flag.
    pub fn maybeAutoCompactHistory(self: *Agent) bool {
        if (!self.compact_context) return false;
        return self.autoCompactHistory() catch false;
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
        }, self.redactor);
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
        // Specific "let me <action-verb>" and "i'll/i will <action-verb>" phrases.
        // Kept as explicit verb+phrase pairs to avoid false-positives on conclusory
        // statements like "I'll note that…", "Let me know if…", or "I will summarize…".
        const ascii_patterns = [_][]const u8{
            // try / retry / attempt
            "i'll try",
            "i will try",
            "let me try",
            "i'll retry",
            "i will retry",
            "let me retry",
            "i'll attempt",
            "i will attempt",
            "let me attempt",
            // check / look / verify
            "i'll look into",
            "i will look into",
            "let me look into",
            "i'll look up",
            "i will look up",
            "let me look up",
            "i'll verify",
            "i will verify",
            "let me verify",
            "i'll check",
            "i will check",
            "let me check",
            // fetch / get / retrieve
            "i'll fetch",
            "i will fetch",
            "let me fetch",
            "i'll get the",
            "i will get the",
            "let me get the",
            "i'll get that",
            "i will get that",
            "let me get that",
            "i'll get this",
            "i will get this",
            "let me get this",
            "i'll get it",
            "i will get it",
            "let me get it",
            "i'll retrieve",
            "i will retrieve",
            "let me retrieve",
            // find / search
            "i'll find",
            "i will find",
            "let me find",
            "i'll search",
            "i will search",
            "let me search",
            "i'll perform a search",
            "i will perform a search",
            "let me perform a search",
            "give me a moment",
            "give me a second",
            "one moment",
            "searching...",
            "checking the web",
            // read / open / load
            "i'll read",
            "i will read",
            "let me read",
            "i'll open",
            "i will open",
            "let me open",
            "i'll load",
            "i will load",
            "let me load",
            // run / execute
            "i'll run the",
            "i will run the",
            "let me run the",
            "i'll run that",
            "i will run that",
            "let me run that",
            "i'll run it",
            "i will run it",
            "let me run it",
            "i'll execute the",
            "i will execute the",
            "let me execute the",
            "i'll execute that",
            "i will execute that",
            "let me execute that",
            "i'll execute it",
            "i will execute it",
            "let me execute it",
            // do / do that
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
            "сейчас поищу",
            "Сейчас поищу",
            "выполню поиск",
            "Выполню поиск",
            "сейчас найду",
            "Сейчас найду",
            "дай мне минуту",
            "Дай мне минуту",
            "дайте мне минуту",
            "Дайте мне минуту",
            "дай мне минутку",
            "Дай мне минутку",
            "дайте мне минутку",
            "Дайте мне минутку",
            "одну минуту",
            "Одну минуту",
            "одну минутку",
            "Одну минутку",
            "подожди",
            "Подожди",
            "подождите",
            "Подождите",
            "один момент",
            "Один момент",
            "посмотрю в интернете",
            "Посмотрю в интернете",
            "проверю информацию",
            "Проверю информацию",
            "сейчас проверю",
            "Сейчас проверю",
            "проведу поиск",
            "Проведу поиск",
            "выполню поиск",
            "Выполню поиск",
            "начинаю поиск",
            "Начинаю поиск",
            "поищу информацию",
            "Поищу информацию",
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

    fn isToolTriggerSeparator(self: *const Agent, c: u8) bool {
        return std.ascii.isWhitespace(c) or std.mem.indexOfScalar(u8, self.tools_config.trigger_punctuation, c) != null;
    }

    fn nextToolTriggerWord(self: *const Agent, text: []const u8, idx: *usize) ?[]const u8 {
        while (idx.* < text.len and self.isToolTriggerSeparator(text[idx.*])) : (idx.* += 1) {}
        if (idx.* >= text.len) return null;

        const start = idx.*;
        while (idx.* < text.len and !self.isToolTriggerSeparator(text[idx.*])) : (idx.* += 1) {}
        return text[start..idx.*];
    }

    fn isToolTriggerModifier(self: *const Agent, word: []const u8) bool {
        for (self.tools_config.trigger_modifiers) |modifier| {
            if (std.ascii.eqlIgnoreCase(word, modifier)) return true;
        }
        return false;
    }

    fn nextUserToolTriggerWord(self: *const Agent, text: []const u8, idx: *usize) ?[]const u8 {
        while (self.nextToolTriggerWord(text, idx)) |word| {
            if (!self.isToolTriggerModifier(word)) return word;
        }
        return null;
    }

    fn normalizedToolTriggerEquals(self: *const Agent, user_message: []const u8, trigger: []const u8) bool {
        var user_idx: usize = 0;
        var trigger_idx: usize = 0;

        while (self.nextToolTriggerWord(trigger, &trigger_idx)) |trigger_word| {
            const user_word = self.nextUserToolTriggerWord(user_message, &user_idx) orelse return false;
            if (!std.ascii.eqlIgnoreCase(user_word, trigger_word)) return false;
        }

        return self.nextUserToolTriggerWord(user_message, &user_idx) == null;
    }

    fn toolTriggerMatchesMessage(self: *const Agent, user_message: []const u8, trigger: []const u8) bool {
        if (containsAsciiIgnoreCase(user_message, trigger)) return true;
        if (self.tools_config.trigger_modifiers.len == 0 and self.tools_config.trigger_punctuation.len == 0) return false;
        return self.normalizedToolTriggerEquals(user_message, trigger);
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
        const now_ms = std_compat.time.milliTimestamp();
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
        const now_ms = std_compat.time.milliTimestamp();

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

    fn execBlockMessageWithOptions(
        self: *Agent,
        args: std.json.ObjectMap,
        approval_granted: bool,
    ) ?[]const u8 {
        return commands.execBlockMessageWithOptions(self, args, approval_granted);
    }

    pub fn formatModelStatus(self: *const Agent) ![]const u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;

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

        const now_ms = std_compat.time.milliTimestamp();
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
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    /// Handle slash commands that don't require LLM.
    /// Returns an owned response string, or null if not a slash command.
    pub fn handleSlashCommand(self: *Agent, message: []const u8) !?[]const u8 {
        return commands.handleSlashCommand(self, message);
    }

    /// Run the caller-provided durable barrier before an external tool effect.
    /// Local approval commands use the same hook as provider-issued tool calls.
    pub fn runBeforeToolDispatchBarrier(self: *Agent) !void {
        const callback = self.before_tool_dispatch_cb orelse return;
        const callback_ctx = self.before_tool_dispatch_ctx orelse
            return error.MissingToolDispatchContext;
        try callback(callback_ctx);
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

    fn toolPriorityScoreForMessage(self: *const Agent, tool_name: []const u8, user_message: []const u8) u16 {
        var best_score: u16 = 0;
        for (self.tools_config.tool_customizations) |custom| {
            if (!custom.enabled or custom.triggers.len == 0) continue;
            if (!std.mem.eql(u8, custom.name, tool_name)) continue;

            for (custom.triggers) |kw| {
                if (!self.toolTriggerMatchesMessage(user_message, kw)) continue;
                const score = @as(u16, custom.priority) + 1;
                if (score > best_score) best_score = score;
                break;
            }
        }
        return best_score;
    }

    fn priorityToolForSpecsMessage(self: *const Agent, specs: []const ToolSpec, user_message: []const u8) ?[]const u8 {
        var best_score: u16 = 0;
        var best_name: ?[]const u8 = null;
        for (specs) |spec| {
            const score = self.toolPriorityScoreForMessage(spec.name, user_message);
            if (score > best_score) {
                best_score = score;
                best_name = spec.name;
            }
        }
        return best_name;
    }

    fn prioritizeToolSpecsForTurn(
        self: *const Agent,
        arena: std.mem.Allocator,
        specs: []const ToolSpec,
        user_message: []const u8,
    ) ![]const ToolSpec {
        if (self.tools_config.tool_customizations.len == 0 or specs.len < 2) return specs;

        var has_triggered_tool = false;
        for (specs) |spec| {
            if (self.toolPriorityScoreForMessage(spec.name, user_message) > 0) {
                has_triggered_tool = true;
                break;
            }
        }
        if (!has_triggered_tool) return specs;

        const prioritized = try arena.dupe(ToolSpec, specs);
        var i: usize = 1;
        while (i < prioritized.len) : (i += 1) {
            const current = prioritized[i];
            const current_score = self.toolPriorityScoreForMessage(current.name, user_message);
            var j = i;
            while (j > 0) {
                const previous_score = self.toolPriorityScoreForMessage(prioritized[j - 1].name, user_message);
                if (previous_score >= current_score) break;
                prioritized[j] = prioritized[j - 1];
                j -= 1;
            }
            prioritized[j] = current;
        }
        return prioritized;
    }

    /// Build a subset of `self.tools` suitable for the text-based system prompt.
    /// Only includes built-in tools and MCP tools from `always` filter groups.
    /// Dynamic-group MCP tools are omitted — their schemas are still available
    /// via native API tool-calling when the turn keywords match.
    fn filterToolsForPromptText(self: *const Agent, arena: std.mem.Allocator) ![]const Tool {
        if (self.tool_filter_groups.len == 0) return self.tools;

        var result: std.ArrayListUnmanaged(Tool) = .empty;
        errdefer result.deinit(arena);

        for (self.tools) |t| {
            if (!std.mem.startsWith(u8, t.name(), "mcp_")) {
                try result.append(arena, t);
                continue;
            }

            for (self.tool_filter_groups) |group| {
                if (group.mode != .always) continue;
                for (group.tools) |pattern| {
                    if (globMatch(pattern, t.name())) {
                        try result.append(arena, t);
                        break;
                    }
                } else continue;
                break;
            }
        }

        return try result.toOwnedSlice(arena);
    }

    /// Filter and prioritize `self.tool_specs` for the current turn.
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
    ///   - Matching `tools.tool_customizations.triggers` move configured tools earlier
    ///     in the turn's schema, sorted by priority while preserving ties.
    fn filterToolSpecsForTurn(
        self: *const Agent,
        arena: std.mem.Allocator,
        user_message: []const u8,
    ) ![]const ToolSpec {
        if (self.tool_filter_groups.len == 0) {
            return self.prioritizeToolSpecsForTurn(arena, self.tool_specs, user_message);
        }

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

        return self.prioritizeToolSpecsForTurn(arena, try result.toOwnedSlice(arena), user_message);
    }

    const TurnOptions = struct {
        internal_tool_result: bool = false,
        input_already_in_history: bool = false,
        continuation_user_message: ?[]const u8 = null,
        model_name_override: ?[]const u8 = null,
        continuation_persistence_message: ?[]const u8 = null,
        replay_results: ?*ToolCallResultCache = null,
    };

    /// Execute a single conversation turn: send messages to LLM, parse tool calls,
    /// execute tools, and loop until a final text response is produced.
    pub fn turn(self: *Agent, user_message: []const u8) ![]const u8 {
        return self.turnWithOptions(user_message, .{});
    }

    pub fn continueAfterApproval(
        self: *Agent,
        tool_result_message: []const u8,
        continuation_user_message: ?[]const u8,
        model_name: ?[]const u8,
        persistence_user_message: ?[]const u8,
        replay_results: *ToolCallResultCache,
    ) ![]const u8 {
        return self.turnWithOptions(tool_result_message, .{
            .internal_tool_result = true,
            .input_already_in_history = true,
            .continuation_user_message = continuation_user_message,
            .model_name_override = model_name,
            .continuation_persistence_message = persistence_user_message,
            .replay_results = replay_results,
        });
    }

    fn turnWithOptions(self: *Agent, user_message: []const u8, options: TurnOptions) ![]const u8 {
        self.context_was_compacted = false;
        commands.refreshSubagentToolContext(self);

        const turn_input = if (options.internal_tool_result)
            commands.TurnInputPlan{ .llm_user_message = user_message }
        else
            commands.planTurnInput(user_message);
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
        var safe_user_message_owned: ?[]u8 = null;
        defer if (safe_user_message_owned) |msg| self.allocator.free(msg);
        const safe_user_message = if (self.redactor) |r| blk: {
            safe_user_message_owned = try r.redact(self.allocator, effective_user_message);
            break :blk safe_user_message_owned.?;
        } else effective_user_message;

        const tool_selection_message = options.continuation_user_message orelse effective_user_message;
        const turn_route_selection = if (options.internal_tool_result)
            null
        else
            self.routeSelectionForTurn(effective_user_message);
        if (turn_route_selection) |selection| {
            try self.setLastRouteTrace(selection);
        }
        const turn_model_name = if (options.model_name_override) |model_name|
            model_name
        else if (turn_route_selection) |selection|
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ selection.route.provider, selection.route.model })
        else
            self.model_name;
        const turn_model_name_owned = options.model_name_override == null and
            !std.mem.eql(u8, turn_model_name, self.model_name);
        defer if (turn_model_name_owned) self.allocator.free(turn_model_name);

        const previous_approval_turn_user_message = self.approval_turn_user_message;
        const previous_approval_turn_model_name = self.approval_turn_model_name;
        const previous_approval_turn_persistence_message = self.approval_turn_persistence_message;
        self.approval_turn_user_message = tool_selection_message;
        self.approval_turn_model_name = turn_model_name;
        self.approval_turn_persistence_message = options.continuation_persistence_message orelse user_message;
        defer {
            self.approval_turn_user_message = previous_approval_turn_user_message;
            self.approval_turn_model_name = previous_approval_turn_model_name;
            self.approval_turn_persistence_message = previous_approval_turn_persistence_message;
        }

        var cfg_for_prompt_opt: ?Config = Config.load(self.allocator) catch null;
        defer if (cfg_for_prompt_opt) |*cfg_loaded| cfg_loaded.deinit();
        const cfg_for_prompt_ptr: ?*const Config = if (cfg_for_prompt_opt) |*cfg_loaded| cfg_loaded else null;

        // Inject system prompt on first turn (or when tracked workspace files changed).
        const workspace_fp: ?u64 = prompt.workspacePromptFingerprint(
            self.allocator,
            self.workspace_dir,
            self.bootstrap,
            if (cfg_for_prompt_ptr) |cfg| cfg.identity else null,
        ) catch null;
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
            var prompt_tools_arena = std.heap.ArenaAllocator.init(self.allocator);
            defer prompt_tools_arena.deinit();
            const prompt_tools = try self.filterToolsForPromptText(prompt_tools_arena.allocator());
            const prompt_is_streaming = self.stream_callback != null and self.stream_ctx != null and self.provider.supportsStreaming();
            const prompt_native_tools_enabled = !prompt_is_streaming and self.provider.supportsNativeTools();

            const capabilities_section = capabilities_mod.buildPromptSection(
                self.allocator,
                cfg_for_prompt_ptr,
                prompt_tools,
            ) catch null;
            defer if (capabilities_section) |section| self.allocator.free(section);

            const full_system = try prompt.buildSystemPrompt(self.allocator, .{
                .workspace_dir = self.workspace_dir,
                .model_name = turn_model_name,
                .tools = prompt_tools,
                .timezone = if (cfg_for_prompt_ptr) |cfg_ptr| cfg_ptr.agent.timezone else "UTC",
                .capabilities_section = capabilities_section,
                .conversation_context = self.conversation_context,
                .bootstrap_provider = self.bootstrap,
                .identity_config = if (cfg_for_prompt_ptr) |cfg| cfg.identity else null,
                .observer = self.observer,
                .native_tools_enabled = prompt_native_tools_enabled,
            });
            const active_skill_section = try commands.buildActiveSkillPromptSection(self);
            defer if (active_skill_section) |section| self.allocator.free(section);

            const final_system = blk: {
                const has_profile_prompt = self.profile_system_prompt != null and self.profile_system_prompt.?.len > 0;
                if (!has_profile_prompt and active_skill_section == null) break :blk full_system;

                defer self.allocator.free(full_system);

                var composed: std.ArrayListUnmanaged(u8) = .empty;
                errdefer composed.deinit(self.allocator);
                var composed_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &composed);
                const w = &composed_writer.writer;

                if (has_profile_prompt) {
                    try w.print(
                        "## Agent Profile\n\nProfile: {s}\n\n{s}",
                        .{
                            self.profile_name orelse "custom",
                            self.profile_system_prompt.?,
                        },
                    );
                }

                if (active_skill_section) |section| {
                    if (composed.items.len > 0) try w.writeAll("\n\n");
                    try w.writeAll(section);
                }

                if (composed.items.len > 0) try w.writeAll("\n\n");
                try w.writeAll(full_system);
                composed = composed_writer.toArrayList();
                break :blk try composed.toOwnedSlice(self.allocator);
            };

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
        if (self.auto_save and !options.internal_tool_result) {
            if (self.mem) |mem| {
                const ts: u128 = @bitCast(std_compat.time.nanoTimestamp());
                const save_key = std.fmt.allocPrint(self.allocator, "autosave_user_{d}", .{ts}) catch null;
                if (save_key) |key| {
                    defer self.allocator.free(key);
                    if (mem.store(key, safe_user_message, .conversation, self.memory_session_id)) |_| {
                        // Vector sync after auto-save
                        if (self.mem_rt) |rt| {
                            rt.syncVectorAfterStore(self.allocator, key, safe_user_message, self.memory_session_id);
                        }
                    } else |_| {}
                }
            }
        }

        // Internal tool results bypass memory retrieval and autosave. They are
        // generated by the authenticated approval control path, not user text.
        if (!options.input_already_in_history) {
            const enriched_raw = if (options.internal_tool_result)
                try self.allocator.dupe(u8, safe_user_message)
            else if (self.mem) |mem|
                try memory_loader.enrichMessageWithRuntime(self.allocator, mem, self.mem_rt, safe_user_message, self.memory_session_id)
            else
                try self.allocator.dupe(u8, safe_user_message);
            const enriched = try self.redactOwnedForHistory(enriched_raw);

            try self.appendOwnedHistoryMessage(.{ .role = .user, .content = enriched });
        }

        var sys_bytes: usize = 0;
        var hist_bytes: usize = 0;
        for (self.history.items) |msg| {
            if (msg.role == .system) {
                sys_bytes += msg.content.len;
            } else {
                hist_bytes += msg.content.len;
            }
        }
        self.last_system_prompt_bytes = sys_bytes;
        self.last_history_bytes = hist_bytes;

        // ── Response cache check ──
        const response_cache_allowed = !options.internal_tool_result and self.responseCacheSafeForTurn(safe_user_message);
        if (response_cache_allowed) {
            if (self.response_cache) |rc| {
                var key_buf: [16]u8 = undefined;
                const system_prompt = if (self.history.items.len > 0 and self.history.items[0].role == .system)
                    self.history.items[0].content
                else
                    null;
                const key_hex = cache.ResponseCache.cacheKeyHex(&key_buf, turn_model_name, system_prompt, safe_user_message);
                if (rc.get(self.allocator, key_hex) catch null) |cached_response| {
                    errdefer self.allocator.free(cached_response);
                    const history_copy = try self.dupeForHistory(cached_response);
                    errdefer self.allocator.free(history_copy);
                    try self.history.append(self.allocator, .{
                        .role = .assistant,
                        .content = history_copy,
                    });
                    self.last_turn_usage = .{};
                    return cached_response;
                }
            }
        }

        const turn_token_limit = context_tokens.resolveContextTokens(self.token_limit_override, turn_model_name);
        const turn_max_tokens_raw = max_tokens_resolver.resolveMaxTokens(self.max_tokens_override, turn_model_name);
        const turn_token_limit_cap: u32 = @intCast(@min(turn_token_limit, @as(u64, std.math.maxInt(u32))));
        const turn_max_tokens = @min(turn_max_tokens_raw, turn_token_limit_cap);

        // Tool call loop — reuse a single arena across iterations (retains pages)
        var iter_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer iter_arena.deinit();

        var iteration: u32 = 0;
        var injection_followups: u32 = 0;
        var forced_follow_through_count: u32 = 0;
        var empty_response_retry_count: u32 = 0;
        var seen_tool_call_results: ToolCallResultCache = if (options.replay_results) |seed| blk: {
            const moved = seed.*;
            seed.* = .empty;
            break :blk moved;
        } else .empty;
        defer deinitSeenToolCallResults(self.allocator, &seen_tool_call_results);
        var tool_dispatch_started = false;
        var tool_write_ahead_completed = false;
        var interrupt_response_fallback: ?[]u8 = null;
        defer if (interrupt_response_fallback) |content| self.allocator.free(content);
        var interrupt_history_fallback: ?[]const u8 = null;
        defer if (interrupt_history_fallback) |content| self.allocator.free(content);
        while (iteration < self.max_tool_iterations +| injection_followups) : (iteration += 1) {
            if (self.isInterruptRequested()) {
                if (tool_dispatch_started) {
                    return self.interruptedReply() catch self.interruptedToolBatchReply(
                        &interrupt_response_fallback,
                        &interrupt_history_fallback,
                    );
                }
                return self.interruptedReply();
            }

            // Drain any mid-turn injection at each tool boundary.
            if (try self.drainPendingInjection()) |injected| {
                const safe_injected = try self.redactOwnedForHistory(injected);
                try self.appendOwnedHistoryMessage(.{ .role = .user, .content = safe_injected });
            }

            _ = iter_arena.reset(.retain_capacity);
            const arena = iter_arena.allocator();

            const timer_start = std_compat.time.milliTimestamp();
            const is_streaming = self.stream_callback != null and self.stream_ctx != null and self.provider.supportsStreaming();
            const native_tools_enabled = !is_streaming and self.provider.supportsNativeTools();
            const include_reasoning = self.reasoning_mode != .off;

            // Filter tool specs for this turn (arena-owned; may be self.tool_specs directly if no groups).
            const turn_tool_specs = try self.filterToolSpecsForTurn(arena, tool_selection_message);
            // Preserve dynamic availability from the original request, but do
            // not re-inject a hard "call immediately" hint after that tool has
            // already executed (or been denied) during an approval continuation.
            const priority_tool = if (options.internal_tool_result)
                null
            else
                self.priorityToolForSpecsMessage(turn_tool_specs, tool_selection_message);

            // Build messages slice for provider (arena-owned; freed at end of iteration).
            const messages = try self.buildProviderMessagesForTurn(arena, turn_model_name, priority_tool);
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
                self.recordLlmRequestEvent(turn_model_name, messages);
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
                        .include_reasoning = include_reasoning,
                    },
                    turn_model_name,
                    self.temperature,
                    self.stream_callback.?,
                    self.stream_ctx.?,
                ) catch |err| retry_stream: {
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - timer_start)));
                    self.recordLlmFailureEvent(turn_model_name, fail_duration, @errorName(err));

                    // Auto-disable vision on first "model does not support vision" error
                    if (self.auto_disable_vision_on_error and err == error.ProviderDoesNotSupportVision) {
                        if (self.verbose_level == .on or self.verbose_level == .full) {
                            log.info("Auto-disabling vision for model {s}", .{turn_model_name});
                        }
                        try self.markVisionDisabled(turn_model_name);
                        const retry_msgs = try self.buildProviderMessagesForTurn(arena, turn_model_name, priority_tool);
                        const retry_max_tokens = self.effectiveMaxTokensForTurn(
                            retry_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.recordLlmRequestEvent(turn_model_name, retry_msgs);
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
                                .include_reasoning = include_reasoning,
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
                    .reasoning_content = stream_result.reasoning_content,
                    .tool_calls = &.{},
                    .usage = stream_result.usage,
                    .model = stream_result.model,
                };
            } else {
                self.recordLlmRequestEvent(turn_model_name, messages);
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
                        .include_reasoning = include_reasoning,
                    },
                    turn_model_name,
                    self.temperature,
                ) catch |err| retry_blk: {
                    // Record the failed attempt
                    const fail_duration: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - timer_start)));
                    self.recordLlmFailureEvent(turn_model_name, fail_duration, @errorName(err));

                    // Auto-disable vision on first "model does not support vision" error
                    if (self.auto_disable_vision_on_error and err == error.ProviderDoesNotSupportVision) {
                        if (self.verbose_level == .on or self.verbose_level == .full) {
                            log.info("Auto-disabling vision for model {s}", .{turn_model_name});
                        }
                        try self.markVisionDisabled(turn_model_name);
                        const retry_msgs = try self.buildProviderMessagesForTurn(arena, turn_model_name, priority_tool);
                        const retry_max_tokens = self.effectiveMaxTokensForTurn(
                            retry_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.recordLlmRequestEvent(turn_model_name, retry_msgs);
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
                                .include_reasoning = include_reasoning,
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
                        const recovery_msgs = self.buildProviderMessagesForTurn(arena, turn_model_name, priority_tool) catch |prep_err| return prep_err;
                        const recovery_max_tokens = self.effectiveMaxTokensForTurn(
                            recovery_msgs,
                            if (native_tools_enabled) turn_tool_specs else null,
                            turn_token_limit,
                            turn_max_tokens,
                        );
                        response_attempt = 2;
                        self.recordLlmRequestEvent(turn_model_name, recovery_msgs);
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
                                .include_reasoning = include_reasoning,
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
                    std_compat.thread.sleep(500 * std.time.ns_per_ms);
                    response_attempt = 2;
                    self.recordLlmRequestEvent(turn_model_name, messages);
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
                            .include_reasoning = include_reasoning,
                        },
                        turn_model_name,
                        self.temperature,
                    ) catch |retry_err| {
                        // Context exhaustion recovery: if we have enough history,
                        // force-compress and retry once more
                        if (self.history.items.len > compaction.CONTEXT_RECOVERY_MIN_HISTORY and self.forceCompressHistory()) {
                            self.context_was_compacted = true;
                            const recovery_msgs = self.buildProviderMessagesForTurn(arena, turn_model_name, priority_tool) catch |prep_err| return prep_err;
                            const recovery_max_tokens = self.effectiveMaxTokensForTurn(
                                recovery_msgs,
                                if (native_tools_enabled) turn_tool_specs else null,
                                turn_token_limit,
                                turn_max_tokens,
                            );
                            response_attempt = 3;
                            self.recordLlmRequestEvent(turn_model_name, recovery_msgs);
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
                                    .include_reasoning = include_reasoning,
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
            // Provider responses own all non-empty slices. Keep a scope guard
            // so every early error/continue path releases them; explicit frees
            // below clear the fields and make this final cleanup a no-op.
            defer self.freeResponseFields(&response);

            const duration_ms: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - timer_start)));

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
            self.total_cost_usd += cost_mod.TokenUsage.fromProviders(turn_model_name, normalized_usage).cost();
            self.last_turn_usage = normalized_usage;
            if (normalized_usage.total_tokens > 0) {
                const usage_metric = observability.ObserverMetric{ .tokens_used = normalized_usage.total_tokens };
                self.observer.recordMetric(&usage_metric);
            }
            self.recordLlmResponseEvent(turn_model_name, duration_ms, &response);
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

            // Parse every call before the first tool can produce a side effect.
            // Otherwise an allocation failure while parsing a later call could
            // unwind the turn after an earlier call already ran, losing the
            // exact-once replay receipts that prevent duplicate execution.
            const prepared_tool_arguments: []const PreparedToolArguments = if (parsed_calls.len > 0)
                try prepareToolArgumentsBatch(arena, parsed_calls)
            else
                &.{};
            if (parsed_calls.len > 0 and !tool_write_ahead_completed) {
                try self.runBeforeToolDispatchBarrier();
                tool_write_ahead_completed = true;
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
                    if (empty_response_retry_count < 1 and
                        iteration + 1 < self.max_tool_iterations)
                    {
                        try self.appendOwnedHistoryMessage(.{ .role = .user, .content = try self.allocator.dupe(u8, "SYSTEM: Your previous reply was empty. Respond with a direct user-visible answer or emit the necessary tool call(s). Do not return an empty response. - If the user asks for information from the internet, web, or external sources (for example: recipes, news, latest documentation), you SHOULD use the `web_search` tool immediately.\n- Do not merely state that you can find the information; execute the tool call in the same turn.\n- NEVER respond with just 'I will search' or 'Let me check' without actually calling the tool in the same response.\n- If the user's intent implies a need for fresh data or external verification, default to using `web_search`.\n\n") });
                        self.trimHistory();
                        empty_response_retry_count += 1;
                        continue;
                    }
                    return error.NoResponseContent;
                }

                // Guardrail: if the model promises "I'll try/check now" but emits no
                // tool call, force one follow-up completion to either act now or
                // explicitly state the limitation without deferred promises.
                // This applies in both streaming and non-streaming paths: the follow-up
                // iteration will stream its own chunks independently.
                if (forced_follow_through_count < 2 and
                    iteration + 1 < self.max_tool_iterations and
                    shouldForceActionFollowThrough(display_text))
                {
                    try self.appendOwnedHistoryMessage(.{ .role = .assistant, .content = try self.dupeForHistory(display_text) });
                    try self.appendOwnedHistoryMessage(.{ .role = .user, .content = try self.allocator.dupe(u8, "SYSTEM: You just promised to take action now (for example: \"I'll try/check now\"). " ++
                        "Do it in this turn by issuing the appropriate tool call(s). " ++
                        "If no tool can perform it, respond with a clear limitation now and do not promise another future attempt.") });
                    self.trimHistory();
                    self.freeResponseFields(&response);
                    forced_follow_through_count += 1;
                    continue;
                }

                // If an inbound message arrived while the final model response
                // was being produced, fold it into this active turn instead of
                // leaving it buffered until an unrelated future message.
                if (injection_followups < MAX_MID_TURN_INJECTION_FOLLOWUPS) {
                    if (try self.drainPendingInjection()) |injected| {
                        try self.appendOwnedHistoryMessage(.{
                            .role = .assistant,
                            .content = try self.dupeForHistory(display_text),
                        });
                        const safe_injected = try self.redactOwnedForHistory(injected);
                        try self.appendOwnedHistoryMessage(.{ .role = .user, .content = safe_injected });
                        self.trimHistory();
                        self.freeResponseFields(&response);
                        injection_followups += 1;
                        continue;
                    }
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
                    .content = try self.dupeForHistory(display_text),
                });

                // Auto-compaction before hard trimming to preserve context.
                self.last_turn_compacted = self.maybeAutoCompactHistory();
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
                        const safe_summary = if (self.redactor) |r|
                            r.redact(arena, summary) catch null
                        else
                            summary;
                        const ts: u128 = @bitCast(std_compat.time.nanoTimestamp());
                        const save_key = std.fmt.allocPrint(self.allocator, "autosave_assistant_{d}", .{ts}) catch null;
                        if (save_key) |key| {
                            defer self.allocator.free(key);
                            if (safe_summary) |content| {
                                if (mem.store(key, content, .conversation, self.memory_session_id)) |_| {
                                    // Vector sync after auto-save
                                    if (self.mem_rt) |rt| {
                                        rt.syncVectorAfterStore(self.allocator, key, content, self.memory_session_id);
                                    }
                                } else |_| {}
                            }
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
                if (response_cache_allowed) {
                    if (self.response_cache) |rc| {
                        var store_key_buf: [16]u8 = undefined;
                        const sys_prompt = if (self.history.items.len > 0 and self.history.items[0].role == .system)
                            self.history.items[0].content
                        else
                            null;
                        const store_key_hex = cache.ResponseCache.cacheKeyHex(&store_key_buf, turn_model_name, sys_prompt, safe_user_message);
                        const token_count: u32 = @intCast(@min(self.last_turn_usage.total_tokens, std.math.maxInt(u32)));
                        rc.put(self.allocator, store_key_hex, turn_model_name, final_text, token_count) catch {};
                    }
                }

                return final_text;
            }

            // There are tool calls — print intermediary text.
            // In tests, stdout is used by Zig's test runner protocol (`--listen`),
            // so avoid writing arbitrary text that can corrupt the control channel.
            if (!builtin.is_test and display_text.len > 0 and parsed_calls.len > 0 and !is_streaming) {
                var out_buf: [4096]u8 = undefined;
                var bw = std_compat.fs.File.stdout().writer(&out_buf);
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
            var safe_assistant_content: ?[]const u8 = try self.redactOwnedForHistory(assistant_content);
            errdefer if (safe_assistant_content) |content| self.allocator.free(content);

            // Reserve every allocation needed by the execution loop before
            // recording its assistant calls or allowing a side effect. Exact
            // receipts and result collection are infallible after this point.
            var results_buf: std.ArrayListUnmanaged(ToolExecutionResult) = .empty;
            defer results_buf.deinit(self.allocator);
            try results_buf.ensureTotalCapacity(self.allocator, parsed_calls.len);
            try seen_tool_call_results.ensureUnusedCapacity(self.allocator, @intCast(parsed_calls.len));
            // The interrupt path closes the completed tool prefix and then
            // appends its final assistant reply, so it needs one more slot
            // than the normal and approval-boundary paths.
            try self.history.ensureUnusedCapacity(self.allocator, 3);
            if (interrupt_response_fallback == null) {
                interrupt_response_fallback = try self.allocator.dupe(
                    u8,
                    "Interrupted by /stop. Halting tool execution for this turn.",
                );
                interrupt_history_fallback = try self.allocator.dupe(
                    u8,
                    "Interrupted by /stop. Halting tool execution for this turn.",
                );
            }
            var tool_results_fallback: ?[]const u8 = try self.allocator.dupe(
                u8,
                "<tool_results status=\"memory_pressure\">The tool batch finished, but detailed results could not be recorded. Treat earlier calls as potentially executed and do not repeat them automatically.</tool_results>",
            );
            defer if (tool_results_fallback) |content| self.allocator.free(content);
            var boundary_assistant_fallback: ?[]const u8 = try self.allocator.dupe(
                u8,
                "The tool batch stopped at an approval boundary. Calls before the boundary may have completed; the approval-gated call and every later call were not executed.",
            );
            defer if (boundary_assistant_fallback) |content| self.allocator.free(content);
            var boundary_cancel_fallback: ?[]const u8 = try self.allocator.dupe(
                u8,
                "The tool batch stopped before its approval-gated call. Earlier calls may have completed; do not repeat them automatically.",
            );
            defer if (boundary_cancel_fallback) |content| self.allocator.free(content);
            var approval_waiting_response: ?[]u8 = try self.allocator.dupe(
                u8,
                "Approval requested. Waiting for your decision.",
            );
            defer if (approval_waiting_response) |content| self.allocator.free(content);
            var approval_failure_response: ?[]u8 = try self.allocator.dupe(
                u8,
                "Approval could not be delivered. Later calls from the same batch were not executed.",
            );
            defer if (approval_failure_response) |content| self.allocator.free(content);
            var interrupt_assistant_fallback: ?[]const u8 = try self.allocator.dupe(
                u8,
                "The tool batch was interrupted. Calls before the interruption may have completed; every later call was not executed and must not be assumed to have run.",
            );
            defer if (interrupt_assistant_fallback) |content| self.allocator.free(content);

            const assistant_history_index = self.history.items.len;
            self.history.appendAssumeCapacity(.{ .role = .assistant, .content = safe_assistant_content.? });
            safe_assistant_content = null;

            // Execute each tool call
            var approval_boundary = false;
            var approval_created = false;
            var approval_call_count: usize = 0;
            var approval_result: ToolExecutionResult = undefined;
            var tools_md_updated = false;

            const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
            if (self.log_tool_calls) {
                log.info("tool-call batch session=0x{x} count={d}", .{ session_hash, parsed_calls.len });
            }

            for (parsed_calls, 0..) |call, idx| {
                if (self.isInterruptRequested()) {
                    const assistant_base_text = if (use_native) response_text else parsed_text;
                    var prepared = self.prepareInterruptedPrefixRich(
                        arena,
                        assistant_base_text,
                        parsed_calls,
                        idx,
                        results_buf.items,
                    ) catch {
                        // A completed prefix may already contain side effects.
                        // Even under memory pressure, remove the unexecuted
                        // tail and close the prefix with the preallocated
                        // replay-receipt fallback before returning.
                        self.history.items[assistant_history_index].deinit(self.allocator);
                        self.history.items[assistant_history_index] = .{
                            .role = .assistant,
                            .content = interrupt_assistant_fallback.?,
                        };
                        interrupt_assistant_fallback = null;
                        if (results_buf.items.len > 0) {
                            self.history.appendAssumeCapacity(.{
                                .role = .user,
                                .content = tool_results_fallback.?,
                            });
                            tool_results_fallback = null;
                        }
                        self.freeResponseFields(&response);
                        return self.interruptedToolBatchReply(
                            &interrupt_response_fallback,
                            &interrupt_history_fallback,
                        );
                    };
                    defer prepared.deinit(self.allocator);

                    self.history.items[assistant_history_index].deinit(self.allocator);
                    self.history.items[assistant_history_index] = .{
                        .role = .assistant,
                        .content = prepared.assistant_content.?,
                    };
                    prepared.assistant_content = null;
                    if (prepared.completed_results) |content| {
                        self.history.appendAssumeCapacity(.{ .role = .user, .content = content });
                        prepared.completed_results = null;
                    }
                    self.freeResponseFields(&response);
                    return self.interruptedToolBatchReply(
                        &interrupt_response_fallback,
                        &interrupt_history_fallback,
                    );
                }

                if (self.log_tool_calls) {
                    log.info(
                        "tool-call start session=0x{x} index={d} name={s} id={s}",
                        .{ session_hash, idx + 1, call.name, call.tool_call_id orelse "-" },
                    );
                }

                const tool_start_event = ObserverEvent{ .tool_call_start = .{ .tool = call.name } };
                self.observer.recordEvent(&tool_start_event);
                if (self.progress_callback) |cb| {
                    if (self.progress_ctx) |pctx| cb(pctx, .{ .text = call.name });
                }

                const tool_timer = std_compat.time.milliTimestamp();
                const pending_request_before: ?[APPROVAL_REQUEST_ID_LEN]u8 = if (self.pending_approval) |pending|
                    pending.request_id
                else
                    null;
                const result = blk: {
                    if (cachedToolCallResultInTurn(&seen_tool_call_results, call)) |cached_result| {
                        break :blk ToolExecutionResult{
                            .name = call.name,
                            .output = cached_result.output,
                            .success = cached_result.success,
                            .tool_call_id = call.tool_call_id,
                        };
                    }
                    prepareToolCallResultReceipt(&seen_tool_call_results, call);
                    const executed_result = if (shouldSkipToolsMemoryStoreDuplicatePrepared(
                        tools_md_updated,
                        call,
                        prepared_tool_arguments[idx],
                    ))
                        ToolExecutionResult{
                            .name = call.name,
                            .output = "Skipped duplicate memory_store: TOOLS.md was updated in the same tool batch",
                            .success = true,
                            .tool_call_id = call.tool_call_id,
                        }
                    else dispatch: {
                        tool_dispatch_started = true;
                        break :dispatch self.executeToolWithPreparedArguments(
                            arena,
                            call,
                            .{},
                            prepared_tool_arguments[idx],
                        );
                    };
                    if (executed_result.approval_boundary) {
                        discardPreparedToolCallResultReceipt(self.allocator, &seen_tool_call_results, call);
                    } else {
                        finalizePreparedToolCallResultReceipt(
                            self.allocator,
                            &seen_tool_call_results,
                            call,
                            executed_result,
                            false,
                        );
                    }
                    break :blk executed_result;
                };
                if (result.success and toolCallUpdatesToolsMdPrepared(call, prepared_tool_arguments[idx])) {
                    // Only earlier successful writes may suppress a duplicate
                    // memory_store. A later call can be canceled at an approval
                    // boundary or fail, so scanning the full batch loses data.
                    tools_md_updated = true;
                }
                const tool_duration: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - tool_timer)));

                if (self.log_tool_calls) {
                    log.info(
                        "tool-call done session=0x{x} index={d} name={s} success={} duration_ms={d}",
                        .{ session_hash, idx + 1, call.name, result.success, tool_duration },
                    );
                }

                var tool_args_buf: [1024]u8 = undefined;
                var tool_detail_buf: [1024]u8 = undefined;
                const tool_args = if (self.log_llm_io) blk: {
                    const safe_args = self.diagnosticText(arena, call.arguments_json);
                    break :blk toolArgsObserverDetail(&tool_args_buf, safe_args);
                } else null;
                const tool_detail = if (self.log_llm_io) blk: {
                    const safe_output = self.safeToolDiagnosticText(arena, result.output);
                    break :blk toolResultObserverDetail(&tool_detail_buf, safe_output);
                } else if (!result.success) blk: {
                    break :blk self.safeToolDiagnosticText(arena, result.output);
                } else null;
                const tool_event = ObserverEvent{ .tool_call = .{
                    .tool = call.name,
                    .duration_ms = tool_duration,
                    .success = result.success,
                    .args = tool_args,
                    .detail = tool_detail,
                } };
                self.observer.recordEvent(&tool_event);

                if (result.approval_boundary) {
                    approval_boundary = true;
                    approval_call_count = idx + 1;
                    approval_result = result;
                    approval_created = if (self.pending_approval) |pending|
                        if (pending_request_before) |previous|
                            !std.mem.eql(u8, &previous, &pending.request_id)
                        else
                            true
                    else
                        false;
                    break;
                }
                results_buf.appendAssumeCapacity(result);
            }

            // Stop at every approval boundary. A successfully prepared request
            // pauses the logical tool loop; delivery failure and an already
            // pending request still cancel the unexecuted tail fail-closed.
            if (approval_boundary) {
                const assistant_base_text = if (use_native) response_text else parsed_text;
                // The fixed-capacity result slice remains valid after adding
                // the boundary failure record below.
                const completed_results = results_buf.items;
                const delivery_failure_result = if (approval_created)
                    ToolExecutionResult{
                        .name = approval_result.name,
                        .output = "Command requires approval, but this channel cannot deliver an interactive approval request",
                        .success = false,
                        .tool_call_id = approval_result.tool_call_id,
                        .approval_boundary = true,
                    }
                else
                    approval_result;
                results_buf.appendAssumeCapacity(delivery_failure_result);

                var prepared = self.prepareApprovalBoundaryRich(
                    arena,
                    assistant_base_text,
                    parsed_calls,
                    approval_call_count,
                    completed_results,
                    results_buf.items,
                ) catch {
                    // A prior tool may already have produced a side effect, so
                    // boundary formatting OOM cannot unwind the turn. Commit a
                    // preallocated canonical summary and retain exact receipts
                    // in the pending continuation instead.
                    self.history.items[assistant_history_index].deinit(self.allocator);
                    self.history.items[assistant_history_index] = .{
                        .role = .assistant,
                        .content = boundary_assistant_fallback.?,
                    };
                    boundary_assistant_fallback = null;
                    self.history.appendAssumeCapacity(.{
                        .role = .user,
                        .content = tool_results_fallback.?,
                    });
                    tool_results_fallback = null;

                    if (approval_created) {
                        const pending = &self.pending_approval.?;
                        pending.history_rollback_index = assistant_history_index;
                        pending.cancel_assistant_content = boundary_cancel_fallback.?;
                        boundary_cancel_fallback = null;
                        pending.replay_results = seen_tool_call_results;
                        seen_tool_call_results = .empty;
                    }

                    const delivered_fallback = approval_created and self.emitApprovalRequest(&self.pending_approval.?);
                    if (!delivered_fallback and approval_created) {
                        self.pending_approval.?.history_rollback_index = null;
                        self.discardPendingApproval();
                    }
                    self.freeResponseFields(&response);
                    const complete_event = ObserverEvent{ .turn_complete = {} };
                    self.observer.recordEvent(&complete_event);
                    if (delivered_fallback) {
                        const output = approval_waiting_response.?;
                        approval_waiting_response = null;
                        return output;
                    }
                    const output = approval_failure_response.?;
                    approval_failure_response = null;
                    return output;
                };
                defer prepared.deinit(self.allocator);

                // Calls after the approval boundary were never executed. The
                // rich canonical assistant contains only the completed prefix
                // and the single approval-gated call.
                self.history.items[assistant_history_index].deinit(self.allocator);
                self.history.items[assistant_history_index] = .{
                    .role = .assistant,
                    .content = prepared.assistant_content.?,
                };
                prepared.assistant_content = null;
                if (prepared.completed_results) |content| {
                    self.history.appendAssumeCapacity(.{ .role = .user, .content = content });
                    prepared.completed_results = null;
                }

                if (approval_created) {
                    const pending = &self.pending_approval.?;
                    pending.history_rollback_index = assistant_history_index;
                    pending.cancel_assistant_content = prepared.cancel_assistant_content.?;
                    prepared.cancel_assistant_content = null;
                    pending.replay_results = seen_tool_call_results;
                    seen_tool_call_results = .empty;
                }

                const delivered = approval_created and self.emitApprovalRequest(&self.pending_approval.?);
                if (!delivered) {
                    // Replace the completed-only history result with a canonical
                    // failure result, closing the current tool call without
                    // executing anything after it.
                    if (approval_created) {
                        self.pending_approval.?.history_rollback_index = null;
                        self.discardPendingApproval();
                    }
                    if (completed_results.len > 0) {
                        self.history.items[self.history.items.len - 1].deinit(self.allocator);
                        self.history.items[self.history.items.len - 1] = .{
                            .role = .user,
                            .content = prepared.failure_results.?,
                        };
                    } else {
                        self.history.appendAssumeCapacity(.{
                            .role = .user,
                            .content = prepared.failure_results.?,
                        });
                    }
                    prepared.failure_results = null;
                    self.freeResponseFields(&response);
                    const complete_event = ObserverEvent{ .turn_complete = {} };
                    self.observer.recordEvent(&complete_event);
                    const output = approval_failure_response.?;
                    approval_failure_response = null;
                    return output;
                }

                self.freeResponseFields(&response);
                const complete_event = ObserverEvent{ .turn_complete = {} };
                self.observer.recordEvent(&complete_event);
                const output = approval_waiting_response.?;
                approval_waiting_response = null;
                return output;
            }

            // Format tool results, scrub credentials, add reflection prompt, and add to history
            var owned_tool_results: ?[]const u8 = null;
            if (dispatcher.formatToolResults(arena, results_buf.items) catch null) |formatted_results| {
                if (providers.scrubToolOutput(arena, formatted_results) catch null) |scrubbed_results| {
                    const redacted_results: ?[]const u8 = if (self.redactor) |redactor|
                        redactor.redact(arena, scrubbed_results) catch null
                    else
                        scrubbed_results;
                    if (redacted_results) |safe_results| {
                        const with_reflection = std.fmt.allocPrint(
                            arena,
                            "{s}\n\nReflect on the tool results above and decide your next steps. " ++
                                "If a tool failed due to policy/permissions, do not repeat the same blocked call; explain the limitation and choose a different available tool or ask the user for permission/config change. " ++
                                "If a tool failed due to a transient issue (timeout/network/rate-limit), proactively retry up to 2 times with adjusted parameters before giving up.",
                            .{safe_results},
                        ) catch null;
                        if (with_reflection) |content| {
                            owned_tool_results = self.allocator.dupe(u8, content) catch null;
                        }
                    }
                }
            }
            const canonical_tool_results = owned_tool_results orelse tool_results_fallback.?;
            if (owned_tool_results != null) self.allocator.free(tool_results_fallback.?);
            tool_results_fallback = null;
            self.history.appendAssumeCapacity(.{
                .role = .user,
                .content = canonical_tool_results,
            });

            self.trimHistory();

            // Free provider response fields now that all borrows are consumed.
            self.freeResponseFields(&response);
        }

        // A tool can request /stop while completing the final allowed
        // iteration. There is no next loop gate in that case, so close the
        // completed prefix instead of making an unauthorized summary call.
        if (self.isInterruptRequested()) {
            if (tool_dispatch_started) {
                return self.interruptedReply() catch self.interruptedToolBatchReply(
                    &interrupt_response_fallback,
                    &interrupt_history_fallback,
                );
            }
            return self.interruptedReply();
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

        // Also redact the iteration-limit summary call. This is a separate
        // build path from `buildProviderMessagesForTurn`, so the main hook does
        // not cover it.
        var summary_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer summary_arena.deinit();
        const send_summary_messages: []ChatMessage = if (self.redactor) |r|
            try redactMessagesForProvider(summary_arena.allocator(), summary_messages, r)
        else
            summary_messages;

        const summary_timer_start = std_compat.time.milliTimestamp();
        self.recordLlmRequestEvent(turn_model_name, send_summary_messages);
        self.logLlmRequest(self.max_tool_iterations + 1, 1, turn_model_name, send_summary_messages, false, false);
        var summary_response = self.provider.chat(
            self.allocator,
            .{
                .messages = send_summary_messages,
                .session_id = self.memory_session_id,
                .model = turn_model_name,
                .temperature = self.temperature,
                .max_tokens = summary_max_tokens,
                .tools = null, // force text-only
                .timeout_secs = self.message_timeout_secs,
                .reasoning_effort = self.reasoning_effort,
            },
            turn_model_name,
            self.temperature,
        ) catch |err| {
            const fail_duration: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - summary_timer_start)));
            self.recordLlmFailureEvent(turn_model_name, fail_duration, @errorName(err));
            const fallback = try std.fmt.allocPrint(self.allocator, "[Tool iteration limit: {d}/{d}] Could not produce a summary. Try /new and repeat your request.", .{ self.max_tool_iterations, self.max_tool_iterations });
            const complete_event = ObserverEvent{ .turn_complete = {} };
            self.observer.recordEvent(&complete_event);
            return fallback;
        };
        self.logLlmResponse(self.max_tool_iterations + 1, 1, &summary_response);
        const summary_duration_ms: u64 = @as(u64, @intCast(@max(0, std_compat.time.milliTimestamp() - summary_timer_start)));
        const summary_text = summary_response.contentOrEmpty();
        var normalized_summary_usage = summary_response.usage;
        if (normalized_summary_usage.total_tokens == 0 and
            (normalized_summary_usage.prompt_tokens > 0 or normalized_summary_usage.completion_tokens > 0))
        {
            normalized_summary_usage.total_tokens = normalized_summary_usage.prompt_tokens +| normalized_summary_usage.completion_tokens;
        }
        if (normalized_summary_usage.total_tokens == 0 and
            normalized_summary_usage.prompt_tokens == 0 and
            normalized_summary_usage.completion_tokens == 0 and
            summary_text.len > 0)
        {
            normalized_summary_usage.completion_tokens = estimate_text_tokens(summary_text);
            normalized_summary_usage.total_tokens = normalized_summary_usage.completion_tokens;
        }
        summary_response.usage = normalized_summary_usage;
        self.total_tokens += normalized_summary_usage.total_tokens;
        self.total_cost_usd += cost_mod.TokenUsage.fromProviders(turn_model_name, normalized_summary_usage).cost();
        self.last_turn_usage = normalized_summary_usage;
        if (normalized_summary_usage.total_tokens > 0) {
            const usage_metric = observability.ObserverMetric{ .tokens_used = normalized_summary_usage.total_tokens };
            self.observer.recordMetric(&usage_metric);
        }
        self.recordLlmResponseEvent(turn_model_name, summary_duration_ms, &summary_response);
        self.emitUsageRecord(&summary_response, true);
        defer self.freeResponseFields(&summary_response);

        const prefixed = try std.fmt.allocPrint(self.allocator, "[Tool iteration limit: {d}/{d}]\n\n{s}", .{ self.max_tool_iterations, self.max_tool_iterations, summary_text });
        errdefer self.allocator.free(prefixed);

        // Store in history (dupe the raw summary, not the prefixed version)
        try self.history.append(self.allocator, .{
            .role = .assistant,
            .content = try self.dupeForHistory(summary_text),
        });

        // Compact/trim history so the next turn doesn't start with bloated context
        self.last_turn_compacted = self.maybeAutoCompactHistory();
        self.trimHistory();

        const complete_event = ObserverEvent{ .turn_complete = {} };
        self.observer.recordEvent(&complete_event);

        return prefixed;
    }

    fn toolCallUpdatesToolsMdPrepared(
        call: ParsedToolCall,
        prepared: PreparedToolArguments,
    ) bool {
        if (!std.mem.eql(u8, call.name, "file_write") and
            !std.mem.eql(u8, call.name, "file_append") and
            !std.mem.eql(u8, call.name, "file_edit") and
            !std.mem.eql(u8, call.name, "file_edit_hashed")) return false;

        const args = switch (prepared) {
            .object => |object| object,
            else => return false,
        };
        const path_value = args.get("path") orelse return false;
        const path = switch (path_value) {
            .string => |value| value,
            else => return false,
        };
        return is_tools_markdown_path(path);
    }

    fn shouldSkipToolsMemoryStoreDuplicatePrepared(
        tools_md_updated: bool,
        call: ParsedToolCall,
        prepared: PreparedToolArguments,
    ) bool {
        if (!tools_md_updated) return false;
        if (!std.mem.eql(u8, call.name, "memory_store")) return false;

        const args = switch (prepared) {
            .object => |object| object,
            else => return false,
        };
        if (args.get("key")) |key_value| {
            const key = switch (key_value) {
                .string => |value| value,
                else => "",
            };
            if (is_tools_memory_key(key)) return true;
        }

        if (args.get("content")) |content_value| {
            const content = switch (content_value) {
                .string => |value| value,
                else => "",
            };
            if (std.ascii.indexOfIgnoreCase(content, "tools.md") != null) return true;
        }

        return false;
    }

    fn toolCallDedupFingerprint(call: ParsedToolCall) u64 {
        var hasher = std.hash.Wyhash.init(0);
        if (call.tool_call_id) |tool_call_id| {
            if (tool_call_id.len > 0) {
                hasher.update("id:");
                hasher.update(tool_call_id);
                return hasher.final();
            }
        }

        hasher.update("sig:");
        hasher.update(call.name);
        hasher.update("\n");
        hasher.update(call.arguments_json);
        return hasher.final();
    }

    fn deinitSeenToolCallResults(
        allocator: std.mem.Allocator,
        seen_tool_call_results: *ToolCallResultCache,
    ) void {
        deinitToolCallResultCache(allocator, seen_tool_call_results);
    }

    fn cachedToolCallResultInTurn(
        seen_tool_call_results: *const ToolCallResultCache,
        call: ParsedToolCall,
    ) ?CachedToolCallResult {
        return seen_tool_call_results.get(toolCallDedupFingerprint(call));
    }

    const TOOL_RESULT_RECEIPT_FALLBACK =
        "Tool execution completed, but detailed output is unavailable due to memory pressure; do not repeat this call automatically";

    /// Install an allocation-free result receipt after reserving map capacity,
    /// before any tool side effect can run. Rich output replaces it best-effort.
    fn prepareToolCallResultReceipt(
        seen_tool_call_results: *ToolCallResultCache,
        call: ParsedToolCall,
    ) void {
        const fingerprint = toolCallDedupFingerprint(call);
        if (seen_tool_call_results.contains(fingerprint)) return;
        seen_tool_call_results.putAssumeCapacity(fingerprint, .{
            .success = false,
            .output = TOOL_RESULT_RECEIPT_FALLBACK,
            .output_owned = false,
        });
    }

    fn discardPreparedToolCallResultReceipt(
        allocator: std.mem.Allocator,
        seen_tool_call_results: *ToolCallResultCache,
        call: ParsedToolCall,
    ) void {
        const removed = seen_tool_call_results.fetchRemove(toolCallDedupFingerprint(call)) orelse return;
        if (removed.value.output_owned and removed.value.output.len > 0) allocator.free(removed.value.output);
    }

    fn finalizePreparedToolCallResultReceipt(
        allocator: std.mem.Allocator,
        seen_tool_call_results: *ToolCallResultCache,
        call: ParsedToolCall,
        result: ToolExecutionResult,
        cache_failed_signature: bool,
    ) void {
        const has_id = call.tool_call_id != null and call.tool_call_id.?.len > 0;
        if (!result.success and !has_id and !cache_failed_signature) {
            discardPreparedToolCallResultReceipt(allocator, seen_tool_call_results, call);
            return;
        }

        const cached = seen_tool_call_results.getPtr(toolCallDedupFingerprint(call)) orelse return;
        // The side effect already completed. Preserve its true status even if
        // copying the rich output fails, otherwise the reflection prompt may
        // misclassify a successful receipt as transient and repeat the call.
        cached.success = result.success;
        const output_copy = if (result.output.len == 0)
            ""
        else
            allocator.dupe(u8, result.output) catch return;
        if (cached.output_owned and cached.output.len > 0) allocator.free(cached.output);
        cached.* = .{
            .success = result.success,
            .output = output_copy,
            .output_owned = output_copy.len > 0,
        };
    }

    fn prepareApprovalBoundaryRich(
        self: *Agent,
        arena: std.mem.Allocator,
        assistant_base_text: []const u8,
        parsed_calls: []const ParsedToolCall,
        approval_call_count: usize,
        completed_results: []const ToolExecutionResult,
        failure_results: []const ToolExecutionResult,
    ) !PreparedApprovalBoundary {
        const raw_assistant = try dispatcher.buildAssistantHistoryWithToolCalls(
            self.allocator,
            assistant_base_text,
            parsed_calls[0..approval_call_count],
        );
        var assistant_content: ?[]const u8 = try self.redactOwnedForHistory(raw_assistant);
        errdefer if (assistant_content) |content| self.allocator.free(content);

        const raw_cancel = try dispatcher.buildAssistantHistoryWithToolCalls(
            self.allocator,
            assistant_base_text,
            parsed_calls[0 .. approval_call_count - 1],
        );
        var cancel_content: ?[]const u8 = try self.redactOwnedForHistory(raw_cancel);
        errdefer if (cancel_content) |content| self.allocator.free(content);

        var owned_completed: ?[]const u8 = null;
        if (completed_results.len > 0) {
            const formatted = try dispatcher.formatToolResults(arena, completed_results);
            const scrubbed = try providers.scrubToolOutput(arena, formatted);
            const safe = if (self.redactor) |redactor| try redactor.redact(arena, scrubbed) else scrubbed;
            owned_completed = try self.allocator.dupe(u8, safe);
        }
        errdefer if (owned_completed) |content| self.allocator.free(content);

        const formatted_failure = try dispatcher.formatToolResults(arena, failure_results);
        const scrubbed_failure = try providers.scrubToolOutput(arena, formatted_failure);
        const safe_failure = if (self.redactor) |redactor| try redactor.redact(arena, scrubbed_failure) else scrubbed_failure;
        var owned_failure: ?[]const u8 = try self.allocator.dupe(u8, safe_failure);
        errdefer if (owned_failure) |content| self.allocator.free(content);

        const prepared = PreparedApprovalBoundary{
            .assistant_content = assistant_content,
            .cancel_assistant_content = cancel_content,
            .completed_results = owned_completed,
            .failure_results = owned_failure,
        };
        assistant_content = null;
        cancel_content = null;
        owned_completed = null;
        owned_failure = null;
        return prepared;
    }

    fn prepareInterruptedPrefixRich(
        self: *Agent,
        arena: std.mem.Allocator,
        assistant_base_text: []const u8,
        parsed_calls: []const ParsedToolCall,
        completed_call_count: usize,
        completed_results: []const ToolExecutionResult,
    ) !PreparedInterruptedPrefix {
        const raw_assistant = try dispatcher.buildAssistantHistoryWithToolCalls(
            self.allocator,
            assistant_base_text,
            parsed_calls[0..completed_call_count],
        );
        var assistant_content: ?[]const u8 = try self.redactOwnedForHistory(raw_assistant);
        errdefer if (assistant_content) |content| self.allocator.free(content);

        var owned_completed: ?[]const u8 = null;
        if (completed_results.len > 0) {
            const formatted = try dispatcher.formatToolResults(arena, completed_results);
            const scrubbed = try providers.scrubToolOutput(arena, formatted);
            const safe = if (self.redactor) |redactor| try redactor.redact(arena, scrubbed) else scrubbed;
            owned_completed = try self.allocator.dupe(u8, safe);
        }
        errdefer if (owned_completed) |content| self.allocator.free(content);

        const prepared = PreparedInterruptedPrefix{
            .assistant_content = assistant_content,
            .completed_results = owned_completed,
        };
        assistant_content = null;
        owned_completed = null;
        return prepared;
    }

    fn rememberApprovalToolCallResultExact(
        allocator: std.mem.Allocator,
        seen_tool_call_results: *ToolCallResultCache,
        call: ParsedToolCall,
        result: ToolExecutionResult,
    ) !void {
        const fingerprint = toolCallDedupFingerprint(call);
        if (seen_tool_call_results.contains(fingerprint)) return;

        const output_copy = if (result.output.len == 0)
            ""
        else
            try allocator.dupe(u8, result.output);
        errdefer if (output_copy.len > 0) allocator.free(output_copy);

        try seen_tool_call_results.put(allocator, fingerprint, .{
            .success = result.success,
            .output = output_copy,
            .output_owned = output_copy.len > 0,
        });
    }

    /// Replace a replay result without growing the map. The map entry is
    /// reserved before an approved side effect runs, so allocation failure here
    /// safely retains the generic exact-once fallback.
    fn updateApprovalToolCallResult(
        allocator: std.mem.Allocator,
        seen_tool_call_results: *ToolCallResultCache,
        call: ParsedToolCall,
        result: ToolExecutionResult,
    ) void {
        const cached = seen_tool_call_results.getPtr(toolCallDedupFingerprint(call)) orelse return;
        // Keep the exact execution outcome independently of best-effort rich
        // output allocation. A false failure receipt could trigger a replay.
        cached.success = result.success;
        const output_copy = if (result.output.len == 0)
            ""
        else
            allocator.dupe(u8, result.output) catch return;
        if (cached.output_owned and cached.output.len > 0) allocator.free(cached.output);
        cached.* = .{
            .success = result.success,
            .output = output_copy,
            .output_owned = output_copy.len > 0,
        };
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

    const PreparedToolArguments = union(enum) {
        invalid_json,
        non_object,
        object: std.json.ObjectMap,
    };

    fn prepareToolArgumentsBatch(
        arena: std.mem.Allocator,
        calls: []const ParsedToolCall,
    ) ![]PreparedToolArguments {
        const prepared = try arena.alloc(PreparedToolArguments, calls.len);
        for (calls, prepared) |call, *entry| {
            const value = std.json.parseFromSliceLeaky(
                std.json.Value,
                arena,
                call.arguments_json,
                .{},
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    entry.* = .invalid_json;
                    continue;
                },
            };
            entry.* = switch (value) {
                .object => |object| .{ .object = object },
                else => .non_object,
            };
        }
        return prepared;
    }

    const ToolExecutionOptions = struct {
        approved: bool = false,
        record_action: bool = true,
    };

    fn queueToolCallApproval(
        self: *Agent,
        tool_allocator: std.mem.Allocator,
        tool_name: []const u8,
        call: ParsedToolCall,
        args: std.json.ObjectMap,
    ) !void {
        const command = tools_mod.getString(args, "command");
        const display_command = if (command) |cmd|
            if (isExecToolName(tool_name)) tools_mod.shell.normalizeCommandInput(cmd) else cmd
        else
            null;
        const cwd = tools_mod.getString(args, "cwd");
        var owned_action: ?[]u8 = null;
        defer if (owned_action) |value| tool_allocator.free(value);
        const action = if (display_command) |cmd|
            if (cwd) |requested_cwd| blk: {
                owned_action = try std.fmt.allocPrint(tool_allocator, "{s} (cwd: {s})", .{ cmd, requested_cwd });
                break :blk owned_action.?;
            } else cmd
        else
            tool_name;
        const risk_level: CommandRiskLevel = blk: {
            if (display_command) |cmd| {
                if (self.policy) |pol| break :blk pol.commandRiskLevel(cmd);
            }
            break :blk .medium;
        };
        try self.setPendingToolApproval(
            tool_name,
            call.tool_call_id,
            action,
            risk_level,
            call.arguments_json,
        );
    }

    fn approvalFailureResult(
        call: ParsedToolCall,
        approval_err: anyerror,
    ) ToolExecutionResult {
        const output = switch (approval_err) {
            error.OutOfMemory => "OutOfMemory",
            error.ApprovalAlreadyPending => "Another tool approval is already pending",
            error.ApprovalUnavailable => "Command requires approval, but this channel cannot deliver an interactive approval request",
            else => @errorName(approval_err),
        };
        return .{
            .name = call.name,
            .output = output,
            .success = false,
            .tool_call_id = call.tool_call_id,
            .approval_boundary = true,
        };
    }

    fn executeTool(self: *Agent, tool_allocator: std.mem.Allocator, call: ParsedToolCall) ToolExecutionResult {
        return self.executeToolWithOptions(tool_allocator, call, .{});
    }

    fn executeToolWithOptions(
        self: *Agent,
        tool_allocator: std.mem.Allocator,
        call: ParsedToolCall,
        options: ToolExecutionOptions,
    ) ToolExecutionResult {
        var parsed = std.json.parseFromSlice(
            std.json.Value,
            tool_allocator,
            call.arguments_json,
            .{},
        ) catch {
            return self.executeToolWithPreparedArguments(
                tool_allocator,
                call,
                options,
                .invalid_json,
            );
        };
        defer parsed.deinit();

        const prepared: PreparedToolArguments = switch (parsed.value) {
            .object => |object| .{ .object = object },
            else => .non_object,
        };
        return self.executeToolWithPreparedArguments(tool_allocator, call, options, prepared);
    }

    fn executeToolWithPreparedArguments(
        self: *Agent,
        tool_allocator: std.mem.Allocator,
        call: ParsedToolCall,
        options: ToolExecutionOptions,
        prepared: PreparedToolArguments,
    ) ToolExecutionResult {
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
            if (options.record_action) {
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
        }

        const trimmed_call_name = std.mem.trim(u8, call.name, " \t\r\n");

        for (self.tools) |t| {
            if (std.ascii.eqlIgnoreCase(t.name(), trimmed_call_name)) {
                // Placeholders are intentionally passed through unchanged;
                // provider-bound redaction must not become an implicit
                // provider-to-tool rehydration channel.
                const args: std.json.ObjectMap = switch (prepared) {
                    .invalid_json => return .{
                        .name = call.name,
                        .output = "Invalid arguments JSON",
                        .success = false,
                        .tool_call_id = call.tool_call_id,
                    },
                    .non_object => return .{
                        .name = call.name,
                        .output = "Arguments must be a JSON object",
                        .success = false,
                        .tool_call_id = call.tool_call_id,
                    },
                    .object => |object| object,
                };

                // Gate the authoritative matched tool name. Provider output is
                // whitespace-tolerant for lookup, so checking the raw call name
                // would let ` shell ` bypass exec approval and policy checks.
                if (isExecToolName(t.name())) {
                    // `/bash` keeps its explicit slash-command approval UX;
                    // model-issued shell calls use the structured WebChannel
                    // flow so the tool batch can suspend before later effects.
                    if (!options.approved and
                        self.exec_ask == .always and
                        self.exec_host != .node and
                        self.exec_security != .deny and
                        self.approval_callback != null and
                        self.approval_ctx != null and
                        tools_mod.getString(args, "command") != null)
                    {
                        self.queueToolCallApproval(tool_allocator, t.name(), call, args) catch |approval_err| {
                            return approvalFailureResult(call, approval_err);
                        };
                        return .{
                            .name = call.name,
                            .output = "Approval pending",
                            .success = false,
                            .tool_call_id = call.tool_call_id,
                            .approval_boundary = true,
                        };
                    }
                    if (self.execBlockMessageWithOptions(args, options.approved)) |msg| {
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
                const previous_memory_session_id = tools_mod.setThreadMemorySessionId(self.memory_session_id);
                defer _ = tools_mod.setThreadMemorySessionId(previous_memory_session_id);
                const previous_approval_grant = tools_mod.setThreadApprovalGrant(if (options.approved) .{
                    .tool_name = t.name(),
                    .command = tools_mod.getString(args, "command"),
                    .cwd = tools_mod.getString(args, "cwd"),
                } else null);
                defer _ = tools_mod.setThreadApprovalGrant(previous_approval_grant);
                const result = t.execute(tool_allocator, args) catch |err| {
                    if (err == error.ApprovalRequired) {
                        if (options.approved) {
                            return .{
                                .name = call.name,
                                .output = "Approved tool invocation requested approval again",
                                .success = false,
                                .tool_call_id = call.tool_call_id,
                            };
                        }
                        self.queueToolCallApproval(tool_allocator, t.name(), call, args) catch |approval_err| {
                            return approvalFailureResult(call, approval_err);
                        };
                        return .{
                            .name = call.name,
                            .output = "Approval pending",
                            .success = false,
                            .tool_call_id = call.tool_call_id,
                            .approval_boundary = true,
                        };
                    }
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
                    if (result.success) {
                        const safe_output = self.safeToolDiagnosticText(tool_allocator, result.output);
                        const output_preview = previewText(safe_output, 256);
                        log.info("tool result: name={s} success={} output_len={d} output={s}{s}", .{
                            call.name,
                            result.success,
                            result.output.len,
                            output_preview.slice,
                            if (output_preview.truncated) "..." else "",
                        });
                    } else {
                        const error_msg = result.error_msg orelse result.output;
                        const safe_error = self.safeToolDiagnosticText(tool_allocator, error_msg);
                        const error_preview = previewText(safe_error, 256);
                        log.info("tool result: name={s} success={} error={s}{s}", .{
                            call.name,
                            result.success,
                            error_preview.slice,
                            if (error_preview.truncated) "..." else "",
                        });
                    }
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

    fn previewText(text: []const u8, max_bytes: usize) TextPreview {
        const preview = util.previewUtf8(text, max_bytes);
        return .{
            .slice = preview.slice,
            .truncated = preview.truncated,
        };
    }

    fn llmLogPreview(text: []const u8) TextPreview {
        return previewText(text, LLM_LOG_MAX_BYTES);
    }

    fn diagnosticText(self: *Agent, allocator: std.mem.Allocator, text: []const u8) []const u8 {
        const r = self.redactor orelse return text;
        return r.redact(allocator, text) catch "[redaction failed]";
    }

    fn safeToolDiagnosticText(self: *Agent, allocator: std.mem.Allocator, text: []const u8) []const u8 {
        const scrubbed = providers.scrubToolOutput(allocator, text) catch text;
        return self.diagnosticText(allocator, scrubbed);
    }

    test "previewText keeps UTF-8 intact when truncating" {
        const preview = previewText("aaa\xd0\x99tail", 4);
        try std.testing.expectEqualStrings("aaa", preview.slice);
        try std.testing.expect(preview.truncated);
        try std.testing.expect(std.unicode.utf8ValidateSlice(preview.slice));
    }

    test "safeToolDiagnosticText scrubs PII and tokens" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var redactor = redaction.Redactor.init(allocator, .{});
        defer redactor.deinit();

        var noop = observability.NoopObserver{};
        var agent = Agent{
            .allocator = allocator,
            .provider = undefined,
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
            .redactor = &redactor,
        };
        defer {
            agent.redactor = null;
            agent.deinit();
        }

        const safe = agent.safeToolDiagnosticText(arena.allocator(), "row email=user@example.com api_key=sk-live-secret");
        try std.testing.expect(std.mem.indexOf(u8, safe, "user@example.com") == null);
        try std.testing.expect(std.mem.indexOf(u8, safe, "sk-live-secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, safe, "[EMAIL_1]") != null);
    }

    fn llmRequestObserverDetail(self: *Agent, allocator: std.mem.Allocator, buf: []u8, messages: []const ChatMessage) ?[]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        const max_messages = @min(messages.len, 6);
        for (messages[0..max_messages], 0..) |msg, idx| {
            const safe_content = self.diagnosticText(allocator, msg.content);
            const preview = previewText(safe_content, 240);
            const parts_count: usize = if (msg.content_parts) |parts| parts.len else 0;
            w.print(
                "#{d} role={s} bytes={d} parts={d} content={f}{s}",
                .{
                    idx + 1,
                    msg.role.toSlice(),
                    msg.content.len,
                    parts_count,
                    std.json.fmt(preview.slice, .{}),
                    if (preview.truncated) " [truncated]" else "",
                },
            ) catch break;
            if (idx + 1 < max_messages) {
                w.writeByte('\n') catch break;
            }
        }
        if (messages.len > max_messages) {
            w.print("\n... {d} more messages", .{messages.len - max_messages}) catch {};
        }
        const written = w.buffered();
        if (written.len == 0) return null;
        return written;
    }

    fn llmResponseObserverDetail(self: *Agent, allocator: std.mem.Allocator, buf: []u8, response: *const ChatResponse) ?[]const u8 {
        var w: std.Io.Writer = .fixed(buf);

        const content = response.contentOrEmpty();
        const safe_content = self.diagnosticText(allocator, content);
        const content_preview = previewText(safe_content, 400);
        w.print(
            "content_bytes={d} content={f}{s}",
            .{
                content.len,
                std.json.fmt(content_preview.slice, .{}),
                if (content_preview.truncated) " [truncated]" else "",
            },
        ) catch return null;

        if (response.reasoning_content) |reasoning| {
            const safe_reasoning = self.diagnosticText(allocator, reasoning);
            const reasoning_preview = previewText(safe_reasoning, 240);
            w.print(
                "\nreasoning_bytes={d} reasoning={f}{s}",
                .{
                    reasoning.len,
                    std.json.fmt(reasoning_preview.slice, .{}),
                    if (reasoning_preview.truncated) " [truncated]" else "",
                },
            ) catch {};
        }

        const max_tool_calls = @min(response.tool_calls.len, 4);
        for (response.tool_calls[0..max_tool_calls], 0..) |tc, idx| {
            const safe_args = self.diagnosticText(allocator, tc.arguments);
            const args_preview = previewText(safe_args, 200);
            w.print(
                "\ntool#{d} id={s} name={s} args={f}{s}",
                .{
                    idx + 1,
                    if (tc.id.len > 0) tc.id else "-",
                    tc.name,
                    std.json.fmt(args_preview.slice, .{}),
                    if (args_preview.truncated) " [truncated]" else "",
                },
            ) catch {};
        }
        if (response.tool_calls.len > max_tool_calls) {
            w.print("\n... {d} more tool calls", .{response.tool_calls.len - max_tool_calls}) catch {};
        }

        const written = w.buffered();
        if (written.len == 0) return null;
        return written;
    }

    fn toolArgsObserverDetail(buf: []u8, arguments_json: []const u8) ?[]const u8 {
        const preview = previewText(arguments_json, @min(buf.len, 512));
        if (preview.slice.len == 0) return null;
        var w: std.Io.Writer = .fixed(buf);
        w.print("{f}{s}", .{
            std.json.fmt(preview.slice, .{}),
            if (preview.truncated) " [truncated]" else "",
        }) catch return null;
        return w.buffered();
    }

    fn toolResultObserverDetail(buf: []u8, output: []const u8) ?[]const u8 {
        const preview = previewText(output, @min(buf.len, 512));
        if (preview.slice.len == 0) return null;
        var w: std.Io.Writer = .fixed(buf);
        w.print("{f}{s}", .{
            std.json.fmt(preview.slice, .{}),
            if (preview.truncated) " [truncated]" else "",
        }) catch return null;
        return w.buffered();
    }

    fn recordLlmRequestEvent(self: *Agent, model_name: []const u8, messages: []const ChatMessage) void {
        var detail_buf: [2048]u8 = undefined;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const event = ObserverEvent{ .llm_request = .{
            .provider = self.provider.getName(),
            .model = model_name,
            .messages_count = messages.len,
            .detail = if (self.log_llm_io) self.llmRequestObserverDetail(arena.allocator(), &detail_buf, messages) else null,
        } };
        self.observer.recordEvent(&event);
    }

    fn recordLlmResponseEvent(self: *Agent, model_name: []const u8, duration_ms: u64, response: *const ChatResponse) void {
        var detail_buf: [2048]u8 = undefined;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const event = ObserverEvent{ .llm_response = .{
            .provider = self.provider.getName(),
            .model = model_name,
            .duration_ms = duration_ms,
            .success = true,
            .error_message = null,
            .prompt_tokens = response.usage.prompt_tokens,
            .completion_tokens = response.usage.completion_tokens,
            .total_tokens = response.usage.total_tokens,
            .detail = if (self.log_llm_io) self.llmResponseObserverDetail(arena.allocator(), &detail_buf, response) else null,
        } };
        self.observer.recordEvent(&event);
    }

    fn recordLlmFailureEvent(self: *Agent, model_name: []const u8, duration_ms: u64, err_name: []const u8) void {
        const event = ObserverEvent{ .llm_response = .{
            .provider = self.provider.getName(),
            .model = model_name,
            .duration_ms = duration_ms,
            .success = false,
            .error_message = err_name,
        } };
        self.observer.recordEvent(&event);
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
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
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
            const safe_content = self.diagnosticText(arena, msg.content);
            const preview = llmLogPreview(safe_content);
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
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const session_hash: u64 = if (self.memory_session_id) |sid| std.hash.Wyhash.hash(0, sid) else 0;
        const content = response.contentOrEmpty();
        const safe_content = self.diagnosticText(arena, content);
        const preview = llmLogPreview(safe_content);
        const reasoning_returned = response.reasoning_content != null and response.reasoning_content.?.len > 0;
        const reasoning_requested = self.reasoning_mode != .off;
        log.info(
            "llm response session=0x{x} iter={d} attempt={d} provider={s} model={s} bytes={d} tool_calls={d} reasoning_mode={s} reasoning_effort={s} reasoning_requested={} reasoning_returned={} usage={f} content={f}{s}",
            .{
                session_hash,
                iteration,
                attempt,
                self.effectiveProvider(response),
                self.effectiveModel(response),
                content.len,
                response.tool_calls.len,
                self.reasoning_mode.toSlice(),
                self.reasoning_effort orelse "off",
                reasoning_requested,
                reasoning_returned,
                std.json.fmt(response.usage, .{}),
                std.json.fmt(preview.slice, .{}),
                if (preview.truncated) " [log preview truncated]" else "",
            },
        );

        // NOTE: Logging-only path. No direct unit test added because verifying structured
        // log emission here would require a log sink harness for Agent runtime logging.
        if (reasoning_requested and !reasoning_returned) {
            log.info(
                "llm response reasoning missing session=0x{x} iter={d} attempt={d} provider={s} model={s} reasoning_mode={s} reasoning_effort={s}",
                .{
                    session_hash,
                    iteration,
                    attempt,
                    self.effectiveProvider(response),
                    self.effectiveModel(response),
                    self.reasoning_mode.toSlice(),
                    self.reasoning_effort orelse "off",
                },
            );
        }

        if (response.reasoning_content) |reasoning| {
            const safe_reasoning = self.diagnosticText(arena, reasoning);
            const r_preview = llmLogPreview(safe_reasoning);
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
            const safe_args = self.diagnosticText(arena, tc.arguments);
            const args_preview = llmLogPreview(safe_args);
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
            .ts = std_compat.time.timestamp(),
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

    fn buildProviderMessagesForTurn(
        self: *Agent,
        arena: std.mem.Allocator,
        model_name: []const u8,
        priority_tool: ?[]const u8,
    ) ![]ChatMessage {
        const raw: []ChatMessage = blk: {
            const messages = try self.buildProviderMessages(arena, model_name);
            const tool_name = priority_tool orelse break :blk messages;

            var i = messages.len;
            while (i > 0) {
                i -= 1;
                if (messages[i].role != .user) continue;
                if (messages[i].content_parts != null) break :blk messages;

                const with_hint = try arena.dupe(ChatMessage, messages);
                with_hint[i].content = try std.fmt.allocPrint(
                    arena,
                    "[PRIORITY: Please call the {s} tool immediately] {s}",
                    .{ tool_name, messages[i].content },
                );
                break :blk with_hint;
            }

            break :blk messages;
        };

        // Optional pre-provider PII redaction. Same Redactor instance is reused
        // across turns so a given email/card maps to the same placeholder id
        // throughout the conversation. The redacted slices live on `arena`
        // (per-turn), while Redactor state stays on `self.allocator`.
        if (self.redactor) |r| {
            return try redactMessagesForProvider(arena, raw, r);
        }
        return raw;
    }

    pub fn redactMessagesForProvider(
        arena: std.mem.Allocator,
        messages: []const ChatMessage,
        redactor: *redaction.Redactor,
    ) ![]ChatMessage {
        const out = try arena.alloc(ChatMessage, messages.len);
        for (messages, 0..) |msg, i| {
            out[i] = msg;
            if (msg.content.len > 0) {
                out[i].content = try redactor.redact(arena, msg.content);
            }
            if (msg.content_parts) |parts| {
                out[i].content_parts = try redactContentParts(arena, parts, redactor);
            }
        }
        return out;
    }

    fn redactContentParts(
        arena: std.mem.Allocator,
        parts: []const ContentPart,
        redactor: *redaction.Redactor,
    ) ![]ContentPart {
        const out = try arena.alloc(ContentPart, parts.len);
        for (parts, 0..) |p, i| {
            out[i] = switch (p) {
                .text => |t| ContentPart{ .text = try redactor.redact(arena, t) },
                .image_url => |img| try redactImageUrlPart(arena, img, redactor),
                .image_base64 => p,
            };
        }
        return out;
    }

    fn redactImageUrlPart(
        arena: std.mem.Allocator,
        img: ContentPart.ImageUrl,
        redactor: *redaction.Redactor,
    ) !ContentPart {
        if (urlHasQueryOrFragment(img.url)) {
            return ContentPart{ .text = "[Remote image URL not sent to provider: query/fragment credentials are not forwarded]" };
        }
        if (redactor.wouldRedact(img.url)) {
            return ContentPart{ .text = "[Remote image URL not sent to provider: URL contains sensitive data]" };
        }
        return ContentPart{ .image_url = .{
            .url = try redactor.redact(arena, img.url),
            .detail = img.detail,
        } };
    }

    fn urlHasQueryOrFragment(url: []const u8) bool {
        return std.mem.indexOfScalar(u8, url, '?') != null or
            std.mem.indexOfScalar(u8, url, '#') != null;
    }

    fn appendMultimodalAllowedDir(
        arena: std.mem.Allocator,
        dirs: *std.ArrayListUnmanaged([]const u8),
        raw_dir: []const u8,
    ) !void {
        const trimmed = std_compat.mem.trimRight(u8, raw_dir, "/\\");
        if (trimmed.len == 0) return;

        if (!containsMultimodalDir(dirs.items, trimmed)) {
            try dirs.append(arena, trimmed);
        }

        // Add canonical path variant too (/var <-> /private/var on macOS).
        const canonical = std_compat.fs.realpathAlloc(arena, trimmed) catch return;
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
        if (self.redactor) |r| r.reset();
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
    /// Entries remain borrowed; the agent duplicates projected content.
    pub fn loadHistory(self: *Agent, entries: anytype) !void {
        const projected = try memory_mod.projectSessionMessages(self.allocator, entries);
        defer memory_mod.freeMessages(self.allocator, projected);
        for (projected) |entry| {
            if (memory_mod.isRuntimeCommandRole(entry.role)) continue;
            const role: providers.Role = if (std.mem.eql(u8, entry.role, "assistant"))
                .assistant
            else if (std.mem.eql(u8, entry.role, "system"))
                .system
            else
                .user;
            const owned_content = try self.allocator.dupe(u8, entry.content);
            errdefer self.allocator.free(owned_content);
            try self.history.append(self.allocator, .{
                .role = role,
                .content = owned_content,
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

test "Agent loadHistory projects completed tool checkpoints" {
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

    const completion = try std.fmt.allocPrint(
        allocator,
        "{s}\n{{\"original_user\":\"run probe\",\"assistant_response\":\"probe complete\"}}",
        .{memory_mod.TOOL_TURN_COMPLETION_CHECKPOINT},
    );
    defer allocator.free(completion);
    const raw = [_]memory_mod.MessageEntry{
        .{ .role = memory_mod.RUNTIME_COMMAND_ROLE, .content = "/usage full" },
        .{
            .role = memory_mod.TOOL_TURN_CHECKPOINT_ROLE,
            .content = memory_mod.TOOL_TURN_WRITE_AHEAD_CHECKPOINT,
        },
        .{ .role = memory_mod.TOOL_TURN_CHECKPOINT_ROLE, .content = completion },
    };

    try agent.loadHistory(&raw);
    try std.testing.expectEqual(@as(usize, 2), agent.historyLen());
    try std.testing.expectEqual(providers.Role.user, agent.history.items[0].role);
    try std.testing.expectEqualStrings("run probe", agent.history.items[0].content);
    try std.testing.expectEqual(providers.Role.assistant, agent.history.items[1].role);
    try std.testing.expectEqualStrings("probe complete", agent.history.items[1].content);
}

fn loadHistoryAllocationHarness(allocator: std.mem.Allocator) !void {
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
    };
    defer agent.deinit();

    const completion = try std.fmt.allocPrint(
        allocator,
        "{s}\n{{\"original_user\":\"first\",\"assistant_response\":\"second\"}}",
        .{memory_mod.TOOL_TURN_COMPLETION_CHECKPOINT},
    );
    defer allocator.free(completion);
    const raw = [_]memory_mod.MessageEntry{
        .{ .role = memory_mod.TOOL_TURN_CHECKPOINT_ROLE, .content = memory_mod.TOOL_TURN_WRITE_AHEAD_CHECKPOINT },
        .{ .role = memory_mod.TOOL_TURN_CHECKPOINT_ROLE, .content = completion },
        .{ .role = "assistant", .content = "third" },
    };
    try agent.loadHistory(&raw);
    try std.testing.expectEqual(@as(usize, 3), agent.historyLen());
}

test "Agent loadHistory frees partial projection on every allocation failure" {
    // Regression: an append failure after duplicating one projected message
    // must not leak either the duplicate or earlier history entries.
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        loadHistoryAllocationHarness,
        .{},
    );
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

// Minimal provider that returns a fixed summary and counts invocations,
// used to observe whether maybeAutoCompactHistory reached the summarizer.
const CompactionTestProvider = struct {
    calls: usize = 0,

    fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
        return allocator.dupe(u8, "");
    }
    fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
        const self: *CompactionTestProvider = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return .{ .content = try allocator.dupe(u8, "auto summary") };
    }
    fn supportsNativeTools(_: *anyopaque) bool {
        return false;
    }
    fn getName(_: *anyopaque) []const u8 {
        return "compaction-test-provider";
    }
    fn deinit(_: *anyopaque) void {}

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystem,
        .chat = chat,
        .supportsNativeTools = supportsNativeTools,
        .getName = getName,
        .deinit = deinit,
    };
};

fn makeCompactionTestAgent(allocator: std.mem.Allocator, observer: anytype, provider: Provider, compact_context: bool) Agent {
    return Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = &.{},
        .mem = null,
        .observer = observer,
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 10,
        .max_history_messages = 4,
        .auto_save = false,
        .compact_context = compact_context,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
        .token_limit = 0,
    };
}

fn fillOverThreshold(allocator: std.mem.Allocator, agent: *Agent) !void {
    try agent.history.append(allocator, .{ .role = .system, .content = try allocator.dupe(u8, "system prompt") });
    for (0..12) |i| {
        try agent.history.append(allocator, .{ .role = .user, .content = try std.fmt.allocPrint(allocator, "message {d}", .{i}) });
        try agent.history.append(allocator, .{ .role = .assistant, .content = try std.fmt.allocPrint(allocator, "reply {d}", .{i}) });
    }
}

test "maybeAutoCompactHistory skips compaction when compact_context is false (regression #937)" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var provider_state = CompactionTestProvider{};
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &CompactionTestProvider.vtable };

    var agent = makeCompactionTestAgent(allocator, noop.observer(), provider, false);
    defer agent.deinit();
    try fillOverThreshold(allocator, &agent);

    const len_before = agent.history.items.len;
    const compacted = agent.maybeAutoCompactHistory();

    // Flag is off: history is left untouched and the summarizer is never called,
    // even though the message count is well over max_history_messages.
    try std.testing.expect(!compacted);
    try std.testing.expectEqual(len_before, agent.history.items.len);
    try std.testing.expectEqual(@as(usize, 0), provider_state.calls);
}

test "maybeAutoCompactHistory compacts when compact_context is true" {
    const allocator = std.testing.allocator;
    var noop = observability.NoopObserver{};
    var provider_state = CompactionTestProvider{};
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &CompactionTestProvider.vtable };

    var agent = makeCompactionTestAgent(allocator, noop.observer(), provider, true);
    defer agent.deinit();
    try fillOverThreshold(allocator, &agent);

    const len_before = agent.history.items.len;
    const compacted = agent.maybeAutoCompactHistory();

    // Flag is on: the same over-threshold history is compacted and the
    // summarizer is invoked, shrinking the message count.
    try std.testing.expect(compacted);
    try std.testing.expect(agent.history.items.len < len_before);
    try std.testing.expect(provider_state.calls > 0);
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
        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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
        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "dummy";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{
        .sub_path = "screen.png",
        .data = "\x89PNG\x0d\x0a\x1a\x0a",
    });

    const allocator = std.testing.allocator;
    const workspace_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(allocator, ".");
    defer allocator.free(workspace_path);
    const image_path = try std_compat.fs.path.join(allocator, &.{ workspace_path, "screen.png" });
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

const RecordingObserver = struct {
    const Self = @This();

    llm_request_count: usize = 0,
    llm_response_count: usize = 0,
    llm_failure_count: usize = 0,
    tool_iterations_exhausted_count: usize = 0,
    turn_complete_count: usize = 0,
    tokens_used_metric_total: u64 = 0,
    last_llm_response_total_tokens: ?u32 = null,
    llm_request_message_counts: [8]usize = [_]usize{0} ** 8,
    llm_request_message_counts_len: usize = 0,
    tool_call_count: usize = 0,
    last_tool_detail: [512]u8 = undefined,
    last_tool_detail_len: usize = 0,
    last_llm_response_detail: [512]u8 = undefined,
    last_llm_response_detail_len: usize = 0,

    const vtable = Observer.VTable{
        .record_event = recordEvent,
        .record_metric = recordMetric,
        .flush = flush,
        .name = getName,
        .get_trace_id = getTraceId,
        .set_trace_id = setTraceId,
    };

    fn observer(self: *Self) Observer {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn resolve(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }

    fn recordEvent(ptr: *anyopaque, event: *const ObserverEvent) void {
        const self = resolve(ptr);
        switch (event.*) {
            .llm_request => |e| {
                self.llm_request_count += 1;
                if (self.llm_request_message_counts_len < self.llm_request_message_counts.len) {
                    self.llm_request_message_counts[self.llm_request_message_counts_len] = e.messages_count;
                    self.llm_request_message_counts_len += 1;
                }
            },
            .llm_response => |e| {
                self.llm_response_count += 1;
                if (!e.success) self.llm_failure_count += 1;
                self.last_llm_response_total_tokens = e.total_tokens;
                if (e.detail) |detail| {
                    const len = @min(detail.len, self.last_llm_response_detail.len);
                    @memcpy(self.last_llm_response_detail[0..len], detail[0..len]);
                    self.last_llm_response_detail_len = len;
                }
            },
            .tool_iterations_exhausted => {
                self.tool_iterations_exhausted_count += 1;
            },
            .turn_complete => {
                self.turn_complete_count += 1;
            },
            .tool_call => |e| {
                self.tool_call_count += 1;
                if (e.detail) |detail| {
                    const len = @min(detail.len, self.last_tool_detail.len);
                    @memcpy(self.last_tool_detail[0..len], detail[0..len]);
                    self.last_tool_detail_len = len;
                }
            },
            else => {},
        }
    }

    fn recordMetric(ptr: *anyopaque, metric: *const observability.ObserverMetric) void {
        const self = resolve(ptr);
        switch (metric.*) {
            .tokens_used => |v| self.tokens_used_metric_total += v,
            else => {},
        }
    }

    fn flush(_: *anyopaque) void {}

    fn getTraceId(_: *anyopaque) ?[32]u8 {
        return null;
    }
    fn setTraceId(_: *anyopaque, _: [32]u8) void {}
    fn getName(_: *anyopaque) []const u8 {
        return "recording-test";
    }
};

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
        captured_system: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (request.messages.len > 0 and request.messages[0].role == .system) {
                if (self.captured_system) |old| self.capture_alloc.free(old);
                self.captured_system = try self.capture_alloc.dupe(u8, request.messages[0].content);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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
    var provider_state = CaptureProvider{ .capture_alloc = allocator };
    defer if (provider_state.captured_system) |c| allocator.free(c);
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

test "Agent.fromConfig applies compact_context flag" {
    // Regression: #937. Parsed `agent.compact_context = false` must reach the
    // runtime Agent so proactive compaction can be skipped.
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.compact_context = false;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expect(!agent.compact_context);
    try std.testing.expect(!agent.maybeAutoCompactHistory());
}

test "Agent.fromConfig applies default_queue_mode" {
    // Regression: parsing the default is insufficient unless both runtime fields receive it.
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    cfg.agent.default_queue_mode = .latest;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, undefined, &.{}, null, noop.observer());
    defer agent.deinit();

    try std.testing.expectEqual(Agent.QueueMode.latest, agent.default_queue_mode);
    try std.testing.expectEqual(Agent.QueueMode.latest, agent.queue_mode);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

test "turn records llm request for immediate context-compaction retry" {
    const RecoveryProvider = struct {
        const State = struct {
            calls: u32 = 0,
        };

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const state: *State = @ptrCast(@alignCast(ptr));
            state.calls += 1;
            if (state.calls == 1) return error.ContextLengthExceeded;
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "recovery-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = RecoveryProvider.State{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = RecoveryProvider.chatWithSystem,
        .chat = RecoveryProvider.chat,
        .supportsNativeTools = RecoveryProvider.supportsNativeTools,
        .getName = RecoveryProvider.getName,
        .deinit = RecoveryProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

    var observer = RecordingObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &.{},
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = observer.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
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
    for (0..7) |idx| {
        const content = try std.fmt.allocPrint(allocator, "m{d}", .{idx});
        try agent.history.append(allocator, .{
            .role = if (idx % 2 == 0) .user else .assistant,
            .content = content,
        });
    }

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "[Context compacted]") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "recovered") != null);
    try std.testing.expectEqual(@as(u32, 2), provider_state.calls);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_request_count);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_response_count);
    try std.testing.expectEqual(@as(usize, 1), observer.llm_failure_count);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_request_message_counts_len);
    try std.testing.expect(observer.llm_request_message_counts[1] < observer.llm_request_message_counts[0]);
    try std.testing.expectEqual(@as(usize, 1), observer.turn_complete_count);
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
    try std.testing.expectEqualStrings("qianfan", agent.default_provider);
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
    try std.testing.expectEqualStrings("qianfan", agent.default_provider);
    try std.testing.expectEqual(@as(u32, 32_768), agent.max_tokens);
}

test "slash /model preserves custom provider prefix when switching explicit provider model" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.max_tokens = 111;

    const response = (try agent.handleSlashCommand(
        "/model custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model",
    )).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model") != null);
    try std.testing.expectEqualStrings(
        "custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model",
        agent.model_name,
    );
    try std.testing.expectEqualStrings(
        "custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model",
        agent.default_model,
    );
    try std.testing.expectEqualStrings("custom:https://gateway.example.com/proxy/v1/openai/v2", agent.default_provider);
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
    const start_ns = std_compat.time.nanoTimestamp();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const hint = agent.selectRouteHintForTurn("show current status");
        try std.testing.expect(hint != null);
        try std.testing.expectEqualStrings("fast", hint.?);
    }
    const elapsed_ns: u64 = @intCast(std_compat.time.nanoTimestamp() - start_ns);
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

test "slash /model renders interactive choices for telegram sessions" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    const configured_providers = [_]config_types.ProviderEntry{
        .{ .name = "anthropic" },
        .{ .name = "openai" },
    };
    agent.memory_session_id = "telegram:chat123";
    agent.default_provider = "anthropic";
    agent.model_name = "claude-opus-4-6";
    agent.default_model = "claude-opus-4-6";
    agent.configured_providers = &configured_providers;

    const response = (try agent.handleSlashCommand("/model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "<nc_choices>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Choose a provider") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/model provider anthropic") != null);
}

test "slash /model provider renders interactive model choices for selected provider" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    const configured_providers = [_]config_types.ProviderEntry{
        .{ .name = "anthropic" },
        .{ .name = "openai" },
    };
    agent.memory_session_id = "telegram:chat123";
    agent.default_provider = "anthropic";
    agent.model_name = "claude-opus-4-6";
    agent.default_model = "claude-opus-4-6";
    agent.configured_providers = &configured_providers;

    const response = (try agent.handleSlashCommand("/model provider anthropic")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "<nc_choices>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Choose a model") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/model anthropic/claude-sonnet-4-6") != null);
}

test "slash /model with a single configured provider renders models directly" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    const configured_providers = [_]config_types.ProviderEntry{
        .{ .name = "anthropic" },
    };
    agent.memory_session_id = "telegram:chat123";
    agent.default_provider = "anthropic";
    agent.model_name = "claude-opus-4-6";
    agent.default_model = "claude-opus-4-6";
    agent.configured_providers = &configured_providers;

    const response = (try agent.handleSlashCommand("/model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "<nc_choices>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Choose a model") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/model anthropic/claude-sonnet-4-6") != null);
}

test "slash /model renders interactive choices for routed slack sessions" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    const configured_providers = [_]config_types.ProviderEntry{
        .{ .name = "anthropic" },
        .{ .name = "openai" },
    };
    agent.memory_session_id = "agent:slack-ops:main";
    agent.conversation_context = .{ .channel = "slack" };
    agent.default_provider = "anthropic";
    agent.model_name = "claude-opus-4-6";
    agent.default_model = "claude-opus-4-6";
    agent.configured_providers = &configured_providers;

    const response = (try agent.handleSlashCommand("/model")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "<nc_choices>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Choose a provider") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/model provider anthropic") != null);
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
    agent.memory_session_id = "chat-123";

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    // Regression: #917 also affected slash `/memory list` when an agent
    // session was active; global memories must still be visible.
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

test "slash /queue reset restores configured default" {
    // Regression: reset must not hardcode off after a non-off config default.
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.default_queue_mode = .latest;
    agent.queue_mode = .serial;

    const response = (try agent.handleSlashCommand("/queue reset")).?;
    defer allocator.free(response);

    try std.testing.expectEqual(Agent.QueueMode.latest, agent.queue_mode);
    try std.testing.expectEqual(@as(u32, 0), agent.queue_debounce_ms);
    try std.testing.expectEqual(@as(u32, 0), agent.queue_cap);
    try std.testing.expect(agent.queue_drop == .summarize);
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

test "active and interrupted tool names remain owned across allocation failure" {
    // Regression: replacing an active name used to free the old value before
    // duplication, and interrupted-name append could leak when growth failed.
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    try agent.setActiveToolName("existing-tool");

    var replace_failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    agent.allocator = replace_failing.allocator();
    try std.testing.expectError(error.OutOfMemory, agent.setActiveToolName("replacement-tool"));
    agent.allocator = allocator;

    const active = (try agent.snapshotActiveToolName(allocator)).?;
    defer allocator.free(active);
    try std.testing.expectEqualStrings("existing-tool", active);

    for (0..2) |fail_index| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        agent.allocator = failing.allocator();
        try std.testing.expectError(error.OutOfMemory, agent.noteInterruptedTool("shell"));
        agent.allocator = allocator;
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), agent.interrupted_tools.items.len);
    }
}

test "interrupt between tool calls commits completed prefix and skips tail" {
    // Regression: an interrupt observed between calls used to return with the
    // full provider batch in history, no result for the completed side effect,
    // and the remaining calls ambiguously recorded as if they had run.
    const InterruptingPrefixTool = struct {
        const Self = @This();
        agent: ?*Agent = null,
        execution_count: *usize,
        failing: ?*std.testing.FailingAllocator = null,
        arm_oom: bool = false,

        pub const tool_name = "interrupt_prefix_probe";
        pub const tool_description = "Completes once, then requests a turn interrupt";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.execution_count.* += 1;
            const output = try allocator.dupe(u8, "prefix-side-effect-complete");
            self.agent.?.requestInterrupt();
            // Arm persistent OOM only after the simulated side effect and its
            // owned result exist. Closing the canonical prefix must now be
            // entirely allocation-free.
            if (self.arm_oom) {
                if (self.failing) |failing| failing.fail_index = failing.alloc_index;
            }
            return .{ .success = true, .output = output };
        }
    };

    const TailProbeTool = struct {
        const Self = @This();
        execution_count: *usize,

        pub const tool_name = "interrupt_tail_probe";
        pub const tool_description = "Must not execute after an interrupt";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.execution_count.* += 1;
            return .{ .success = true, .output = try allocator.dupe(u8, "tail-side-effect-complete") };
        }
    };

    const BatchProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            const tool_calls = try allocator.alloc(providers.ToolCall, 2);
            tool_calls[0] = .{
                .id = try allocator.dupe(u8, "interrupt-prefix-id"),
                .name = try allocator.dupe(u8, "interrupt_prefix_probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            tool_calls[1] = .{
                .id = try allocator.dupe(u8, "interrupt-tail-id"),
                .name = try allocator.dupe(u8, "interrupt_tail_probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            return .{
                .content = try allocator.dupe(u8, "executing interrupt batch"),
                .tool_calls = tool_calls,
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "interrupt-batch-provider";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    var prefix_execution_count: usize = 0;
    var tail_execution_count: usize = 0;
    var prefix_impl = InterruptingPrefixTool{
        .execution_count = &prefix_execution_count,
        .failing = &failing,
    };
    var tail_impl = TailProbeTool{ .execution_count = &tail_execution_count };
    const tools = [_]Tool{ prefix_impl.tool(), tail_impl.tool() };

    const specs = try allocator.alloc(ToolSpec, tools.len);
    for (tools, 0..) |tool, i| {
        specs[i] = .{
            .name = tool.name(),
            .description = tool.description(),
            .parameters_json = tool.parametersJson(),
        };
    }

    var provider_state = BatchProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = BatchProvider.chatWithSystem,
        .chat = BatchProvider.chat,
        .supportsNativeTools = BatchProvider.supportsNativeTools,
        .getName = BatchProvider.getName,
        .deinit = BatchProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

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
    prefix_impl.agent = &agent;

    const rich_response = try agent.turn("run interrupt batch");
    defer allocator.free(rich_response);

    try std.testing.expect(std.mem.indexOf(u8, rich_response, "Interrupted by /stop") != null);
    try std.testing.expectEqual(@as(usize, 1), prefix_execution_count);
    try std.testing.expectEqual(@as(usize, 0), tail_execution_count);
    try std.testing.expectEqual(@as(usize, 1), provider_state.call_count);

    var found_rich_assistant = false;
    var found_rich_result = false;
    for (agent.history.items) |message| {
        if (message.role == .assistant and
            std.mem.indexOf(u8, message.content, "interrupt_prefix_probe") != null)
        {
            found_rich_assistant = true;
            try std.testing.expect(std.mem.indexOf(u8, message.content, "interrupt_tail_probe") == null);
        }
        if (message.role == .user and
            std.mem.indexOf(u8, message.content, "prefix-side-effect-complete") != null)
        {
            found_rich_result = true;
            try std.testing.expect(std.mem.indexOf(u8, message.content, "tail-side-effect-complete") == null);
        }
    }
    try std.testing.expect(found_rich_assistant);
    try std.testing.expect(found_rich_result);
    try std.testing.expectEqualStrings(rich_response, agent.history.items[agent.history.items.len - 1].content);

    prefix_impl.arm_oom = true;
    const response = try agent.turn("run interrupt batch under memory pressure");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Interrupted by /stop") != null);
    try std.testing.expectEqual(@as(usize, 2), prefix_execution_count);
    try std.testing.expectEqual(@as(usize, 0), tail_execution_count);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(failing.has_induced_failure);

    var found_prefix_assistant = false;
    var found_prefix_result = false;
    for (agent.history.items) |message| {
        if (message.role == .assistant and
            std.mem.indexOf(u8, message.content, "tool batch was interrupted") != null)
        {
            found_prefix_assistant = true;
            try std.testing.expect(std.mem.indexOf(u8, message.content, "interrupt_tail_probe") == null);
        }
        if (message.role == .user and
            std.mem.indexOf(u8, message.content, "status=\"memory_pressure\"") != null)
        {
            found_prefix_result = true;
            try std.testing.expect(std.mem.indexOf(u8, message.content, "tail-side-effect-complete") == null);
        }
    }
    try std.testing.expect(found_prefix_assistant);
    try std.testing.expect(found_prefix_result);
    try std.testing.expectEqualStrings(response, agent.history.items[agent.history.items.len - 1].content);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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
                std_compat.thread.sleep(10 * std.time.ns_per_ms);
            }
            std_compat.thread.sleep(80 * std.time.ns_per_ms);
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
        // Regression: an interrupt requested by the only tool on the final
        // allowed iteration must return now, without a summary provider call.
        .max_tool_iterations = 1,
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

test "direct slash bash waits for durable tool barrier" {
    // Regression: /bash bypasses the provider tool loop, but must not execute
    // its shell tool when the caller cannot establish a durable write-ahead
    // fence first.
    const DirectShellProbe = struct {
        execution_count: usize = 0,

        pub const tool_name = "shell";
        pub const tool_description = "Direct slash barrier regression tool";
        pub const tool_params =
            \\{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}
        ;
        const vtable = tools_mod.ToolVTable(@This());

        fn tool(self: *@This()) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *@This(), _: std.mem.Allocator, _: std.json.ObjectMap) !tools_mod.ToolResult {
            self.execution_count += 1;
            return tools_mod.ToolResult.ok("unexpected execution");
        }
    };
    const BarrierProbe = struct {
        calls: usize = 0,

        fn callback(ctx: *anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return error.InjectedToolFenceFailure;
        }
    };

    const allocator = std.testing.allocator;
    var shell_impl = DirectShellProbe{};
    const shell_tools = [_]Tool{shell_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &shell_tools, noop.observer(), &capture);
    defer agent.deinit();
    var barrier = BarrierProbe{};
    agent.before_tool_dispatch_cb = BarrierProbe.callback;
    agent.before_tool_dispatch_ctx = @ptrCast(&barrier);

    try std.testing.expectError(
        error.InjectedToolFenceFailure,
        agent.handleSlashCommand("/bash guarded-command"),
    );
    try std.testing.expectEqual(@as(usize, 1), barrier.calls);
    try std.testing.expectEqual(@as(usize, 0), shell_impl.execution_count);
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
    agent.default_queue_mode = .latest;
    agent.queue_mode = .serial;
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
    // Regression: /restart clears overrides but keeps the configured queue default.
    try std.testing.expectEqual(Agent.QueueMode.latest, agent.queue_mode);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

    try std.testing.expect(std.mem.indexOf(u8, response, "Reasoning:\n> thinking trace") != null);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("SOUL.md", .{});
        defer f.close();
        try f.writeAll("SOUL-V1");
    }

    const workspace = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("SOUL.md", .{ .truncate = true });
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("TOOLS.md", .{});
        defer f.close();
        try f.writeAll("TOOLS-V1");
    }

    const workspace = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("TOOLS.md", .{ .truncate = true });
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** USER-V1");
    }

    const workspace = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("USER.md", .{ .truncate = true });
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "reload-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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
        // Regression: lookup trims provider tool names; the approval gate must
        // use the matched tool identity instead of this untrusted spelling.
        .name = " shell ",
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
    var capture = ApprovalCapture{};
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
        .approval_callback = ApprovalCapture.callback,
        .approval_ctx = @ptrCast(&capture),
    };
    defer agent.deinit();

    const cmd_resp = (try agent.handleSlashCommand("/exec ask=always")).?;
    defer allocator.free(cmd_resp);

    const call = ParsedToolCall{
        .name = "\tShell \n",
        .arguments_json = "{\"command\":\"```bash\\necho hello\\n```\",\"cwd\":\"/tmp/work-a\"}",
        .tool_call_id = null,
    };
    const result = agent.executeTool(allocator, call);

    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Approval pending", result.output);
    try std.testing.expect(agent.pending_approval != null);
    try std.testing.expect(agent.pending_exec_command == null);
    try emitPreparedApprovalForTest(&agent);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    // Regression: the prompt and risk evaluation must describe the same
    // normalized command ShellTool will execute, while the grant stays exact.
    try std.testing.expectEqualStrings("echo hello (cwd: /tmp/work-a)", agent.pending_approval.?.action);
}

test "exec ask always preserves legacy approval without structured sink" {
    // Regression: CLI and non-Web channels do not install an approval sink;
    // model-issued shell calls must retain the existing `/approve` workflow.
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
    const result = agent.executeTool(allocator, .{
        .name = "shell",
        .arguments_json = "{\"command\":\"echo hello\"}",
        .tool_call_id = "cli-shell-call",
    });

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Use /approve") != null);
    try std.testing.expect(agent.pending_approval == null);
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
        "/config reload",
        "/config get model",
        "/skills",
        "/skill reload",
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

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = try agent.handleSlashCommand("/newsdigest latest ai news");
    try std.testing.expect(response == null);
}

test "direct slash skill command reports ambiguous normalized alias" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news_ digest");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news_ digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news_ digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect other news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Ambiguous skill name") != null);
}

test "direct slash skill command does not shadow built in doctor" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/doctor");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/doctor/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/doctor/SKILL.md", .{});
        defer f.close();
        try f.writeAll("This should not shadow /doctor.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
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

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news");
    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news/SKILL.md", .{});
        defer f.close();
        try f.writeAll("General news skill body.");
    }
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
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
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Digest skill body.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const response = (try agent.handleSlashCommand("/news digest latest ai news")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Ambiguous skill name") != null);
}

test "slash /skill activates session skill and /skill clear removes it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir = std_compat.fs.Dir.wrap(tmp.dir);

    try tmp_dir.makePath("skills/news-digest");
    {
        const f = try tmp_dir.createFile("skills/news-digest/skill.json", .{});
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
        const f = try tmp_dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp_dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    const activate = (try agent.handleSlashCommand("/skill news-digest")).?;
    defer allocator.free(activate);
    try std.testing.expect(std.mem.indexOf(u8, activate, "Active skill set to `news-digest`") != null);
    try std.testing.expectEqualStrings("news-digest", agent.active_skill_name.?);
    try std.testing.expect(!agent.active_skill_interactive);

    const status = (try agent.handleSlashCommand("/skill status")).?;
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "Active skill: news-digest") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "Mode: non-interactive") != null);

    const clear = (try agent.handleSlashCommand("/skill clear")).?;
    defer allocator.free(clear);
    try std.testing.expect(std.mem.indexOf(u8, clear, "cleared") != null);
    try std.testing.expect(agent.active_skill_name == null);
}

test "slash /skills renders telegram choice buttons" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir = std_compat.fs.Dir.wrap(tmp.dir);

    try tmp_dir.makePath("skills/news-digest");
    try tmp_dir.makePath("skills/commit");
    {
        const f = try tmp_dir.createFile("skills/news-digest/skill.json", .{});
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
        const f = try tmp_dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }
    {
        const f = try tmp_dir.createFile("skills/commit/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "commit",
            \\  "description": "Write commit message",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp_dir.createFile("skills/commit/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Create a commit message.");
    }
    try tmp_dir.makePath("skills/gv-homework-util");
    {
        const f = try tmp_dir.createFile("skills/gv-homework-util/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "gv-homework-util",
            \\  "description": "Homework helper",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp_dir.createFile("skills/gv-homework-util/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Help with homework.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp_dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);
    agent.conversation_context = .{
        .channel = "telegram",
        .account_id = "main",
        .peer_id = "-100123:thread:7",
        .group_id = "-100123",
        .is_group = true,
    };

    const response = (try agent.handleSlashCommand("/skills")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Skill browser: 3 available") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<nc_choices>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"columns\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/skills letters a-f") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "/skills prefixes") != null);
}

test "slash /skills exposes letter and prefix browsers for hyphenated skills" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir = std_compat.fs.Dir.wrap(tmp.dir);

    try tmp_dir.makePath("skills/gv-homework-util");
    try tmp_dir.makePath("skills/mb3-critic");
    {
        const f = try tmp_dir.createFile("skills/gv-homework-util/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "gv-homework-util",
            \\  "description": "Homework helper",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp_dir.createFile("skills/gv-homework-util/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Help with homework.");
    }
    {
        const f = try tmp_dir.createFile("skills/mb3-critic/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "mb3-critic",
            \\  "description": "Critic skill",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try tmp_dir.createFile("skills/mb3-critic/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Critique plans.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp_dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);
    agent.conversation_context = .{
        .channel = "telegram",
        .account_id = "main",
        .peer_id = "-100123:thread:7",
        .group_id = "-100123",
        .is_group = true,
    };

    const letters = (try agent.handleSlashCommand("/skills letters g-l")).?;
    defer allocator.free(letters);
    try std.testing.expect(std.mem.indexOf(u8, letters, "/skills letter g") != null);
    try std.testing.expect(std.mem.indexOf(u8, letters, "/skills letter h") != null);

    const prefixes = (try agent.handleSlashCommand("/skills prefixes")).?;
    defer allocator.free(prefixes);
    try std.testing.expect(std.mem.indexOf(u8, prefixes, "/skills prefix gv") != null);
    try std.testing.expect(std.mem.indexOf(u8, prefixes, "/skills prefix mb3") != null);
}

test "active skill session is injected into system prompt" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir = std_compat.fs.Dir.wrap(tmp.dir);

    try tmp_dir.makePath("skills/news-digest");
    {
        const f = try tmp_dir.createFile("skills/news-digest/skill.json", .{});
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
        const f = try tmp_dir.createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news and format digest.");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try tmp_dir.realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);
    agent.conversation_context = .{
        .channel = "telegram",
        .account_id = "main",
        .peer_id = "-100123:thread:7",
        .group_id = "-100123",
        .is_group = true,
    };

    const activate = (try agent.handleSlashCommand("/iskill news-digest")).?;
    defer allocator.free(activate);

    const reply = try agent.turn("Collect today's AI news");
    defer allocator.free(reply);
    try std.testing.expectEqual(@as(usize, 3), agent.history.items.len);
    try std.testing.expectEqual(providers.Role.system, agent.history.items[0].role);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "## Active Skill Session") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Skill: news-digest") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Interaction mode: interactive") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent.history.items[0].content, "Peer ID: -100123:thread:7") != null);
}

test "slash /skill reload invalidates prompt caches" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/broken");
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/broken/skill.json", .{});
        defer f.close();
        try f.writeAll("{ invalid json");
    }

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    agent.workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(agent.workspace_dir);

    agent.has_system_prompt = true;
    agent.system_prompt_has_conversation_context = true;
    agent.workspace_prompt_fingerprint = 1234;
    agent.system_prompt_model_name = try allocator.dupe(u8, "openrouter/gpt-4o");

    const response = (try agent.handleSlashCommand("/skill reload")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Skills reloaded") != null);
    try std.testing.expect(!agent.has_system_prompt);
    try std.testing.expect(!agent.system_prompt_has_conversation_context);
    try std.testing.expect(agent.workspace_prompt_fingerprint == null);
    try std.testing.expect(agent.system_prompt_model_name == null);
}

test "slash /config reload returns summary" {
    const allocator = std.testing.allocator;
    var agent = try makeTestAgent(allocator);
    defer agent.deinit();

    const response = (try agent.handleSlashCommand("/config reload")).?;
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "Config hot reload complete") != null);
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
    try std.testing.expect(agent.progress_callback == null);
    try std.testing.expect(agent.progress_ctx == null);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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
    const timer_start = std_compat.time.milliTimestamp() + 10_000;
    const diff = std_compat.time.milliTimestamp() - timer_start;
    // diff < 0 here; @max(0, diff) must clamp to 0 without panic
    const clamped = @max(0, diff);
    const duration: u64 = @as(u64, @intCast(clamped));
    try std.testing.expectEqual(@as(u64, 0), duration);
}

test "prepared tool arguments apply TOOLS.md dedup sequentially" {
    const calls = [_]ParsedToolCall{
        .{ .name = "file_edit_hashed", .arguments_json = "{\"path\":\"./config/TOOLS.md\",\"target\":\"L4:def\",\"new_text\":\"new\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"pref.tools.file_read_over_cat\",\"content\":\"Always use file_read\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"user.nickname\",\"content\":\"DonPrus\"}" },
        .{ .name = "memory_store", .arguments_json = "{\"key\":\"session.note\",\"content\":\"Rule is documented in TOOLS.md\"}" },
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const prepared = try Agent.prepareToolArgumentsBatch(arena.allocator(), &calls);

    try std.testing.expect(Agent.toolCallUpdatesToolsMdPrepared(calls[0], prepared[0]));
    // A later TOOLS.md write must never suppress an earlier memory_store.
    try std.testing.expect(!Agent.shouldSkipToolsMemoryStoreDuplicatePrepared(false, calls[1], prepared[1]));
    try std.testing.expect(Agent.shouldSkipToolsMemoryStoreDuplicatePrepared(true, calls[1], prepared[1]));
    try std.testing.expect(!Agent.shouldSkipToolsMemoryStoreDuplicatePrepared(true, calls[2], prepared[2]));
    try std.testing.expect(Agent.shouldSkipToolsMemoryStoreDuplicatePrepared(true, calls[3], prepared[3]));
}

test "tool argument batch parsing completes before the first side effect" {
    // Regression: OOM while parsing a later call must occur before an earlier
    // call is allowed to execute. The large second value forces the arena to
    // request more than its initial backing allocation.
    const large_arguments = "{\"content\":\"" ++ ("x" ** 32_768) ++ "\"}";
    const calls = [_]ParsedToolCall{
        .{ .name = "first_effect", .arguments_json = "{\"value\":1}" },
        .{ .name = "later_call", .arguments_json = large_arguments },
    };

    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var arena = std.heap.ArenaAllocator.init(counting.allocator());
        defer arena.deinit();
        _ = try Agent.prepareToolArgumentsBatch(arena.allocator(), &calls);
    }
    const allocation_count = counting.alloc_index;
    try std.testing.expect(allocation_count > 1);

    var observed_late_failure = false;
    for (0..allocation_count) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var arena = std.heap.ArenaAllocator.init(failing.allocator());
        defer arena.deinit();
        var side_effect_count: usize = 0;
        if (Agent.prepareToolArgumentsBatch(arena.allocator(), &calls)) |_| {
            side_effect_count += 1;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 0), side_effect_count);
            if (fail_index > 0) observed_late_failure = true;
        }
        try std.testing.expect(failing.has_induced_failure);
    }
    try std.testing.expect(observed_late_failure);
}

test "toolCallDedupFingerprint prefers tool_call_id over arguments" {
    const call_a = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"pwd\"}",
        .tool_call_id = "call_abc",
    };
    const call_b = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"ls\"}",
        .tool_call_id = "call_abc",
    };
    try std.testing.expectEqual(Agent.toolCallDedupFingerprint(call_a), Agent.toolCallDedupFingerprint(call_b));
}

test "prepared tool receipt reuses repeated calls in same batch" {
    const allocator = std.testing.allocator;
    var seen: ToolCallResultCache = .empty;
    defer Agent.deinitSeenToolCallResults(allocator, &seen);

    const call_a = ParsedToolCall{
        .name = "memory_search",
        .arguments_json = "{\"query\":\"hello\"}",
        .tool_call_id = null,
    };
    const call_b = ParsedToolCall{
        .name = "memory_search",
        .arguments_json = "{\"query\":\"hello\"}",
        .tool_call_id = null,
    };
    const call_c = ParsedToolCall{
        .name = "memory_search",
        .arguments_json = "{\"query\":\"world\"}",
        .tool_call_id = null,
    };

    try std.testing.expect(Agent.cachedToolCallResultInTurn(&seen, call_a) == null);

    try seen.ensureUnusedCapacity(allocator, 1);
    Agent.prepareToolCallResultReceipt(&seen, call_a);
    Agent.finalizePreparedToolCallResultReceipt(allocator, &seen, call_a, .{
        .name = call_a.name,
        .output = "first result",
        .success = true,
        .tool_call_id = null,
    }, false);

    const cached_b = Agent.cachedToolCallResultInTurn(&seen, call_b).?;
    try std.testing.expect(cached_b.success);
    try std.testing.expectEqualStrings("first result", cached_b.output);
    try std.testing.expect(Agent.cachedToolCallResultInTurn(&seen, call_c) == null);
}

test "prepared tool receipt preserves failed result for replayed tool_call_id" {
    const allocator = std.testing.allocator;
    var seen: ToolCallResultCache = .empty;
    defer Agent.deinitSeenToolCallResults(allocator, &seen);

    const original_call = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"curl https://example.com\"}",
        .tool_call_id = "call_retry_me",
    };
    const replayed_call = ParsedToolCall{
        .name = "shell",
        .arguments_json = "{\"command\":\"curl https://example.com --retry 2\"}",
        .tool_call_id = "call_retry_me",
    };

    try seen.ensureUnusedCapacity(allocator, 1);
    Agent.prepareToolCallResultReceipt(&seen, original_call);
    Agent.finalizePreparedToolCallResultReceipt(allocator, &seen, original_call, .{
        .name = original_call.name,
        .output = "Rate limit exceeded",
        .success = false,
        .tool_call_id = original_call.tool_call_id,
    }, false);

    const cached_replay = Agent.cachedToolCallResultInTurn(&seen, replayed_call).?;
    try std.testing.expect(!cached_replay.success);
    try std.testing.expectEqualStrings("Rate limit exceeded", cached_replay.output);
}

test "prepared tool receipt skips failed signature-only calls" {
    const allocator = std.testing.allocator;
    var seen: ToolCallResultCache = .empty;
    defer Agent.deinitSeenToolCallResults(allocator, &seen);

    const failed_call = ParsedToolCall{
        .name = "file_read",
        .arguments_json = "{\"path\":\"missing.txt\"}",
        .tool_call_id = null,
    };

    try seen.ensureUnusedCapacity(allocator, 1);
    Agent.prepareToolCallResultReceipt(&seen, failed_call);
    Agent.finalizePreparedToolCallResultReceipt(allocator, &seen, failed_call, .{
        .name = failed_call.name,
        .output = "FileNotFound",
        .success = false,
        .tool_call_id = null,
    }, false);

    try std.testing.expect(Agent.cachedToolCallResultInTurn(&seen, failed_call) == null);
}

test "prepared tool receipt survives post execution allocation failure" {
    // Regression: a successful call before an approval boundary must retain an
    // exact replay receipt even if copying its rich output runs out of memory.
    const allocator = std.testing.allocator;
    var seen: ToolCallResultCache = .empty;
    defer Agent.deinitSeenToolCallResults(allocator, &seen);
    try seen.ensureUnusedCapacity(allocator, 1);

    const call = ParsedToolCall{
        .name = "side_effect_probe",
        .arguments_json = "{}",
        .tool_call_id = "completed-before-approval",
    };
    Agent.prepareToolCallResultReceipt(&seen, call);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    Agent.finalizePreparedToolCallResultReceipt(failing.allocator(), &seen, call, .{
        .name = call.name,
        .output = "rich side effect result",
        .success = true,
        .tool_call_id = call.tool_call_id,
    }, false);
    try std.testing.expect(failing.has_induced_failure);

    const replay = Agent.cachedToolCallResultInTurn(&seen, call) orelse return error.TestUnexpectedResult;
    try std.testing.expect(replay.success);
    try std.testing.expectEqualStrings(Agent.TOOL_RESULT_RECEIPT_FALLBACK, replay.output);
}

test "approved tool receipt preserves success when rich output allocation fails" {
    // Regression: the approved side effect already ran, so OOM while copying
    // its output must not leave a false failure receipt that invites a retry.
    const allocator = std.testing.allocator;
    var seen: ToolCallResultCache = .empty;
    defer Agent.deinitSeenToolCallResults(allocator, &seen);
    try seen.ensureUnusedCapacity(allocator, 1);

    const call = ParsedToolCall{
        .name = "approved_side_effect_probe",
        .arguments_json = "{}",
        .tool_call_id = "approved-complete",
    };
    Agent.prepareToolCallResultReceipt(&seen, call);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    Agent.updateApprovalToolCallResult(failing.allocator(), &seen, call, .{
        .name = call.name,
        .output = "rich approved result",
        .success = true,
        .tool_call_id = call.tool_call_id,
    });
    try std.testing.expect(failing.has_induced_failure);

    const replay = Agent.cachedToolCallResultInTurn(&seen, call) orelse return error.TestUnexpectedResult;
    try std.testing.expect(replay.success);
    try std.testing.expectEqualStrings(Agent.TOOL_RESULT_RECEIPT_FALLBACK, replay.output);
}

test "Agent turn skips replayed tool_call_id across iterations" {
    const ProbeTool = struct {
        const Self = @This();
        count: *usize,
        pub const tool_name = "probe";
        pub const tool_description = "probe";
        pub const tool_params =
            \\{"type":"object","properties":{"value":{"type":"number"}},"required":["value"]}
        ;
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, _: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            self.count.* += 1;
            return .{ .success = true, .output = "probe ok" };
        }
    };

    const ReplayProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count <= 2) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-replay-1"),
                    .name = try allocator.dupe(u8, "probe"),
                    .arguments = try allocator.dupe(u8, "{\"value\":1}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "replaying"),
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "replay-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = ReplayProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ReplayProvider.chatWithSystem,
        .chat = ReplayProvider.chat,
        .supportsNativeTools = ReplayProvider.supportsNativeTools,
        .getName = ReplayProvider.getName,
        .deinit = ReplayProvider.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var probe_count: usize = 0;
    var probe_tool_impl = ProbeTool{ .count = &probe_count };
    const tool_list = [_]Tool{probe_tool_impl.tool()};

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
        .max_tool_iterations = 5,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("run probe");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("done", response);
    try std.testing.expectEqual(@as(usize, 1), probe_count);
    try std.testing.expectEqual(@as(usize, 3), provider_state.call_count);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

test "Agent tool-limit summary records observer events and token metric" {
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
            return .{ .success = true, .output = try allocator.dupe(u8, "ok") };
        }
    };

    const SummaryProvider = struct {
        const Self = @This();
        calls: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.calls += 1;

            if (self.calls == 1) {
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

            return .{
                .content = try allocator.dupe(u8, "summary"),
                .tool_calls = &.{},
                .usage = .{ .total_tokens = 5 },
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "summary-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = SummaryProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = SummaryProvider.chatWithSystem,
        .chat = SummaryProvider.chat,
        .supportsNativeTools = SummaryProvider.supportsNativeTools,
        .getName = SummaryProvider.getName,
        .deinit = SummaryProvider.deinitFn,
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

    var observer = RecordingObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tool_list,
        .tool_specs = specs,
        .mem = null,
        .observer = observer.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 1,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("trigger summary");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("[Tool iteration limit: 1/1]\n\nsummary", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.calls);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_request_count);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_response_count);
    try std.testing.expectEqual(@as(usize, 0), observer.llm_failure_count);
    try std.testing.expectEqual(@as(usize, 1), observer.tool_iterations_exhausted_count);
    try std.testing.expectEqual(@as(usize, 1), observer.turn_complete_count);
    try std.testing.expectEqual(@as(u64, estimate_text_tokens("running tool") + 5), observer.tokens_used_metric_total);
    try std.testing.expectEqual(@as(?u32, 5), observer.last_llm_response_total_tokens);
    try std.testing.expectEqual(@as(u64, estimate_text_tokens("running tool") + 5), agent.tokensUsed());
    try std.testing.expectEqual(@as(u32, 5), agent.last_turn_usage.total_tokens);
}

test "Agent tool-limit summary records llm failure when summary call fails" {
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
            return .{ .success = true, .output = try allocator.dupe(u8, "ok") };
        }
    };

    const SummaryFailProvider = struct {
        const Self = @This();
        calls: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.calls += 1;

            if (self.calls == 1) {
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

            return error.ProviderFailed;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "summary-fail-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;

    var provider_state = SummaryFailProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = SummaryFailProvider.chatWithSystem,
        .chat = SummaryFailProvider.chat,
        .supportsNativeTools = SummaryFailProvider.supportsNativeTools,
        .getName = SummaryFailProvider.getName,
        .deinit = SummaryFailProvider.deinitFn,
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

    var observer = RecordingObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tool_list,
        .tool_specs = specs,
        .mem = null,
        .observer = observer.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 1,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("trigger summary failure");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("[Tool iteration limit: 1/1] Could not produce a summary. Try /new and repeat your request.", response);
    try std.testing.expectEqual(@as(usize, 2), provider_state.calls);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_request_count);
    try std.testing.expectEqual(@as(usize, 2), observer.llm_response_count);
    try std.testing.expectEqual(@as(usize, 1), observer.llm_failure_count);
    try std.testing.expectEqual(@as(usize, 1), observer.tool_iterations_exhausted_count);
    try std.testing.expectEqual(@as(usize, 1), observer.turn_complete_count);
    try std.testing.expectEqual(@as(u64, estimate_text_tokens("running tool")), observer.tokens_used_metric_total);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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
    try std.testing.expect(Agent.shouldForceActionFollowThrough("I'll look into that for you"));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("I will fetch the file now"));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Let me search for that"));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("I'll run the tool now"));
    // Regression: "let me get/fetch/find" must be caught (was the exact failure mode with vikunja-mcp)
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Found the Workstream Board (project ID 4). Let me get the Kanban columns (buckets) for it."));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Let me fetch the list of projects."));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Let me look up the tasks now."));
}

test "Agent shouldForceActionFollowThrough ignores conclusory english statements" {
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Let me know if you need anything else."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Let me show you how this works with a small example."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Let me list the main tradeoffs before the code."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I will call this helper once during initialization."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I'll use a simple example to explain the flow."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Let me get straight to the point."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I'll note that this is a known limitation."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I will summarize what I found: the directory contains 3 files."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("I cannot do that in this environment."));
}

test "Agent shouldForceActionFollowThrough detects russian deferred promise" {
    try std.testing.expect(Agent.shouldForceActionFollowThrough("Сейчас попробую переснять и отправить файл."));
    try std.testing.expect(Agent.shouldForceActionFollowThrough("сейчас проверю и вернусь с результатом"));
}

test "Agent shouldForceActionFollowThrough ignores russian duration nouns" {
    // Regression: bare words like "минуту" and "секунду" are too broad for
    // substring matching and can appear in ordinary final answers.
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Запустите таймер на минуту."));
    try std.testing.expect(!Agent.shouldForceActionFollowThrough("Пауза должна длиться одну секунду после запуска сервиса."));
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

test "Agent selectDisplayText hides orphan closing tool_call tag" {
    // Model emits </tool_call> without an opener — must not leak to user.
    const raw = "Here are the results:\n</tool_call>\nSome reply";
    const selected = Agent.selectDisplayText(raw, "", 0);
    try std.testing.expectEqualStrings("", selected);

    const bracket_raw = "Here are the results:\n[/tool_call]\nSome reply";
    const bracket_selected = Agent.selectDisplayText(bracket_raw, "", 0);
    try std.testing.expectEqualStrings("", bracket_selected);
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
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

test "Agent retries empty streaming response once" {
    const EmptyThenRecoveredStreamingProvider = struct {
        const Self = @This();

        call_count: usize = 0,
        saw_empty_retry_prompt: bool = false,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return error.ShouldUseStreamChat;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn supportsStreaming(_: *anyopaque) bool {
            return true;
        }

        fn streamChat(
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: providers.ChatRequest,
            _: []const u8,
            _: f64,
            callback: providers.StreamCallback,
            callback_ctx: *anyopaque,
        ) anyerror!providers.StreamChatResult {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 2) {
                for (request.messages) |msg| {
                    if (msg.role == .user and
                        std.mem.indexOf(u8, msg.content, "Your previous reply was empty") != null)
                    {
                        self.saw_empty_retry_prompt = true;
                        break;
                    }
                }
                callback(callback_ctx, providers.StreamChunk.textDelta("recovered"));
                callback(callback_ctx, providers.StreamChunk.finalChunk());
                return .{
                    .content = try allocator.dupe(u8, "recovered"),
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            callback(callback_ctx, providers.StreamChunk.finalChunk());
            return .{
                .content = null,
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "empty-then-recovered-streaming-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const StreamCollector = struct {
        chunks: std.ArrayListUnmanaged(u8) = .empty,

        fn callback(ctx: *anyopaque, chunk: providers.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!chunk.is_final and chunk.delta.len > 0) {
                self.chunks.appendSlice(std.testing.allocator, chunk.delta) catch unreachable;
            }
        }

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.chunks.deinit(allocator);
        }
    };

    const allocator = std.testing.allocator;

    var provider_state = EmptyThenRecoveredStreamingProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = EmptyThenRecoveredStreamingProvider.chatWithSystem,
        .chat = EmptyThenRecoveredStreamingProvider.chat,
        .supportsNativeTools = EmptyThenRecoveredStreamingProvider.supportsNativeTools,
        .getName = EmptyThenRecoveredStreamingProvider.getName,
        .deinit = EmptyThenRecoveredStreamingProvider.deinitFn,
        .supports_streaming = EmptyThenRecoveredStreamingProvider.supportsStreaming,
        .stream_chat = EmptyThenRecoveredStreamingProvider.streamChat,
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

    var collector = StreamCollector{};
    defer collector.deinit(allocator);
    agent.stream_callback = StreamCollector.callback;
    agent.stream_ctx = @ptrCast(&collector);

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("recovered", response);
    try std.testing.expectEqualStrings("recovered", collector.chunks.items);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(provider_state.saw_empty_retry_prompt);
}

test "Agent forces follow-through retry for streaming deferred promise" {
    const DeferredPromiseStreamingProvider = struct {
        const Self = @This();

        call_count: usize = 0,
        saw_follow_through_prompt: bool = false,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return error.ShouldUseStreamChat;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn supportsStreaming(_: *anyopaque) bool {
            return true;
        }

        fn streamChat(
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: providers.ChatRequest,
            _: []const u8,
            _: f64,
            callback: providers.StreamCallback,
            callback_ctx: *anyopaque,
        ) anyerror!providers.StreamChatResult {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;

            if (self.call_count == 2) {
                for (request.messages) |msg| {
                    if (msg.role == .user and
                        std.mem.indexOf(u8, msg.content, "You just promised to take action now") != null)
                    {
                        self.saw_follow_through_prompt = true;
                        break;
                    }
                }
                callback(callback_ctx, providers.StreamChunk.textDelta("I cannot access that tool in this environment."));
                callback(callback_ctx, providers.StreamChunk.finalChunk());
                return .{
                    .content = try allocator.dupe(u8, "I cannot access that tool in this environment."),
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }

            // Regression: A2A streaming replies like this must trigger a follow-up iteration.
            const deferred = "Found the Workstream Board (project ID 4). Let me get the Kanban columns (buckets) for it.";
            callback(callback_ctx, providers.StreamChunk.textDelta(deferred));
            callback(callback_ctx, providers.StreamChunk.finalChunk());
            return .{
                .content = try allocator.dupe(u8, deferred),
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "deferred-promise-streaming-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const StreamCollector = struct {
        chunks: std.ArrayListUnmanaged(u8) = .empty,

        fn callback(ctx: *anyopaque, chunk: providers.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!chunk.is_final and chunk.delta.len > 0) {
                self.chunks.appendSlice(std.testing.allocator, chunk.delta) catch unreachable;
            }
        }

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.chunks.deinit(allocator);
        }
    };

    const allocator = std.testing.allocator;

    var provider_state = DeferredPromiseStreamingProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = DeferredPromiseStreamingProvider.chatWithSystem,
        .chat = DeferredPromiseStreamingProvider.chat,
        .supportsNativeTools = DeferredPromiseStreamingProvider.supportsNativeTools,
        .getName = DeferredPromiseStreamingProvider.getName,
        .deinit = DeferredPromiseStreamingProvider.deinitFn,
        .supports_streaming = DeferredPromiseStreamingProvider.supportsStreaming,
        .stream_chat = DeferredPromiseStreamingProvider.streamChat,
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

    var collector = StreamCollector{};
    defer collector.deinit(allocator);
    agent.stream_callback = StreamCollector.callback;
    agent.stream_ctx = @ptrCast(&collector);

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("I cannot access that tool in this environment.", response);
    try std.testing.expect(std.mem.indexOf(u8, collector.chunks.items, "Let me get the Kanban columns") != null);
    try std.testing.expect(std.mem.indexOf(u8, collector.chunks.items, "I cannot access that tool in this environment.") != null);
    try std.testing.expectEqual(@as(usize, 2), provider_state.call_count);
    try std.testing.expect(provider_state.saw_follow_through_prompt);
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
    var args1: std.json.ObjectMap = .empty;
    defer args1.deinit(allocator);
    try args1.put(allocator, "command", .{ .string = "rm -rf /tmp/test" });
    try std.testing.expect(agent.execBlockMessage(args1) == null);

    var args2: std.json.ObjectMap = .empty;
    defer args2.deinit(allocator);
    try args2.put(allocator, "command", .{ .string = "curl https://example.com" });
    try std.testing.expect(agent.execBlockMessage(args2) == null);

    var args3: std.json.ObjectMap = .empty;
    defer args3.deinit(allocator);
    try args3.put(allocator, "command", .{ .string = "ls -la" });
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
    var args1: std.json.ObjectMap = .empty;
    defer args1.deinit(allocator);
    try args1.put(allocator, "command", .{ .string = "ls -la" });
    try std.testing.expect(agent.execBlockMessage(args1) == null);

    // Disallowed command is blocked
    var args2: std.json.ObjectMap = .empty;
    defer args2.deinit(allocator);
    try args2.put(allocator, "command", .{ .string = "curl https://example.com" });
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
    var args: std.json.ObjectMap = .empty;
    defer args.deinit(allocator);
    try args.put(allocator, "command", .{ .string = "python3 script.py" });
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

test "approval continuation preserves routed model and original dynamic tool trigger" {
    // Regression: #900 the synthetic tool-result text must not replace the
    // original user request for model routing or dynamic MCP tool filtering.
    const ContinuationProvider = struct {
        model_preserved: bool = false,
        task_tool_present: bool = false,
        browser_tool_present: bool = false,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "continued");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.model_preserved = std.mem.eql(u8, request.model, "provider/routed-model") and
                std.mem.eql(u8, model, "provider/routed-model");
            for (request.tools orelse &.{}) |spec| {
                if (std.mem.eql(u8, spec.name, "mcp_vikunja_list_tasks")) self.task_tool_present = true;
                if (std.mem.eql(u8, spec.name, "mcp_browser_open")) self.browser_tool_present = true;
            }
            return .{
                .content = try allocator.dupe(u8, "continued"),
                .usage = .{},
                .model = try allocator.dupe(u8, "provider/routed-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "continuation-provider";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var provider_state = ContinuationProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = ContinuationProvider.chatWithSystem,
        .chat = ContinuationProvider.chat,
        .supportsNativeTools = ContinuationProvider.supportsNativeTools,
        .getName = ContinuationProvider.getName,
        .deinit = ContinuationProvider.deinitFn,
    };
    var noop = observability.NoopObserver{};
    const specs = try allocator.dupe(ToolSpec, &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "mcp_vikunja_list_tasks", .description = "list tasks", .parameters_json = "{}" },
        .{ .name = "mcp_browser_open", .description = "open browser", .parameters_json = "{}" },
    });
    var agent = Agent{
        .allocator = allocator,
        .provider = .{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable },
        .tools = &.{},
        .tool_specs = specs,
        .mem = null,
        .observer = noop.observer(),
        .model_name = "default-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = 2,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .tool_filter_groups = &.{
            .{ .mode = .dynamic, .tools = &.{"mcp_vikunja_*"}, .keywords = &.{"task"} },
            .{ .mode = .dynamic, .tools = &.{"mcp_browser_*"}, .keywords = &.{"browser"} },
        },
    };
    defer agent.deinit();

    var replay_results: ToolCallResultCache = .empty;
    defer deinitToolCallResultCache(allocator, &replay_results);
    const response = try agent.continueAfterApproval(
        "approved execution completed",
        "show my tasks",
        "provider/routed-model",
        "show my tasks",
        &replay_results,
    );
    defer allocator.free(response);
    try std.testing.expectEqualStrings("continued", response);
    try std.testing.expect(provider_state.model_preserved);
    try std.testing.expect(provider_state.task_tool_present);
    try std.testing.expect(!provider_state.browser_tool_present);
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

test "filterToolSpecsForTurn prioritizes triggered custom tools" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "file_read", .description = "read files", .parameters_json = "{}" },
        .{ .name = "calculator", .description = "math", .parameters_json = "{}" },
    };
    agent.tools_config = .{
        .tool_customizations = &.{
            .{ .name = "calculator", .triggers = &.{"calc"}, .priority = 1 },
            .{ .name = "file_read", .triggers = &.{"read"}, .priority = 10 },
        },
    };

    const result = try agent.filterToolSpecsForTurn(arena, "read this file and calc the total");
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("file_read", result[0].name);
    try std.testing.expectEqualStrings("calculator", result[1].name);
    try std.testing.expectEqualStrings("shell", result[2].name);
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "filterToolSpecsForTurn applies trigger modifiers and punctuation" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "file_read", .description = "read files", .parameters_json = "{}" },
    };
    agent.tools_config = .{
        .trigger_modifiers = &.{ "please", "now" },
        .trigger_punctuation = "-!",
        .tool_customizations = &.{
            .{ .name = "file_read", .triggers = &.{"read file"}, .priority = 5 },
        },
    };

    const result = try agent.filterToolSpecsForTurn(arena, "please read-file now!");
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("file_read", result[0].name);
    try std.testing.expectEqualStrings("shell", result[1].name);
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

test "priorityToolForSpecsMessage ignores tools excluded from turn specs" {
    // Regression: priority hints must not ask for a tool that filterToolSpecsForTurn
    // excluded from the current turn's advertised schema.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tool_specs);
    agent.tool_specs = &.{
        .{ .name = "shell", .description = "run shell", .parameters_json = "{}" },
        .{ .name = "mcp_private_lookup", .description = "private lookup", .parameters_json = "{}" },
    };
    const patterns: []const []const u8 = &.{"mcp_private_*"};
    const keywords: []const []const u8 = &.{"lookup"};
    agent.tool_filter_groups = &.{
        .{ .mode = .dynamic, .tools = patterns, .keywords = keywords },
    };
    agent.tools_config = .{
        .tool_customizations = &.{
            .{ .name = "mcp_private_lookup", .triggers = &.{"private"}, .priority = 10 },
        },
    };

    const turn_specs = try agent.filterToolSpecsForTurn(arena, "private");
    try std.testing.expectEqual(@as(usize, 1), turn_specs.len);
    try std.testing.expectEqualStrings("shell", turn_specs[0].name);
    try std.testing.expect(agent.priorityToolForSpecsMessage(turn_specs, "private") == null);
    agent.tool_specs = try allocator.alloc(ToolSpec, 0);
}

// ── filterToolsForPromptText tests ─────────────────────────────────

const MockFilterTool = struct {
    name_buf: []const u8,
    desc_buf: []const u8,
};

fn mockFilterToolVTable() tools_mod.Tool.VTable {
    return .{
        .name = struct {
            fn f(ptr: *anyopaque) []const u8 {
                return @as(*const MockFilterTool, @ptrCast(@alignCast(ptr))).name_buf;
            }
        }.f,
        .description = struct {
            fn f(ptr: *anyopaque) []const u8 {
                return @as(*const MockFilterTool, @ptrCast(@alignCast(ptr))).desc_buf;
            }
        }.f,
        .parameters_json = struct {
            fn f(_: *anyopaque) []const u8 {
                return "{}";
            }
        }.f,
        .execute = struct {
            fn f(_: *anyopaque, _: std.mem.Allocator, _: tools_mod.JsonObjectMap) anyerror!tools_mod.ToolResult {
                return tools_mod.ToolResult.ok("");
            }
        }.f,
    };
}

fn makeMockFilterTool(allocator: std.mem.Allocator, name: []const u8) !Tool {
    const m = try allocator.create(MockFilterTool);
    m.* = .{ .name_buf = try allocator.dupe(u8, name), .desc_buf = try allocator.dupe(u8, name) };
    const vt = try allocator.create(tools_mod.Tool.VTable);
    vt.* = mockFilterToolVTable();
    return .{ .ptr = @ptrCast(m), .vtable = vt };
}

fn freeMockFilterTool(tool: Tool, allocator: std.mem.Allocator) void {
    const m: *MockFilterTool = @ptrCast(@alignCast(tool.ptr));
    allocator.free(m.name_buf);
    allocator.free(m.desc_buf);
    allocator.destroy(m);
    allocator.destroy(@constCast(tool.vtable));
}

test "filterToolsForPromptText no groups returns all tools" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tools);

    agent.tools = &.{
        try makeMockFilterTool(allocator, "shell"),
        try makeMockFilterTool(allocator, "mcp_webdav_read"),
    };
    defer for (agent.tools) |t| freeMockFilterTool(t, allocator);

    const result = try agent.filterToolsForPromptText(arena.allocator());
    try std.testing.expectEqual(@as(usize, 2), result.len);
}

test "filterToolsForPromptText always group includes matching MCP" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tools);

    agent.tools = &.{
        try makeMockFilterTool(allocator, "shell"),
        try makeMockFilterTool(allocator, "mcp_webdav_read"),
        try makeMockFilterTool(allocator, "mcp_browser_open"),
    };
    defer for (agent.tools) |t| freeMockFilterTool(t, allocator);
    agent.tool_filter_groups = &.{
        .{ .mode = .always, .tools = &.{"mcp_webdav_*"} },
    };

    const result = try agent.filterToolsForPromptText(arena.allocator());
    try std.testing.expectEqual(@as(usize, 2), result.len);
}

test "filterToolsForPromptText dynamic group excluded from text" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tools);

    agent.tools = &.{
        try makeMockFilterTool(allocator, "shell"),
        try makeMockFilterTool(allocator, "mcp_vikunja_create_task"),
        try makeMockFilterTool(allocator, "mcp_webdav_read"),
    };
    defer for (agent.tools) |t| freeMockFilterTool(t, allocator);
    agent.tool_filter_groups = &.{
        .{ .mode = .dynamic, .tools = &.{"mcp_vikunja_*"}, .keywords = &.{"task"} },
        .{ .mode = .always, .tools = &.{"mcp_webdav_*"} },
    };

    const result = try agent.filterToolsForPromptText(arena.allocator());
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name());
}

test "filterToolsForPromptText empty group excludes MCP tools" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    allocator.free(agent.tools);

    agent.tools = &.{
        try makeMockFilterTool(allocator, "shell"),
        try makeMockFilterTool(allocator, "mcp_webdav_read"),
    };
    defer for (agent.tools) |t| freeMockFilterTool(t, allocator);
    agent.tool_filter_groups = &.{
        .{ .mode = .always, .tools = &.{} },
    };

    const result = try agent.filterToolsForPromptText(arena.allocator());
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("shell", result[0].name());
}

test "Agent system prompt keeps parameters when streaming disables native tool schemas" {
    // Regression: streaming turns send tools=null, so the text prompt must keep
    // Parameters even if the provider supports native tools.
    const StreamingPromptCapture = struct {
        captured_system: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator_: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator_.dupe(u8, "ok");
        }

        fn chat(_: *anyopaque, _: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            return error.ShouldNotUseBlockingChat;
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn supportsStreaming(_: *anyopaque) bool {
            return true;
        }

        fn streamChat(
            ptr: *anyopaque,
            allocator_: std.mem.Allocator,
            request: providers.ChatRequest,
            model: []const u8,
            _: f64,
            callback: providers.StreamCallback,
            callback_ctx: *anyopaque,
        ) anyerror!providers.StreamChatResult {
            try std.testing.expect(request.tools == null);
            const self: *@This() = @ptrCast(@alignCast(ptr));
            for (request.messages) |msg| {
                if (msg.role == .system) {
                    if (self.captured_system) |old| self.capture_alloc.free(old);
                    self.captured_system = try self.capture_alloc.dupe(u8, msg.content);
                    break;
                }
            }
            callback(callback_ctx, providers.StreamChunk.textDelta("ok"));
            callback(callback_ctx, providers.StreamChunk.finalChunk());
            return .{
                .content = try allocator_.dupe(u8, "ok"),
                .model = try allocator_.dupe(u8, model),
            };
        }

        fn getName(_: *anyopaque) []const u8 {
            return "streaming-prompt-capture";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var provider_state = StreamingPromptCapture{ .capture_alloc = allocator };
    defer if (provider_state.captured_system) |captured| allocator.free(captured);
    const provider_vtable = Provider.VTable{
        .chatWithSystem = StreamingPromptCapture.chatWithSystem,
        .chat = StreamingPromptCapture.chat,
        .supportsNativeTools = StreamingPromptCapture.supportsNativeTools,
        .getName = StreamingPromptCapture.getName,
        .deinit = StreamingPromptCapture.deinitFn,
        .supports_streaming = StreamingPromptCapture.supportsStreaming,
        .stream_chat = StreamingPromptCapture.streamChat,
    };
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

    const runtime_tools = [_]Tool{
        try makeMockFilterTool(allocator, "shell"),
        try makeMockFilterTool(allocator, "mcp_secret_lookup"),
    };
    defer for (runtime_tools) |t| freeMockFilterTool(t, allocator);

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .default_model = "openai/gpt-4.1-mini",
        .allocator = allocator,
    };
    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfig(allocator, &cfg, provider, &runtime_tools, null, noop.observer());
    defer agent.deinit();
    agent.tool_filter_groups = &.{
        .{ .mode = .dynamic, .tools = &.{"mcp_secret_*"}, .keywords = &.{"secret"} },
    };

    const StreamSink = struct {
        fn onChunk(_: *anyopaque, _: providers.StreamChunk) void {}
    };
    var stream_ctx: u8 = 0;
    agent.stream_callback = StreamSink.onChunk;
    agent.stream_ctx = @ptrCast(&stream_ctx);

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(provider_state.captured_system != null);
    const captured = provider_state.captured_system.?;
    try std.testing.expect(std.mem.indexOf(u8, captured, "**shell**: shell") != null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "Parameters: `{}`") != null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "mcp_secret_lookup") == null);
}

test "buildProviderMessagesForTurn adds priority hint without mutating history" {
    // Regression: priority hints must not be persisted as user text in history/memory/cache.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var agent = try makeTestAgent(allocator);
    defer agent.deinit();
    try agent.history.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, "please read this file"),
    });

    const messages = try agent.buildProviderMessagesForTurn(arena, agent.model_name, "file_read");
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expect(std.mem.indexOf(u8, messages[0].content, "[PRIORITY: Please call the file_read tool immediately]") != null);
    try std.testing.expectEqualStrings("please read this file", agent.history.items[0].content);
}

test "globMatch handles prefix wildcard" {
    try std.testing.expect(Agent.globMatch("mcp_vikunja_*", "mcp_vikunja_list_tasks"));
    try std.testing.expect(Agent.globMatch("mcp_vikunja_*", "mcp_vikunja_create_task"));
    try std.testing.expect(!Agent.globMatch("mcp_vikunja_*", "mcp_browser_open"));
    try std.testing.expect(Agent.globMatch("*", "anything"));
    try std.testing.expect(Agent.globMatch("shell", "shell"));
    try std.testing.expect(!Agent.globMatch("shell", "shell_extra"));
}

test "loop honors max_tool_iterations limit" {
    // Verifies that when a provider always returns a tool call, the agent loop
    // stops at exactly max_tool_iterations and emits tool_iterations_exhausted.
    const NoopTool = struct {
        const Self = @This();
        pub const tool_name = "noop_iter";
        pub const tool_description = "noop for iteration cap test";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{ .success = true, .output = try allocator.dupe(u8, "noop ok") };
        }
    };

    // Provider always returns a tool call so it never completes voluntarily.
    // On the summary call (after cap is hit) it returns a plain text response.
    const LoopingProvider = struct {
        const Self = @This();
        calls: usize = 0,
        cap: usize,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            // Within the cap: always return a tool call to keep the loop going.
            // On the summary call (calls > cap): return plain text.
            if (self.calls <= self.cap) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-noop-iter"),
                    .name = try allocator.dupe(u8, "noop_iter"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "calling tool"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }
            return .{
                .content = try allocator.dupe(u8, "summary after cap"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getTraceId(_: *anyopaque) ?[32]u8 {
            return null;
        }
        fn setTraceId(_: *anyopaque, _: [32]u8) void {}
        fn getName(_: *anyopaque) []const u8 {
            return "looping-provider";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const max_iters: u32 = 2;
    const allocator = std.testing.allocator;

    var provider_state = LoopingProvider{ .cap = max_iters };
    const provider_vtable = Provider.VTable{
        .chatWithSystem = LoopingProvider.chatWithSystem,
        .chat = LoopingProvider.chat,
        .supportsNativeTools = LoopingProvider.supportsNativeTools,
        .getName = LoopingProvider.getName,
        .deinit = LoopingProvider.deinitFn,
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

    var observer = RecordingObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &tool_list,
        .tool_specs = specs,
        .mem = null,
        .observer = observer.observer(),
        .model_name = "test-model",
        .temperature = 0.7,
        .workspace_dir = "/tmp",
        .max_tool_iterations = max_iters,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .total_tokens = 0,
        .has_system_prompt = false,
    };
    defer agent.deinit();

    const response = try agent.turn("loop forever");
    defer allocator.free(response);

    // Loop must stop — not infinite loop.
    // tool_iterations_exhausted event fired exactly once.
    try std.testing.expectEqual(@as(usize, 1), observer.tool_iterations_exhausted_count);
    // turn_complete fired exactly once.
    try std.testing.expectEqual(@as(usize, 1), observer.turn_complete_count);
    // Provider called max_iters times for tool iterations + 1 for the summary call.
    try std.testing.expectEqual(max_iters + 1, @as(u32, @intCast(provider_state.calls)));
    // Response contains the iteration-limit prefix.
    try std.testing.expect(std.mem.indexOf(u8, response, "[Tool iteration limit:") != null);
}

// ═══════════════════════════════════════════════════════════════════════════
// Pre-provider PII redaction tests
// ═══════════════════════════════════════════════════════════════════════════

const RedactCaptureProvider = struct {
    captured_user: ?[]u8 = null,
    capture_alloc: std.mem.Allocator,

    fn chatWithSystem(_: *anyopaque, alloc: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
        return alloc.dupe(u8, "");
    }

    fn chat(ptr: *anyopaque, alloc: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        // Capture the LAST user message content (turn may issue multiple calls; we want the most recent).
        var i = request.messages.len;
        while (i > 0) {
            i -= 1;
            if (request.messages[i].role == .user) {
                if (self.captured_user) |old| self.capture_alloc.free(old);
                self.captured_user = try self.capture_alloc.dupe(u8, request.messages[i].content);
                break;
            }
        }
        return .{
            .content = try alloc.dupe(u8, "ok"),
            .tool_calls = &.{},
            .usage = .{},
            .model = try alloc.dupe(u8, model),
        };
    }

    fn supportsNativeTools(_: *anyopaque) bool {
        return false;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "redact-capture";
    }

    fn deinitFn(_: *anyopaque) void {}
};

const redact_capture_vtable = Provider.VTable{
    .chatWithSystem = RedactCaptureProvider.chatWithSystem,
    .chat = RedactCaptureProvider.chat,
    .supportsNativeTools = RedactCaptureProvider.supportsNativeTools,
    .getName = RedactCaptureProvider.getName,
    .deinit = RedactCaptureProvider.deinitFn,
};

fn redactionBaseConfig(allocator: std.mem.Allocator) Config {
    return Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_provider = "openrouter",
        .default_model = "openrouter/test-model",
        .allocator = allocator,
    };
}

fn redactionFromConfigAllocationTest(allocator: std.mem.Allocator) !void {
    var state = RedactCaptureProvider{ .capture_alloc = std.testing.allocator };
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    cfg.memory.backend = "none";

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), null);
    defer agent.deinit();
}

test "Agent.fromConfigWithProfile handles allocation failures without leaks" {
    // Regression: init-time OOM after bootstrap provider creation must deinit
    // bootstrap/redactor/spec resources before returning error.OutOfMemory.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, redactionFromConfigAllocationTest, .{});
}

test "Agent: redactor enabled scrubs email before provider" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "redact-on",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    try std.testing.expect(agent.redactor != null);

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    try std.testing.expect(state.captured_user != null);
    const got = state.captured_user.?;
    // Regression: email in user message must be replaced with a numbered placeholder.
    try std.testing.expect(std.mem.indexOf(u8, got, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "user@example.com") == null);
}

test "Agent: redactor stores redacted user content in local history" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), null);
    defer agent.deinit();

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    var saw_redacted_user = false;
    for (agent.history.items) |msg| {
        if (msg.role != .user) continue;
        try std.testing.expect(std.mem.indexOf(u8, msg.content, "user@example.com") == null);
        if (std.mem.indexOf(u8, msg.content, "[EMAIL_1]") != null) saw_redacted_user = true;
    }
    try std.testing.expect(saw_redacted_user);
}

test "Agent: redactor stores redacted autosave memory" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var mem_backend = memory_mod.memory_lru.InMemoryLruMemory.init(allocator, 16);
    defer mem_backend.deinit();
    const mem = mem_backend.memory();

    var cfg = redactionBaseConfig(allocator);
    cfg.memory.auto_save = true;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, mem, noop.observer(), null);
    defer agent.deinit();

    const response = try agent.turn("remember user@example.com for the test");
    defer allocator.free(response);

    const entries = try mem.list(allocator, .conversation, null);
    defer memory_mod.freeEntries(allocator, entries);

    var saw_redacted_autosave = false;
    for (entries) |entry| {
        try std.testing.expect(std.mem.indexOf(u8, entry.content, "user@example.com") == null);
        if (std.mem.indexOf(u8, entry.content, "[EMAIL_1]") != null) saw_redacted_autosave = true;
    }
    try std.testing.expect(saw_redacted_autosave);
}

test "Agent: redactor scrubs failed tool output in observer detail" {
    const PiiFailureTool = struct {
        const Self = @This();
        pub const tool_name = "pii_failure_probe";
        pub const tool_description = "Returns a failing output with PII for redaction regression testing.";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{
                .success = false,
                .output = try allocator.dupe(u8, "lookup failed for user@example.com"),
            };
        }
    };

    const ToolThenFinalProvider = struct {
        const Self = @This();
        call_count: usize = 0,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-pii-failure"),
                    .name = try allocator.dupe(u8, "pii_failure_probe"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "checking"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, model),
                };
            }
            return .{
                .content = try allocator.dupe(u8, "done"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "tool-then-final";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const provider_vtable = Provider.VTable{
        .chatWithSystem = ToolThenFinalProvider.chatWithSystem,
        .chat = ToolThenFinalProvider.chat,
        .supportsNativeTools = ToolThenFinalProvider.supportsNativeTools,
        .getName = ToolThenFinalProvider.getName,
        .deinit = ToolThenFinalProvider.deinitFn,
    };

    const allocator = std.testing.allocator;
    var provider_state = ToolThenFinalProvider{};
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };
    var tool_state = PiiFailureTool{};
    const tool = tool_state.tool();

    var cfg = redactionBaseConfig(allocator);
    var observer = RecordingObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{tool}, null, observer.observer(), null);
    defer agent.deinit();

    const response = try agent.turn("run the failure probe");
    defer allocator.free(response);

    try std.testing.expect(observer.tool_call_count >= 1);
    const detail = observer.last_tool_detail[0..observer.last_tool_detail_len];
    try std.testing.expect(std.mem.indexOf(u8, detail, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "[EMAIL_1]") != null);
}

test "Agent: redactor scrubs successful tool output in next provider request" {
    // Regression: a successful tool that emits raw PII must not leak that
    // PII into the ChatRequest sent to the provider on the next iteration.
    // The agent merges tool output into a user-role reflection message
    // so this test concatenates every message
    // content on the second hop and asserts nothing raw survives.
    const PiiSuccessTool = struct {
        const Self = @This();
        pub const tool_name = "pii_success_probe";
        pub const tool_description = "Returns a successful output containing PII for redaction regression testing.";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{
                .success = true,
                .output = try allocator.dupe(u8, "lookup ok: user@example.com"),
            };
        }
    };

    const ToolThenCaptureProvider = struct {
        const Self = @This();
        call_count: usize = 0,
        captured_concat: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            if (self.call_count == 1) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-pii-success"),
                    .name = try allocator.dupe(u8, "pii_success_probe"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "checking"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, model),
                };
            }
            var concat: std.ArrayListUnmanaged(u8) = .empty;
            defer concat.deinit(self.capture_alloc);
            for (request.messages) |msg| {
                try concat.appendSlice(self.capture_alloc, msg.content);
                try concat.append(self.capture_alloc, '\n');
            }
            if (self.captured_concat) |old| self.capture_alloc.free(old);
            self.captured_concat = try self.capture_alloc.dupe(u8, concat.items);
            return .{
                .content = try allocator.dupe(u8, "done"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "tool-then-capture";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const provider_vtable = Provider.VTable{
        .chatWithSystem = ToolThenCaptureProvider.chatWithSystem,
        .chat = ToolThenCaptureProvider.chat,
        .supportsNativeTools = ToolThenCaptureProvider.supportsNativeTools,
        .getName = ToolThenCaptureProvider.getName,
        .deinit = ToolThenCaptureProvider.deinitFn,
    };

    const allocator = std.testing.allocator;
    var provider_state = ToolThenCaptureProvider{ .capture_alloc = allocator };
    defer if (provider_state.captured_concat) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };
    var tool_state = PiiSuccessTool{};
    const tool = tool_state.tool();

    var cfg = redactionBaseConfig(allocator);
    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{tool}, null, noop.observer(), null);
    defer agent.deinit();

    const response = try agent.turn("run the success probe");
    defer allocator.free(response);

    try std.testing.expect(provider_state.captured_concat != null);
    const captured = provider_state.captured_concat.?;
    try std.testing.expect(std.mem.indexOf(u8, captured, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "[EMAIL_1]") != null);
}

test "Agent: redactor scrubs LLM response observer detail" {
    const RawEmailResponseProvider = struct {
        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "reply mentions user@example.com"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "raw-email-response";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const provider_vtable = Provider.VTable{
        .chatWithSystem = RawEmailResponseProvider.chatWithSystem,
        .chat = RawEmailResponseProvider.chat,
        .supportsNativeTools = RawEmailResponseProvider.supportsNativeTools,
        .getName = RawEmailResponseProvider.getName,
        .deinit = RawEmailResponseProvider.deinitFn,
    };

    const allocator = std.testing.allocator;
    var provider_state: u8 = 0;
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

    var cfg = redactionBaseConfig(allocator);
    cfg.diagnostics.log_llm_io = true;

    var observer = RecordingObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, observer.observer(), null);
    defer agent.deinit();

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(observer.llm_response_count >= 1);
    const detail = observer.last_llm_response_detail[0..observer.last_llm_response_detail_len];
    try std.testing.expect(std.mem.indexOf(u8, detail, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "[EMAIL_1]") != null);
}

test "Agent: redactor disabled passes content through verbatim" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "redact-off",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = false,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    try std.testing.expect(agent.redactor == null);

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    try std.testing.expect(state.captured_user != null);
    const got = state.captured_user.?;
    // When disabled, original content must reach the provider untouched.
    try std.testing.expect(std.mem.indexOf(u8, got, "user@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "[EMAIL_1]") == null);
}

test "Agent: root redactor can be disabled from agent config" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    cfg.agent.enable_pii_redaction = false;

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), null);
    defer agent.deinit();

    try std.testing.expect(agent.redactor == null);

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    try std.testing.expect(state.captured_user != null);
    const got = state.captured_user.?;
    try std.testing.expect(std.mem.indexOf(u8, got, "user@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "[EMAIL_1]") == null);
}

test "Agent: redactor preserves cross-turn placeholder ids" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "redact-cross-turn",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    // Turn 1: introduce a@b.co — should become EMAIL_1.
    const r1 = try agent.turn("first ping a@b.co");
    defer allocator.free(r1);
    try std.testing.expect(state.captured_user != null);
    try std.testing.expect(std.mem.indexOf(u8, state.captured_user.?, "[EMAIL_1]") != null);

    // Turn 2: same email — must reuse EMAIL_1, not bump to EMAIL_2.
    const r2 = try agent.turn("follow-up to a@b.co");
    defer allocator.free(r2);
    try std.testing.expect(state.captured_user != null);
    const got2 = state.captured_user.?;
    try std.testing.expect(std.mem.indexOf(u8, got2, "[EMAIL_1]") != null);
    // Regression: counter must NOT have advanced to EMAIL_2 for the same email.
    try std.testing.expect(std.mem.indexOf(u8, got2, "[EMAIL_2]") == null);
}

test "Agent: clearHistory resets redactor placeholder state" {
    const allocator = std.testing.allocator;
    var state = RedactCaptureProvider{ .capture_alloc = allocator };
    defer if (state.captured_user) |c| allocator.free(c);
    const provider = Provider{ .ptr = @ptrCast(&state), .vtable = &redact_capture_vtable };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "redact-reset",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    const r1 = try agent.turn("first ping a@b.co");
    defer allocator.free(r1);
    try std.testing.expect(std.mem.indexOf(u8, state.captured_user.?, "[EMAIL_1]") != null);

    agent.clearHistory();

    const r2 = try agent.turn("new chat x@y.zz");
    defer allocator.free(r2);
    try std.testing.expect(std.mem.indexOf(u8, state.captured_user.?, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, state.captured_user.?, "[EMAIL_2]") == null);
}

test "Agent: response cache bypasses redacted prompt placeholders" {
    // Regression: cache keys built from redacted prompts collapse distinct raw
    // PII values after a conversation reset (alice -> [EMAIL_1],
    // bob -> [EMAIL_1]). Governance turns must call the provider again instead
    // of replaying a response computed for a different original value.
    const CountingProvider = struct {
        calls: u32 = 0,

        fn chatWithSystem(_: *anyopaque, alloc: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return alloc.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, alloc: std.mem.Allocator, _: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            return .{
                .content = try std.fmt.allocPrint(alloc, "reply-{d}", .{self.calls}),
                .tool_calls = &.{},
                .usage = .{},
                .model = try alloc.dupe(u8, model),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "counting-redaction-cache";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const provider_vtable = Provider.VTable{
        .chatWithSystem = CountingProvider.chatWithSystem,
        .chat = CountingProvider.chat,
        .supportsNativeTools = CountingProvider.supportsNativeTools,
        .getName = CountingProvider.getName,
        .deinit = CountingProvider.deinitFn,
    };

    const allocator = std.testing.allocator;
    var provider_state = CountingProvider{};
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

    var response_cache = try cache.ResponseCache.init(":memory:", 60, 1000);
    defer response_cache.deinit();

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "redact-cache",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    agent.response_cache = &response_cache;
    defer agent.deinit();

    const first = try agent.turn("contact alice@example.com");
    defer allocator.free(first);
    try std.testing.expectEqualStrings("reply-1", first);
    try std.testing.expectEqual(@as(u32, 1), provider_state.calls);

    agent.clearHistory();

    const second = try agent.turn("contact bob@example.com");
    defer allocator.free(second);
    try std.testing.expectEqualStrings("reply-2", second);
    try std.testing.expectEqual(@as(u32, 2), provider_state.calls);
}

test "Agent.redactMessagesForProvider redacts multimodal text and drops unsafe image URLs" {
    // Direct unit test on the helper: text content_parts and image URLs get
    // scrubbed before provider handoff. Query/fragment URLs are not forwarded:
    // stripping them would send a broken signed URL while forwarding leaks
    // credentials.
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var redactor = redaction.Redactor.init(allocator, .{});
    defer redactor.deinit();

    const parts = [_]ContentPart{
        ContentPart{ .text = "see a@b.co for context" },
        ContentPart{ .image_url = .{ .url = "https://example.com/user@example.com/x.png?token=abc123&X-Amz-Signature=deadbeef#frag" } },
    };
    const messages = [_]ChatMessage{
        ChatMessage{
            .role = .user,
            .content = "",
            .content_parts = &parts,
        },
    };

    const out = try Agent.redactMessagesForProvider(arena.allocator(), &messages, &redactor);

    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expect(out[0].content_parts != null);
    const out_parts = out[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 2), out_parts.len);

    // Text part redacted.
    try std.testing.expect(std.meta.activeTag(out_parts[0]) == .text);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[0].text, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[0].text, "a@b.co") == null);

    // Signed/query URLs are replaced by an explicit provider note instead of a
    // broken redacted URL.
    try std.testing.expect(std.meta.activeTag(out_parts[1]) == .text);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[1].text, "not sent to provider") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[1].text, "abc123") == null);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[1].text, "deadbeef") == null);
    try std.testing.expect(std.mem.indexOf(u8, out_parts[1].text, "user@example.com") == null);
}

test "Agent.redactMessagesForProvider preserves safe image URLs" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var redactor = redaction.Redactor.init(allocator, .{});
    defer redactor.deinit();

    const parts = [_]ContentPart{
        ContentPart{ .image_url = .{ .url = "https://cdn.example.com/public/cat.png" } },
    };
    const messages = [_]ChatMessage{
        ChatMessage{ .role = .user, .content = "", .content_parts = &parts },
    };

    const out = try Agent.redactMessagesForProvider(arena.allocator(), &messages, &redactor);
    const out_parts = out[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 1), out_parts.len);
    try std.testing.expect(std.meta.activeTag(out_parts[0]) == .image_url);
    try std.testing.expectEqualStrings("https://cdn.example.com/public/cat.png", out_parts[0].image_url.url);
}

test "Agent.executeTool does not rehydrate redactor placeholders in tool args" {
    // Regression: provider-bound redaction must not become a provider->tool
    // exfiltration channel. Tools receive literal placeholders by default.
    const RecordTool = struct {
        const Self = @This();
        last_seen: ?[]u8 = null,
        alloc: std.mem.Allocator,

        pub const tool_name = "record_args";
        pub const tool_description = "Captures the `text` argument verbatim.";
        pub const tool_params =
            "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}";
        pub const vtable = tools_mod.ToolVTable(Self);

        pub fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *Self, allocator: std.mem.Allocator, args: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            const text = tools_mod.getString(args, "text") orelse "";
            if (self.last_seen) |old| self.alloc.free(old);
            self.last_seen = try self.alloc.dupe(u8, text);
            return .{ .success = true, .output = try allocator.dupe(u8, "ok") };
        }
    };

    const allocator = std.testing.allocator;

    var record_impl: RecordTool = .{ .alloc = allocator };
    defer if (record_impl.last_seen) |s| allocator.free(s);
    const record_tool = record_impl.tool();

    var redactor = redaction.Redactor.init(allocator, .{ .record_originals = true });
    defer redactor.deinit();

    // Populate reverse map: alice -> [EMAIL_1].
    const seeded = try redactor.redact(allocator, "ping alice@acme.com");
    defer allocator.free(seeded);

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{record_tool},
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
        .redactor = &redactor,
    };
    // Don't deinit redactor inside agent.deinit (we own it on the stack frame).
    defer {
        agent.redactor = null;
        agent.deinit();
    }

    const call = ParsedToolCall{
        .name = "record_args",
        .arguments_json = "{\"text\":\"please notify [EMAIL_1] about the issue\"}",
        .tool_call_id = null,
    };
    var tool_arena = std.heap.ArenaAllocator.init(allocator);
    defer tool_arena.deinit();
    const result = agent.executeTool(tool_arena.allocator(), call);

    try std.testing.expect(result.success);
    try std.testing.expect(record_impl.last_seen != null);
    try std.testing.expectEqualStrings(
        "please notify [EMAIL_1] about the issue",
        record_impl.last_seen.?,
    );
}

test "Agent: signed image_url is not forwarded as a broken redacted URL" {
    // Regression: stripping query credentials from a signed URL protects
    // secrets but leaves the provider with a URL that cannot fetch the image.
    // The governed path must send an explicit text note instead.
    const allocator = std.testing.allocator;
    var redactor = redaction.Redactor.init(allocator, .{ .record_originals = true });
    defer redactor.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const parts = [_]ContentPart{
        ContentPart{ .image_url = .{ .url = "https://example.com/user@example.com/p.png?sig=raw-secret" } },
    };
    const messages = [_]ChatMessage{
        ChatMessage{ .role = .user, .content = "", .content_parts = &parts },
    };
    const out = try Agent.redactMessagesForProvider(arena.allocator(), &messages, &redactor);
    try std.testing.expect(out[0].content_parts != null);
    const part = out[0].content_parts.?[0];
    try std.testing.expect(std.meta.activeTag(part) == .text);
    try std.testing.expect(std.mem.indexOf(u8, part.text, "not sent to provider") != null);
    try std.testing.expect(std.mem.indexOf(u8, part.text, "raw-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, part.text, "user@example.com") == null);
}

// ---- iteration-exhausted summary path ----

test "Agent: redactor scrubs PII in iteration-exhausted summary call" {
    // Regression: iteration-limit summary calls use a separate provider path.
    // Force the loop to exhaust and assert the summary prompt is redacted.

    const NoopIterTool = struct {
        const Self = @This();
        pub const tool_name = "noop_iter_redaction";
        pub const tool_description = "noop for redaction iteration cap test";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        pub const vtable = tools_mod.ToolVTable(Self);

        fn tool(self: *Self) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *Self, allocator: std.mem.Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
            return .{ .success = true, .output = try allocator.dupe(u8, "noop ok") };
        }
    };

    const LoopingRedactCapture = struct {
        const Self = @This();
        calls: usize = 0,
        cap: usize,
        last_user: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, _: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            // Capture the FIRST user message — that's the original turn input
            // (the one that contained the email). On the post-cap summary call,
            // the agent appends a pseudo-user "SYSTEM: max iterations…" message
            // that DOES NOT contain PII, so capturing the *last* user would
            // silently miss the actual regression we're guarding.
            for (request.messages) |msg| {
                if (msg.role == .user) {
                    if (self.last_user) |old| self.capture_alloc.free(old);
                    self.last_user = try self.capture_alloc.dupe(u8, msg.content);
                    break;
                }
            }
            // Within cap: keep loop alive with a tool call. After cap: plain text.
            if (self.calls <= self.cap) {
                const tool_calls = try allocator.alloc(providers.ToolCall, 1);
                tool_calls[0] = .{
                    .id = try allocator.dupe(u8, "call-noop-iter-redaction"),
                    .name = try allocator.dupe(u8, "noop_iter_redaction"),
                    .arguments = try allocator.dupe(u8, "{}"),
                };
                return .{
                    .content = try allocator.dupe(u8, "calling tool"),
                    .tool_calls = tool_calls,
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }
            return .{
                .content = try allocator.dupe(u8, "post-cap summary"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "looping-redact-capture";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    const max_iters: u32 = 1;

    var provider_state = LoopingRedactCapture{ .cap = max_iters, .capture_alloc = allocator };
    defer if (provider_state.last_user) |c| allocator.free(c);

    const provider_vtable = Provider.VTable{
        .chatWithSystem = LoopingRedactCapture.chatWithSystem,
        .chat = LoopingRedactCapture.chat,
        .supportsNativeTools = LoopingRedactCapture.supportsNativeTools,
        .getName = LoopingRedactCapture.getName,
        .deinit = LoopingRedactCapture.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var noop_tool = NoopIterTool{};
    const tool_list = [_]Tool{noop_tool.tool()};
    const specs = try allocator.alloc(ToolSpec, tool_list.len);
    for (tool_list, 0..) |t, i| {
        specs[i] = .{
            .name = t.name(),
            .description = t.description(),
            .parameters_json = t.parametersJson(),
        };
    }
    // `fromConfigWithProfile` doesn't take tools; we'll wire them on the agent struct.
    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "iter-exhausted",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, tool_list[0..], null, noop.observer(), profile);
    defer agent.deinit();
    // Override default tool_specs with our build (deinit will free this).
    allocator.free(agent.tool_specs);
    agent.tool_specs = specs;
    agent.max_tool_iterations = max_iters;

    try std.testing.expect(agent.redactor != null);

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    // Iteration exhausted path produces a response prefixed with "[Tool iteration limit:"
    // ONLY when summary_response itself fails. On happy path (provider returns plain text
    // post-cap), agent uses the summary response as its response. Either way, the
    // critical invariant is that the captured user message in the post-cap call
    // had the email already redacted.
    try std.testing.expect(provider_state.calls >= max_iters + 1);
    try std.testing.expect(provider_state.last_user != null);
    const captured = provider_state.last_user.?;
    // Regression guard: raw email must never reach the summarizer prompt.
    try std.testing.expect(std.mem.indexOf(u8, captured, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "[EMAIL_1]") != null);
}

// ---- streaming path ----

test "Agent: redactor scrubs PII before provider.streamChat" {
    // Regression: streamChat path must apply the same hook as chat. The hook
    // lives inside buildProviderMessagesForTurn so it covers both call sites,
    // but a future refactor that splits streaming-only message-building would
    // silently regress. This test guards that path explicitly.

    const StreamRedactCapture = struct {
        const Self = @This();
        captured_user: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        // Fallback chat (should not be called in this test).
        fn chat(_: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            return .{
                .content = try allocator.dupe(u8, "should-not-be-used"),
                .tool_calls = &.{},
                .usage = .{},
                .model = try allocator.dupe(u8, model),
            };
        }

        fn streamChat(
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: providers.ChatRequest,
            _: []const u8,
            _: f64,
            callback: providers.StreamCallback,
            callback_ctx: *anyopaque,
        ) anyerror!providers.StreamChatResult {
            const self: *Self = @ptrCast(@alignCast(ptr));
            // Capture the last user message content (post-redaction view).
            var i = request.messages.len;
            while (i > 0) {
                i -= 1;
                if (request.messages[i].role == .user) {
                    if (self.captured_user) |old| self.capture_alloc.free(old);
                    self.captured_user = try self.capture_alloc.dupe(u8, request.messages[i].content);
                    break;
                }
            }
            // Emit single content chunk + final.
            callback(callback_ctx, providers.StreamChunk.textDelta("ok"));
            callback(callback_ctx, providers.StreamChunk.finalChunk());
            return .{
                .content = try allocator.dupe(u8, "ok"),
                .reasoning_content = null,
                .usage = .{},
                .model = try allocator.dupe(u8, "stream-test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return false;
        }

        fn supportsStreaming(_: *anyopaque) bool {
            return true;
        }

        fn getName(_: *anyopaque) []const u8 {
            return "streaming-redact-capture";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var provider_state = StreamRedactCapture{ .capture_alloc = allocator };
    defer if (provider_state.captured_user) |c| allocator.free(c);

    const provider_vtable = Provider.VTable{
        .chatWithSystem = StreamRedactCapture.chatWithSystem,
        .chat = StreamRedactCapture.chat,
        .supportsNativeTools = StreamRedactCapture.supportsNativeTools,
        .getName = StreamRedactCapture.getName,
        .deinit = StreamRedactCapture.deinitFn,
        .stream_chat = StreamRedactCapture.streamChat,
        .supports_streaming = StreamRedactCapture.supportsStreaming,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "streaming-redact",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    // Activate streaming path: both callback and ctx must be non-null AND provider
    // must report supportsStreaming() true.
    const StreamSink = struct {
        fn onChunk(_: *anyopaque, _: providers.StreamChunk) void {}
    };
    var sink_ctx: u8 = 0;
    agent.stream_callback = StreamSink.onChunk;
    agent.stream_ctx = @ptrCast(&sink_ctx);

    try std.testing.expect(agent.redactor != null);

    const response = try agent.turn("contact me at user@example.com please");
    defer allocator.free(response);

    try std.testing.expect(provider_state.captured_user != null);
    const captured = provider_state.captured_user.?;
    try std.testing.expect(std.mem.indexOf(u8, captured, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "user@example.com") == null);
}

// ---- system prompt with PII ----

test "Agent: redactor scrubs PII in system prompt" {
    // Regression: redaction must apply to ALL roles, including system. System
    // prompts often hardcode example data with PII shapes (e.g. "support
    // email: support@example.com"); test that they don't leak verbatim.

    const SystemPromptCapture = struct {
        const Self = @This();
        captured_system: ?[]u8 = null,
        capture_alloc: std.mem.Allocator,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *Self = @ptrCast(@alignCast(ptr));
            // Capture the FIRST system message (the prompt).
            for (request.messages) |msg| {
                if (msg.role == .system) {
                    if (self.captured_system) |old| self.capture_alloc.free(old);
                    self.captured_system = try self.capture_alloc.dupe(u8, msg.content);
                    break;
                }
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
            return "system-prompt-capture";
        }

        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var provider_state = SystemPromptCapture{ .capture_alloc = allocator };
    defer if (provider_state.captured_system) |c| allocator.free(c);

    const provider_vtable = Provider.VTable{
        .chatWithSystem = SystemPromptCapture.chatWithSystem,
        .chat = SystemPromptCapture.chat,
        .supportsNativeTools = SystemPromptCapture.supportsNativeTools,
        .getName = SystemPromptCapture.getName,
        .deinit = SystemPromptCapture.deinitFn,
    };
    const provider = Provider{
        .ptr = @ptrCast(&provider_state),
        .vtable = &provider_vtable,
    };

    var cfg = redactionBaseConfig(allocator);
    const profile = config_types.NamedAgentConfig{
        .name = "system-pii",
        .provider = "openrouter",
        .model = "openrouter/test-model",
        .system_prompt = "Help the user with email user@example.com please",
        .enable_pii_redaction = true,
    };

    var noop = observability.NoopObserver{};
    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider, &.{}, null, noop.observer(), profile);
    defer agent.deinit();

    const response = try agent.turn("hello");
    defer allocator.free(response);

    try std.testing.expect(provider_state.captured_system != null);
    const captured = provider_state.captured_system.?;
    // System prompt content must reach provider with email redacted.
    try std.testing.expect(std.mem.indexOf(u8, captured, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, captured, "user@example.com") == null);
}

// ── Approval flow tests ───────────────────────────────────────────────────

const ApprovalTestTool = struct {
    execution_count: usize = 0,

    pub const tool_name = "approval_test";
    pub const tool_description = "Approval regression test tool";
    pub const tool_params =
        \\{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}
    ;
    const vtable = tools_mod.ToolVTable(@This());

    fn tool(self: *ApprovalTestTool) Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn execute(self: *ApprovalTestTool, _: std.mem.Allocator, args: std.json.ObjectMap) !tools_mod.ToolResult {
        const command = tools_mod.getString(args, "command") orelse return tools_mod.ToolResult.fail("missing command");
        if (!tools_mod.threadCommandApproved(tool_name, command, null)) return error.ApprovalRequired;
        self.execution_count += 1;
        return tools_mod.ToolResult.ok("api_key=test-key-approved-output");
    }
};

const SlashApprovalTestTool = struct {
    execution_count: usize = 0,

    pub const tool_name = "shell";
    pub const tool_description = "Slash approval regression test tool";
    pub const tool_params =
        \\{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}
    ;
    const vtable = tools_mod.ToolVTable(@This());

    fn tool(self: *SlashApprovalTestTool) Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn execute(self: *SlashApprovalTestTool, _: std.mem.Allocator, args: std.json.ObjectMap) !tools_mod.ToolResult {
        const command = tools_mod.getString(args, "command") orelse return tools_mod.ToolResult.fail("missing command");
        if (!tools_mod.threadCommandApproved(tool_name, command, null)) return error.ApprovalRequired;
        self.execution_count += 1;
        return tools_mod.ToolResult.ok("mock command completed");
    }
};

const ApprovalCapture = struct {
    accepted: bool = true,
    count: usize = 0,
    request_id: [APPROVAL_REQUEST_ID_LEN]u8 = [_]u8{0} ** APPROVAL_REQUEST_ID_LEN,

    fn callback(ctx: *anyopaque, request: ApprovalRequest) bool {
        const self: *ApprovalCapture = @ptrCast(@alignCast(ctx));
        self.count += 1;
        if (request.request_id.len == APPROVAL_REQUEST_ID_LEN) {
            @memcpy(&self.request_id, request.request_id);
        }
        return self.accepted;
    }
};

fn makeApprovalTestAgent(
    allocator: std.mem.Allocator,
    tools: []const Tool,
    observer: Observer,
    capture: *ApprovalCapture,
) !Agent {
    return .{
        .allocator = allocator,
        .provider = undefined,
        .tools = tools,
        .tool_specs = try allocator.alloc(ToolSpec, 0),
        .mem = null,
        .observer = observer,
        .model_name = "test",
        .temperature = 0.7,
        .workspace_dir = "/tmp/test",
        .max_tool_iterations = 10,
        .max_history_messages = 50,
        .auto_save = false,
        .history = .empty,
        .approval_callback = ApprovalCapture.callback,
        .approval_ctx = @ptrCast(capture),
    };
}

fn emitPreparedApprovalForTest(agent: *Agent) !void {
    const pending = if (agent.pending_approval) |*value| value else return error.TestUnexpectedResult;
    if (pending.history_rollback_index == null) {
        const assistant_content = try agent.allocator.dupe(u8, "<tool_call name=\"approval_test\">{}</tool_call>");
        errdefer agent.allocator.free(assistant_content);
        const cancel_content = try agent.allocator.dupe(u8, "");
        errdefer agent.allocator.free(cancel_content);
        const history_index = agent.history.items.len;
        try agent.history.append(agent.allocator, .{ .role = .assistant, .content = assistant_content });
        pending.history_rollback_index = history_index;
        pending.cancel_assistant_content = cancel_content;
    }
    if (!agent.emitApprovalRequest(pending)) {
        agent.clearPendingApproval();
        return error.ApprovalUnavailable;
    }
}

test "pending approvals prevent mid-turn injection drain" {
    // Regression: an approval created inside Agent.turn must not consume text
    // that arrived while the turn was running; the text remains queued for a
    // separate authenticated turn after the approval is resolved.
    const DrainProbe = struct {
        call_count: usize = 0,

        fn callback(ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!?[]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.call_count += 1;
            return try allocator.dupe(u8, "queued user text");
        }
    };

    const allocator = std.testing.allocator;
    const no_tools = [_]Tool{};
    var noop = observability.NoopObserver{};
    var approval_capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &no_tools, noop.observer(), &approval_capture);
    defer agent.deinit();
    var drain_probe = DrainProbe{};
    agent.drain_injection_cb = DrainProbe.callback;
    agent.drain_injection_ctx = @ptrCast(&drain_probe);

    agent.pending_exec_command = "legacy pending command";
    try std.testing.expect((try agent.drainPendingInjection()) == null);
    try std.testing.expectEqual(@as(usize, 0), drain_probe.call_count);
    agent.pending_exec_command = null;

    try agent.setPendingToolApproval(
        "approval_test",
        "provider-call-id",
        "guarded action",
        .medium,
        "{\"command\":\"guarded action\"}",
    );
    try std.testing.expect((try agent.drainPendingInjection()) == null);
    try std.testing.expectEqual(@as(usize, 0), drain_probe.call_count);
    agent.clearPendingApproval();

    const drained = (try agent.drainPendingInjection()) orelse return error.TestUnexpectedResult;
    defer allocator.free(drained);
    try std.testing.expectEqualStrings("queued user text", drained);
    try std.testing.expectEqual(@as(usize, 1), drain_probe.call_count);
}

test "approval request uses one-shot server id and exact approved invocation" {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    var arena_impl = std.heap.ArenaAllocator.init(allocator);
    defer arena_impl.deinit();
    const call = ParsedToolCall{
        .name = "approval_test",
        .arguments_json = "{\"command\":\"approved command\"}",
        .tool_call_id = "provider-call-id",
    };

    const pending_result = agent.executeTool(arena_impl.allocator(), call);
    try std.testing.expect(!pending_result.success);
    try std.testing.expect(agent.pending_approval != null);
    try std.testing.expectEqual(@as(usize, 0), capture.count);
    try emitPreparedApprovalForTest(&agent);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);

    var mismatch = try agent.resolveApproval("not-the-server-id", true, null);
    defer mismatch.deinit(allocator);
    try std.testing.expect(mismatch == .request_mismatch);
    try std.testing.expect(agent.pending_approval != null);

    var resolved = try agent.resolveApproval(&capture.request_id, true, null);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved == .resolved);
    try std.testing.expectEqual(@as(usize, 1), tool_impl.execution_count);
    try std.testing.expect(agent.pending_approval == null);
    try std.testing.expect(std.mem.indexOf(u8, resolved.resolved.tool_result_message, "test-key-approved-output") == null);

    var replay = try agent.resolveApproval(&capture.request_id, true, null);
    defer replay.deinit(allocator);
    try std.testing.expect(replay == .no_pending);
}

test "slash approve supplies an exact grant to approval-aware shell tools" {
    const BarrierProbe = struct {
        calls: usize = 0,

        fn callback(ctx: *anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            if (self.calls > 1) return error.DuplicateBarrierCall;
        }
    };

    const allocator = std.testing.allocator;
    var tool_impl = SlashApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    const exec_response = (try agent.handleSlashCommand("/exec ask=always")).?;
    defer allocator.free(exec_response);
    const owner_context: prompt.ConversationContext = .{
        .channel = "web",
        .account_id = "web-main",
        .sender_id = "owner-a",
        .peer_id = "shared-session",
        .is_group = false,
    };
    agent.conversation_context = owner_context;
    const pending_response = (try agent.handleSlashCommand("/bash guarded-command")).?;
    defer allocator.free(pending_response);
    try std.testing.expect(agent.pending_exec_command != null);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);

    // Regression: collapsed DM scopes can share an Agent. A different
    // authenticated principal must neither inspect nor consume the owner's
    // legacy slash-command approval.
    agent.conversation_context = .{
        .channel = "web",
        .account_id = "web-main",
        .sender_id = "attacker-b",
        .peer_id = "shared-session",
        .is_group = false,
    };
    const foreign_response = (try agent.handleSlashCommand("/approve allow-once")).?;
    defer allocator.free(foreign_response);
    try std.testing.expectEqualStrings("No pending approval requests.", foreign_response);
    try std.testing.expect(agent.pending_exec_command != null);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);

    agent.conversation_context = owner_context;
    var barrier = BarrierProbe{};
    agent.before_tool_dispatch_cb = BarrierProbe.callback;
    agent.before_tool_dispatch_ctx = @ptrCast(&barrier);
    const approved_response = (try agent.handleSlashCommand("/approve allow-always")).?;
    defer allocator.free(approved_response);
    try std.testing.expect(std.mem.indexOf(u8, approved_response, "mock command completed") != null);
    try std.testing.expectEqual(@as(usize, 1), barrier.calls);
    try std.testing.expectEqual(@as(usize, 1), tool_impl.execution_count);
    try std.testing.expect(agent.pending_exec_command == null);
    try std.testing.expect(agent.exec_ask == .off);
}

test "approved tool rechecks current execution security" {
    const allocator = std.testing.allocator;
    var tool_impl = SlashApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    try agent.setPendingToolApproval("shell", null, "guarded-command", .medium, "{\"command\":\"guarded-command\"}");
    try emitPreparedApprovalForTest(&agent);
    agent.exec_security = .deny;
    var blocked = try agent.resolveApproval(&capture.request_id, true, null);
    defer blocked.deinit(allocator);
    try std.testing.expect(blocked == .resolved);
    try std.testing.expect(std.mem.indexOf(u8, blocked.resolved.tool_result_message, "security=deny") != null);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);

    agent.exec_security = .allowlist;
    agent.exec_ask = .always;
    try agent.setPendingToolApproval("shell", null, "guarded-command", .medium, "{\"command\":\"guarded-command\"}");
    try emitPreparedApprovalForTest(&agent);
    var allowed = try agent.resolveApproval(&capture.request_id, true, null);
    defer allowed.deinit(allocator);
    try std.testing.expect(allowed == .resolved);
    try std.testing.expectEqual(@as(usize, 1), tool_impl.execution_count);
}

test "approval denial and expiry never execute tool" {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    try agent.setPendingToolApproval("approval_test", null, "denied command", .high, "{\"command\":\"denied command\"}");
    try emitPreparedApprovalForTest(&agent);
    var denied = try agent.resolveApproval(&capture.request_id, false, "not now");
    defer denied.deinit(allocator);
    try std.testing.expect(denied == .resolved);
    try std.testing.expect(std.mem.indexOf(u8, denied.resolved.tool_result_message, "denied") != null);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);

    try agent.setPendingToolApproval("approval_test", null, "expired command", .medium, "{\"command\":\"expired command\"}");
    try emitPreparedApprovalForTest(&agent);
    agent.pending_approval.?.timestamp = std_compat.time.timestamp() - APPROVAL_REQUEST_TTL_SECS - 1;
    var expired = try agent.resolveApproval(&agent.pending_approval.?.request_id, true, null);
    defer expired.deinit(allocator);
    try std.testing.expect(expired == .expired);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);
}

test "approval TTL expires at boundary and on wall clock rollback" {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    try agent.setPendingToolApproval("approval_test", null, "boundary command", .medium, "{\"command\":\"boundary command\"}");
    try emitPreparedApprovalForTest(&agent);
    agent.pending_approval.?.timestamp = std_compat.time.timestamp() - APPROVAL_REQUEST_TTL_SECS;
    var boundary = try agent.resolveApproval(&capture.request_id, true, null);
    defer boundary.deinit(allocator);
    try std.testing.expect(boundary == .expired);

    try agent.setPendingToolApproval("approval_test", null, "rollback command", .medium, "{\"command\":\"rollback command\"}");
    try emitPreparedApprovalForTest(&agent);
    agent.pending_approval.?.timestamp = std_compat.time.timestamp() + 60;
    var rollback = try agent.resolveApproval(&capture.request_id, true, null);
    defer rollback.deinit(allocator);
    try std.testing.expect(rollback == .expired);
    try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);
}

test "approval request fails closed when delivery is unavailable or another request is pending" {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{ .accepted = false };
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    try agent.setPendingToolApproval("approval_test", null, "first command", .medium, "{\"command\":\"first command\"}");
    try std.testing.expectError(error.ApprovalUnavailable, emitPreparedApprovalForTest(&agent));
    try std.testing.expect(agent.pending_approval == null);

    capture.accepted = true;
    try agent.setPendingToolApproval("approval_test", null, "first command", .medium, "{\"command\":\"first command\"}");
    try emitPreparedApprovalForTest(&agent);
    const first_request_id = agent.pending_approval.?.request_id;
    try std.testing.expectError(
        error.ApprovalAlreadyPending,
        agent.setPendingToolApproval("approval_test", null, "second command", .medium, "{\"command\":\"second command\"}"),
    );
    try std.testing.expectEqualSlices(u8, &first_request_id, &agent.pending_approval.?.request_id);
    try std.testing.expectEqualStrings("first command", agent.pending_approval.?.action);
}

test "approval lifecycle is visible to poll and cleared by stop and reset" {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();

    try agent.setPendingToolApproval("approval_test", null, "lifecycle command", .medium, "{\"command\":\"lifecycle command\"}");
    try emitPreparedApprovalForTest(&agent);
    const poll_response = (try agent.handleSlashCommand("/poll")).?;
    defer allocator.free(poll_response);
    try std.testing.expect(std.mem.indexOf(u8, poll_response, "request_id=") == null);
    try std.testing.expect(std.mem.indexOf(u8, poll_response, &capture.request_id) == null);
    try std.testing.expect(std.mem.indexOf(u8, poll_response, "lifecycle command") == null);
    try std.testing.expect(std.mem.indexOf(u8, poll_response, "tool=approval_test") != null);

    const stop_response = (try agent.handleSlashCommand("/stop")).?;
    defer allocator.free(stop_response);
    try std.testing.expect(agent.pending_approval == null);

    try agent.setPendingToolApproval("approval_test", null, "reset command", .medium, "{\"command\":\"reset command\"}");
    try emitPreparedApprovalForTest(&agent);
    const reset_response = (try agent.handleSlashCommand("/new")).?;
    defer allocator.free(reset_response);
    try std.testing.expect(agent.pending_approval == null);
}

test "approval pauses a multi-tool batch before later side effects" {
    // Regression: #900 a pending approval must suspend the turn instead of
    // allowing later tool calls in the same provider batch to execute.
    const SideEffectProbe = struct {
        execution_count: usize = 0,

        pub const tool_name = "side_effect_probe";
        pub const tool_description = "Approval batch regression probe";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{}}";
        const vtable = tools_mod.ToolVTable(@This());

        fn tool(self: *@This()) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *@This(), _: std.mem.Allocator, _: std.json.ObjectMap) !tools_mod.ToolResult {
            self.execution_count += 1;
            return tools_mod.ToolResult.ok("probe executed");
        }
    };

    const PreApprovalProbe = struct {
        execution_count: usize = 0,

        pub const tool_name = "pre_approval_probe";
        pub const tool_description = "Completed-result preservation probe";
        pub const tool_params = "{\"type\":\"object\",\"properties\":{}}";
        const vtable = tools_mod.ToolVTable(@This());

        fn tool(self: *@This()) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(self: *@This(), _: std.mem.Allocator, _: std.json.ObjectMap) !tools_mod.ToolResult {
            self.execution_count += 1;
            return tools_mod.ToolResult.ok("pre-approval result preserved");
        }
    };

    const BatchProvider = struct {
        call_count: usize = 0,
        continuation_model_preserved: bool = false,
        continuation_has_tool_result: bool = false,
        continuation_has_later_call: bool = false,

        fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
            return allocator.dupe(u8, "");
        }

        fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, request: providers.ChatRequest, model: []const u8, _: f64) anyerror!providers.ChatResponse {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
            if (self.call_count > 1) {
                self.continuation_model_preserved = std.mem.eql(u8, request.model, "test-model") and
                    std.mem.eql(u8, model, "test-model");
                for (request.messages) |message| {
                    if (std.mem.indexOf(u8, message.content, "<tool_result name=\"approval_test\"") != null) {
                        self.continuation_has_tool_result = true;
                    }
                    if (message.role == .assistant and std.mem.indexOf(u8, message.content, "side_effect_probe") != null) {
                        self.continuation_has_later_call = true;
                    }
                }
                if (self.call_count == 2) {
                    // Regression: provider retries the exact completed calls
                    // after the approval split. The logical-turn dedup cache
                    // must return prior results without repeating side effects.
                    const repeated_calls = try allocator.alloc(providers.ToolCall, 2);
                    repeated_calls[0] = .{
                        .id = try allocator.dupe(u8, "pre-approval-call"),
                        .name = try allocator.dupe(u8, "pre_approval_probe"),
                        .arguments = try allocator.dupe(u8, "{}"),
                    };
                    repeated_calls[1] = .{
                        .id = try allocator.dupe(u8, "approval-call"),
                        .name = try allocator.dupe(u8, "approval_test"),
                        .arguments = try allocator.dupe(u8, "{\"command\":\"guarded command\"}"),
                    };
                    return .{
                        .content = try allocator.dupe(u8, "replaying completed calls"),
                        .tool_calls = repeated_calls,
                        .usage = .{},
                        .model = try allocator.dupe(u8, "test-model"),
                    };
                }
                return .{
                    .content = try allocator.dupe(u8, "batch continued after approval"),
                    .usage = .{},
                    .model = try allocator.dupe(u8, "test-model"),
                };
            }
            const tool_calls = try allocator.alloc(providers.ToolCall, 3);
            tool_calls[0] = .{
                .id = try allocator.dupe(u8, "pre-approval-call"),
                .name = try allocator.dupe(u8, "pre_approval_probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            tool_calls[1] = .{
                .id = try allocator.dupe(u8, "approval-call"),
                .name = try allocator.dupe(u8, "approval_test"),
                .arguments = try allocator.dupe(u8, "{\"command\":\"guarded command\"}"),
            };
            tool_calls[2] = .{
                .id = try allocator.dupe(u8, "side-effect-call"),
                .name = try allocator.dupe(u8, "side_effect_probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            return .{
                .content = try allocator.dupe(u8, "requesting tools"),
                .tool_calls = tool_calls,
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        fn supportsNativeTools(_: *anyopaque) bool {
            return true;
        }
        fn getName(_: *anyopaque) []const u8 {
            return "approval-batch-provider";
        }
        fn deinitFn(_: *anyopaque) void {}
    };

    const allocator = std.testing.allocator;
    var provider_state = BatchProvider{};
    const provider_vtable = Provider.VTable{
        .chatWithSystem = BatchProvider.chatWithSystem,
        .chat = BatchProvider.chat,
        .supportsNativeTools = BatchProvider.supportsNativeTools,
        .getName = BatchProvider.getName,
        .deinit = BatchProvider.deinitFn,
    };
    const provider = Provider{ .ptr = @ptrCast(&provider_state), .vtable = &provider_vtable };

    var pre_approval_tool_impl = PreApprovalProbe{};
    var approval_tool_impl = ApprovalTestTool{};
    var side_effect_tool_impl = SideEffectProbe{};
    const test_tools = [_]Tool{ pre_approval_tool_impl.tool(), approval_tool_impl.tool(), side_effect_tool_impl.tool() };
    var specs = try allocator.alloc(ToolSpec, test_tools.len);
    for (test_tools, 0..) |tool, index| {
        specs[index] = .{
            .name = tool.name(),
            .description = tool.description(),
            .parameters_json = tool.parametersJson(),
        };
    }

    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = Agent{
        .allocator = allocator,
        .provider = provider,
        .tools = &test_tools,
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
        .approval_callback = ApprovalCapture.callback,
        .approval_ctx = @ptrCast(&capture),
    };
    defer agent.deinit();

    const response = try agent.turn("run guarded batch");
    defer allocator.free(response);
    try std.testing.expectEqualStrings("Approval requested. Waiting for your decision.", response);
    try std.testing.expectEqual(@as(usize, 1), provider_state.call_count);
    try std.testing.expectEqual(@as(usize, 1), pre_approval_tool_impl.execution_count);
    try std.testing.expectEqual(@as(usize, 0), approval_tool_impl.execution_count);
    try std.testing.expectEqual(@as(usize, 0), side_effect_tool_impl.execution_count);
    try std.testing.expect(agent.pending_approval != null);
    var preserved_result_found = false;
    var later_call_found = false;
    for (agent.history.items) |message| {
        if (std.mem.indexOf(u8, message.content, "pre-approval result preserved") != null) {
            preserved_result_found = true;
        }
        if (message.role == .assistant and std.mem.indexOf(u8, message.content, "side_effect_probe") != null) {
            later_call_found = true;
        }
    }
    try std.testing.expect(preserved_result_found);
    try std.testing.expect(!later_call_found);

    var resolution = try agent.resolveApproval(&capture.request_id, true, null);
    defer resolution.deinit(allocator);
    if (resolution != .resolved) return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("run guarded batch", resolution.resolved.user_message.?);
    try std.testing.expectEqualStrings("test-model", resolution.resolved.model_name.?);
    const continued = try agent.continueAfterApproval(
        resolution.resolved.tool_result_message,
        resolution.resolved.user_message,
        resolution.resolved.model_name,
        resolution.resolved.persistence_user_message,
        &resolution.resolved.replay_results,
    );
    defer allocator.free(continued);
    try std.testing.expectEqualStrings("batch continued after approval", continued);
    try std.testing.expectEqual(@as(usize, 3), provider_state.call_count);
    try std.testing.expectEqual(@as(usize, 1), approval_tool_impl.execution_count);
    try std.testing.expectEqual(@as(usize, 0), side_effect_tool_impl.execution_count);
    try std.testing.expect(provider_state.continuation_model_preserved);
    try std.testing.expect(provider_state.continuation_has_tool_result);
    try std.testing.expect(!provider_state.continuation_has_later_call);
}

fn configureApprovalAllocationContext(agent: *Agent) void {
    agent.conversation_context = .{
        .channel = "web",
        .account_id = "web-main",
        .delivery_chat_id = "session-a",
        .sender_id = "owner-a",
        .peer_id = "session-a",
        .group_id = "group-a",
        .is_group = false,
    };
    agent.approval_turn_user_message = "original routed user request";
    agent.approval_turn_model_name = "provider/routed-model";
    agent.approval_turn_persistence_message = "raw original user request";
}

fn approvalAllocationHarness(allocator: std.mem.Allocator) !void {
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();
    configureApprovalAllocationContext(&agent);
    try agent.setPendingToolApproval(
        "approval_test",
        "provider-call-id",
        "test command",
        .medium,
        "{\"command\":\"test command\"}",
    );
}

const ApprovalResolutionFailureOutcome = struct {
    resolved: bool = false,
    execution_count: usize = 0,
};

fn approvalResolutionFailureCase(
    failing: *std.testing.FailingAllocator,
    outcome: *ApprovalResolutionFailureOutcome,
) !void {
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();
    configureApprovalAllocationContext(&agent);
    try agent.setPendingToolApproval(
        "approval_test",
        "provider-call-id",
        "test command",
        .medium,
        "{\"command\":\"test command\"}",
    );
    try emitPreparedApprovalForTest(&agent);
    const request_id = capture.request_id;

    agent.allocator = failing.allocator();
    const history_len_before = agent.history.items.len;
    var resolved = agent.resolveApproval(&request_id, true, null) catch |err| {
        agent.allocator = allocator;
        try std.testing.expectEqual(error.OutOfMemory, err);
        // Every propagated OOM occurs before the approved invocation starts,
        // so the authenticated one-shot request remains safely retryable.
        try std.testing.expect(agent.pending_approval != null);
        try std.testing.expectEqual(@as(usize, 0), tool_impl.execution_count);
        try std.testing.expectEqual(history_len_before, agent.history.items.len);
        return;
    };
    agent.allocator = allocator;
    defer resolved.deinit(allocator);
    if (resolved != .resolved) return error.TestUnexpectedResult;
    outcome.resolved = true;
    outcome.execution_count = tool_impl.execution_count;
    try std.testing.expect(agent.pending_approval == null);
    try std.testing.expectEqual(history_len_before + 1, agent.history.items.len);
    try std.testing.expectEqual(providers.Role.user, agent.history.items[agent.history.items.len - 1].role);
    try std.testing.expectEqual(@as(usize, 1), resolved.resolved.replay_results.count());
    try std.testing.expect(tool_impl.execution_count <= 1);

    var replay = try agent.resolveApproval(&request_id, true, null);
    defer replay.deinit(allocator);
    try std.testing.expect(replay == .no_pending);
    try std.testing.expectEqual(outcome.execution_count, tool_impl.execution_count);
}

test "approval pending state handles every allocation failure without leaks" {
    // Regression: #900 approval creation must fail closed on OOM rather than
    // dropping its correlation id or leaking a partially built request.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, approvalAllocationHarness, .{});
}

test "approval resolution remains exact once at every allocation failure" {
    // Regression: #900 OOM before execution leaves the request pending, while
    // OOM after execution consumes it with a replay fallback. Neither path may
    // execute the approved side effect twice or leak owned approval state.
    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var counted_outcome = ApprovalResolutionFailureOutcome{};
    try approvalResolutionFailureCase(&counting, &counted_outcome);
    try std.testing.expect(counted_outcome.resolved);
    const allocation_count = counting.alloc_index;
    try std.testing.expect(allocation_count > 0);

    for (0..allocation_count) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var outcome = ApprovalResolutionFailureOutcome{};
        try approvalResolutionFailureCase(&failing, &outcome);
        try std.testing.expect(failing.has_induced_failure);
    }
}

test "approval continuation OOM leaves canonical paired history" {
    // Regression: once an approved side effect has run, a later continuation
    // allocation failure must not leave the assistant tool call dangling.
    const allocator = std.testing.allocator;
    var tool_impl = ApprovalTestTool{};
    const test_tools = [_]Tool{tool_impl.tool()};
    var noop = observability.NoopObserver{};
    var capture = ApprovalCapture{};
    var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
    defer agent.deinit();
    var provider_state = CompactionTestProvider{};
    agent.provider = .{ .ptr = @ptrCast(&provider_state), .vtable = &CompactionTestProvider.vtable };
    configureApprovalAllocationContext(&agent);
    try agent.setPendingToolApproval(
        "approval_test",
        "provider-call-id",
        "test command",
        .medium,
        "{\"command\":\"test command\"}",
    );
    try emitPreparedApprovalForTest(&agent);

    var resolution = try agent.resolveApproval(&capture.request_id, true, null);
    defer resolution.deinit(allocator);
    if (resolution != .resolved) return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), tool_impl.execution_count);
    const paired_history_len = agent.history.items.len;
    try std.testing.expectEqual(providers.Role.user, agent.history.items[paired_history_len - 1].role);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    agent.allocator = failing.allocator();
    _ = agent.continueAfterApproval(
        resolution.resolved.tool_result_message,
        resolution.resolved.user_message,
        resolution.resolved.model_name,
        resolution.resolved.persistence_user_message,
        &resolution.resolved.replay_results,
    ) catch {
        agent.allocator = allocator;
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(paired_history_len, agent.history.items.len);
        try std.testing.expectEqual(@as(usize, 1), tool_impl.execution_count);
        return;
    };
    agent.allocator = allocator;
    return error.TestUnexpectedResult;
}

test "approval boundary formatting OOM after prior side effect remains exact once" {
    // Regression: #900 a failure while canonicalizing an approval boundary
    // happens after earlier calls in the same batch may have produced side
    // effects. That failure must use the preallocated fallback, retain replay
    // receipts, and never run either completed call again on continuation.
    const Harness = struct {
        const Stats = struct {
            first_effect_alloc_index: usize = 0,
            allocation_count: usize = 0,
        };

        const PreApprovalProbe = struct {
            failing: *std.testing.FailingAllocator,
            execution_count: usize = 0,
            alloc_index_at_effect: usize = 0,

            pub const tool_name = "approval_boundary_pre_probe";
            pub const tool_description = "Approval boundary allocation regression probe";
            pub const tool_params = "{\"type\":\"object\",\"properties\":{}}";
            const vtable = tools_mod.ToolVTable(@This());

            fn tool(self: *@This()) Tool {
                return .{ .ptr = @ptrCast(self), .vtable = &vtable };
            }

            pub fn execute(self: *@This(), _: std.mem.Allocator, _: std.json.ObjectMap) !tools_mod.ToolResult {
                self.execution_count += 1;
                self.alloc_index_at_effect = self.failing.alloc_index;
                return tools_mod.ToolResult.ok("pre-approval side effect completed");
            }
        };

        const BatchProvider = struct {
            call_count: usize = 0,

            fn makeToolCall(
                allocator: std.mem.Allocator,
                id: []const u8,
                name: []const u8,
                arguments: []const u8,
            ) !providers.ToolCall {
                const owned_id = try allocator.dupe(u8, id);
                errdefer allocator.free(owned_id);
                const owned_name = try allocator.dupe(u8, name);
                errdefer allocator.free(owned_name);
                const owned_arguments = try allocator.dupe(u8, arguments);
                return .{
                    .id = owned_id,
                    .name = owned_name,
                    .arguments = owned_arguments,
                };
            }

            fn batchResponse(allocator: std.mem.Allocator) !ChatResponse {
                const calls = try allocator.alloc(providers.ToolCall, 2);
                var initialized: usize = 0;
                errdefer {
                    for (calls[0..initialized]) |call| {
                        allocator.free(call.id);
                        allocator.free(call.name);
                        allocator.free(call.arguments);
                    }
                    allocator.free(calls);
                }
                calls[0] = try makeToolCall(
                    allocator,
                    "pre-approval-call",
                    "approval_boundary_pre_probe",
                    "{}",
                );
                initialized = 1;
                calls[1] = try makeToolCall(
                    allocator,
                    "approval-call",
                    "approval_test",
                    "{\"command\":\"guarded command\"}",
                );
                return .{ .tool_calls = calls };
            }

            fn chatWithSystem(_: *anyopaque, allocator: std.mem.Allocator, _: ?[]const u8, _: []const u8, _: []const u8, _: f64) anyerror![]const u8 {
                return allocator.dupe(u8, "unused");
            }

            fn chat(ptr: *anyopaque, allocator: std.mem.Allocator, _: providers.ChatRequest, _: []const u8, _: f64) anyerror!ChatResponse {
                const self: *@This() = @ptrCast(@alignCast(ptr));
                self.call_count += 1;
                if (self.call_count <= 2) return batchResponse(allocator);
                return .{ .content = try allocator.dupe(u8, "continued after approval") };
            }

            fn supportsNativeTools(_: *anyopaque) bool {
                return true;
            }

            fn getName(_: *anyopaque) []const u8 {
                return "approval-boundary-oom-provider";
            }

            fn deinitFn(_: *anyopaque) void {}

            const vtable = Provider.VTable{
                .chatWithSystem = chatWithSystem,
                .chat = chat,
                .supportsNativeTools = supportsNativeTools,
                .getName = getName,
                .deinit = deinitFn,
            };
        };

        fn run(fail_index: usize, stats: *Stats) !bool {
            const allocator = std.testing.allocator;
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
            var pre_approval_tool = PreApprovalProbe{ .failing = &failing };
            var approval_tool = ApprovalTestTool{};
            const test_tools = [_]Tool{ pre_approval_tool.tool(), approval_tool.tool() };
            var noop = observability.NoopObserver{};
            var capture = ApprovalCapture{};
            var provider_state = BatchProvider{};
            var agent = try makeApprovalTestAgent(allocator, &test_tools, noop.observer(), &capture);
            defer {
                // FailingAllocator delegates to testing.allocator, so restoring
                // the base allocator is sufficient to release all surviving
                // allocations even when the injected failure remains armed.
                agent.allocator = allocator;
                agent.deinit();
            }
            agent.provider = .{ .ptr = @ptrCast(&provider_state), .vtable = &BatchProvider.vtable };
            agent.model_name = "approval-boundary-oom-model";

            agent.allocator = failing.allocator();
            const response = agent.turn("run guarded batch") catch |err| {
                agent.allocator = allocator;
                stats.* = .{
                    .first_effect_alloc_index = pre_approval_tool.alloc_index_at_effect,
                    .allocation_count = failing.alloc_index,
                };
                try std.testing.expectEqual(error.OutOfMemory, err);
                // This index failed before a prepared approval existed. The
                // regression below selects only the later index that reaches
                // the boundary's canonical preallocated fallback.
                return false;
            };
            agent.allocator = allocator;
            defer allocator.free(response);
            stats.* = .{
                .first_effect_alloc_index = pre_approval_tool.alloc_index_at_effect,
                .allocation_count = failing.alloc_index,
            };

            if (!failing.has_induced_failure) return false;
            const pending = if (agent.pending_approval) |*value| value else return false;
            const history_index = pending.history_rollback_index orelse return false;
            if (history_index + 1 >= agent.history.items.len) return false;
            const assistant_entry = agent.history.items[history_index];
            const result_entry = agent.history.items[history_index + 1];
            const used_boundary_fallback =
                std.mem.indexOf(u8, assistant_entry.content, "stopped at an approval boundary") != null and
                std.mem.indexOf(u8, result_entry.content, "<tool_results status=\"memory_pressure\">") != null;
            if (!used_boundary_fallback) return false;

            try std.testing.expectEqualStrings("Approval requested. Waiting for your decision.", response);
            try std.testing.expectEqual(providers.Role.assistant, assistant_entry.role);
            try std.testing.expectEqual(providers.Role.user, result_entry.role);
            try std.testing.expectEqual(@as(usize, 1), pre_approval_tool.execution_count);
            try std.testing.expectEqual(@as(usize, 0), approval_tool.execution_count);
            try std.testing.expectEqual(@as(usize, 1), capture.count);
            try std.testing.expectEqual(@as(usize, 1), pending.replay_results.count());

            const request_id = capture.request_id;
            var resolution = try agent.resolveApproval(&request_id, true, null);
            defer resolution.deinit(allocator);
            if (resolution != .resolved) return error.TestUnexpectedResult;
            try std.testing.expect(agent.pending_approval == null);
            try std.testing.expectEqual(@as(usize, 1), pre_approval_tool.execution_count);
            try std.testing.expectEqual(@as(usize, 1), approval_tool.execution_count);

            var replay = try agent.resolveApproval(&request_id, true, null);
            defer replay.deinit(allocator);
            try std.testing.expect(replay == .no_pending);

            const continued = try agent.continueAfterApproval(
                resolution.resolved.tool_result_message,
                resolution.resolved.user_message,
                resolution.resolved.model_name,
                resolution.resolved.persistence_user_message,
                &resolution.resolved.replay_results,
            );
            defer allocator.free(continued);
            try std.testing.expectEqualStrings("continued after approval", continued);
            try std.testing.expectEqual(@as(usize, 3), provider_state.call_count);
            try std.testing.expectEqual(@as(usize, 1), pre_approval_tool.execution_count);
            try std.testing.expectEqual(@as(usize, 1), approval_tool.execution_count);
            return true;
        }
    };

    var baseline_stats = Harness.Stats{};
    try std.testing.expect(!try Harness.run(std.math.maxInt(usize), &baseline_stats));
    try std.testing.expect(baseline_stats.allocation_count > baseline_stats.first_effect_alloc_index);

    var found_boundary_failure = false;
    for (baseline_stats.first_effect_alloc_index..baseline_stats.allocation_count) |fail_index| {
        var failure_stats = Harness.Stats{};
        if (try Harness.run(fail_index, &failure_stats)) {
            found_boundary_failure = true;
            break;
        }
    }
    try std.testing.expect(found_boundary_failure);
}
