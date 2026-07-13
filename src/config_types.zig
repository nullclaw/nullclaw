const std = @import("std");
const net_security = @import("net_security.zig");
const search_base_url = @import("search_base_url.zig");
const tunnel_mod = @import("tunnel.zig");

/// Default context token budget used by agent compaction/context management.
/// Runtime fallback (`DEFAULT_CONTEXT_TOKENS`).
pub const DEFAULT_AGENT_TOKEN_LIMIT: u64 = 200_000;
/// Default generation cap when model/provider metadata does not define max output.
/// Runtime fallback (`DEFAULT_MODEL_MAX_TOKENS`).
pub const DEFAULT_MODEL_MAX_TOKENS: u32 = 8192;

// ── Autonomy Level ──────────────────────────────────────────────

/// Re-exported from security/policy.zig — single source of truth (with methods).
pub const AutonomyLevel = @import("security/policy.zig").AutonomyLevel;

// ── Hardware Transport ──────────────────────────────────────────

pub const HardwareTransport = enum {
    none,
    native,
    serial,
    probe,
};

// ── Sandbox Backend ─────────────────────────────────────────────

pub const SandboxBackend = enum {
    auto,
    landlock,
    firejail,
    bubblewrap,
    docker,
    none,
};

// ── Provider entry (for "providers" config section) ─────────────

pub const ProviderEntry = struct {
    pub const ApiMode = enum {
        chat_completions,
        responses,
        invalid,

        pub fn parse(raw: []const u8) ApiMode {
            if (std.mem.eql(u8, raw, "chat_completions")) return .chat_completions;
            if (std.mem.eql(u8, raw, "responses")) return .responses;
            return .invalid;
        }

        pub fn toSlice(self: ApiMode) []const u8 {
            return switch (self) {
                .chat_completions => "chat_completions",
                .responses => "responses",
                .invalid => "invalid",
            };
        }
    };

    name: []const u8,
    /// Provider credential payload.
    /// Usually a string API key/token.
    /// For providers that support structured credentials (e.g. Vertex service-account JSON),
    /// the parser accepts object/array JSON and stores it as a compact JSON string.
    api_key: ?[]const u8 = null,
    base_url: ?[]const u8 = null,
    /// Whether this provider supports native OpenAI-style tool_calls.
    /// Set to false to use XML tool format via system prompt instead.
    native_tools: bool = true,
    /// Optional User-Agent header for HTTP requests to this provider.
    /// When set, requests will include "User-Agent: {value}" header.
    user_agent: ?[]const u8 = null,
    /// Primary OpenAI-compatible protocol to use for this provider.
    /// Defaults to chat_completions for backward compatibility.
    api_mode: ApiMode = .chat_completions,
    /// When true, include `chat_template_kwargs.enable_thinking` in
    /// OpenAI-compatible chat requests based on `reasoning_effort`.
    /// Useful for custom vLLM/Qwen endpoints that require chat-template
    /// toggles instead of standard OpenAI reasoning fields.
    chat_template_enable_thinking_param: bool = false,
    /// Maximum estimated request text bytes before the streaming path is
    /// skipped and a non-streaming POST is used instead.
    /// null means no limit — streaming is always attempted (recommended for
    /// modern LLMs with large context windows).
    /// When set, 0 forces the non-streaming path for every request and any
    /// positive value applies that byte threshold. Example: 524288 for 512 KiB.
    max_streaming_prompt_bytes: ?usize = null,
    /// Optional compact JSON string of additional key-value pairs to merge into
    /// request bodies for OpenAI-compatible providers. The encoded value must
    /// be a JSON object.
    extra_body_params: ?[]const u8 = null,

    /// Provider base URLs must be absolute http(s) URLs with no query/fragment.
    /// Plain HTTP is accepted only for local/private hosts so intentional
    /// loopback and LAN providers keep working.
    pub fn isValidBaseUrl(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return false;
        if (std.mem.indexOfAny(u8, trimmed, " \t\r\n?#") != null) return false;

        const uri = std.Uri.parse(trimmed) catch return false;
        if (uri.query != null or uri.fragment != null) return false;
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        if (!is_https and !is_http) return false;

        const host = net_security.extractHost(trimmed) orelse return false;
        if (is_http and !net_security.isLocalHost(host)) return false;
        return true;
    }
};

// ── Audio media config (tools.media.audio) ─────────────────────

pub const AudioMediaConfig = struct {
    enabled: bool = true,
    provider: []const u8 = "groq",
    model: []const u8 = "whisper-large-v3",
    base_url: ?[]const u8 = null,
    language: ?[]const u8 = null,

    /// Audio transcription endpoints carry provider credentials. Keep the same
    /// URL boundary as provider base URLs: HTTPS for remote hosts, plain HTTP
    /// only for explicit local/private endpoints, and no query/fragment.
    pub fn isValidBaseUrl(raw: []const u8) bool {
        return ProviderEntry.isValidBaseUrl(raw);
    }
};

// ── Sub-config structs ──────────────────────────────────────────

pub const DiagnosticsConfig = struct {
    pub const OtelHeaderEntry = struct {
        key: []const u8,
        value: []const u8,
    };

    backend: []const u8 = "none",
    otel_endpoint: ?[]const u8 = null,
    otel_service_name: ?[]const u8 = null,
    otel_headers: []const OtelHeaderEntry = &.{},
    /// Optional max length for user-visible provider/API errors after scrubbing.
    /// If null, uses env var NULLCLAW_MAX_ERROR_CHARS (or built-in default).
    api_error_max_chars: ?u32 = null,
    /// Emit info logs for every executed tool call (name/id/duration/success).
    /// Arguments and tool output are never logged.
    log_tool_calls: bool = false,
    /// Emit info logs when a user message is received by SessionManager.
    /// Only metadata is logged (channel/session hash/message size), not content.
    log_message_receipts: bool = false,
    /// Emit full inbound/outbound user-visible message payloads.
    /// Intended for local debugging only (can include sensitive text).
    log_message_payloads: bool = false,
    /// Emit request/response payloads around provider chat calls.
    /// Intended for local debugging only (can include sensitive text).
    log_llm_io: bool = false,
    /// Persist per-response token counters to a JSONL ledger near config.json.
    /// This stores token counts only (provider/model/prompt/completion/total), not message text.
    token_usage_ledger_enabled: bool = true,
    /// Reset token usage ledger after this many hours. 0 disables time-based reset.
    token_usage_ledger_window_hours: u32 = 24,
    /// Maximum ledger file size before reset. 0 disables size-based reset.
    token_usage_ledger_max_bytes: u64 = 0,
    /// Maximum number of JSONL rows before reset. 0 disables row-limit reset.
    token_usage_ledger_max_lines: u64 = 0,

    /// OTLP endpoint must be an absolute HTTPS URL, or a local/private HTTP URL
    /// when exporting to a collector on the same machine, private network, or
    /// container runtime bridge.
    pub fn isValidOtelEndpoint(raw: []const u8) bool {
        var trimmed = std.mem.trim(u8, raw, " \t\r\n");
        while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
            trimmed = trimmed[0 .. trimmed.len - 1];
        }
        if (trimmed.len == 0) return false;

        const uri = std.Uri.parse(trimmed) catch return false;
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        if (!is_https and !is_http) return false;

        const host_comp = uri.host orelse return false;
        const host = switch (host_comp) {
            .raw => |h| h,
            .percent_encoded => |h| blk: {
                if (std.mem.indexOfScalar(u8, h, '%') != null) return false;
                break :blk h;
            },
        };
        if (host.len == 0) return false;
        if (std.mem.indexOfAny(u8, host, " \t\r\n") != null) return false;
        if (host[0] == ':') return false;

        if (is_http and !isPrivateOtelCollectorHost(host)) return false;

        if (host[0] == '[') {
            const close = std.mem.indexOfScalar(u8, host, ']') orelse return false;
            if (close != host.len - 1) return false;
        }

        if (uri.query != null or uri.fragment != null) return false;
        if (uri.port) |port| if (port == 0) return false;
        return true;
    }

    fn isPrivateOtelCollectorHost(host: []const u8) bool {
        if (net_security.isLocalHost(host)) return true;

        const bare = if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]"))
            host[1 .. host.len - 1]
        else
            host;
        if (bare.len == 0) return false;

        // Container networks commonly expose services by a single-label DNS
        // name such as `otel`. Keep the plaintext OTEL exception scoped to
        // runtime-local service names rather than broader dotted domains.
        if (std.mem.indexOfScalar(u8, bare, '.') == null and std.mem.indexOfScalar(u8, bare, ':') == null) {
            return true;
        }

        return false;
    }

    pub fn isValidOtelHeaderName(raw: []const u8) bool {
        return isValidHttpHeaderName(raw);
    }

    pub fn isValidOtelHeaderValue(raw: []const u8) bool {
        return isValidHttpHeaderValue(raw);
    }
};

fn isValidHttpsOrLocalHttpUrl(raw: []const u8) bool {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (std.mem.indexOfAny(u8, trimmed, " \t\r\n") != null) return false;

    const uri = std.Uri.parse(trimmed) catch return false;
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
    if (!is_https and !is_http) return false;

    const host_comp = uri.host orelse return false;
    const host = switch (host_comp) {
        .raw => |h| h,
        .percent_encoded => |h| blk: {
            if (std.mem.indexOfScalar(u8, h, '%') != null) return false;
            break :blk h;
        },
    };
    if (host.len == 0) return false;
    if (std.mem.indexOfAny(u8, host, " \t\r\n") != null) return false;
    if (host[0] == ':') return false;

    if (is_http and !net_security.isLocalHost(host)) return false;

    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return false;
        if (close != host.len - 1) return false;
    }

    if (std.mem.indexOfScalar(u8, trimmed, '#') != null) return false;
    if (uri.port) |port| if (port == 0) return false;
    return true;
}

fn isValidHttpHeaderName(raw: []const u8) bool {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return false;
    for (trimmed) |ch| {
        // RFC 7230 token subset; keep strict to prevent header injection.
        if (ch <= 0x20 or ch >= 0x7f) return false;
        if (ch == ':' or ch == '"' or ch == '\\') return false;
    }
    return true;
}

fn isValidHttpHeaderValue(raw: []const u8) bool {
    if (std.mem.indexOfAny(u8, raw, "\r\n") != null) return false;
    return true;
}

pub const AutonomyConfig = struct {
    level: AutonomyLevel = .supervised,
    workspace_only: bool = true,
    max_actions_per_hour: u32 = 20,
    require_approval_for_medium_risk: bool = true,
    block_high_risk_commands: bool = true,
    /// When true, block medium-risk commands. This includes network/transfer
    /// commands (curl, wget, nc, scp, ftp, telnet) and state-changing commands
    /// classified by arguments (git commit, npm install, touch, mkdir, etc.).
    block_medium_risk_commands: bool = true,
    allowed_commands: []const []const u8 = &.{},
    /// When true, skip the single-`&` shell-operator check so that bare
    /// `&` in URLs (e.g. `curl https://...?a=1&b=2`) is permitted.
    allow_raw_url_chars: bool = false,
    /// Additional directories (absolute paths) the agent may access beyond workspace_dir.
    /// Resolved via realpath at check time; system-critical paths are always blocked.
    allowed_paths: []const []const u8 = &.{},
};

pub const DockerRuntimeConfig = struct {
    image: []const u8 = "alpine:3.20",
    network: []const u8 = "none",
    memory_limit_mb: ?u64 = 512,
    cpu_limit: ?f64 = 1.0,
    read_only_rootfs: bool = true,
    mount_workspace: bool = true,
};

pub const RuntimeConfig = struct {
    kind: []const u8 = "native",
    docker: DockerRuntimeConfig = .{},
};

pub const ModelFallbackEntry = struct {
    model: []const u8,
    fallbacks: []const []const u8,
};

pub const ReliabilityConfig = struct {
    provider_retries: u32 = 2,
    provider_backoff_ms: u64 = 500,
    channel_initial_backoff_secs: u64 = 2,
    channel_max_backoff_secs: u64 = 60,
    scheduler_poll_secs: u64 = 15,
    scheduler_retries: u32 = 2,
    fallback_providers: []const []const u8 = &.{},
    api_keys: []const []const u8 = &.{},
    model_fallbacks: []const ModelFallbackEntry = &.{},
};

pub const InboundMessagesConfig = struct {
    debounce_ms: u32 = 3_000,
};

pub const MessagesConfig = struct {
    inbound: InboundMessagesConfig = .{},
};

pub const SchedulerConfig = struct {
    enabled: bool = true,
    max_tasks: u32 = 64,
    max_concurrent: u32 = 4,
    /// Hard timeout for cron agent subprocess execution. 0 = no timeout.
    agent_timeout_secs: u64 = 0,
};

// ── Tool filter groups ──────────────────────────────────────────

/// Controls which MCP tools are included in the schema sent to the LLM each turn.
///
/// Two modes:
///   - `always`:  tools matching `tools` patterns are always included (no keywords needed).
///   - `dynamic`: tools matching `tools` patterns are included only when the user message
///                contains at least one of the `keywords` (case-insensitive substring match).
///
/// Built-in (non-MCP) tools are always included regardless of filter groups.
/// If no filter groups are configured, all tools pass through unchanged.
pub const ToolFilterGroupMode = enum {
    always,
    dynamic,
};

pub const ToolFilterGroup = struct {
    mode: ToolFilterGroupMode,
    /// Glob patterns matched against tool names (e.g. "mcp_vikunja_*").
    /// Supports `*` wildcard only (prefix/suffix/infix).
    tools: []const []const u8 = &.{},
    /// Keywords for `dynamic` mode — case-insensitive substring match against user message.
    /// Ignored when mode is `always`.
    keywords: []const []const u8 = &.{},
};

pub const QueueMode = enum {
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

    pub fn fromSlice(s: []const u8) ?QueueMode {
        return if (std.ascii.eqlIgnoreCase(s, "off"))
            .off
        else if (std.ascii.eqlIgnoreCase(s, "serial"))
            .serial
        else if (std.ascii.eqlIgnoreCase(s, "latest"))
            .latest
        else if (std.ascii.eqlIgnoreCase(s, "debounce"))
            .debounce
        else
            null;
    }
};

pub const AgentConfig = struct {
    /// When true (default), history is auto-compacted once it crosses the
    /// token / message thresholds. Set to false to skip proactive LLM
    /// summarization while retaining hard trimming and emergency compression.
    /// Default is true to preserve the historical always-compact behavior.
    compact_context: bool = true,
    max_tool_iterations: u32 = 1000,
    max_history_messages: u32 = 100,
    parallel_tools: bool = false,
    tool_dispatcher: []const u8 = "auto",
    default_queue_mode: QueueMode = .off,
    token_limit: u64 = DEFAULT_AGENT_TOKEN_LIMIT,
    /// Internal parse marker: true only when token_limit is explicitly set in config.
    /// Not serialized; used to distinguish override vs default fallback chain.
    token_limit_explicit: bool = false,
    session_idle_timeout_secs: u64 = 1800, // evict idle sessions after 30 min
    compaction_keep_recent: u32 = 20,
    compaction_max_summary_chars: u32 = 2_000,
    compaction_max_source_chars: u32 = 12_000,
    /// Include emoji prefixes in `/status` output.
    status_show_emojis: bool = true,
    /// Max seconds to wait for an LLM HTTP response (curl --max-time). 0 = no limit.
    message_timeout_secs: u64 = 600,
    /// Timezone label used for prompt date/time section.
    /// Supported values: "UTC", "UTC+HH:MM", "UTC-HH:MM".
    timezone: []const u8 = "UTC",
    /// Per-turn MCP tool filtering. Empty slice = no filtering (all tools included).
    /// See ToolFilterGroup for semantics.
    tool_filter_groups: []const ToolFilterGroup = &.{},
    /// List of models that do not support image/vision input.
    /// When image markers are detected and the model is in this list,
    /// the agent will skip processing images instead of returning an error.
    vision_disabled_models: []const []const u8 = &.{},
    /// When true, automatically adds the current model to vision_disabled_models
    /// upon receiving a "model does not support vision" error.
    auto_disable_vision_on_error: bool = true,
    /// Redact PII in outbound provider messages for the root agent.
    enable_pii_redaction: bool = true,

    pub fn parseTimezoneOffsetSeconds(raw: []const u8) ?i64 {
        if (std.ascii.eqlIgnoreCase(raw, "UTC")) return 0;
        if (raw.len != 9) return null;
        if (!std.ascii.eqlIgnoreCase(raw[0..3], "UTC")) return null;

        const sign = raw[3];
        if (sign != '+' and sign != '-') return null;
        if (raw[6] != ':') return null;

        const hours = std.fmt.parseInt(i64, raw[4..6], 10) catch return null;
        const minutes = std.fmt.parseInt(i64, raw[7..9], 10) catch return null;
        if (hours < 0 or hours > 23) return null;
        if (minutes < 0 or minutes > 59) return null;

        const total = hours * 3600 + minutes * 60;
        return if (sign == '-') -total else total;
    }

    pub fn isValidTimezone(raw: []const u8) bool {
        return parseTimezoneOffsetSeconds(raw) != null;
    }
};

pub const ToolCustomization = struct {
    /// Tool name (e.g., "screenshot", "file_read", "shell")
    name: []const u8,
    /// Custom system prompt for this tool.
    /// If provided, this will override the default tool description.
    system_prompt: ?[]const u8 = null,
    /// Trigger keywords for this tool.
    /// When user message contains any of these keywords,
    /// the tool will be prioritized.
    triggers: []const []const u8 = &.{},
    /// Priority level (higher = more important).
    /// Default is 0.
    priority: u8 = 0,
    /// Whether this tool is enabled.
    enabled: bool = true,
};

pub const ToolsConfig = struct {
    shell_timeout_secs: u64 = 60,
    shell_max_output_bytes: u32 = 1_048_576, // 1MB
    max_file_size_bytes: u32 = 10_485_760, // 10MB — shared file_read/edit/append
    web_fetch_max_chars: u32 = 100_000,
    /// Environment variables whose values are platform path-list strings.
    /// Each path component is validated against workspace + allowed_paths
    /// using the same sandbox rules as file access (system blocklist,
    /// realpath canonicalization). Only vars where ALL path components
    /// resolve within allowed areas are passed to shell child processes.
    ///
    /// Example: ["LD_LIBRARY_PATH", "PYTHONHOME", "NODE_PATH"]
    path_env_vars: []const []const u8 = &.{},
    /// Tool customization configuration.
    /// Allows customizing system prompts, trigger keywords, and priorities for individual tools.
    tool_customizations: []const ToolCustomization = &.{},
    /// Optional path to external JSON file containing tool customizations.
    tool_customizations_file: ?[]const u8 = null,
    /// Custom modifiers to remove from user input when checking for exact trigger matches.
    trigger_modifiers: []const []const u8 = &.{},
    /// Custom punctuation characters to remove when checking for exact trigger matches.
    trigger_punctuation: []const u8 = "",
};

pub const ModelRouteCostClass = enum {
    free,
    cheap,
    standard,
    premium,
};

pub const ModelRouteQuotaClass = enum {
    unlimited,
    normal,
    constrained,
};

pub const ModelRouteConfig = struct {
    hint: []const u8,
    provider: []const u8,
    model: []const u8,
    api_key: ?[]const u8 = null,
    cost_class: ModelRouteCostClass = .standard,
    quota_class: ModelRouteQuotaClass = .normal,
};

pub const HeartbeatConfig = struct {
    enabled: bool = false,
    interval_minutes: u32 = 30,
    prompt: ?[]const u8 = null,
    model: ?[]const u8 = null,
    timeout_secs: u32 = 120,
    delivery_mode: ?[]const u8 = null,
    delivery_channel: ?[]const u8 = null,
    delivery_to: ?[]const u8 = null,
    delivery_account_id: ?[]const u8 = null,
    delivery_peer_kind: ?[]const u8 = null,
    delivery_peer_id: ?[]const u8 = null,
    delivery_thread_id: ?[]const u8 = null,
    delivery_best_effort: bool = true,
};

pub const CronConfig = struct {
    enabled: bool = false,
    interval_minutes: u32 = 30,
    max_run_history: u32 = 50,
};

// ── Channel configs ─────────────────────────────────────────────

pub const TelegramInteractiveConfig = struct {
    enabled: bool = false,
    ttl_secs: u64 = 900,
    owner_only: bool = true,
    remove_on_click: bool = true,
};

pub const TelegramReactionEmojisConfig = struct {
    accepted: []const u8 = "👀",
    running: []const u8 = "⚡",
    done: []const u8 = "👍",
    failed: []const u8 = "💔",
};

pub const TelegramCommandsMenuMode = enum {
    off,
    flat,
    scoped,
};

pub const MaxListenerMode = enum {
    polling,
    webhook,
};

pub const MaxInteractiveConfig = struct {
    enabled: bool = false,
    ttl_secs: u64 = 900,
    owner_only: bool = true,
};

pub const MaxConfig = struct {
    account_id: []const u8 = "default",
    bot_token: []const u8,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
    proxy: ?[]const u8 = null,
    mode: MaxListenerMode = .polling,
    webhook_url: ?[]const u8 = null,
    webhook_secret: ?[]const u8 = null,
    interactive: MaxInteractiveConfig = .{},
    require_mention: bool = false,
    streaming: bool = true,
};

pub const TelegramConfig = struct {
    account_id: []const u8 = "default",
    bot_token: []const u8,
    /// Secret required in Telegram's X-Telegram-Bot-Api-Secret-Token header for webhook delivery.
    webhook_secret: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
    /// Use reply-to in private (1:1) chats. Groups always use reply-to.
    reply_in_private: bool = true,
    /// Optional SOCKS5/HTTP proxy URL for all Telegram API requests (e.g. "socks5://host:port").
    proxy: ?[]const u8 = null,
    interactive: TelegramInteractiveConfig = .{},
    /// When true, only respond to messages that @mention the bot (in groups).
    require_mention: bool = false,
    /// Enable streaming response generation for Telegram. When combined with
    /// `draft_previews=true`, partial responses are shown via sendMessageDraft.
    streaming: bool = true,
    /// Show ephemeral sendMessageDraft previews while the reply is still being generated.
    /// Disabled by default because Telegram drafts can disappear and reappear in a confusing way.
    draft_previews: bool = false,
    /// Show task lifecycle on the triggering user message via Telegram reactions.
    status_reactions: bool = false,
    /// Per-state reaction emoji overrides. Empty string clears the reaction for that state.
    reaction_emojis: TelegramReactionEmojisConfig = .{},
    /// Enable Telegram-specific binding commands such as /bind.
    binding_commands_enabled: bool = true,
    /// Enable Telegram-specific topic management commands such as /topic.
    topic_commands_enabled: bool = true,
    /// Enable Telegram-specific topic/session map command such as /topics.
    topic_map_command_enabled: bool = true,
    /// Publish Telegram slash-command menu:
    /// off = clear it, flat = one global list, scoped = separate private/group menus.
    commands_menu_mode: TelegramCommandsMenuMode = .flat,

    pub fn isValidWebhookSecret(raw: []const u8) bool {
        return WebConfig.isValidAuthToken(raw);
    }
};

pub const DiscordConfig = struct {
    account_id: []const u8 = "default",
    token: []const u8,
    guild_id: ?[]const u8 = null,
    allow_bots: bool = false,
    allow_from: []const []const u8 = &.{},
    require_mention: bool = false,
    intents: u32 = 37377, // GUILDS|GUILD_MESSAGES|MESSAGE_CONTENT|DIRECT_MESSAGES
};

pub const SlackReceiveMode = enum {
    socket,
    http,
};

pub const SlackReplyToMode = enum {
    /// Only thread when the triggering message is already a thread reply
    /// (thread_ts present and differs from ts). Default.
    off,
    /// Always reply in a thread, using thread_ts if present or message ts otherwise.
    all,
};

pub const SlackConfig = struct {
    account_id: []const u8 = "default",
    mode: SlackReceiveMode = .socket,
    bot_token: []const u8,
    app_token: ?[]const u8 = null,
    signing_secret: ?[]const u8 = null,
    webhook_path: []const u8 = "/slack/events",
    channel_id: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
    dm_policy: []const u8 = "pairing",
    group_policy: []const u8 = "mention_only",
    reply_to_mode: SlackReplyToMode = .off,
};

pub const TeamsConfig = struct {
    account_id: []const u8 = "default",
    client_id: []const u8,
    client_secret: []const u8,
    tenant_id: []const u8,
    webhook_secret: ?[]const u8 = null,
    notification_channel_id: ?[]const u8 = null,
    bot_id: ?[]const u8 = null,
    config_dir: []const u8 = ".",

    pub fn isValidWebhookSecret(raw: []const u8) bool {
        return WebConfig.isValidAuthToken(raw);
    }
};

pub const WebhookConfig = struct {
    port: u16 = 8080,
    secret: ?[]const u8 = null,
};

pub const IMessageConfig = struct {
    account_id: []const u8 = "default",
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
    db_path: ?[]const u8 = null,
    enabled: bool = false,
};

pub const MatrixConfig = struct {
    account_id: []const u8 = "default",
    homeserver: []const u8,
    access_token: []const u8,
    room_id: []const u8,
    user_id: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    dm_policy: []const u8 = "allowlist",
    group_policy: []const u8 = "allowlist",
    require_mention: bool = false,
    /// Optional pantalaimon E2EE proxy URL (e.g. "http://localhost:8008").
    /// When set, all Matrix API requests are routed through the proxy instead
    /// of directly to the homeserver. The homeserver field is still required
    /// for display and onboarding purposes.
    pantalaimon_proxy_url: ?[]const u8 = null,
};

pub const MattermostConfig = struct {
    account_id: []const u8 = "default",
    bot_token: []const u8,
    base_url: []const u8,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    dm_policy: []const u8 = "allowlist",
    group_policy: []const u8 = "allowlist",
    chatmode: []const u8 = "oncall",
    onchar_prefixes: []const []const u8 = &.{ ">", "!" },
    require_mention: bool = true,
};

pub const WhatsAppConfig = struct {
    account_id: []const u8 = "default",
    access_token: []const u8,
    phone_number_id: []const u8,
    verify_token: []const u8,
    app_secret: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    groups: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
};

pub const IrcConfig = struct {
    account_id: []const u8 = "default",
    host: []const u8,
    port: u16 = 6697,
    nick: []const u8,
    username: ?[]const u8 = null,
    channels: []const []const u8 = &.{},
    allow_from: []const []const u8 = &.{},
    server_password: ?[]const u8 = null,
    nickserv_password: ?[]const u8 = null,
    sasl_password: ?[]const u8 = null,
    tls: bool = true,
};

pub const LarkReceiveMode = enum {
    websocket,
    webhook,
};

pub const LarkConfig = struct {
    account_id: []const u8 = "default",
    app_id: []const u8,
    app_secret: []const u8,
    encrypt_key: ?[]const u8 = null,
    verification_token: ?[]const u8 = null,
    use_feishu: bool = false,
    allow_from: []const []const u8 = &.{},
    receive_mode: LarkReceiveMode = .websocket,
    port: ?u16 = null,
    reaction_emojis: []const []const u8 = &.{},
};

pub const DingTalkConfig = struct {
    account_id: []const u8 = "default",
    client_id: []const u8,
    client_secret: []const u8,
    allow_from: []const []const u8 = &.{},
    ai_card_template_id: ?[]const u8 = null,
    ai_card_streaming_key: ?[]const u8 = null,
};

pub const WeChatConfig = struct {
    account_id: []const u8 = "default",
    /// Callback verification token used by WeChat signature check.
    callback_token: []const u8,
    /// WeChat EncodingAESKey (43 chars base64 sem padding) para callbacks seguros (encrypt_type=aes).
    encoding_aes_key: ?[]const u8 = null,
    /// Optional Official Account app id (reserved for outbound API support).
    app_id: ?[]const u8 = null,
    /// Optional Official Account app secret (reserved for outbound API support).
    app_secret: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
};

pub const WeComConfig = struct {
    account_id: []const u8 = "default",
    webhook_url: []const u8,
    /// Callback verification token (used to compute/verify msg_signature).
    callback_token: ?[]const u8 = null,
    /// WeCom EncodingAESKey (43 chars base64 without padding) used to decrypt callback payloads.
    encoding_aes_key: ?[]const u8 = null,
    /// Expected receiver ID (typically CorpID) for decrypted callback validation.
    corp_id: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
};

pub const WeixinConfig = struct {
    account_id: []const u8 = "default",
    /// Bot token obtained from iLink QR code login flow.
    token: []const u8 = "",
    /// iLink API base URL (may be region-specific after login redirect).
    base_url: []const u8 = "https://ilinkai.weixin.qq.com/",
    /// Optional HTTP proxy URL for API requests.
    proxy: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
};

pub const SignalConfig = struct {
    account_id: []const u8 = "default",
    http_url: []const u8,
    account: []const u8,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
    ignore_attachments: bool = false,
    ignore_stories: bool = false,
};

pub const EmailConfig = struct {
    account_id: []const u8 = "default",
    imap_host: []const u8 = "",
    imap_port: u16 = 993,
    imap_folder: []const u8 = "INBOX",
    smtp_host: []const u8 = "",
    smtp_port: u16 = 587,
    smtp_tls: bool = true,
    username: []const u8 = "",
    password: []const u8 = "",
    from_address: []const u8 = "",
    poll_interval_secs: u64 = 60,
    allow_from: []const []const u8 = &.{},
    consent_granted: bool = true,
};

pub const LineConfig = struct {
    account_id: []const u8 = "default",
    access_token: []const u8,
    channel_secret: []const u8,
    port: u16 = 3000,
    allow_from: []const []const u8 = &.{},
};

pub const QQGroupPolicy = enum {
    allow,
    allowlist,
};

pub const QQReceiveMode = enum {
    websocket,
    webhook,
};

pub const QQConfig = struct {
    account_id: []const u8 = "default",
    app_id: []const u8 = "",
    app_secret: []const u8 = "",
    bot_token: []const u8 = "",
    sandbox: bool = false,
    receive_mode: QQReceiveMode = .webhook,
    group_policy: QQGroupPolicy = .allow,
    allowed_groups: []const []const u8 = &.{},
    allow_from: []const []const u8 = &.{},
};

pub const OneBotConfig = struct {
    account_id: []const u8 = "default",
    url: []const u8 = "ws://localhost:6700",
    access_token: ?[]const u8 = null,
    group_trigger_prefix: ?[]const u8 = null,
    allow_from: []const []const u8 = &.{},
};

pub const MaixCamConfig = struct {
    account_id: []const u8 = "default",
    port: u16 = 7777,
    host: []const u8 = "0.0.0.0",
    allow_from: []const []const u8 = &.{},
    name: []const u8 = "maixcam",
};

pub const WebConfig = struct {
    pub const DEFAULT_PATH: []const u8 = "/ws";
    pub const DEFAULT_TRANSPORT: []const u8 = "local";
    pub const DEFAULT_MESSAGE_AUTH_MODE: []const u8 = "pairing";
    pub const DEFAULT_MAX_HANDSHAKE_SIZE: u16 = 8_192;
    pub const MIN_AUTH_TOKEN_LEN: usize = 16;
    pub const MAX_AUTH_TOKEN_LEN: usize = 128;
    pub const MAX_RELAY_AGENT_ID_LEN: usize = 64;
    pub const MIN_RELAY_PAIRING_CODE_TTL_SECS: u32 = 60;
    pub const MAX_RELAY_PAIRING_CODE_TTL_SECS: u32 = 300;
    pub const MIN_RELAY_UI_TOKEN_TTL_SECS: u32 = 300;
    pub const MAX_RELAY_UI_TOKEN_TTL_SECS: u32 = 2_592_000; // 30 days
    pub const MIN_RELAY_TOKEN_TTL_SECS: u32 = 3_600;
    pub const MAX_RELAY_TOKEN_TTL_SECS: u32 = 31_536_000; // 365 days

    account_id: []const u8 = "default",
    /// "local" starts an inbound WS listener in nullclaw.
    /// "relay" keeps a single outbound WS connection to a relay service.
    transport: []const u8 = DEFAULT_TRANSPORT,
    port: u16 = 32123,
    listen: []const u8 = "127.0.0.1",
    path: []const u8 = DEFAULT_PATH,
    max_connections: u16 = 10,
    /// Max bytes allowed for the HTTP upgrade request headers during WS handshake.
    /// Increase this when running behind reverse proxies that append many headers.
    max_handshake_size: u16 = DEFAULT_MAX_HANDSHAKE_SIZE,
    /// Optional WebSocket-upgrade auth token for browser/extension clients.
    /// Used for WebSocket-upgrade hardening and for `message_auth_mode="token"`.
    /// If null, WebChannel falls back to env (NULLCLAW_WEB_TOKEN/NULLCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_TOKEN),
    /// then to an ephemeral runtime token.
    auth_token: ?[]const u8 = null,
    /// Authentication mode for inbound user_message events.
    /// - "pairing": require UI JWT access_token from pairing flow.
    /// - "token": require channel auth token in auth_token (or access_token for compatibility).
    message_auth_mode: []const u8 = DEFAULT_MESSAGE_AUTH_MODE,
    /// Optional allowlist for Origin header values (exact match, supports "*").
    /// Empty = allow any origin.
    allowed_origins: []const []const u8 = &.{},
    /// Relay endpoint for transport="relay" (must be wss://...).
    relay_url: ?[]const u8 = null,
    /// Stable logical agent identity on relay side.
    relay_agent_id: []const u8 = "default",
    /// Optional dedicated relay auth token.
    /// If omitted, relay lifecycle resolves token from NULLCLAW_RELAY_TOKEN,
    /// then persisted `web-relay-<account_id>` credential, then generates one.
    relay_token: ?[]const u8 = null,
    /// Expiry for persisted relay token lifecycle (seconds).
    relay_token_ttl_secs: u32 = 2_592_000,
    /// One-time pairing code lifetime for relay UI binding (seconds).
    relay_pairing_code_ttl_secs: u32 = 300,
    /// UI access token (JWT) TTL in relay mode (seconds).
    relay_ui_token_ttl_secs: u32 = 86_400,
    /// Require E2E payload encryption for relay user_message events.
    relay_e2e_required: bool = false,

    fn trimTrailingSlash(value: []const u8) []const u8 {
        if (value.len <= 1) return value;
        if (value[value.len - 1] == '/') return value[0 .. value.len - 1];
        return value;
    }

    pub fn normalizePath(raw: []const u8) []const u8 {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] != '/') return DEFAULT_PATH;
        return trimTrailingSlash(trimmed);
    }

    pub fn isPathWellFormed(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] != '/') return false;
        if (std.mem.indexOfAny(u8, trimmed, "?#")) |_| return false;
        return true;
    }

    pub fn isValidTransport(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, "local") or std.mem.eql(u8, trimmed, "relay");
    }

    pub fn isRelayTransport(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, "relay");
    }

    pub fn isValidMessageAuthMode(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, "pairing") or std.mem.eql(u8, trimmed, "token");
    }

    pub fn isTokenMessageAuthMode(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, "token");
    }

    fn isAllowedTokenByte(byte: u8) bool {
        return byte >= 0x21 and byte <= 0x7e and !std.ascii.isWhitespace(byte);
    }

    pub fn isValidAuthToken(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len < MIN_AUTH_TOKEN_LEN or trimmed.len > MAX_AUTH_TOKEN_LEN) return false;
        for (trimmed) |byte| {
            if (!isAllowedTokenByte(byte)) return false;
        }
        return true;
    }

    pub fn isValidAllowedOrigin(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return false;
        if (std.mem.eql(u8, trimmed, "*")) return true;
        if (std.mem.eql(u8, trimmed, "null")) return true;
        if (std.mem.indexOfAny(u8, trimmed, " \t\r\n")) |_| return false;
        const normalized = trimTrailingSlash(trimmed);
        const scheme_sep = std.mem.indexOf(u8, normalized, "://") orelse return false;
        if (scheme_sep == 0) return false;
        const authority = normalized[scheme_sep + 3 ..];
        if (authority.len == 0) return false;
        if (std.mem.indexOfAny(u8, authority, "/?#")) |_| return false;
        return true;
    }

    pub fn isValidRelayUrl(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (!std.mem.startsWith(u8, trimmed, "wss://")) return false;
        const no_scheme = trimmed["wss://".len..];
        if (no_scheme.len == 0) return false;
        const path_pos = std.mem.indexOfAny(u8, no_scheme, "/?");
        const authority = if (path_pos) |idx| no_scheme[0..idx] else no_scheme;
        if (authority.len == 0) return false;
        if (std.mem.indexOfAny(u8, authority, " \t\r\n")) |_| return false;
        if (path_pos) |idx| {
            const tail = no_scheme[idx..];
            // Keep runtime parser contract: optional path must start with '/'.
            if (tail.len > 0 and tail[0] != '/') return false;
            if (std.mem.indexOfScalar(u8, tail, '#') != null) return false;
        }
        return true;
    }

    pub fn isValidRelayAgentId(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0 or trimmed.len > MAX_RELAY_AGENT_ID_LEN) return false;
        if (std.mem.indexOfAny(u8, trimmed, " \t\r\n")) |_| return false;
        return true;
    }

    pub fn isValidRelayPairingCodeTtl(ttl_secs: u32) bool {
        return ttl_secs >= MIN_RELAY_PAIRING_CODE_TTL_SECS and ttl_secs <= MAX_RELAY_PAIRING_CODE_TTL_SECS;
    }

    pub fn isValidRelayUiTokenTtl(ttl_secs: u32) bool {
        return ttl_secs >= MIN_RELAY_UI_TOKEN_TTL_SECS and ttl_secs <= MAX_RELAY_UI_TOKEN_TTL_SECS;
    }

    pub fn isValidRelayTokenTtl(ttl_secs: u32) bool {
        return ttl_secs >= MIN_RELAY_TOKEN_TTL_SECS and ttl_secs <= MAX_RELAY_TOKEN_TTL_SECS;
    }
};

pub const NostrConfig = struct {
    /// Private key: must be enc2:-encrypted via SecretStore (use onboarding wizard or SecretStore.encryptSecret).
    /// Not required when bunker_uri is set (external bunker handles signing).
    private_key: []const u8,
    /// Owner's public key — must be 64-char lowercase hex (not npub). Always allowed through DM policy.
    owner_pubkey: []const u8,
    /// Bot's own public key — must be 64-char lowercase hex. Derived from private_key during onboarding.
    /// Used as the -p filter for the listener so incoming gift wraps reach the bot, not the owner.
    /// Empty string means not set (old config — re-run onboarding to populate).
    bot_pubkey: []const u8 = "",
    /// Relay URLs for publishing and subscribing.
    relays: []const []const u8 = &.{
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.nostr.band",
        "wss://auth.nostr1.com",
        "wss://relay.primal.net",
    },
    /// Relay URLs announced in kind:10050 (NIP-17 DM inbox).
    /// Senders look up this event to know where to address gift-wrapped DMs.
    /// The listener subscribes here in addition to `relays`, so the bot
    /// receives DMs on whichever relay the sender used.
    dm_relays: []const []const u8 = &.{"wss://auth.nostr1.com"},
    /// Pubkeys allowed to send DMs. Empty = deny all. ["*"] = allow all.
    /// Owner is always implicitly allowed regardless of this list.
    dm_allowed_pubkeys: []const []const u8 = &.{},
    /// Display name for kind:0 metadata.
    display_name: []const u8 = "NullClaw",
    /// About text for kind:0 metadata.
    about: []const u8 = "AI assistant",
    /// Path to profile picture file. Published in kind:0 metadata as "picture" field.
    display_pic: ?[]const u8 = null,
    /// LNURL for Lightning Network & Cashu zaps (NIP-57). Published in kind:0 metadata as "lud16" field.
    lnurl: ?[]const u8 = null,
    /// NIP-05 identifier (e.g. "user@domain.com"). Published in kind:0 metadata as "nip05" field.
    nip05: ?[]const u8 = null,
    /// Path to the nak binary.
    nak_path: []const u8 = "nak",
    /// Bunker URI (auto-populated at first start, or manually set for external bunker).
    bunker_uri: ?[]const u8 = null,
    /// Directory containing the config file and .secret_key.
    /// Set at construction time by the config loader or onboarding wizard.
    /// Used by vtableStart to instantiate SecretStore for key decryption.
    config_dir: []const u8 = ".",
};

pub const ExternalChannelConfig = struct {
    pub const EnvEntry = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const TransportConfig = struct {
        command: []const u8 = "",
        args: []const []const u8 = &.{},
        env: []const EnvEntry = &.{},
        timeout_ms: u32 = 10_000,
    };

    account_id: []const u8 = "default",
    /// Runtime channel identifier exposed inside nullclaw routing and bindings.
    /// Example: "whatsapp_web"
    runtime_name: []const u8 = "",
    /// Plugin process transport configuration (JSON-RPC over stdio).
    transport: TransportConfig = .{},
    /// Raw JSON object forwarded as params.config during the start request.
    plugin_config_json: []const u8 = "{}",
    /// Runtime-only host-owned state directory for plugin persistence.
    /// Backfilled by Config.load(); never serialized.
    state_dir: []const u8 = ".",

    pub fn isValidRuntimeName(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0 or trimmed.len > 128) return false;
        for (trimmed) |ch| {
            if (std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.') continue;
            return false;
        }
        return true;
    }

    pub fn hasCommand(raw: []const u8) bool {
        return std.mem.trim(u8, raw, " \t\r\n").len > 0;
    }

    pub fn isValidTimeoutMs(timeout_ms: u32) bool {
        return timeout_ms >= 1 and timeout_ms <= 600_000;
    }
};

pub const ChannelsConfig = struct {
    cli: bool = true,
    telegram: []const TelegramConfig = &.{},
    discord: []const DiscordConfig = &.{},
    slack: []const SlackConfig = &.{},
    webhook: ?WebhookConfig = null,
    imessage: []const IMessageConfig = &.{},
    matrix: []const MatrixConfig = &.{},
    mattermost: []const MattermostConfig = &.{},
    whatsapp: []const WhatsAppConfig = &.{},
    teams: []const TeamsConfig = &.{},
    irc: []const IrcConfig = &.{},
    lark: []const LarkConfig = &.{},
    dingtalk: []const DingTalkConfig = &.{},
    wechat: []const WeChatConfig = &.{},
    wecom: []const WeComConfig = &.{},
    weixin: []const WeixinConfig = &.{},
    signal: []const SignalConfig = &.{},
    email: []const EmailConfig = &.{},
    line: []const LineConfig = &.{},
    qq: []const QQConfig = &.{},
    onebot: []const OneBotConfig = &.{},
    maixcam: []const MaixCamConfig = &.{},
    web: []const WebConfig = &.{},
    max: []const MaxConfig = &.{},
    external: []const ExternalChannelConfig = &.{},
    nostr: ?*NostrConfig = null,

    fn primaryAccount(comptime T: type, items: []const T) ?T {
        if (items.len == 0) return null;
        if (comptime @hasField(T, "account_id")) {
            for (items) |item| {
                if (std.mem.eql(u8, item.account_id, "default")) return item;
            }
            for (items) |item| {
                if (std.mem.eql(u8, item.account_id, "main")) return item;
            }
        }
        return items[0];
    }

    /// Get preferred account for a channel, or null if none configured.
    /// Selection order: `account_id=default`, then `account_id=main`, then first entry.
    pub fn telegramPrimary(self: *const ChannelsConfig) ?TelegramConfig {
        return primaryAccount(TelegramConfig, self.telegram);
    }
    pub fn discordPrimary(self: *const ChannelsConfig) ?DiscordConfig {
        return primaryAccount(DiscordConfig, self.discord);
    }
    pub fn slackPrimary(self: *const ChannelsConfig) ?SlackConfig {
        return primaryAccount(SlackConfig, self.slack);
    }
    pub fn signalPrimary(self: *const ChannelsConfig) ?SignalConfig {
        return primaryAccount(SignalConfig, self.signal);
    }
    pub fn imessagePrimary(self: *const ChannelsConfig) ?IMessageConfig {
        return primaryAccount(IMessageConfig, self.imessage);
    }
    pub fn matrixPrimary(self: *const ChannelsConfig) ?MatrixConfig {
        return primaryAccount(MatrixConfig, self.matrix);
    }
    pub fn mattermostPrimary(self: *const ChannelsConfig) ?MattermostConfig {
        return primaryAccount(MattermostConfig, self.mattermost);
    }
    pub fn whatsappPrimary(self: *const ChannelsConfig) ?WhatsAppConfig {
        return primaryAccount(WhatsAppConfig, self.whatsapp);
    }
    pub fn teamsPrimary(self: *const ChannelsConfig) ?TeamsConfig {
        return primaryAccount(TeamsConfig, self.teams);
    }
    pub fn ircPrimary(self: *const ChannelsConfig) ?IrcConfig {
        return primaryAccount(IrcConfig, self.irc);
    }
    pub fn larkPrimary(self: *const ChannelsConfig) ?LarkConfig {
        return primaryAccount(LarkConfig, self.lark);
    }
    pub fn dingtalkPrimary(self: *const ChannelsConfig) ?DingTalkConfig {
        return primaryAccount(DingTalkConfig, self.dingtalk);
    }
    pub fn wechatPrimary(self: *const ChannelsConfig) ?WeChatConfig {
        return primaryAccount(WeChatConfig, self.wechat);
    }
    pub fn wecomPrimary(self: *const ChannelsConfig) ?WeComConfig {
        return primaryAccount(WeComConfig, self.wecom);
    }
    pub fn weixinPrimary(self: *const ChannelsConfig) ?WeixinConfig {
        return primaryAccount(WeixinConfig, self.weixin);
    }
    pub fn emailPrimary(self: *const ChannelsConfig) ?EmailConfig {
        return primaryAccount(EmailConfig, self.email);
    }
    pub fn linePrimary(self: *const ChannelsConfig) ?LineConfig {
        return primaryAccount(LineConfig, self.line);
    }
    pub fn qqPrimary(self: *const ChannelsConfig) ?QQConfig {
        return primaryAccount(QQConfig, self.qq);
    }
    pub fn onebotPrimary(self: *const ChannelsConfig) ?OneBotConfig {
        return primaryAccount(OneBotConfig, self.onebot);
    }
    pub fn maixcamPrimary(self: *const ChannelsConfig) ?MaixCamConfig {
        return primaryAccount(MaixCamConfig, self.maixcam);
    }
    pub fn webPrimary(self: *const ChannelsConfig) ?WebConfig {
        return primaryAccount(WebConfig, self.web);
    }
    pub fn maxPrimary(self: *const ChannelsConfig) ?MaxConfig {
        return primaryAccount(MaxConfig, self.max);
    }
    pub fn externalPrimary(self: *const ChannelsConfig) ?ExternalChannelConfig {
        return primaryAccount(ExternalChannelConfig, self.external);
    }
};

// ── Memory config ───────────────────────────────────────────────

/// Memory configuration profile presets.
pub const MemoryProfile = enum {
    /// Hybrid: SQLite backend with workspace bootstrap files.
    hybrid_keyword,
    /// SQLite keyword-only (default).
    local_keyword,
    /// File-based markdown memory.
    markdown_only,
    /// PostgreSQL keyword-only.
    postgres_keyword,
    /// SQLite + vector hybrid.
    local_hybrid,
    /// PostgreSQL + vector hybrid.
    postgres_hybrid,
    /// Stateless no-op.
    minimal_none,
    /// Custom — no profile defaults applied.
    custom,

    pub fn fromString(s: []const u8) MemoryProfile {
        if (std.mem.eql(u8, s, "hybrid_keyword")) return .hybrid_keyword;
        if (std.mem.eql(u8, s, "local_keyword")) return .local_keyword;
        if (std.mem.eql(u8, s, "markdown_only")) return .markdown_only;
        if (std.mem.eql(u8, s, "postgres_keyword")) return .postgres_keyword;
        if (std.mem.eql(u8, s, "local_hybrid")) return .local_hybrid;
        if (std.mem.eql(u8, s, "postgres_hybrid")) return .postgres_hybrid;
        if (std.mem.eql(u8, s, "minimal_none")) return .minimal_none;
        return .custom;
    }
};

pub const MemoryConfig = struct {
    pub const DEFAULT_MEMORY_BACKEND: []const u8 = "hybrid";

    /// Profile preset — convenience shortcut for common setups.
    profile: []const u8 = "hybrid_keyword",
    backend: []const u8 = DEFAULT_MEMORY_BACKEND,
    instance_id: []const u8 = "",
    auto_save: bool = true,
    citations: []const u8 = "auto",
    search: MemorySearchConfig = .{},
    qmd: MemoryQmdConfig = .{},
    lifecycle: MemoryLifecycleConfig = .{},
    response_cache: MemoryResponseCacheConfig = .{},
    reliability: MemoryReliabilityConfig = .{},
    postgres: MemoryPostgresConfig = .{},
    redis: MemoryRedisConfig = .{},
    api: MemoryApiConfig = .{},
    clickhouse: MemoryClickHouseConfig = .{},
    retrieval_stages: MemoryRetrievalStagesConfig = .{},
    summarizer: MemorySummarizerConfig = .{},

    /// Apply profile defaults. Only sets fields that are still at their default values,
    /// so explicit user overrides always win (profile is applied AFTER parsing).
    pub fn applyProfileDefaults(self: *MemoryConfig) void {
        const rollout_off = "off";
        const rollout_on = "on";
        const p = MemoryProfile.fromString(self.profile);
        switch (p) {
            .hybrid_keyword => {
                // Base default is already hybrid.
            },
            .local_keyword => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "sqlite";
            },
            .markdown_only => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "markdown";
                if (!self.search.query.hybrid.enabled) self.search.query.hybrid.enabled = true;
                if (!self.search.query.hybrid.temporal_decay.enabled) self.search.query.hybrid.temporal_decay.enabled = true;
                if (std.mem.eql(u8, self.reliability.rollout_mode, rollout_off)) self.reliability.rollout_mode = rollout_on;
            },
            .postgres_keyword => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "postgres";
            },
            .local_hybrid => {
                // SQLite + vector hybrid
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "sqlite";
                if (std.mem.eql(u8, self.search.provider, "none")) self.search.provider = "openai";
                if (!self.search.query.hybrid.enabled) self.search.query.hybrid.enabled = true;
                if (std.mem.eql(u8, self.reliability.rollout_mode, rollout_off)) self.reliability.rollout_mode = rollout_on;
            },
            .postgres_hybrid => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "postgres";
                if (std.mem.eql(u8, self.search.provider, "none")) self.search.provider = "openai";
                if (!self.search.query.hybrid.enabled) self.search.query.hybrid.enabled = true;
                if (std.mem.eql(u8, self.search.store.kind, "auto")) self.search.store.kind = "pgvector";
                if (std.mem.eql(u8, self.reliability.rollout_mode, rollout_off)) self.reliability.rollout_mode = rollout_on;
            },
            .minimal_none => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "none";
                if (self.auto_save) self.auto_save = false;
            },
            .custom => {
                // No defaults applied — user controls everything.
            },
        }
    }
};

pub const MemorySearchConfig = struct {
    enabled: bool = true,
    provider: []const u8 = "none",
    model: []const u8 = "text-embedding-3-small",
    dimensions: u32 = 1536,
    fallback_provider: []const u8 = "none",
    store: MemoryVectorStoreConfig = .{},
    chunking: MemoryChunkingConfig = .{},
    sync: MemorySyncConfig = .{},
    query: MemoryQueryConfig = .{},
    cache: MemoryEmbeddingCacheConfig = .{},
};

pub const MemoryQmdConfig = struct {
    enabled: bool = false,
    command: []const u8 = "qmd",
    search_mode: []const u8 = "search",
    include_default_memory: bool = true,
    mcporter: QmdMcporterConfig = .{},
    paths: []const QmdIndexPath = &.{},
    sessions: QmdSessionConfig = .{},
    update: QmdUpdateConfig = .{},
    limits: QmdLimitsConfig = .{},
};

pub const QmdIndexPath = struct {
    path: []const u8 = "",
    name: []const u8 = "",
    pattern: []const u8 = "**/*.md",
};

pub const QmdMcporterConfig = struct {
    enabled: bool = false,
    server_name: []const u8 = "qmd",
    start_daemon: bool = true,
};

pub const QmdSessionConfig = struct {
    enabled: bool = false,
    export_dir: []const u8 = "",
    retention_days: u32 = 30,
};

pub const QmdUpdateConfig = struct {
    interval_ms: u32 = 300_000,
    debounce_ms: u32 = 15_000,
    on_boot: bool = true,
    wait_for_boot_sync: bool = false,
    embed_interval_ms: u32 = 3_600_000,
    command_timeout_ms: u32 = 30_000,
    update_timeout_ms: u32 = 120_000,
    embed_timeout_ms: u32 = 120_000,
};

pub const QmdLimitsConfig = struct {
    max_results: u32 = 6,
    max_snippet_chars: u32 = 700,
    max_injected_chars: u32 = 4_000,
    timeout_ms: u32 = 4_000,
};

pub const MemoryVectorStoreConfig = struct {
    kind: []const u8 = "auto",
    sidecar_path: []const u8 = "",
    qdrant_url: []const u8 = "",
    qdrant_api_key: []const u8 = "",
    qdrant_collection: []const u8 = "nullclaw_memories",
    pgvector_table: []const u8 = "memory_embeddings",
    // sqlite_ann (experimental): candidate prefilter tuning.
    ann_candidate_multiplier: u32 = 12,
    ann_min_candidates: u32 = 64,
};

pub const MemoryChunkingConfig = struct {
    max_tokens: u32 = 512,
    overlap: u32 = 64,
};

pub const MemorySyncConfig = struct {
    mode: []const u8 = "best_effort",
    embed_timeout_ms: u32 = 15_000,
    vector_timeout_ms: u32 = 5_000,
    embed_max_retries: u32 = 2,
    vector_max_retries: u32 = 2,
};

pub const MemoryQueryConfig = struct {
    max_results: u32 = 6,
    min_score: f64 = 0.0,
    merge_strategy: []const u8 = "rrf",
    rrf_k: u32 = 60,
    hybrid: MemoryHybridConfig = .{},
};

pub const MemoryHybridConfig = struct {
    enabled: bool = false,
    vector_weight: f64 = 0.7,
    text_weight: f64 = 0.3,
    candidate_multiplier: u32 = 4,
    mmr: MemoryMmrConfig = .{},
    temporal_decay: MemoryTemporalDecayConfig = .{},
};

pub const MemoryMmrConfig = struct {
    enabled: bool = false,
    lambda: f64 = 0.7,
};

pub const MemoryTemporalDecayConfig = struct {
    enabled: bool = false,
    half_life_days: u32 = 30,
};

pub const MemoryEmbeddingCacheConfig = struct {
    enabled: bool = true,
    max_entries: u32 = 10_000,
};

pub const MemoryLifecycleConfig = struct {
    hygiene_enabled: bool = true,
    archive_after_days: u32 = 7,
    purge_after_days: u32 = 30,
    preserve_before_purge: bool = true,
    conversation_retention_days: u32 = 30,
    snapshot_enabled: bool = false,
    snapshot_on_hygiene: bool = false,
    auto_hydrate: bool = true,
};

pub const MemoryResponseCacheConfig = struct {
    enabled: bool = false,
    ttl_minutes: u32 = 60,
    max_entries: u32 = 5_000,
};

pub const MemoryReliabilityConfig = struct {
    rollout_mode: []const u8 = "off",
    circuit_breaker_failures: u32 = 5,
    circuit_breaker_cooldown_ms: u32 = 30_000,
    shadow_hybrid_percent: u32 = 0,
    canary_hybrid_percent: u32 = 0,
    /// Fallback policy when optional subsystems (vector plane, cache) fail to init.
    /// "degrade" (default): silently disable the failed subsystem, log a warning.
    /// "fail_fast": return null from initRuntime, preventing startup.
    fallback_policy: []const u8 = "degrade",
};

pub const MemoryPostgresConfig = struct {
    url: []const u8 = "",
    schema: []const u8 = "public",
    table: []const u8 = "memories",
    connect_timeout_secs: u32 = 30,
};

pub const MemoryRedisConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    password: []const u8 = "",
    db_index: u8 = 0,
    key_prefix: []const u8 = "nullclaw",
    ttl_seconds: u32 = 0, // 0 = no expiry
};

pub const MemoryApiConfig = struct {
    url: []const u8 = "",
    api_key: []const u8 = "",
    timeout_ms: u32 = 10_000,
    namespace: []const u8 = "",
};

pub const MemoryClickHouseConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8123,
    database: []const u8 = "default",
    table: []const u8 = "memories",
    user: []const u8 = "",
    password: []const u8 = "",
    /// Plain HTTP is accepted only for loopback hosts; remote endpoints must use HTTPS.
    use_https: bool = false,
};

pub const MemoryRetrievalStagesConfig = struct {
    query_expansion_enabled: bool = false,
    adaptive_retrieval_enabled: bool = false,
    adaptive_keyword_max_tokens: u32 = 3,
    adaptive_vector_min_tokens: u32 = 6,
    llm_reranker_enabled: bool = false,
    llm_reranker_max_candidates: u32 = 10,
    llm_reranker_timeout_ms: u32 = 5_000,
};

pub const MemorySummarizerConfig = struct {
    enabled: bool = false,
    window_size_tokens: u32 = 4000,
    summary_max_tokens: u32 = 500,
    auto_extract_semantic: bool = true,
};

// ── Tunnel config ───────────────────────────────────────────────

// Re-export tunnel config types from tunnel.zig so config parsing stays
// aligned with the runtime tunnel factory shape.
pub const CloudflareTunnelConfig = tunnel_mod.CloudflareTunnelConfig;
pub const TailscaleTunnelConfig = tunnel_mod.TailscaleTunnelConfig;
pub const NgrokTunnelConfig = tunnel_mod.NgrokTunnelConfig;
pub const CustomTunnelConfig = tunnel_mod.CustomTunnelConfig;
pub const TunnelConfig = tunnel_mod.TunnelFullConfig;

// ── Gateway config ──────────────────────────────────────────────

pub const GatewayConfig = struct {
    port: u16 = 3000,
    host: []const u8 = "127.0.0.1",
    require_pairing: bool = true,
    allow_public_bind: bool = false,
    pair_rate_limit_per_minute: u32 = 10,
    webhook_rate_limit_per_minute: u32 = 60,
    idempotency_ttl_secs: u64 = 300,
    paired_tokens: []const []const u8 = &.{},
    /// Maximum HTTP request body size in bytes.
    /// Default 65536 (64 KB). Raise this when the gateway is configured
    /// for multi-modal use and needs to accept image payloads.
    max_body_size_bytes: usize = 65_536,
    /// Socket read timeout for incoming HTTP requests in seconds.
    /// Default 30s. Raise this when accepting large payloads (e.g. images)
    /// over slow or high-latency connections.
    request_timeout_secs: u64 = 30,
    /// When true, /webhook requests authenticated with a token from
    /// `paired_tokens` are routed through the synchronous session-manager
    /// path instead of being published to the event bus. The caller then
    /// receives `{"status":"ok","response":"...","thread_events":[...]}`,
    /// which is the response shape the NullBoiler dispatch contract
    /// requires from a worker (see `docs/integration-analysis.md` Gap 3).
    /// Unauthenticated webhooks and webhooks from non-paired bearers
    /// continue to take the bus path, so existing channel integrations
    /// (Telegram, Discord, Slack, …) are unaffected. Default false to keep
    /// behavior unchanged for existing deployments.
    webhook_sync_for_workers: bool = false,
};

// ── A2A (Agent-to-Agent) protocol config ────────────────────────

pub const A2aConfig = struct {
    enabled: bool = false,
    name: []const u8 = "NullClaw",
    description: []const u8 = "AI assistant",
    url: []const u8 = "",
    version: []const u8 = "1.0.0",
    /// When true, the agent card advertises multi_modal capability,
    /// signalling that the gateway's model accepts image/file attachments.
    multi_modal: bool = false,
};

// ── Composio config ─────────────────────────────────────────────

pub const ComposioConfig = struct {
    enabled: bool = false,
    api_key: ?[]const u8 = null,
    entity_id: []const u8 = "default",
};

// ── Secrets config ──────────────────────────────────────────────

pub const SecretsConfig = struct {
    encrypt: bool = true,
};

// ── Browser config ──────────────────────────────────────────────

pub const BrowserComputerUseConfig = struct {
    endpoint: []const u8 = "http://127.0.0.1:8787/v1/actions",
    api_key: ?[]const u8 = null,
    timeout_ms: u64 = 15_000,
    allow_remote_endpoint: bool = false,
    max_coordinate_x: ?i64 = null,
    max_coordinate_y: ?i64 = null,
};

pub const BrowserConfig = struct {
    enabled: bool = false,
    session_name: ?[]const u8 = null,
    backend: []const u8 = "agent_browser",
    native_headless: bool = true,
    native_webdriver_url: []const u8 = "http://127.0.0.1:9515",
    native_chrome_path: ?[]const u8 = null,
    computer_use: BrowserComputerUseConfig = .{},
    allowed_domains: []const []const u8 = &.{},
};

// ── HTTP request config ─────────────────────────────────────────

pub const HttpRequestConfig = struct {
    enabled: bool = false,
    max_response_size: u32 = 1_000_000,
    timeout_secs: u64 = 30,
    allowed_domains: []const []const u8 = &.{},
    /// Optional outbound proxy URL used for provider/network curl requests.
    /// Supported schemes: http://, https://, socks5://
    proxy: ?[]const u8 = null,
    /// Optional SearXNG instance URL used by web_search as a fallback when
    /// BRAVE_API_KEY is not available.
    /// HTTPS is allowed for any host. Plain HTTP is allowed only for local or
    /// private hosts such as localhost, .local names, or private IP ranges.
    /// Examples:
    ///   - "https://searx.example.com"
    ///   - "http://localhost:8888"
    ///   - "https://searx.example.com/search"
    search_base_url: ?[]const u8 = null,
    /// Search provider for web_search.
    /// Supported: auto, searxng, duckduckgo (ddg), brave, firecrawl,
    /// tavily, perplexity, exa, jina.
    search_provider: []const u8 = "auto",
    /// Optional fallback provider chain used when the primary provider fails.
    search_fallback_providers: []const []const u8 = &.{},

    /// Validate optional SearXNG base URL accepted by web_search.
    /// Allowed forms:
    ///   - https://host
    ///   - https://host/search
    ///   - http://localhost[:port][/search]
    ///   - http://192.168.1.10[:port][/search]
    ///   - http://searx.local[:port][/search]
    pub fn isValidSearchBaseUrl(raw: []const u8) bool {
        return search_base_url.isValid(raw);
    }

    pub fn isValidSearchProviderName(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.ascii.eqlIgnoreCase(trimmed, "auto") or
            std.ascii.eqlIgnoreCase(trimmed, "searxng") or
            std.ascii.eqlIgnoreCase(trimmed, "duckduckgo") or
            std.ascii.eqlIgnoreCase(trimmed, "ddg") or
            std.ascii.eqlIgnoreCase(trimmed, "brave") or
            std.ascii.eqlIgnoreCase(trimmed, "firecrawl") or
            std.ascii.eqlIgnoreCase(trimmed, "tavily") or
            std.ascii.eqlIgnoreCase(trimmed, "perplexity") or
            std.ascii.eqlIgnoreCase(trimmed, "exa") or
            std.ascii.eqlIgnoreCase(trimmed, "jina");
    }

    pub fn isValidSearchFallbackProviderName(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "auto")) return false;
        return isValidSearchProviderName(trimmed);
    }

    pub fn isValidProxyUrl(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return false;
        if (std.mem.indexOfAny(u8, trimmed, " \t\r\n") != null) return false;
        if (std.mem.indexOfAny(u8, trimmed, "?#") != null) return false;

        const uri = std.Uri.parse(trimmed) catch return false;
        const scheme_ok = std.ascii.eqlIgnoreCase(uri.scheme, "http") or
            std.ascii.eqlIgnoreCase(uri.scheme, "https") or
            std.ascii.eqlIgnoreCase(uri.scheme, "socks5");
        if (!scheme_ok) return false;

        const host_comp = uri.host orelse return false;
        const host = switch (host_comp) {
            .raw => |h| h,
            .percent_encoded => |h| blk: {
                // Reject percent-escaped hosts like %31%32%37.0.0.1.
                if (std.mem.indexOfScalar(u8, h, '%') != null) return false;
                break :blk h;
            },
        };
        if (host.len == 0) return false;
        if (host[0] == ':') return false;
        if (std.mem.indexOfAny(u8, host, " \t\r\n") != null) return false;

        if (host[0] == '[') {
            const close = std.mem.indexOfScalar(u8, host, ']') orelse return false;
            if (close != host.len - 1) return false;
        }

        if (uri.port) |port| {
            if (port == 0) return false;
        }

        const path = switch (uri.path) {
            .raw => |p| p,
            .percent_encoded => |p| p,
        };
        if (path.len > 0 and !std.mem.eql(u8, path, "/")) return false;
        return true;
    }
};

// ── Identity config ─────────────────────────────────────────────

pub const IdentityConfig = struct {
    format: []const u8 = "nullclaw",
    aieos_path: ?[]const u8 = null,
    aieos_inline: ?[]const u8 = null,
};

// ── Cost config ─────────────────────────────────────────────────

pub const CostConfig = struct {
    enabled: bool = false,
    daily_limit_usd: f64 = 10.0,
    monthly_limit_usd: f64 = 100.0,
    warn_at_percent: u8 = 80,
    allow_override: bool = false,
};

// ── Peripherals config ──────────────────────────────────────────

pub const PeripheralBoardConfig = struct {
    board: []const u8 = "",
    transport: []const u8 = "serial",
    path: ?[]const u8 = null,
    baud: u32 = 115200,
};

pub const PeripheralsConfig = struct {
    enabled: bool = false,
    datasheet_dir: ?[]const u8 = null,
    boards: []const PeripheralBoardConfig = &.{},
};

// ── Hardware config ─────────────────────────────────────────────

pub const HardwareConfig = struct {
    enabled: bool = false,
    transport: HardwareTransport = .none,
    serial_port: ?[]const u8 = null,
    baud_rate: u32 = 115200,
    probe_target: ?[]const u8 = null,
    workspace_datasheets: bool = false,
};

// ── Workspace audit config ──────────────────────────────────────

pub const WorkspaceAuditTriageConfig = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    max_calls: ?usize = null,
};

pub const WorkspaceAuditConfig = struct {
    llm_triage: WorkspaceAuditTriageConfig = .{},
};

// ── Security sub-configs ────────────────────────────────────────

pub const SandboxConfig = struct {
    enabled: ?bool = null,
    backend: SandboxBackend = .auto,
    firejail_args: []const []const u8 = &.{},
};

pub const ResourceLimitsConfig = struct {
    max_memory_mb: u32 = 512,
    max_cpu_percent: u32 = 80,
    max_disk_mb: u32 = 1024,
    max_cpu_time_seconds: u64 = 60,
    max_subprocesses: u32 = 10,
    memory_monitoring: bool = true,
};

pub const AuditConfig = struct {
    enabled: bool = true,
    log_file: ?[]const u8 = null,
    log_path: []const u8 = "audit.log",
    retention_days: u32 = 90,
    max_size_mb: u32 = 100,
    sign_events: bool = false,
};

pub const SecurityConfig = struct {
    sandbox: SandboxConfig = .{},
    resources: ResourceLimitsConfig = .{},
    audit: AuditConfig = .{},
};

// ── Delegate agent config ───────────────────────────────────────

pub const DelegateAgentConfig = struct {
    name: []const u8 = "",
    provider: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
    temperature: ?f64 = null,
    max_depth: u32 = 3,
};

// ── Named agent config (for agents map in JSON) ────────────────

pub const NamedAgentConfig = struct {
    name: []const u8,
    provider: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8 = null,
    /// Runtime-only source path preserved so Config.save() can round-trip file-backed prompts.
    system_prompt_path: ?[]const u8 = null,
    workspace_path: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
    temperature: ?f64 = null,
    max_depth: u32 = 3,
    /// Redact PII (email, phone, card+Luhn, passport-anchored ID, tokens) in
    /// outbound provider messages so user data does not leak to remote LLMs.
    /// Default true (secure-by-default). Disable explicitly for known-local-only agents.
    enable_pii_redaction: bool = true,
};

// ── MCP Server Config ──────────────────────────────────────────

pub const McpServerConfig = struct {
    pub const DEFAULT_TRANSPORT = "stdio";
    pub const HTTP_TRANSPORT = "http";

    name: []const u8,
    transport: []const u8 = DEFAULT_TRANSPORT,
    command: []const u8 = "",
    url: ?[]const u8 = null,
    /// Per-request wall clock timeout for HTTP transport. 0 = default.
    timeout_ms: u32 = 10_000,
    args: []const []const u8 = &.{},
    env: []const McpEnvEntry = &.{},
    headers: []const McpHeaderEntry = &.{},

    pub const McpEnvEntry = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const McpHeaderEntry = struct {
        key: []const u8,
        value: []const u8,
    };

    pub fn isValidTransport(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, DEFAULT_TRANSPORT) or std.mem.eql(u8, trimmed, HTTP_TRANSPORT);
    }

    pub fn isHttpTransport(raw: []const u8) bool {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        return std.mem.eql(u8, trimmed, HTTP_TRANSPORT);
    }

    pub fn isValidHttpUrl(raw: []const u8) bool {
        return isValidHttpsOrLocalHttpUrl(raw);
    }

    pub fn isValidHeaderName(raw: []const u8) bool {
        return isValidHttpHeaderName(raw);
    }

    pub fn isValidHeaderValue(raw: []const u8) bool {
        return isValidHttpHeaderValue(raw);
    }
};

// ── Model Pricing ──────────────────────────────────────────────

pub const ModelPricing = struct {
    model: []const u8 = "",
    input_cost_per_1k: f64 = 0.0,
    output_cost_per_1k: f64 = 0.0,
};

// ── Session Config ──────────────────────────────────────────────

pub const DmScope = enum {
    /// Single shared session for all DMs.
    main,
    /// One session per peer across all channels.
    per_peer,
    /// One session per (channel, peer) pair (default).
    per_channel_peer,
    /// One session per (account, channel, peer) triple.
    per_account_channel_peer,
};

pub const IdentityLink = struct {
    canonical: []const u8,
    peers: []const []const u8 = &.{},
};

pub const SessionConfig = struct {
    dm_scope: DmScope = .per_channel_peer,
    idle_minutes: u32 = 60,
    identity_links: []const IdentityLink = &.{},
    /// Automatically route direct messages from unknown peers into deterministic
    /// per-peer agent IDs (agent runtime/workspace/memory isolation).
    auto_provision_direct_agents: bool = false,
    /// Optional HMAC secret used to verify `/claim <token>` identity assertions.
    /// When unset, direct-peer auto-provisioning is not gated by identity claims.
    claim_secret: ?[]const u8 = null,
    /// Optional shared secret for manual `/revoke <admin-secret>` operations.
    claim_admin_secret: ?[]const u8 = null,
    /// Failed `/claim` attempts allowed before lockout kicks in.
    claim_max_attempts: u32 = 5,
    /// Lockout duration in seconds after too many failed claim attempts.
    claim_lockout_secs: u32 = 300,
    typing_interval_secs: u32 = 5,
    /// Maximum concurrent message processing tasks per channel.
    /// When set to 0 or 1, messages are processed sequentially.
    /// Higher values enable parallel processing across different sessions.
    max_concurrent_tasks: u32 = 4,
};

test "WebConfig defaults" {
    const cfg = WebConfig{};
    try std.testing.expectEqualStrings("default", cfg.account_id);
    try std.testing.expectEqualStrings(WebConfig.DEFAULT_TRANSPORT, cfg.transport);
    try std.testing.expectEqual(@as(u16, 32123), cfg.port);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.listen);
    try std.testing.expectEqualStrings(WebConfig.DEFAULT_PATH, cfg.path);
    try std.testing.expectEqual(@as(u16, 10), cfg.max_connections);
    try std.testing.expectEqual(WebConfig.DEFAULT_MAX_HANDSHAKE_SIZE, cfg.max_handshake_size);
    try std.testing.expect(cfg.auth_token == null);
    try std.testing.expectEqualStrings(WebConfig.DEFAULT_MESSAGE_AUTH_MODE, cfg.message_auth_mode);
    try std.testing.expectEqual(@as(usize, 0), cfg.allowed_origins.len);
    try std.testing.expect(cfg.relay_url == null);
    try std.testing.expectEqualStrings("default", cfg.relay_agent_id);
    try std.testing.expect(cfg.relay_token == null);
    try std.testing.expectEqual(@as(u32, 2_592_000), cfg.relay_token_ttl_secs);
    try std.testing.expectEqual(@as(u32, 300), cfg.relay_pairing_code_ttl_secs);
    try std.testing.expectEqual(@as(u32, 86_400), cfg.relay_ui_token_ttl_secs);
    try std.testing.expect(!cfg.relay_e2e_required);
}

test "security defaults stay least-privilege" {
    const diagnostics = DiagnosticsConfig{};
    try std.testing.expect(diagnostics.api_error_max_chars == null);
    try std.testing.expect(diagnostics.otel_endpoint == null);

    const autonomy = AutonomyConfig{};
    try std.testing.expectEqual(AutonomyLevel.supervised, autonomy.level);
    try std.testing.expect(autonomy.workspace_only);
    try std.testing.expectEqual(@as(u32, 20), autonomy.max_actions_per_hour);
    try std.testing.expect(autonomy.require_approval_for_medium_risk);
    try std.testing.expect(autonomy.block_high_risk_commands);
    try std.testing.expect(autonomy.block_medium_risk_commands);
    try std.testing.expect(!autonomy.allow_raw_url_chars);

    const http_request = HttpRequestConfig{};
    try std.testing.expect(!http_request.enabled);
    try std.testing.expect(http_request.proxy == null);
    try std.testing.expect(http_request.search_base_url == null);
    try std.testing.expectEqualStrings("auto", http_request.search_provider);
}

test "McpServerConfig transport validation" {
    try std.testing.expect(McpServerConfig.isValidTransport("stdio"));
    try std.testing.expect(McpServerConfig.isValidTransport("http"));
    try std.testing.expect(!McpServerConfig.isValidTransport("sse"));
}

test "McpServerConfig http url validation" {
    try std.testing.expect(McpServerConfig.isValidHttpUrl("https://mcp.example.com"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("https://mcp.example.com/mcp"));
    try std.testing.expect(!McpServerConfig.isValidHttpUrl("http://mcp.example.com/mcp"));
    try std.testing.expect(!McpServerConfig.isValidHttpUrl("https://mcp.example.com/mcp#frag"));
    // Regression: MCP HTTP URLs must stay aligned with shared local-host rules.
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://localhost:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://foo.localhost:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://mcp.local:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://host.docker.internal:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://host.containers.internal:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://127.0.0.1:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://10.0.0.1:8080/rpc"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://192.168.1.1:8080/rpc"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://172.16.0.1:8080/rpc"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://[::1]:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://[fd00::1]:6000/mcp"));
    try std.testing.expect(!McpServerConfig.isValidHttpUrl("http://example.com:6000/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://100.64.0.1:8931/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://100.120.137.95:8931/mcp"));
    try std.testing.expect(McpServerConfig.isValidHttpUrl("http://100.127.255.254:6000/mcp"));
    try std.testing.expect(!McpServerConfig.isValidHttpUrl("http://100.128.0.1:8080/rpc"));
    try std.testing.expect(!McpServerConfig.isValidHttpUrl("http://100.63.0.1:8080/rpc"));
}

test "DiagnosticsConfig otel endpoint validation" {
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com/collector"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com/"));

    // Regression: OTEL exporters must not allow remote plaintext collectors.
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://localhost:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://127.0.0.1:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://10.0.0.5:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://otel:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://host.docker.internal:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://host.containers.internal:4318"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("http://otel.example.com:4318"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("http://otel.example.internal:4318"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com?x=1"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com#frag"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("ftp://otel.example.com"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("https://"));
}

test "McpServerConfig timeout defaults" {
    const cfg = McpServerConfig{ .name = "x", .command = "echo" };
    try std.testing.expectEqual(@as(u32, 10_000), cfg.timeout_ms);
}

test "McpServerConfig header validation" {
    try std.testing.expect(McpServerConfig.isValidHeaderName("Authorization"));
    try std.testing.expect(!McpServerConfig.isValidHeaderName("Bad Header"));
    try std.testing.expect(McpServerConfig.isValidHeaderValue("Bearer token"));
    try std.testing.expect(!McpServerConfig.isValidHeaderValue("line1\nline2"));
}

test "HttpRequestConfig proxy URL validation" {
    try std.testing.expect(HttpRequestConfig.isValidProxyUrl("http://127.0.0.1:8080"));
    try std.testing.expect(HttpRequestConfig.isValidProxyUrl("https://proxy.example.com:8443"));
    try std.testing.expect(HttpRequestConfig.isValidProxyUrl("socks5://127.0.0.1:1080"));
    try std.testing.expect(HttpRequestConfig.isValidProxyUrl("http://proxy.example.com/"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl(""));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("proxy.example.com:8080"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("ftp://proxy.example.com:21"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("http://"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("http:///"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("http://:8080"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("http://proxy.example.com/path"));
    try std.testing.expect(!HttpRequestConfig.isValidProxyUrl("http://proxy.example.com?x=1"));
}

test "ProviderEntry base URL validation keeps local providers and rejects remote http" {
    try std.testing.expect(ProviderEntry.isValidBaseUrl("https://api.example.com/v1"));
    try std.testing.expect(ProviderEntry.isValidBaseUrl("http://localhost:1234/v1"));
    try std.testing.expect(ProviderEntry.isValidBaseUrl("http://127.0.0.1:1234/v1"));
    try std.testing.expect(ProviderEntry.isValidBaseUrl("http://192.168.1.10:1234/v1"));
    try std.testing.expect(!ProviderEntry.isValidBaseUrl("http://api.example.com/v1"));
    try std.testing.expect(!ProviderEntry.isValidBaseUrl("https://api.example.com/v1?x=1"));
    try std.testing.expect(!ProviderEntry.isValidBaseUrl("ftp://api.example.com/v1"));
}

test "WebConfig normalizePath trims and normalizes" {
    try std.testing.expectEqualStrings("/ws", WebConfig.normalizePath("/ws/"));
    try std.testing.expectEqualStrings("/relay", WebConfig.normalizePath(" /relay/ "));
    try std.testing.expectEqualStrings(WebConfig.DEFAULT_PATH, WebConfig.normalizePath("relay"));
    try std.testing.expectEqualStrings(WebConfig.DEFAULT_PATH, WebConfig.normalizePath(""));
}

test "AgentConfig timezone validation accepts UTC and fixed offsets" {
    try std.testing.expect(AgentConfig.isValidTimezone("UTC"));
    try std.testing.expect(AgentConfig.isValidTimezone("UTC+05:30"));
    try std.testing.expect(AgentConfig.isValidTimezone("UTC-03:00"));
    try std.testing.expect(AgentConfig.isValidTimezone("utc+08:00"));

    try std.testing.expect(!AgentConfig.isValidTimezone("Asia/Shanghai"));
    try std.testing.expect(!AgentConfig.isValidTimezone("UTC+25:00"));
    try std.testing.expect(!AgentConfig.isValidTimezone("UTC+08"));
}

test "WebConfig token validation enforces printable no-whitespace constraints" {
    try std.testing.expect(WebConfig.isValidAuthToken("relay-token-0123456789"));
    try std.testing.expect(WebConfig.isValidAuthToken("token/with+symbols=0123456789"));
    try std.testing.expect(!WebConfig.isValidAuthToken("short"));
    try std.testing.expect(!WebConfig.isValidAuthToken("invalid token with spaces"));
    try std.testing.expect(!WebConfig.isValidAuthToken("line\nbreak-token-0123456789"));
}

test "WebConfig origin validation accepts wildcard and absolute origins" {
    try std.testing.expect(WebConfig.isValidAllowedOrigin("*"));
    try std.testing.expect(WebConfig.isValidAllowedOrigin("null"));
    try std.testing.expect(WebConfig.isValidAllowedOrigin("https://relay.nullclaw.io"));
    try std.testing.expect(WebConfig.isValidAllowedOrigin("https://relay.nullclaw.io/"));
    try std.testing.expect(WebConfig.isValidAllowedOrigin("chrome-extension://abcdefghijklmnop"));
    try std.testing.expect(!WebConfig.isValidAllowedOrigin(""));
    try std.testing.expect(!WebConfig.isValidAllowedOrigin("relay.nullclaw.io"));
    try std.testing.expect(!WebConfig.isValidAllowedOrigin("https://relay.nullclaw.io/path"));
}

test "WebConfig transport validation supports local and relay" {
    try std.testing.expect(WebConfig.isValidTransport("local"));
    try std.testing.expect(WebConfig.isValidTransport("relay"));
    try std.testing.expect(!WebConfig.isValidTransport("direct"));
    try std.testing.expect(WebConfig.isRelayTransport("relay"));
    try std.testing.expect(!WebConfig.isRelayTransport("local"));
}

test "WebConfig message auth mode validation supports pairing and token" {
    try std.testing.expect(WebConfig.isValidMessageAuthMode("pairing"));
    try std.testing.expect(WebConfig.isValidMessageAuthMode("token"));
    try std.testing.expect(WebConfig.isTokenMessageAuthMode("token"));
    try std.testing.expect(!WebConfig.isTokenMessageAuthMode("pairing"));
    try std.testing.expect(!WebConfig.isValidMessageAuthMode("jwt"));
}

test "WebConfig relay URL validation requires wss authority" {
    try std.testing.expect(WebConfig.isValidRelayUrl("wss://relay.nullclaw.io/ws"));
    try std.testing.expect(WebConfig.isValidRelayUrl("wss://relay.nullclaw.io"));
    try std.testing.expect(!WebConfig.isValidRelayUrl("ws://relay.nullclaw.io/ws"));
    try std.testing.expect(!WebConfig.isValidRelayUrl("https://relay.nullclaw.io/ws"));
    try std.testing.expect(!WebConfig.isValidRelayUrl("wss://"));
    try std.testing.expect(!WebConfig.isValidRelayUrl("wss://relay.nullclaw.io?x=1"));
    try std.testing.expect(!WebConfig.isValidRelayUrl("wss://relay.nullclaw.io/ws#frag"));
}

test "WebConfig relay agent id validation enforces non-empty id" {
    try std.testing.expect(WebConfig.isValidRelayAgentId("default"));
    try std.testing.expect(!WebConfig.isValidRelayAgentId(""));
    try std.testing.expect(!WebConfig.isValidRelayAgentId("agent id with spaces"));
}

test "WebConfig relay ttl validation enforces documented ranges" {
    try std.testing.expect(WebConfig.isValidRelayPairingCodeTtl(60));
    try std.testing.expect(WebConfig.isValidRelayPairingCodeTtl(300));
    try std.testing.expect(!WebConfig.isValidRelayPairingCodeTtl(59));
    try std.testing.expect(!WebConfig.isValidRelayPairingCodeTtl(301));

    try std.testing.expect(WebConfig.isValidRelayUiTokenTtl(300));
    try std.testing.expect(WebConfig.isValidRelayUiTokenTtl(86_400));
    try std.testing.expect(!WebConfig.isValidRelayUiTokenTtl(299));

    try std.testing.expect(WebConfig.isValidRelayTokenTtl(3_600));
    try std.testing.expect(WebConfig.isValidRelayTokenTtl(2_592_000));
    try std.testing.expect(!WebConfig.isValidRelayTokenTtl(3_599));
}

test "HttpRequestConfig search base URL validation" {
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com/"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com/search"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com/search/"));

    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://localhost:8888"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://localhost:8888/"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://localhost:8888/search"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://localhost:8888/search/"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://192.168.1.10:8888/search"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://searx.local/search"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://host.docker.internal:8888/search"));
    try std.testing.expect(HttpRequestConfig.isValidSearchBaseUrl("http://host.containers.internal:8888/search"));

    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("ftp://searx.example.com"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("https://"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("http://"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("http://searx.example.com"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("http://searx.example.com/search"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com?x=1"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com#frag"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("https://searx.example.com/custom"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchBaseUrl("https://:8080/search"));
}

test "HttpRequestConfig search provider validation" {
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("auto"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("searxng"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("duckduckgo"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("ddg"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("brave"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("firecrawl"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("tavily"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("perplexity"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("exa"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("jina"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("BRAVE"));
    try std.testing.expect(HttpRequestConfig.isValidSearchProviderName("DDG"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchProviderName("google"));
}

test "HttpRequestConfig fallback provider validation disallows auto" {
    try std.testing.expect(HttpRequestConfig.isValidSearchFallbackProviderName("brave"));
    try std.testing.expect(HttpRequestConfig.isValidSearchFallbackProviderName("ddg"));
    try std.testing.expect(HttpRequestConfig.isValidSearchFallbackProviderName("JINA"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchFallbackProviderName("auto"));
    try std.testing.expect(!HttpRequestConfig.isValidSearchFallbackProviderName("AUTO"));
}

test "DiagnosticsConfig OTEL endpoint validation allows local http and remote https" {
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://localhost:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("http://127.0.0.1:4318"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelEndpoint("https://otel.example.com:4318"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelEndpoint("http://otel.example.com:4318"));
}

test "DiagnosticsConfig OTEL header validation rejects CRLF injection" {
    try std.testing.expect(DiagnosticsConfig.isValidOtelHeaderName("Authorization"));
    try std.testing.expect(DiagnosticsConfig.isValidOtelHeaderValue("Bearer safe"));
    try std.testing.expect(!DiagnosticsConfig.isValidOtelHeaderValue("Bearer safe\r\nX-Injected: yes"));
}

test "ProviderEntry.max_streaming_prompt_bytes defaults to null" {
    // GAP-5: Documents that zero-init ProviderEntry has no streaming limit.
    const pe = ProviderEntry{ .name = "test" };
    try std.testing.expectEqual(@as(?usize, null), pe.max_streaming_prompt_bytes);
}

test "ProviderEntry.api_mode defaults to chat_completions" {
    const pe = ProviderEntry{ .name = "test" };
    try std.testing.expectEqual(ProviderEntry.ApiMode.chat_completions, pe.api_mode);
}

test "markdown_only profile enables markdown retrieval defaults" {
    var cfg = MemoryConfig{
        .profile = "markdown_only",
    };

    cfg.applyProfileDefaults();

    try std.testing.expectEqualStrings("markdown", cfg.backend);
    try std.testing.expect(cfg.search.query.hybrid.enabled);
    try std.testing.expect(cfg.search.query.hybrid.temporal_decay.enabled);
    try std.testing.expectEqual(@as(u32, 30), cfg.search.query.hybrid.temporal_decay.half_life_days);
    try std.testing.expectEqualStrings("on", cfg.reliability.rollout_mode);
}

test "markdown_only profile preserves explicit half-life override" {
    var cfg = MemoryConfig{
        .profile = "markdown_only",
        .search = .{
            .query = .{
                .hybrid = .{
                    .temporal_decay = .{
                        .half_life_days = 0,
                    },
                },
            },
        },
    };

    cfg.applyProfileDefaults();

    // Regression: markdown_only should not clobber an explicit half-life override.
    try std.testing.expectEqual(@as(u32, 0), cfg.search.query.hybrid.temporal_decay.half_life_days);
}

test "QueueMode parser and serializer cover every mode" {
    // Regression: config parsing and /queue must share one canonical mapping.
    const cases = [_]struct {
        mode: QueueMode,
        text: []const u8,
    }{
        .{ .mode = .off, .text = "off" },
        .{ .mode = .serial, .text = "serial" },
        .{ .mode = .latest, .text = "latest" },
        .{ .mode = .debounce, .text = "debounce" },
    };

    for (cases) |case| {
        try std.testing.expectEqualStrings(case.text, case.mode.toSlice());
        try std.testing.expectEqual(case.mode, QueueMode.fromSlice(case.text).?);
    }
    try std.testing.expectEqual(QueueMode.latest, QueueMode.fromSlice("LATEST").?);
    try std.testing.expect(QueueMode.fromSlice("lastest") == null);
}
