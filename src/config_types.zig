const std = @import("std");

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
    name: []const u8,
    api_key: ?[]const u8 = null,
    base_url: ?[]const u8 = null,
    /// Whether this provider supports native OpenAI-style tool_calls.
    /// Set to false to use XML tool format via system prompt instead.
    native_tools: bool = true,
};

// ── Audio media config (tools.media.audio) ─────────────────────

pub const AudioMediaConfig = struct {
    enabled: bool = true,
    provider: []const u8 = "groq",
    model: []const u8 = "whisper-large-v3",
    base_url: ?[]const u8 = null,
    language: ?[]const u8 = null,
};

// ── Sub-config structs ──────────────────────────────────────────

pub const DiagnosticsConfig = struct {
    backend: []const u8 = "none",
    otel_endpoint: ?[]const u8 = null,
    otel_service_name: ?[]const u8 = null,
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
};

pub const AutonomyConfig = struct {
    level: AutonomyLevel = .supervised,
    workspace_only: bool = true,
    max_actions_per_hour: u32 = 20,
    require_approval_for_medium_risk: bool = true,
    block_high_risk_commands: bool = true,
    allowed_commands: []const []const u8 = &.{},
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

pub const SchedulerConfig = struct {
    enabled: bool = true,
    max_tasks: u32 = 64,
    max_concurrent: u32 = 4,
};

pub const AgentConfig = struct {
    compact_context: bool = false,
    max_tool_iterations: u32 = 1000,
    max_history_messages: u32 = 100,
    parallel_tools: bool = false,
    tool_dispatcher: []const u8 = "auto",
    token_limit: u64 = DEFAULT_AGENT_TOKEN_LIMIT,
    /// Internal parse marker: true only when token_limit is explicitly set in config.
    /// Not serialized; used to distinguish override vs default fallback chain.
    token_limit_explicit: bool = false,
    session_idle_timeout_secs: u64 = 1800, // evict idle sessions after 30 min
    compaction_keep_recent: u32 = 20,
    compaction_max_summary_chars: u32 = 2_000,
    compaction_max_source_chars: u32 = 12_000,
    /// Max seconds to wait for an LLM HTTP response (curl --max-time). 0 = no limit.
    message_timeout_secs: u64 = 600,
};

pub const ToolsConfig = struct {
    shell_timeout_secs: u64 = 60,
    shell_max_output_bytes: u32 = 1_048_576, // 1MB
    max_file_size_bytes: u32 = 10_485_760, // 10MB — shared file_read/edit/append
    web_fetch_max_chars: u32 = 100_000,
};

pub const ModelRouteConfig = struct {
    hint: []const u8,
    provider: []const u8,
    model: []const u8,
    api_key: ?[]const u8 = null,
};

pub const HeartbeatConfig = struct {
    enabled: bool = false,
    interval_minutes: u32 = 30,
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

pub const TelegramConfig = struct {
    account_id: []const u8 = "default",
    bot_token: []const u8,
    allow_from: []const []const u8 = &.{},
    group_allow_from: []const []const u8 = &.{},
    group_policy: []const u8 = "allowlist",
    /// Use reply-to in private (1:1) chats. Groups always use reply-to.
    reply_in_private: bool = true,
    /// Optional SOCKS5/HTTP proxy URL for all Telegram API requests (e.g. "socks5://host:port").
    proxy: ?[]const u8 = null,
    interactive: TelegramInteractiveConfig = .{},
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
    group_policy: []const u8 = "allowlist",
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
};

pub const DingTalkConfig = struct {
    account_id: []const u8 = "default",
    client_id: []const u8,
    client_secret: []const u8,
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

pub const QQConfig = struct {
    account_id: []const u8 = "default",
    app_id: []const u8 = "",
    app_secret: []const u8 = "",
    bot_token: []const u8 = "",
    sandbox: bool = false,
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
    irc: []const IrcConfig = &.{},
    lark: []const LarkConfig = &.{},
    dingtalk: []const DingTalkConfig = &.{},
    signal: []const SignalConfig = &.{},
    email: []const EmailConfig = &.{},
    line: []const LineConfig = &.{},
    qq: []const QQConfig = &.{},
    onebot: []const OneBotConfig = &.{},
    maixcam: []const MaixCamConfig = &.{},

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
    pub fn ircPrimary(self: *const ChannelsConfig) ?IrcConfig {
        return primaryAccount(IrcConfig, self.irc);
    }
    pub fn larkPrimary(self: *const ChannelsConfig) ?LarkConfig {
        return primaryAccount(LarkConfig, self.lark);
    }
    pub fn dingtalkPrimary(self: *const ChannelsConfig) ?DingTalkConfig {
        return primaryAccount(DingTalkConfig, self.dingtalk);
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
};

// ── Memory config ───────────────────────────────────────────────

/// Memory configuration profile presets.
pub const MemoryProfile = enum {
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
    pub const DEFAULT_MEMORY_BACKEND: []const u8 = "markdown";

    /// Profile preset — convenience shortcut for common setups.
    profile: []const u8 = "markdown_only",
    backend: []const u8 = DEFAULT_MEMORY_BACKEND,
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
    retrieval_stages: MemoryRetrievalStagesConfig = .{},
    summarizer: MemorySummarizerConfig = .{},

    /// Apply profile defaults. Only sets fields that are still at their default values,
    /// so explicit user overrides always win (profile is applied AFTER parsing).
    pub fn applyProfileDefaults(self: *MemoryConfig) void {
        const p = MemoryProfile.fromString(self.profile);
        switch (p) {
            .local_keyword => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "sqlite";
            },
            .markdown_only => {
                // Base default is already markdown.
            },
            .postgres_keyword => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "postgres";
            },
            .local_hybrid => {
                // SQLite + vector hybrid
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "sqlite";
                if (std.mem.eql(u8, self.search.provider, "none")) self.search.provider = "openai";
                if (!self.search.query.hybrid.enabled) self.search.query.hybrid.enabled = true;
                if (std.mem.eql(u8, self.reliability.rollout_mode, "off")) self.reliability.rollout_mode = "on";
            },
            .postgres_hybrid => {
                if (std.mem.eql(u8, self.backend, DEFAULT_MEMORY_BACKEND)) self.backend = "postgres";
                if (std.mem.eql(u8, self.search.provider, "none")) self.search.provider = "openai";
                if (!self.search.query.hybrid.enabled) self.search.query.hybrid.enabled = true;
                if (std.mem.eql(u8, self.search.store.kind, "auto")) self.search.store.kind = "pgvector";
                if (std.mem.eql(u8, self.reliability.rollout_mode, "off")) self.reliability.rollout_mode = "on";
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

pub const TunnelConfig = struct {
    provider: []const u8 = "none",
};

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
    api_key: ?[]const u8 = null,
    temperature: ?f64 = null,
    max_depth: u32 = 3,
};

// ── MCP Server Config ──────────────────────────────────────────

pub const McpServerConfig = struct {
    name: []const u8,
    command: []const u8,
    args: []const []const u8 = &.{},
    env: []const McpEnvEntry = &.{},

    pub const McpEnvEntry = struct {
        key: []const u8,
        value: []const u8,
    };
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
    typing_interval_secs: u32 = 5,
};
