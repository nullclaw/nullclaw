const std = @import("std");
const platform = @import("platform.zig");
pub const config_types = @import("config_types.zig");
pub const config_parse = @import("config_parse.zig");

// ── Re-export all types so downstream `@import("config.zig").Foo` still works ──

pub const AutonomyLevel = config_types.AutonomyLevel;
pub const HardwareTransport = config_types.HardwareTransport;
pub const SandboxBackend = config_types.SandboxBackend;
pub const DiagnosticsConfig = config_types.DiagnosticsConfig;
pub const AutonomyConfig = config_types.AutonomyConfig;
pub const DockerRuntimeConfig = config_types.DockerRuntimeConfig;
pub const RuntimeConfig = config_types.RuntimeConfig;
pub const ModelFallbackEntry = config_types.ModelFallbackEntry;
pub const ReliabilityConfig = config_types.ReliabilityConfig;
pub const SchedulerConfig = config_types.SchedulerConfig;
pub const AgentConfig = config_types.AgentConfig;
pub const ModelRouteConfig = config_types.ModelRouteConfig;
pub const HeartbeatConfig = config_types.HeartbeatConfig;
pub const CronConfig = config_types.CronConfig;
pub const TelegramConfig = config_types.TelegramConfig;
pub const DiscordConfig = config_types.DiscordConfig;
pub const SlackReceiveMode = config_types.SlackReceiveMode;
pub const SlackConfig = config_types.SlackConfig;
pub const WebhookConfig = config_types.WebhookConfig;
pub const IMessageConfig = config_types.IMessageConfig;
pub const MatrixConfig = config_types.MatrixConfig;
pub const MattermostConfig = config_types.MattermostConfig;
pub const WhatsAppConfig = config_types.WhatsAppConfig;
pub const IrcConfig = config_types.IrcConfig;
pub const LarkReceiveMode = config_types.LarkReceiveMode;
pub const LarkConfig = config_types.LarkConfig;
pub const DingTalkConfig = config_types.DingTalkConfig;
pub const SignalConfig = config_types.SignalConfig;
pub const EmailConfig = config_types.EmailConfig;
pub const LineConfig = config_types.LineConfig;
pub const QQGroupPolicy = config_types.QQGroupPolicy;
pub const QQConfig = config_types.QQConfig;
pub const OneBotConfig = config_types.OneBotConfig;
pub const MaixCamConfig = config_types.MaixCamConfig;
pub const ChannelsConfig = config_types.ChannelsConfig;
pub const MemoryConfig = config_types.MemoryConfig;
pub const TunnelConfig = config_types.TunnelConfig;
pub const GatewayConfig = config_types.GatewayConfig;
pub const ComposioConfig = config_types.ComposioConfig;
pub const SecretsConfig = config_types.SecretsConfig;
pub const BrowserComputerUseConfig = config_types.BrowserComputerUseConfig;
pub const BrowserConfig = config_types.BrowserConfig;
pub const HttpRequestConfig = config_types.HttpRequestConfig;
pub const IdentityConfig = config_types.IdentityConfig;
pub const CostConfig = config_types.CostConfig;
pub const PeripheralBoardConfig = config_types.PeripheralBoardConfig;
pub const PeripheralsConfig = config_types.PeripheralsConfig;
pub const HardwareConfig = config_types.HardwareConfig;
pub const SandboxConfig = config_types.SandboxConfig;
pub const ResourceLimitsConfig = config_types.ResourceLimitsConfig;
pub const AuditConfig = config_types.AuditConfig;
pub const SecurityConfig = config_types.SecurityConfig;
pub const DelegateAgentConfig = config_types.DelegateAgentConfig;
pub const NamedAgentConfig = config_types.NamedAgentConfig;
pub const McpServerConfig = config_types.McpServerConfig;
pub const ModelPricing = config_types.ModelPricing;
pub const ToolsConfig = config_types.ToolsConfig;
pub const ProviderEntry = config_types.ProviderEntry;
pub const AudioMediaConfig = config_types.AudioMediaConfig;
pub const DmScope = config_types.DmScope;
pub const IdentityLink = config_types.IdentityLink;
pub const SessionConfig = config_types.SessionConfig;

// ── Top-level Config ────────────────────────────────────────────

pub const Config = struct {
    // Computed paths (not serialized)
    workspace_dir: []const u8,
    config_path: []const u8,

    // Top-level fields
    providers: []const ProviderEntry = &.{},
    audio_media: AudioMediaConfig = .{},
    default_provider: []const u8 = "openrouter",
    default_model: ?[]const u8 = "anthropic/claude-sonnet-4",
    default_temperature: f64 = 0.7,
    reasoning_effort: ?[]const u8 = null,

    // Model routing and delegate agents
    model_routes: []const ModelRouteConfig = &.{},
    agents: []const NamedAgentConfig = &.{},
    agent_bindings: []const @import("agent_routing.zig").AgentBinding = &.{},
    mcp_servers: []const McpServerConfig = &.{},

    // Nested sub-configs
    diagnostics: DiagnosticsConfig = .{},
    autonomy: AutonomyConfig = .{},
    runtime: RuntimeConfig = .{},
    reliability: ReliabilityConfig = .{},
    scheduler: SchedulerConfig = .{},
    agent: AgentConfig = .{},
    heartbeat: HeartbeatConfig = .{},
    cron: CronConfig = .{},
    channels: ChannelsConfig = .{},
    memory: MemoryConfig = .{},
    tunnel: TunnelConfig = .{},
    gateway: GatewayConfig = .{},
    composio: ComposioConfig = .{},
    secrets: SecretsConfig = .{},
    browser: BrowserConfig = .{},
    http_request: HttpRequestConfig = .{},
    identity: IdentityConfig = .{},
    cost: CostConfig = .{},
    peripherals: PeripheralsConfig = .{},
    hardware: HardwareConfig = .{},
    security: SecurityConfig = .{},
    tools: ToolsConfig = .{},
    session: SessionConfig = .{},

    // Convenience aliases for backward-compat flat access used by other modules.
    // These are set during load() to mirror nested values.
    temperature: f64 = 0.7,
    max_tokens: ?u32 = null,
    memory_backend: []const u8 = "sqlite",
    memory_auto_save: bool = true,
    heartbeat_enabled: bool = false,
    heartbeat_interval_minutes: u32 = 30,
    gateway_host: []const u8 = "127.0.0.1",
    gateway_port: u16 = 3000,
    workspace_only: bool = true,
    max_actions_per_hour: u32 = 20,

    allocator: std.mem.Allocator,
    arena: ?*std.heap.ArenaAllocator = null,

    /// Look up a provider's API key from the providers list.
    pub fn getProviderKey(self: *const Config, name: []const u8) ?[]const u8 {
        for (self.providers) |e| {
            if (std.mem.eql(u8, e.name, name)) return e.api_key;
        }
        return null;
    }

    /// Convenience: API key for the default_provider.
    pub fn defaultProviderKey(self: *const Config) ?[]const u8 {
        return self.getProviderKey(self.default_provider);
    }

    /// Look up a provider's base_url from the providers list.
    pub fn getProviderBaseUrl(self: *const Config, name: []const u8) ?[]const u8 {
        for (self.providers) |e| {
            if (std.mem.eql(u8, e.name, name)) return e.base_url;
        }
        return null;
    }

    /// Sync flat convenience fields from the nested sub-configs.
    pub fn syncFlatFields(self: *Config) void {
        self.temperature = self.default_temperature;
        self.memory_backend = self.memory.backend;
        self.memory_auto_save = self.memory.auto_save;
        self.heartbeat_enabled = self.heartbeat.enabled;
        self.heartbeat_interval_minutes = self.heartbeat.interval_minutes;
        self.gateway_host = self.gateway.host;
        self.gateway_port = self.gateway.port;
        self.workspace_only = self.autonomy.workspace_only;
        self.max_actions_per_hour = self.autonomy.max_actions_per_hour;
    }

    pub fn load(backing_allocator: std.mem.Allocator) !Config {
        // Use an arena so deinit() can free everything in one shot.
        const arena_ptr = try backing_allocator.create(std.heap.ArenaAllocator);
        arena_ptr.* = std.heap.ArenaAllocator.init(backing_allocator);
        errdefer {
            arena_ptr.deinit();
            backing_allocator.destroy(arena_ptr);
        }
        const allocator = arena_ptr.allocator();

        const home = platform.getHomeDir(allocator) catch return error.NoHomeDir;

        const config_dir = try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
        const config_path = try std.fs.path.join(allocator, &.{ config_dir, "config.json" });
        const workspace_dir = try std.fs.path.join(allocator, &.{ config_dir, "workspace" });

        var cfg = Config{
            .workspace_dir = workspace_dir,
            .config_path = config_path,
            .allocator = allocator,
            .arena = arena_ptr,
        };

        // Try to read existing config file
        if (std.fs.openFileAbsolute(config_path, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(allocator, 1024 * 64);
            cfg.parseJson(content) catch {};
        } else |_| {
            // Config file doesn't exist yet — use defaults
        }

        // Environment variable overrides
        cfg.applyEnvOverrides();

        // Sync flat fields from nested structs
        cfg.syncFlatFields();

        return cfg;
    }

    /// Free all memory owned by this config (arena + heap pointer).
    /// No-op for configs created without load() (e.g. in tests).
    pub fn deinit(self: *Config) void {
        if (self.arena) |arena| {
            const backing = arena.child_allocator;
            arena.deinit();
            backing.destroy(arena);
            self.arena = null;
        }
    }

    /// Parse a JSON array of strings into an allocated slice.
    pub fn parseStringArray(self: *Config, arr: std.json.Array) ![]const []const u8 {
        return config_parse.parseStringArray(self.allocator, arr);
    }

    pub fn parseJson(self: *Config, content: []const u8) !void {
        return config_parse.parseJson(self, content);
    }

    /// Apply NULLCLAW_* environment variable overrides.
    pub fn applyEnvOverrides(self: *Config) void {
        // Provider
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_PROVIDER")) |prov| {
            self.default_provider = prov;
        } else |_| {}

        // Model
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_MODEL")) |model| {
            self.default_model = model;
        } else |_| {}

        // Temperature
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_TEMPERATURE")) |temp_str| {
            defer self.allocator.free(temp_str);
            if (std.fmt.parseFloat(f64, temp_str)) |temp| {
                if (temp >= 0.0 and temp <= 2.0) {
                    self.default_temperature = temp;
                }
            } else |_| {}
        } else |_| {}

        // Gateway port
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_GATEWAY_PORT")) |port_str| {
            defer self.allocator.free(port_str);
            if (std.fmt.parseInt(u16, port_str, 10)) |port| {
                self.gateway.port = port;
            } else |_| {}
        } else |_| {}

        // Gateway host
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_GATEWAY_HOST")) |host| {
            self.gateway.host = host;
        } else |_| {}

        // Workspace
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_WORKSPACE")) |ws| {
            self.workspace_dir = ws;
        } else |_| {}

        // Allow public bind
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_ALLOW_PUBLIC_BIND")) |val| {
            defer self.allocator.free(val);
            self.gateway.allow_public_bind = std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
        } else |_| {}
    }

    /// Save config as JSON to the config_path.
    pub fn save(self: *const Config) !void {
        const dir = std.fs.path.dirname(self.config_path) orelse return error.InvalidConfigPath;

        // Ensure parent directory exists
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const file = try std.fs.createFileAbsolute(self.config_path, .{});
        defer file.close();

        var buf: [8192]u8 = undefined;
        var bw = file.writer(&buf);
        const w = &bw.interface;

        try w.print("{{\n", .{});

        // Top-level fields
        try w.print("  \"default_provider\": \"{s}\",\n", .{self.default_provider});
        try w.print("  \"default_temperature\": {d:.1},\n", .{self.default_temperature});

        // models.providers
        if (self.providers.len > 0) {
            try w.print("  \"models\": {{\n    \"providers\": {{\n", .{});
            for (self.providers, 0..) |entry, i| {
                try w.print("      \"{s}\": {{", .{entry.name});
                var has_field = false;
                if (entry.api_key) |key| {
                    try w.print("\"api_key\": \"{s}\"", .{key});
                    has_field = true;
                }
                if (entry.base_url) |base| {
                    if (has_field) try w.print(", ", .{});
                    try w.print("\"base_url\": \"{s}\"", .{base});
                }
                try w.print("}}", .{});
                if (i + 1 < self.providers.len) try w.print(",", .{});
                try w.print("\n", .{});
            }
            try w.print("    }}\n  }},\n", .{});
        }

        // agents.defaults (model + heartbeat)
        {
            const has_model = self.default_model != null;
            const has_heartbeat = self.heartbeat.enabled or self.heartbeat.interval_minutes != 30;
            if (has_model or has_heartbeat) {
                try w.print("  \"agents\": {{\n    \"defaults\": {{\n", .{});
                if (self.default_model) |model| {
                    try w.print("      \"model\": {{\"primary\": \"{s}\"}}", .{model});
                    if (has_heartbeat) try w.print(",", .{});
                    try w.print("\n", .{});
                }
                if (has_heartbeat) {
                    try w.print("      \"heartbeat\": {{", .{});
                    // Convert interval_minutes to "every" string
                    const mins = self.heartbeat.interval_minutes;
                    if (mins >= 60 and mins % 60 == 0) {
                        try w.print("\"every\": \"{d}h\"", .{mins / 60});
                    } else {
                        try w.print("\"every\": \"{d}m\"", .{mins});
                    }
                    if (!self.heartbeat.enabled) {
                        try w.print(", \"enabled\": false", .{});
                    }
                    try w.print("}}\n", .{});
                }
                try w.print("    }}\n  }},\n", .{});
            }
        }

        // Diagnostics (with nested otel)
        try w.print("  \"diagnostics\": {{\n", .{});
        try w.print("    \"backend\": \"{s}\"", .{self.diagnostics.backend});
        if (self.diagnostics.otel_endpoint != null or self.diagnostics.otel_service_name != null) {
            try w.print(",\n    \"otel\": {{", .{});
            var otel_first = true;
            if (self.diagnostics.otel_endpoint) |ep| {
                try w.print("\"endpoint\": \"{s}\"", .{ep});
                otel_first = false;
            }
            if (self.diagnostics.otel_service_name) |sn| {
                if (!otel_first) try w.print(", ", .{});
                try w.print("\"service_name\": \"{s}\"", .{sn});
            }
            try w.print("}}", .{});
        }
        try w.print("\n  }},\n", .{});

        // Autonomy
        try w.print("  \"autonomy\": {{\n", .{});
        try w.print("    \"level\": \"{s}\",\n", .{@tagName(self.autonomy.level)});
        try w.print("    \"workspace_only\": {s},\n", .{if (self.autonomy.workspace_only) "true" else "false"});
        if (self.autonomy.allowed_paths.len > 0) {
            try w.print("    \"max_actions_per_hour\": {d},\n", .{self.autonomy.max_actions_per_hour});
            try w.print("    \"allowed_paths\": [", .{});
            for (self.autonomy.allowed_paths, 0..) |p, i| {
                if (i > 0) try w.print(", ", .{});
                try w.print("\"{s}\"", .{p});
            }
            try w.print("]\n", .{});
        } else {
            try w.print("    \"max_actions_per_hour\": {d}\n", .{self.autonomy.max_actions_per_hour});
        }
        try w.print("  }},\n", .{});

        // Memory
        try w.print("  \"memory\": {{\n", .{});
        try w.print("    \"backend\": \"{s}\",\n", .{self.memory.backend});
        try w.print("    \"auto_save\": {s},\n", .{if (self.memory.auto_save) "true" else "false"});
        try w.print("    \"hygiene_enabled\": {s},\n", .{if (self.memory.hygiene_enabled) "true" else "false"});
        try w.print("    \"archive_after_days\": {d},\n", .{self.memory.archive_after_days});
        try w.print("    \"purge_after_days\": {d},\n", .{self.memory.purge_after_days});
        try w.print("    \"conversation_retention_days\": {d}\n", .{self.memory.conversation_retention_days});
        try w.print("  }},\n", .{});

        // Gateway
        try w.print("  \"gateway\": {{\n", .{});
        try w.print("    \"port\": {d},\n", .{self.gateway.port});
        try w.print("    \"host\": \"{s}\",\n", .{self.gateway.host});
        try w.print("    \"require_pairing\": {s}\n", .{if (self.gateway.require_pairing) "true" else "false"});
        try w.print("  }},\n", .{});

        // Cost
        try w.print("  \"cost\": {{\n", .{});
        try w.print("    \"enabled\": {s},\n", .{if (self.cost.enabled) "true" else "false"});
        try w.print("    \"daily_limit_usd\": {d:.1},\n", .{self.cost.daily_limit_usd});
        try w.print("    \"monthly_limit_usd\": {d:.1}\n", .{self.cost.monthly_limit_usd});
        try w.print("  }},\n", .{});

        // Tools (with media.audio)
        try w.print("  \"tools\": {{\n", .{});
        try w.print("    \"shell_timeout_secs\": {d},\n", .{self.tools.shell_timeout_secs});
        try w.print("    \"shell_max_output_bytes\": {d},\n", .{self.tools.shell_max_output_bytes});
        try w.print("    \"max_file_size_bytes\": {d},\n", .{self.tools.max_file_size_bytes});
        try w.print("    \"web_fetch_max_chars\": {d}", .{self.tools.web_fetch_max_chars});
        // tools.media.audio
        {
            const am = self.audio_media;
            const is_default = am.enabled and
                std.mem.eql(u8, am.provider, "groq") and
                std.mem.eql(u8, am.model, "whisper-large-v3") and
                am.base_url == null and am.language == null;
            if (!is_default) {
                try w.print(",\n    \"media\": {{\n      \"audio\": {{\n", .{});
                try w.print("        \"enabled\": {s}", .{if (am.enabled) "true" else "false"});
                if (am.language) |lang| {
                    try w.print(",\n        \"language\": \"{s}\"", .{lang});
                }
                try w.print(",\n        \"models\": [{{\"provider\": \"{s}\", \"model\": \"{s}\"", .{ am.provider, am.model });
                if (am.base_url) |bu| {
                    try w.print(", \"base_url\": \"{s}\"", .{bu});
                }
                try w.print("}}]\n      }}\n    }}", .{});
            }
        }
        try w.print("\n  }},\n", .{});

        // Hardware
        try w.print("  \"hardware\": {{\n", .{});
        try w.print("    \"enabled\": {s},\n", .{if (self.hardware.enabled) "true" else "false"});
        try w.print("    \"transport\": \"{s}\",\n", .{@tagName(self.hardware.transport)});
        try w.print("    \"baud_rate\": {d}\n", .{self.hardware.baud_rate});
        try w.print("  }}\n", .{});

        try w.print("}}\n", .{});
        try w.flush();
    }

    // ── Validation ──────────────────────────────────────────────

    pub const ValidationError = error{
        TemperatureOutOfRange,
        InvalidPort,
        InvalidRetryCount,
        InvalidBackoffMs,
    };

    pub fn validate(self: *const Config) ValidationError!void {
        if (self.default_temperature < 0.0 or self.default_temperature > 2.0) {
            return ValidationError.TemperatureOutOfRange;
        }
        if (self.gateway.port == 0) {
            return ValidationError.InvalidPort;
        }
        if (self.reliability.provider_retries > 100) {
            return ValidationError.InvalidRetryCount;
        }
        if (self.reliability.provider_backoff_ms > 600_000) {
            return ValidationError.InvalidBackoffMs;
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────

test "json parse roundtrip" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "default_provider": "anthropic",
        \\  "default_temperature": 0.5,
        \\  "models": {"providers": {"anthropic": {"api_key": "sk-test"}}},
        \\  "agents": {"defaults": {"model": {"primary": "claude-opus-4"}, "heartbeat": {"every": "15m"}}},
        \\  "memory": {"backend": "markdown", "auto_save": false},
        \\  "gateway": {"port": 9090, "host": "0.0.0.0"},
        \\  "autonomy": {"level": "full", "workspace_only": false, "max_actions_per_hour": 50},
        \\  "runtime": {"kind": "docker"},
        \\  "cost": {"enabled": true, "daily_limit_usd": 25.0}
        \\}
    ;

    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    cfg.syncFlatFields();

    try std.testing.expectEqualStrings("anthropic", cfg.default_provider);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.default_model.?);
    try std.testing.expectEqual(@as(f64, 0.5), cfg.default_temperature);
    try std.testing.expectEqual(@as(f64, 0.5), cfg.temperature);
    try std.testing.expectEqualStrings("sk-test", cfg.defaultProviderKey().?);
    try std.testing.expect(cfg.heartbeat.enabled);
    try std.testing.expect(cfg.heartbeat_enabled);
    try std.testing.expectEqual(@as(u32, 15), cfg.heartbeat.interval_minutes);
    try std.testing.expectEqualStrings("markdown", cfg.memory.backend);
    try std.testing.expectEqualStrings("markdown", cfg.memory_backend);
    try std.testing.expect(!cfg.memory.auto_save);
    try std.testing.expect(!cfg.memory_auto_save);
    try std.testing.expectEqual(@as(u16, 9090), cfg.gateway.port);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.gateway.host);
    try std.testing.expectEqual(AutonomyLevel.full, cfg.autonomy.level);
    try std.testing.expect(!cfg.autonomy.workspace_only);
    try std.testing.expect(!cfg.workspace_only);
    try std.testing.expectEqual(@as(u32, 50), cfg.autonomy.max_actions_per_hour);
    try std.testing.expectEqualStrings("docker", cfg.runtime.kind);
    try std.testing.expect(cfg.cost.enabled);
    try std.testing.expectEqual(@as(f64, 25.0), cfg.cost.daily_limit_usd);

    // Clean up allocated strings
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
    for (cfg.providers) |e| {
        allocator.free(e.name);
        if (e.api_key) |k| allocator.free(k);
        if (e.base_url) |b| allocator.free(b);
    }
    allocator.free(cfg.providers);
    allocator.free(cfg.memory.backend);
    allocator.free(cfg.gateway.host);
    allocator.free(cfg.runtime.kind);
}

test "validation rejects bad temperature" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 5.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "validation rejects zero port" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.gateway.port = 0;
    try std.testing.expectError(Config.ValidationError.InvalidPort, cfg.validate());
}

test "validation passes for defaults" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try cfg.validate();
}

test "syncFlatFields propagates nested values" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.default_temperature = 1.5;
    cfg.memory.backend = "lucid";
    cfg.memory.auto_save = false;
    cfg.heartbeat.enabled = true;
    cfg.heartbeat.interval_minutes = 10;
    cfg.gateway.host = "0.0.0.0";
    cfg.gateway.port = 9999;
    cfg.autonomy.workspace_only = false;
    cfg.autonomy.max_actions_per_hour = 999;

    cfg.syncFlatFields();

    try std.testing.expectEqual(@as(f64, 1.5), cfg.temperature);
    try std.testing.expectEqualStrings("lucid", cfg.memory_backend);
    try std.testing.expect(!cfg.memory_auto_save);
    try std.testing.expect(cfg.heartbeat_enabled);
    try std.testing.expectEqual(@as(u32, 10), cfg.heartbeat_interval_minutes);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.gateway_host);
    try std.testing.expectEqual(@as(u16, 9999), cfg.gateway_port);
    try std.testing.expect(!cfg.workspace_only);
    try std.testing.expectEqual(@as(u32, 999), cfg.max_actions_per_hour);
}

// ── Security-critical defaults ───────────────────────────────────

test "gateway config requires pairing by default" {
    const g = GatewayConfig{};
    try std.testing.expect(g.require_pairing);
}

test "gateway config blocks public bind by default" {
    const g = GatewayConfig{};
    try std.testing.expect(!g.allow_public_bind);
}

test "secrets config default encrypts" {
    const s = SecretsConfig{};
    try std.testing.expect(s.encrypt);
}

// ── Validation edge cases ───────────────────────────────────────

test "validation rejects negative temperature" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = -1.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "validation accepts boundary temperatures" {
    const cfg_zero = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 0.0,
        .allocator = std.testing.allocator,
    };
    try cfg_zero.validate();

    const cfg_two = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 2.0,
        .allocator = std.testing.allocator,
    };
    try cfg_two.validate();
}

test "validation rejects excessive retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 101;
    try std.testing.expectError(Config.ValidationError.InvalidRetryCount, cfg.validate());
}

test "validation rejects excessive backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 700_000;
    try std.testing.expectError(Config.ValidationError.InvalidBackoffMs, cfg.validate());
}

test "validation accepts max boundary retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 100;
    try cfg.validate();
}

test "validation accepts max boundary backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 600_000;
    try cfg.validate();
}

// ── JSON parse: sub-config sections ─────────────────────────────

test "json parse diagnostics section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"diagnostics": {"backend": "otel", "otel": {"endpoint": "http://localhost:4318", "service_name": "yc"}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("otel", cfg.diagnostics.backend);
    try std.testing.expectEqualStrings("http://localhost:4318", cfg.diagnostics.otel_endpoint.?);
    try std.testing.expectEqualStrings("yc", cfg.diagnostics.otel_service_name.?);
    allocator.free(cfg.diagnostics.backend);
    allocator.free(cfg.diagnostics.otel_endpoint.?);
    allocator.free(cfg.diagnostics.otel_service_name.?);
}

test "json parse scheduler section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"scheduler": {"enabled": false, "max_tasks": 128, "max_concurrent": 8}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.scheduler.enabled);
    try std.testing.expectEqual(@as(u32, 128), cfg.scheduler.max_tasks);
    try std.testing.expectEqual(@as(u32, 8), cfg.scheduler.max_concurrent);
}

test "json parse agent section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agent": {"compact_context": true, "max_tool_iterations": 20, "max_history_messages": 80, "parallel_tools": true, "tool_dispatcher": "xml"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.agent.compact_context);
    try std.testing.expectEqual(@as(u32, 20), cfg.agent.max_tool_iterations);
    try std.testing.expectEqual(@as(u32, 80), cfg.agent.max_history_messages);
    try std.testing.expect(cfg.agent.parallel_tools);
    try std.testing.expectEqualStrings("xml", cfg.agent.tool_dispatcher);
    allocator.free(cfg.agent.tool_dispatcher);
}

test "json parse composio section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"composio": {"enabled": true, "api_key": "comp-key", "entity_id": "user1"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.composio.enabled);
    try std.testing.expectEqualStrings("comp-key", cfg.composio.api_key.?);
    try std.testing.expectEqualStrings("user1", cfg.composio.entity_id);
    allocator.free(cfg.composio.api_key.?);
    allocator.free(cfg.composio.entity_id);
}

test "json parse secrets section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"secrets": {"encrypt": false}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.secrets.encrypt);
}

test "json parse identity section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"identity": {"format": "aieos", "aieos_path": "id.json"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("aieos", cfg.identity.format);
    try std.testing.expectEqualStrings("id.json", cfg.identity.aieos_path.?);
    allocator.free(cfg.identity.format);
    allocator.free(cfg.identity.aieos_path.?);
}

test "json parse hardware section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"hardware": {"enabled": true, "transport": "serial", "serial_port": "/dev/ttyACM0", "baud_rate": 9600}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.hardware.enabled);
    try std.testing.expectEqual(HardwareTransport.serial, cfg.hardware.transport);
    try std.testing.expectEqualStrings("/dev/ttyACM0", cfg.hardware.serial_port.?);
    try std.testing.expectEqual(@as(u32, 9600), cfg.hardware.baud_rate);
    allocator.free(cfg.hardware.serial_port.?);
}

test "json parse security section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"security": {"sandbox": {"enabled": true, "backend": "firejail"}, "resources": {"max_memory_mb": 1024, "max_cpu_time_seconds": 120}, "audit": {"enabled": false, "log_path": "custom.log"}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.security.sandbox.enabled.?);
    try std.testing.expectEqual(SandboxBackend.firejail, cfg.security.sandbox.backend);
    try std.testing.expectEqual(@as(u32, 1024), cfg.security.resources.max_memory_mb);
    try std.testing.expectEqual(@as(u64, 120), cfg.security.resources.max_cpu_time_seconds);
    try std.testing.expect(!cfg.security.audit.enabled);
    try std.testing.expectEqualStrings("custom.log", cfg.security.audit.log_path);
    allocator.free(cfg.security.audit.log_path);
}

test "json parse browser section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"browser": {"enabled": true, "backend": "auto", "native_headless": false}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.browser.enabled);
    try std.testing.expectEqualStrings("auto", cfg.browser.backend);
    try std.testing.expect(!cfg.browser.native_headless);
    allocator.free(cfg.browser.backend);
}

test "json parse empty object uses defaults" {
    const allocator = std.testing.allocator;
    const json = "{}";
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("openrouter", cfg.default_provider);
    try std.testing.expectEqual(@as(f64, 0.7), cfg.default_temperature);
    try std.testing.expect(cfg.secrets.encrypt);
}

test "json parse integer temperature coerced to float" {
    const allocator = std.testing.allocator;
    const json =
        \\{"default_temperature": 1}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(f64, 1.0), cfg.default_temperature);
}

test "json parse autonomy allowed commands" {
    const allocator = std.testing.allocator;
    const json =
        \\{"autonomy": {"allowed_commands": ["ls", "cat", "git status"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.autonomy.allowed_commands.len);
    try std.testing.expectEqualStrings("ls", cfg.autonomy.allowed_commands[0]);
    try std.testing.expectEqualStrings("cat", cfg.autonomy.allowed_commands[1]);
    try std.testing.expectEqualStrings("git status", cfg.autonomy.allowed_commands[2]);
    for (cfg.autonomy.allowed_commands) |cmd| allocator.free(cmd);
    allocator.free(cfg.autonomy.allowed_commands);
}

test "json parse autonomy allowed_paths" {
    const allocator = std.testing.allocator;
    const json =
        \\{"autonomy": {"allowed_paths": ["/Users/igor/projects", "/tmp/scratch"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.autonomy.allowed_paths.len);
    try std.testing.expectEqualStrings("/Users/igor/projects", cfg.autonomy.allowed_paths[0]);
    try std.testing.expectEqualStrings("/tmp/scratch", cfg.autonomy.allowed_paths[1]);
    for (cfg.autonomy.allowed_paths) |p| allocator.free(p);
    allocator.free(cfg.autonomy.allowed_paths);
}

test "json parse gateway paired tokens" {
    const allocator = std.testing.allocator;
    const json =
        \\{"gateway": {"paired_tokens": ["token-1", "token-2", "token-3"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.gateway.paired_tokens.len);
    try std.testing.expectEqualStrings("token-1", cfg.gateway.paired_tokens[0]);
    try std.testing.expectEqualStrings("token-2", cfg.gateway.paired_tokens[1]);
    try std.testing.expectEqualStrings("token-3", cfg.gateway.paired_tokens[2]);
    for (cfg.gateway.paired_tokens) |t| allocator.free(t);
    allocator.free(cfg.gateway.paired_tokens);
}

test "json parse browser allowed domains" {
    const allocator = std.testing.allocator;
    const json =
        \\{"browser": {"enabled": true, "allowed_domains": ["github.com", "docs.rs"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.browser.enabled);
    try std.testing.expectEqual(@as(usize, 2), cfg.browser.allowed_domains.len);
    try std.testing.expectEqualStrings("github.com", cfg.browser.allowed_domains[0]);
    try std.testing.expectEqualStrings("docs.rs", cfg.browser.allowed_domains[1]);
    for (cfg.browser.allowed_domains) |d| allocator.free(d);
    allocator.free(cfg.browser.allowed_domains);
}

test "json parse model routes" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "reasoning", "provider": "openrouter", "model": "anthropic/claude-opus-4"},
        \\  {"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "api_key": "gsk_test"}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.model_routes.len);
    try std.testing.expectEqualStrings("reasoning", cfg.model_routes[0].hint);
    try std.testing.expectEqualStrings("openrouter", cfg.model_routes[0].provider);
    try std.testing.expectEqualStrings("anthropic/claude-opus-4", cfg.model_routes[0].model);
    try std.testing.expect(cfg.model_routes[0].api_key == null);
    try std.testing.expectEqualStrings("fast", cfg.model_routes[1].hint);
    try std.testing.expectEqualStrings("groq", cfg.model_routes[1].provider);
    try std.testing.expectEqualStrings("llama-3.3-70b", cfg.model_routes[1].model);
    try std.testing.expectEqualStrings("gsk_test", cfg.model_routes[1].api_key.?);
    // Cleanup
    for (cfg.model_routes) |r| {
        allocator.free(r.hint);
        allocator.free(r.provider);
        allocator.free(r.model);
        if (r.api_key) |k| allocator.free(k);
    }
    allocator.free(cfg.model_routes);
}

test "json parse model routes skips invalid entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "ok", "provider": "p", "model": "m"},
        \\  {"hint": "missing_model", "provider": "p"},
        \\  {"invalid": true}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqualStrings("ok", cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
}

test "json parse agents" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [
        \\  {"name": "researcher", "provider": "anthropic", "model": "claude-sonnet-4", "system_prompt": "Research things", "max_depth": 5},
        \\  {"name": "coder", "provider": "openai", "model": "gpt-4o", "api_key": "sk-test", "temperature": 0.3}
        \\]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.agents.len);
    try std.testing.expectEqualStrings("researcher", cfg.agents[0].name);
    try std.testing.expectEqualStrings("anthropic", cfg.agents[0].provider);
    try std.testing.expectEqualStrings("claude-sonnet-4", cfg.agents[0].model);
    try std.testing.expectEqualStrings("Research things", cfg.agents[0].system_prompt.?);
    try std.testing.expectEqual(@as(u32, 5), cfg.agents[0].max_depth);
    try std.testing.expect(cfg.agents[0].api_key == null);
    try std.testing.expectEqualStrings("coder", cfg.agents[1].name);
    try std.testing.expectEqualStrings("openai", cfg.agents[1].provider);
    try std.testing.expectEqualStrings("gpt-4o", cfg.agents[1].model);
    try std.testing.expectEqualStrings("sk-test", cfg.agents[1].api_key.?);
    try std.testing.expectEqual(@as(f64, 0.3), cfg.agents[1].temperature.?);
    try std.testing.expectEqual(@as(u32, 3), cfg.agents[1].max_depth);
    // Cleanup
    for (cfg.agents) |a| {
        allocator.free(a.name);
        allocator.free(a.provider);
        allocator.free(a.model);
        if (a.system_prompt) |sp| allocator.free(sp);
        if (a.api_key) |k| allocator.free(k);
    }
    allocator.free(cfg.agents);
}

test "json parse agents skips invalid entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [
        \\  {"name": "ok", "provider": "p", "model": "m"},
        \\  {"name": "missing_model", "provider": "p"},
        \\  42
        \\]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("ok", cfg.agents[0].name);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
}

// ── Combined: all new fields in one JSON ────────────────────────

test "json parse all new fields together" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "model_routes": [{"hint": "fast", "provider": "groq", "model": "llama-3.3-70b"}],
        \\  "agents": {"list": [{"name": "helper", "provider": "anthropic", "model": "claude-haiku-3.5"}]},
        \\  "autonomy": {"allowed_commands": ["ls"]},
        \\  "gateway": {"paired_tokens": ["tok-1"]},
        \\  "browser": {"allowed_domains": ["example.com"]}
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.autonomy.allowed_commands.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.gateway.paired_tokens.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.browser.allowed_domains.len);
    // Cleanup
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
    allocator.free(cfg.autonomy.allowed_commands[0]);
    allocator.free(cfg.autonomy.allowed_commands);
    allocator.free(cfg.gateway.paired_tokens[0]);
    allocator.free(cfg.gateway.paired_tokens);
    allocator.free(cfg.browser.allowed_domains[0]);
    allocator.free(cfg.browser.allowed_domains);
}

test "parse agents.defaults.model.primary" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"defaults": {"model": {"primary": "anthropic/claude-opus-4"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("anthropic/claude-opus-4", cfg.default_model.?);
    allocator.free(cfg.default_model.?);
}

test "parse agents.list with model object" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"name": "res", "provider": "anthropic", "model": {"primary": "claude-opus-4"}}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.agents[0].model);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
}

test "parse agents.list with id field" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"id": "researcher", "provider": "anthropic", "model": "claude-sonnet-4"}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("researcher", cfg.agents[0].name);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
}

test "parse top-level bindings with snake_case fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{
        \\  "bindings": [
        \\    {
        \\      "agent_id": "helper",
        \\      "comment": "primary route",
        \\      "match": {
        \\        "channel": "signal",
        \\        "account_id": "phone",
        \\        "peer": {"kind": "group", "id": "grp-1"},
        \\        "guild_id": "guild-9",
        \\        "team_id": "team-2",
        \\        "roles": ["mod", "ops"]
        \\      }
        \\    }
        \\  ]
        \\}
    ;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.agent_bindings.len);
    const binding = cfg.agent_bindings[0];
    try std.testing.expectEqualStrings("helper", binding.agent_id);
    try std.testing.expectEqualStrings("primary route", binding.comment.?);
    try std.testing.expectEqualStrings("signal", binding.match.channel.?);
    try std.testing.expectEqualStrings("phone", binding.match.account_id.?);
    try std.testing.expectEqualStrings("guild-9", binding.match.guild_id.?);
    try std.testing.expectEqualStrings("team-2", binding.match.team_id.?);
    try std.testing.expectEqual(@as(usize, 2), binding.match.roles.len);
    try std.testing.expectEqualStrings("mod", binding.match.roles[0]);
    try std.testing.expectEqualStrings("ops", binding.match.roles[1]);
    try std.testing.expect(binding.match.peer != null);
    try std.testing.expectEqual(@as(@import("agent_routing.zig").ChatType, .group), binding.match.peer.?.kind);
    try std.testing.expectEqualStrings("grp-1", binding.match.peer.?.id);
}

test "ignore nested agents.bindings alias" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{
        \\  "agents": {
        \\    "bindings": [
        \\      {
        \\        "agent_id": "main",
        \\        "match": {
        \\          "channel": "telegram",
        \\          "peer": {"kind": "direct", "id": "12345"}
        \\        }
        \\      }
        \\    ]
        \\  }
        \\}
    ;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 0), cfg.agent_bindings.len);
}

// ── Environment variable override tests ─────────────────────────

test "applyEnvOverrides does not crash on default config" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    // Should not crash even when no NULLCLAW_* env vars are set
    cfg.applyEnvOverrides();
    // Default values should remain intact
    try std.testing.expectEqualStrings("openrouter", cfg.default_provider);
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4", cfg.default_model.?);
    try std.testing.expectEqual(@as(usize, 0), cfg.providers.len);
}

test "json parse mcp_servers" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "filesystem": {
        \\    "command": "npx",
        \\    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        \\  },
        \\  "git": {
        \\    "command": "mcp-server-git"
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.mcp_servers.len);
    // Find filesystem entry (order may vary due to hash map)
    var found_fs = false;
    var found_git = false;
    for (cfg.mcp_servers) |s| {
        if (std.mem.eql(u8, s.name, "filesystem")) {
            found_fs = true;
            try std.testing.expectEqualStrings("npx", s.command);
            try std.testing.expectEqual(@as(usize, 3), s.args.len);
            try std.testing.expectEqualStrings("-y", s.args[0]);
        }
        if (std.mem.eql(u8, s.name, "git")) {
            found_git = true;
            try std.testing.expectEqualStrings("mcp-server-git", s.command);
            try std.testing.expectEqual(@as(usize, 0), s.args.len);
        }
    }
    try std.testing.expect(found_fs);
    try std.testing.expect(found_git);
    // Cleanup
    for (cfg.mcp_servers) |s| {
        allocator.free(s.name);
        allocator.free(s.command);
        for (s.args) |a| allocator.free(a);
        allocator.free(s.args);
    }
    allocator.free(cfg.mcp_servers);
}

test "json parse mcp_servers with env" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "myserver": {
        \\    "command": "/usr/bin/server",
        \\    "args": ["--verbose"],
        \\    "env": {"NODE_ENV": "production", "DEBUG": "true"}
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.mcp_servers.len);
    const s = cfg.mcp_servers[0];
    try std.testing.expectEqualStrings("myserver", s.name);
    try std.testing.expectEqualStrings("/usr/bin/server", s.command);
    try std.testing.expectEqual(@as(usize, 1), s.args.len);
    try std.testing.expectEqual(@as(usize, 2), s.env.len);
    // Find env entries (order may vary)
    var found_node = false;
    var found_debug = false;
    for (s.env) |e| {
        if (std.mem.eql(u8, e.key, "NODE_ENV")) {
            found_node = true;
            try std.testing.expectEqualStrings("production", e.value);
        }
        if (std.mem.eql(u8, e.key, "DEBUG")) {
            found_debug = true;
            try std.testing.expectEqualStrings("true", e.value);
        }
    }
    try std.testing.expect(found_node);
    try std.testing.expect(found_debug);
    // Cleanup
    allocator.free(s.name);
    allocator.free(s.command);
    for (s.args) |a| allocator.free(a);
    allocator.free(s.args);
    for (s.env) |e| {
        allocator.free(e.key);
        allocator.free(e.value);
    }
    allocator.free(s.env);
    allocator.free(cfg.mcp_servers);
}

test "json parse providers section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"models": {"providers": {"openrouter": {"api_key": "sk-or-abc"}, "groq": {"api_key": "gsk_123", "base_url": "https://custom.groq.dev"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.providers.len);
    try std.testing.expectEqualStrings("sk-or-abc", cfg.getProviderKey("openrouter").?);
    try std.testing.expectEqualStrings("gsk_123", cfg.getProviderKey("groq").?);
    try std.testing.expectEqualStrings("https://custom.groq.dev", cfg.getProviderBaseUrl("groq").?);
    try std.testing.expect(cfg.getProviderBaseUrl("openrouter") == null);
    // Cleanup
    for (cfg.providers) |e| {
        allocator.free(e.name);
        if (e.api_key) |k| allocator.free(k);
        if (e.base_url) |b| allocator.free(b);
    }
    allocator.free(cfg.providers);
}

test "json parse tools.media.audio section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tools": {"media": {"audio": {"enabled": true, "language": "en", "models": [{"provider": "openai", "model": "whisper-1", "base_url": "https://api.openai.com/v1/audio/transcriptions"}]}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.audio_media.enabled);
    try std.testing.expectEqualStrings("openai", cfg.audio_media.provider);
    try std.testing.expectEqualStrings("whisper-1", cfg.audio_media.model);
    try std.testing.expectEqualStrings("https://api.openai.com/v1/audio/transcriptions", cfg.audio_media.base_url.?);
    try std.testing.expectEqualStrings("en", cfg.audio_media.language.?);
    allocator.free(cfg.audio_media.provider);
    allocator.free(cfg.audio_media.model);
    allocator.free(cfg.audio_media.base_url.?);
    allocator.free(cfg.audio_media.language.?);
}

test "getProviderKey returns null for missing provider" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(cfg.getProviderKey("nonexistent") == null);
    try std.testing.expect(cfg.defaultProviderKey() == null);
}

test "providers defaults to empty" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqual(@as(usize, 0), cfg.providers.len);
}

test "audio_media defaults" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(cfg.audio_media.enabled);
    try std.testing.expectEqualStrings("groq", cfg.audio_media.provider);
    try std.testing.expectEqualStrings("whisper-large-v3", cfg.audio_media.model);
    try std.testing.expect(cfg.audio_media.base_url == null);
    try std.testing.expect(cfg.audio_media.language == null);
}

test "defaultProviderKey returns key for default provider" {
    const allocator = std.testing.allocator;
    const json =
        \\{"default_provider": "groq", "models": {"providers": {"groq": {"api_key": "gsk_found"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("gsk_found", cfg.defaultProviderKey().?);
    // Cleanup
    allocator.free(cfg.default_provider);
    for (cfg.providers) |e| {
        allocator.free(e.name);
        if (e.api_key) |k| allocator.free(k);
        if (e.base_url) |b| allocator.free(b);
    }
    allocator.free(cfg.providers);
}

test "tools.media.audio with language only parses correctly" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tools": {"media": {"audio": {"language": "ru"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("ru", cfg.audio_media.language.?);
    // provider/model remain defaults (string literals, not allocated)
    try std.testing.expectEqualStrings("groq", cfg.audio_media.provider);
    try std.testing.expectEqualStrings("whisper-large-v3", cfg.audio_media.model);
    allocator.free(cfg.audio_media.language.?);
}

test "parse agents.defaults.heartbeat with every string" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"defaults": {"heartbeat": {"every": "30m"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.heartbeat.enabled);
    try std.testing.expectEqual(@as(u32, 30), cfg.heartbeat.interval_minutes);
}

test "parse agents.defaults.heartbeat with hours" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"defaults": {"heartbeat": {"every": "2h"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.heartbeat.enabled);
    try std.testing.expectEqual(@as(u32, 120), cfg.heartbeat.interval_minutes);
}

test "parse agents.defaults.heartbeat disabled" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"defaults": {"heartbeat": {"every": "30m", "enabled": false}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.heartbeat.enabled);
    try std.testing.expectEqual(@as(u32, 30), cfg.heartbeat.interval_minutes);
}

test "tools.media.audio disabled" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tools": {"media": {"audio": {"enabled": false}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.audio_media.enabled);
    // defaults remain
    try std.testing.expectEqualStrings("groq", cfg.audio_media.provider);
}

test "parse telegram accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"main": {"bot_token": "123:ABC", "allow_from": ["user1"], "reply_in_private": false, "proxy": "socks5://host:1080"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.telegram.len > 0);
    const tg = cfg.channels.telegram[0];
    try std.testing.expectEqualStrings("main", tg.account_id);
    try std.testing.expectEqualStrings("123:ABC", tg.bot_token);
    try std.testing.expectEqual(@as(usize, 1), tg.allow_from.len);
    try std.testing.expectEqualStrings("user1", tg.allow_from[0]);
    try std.testing.expect(!tg.reply_in_private);
    try std.testing.expectEqualStrings("socks5://host:1080", tg.proxy.?);
    allocator.free(tg.account_id);
    allocator.free(tg.bot_token);
    for (tg.allow_from) |u| allocator.free(u);
    allocator.free(tg.allow_from);
    allocator.free(tg.proxy.?);
    allocator.free(cfg.channels.telegram);
}

test "parse telegram multi-account sorted alphabetically" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"main": {"bot_token": "main:tok"}, "default": {"bot_token": "default:tok"}, "backup": {"bot_token": "backup:tok"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.channels.telegram.len);
    // Sorted alphabetically: backup < default < main
    try std.testing.expectEqualStrings("backup", cfg.channels.telegram[0].account_id);
    try std.testing.expectEqualStrings("default", cfg.channels.telegram[1].account_id);
    try std.testing.expectEqualStrings("main", cfg.channels.telegram[2].account_id);
    // Free all accounts
    for (cfg.channels.telegram) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.telegram);
}

test "parse telegram accounts keeps single custom account id" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"phone_1": {"bot_token": "123:ABC"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.telegram.len > 0);
    const tg = cfg.channels.telegram[0];
    try std.testing.expectEqualStrings("phone_1", tg.account_id);
    try std.testing.expectEqualStrings("123:ABC", tg.bot_token);
    allocator.free(tg.account_id);
    allocator.free(tg.bot_token);
    allocator.free(cfg.channels.telegram);
}

test "parse discord accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"discord": {"accounts": {"main": {"token": "disc-tok", "guild_id": "12345", "allow_from": ["u1"], "require_mention": true}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.discord.len > 0);
    const dc = cfg.channels.discord[0];
    try std.testing.expectEqualStrings("main", dc.account_id);
    try std.testing.expectEqualStrings("disc-tok", dc.token);
    try std.testing.expectEqualStrings("12345", dc.guild_id.?);
    try std.testing.expect(dc.require_mention);
    allocator.free(dc.account_id);
    allocator.free(dc.token);
    allocator.free(dc.guild_id.?);
    for (dc.allow_from) |u| allocator.free(u);
    allocator.free(dc.allow_from);
    allocator.free(cfg.channels.discord);
}

test "parse discord mention_only is ignored (snake_case only)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"discord": {"accounts": {"main": {"token": "disc-tok", "mention_only": true}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.discord.len);
    try std.testing.expect(!cfg.channels.discord[0].require_mention);
    allocator.free(cfg.channels.discord[0].account_id);
    allocator.free(cfg.channels.discord[0].token);
    allocator.free(cfg.channels.discord);
}

test "parse slack accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"slack": {"accounts": {"main": {"bot_token": "xoxb-123", "app_token": "xapp-456", "allow_from": ["u1"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.slack.len > 0);
    const sc = cfg.channels.slack[0];
    try std.testing.expectEqualStrings("main", sc.account_id);
    try std.testing.expectEqualStrings("xoxb-123", sc.bot_token);
    try std.testing.expectEqualStrings("xapp-456", sc.app_token.?);
    allocator.free(sc.account_id);
    allocator.free(sc.bot_token);
    allocator.free(sc.app_token.?);
    for (sc.allow_from) |u| allocator.free(u);
    allocator.free(sc.allow_from);
    allocator.free(cfg.channels.slack);
}

test "parse irc accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"irc": {"accounts": {"freenode": {"host": "irc.libera.chat", "nick": "bot", "port": 6667, "channels": ["#test"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.irc.len);
    const ic = cfg.channels.irc[0];
    try std.testing.expectEqualStrings("freenode", ic.account_id);
    try std.testing.expectEqualStrings("irc.libera.chat", ic.host);
    try std.testing.expectEqualStrings("bot", ic.nick);
    try std.testing.expectEqual(@as(u16, 6667), ic.port);
    try std.testing.expectEqual(@as(usize, 1), ic.channels.len);
    allocator.free(ic.account_id);
    allocator.free(ic.host);
    allocator.free(ic.nick);
    for (ic.channels) |c| allocator.free(c);
    allocator.free(ic.channels);
    allocator.free(cfg.channels.irc);
}

test "parse matrix accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"matrix": {"accounts": {"main": {"homeserver": "https://matrix.org", "access_token": "syt_abc", "room_id": "!room:matrix.org", "user_id": "@bot:matrix.org", "group_allow_from": ["@alice:matrix.org"], "group_policy": "open"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.matrix.len);
    const mc = cfg.channels.matrix[0];
    try std.testing.expectEqualStrings("main", mc.account_id);
    try std.testing.expectEqualStrings("https://matrix.org", mc.homeserver);
    try std.testing.expectEqualStrings("syt_abc", mc.access_token);
    try std.testing.expectEqualStrings("!room:matrix.org", mc.room_id);
    try std.testing.expectEqualStrings("@bot:matrix.org", mc.user_id.?);
    try std.testing.expectEqualStrings("open", mc.group_policy);
    try std.testing.expectEqual(@as(usize, 1), mc.group_allow_from.len);
    try std.testing.expectEqualStrings("@alice:matrix.org", mc.group_allow_from[0]);
    allocator.free(mc.account_id);
    allocator.free(mc.homeserver);
    allocator.free(mc.access_token);
    allocator.free(mc.room_id);
    allocator.free(mc.user_id.?);
    allocator.free(mc.group_policy);
    for (mc.group_allow_from) |entry| allocator.free(entry);
    allocator.free(mc.group_allow_from);
    allocator.free(cfg.channels.matrix);
}

test "parse mattermost accounts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"channels": {"mattermost": {"accounts": {"main": {"bot_token": "mm-token", "base_url": "https://chat.example.com", "allow_from": ["user-a"], "group_allow_from": ["@alice"], "dm_policy": "open", "group_policy": "allowlist", "chatmode": "onchar", "onchar_prefixes": ["!"], "require_mention": false}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.mattermost.len);
    const mm = cfg.channels.mattermost[0];
    try std.testing.expectEqualStrings("main", mm.account_id);
    try std.testing.expectEqualStrings("mm-token", mm.bot_token);
    try std.testing.expectEqualStrings("https://chat.example.com", mm.base_url);
    try std.testing.expectEqual(@as(usize, 1), mm.allow_from.len);
    try std.testing.expectEqualStrings("user-a", mm.allow_from[0]);
    try std.testing.expectEqual(@as(usize, 1), mm.group_allow_from.len);
    try std.testing.expectEqualStrings("@alice", mm.group_allow_from[0]);
    try std.testing.expectEqualStrings("open", mm.dm_policy);
    try std.testing.expectEqualStrings("allowlist", mm.group_policy);
    try std.testing.expectEqualStrings("onchar", mm.chatmode);
    try std.testing.expectEqual(@as(usize, 1), mm.onchar_prefixes.len);
    try std.testing.expectEqualStrings("!", mm.onchar_prefixes[0]);
    try std.testing.expect(!mm.require_mention);
}

test "parse lark accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"lark": {"accounts": {"main": {"app_id": "cli_abc", "app_secret": "sec123", "use_feishu": true}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.lark.len);
    const lc = cfg.channels.lark[0];
    try std.testing.expectEqualStrings("main", lc.account_id);
    try std.testing.expectEqualStrings("cli_abc", lc.app_id);
    try std.testing.expectEqualStrings("sec123", lc.app_secret);
    try std.testing.expect(lc.use_feishu);
    allocator.free(lc.account_id);
    allocator.free(lc.app_id);
    allocator.free(lc.app_secret);
    allocator.free(cfg.channels.lark);
}

test "parse dingtalk accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"dingtalk": {"accounts": {"main": {"client_id": "cid", "client_secret": "csec", "allow_from": ["u1"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.dingtalk.len);
    const dc = cfg.channels.dingtalk[0];
    try std.testing.expectEqualStrings("main", dc.account_id);
    try std.testing.expectEqualStrings("cid", dc.client_id);
    try std.testing.expectEqualStrings("csec", dc.client_secret);
    allocator.free(dc.account_id);
    allocator.free(dc.client_id);
    allocator.free(dc.client_secret);
    for (dc.allow_from) |u| allocator.free(u);
    allocator.free(dc.allow_from);
    allocator.free(cfg.channels.dingtalk);
}

test "parse whatsapp accounts" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"whatsapp": {"accounts": {"main": {"access_token": "wa-tok", "phone_number_id": "12345", "verify_token": "vtok", "app_secret": "sec", "allow_from": ["+1234"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.whatsapp.len);
    const wc = cfg.channels.whatsapp[0];
    try std.testing.expectEqualStrings("main", wc.account_id);
    try std.testing.expectEqualStrings("wa-tok", wc.access_token);
    try std.testing.expectEqualStrings("12345", wc.phone_number_id);
    try std.testing.expectEqualStrings("vtok", wc.verify_token);
    try std.testing.expectEqualStrings("sec", wc.app_secret.?);
    try std.testing.expectEqual(@as(usize, 1), wc.allow_from.len);
    allocator.free(wc.account_id);
    allocator.free(wc.access_token);
    allocator.free(wc.phone_number_id);
    allocator.free(wc.verify_token);
    allocator.free(wc.app_secret.?);
    for (wc.allow_from) |u| allocator.free(u);
    allocator.free(wc.allow_from);
    allocator.free(cfg.channels.whatsapp);
}

test "parse signal multi-account sorted alphabetically" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"signal": {"accounts": {"z-main": {"http_url": "http://localhost:8082", "account": "+155502", "ignore_attachments": true}, "a-main": {"http_url": "http://localhost:8081", "account": "+155501"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.signal.len);
    try std.testing.expectEqualStrings("a-main", cfg.channels.signal[0].account_id);
    try std.testing.expectEqualStrings("+155501", cfg.channels.signal[0].account);
    try std.testing.expectEqualStrings("z-main", cfg.channels.signal[1].account_id);
    try std.testing.expect(cfg.channels.signal[1].ignore_attachments);
}

test "parse qq accounts include allowlist and allowed_groups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"qq": {"accounts": {"qq-backup": {"app_id": "app2", "bot_token": "tok2"}, "qq-main": {"app_id": "app1", "app_secret": "sec1", "bot_token": "tok1", "group_policy": "allowlist", "allowed_groups": ["group-a", "group-b"], "allow_from": ["user-a"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.qq.len);
    try std.testing.expectEqualStrings("qq-backup", cfg.channels.qq[0].account_id);
    try std.testing.expectEqualStrings("qq-main", cfg.channels.qq[1].account_id);
    try std.testing.expectEqual(config_types.QQGroupPolicy.allowlist, cfg.channels.qq[1].group_policy);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.qq[1].allowed_groups.len);
    try std.testing.expectEqualStrings("group-a", cfg.channels.qq[1].allowed_groups[0]);
    try std.testing.expectEqualStrings("group-b", cfg.channels.qq[1].allowed_groups[1]);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.qq[1].allow_from.len);
    try std.testing.expectEqualStrings("user-a", cfg.channels.qq[1].allow_from[0]);
}

test "parse onebot multi-account sorted alphabetically" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"onebot": {"accounts": {"west": {"url": "ws://west.local:6700"}, "east": {"url": "ws://east.local:6700", "group_trigger_prefix": "/bot"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.onebot.len);
    try std.testing.expectEqualStrings("east", cfg.channels.onebot[0].account_id);
    try std.testing.expectEqualStrings("ws://east.local:6700", cfg.channels.onebot[0].url);
    try std.testing.expectEqualStrings("/bot", cfg.channels.onebot[0].group_trigger_prefix.?);
    try std.testing.expectEqualStrings("west", cfg.channels.onebot[1].account_id);
}

test "parse onebot account_id in payload is overridden by account key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"onebot": {"accounts": {"edge": {"account_id": "wrong", "url": "ws://edge.local:6700"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.onebot.len);
    try std.testing.expectEqualStrings("edge", cfg.channels.onebot[0].account_id);
    try std.testing.expectEqualStrings("ws://edge.local:6700", cfg.channels.onebot[0].url);
}

test "parse maixcam multi-account sorted with custom names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"maixcam": {"accounts": {"cam-z": {"port": 8888, "name": "vision-z"}, "cam-a": {"port": 7777, "name": "vision-a", "allow_from": ["device-1"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.maixcam.len);
    try std.testing.expectEqualStrings("cam-a", cfg.channels.maixcam[0].account_id);
    try std.testing.expectEqualStrings("vision-a", cfg.channels.maixcam[0].name);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.maixcam[0].allow_from.len);
    try std.testing.expectEqualStrings("device-1", cfg.channels.maixcam[0].allow_from[0]);
    try std.testing.expectEqualStrings("cam-z", cfg.channels.maixcam[1].account_id);
    try std.testing.expectEqual(@as(u16, 8888), cfg.channels.maixcam[1].port);
}

test "multi-account channels keep all accounts sorted by account id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"line": {"accounts": {"main": {"access_token": "line-main", "channel_secret": "line-main-secret"}, "default": {"access_token": "line-default", "channel_secret": "line-default-secret"}}}, "whatsapp": {"accounts": {"main": {"access_token": "wa-main", "phone_number_id": "100", "verify_token": "main-v"}, "default": {"access_token": "wa-default", "phone_number_id": "200", "verify_token": "default-v"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.line.len);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.whatsapp.len);
    try std.testing.expectEqualStrings("default", cfg.channels.line[0].account_id);
    try std.testing.expectEqualStrings("line-default", cfg.channels.line[0].access_token);
    try std.testing.expectEqualStrings("main", cfg.channels.line[1].account_id);
    try std.testing.expectEqualStrings("default", cfg.channels.whatsapp[0].account_id);
    try std.testing.expectEqualStrings("wa-default", cfg.channels.whatsapp[0].access_token);
    try std.testing.expectEqualStrings("main", cfg.channels.whatsapp[1].account_id);
}

test "multi-account channels without default keep sorted order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"channels": {"lark": {"accounts": {"backup": {"app_id": "app-b", "app_secret": "sec-b"}, "main": {"app_id": "app-main", "app_secret": "sec-main"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.lark.len);
    try std.testing.expectEqualStrings("backup", cfg.channels.lark[0].account_id);
    try std.testing.expectEqualStrings("app-b", cfg.channels.lark[0].app_id);
    try std.testing.expectEqualStrings("main", cfg.channels.lark[1].account_id);
    try std.testing.expectEqualStrings("app-main", cfg.channels.lark[1].app_id);
}

test "parse imessage config" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"imessage": {"enabled": true, "allow_from": ["user@icloud.com"]}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.imessage.len);
    const ic = cfg.channels.imessage[0];
    try std.testing.expectEqualStrings("default", ic.account_id);
    try std.testing.expect(ic.enabled);
    try std.testing.expectEqual(@as(usize, 1), ic.allow_from.len);
    for (ic.allow_from) |u| allocator.free(u);
    allocator.free(ic.allow_from);
    allocator.free(cfg.channels.imessage);
}

test "parse imessage multi-account and preferred primary" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"imessage": {"accounts": {"main": {"enabled": true}, "default": {"enabled": false}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.imessage.len);

    const primary = cfg.channels.imessagePrimary();
    try std.testing.expect(primary != null);
    try std.testing.expectEqualStrings("default", primary.?.account_id);
    try std.testing.expect(!primary.?.enabled);

    for (cfg.channels.imessage) |acc| allocator.free(acc.account_id);
    allocator.free(cfg.channels.imessage);
}

test "json parse reasoning_effort" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "high"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("high", cfg.reasoning_effort.?);
    allocator.free(cfg.reasoning_effort.?);
}

test "json parse invalid reasoning_effort ignored" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "invalid"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.reasoning_effort == null);
}

test "json parse reasoning_effort medium" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "medium"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("medium", cfg.reasoning_effort.?);
    allocator.free(cfg.reasoning_effort.?);
}

test "json parse reasoning_effort low" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "low"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("low", cfg.reasoning_effort.?);
    allocator.free(cfg.reasoning_effort.?);
}

test "unknown openclaw fields silently ignored" {
    const allocator = std.testing.allocator;
    const json =
        \\{"models": {"bedrock_discovery": true, "providers": {}}, "tts": {"enabled": true}, "session": {}, "ui": {}, "skills": []}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    // Should not crash — unknown fields are silently ignored
    try std.testing.expectEqual(@as(usize, 0), cfg.providers.len);
}

// ═══════════════════════════════════════════════════════════════════════════
// Parity tests: multi-account config, account list helpers, session config
// ═══════════════════════════════════════════════════════════════════════════

test "multi-account: empty accounts object returns empty slice" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 0), cfg.channels.telegram.len);
}

test "multi-account: missing accounts key returns empty slice" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 0), cfg.channels.telegram.len);
}

test "multi-account: missing channel config returns empty slice" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 0), cfg.channels.telegram.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.channels.discord.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.channels.slack.len);
}

test "multi-account: sorted alphabetically across channels" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"discord": {"accounts": {"z-server": {"token": "zt"}, "a-server": {"token": "at"}, "m-server": {"token": "mt"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.channels.discord.len);
    try std.testing.expectEqualStrings("a-server", cfg.channels.discord[0].account_id);
    try std.testing.expectEqualStrings("m-server", cfg.channels.discord[1].account_id);
    try std.testing.expectEqualStrings("z-server", cfg.channels.discord[2].account_id);
    for (cfg.channels.discord) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.token);
    }
    allocator.free(cfg.channels.discord);
}

test "multi-account: telegram primary falls back to first account when no default/main exists" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"alpha": {"bot_token": "a-tok"}, "beta": {"bot_token": "b-tok"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    const primary = cfg.channels.telegramPrimary();
    try std.testing.expect(primary != null);
    try std.testing.expectEqualStrings("alpha", primary.?.account_id);
    for (cfg.channels.telegram) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.telegram);
}

test "multi-account: primary prefers default then main account ids" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"zeta": {"bot_token": "z-tok"}, "default": {"bot_token": "d-tok"}, "main": {"bot_token": "m-tok"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    const primary = cfg.channels.telegramPrimary();
    try std.testing.expect(primary != null);
    try std.testing.expectEqualStrings("default", primary.?.account_id);
    try std.testing.expectEqualStrings("d-tok", primary.?.bot_token);

    for (cfg.channels.telegram) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.telegram);
}

test "multi-account: primary returns null for empty slice" {
    const cfg_ch = config_types.ChannelsConfig{};
    try std.testing.expect(cfg_ch.telegramPrimary() == null);
    try std.testing.expect(cfg_ch.discordPrimary() == null);
    try std.testing.expect(cfg_ch.slackPrimary() == null);
    try std.testing.expect(cfg_ch.signalPrimary() == null);
    try std.testing.expect(cfg_ch.imessagePrimary() == null);
    try std.testing.expect(cfg_ch.mattermostPrimary() == null);
    try std.testing.expect(cfg_ch.qqPrimary() == null);
    try std.testing.expect(cfg_ch.onebotPrimary() == null);
    try std.testing.expect(cfg_ch.maixcamPrimary() == null);
}

test "multi-account: account config overrides base fields" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"work": {"bot_token": "work-tok", "reply_in_private": true}, "personal": {"bot_token": "pers-tok"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.telegram.len);
    // personal < work alphabetically
    try std.testing.expectEqualStrings("personal", cfg.channels.telegram[0].account_id);
    try std.testing.expectEqualStrings("pers-tok", cfg.channels.telegram[0].bot_token);
    try std.testing.expect(cfg.channels.telegram[0].reply_in_private); // default is true
    try std.testing.expectEqualStrings("work", cfg.channels.telegram[1].account_id);
    try std.testing.expectEqualStrings("work-tok", cfg.channels.telegram[1].bot_token);
    try std.testing.expect(cfg.channels.telegram[1].reply_in_private);
    for (cfg.channels.telegram) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.telegram);
}

test "multi-account: multiple channels configured simultaneously" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"main": {"bot_token": "tg-tok"}}}, "discord": {"accounts": {"main": {"token": "dc-tok"}}}, "slack": {"accounts": {"main": {"bot_token": "sl-tok"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.telegram.len > 0);
    try std.testing.expect(cfg.channels.discord.len > 0);
    try std.testing.expect(cfg.channels.slack.len > 0);
    try std.testing.expectEqualStrings("tg-tok", cfg.channels.telegram[0].bot_token);
    try std.testing.expectEqualStrings("dc-tok", cfg.channels.discord[0].token);
    try std.testing.expectEqualStrings("sl-tok", cfg.channels.slack[0].bot_token);
    for (cfg.channels.telegram) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.telegram);
    for (cfg.channels.discord) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.token);
    }
    allocator.free(cfg.channels.discord);
    for (cfg.channels.slack) |acc| {
        allocator.free(acc.account_id);
        allocator.free(acc.bot_token);
    }
    allocator.free(cfg.channels.slack);
}

test "session config: parse dm_scope with dash format" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"dm_scope": "per-peer"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DmScope.per_peer, cfg.session.dm_scope);
}

test "session config: parse dm_scope with underscore format" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"dm_scope": "per_peer"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DmScope.per_peer, cfg.session.dm_scope);
}

test "session config: parse per-account-channel-peer scope" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"dm_scope": "per-account-channel-peer"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DmScope.per_account_channel_peer, cfg.session.dm_scope);
}

test "session config: default dm_scope is per_channel_peer" {
    const allocator = std.testing.allocator;
    const json =
        \\{}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DmScope.per_channel_peer, cfg.session.dm_scope);
}

test "session config: parse idle_minutes" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"idle_minutes": 30}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(u32, 30), cfg.session.idle_minutes);
}

test "session config: ignores idleMinutes camelCase alias" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"idleMinutes": 45}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(u32, 60), cfg.session.idle_minutes);
}

test "session config: parse identity_links map format" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"identity_links": {"alice": ["telegram:111", "discord:222"]}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.session.identity_links.len);
    try std.testing.expectEqualStrings("alice", cfg.session.identity_links[0].canonical);
    try std.testing.expectEqual(@as(usize, 2), cfg.session.identity_links[0].peers.len);
    allocator.free(cfg.session.identity_links[0].canonical);
    for (cfg.session.identity_links[0].peers) |p| allocator.free(p);
    allocator.free(cfg.session.identity_links[0].peers);
    allocator.free(cfg.session.identity_links);
}

test "session config: parse identity_links array format" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"identity_links": [{"canonical": "bob", "peers": ["slack:999"]}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.session.identity_links.len);
    try std.testing.expectEqualStrings("bob", cfg.session.identity_links[0].canonical);
    try std.testing.expectEqual(@as(usize, 1), cfg.session.identity_links[0].peers.len);
    try std.testing.expectEqualStrings("slack:999", cfg.session.identity_links[0].peers[0]);
    allocator.free(cfg.session.identity_links[0].canonical);
    for (cfg.session.identity_links[0].peers) |p| allocator.free(p);
    allocator.free(cfg.session.identity_links[0].peers);
    allocator.free(cfg.session.identity_links);
}

test "session config: empty session block uses defaults" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DmScope.per_channel_peer, cfg.session.dm_scope);
    try std.testing.expectEqual(@as(u32, 60), cfg.session.idle_minutes);
    try std.testing.expectEqual(@as(usize, 0), cfg.session.identity_links.len);
}

test "session config: all dm_scope values accepted" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "main", config_types.DmScope.main },
        .{ "per-peer", config_types.DmScope.per_peer },
        .{ "per-channel-peer", config_types.DmScope.per_channel_peer },
        .{ "per-account-channel-peer", config_types.DmScope.per_account_channel_peer },
        .{ "per_peer", config_types.DmScope.per_peer },
        .{ "per_channel_peer", config_types.DmScope.per_channel_peer },
        .{ "per_account_channel_peer", config_types.DmScope.per_account_channel_peer },
    };
    inline for (cases) |c| {
        const json = "{\"session\": {\"dm_scope\": \"" ++ c[0] ++ "\"}}";
        var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
        try cfg.parseJson(json);
        try std.testing.expectEqual(c[1], cfg.session.dm_scope);
    }
}
