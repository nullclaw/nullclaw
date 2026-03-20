const std = @import("std");
const platform = @import("platform.zig");
const provider_names = @import("provider_names.zig");
const secrets = @import("security/secrets.zig");
pub const config_types = @import("config_types.zig");
pub const config_parse = @import("config_parse.zig");
/// Write a JSON-escaped string (with enclosing quotes) to any writer.
/// Mirrors json_util.appendJsonString but works with writer-based output.
fn writeJsonStr(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    var esc: [6]u8 = undefined;
                    const escape = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch unreachable;
                    try w.writeAll(escape);
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeByte('"');
}

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
pub const ToolFilterGroup = config_types.ToolFilterGroup;
pub const ToolFilterGroupMode = config_types.ToolFilterGroupMode;
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
pub const MaxConfig = config_types.MaxConfig;
pub const MattermostConfig = config_types.MattermostConfig;
pub const WhatsAppConfig = config_types.WhatsAppConfig;
pub const ExternalChannelConfig = config_types.ExternalChannelConfig;
pub const IrcConfig = config_types.IrcConfig;
pub const LarkReceiveMode = config_types.LarkReceiveMode;
pub const LarkConfig = config_types.LarkConfig;
pub const DingTalkConfig = config_types.DingTalkConfig;
pub const SignalConfig = config_types.SignalConfig;
pub const EmailConfig = config_types.EmailConfig;
pub const LineConfig = config_types.LineConfig;
pub const QQGroupPolicy = config_types.QQGroupPolicy;
pub const QQReceiveMode = config_types.QQReceiveMode;
pub const QQConfig = config_types.QQConfig;
pub const OneBotConfig = config_types.OneBotConfig;
pub const MaixCamConfig = config_types.MaixCamConfig;
pub const WebConfig = config_types.WebConfig;
pub const ChannelsConfig = config_types.ChannelsConfig;
pub const MemoryConfig = config_types.MemoryConfig;
pub const TunnelConfig = config_types.TunnelConfig;
pub const GatewayConfig = config_types.GatewayConfig;
pub const A2aConfig = config_types.A2aConfig;
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
pub const NostrConfig = config_types.NostrConfig;

const SerializedNamedAgentConfig = struct {
    name: []const u8,
    provider: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8 = null,
    workspace_path: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
    temperature: ?f64 = null,
    max_depth: u32 = 3,
};

const SerializedModelRouteConfig = struct {
    hint: []const u8,
    provider: []const u8,
    model: []const u8,
    api_key: ?[]const u8 = null,
    cost_class: config_types.ModelRouteCostClass = .standard,
    quota_class: config_types.ModelRouteQuotaClass = .normal,
};

fn freeNamedAgentSlice(allocator: std.mem.Allocator, agents: []const NamedAgentConfig) void {
    for (agents) |agent_cfg| {
        allocator.free(agent_cfg.name);
        allocator.free(agent_cfg.provider);
        allocator.free(agent_cfg.model);
        if (agent_cfg.system_prompt) |system_prompt| allocator.free(system_prompt);
        if (agent_cfg.system_prompt_path) |system_prompt_path| allocator.free(system_prompt_path);
        if (agent_cfg.workspace_path) |workspace_path| allocator.free(workspace_path);
        if (agent_cfg.api_key) |api_key| allocator.free(api_key);
    }
    allocator.free(agents);
}

// ── Top-level Config ────────────────────────────────────────────

pub const Config = struct {
    // Computed paths (not serialized)
    workspace_dir: []const u8,
    config_path: []const u8,

    // Top-level fields
    workspace_dir_override: ?[]const u8 = null, // User-specified workspace path (if set, overrides default)
    providers: []const ProviderEntry = &.{},
    audio_media: AudioMediaConfig = .{},
    default_provider: []const u8 = "openrouter",
    default_model: ?[]const u8 = null,
    legacy_default_provider_detected: bool = false,
    legacy_default_model_detected: bool = false,
    default_temperature: f64 = 0.7,
    reasoning_effort: ?[]const u8 = null,

    // Model routing and delegate agents
    model_routes: []const ModelRouteConfig = &.{},
    agents: []const NamedAgentConfig = &.{},
    agent_bindings: []const @import("agent_routing.zig").AgentBinding = &.{},
    /// Runtime-only flag used by live `/bind` updates.
    agent_bindings_runtime_owned: bool = false,
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
    a2a: A2aConfig = .{},
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
    memory_backend: []const u8 = config_types.MemoryConfig.DEFAULT_MEMORY_BACKEND,
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
            if (provider_names.providerNamesMatch(e.name, name)) return e.api_key;
        }
        return null;
    }

    /// Convenience: API key for the default_provider.
    pub fn defaultProviderKey(self: *const Config) ?[]const u8 {
        return self.getProviderKey(self.default_provider);
    }

    fn sanitizeStatePathSegment(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        for (trimmed) |ch| {
            if (std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.') {
                try buf.append(allocator, ch);
            } else {
                try buf.append(allocator, '_');
            }
        }
        if (buf.items.len == 0) {
            try buf.appendSlice(allocator, "default");
        }
        return buf.toOwnedSlice(allocator);
    }

    fn backfillExternalChannelStateDirs(self: *Config) !void {
        const config_dir = std.fs.path.dirname(self.config_path) orelse ".";
        const external_mut = @constCast(self.channels.external);
        for (external_mut) |*external_cfg| {
            const runtime_segment = try sanitizeStatePathSegment(self.allocator, external_cfg.runtime_name);
            defer self.allocator.free(runtime_segment);
            const account_segment = try sanitizeStatePathSegment(self.allocator, external_cfg.account_id);
            defer self.allocator.free(account_segment);

            external_cfg.state_dir = try std.fs.path.join(self.allocator, &.{
                config_dir,
                "state",
                "external",
                runtime_segment,
                account_segment,
            });
        }
    }

    pub fn backfillRuntimeDerivedFields(self: *Config) !void {
        if (self.channels.nostr) |ns| {
            ns.config_dir = std.fs.path.dirname(self.config_path) orelse ".";
        }

        {
            const dir = std.fs.path.dirname(self.config_path) orelse ".";
            const teams_mut = @constCast(self.channels.teams);
            for (teams_mut) |*tc| {
                tc.config_dir = dir;
            }
        }

        try self.backfillExternalChannelStateDirs();
    }

    /// Look up a provider's base_url from the providers list.
    pub fn getProviderBaseUrl(self: *const Config, name: []const u8) ?[]const u8 {
        for (self.providers) |e| {
            if (provider_names.providerNamesMatch(e.name, name)) return e.base_url;
        }
        return null;
    }

    /// Look up whether a provider supports native tool calls.
    /// Returns true (default) if provider is not in the list.
    pub fn getProviderNativeTools(self: *const Config, name: []const u8) bool {
        for (self.providers) |e| {
            if (provider_names.providerNamesMatch(e.name, name)) return e.native_tools;
        }
        return true;
    }

    fn isReservedRuntimeChannelName(runtime_name: []const u8) bool {
        inline for (std.meta.fields(config_types.ChannelsConfig)) |field| {
            if (std.mem.eql(u8, field.name, runtime_name)) return true;
        }
        return false;
    }

    fn externalRuntimeNameConflicts(self: *const Config, runtime_name: []const u8, current_index: usize) bool {
        if (isReservedRuntimeChannelName(runtime_name)) return true;
        for (self.channels.maixcam) |maixcam_cfg| {
            if (std.mem.eql(u8, maixcam_cfg.name, runtime_name)) return true;
        }
        for (self.channels.external, 0..) |external_cfg, index| {
            if (index == current_index) continue;
            if (std.mem.eql(u8, external_cfg.runtime_name, runtime_name)) return true;
        }
        return false;
    }

    fn isValidExternalPluginConfigJson(allocator: std.mem.Allocator, raw: []const u8) bool {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return false;
        defer parsed.deinit();
        return parsed.value == .object;
    }

    /// Look up the optional User-Agent for a provider.
    /// Returns null if provider is not in the list or has no user_agent set.
    pub fn getProviderUserAgent(self: *const Config, name: []const u8) ?[]const u8 {
        for (self.providers) |e| {
            if (provider_names.providerNamesMatch(e.name, name)) return e.user_agent;
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

        // NULLCLAW_HOME overrides the default config directory (~/.nullclaw/).
        const config_dir = std.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => blk: {
                const home = platform.getHomeDir(allocator) catch return error.NoHomeDir;
                break :blk try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
            },
            else => return err,
        };
        const config_path = try std.fs.path.join(allocator, &.{ config_dir, "config.json" });
        const default_workspace_dir = try std.fs.path.join(allocator, &.{ config_dir, "workspace" });

        var cfg = Config{
            .workspace_dir = default_workspace_dir, // temporarily set to default
            .config_path = config_path,
            .allocator = allocator,
            .arena = arena_ptr,
        };

        // Try to read existing config file
        if (std.fs.openFileAbsolute(config_path, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(allocator, 1024 * 64);
            cfg.parseJson(content) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    // Log parse errors so users can diagnose corrupted or
                    // invalid configuration files. We still fall back to
                    // defaults so the CLI remains usable, but the warning
                    // makes the problem visible during debugging.
                    std.debug.print("Warning: failed to parse config.json: {s}\n", .{@errorName(err)});
                },
            };
        } else |_| {
            // Config file doesn't exist yet — use defaults
        }

        // Use workspace_dir_override if set, otherwise use default
        if (cfg.workspace_dir_override != null) {
            cfg.workspace_dir = cfg.workspace_dir_override.?;
        }

        // Backfill runtime-derived fields not present in JSON
        try cfg.backfillRuntimeDerivedFields();

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

    fn writeChannelFieldSeparator(w: *std.Io.Writer, wrote_any: bool) !void {
        if (wrote_any) {
            try w.print(",\n", .{});
        }
    }

    fn secretStore(self: *const Config) secrets.SecretStore {
        const config_dir = std.fs.path.dirname(self.config_path) orelse ".";
        return secrets.SecretStore.init(config_dir, self.secrets.encrypt);
    }

    fn encryptConfigSecret(
        self: *const Config,
        store: *const secrets.SecretStore,
        value: ?[]const u8,
    ) !?[]u8 {
        const secret = value orelse return null;
        return try store.encryptSecret(self.allocator, secret);
    }

    fn encryptConfigSecretArray(
        self: *const Config,
        store: *const secrets.SecretStore,
        values: []const []const u8,
    ) ![][]const u8 {
        var encrypted = try self.allocator.alloc([]const u8, values.len);
        var count: usize = 0;
        errdefer {
            for (encrypted[0..count]) |value| self.allocator.free(value);
            self.allocator.free(encrypted);
        }

        for (values, 0..) |value, i| {
            encrypted[i] = try store.encryptSecret(self.allocator, value);
            count += 1;
        }
        return encrypted;
    }

    fn writeIndentedMultilineJson(w: *std.Io.Writer, json: []const u8, continuation_indent: []const u8) !void {
        var start: usize = 0;
        while (start < json.len) {
            const rel_nl = std.mem.indexOfScalar(u8, json[start..], '\n');
            if (rel_nl) |nl| {
                const end = start + nl;
                try w.writeAll(json[start..end]);
                try w.writeAll("\n");
                const next_start = end + 1;
                if (next_start < json.len) {
                    try w.writeAll(continuation_indent);
                }
                start = next_start;
            } else {
                try w.writeAll(json[start..]);
                break;
            }
        }
    }

    fn writePrettyJsonInline(allocator: std.mem.Allocator, w: *std.Io.Writer, value: anytype, continuation_indent: []const u8) !void {
        const pretty = try std.json.Stringify.valueAlloc(allocator, value, .{ .whitespace = .indent_2 });
        defer allocator.free(pretty);
        try writeIndentedMultilineJson(w, pretty, continuation_indent);
    }

    fn writeChannelAccounts(allocator: std.mem.Allocator, w: *std.Io.Writer, channel_name: []const u8, accounts: anytype) !void {
        try w.print("    \"{s}\": {{\n      \"accounts\": {{", .{channel_name});
        for (accounts, 0..) |account, i| {
            if (i == 0) {
                try w.print("\n", .{});
            } else {
                try w.print(",\n", .{});
            }
            const account_id = if (comptime @hasField(@TypeOf(account), "account_id"))
                account.account_id
            else
                "default";
            try w.print("        \"{s}\": ", .{account_id});
            try writePrettyJsonInline(allocator, w, account, "        ");
        }
        try w.print("\n      }}\n    }}", .{});
    }

    fn writeExternalTransport(self: *const Config, w: *std.Io.Writer, transport: ExternalChannelConfig.TransportConfig) !void {
        _ = self;
        try w.print("{{\"command\": {f}", .{std.json.fmt(transport.command, .{})});

        if (transport.args.len > 0) {
            try w.print(", \"args\": {f}", .{std.json.fmt(transport.args, .{})});
        }
        if (transport.env.len > 0) {
            try w.print(", \"env\": {{", .{});
            for (transport.env, 0..) |entry, index| {
                if (index > 0) try w.print(", ", .{});
                try w.print("{f}: {f}", .{
                    std.json.fmt(entry.key, .{}),
                    std.json.fmt(entry.value, .{}),
                });
            }
            try w.print("}}", .{});
        }
        if (transport.timeout_ms != 10_000) {
            try w.print(", \"timeout_ms\": {d}", .{transport.timeout_ms});
        }
        try w.print("}}", .{});
    }

    fn writeExternalChannelAccount(self: *const Config, w: *std.Io.Writer, account: ExternalChannelConfig) !void {
        try w.print("{{\"runtime_name\": {f}, \"transport\": ", .{
            std.json.fmt(account.runtime_name, .{}),
        });
        try self.writeExternalTransport(w, account.transport);

        try w.print(", \"config\": ", .{});
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, account.plugin_config_json, .{}) catch {
            try w.print("{f}", .{std.json.fmt(account.plugin_config_json, .{})});
            try w.print("}}", .{});
            return;
        };
        defer parsed.deinit();
        try writePrettyJsonInline(self.allocator, w, parsed.value, "");
        try w.print("}}", .{});
    }

    fn writeExternalChannelAccounts(self: *const Config, w: *std.Io.Writer, accounts: []const ExternalChannelConfig) !void {
        try w.print("    \"external\": {{\n      \"accounts\": {{", .{});
        for (accounts, 0..) |account, index| {
            if (index == 0) {
                try w.print("\n", .{});
            } else {
                try w.print(",\n", .{});
            }
            try w.print("        \"{s}\": ", .{account.account_id});
            try self.writeExternalChannelAccount(w, account);
        }
        try w.print("\n      }}\n    }}", .{});
    }

    fn writeChannelsSection(self: *const Config, w: *std.Io.Writer) !void {
        try w.print("  \"channels\": {{\n", .{});

        var wrote_any = false;
        if (!self.channels.cli) {
            try writeChannelFieldSeparator(w, wrote_any);
            try w.print("    \"cli\": false", .{});
            wrote_any = true;
        }

        inline for (std.meta.fields(ChannelsConfig)) |field| {
            if (comptime std.mem.eql(u8, field.name, "cli")) continue;
            if (comptime std.mem.eql(u8, field.name, "nostr")) continue;

            const channel_value = @field(self.channels, field.name);
            if (comptime std.mem.eql(u8, field.name, "external")) {
                if (channel_value.len > 0) {
                    try writeChannelFieldSeparator(w, wrote_any);
                    try self.writeExternalChannelAccounts(w, channel_value);
                    wrote_any = true;
                }
                continue;
            }
            switch (@typeInfo(field.type)) {
                .pointer => |ptr| {
                    if (ptr.size == .slice and channel_value.len > 0) {
                        try writeChannelFieldSeparator(w, wrote_any);
                        try writeChannelAccounts(self.allocator, w, field.name, channel_value);
                        wrote_any = true;
                    }
                },
                .optional => {
                    if (channel_value) |val| {
                        try writeChannelFieldSeparator(w, wrote_any);
                        try w.print("    \"{s}\": ", .{field.name});
                        try writePrettyJsonInline(self.allocator, w, val, "    ");
                        wrote_any = true;
                    }
                },
                else => {},
            }
        }

        if (self.channels.nostr) |ns| {
            try writeChannelFieldSeparator(w, wrote_any);
            try w.print("    \"nostr\": ", .{});
            try writeNostrChannel(w, ns.*);
            wrote_any = true;
        }

        if (wrote_any) {
            try w.print("\n  }},\n", .{});
        } else {
            try w.print("  }},\n", .{});
        }
    }

    fn writeNostrChannel(w: *std.Io.Writer, ns: NostrConfig) !void {
        try w.print("{{\n", .{});
        try w.print("      \"private_key\": ", .{});
        try writeJsonStr(w, ns.private_key);
        try w.print(",\n      \"owner_pubkey\": ", .{});
        try writeJsonStr(w, ns.owner_pubkey);
        try w.print(",\n      \"bot_pubkey\": ", .{});
        try writeJsonStr(w, ns.bot_pubkey);
        try w.print(",\n      \"relays\": ", .{});
        try writeStringArray(w, ns.relays);
        try w.print(",\n      \"dm_relays\": ", .{});
        try writeStringArray(w, ns.dm_relays);
        try w.print(",\n      \"dm_allowed_pubkeys\": ", .{});
        try writeStringArray(w, ns.dm_allowed_pubkeys);
        try w.print(",\n      \"display_name\": ", .{});
        try writeJsonStr(w, ns.display_name);
        try w.print(",\n      \"about\": ", .{});
        try writeJsonStr(w, ns.about);
        if (ns.display_pic) |dp| {
            try w.print(",\n      \"display_pic\": ", .{});
            try writeJsonStr(w, dp);
        }
        if (ns.lnurl) |lnurl| {
            try w.print(",\n      \"lnurl\": ", .{});
            try writeJsonStr(w, lnurl);
        }
        if (ns.nip05) |nip05| {
            try w.print(",\n      \"nip05\": ", .{});
            try writeJsonStr(w, nip05);
        }
        try w.print(",\n      \"nak_path\": ", .{});
        try writeJsonStr(w, ns.nak_path);
        if (ns.bunker_uri) |bu| {
            try w.print(",\n      \"bunker_uri\": ", .{});
            try writeJsonStr(w, bu);
        }
        try w.print("\n    }}", .{});
    }

    fn writeStringArray(w: *std.Io.Writer, values: []const []const u8) !void {
        try w.print("[", .{});
        for (values, 0..) |value, i| {
            if (i > 0) try w.print(", ", .{});
            try w.print("\"{s}\"", .{value});
        }
        try w.print("]", .{});
    }

    fn writeReliabilitySection(self: *const Config, w: *std.Io.Writer, store: *const secrets.SecretStore) !void {
        try w.print("  \"reliability\": {{\n", .{});
        try w.print("    \"provider_retries\": {d},\n", .{self.reliability.provider_retries});
        try w.print("    \"provider_backoff_ms\": {d},\n", .{self.reliability.provider_backoff_ms});
        try w.print("    \"channel_initial_backoff_secs\": {d},\n", .{self.reliability.channel_initial_backoff_secs});
        try w.print("    \"channel_max_backoff_secs\": {d},\n", .{self.reliability.channel_max_backoff_secs});
        try w.print("    \"scheduler_poll_secs\": {d},\n", .{self.reliability.scheduler_poll_secs});
        try w.print("    \"scheduler_retries\": {d},\n", .{self.reliability.scheduler_retries});

        try w.print("    \"fallback_providers\": ", .{});
        try writeStringArray(w, self.reliability.fallback_providers);
        try w.print(",\n", .{});

        try w.print("    \"api_keys\": ", .{});
        const encrypted_api_keys = try self.encryptConfigSecretArray(store, self.reliability.api_keys);
        defer {
            for (encrypted_api_keys) |value| self.allocator.free(value);
            self.allocator.free(encrypted_api_keys);
        }
        try writeStringArray(w, encrypted_api_keys);
        try w.print(",\n", .{});

        try w.print("    \"model_fallbacks\": [", .{});
        for (self.reliability.model_fallbacks, 0..) |entry, i| {
            if (i > 0) try w.print(", ", .{});
            try w.print("{{\"model\": \"{s}\", \"fallbacks\": ", .{entry.model});
            try writeStringArray(w, entry.fallbacks);
            try w.print("}}", .{});
        }
        try w.print("]\n", .{});
        try w.print("  }},\n", .{});
    }

    fn writeMcpServersSection(self: *const Config, w: *std.Io.Writer) !void {
        try w.print("  \"mcp_servers\": {{\n", .{});
        for (self.mcp_servers, 0..) |server, i| {
            try w.print("    {f}: {{", .{std.json.fmt(server.name, .{})});

            var wrote_field = false;
            if (!std.mem.eql(u8, server.transport, McpServerConfig.DEFAULT_TRANSPORT)) {
                try w.print("\"transport\": {f}", .{std.json.fmt(server.transport, .{})});
                wrote_field = true;
            }
            if (server.command.len > 0) {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"command\": {f}", .{std.json.fmt(server.command, .{})});
                wrote_field = true;
            }
            if (server.url) |url| {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"url\": {f}", .{std.json.fmt(url, .{})});
                wrote_field = true;
            }
            if (server.timeout_ms != 10_000) {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"timeout_ms\": {d}", .{server.timeout_ms});
                wrote_field = true;
            }
            if (server.args.len > 0) {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"args\": {f}", .{std.json.fmt(server.args, .{})});
                wrote_field = true;
            }
            if (server.env.len > 0) {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"env\": {{", .{});
                for (server.env, 0..) |entry, env_i| {
                    if (env_i > 0) try w.print(", ", .{});
                    try w.print("{f}: {f}", .{
                        std.json.fmt(entry.key, .{}),
                        std.json.fmt(entry.value, .{}),
                    });
                }
                try w.print("}}", .{});
                wrote_field = true;
            }
            if (server.headers.len > 0) {
                if (wrote_field) try w.print(", ", .{});
                try w.print("\"headers\": {{", .{});
                for (server.headers, 0..) |entry, hdr_i| {
                    if (hdr_i > 0) try w.print(", ", .{});
                    try w.print("{f}: {f}", .{
                        std.json.fmt(entry.key, .{}),
                        std.json.fmt(entry.value, .{}),
                    });
                }
                try w.print("}}", .{});
                wrote_field = true;
            }
            try w.print("}}", .{});
            if (i + 1 < self.mcp_servers.len) try w.print(",", .{});
            try w.print("\n", .{});
        }
        try w.print("  }},\n", .{});
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
        const store = self.secretStore();

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
        if (self.workspace_dir_override) |workspace| {
            // JSON-escape the workspace string so backslashes, quotes etc. are
            // handled correctly. Previously we just printed with "{s}" which
            // could produce invalid JSON when the path contained a backslash or
            // other special character. Use our helper to stringify any value
            // inline instead.
            try w.print("  \"workspace\": ", .{});
            try writePrettyJsonInline(self.allocator, w, workspace, "");
            try w.print(",\n", .{});
        }
        try w.print("  \"default_temperature\": {d:.1},\n", .{self.default_temperature});
        if (self.reasoning_effort) |value| {
            try w.print("  \"reasoning_effort\": \"{s}\",\n", .{value});
        }

        // models.providers
        if (self.providers.len > 0) {
            try w.print("  \"models\": {{\n    \"providers\": {{\n", .{});
            for (self.providers, 0..) |entry, i| {
                try w.print("      \"{s}\": {{", .{entry.name});
                var has_field = false;
                if (entry.api_key) |key| {
                    const encrypted_key = try self.encryptConfigSecret(&store, key);
                    defer if (encrypted_key) |value| self.allocator.free(value);
                    try w.print("\"api_key\": ", .{});
                    try writePrettyJsonInline(self.allocator, w, encrypted_key.?, "");
                    has_field = true;
                }
                if (entry.base_url) |base| {
                    if (has_field) try w.print(", ", .{});
                    try w.print("\"base_url\": ", .{});
                    try writePrettyJsonInline(self.allocator, w, base, "");
                    has_field = true;
                }
                if (comptime @hasField(ProviderEntry, "native_tools")) {
                    if (!entry.native_tools) {
                        if (has_field) try w.print(", ", .{});
                        try w.print("\"native_tools\": false", .{});
                        has_field = true;
                    }
                }
                if (comptime @hasField(ProviderEntry, "user_agent")) {
                    if (entry.user_agent) |ua| {
                        if (has_field) try w.print(", ", .{});
                        try w.print("\"user_agent\": ", .{});
                        try writePrettyJsonInline(self.allocator, w, ua, "");
                        has_field = true;
                    }
                }
                try w.print("}}", .{});
                if (i + 1 < self.providers.len) try w.print(",", .{});
                try w.print("\n", .{});
            }
            try w.print("    }}\n  }},\n", .{});
        }

        if (self.model_routes.len > 0) {
            const serialized_routes = try self.allocator.alloc(SerializedModelRouteConfig, self.model_routes.len);
            defer self.allocator.free(serialized_routes);
            var route_count: usize = 0;
            errdefer {
                for (serialized_routes[0..route_count]) |route| {
                    if (route.api_key) |value| self.allocator.free(value);
                }
            }
            for (self.model_routes, 0..) |route, i| {
                const encrypted_key = try self.encryptConfigSecret(&store, route.api_key);
                serialized_routes[i] = .{
                    .hint = route.hint,
                    .provider = route.provider,
                    .model = route.model,
                    .api_key = encrypted_key,
                    .cost_class = route.cost_class,
                    .quota_class = route.quota_class,
                };
                route_count += 1;
            }
            defer {
                for (serialized_routes) |route| {
                    if (route.api_key) |value| self.allocator.free(value);
                }
            }
            try w.print("  \"model_routes\": {f},\n", .{std.json.fmt(serialized_routes, .{})});
        }

        // agents.defaults (model + heartbeat) + agents.list
        {
            const has_model = self.default_model != null;
            const has_heartbeat = self.heartbeat.enabled or self.heartbeat.interval_minutes != 30;
            const has_agents = self.agents.len > 0;
            if (has_model or has_heartbeat or has_agents) {
                try w.print("  \"agents\": {{\n", .{});
                var wrote_agent_field = false;
                if (has_model or has_heartbeat) {
                    try w.print("    \"defaults\": {{\n", .{});
                    wrote_agent_field = true;
                }
                if (self.default_model) |model| {
                    try w.print("      \"model\": {{\"primary\": \"{s}/{s}\"}}", .{ self.default_provider, model });
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
                if (has_model or has_heartbeat) {
                    try w.print("    }}", .{});
                }
                if (has_agents) {
                    const serialized_agents = try self.allocator.alloc(SerializedNamedAgentConfig, self.agents.len);
                    defer self.allocator.free(serialized_agents);
                    var agent_count: usize = 0;
                    errdefer {
                        for (serialized_agents[0..agent_count]) |agent_cfg| {
                            if (agent_cfg.api_key) |value| self.allocator.free(value);
                        }
                    }
                    for (self.agents, 0..) |agent_cfg, i| {
                        const encrypted_key = try self.encryptConfigSecret(&store, agent_cfg.api_key);
                        serialized_agents[i] = .{
                            .name = agent_cfg.name,
                            .provider = agent_cfg.provider,
                            .model = agent_cfg.model,
                            .system_prompt = agent_cfg.system_prompt_path orelse agent_cfg.system_prompt,
                            .workspace_path = agent_cfg.workspace_path,
                            .api_key = encrypted_key,
                            .temperature = agent_cfg.temperature,
                            .max_depth = agent_cfg.max_depth,
                        };
                        agent_count += 1;
                    }
                    defer {
                        for (serialized_agents) |agent_cfg| {
                            if (agent_cfg.api_key) |value| self.allocator.free(value);
                        }
                    }
                    if (wrote_agent_field) {
                        try w.print(",\n", .{});
                    }
                    try w.print("    \"list\": {f}\n", .{std.json.fmt(serialized_agents, .{})});
                } else {
                    try w.print("\n", .{});
                }
                try w.print("  }},\n", .{});
            }
        }

        if (self.agent_bindings.len > 0) {
            try w.print("  \"bindings\": {f},\n", .{std.json.fmt(self.agent_bindings, .{})});
        }
        if (self.mcp_servers.len > 0) {
            try self.writeMcpServersSection(w);
        }

        // Diagnostics (with nested otel)
        try w.print("  \"diagnostics\": {{\n", .{});
        try w.print("    \"backend\": \"{s}\"", .{self.diagnostics.backend});
        try w.print(",\n    \"log_tool_calls\": {s}", .{if (self.diagnostics.log_tool_calls) "true" else "false"});
        try w.print(",\n    \"log_message_receipts\": {s}", .{if (self.diagnostics.log_message_receipts) "true" else "false"});
        try w.print(",\n    \"log_message_payloads\": {s}", .{if (self.diagnostics.log_message_payloads) "true" else "false"});
        try w.print(",\n    \"log_llm_io\": {s}", .{if (self.diagnostics.log_llm_io) "true" else "false"});
        if (self.diagnostics.api_error_max_chars) |n| {
            try w.print(",\n    \"api_error_max_chars\": {d}", .{n});
        }
        try w.print(",\n    \"token_usage_ledger_enabled\": {s}", .{if (self.diagnostics.token_usage_ledger_enabled) "true" else "false"});
        try w.print(",\n    \"token_usage_ledger_window_hours\": {d}", .{self.diagnostics.token_usage_ledger_window_hours});
        try w.print(",\n    \"token_usage_ledger_max_bytes\": {d}", .{self.diagnostics.token_usage_ledger_max_bytes});
        try w.print(",\n    \"token_usage_ledger_max_lines\": {d}", .{self.diagnostics.token_usage_ledger_max_lines});
        if (self.diagnostics.otel_endpoint != null or self.diagnostics.otel_service_name != null or self.diagnostics.otel_headers.len > 0) {
            try w.print(",\n    \"otel\": {{", .{});
            var otel_first = true;
            if (self.diagnostics.otel_endpoint) |ep| {
                try w.print("\"endpoint\": \"{s}\"", .{ep});
                otel_first = false;
            }
            if (self.diagnostics.otel_service_name) |sn| {
                if (!otel_first) try w.print(", ", .{});
                try w.print("\"service_name\": \"{s}\"", .{sn});
                otel_first = false;
            }
            if (self.diagnostics.otel_headers.len > 0) {
                if (!otel_first) try w.print(", ", .{});
                try w.print("\"headers\": {{", .{});
                for (self.diagnostics.otel_headers, 0..) |header, i| {
                    if (i > 0) try w.print(", ", .{});
                    try writeJsonStr(w, header.key);
                    try w.print(": ", .{});
                    try writeJsonStr(w, header.value);
                }
                try w.print("}}", .{});
            }
            try w.print("}}", .{});
        }
        try w.print("\n  }},\n", .{});

        try w.print("  \"autonomy\": {f},\n", .{std.json.fmt(self.autonomy, .{})});
        try w.print("  \"runtime\": {f},\n", .{std.json.fmt(.{
            .kind = self.runtime.kind,
            .docker = .{
                .image = self.runtime.docker.image,
                .network = self.runtime.docker.network,
                .memory_limit_mb = self.runtime.docker.memory_limit_mb,
                .read_only_rootfs = self.runtime.docker.read_only_rootfs,
                .mount_workspace = self.runtime.docker.mount_workspace,
            },
        }, .{})});

        // Reliability
        try self.writeReliabilitySection(w, &store);
        try w.print("  \"scheduler\": {f},\n", .{std.json.fmt(self.scheduler, .{})});
        try w.print("  \"agent\": {f},\n", .{std.json.fmt(.{
            .compact_context = self.agent.compact_context,
            .max_tool_iterations = self.agent.max_tool_iterations,
            .max_history_messages = self.agent.max_history_messages,
            .parallel_tools = self.agent.parallel_tools,
            .tool_dispatcher = self.agent.tool_dispatcher,
            .session_idle_timeout_secs = self.agent.session_idle_timeout_secs,
            .compaction_keep_recent = self.agent.compaction_keep_recent,
            .compaction_max_summary_chars = self.agent.compaction_max_summary_chars,
            .compaction_max_source_chars = self.agent.compaction_max_source_chars,
            .status_show_emojis = self.agent.status_show_emojis,
            .message_timeout_secs = self.agent.message_timeout_secs,
            .vision_disabled_models = self.agent.vision_disabled_models,
            .auto_disable_vision_on_error = self.agent.auto_disable_vision_on_error,
        }, .{})});

        // Channels
        try self.writeChannelsSection(w);

        var serialized_memory = self.memory;
        if (serialized_memory.search.store.qdrant_api_key.len > 0) {
            serialized_memory.search.store.qdrant_api_key = try store.encryptSecret(self.allocator, serialized_memory.search.store.qdrant_api_key);
        }
        defer if (serialized_memory.search.store.qdrant_api_key.ptr != self.memory.search.store.qdrant_api_key.ptr) {
            self.allocator.free(serialized_memory.search.store.qdrant_api_key);
        };
        if (serialized_memory.api.api_key.len > 0) {
            serialized_memory.api.api_key = try store.encryptSecret(self.allocator, serialized_memory.api.api_key);
        }
        defer if (serialized_memory.api.api_key.ptr != self.memory.api.api_key.ptr) {
            self.allocator.free(serialized_memory.api.api_key);
        };
        try w.print("  \"memory\": {f},\n", .{std.json.fmt(serialized_memory, .{})});
        try w.print("  \"gateway\": {f},\n", .{std.json.fmt(self.gateway, .{})});
        try w.print("  \"a2a\": {f},\n", .{std.json.fmt(self.a2a, .{})});
        try w.print("  \"tunnel\": {f},\n", .{std.json.fmt(self.tunnel, .{})});
        var serialized_composio = self.composio;
        if (serialized_composio.api_key) |api_key| {
            serialized_composio.api_key = try store.encryptSecret(self.allocator, api_key);
        }
        defer if (serialized_composio.api_key) |api_key| {
            if (self.composio.api_key == null or api_key.ptr != self.composio.api_key.?.ptr) {
                self.allocator.free(api_key);
            }
        };
        try w.print("  \"composio\": {f},\n", .{std.json.fmt(serialized_composio, .{})});
        try w.print("  \"secrets\": {f},\n", .{std.json.fmt(self.secrets, .{})});
        try w.print("  \"browser\": {f},\n", .{std.json.fmt(.{
            .enabled = self.browser.enabled,
            .session_name = self.browser.session_name,
            .backend = self.browser.backend,
            .native_headless = self.browser.native_headless,
            .native_webdriver_url = self.browser.native_webdriver_url,
            .native_chrome_path = self.browser.native_chrome_path,
            .allowed_domains = self.browser.allowed_domains,
        }, .{})});
        try w.print("  \"http_request\": {f},\n", .{std.json.fmt(.{
            .enabled = self.http_request.enabled,
            .max_response_size = self.http_request.max_response_size,
            .timeout_secs = self.http_request.timeout_secs,
            .allowed_domains = self.http_request.allowed_domains,
            .proxy = self.http_request.proxy,
            .search_base_url = self.http_request.search_base_url,
            .search_provider = self.http_request.search_provider,
            .search_fallback_providers = self.http_request.search_fallback_providers,
        }, .{})});
        try w.print("  \"identity\": {f},\n", .{std.json.fmt(self.identity, .{})});
        try w.print("  \"cost\": {f},\n", .{std.json.fmt(self.cost, .{})});
        try w.print("  \"security\": {f},\n", .{std.json.fmt(.{
            .sandbox = .{
                .enabled = self.security.sandbox.enabled,
                .backend = self.security.sandbox.backend,
            },
            .resources = .{
                .max_memory_mb = self.security.resources.max_memory_mb,
                .max_cpu_time_seconds = self.security.resources.max_cpu_time_seconds,
                .max_subprocesses = self.security.resources.max_subprocesses,
                .memory_monitoring = self.security.resources.memory_monitoring,
            },
            .audit = .{
                .enabled = self.security.audit.enabled,
                .log_path = self.security.audit.log_path,
                .max_size_mb = self.security.audit.max_size_mb,
                .sign_events = self.security.audit.sign_events,
            },
        }, .{})});
        try w.print("  \"peripherals\": {f},\n", .{std.json.fmt(.{
            .enabled = self.peripherals.enabled,
            .datasheet_dir = self.peripherals.datasheet_dir,
        }, .{})});

        // Tools (with media.audio)
        try w.print("  \"tools\": {{\n", .{});
        try w.print("    \"shell_timeout_secs\": {d},\n", .{self.tools.shell_timeout_secs});
        try w.print("    \"shell_max_output_bytes\": {d},\n", .{self.tools.shell_max_output_bytes});
        try w.print("    \"max_file_size_bytes\": {d},\n", .{self.tools.max_file_size_bytes});
        try w.print("    \"web_fetch_max_chars\": {d},\n", .{self.tools.web_fetch_max_chars});
        try w.print("    \"path_env_vars\": {f}", .{std.json.fmt(self.tools.path_env_vars, .{})});
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

        try w.print("  \"hardware\": {f},\n", .{std.json.fmt(self.hardware, .{})});
        try w.print("  \"session\": {f}\n", .{std.json.fmt(self.session, .{})});

        try w.print("}}\n", .{});
        try w.flush();
    }

    // ── Validation ──────────────────────────────────────────────

    pub const ValidationError = error{
        LegacyDefaultProviderField,
        LegacyDefaultModelField,
        InvalidDefaultModelPrimary,
        NoDefaultModel,
        TemperatureOutOfRange,
        InvalidPort,
        InvalidRetryCount,
        InvalidBackoffMs,
        InvalidHttpProxyUrl,
        InvalidApiErrorMaxChars,
        InvalidHttpSearchBaseUrl,
        InvalidHttpSearchProvider,
        InvalidHttpSearchFallbackProvider,
        InvalidMcpTransport,
        MissingMcpCommand,
        MissingMcpHttpUrl,
        InvalidMcpHttpUrl,
        InvalidMcpHeader,
        InvalidMcpTimeoutMs,
        InvalidExternalRuntimeName,
        ConflictingExternalRuntimeName,
        MissingExternalTransportCommand,
        InvalidExternalTransportTimeoutMs,
        InvalidExternalPluginConfig,
        InvalidWebTransport,
        InvalidWebPath,
        InvalidWebAuthToken,
        InvalidWebMessageAuthMode,
        InvalidWebMessageAuthTransport,
        InvalidWebOrigin,
        MissingWebRelayUrl,
        InvalidWebRelayUrl,
        InvalidWebRelayAgentId,
        InvalidWebRelayPairingCodeTtl,
        InvalidWebRelayUiTokenTtl,
        InvalidWebRelayTokenTtl,
        InsecurePlaintextSecrets,
    };

    pub fn validate(self: *const Config) ValidationError!void {
        if (self.legacy_default_provider_detected) {
            return ValidationError.LegacyDefaultProviderField;
        }
        if (self.legacy_default_model_detected) {
            return ValidationError.LegacyDefaultModelField;
        }
        if (self.default_provider.len == 0) {
            return ValidationError.InvalidDefaultModelPrimary;
        }
        if (self.default_model == null) {
            return ValidationError.NoDefaultModel;
        }
        if (self.default_temperature < 0.0 or self.default_temperature > 2.0) {
            return ValidationError.TemperatureOutOfRange;
        }
        if (self.gateway.port == 0) {
            return ValidationError.InvalidPort;
        }
        if (!self.secrets.encrypt) {
            return ValidationError.InsecurePlaintextSecrets;
        }
        if (self.reliability.provider_retries > 100) {
            return ValidationError.InvalidRetryCount;
        }
        if (self.reliability.provider_backoff_ms > 600_000) {
            return ValidationError.InvalidBackoffMs;
        }
        if (self.http_request.proxy) |proxy_url| {
            if (!config_types.HttpRequestConfig.isValidProxyUrl(proxy_url)) {
                return ValidationError.InvalidHttpProxyUrl;
            }
        }
        if (self.diagnostics.api_error_max_chars) |n| {
            if (n < 200 or n > 10_000) {
                return ValidationError.InvalidApiErrorMaxChars;
            }
        }
        if (self.http_request.search_base_url) |search_base_url| {
            if (!config_types.HttpRequestConfig.isValidSearchBaseUrl(search_base_url)) {
                return ValidationError.InvalidHttpSearchBaseUrl;
            }
        }
        if (!config_types.HttpRequestConfig.isValidSearchProviderName(self.http_request.search_provider)) {
            return ValidationError.InvalidHttpSearchProvider;
        }
        for (self.http_request.search_fallback_providers) |provider| {
            if (!config_types.HttpRequestConfig.isValidSearchFallbackProviderName(provider)) {
                return ValidationError.InvalidHttpSearchFallbackProvider;
            }
        }
        for (self.mcp_servers) |mcp_cfg| {
            if (!config_types.McpServerConfig.isValidTransport(mcp_cfg.transport)) {
                return ValidationError.InvalidMcpTransport;
            }
            if (config_types.McpServerConfig.isHttpTransport(mcp_cfg.transport)) {
                const mcp_url = mcp_cfg.url orelse return ValidationError.MissingMcpHttpUrl;
                if (!config_types.McpServerConfig.isValidHttpUrl(mcp_url)) {
                    return ValidationError.InvalidMcpHttpUrl;
                }
                if (mcp_cfg.timeout_ms == 0 or mcp_cfg.timeout_ms > 600_000) {
                    return ValidationError.InvalidMcpTimeoutMs;
                }
                for (mcp_cfg.headers) |entry| {
                    if (!config_types.McpServerConfig.isValidHeaderName(entry.key) or
                        !config_types.McpServerConfig.isValidHeaderValue(entry.value))
                    {
                        return ValidationError.InvalidMcpHeader;
                    }
                }
            } else {
                if (std.mem.trim(u8, mcp_cfg.command, " \t\r\n").len == 0) {
                    return ValidationError.MissingMcpCommand;
                }
            }
        }
        for (self.channels.external, 0..) |external_cfg, index| {
            if (!config_types.ExternalChannelConfig.isValidRuntimeName(external_cfg.runtime_name)) {
                return ValidationError.InvalidExternalRuntimeName;
            }
            if (self.externalRuntimeNameConflicts(external_cfg.runtime_name, index)) {
                return ValidationError.ConflictingExternalRuntimeName;
            }
            if (!config_types.ExternalChannelConfig.hasCommand(external_cfg.transport.command)) {
                return ValidationError.MissingExternalTransportCommand;
            }
            if (!config_types.ExternalChannelConfig.isValidTimeoutMs(external_cfg.transport.timeout_ms)) {
                return ValidationError.InvalidExternalTransportTimeoutMs;
            }
            if (!isValidExternalPluginConfigJson(self.allocator, external_cfg.plugin_config_json)) {
                return ValidationError.InvalidExternalPluginConfig;
            }
        }
        for (self.channels.web) |web_cfg| {
            if (!config_types.WebConfig.isValidTransport(web_cfg.transport)) {
                return ValidationError.InvalidWebTransport;
            }
            const relay_transport = config_types.WebConfig.isRelayTransport(web_cfg.transport);
            if (!relay_transport and !config_types.WebConfig.isPathWellFormed(web_cfg.path)) {
                return ValidationError.InvalidWebPath;
            }
            if (web_cfg.auth_token) |token| {
                if (!config_types.WebConfig.isValidAuthToken(token)) {
                    return ValidationError.InvalidWebAuthToken;
                }
            }
            if (web_cfg.relay_token) |token| {
                if (!config_types.WebConfig.isValidAuthToken(token)) {
                    return ValidationError.InvalidWebAuthToken;
                }
            }
            if (!config_types.WebConfig.isValidMessageAuthMode(web_cfg.message_auth_mode)) {
                return ValidationError.InvalidWebMessageAuthMode;
            }
            if (relay_transport and config_types.WebConfig.isTokenMessageAuthMode(web_cfg.message_auth_mode)) {
                return ValidationError.InvalidWebMessageAuthTransport;
            }
            if (relay_transport) {
                const relay_url = web_cfg.relay_url orelse return ValidationError.MissingWebRelayUrl;
                if (!config_types.WebConfig.isValidRelayUrl(relay_url)) {
                    return ValidationError.InvalidWebRelayUrl;
                }
                if (!config_types.WebConfig.isValidRelayAgentId(web_cfg.relay_agent_id)) {
                    return ValidationError.InvalidWebRelayAgentId;
                }
                if (!config_types.WebConfig.isValidRelayPairingCodeTtl(web_cfg.relay_pairing_code_ttl_secs)) {
                    return ValidationError.InvalidWebRelayPairingCodeTtl;
                }
                if (!config_types.WebConfig.isValidRelayUiTokenTtl(web_cfg.relay_ui_token_ttl_secs)) {
                    return ValidationError.InvalidWebRelayUiTokenTtl;
                }
                if (!config_types.WebConfig.isValidRelayTokenTtl(web_cfg.relay_token_ttl_secs)) {
                    return ValidationError.InvalidWebRelayTokenTtl;
                }
            } else {
                for (web_cfg.allowed_origins) |origin| {
                    if (!config_types.WebConfig.isValidAllowedOrigin(origin)) {
                        return ValidationError.InvalidWebOrigin;
                    }
                }
            }
        }
    }

    /// Print a human-readable validation error to stderr.
    pub fn printValidationError(err: ValidationError) void {
        switch (err) {
            ValidationError.LegacyDefaultProviderField => std.debug.print(
                "Config error: top-level default_provider is not supported. Set agents.defaults.model.primary instead.\n",
                .{},
            ),
            ValidationError.LegacyDefaultModelField => std.debug.print(
                "Config error: top-level default_model is not supported. Set agents.defaults.model.primary instead.\n",
                .{},
            ),
            ValidationError.InvalidDefaultModelPrimary => std.debug.print(
                "Config error: agents.defaults.model.primary must be in \"provider/model\" format.\n",
                .{},
            ),
            ValidationError.NoDefaultModel => std.debug.print(
                "No default model configured. Set agents.defaults.model.primary in ~/.nullclaw/config.json or run `nullclaw onboard`.\n",
                .{},
            ),
            ValidationError.TemperatureOutOfRange => std.debug.print("Config error: temperature must be between 0.0 and 2.0.\n", .{}),
            ValidationError.InvalidPort => std.debug.print("Config error: gateway port must be non-zero.\n", .{}),
            ValidationError.InsecurePlaintextSecrets => std.debug.print("Config error: secrets.encrypt=false is not allowed because it stores secrets in plaintext.\n", .{}),
            ValidationError.InvalidRetryCount => std.debug.print("Config error: provider_retries must be <= 100.\n", .{}),
            ValidationError.InvalidBackoffMs => std.debug.print("Config error: provider_backoff_ms must be <= 600000.\n", .{}),
            ValidationError.InvalidHttpProxyUrl => std.debug.print("Config error: http_request.proxy must be a non-empty http://, https://, or socks5:// URL.\n", .{}),
            ValidationError.InvalidApiErrorMaxChars => std.debug.print("Config error: diagnostics.api_error_max_chars must be in [200, 10000].\n", .{}),
            ValidationError.InvalidHttpSearchBaseUrl => std.debug.print("Config error: http_request.search_base_url must be https://host[/search] or local http://host[:port][/search] (no query/fragment).\n", .{}),
            ValidationError.InvalidHttpSearchProvider => std.debug.print("Config error: http_request.search_provider must be one of: auto, searxng, duckduckgo(ddg), brave, firecrawl, tavily, perplexity, exa, jina.\n", .{}),
            ValidationError.InvalidHttpSearchFallbackProvider => std.debug.print("Config error: http_request.search_fallback_providers entries must be valid providers and cannot be 'auto'.\n", .{}),
            ValidationError.InvalidMcpTransport => std.debug.print("Config error: mcp_servers.<name>.transport must be 'stdio' or 'http'.\n", .{}),
            ValidationError.MissingMcpCommand => std.debug.print("Config error: mcp_servers.<name>.command is required when transport='stdio'.\n", .{}),
            ValidationError.MissingMcpHttpUrl => std.debug.print("Config error: mcp_servers.<name>.url is required when transport='http'.\n", .{}),
            ValidationError.InvalidMcpHttpUrl => std.debug.print("Config error: mcp_servers.<name>.url must be an absolute https:// URL.\n", .{}),
            ValidationError.InvalidMcpHeader => std.debug.print("Config error: mcp_servers.<name>.headers must contain valid HTTP header names/values (no CR/LF).\n", .{}),
            ValidationError.InvalidMcpTimeoutMs => std.debug.print("Config error: mcp_servers.<name>.timeout_ms must be in [1, 600000].\n", .{}),
            ValidationError.InvalidExternalRuntimeName => std.debug.print("Config error: channels.external.accounts.<id>.runtime_name must be non-empty and contain only letters, digits, '_', '-', or '.'.\n", .{}),
            ValidationError.ConflictingExternalRuntimeName => std.debug.print("Config error: channels.external.accounts.<id>.runtime_name must not reuse a built-in or already-configured runtime channel name.\n", .{}),
            ValidationError.MissingExternalTransportCommand => std.debug.print("Config error: channels.external.accounts.<id>.transport.command is required.\n", .{}),
            ValidationError.InvalidExternalTransportTimeoutMs => std.debug.print("Config error: channels.external.accounts.<id>.transport.timeout_ms must be in [1, 600000].\n", .{}),
            ValidationError.InvalidExternalPluginConfig => std.debug.print("Config error: channels.external.accounts.<id>.config must be a JSON object.\n", .{}),
            ValidationError.InvalidWebTransport => std.debug.print("Config error: channels.web.accounts.<id>.transport must be 'local' or 'relay'.\n", .{}),
            ValidationError.InvalidWebPath => std.debug.print("Config error: channels.web.accounts.<id>.path must start with '/'.\n", .{}),
            ValidationError.InvalidWebAuthToken => std.debug.print("Config error: channels.web.accounts.<id>.auth_token/relay_token must be 16-128 printable chars without whitespace.\n", .{}),
            ValidationError.InvalidWebMessageAuthMode => std.debug.print("Config error: channels.web.accounts.<id>.message_auth_mode must be 'pairing' or 'token'.\n", .{}),
            ValidationError.InvalidWebMessageAuthTransport => std.debug.print("Config error: channels.web.accounts.<id>.message_auth_mode='token' is supported only when transport='local'.\n", .{}),
            ValidationError.InvalidWebOrigin => std.debug.print("Config error: channels.web.accounts.<id>.allowed_origins entries must be '*', 'null', or absolute origins (scheme://...).\n", .{}),
            ValidationError.MissingWebRelayUrl => std.debug.print("Config error: channels.web.accounts.<id>.relay_url is required when transport='relay'.\n", .{}),
            ValidationError.InvalidWebRelayUrl => std.debug.print("Config error: channels.web.accounts.<id>.relay_url must be an absolute wss:// URL.\n", .{}),
            ValidationError.InvalidWebRelayAgentId => std.debug.print("Config error: channels.web.accounts.<id>.relay_agent_id must be non-empty, <=64 chars, and contain no whitespace.\n", .{}),
            ValidationError.InvalidWebRelayPairingCodeTtl => std.debug.print("Config error: channels.web.accounts.<id>.relay_pairing_code_ttl_secs must be in [60, 300].\n", .{}),
            ValidationError.InvalidWebRelayUiTokenTtl => std.debug.print("Config error: channels.web.accounts.<id>.relay_ui_token_ttl_secs must be in [300, 2592000].\n", .{}),
            ValidationError.InvalidWebRelayTokenTtl => std.debug.print("Config error: channels.web.accounts.<id>.relay_token_ttl_secs must be in [3600, 31536000].\n", .{}),
        }
    }

    /// Print configured models summary to stderr (for startup banners).
    pub fn printModelConfig(self: *const Config) void {
        std.debug.print("  Model:    {s}\n", .{self.default_model orelse "(not set)"});
        std.debug.print("  Provider: {s}\n", .{self.default_provider});
        if (self.model_routes.len > 0) {
            std.debug.print("  Routes:   {d} configured\n", .{self.model_routes.len});
            for (self.model_routes) |r| {
                std.debug.print(
                    "            [{s}] {s}/{s} (cost={s}, quota={s})\n",
                    .{ r.hint, r.provider, r.model, @tagName(r.cost_class), @tagName(r.quota_class) },
                );
            }
        }
        if (self.agents.len > 0) {
            std.debug.print("  Agents:   {d} configured\n", .{self.agents.len});
            for (self.agents) |a| {
                std.debug.print("            {s} → {s}/{s}\n", .{ a.name, a.provider, a.model });
            }
        }
    }

    pub fn resolveAgentWorkspacePath(self: *const Config, allocator: std.mem.Allocator, workspace_path: []const u8) ![]const u8 {
        if (std.fs.path.isAbsolute(workspace_path)) {
            return try allocator.dupe(u8, workspace_path);
        }
        const normalized_workspace_path = try normalizeHostPathSeparators(allocator, workspace_path);
        defer allocator.free(normalized_workspace_path);
        const home_dir = std.fs.path.dirname(self.config_path) orelse self.workspace_dir;
        return try std.fs.path.join(allocator, &.{ home_dir, normalized_workspace_path });
    }

    pub fn resolveAgentWorkspace(self: *const Config, allocator: std.mem.Allocator, agent_name: []const u8) ![]const u8 {
        for (self.agents) |agent_cfg| {
            if (!std.mem.eql(u8, agent_cfg.name, agent_name)) continue;
            if (agent_cfg.workspace_path) |workspace_path| {
                return try self.resolveAgentWorkspacePath(allocator, workspace_path);
            }
            break;
        }
        return try allocator.dupe(u8, self.workspace_dir);
    }

    pub fn scaffoldAgentWorkspace(allocator: std.mem.Allocator, workspace_path: []const u8) !void {
        std.fs.cwd().makePath(workspace_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const files = [_]struct {
            name: []const u8,
            content: []const u8,
        }{
            .{
                .name = "AGENTS.md",
                .content = "# Agent Instructions\n\nDefine this agent's operating rules, workflow, and guardrails here.\n",
            },
            .{
                .name = "SOUL.md",
                .content = "# Soul\n\nDefine this agent's persona, tone, and communication style here.\n",
            },
            .{
                .name = "IDENTITY.md",
                .content = "# Identity\n\nDefine this agent's name, role, and purpose here.\n",
            },
            .{
                .name = "MEMORY.md",
                .content = "# Memory\n",
            },
        };

        for (files) |file_spec| {
            const path = try std.fs.path.join(allocator, &.{ workspace_path, file_spec.name });
            defer allocator.free(path);

            const file = std.fs.createFileAbsolute(path, .{ .exclusive = true }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            defer file.close();
            try file.writeAll(file_spec.content);
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────

/// Helper used by tests to compare paths on Windows without worrying about
/// JSON escaping or backslashes vs. forward slashes. Converts all '\\' to '/'.
fn normalizePathSeparators(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const dup = try allocator.dupe(u8, path);
    for (dup) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    return dup;
}

pub fn normalizeHostPathSeparators(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const dup = try allocator.dupe(u8, path);
    for (dup) |*c| {
        if (c.* == '/' or c.* == '\\') c.* = std.fs.path.sep;
    }
    return dup;
}

test "json parse roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{
        \\  "workspace": "/custom/path",
        \\  "default_temperature": 0.5,
        \\  "models": {"providers": {"anthropic": {"api_key": "sk-test"}}},
        \\  "agents": {"defaults": {"model": {"primary": "anthropic/claude-opus-4"}, "heartbeat": {"every": "15m"}}},
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

    try std.testing.expectEqualStrings("/custom/path", cfg.workspace_dir_override.?);
    try std.testing.expectEqualStrings("/custom/path", cfg.workspace_dir);

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
}

test "validation rejects bad temperature" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .default_temperature = 5.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "json parse reads reliability fallback providers and model fallbacks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{
        \\  "agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.3-codex"}}},
        \\  "reliability": {
        \\    "provider_retries": 3,
        \\    "provider_backoff_ms": 750,
        \\    "fallback_providers": ["openrouter", "groq"],
        \\    "api_keys": ["key_a", "key_b"],
        \\    "model_fallbacks": [
        \\      {"model": "gpt-5.3-codex", "fallbacks": ["openrouter/anthropic/claude-sonnet-4"]},
        \\      {"model": "claude-opus-4", "fallbacks": ["claude-sonnet-4", "claude-haiku-3.5"]}
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

    try std.testing.expectEqual(@as(u32, 3), cfg.reliability.provider_retries);
    try std.testing.expectEqual(@as(u64, 750), cfg.reliability.provider_backoff_ms);
    try std.testing.expectEqual(@as(usize, 2), cfg.reliability.fallback_providers.len);
    try std.testing.expectEqualStrings("openrouter", cfg.reliability.fallback_providers[0]);
    try std.testing.expectEqualStrings("groq", cfg.reliability.fallback_providers[1]);
    try std.testing.expectEqual(@as(usize, 2), cfg.reliability.api_keys.len);
    try std.testing.expectEqualStrings("key_a", cfg.reliability.api_keys[0]);
    try std.testing.expectEqualStrings("key_b", cfg.reliability.api_keys[1]);
    try std.testing.expectEqual(@as(usize, 2), cfg.reliability.model_fallbacks.len);
    try std.testing.expectEqualStrings("gpt-5.3-codex", cfg.reliability.model_fallbacks[0].model);
    try std.testing.expectEqual(@as(usize, 1), cfg.reliability.model_fallbacks[0].fallbacks.len);
    try std.testing.expectEqualStrings(
        "openrouter/anthropic/claude-sonnet-4",
        cfg.reliability.model_fallbacks[0].fallbacks[0],
    );
}

test "validation rejects zero port" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.gateway.port = 0;
    try std.testing.expectError(Config.ValidationError.InvalidPort, cfg.validate());
}

test "validation passes for defaults" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "test/model",
        .allocator = std.testing.allocator,
    };
    try cfg.validate();
}

test "validation rejects plaintext secrets" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "test/model",
        .allocator = std.testing.allocator,
    };
    cfg.secrets.encrypt = false;
    try std.testing.expectError(Config.ValidationError.InsecurePlaintextSecrets, cfg.validate());
}

test "validation rejects null default_model" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.NoDefaultModel, cfg.validate());
}

test "validation rejects top-level default_provider" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"default_provider":"anthropic","agents":{"defaults":{"model":{"primary":"anthropic/claude-opus-4"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.legacy_default_provider_detected);
    try std.testing.expectError(Config.ValidationError.LegacyDefaultProviderField, cfg.validate());
}

test "json parse top-level default_model" {
    const allocator = std.testing.allocator;
    const json =
        \\{"default_model": "meta-llama/llama-3.3-70b-instruct:free"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.legacy_default_model_detected);
    try std.testing.expect(cfg.default_model == null);
    try std.testing.expectError(Config.ValidationError.LegacyDefaultModelField, cfg.validate());
}

test "validation rejects top-level default_model even when nested model exists" {
    const allocator = std.testing.allocator;
    // use an arena to match production behavior (both allocs are freed together)
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = a };
    try cfg.parseJson(
        \\{"default_model": "top-level-model", "agents": {"defaults": {"model": {"primary": "anthropic/nested-model"}}}}
    );
    try std.testing.expect(cfg.legacy_default_model_detected);
    try std.testing.expectEqualStrings("nested-model", cfg.default_model.?);
    try std.testing.expectError(Config.ValidationError.LegacyDefaultModelField, cfg.validate());
}

test "validation rejects defaults.model.primary without provider prefix" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents":{"defaults":{"model":{"primary":"claude-opus-4"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectError(Config.ValidationError.InvalidDefaultModelPrimary, cfg.validate());
}

test "save includes channels section by default" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"channels\": {") != null);
}

test "save writes configured telegram channel account" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.channels.telegram = &.{
        .{
            .account_id = "main",
            .bot_token = "123:ABC",
            .allow_from = &.{"user1"},
            .interactive = .{
                .enabled = true,
                .ttl_secs = 120,
                .owner_only = true,
                .remove_on_click = false,
            },
        },
    };
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"telegram\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"accounts\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"main\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"account_id\": \"main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"bot_token\": \"123:ABC\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"interactive\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"enabled\": true") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"ttl_secs\": 120") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"remove_on_click\": false") != null);
}

test "save roundtrip preserves telegram interactive settings" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.channels.telegram = &.{
        .{
            .account_id = "main",
            .bot_token = "123:ABC",
            .interactive = .{
                .enabled = true,
                .ttl_secs = 321,
                .owner_only = false,
                .remove_on_click = false,
            },
        },
    };
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);
    try std.testing.expectEqual(@as(usize, 1), loaded.channels.telegram.len);
    try std.testing.expect(loaded.channels.telegram[0].interactive.enabled);
    try std.testing.expectEqual(@as(u64, 321), loaded.channels.telegram[0].interactive.ttl_secs);
    try std.testing.expect(!loaded.channels.telegram[0].interactive.owner_only);
    try std.testing.expect(!loaded.channels.telegram[0].interactive.remove_on_click);
}

test "save roundtrip preserves external channel config" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    const external_env = [_]ExternalChannelConfig.EnvEntry{
        .{ .key = "TOKEN", .value = "secret" },
    };
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "whatsapp_web",
            .transport = .{
                .command = "nullclaw-plugin-whatsapp-web",
                .args = &.{"--stdio"},
                .env = &external_env,
                .timeout_ms = 2500,
            },
            .plugin_config_json = "{\"bridge_url\":\"http://127.0.0.1:3301\",\"group_policy\":\"allowlist\"}",
        },
    };

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.channels.external = &external_accounts;
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"external\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"runtime_name\": \"whatsapp_web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"transport\": {") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"command\": \"nullclaw-plugin-whatsapp-web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"config\": {") != null);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expectEqual(@as(usize, 1), loaded.channels.external.len);
    const external_cfg = loaded.channels.external[0];
    try std.testing.expectEqualStrings("main", external_cfg.account_id);
    try std.testing.expectEqualStrings("whatsapp_web", external_cfg.runtime_name);
    try std.testing.expectEqualStrings("nullclaw-plugin-whatsapp-web", external_cfg.transport.command);
    try std.testing.expectEqual(@as(u32, 2500), external_cfg.transport.timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), external_cfg.transport.env.len);
    try std.testing.expectEqualStrings("TOKEN", external_cfg.transport.env[0].key);
    try std.testing.expect(std.mem.indexOf(u8, external_cfg.plugin_config_json, "\"group_policy\":\"allowlist\"") != null);
}

test "save roundtrip preserves diagnostics logging flags" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.diagnostics.log_tool_calls = true;
    cfg.diagnostics.log_message_receipts = true;
    cfg.diagnostics.log_message_payloads = true;
    cfg.diagnostics.log_llm_io = true;
    cfg.diagnostics.token_usage_ledger_enabled = false;
    cfg.diagnostics.token_usage_ledger_window_hours = 6;
    cfg.diagnostics.token_usage_ledger_max_bytes = 131072;
    cfg.diagnostics.token_usage_ledger_max_lines = 2048;
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expect(loaded.diagnostics.log_tool_calls);
    try std.testing.expect(loaded.diagnostics.log_message_receipts);
    try std.testing.expect(loaded.diagnostics.log_message_payloads);
    try std.testing.expect(loaded.diagnostics.log_llm_io);
    try std.testing.expect(!loaded.diagnostics.token_usage_ledger_enabled);
    try std.testing.expectEqual(@as(u32, 6), loaded.diagnostics.token_usage_ledger_window_hours);
    try std.testing.expectEqual(@as(u64, 131072), loaded.diagnostics.token_usage_ledger_max_bytes);
    try std.testing.expectEqual(@as(u64, 2048), loaded.diagnostics.token_usage_ledger_max_lines);
}

test "save roundtrip preserves diagnostics otel headers" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    const headers = [_]DiagnosticsConfig.OtelHeaderEntry{
        .{ .key = "Authorization", .value = "Bearer secret-token" },
        .{ .key = "x-nullwatch-source", .value = "nullclaw" },
    };

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.diagnostics.backend = "otel";
    cfg.diagnostics.otel_endpoint = "http://127.0.0.1:7710";
    cfg.diagnostics.otel_service_name = "nullclaw";
    cfg.diagnostics.otel_headers = &headers;
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);
    try std.testing.expectEqualStrings("otel", loaded.diagnostics.backend);
    try std.testing.expectEqualStrings("http://127.0.0.1:7710", loaded.diagnostics.otel_endpoint.?);
    try std.testing.expectEqualStrings("nullclaw", loaded.diagnostics.otel_service_name.?);
    try std.testing.expectEqual(@as(usize, 2), loaded.diagnostics.otel_headers.len);
    try std.testing.expectEqualStrings("Authorization", loaded.diagnostics.otel_headers[0].key);
    try std.testing.expectEqualStrings("Bearer secret-token", loaded.diagnostics.otel_headers[0].value);
    try std.testing.expectEqualStrings("x-nullwatch-source", loaded.diagnostics.otel_headers[1].key);
    try std.testing.expectEqualStrings("nullclaw", loaded.diagnostics.otel_headers[1].value);
}

test "save roundtrip preserves reliability settings" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    const fallback_models = [_][]const u8{
        "openrouter/anthropic/claude-sonnet-4",
        "groq/llama-3.3-70b",
    };
    const model_fallbacks = [_]ModelFallbackEntry{
        .{
            .model = "gpt-5.3-codex",
            .fallbacks = &fallback_models,
        },
    };

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.reliability.provider_retries = 4;
    cfg.reliability.provider_backoff_ms = 1200;
    cfg.reliability.channel_initial_backoff_secs = 5;
    cfg.reliability.channel_max_backoff_secs = 90;
    cfg.reliability.scheduler_poll_secs = 20;
    cfg.reliability.scheduler_retries = 3;
    cfg.reliability.fallback_providers = &.{ "openrouter", "groq" };
    cfg.reliability.api_keys = &.{ "rk_a", "rk_b" };
    cfg.reliability.model_fallbacks = &model_fallbacks;
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expectEqual(@as(u32, 4), loaded.reliability.provider_retries);
    try std.testing.expectEqual(@as(u64, 1200), loaded.reliability.provider_backoff_ms);
    try std.testing.expectEqual(@as(u64, 5), loaded.reliability.channel_initial_backoff_secs);
    try std.testing.expectEqual(@as(u64, 90), loaded.reliability.channel_max_backoff_secs);
    try std.testing.expectEqual(@as(u64, 20), loaded.reliability.scheduler_poll_secs);
    try std.testing.expectEqual(@as(u32, 3), loaded.reliability.scheduler_retries);
    try std.testing.expectEqual(@as(usize, 2), loaded.reliability.fallback_providers.len);
    try std.testing.expectEqualStrings("openrouter", loaded.reliability.fallback_providers[0]);
    try std.testing.expectEqualStrings("groq", loaded.reliability.fallback_providers[1]);
    try std.testing.expectEqual(@as(usize, 2), loaded.reliability.api_keys.len);
    try std.testing.expectEqualStrings("rk_a", loaded.reliability.api_keys[0]);
    try std.testing.expectEqualStrings("rk_b", loaded.reliability.api_keys[1]);
    try std.testing.expectEqual(@as(usize, 1), loaded.reliability.model_fallbacks.len);
    try std.testing.expectEqualStrings("gpt-5.3-codex", loaded.reliability.model_fallbacks[0].model);
    try std.testing.expectEqual(@as(usize, 2), loaded.reliability.model_fallbacks[0].fallbacks.len);
    try std.testing.expectEqualStrings("openrouter/anthropic/claude-sonnet-4", loaded.reliability.model_fallbacks[0].fallbacks[0]);
    try std.testing.expectEqualStrings("groq/llama-3.3-70b", loaded.reliability.model_fallbacks[0].fallbacks[1]);
}

test "json parse memory weights accept integer values" {
    const allocator = std.testing.allocator;
    const json =
        \\{"memory":{"search":{"query":{"hybrid":{"vector_weight":1,"text_weight":0}}}}}
    ;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(f64, 1.0), cfg.memory.search.query.hybrid.vector_weight);
    try std.testing.expectEqual(@as(f64, 0.0), cfg.memory.search.query.hybrid.text_weight);
}

test "json parse memory sqlite_ann store options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"memory":{"search":{"store":{"kind":"sqlite_ann","ann_candidate_multiplier":9,"ann_min_candidates":77}}}}
    ;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("sqlite_ann", cfg.memory.search.store.kind);
    try std.testing.expectEqual(@as(u32, 9), cfg.memory.search.store.ann_candidate_multiplier);
    try std.testing.expectEqual(@as(u32, 77), cfg.memory.search.store.ann_min_candidates);
}

test "json parse memory sqlite_ann store options clamp and ignore invalid integers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"memory":{"search":{"store":{"kind":"sqlite_ann","ann_candidate_multiplier":-5,"ann_min_candidates":5000000000}}}}
    ;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("sqlite_ann", cfg.memory.search.store.kind);
    try std.testing.expectEqual(@as(u32, 12), cfg.memory.search.store.ann_candidate_multiplier);
    try std.testing.expectEqual(@as(u32, std.math.maxInt(u32)), cfg.memory.search.store.ann_min_candidates);
}

test "save roundtrip preserves extended config sections" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.reasoning_effort = "high";
    cfg.model_routes = &.{
        .{
            .hint = "fast",
            .provider = "groq",
            .model = "llama-3.3-70b",
            .api_key = "gsk_test",
            .cost_class = .cheap,
            .quota_class = .unlimited,
        },
    };
    cfg.agents = &.{
        .{
            .name = "helper",
            .provider = "openrouter",
            .model = "openai/gpt-4o-mini",
            .system_prompt = "You are helper.",
            .api_key = "rk_test",
            .temperature = 0.2,
            .max_depth = 5,
        },
    };
    cfg.agent_bindings = &.{
        .{
            .agent_id = "helper",
            .comment = "discord-main",
            .match = .{
                .channel = "discord",
                .account_id = "main",
            },
        },
    };
    cfg.mcp_servers = &.{
        .{
            .name = "context7",
            .command = "npx",
            .args = &.{
                "-y",
                "@upstash/context7-mcp",
            },
            .env = &.{
                .{
                    .key = "OPENROUTER_API_KEY",
                    .value = "sk-test",
                },
            },
        },
    };

    cfg.runtime.kind = "docker";
    cfg.runtime.docker.image = "alpine:3.20";
    cfg.runtime.docker.network = "bridge";
    cfg.runtime.docker.memory_limit_mb = 768;
    cfg.runtime.docker.read_only_rootfs = false;
    cfg.runtime.docker.mount_workspace = false;

    cfg.scheduler.enabled = false;
    cfg.scheduler.max_tasks = 32;
    cfg.scheduler.max_concurrent = 2;
    cfg.scheduler.agent_timeout_secs = 123;

    cfg.agent.compact_context = true;
    cfg.agent.max_tool_iterations = 7;
    cfg.agent.max_history_messages = 21;
    cfg.agent.parallel_tools = true;
    cfg.agent.tool_dispatcher = "parallel";
    cfg.agent.session_idle_timeout_secs = 90;
    cfg.agent.compaction_keep_recent = 12;
    cfg.agent.compaction_max_summary_chars = 3000;
    cfg.agent.compaction_max_source_chars = 9000;
    cfg.agent.status_show_emojis = false;
    cfg.agent.message_timeout_secs = 60;

    cfg.memory.search.provider = "openai";
    cfg.memory.search.model = "text-embedding-3-small";
    cfg.memory.search.dimensions = 1536;
    cfg.memory.search.query.hybrid.vector_weight = 0.6;
    cfg.memory.search.query.hybrid.text_weight = 0.4;
    cfg.memory.search.cache.max_entries = 333;
    cfg.memory.search.chunking.max_tokens = 1024;
    cfg.memory.response_cache.enabled = true;
    cfg.memory.response_cache.ttl_minutes = 15;
    cfg.memory.response_cache.max_entries = 123;
    cfg.memory.lifecycle.snapshot_enabled = true;
    cfg.memory.lifecycle.snapshot_on_hygiene = true;
    cfg.memory.lifecycle.auto_hydrate = false;

    cfg.gateway.allow_public_bind = true;
    cfg.gateway.pair_rate_limit_per_minute = 20;
    cfg.gateway.webhook_rate_limit_per_minute = 80;
    cfg.gateway.idempotency_ttl_secs = 120;
    cfg.gateway.paired_tokens = &.{ "tok-1", "tok-2" };

    cfg.tunnel.provider = "ngrok";
    cfg.tunnel.ngrok = .{
        .auth_token = "ngrok-test-token",
        .domain = "test.ngrok-free.app",
    };

    cfg.composio.enabled = true;
    cfg.composio.api_key = "comp-key";
    cfg.composio.entity_id = "entity-1";

    cfg.secrets.encrypt = false;

    cfg.browser.enabled = true;
    cfg.browser.session_name = "demo";
    cfg.browser.backend = "native";
    cfg.browser.native_headless = false;
    cfg.browser.native_webdriver_url = "http://127.0.0.1:9515";
    cfg.browser.native_chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    cfg.browser.allowed_domains = &.{ "github.com", "docs.rs" };

    cfg.http_request.enabled = true;
    cfg.http_request.max_response_size = 12345;
    cfg.http_request.timeout_secs = 8;
    cfg.http_request.proxy = "socks5://127.0.0.1:1080";
    cfg.http_request.search_base_url = "https://searx.example.com";
    cfg.http_request.search_provider = "brave";
    cfg.http_request.search_fallback_providers = &.{ "jina", "duckduckgo" };
    cfg.diagnostics.api_error_max_chars = 500;

    cfg.identity.format = "aieos";
    cfg.identity.aieos_path = "id.json";
    cfg.identity.aieos_inline = "inline-id";

    cfg.cost.warn_at_percent = 70;
    cfg.cost.allow_override = true;

    cfg.security.sandbox.enabled = true;
    cfg.security.sandbox.backend = .firejail;
    cfg.security.resources.max_memory_mb = 1024;
    cfg.security.resources.max_cpu_time_seconds = 120;
    cfg.security.resources.max_subprocesses = 20;
    cfg.security.resources.memory_monitoring = false;
    cfg.security.audit.enabled = false;
    cfg.security.audit.log_path = "custom.log";
    cfg.security.audit.max_size_mb = 9;
    cfg.security.audit.sign_events = true;

    cfg.peripherals.enabled = true;
    cfg.peripherals.datasheet_dir = "/tmp/ds";

    cfg.hardware.serial_port = "/dev/tty.usbmodem1";
    cfg.hardware.probe_target = "stm32f401cc";
    cfg.hardware.workspace_datasheets = true;

    cfg.session.dm_scope = .per_peer;
    cfg.session.idle_minutes = 45;
    cfg.session.typing_interval_secs = 2;
    cfg.session.identity_links = &.{
        .{
            .canonical = "alice",
            .peers = &.{ "telegram:111", "discord:222" },
        },
    };

    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 256 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expectEqualStrings("high", loaded.reasoning_effort.?);
    try std.testing.expectEqual(@as(usize, 1), loaded.model_routes.len);
    try std.testing.expectEqualStrings("fast", loaded.model_routes[0].hint);
    try std.testing.expectEqualStrings("gsk_test", loaded.model_routes[0].api_key.?);
    try std.testing.expectEqual(@as(usize, 1), loaded.agents.len);
    try std.testing.expectEqualStrings("helper", loaded.agents[0].name);
    try std.testing.expectEqual(@as(usize, 1), loaded.agent_bindings.len);
    try std.testing.expectEqualStrings("discord", loaded.agent_bindings[0].match.channel.?);
    try std.testing.expectEqualStrings("main", loaded.agent_bindings[0].match.account_id.?);
    try std.testing.expectEqual(@as(usize, 1), loaded.mcp_servers.len);
    try std.testing.expectEqualStrings("context7", loaded.mcp_servers[0].name);
    try std.testing.expectEqualStrings("stdio", loaded.mcp_servers[0].transport);
    try std.testing.expectEqual(@as(usize, 2), loaded.mcp_servers[0].args.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.mcp_servers[0].env.len);
    try std.testing.expectEqualStrings("OPENROUTER_API_KEY", loaded.mcp_servers[0].env[0].key);

    try std.testing.expectEqualStrings("docker", loaded.runtime.kind);
    try std.testing.expectEqual(@as(u32, 32), loaded.scheduler.max_tasks);
    try std.testing.expectEqual(@as(u64, 123), loaded.scheduler.agent_timeout_secs);
    try std.testing.expect(loaded.agent.parallel_tools);
    try std.testing.expect(!loaded.agent.status_show_emojis);

    try std.testing.expectEqualStrings("openai", loaded.memory.search.provider);
    try std.testing.expect(loaded.memory.response_cache.enabled);
    try std.testing.expectEqual(@as(u32, 2), loaded.gateway.paired_tokens.len);
    try std.testing.expect(loaded.gateway.allow_public_bind);
    try std.testing.expectEqualStrings("ngrok", loaded.tunnel.provider);
    try std.testing.expect(loaded.tunnel.ngrok != null);
    try std.testing.expectEqualStrings("ngrok-test-token", loaded.tunnel.ngrok.?.auth_token.?);
    try std.testing.expectEqualStrings("test.ngrok-free.app", loaded.tunnel.ngrok.?.domain.?);
    try std.testing.expect(loaded.composio.enabled);
    try std.testing.expect(!loaded.secrets.encrypt);
    try std.testing.expect(loaded.browser.enabled);
    try std.testing.expectEqual(@as(usize, 2), loaded.browser.allowed_domains.len);
    try std.testing.expect(loaded.http_request.enabled);
    try std.testing.expectEqualStrings("socks5://127.0.0.1:1080", loaded.http_request.proxy.?);
    try std.testing.expectEqualStrings("https://searx.example.com", loaded.http_request.search_base_url.?);
    try std.testing.expectEqualStrings("brave", loaded.http_request.search_provider);
    try std.testing.expectEqual(@as(usize, 2), loaded.http_request.search_fallback_providers.len);
    try std.testing.expectEqualStrings("jina", loaded.http_request.search_fallback_providers[0]);
    try std.testing.expectEqual(@as(?u32, 500), loaded.diagnostics.api_error_max_chars);
    try std.testing.expectEqualStrings("aieos", loaded.identity.format);
    try std.testing.expectEqual(@as(u8, 70), loaded.cost.warn_at_percent);
    try std.testing.expectEqual(config_types.SandboxBackend.firejail, loaded.security.sandbox.backend);
    try std.testing.expect(loaded.peripherals.enabled);
    try std.testing.expectEqualStrings("/dev/tty.usbmodem1", loaded.hardware.serial_port.?);
    try std.testing.expectEqual(config_types.DmScope.per_peer, loaded.session.dm_scope);
    try std.testing.expectEqual(@as(usize, 1), loaded.session.identity_links.len);
}

test "save escapes mcp_servers strings safely" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.default_model = "gpt-5";
    cfg.mcp_servers = &.{
        .{
            .name = "ctx\"7",
            .command = "npx \"@scope/pkg\"\nrun",
            .args = &.{
                "--path=C:\\tmp\\file",
                "line\nbreak",
            },
            .env = &.{
                .{
                    .key = "OPEN\"KEY",
                    .value = "ab\\cd\"ef\nz",
                },
            },
        },
    };

    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expectEqual(@as(usize, 1), loaded.mcp_servers.len);
    try std.testing.expectEqualStrings("ctx\"7", loaded.mcp_servers[0].name);
    try std.testing.expectEqualStrings("stdio", loaded.mcp_servers[0].transport);
    try std.testing.expectEqualStrings("npx \"@scope/pkg\"\nrun", loaded.mcp_servers[0].command);
    try std.testing.expectEqual(@as(usize, 2), loaded.mcp_servers[0].args.len);
    try std.testing.expectEqualStrings("--path=C:\\tmp\\file", loaded.mcp_servers[0].args[0]);
    try std.testing.expectEqualStrings("line\nbreak", loaded.mcp_servers[0].args[1]);
    try std.testing.expectEqual(@as(usize, 1), loaded.mcp_servers[0].env.len);
    try std.testing.expectEqualStrings("OPEN\"KEY", loaded.mcp_servers[0].env[0].key);
    try std.testing.expectEqualStrings("ab\\cd\"ef\nz", loaded.mcp_servers[0].env[0].value);
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

test "syncFlatFields keeps explicit workspace_dir" {
    var cfg = Config{
        .workspace_dir = "/workspace/from-env",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.workspace_dir_override = "/workspace/from-json";

    cfg.syncFlatFields();

    try std.testing.expectEqualStrings("/workspace/from-env", cfg.workspace_dir);
    try std.testing.expectEqualStrings("/workspace/from-json", cfg.workspace_dir_override.?);
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
        .default_model = "x",
        .default_temperature = -1.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "validation accepts boundary temperatures" {
    const cfg_zero = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .default_temperature = 0.0,
        .allocator = std.testing.allocator,
    };
    try cfg_zero.validate();

    const cfg_two = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .default_temperature = 2.0,
        .allocator = std.testing.allocator,
    };
    try cfg_two.validate();
}

test "validation rejects excessive retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 101;
    try std.testing.expectError(Config.ValidationError.InvalidRetryCount, cfg.validate());
}

test "validation rejects excessive backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 700_000;
    try std.testing.expectError(Config.ValidationError.InvalidBackoffMs, cfg.validate());
}

test "validation accepts max boundary retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 100;
    try cfg.validate();
}

test "validation accepts max boundary backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 600_000;
    try cfg.validate();
}

test "validation rejects invalid http_request search base URL" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_base_url = "https://searx.example.com?bad=1";
    try std.testing.expectError(Config.ValidationError.InvalidHttpSearchBaseUrl, cfg.validate());
}

test "validation accepts valid http_request search base URL" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_base_url = "https://searx.example.com/search";
    try cfg.validate();
}

test "validation accepts local http_request search base URL" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_base_url = "http://localhost:8888/search";
    try cfg.validate();
}

test "validation rejects remote http_request search base URL over plain http" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_base_url = "http://searx.example.com/search";
    try std.testing.expectError(Config.ValidationError.InvalidHttpSearchBaseUrl, cfg.validate());
}

test "validation rejects invalid http_request search provider" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_provider = "google";
    try std.testing.expectError(Config.ValidationError.InvalidHttpSearchProvider, cfg.validate());
}

test "validation rejects invalid http_request search fallback provider" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.search_fallback_providers = &.{"auto"};
    try std.testing.expectError(Config.ValidationError.InvalidHttpSearchFallbackProvider, cfg.validate());
}

test "validation rejects invalid http_request proxy URL" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.http_request.proxy = "ftp://proxy.example.com:21";
    try std.testing.expectError(Config.ValidationError.InvalidHttpProxyUrl, cfg.validate());
}

test "validation rejects out-of-range diagnostics api_error_max_chars" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
    };
    cfg.diagnostics.api_error_max_chars = 120;
    try std.testing.expectError(Config.ValidationError.InvalidApiErrorMaxChars, cfg.validate());
}

test "validation rejects malformed web path" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .path = "relay",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebPath, cfg.validate());
}

test "validation rejects malformed web auth token" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .path = "/ws",
            .auth_token = "bad token",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebAuthToken, cfg.validate());
}

test "validation rejects malformed web origin entry" {
    const origins = [_][]const u8{"relay.nullclaw.io"};
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .path = "/ws",
            .auth_token = "relay-token-0123456789",
            .allowed_origins = &origins,
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebOrigin, cfg.validate());
}

test "validation accepts well formed web channel config" {
    const origins = [_][]const u8{
        "https://relay.nullclaw.io",
        "chrome-extension://abcdefghijklmnop",
    };
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .path = "/ws",
            .auth_token = "relay-token-0123456789",
            .allowed_origins = &origins,
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try cfg.validate();
}

test "validation rejects unknown web transport mode" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "direct",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebTransport, cfg.validate());
}

test "validation accepts mcp http transport config" {
    const headers = [_]McpServerConfig.McpHeaderEntry{
        .{ .key = "Authorization", .value = "Bearer test-token" },
    };
    const mcp_servers = [_]McpServerConfig{
        .{
            .name = "remote",
            .transport = "http",
            .url = "https://mcp.example.com/rpc",
            .timeout_ms = 5000,
            .headers = &headers,
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .mcp_servers = &mcp_servers,
    };
    try cfg.validate();
}

test "validation rejects mcp http transport without url" {
    const mcp_servers = [_]McpServerConfig{
        .{
            .name = "remote",
            .transport = "http",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .mcp_servers = &mcp_servers,
    };
    try std.testing.expectError(Config.ValidationError.MissingMcpHttpUrl, cfg.validate());
}

test "validation rejects mcp stdio transport without command" {
    const mcp_servers = [_]McpServerConfig{
        .{
            .name = "local",
            .transport = "stdio",
            .command = "",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .mcp_servers = &mcp_servers,
    };
    try std.testing.expectError(Config.ValidationError.MissingMcpCommand, cfg.validate());
}

test "validation rejects mcp http transport with malformed header" {
    const headers = [_]McpServerConfig.McpHeaderEntry{
        .{ .key = "Authorization", .value = "line1\nline2" },
    };
    const mcp_servers = [_]McpServerConfig{
        .{
            .name = "remote",
            .transport = "http",
            .url = "https://mcp.example.com/rpc",
            .headers = &headers,
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .mcp_servers = &mcp_servers,
    };
    try std.testing.expectError(Config.ValidationError.InvalidMcpHeader, cfg.validate());
}

test "validation rejects mcp http transport with invalid timeout_ms" {
    const mcp_servers = [_]McpServerConfig{
        .{
            .name = "remote",
            .transport = "http",
            .url = "https://mcp.example.com/rpc",
            .timeout_ms = 0,
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .mcp_servers = &mcp_servers,
    };
    try std.testing.expectError(Config.ValidationError.InvalidMcpTimeoutMs, cfg.validate());
}

test "validation rejects external channel with invalid timeout_ms" {
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "whatsapp_web",
            .transport = .{
                .command = "nullclaw-plugin-whatsapp-web",
                .timeout_ms = 0,
            },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .external = &external_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidExternalTransportTimeoutMs, cfg.validate());
}

test "validation rejects external runtime name that collides with built-in channel" {
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "telegram",
            .transport = .{ .command = "plugin" },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .external = &external_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.ConflictingExternalRuntimeName, cfg.validate());
}

test "validation rejects external runtime name that collides with maixcam runtime" {
    const maixcam_accounts = [_]MaixCamConfig{
        .{
            .account_id = "cam-main",
            .name = "vision-lab",
            .host = "127.0.0.1",
            .port = 8080,
        },
    };
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "vision-lab",
            .transport = .{ .command = "plugin" },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .maixcam = &maixcam_accounts,
            .external = &external_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.ConflictingExternalRuntimeName, cfg.validate());
}

test "validation rejects duplicate external runtime names across accounts" {
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "whatsapp_web",
            .transport = .{ .command = "plugin-a" },
        },
        .{
            .account_id = "backup",
            .runtime_name = "whatsapp_web",
            .transport = .{ .command = "plugin-b" },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .external = &external_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.ConflictingExternalRuntimeName, cfg.validate());
}

test "validation rejects external channel config that is not a JSON object" {
    const external_accounts = [_]ExternalChannelConfig{
        .{
            .account_id = "main",
            .runtime_name = "whatsapp_web",
            .transport = .{ .command = "plugin" },
            .plugin_config_json = "\"oops\"",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .external = &external_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidExternalPluginConfig, cfg.validate());
}

test "validation rejects unsupported web message_auth_mode value" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .message_auth_mode = "jwt",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebMessageAuthMode, cfg.validate());
}

test "validation rejects token message_auth_mode for relay transport" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .message_auth_mode = "token",
            .relay_url = "wss://relay.nullclaw.io/ws/agent",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebMessageAuthTransport, cfg.validate());
}

test "validation rejects relay transport without relay_url" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.MissingWebRelayUrl, cfg.validate());
}

test "validation rejects malformed relay url and agent id" {
    const bad_url_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "https://relay.nullclaw.io/ws",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
        },
    };
    const cfg_bad_url = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &bad_url_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebRelayUrl, cfg_bad_url.validate());

    const bad_agent_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "wss://relay.nullclaw.io/ws",
            .relay_agent_id = "bad agent",
            .relay_token = "relay-token-0123456789",
        },
    };
    const cfg_bad_agent = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &bad_agent_accounts,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebRelayAgentId, cfg_bad_agent.validate());
}

test "validation accepts well formed web relay config" {
    const web_accounts = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "wss://relay.nullclaw.io/ws/agent",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };
    try cfg.validate();
}

test "validation rejects relay ttl values outside supported ranges" {
    const bad_pair_ttl = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "wss://relay.nullclaw.io/ws/agent",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
            .relay_pairing_code_ttl_secs = 30,
        },
    };
    const cfg_bad_pair_ttl = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &bad_pair_ttl,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebRelayPairingCodeTtl, cfg_bad_pair_ttl.validate());

    const bad_ui_ttl = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "wss://relay.nullclaw.io/ws/agent",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
            .relay_ui_token_ttl_secs = 120,
        },
    };
    const cfg_bad_ui_ttl = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &bad_ui_ttl,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebRelayUiTokenTtl, cfg_bad_ui_ttl.validate());

    const bad_relay_token_ttl = [_]WebConfig{
        .{
            .account_id = "default",
            .transport = "relay",
            .relay_url = "wss://relay.nullclaw.io/ws/agent",
            .relay_agent_id = "agent-1",
            .relay_token = "relay-token-0123456789",
            .relay_token_ttl_secs = 120,
        },
    };
    const cfg_bad_relay_token_ttl = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_model = "x",
        .allocator = std.testing.allocator,
        .channels = .{
            .web = &bad_relay_token_ttl,
        },
    };
    try std.testing.expectError(Config.ValidationError.InvalidWebRelayTokenTtl, cfg_bad_relay_token_ttl.validate());
}

// ── JSON parse: sub-config sections ─────────────────────────────

test "json parse diagnostics section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"diagnostics": {"backend": "otel", "log_tool_calls": true, "log_message_receipts": true, "log_message_payloads": true, "log_llm_io": true, "token_usage_ledger_enabled": false, "token_usage_ledger_window_hours": 12, "token_usage_ledger_max_bytes": 262144, "token_usage_ledger_max_lines": 4096, "otel": {"endpoint": "http://localhost:4318", "service_name": "yc", "headers": {"Authorization": "Bearer test", "x-nullwatch-source": "nullclaw"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("otel", cfg.diagnostics.backend);
    try std.testing.expect(cfg.diagnostics.log_tool_calls);
    try std.testing.expect(cfg.diagnostics.log_message_receipts);
    try std.testing.expect(cfg.diagnostics.log_message_payloads);
    try std.testing.expect(cfg.diagnostics.log_llm_io);
    try std.testing.expect(!cfg.diagnostics.token_usage_ledger_enabled);
    try std.testing.expectEqual(@as(u32, 12), cfg.diagnostics.token_usage_ledger_window_hours);
    try std.testing.expectEqual(@as(u64, 262144), cfg.diagnostics.token_usage_ledger_max_bytes);
    try std.testing.expectEqual(@as(u64, 4096), cfg.diagnostics.token_usage_ledger_max_lines);
    try std.testing.expectEqualStrings("http://localhost:4318", cfg.diagnostics.otel_endpoint.?);
    try std.testing.expectEqualStrings("yc", cfg.diagnostics.otel_service_name.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.diagnostics.otel_headers.len);
    try std.testing.expectEqualStrings("Authorization", cfg.diagnostics.otel_headers[0].key);
    try std.testing.expectEqualStrings("Bearer test", cfg.diagnostics.otel_headers[0].value);
    try std.testing.expectEqualStrings("x-nullwatch-source", cfg.diagnostics.otel_headers[1].key);
    try std.testing.expectEqualStrings("nullclaw", cfg.diagnostics.otel_headers[1].value);
    allocator.free(cfg.diagnostics.backend);
    allocator.free(cfg.diagnostics.otel_endpoint.?);
    allocator.free(cfg.diagnostics.otel_service_name.?);
    for (cfg.diagnostics.otel_headers) |header| {
        allocator.free(header.key);
        allocator.free(header.value);
    }
    allocator.free(cfg.diagnostics.otel_headers);
}

test "json parse scheduler section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"scheduler": {"enabled": false, "max_tasks": 128, "max_concurrent": 8, "agent_timeout_secs": 600}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.scheduler.enabled);
    try std.testing.expectEqual(@as(u32, 128), cfg.scheduler.max_tasks);
    try std.testing.expectEqual(@as(u32, 8), cfg.scheduler.max_concurrent);
    try std.testing.expectEqual(@as(u64, 600), cfg.scheduler.agent_timeout_secs);
}

test "json parse agent section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"agent": {"compact_context": true, "max_tool_iterations": 20, "max_history_messages": 80, "parallel_tools": true, "tool_dispatcher": "xml", "token_limit": 64000, "status_show_emojis": false, "vision_disabled_models": ["router/text-only"], "auto_disable_vision_on_error": false}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.agent.compact_context);
    try std.testing.expectEqual(@as(u32, 20), cfg.agent.max_tool_iterations);
    try std.testing.expectEqual(@as(u32, 80), cfg.agent.max_history_messages);
    try std.testing.expect(cfg.agent.parallel_tools);
    try std.testing.expectEqualStrings("xml", cfg.agent.tool_dispatcher);
    try std.testing.expectEqual(@as(u64, 64_000), cfg.agent.token_limit);
    try std.testing.expect(cfg.agent.token_limit_explicit);
    try std.testing.expect(!cfg.agent.status_show_emojis);
    try std.testing.expectEqual(@as(usize, 1), cfg.agent.vision_disabled_models.len);
    try std.testing.expectEqualStrings("router/text-only", cfg.agent.vision_disabled_models[0]);
    try std.testing.expect(!cfg.agent.auto_disable_vision_on_error);
}

test "json parse agent token_limit explicit remains false when omitted" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agent": {"max_tool_iterations": 20}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(config_types.DEFAULT_AGENT_TOKEN_LIMIT, cfg.agent.token_limit);
    try std.testing.expect(!cfg.agent.token_limit_explicit);
    try std.testing.expect(cfg.agent.status_show_emojis);
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

test "json parse tools.path_env_vars" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tools": {"path_env_vars": ["LD_LIBRARY_PATH", "PYTHONHOME"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.tools.path_env_vars.len);
    try std.testing.expectEqualStrings("LD_LIBRARY_PATH", cfg.tools.path_env_vars[0]);
    try std.testing.expectEqualStrings("PYTHONHOME", cfg.tools.path_env_vars[1]);
    for (cfg.tools.path_env_vars) |p| allocator.free(p);
    allocator.free(cfg.tools.path_env_vars);
}

test "save roundtrip preserves tools.path_env_vars" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.tools.path_env_vars = &.{ "LD_LIBRARY_PATH", "PYTHONHOME" };
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);
    try std.testing.expectEqual(@as(usize, 2), loaded.tools.path_env_vars.len);
    try std.testing.expectEqualStrings("LD_LIBRARY_PATH", loaded.tools.path_env_vars[0]);
    try std.testing.expectEqualStrings("PYTHONHOME", loaded.tools.path_env_vars[1]);
}

test "json parse autonomy allow_raw_url_chars" {
    const allocator = std.testing.allocator;
    const json =
        \\{"autonomy": {"allow_raw_url_chars": true}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.autonomy.allow_raw_url_chars);
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

test "json parse http_request search_base_url" {
    const allocator = std.testing.allocator;
    const json =
        \\{"http_request": {"enabled": true, "search_base_url": "https://searx.example.com"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.http_request.enabled);
    try std.testing.expectEqualStrings("https://searx.example.com", cfg.http_request.search_base_url.?);
    allocator.free(cfg.http_request.search_base_url.?);
}

test "json parse http_request search provider settings" {
    const allocator = std.testing.allocator;
    const json =
        \\{"http_request": {"search_provider": "tavily", "search_fallback_providers": ["exa", "jina"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("tavily", cfg.http_request.search_provider);
    try std.testing.expectEqual(@as(usize, 2), cfg.http_request.search_fallback_providers.len);
    try std.testing.expectEqualStrings("exa", cfg.http_request.search_fallback_providers[0]);
    try std.testing.expectEqualStrings("jina", cfg.http_request.search_fallback_providers[1]);
    allocator.free(cfg.http_request.search_provider);
    for (cfg.http_request.search_fallback_providers) |provider| allocator.free(provider);
    allocator.free(cfg.http_request.search_fallback_providers);
}

test "json parse http_request proxy and diagnostics api_error_max_chars" {
    const allocator = std.testing.allocator;
    const json =
        \\{"http_request": {"proxy": "http://proxy.example.com:8080"}, "diagnostics": {"api_error_max_chars": 640}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("http://proxy.example.com:8080", cfg.http_request.proxy.?);
    try std.testing.expectEqual(@as(?u32, 640), cfg.diagnostics.api_error_max_chars);
    allocator.free(cfg.http_request.proxy.?);
}

test "json parse model routes" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "reasoning", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained"},
        \\  {"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "api_key": "gsk_test", "cost_class": "free", "quota_class": "unlimited"}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.model_routes.len);
    try std.testing.expectEqualStrings("reasoning", cfg.model_routes[0].hint);
    try std.testing.expectEqualStrings("openrouter", cfg.model_routes[0].provider);
    try std.testing.expectEqualStrings("anthropic/claude-opus-4", cfg.model_routes[0].model);
    try std.testing.expect(cfg.model_routes[0].api_key == null);
    try std.testing.expectEqual(config_types.ModelRouteCostClass.premium, cfg.model_routes[0].cost_class);
    try std.testing.expectEqual(config_types.ModelRouteQuotaClass.constrained, cfg.model_routes[0].quota_class);
    try std.testing.expectEqualStrings("fast", cfg.model_routes[1].hint);
    try std.testing.expectEqualStrings("groq", cfg.model_routes[1].provider);
    try std.testing.expectEqualStrings("llama-3.3-70b", cfg.model_routes[1].model);
    try std.testing.expectEqualStrings("gsk_test", cfg.model_routes[1].api_key.?);
    try std.testing.expectEqual(config_types.ModelRouteCostClass.free, cfg.model_routes[1].cost_class);
    try std.testing.expectEqual(config_types.ModelRouteQuotaClass.unlimited, cfg.model_routes[1].quota_class);
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

test "json parse model route metadata falls back to defaults on unknown values" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "mystery", "quota_class": "burst"}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqual(config_types.ModelRouteCostClass.standard, cfg.model_routes[0].cost_class);
    try std.testing.expectEqual(config_types.ModelRouteQuotaClass.normal, cfg.model_routes[0].quota_class);
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
}

fn parseModelRoutesForAllocationTest(allocator: std.mem.Allocator, json: []const u8) !void {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    for (cfg.model_routes) |route| {
        allocator.free(route.hint);
        allocator.free(route.provider);
        allocator.free(route.model);
        if (route.api_key) |api_key| allocator.free(api_key);
    }
    allocator.free(cfg.model_routes);
}

test "json parse model routes frees partial allocations on out-of-memory" {
    const json =
        \\{"model_routes": [
        \\  {"hint": "reasoning", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained"},
        \\  {"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "api_key": "gsk_test", "cost_class": "free", "quota_class": "unlimited"}
        \\]}
    ;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseModelRoutesForAllocationTest, .{json});
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
    defer freeNamedAgentSlice(allocator, cfg.agents);
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
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("ok", cfg.agents[0].name);
}

test "system_prompt absolute file path loads file content" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const prompt_content = "You are a helpful coding assistant from file.";
    try tmp.dir.writeFile(.{ .sub_path = "prompt.md", .data = prompt_content });

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const prompt_path = try std.fmt.allocPrint(allocator, "{s}{c}prompt.md", .{ base, std.fs.path.sep });
    defer allocator.free(prompt_path);
    const prompt_path_json = try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .string = prompt_path }, .{});
    defer allocator.free(prompt_path_json);

    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"agents\": {{\"list\": [{{\"name\": \"file_agent\", \"provider\": \"openai\", \"model\": \"gpt-4\", \"system_prompt\": {s}}}]}}}}",
        .{prompt_path_json},
    );
    defer allocator.free(json);

    var cfg = Config{ .workspace_dir = base, .config_path = base, .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);

    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings(prompt_content, cfg.agents[0].system_prompt.?);
    try std.testing.expectEqualStrings(prompt_path, cfg.agents[0].system_prompt_path.?);
}

test "system_prompt missing file falls back to raw string and keeps remaining fields" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const missing_path = try std.fmt.allocPrint(allocator, "{s}{c}missing-prompt.md", .{ base, std.fs.path.sep });
    defer allocator.free(missing_path);
    const missing_path_json = try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .string = missing_path }, .{});
    defer allocator.free(missing_path_json);

    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"agents\": {{\"list\": [{{\"name\": \"full\", \"provider\": \"p\", \"model\": \"m\", \"system_prompt\": {s}, \"temperature\": 0.5, \"max_depth\": 7}}]}}}}",
        .{missing_path_json},
    );
    defer allocator.free(json);

    var cfg = Config{ .workspace_dir = base, .config_path = base, .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);

    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings(missing_path, cfg.agents[0].system_prompt.?);
    try std.testing.expect(cfg.agents[0].system_prompt_path == null);
    try std.testing.expectEqual(@as(f64, 0.5), cfg.agents[0].temperature.?);
    try std.testing.expectEqual(@as(u32, 7), cfg.agents[0].max_depth);
}

test "system_prompt with newlines stays inline" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [
        \\  {"name": "inline", "provider": "p", "model": "m", "system_prompt": "Line one\nLine two"}
        \\]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);

    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("Line one\nLine two", cfg.agents[0].system_prompt.?);
    try std.testing.expect(cfg.agents[0].system_prompt_path == null);
}

// ── Combined: all new fields in one JSON ────────────────────────

test "json parse all new fields together" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "model_routes": [{"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "cheap", "quota_class": "normal"}],
        \\  "agents": {"list": [{"name": "helper", "provider": "anthropic", "model": "claude-haiku-3.5"}]},
        \\  "autonomy": {"allowed_commands": ["ls"]},
        \\  "gateway": {"paired_tokens": ["tok-1"]},
        \\  "browser": {"allowed_domains": ["example.com"]}
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqual(config_types.ModelRouteCostClass.cheap, cfg.model_routes[0].cost_class);
    try std.testing.expectEqual(config_types.ModelRouteQuotaClass.normal, cfg.model_routes[0].quota_class);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.autonomy.allowed_commands.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.gateway.paired_tokens.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.browser.allowed_domains.len);
    // Cleanup
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
    freeNamedAgentSlice(allocator, cfg.agents);
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
    try std.testing.expectEqualStrings("anthropic", cfg.default_provider);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.default_model.?);
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
}

test "parse agents.defaults.model.primary custom provider supports versioned path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"agents":{"defaults":{"model":{"primary":"custom:https://api.example.com/openai/v2/minimaxai/minimax-m2.1"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("custom:https://api.example.com/openai/v2", cfg.default_provider);
    try std.testing.expectEqualStrings("minimaxai/minimax-m2.1", cfg.default_model.?);
}

test "parse legacy default_provider with model-only primary preserves model" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"default_provider":"openai","agents":{"defaults":{"model":{"primary":"gpt-5.2"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.legacy_default_provider_detected);
    try std.testing.expectEqualStrings("openai", cfg.default_provider);
    try std.testing.expectEqualStrings("gpt-5.2", cfg.default_model.?);
}

// verify that workspace override field (with backslashes) does not
// crash parsing and the default model is still picked up.
test "parse with workspace override" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{
        \\  "workspace": "C:\\Users\\menger\\Desktop\\myspace",
        \\  "agents": {"defaults": {"model": {"primary": "glm/glm-4.7"}}}
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("glm", cfg.default_provider);
    try std.testing.expectEqualStrings("glm-4.7", cfg.default_model.?);
    // workspace_dir_override should be preserved as-is from JSON
    try std.testing.expect(cfg.workspace_dir_override != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg.workspace_dir_override.?, "Users") != null);
}

// roundtrip save/load should retain model and workspace override
// and produce valid JSON that can be parsed back.
test "save and load roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    // some settings
    cfg.default_provider = try allocator.dupe(u8, "glm");
    cfg.default_model = try allocator.dupe(u8, "glm-4.7");
    cfg.workspace_dir_override = try allocator.dupe(u8, "C:\\Users\\menger\\Desktop\\myspace");
    cfg.agent.vision_disabled_models = &.{ "router/text-only", "router/backup-text" };
    cfg.agent.auto_disable_vision_on_error = false;

    try cfg.save();

    // load back by reading and parsing the saved file
    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 1024 * 64);

    var cfg2 = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    try cfg2.parseJson(content);

    try std.testing.expectEqualStrings("glm", cfg2.default_provider);
    try std.testing.expectEqualStrings("glm-4.7", cfg2.default_model.?);
    try std.testing.expect(cfg2.workspace_dir_override != null);
    try std.testing.expectEqual(@as(usize, 2), cfg2.agent.vision_disabled_models.len);
    try std.testing.expectEqualStrings("router/text-only", cfg2.agent.vision_disabled_models[0]);
    try std.testing.expect(!cfg2.agent.auto_disable_vision_on_error);
}

test "save preserves file-backed system_prompt path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}{c}config.json", .{ base, std.fs.path.sep });
    defer allocator.free(config_path);
    const prompt_path = try std.fmt.allocPrint(allocator, "{s}{c}prompt.md", .{ base, std.fs.path.sep });
    defer allocator.free(prompt_path);
    const prompt_content = "Prompt content that must stay in the file.";

    try tmp.dir.writeFile(.{ .sub_path = "prompt.md", .data = prompt_content });

    const prompt_path_json = try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .string = prompt_path }, .{});
    defer allocator.free(prompt_path_json);
    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"agents\": {{\"list\": [{{\"name\": \"file_agent\", \"provider\": \"openai\", \"model\": \"gpt-4\", \"system_prompt\": {s}}}]}}}}",
        .{prompt_path_json},
    );
    defer allocator.free(json);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const raw = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(raw);

    try std.testing.expect(std.mem.indexOf(u8, raw, prompt_content) == null);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(raw);
    try std.testing.expectEqual(@as(usize, 1), loaded.agents.len);
    try std.testing.expectEqualStrings(prompt_content, loaded.agents[0].system_prompt.?);
    try std.testing.expectEqualStrings(prompt_path, loaded.agents[0].system_prompt_path.?);
}

test "parse agents.list with model object" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"name": "res", "provider": "anthropic", "model": {"primary": "claude-opus-4"}}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.agents[0].model);
}

test "parse agents.list with id field" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"id": "researcher", "provider": "anthropic", "model": "claude-sonnet-4"}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("researcher", cfg.agents[0].name);
}

test "parse agents.list primary model ref without provider field" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"id": "coder", "model": {"primary": "ollama/qwen3.5:cloud"}}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("coder", cfg.agents[0].name);
    try std.testing.expectEqualStrings("ollama", cfg.agents[0].provider);
    try std.testing.expectEqualStrings("qwen3.5:cloud", cfg.agents[0].model);
}

test "parse agents.list with workspace_path" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": {"list": [{"name": "coder", "provider": "openai", "model": "gpt-5.2", "workspace_path": "agents/coder"}]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);

    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("agents/coder", cfg.agents[0].workspace_path.?);
}

test "resolveAgentWorkspace resolves relative path against config directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);
    const expected_workspace = try std.fs.path.join(allocator, &.{ base, "agents", "coder" });
    defer allocator.free(expected_workspace);

    const agents = [_]NamedAgentConfig{.{
        .name = "coder",
        .provider = "openai",
        .model = "gpt-5.2",
        .workspace_path = "agents/coder",
    }};
    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
        .agents = &agents,
    };

    const resolved = try cfg.resolveAgentWorkspace(allocator, "coder");
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(expected_workspace, resolved);
}

test "scaffoldAgentWorkspace leaves markdown memory empty" {
    const allocator = std.testing.allocator;
    const markdown = @import("memory/engines/markdown.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const workspace = try std.fs.path.join(allocator, &.{ base, "agents", "writer" });
    defer allocator.free(workspace);

    try Config.scaffoldAgentWorkspace(allocator, workspace);

    var mem = try markdown.MarkdownMemory.init(allocator, workspace);
    defer mem.deinit();

    const entries = try mem.memory().list(allocator, null, null);
    defer @import("memory/root.zig").freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "parse agents object-of-objects shape" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "agents": {
        \\    "defaults": {"model": {"primary": "anthropic/claude-opus-4"}},
        \\    "coder": {"provider": "openrouter", "model": "openai/gpt-4.1-mini", "temperature": 0.2},
        \\    "researcher": {"provider": "anthropic", "model": {"primary": "claude-sonnet-4"}, "max_depth": 5}
        \\  }
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqualStrings("anthropic", cfg.default_provider);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.default_model.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.agents.len);
    try std.testing.expectEqualStrings("coder", cfg.agents[0].name);
    try std.testing.expectEqualStrings("openrouter", cfg.agents[0].provider);
    try std.testing.expectEqualStrings("openai/gpt-4.1-mini", cfg.agents[0].model);
    try std.testing.expectEqual(@as(f64, 0.2), cfg.agents[0].temperature.?);
    try std.testing.expectEqualStrings("researcher", cfg.agents[1].name);
    try std.testing.expectEqualStrings("anthropic", cfg.agents[1].provider);
    try std.testing.expectEqualStrings("claude-sonnet-4", cfg.agents[1].model);
    try std.testing.expectEqual(@as(u32, 5), cfg.agents[1].max_depth);
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
}

test "parse agents object-of-objects primary model ref without provider" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "agents": {
        \\    "defaults": {"model": {"primary": "anthropic/claude-opus-4"}},
        \\    "coder": {"model": {"primary": "ollama/qwen3.5:cloud"}}
        \\  }
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    defer freeNamedAgentSlice(allocator, cfg.agents);
    try std.testing.expectEqualStrings("anthropic", cfg.default_provider);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.default_model.?);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("coder", cfg.agents[0].name);
    try std.testing.expectEqualStrings("ollama", cfg.agents[0].provider);
    try std.testing.expectEqualStrings("qwen3.5:cloud", cfg.agents[0].model);
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
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
    try std.testing.expect(cfg.default_model == null);
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
            try std.testing.expectEqualStrings("stdio", s.transport);
            try std.testing.expectEqualStrings("npx", s.command);
            try std.testing.expectEqual(@as(usize, 3), s.args.len);
            try std.testing.expectEqualStrings("-y", s.args[0]);
        }
        if (std.mem.eql(u8, s.name, "git")) {
            found_git = true;
            try std.testing.expectEqualStrings("stdio", s.transport);
            try std.testing.expectEqualStrings("mcp-server-git", s.command);
            try std.testing.expectEqual(@as(usize, 0), s.args.len);
        }
    }
    try std.testing.expect(found_fs);
    try std.testing.expect(found_git);
    // Cleanup
    for (cfg.mcp_servers) |s| {
        allocator.free(s.name);
        allocator.free(s.transport);
        allocator.free(s.command);
        if (s.url) |u| allocator.free(u);
        for (s.args) |a| allocator.free(a);
        allocator.free(s.args);
        for (s.headers) |h| {
            allocator.free(h.key);
            allocator.free(h.value);
        }
        allocator.free(s.headers);
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
    allocator.free(s.transport);
    allocator.free(s.command);
    if (s.url) |u| allocator.free(u);
    for (s.args) |a| allocator.free(a);
    allocator.free(s.args);
    for (s.env) |e| {
        allocator.free(e.key);
        allocator.free(e.value);
    }
    allocator.free(s.env);
    for (s.headers) |h| {
        allocator.free(h.key);
        allocator.free(h.value);
    }
    allocator.free(s.headers);
    allocator.free(cfg.mcp_servers);
}

test "json parse mcp_servers http transport" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "remote": {
        \\    "transport": "http",
        \\    "url": "https://mcp.example.com/rpc",
        \\    "timeout_ms": 2500,
        \\    "headers": {"Authorization": "Bearer test-token"}
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.mcp_servers.len);
    const s = cfg.mcp_servers[0];
    try std.testing.expectEqualStrings("remote", s.name);
    try std.testing.expectEqualStrings("http", s.transport);
    try std.testing.expectEqualStrings("", s.command);
    try std.testing.expectEqualStrings("https://mcp.example.com/rpc", s.url.?);
    try std.testing.expectEqual(@as(u32, 2500), s.timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), s.headers.len);
    try std.testing.expectEqualStrings("Authorization", s.headers[0].key);
    try std.testing.expectEqualStrings("Bearer test-token", s.headers[0].value);

    allocator.free(s.name);
    allocator.free(s.transport);
    allocator.free(s.command);
    if (s.url) |u| allocator.free(u);
    for (s.args) |a| allocator.free(a);
    allocator.free(s.args);
    for (s.env) |e| {
        allocator.free(e.key);
        allocator.free(e.value);
    }
    allocator.free(s.env);
    for (s.headers) |h| {
        allocator.free(h.key);
        allocator.free(h.value);
    }
    allocator.free(s.headers);
    allocator.free(cfg.mcp_servers);
}

test "json parse mcp_servers infers http transport from url" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "remote": {
        \\    "url": "https://mcp.example.com/rpc",
        \\    "timeout_ms": 2500,
        \\    "headers": {"Authorization": "Bearer test-token"}
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.mcp_servers.len);
    const s = cfg.mcp_servers[0];
    try std.testing.expectEqualStrings("remote", s.name);
    try std.testing.expectEqualStrings("http", s.transport);
    try std.testing.expectEqualStrings("", s.command);
    try std.testing.expectEqualStrings("https://mcp.example.com/rpc", s.url.?);
    try std.testing.expectEqual(@as(u32, 2500), s.timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), s.headers.len);
    try std.testing.expectEqualStrings("Authorization", s.headers[0].key);
    try std.testing.expectEqualStrings("Bearer test-token", s.headers[0].value);

    allocator.free(s.name);
    allocator.free(s.transport);
    allocator.free(s.command);
    if (s.url) |u| allocator.free(u);
    for (s.args) |a| allocator.free(a);
    allocator.free(s.args);
    for (s.env) |e| {
        allocator.free(e.key);
        allocator.free(e.value);
    }
    allocator.free(s.env);
    for (s.headers) |h| {
        allocator.free(h.key);
        allocator.free(h.value);
    }
    allocator.free(s.headers);
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
        if (e.user_agent) |ua| allocator.free(ua);
    }
    allocator.free(cfg.providers);
}

test "json parse providers section accepts object api_key" {
    const allocator = std.testing.allocator;
    const json =
        \\{"models":{"providers":{"vertex":{"api_key":{"type":"service_account","project_id":"proj-obj","client_email":"svc@proj-obj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.providers.len);
    const key = cfg.getProviderKey("vertex") orelse return error.TestExpectedEqual;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, key, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("service_account", obj.get("type").?.string);
    try std.testing.expectEqualStrings("proj-obj", obj.get("project_id").?.string);
    try std.testing.expectEqualStrings("svc@proj-obj.iam.gserviceaccount.com", obj.get("client_email").?.string);

    for (cfg.providers) |e| {
        allocator.free(e.name);
        if (e.api_key) |k| allocator.free(k);
        if (e.base_url) |b| allocator.free(b);
        if (e.user_agent) |ua| allocator.free(ua);
    }
    allocator.free(cfg.providers);
}

test "save writes provider native_tools when false" {
    if (!comptime @hasField(ProviderEntry, "native_tools")) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.providers = &.{
        .{
            .name = "groq",
            .api_key = "gsk_test",
            .native_tools = false,
            .user_agent = "nullclaw-test/1.0",
        },
    };

    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"native_tools\": false") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"user_agent\": \"nullclaw-test/1.0\"") != null);
}

test "save escapes provider string fields" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.secrets.encrypt = false;
    cfg.providers = &.{
        .{
            .name = "openai",
            .api_key = "sk-\"quoted\"",
            .base_url = "https://api.example.com/v1/\"quoted\"",
            .user_agent = "nullclaw \"agent\"",
        },
    };

    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const models = parsed.value.object.get("models").?.object;
    const providers = models.get("providers").?.object;
    const openai = providers.get("openai").?.object;

    try std.testing.expectEqualStrings("sk-\"quoted\"", openai.get("api_key").?.string);
    try std.testing.expectEqualStrings("https://api.example.com/v1/\"quoted\"", openai.get("base_url").?.string);
    try std.testing.expectEqualStrings("nullclaw \"agent\"", openai.get("user_agent").?.string);
}

test "save encrypts persisted api keys and parse decrypts them" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    var cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };
    cfg.providers = &.{
        .{
            .name = "openrouter",
            .api_key = "sk-or-secret",
        },
    };
    cfg.reliability.api_keys = &.{ "rel-key-a", "rel-key-b" };
    cfg.model_routes = &.{
        .{
            .hint = "fast",
            .provider = "groq",
            .model = "llama-3.3-70b",
            .api_key = "gsk-secret",
        },
    };
    cfg.agents = &.{
        .{
            .name = "helper",
            .provider = "openrouter",
            .model = "openai/gpt-4o-mini",
            .api_key = "agent-secret",
        },
    };
    cfg.memory.search.store.qdrant_api_key = "qdrant-secret";
    cfg.memory.api.api_key = "memory-secret";
    cfg.composio.api_key = "comp-secret";

    try cfg.save();

    const file = try std.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(content);

    const secret_values = [_][]const u8{
        "sk-or-secret",
        "rel-key-a",
        "rel-key-b",
        "gsk-secret",
        "agent-secret",
        "qdrant-secret",
        "memory-secret",
        "comp-secret",
    };
    for (secret_values) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, content, secret) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, content, "\"api_key\": \"enc2:") != null);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    try std.testing.expectEqualStrings("sk-or-secret", loaded.getProviderKey("openrouter").?);
    try std.testing.expectEqualStrings("rel-key-a", loaded.reliability.api_keys[0]);
    try std.testing.expectEqualStrings("rel-key-b", loaded.reliability.api_keys[1]);
    try std.testing.expectEqualStrings("gsk-secret", loaded.model_routes[0].api_key.?);
    try std.testing.expectEqualStrings("agent-secret", loaded.agents[0].api_key.?);
    try std.testing.expectEqualStrings("qdrant-secret", loaded.memory.search.store.qdrant_api_key);
    try std.testing.expectEqualStrings("memory-secret", loaded.memory.api.api_key);
    try std.testing.expectEqualStrings("comp-secret", loaded.composio.api_key.?);
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

test "provider config lookups match canonical aliases" {
    const entries = [_]ProviderEntry{
        .{
            .name = "azure",
            .api_key = "azure-test",
            .base_url = "https://resource.openai.azure.com/openai/v1",
            .native_tools = false,
            .user_agent = "nullclaw-test/1.0",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .providers = &entries,
        .allocator = std.testing.allocator,
    };

    try std.testing.expectEqualStrings("azure-test", cfg.getProviderKey("azure-openai").?);
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", cfg.getProviderBaseUrl("azure_openai").?);
    try std.testing.expect(!cfg.getProviderNativeTools("azure-openai"));
    try std.testing.expectEqualStrings("nullclaw-test/1.0", cfg.getProviderUserAgent("azure_openai").?);
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
        \\{"agents":{"defaults":{"model":{"primary":"groq/llama-3.3-70b"}}},"models":{"providers":{"groq":{"api_key":"gsk_found"}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("gsk_found", cfg.defaultProviderKey().?);
    // Cleanup
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
    for (cfg.providers) |e| {
        allocator.free(e.name);
        if (e.api_key) |k| allocator.free(k);
        if (e.base_url) |b| allocator.free(b);
        if (e.user_agent) |ua| allocator.free(ua);
    }
    allocator.free(cfg.providers);
}

test "defaultProviderKey stays null when provider entry omits api key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json =
        \\{"agents":{"defaults":{"model":{"primary":"openrouter/anthropic/claude-sonnet-4"}}},"models":{"providers":{"openrouter":{}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.defaultProviderKey() == null);
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
        \\{"channels": {"telegram": {"accounts": {"main": {"bot_token": "123:ABC", "allow_from": ["user1"], "reply_in_private": false, "proxy": "socks5://host:1080", "status_reactions": true, "binding_commands_enabled": false, "topic_commands_enabled": false, "topic_map_command_enabled": false, "commands_menu_mode": "scoped", "reaction_emojis": {"accepted": "🟡", "running": "🔵", "done": "🟢", "failed": "🔴"}, "interactive": {"enabled": true, "ttl_secs": 42, "owner_only": false, "remove_on_click": false}}}}}}
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
    try std.testing.expect(tg.status_reactions);
    try std.testing.expect(!tg.binding_commands_enabled);
    try std.testing.expect(!tg.topic_commands_enabled);
    try std.testing.expect(!tg.topic_map_command_enabled);
    try std.testing.expect(tg.commands_menu_mode == .scoped);
    try std.testing.expectEqualStrings("🟡", tg.reaction_emojis.accepted);
    try std.testing.expectEqualStrings("🔵", tg.reaction_emojis.running);
    try std.testing.expectEqualStrings("🟢", tg.reaction_emojis.done);
    try std.testing.expectEqualStrings("🔴", tg.reaction_emojis.failed);
    try std.testing.expect(tg.interactive.enabled);
    try std.testing.expectEqual(@as(u64, 42), tg.interactive.ttl_secs);
    try std.testing.expect(!tg.interactive.owner_only);
    try std.testing.expect(!tg.interactive.remove_on_click);
    allocator.free(tg.account_id);
    allocator.free(tg.bot_token);
    for (tg.allow_from) |u| allocator.free(u);
    allocator.free(tg.allow_from);
    allocator.free(tg.proxy.?);
    allocator.free(tg.reaction_emojis.accepted);
    allocator.free(tg.reaction_emojis.running);
    allocator.free(tg.reaction_emojis.done);
    allocator.free(tg.reaction_emojis.failed);
    allocator.free(cfg.channels.telegram);
}

test "parse telegram accounts interactive defaults when omitted" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"telegram": {"accounts": {"main": {"bot_token": "123:ABC"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.telegram.len);
    try std.testing.expect(!cfg.channels.telegram[0].status_reactions);
    try std.testing.expect(cfg.channels.telegram[0].binding_commands_enabled);
    try std.testing.expect(cfg.channels.telegram[0].topic_commands_enabled);
    try std.testing.expect(cfg.channels.telegram[0].topic_map_command_enabled);
    try std.testing.expect(cfg.channels.telegram[0].commands_menu_mode == .flat);
    try std.testing.expectEqualStrings("👀", cfg.channels.telegram[0].reaction_emojis.accepted);
    const tg = cfg.channels.telegram[0];
    try std.testing.expect(!tg.interactive.enabled);
    try std.testing.expectEqual(@as(u64, 900), tg.interactive.ttl_secs);
    try std.testing.expect(tg.interactive.owner_only);
    try std.testing.expect(tg.interactive.remove_on_click);
    allocator.free(tg.account_id);
    allocator.free(tg.bot_token);
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
    try std.testing.expectEqualStrings("pairing", sc.dm_policy);
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
        \\{"channels": {"matrix": {"accounts": {"main": {"homeserver": "https://matrix.org", "access_token": "syt_abc", "room_id": "!room:matrix.org", "user_id": "@bot:matrix.org", "group_allow_from": ["@alice:matrix.org"], "dm_policy": "open", "group_policy": "open", "require_mention": true}}}}}
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
    try std.testing.expectEqualStrings("open", mc.dm_policy);
    try std.testing.expectEqualStrings("open", mc.group_policy);
    try std.testing.expect(mc.require_mention);
    try std.testing.expectEqual(@as(usize, 1), mc.group_allow_from.len);
    try std.testing.expectEqualStrings("@alice:matrix.org", mc.group_allow_from[0]);
    allocator.free(mc.account_id);
    allocator.free(mc.homeserver);
    allocator.free(mc.access_token);
    allocator.free(mc.room_id);
    allocator.free(mc.user_id.?);
    allocator.free(mc.dm_policy);
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

test "parse external channel accounts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"channels":{"external":{"accounts":{"wa-web":{"runtime_name":"whatsapp_web","transport":{"command":"nullclaw-plugin-whatsapp-web","args":["--stdio"],"env":{"TOKEN":"secret"},"timeout_ms":2500},"config":{"bridge_url":"http://127.0.0.1:3301","allow_from":["*"]}}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.external.len);
    const external_cfg = cfg.channels.external[0];
    try std.testing.expectEqualStrings("wa-web", external_cfg.account_id);
    try std.testing.expectEqualStrings("whatsapp_web", external_cfg.runtime_name);
    try std.testing.expectEqualStrings("nullclaw-plugin-whatsapp-web", external_cfg.transport.command);
    try std.testing.expectEqual(@as(usize, 1), external_cfg.transport.args.len);
    try std.testing.expectEqualStrings("--stdio", external_cfg.transport.args[0]);
    try std.testing.expectEqual(@as(usize, 1), external_cfg.transport.env.len);
    try std.testing.expectEqualStrings("TOKEN", external_cfg.transport.env[0].key);
    try std.testing.expectEqualStrings("secret", external_cfg.transport.env[0].value);
    try std.testing.expectEqual(@as(u32, 2500), external_cfg.transport.timeout_ms);
    try std.testing.expect(std.mem.indexOf(u8, external_cfg.plugin_config_json, "\"bridge_url\":\"http://127.0.0.1:3301\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, external_cfg.plugin_config_json, "\"allow_from\":[\"*\"]") != null);
}

test "parse external channel preserves invalid timeout for validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"channels":{"external":{"accounts":{"wa-web":{"runtime_name":"whatsapp_web","transport":{"command":"nullclaw-plugin-whatsapp-web","timeout_ms":0}}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    cfg.default_model = "test/model";

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.external.len);
    try std.testing.expectEqual(@as(u32, 0), cfg.channels.external[0].transport.timeout_ms);
    try std.testing.expectError(Config.ValidationError.InvalidExternalTransportTimeoutMs, cfg.validate());
}

test "parse external channel rejects timeout with wrong type" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"channels":{"external":{"accounts":{"wa-web":{"runtime_name":"whatsapp_web","transport":{"command":"nullclaw-plugin-whatsapp-web","timeout_ms":"slow"}}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    cfg.default_model = "test/model";

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.external.len);
    try std.testing.expectEqual(@as(u32, 0), cfg.channels.external[0].transport.timeout_ms);
    try std.testing.expectError(Config.ValidationError.InvalidExternalTransportTimeoutMs, cfg.validate());
}

test "parse external channel rejects scalar config at validation time" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"channels":{"external":{"accounts":{"wa-web":{"runtime_name":"whatsapp_web","transport":{"command":"nullclaw-plugin-whatsapp-web"},"config":"oops"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    cfg.default_model = "test/model";

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.external.len);
    try std.testing.expectEqualStrings("\"oops\"", cfg.channels.external[0].plugin_config_json);
    try std.testing.expectError(Config.ValidationError.InvalidExternalPluginConfig, cfg.validate());
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
        \\{"channels": {"dingtalk": {"accounts": {"main": {"client_id": "cid", "client_secret": "csec", "allow_from": ["u1"], "ai_card_template_id": "tmpl.schema", "ai_card_streaming_key": "contentStreamingKey"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.dingtalk.len);
    const dc = cfg.channels.dingtalk[0];
    try std.testing.expectEqualStrings("main", dc.account_id);
    try std.testing.expectEqualStrings("cid", dc.client_id);
    try std.testing.expectEqualStrings("csec", dc.client_secret);
    try std.testing.expectEqualStrings("tmpl.schema", dc.ai_card_template_id.?);
    try std.testing.expectEqualStrings("contentStreamingKey", dc.ai_card_streaming_key.?);
    allocator.free(dc.account_id);
    allocator.free(dc.client_id);
    allocator.free(dc.client_secret);
    allocator.free(dc.ai_card_template_id.?);
    allocator.free(dc.ai_card_streaming_key.?);
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
        \\{"channels": {"qq": {"accounts": {"qq-backup": {"app_id": "app2", "bot_token": "tok2"}, "qq-main": {"app_id": "app1", "app_secret": "sec1", "bot_token": "tok1", "receive_mode": "websocket", "group_policy": "allowlist", "allowed_groups": ["group-a", "group-b"], "allow_from": ["user-a"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.channels.qq.len);
    try std.testing.expectEqualStrings("qq-backup", cfg.channels.qq[0].account_id);
    try std.testing.expectEqualStrings("qq-main", cfg.channels.qq[1].account_id);
    try std.testing.expectEqual(config_types.QQReceiveMode.webhook, cfg.channels.qq[0].receive_mode);
    try std.testing.expectEqual(config_types.QQReceiveMode.websocket, cfg.channels.qq[1].receive_mode);
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

test "parse web accounts with auth token path and allowed origins" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"web": {"accounts": {"default": {"listen": "0.0.0.0", "port": 32123, "path": "/ws", "auth_token": "relay-token-123456", "allowed_origins": ["https://relay.nullclaw.io", "chrome-extension://abc"]}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.web.len);
    const wc = cfg.channels.web[0];
    try std.testing.expectEqualStrings("default", wc.account_id);
    try std.testing.expectEqualStrings("0.0.0.0", wc.listen);
    try std.testing.expectEqual(@as(u16, 32123), wc.port);
    try std.testing.expectEqualStrings("/ws", wc.path);
    try std.testing.expectEqualStrings("relay-token-123456", wc.auth_token.?);
    try std.testing.expectEqualStrings("pairing", wc.message_auth_mode);
    try std.testing.expectEqual(@as(usize, 2), wc.allowed_origins.len);
    try std.testing.expectEqualStrings("https://relay.nullclaw.io", wc.allowed_origins[0]);
    try std.testing.expectEqualStrings("chrome-extension://abc", wc.allowed_origins[1]);

    allocator.free(wc.account_id);
    allocator.free(wc.listen);
    allocator.free(wc.path);
    allocator.free(wc.auth_token.?);
    for (wc.allowed_origins) |origin| allocator.free(origin);
    allocator.free(wc.allowed_origins);
    allocator.free(cfg.channels.web);
}

test "parse web account with token message auth mode" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"web": {"accounts": {"default": {"listen": "127.0.0.1", "port": 32123, "path": "/ws", "auth_token": "token-mode-1234567890", "message_auth_mode": "token"}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.web.len);
    const wc = cfg.channels.web[0];
    try std.testing.expectEqualStrings("token", wc.message_auth_mode);
    try std.testing.expectEqualStrings("token-mode-1234567890", wc.auth_token.?);

    allocator.free(wc.account_id);
    allocator.free(wc.listen);
    allocator.free(wc.path);
    allocator.free(wc.auth_token.?);
    allocator.free(wc.message_auth_mode);
    allocator.free(cfg.channels.web);
}

test "parse web relay account fields" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"web": {"accounts": {"default": {"transport": "relay", "relay_url": "wss://relay.nullclaw.io/ws/agent", "relay_agent_id": "edge-1", "relay_token": "relay-token-999999", "relay_token_ttl_secs": 7200, "relay_pairing_code_ttl_secs": 180, "relay_ui_token_ttl_secs": 86400, "relay_e2e_required": true}}}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);

    try std.testing.expectEqual(@as(usize, 1), cfg.channels.web.len);
    const wc = cfg.channels.web[0];
    try std.testing.expectEqualStrings("default", wc.account_id);
    try std.testing.expectEqualStrings("relay", wc.transport);
    try std.testing.expectEqualStrings("wss://relay.nullclaw.io/ws/agent", wc.relay_url.?);
    try std.testing.expectEqualStrings("edge-1", wc.relay_agent_id);
    try std.testing.expectEqualStrings("relay-token-999999", wc.relay_token.?);
    try std.testing.expectEqual(@as(u32, 7200), wc.relay_token_ttl_secs);
    try std.testing.expectEqual(@as(u32, 180), wc.relay_pairing_code_ttl_secs);
    try std.testing.expectEqual(@as(u32, 86_400), wc.relay_ui_token_ttl_secs);
    try std.testing.expect(wc.relay_e2e_required);

    allocator.free(wc.account_id);
    allocator.free(wc.transport);
    allocator.free(wc.relay_url.?);
    allocator.free(wc.relay_agent_id);
    allocator.free(wc.relay_token.?);
    allocator.free(cfg.channels.web);
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

test "json parse reasoning_effort minimal" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "minimal"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("minimal", cfg.reasoning_effort.?);
    allocator.free(cfg.reasoning_effort.?);
}

test "json parse reasoning_effort xhigh" {
    const allocator = std.testing.allocator;
    const json =
        \\{"reasoning_effort": "xhigh"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("xhigh", cfg.reasoning_effort.?);
    allocator.free(cfg.reasoning_effort.?);
}

test "unknown foreign fields silently ignored" {
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

test "session config: parse auto_provision_direct_agents" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"auto_provision_direct_agents": true}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.session.auto_provision_direct_agents);
}

test "session config: parse claim gate settings" {
    const allocator = std.testing.allocator;
    const json =
        \\{"session": {"claim_secret": "hmac-secret", "claim_admin_secret": "admin-secret", "claim_max_attempts": 7, "claim_lockout_secs": 120}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.session.claim_secret != null);
    try std.testing.expect(cfg.session.claim_admin_secret != null);
    try std.testing.expectEqualStrings("hmac-secret", cfg.session.claim_secret.?);
    try std.testing.expectEqualStrings("admin-secret", cfg.session.claim_admin_secret.?);
    try std.testing.expectEqual(@as(u32, 7), cfg.session.claim_max_attempts);
    try std.testing.expectEqual(@as(u32, 120), cfg.session.claim_lockout_secs);
    allocator.free(cfg.session.claim_secret.?);
    allocator.free(cfg.session.claim_admin_secret.?);
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
    try std.testing.expect(!cfg.session.auto_provision_direct_agents);
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

test "save includes nostr channel when configured" {
    const allocator = std.testing.allocator;

    const tmp_path = "/tmp/nullclaw_test_nostr_save.json";

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = allocator,
    };

    const owner_pubkey = "a" ** 64;
    var ns_cfg = NostrConfig{
        .private_key = "enc2:abc",
        .owner_pubkey = owner_pubkey,
        .nak_path = "nak",
        // display_pic, lnurl, nip05, bunker_uri intentionally null
    };
    cfg.channels.nostr = &ns_cfg;

    try cfg.save();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    const file = try std.fs.openFileAbsolute(tmp_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    // Must contain nostr channel fields
    try std.testing.expect(std.mem.indexOf(u8, content, "\"nostr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"private_key\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"owner_pubkey\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"bot_pubkey\"") != null);

    // Relays array must contain at least the first default relay
    try std.testing.expect(std.mem.indexOf(u8, content, "wss://relay.damus.io") != null);

    // Optional fields that are null in this config must NOT appear in output
    try std.testing.expect(std.mem.indexOf(u8, content, "\"display_pic\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"lnurl\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "nip05") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "bunker_uri") == null);

    // Must NOT contain the runtime-only config_dir field
    try std.testing.expect(std.mem.indexOf(u8, content, "config_dir") == null);
}

test "save includes dm_relays in nostr section" {
    const allocator = std.testing.allocator;
    const tmp_path = "/tmp/nullclaw_test_dm_relays_save.json";

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = allocator,
    };
    var ns_cfg = config_types.NostrConfig{
        .private_key = "enc2:abc",
        .owner_pubkey = "a" ** 64,
        .dm_relays = &.{ "wss://auth.nostr1.com", "wss://relay.damus.io" },
    };
    cfg.channels.nostr = &ns_cfg;

    try cfg.save();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    const file = try std.fs.openFileAbsolute(tmp_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"dm_relays\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "auth.nostr1.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "config_dir") == null);
}

test "dm_relays round-trips through save and load" {
    const allocator = std.testing.allocator;
    const tmp_path = "/tmp/nullclaw_test_dm_relays_roundtrip.json";

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = allocator,
    };
    var ns_cfg = config_types.NostrConfig{
        .private_key = "enc2:abc",
        .owner_pubkey = "a" ** 64,
        .dm_relays = &.{ "wss://auth.nostr1.com", "wss://relay.damus.io" },
    };
    cfg.channels.nostr = &ns_cfg;

    try cfg.save();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    const file = try std.fs.openFileAbsolute(tmp_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    // Use an arena so all allocations made by parseJson are freed in bulk.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(content);

    const ns = loaded.channels.nostr.?;
    try std.testing.expectEqual(@as(usize, 2), ns.dm_relays.len);
    try std.testing.expectEqualStrings("wss://auth.nostr1.com", ns.dm_relays[0]);
    try std.testing.expectEqualStrings("wss://relay.damus.io", ns.dm_relays[1]);
}

test "nostr display_name with special chars round-trips correctly" {
    const allocator = std.testing.allocator;
    const tmp_path = "/tmp/nullclaw_test_nostr_escape.json";

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = allocator,
    };
    var ns_cfg = config_types.NostrConfig{
        .private_key = "enc2:abc",
        .owner_pubkey = "a" ** 64,
        .display_name = "Bot \"NullClaw\" v1",
        .about = "Line1\nLine2",
    };
    cfg.channels.nostr = &ns_cfg;

    try cfg.save();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    const file_content = try std.fs.openFileAbsolute(tmp_path, .{});
    defer file_content.close();
    const raw = try file_content.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(raw);

    // Verify the escaping is present in the raw JSON
    try std.testing.expect(std.mem.indexOf(u8, raw, "\\\"NullClaw\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "\\n") != null);

    // Round-trip: parse back and verify the original strings are recovered
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var loaded = Config{
        .workspace_dir = "/tmp",
        .config_path = tmp_path,
        .allocator = arena.allocator(),
    };
    try loaded.parseJson(raw);

    const ns = loaded.channels.nostr.?;
    try std.testing.expectEqualStrings("Bot \"NullClaw\" v1", ns.display_name);
    try std.testing.expectEqualStrings("Line1\nLine2", ns.about);
}

test "parse nostr channel from JSON" {
    const allocator = std.testing.allocator;
    const json =
        \\{"channels": {"nostr": {
        \\  "private_key": "enc2:deadbeef",
        \\  "owner_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "relays": ["wss://relay.damus.io", "wss://nos.lol"],
        \\  "dm_allowed_pubkeys": ["*"],
        \\  "display_name": "TestBot",
        \\  "about": "A test bot",
        \\  "nak_path": "/usr/local/bin/nak",
        \\  "bunker_uri": null,
        \\  "display_pic": null,
        \\  "lnurl": null,
        \\  "nip05": null
        \\}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.channels.nostr != null);
    const ns = cfg.channels.nostr.?;
    defer allocator.destroy(ns);
    defer allocator.free(ns.private_key);
    defer allocator.free(ns.owner_pubkey);
    defer {
        for (ns.relays) |r| allocator.free(r);
        allocator.free(ns.relays);
    }
    defer {
        for (ns.dm_allowed_pubkeys) |p| allocator.free(p);
        allocator.free(ns.dm_allowed_pubkeys);
    }
    defer allocator.free(ns.display_name);
    defer allocator.free(ns.about);
    defer allocator.free(ns.nak_path);
    try std.testing.expectEqualStrings("enc2:deadbeef", ns.private_key);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ns.owner_pubkey);
    try std.testing.expectEqual(@as(usize, 2), ns.relays.len);
    try std.testing.expectEqualStrings("wss://relay.damus.io", ns.relays[0]);
    try std.testing.expectEqualStrings("wss://nos.lol", ns.relays[1]);
    try std.testing.expectEqual(@as(usize, 1), ns.dm_allowed_pubkeys.len);
    try std.testing.expectEqualStrings("*", ns.dm_allowed_pubkeys[0]);
    try std.testing.expectEqualStrings("TestBot", ns.display_name);
    try std.testing.expectEqualStrings("/usr/local/bin/nak", ns.nak_path);
    // config_dir defaults to "." when not loaded via load() (no config_path dirname backfill in tests)
    try std.testing.expectEqualStrings(".", ns.config_dir);
}

test "parse nostr channel missing required fields yields null" {
    const allocator = std.testing.allocator;

    // Required fields are JSON null (not strings) — no allocation occurs, result must be null
    const json_null_fields =
        \\{"channels": {"nostr": {"private_key": null, "owner_pubkey": null}}}
    ;
    var cfg1 = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg1.parseJson(json_null_fields);
    try std.testing.expect(cfg1.channels.nostr == null);

    // Both required fields absent from the JSON object entirely — result must also be null
    const json_absent =
        \\{"channels": {"nostr": {}}}
    ;
    var cfg2 = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg2.parseJson(json_absent);
    try std.testing.expect(cfg2.channels.nostr == null);

    // Asymmetric: private_key present as string, owner_pubkey absent.
    // The parser allocates private_key then discards the local struct when the guard fails.
    // Use an arena so the partial allocation is freed in bulk rather than leaking
    // under std.testing.allocator (same pattern as production Config.load()).
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const json_one_field =
        \\{"channels": {"nostr": {"private_key": "enc2:abc"}}}
    ;
    var cfg3 = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = arena.allocator() };
    try cfg3.parseJson(json_one_field);
    try std.testing.expect(cfg3.channels.nostr == null);
}

test "NostrConfig dm_relays default is auth.nostr1.com" {
    const cfg = config_types.NostrConfig{
        .private_key = "enc2:x",
        .owner_pubkey = "a" ** 64,
    };
    try std.testing.expectEqual(@as(usize, 1), cfg.dm_relays.len);
    try std.testing.expectEqualStrings("wss://auth.nostr1.com", cfg.dm_relays[0]);
}
