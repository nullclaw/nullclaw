//! CLI entry point — single-message and interactive REPL modes.
//!
//! Extracted from agent/root.zig. Contains `run()` (the main entry point
//! for `nullclaw agent`) and the streaming stdout callback.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const log = std.log.scoped(.agent);
const Config = @import("../config.zig").Config;
const config_types = @import("../config_types.zig");
const agent_routing = @import("../agent_routing.zig");
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const http_util = @import("../http_util.zig");
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const bootstrap_mod = @import("../bootstrap/root.zig");
const observability = @import("../observability.zig");
const Observer = observability.Observer;
const ObserverEvent = observability.ObserverEvent;
const subagent_mod = @import("../subagent.zig");
const subagent_runner = @import("../subagent_runner.zig");
const bus_mod = @import("../bus.zig");
const cli_mod = @import("../channels/cli.zig");
const inbound_debounce = @import("../inbound_debounce.zig");
const security = @import("../security/policy.zig");
const codex_support = @import("../codex_support.zig");
const onboard = @import("../onboard.zig");
const streaming = @import("../streaming.zig");
const verbose = @import("../verbose.zig");
const redaction = @import("../redaction.zig");

const Agent = @import("root.zig").Agent;
const turn_persistence = @import("turn_persistence.zig");
const commands = @import("commands.zig");
const cost_mod = @import("../cost.zig");

const CliStreamCtx = struct {
    sink: streaming.Sink,
    emitted_text: bool = false,
    filter: streaming.TagFilter = undefined,
    /// When true, the streaming callback drops live token chunks; the full
    /// reply is printed once at end-of-turn so it can pass through
    /// `redactor.unredact()` and the user sees originals instead of
    /// `[EMAIL_N]`/`[PHONE_N]`/etc. Provider streaming still happens under
    /// the hood (lower TTFB, request can still be cancelled), only the live
    /// terminal render is suppressed.
    suppress_live: bool = false,
    think_filter: streaming.ThinkPassthroughFilter = undefined,
};

const CliProviderContext = struct {
    holder: providers.ProviderHolder,
    owned_api_key: ?[]u8 = null,

    fn deinit(self: *CliProviderContext, allocator: std.mem.Allocator) void {
        self.holder.deinit();
        if (self.owned_api_key) |api_key| {
            allocator.free(api_key);
            self.owned_api_key = null;
        }
    }
};

fn shouldPrintTurnResponse(supports_streaming: bool, emitted_text: bool) bool {
    return !supports_streaming or !emitted_text;
}

fn shouldSuppressLiveForRedaction(redactor: ?*redaction.Redactor, content: []const u8) bool {
    const r = redactor orelse return false;
    return r.wouldRehydrate() or (r.config.record_originals and r.wouldRedact(content));
}

fn shouldPrintSeparateUsage(supports_streaming: bool, emitted_text: bool) bool {
    // Agent.turn already embeds usage in the returned final text. The CLI only
    // needs a separate usage line when streaming printed that final text live.
    return supports_streaming and emitted_text;
}

fn maybePrintUsage(w: anytype, agent: *const Agent) !void {
    if (agent.usage_mode == .off) return;
    const usage = agent.last_turn_usage;
    const cost = @import("../cost.zig").TokenUsage.fromProviders(agent.model_name, usage).cost();

    switch (agent.usage_mode) {
        .tokens => try w.print("Usage: {d} tokens\n", .{usage.total_tokens}),
        .cost => try w.print("Usage: ${d:.4}\n", .{cost}),
        .full => {
            const total_bytes = agent.last_system_prompt_bytes + agent.last_history_bytes;
            const sys = if (total_bytes > 0)
                @as(u32, @intCast((@as(u64, usage.prompt_tokens) * agent.last_system_prompt_bytes) / total_bytes))
            else
                0;
            const usr = usage.prompt_tokens - sys;
            try w.print("Usage: prompt={d} (rag=~{d} + query=~{d}) completion={d} total={d} (${d:.4}) | Session: ${d:.4}\n", .{
                usage.prompt_tokens,
                sys,
                usr,
                usage.completion_tokens,
                usage.total_tokens,
                cost,
                agent.total_cost_usd,
            });
        },
        .off => unreachable,
    }
}

fn cliUsageRecordCallback(ctx: *anyopaque, record: Agent.UsageRecord) void {
    const tracker: *cost_mod.CostTracker = @ptrCast(@alignCast(ctx));
    const usage = cost_mod.TokenUsage.fromProviders(record.model, record.usage);
    tracker.recordUsage(usage) catch |err| {
        log.err("Failed to record usage in CostTracker: {s}", .{@errorName(err)});
    };
}

fn persistCliTurn(agent: *const Agent, content: []const u8, response: []const u8) void {
    const store = agent.session_store orelse return;
    const session_key = agent.memory_session_id orelse return;

    const persisted_content = if (agent.redactor) |r|
        r.redact(agent.allocator, content) catch null
    else
        null;
    defer if (persisted_content) |text| agent.allocator.free(text);

    const persisted_response = if (agent.redactor) |r|
        r.redact(agent.allocator, response) catch null
    else
        null;
    defer if (persisted_response) |text| agent.allocator.free(text);

    turn_persistence.persistTurn(store, .{
        .history = agent.history.items,
        .total_tokens = agent.total_tokens,
    }, session_key, persisted_content orelse content, persisted_response orelse response);
}

fn printPendingSubagentNotices(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    manager: *subagent_mod.SubagentManager,
    session_key: ?[]const u8,
) !void {
    const notices = try manager.takeCompletionNoticesForSession(allocator, session_key);
    defer subagent_mod.SubagentManager.freeCompletionNotices(allocator, notices);
    for (notices) |notice| {
        try writer.print("\n{s}\n\n", .{notice.content});
    }
    if (notices.len > 0) {
        try writer.flush();
    }
}

fn cliStreamSinkCallback(ctx_ptr: *anyopaque, event: streaming.Event) void {
    if (event.stage != .chunk or event.text.len == 0) return;
    const stream_ctx: *CliStreamCtx = @ptrCast(@alignCast(ctx_ptr));

    // Redactor-aware: if live render is suppressed we also leave
    // `emitted_text` false so shouldPrintTurnResponse() still fires the final
    // print path, where the full reply is unredacted before display.
    if (stream_ctx.suppress_live) return;

    stream_ctx.emitted_text = true;

    // In tests, stdout is used by Zig's test runner protocol (`--listen`).
    if (builtin.is_test) return;

    var buf: [4096]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&buf);
    const wr = &bw.interface;
    wr.print("{s}", .{event.text}) catch {};
    wr.flush() catch {};
}

fn makeCliStreamSink(raw_sink: streaming.Sink, filter: *streaming.TagFilter) streaming.Sink {
    filter.* = streaming.TagFilter.init(raw_sink);
    return filter.sink();
}

/// Like makeCliStreamSink but passes <think> blocks through with a header/footer
/// instead of stripping them. Used when reasoning_mode == .stream.
fn makeCliStreamSinkPassthrough(raw_sink: streaming.Sink, filter: *streaming.ThinkPassthroughFilter) streaming.Sink {
    filter.* = streaming.ThinkPassthroughFilter.init(raw_sink);
    return filter.sink();
}

/// Streaming callback that forwards provider chunks into unified stream sink events.
fn cliStreamCallback(ctx_ptr: *anyopaque, chunk: providers.StreamChunk) void {
    const stream_ctx: *CliStreamCtx = @ptrCast(@alignCast(ctx_ptr));
    streaming.forwardProviderChunk(stream_ctx.sink, chunk);
}

fn hasOpenAiCodexCredential(allocator: std.mem.Allocator) bool {
    return codex_support.hasOpenAiCodexCredential(allocator);
}

fn shouldPrintOpenAiCodexHint(default_provider: []const u8, has_codex_credential: bool) bool {
    return has_codex_credential and !std.mem.eql(u8, default_provider, "openai-codex");
}

fn maybePrintAllProvidersFailedHint(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    default_provider: []const u8,
) !void {
    if (!shouldPrintOpenAiCodexHint(default_provider, hasOpenAiCodexCredential(allocator))) return;
    try w.print(
        "Hint: openai-codex is authenticated, but current provider is {s}. Set \"agents.defaults.model.primary\": \"openai-codex/{s}\" or run with --provider openai-codex --model {s}.\n",
        .{ default_provider, codex_support.DEFAULT_CODEX_MODEL, codex_support.DEFAULT_CODEX_MODEL },
    );
}

fn providerFailureLooksQuotaConstrained(detail: []const u8) bool {
    return providers.reliable.isRateLimited(detail) or
        std.ascii.indexOfIgnoreCase(detail, "quota") != null or
        std.ascii.indexOfIgnoreCase(detail, "credit") != null or
        std.ascii.indexOfIgnoreCase(detail, "billing") != null or
        std.ascii.indexOfIgnoreCase(detail, "out of credits") != null;
}

fn writeRateLimitHint(w: *std.Io.Writer, default_provider: []const u8) !void {
    try w.print(
        "Hint: {s} appears rate-limited or quota-constrained. Low-quota coding plans often reject tool-heavy agent loops even when plain chat still works.\n",
        .{default_provider},
    );
    try w.writeAll(
        "Hint: keep \"reliability.provider_retries\" low, raise \"reliability.provider_backoff_ms\", and add \"reliability.fallback_providers\" or \"reliability.api_keys\" if you have alternatives.\n",
    );
    try w.writeAll(
        "Hint: use `nullclaw agent --verbose` for foreground runs. In service mode, inspect `~/.nullclaw/logs/daemon.stdout.log` and `~/.nullclaw/logs/daemon.stderr.log`.\n",
    );
}

fn maybePrintRateLimitHint(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    default_provider: []const u8,
) !void {
    const detail = providers.snapshotLastApiErrorDetail(allocator) catch null;
    if (detail) |msg| {
        defer allocator.free(msg);
        if (!providerFailureLooksQuotaConstrained(msg)) return;
        try writeRateLimitHint(w, default_provider);
    }
}

fn maybePrintLastProviderApiError(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
) !void {
    const detail = providers.snapshotLastApiErrorDetail(allocator) catch null;
    if (detail) |msg| {
        defer allocator.free(msg);
        try w.print("Last provider error: {s}\n", .{msg});
    }
}

const ParsedAgentArgs = struct {
    message_arg: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    provider_override: ?[]const u8 = null,
    model_override: ?[]const u8 = null,
    temperature_override: ?f64 = null,
    agent_name: ?[]const u8 = null,
    workspace_override: ?[]const u8 = null,
    skill_name: ?[]const u8 = null,
    origin_channel: ?[]const u8 = null,
    origin_account_id: ?[]const u8 = null,
    verbose: bool = false,
};

const AgentArgParseResult = union(enum) {
    ok: ParsedAgentArgs,
    missing_value: []const u8,
    invalid_temperature: []const u8,
};

fn parseAgentArgs(args: []const []const u8) AgentArgParseResult {
    var parsed = ParsedAgentArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--message")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.message_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--session")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.session_id = args[i];
        } else if (std.mem.eql(u8, arg, "--provider")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.provider_override = args[i];
        } else if (std.mem.eql(u8, arg, "--model")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.model_override = args[i];
        } else if (std.mem.eql(u8, arg, "--temperature")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            const temp = std.fmt.parseFloat(f64, args[i]) catch return .{ .invalid_temperature = args[i] };
            parsed.temperature_override = temp;
        } else if (std.mem.eql(u8, arg, "--agent")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.agent_name = args[i];
        } else if (std.mem.eql(u8, arg, "--workspace")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.workspace_override = args[i];
        } else if (std.mem.eql(u8, arg, "--skill")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.skill_name = args[i];
        } else if (std.mem.eql(u8, arg, "--origin-channel")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.origin_channel = args[i];
        } else if (std.mem.eql(u8, arg, "--origin-account-id")) {
            if (i + 1 >= args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.origin_account_id = args[i];
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            parsed.verbose = true;
        }
    }
    return .{ .ok = parsed };
}

fn findNamedAgentProfile(agents: []const config_types.NamedAgentConfig, requested_name: []const u8) ?config_types.NamedAgentConfig {
    for (agents) |agent_cfg| {
        if (std.mem.eql(u8, agent_cfg.name, requested_name)) return agent_cfg;

        var requested_buf: [64]u8 = undefined;
        var agent_buf: [64]u8 = undefined;
        const normalized_requested = agent_routing.normalizeId(&requested_buf, requested_name);
        const normalized_agent = agent_routing.normalizeId(&agent_buf, agent_cfg.name);
        if (std.mem.eql(u8, normalized_requested, normalized_agent)) return agent_cfg;
    }
    return null;
}

fn profileMemoryNamespace(allocator: std.mem.Allocator, profile_name: []const u8) ![]u8 {
    var normalized_buf: [64]u8 = undefined;
    const normalized_name = agent_routing.normalizeId(&normalized_buf, profile_name);
    return std.fmt.allocPrint(allocator, "agent:{s}", .{normalized_name});
}

fn resolveProfileProvider(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    profile: config_types.NamedAgentConfig,
) !CliProviderContext {
    var owned_api_key: ?[]u8 = null;
    errdefer if (owned_api_key) |api_key| allocator.free(api_key);

    const provider_api_key = profile.api_key orelse blk: {
        owned_api_key = providers.resolveApiKeyFromConfig(
            allocator,
            profile.provider,
            cfg.providers,
        ) catch null;
        break :blk owned_api_key;
    };

    const holder = providers.holderFromConfig(
        allocator,
        cfg,
        profile.provider,
        provider_api_key,
    );
    return .{
        .holder = holder,
        .owned_api_key = owned_api_key,
    };
}

/// Resolve the provider only after any holder-backed override reaches stable storage.
fn activeCliProvider(
    provider_ctx: ?*CliProviderContext,
    runtime_provider: ?*providers.runtime_bundle.RuntimeProviderBundle,
) Provider {
    return if (provider_ctx) |ctx| ctx.holder.provider() else runtime_provider.?.provider();
}

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var cfg = Config.load(allocator) catch {
        log.err("No config found. Run `nullclaw onboard` first.", .{});
        return;
    };
    defer cfg.deinit();

    var cost_tracker: ?cost_mod.CostTracker = if (cfg.cost.enabled)
        cost_mod.CostTracker.init(allocator, cfg.workspace_dir, cfg.cost.enabled, cfg.cost.daily_limit_usd, cfg.cost.monthly_limit_usd, cfg.cost.warn_at_percent)
    else
        null;
    defer if (cost_tracker) |*tracker| tracker.deinit();

    const parsed_args = switch (parseAgentArgs(args)) {
        .ok => |parsed| parsed,
        .missing_value => |opt| {
            log.err("Missing value for {s}", .{opt});
            return;
        },
        .invalid_temperature => |value| {
            log.err("Invalid --temperature value: {s}", .{value});
            return;
        },
    };
    if (parsed_args.provider_override) |provider| {
        if (parsed_args.agent_name == null) {
            cfg.default_provider = provider;
        }
    }
    if (parsed_args.model_override) |model| {
        if (parsed_args.agent_name == null) {
            cfg.default_model = model;
        }
    }
    if (parsed_args.temperature_override) |temp| {
        if (parsed_args.agent_name == null) {
            cfg.default_temperature = temp;
            cfg.temperature = temp;
        }
    }
    if (parsed_args.verbose) {
        log.warn("Verbose flag detected, enabling verbose logging", .{});
        verbose.setVerbose(true);
    }

    var selected_profile_storage: ?config_types.NamedAgentConfig = null;
    if (parsed_args.agent_name) |agent_name| {
        const found_profile = findNamedAgentProfile(cfg.agents, agent_name) orelse {
            log.err("Unknown named agent profile: {s}", .{agent_name});
            return;
        };
        var adjusted_profile = found_profile;
        if (parsed_args.provider_override) |provider| adjusted_profile.provider = provider;
        if (parsed_args.model_override) |model| adjusted_profile.model = model;
        if (parsed_args.temperature_override) |temp| adjusted_profile.temperature = temp;
        selected_profile_storage = adjusted_profile;
    }

    var selected_workspace_dir: ?[]const u8 = null;
    defer if (selected_workspace_dir) |workspace_dir| allocator.free(workspace_dir);
    if (selected_profile_storage) |profile| {
        if (profile.workspace_path) |workspace_path| {
            selected_workspace_dir = try cfg.resolveAgentWorkspacePath(allocator, workspace_path);
            cfg.workspace_dir = selected_workspace_dir.?;
        }
    }
    if (parsed_args.workspace_override) |workspace| {
        cfg.workspace_dir = workspace;
    }

    var agent_memory_session_id: ?[]u8 = null;
    defer if (agent_memory_session_id) |memory_session_id| allocator.free(memory_session_id);
    if (selected_profile_storage) |profile| {
        if (profile.workspace_path != null) {
            agent_memory_session_id = try profileMemoryNamespace(allocator, profile.name);
        }
    }

    cfg.validate() catch |err| {
        Config.printValidationError(err);
        return;
    };

    http_util.setProxyOverride(cfg.http_request.proxy) catch |err| {
        log.err("Invalid http_request.proxy override: {s}", .{@errorName(err)});
        return;
    };
    providers.setApiErrorLimitOverride(cfg.diagnostics.api_error_max_chars) catch |err| {
        log.err("Invalid diagnostics.api_error_max_chars override: {s}", .{@errorName(err)});
        return;
    };

    var out_buf: [4096]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&out_buf);
    const w = &bw.interface;

    const message_arg = parsed_args.message_arg;
    const session_id = parsed_args.session_id;

    const runtime_observer = try observability.RuntimeObserver.create(
        allocator,
        .{
            .workspace_dir = cfg.workspace_dir,
            .backend = cfg.diagnostics.backend,
            .otel_endpoint = cfg.diagnostics.otel_endpoint,
            .otel_service_name = cfg.diagnostics.otel_service_name,
        },
        cfg.diagnostics.otel_headers,
        &.{},
    );
    defer runtime_observer.destroy();
    const obs = runtime_observer.observer();

    // Record agent start
    const start_event = ObserverEvent{ .agent_start = .{
        .provider = if (selected_profile_storage) |profile| profile.provider else cfg.default_provider,
        .model = if (selected_profile_storage) |profile| profile.model else (cfg.default_model orelse "(default)"),
        .channel = parsed_args.origin_channel orelse "cli",
        .bot_account = parsed_args.origin_account_id,
    } };
    obs.recordEvent(&start_event);

    // Build security policy from config
    var tracker = security.RateTracker.init(allocator, cfg.autonomy.max_actions_per_hour);
    defer tracker.deinit();

    var policy = security.SecurityPolicy{
        .autonomy = cfg.autonomy.level,
        .workspace_dir = cfg.workspace_dir,
        .workspace_only = cfg.autonomy.workspace_only,
        .allowed_commands = security.resolveAllowedCommands(cfg.autonomy.level, cfg.autonomy.allowed_commands),
        .max_actions_per_hour = cfg.autonomy.max_actions_per_hour,
        .require_approval_for_medium_risk = cfg.autonomy.require_approval_for_medium_risk,
        .block_high_risk_commands = cfg.autonomy.block_high_risk_commands,
        .block_medium_risk_commands = cfg.autonomy.block_medium_risk_commands,
        .allow_raw_url_chars = cfg.autonomy.allow_raw_url_chars,
        .tracker = &tracker,
    };

    var runtime_provider: ?providers.runtime_bundle.RuntimeProviderBundle = null;
    defer if (runtime_provider) |*bundle| bundle.deinit();
    var provider_ctx: ?CliProviderContext = null;
    defer if (provider_ctx) |*ctx| ctx.deinit(allocator);

    if (selected_profile_storage) |profile| {
        provider_ctx = try resolveProfileProvider(allocator, &cfg, profile);
    } else {
        runtime_provider = try providers.runtime_bundle.RuntimeProviderBundle.init(allocator, &cfg);
    }

    const resolved_api_key = if (provider_ctx) |ctx|
        (ctx.owned_api_key orelse selected_profile_storage.?.api_key)
    else
        runtime_provider.?.primaryApiKey();

    var subagent_manager = subagent_mod.SubagentManager.init(allocator, &cfg, null, .{});
    subagent_manager.observer = runtime_observer.backendObserver();
    subagent_manager.task_runner = subagent_runner.runTaskWithTools;
    defer subagent_manager.deinit();

    // Optional memory backend.
    var mem_rt = memory_mod.initRuntime(allocator, &cfg.memory, cfg.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?Memory = if (mem_rt) |rt| rt.memory else null;

    const bootstrap_provider: ?bootstrap_mod.BootstrapProvider = bootstrap_mod.createProvider(
        allocator,
        cfg.memory.backend,
        mem_opt,
        cfg.workspace_dir,
    ) catch null;
    defer if (bootstrap_provider) |bp| bp.deinit();

    // Ensure lifecycle parity: seed workspace files on first agent run
    // so prompts always have the expected bootstrap context.
    try onboard.scaffoldWorkspace(
        allocator,
        cfg.workspace_dir,
        &onboard.ProjectContext{},
        bootstrap_provider,
    );

    // Create tools (with agents config for delegate depth enforcement)
    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .http_allowed_domains = cfg.http_request.allowed_domains,
        .http_max_response_size = cfg.http_request.max_response_size,
        .http_timeout_secs = cfg.http_request.timeout_secs,
        .web_search_base_url = cfg.http_request.search_base_url,
        .web_search_provider = cfg.http_request.search_provider,
        .web_search_fallback_providers = cfg.http_request.search_fallback_providers,
        .browser_enabled = cfg.browser.enabled,
        .screenshot_enabled = true,
        .mcp_server_configs = cfg.mcp_servers,
        .agents = cfg.agents,
        .configured_providers = cfg.providers,
        .fallback_api_key = resolved_api_key,
        .tools_config = cfg.tools,
        .allowed_paths = cfg.autonomy.allowed_paths,
        .policy = &policy,
        .subagent_manager = &subagent_manager,
        .bootstrap_provider = bootstrap_provider,
        .backend_name = cfg.memory.backend,
        .sandbox_backend = cfg.security.sandbox.backend,
        .sandbox_enabled = cfg.sandboxEnabled(),
    });
    defer tools_mod.deinitTools(allocator, tools);

    // Bind memory backend once for this tool set before creating agents.
    tools_mod.bindMemoryTools(tools, mem_opt);

    // Bind MemoryRuntime to memory tools for hybrid search and vector sync.
    if (mem_rt) |*rt| {
        tools_mod.bindMemoryRuntime(tools, rt);
    }

    const provider_i = activeCliProvider(
        if (provider_ctx) |*ctx| ctx else null,
        if (runtime_provider) |*bundle| bundle else null,
    );

    const supports_streaming = provider_i.supportsStreaming();

    // Single message mode: nullclaw agent -m "hello"
    if (message_arg) |message| {
        // Keep subprocess runs quiet by default; cron and other callers
        // consume this mode programmatically and should only see the response.
        if (verbose.isVerbose()) {
            log.info("Sending to {s}...", .{if (selected_profile_storage) |profile| profile.provider else cfg.default_provider});
            if (session_id) |sid| {
                log.info("Session: {s}", .{sid});
            }
        }

        var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider_i, tools, mem_opt, obs, selected_profile_storage);
        agent.policy = &policy;
        agent.session_store = if (mem_rt) |rt| rt.session_store else null;
        agent.response_cache = if (mem_rt) |*rt| rt.response_cache else null;
        agent.mem_rt = if (mem_rt) |*rt| rt else null;
        if (parsed_args.provider_override != null or parsed_args.model_override != null) {
            agent.model_pinned_by_user = true;
        }
        if (session_id) |sid| {
            agent.memory_session_id = sid;
        } else if (agent_memory_session_id) |memory_session_id| {
            agent.memory_session_id = memory_session_id;
        }
        if (parsed_args.skill_name) |sname| {
            _ = try commands.activateSkillByName(&agent, sname);
        }
        if (cost_tracker) |*c_tracker| {
            agent.usage_record_callback = cliUsageRecordCallback;
            agent.usage_record_ctx = @ptrCast(c_tracker);
        }
        defer agent.deinit();

        // Enable streaming if provider supports it.
        // When reasoning_mode == .stream, use ThinkPassthroughFilter so that
        // <think> content is printed live instead of being silently stripped.
        var stream_ctx = CliStreamCtx{
            .sink = undefined,
            .suppress_live = shouldSuppressLiveForRedaction(agent.redactor, message),
        };
        const raw_stream_sink = streaming.Sink{
            .callback = cliStreamSinkCallback,
            .ctx = @ptrCast(&stream_ctx),
        };
        if (agent.reasoning_mode == .stream) {
            stream_ctx.sink = makeCliStreamSinkPassthrough(raw_stream_sink, &stream_ctx.think_filter);
        } else {
            stream_ctx.sink = makeCliStreamSink(raw_stream_sink, &stream_ctx.filter);
        }
        if (supports_streaming) {
            agent.stream_callback = cliStreamCallback;
            agent.stream_ctx = @ptrCast(&stream_ctx);
        }

        stream_ctx.emitted_text = false;
        const response = agent.turn(message) catch |err| {
            if (err == error.ProviderDoesNotSupportVision) {
                try w.print("Error: The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.\n", .{});
                try w.flush();
                return;
            }
            if (err == error.RateLimited) {
                try w.print("Error: {}\n", .{err});
                try maybePrintLastProviderApiError(allocator, w);
                try writeRateLimitHint(w, cfg.default_provider);
                try w.flush();
            }
            if (err == error.AllProvidersFailed) {
                try maybePrintLastProviderApiError(allocator, w);
                try maybePrintRateLimitHint(allocator, w, cfg.default_provider);
                try maybePrintAllProvidersFailedHint(allocator, w, cfg.default_provider);
                try w.flush();
            }
            return err;
        };
        defer allocator.free(response);

        persistCliTurn(&agent, message, response);

        if (shouldPrintTurnResponse(supports_streaming, stream_ctx.emitted_text)) {
            // unredact() always returns a fresh allocation when the redactor
            // is on. Use an optional so cleanup logic doesn't depend on
            // pointer identity.
            const unredacted: ?[]u8 = if (agent.redactor) |r|
                (if (r.wouldRehydrate()) try r.unredact(allocator, response) else null)
            else
                null;
            defer if (unredacted) |s| allocator.free(s);
            const display: []const u8 = unredacted orelse response;
            try w.print("{s}\n", .{display});
        } else {
            try w.print("\n", .{});
        }
        if (shouldPrintSeparateUsage(supports_streaming, stream_ctx.emitted_text)) {
            try maybePrintUsage(w, &agent);
        }
        try w.flush();
        return;
    }

    // Interactive REPL mode
    cfg.printModelConfig();
    try w.print("nullclaw Agent -- Interactive Mode\n", .{});
    try w.print("Provider: {s} | Model: {s}\n", .{
        if (selected_profile_storage) |profile| profile.provider else cfg.default_provider,
        if (selected_profile_storage) |profile| profile.model else (cfg.default_model orelse "(default)"),
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

    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, provider_i, tools, mem_opt, obs, selected_profile_storage);
    agent.policy = &policy;
    agent.session_store = if (mem_rt) |rt| rt.session_store else null;
    agent.response_cache = if (mem_rt) |*rt| rt.response_cache else null;
    agent.mem_rt = if (mem_rt) |*rt| rt else null;

    if (cost_tracker) |*c_tracker| {
        agent.usage_record_callback = cliUsageRecordCallback;
        agent.usage_record_ctx = @ptrCast(c_tracker);
    }

    if (parsed_args.provider_override != null or parsed_args.model_override != null) {
        agent.model_pinned_by_user = true;
    }
    if (session_id) |sid| {
        agent.memory_session_id = sid;
    } else if (agent_memory_session_id) |memory_session_id| {
        agent.memory_session_id = memory_session_id;
    }
    if (parsed_args.skill_name) |sname| {
        _ = try commands.activateSkillByName(&agent, sname);
    }
    defer agent.deinit();

    // Enable streaming if provider supports it.
    // When reasoning_mode == .stream, use ThinkPassthroughFilter so that
    // <think> content is printed live instead of being silently stripped.
    var stream_ctx = CliStreamCtx{
        .sink = undefined,
        .suppress_live = false,
    };
    const raw_stream_sink = streaming.Sink{
        .callback = cliStreamSinkCallback,
        .ctx = @ptrCast(&stream_ctx),
    };
    if (agent.reasoning_mode == .stream) {
        stream_ctx.sink = makeCliStreamSinkPassthrough(raw_stream_sink, &stream_ctx.think_filter);
    } else {
        stream_ctx.sink = makeCliStreamSink(raw_stream_sink, &stream_ctx.filter);
    }
    if (supports_streaming) {
        agent.stream_callback = cliStreamCallback;
        agent.stream_ctx = @ptrCast(&stream_ctx);
    }

    const stdin = std_compat.fs.File.stdin();
    var line_buf: [4096]u8 = undefined;
    var pending_line: ?[]u8 = null;
    defer if (pending_line) |line| allocator.free(line);

    while (true) {
        printPendingSubagentNotices(allocator, w, &subagent_manager, agent.memory_session_id) catch {};

        var owned_line: ?[]u8 = null;
        defer if (owned_line) |line| allocator.free(line);

        const line = blk: {
            if (pending_line) |queued| {
                pending_line = null;
                owned_line = queued;
                break :blk queued;
            }

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
            break :blk line_buf[0..pos];
        };

        if (line.len == 0) continue;
        if (cli_mod.CliChannel.isQuitCommand(line)) return;

        var debounced_input = try collectCliDebouncedInput(allocator, stdin, line, cfg.messages.inbound.debounce_ms);
        defer debounced_input.deinit(allocator);
        if (debounced_input.queued_next) |queued| {
            pending_line = queued;
            debounced_input.queued_next = null;
        }

        // Append the effective turn input after debounce coalescing.
        repl_history.append(allocator, allocator.dupe(u8, debounced_input.current) catch continue) catch {};

        // Re-evaluate sink in case reasoning_mode was changed by a previous slash command
        const repl_raw_sink = streaming.Sink{
            .callback = cliStreamSinkCallback,
            .ctx = @ptrCast(&stream_ctx),
        };
        if (agent.reasoning_mode == .stream) {
            stream_ctx.sink = makeCliStreamSinkPassthrough(repl_raw_sink, &stream_ctx.think_filter);
        } else {
            stream_ctx.sink = makeCliStreamSink(repl_raw_sink, &stream_ctx.filter);
        }

        stream_ctx.emitted_text = false;
        stream_ctx.suppress_live = shouldSuppressLiveForRedaction(agent.redactor, debounced_input.current);
        const response = agent.turn(debounced_input.current) catch |err| {
            if (err == error.ProviderDoesNotSupportVision) {
                try w.print("Error: The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.\n", .{});
            } else if (err == error.RateLimited) {
                try w.print("Error: {}\n", .{err});
                try maybePrintLastProviderApiError(allocator, w);
                try writeRateLimitHint(w, cfg.default_provider);
            } else if (err == error.AllProvidersFailed) {
                try w.print("Error: {}\n", .{err});
                try maybePrintLastProviderApiError(allocator, w);
                try maybePrintRateLimitHint(allocator, w, cfg.default_provider);
                try maybePrintAllProvidersFailedHint(allocator, w, cfg.default_provider);
            } else {
                try w.print("Error: {}\n", .{err});
            }
            try w.flush();
            continue;
        };
        defer allocator.free(response);

        persistCliTurn(&agent, debounced_input.current, response);

        if (shouldPrintTurnResponse(supports_streaming, stream_ctx.emitted_text)) {
            const unredacted: ?[]u8 = if (agent.redactor) |r|
                (if (r.wouldRehydrate()) try r.unredact(allocator, response) else null)
            else
                null;
            defer if (unredacted) |s| allocator.free(s);
            const display: []const u8 = unredacted orelse response;
            try w.print("\n{s}\n\n", .{display});
        } else {
            try w.print("\n\n", .{});
        }
        if (shouldPrintSeparateUsage(supports_streaming, stream_ctx.emitted_text)) {
            try maybePrintUsage(w, &agent);
        }
        try w.flush();
    }
}

fn collectCliDebouncedInput(
    allocator: std.mem.Allocator,
    stdin: std_compat.fs.File,
    first_line: []const u8,
    debounce_ms: u32,
) !CliDebouncedInput {
    if (debounce_ms == 0 or @import("builtin").os.tag == .windows) {
        return .{ .current = try allocator.dupe(u8, first_line) };
    }

    var debouncer = inbound_debounce.InboundDebouncer.init(allocator, debounce_ms);
    defer debouncer.deinit();

    var ready: std.ArrayListUnmanaged(bus_mod.InboundMessage) = .empty;
    defer {
        for (ready.items) |msg| msg.deinit(allocator);
        ready.deinit(allocator);
    }

    try debouncer.push(try bus_mod.makeInbound(allocator, "cli", "local-user", "cli", first_line, "cli:repl"), inbound_debounce.nowMs(), &ready);

    while (ready.items.len == 0) {
        const timeout_ms = debouncer.nextPollTimeoutMs(inbound_debounce.nowMs());
        if (timeout_ms == 0) {
            try debouncer.flushMatured(inbound_debounce.nowMs(), &ready);
            continue;
        }

        const poll_timeout: i32 = if (timeout_ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(timeout_ms);
        if (comptime builtin.os.tag == .windows) {
            if (poll_timeout > 0) {
                std_compat.thread.sleep(@as(u64, @intCast(poll_timeout)) * std.time.ns_per_ms);
            }
            try debouncer.flushMatured(inbound_debounce.nowMs(), &ready);
            continue;
        }
        var poll_fds = [_]std.posix.pollfd{
            .{ .fd = stdin.handle, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const events = std.posix.poll(&poll_fds, poll_timeout) catch 0;
        if (events > 0 and (poll_fds[0].revents & std.posix.POLL.IN) != 0) {
            var extra_line_buf: [4096]u8 = undefined;
            const extra_line = readCliLine(stdin, &extra_line_buf) orelse break;
            if (extra_line.len > 0) {
                try debouncer.push(try bus_mod.makeInbound(allocator, "cli", "local-user", "cli", extra_line, "cli:repl"), inbound_debounce.nowMs(), &ready);
            }
        } else {
            try debouncer.flushMatured(inbound_debounce.nowMs(), &ready);
        }
    }

    if (ready.items.len == 0) {
        return .{ .current = try allocator.dupe(u8, first_line) };
    }
    return try buildCliDebouncedInput(allocator, ready.items);
}

fn readCliLine(stdin: std_compat.fs.File, buf: []u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = stdin.read(buf[pos .. pos + 1]) catch return null;
        if (n == 0) return null;
        if (buf[pos] == '\n') break;
        pos += 1;
    }
    return buf[0..pos];
}

const CliDebouncedInput = struct {
    current: []u8,
    queued_next: ?[]u8 = null,

    fn deinit(self: *CliDebouncedInput, allocator: std.mem.Allocator) void {
        allocator.free(self.current);
        if (self.queued_next) |queued| allocator.free(queued);
    }
};

fn buildCliDebouncedInput(
    allocator: std.mem.Allocator,
    ready: []const bus_mod.InboundMessage,
) !CliDebouncedInput {
    std.debug.assert(ready.len > 0);

    var input = CliDebouncedInput{
        .current = try allocator.dupe(u8, ready[0].content),
    };
    errdefer input.deinit(allocator);

    if (ready.len > 1) {
        input.queued_next = try allocator.dupe(u8, ready[1].content);
    }
    return input;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

fn noopSinkEvent(_: *anyopaque, _: streaming.Event) void {}

test "cliStreamCallback handles empty delta" {
    var sink_ctx: u8 = 0;
    var ctx = CliStreamCtx{
        .sink = .{
            .callback = noopSinkEvent,
            .ctx = @ptrCast(&sink_ctx),
        },
    };
    const chunk = providers.StreamChunk.finalChunk();
    cliStreamCallback(@ptrCast(&ctx), chunk);
    try std.testing.expect(!ctx.emitted_text);
}

test "buildCliDebouncedInput preserves queued bypass command" {
    const allocator = std.testing.allocator;
    var ready: std.ArrayListUnmanaged(bus_mod.InboundMessage) = .empty;
    defer {
        for (ready.items) |msg| msg.deinit(allocator);
        ready.deinit(allocator);
    }

    try ready.append(
        allocator,
        try bus_mod.makeInbound(allocator, "cli", "local-user", "cli", "hello", "cli:repl"),
    );
    try ready.append(
        allocator,
        try bus_mod.makeInbound(allocator, "cli", "local-user", "cli", "/quit", "cli:repl"),
    );

    var input = try buildCliDebouncedInput(allocator, ready.items);
    defer input.deinit(allocator);

    try std.testing.expectEqualStrings("hello", input.current);
    try std.testing.expect(input.queued_next != null);
    try std.testing.expectEqualStrings("/quit", input.queued_next.?);
}

test "cliStreamCallback text delta chunk" {
    var ctx = CliStreamCtx{
        .sink = undefined,
    };
    const raw_sink = streaming.Sink{
        .callback = cliStreamSinkCallback,
        .ctx = @ptrCast(&ctx),
    };
    ctx.sink = makeCliStreamSink(raw_sink, &ctx.filter);
    const chunk = providers.StreamChunk.textDelta("hello");
    cliStreamCallback(@ptrCast(&ctx), chunk);
    try std.testing.expectEqualStrings("hello", chunk.delta);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqual(@as(u32, 2), chunk.token_count);
    try std.testing.expect(ctx.emitted_text);
}

test "makeCliStreamSink strips streamed tool_call markup" {
    const Collector = struct {
        buf: [128]u8 = undefined,
        len: usize = 0,

        fn callback(ctx_ptr: *anyopaque, event: streaming.Event) void {
            if (event.stage != .chunk or event.text.len == 0) return;
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            @memcpy(self.buf[self.len..][0..event.text.len], event.text);
            self.len += event.text.len;
        }
    };

    var collector = Collector{};
    var filter: streaming.TagFilter = undefined;
    const raw_sink = streaming.Sink{
        .callback = Collector.callback,
        .ctx = @ptrCast(&collector),
    };
    const filtered_sink = makeCliStreamSink(raw_sink, &filter);

    var ctx = CliStreamCtx{ .sink = filtered_sink };
    cliStreamCallback(@ptrCast(&ctx), providers.StreamChunk.textDelta(
        "Let me check the projects for you.<tool_call>{\"name\":\"mcp_vikunja_vikunja_list_projects\",\"arguments\":{}}</tool_call>",
    ));
    cliStreamCallback(@ptrCast(&ctx), providers.StreamChunk.finalChunk());

    try std.testing.expectEqualStrings("Let me check the projects for you.", collector.buf[0..collector.len]);
}

test "cliStreamCallback keeps emitted_text false for filtered tool_call-only chunk" {
    var ctx = CliStreamCtx{
        .sink = undefined,
    };
    const raw_sink = streaming.Sink{
        .callback = cliStreamSinkCallback,
        .ctx = @ptrCast(&ctx),
    };
    ctx.sink = makeCliStreamSink(raw_sink, &ctx.filter);

    // Regression: tool-only streamed control markup must not suppress the final fallback response.
    cliStreamCallback(@ptrCast(&ctx), providers.StreamChunk.textDelta(
        "<tool_call>{\"name\":\"mcp_vikunja_vikunja_list_projects\",\"arguments\":{}}</tool_call>",
    ));
    cliStreamCallback(@ptrCast(&ctx), providers.StreamChunk.finalChunk());

    try std.testing.expect(!ctx.emitted_text);
    try std.testing.expect(shouldPrintTurnResponse(true, ctx.emitted_text));
}

test "parseAgentArgs parses provider and model overrides" {
    const args = [_][]const u8{
        "-m",
        "hi",
        "--provider",
        "ollama",
        "--model",
        "llama3.2:latest",
        "--temperature",
        "0.25",
    };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("hi", parsed.message_arg.?);
    try std.testing.expectEqualStrings("ollama", parsed.provider_override.?);
    try std.testing.expectEqualStrings("llama3.2:latest", parsed.model_override.?);
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), parsed.temperature_override.?, 0.000001);
}

test "activeCliProvider uses returned holder storage for named agents" {
    var cfg = Config{
        .allocator = std.testing.allocator,
        .workspace_dir = "/tmp/nullclaw-cli-test",
        .config_path = "/tmp/nullclaw-cli-test/config.json",
        .providers = &.{
            .{
                .name = "custom:dmr",
                .base_url = "http://127.0.0.1:8080/v1",
            },
        },
    };
    const profile = config_types.NamedAgentConfig{
        .name = "sub",
        .provider = "custom:dmr",
        .model = "smollm2",
        .api_key = "placeholder",
    };

    // Regression: issue #811 requires the runtime Provider to be derived from
    // the returned holder storage, not from resolveProfileProvider's stack frame.
    var provider_ctx = try resolveProfileProvider(std.testing.allocator, &cfg, profile);
    defer provider_ctx.deinit(std.testing.allocator);

    const provider = activeCliProvider(&provider_ctx, null);
    const holder_provider = provider_ctx.holder.provider();
    try std.testing.expectEqual(@intFromPtr(holder_provider.ptr), @intFromPtr(provider.ptr));
    try std.testing.expectEqual(@intFromPtr(holder_provider.vtable), @intFromPtr(provider.vtable));
    switch (provider_ctx.holder) {
        .compatible => |*compatible_provider| {
            try std.testing.expectEqual(@intFromPtr(compatible_provider), @intFromPtr(provider.ptr));
        },
        else => unreachable,
    }
}

test "shouldPrintTurnResponse prints fallback when streaming emits no text" {
    try std.testing.expect(shouldPrintTurnResponse(true, false));
    try std.testing.expect(shouldPrintTurnResponse(false, false));
}

test "shouldPrintTurnResponse suppresses duplicate output after streamed text" {
    try std.testing.expect(!shouldPrintTurnResponse(true, true));
}

test "persistCliTurn redacts PII before session persistence" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    var redactor = redaction.Redactor.init(allocator, .{ .record_originals = true });
    defer redactor.deinit();

    var noop = observability.NoopObserver{};
    var agent = Agent{
        .allocator = allocator,
        .provider = undefined,
        .tools = &.{},
        .tool_specs = try allocator.alloc(providers.ToolSpec, 0),
        .mem = null,
        .session_store = mem.sessionStore(),
        .memory_session_id = "cli-redaction-session",
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

    persistCliTurn(&agent, "contact alice@example.com", "sent to alice@example.com");

    const detailed = try mem.sessionStore().loadMessagesDetailed(allocator, "cli-redaction-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[1].content, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[1].content, "[EMAIL_1]") != null);
}

test "parseAgentArgs keeps the last override value" {
    const args = [_][]const u8{
        "--provider",
        "openrouter",
        "--provider",
        "anthropic",
        "--model",
        "first",
        "--model",
        "second",
        "--temperature",
        "0.1",
        "--temperature",
        "0.7",
    };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("anthropic", parsed.provider_override.?);
    try std.testing.expectEqualStrings("second", parsed.model_override.?);
    try std.testing.expectApproxEqAbs(@as(f64, 0.7), parsed.temperature_override.?, 0.000001);
}

test "parseAgentArgs returns error for missing option value" {
    const args = [_][]const u8{"--provider"};
    switch (parseAgentArgs(&args)) {
        .missing_value => |opt| try std.testing.expectEqualStrings("--provider", opt),
        else => unreachable,
    }
}

test "parseAgentArgs returns error for invalid temperature value" {
    const args = [_][]const u8{
        "--temperature",
        "hot",
    };
    switch (parseAgentArgs(&args)) {
        .invalid_temperature => |value| try std.testing.expectEqualStrings("hot", value),
        else => unreachable,
    }
}

test "parseAgentArgs parses --agent" {
    const args = [_][]const u8{ "--agent", "researcher", "-m", "hello" };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("researcher", parsed.agent_name.?);
    try std.testing.expectEqualStrings("hello", parsed.message_arg.?);
}

test "parseAgentArgs returns missing value for --agent" {
    const args = [_][]const u8{"--agent"};
    switch (parseAgentArgs(&args)) {
        .missing_value => |value| try std.testing.expectEqualStrings("--agent", value),
        else => unreachable,
    }
}

test "parseAgentArgs parses --workspace" {
    const args = [_][]const u8{ "--workspace", "/custom/ws", "-m", "hi" };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("/custom/ws", parsed.workspace_override.?);
    try std.testing.expectEqualStrings("hi", parsed.message_arg.?);
}

test "parseAgentArgs returns missing value for --workspace" {
    const args = [_][]const u8{"--workspace"};
    switch (parseAgentArgs(&args)) {
        .missing_value => |value| try std.testing.expectEqualStrings("--workspace", value),
        else => unreachable,
    }
}

test "parseAgentArgs parses --skill" {
    const args = [_][]const u8{ "--skill", "news-digest", "-m", "go" };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("news-digest", parsed.skill_name.?);
    try std.testing.expectEqualStrings("go", parsed.message_arg.?);
}

test "parseAgentArgs parses cron origin attribution" {
    // Regression: scheduled child agents must retain delivery origin observability fields.
    const args = [_][]const u8{
        "--origin-channel",
        "telegram",
        "--origin-account-id",
        "main",
        "-m",
        "go",
    };
    const parsed = switch (parseAgentArgs(&args)) {
        .ok => |value| value,
        else => unreachable,
    };
    try std.testing.expectEqualStrings("telegram", parsed.origin_channel.?);
    try std.testing.expectEqualStrings("main", parsed.origin_account_id.?);
    try std.testing.expectEqualStrings("go", parsed.message_arg.?);
}

test "parseAgentArgs returns missing value for --skill" {
    const args = [_][]const u8{"--skill"};
    switch (parseAgentArgs(&args)) {
        .missing_value => |value| try std.testing.expectEqualStrings("--skill", value),
        else => unreachable,
    }
}

test "parseAgentArgs returns missing value for origin attribution" {
    // Regression: incomplete internal origin flags must fail before agent startup.
    const flags = [_][]const u8{ "--origin-channel", "--origin-account-id" };
    for (flags) |flag| {
        const args = [_][]const u8{flag};
        switch (parseAgentArgs(&args)) {
            .missing_value => |value| try std.testing.expectEqualStrings(flag, value),
            else => unreachable,
        }
    }
}

test "shouldPrintOpenAiCodexHint true when codex auth exists and provider differs" {
    try std.testing.expect(shouldPrintOpenAiCodexHint("openai", true));
}

test "shouldPrintOpenAiCodexHint false when provider is openai-codex" {
    try std.testing.expect(!shouldPrintOpenAiCodexHint("openai-codex", true));
}

test "shouldPrintOpenAiCodexHint false when codex auth is missing" {
    try std.testing.expect(!shouldPrintOpenAiCodexHint("openai", false));
}

test "providerFailureLooksQuotaConstrained detects rate and quota detail" {
    try std.testing.expect(providerFailureLooksQuotaConstrained("compatible: status=429 message=Rate limit exceeded"));
    try std.testing.expect(providerFailureLooksQuotaConstrained("groq: out of credits"));
    try std.testing.expect(providerFailureLooksQuotaConstrained("openai: billing hard limit reached"));
    try std.testing.expect(!providerFailureLooksQuotaConstrained("compatible: status=401 message=Unauthorized"));
}

test "shouldPrintSeparateUsage only for streaming text already emitted" {
    // Regression: non-streaming CLI responses already include composeFinalReply
    // usage details, so a second CLI usage line would duplicate the same turn.
    try std.testing.expect(!shouldPrintSeparateUsage(false, false));
    try std.testing.expect(!shouldPrintSeparateUsage(true, false));
    try std.testing.expect(shouldPrintSeparateUsage(true, true));
}

test "writeRateLimitHint mentions reliability knobs and logs" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeRateLimitHint(&aw.writer, "kimi");
    const rendered = aw.written();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "reliability.provider_backoff_ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "~/.nullclaw/logs/daemon.stdout.log") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "kimi appears rate-limited or quota-constrained") != null);
}
