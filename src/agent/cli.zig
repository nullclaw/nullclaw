//! CLI entry point — single-message and interactive REPL modes.
//!
//! Extracted from agent/root.zig. Contains `run()` (the main entry point
//! for `nullclaw agent`) and the streaming stdout callback.

const std = @import("std");
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
const cli_mod = @import("../channels/cli.zig");
const security = @import("../security/policy.zig");
const codex_support = @import("../codex_support.zig");
const onboard = @import("../onboard.zig");
const streaming = @import("../streaming.zig");
const verbose = @import("../verbose.zig");

const Agent = @import("root.zig").Agent;

const CliStreamCtx = struct {
    sink: streaming.Sink,
    emitted_text: bool = false,
};

const CliProviderContext = struct {
    provider: Provider,
    holder: ?providers.ProviderHolder = null,
    owned_api_key: ?[]u8 = null,

    fn deinit(self: *CliProviderContext, allocator: std.mem.Allocator) void {
        if (self.holder) |*holder| {
            holder.deinit();
            self.holder = null;
        }
        if (self.owned_api_key) |api_key| {
            allocator.free(api_key);
            self.owned_api_key = null;
        }
    }
};

fn shouldPrintTurnResponse(supports_streaming: bool, emitted_text: bool) bool {
    return !supports_streaming or !emitted_text;
}

fn cliStreamSinkCallback(_: *anyopaque, event: streaming.Event) void {
    if (event.stage != .chunk or event.text.len == 0) return;
    var buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const wr = &bw.interface;
    wr.print("{s}", .{event.text}) catch {};
    wr.flush() catch {};
}

/// Streaming callback that forwards provider chunks into unified stream sink events.
fn cliStreamCallback(ctx_ptr: *anyopaque, chunk: providers.StreamChunk) void {
    const stream_ctx: *CliStreamCtx = @ptrCast(@alignCast(ctx_ptr));
    if (!chunk.is_final and chunk.delta.len > 0) {
        stream_ctx.emitted_text = true;
    }
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

    var holder = providers.ProviderHolder.fromConfig(
        allocator,
        profile.provider,
        provider_api_key,
        cfg.getProviderBaseUrl(profile.provider),
        cfg.getProviderNativeTools(profile.provider),
        cfg.getProviderUserAgent(profile.provider),
    );
    return .{
        .provider = holder.provider(),
        .holder = holder,
        .owned_api_key = owned_api_key,
    };
}

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var cfg = Config.load(allocator) catch {
        log.err("No config found. Run `nullclaw onboard` first.", .{});
        return;
    };
    defer cfg.deinit();

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
    var bw = std.fs.File.stdout().writer(&out_buf);
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
    });
    defer tools_mod.deinitTools(allocator, tools);

    // Bind memory backend once for this tool set before creating agents.
    tools_mod.bindMemoryTools(tools, mem_opt);

    // Bind MemoryRuntime to memory tools for hybrid search and vector sync.
    if (mem_rt) |*rt| {
        tools_mod.bindMemoryRuntime(tools, rt);
    }

    const provider_i: Provider = if (provider_ctx) |ctx| ctx.provider else runtime_provider.?.provider();

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
        defer agent.deinit();

        // Enable streaming if provider supports it
        var stream_sink_ctx: u8 = 0;
        var stream_ctx = CliStreamCtx{
            .sink = .{
                .callback = cliStreamSinkCallback,
                .ctx = @ptrCast(&stream_sink_ctx),
            },
        };
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

        if (shouldPrintTurnResponse(supports_streaming, stream_ctx.emitted_text)) {
            try w.print("{s}\n", .{response});
        } else {
            try w.print("\n", .{});
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
    if (parsed_args.provider_override != null or parsed_args.model_override != null) {
        agent.model_pinned_by_user = true;
    }
    if (session_id) |sid| {
        agent.memory_session_id = sid;
    } else if (agent_memory_session_id) |memory_session_id| {
        agent.memory_session_id = memory_session_id;
    }
    defer agent.deinit();

    // Enable streaming if provider supports it
    var stream_sink_ctx: u8 = 0;
    var stream_ctx = CliStreamCtx{
        .sink = .{
            .callback = cliStreamSinkCallback,
            .ctx = @ptrCast(&stream_sink_ctx),
        },
    };
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

        stream_ctx.emitted_text = false;
        const response = agent.turn(line) catch |err| {
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

        if (shouldPrintTurnResponse(supports_streaming, stream_ctx.emitted_text)) {
            try w.print("\n{s}\n\n", .{response});
        } else {
            try w.print("\n\n", .{});
        }
        try w.flush();
    }
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

test "cliStreamCallback text delta chunk" {
    var sink_ctx: u8 = 0;
    var ctx = CliStreamCtx{
        .sink = .{
            .callback = noopSinkEvent,
            .ctx = @ptrCast(&sink_ctx),
        },
    };
    const chunk = providers.StreamChunk.textDelta("hello");
    cliStreamCallback(@ptrCast(&ctx), chunk);
    try std.testing.expectEqualStrings("hello", chunk.delta);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqual(@as(u32, 2), chunk.token_count);
    try std.testing.expect(ctx.emitted_text);
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

test "shouldPrintTurnResponse prints fallback when streaming emits no text" {
    try std.testing.expect(shouldPrintTurnResponse(true, false));
    try std.testing.expect(shouldPrintTurnResponse(false, false));
}

test "shouldPrintTurnResponse suppresses duplicate output after streamed text" {
    try std.testing.expect(!shouldPrintTurnResponse(true, true));
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

test "writeRateLimitHint mentions reliability knobs and logs" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeRateLimitHint(&aw.writer, "kimi");
    const rendered = aw.written();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "reliability.provider_backoff_ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "~/.nullclaw/logs/daemon.stdout.log") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "kimi appears rate-limited or quota-constrained") != null);
}
