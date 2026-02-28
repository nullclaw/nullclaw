//! CLI entry point — single-message and interactive REPL modes.
//!
//! Extracted from agent/root.zig. Contains `run()` (the main entry point
//! for `nullclaw agent`) and the streaming stdout callback.

const std = @import("std");
const log = std.log.scoped(.agent);
const Config = @import("../config.zig").Config;
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const observability = @import("../observability.zig");
const Observer = observability.Observer;
const ObserverEvent = observability.ObserverEvent;
const subagent_mod = @import("../subagent.zig");
const cli_mod = @import("../channels/cli.zig");
const security = @import("../security/policy.zig");
const onboard = @import("../onboard.zig");
const streaming = @import("../streaming.zig");

const Agent = @import("root.zig").Agent;

const CliStreamCtx = struct {
    sink: streaming.Sink,
};

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
    streaming.forwardProviderChunk(stream_ctx.sink, chunk);
}

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var cfg = Config.load(allocator) catch {
        log.err("No config found. Run `nullclaw onboard` first.", .{});
        return;
    };
    defer cfg.deinit();

    cfg.validate() catch |err| {
        Config.printValidationError(err);
        return;
    };

    // Ensure lifecycle parity: seed workspace files on first agent run
    // so prompts always have the expected bootstrap context.
    try onboard.scaffoldWorkspace(allocator, cfg.workspace_dir, &onboard.ProjectContext{});

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
    defer if (mcp_tools) |mt| allocator.free(mt);

    // Build security policy from config
    var tracker = security.RateTracker.init(allocator, cfg.autonomy.max_actions_per_hour);
    defer tracker.deinit();

    var policy = security.SecurityPolicy{
        .autonomy = cfg.autonomy.level,
        .workspace_dir = cfg.workspace_dir,
        .workspace_only = cfg.autonomy.workspace_only,
        .allowed_commands = if (cfg.autonomy.allowed_commands.len > 0) cfg.autonomy.allowed_commands else &security.default_allowed_commands,
        .max_actions_per_hour = cfg.autonomy.max_actions_per_hour,
        .require_approval_for_medium_risk = cfg.autonomy.require_approval_for_medium_risk,
        .block_high_risk_commands = cfg.autonomy.block_high_risk_commands,
        .tracker = &tracker,
    };

    // Provider runtime bundle (primary provider + reliability wrapper).
    var runtime_provider = try providers.runtime_bundle.RuntimeProviderBundle.init(allocator, &cfg);
    defer runtime_provider.deinit();
    const resolved_api_key = runtime_provider.primaryApiKey();

    var subagent_manager = subagent_mod.SubagentManager.init(allocator, &cfg, null, .{});
    defer subagent_manager.deinit();

    // Create tools (with agents config for delegate depth enforcement)
    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .http_allowed_domains = cfg.http_request.allowed_domains,
        .http_max_response_size = cfg.http_request.max_response_size,
        .http_timeout_secs = cfg.http_request.timeout_secs,
        .web_search_base_url = cfg.http_request.search_base_url,
        .browser_enabled = cfg.browser.enabled,
        .mcp_tools = mcp_tools,
        .agents = cfg.agents,
        .fallback_api_key = resolved_api_key,
        .tools_config = cfg.tools,
        .allowed_paths = cfg.autonomy.allowed_paths,
        .policy = &policy,
        .subagent_manager = &subagent_manager,
    });
    defer tools_mod.deinitTools(allocator, tools);

    // Create memory (optional — don't fail if it can't init)
    var mem_rt = memory_mod.initRuntime(allocator, &cfg.memory, cfg.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?Memory = if (mem_rt) |rt| rt.memory else null;

    // Bind memory backend once for this tool set before creating agents.
    tools_mod.bindMemoryTools(tools, mem_opt);

    // Bind MemoryRuntime to memory tools for hybrid search and vector sync.
    if (mem_rt) |*rt| {
        tools_mod.bindMemoryRuntime(tools, rt);
    }

    // Provider interface from runtime bundle (includes retries/fallbacks).
    const provider_i: Provider = runtime_provider.provider();

    const supports_streaming = provider_i.supportsStreaming();

    // Single message mode: nullclaw agent -m "hello"
    if (message_arg) |message| {
        try w.print("Sending to {s}...\n", .{cfg.default_provider});
        if (session_id) |sid| {
            try w.print("Session: {s}\n", .{sid});
        }
        try w.flush();

        var agent = try Agent.fromConfig(allocator, &cfg, provider_i, tools, mem_opt, obs);
        agent.policy = &policy;
        agent.session_store = if (mem_rt) |rt| rt.session_store else null;
        agent.response_cache = if (mem_rt) |*rt| rt.response_cache else null;
        agent.mem_rt = if (mem_rt) |*rt| rt else null;
        if (session_id) |sid| {
            agent.memory_session_id = sid;
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

        const response = agent.turn(message) catch |err| {
            if (err == error.ProviderDoesNotSupportVision) {
                try w.print("Error: The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.\n", .{});
                try w.flush();
                return;
            }
            return err;
        };
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
    cfg.printModelConfig();
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
    agent.policy = &policy;
    agent.session_store = if (mem_rt) |rt| rt.session_store else null;
    agent.response_cache = if (mem_rt) |*rt| rt.response_cache else null;
    agent.mem_rt = if (mem_rt) |*rt| rt else null;
    if (session_id) |sid| {
        agent.memory_session_id = sid;
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

        const response = agent.turn(line) catch |err| {
            if (err == error.ProviderDoesNotSupportVision) {
                try w.print("Error: The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.\n", .{});
            } else {
                try w.print("Error: {}\n", .{err});
            }
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
}

test "cliStreamCallback text delta chunk" {
    const chunk = providers.StreamChunk.textDelta("hello");
    try std.testing.expectEqualStrings("hello", chunk.delta);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqual(@as(u32, 2), chunk.token_count);
}
