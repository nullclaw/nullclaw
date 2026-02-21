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
const cli_mod = @import("../channels/cli.zig");
const security = @import("../security/policy.zig");

const Agent = @import("root.zig").Agent;

/// Streaming callback that writes chunks directly to stdout.
fn cliStreamCallback(_: *anyopaque, chunk: providers.StreamChunk) void {
    if (chunk.delta.len == 0) return;
    var buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const wr = &bw.interface;
    wr.print("{s}", .{chunk.delta}) catch {};
    wr.flush() catch {};
}

/// Run the agent in single-message or interactive REPL mode.
/// This is the main entry point called by `nullclaw agent`.
pub fn run(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var cfg = Config.load(allocator) catch {
        log.err("No config found. Run `nullclaw onboard` first.", .{});
        return;
    };
    defer cfg.deinit();

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

    // Create tools (with agents config for delegate depth enforcement)
    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .browser_enabled = cfg.browser.enabled,
        .mcp_tools = mcp_tools,
        .agents = cfg.agents,
        .fallback_api_key = cfg.defaultProviderKey(),
        .tools_config = cfg.tools,
        .allowed_paths = cfg.autonomy.allowed_paths,
        .policy = &policy,
    });
    defer allocator.free(tools);

    // Create memory (optional — don't fail if it can't init)
    var mem_opt: ?Memory = null;
    const db_path = try std.fs.path.joinZ(allocator, &.{ cfg.workspace_dir, "memory.db" });
    defer allocator.free(db_path);
    if (memory_mod.createMemory(allocator, cfg.memory.backend, db_path)) |mem| {
        mem_opt = mem;
    } else |_| {}

    // Create provider via centralized ProviderHolder (concrete struct lives on the stack)
    const api_key = providers.resolveApiKeyFromConfig(
        allocator,
        cfg.default_provider,
        cfg.providers,
        cfg.allowEnvApiKeys(),
    ) catch null;
    var holder = providers.ProviderHolder.fromConfig(allocator, cfg.default_provider, api_key);
    const provider_i: Provider = holder.provider();

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
        defer agent.deinit();

        // Enable streaming if provider supports it
        var stream_ctx: u8 = 0;
        if (supports_streaming) {
            agent.stream_callback = cliStreamCallback;
            agent.stream_ctx = @ptrCast(&stream_ctx);
        }

        const response = try agent.turn(message);
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
    defer agent.deinit();

    // Enable streaming if provider supports it
    var stream_ctx: u8 = 0;
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
            try w.print("Error: {}\n", .{err});
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

test "cliStreamCallback handles empty delta" {
    const chunk = providers.StreamChunk.finalChunk();
    cliStreamCallback(undefined, chunk);
}

test "cliStreamCallback text delta chunk" {
    const chunk = providers.StreamChunk.textDelta("hello");
    try std.testing.expectEqualStrings("hello", chunk.delta);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqual(@as(u32, 2), chunk.token_count);
}
