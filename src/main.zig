const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const build_options = @import("build_options");
const yc = @import("nullclaw");
const control_plane = yc.control_plane;
const util = yc.util;

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    std_compat.fs.File.stderr().writeAll("panic: ") catch {};
    std_compat.fs.File.stderr().writeAll(msg) catch {};
    std_compat.fs.File.stderr().writeAll("\n") catch {};
    std_compat.process.exit(1);
}

const log = std.log.scoped(.main);

const Command = enum {
    agent,
    acp,
    gateway,
    service,
    config,
    status,
    version,
    onboard,
    doctor,
    cron,
    channel,
    skills,
    hardware,
    migrate,
    memory,
    history,
    workspace,
    capabilities,
    models,
    mcp,
    auth,
    update,
    help,
};

const SERVICE_SUBCOMMANDS = "install|start|stop|restart|status|uninstall";
const CONFIG_SUBCOMMANDS = "show|get|set|unset|reload|validate";
const CRON_SUBCOMMANDS = "list|get|status|add|add-agent|once|once-agent|remove|pause|resume|run|update|runs";
const CHANNEL_SUBCOMMANDS = "list|info|start|status|add|remove";
const SKILLS_SUBCOMMANDS = "list|install|remove|info";
const HARDWARE_SUBCOMMANDS = "scan|flash|monitor";
const MEMORY_SUBCOMMANDS = "stats|count|reindex|search|get|list|export-jsonl|hygiene-report|store|update|delete|drain-outbox|forget";
const HISTORY_SUBCOMMANDS = "list|show";
const WORKSPACE_SUBCOMMANDS = "edit|reset-md|audit";
const MODELS_SUBCOMMANDS = "list|summary|info|benchmark|refresh";
const MCP_SUBCOMMANDS = "list|info";
const AUTH_SUBCOMMANDS = "login|status|logout";

const TOP_LEVEL_USAGE = std.fmt.comptimePrint(
    \\nullclaw -- The smallest AI assistant. Zig-powered.
    \\
    \\USAGE:
    \\  nullclaw <command> [options]
    \\
    \\COMMANDS:
    \\  onboard      Initialize workspace and configuration
    \\  agent        Start the AI agent loop
    \\  acp          Start Agent Client Protocol server (stdio JSON-RPC)
    \\  gateway      Start the gateway server (HTTP/WebSocket)
    \\  service      Manage OS service lifecycle
    \\  config       Inspect resolved config values
    \\  status       Show system status
    \\  version      Show CLI version
    \\  doctor       Run diagnostics
    \\  cron         Manage scheduled tasks
    \\  channel      Manage channels (Telegram, Discord, Slack, ...)
    \\  skills       Manage skills
    \\  hardware     Discover and manage hardware
    \\  migrate      Migrate data from other agent runtimes
    \\  memory       Inspect and maintain memory subsystem
    \\  history      View session conversation history
    \\  workspace    Maintain workspace markdown/bootstrap files
    \\  capabilities Show runtime capabilities manifest
    \\  models       Manage provider model catalogs
    \\  mcp          Inspect configured MCP servers
    \\  auth         Manage OAuth authentication (OpenAI Codex)
    \\  update       Check for and install updates
    \\  help         Show this help
    \\
    \\OPTIONS:
    \\  onboard [--interactive] [--api-key KEY] [--provider PROV] [--model MODEL] [--memory MEM]
    \\  agent [-m MESSAGE] [-s SESSION] [--provider PROVIDER] [--model MODEL] [--temperature TEMP] [--workspace PATH] [--skill SKILL]
    \\  acp [--provider PROVIDER] [--model MODEL] [--temperature TEMP] [--agent NAME] [--skill NAME]
    \\  gateway [--port PORT] [--host HOST] [--workspace PATH]
    \\  status [--json]
    \\  version | --version | -V
    \\  service <{s}>
    \\  config <{s}> [ARGS]
    \\  cron <{s}> [ARGS]
    \\  channel <{s}> [ARGS]
    \\  skills <{s}> [ARGS]
    \\  hardware <{s}> [ARGS]
    \\  migrate openclaw [--dry-run] [--source PATH]
    \\  memory <{s}> [ARGS]
    \\  history <{s}> [ARGS]
    \\  workspace <{s}> [ARGS]
    \\  capabilities [--json]
    \\  models <{s}> [ARGS]
    \\  mcp <{s}> [ARGS]
    \\  auth <{s}> <provider> [--import-codex]
    \\  update [--check] [--yes]
    \\
,
    .{
        SERVICE_SUBCOMMANDS,
        CONFIG_SUBCOMMANDS,
        CRON_SUBCOMMANDS,
        CHANNEL_SUBCOMMANDS,
        SKILLS_SUBCOMMANDS,
        HARDWARE_SUBCOMMANDS,
        MEMORY_SUBCOMMANDS,
        HISTORY_SUBCOMMANDS,
        WORKSPACE_SUBCOMMANDS,
        MODELS_SUBCOMMANDS,
        MCP_SUBCOMMANDS,
        AUTH_SUBCOMMANDS,
    },
);

fn parseCommand(arg: []const u8) ?Command {
    const command_map = std.StaticStringMap(Command).initComptime(.{
        .{ "agent", .agent },
        .{ "acp", .acp },
        .{ "gateway", .gateway },
        .{ "service", .service },
        .{ "config", .config },
        .{ "status", .status },
        .{ "version", .version },
        .{ "--version", .version },
        .{ "-V", .version },
        .{ "onboard", .onboard },
        .{ "doctor", .doctor },
        .{ "cron", .cron },
        .{ "channel", .channel },
        .{ "skills", .skills },
        .{ "hardware", .hardware },
        .{ "migrate", .migrate },
        .{ "memory", .memory },
        .{ "history", .history },
        .{ "workspace", .workspace },
        .{ "capabilities", .capabilities },
        .{ "models", .models },
        .{ "mcp", .mcp },
        .{ "auth", .auth },
        .{ "update", .update },
        .{ "help", .help },
        .{ "--help", .help },
        .{ "-h", .help },
    });
    return command_map.get(arg);
}

extern "kernel32" fn SetConsoleCP(wCodePageID: std.os.windows.UINT) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn SetConsoleOutputCP(wCodePageID: std.os.windows.UINT) callconv(.winapi) std.os.windows.BOOL;

fn configureWindowsConsoleUtf8() void {
    if (comptime builtin.os.tag == .windows) {
        // Set both output and input code pages to UTF-8 so interactive
        // terminal sessions preserve non-ASCII user input.
        _ = SetConsoleOutputCP(65001);
        _ = SetConsoleCP(65001);
    }
}

pub fn main(init: std.process.Init) !void {
    std_compat.initProcess(init);
    configureWindowsConsoleUtf8();

    const allocator = std.heap.smp_allocator;

    const args = try std_compat.process.argsAlloc(allocator);
    defer std_compat.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    // Manifest protocol flags (checked before command dispatch)
    if (std.mem.eql(u8, args[1], "--export-manifest")) {
        try yc.export_manifest.run();
        return;
    }
    if (std.mem.eql(u8, args[1], "--list-models")) {
        try yc.list_models.run(allocator, args[2..]);
        return;
    }
    if (std.mem.eql(u8, args[1], "--probe-provider-health")) {
        try yc.provider_probe.run(allocator, args[2..]);
        return;
    }
    if (std.mem.eql(u8, args[1], "--probe-channel-health")) {
        try yc.channel_probe.run(allocator, args[2..]);
        return;
    }
    if (std.mem.eql(u8, args[1], "--from-json")) {
        try yc.from_json.run(allocator, args[2..]);
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        if (yc.service.isWindowsServiceGatewayArg(args[1])) {
            try yc.service.runWindowsServiceGateway(allocator);
            return;
        }
    }

    const cmd = parseCommand(args[1]) orelse {
        std.debug.print("Unknown command: {s}\n\n", .{args[1]});
        printUsage();
        std_compat.process.exit(1);
    };

    const sub_args = args[2..];

    switch (cmd) {
        .version => printVersion(),
        .status => try yc.status.run(allocator, args[2..]),
        .agent => if (agentAdminRequested(sub_args)) {
            try runAgentAdmin(allocator, sub_args);
        } else if (agentHelpRequested(sub_args)) {
            printAgentUsage();
        } else {
            try yc.agent.run(allocator, sub_args);
        },
        .acp => try yc.acp.run(allocator, sub_args),
        .onboard => try runOnboard(allocator, sub_args),
        .doctor => try runDoctorCommand(allocator, sub_args),
        .help => printUsage(),
        .gateway => try runGateway(allocator, sub_args),
        .service => try runService(allocator, sub_args),
        .config => try runConfig(allocator, sub_args),
        .cron => try runCron(allocator, sub_args),
        .channel => try runChannel(allocator, sub_args),
        .skills => try runSkills(allocator, sub_args),
        .hardware => try runHardware(allocator, sub_args),
        .migrate => try runMigrate(allocator, sub_args),
        .memory => try runMemory(allocator, sub_args),
        .history => try runHistory(allocator, sub_args),
        .workspace => try runWorkspace(allocator, sub_args),
        .capabilities => try runCapabilities(allocator, sub_args),
        .models => try runModels(allocator, sub_args),
        .mcp => try runMcp(allocator, sub_args),
        .auth => try runAuth(allocator, sub_args),
        .update => try runUpdate(allocator, sub_args),
    }
}

fn printVersion() void {
    var buf: [256]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&buf);
    bw.interface.print("nullclaw {s}\n", .{yc.version.string}) catch return;
    bw.interface.flush() catch return;
}

const GatewayDaemonOverrideError = error{InvalidPort};

fn applyRuntimeProviderOverrides(config: *const yc.config.Config) void {
    yc.http_util.setProxyOverride(config.http_request.proxy) catch |err| {
        std.debug.print("Invalid http_request.proxy override: {s}\n", .{@errorName(err)});
        std_compat.process.exit(1);
    };
    yc.providers.setApiErrorLimitOverride(config.diagnostics.api_error_max_chars) catch |err| {
        std.debug.print("Invalid diagnostics.api_error_max_chars override: {s}\n", .{@errorName(err)});
        std_compat.process.exit(1);
    };
}

fn hasVerboseFlag(args: []const []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            return true;
        }
    }
    return false;
}

fn agentHelpRequested(args: []const []const u8) bool {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return true;
        }
        if (std.mem.eql(u8, arg, "-m") or
            std.mem.eql(u8, arg, "--message") or
            std.mem.eql(u8, arg, "-s") or
            std.mem.eql(u8, arg, "--session") or
            std.mem.eql(u8, arg, "--provider") or
            std.mem.eql(u8, arg, "--model") or
            std.mem.eql(u8, arg, "--temperature") or
            std.mem.eql(u8, arg, "--agent") or
            std.mem.eql(u8, arg, "--workspace") or
            std.mem.eql(u8, arg, "--skill"))
        {
            if (i + 1 < args.len) i += 1;
        }
    }
    return false;
}

fn agentAdminRequested(args: []const []const u8) bool {
    if (args.len == 0) return false;
    return std.mem.eql(u8, args[0], "invoke") or std.mem.eql(u8, args[0], "sessions");
}

fn gatewayHelpRequested(args: []const []const u8) bool {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return true;
        }
        if (std.mem.eql(u8, arg, "--port") or
            std.mem.eql(u8, arg, "-p") or
            std.mem.eql(u8, arg, "--host") or
            std.mem.eql(u8, arg, "--workspace"))
        {
            if (i + 1 < args.len) i += 1;
        }
    }
    return false;
}

fn applyGatewayDaemonOverrides(cfg: *yc.config.Config, sub_args: []const []const u8) GatewayDaemonOverrideError!void {
    var port: u16 = cfg.gateway.port;
    var host: []const u8 = cfg.gateway.host;

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        if ((std.mem.eql(u8, sub_args[i], "--port") or std.mem.eql(u8, sub_args[i], "-p")) and i + 1 < sub_args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, sub_args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, sub_args[i], "--host") and i + 1 < sub_args.len) {
            i += 1;
            host = sub_args[i];
        } else if (std.mem.eql(u8, sub_args[i], "--workspace") and i + 1 < sub_args.len) {
            i += 1;
            cfg.workspace_dir = sub_args[i];
        }
    }

    cfg.gateway.port = port;
    cfg.gateway.host = host;
}

// ── Gateway ──────────────────────────────────────────────────────

fn printGatewayUsage() void {
    std.debug.print(
        \\Usage: nullclaw gateway [options]
        \\
        \\Start the gateway server (HTTP/WebSocket).
        \\
        \\OPTIONS:
        \\  --port PORT, -p PORT   Override gateway listen port
        \\  --host HOST            Override gateway listen host
        \\  --workspace PATH       Override workspace directory
        \\  --verbose, -v          Enable verbose logging
        \\  --help, -h             Show this help
        \\
    , .{});
}

fn printAgentUsage() void {
    std.debug.print(
        \\Usage: nullclaw agent [options]
        \\
        \\Start the AI agent loop.
        \\
        \\OPTIONS:
        \\  invoke --message MESSAGE [--session SESSION] [--workspace PATH] [--skill SKILL] [--json]
        \\                               Run one machine-readable agent turn
        \\  sessions list [--json]       List persisted agent sessions
        \\  sessions get <session> [--json]
        \\                               Show persisted session metadata
        \\  sessions terminate <session> [--json]
        \\                               Clear persisted session state
        \\
        \\INTERACTIVE / SINGLE-TURN MODE:
        \\  -m, --message MESSAGE        Run a single message (non-interactive)
        \\  -s, --session SESSION         Resume a specific session
        \\  --provider PROVIDER           Override default provider
        \\  --model MODEL                 Override default model
        \\  --temperature TEMP            Override sampling temperature
        \\  --workspace PATH              Override workspace directory
        \\  --skill SKILL                 Activate a named skill at startup
        \\  --verbose, -v                 Enable verbose logging
        \\  --help, -h                    Show this help
        \\
    , .{});
}

const HistoryStoreContext = struct {
    cfg: yc.config.Config,
    mem_rt: yc.memory.MemoryRuntime,
    session_store: yc.memory.SessionStore,

    fn init(allocator: std.mem.Allocator, workspace_override: ?[]const u8) !HistoryStoreContext {
        var cfg = yc.config.Config.load(allocator) catch return error.ConfigNotFound;
        errdefer cfg.deinit();
        applyHistoryWorkspaceOverride(&cfg, workspace_override);

        var history_memory_cfg = buildHistoryMemoryConfig(cfg.memory);
        var mem_rt = yc.memory.initRuntime(allocator, &history_memory_cfg, cfg.workspace_dir) orelse return error.MemoryRuntimeUnavailable;
        errdefer mem_rt.deinit();

        const session_store = mem_rt.session_store orelse return error.SessionStoreUnavailable;
        return .{
            .cfg = cfg,
            .mem_rt = mem_rt,
            .session_store = session_store,
        };
    }

    fn deinit(self: *HistoryStoreContext) void {
        self.mem_rt.deinit();
        self.cfg.deinit();
        self.* = undefined;
    }
};

fn applyHistoryWorkspaceOverride(cfg: *yc.config.Config, workspace_override: ?[]const u8) void {
    if (workspace_override) |workspace| {
        cfg.workspace_dir = workspace;
    }
}

fn runDoctorCommand(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len == 0) {
        try yc.doctor.run(allocator);
        return;
    }
    if (sub_args.len == 1 and std.mem.eql(u8, sub_args[0], "--json")) {
        yc.doctor.runJson(allocator) catch |err| {
            writeJsonError("doctor_failed", @errorName(err), null);
            std_compat.process.exit(1);
        };
        return;
    }

    std.debug.print("Usage: nullclaw doctor [--json]\n", .{});
    std_compat.process.exit(1);
}

fn selfCommandResult(allocator: std.mem.Allocator, args: []const []const u8) !std_compat.process.Child.RunResult {
    const exe_path = try std_compat.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, exe_path);
    for (args) |arg| try argv.append(allocator, arg);

    return std_compat.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
    });
}

fn trimTrailingNewline(text: []const u8) []const u8 {
    var trimmed = text;
    while (trimmed.len > 0 and (trimmed[trimmed.len - 1] == '\n' or trimmed[trimmed.len - 1] == '\r')) {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    return trimmed;
}

fn appendAgentSessionListJson(out: anytype, sessions: []const yc.memory.SessionInfo, total: u64) !void {
    try out.writeAll("{\"sessions\":[");
    for (sessions, 0..) |session, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.writeAll("{\"session_key\":");
        try writeJsonString(out, session.session_id);
        try out.writeAll(",\"created_at\":");
        try writeJsonString(out, session.first_message_at);
        try out.writeAll(",\"last_active\":");
        try writeJsonString(out, session.last_message_at);
        try out.print(",\"turn_count\":{d},\"turn_running\":false}}", .{session.message_count / 2});
    }
    try out.print("],\"total\":{d}}}", .{total});
}

fn writeAgentSessionListJson(sessions: []const yc.memory.SessionInfo, total: u64) !void {
    writeRenderedJsonLine(appendAgentSessionListJson, .{ sessions, total });
}

fn appendAgentSessionDetailJson(out: anytype, session: yc.memory.SessionInfo) !void {
    try out.writeAll("{\"session_key\":");
    try writeJsonString(out, session.session_id);
    try out.writeAll(",\"created_at\":");
    try writeJsonString(out, session.first_message_at);
    try out.writeAll(",\"last_active\":");
    try writeJsonString(out, session.last_message_at);
    try out.print(",\"turn_count\":{d},\"turn_running\":false}}", .{session.message_count / 2});
}

fn writeAgentSessionDetailJson(session: yc.memory.SessionInfo) void {
    writeRenderedJsonLine(appendAgentSessionDetailJson, .{session});
}

fn appendAgentInvokeResponseJson(out: anytype, session_key: []const u8, response: []const u8, turn_count: u64) !void {
    try out.writeAll("{\"session\":");
    try writeJsonString(out, session_key);
    try out.writeAll(",\"response\":");
    try writeJsonString(out, response);
    try out.print(",\"turn_count\":{d}}}", .{turn_count});
}

fn runAgentAdmin(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len == 0) {
        printAgentUsage();
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];
    if (std.mem.eql(u8, subcmd, "invoke")) {
        try runAgentInvokeJson(allocator, sub_args[1..]);
        return;
    }
    if (std.mem.eql(u8, subcmd, "sessions")) {
        try runAgentSessionsAdmin(allocator, sub_args[1..]);
        return;
    }

    printAgentUsage();
    std_compat.process.exit(1);
}

const AgentInvokeForwardOptions = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    temperature: ?[]const u8 = null,
    agent_name: ?[]const u8 = null,
    workspace: ?[]const u8 = null,
    skill_name: ?[]const u8 = null,
};

fn appendAgentInvokeForwardArgs(
    allocator: std.mem.Allocator,
    argv: *std.ArrayListUnmanaged([]const u8),
    message_text: []const u8,
    session: []const u8,
    options: AgentInvokeForwardOptions,
) !void {
    try argv.append(allocator, "agent");
    try argv.append(allocator, "-m");
    try argv.append(allocator, message_text);
    try argv.append(allocator, "-s");
    try argv.append(allocator, session);
    if (options.provider) |value| {
        try argv.append(allocator, "--provider");
        try argv.append(allocator, value);
    }
    if (options.model) |value| {
        try argv.append(allocator, "--model");
        try argv.append(allocator, value);
    }
    if (options.temperature) |value| {
        try argv.append(allocator, "--temperature");
        try argv.append(allocator, value);
    }
    if (options.agent_name) |value| {
        try argv.append(allocator, "--agent");
        try argv.append(allocator, value);
    }
    if (options.workspace) |value| {
        try argv.append(allocator, "--workspace");
        try argv.append(allocator, value);
    }
    if (options.skill_name) |value| {
        try argv.append(allocator, "--skill");
        try argv.append(allocator, value);
    }
}

fn runAgentInvokeJson(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var message: ?[]const u8 = null;
    var session: ?[]const u8 = null;
    var provider: ?[]const u8 = null;
    var model: ?[]const u8 = null;
    var temperature: ?[]const u8 = null;
    var agent_name: ?[]const u8 = null;
    var workspace: ?[]const u8 = null;
    var skill_name: ?[]const u8 = null;
    var json_mode = false;

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        const arg = sub_args[i];
        if (std.mem.eql(u8, arg, "--message") or std.mem.eql(u8, arg, "-m")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --message", null);
                std_compat.process.exit(1);
            }
            i += 1;
            message = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--session") or std.mem.eql(u8, arg, "-s")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --session", null);
                std_compat.process.exit(1);
            }
            i += 1;
            session = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--provider")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --provider", null);
                std_compat.process.exit(1);
            }
            i += 1;
            provider = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--model")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --model", null);
                std_compat.process.exit(1);
            }
            i += 1;
            model = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--temperature")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --temperature", null);
                std_compat.process.exit(1);
            }
            i += 1;
            temperature = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--agent")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --agent", null);
                std_compat.process.exit(1);
            }
            i += 1;
            agent_name = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--workspace")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --workspace", null);
                std_compat.process.exit(1);
            }
            i += 1;
            workspace = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--skill")) {
            if (i + 1 >= sub_args.len) {
                writeJsonError("bad_request", "Missing value for --skill", null);
                std_compat.process.exit(1);
            }
            i += 1;
            skill_name = sub_args[i];
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
        } else {
            writeJsonError("bad_request", "Unknown option for agent invoke", null);
            std_compat.process.exit(1);
        }
    }

    if (!json_mode) {
        writeJsonError("bad_request", "agent invoke requires --json", null);
        std_compat.process.exit(1);
    }
    const message_text = message orelse {
        writeJsonError("bad_request", "agent invoke requires --message", null);
        std_compat.process.exit(1);
    };
    if (std.mem.trim(u8, message_text, " \t\r\n").len == 0) {
        writeJsonError("bad_request", "agent invoke message must not be empty", null);
        std_compat.process.exit(1);
    }

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(allocator);

    const effective_session = session orelse "api:default";
    try appendAgentInvokeForwardArgs(allocator, &argv, message_text, effective_session, .{
        .provider = provider,
        .model = model,
        .temperature = temperature,
        .agent_name = agent_name,
        .workspace = workspace,
        .skill_name = skill_name,
    });

    const result = selfCommandResult(allocator, argv.items) catch |err| {
        writeJsonError("agent_invoke_failed", @errorName(err), null);
        std_compat.process.exit(1);
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    }) {
        var ctx = HistoryStoreContext.init(allocator, workspace) catch |err| switch (err) {
            error.ConfigNotFound => {
                writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
                std_compat.process.exit(1);
            },
            error.MemoryRuntimeUnavailable => {
                writeJsonError("session_store_unavailable", "Failed to initialize session store", null);
                std_compat.process.exit(1);
            },
            error.SessionStoreUnavailable => {
                writeJsonError("session_store_unavailable", "Session store not available for configured backend", null);
                std_compat.process.exit(1);
            },
        };
        defer ctx.deinit();

        const total = ctx.session_store.countDetailedMessages(effective_session) catch 0;
        const turn_count: u64 = total / 2;
        const response_text = trimTrailingNewline(result.stdout);

        writeRenderedJsonLine(appendAgentInvokeResponseJson, .{ effective_session, response_text, turn_count });
        return;
    }

    const stderr_line = trimTrailingNewline(result.stderr);
    if (stderr_line.len > 0) {
        writeJsonError("agent_invoke_failed", stderr_line, null);
    } else {
        writeJsonError("agent_invoke_failed", "Agent invocation failed", null);
    }
    std_compat.process.exit(1);
}

fn runAgentSessionsAdmin(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len == 0) {
        writeJsonError("bad_request", "Usage: nullclaw agent sessions <list|get|terminate> ...", null);
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];
    const json_mode = hasJsonFlag(sub_args[1..]);

    var ctx = HistoryStoreContext.init(allocator, null) catch |err| switch (err) {
        error.ConfigNotFound => {
            if (json_mode) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
            std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
            std_compat.process.exit(1);
        },
        error.MemoryRuntimeUnavailable, error.SessionStoreUnavailable => {
            if (json_mode) writeJsonError("session_store_unavailable", "Session store is not available for configured backend", null);
            std.debug.print("Session store is not available for configured backend\n", .{});
            std_compat.process.exit(1);
        },
    };
    defer ctx.deinit();

    if (std.mem.eql(u8, subcmd, "list")) {
        if (sub_args.len > 2 or !json_mode) {
            writeJsonError("bad_request", "Usage: nullclaw agent sessions list --json", null);
            std_compat.process.exit(1);
        }
        const total = ctx.session_store.countSessions() catch |err| {
            writeJsonError("session_list_failed", @errorName(err), ctx.cfg.memory.backend);
            std_compat.process.exit(1);
        };
        const sessions = ctx.session_store.listSessions(allocator, @intCast(@max(total, 1)), 0) catch |err| {
            writeJsonError("session_list_failed", @errorName(err), ctx.cfg.memory.backend);
            std_compat.process.exit(1);
        };
        defer yc.memory.freeSessionInfos(allocator, sessions);
        try writeAgentSessionListJson(sessions, total);
        return;
    }

    if (sub_args.len < 2 or !json_mode) {
        writeJsonError("bad_request", "Usage: nullclaw agent sessions <get|terminate> <session> --json", null);
        std_compat.process.exit(1);
    }
    const session_key = sub_args[1];

    const total = ctx.session_store.countSessions() catch |err| {
        writeJsonError("session_list_failed", @errorName(err), ctx.cfg.memory.backend);
        std_compat.process.exit(1);
    };
    const sessions = ctx.session_store.listSessions(allocator, @intCast(@max(total, 1)), 0) catch |err| {
        writeJsonError("session_list_failed", @errorName(err), ctx.cfg.memory.backend);
        std_compat.process.exit(1);
    };
    defer yc.memory.freeSessionInfos(allocator, sessions);

    const session = blk: {
        for (sessions) |item| {
            if (std.mem.eql(u8, item.session_id, session_key)) break :blk item;
        }
        break :blk null;
    };

    if (std.mem.eql(u8, subcmd, "get")) {
        if (session) |value| {
            writeAgentSessionDetailJson(value);
            return;
        }
        writeJsonError("session_not_found", "No session with that key", ctx.cfg.memory.backend);
        std_compat.process.exit(1);
    }

    if (std.mem.eql(u8, subcmd, "terminate")) {
        if (session == null) {
            writeJsonError("session_not_found", "No session with that key", ctx.cfg.memory.backend);
            std_compat.process.exit(1);
        }

        ctx.session_store.clearMessages(session_key) catch |err| {
            writeJsonError("session_terminate_failed", @errorName(err), ctx.cfg.memory.backend);
            std_compat.process.exit(1);
        };
        ctx.session_store.clearAutoSaved(session_key) catch {};

        const entries_opt = ctx.mem_rt.memory.list(allocator, null, session_key) catch null;
        if (entries_opt) |entries| {
            defer yc.memory.freeEntries(allocator, entries);
            for (entries) |entry| {
                _ = ctx.mem_rt.memory.forgetScoped(allocator, entry.key, session_key) catch {};
            }
        }

        writeRenderedJsonLine(appendAgentSessionTerminationJson, .{session_key});
        return;
    }

    writeJsonError("bad_request", "Unknown agent sessions command", null);
    std_compat.process.exit(1);
}

fn runGateway(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (gatewayHelpRequested(sub_args)) {
        printGatewayUsage();
        return;
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    applyGatewayDaemonOverrides(&cfg, sub_args) catch {
        std.debug.print("Invalid port in CLI args.\n", .{});
        std_compat.process.exit(1);
    };

    if (!yc.security.isYoloGatewayAllowed(cfg.autonomy.level, cfg.gateway.host, yc.security.isYoloForceEnabled(allocator))) {
        std.debug.print(
            "Refusing to start gateway with autonomy.level=yolo on non-local host '{s}'. Use localhost or set NULLCLAW_ALLOW_YOLO=1 to force this insecure mode.\n",
            .{cfg.gateway.host},
        );
        std_compat.process.exit(1);
    }

    // Check both sub_args and global args for --verbose flag
    var verbose = hasVerboseFlag(sub_args);
    if (!verbose) {
        // Also check global args for --verbose flag
        const args = std_compat.process.argsAlloc(allocator) catch &.{};
        defer std_compat.process.argsFree(allocator, args);
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
                verbose = true;
                break;
            }
        }
    }
    if (verbose) {
        log.warn("Verbose flag detected, enabling verbose logging", .{});
        yc.verbose.setVerbose(true);
    }
    cfg.validate() catch |err| {
        yc.config.Config.printValidationError(err);
        std_compat.process.exit(1);
    };
    applyRuntimeProviderOverrides(&cfg);

    try yc.daemon.run(allocator, &cfg, cfg.gateway.host, cfg.gateway.port);
}

// ── Service ──────────────────────────────────────────────────────

fn runService(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint("Usage: nullclaw service <{s}>\n", .{SERVICE_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];
    const service_cmd: yc.service.ServiceCommand = blk: {
        const map = .{
            .{ "install", yc.service.ServiceCommand.install },
            .{ "start", yc.service.ServiceCommand.start },
            .{ "stop", yc.service.ServiceCommand.stop },
            .{ "restart", yc.service.ServiceCommand.restart },
            .{ "status", yc.service.ServiceCommand.status },
            .{ "uninstall", yc.service.ServiceCommand.uninstall },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, subcmd, entry[0])) break :blk entry[1];
        }
        std.debug.print("Unknown service command: {s}\n", .{subcmd});
        std.debug.print(std.fmt.comptimePrint("Usage: nullclaw service <{s}>\n", .{SERVICE_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    };

    yc.service.handleCommand(allocator, service_cmd) catch |err| {
        const any_err: anyerror = err;
        switch (any_err) {
            error.UnsupportedPlatform => {
                std.debug.print("Service management is not supported on this platform.\n", .{});
            },
            error.NoHomeDir => {
                std.debug.print("Could not resolve home directory for service files.\n", .{});
            },
            error.OpenRcUnavailable => {
                std.debug.print("OpenRC was detected, but the required OpenRC commands are unavailable.\n", .{});
                std.debug.print("Verify `rc-service`, `rc-update`, and `openrc-run` are installed.\n", .{});
            },
            error.SystemctlUnavailable => {
                std.debug.print("`systemctl` is not available and no supported Linux fallback service manager was detected.\n", .{});
                std.debug.print("Install OpenRC or SysVinit support, or run `nullclaw gateway` in the foreground.\n", .{});
            },
            error.SystemdUserUnavailable => {
                std.debug.print("systemd user services are unavailable (`systemctl --user`).\n", .{});
                std.debug.print("Verify with `systemctl --user status` or run `nullclaw gateway` in the foreground.\n", .{});
            },
            error.CommandFailed => {
                std.debug.print("Service command failed: {s}\n", .{subcmd});
            },
            else => return any_err,
        }
        std_compat.process.exit(1);
    };
}

// ── Cron ─────────────────────────────────────────────────────────

const CronAddAgentOptions = struct {
    model: ?[]const u8 = null,
    session_target: yc.cron.SessionTarget = .isolated,
    delivery: yc.cron.DeliveryConfig = .{},
};

fn parseCronSessionTargetArg(raw: []const u8) !yc.cron.SessionTarget {
    return yc.cron.SessionTarget.parseStrict(raw);
}

fn cronAgentOptionValue(sub_args: []const []const u8, option_index: usize) ![]const u8 {
    if (option_index + 1 >= sub_args.len or std.mem.startsWith(u8, sub_args[option_index + 1], "--")) {
        return error.MissingCronOptionValue;
    }
    return sub_args[option_index + 1];
}

fn parseCronAgentOptions(sub_args: []const []const u8, start_index: usize) !CronAddAgentOptions {
    var options = CronAddAgentOptions{};
    var i: usize = start_index;
    while (i < sub_args.len) : (i += 1) {
        if (std.mem.eql(u8, sub_args[i], "--model")) {
            options.model = try cronAgentOptionValue(sub_args, i);
            i += 1;
        } else if (std.mem.eql(u8, sub_args[i], "--session-target")) {
            options.session_target = try parseCronSessionTargetArg(try cronAgentOptionValue(sub_args, i));
            i += 1;
        } else if (std.mem.eql(u8, sub_args[i], "--announce")) {
            options.delivery.mode = .always;
        } else if (std.mem.eql(u8, sub_args[i], "--channel")) {
            options.delivery.channel = try cronAgentOptionValue(sub_args, i);
            i += 1;
        } else if (std.mem.eql(u8, sub_args[i], "--account")) {
            options.delivery.account_id = try cronAgentOptionValue(sub_args, i);
            i += 1;
        } else if (std.mem.eql(u8, sub_args[i], "--to")) {
            options.delivery.to = try cronAgentOptionValue(sub_args, i);
            i += 1;
        } else {
            return error.UnknownCronOption;
        }
    }
    return options;
}

fn parseCronAddAgentOptions(sub_args: []const []const u8) !CronAddAgentOptions {
    return parseCronAgentOptions(sub_args, 3);
}

fn runCron(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw cron <{s}> [args]
            \\
            \\Commands:
            \\  list [--json]                 List all scheduled tasks
            \\  get <id> [--json]             Show one scheduled task
            \\  status [--json]               Show scheduler daemon status
            \\  add <expression> <command>    Add a recurring cron job
            \\  add-agent <expression> <prompt> [--model <model>] [--session-target <isolated|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]
            \\                                Add a recurring agent cron job
            \\  once <delay> <command>        Add a one-shot delayed task
            \\  once-agent <delay> <prompt> [--model <model>] [--session-target <isolated|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]
            \\                                Add a one-shot delayed agent task
            \\  remove <id>                   Remove a scheduled task
            \\  pause <id>                    Pause a scheduled task
            \\  resume <id>                   Resume a paused task
            \\  run <id>                      Run a scheduled task immediately
            \\  update <id> [options]         Update a cron job
            \\  runs <id> [--limit N] [--json]
            \\                                List recent run history for a job
            \\
        , .{CRON_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            std.debug.print("Usage: nullclaw cron list [--json]\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliListJobs(allocator, hasJsonFlag(sub_args[1..]));
    } else if (std.mem.eql(u8, subcmd, "get")) {
        if (sub_args.len < 2 or sub_args.len > 3 or (sub_args.len == 3 and !std.mem.eql(u8, sub_args[2], "--json"))) {
            std.debug.print("Usage: nullclaw cron get <id> [--json]\n", .{});
            std_compat.process.exit(1);
        }

        var scheduler = yc.cron.CronScheduler.init(allocator, 1024, true);
        defer scheduler.deinit();
        try yc.cron.loadJobs(&scheduler);

        const job = scheduler.getJob(sub_args[1]) orelse {
            if (hasJsonFlag(sub_args[2..])) {
                printStdoutBytes("null\n");
            } else {
                std.debug.print("Cron job '{s}' not found\n", .{sub_args[1]});
                std_compat.process.exit(1);
            }
            return;
        };

        if (hasJsonFlag(sub_args[2..])) {
            writeCronJobJson(job);
        } else {
            std.debug.print("Cron job: {s}\n", .{job.id});
            std.debug.print("  Expression:  {s}\n", .{job.expression});
            std.debug.print("  Command:     {s}\n", .{job.command});
            std.debug.print("  Type:        {s}\n", .{job.job_type.asStr()});
            std.debug.print("  Next run:    {d}\n", .{job.next_run_secs});
        }
    } else if (std.mem.eql(u8, subcmd, "status")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            std.debug.print("Usage: nullclaw cron status [--json]\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliStatus(allocator, hasJsonFlag(sub_args[1..]));
    } else if (std.mem.eql(u8, subcmd, "add")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron add <expression> <command>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliAddJob(allocator, sub_args[1], sub_args[2]);
    } else if (std.mem.eql(u8, subcmd, "add-agent")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron add-agent <expression> <prompt> [--model <model>] [--session-target <isolated|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]\n", .{});
            std_compat.process.exit(1);
        }
        const options = parseCronAddAgentOptions(sub_args) catch |err| switch (err) {
            error.InvalidSessionTarget => {
                std.debug.print("Invalid --session-target: expected 'isolated' or 'main'\n", .{});
                std_compat.process.exit(1);
            },
            error.MissingCronOptionValue => {
                std.debug.print("Missing value for cron agent option\n", .{});
                std_compat.process.exit(1);
            },
            error.UnknownCronOption => {
                std.debug.print("Unknown cron agent option\n", .{});
                std_compat.process.exit(1);
            },
        };
        try yc.cron.cliAddAgentJob(allocator, sub_args[1], sub_args[2], options.model, options.session_target, options.delivery);
    } else if (std.mem.eql(u8, subcmd, "once")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron once <delay> <command>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliAddOnce(allocator, sub_args[1], sub_args[2]);
    } else if (std.mem.eql(u8, subcmd, "once-agent")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron once-agent <delay> <prompt> [--model <model>] [--session-target <isolated|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]\n", .{});
            std_compat.process.exit(1);
        }
        const options = parseCronAgentOptions(sub_args, 3) catch |err| switch (err) {
            error.InvalidSessionTarget => {
                std.debug.print("Invalid --session-target: expected 'isolated' or 'main'\n", .{});
                std_compat.process.exit(1);
            },
            error.MissingCronOptionValue => {
                std.debug.print("Missing value for cron agent option\n", .{});
                std_compat.process.exit(1);
            },
            error.UnknownCronOption => {
                std.debug.print("Unknown cron agent option\n", .{});
                std_compat.process.exit(1);
            },
        };
        try yc.cron.cliAddAgentOnce(allocator, sub_args[1], sub_args[2], options.model, options.session_target, options.delivery);
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron remove <id>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliRemoveJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "pause")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron pause <id>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliPauseJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "resume")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron resume <id>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliResumeJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "run")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron run <id>\n", .{});
            std_compat.process.exit(1);
        }
        try yc.cron.cliRunJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "update")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron update <id> [--expression <expr>] [--command <cmd>] [--prompt <prompt>] [--model <model>] [--session-target <isolated|main>] [--enable] [--disable]\n", .{});
            std_compat.process.exit(1);
        }
        const id = sub_args[1];
        var expression: ?[]const u8 = null;
        var command: ?[]const u8 = null;
        var prompt: ?[]const u8 = null;
        var model: ?[]const u8 = null;
        var enabled: ?bool = null;
        var session_target: ?yc.cron.SessionTarget = null;
        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--expression") and i + 1 < sub_args.len) {
                i += 1;
                expression = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--command") and i + 1 < sub_args.len) {
                i += 1;
                command = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--prompt") and i + 1 < sub_args.len) {
                i += 1;
                prompt = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--model") and i + 1 < sub_args.len) {
                i += 1;
                model = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--session-target") and i + 1 < sub_args.len) {
                i += 1;
                session_target = parseCronSessionTargetArg(sub_args[i]) catch |err| switch (err) {
                    error.InvalidSessionTarget => {
                        std.debug.print("Invalid --session-target: expected 'isolated' or 'main'\n", .{});
                        std_compat.process.exit(1);
                    },
                };
            } else if (std.mem.eql(u8, sub_args[i], "--enable")) {
                enabled = true;
            } else if (std.mem.eql(u8, sub_args[i], "--disable")) {
                enabled = false;
            }
        }
        yc.cron.cliUpdateJob(allocator, id, expression, command, prompt, model, enabled, session_target) catch |err| switch (err) {
            error.SessionTargetRequiresAgentJob => {
                std.debug.print("session_target can only be updated for agent jobs\n", .{});
                std_compat.process.exit(1);
            },
            else => return err,
        };
    } else if (std.mem.eql(u8, subcmd, "runs")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron runs <id> [--limit N] [--json]\n", .{});
            std_compat.process.exit(1);
        }
        var limit: usize = 10;
        var json_mode = false;
        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw cron runs <id> [--limit N] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for cron runs: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        if (!json_mode and limit == 10 and sub_args.len == 2) {
            try yc.cron.cliListRuns(allocator, sub_args[1]);
            return;
        }

        var scheduler = yc.cron.CronScheduler.init(allocator, 1024, true);
        defer scheduler.deinit();
        try yc.cron.loadJobs(&scheduler);
        const runs = try scheduler.listRuns(allocator, sub_args[1], limit);
        defer allocator.free(runs);

        if (json_mode) {
            writeCronRunsJson(runs);
        } else {
            if (runs.len == 0) {
                std.debug.print("No recorded runs for job '{s}'\n", .{sub_args[1]});
                return;
            }
            std.debug.print("Run history for job {s}:\n", .{sub_args[1]});
            for (runs) |run| {
                std.debug.print("  #{d} {s} {d}->{d}\n", .{ run.id, run.status, run.started_at_s, run.finished_at_s });
            }
        }
    } else {
        std.debug.print("Unknown cron command: {s}\n", .{subcmd});
        std_compat.process.exit(1);
    }
}

// ── Channel ──────────────────────────────────────────────────────

fn runChannel(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw channel <{s}> [args]
            \\
            \\Commands:
            \\  list [--json]                 List configured channels
            \\  info <type> [--json]          Show details for a channel type
            \\  start [channel]               Start a channel (default: first available)
            \\  status                        Show channel health/status
            \\  add <type> <config_json>      Add a channel
            \\  remove <name>                 Remove a channel
            \\
        , .{CHANNEL_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];
    const wants_json = hasJsonFlag(sub_args[1..]);

    var cfg = yc.config.Config.load(allocator) catch {
        if (wants_json) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    if (std.mem.eql(u8, subcmd, "list")) {
        if (wants_json) {
            const items = blk: {
                if (tryReadGatewayRuntimeStatusJson(allocator)) |runtime_status_json| {
                    defer allocator.free(runtime_status_json);
                    if (yc.channel_admin.collectConfiguredChannelsFromRuntimeStatusJson(allocator, &cfg.channels, runtime_status_json)) |live_items| {
                        break :blk live_items;
                    } else |_| {}
                }

                const snapshot = yc.health.snapshot(allocator) catch |err| {
                    writeJsonError("channel_health_failed", "Failed to read channel health", null);
                    std.debug.print("Failed to read channel health: {s}\n", .{@errorName(err)});
                    std_compat.process.exit(1);
                };
                defer snapshot.deinit(allocator);

                break :blk yc.channel_admin.collectConfiguredChannels(allocator, &cfg.channels, snapshot) catch |err| {
                    writeJsonError("channel_list_failed", "Failed to build channel list", null);
                    std.debug.print("Failed to build channel list: {s}\n", .{@errorName(err)});
                    std_compat.process.exit(1);
                };
            };
            defer allocator.free(items);

            const rendered = std.json.Stringify.valueAlloc(allocator, items, .{
                .emit_null_optional_fields = false,
            }) catch |err| {
                writeJsonError("channel_list_failed", "Failed to render channel list", null);
                std.debug.print("Failed to render channel list: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            defer allocator.free(rendered);

            printStdoutBytes(rendered);
            printStdoutBytes("\n");
        } else {
            std.debug.print("Configured channels:\n", .{});
            for (yc.channel_catalog.known_channels) |meta| {
                var status_buf: [64]u8 = undefined;
                const status_text = yc.channel_catalog.statusText(&cfg, meta, &status_buf);
                std.debug.print("  {s}: {s}\n", .{ meta.label, status_text });
            }
        }
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw channel info <type> [--json]\n", .{});
            std_compat.process.exit(1);
        }

        var detail = blk: {
            if (tryReadGatewayRuntimeStatusJson(allocator)) |runtime_status_json| {
                defer allocator.free(runtime_status_json);
                if (yc.channel_admin.readChannelTypeDetailFromRuntimeStatusJson(allocator, &cfg.channels, runtime_status_json, sub_args[1])) |live_detail_opt| {
                    if (live_detail_opt) |live_detail| break :blk live_detail;
                } else |_| {}
            }

            const snapshot = yc.health.snapshot(allocator) catch |err| {
                if (hasJsonFlag(sub_args[2..])) writeJsonError("channel_health_failed", "Failed to read channel health", null);
                std.debug.print("Failed to read channel health: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            defer snapshot.deinit(allocator);

            break :blk yc.channel_admin.readChannelTypeDetail(allocator, &cfg.channels, snapshot, sub_args[1]) catch |err| {
                if (hasJsonFlag(sub_args[2..])) writeJsonError("channel_detail_failed", "Failed to read channel detail", null);
                std.debug.print("Failed to read channel detail: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            } orelse {
                if (hasJsonFlag(sub_args[2..])) writeJsonError("channel_type_not_found", "Unknown channel type", null);
                std.debug.print("Unknown channel type: {s}\n", .{sub_args[1]});
                std_compat.process.exit(1);
            };
        };
        defer detail.deinit(allocator);

        if (hasJsonFlag(sub_args[2..])) {
            const rendered = std.json.Stringify.valueAlloc(allocator, detail, .{
                .emit_null_optional_fields = false,
            }) catch |err| {
                writeJsonError("channel_detail_failed", "Failed to render channel detail", null);
                std.debug.print("Failed to render channel detail: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            defer allocator.free(rendered);

            printStdoutBytes(rendered);
            printStdoutBytes("\n");
        } else {
            std.debug.print("Channel: {s}\n", .{detail.type});
            std.debug.print("  Status: {s}\n", .{detail.status});
            if (detail.accounts.len == 0) {
                std.debug.print("  Accounts: (none configured)\n", .{});
            } else {
                std.debug.print("  Accounts:\n", .{});
                for (detail.accounts) |account| {
                    std.debug.print("    - {s} [{s}]\n", .{ account.account_id, account.status });
                }
            }
        }
    } else if (std.mem.eql(u8, subcmd, "start")) {
        try runChannelStart(allocator, sub_args[1..]);
    } else if (std.mem.eql(u8, subcmd, "status")) {
        std.debug.print("Channel health:\n", .{});
        std.debug.print("  CLI: ok\n", .{});
        for (yc.channel_catalog.known_channels) |meta| {
            if (meta.id == .cli) continue;
            if (!yc.channel_catalog.isConfigured(&cfg, meta.id)) continue;
            std.debug.print("  {s}: configured (use `channel start` to verify)\n", .{meta.label});
        }
    } else if (std.mem.eql(u8, subcmd, "add")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw channel add <type>\n", .{});
            std.debug.print("Types:", .{});
            for (yc.channel_catalog.known_channels) |meta| {
                if (meta.id == .cli) continue;
                std.debug.print(" {s}", .{meta.key});
            }
            std.debug.print("\n", .{});
            std_compat.process.exit(1);
        }
        std.debug.print("To add a '{s}' channel, edit your config file:\n  {s}\n", .{ sub_args[1], cfg.config_path });
        std.debug.print("Add a \"{s}\" object under \"channels\" with the required fields.\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw channel remove <name>\n", .{});
            std_compat.process.exit(1);
        }
        std.debug.print("To remove the '{s}' channel, edit your config file:\n  {s}\n", .{ sub_args[1], cfg.config_path });
        std.debug.print("Remove or set the \"{s}\" object to null under \"channels\".\n", .{sub_args[1]});
    } else {
        std.debug.print("Unknown channel command: {s}\n", .{subcmd});
        std_compat.process.exit(1);
    }
}

fn tryReadGatewayRuntimeStatusJson(allocator: std.mem.Allocator) ?[]const u8 {
    switch (yc.cron.requestGatewayGet(allocator, "/status")) {
        .unavailable => return null,
        .response => |resp| {
            if (resp.status_code >= 200 and resp.status_code < 300) {
                return resp.body;
            }
            allocator.free(resp.body);
            return null;
        },
    }
}

// ── Skills ───────────────────────────────────────────────────────

fn runSkills(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw skills <{s}> [args]
            \\
            \\Commands:
            \\  list [--json]                 List installed skills
            \\  install <source>              Install from GitHub URL or path
            \\  install --name <query>        Search registry and install best match
            \\  remove <name>                 Remove a skill
            \\  info <name> [--json]          Show skill details
            \\
        , .{SKILLS_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        const json_mode = hasJsonFlag(sub_args[1..]);
        var visible = loadVisibleSkills(allocator, cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to list skills: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer visible.deinit(allocator);

        if (json_mode) {
            writeSkillListJson(cfg.workspace_dir, visible.community_base, visible.skills);
        } else {
            if (visible.skills.len == 0) {
                std.debug.print("No skills installed.\n", .{});
            } else {
                std.debug.print("Installed skills ({d}):\n", .{visible.skills.len});
                for (visible.skills) |skill| {
                    std.debug.print("  {s} v{s}", .{ skill.name, skill.version });
                    if (skill.description.len > 0) {
                        std.debug.print(" -- {s}", .{skill.description});
                    }
                    const source = skillSource(cfg.workspace_dir, visible.community_base, skill);
                    if (!std.mem.eql(u8, source, "workspace")) {
                        std.debug.print(" [{s}]", .{source});
                    }
                    if (!skill.available and skill.missing_deps.len > 0) {
                        std.debug.print(" (missing:{s})", .{skill.missing_deps});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
    } else if (std.mem.eql(u8, subcmd, "install")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills install <source> | --name <query>\n", .{});
            std_compat.process.exit(1);
        }
        var install_name: ?[]const u8 = null;
        var direct_source: ?[]const u8 = null;
        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            const arg = sub_args[i];
            if (std.mem.eql(u8, arg, "--name")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw skills install --name <query>\n", .{});
                    std_compat.process.exit(1);
                }
                if (install_name != null or direct_source != null) {
                    std.debug.print("Provide only one install target.\n", .{});
                    std_compat.process.exit(1);
                }
                install_name = sub_args[i + 1];
                i += 1;
                continue;
            }
            if (std.mem.startsWith(u8, arg, "--")) {
                std.debug.print("Unknown skills install option: {s}\n", .{arg});
                std_compat.process.exit(1);
            }
            if (direct_source != null or install_name != null) {
                std.debug.print("Provide only one install target.\n", .{});
                std_compat.process.exit(1);
            }
            direct_source = arg;
        }
        if (install_name == null and direct_source == null) {
            std.debug.print("Usage: nullclaw skills install <source> | --name <query>\n", .{});
            std_compat.process.exit(1);
        }
        var install_error_detail: ?[]u8 = null;
        defer if (install_error_detail) |msg| allocator.free(msg);
        if (install_name) |query| {
            yc.skills.installSkillByNameWithDetail(allocator, query, cfg.workspace_dir, &install_error_detail) catch |err| {
                if (install_error_detail) |msg| {
                    std.debug.print("{s}\n", .{msg});
                }
                std.debug.print("Failed to install skill: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            std.debug.print("Skill installed from registry search: {s}\n", .{query});
            return;
        }
        yc.skills.installSkillWithDetail(allocator, direct_source.?, cfg.workspace_dir, &install_error_detail) catch |err| {
            if (install_error_detail) |msg| {
                std.debug.print("{s}\n", .{msg});
            }
            std.debug.print("Failed to install skill: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        std.debug.print("Skill installed from: {s}\n", .{direct_source.?});
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills remove <name>\n", .{});
            std_compat.process.exit(1);
        }
        yc.skills.removeSkill(allocator, sub_args[1], cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to remove skill '{s}': {s}\n", .{ sub_args[1], @errorName(err) });
            std_compat.process.exit(1);
        };
        std.debug.print("Removed skill: {s}\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills info <name> [--json]\n", .{});
            std_compat.process.exit(1);
        }
        const json_mode = hasJsonFlag(sub_args[2..]);
        var visible = loadVisibleSkills(allocator, cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to list skills: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer visible.deinit(allocator);

        const skill = findSkillByName(visible.skills, sub_args[1]) orelse {
            if (json_mode) {
                printStdoutBytes("null\n");
                return;
            } else {
                std.debug.print("Skill '{s}' not found or invalid.\n", .{sub_args[1]});
            }
            std_compat.process.exit(1);
        };

        if (json_mode) {
            writeSkillDetailJson(cfg.workspace_dir, visible.community_base, skill.*);
        } else {
            std.debug.print("Skill: {s}\n", .{skill.name});
            std.debug.print("  Version:     {s}\n", .{skill.version});
            if (skill.description.len > 0) {
                std.debug.print("  Description: {s}\n", .{skill.description});
            }
            if (skill.author.len > 0) {
                std.debug.print("  Author:      {s}\n", .{skill.author});
            }
            std.debug.print("  Enabled:     {}\n", .{skill.enabled});
            std.debug.print("  Available:   {}\n", .{skill.available});
            std.debug.print("  Source:      {s}\n", .{skillSource(cfg.workspace_dir, visible.community_base, skill.*)});
            std.debug.print("  Path:        {s}\n", .{skill.path});
            if (skill.missing_deps.len > 0) {
                std.debug.print("  Missing:     {s}\n", .{skill.missing_deps});
            }
            if (skill.instructions.len > 0) {
                std.debug.print("  Instructions: {d} bytes\n", .{skill.instructions.len});
            }
        }
    } else {
        std.debug.print("Unknown skills command: {s}\n", .{subcmd});
        std_compat.process.exit(1);
    }
}

// ── Hardware ─────────────────────────────────────────────────────

fn runHardware(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw hardware <{s}> [args]
            \\
            \\Commands:
            \\  scan                          Scan for connected hardware
            \\  flash                         Flash firmware to a device
            \\  monitor                       Monitor connected devices
            \\
        , .{HARDWARE_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "scan")) {
        std.debug.print("Scanning for hardware devices...\n", .{});
        std.debug.print("Known board registry: {d} entries\n", .{yc.hardware.knownBoards().len});

        const devices = yc.hardware.discoverHardware(allocator) catch |err| {
            std.debug.print("Discovery failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.hardware.freeDiscoveredDevices(allocator, devices);

        if (devices.len == 0) {
            std.debug.print("No recognized devices found.\n", .{});
        } else {
            std.debug.print("Discovered {d} device(s):\n", .{devices.len});
            for (devices) |dev| {
                std.debug.print("  {s}", .{dev.name});
                if (dev.detail) |det| {
                    std.debug.print(" ({s})", .{det});
                }
                if (dev.device_path) |path| {
                    std.debug.print(" @ {s}", .{path});
                }
                std.debug.print("\n", .{});
            }
        }
    } else if (std.mem.eql(u8, subcmd, "flash")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw hardware flash <firmware_file> [--target <board>]\n", .{});
            std_compat.process.exit(1);
        }
        std.debug.print("Flash not yet implemented. Firmware file: {s}\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "monitor")) {
        std.debug.print("Monitor not yet implemented. Use `nullclaw hardware scan` to discover devices first.\n", .{});
    } else {
        std.debug.print("Unknown hardware command: {s}\n", .{subcmd});
        std_compat.process.exit(1);
    }
}

// ── Migrate ──────────────────────────────────────────────────────

fn runMigrate(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw migrate <source> [options]
            \\
            \\Sources:
            \\  openclaw                      Import from OpenClaw workspace (+ config migration)
            \\
            \\Options:
            \\  --dry-run                     Preview without writing
            \\  --source <path>               Source workspace path
            \\
        , .{});
        std_compat.process.exit(1);
    }

    if (std.mem.eql(u8, sub_args[0], "openclaw")) {
        var dry_run = false;
        var source_path: ?[]const u8 = null;

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--dry-run")) {
                dry_run = true;
            } else if (std.mem.eql(u8, sub_args[i], "--source") and i + 1 < sub_args.len) {
                i += 1;
                source_path = sub_args[i];
            }
        }

        var cfg = yc.config.Config.load(allocator) catch {
            std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
            std_compat.process.exit(1);
        };
        defer cfg.deinit();

        const stats = yc.migration.migrateOpenclaw(allocator, &cfg, source_path, dry_run) catch |err| {
            std.debug.print("Migration failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        if (dry_run) {
            std.debug.print("[DRY RUN] ", .{});
        }
        std.debug.print("Migration complete: {d} imported, {d} skipped\n", .{ stats.imported, stats.skipped_unchanged });
        if (stats.config_migrated) {
            if (dry_run) {
                std.debug.print("[DRY RUN] Config migration preview: ~/.openclaw/config.json -> {s}\n", .{cfg.config_path});
            } else {
                std.debug.print("Config migrated: ~/.openclaw/config.json -> {s}\n", .{cfg.config_path});
            }
        }
    } else {
        std.debug.print("Unknown migration source: {s}\n", .{sub_args[0]});
        std_compat.process.exit(1);
    }
}

// ── Memory ───────────────────────────────────────────────────────

fn printMemoryUsage() void {
    std.debug.print(std.fmt.comptimePrint(
        \\Usage: nullclaw memory <{s}> [args]
        \\
        \\Commands:
        \\  stats [--json]                Show resolved memory config and key counters
        \\  count                         Show total number of memory entries
        \\  reindex                       Rebuild vector index from primary memory
        \\  search <query> [--limit N] [--session ID] [--json]
        \\                                Run runtime retrieval (keyword/hybrid)
        \\  get <key> [--session ID] [--json]
        \\                                Show a single memory entry by key
        \\  list [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--json]
        \\                                List memory entries (default limit: 20)
        \\  export-jsonl [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--include-pii]
        \\                                Export redacted memory entries as JSONL (default limit: 1000)
        \\  hygiene-report [--category C] [--limit N] [--session ID] [--include-internal] [--json]
        \\                                Dry-run duplicate/near-duplicate memory report
        \\  store <key> <content> [--category C] [--session ID] [--json]
        \\                                Create or overwrite a memory entry
        \\  update <key> <content> [--category C] [--session ID] [--json]
        \\                                Update an existing memory entry
        \\  delete <key> [--session ID] [--json]
        \\                                Delete an entry from primary memory
        \\  drain-outbox [--json]         Drain durable vector outbox queue
        \\  forget <key>                  Legacy alias for delete
        \\
    , .{MEMORY_SUBCOMMANDS}), .{});
}

fn printWorkspaceUsage() void {
    std.debug.print(std.fmt.comptimePrint(
        \\Usage: nullclaw workspace <{s}> [args]
        \\
        \\Commands:
        \\  edit <filename>
        \\      Open a bootstrap file (SOUL.md, AGENTS.md, etc.) in $EDITOR.
        \\      For file-based backends (markdown, hybrid) edits the file directly.
        \\      For DB-backed backends, use the agent's memory_store tool instead.
        \\
        \\  reset-md [--dry-run] [--include-bootstrap] [--clear-memory-md]
        \\      Reset prompt markdown files (AGENTS/SOUL/TOOLS/IDENTITY/USER/HEARTBEAT)
        \\      to bundled defaults.
        \\      --include-bootstrap  Also rewrite BOOTSTRAP.md
        \\      --clear-memory-md    Remove MEMORY.md and memory.md if present
        \\      --dry-run            Show what would be changed without modifying files
        \\
        \\  audit [--json] [--staged | --commit <sha> | --range <a>..<b>] [--only-secrets] [--exclude <path-substring>] [--fail-on <none|medium|high|critical>]
        \\      Scan the workspace, staged Git diff, or Git history for likely secret leaks.
        \\      --staged             Audit only the staged diff (git diff --cached)
        \\      --commit             Audit a single historical commit via git show
        \\      --range              Audit a git revision range via git diff <a>..<b>
        \\      --json               Emit machine-readable JSON
        \\      --only-secrets       Report only high/critical findings
        \\      --exclude            Repeatable path substring to skip during scanning
        \\      --fail-on            Exit non-zero when findings meet or exceed the threshold
        \\      --llm-triage MODE    LLM triage of findings: off | dry-run | external
        \\                           dry-run prints privacy-safe envelopes without sending
        \\                           external sends envelopes to the agent's configured
        \\                           provider (anthropic/openai/openrouter/ollama/...)
        \\                           (raw secret values are NEVER included in envelopes)
        \\      --llm-model NAME     Model override (default: workspace_audit.llm_triage.model,
        \\                           then cfg.agents.defaults.model.primary)
        \\      --llm-provider NAME  Provider override (default: workspace_audit.llm_triage.provider,
        \\                           then cfg.default_provider)
        \\      --llm-max-calls N    External LLM call cap (default: workspace_audit.llm_triage.max_calls,
        \\                           then 50)
        \\
    , .{WORKSPACE_SUBCOMMANDS}), .{});
}

fn parsePositiveUsize(arg: []const u8) ?usize {
    const n = std.fmt.parseInt(usize, arg, 10) catch return null;
    if (n == 0) return null;
    return n;
}

fn parseNonNegativeUsize(arg: []const u8) ?usize {
    return std.fmt.parseInt(usize, arg, 10) catch null;
}

fn hasJsonFlag(args: []const []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) return true;
    }
    return false;
}

const VisibleSkills = struct {
    skills: []yc.skills.Skill,
    community_base: ?[]u8 = null,

    fn deinit(self: *VisibleSkills, allocator: std.mem.Allocator) void {
        yc.skills.freeSkills(allocator, self.skills);
        if (self.community_base) |path| allocator.free(path);
        self.* = undefined;
    }
};

fn loadVisibleSkills(allocator: std.mem.Allocator, workspace_dir: []const u8) !VisibleSkills {
    var community_base: ?[]u8 = yc.config_paths.defaultConfigDir(allocator) catch null;
    errdefer if (community_base) |path| allocator.free(path);

    if (community_base) |base| {
        if (yc.skills.listSkillsMerged(allocator, base, workspace_dir, null)) |skills| {
            return .{
                .skills = skills,
                .community_base = base,
            };
        } else |_| {
            allocator.free(base);
            community_base = null;
        }
    }

    const skills = try yc.skills.listSkills(allocator, workspace_dir, null);
    for (skills) |*skill| {
        yc.skills.checkRequirements(allocator, skill);
    }
    return .{
        .skills = skills,
        .community_base = null,
    };
}

fn skillSource(workspace_dir: []const u8, community_base: ?[]const u8, skill: yc.skills.Skill) []const u8 {
    if (std.mem.startsWith(u8, skill.path, workspace_dir)) return "workspace";
    if (community_base) |base| {
        if (std.mem.startsWith(u8, skill.path, base)) return "community";
    }
    return "unknown";
}

fn findSkillByName(skills: []const yc.skills.Skill, name: []const u8) ?*const yc.skills.Skill {
    for (skills) |*skill| {
        if (std.mem.eql(u8, skill.name, name)) return skill;
    }
    return null;
}

fn writeJsonString(out: anytype, s: []const u8) !void {
    try out.writeByte('"');
    try writeJsonEscaped(out, s);
    try out.writeByte('"');
}

fn writeJsonNullableString(out: anytype, value: ?[]const u8) !void {
    if (value) |text| {
        try writeJsonString(out, text);
    } else {
        try out.writeAll("null");
    }
}

fn writeJsonNullableU32(out: anytype, value: ?u32) !void {
    if (value) |n| {
        try out.print("{d}", .{n});
    } else {
        try out.writeAll("null");
    }
}

fn writeJsonNullableF32(out: anytype, value: ?f32) !void {
    if (value) |n| {
        try out.print("{d}", .{n});
    } else {
        try out.writeAll("null");
    }
}

fn writeJsonNullableI64(out: anytype, value: ?i64) !void {
    if (value) |n| {
        try out.print("{d}", .{n});
    } else {
        try out.writeAll("null");
    }
}

fn writeJsonBool(out: anytype, value: bool) !void {
    try out.writeAll(if (value) "true" else "false");
}

fn appendJsonError(out: anytype, code: []const u8, message: []const u8, backend: ?[]const u8) !void {
    try out.writeAll("{\"error\":");
    try writeJsonString(out, code);
    try out.writeAll(",\"message\":");
    try writeJsonString(out, message);
    if (backend) |value| {
        try out.writeAll(",\"backend\":");
        try writeJsonString(out, value);
    }
    try out.writeAll("}");
}

fn writeJsonError(code: []const u8, message: []const u8, backend: ?[]const u8) void {
    writeRenderedJsonLine(appendJsonError, .{ code, message, backend });
}

fn appendConfigMutationJson(
    out: anytype,
    action: yc.config_mutator.MutationAction,
    result: *const yc.config_mutator.MutationResult,
) !void {
    try out.writeAll("{\"action\":");
    try writeJsonString(out, @tagName(action));
    try out.writeAll(",\"path\":");
    try writeJsonString(out, result.path);
    try out.writeAll(",\"changed\":");
    try writeJsonBool(out, result.changed);
    try out.writeAll(",\"applied\":");
    try writeJsonBool(out, result.applied);
    try out.writeAll(",\"requires_restart\":");
    try writeJsonBool(out, result.requires_restart);
    try out.writeAll(",\"old_value\":");
    try out.writeAll(result.old_value_json);
    try out.writeAll(",\"new_value\":");
    try out.writeAll(result.new_value_json);
    try out.writeAll(",\"backup_path\":");
    try writeJsonNullableString(out, result.backup_path);
    try out.writeAll("}");
}

fn writeConfigMutationJson(
    action: yc.config_mutator.MutationAction,
    result: *const yc.config_mutator.MutationResult,
) void {
    writeRenderedJsonLine(appendConfigMutationJson, .{ action, result });
}

fn modelCanonicalProvider(raw_model: []const u8) ?[]const u8 {
    const slash = std.mem.indexOfScalar(u8, raw_model, '/') orelse return null;
    if (slash == 0) return null;
    return yc.onboard.canonicalProviderName(raw_model[0..slash]);
}

fn appendModelInfoJson(out: anytype, model_name: []const u8) !void {
    const provider = modelCanonicalProvider(model_name);

    try out.writeAll("{\"name\":");
    try writeJsonString(out, model_name);
    try out.writeAll(",\"provider\":");
    try writeJsonNullableString(out, provider);
    try out.writeAll(",\"canonical_name\":");
    if (provider) |canonical_provider| {
        const slash = std.mem.indexOfScalar(u8, model_name, '/').?;
        if (slash + 1 < model_name.len) {
            try out.writeByte('"');
            try writeJsonEscaped(out, canonical_provider);
            try out.writeByte('/');
            try writeJsonEscaped(out, model_name[slash + 1 ..]);
            try out.writeByte('"');
        } else {
            try writeJsonString(out, canonical_provider);
        }
    } else {
        try writeJsonString(out, model_name);
    }
    try out.writeAll(",\"context_window\":null}");
}

fn writeModelInfoJson(model_name: []const u8) void {
    writeRenderedJsonLine(appendModelInfoJson, .{model_name});
}

fn appendCronJobJson(out: anytype, job: *const yc.cron.CronJob) !void {
    try out.writeAll("{\"id\":");
    try writeJsonString(out, job.id);
    try out.writeAll(",\"expression\":");
    try writeJsonString(out, job.expression);
    try out.writeAll(",\"command\":");
    try writeJsonString(out, job.command);
    try out.print(",\"next_run_secs\":{d}", .{job.next_run_secs});
    try out.writeAll(",\"last_run_secs\":");
    try writeJsonNullableI64(out, job.last_run_secs);
    try out.writeAll(",\"last_status\":");
    try writeJsonNullableString(out, job.last_status);
    try out.writeAll(",\"paused\":");
    try writeJsonBool(out, job.paused);
    try out.writeAll(",\"one_shot\":");
    try writeJsonBool(out, job.one_shot);
    try out.writeAll(",\"job_type\":");
    try writeJsonString(out, job.job_type.asStr());
    try out.writeAll(",\"session_target\":");
    try writeJsonString(out, job.session_target.asStr());
    try out.writeAll(",\"prompt\":");
    try writeJsonNullableString(out, job.prompt);
    try out.writeAll(",\"name\":");
    try writeJsonNullableString(out, job.name);
    try out.writeAll(",\"model\":");
    try writeJsonNullableString(out, job.model);
    try out.writeAll(",\"enabled\":");
    try writeJsonBool(out, job.enabled);
    try out.writeAll(",\"delete_after_run\":");
    try writeJsonBool(out, job.delete_after_run);
    try out.print(",\"created_at_s\":{d}", .{job.created_at_s});
    try out.writeAll(",\"last_output\":");
    try writeJsonNullableString(out, job.last_output);
    try out.writeAll("}");
}

fn writeCronJobJson(job: *const yc.cron.CronJob) void {
    writeRenderedJsonLine(appendCronJobJson, .{job});
}

fn appendCronRunsJson(out: anytype, runs: []const yc.cron.CronRun) !void {
    try out.writeAll("{\"runs\":[");
    for (runs, 0..) |run, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.print("{{\"id\":{d},\"job_id\":", .{run.id});
        try writeJsonString(out, run.job_id);
        try out.print(",\"started_at_s\":{d},\"finished_at_s\":{d},\"status\":", .{ run.started_at_s, run.finished_at_s });
        try writeJsonString(out, run.status);
        try out.writeAll(",\"output\":");
        try writeJsonNullableString(out, run.output);
        try out.writeAll(",\"duration_ms\":");
        try writeJsonNullableI64(out, run.duration_ms);
        try out.writeAll("}");
    }
    try out.print("],\"total\":{d}}}", .{runs.len});
}

fn writeCronRunsJson(runs: []const yc.cron.CronRun) void {
    writeRenderedJsonLine(appendCronRunsJson, .{runs});
}

fn writeSkillJson(
    out: anytype,
    workspace_dir: []const u8,
    community_base: ?[]const u8,
    skill: yc.skills.Skill,
) !void {
    try out.writeAll("{\"name\":");
    try writeJsonString(out, skill.name);
    try out.writeAll(",\"version\":");
    try writeJsonString(out, skill.version);
    try out.writeAll(",\"description\":");
    try writeJsonString(out, skill.description);
    try out.writeAll(",\"author\":");
    try writeJsonString(out, skill.author);
    try out.writeAll(",\"enabled\":");
    try out.writeAll(if (skill.enabled) "true" else "false");
    try out.writeAll(",\"always\":");
    try out.writeAll(if (skill.always) "true" else "false");
    try out.writeAll(",\"available\":");
    try out.writeAll(if (skill.available) "true" else "false");
    try out.writeAll(",\"missing_deps\":");
    try writeJsonString(out, skill.missing_deps);
    try out.writeAll(",\"path\":");
    try writeJsonString(out, skill.path);
    try out.writeAll(",\"source\":");
    try writeJsonString(out, skillSource(workspace_dir, community_base, skill));
    try out.print(",\"instructions_bytes\":{d}}}", .{skill.instructions.len});
}

fn appendSkillListJson(
    out: anytype,
    workspace_dir: []const u8,
    community_base: ?[]const u8,
    skills: []const yc.skills.Skill,
) !void {
    try out.writeAll("[");
    for (skills, 0..) |skill, idx| {
        if (idx > 0) try out.writeAll(",");
        try writeSkillJson(out, workspace_dir, community_base, skill);
    }
    try out.writeAll("]");
}

fn writeSkillListJson(
    workspace_dir: []const u8,
    community_base: ?[]const u8,
    skills: []const yc.skills.Skill,
) void {
    writeRenderedJsonLine(appendSkillListJson, .{ workspace_dir, community_base, skills });
}

fn writeSkillDetailJson(
    workspace_dir: []const u8,
    community_base: ?[]const u8,
    skill: yc.skills.Skill,
) void {
    writeRenderedJsonLine(writeSkillJson, .{ workspace_dir, community_base, skill });
}

fn memoryEntryVisible(include_internal: bool, entry: yc.memory.MemoryEntry) bool {
    return include_internal or !yc.memory.isInternalMemoryEntryKeyOrContent(entry.key, entry.content);
}

fn cloneMemoryCategory(allocator: std.mem.Allocator, category: yc.memory.MemoryCategory) !yc.memory.MemoryCategory {
    return switch (category) {
        .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
        else => category,
    };
}

fn cloneMemoryEntry(allocator: std.mem.Allocator, entry: yc.memory.MemoryEntry) !yc.memory.MemoryEntry {
    const id = try allocator.dupe(u8, entry.id);
    errdefer allocator.free(id);
    const key = try allocator.dupe(u8, entry.key);
    errdefer allocator.free(key);
    const content = try allocator.dupe(u8, entry.content);
    errdefer allocator.free(content);
    const timestamp = try allocator.dupe(u8, entry.timestamp);
    errdefer allocator.free(timestamp);
    const session_id = if (entry.session_id) |sid| try allocator.dupe(u8, sid) else null;
    errdefer if (session_id) |sid| allocator.free(sid);
    const category = try cloneMemoryCategory(allocator, entry.category);
    errdefer switch (category) {
        .custom => |name| allocator.free(name),
        else => {},
    };
    return .{
        .id = id,
        .key = key,
        .content = content,
        .category = category,
        .timestamp = timestamp,
        .session_id = session_id,
        .score = entry.score,
    };
}

fn appendClonedMemoryEntry(
    allocator: std.mem.Allocator,
    kept: *std.ArrayListUnmanaged(yc.memory.MemoryEntry),
    entry: yc.memory.MemoryEntry,
) !void {
    var clone = try cloneMemoryEntry(allocator, entry);
    kept.append(allocator, clone) catch |err| {
        clone.deinit(allocator);
        return err;
    };
}

fn loadMemoryListPage(
    allocator: std.mem.Allocator,
    mem: yc.memory.Memory,
    category: ?yc.memory.MemoryCategory,
    session_id: ?[]const u8,
    limit: usize,
    offset: usize,
    include_internal: bool,
) ![]yc.memory.MemoryEntry {
    if (include_internal) {
        return mem.listPaged(allocator, category, session_id, limit, offset);
    }

    if (!mem.hasNativePagedList()) {
        const entries = try mem.list(allocator, category, session_id);
        defer yc.memory.freeEntries(allocator, entries);

        var visible_seen: usize = 0;
        var kept: std.ArrayListUnmanaged(yc.memory.MemoryEntry) = .empty;
        errdefer {
            for (kept.items) |*entry| entry.deinit(allocator);
            kept.deinit(allocator);
        }

        for (entries) |*entry| {
            if (!memoryEntryVisible(false, entry.*)) {
                continue;
            }
            if (visible_seen < offset) {
                visible_seen += 1;
                continue;
            }
            if (kept.items.len < limit) {
                try appendClonedMemoryEntry(allocator, &kept, entry.*);
            }
        }
        return kept.toOwnedSlice(allocator);
    }

    var kept: std.ArrayListUnmanaged(yc.memory.MemoryEntry) = .empty;
    errdefer {
        for (kept.items) |*entry| entry.deinit(allocator);
        kept.deinit(allocator);
    }

    const chunk_size = @max(limit, @as(usize, 64));
    var raw_offset: usize = 0;
    var visible_seen: usize = 0;

    while (kept.items.len < limit) {
        const page = try mem.listPaged(allocator, category, session_id, chunk_size, raw_offset);
        defer yc.memory.freeEntries(allocator, page);
        if (page.len == 0) {
            break;
        }

        for (page) |*entry| {
            if (!memoryEntryVisible(false, entry.*)) {
                continue;
            }
            if (visible_seen < offset) {
                visible_seen += 1;
                continue;
            }
            if (kept.items.len < limit) {
                try appendClonedMemoryEntry(allocator, &kept, entry.*);
            }
        }

        raw_offset += page.len;
        const short_page = page.len < chunk_size;
        if (short_page) break;
    }

    return kept.toOwnedSlice(allocator);
}

fn writeMemoryEntryJson(out: anytype, entry: yc.memory.MemoryEntry) !void {
    try out.writeAll("{\"key\":");
    try writeJsonString(out, entry.key);
    try out.writeAll(",\"category\":");
    try writeJsonString(out, entry.category.toString());
    try out.writeAll(",\"timestamp\":");
    try writeJsonString(out, entry.timestamp);
    try out.writeAll(",\"content\":");
    try writeJsonString(out, entry.content);
    try out.writeAll(",\"session_id\":");
    try writeJsonNullableString(out, entry.session_id);
    try out.writeAll("}");
}

const MemoryExportOptions = struct {
    category: ?yc.memory.MemoryCategory = null,
    session_id: ?[]const u8 = null,
    limit: usize = 1000,
    offset: usize = 0,
    include_internal: bool = false,
    include_pii: bool = false,
};

const MEMORY_EXPORT_STREAM_CHUNK_SIZE: usize = 64;

const DuplicateStats = struct {
    groups: usize = 0,
    extra_entries: usize = 0,
};

const MemoryHygieneDryRunReport = struct {
    scanned_entries: usize = 0,
    exact_duplicates: DuplicateStats = .{},
    normalized_duplicates: DuplicateStats = .{},
};

const MemoryHygieneOptions = struct {
    category: ?yc.memory.MemoryCategory = null,
    session_id: ?[]const u8 = null,
    limit: usize = 1000,
    include_internal: bool = false,
};

fn writeMemoryExportEntryJson(
    out: anytype,
    entry: yc.memory.MemoryEntry,
    key: []const u8,
    content: []const u8,
    session_id: ?[]const u8,
) !void {
    try out.writeAll("{\"schema_version\":1,\"key\":");
    try writeJsonString(out, key);
    try out.writeAll(",\"category\":");
    try writeJsonString(out, entry.category.toString());
    try out.writeAll(",\"timestamp\":");
    try writeJsonString(out, entry.timestamp);
    try out.writeAll(",\"session_id\":");
    try writeJsonNullableString(out, session_id);
    try out.writeAll(",\"content\":");
    try writeJsonString(out, content);
    try out.writeAll("}");
}

fn writeRedactedMemoryExportEntryJson(
    out: anytype,
    allocator: std.mem.Allocator,
    redactor: *yc.redaction.Redactor,
    entry: yc.memory.MemoryEntry,
) !void {
    const redacted_key = try redactor.redact(allocator, entry.key);
    defer allocator.free(redacted_key);
    const redacted_content = try redactor.redact(allocator, entry.content);
    defer allocator.free(redacted_content);
    const redacted_session_id = if (entry.session_id) |sid| try redactor.redact(allocator, sid) else null;
    defer if (redacted_session_id) |sid| allocator.free(sid);

    try writeMemoryExportEntryJson(out, entry, redacted_key, redacted_content, redacted_session_id);
}

fn writeMemoryExportJsonlEntries(
    out: anytype,
    allocator: std.mem.Allocator,
    entries: []const yc.memory.MemoryEntry,
    include_pii: bool,
    redactor: ?*yc.redaction.Redactor,
) !void {
    if (include_pii) {
        for (entries) |entry| {
            try writeMemoryExportEntryJson(out, entry, entry.key, entry.content, entry.session_id);
            try out.writeByte('\n');
        }
    } else {
        const r = redactor orelse return error.InvalidRedactor;
        for (entries) |entry| {
            try writeRedactedMemoryExportEntryJson(out, allocator, r, entry);
            try out.writeByte('\n');
        }
    }
}

fn writeMemoryExportJsonlStream(
    allocator: std.mem.Allocator,
    out: anytype,
    mem: yc.memory.Memory,
    options: MemoryExportOptions,
) !void {
    var redactor = yc.redaction.Redactor.init(allocator, .{});
    defer redactor.deinit();

    var written: usize = 0;
    var page_offset = options.offset;
    while (written < options.limit) {
        const take = @min(MEMORY_EXPORT_STREAM_CHUNK_SIZE, options.limit - written);
        if (take == 0) break;

        const page_len = blk: {
            const entries = try loadMemoryListPage(
                allocator,
                mem,
                options.category,
                options.session_id,
                take,
                page_offset,
                options.include_internal,
            );
            defer yc.memory.freeEntries(allocator, entries);

            if (entries.len == 0) break :blk 0;
            try writeMemoryExportJsonlEntries(
                out,
                allocator,
                entries,
                options.include_pii,
                if (options.include_pii) null else &redactor,
            );
            break :blk entries.len;
        };

        if (page_len == 0) break;
        written += page_len;
        page_offset += page_len;
        if (page_len < take) break;
    }
}

fn appendMemoryExportJsonl(
    out: anytype,
    allocator: std.mem.Allocator,
    mem: yc.memory.Memory,
    options: MemoryExportOptions,
) !void {
    try writeMemoryExportJsonlStream(allocator, out, mem, options);
}

fn buildMemoryExportJsonl(
    allocator: std.mem.Allocator,
    mem: yc.memory.Memory,
    options: MemoryExportOptions,
) ![]u8 {
    return yc.admin_output.renderBytes(allocator, appendMemoryExportJsonl, .{ allocator, mem, options });
}

fn writeMemoryExportJsonlStdout(
    allocator: std.mem.Allocator,
    mem: yc.memory.Memory,
    options: MemoryExportOptions,
) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&stdout_buf);
    try writeMemoryExportJsonlStream(allocator, &bw.interface, mem, options);
    try bw.interface.flush();
}

fn freeStringUsizeMap(map: *std.StringHashMapUnmanaged(usize), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.deinit(allocator);
}

fn buildDedupScopeKey(
    allocator: std.mem.Allocator,
    entry: yc.memory.MemoryEntry,
    content: []const u8,
) ![]u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{s}\x1f{s}\x1f{s}",
        .{ entry.category.toString(), entry.session_id orelse "", content },
    );
}

fn putDedupKey(
    allocator: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged(usize),
    key: []u8,
) !void {
    errdefer allocator.free(key);
    const gop = try map.getOrPut(allocator, key);
    if (gop.found_existing) {
        allocator.free(key);
        gop.value_ptr.* += 1;
    } else {
        gop.key_ptr.* = key;
        gop.value_ptr.* = 1;
    }
}

fn normalizeMemoryContentForDedup(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var pending_space = false;
    for (content) |ch| {
        if (std.ascii.isWhitespace(ch)) {
            pending_space = true;
            continue;
        }
        if (out.items.len > 0 and pending_space) {
            try out.append(allocator, ' ');
        }
        pending_space = false;
        try out.append(allocator, std.ascii.toLower(ch));
    }

    return try out.toOwnedSlice(allocator);
}

fn countDuplicateStats(map: *const std.StringHashMapUnmanaged(usize)) DuplicateStats {
    var stats = DuplicateStats{};
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* > 1) {
            stats.groups += 1;
            stats.extra_entries += entry.value_ptr.* - 1;
        }
    }
    return stats;
}

fn buildMemoryHygieneDryRunReport(
    allocator: std.mem.Allocator,
    mem: yc.memory.Memory,
    options: MemoryHygieneOptions,
) !MemoryHygieneDryRunReport {
    const entries = try loadMemoryListPage(
        allocator,
        mem,
        options.category,
        options.session_id,
        options.limit,
        0,
        options.include_internal,
    );
    defer yc.memory.freeEntries(allocator, entries);

    var exact_map: std.StringHashMapUnmanaged(usize) = .{};
    defer freeStringUsizeMap(&exact_map, allocator);
    var normalized_map: std.StringHashMapUnmanaged(usize) = .{};
    defer freeStringUsizeMap(&normalized_map, allocator);

    var report = MemoryHygieneDryRunReport{ .scanned_entries = entries.len };

    for (entries) |entry| {
        const trimmed = std.mem.trim(u8, entry.content, " \t\r\n");
        if (trimmed.len == 0) continue;

        const exact_key = try buildDedupScopeKey(allocator, entry, trimmed);
        try putDedupKey(allocator, &exact_map, exact_key);

        const normalized = try normalizeMemoryContentForDedup(allocator, trimmed);
        defer allocator.free(normalized);
        if (normalized.len == 0) continue;
        const normalized_key = try buildDedupScopeKey(allocator, entry, normalized);
        try putDedupKey(allocator, &normalized_map, normalized_key);
    }

    report.exact_duplicates = countDuplicateStats(&exact_map);
    report.normalized_duplicates = countDuplicateStats(&normalized_map);
    return report;
}

fn appendMemoryHygieneDryRunJson(out: anytype, report: MemoryHygieneDryRunReport) !void {
    try out.print(
        "{{\"dry_run\":true,\"scanned_entries\":{d},\"exact_duplicate_groups\":{d},\"exact_duplicate_extra_entries\":{d},\"normalized_duplicate_groups\":{d},\"normalized_duplicate_extra_entries\":{d}}}",
        .{
            report.scanned_entries,
            report.exact_duplicates.groups,
            report.exact_duplicates.extra_entries,
            report.normalized_duplicates.groups,
            report.normalized_duplicates.extra_entries,
        },
    );
}

fn appendMemoryHygieneDryRunText(out: anytype, report: MemoryHygieneDryRunReport) !void {
    try out.print(
        \\Memory hygiene dry-run
        \\  scanned entries: {d}
        \\  exact duplicate groups: {d} (extra entries: {d})
        \\  normalized duplicate groups: {d} (extra entries: {d})
        \\  changes made: 0
        \\
    , .{
        report.scanned_entries,
        report.exact_duplicates.groups,
        report.exact_duplicates.extra_entries,
        report.normalized_duplicates.groups,
        report.normalized_duplicates.extra_entries,
    });
}

const MemoryStatsPayload = struct {
    backend: []const u8,
    retrieval: []const u8,
    vector: []const u8,
    embedding: []const u8,
    rollout: []const u8,
    sync: []const u8,
    sources: usize,
    fallback: []const u8,
    entries: usize,
    vector_entries: ?usize,
    outbox_pending: ?usize,
};

fn appendMemoryStatsJson(out: anytype, payload: MemoryStatsPayload) !void {
    try out.writeAll("{\"backend\":");
    try writeJsonString(out, payload.backend);
    try out.writeAll(",\"retrieval\":");
    try writeJsonString(out, payload.retrieval);
    try out.writeAll(",\"vector\":");
    try writeJsonString(out, payload.vector);
    try out.writeAll(",\"embedding\":");
    try writeJsonString(out, payload.embedding);
    try out.writeAll(",\"rollout\":");
    try writeJsonString(out, payload.rollout);
    try out.writeAll(",\"sync\":");
    try writeJsonString(out, payload.sync);
    try out.print(",\"sources\":{d},\"fallback\":", .{payload.sources});
    try writeJsonString(out, payload.fallback);
    try out.print(",\"entries\":{d},\"vector_entries\":", .{payload.entries});
    if (payload.vector_entries) |value| {
        try out.print("{d}", .{value});
    } else {
        try out.writeAll("null");
    }
    try out.writeAll(",\"outbox_pending\":");
    if (payload.outbox_pending) |value| {
        try out.print("{d}", .{value});
    } else {
        try out.writeAll("null");
    }
    try out.writeAll("}");
}

fn appendMemoryMaintenanceJson(out: anytype, field_name: []const u8, count: usize, skipped: ?bool) !void {
    try out.writeAll("{\"");
    try out.writeAll(field_name);
    try out.print("\":{d}", .{count});
    if (skipped) |flag| {
        try out.writeAll(",\"skipped\":");
        try writeJsonBool(out, flag);
    }
    try out.writeAll("}");
}

fn appendMemoryMutationJson(out: anytype, action: []const u8, entry: yc.memory.MemoryEntry) !void {
    try out.writeAll("{\"action\":");
    try writeJsonString(out, action);
    try out.writeAll(",\"entry\":");
    try writeMemoryEntryJson(out, entry);
    try out.writeAll("}");
}

fn appendMemoryDeleteJson(out: anytype, key: []const u8, session_id: ?[]const u8, deleted: bool) !void {
    try out.writeAll("{\"key\":");
    try writeJsonString(out, key);
    try out.writeAll(",\"session_id\":");
    try writeJsonNullableString(out, session_id);
    try out.writeAll(",\"deleted\":");
    try writeJsonBool(out, deleted);
    try out.writeAll("}");
}

fn appendMemorySearchResultsJson(out: anytype, results: []const yc.memory.RetrievalCandidate) !void {
    try out.writeAll("[");
    for (results, 0..) |rc, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.writeAll("{\"key\":");
        try writeJsonString(out, rc.key);
        try out.writeAll(",\"category\":");
        try writeJsonString(out, rc.category.toString());
        try out.writeAll(",\"snippet\":");
        try writeJsonString(out, rc.snippet);
        try out.writeAll(",\"source\":");
        try writeJsonString(out, rc.source);
        try out.writeAll(",\"source_path\":");
        try writeJsonString(out, rc.source_path);
        try out.print(",\"final_score\":{d},\"start_line\":{d},\"end_line\":{d},\"created_at\":{d},\"keyword_rank\":", .{
            rc.final_score,
            rc.start_line,
            rc.end_line,
            rc.created_at,
        });
        try writeJsonNullableU32(out, rc.keyword_rank);
        try out.writeAll(",\"vector_score\":");
        try writeJsonNullableF32(out, rc.vector_score);
        try out.writeAll("}");
    }
    try out.writeAll("]");
}

fn appendMemoryListJson(
    out: anytype,
    entries: []const yc.memory.MemoryEntry,
    shown: usize,
    include_internal: bool,
) !void {
    try out.writeAll("[");
    var written: usize = 0;
    for (entries) |entry| {
        if (!memoryEntryVisible(include_internal, entry)) continue;
        if (written >= shown) break;
        if (written > 0) try out.writeAll(",");
        try writeMemoryEntryJson(out, entry);
        written += 1;
    }
    try out.writeAll("]");
}

fn writeMemoryStatsJson(payload: MemoryStatsPayload) void {
    writeRenderedJsonLine(appendMemoryStatsJson, .{payload});
}

fn writeMemoryMaintenanceJsonLine(field_name: []const u8, count: usize, skipped: ?bool) void {
    writeRenderedJsonLine(appendMemoryMaintenanceJson, .{ field_name, count, skipped });
}

fn writeMemoryDeleteJsonLine(key: []const u8, session_id: ?[]const u8, deleted: bool) void {
    writeRenderedJsonLine(appendMemoryDeleteJson, .{ key, session_id, deleted });
}

fn writeMemoryEntryJsonLine(entry: yc.memory.MemoryEntry) void {
    writeRenderedJsonLine(writeMemoryEntryJson, .{entry});
}

fn writeMemoryListJson(entries: []const yc.memory.MemoryEntry, shown: usize, include_internal: bool) void {
    writeRenderedJsonLine(appendMemoryListJson, .{ entries, shown, include_internal });
}

fn writeMemorySearchResultsJsonLine(results: []const yc.memory.RetrievalCandidate) void {
    writeRenderedJsonLine(appendMemorySearchResultsJson, .{results});
}

fn writeMemoryMutationJsonLine(action: []const u8, entry: yc.memory.MemoryEntry) void {
    writeRenderedJsonLine(appendMemoryMutationJson, .{ action, entry });
}

fn appendAgentSessionTerminationJson(out: anytype, session_key: []const u8) !void {
    try out.writeAll("{\"session_key\":");
    try writeJsonString(out, session_key);
    try out.writeAll(",\"terminated\":true}");
}

fn printMemoryRuntimeInitFailure(allocator: std.mem.Allocator, backend: []const u8) void {
    const enabled = yc.memory.registry.formatEnabledBackends(allocator) catch null;
    defer if (enabled) |names| allocator.free(names);

    if (yc.memory.registry.isKnownBackend(backend) and yc.memory.findBackend(backend) == null) {
        const engine_token = yc.memory.registry.engineTokenForBackend(backend) orelse backend;
        std.debug.print("Memory backend '{s}' is configured but disabled in this build.\n", .{backend});
        std.debug.print("Rebuild with -Dengines={s} (or include it in -Dengines=... list).\n", .{engine_token});
    } else if (!yc.memory.registry.isKnownBackend(backend)) {
        std.debug.print("Unknown memory backend '{s}'.\n", .{backend});
        std.debug.print("Known memory backends: {s}\n", .{yc.memory.registry.known_backends_csv});
    } else {
        std.debug.print("Memory runtime init failed for backend '{s}'. Check memory config and logs.\n", .{backend});
    }

    if (enabled) |names| {
        std.debug.print("Enabled memory backends in this build: {s}\n", .{names});
    }
}

fn printRetrievalScoreLine(c: yc.memory.RetrievalCandidate) void {
    const kw_rank: []const u8 = if (c.keyword_rank != null) "yes" else "no";
    const vec_score: f32 = c.vector_score orelse -1.0;
    if (c.vector_score) |_| {
        std.debug.print("     score={d:.4} keyword_ranked={s} vector_score={d:.4} source={s}\n", .{
            c.final_score,
            kw_rank,
            vec_score,
            c.source,
        });
    } else {
        std.debug.print("     score={d:.4} keyword_ranked={s} vector_score=n/a source={s}\n", .{
            c.final_score,
            kw_rank,
            c.source,
        });
    }
}

fn buildHistoryMemoryConfig(base: yc.config.config_types.MemoryConfig) yc.config.config_types.MemoryConfig {
    var cfg = base;
    // History is read-only; avoid bootstrapping retrieval/vector paths or maintenance hooks.
    cfg.search.enabled = false;
    cfg.qmd.enabled = false;
    cfg.lifecycle.hygiene_enabled = false;
    cfg.lifecycle.snapshot_on_hygiene = false;
    cfg.lifecycle.auto_hydrate = false;
    cfg.response_cache.enabled = false;
    return cfg;
}

fn runMemory(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        printMemoryUsage();
        std_compat.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    var mem_rt = yc.memory.initRuntime(allocator, &cfg.memory, cfg.workspace_dir) orelse {
        printMemoryRuntimeInitFailure(allocator, cfg.memory.backend);
        std_compat.process.exit(1);
    };
    defer mem_rt.deinit();

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "stats")) {
        const json_mode = hasJsonFlag(sub_args[1..]);
        const r = mem_rt.resolved;
        const report = mem_rt.diagnose();
        if (json_mode) {
            writeMemoryStatsJson(.{
                .backend = r.primary_backend,
                .retrieval = r.retrieval_mode,
                .vector = r.vector_mode,
                .embedding = r.embedding_provider,
                .rollout = r.rollout_mode,
                .sync = r.vector_sync_mode,
                .sources = r.source_count,
                .fallback = r.fallback_policy,
                .entries = report.entry_count,
                .vector_entries = report.vector_entry_count,
                .outbox_pending = report.outbox_pending,
            });
        } else {
            std.debug.print("Memory stats:\n", .{});
            std.debug.print("  backend: {s}\n", .{r.primary_backend});
            std.debug.print("  retrieval: {s}\n", .{r.retrieval_mode});
            std.debug.print("  vector: {s}\n", .{r.vector_mode});
            std.debug.print("  embedding: {s}\n", .{r.embedding_provider});
            std.debug.print("  rollout: {s}\n", .{r.rollout_mode});
            std.debug.print("  sync: {s}\n", .{r.vector_sync_mode});
            std.debug.print("  sources: {d}\n", .{r.source_count});
            std.debug.print("  fallback: {s}\n", .{r.fallback_policy});
            std.debug.print("  entries: {d}\n", .{report.entry_count});
            if (report.vector_entry_count) |n| {
                std.debug.print("  vector_entries: {d}\n", .{n});
            } else {
                std.debug.print("  vector_entries: n/a\n", .{});
            }
            if (report.outbox_pending) |n| {
                std.debug.print("  outbox_pending: {d}\n", .{n});
            } else {
                std.debug.print("  outbox_pending: n/a\n", .{});
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "count")) {
        const count = mem_rt.memory.count() catch |err| {
            std.debug.print("memory count failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        std.debug.print("{d}\n", .{count});
        return;
    }

    if (std.mem.eql(u8, subcmd, "reindex")) {
        const json_mode = hasJsonFlag(sub_args[1..]);
        const count = mem_rt.reindex(allocator);
        const skipped = std.mem.eql(u8, mem_rt.resolved.vector_mode, "none");
        if (json_mode) {
            writeMemoryMaintenanceJsonLine("reindexed", count, skipped);
        } else if (skipped) {
            std.debug.print("Vector plane is disabled; reindex skipped (0 entries).\n", .{});
        } else {
            std.debug.print("Reindex complete: {d} entries reindexed.\n", .{count});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "drain-outbox")) {
        const json_mode = hasJsonFlag(sub_args[1..]);
        const drained = mem_rt.drainOutbox(allocator);
        if (json_mode) {
            writeMemoryMaintenanceJsonLine("drained", drained, null);
        } else {
            std.debug.print("Outbox drain complete: {d} operation(s) processed.\n", .{drained});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "forget") or std.mem.eql(u8, subcmd, "delete")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory delete <key> [--session ID] [--json]\n", .{});
            std_compat.process.exit(1);
        }
        const key = sub_args[1];
        var session_id: ?[]const u8 = null;
        var json_mode = false;

        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory delete <key> [--session ID] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory delete: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        var vector_delete_scopes: std.ArrayListUnmanaged(?[]u8) = .empty;
        defer {
            for (vector_delete_scopes.items) |sid_opt| {
                if (sid_opt) |sid| allocator.free(sid);
            }
            vector_delete_scopes.deinit(allocator);
        }

        const existing_entries = mem_rt.memory.list(allocator, null, session_id) catch |err| {
            std.debug.print("memory list failed before delete: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.memory.freeEntries(allocator, existing_entries);

        var saw_global = false;
        for (existing_entries) |entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            if (entry.session_id) |sid| {
                var seen = false;
                for (vector_delete_scopes.items) |existing_sid| {
                    if (existing_sid) |existing| {
                        if (std.mem.eql(u8, existing, sid)) {
                            seen = true;
                            break;
                        }
                    }
                }
                if (!seen) {
                    try vector_delete_scopes.append(allocator, try allocator.dupe(u8, sid));
                }
            } else if (!saw_global) {
                saw_global = true;
                try vector_delete_scopes.append(allocator, null);
            }
        }

        const deleted = mem_rt.memory.forgetScoped(allocator, key, session_id) catch |err| {
            std.debug.print("memory forget failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        if (deleted) {
            for (vector_delete_scopes.items) |sid_opt| {
                mem_rt.deleteFromVectorStore(key, sid_opt);
            }
            if (json_mode) {
                writeMemoryDeleteJsonLine(key, session_id, true);
            } else {
                std.debug.print("Deleted memory entry: {s}\n", .{key});
            }
        } else {
            if (json_mode) {
                writeMemoryDeleteJsonLine(key, session_id, false);
            } else {
                std.debug.print("Entry not deleted (missing or backend is append-only): {s}\n", .{key});
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "get")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory get <key> [--session ID] [--json]\n", .{});
            std_compat.process.exit(1);
        }
        const key = sub_args[1];
        var session_id: ?[]const u8 = null;
        var json_mode = false;
        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory get <key> [--session ID] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory get: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const entry = mem_rt.memory.getScoped(allocator, key, session_id) catch |err| {
            std.debug.print("memory get failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        if (entry) |e| {
            defer e.deinit(allocator);
            if (json_mode) {
                writeMemoryEntryJsonLine(e);
            } else {
                std.debug.print("key: {s}\ncategory: {s}\ntimestamp: {s}\ncontent:\n{s}\n", .{
                    e.key,
                    e.category.toString(),
                    e.timestamp,
                    e.content,
                });
            }
        } else {
            if (json_mode) {
                printStdoutBytes("null\n");
            } else {
                std.debug.print("Not found: {s}\n", .{key});
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "list")) {
        var limit: usize = 20;
        var offset: usize = 0;
        var category_opt: ?yc.memory.MemoryCategory = null;
        var session_id: ?[]const u8 = null;
        var include_internal = false;
        var json_mode = false;

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--offset")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                offset = parseNonNegativeUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --offset value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--category")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                category_opt = yc.memory.MemoryCategory.fromString(sub_args[i]);
            } else if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--include-internal")) {
                include_internal = true;
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory list: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const entries = loadMemoryListPage(allocator, mem_rt.memory, category_opt, session_id, limit, offset, include_internal) catch |err| {
            std.debug.print("memory paged list failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.memory.freeEntries(allocator, entries);

        const shown = entries.len;

        if (json_mode) {
            writeMemoryListJson(entries, shown, true);
        } else {
            std.debug.print("Memory entries: showing {d} from offset {d}\n", .{ shown, offset });
            var written: usize = 0;
            for (entries) |e| {
                const preview = util.previewUtf8(e.content, 120);
                std.debug.print("  {d}. {s} [{s}] {s}\n     {s}{s}\n", .{
                    offset + written + 1,
                    e.key,
                    e.category.toString(),
                    e.timestamp,
                    preview.slice,
                    if (preview.truncated) "..." else "",
                });
                written += 1;
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "export-jsonl")) {
        var options = MemoryExportOptions{};

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory export-jsonl [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--include-pii] [--redact-pii]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--offset")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory export-jsonl [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--include-pii] [--redact-pii]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.offset = parseNonNegativeUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --offset value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--category")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory export-jsonl [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--include-pii] [--redact-pii]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.category = yc.memory.MemoryCategory.fromString(sub_args[i]);
            } else if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory export-jsonl [--category C] [--limit N] [--offset N] [--session ID] [--include-internal] [--include-pii] [--redact-pii]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--include-internal")) {
                options.include_internal = true;
            } else if (std.mem.eql(u8, sub_args[i], "--include-pii")) {
                options.include_pii = true;
            } else if (std.mem.eql(u8, sub_args[i], "--redact-pii")) {
                options.include_pii = false;
            } else {
                std.debug.print("Unknown option for memory export-jsonl: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        writeMemoryExportJsonlStdout(allocator, mem_rt.memory, options) catch |err| {
            std.debug.print("memory export-jsonl failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        return;
    }

    if (std.mem.eql(u8, subcmd, "hygiene-report")) {
        var options = MemoryHygieneOptions{};
        var json_mode = false;

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory hygiene-report [--category C] [--limit N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--category")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory hygiene-report [--category C] [--limit N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.category = yc.memory.MemoryCategory.fromString(sub_args[i]);
            } else if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory hygiene-report [--category C] [--limit N] [--session ID] [--include-internal] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                options.session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--include-internal")) {
                options.include_internal = true;
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory hygiene-report: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const report = buildMemoryHygieneDryRunReport(allocator, mem_rt.memory, options) catch |err| {
            std.debug.print("memory hygiene-report failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        if (json_mode) {
            writeRenderedJsonLine(appendMemoryHygieneDryRunJson, .{report});
        } else {
            const rendered = yc.admin_output.renderBytes(allocator, appendMemoryHygieneDryRunText, .{report}) catch |err| {
                std.debug.print("memory hygiene-report render failed: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            defer allocator.free(rendered);
            printStdoutBytes(rendered);
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "search")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory search <query> [--limit N] [--session ID] [--json]\n", .{});
            std_compat.process.exit(1);
        }
        const query = sub_args[1];
        var limit: usize = 6;
        var session_id: ?[]const u8 = null;
        var json_mode = false;

        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory search <query> [--limit N] [--session ID] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory search <query> [--limit N] [--session ID] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory search: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const results = mem_rt.search(allocator, query, limit, session_id) catch |err| {
            std.debug.print("memory search failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.memory.retrieval.freeCandidates(allocator, results);

        if (json_mode) {
            writeMemorySearchResultsJsonLine(results);
        } else {
            std.debug.print("Search results: {d}\n", .{results.len});
            for (results, 0..) |rc, idx| {
                std.debug.print("  {d}. {s} [{s}]\n", .{ idx + 1, rc.key, rc.category.toString() });
                printRetrievalScoreLine(rc);
                const preview = util.previewUtf8(rc.snippet, 140);
                std.debug.print("     {s}{s}\n", .{ preview.slice, if (preview.truncated) "..." else "" });
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "store") or std.mem.eql(u8, subcmd, "update")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw memory {s} <key> <content> [--category C] [--session ID] [--json]\n", .{subcmd});
            std_compat.process.exit(1);
        }

        const key = sub_args[1];
        const content = sub_args[2];
        var category: yc.memory.MemoryCategory = .conversation;
        var session_id: ?[]const u8 = null;
        var json_mode = false;

        var i: usize = 3;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--category")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory {s} <key> <content> [--category C] [--session ID] [--json]\n", .{subcmd});
                    std_compat.process.exit(1);
                }
                i += 1;
                category = yc.memory.MemoryCategory.fromString(sub_args[i]);
            } else if (std.mem.eql(u8, sub_args[i], "--session")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory {s} <key> <content> [--category C] [--session ID] [--json]\n", .{subcmd});
                    std_compat.process.exit(1);
                }
                i += 1;
                session_id = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option for memory {s}: {s}\n", .{ subcmd, sub_args[i] });
                std_compat.process.exit(1);
            }
        }

        if (std.mem.eql(u8, subcmd, "update")) {
            const existing = mem_rt.memory.getScoped(allocator, key, session_id) catch |err| {
                std.debug.print("memory get failed before update: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
            if (existing) |entry| {
                entry.deinit(allocator);
            } else {
                if (json_mode) writeJsonError("memory_not_found", "Memory entry not found", cfg.memory.backend);
                std.debug.print("Memory entry not found: {s}\n", .{key});
                std_compat.process.exit(1);
            }
        }

        mem_rt.memory.store(key, content, category, session_id) catch |err| {
            if (json_mode) writeJsonError("memory_store_failed", @errorName(err), cfg.memory.backend);
            std.debug.print("memory {s} failed: {s}\n", .{ subcmd, @errorName(err) });
            std_compat.process.exit(1);
        };

        const stored = mem_rt.memory.getScoped(allocator, key, session_id) catch |err| {
            if (json_mode) writeJsonError("memory_store_failed", @errorName(err), cfg.memory.backend);
            std.debug.print("memory reload failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        if (stored) |entry| {
            defer entry.deinit(allocator);
            if (json_mode) {
                writeMemoryMutationJsonLine(if (std.mem.eql(u8, subcmd, "update")) "update" else "store", entry);
            } else {
                std.debug.print("Stored memory entry: {s}\n", .{key});
            }
            return;
        }

        if (json_mode) writeJsonError("memory_store_failed", "Stored entry could not be re-read", cfg.memory.backend);
        std.debug.print("Stored entry could not be re-read: {s}\n", .{key});
        std_compat.process.exit(1);
    }

    std.debug.print("Unknown memory command: {s}\n\n", .{subcmd});
    printMemoryUsage();
    std_compat.process.exit(1);
}

// ── History ──────────────────────────────────────────────────────

fn runHistory(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw history <{s}> [args]
            \\
            \\Commands:
            \\  list [--limit N] [--offset N] [--json]
            \\                                List conversation sessions
            \\  show <session_id> [--limit N] [--offset N] [--json]
            \\                                Show messages for a session
            \\
        , .{HISTORY_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const wants_json = hasJsonFlag(sub_args[1..]);

    var cfg = yc.config.Config.load(allocator) catch {
        if (wants_json) {
            writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
        }
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    var history_memory_cfg = buildHistoryMemoryConfig(cfg.memory);
    var mem_rt = yc.memory.initRuntime(allocator, &history_memory_cfg, cfg.workspace_dir) orelse {
        if (wants_json) {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Failed to initialize history runtime (backend: {s})", .{cfg.memory.backend}) catch "Failed to initialize history runtime";
            writeJsonError("memory_runtime_init_failed", msg, cfg.memory.backend);
        }
        std.debug.print("Failed to initialize history runtime (backend: {s})\n", .{cfg.memory.backend});
        std_compat.process.exit(1);
    };
    defer mem_rt.deinit();

    const session_store = mem_rt.session_store orelse {
        if (wants_json) {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Session store not available for backend: {s}", .{cfg.memory.backend}) catch "Session store not available";
            writeJsonError("session_store_unavailable", msg, cfg.memory.backend);
        }
        std.debug.print("Session store not available for backend: {s}\n", .{cfg.memory.backend});
        std_compat.process.exit(1);
    };

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        var limit: usize = 50;
        var offset: usize = 0;
        var json_mode = false;

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw history list [--limit N] [--offset N] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--offset")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw history list [--limit N] [--offset N] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                offset = parseNonNegativeUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --offset value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const total = session_store.countSessions() catch |err| {
            if (err == error.NotSupported) {
                if (json_mode) {
                    var msg_buf: [256]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "History listing not supported for backend: {s}", .{cfg.memory.backend}) catch "History listing not supported";
                    writeJsonError("history_not_supported", msg, cfg.memory.backend);
                }
                std.debug.print("History listing not supported for backend: {s}\n", .{cfg.memory.backend});
                std_compat.process.exit(1);
            }
            if (json_mode) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Failed to count sessions: {s}", .{@errorName(err)}) catch "Failed to count sessions";
                writeJsonError("history_count_failed", msg, cfg.memory.backend);
            }
            std.debug.print("Failed to count sessions: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        const sessions = session_store.listSessions(allocator, limit, offset) catch |err| {
            if (err == error.NotSupported) {
                if (json_mode) {
                    var msg_buf: [256]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "History listing not supported for backend: {s}", .{cfg.memory.backend}) catch "History listing not supported";
                    writeJsonError("history_not_supported", msg, cfg.memory.backend);
                }
                std.debug.print("History listing not supported for backend: {s}\n", .{cfg.memory.backend});
                std_compat.process.exit(1);
            }
            if (json_mode) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Failed to list sessions: {s}", .{@errorName(err)}) catch "Failed to list sessions";
                writeJsonError("history_list_failed", msg, cfg.memory.backend);
            }
            std.debug.print("Failed to list sessions: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.memory.freeSessionInfos(allocator, sessions);

        if (json_mode) {
            writeHistoryListJson(sessions, total, limit, offset);
        } else {
            if (sessions.len == 0) {
                std.debug.print("No sessions found.\n", .{});
            } else {
                const shown_from: u64 = @intCast(offset + 1);
                const shown_to: u64 = @intCast(offset + sessions.len);
                std.debug.print("Sessions: showing {d}-{d} of {d}\n", .{ shown_from, shown_to, total });
                for (sessions, 0..) |s, idx| {
                    std.debug.print("  {d}. {s}  msgs={d}  first={s}  last={s}\n", .{
                        offset + idx + 1, s.session_id, s.message_count, s.first_message_at, s.last_message_at,
                    });
                }
            }
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "show")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw history show <session_id> [--limit N] [--offset N] [--json]\n", .{});
            std_compat.process.exit(1);
        }
        const session_id = sub_args[1];
        var limit: usize = 100;
        var offset: usize = 0;
        var json_mode = false;

        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw history show <session_id> [--limit N] [--offset N] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--offset")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw history show <session_id> [--limit N] [--offset N] [--json]\n", .{});
                    std_compat.process.exit(1);
                }
                i += 1;
                offset = parseNonNegativeUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --offset value: {s}\n", .{sub_args[i]});
                    std_compat.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{sub_args[i]});
                std_compat.process.exit(1);
            }
        }

        const total = session_store.countDetailedMessages(session_id) catch |err| {
            if (err == error.NotSupported) {
                if (json_mode) {
                    var msg_buf: [256]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "Detailed history not supported for backend: {s}", .{cfg.memory.backend}) catch "Detailed history not supported";
                    writeJsonError("history_not_supported", msg, cfg.memory.backend);
                }
                std.debug.print("Detailed history not supported for backend: {s}\n", .{cfg.memory.backend});
                std_compat.process.exit(1);
            }
            if (json_mode) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Failed to count messages: {s}", .{@errorName(err)}) catch "Failed to count messages";
                writeJsonError("history_count_failed", msg, cfg.memory.backend);
            }
            std.debug.print("Failed to count messages: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        const messages = session_store.loadMessagesDetailed(allocator, session_id, limit, offset) catch |err| {
            if (err == error.NotSupported) {
                if (json_mode) {
                    var msg_buf: [256]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "Detailed history not supported for backend: {s}", .{cfg.memory.backend}) catch "Detailed history not supported";
                    writeJsonError("history_not_supported", msg, cfg.memory.backend);
                }
                std.debug.print("Detailed history not supported for backend: {s}\n", .{cfg.memory.backend});
                std_compat.process.exit(1);
            }
            if (json_mode) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Failed to load messages: {s}", .{@errorName(err)}) catch "Failed to load messages";
                writeJsonError("history_show_failed", msg, cfg.memory.backend);
            }
            std.debug.print("Failed to load messages: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer yc.memory.freeDetailedMessages(allocator, messages);

        if (json_mode) {
            writeHistoryShowJson(session_id, messages, total, limit, offset);
        } else {
            if (messages.len == 0) {
                std.debug.print("No messages for session: {s}\n", .{session_id});
            } else {
                const shown_from: u64 = @intCast(offset + 1);
                const shown_to: u64 = @intCast(offset + messages.len);
                std.debug.print("Session: {s} (showing {d}-{d} of {d})\n\n", .{ session_id, shown_from, shown_to, total });
                for (messages) |m| {
                    std.debug.print("[{s}] {s}:\n{s}\n\n", .{ m.created_at, m.role, m.content });
                }
            }
        }
        return;
    }

    std.debug.print("Unknown history command: {s}\n", .{subcmd});
    std_compat.process.exit(1);
}

fn appendHistoryListJson(out: anytype, sessions: []const yc.memory.SessionInfo, total: u64, limit: usize, offset: usize) !void {
    try out.print("{{\"total\":{d},\"limit\":{d},\"offset\":{d},\"sessions\":[", .{ total, limit, offset });
    for (sessions, 0..) |s, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.writeAll("{\"session_id\":");
        try writeJsonString(out, s.session_id);
        try out.print(",\"message_count\":{d},\"first_message_at\":", .{s.message_count});
        try writeJsonString(out, s.first_message_at);
        try out.writeAll(",\"last_message_at\":");
        try writeJsonString(out, s.last_message_at);
        try out.writeAll("}");
    }
    try out.writeAll("]}");
}

fn writeHistoryListJson(sessions: []const yc.memory.SessionInfo, total: u64, limit: usize, offset: usize) void {
    writeRenderedJsonLine(appendHistoryListJson, .{ sessions, total, limit, offset });
}

fn appendHistoryShowJson(out: anytype, session_id: []const u8, messages: []const yc.memory.DetailedMessageEntry, total: u64, limit: usize, offset: usize) !void {
    try out.writeAll("{\"session_id\":");
    try writeJsonString(out, session_id);
    try out.print(",\"total\":{d},\"limit\":{d},\"offset\":{d},\"messages\":[", .{ total, limit, offset });
    for (messages, 0..) |m, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.writeAll("{\"role\":");
        try writeJsonString(out, m.role);
        try out.writeAll(",\"content\":");
        try writeJsonString(out, m.content);
        try out.writeAll(",\"created_at\":");
        try writeJsonString(out, m.created_at);
        try out.writeAll("}");
    }
    try out.writeAll("]}");
}

fn writeHistoryShowJson(session_id: []const u8, messages: []const yc.memory.DetailedMessageEntry, total: u64, limit: usize, offset: usize) void {
    writeRenderedJsonLine(appendHistoryShowJson, .{ session_id, messages, total, limit, offset });
}

fn writeJsonEscaped(out: anytype, s: []const u8) !void {
    for (s) |ch| {
        switch (ch) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (ch < 0x20) {
                    try out.print("\\u{x:0>4}", .{ch});
                } else {
                    try out.writeByte(ch);
                }
            },
        }
    }
}

fn runWorkspace(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        printWorkspaceUsage();
        std_compat.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    const subcmd = sub_args[0];
    if (std.mem.eql(u8, subcmd, "edit")) {
        runWorkspaceEdit(allocator, sub_args[1..], cfg);
        return;
    }

    if (std.mem.eql(u8, subcmd, "audit")) {
        try runWorkspaceAudit(allocator, sub_args[1..], cfg);
        return;
    }

    if (!std.mem.eql(u8, subcmd, "reset-md")) {
        std.debug.print("Unknown workspace command: {s}\n\n", .{subcmd});
        printWorkspaceUsage();
        std_compat.process.exit(1);
    }

    var include_bootstrap = false;
    var clear_memory_md = false;
    var dry_run = false;

    var i: usize = 1;
    while (i < sub_args.len) : (i += 1) {
        const arg = sub_args[i];
        if (std.mem.eql(u8, arg, "--include-bootstrap")) {
            include_bootstrap = true;
        } else if (std.mem.eql(u8, arg, "--clear-memory-md")) {
            clear_memory_md = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else {
            std.debug.print("Unknown option for workspace reset-md: {s}\n\n", .{arg});
            printWorkspaceUsage();
            std_compat.process.exit(1);
        }
    }

    const report = try yc.onboard.resetWorkspacePromptFiles(
        allocator,
        cfg.workspace_dir,
        &yc.onboard.ProjectContext{},
        .{
            .include_bootstrap = include_bootstrap,
            .clear_memory_markdown = clear_memory_md,
            .dry_run = dry_run,
        },
        null,
    );

    if (dry_run) {
        std.debug.print(
            "Dry run complete: would rewrite {d} file(s), would remove {d} file(s).\n",
            .{ report.rewritten_files, report.removed_files },
        );
    } else {
        std.debug.print(
            "Workspace markdown reset complete: rewrote {d} file(s), removed {d} file(s).\n",
            .{ report.rewritten_files, report.removed_files },
        );
    }
}

fn runWorkspaceEdit(allocator: std.mem.Allocator, args: []const []const u8, cfg: yc.config.Config) void {
    if (args.len < 1) {
        std.debug.print("Usage: nullclaw workspace edit <filename>\n\n", .{});
        std.debug.print("Bootstrap files: SOUL.md, AGENTS.md, TOOLS.md, CONFIG.md, IDENTITY.md, USER.md, HEARTBEAT.md, BOOTSTRAP.md, MEMORY.md\n", .{});
        std_compat.process.exit(1);
    }
    const filename = args[0];

    if (!yc.bootstrap.isBootstrapFilename(filename)) {
        std.debug.print("Not a bootstrap file: {s}\n", .{filename});
        std.debug.print("Bootstrap files: SOUL.md, AGENTS.md, TOOLS.md, CONFIG.md, IDENTITY.md, USER.md, HEARTBEAT.md, BOOTSTRAP.md, MEMORY.md\n", .{});
        std_compat.process.exit(1);
    }

    // Only file-based backends (markdown, hybrid) support direct editing.
    if (!yc.memory.usesWorkspaceBootstrapFiles(cfg.memory.backend)) {
        std.debug.print(
            "The '{s}' backend stores bootstrap files in the database.\n" ++
                "Edit bootstrap files through the agent using the memory_store tool,\n" ++
                "or switch to the hybrid backend for file-based editing.\n",
            .{cfg.memory.backend},
        );
        std_compat.process.exit(1);
    }

    const filepath = std.fmt.allocPrint(allocator, "{s}/{s}", .{ cfg.workspace_dir, filename }) catch {
        std.debug.print("Failed to build file path\n", .{});
        std_compat.process.exit(1);
    };
    defer allocator.free(filepath);

    // Determine editor: $VISUAL, $EDITOR, fallback to vi
    var editor_owned = getEnvVarOwnedOrNull(allocator, "VISUAL");
    if (editor_owned == null) {
        editor_owned = getEnvVarOwnedOrNull(allocator, "EDITOR");
    }
    defer if (editor_owned) |value| allocator.free(value);
    const editor = if (editor_owned) |value| value else "vi";

    var child = std_compat.process.Child.init(&.{ editor, filepath }, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    _ = child.spawnAndWait() catch |err| {
        std.debug.print("Failed to launch editor '{s}': {s}\n", .{ editor, @errorName(err) });
        std_compat.process.exit(1);
    };
}

fn workspaceAuditTriageProviderName(cli_provider: ?[]const u8, cfg: *const yc.config.Config) []const u8 {
    return cli_provider orelse cfg.workspace_audit.llm_triage.provider orelse cfg.default_provider;
}

fn workspaceAuditTriageModelName(cli_model: ?[]const u8, cfg: *const yc.config.Config) ?[]const u8 {
    return cli_model orelse cfg.workspace_audit.llm_triage.model orelse cfg.default_model;
}

fn workspaceAuditTriageMaxLlmCalls(cfg: *const yc.config.Config) usize {
    return cfg.workspace_audit.llm_triage.max_calls orelse yc.audit.triager.DEFAULT_MAX_LLM_CALLS;
}

fn runWorkspaceAudit(allocator: std.mem.Allocator, args: []const []const u8, cfg: yc.config.Config) !void {
    var exclude_patterns: std.ArrayListUnmanaged([]const u8) = .empty;
    defer exclude_patterns.deinit(allocator);

    var options = yc.workspace_audit.Options{
        .workspace_dir = cfg.workspace_dir,
    };
    var triage_options = yc.audit.triager.Options{
        .max_llm_calls = workspaceAuditTriageMaxLlmCalls(&cfg),
    };
    var triage_provider_name: ?[]const u8 = null;
    var triage_model_name: ?[]const u8 = null;
    var owned_provider_api_key: ?[]u8 = null;
    defer if (owned_provider_api_key) |key| allocator.free(key);
    var triage_provider_holder: ?yc.providers.ProviderHolder = null;
    defer if (triage_provider_holder) |*holder| holder.deinit();
    var provider_triage_client: ?yc.audit.llm_client.ProviderTriageClient = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
        } else if (std.mem.eql(u8, arg, "--staged")) {
            options.staged = true;
        } else if (std.mem.eql(u8, arg, "--commit")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --commit\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            options.commit = args[i];
        } else if (std.mem.eql(u8, arg, "--range")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --range\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            options.range = args[i];
        } else if (std.mem.eql(u8, arg, "--only-secrets")) {
            options.only_secrets = true;
        } else if (std.mem.eql(u8, arg, "--exclude")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --exclude\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            try exclude_patterns.append(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "--fail-on")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --fail-on\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            options.fail_on = yc.workspace_audit.FailureThreshold.parse(args[i]) orelse {
                std.debug.print("Invalid --fail-on value: {s}\n\n", .{args[i]});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--llm-triage")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --llm-triage (off|dry-run|external)\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            triage_options.mode = yc.audit.TriageMode.parse(args[i]) orelse {
                std.debug.print("Invalid --llm-triage value: {s} (use off|dry-run|external)\n\n", .{args[i]});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--llm-model")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --llm-model\n\n", .{});
                std_compat.process.exit(1);
            }
            triage_model_name = args[i];
        } else if (std.mem.eql(u8, arg, "--llm-provider")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --llm-provider\n\n", .{});
                std_compat.process.exit(1);
            }
            triage_provider_name = args[i];
        } else if (std.mem.eql(u8, arg, "--llm-max-calls")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Missing value for --llm-max-calls\n\n", .{});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            }
            triage_options.max_llm_calls = parseNonNegativeUsize(args[i]) orelse {
                std.debug.print("Invalid --llm-max-calls value: {s}\n\n", .{args[i]});
                printWorkspaceUsage();
                std_compat.process.exit(1);
            };
        } else {
            std.debug.print("Unknown workspace audit option: {s}\n\n", .{arg});
            printWorkspaceUsage();
            std_compat.process.exit(1);
        }
    }

    options.exclude_patterns = exclude_patterns.items;
    options.collect_triage_context = triage_options.mode != .off;

    if (triage_options.mode == .external) {
        const provider_name = workspaceAuditTriageProviderName(triage_provider_name, &cfg);
        if (!workspaceAuditTriageProviderIsAllowed(&cfg, provider_name)) {
            std.debug.print("workspace audit: unknown LLM provider '{s}'. Use a built-in provider name or configure models.providers.{s}.base_url explicitly.\n", .{ provider_name, provider_name });
            std_compat.process.exit(1);
        }
        const model_name = workspaceAuditTriageModelName(triage_model_name, &cfg) orelse {
            std.debug.print("workspace audit: no model configured. Set workspace_audit.llm_triage.model, agents.defaults.model.primary, or pass --llm-model.\n", .{});
            std_compat.process.exit(1);
        };
        owned_provider_api_key = resolveWorkspaceAuditTriageApiKey(allocator, &cfg, provider_name) catch |err| switch (err) {
            error.NoApiKey => {
                std.debug.print("workspace audit: no api_key for provider '{s}'. Set providers.{s}.api_key, an environment key, or use a local/keyless provider.\n", .{ provider_name, provider_name });
                std_compat.process.exit(1);
            },
            else => return err,
        };
        triage_provider_holder = workspaceAuditTriageProviderHolder(
            allocator,
            &cfg,
            provider_name,
            owned_provider_api_key,
        );
        if (triage_provider_holder) |*holder| {
            provider_triage_client = .{
                .provider = holder.provider(),
                .model = model_name,
                .temperature = 0.0,
            };
            if (provider_triage_client) |*client| {
                triage_options.client = client.client();
            }
        }
    }

    var git_modes: usize = 0;
    if (options.staged) git_modes += 1;
    if (options.commit != null) git_modes += 1;
    if (options.range != null) git_modes += 1;
    if (git_modes > 1) {
        std.debug.print("Choose only one of --staged, --commit, or --range\n\n", .{});
        printWorkspaceUsage();
        std_compat.process.exit(1);
    }

    const exit_code = executeWorkspaceAudit(allocator, &cfg, options, triage_options) catch |err| {
        switch (err) {
            error.NotGitRepository => std.debug.print("workspace audit: staged mode requires a Git repository\n", .{}),
            error.GitUnavailable => std.debug.print("workspace audit: git is not available in this environment\n", .{}),
            error.GitDiffFailed => std.debug.print("workspace audit: failed to read staged diff\n", .{}),
            error.InvalidHistoryTarget => std.debug.print("workspace audit: invalid --commit or --range target\n", .{}),
            else => std.debug.print("workspace audit failed: {s}\n", .{@errorName(err)}),
        }
        std_compat.process.exit(1);
    };
    if (exit_code != 0) std_compat.process.exit(exit_code);
}

fn executeWorkspaceAudit(
    allocator: std.mem.Allocator,
    cfg: *const yc.config.Config,
    options: yc.workspace_audit.Options,
    triage_options: yc.audit.triager.Options,
) !u8 {
    const resolved_workspace = try yc.fs_compat.realpathAllocPath(allocator, options.workspace_dir);
    defer allocator.free(resolved_workspace);

    var scan_options = options;
    scan_options.workspace_dir = resolved_workspace;

    var report = try yc.workspace_audit.buildReport(allocator, resolved_workspace, scan_options);
    defer report.deinit(allocator);

    var maybe_stats: ?yc.audit.TriageStats = null;
    if (triage_options.mode != .off) {
        const log_path = try defaultWorkspaceAuditLogPath(allocator, cfg);
        defer allocator.free(log_path);
        maybe_stats = try yc.audit.triager.runTriage(allocator, &report, triage_options, log_path);
    }

    const rendered = try yc.workspace_audit.renderReport(
        allocator,
        report,
        options.fail_on,
        options.json,
        maybe_stats,
    );
    defer allocator.free(rendered);

    try yc.admin_output.writeStdoutBytes(rendered);
    if (rendered.len == 0 or rendered[rendered.len - 1] != '\n') {
        try yc.admin_output.writeStdoutBytes("\n");
    }

    return if (report.exceedsThreshold(options.fail_on)) 1 else 0;
}

fn defaultWorkspaceAuditLogPath(allocator: std.mem.Allocator, cfg: *const yc.config.Config) ![]u8 {
    const config_dir = std.fs.path.dirname(cfg.config_path) orelse ".";
    return std_compat.fs.path.join(allocator, &.{ config_dir, "audit-log.jsonl" });
}

fn workspaceAuditTriageProviderIsAllowed(cfg: *const yc.config.Config, provider_name: []const u8) bool {
    if (yc.providers.classifyProvider(provider_name) != .unknown) return true;
    const base_url = cfg.getProviderBaseUrl(provider_name) orelse return false;
    return yc.config.ProviderEntry.isValidBaseUrl(base_url);
}

fn resolveWorkspaceAuditTriageApiKey(
    allocator: std.mem.Allocator,
    cfg: *const yc.config.Config,
    provider_name: []const u8,
) !?[]u8 {
    if (cfg.getProviderKey(provider_name)) |key| {
        const trimmed = std.mem.trim(u8, key, " \t\r\n");
        if (trimmed.len > 0) return try allocator.dupe(u8, trimmed);
    }

    if (yc.provider_probe.providerRequiresApiKey(provider_name, cfg.getProviderBaseUrl(provider_name))) {
        return (try yc.providers.resolveApiKey(allocator, provider_name, null)) orelse error.NoApiKey;
    }
    return null;
}

fn workspaceAuditTriageProviderHolder(
    allocator: std.mem.Allocator,
    cfg: *const yc.config.Config,
    provider_name: []const u8,
    api_key: ?[]const u8,
) yc.providers.ProviderHolder {
    return yc.providers.holderFromConfig(
        allocator,
        cfg,
        provider_name,
        api_key,
    );
}

fn getEnvVarOwnedOrNull(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
    return std_compat.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => null,
    };
}

fn runCapabilities(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var as_json = false;
    if (sub_args.len > 0) {
        if (sub_args.len == 1 and (std.mem.eql(u8, sub_args[0], "--json") or std.mem.eql(u8, sub_args[0], "json"))) {
            as_json = true;
        } else {
            std.debug.print("Usage: nullclaw capabilities [--json]\n", .{});
            std_compat.process.exit(1);
        }
    }

    var cfg_opt: ?yc.config.Config = yc.config.Config.load(allocator) catch null;
    defer if (cfg_opt) |*cfg| cfg.deinit();
    const cfg_ptr: ?*const yc.config.Config = if (cfg_opt) |*cfg| cfg else null;
    const colorize = yc.doctor.shouldColorize(std_compat.fs.File.stdout());

    const output = if (as_json)
        try yc.capabilities.buildManifestJson(allocator, cfg_ptr, null)
    else
        try yc.capabilities.buildSummaryTextWithColor(allocator, cfg_ptr, null, colorize);
    defer allocator.free(output);

    try yc.admin_output.writeStdoutBytes(output);
}

// ── Config ───────────────────────────────────────────────────────

const ModelProviderSummary = struct {
    name: []const u8,
    has_key: bool,
};

fn printStdoutBytes(text: []const u8) void {
    yc.admin_output.writeStdoutBytes(text) catch return;
}

fn writeRenderedJsonLine(comptime render_fn: anytype, args: anytype) void {
    const allocator = std.heap.smp_allocator;
    yc.admin_output.writeRenderedLine(allocator, render_fn, args) catch {
        std_compat.process.exit(1);
    };
}

fn appendJsonEscaped(buf: *std.array_list.Managed(u8), s: []const u8) !void {
    for (s) |ch| {
        switch (ch) {
            '"' => try buf.appendSlice("\\\""),
            '\\' => try buf.appendSlice("\\\\"),
            '\n' => try buf.appendSlice("\\n"),
            '\r' => try buf.appendSlice("\\r"),
            '\t' => try buf.appendSlice("\\t"),
            else => {
                if (ch < 0x20) {
                    var escape_buf: [6]u8 = undefined;
                    const escape = try std.fmt.bufPrint(&escape_buf, "\\u{x:0>4}", .{ch});
                    try buf.appendSlice(escape);
                } else {
                    try buf.append(ch);
                }
            },
        }
    }
}

fn allocDefaultModelRef(allocator: std.mem.Allocator, cfg: *const yc.config.Config) !?[]u8 {
    const model = cfg.default_model orelse return null;
    if (cfg.default_provider.len == 0) return try allocator.dupe(u8, model);
    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cfg.default_provider, model });
}

fn buildModelsSummaryJson(allocator: std.mem.Allocator, cfg: *const yc.config.Config) ![]u8 {
    var providers = std.ArrayListUnmanaged(ModelProviderSummary).empty;
    defer providers.deinit(allocator);

    for (cfg.providers) |provider| {
        const has_key = if (provider.api_key) |key|
            std.mem.trim(u8, key, " \t\r\n").len > 0
        else
            false;
        try providers.append(allocator, .{
            .name = provider.name,
            .has_key = has_key,
        });
    }

    std.mem.sort(ModelProviderSummary, providers.items, {}, struct {
        fn lessThan(_: void, lhs: ModelProviderSummary, rhs: ModelProviderSummary) bool {
            return std.mem.order(u8, lhs.name, rhs.name) == .lt;
        }
    }.lessThan);

    const default_model_ref = try allocDefaultModelRef(allocator, cfg);
    defer if (default_model_ref) |value| allocator.free(value);

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    try out.appendSlice("{\"default_provider\":");
    if (cfg.default_provider.len > 0) {
        try out.append('"');
        try appendJsonEscaped(&out, cfg.default_provider);
        try out.append('"');
    } else {
        try out.appendSlice("null");
    }

    try out.appendSlice(",\"default_model\":");
    if (default_model_ref) |value| {
        try out.append('"');
        try appendJsonEscaped(&out, value);
        try out.append('"');
    } else {
        try out.appendSlice("null");
    }

    try out.appendSlice(",\"providers\":[");
    for (providers.items, 0..) |provider, idx| {
        if (idx > 0) try out.append(',');
        try out.appendSlice("{\"name\":\"");
        try appendJsonEscaped(&out, provider.name);
        try out.appendSlice("\",\"has_key\":");
        try out.appendSlice(if (provider.has_key) "true" else "false");
        try out.append('}');
    }
    try out.appendSlice("]}");
    return try out.toOwnedSlice();
}

fn appendConfigValueResult(out: anytype, path: []const u8, value_json: []const u8) !void {
    try out.writeAll("{\"path\":");
    try writeJsonString(out, path);
    try out.writeAll(",\"value\":");
    try out.writeAll(value_json);
    try out.writeAll("}");
}

fn appendConfigReloadJson(out: anytype) !void {
    try out.writeAll(
        "{\"reloaded\":true,\"live_applied\":false,\"message\":\"config.json re-read from disk; restart running daemons to apply changes\"}",
    );
}

fn appendValidationJson(out: anytype, valid: bool) !void {
    try out.writeAll("{\"valid\":");
    try writeJsonBool(out, valid);
    try out.writeAll("}");
}

fn writeConfigValueResult(path: []const u8, value_json: []const u8) void {
    writeRenderedJsonLine(appendConfigValueResult, .{ path, value_json });
}

fn printConfigUsage() void {
    std.debug.print(std.fmt.comptimePrint(
        \\Usage: nullclaw config <{s}> [args]
        \\
        \\Commands:
        \\  show [--json]                  Print config.json as JSON
        \\  get <path> [--json]            Read a dotted config path
        \\  set <path> <value> [--json]    Persist a dotted config value
        \\  unset <path> [--json]          Remove/reset a dotted config value
        \\  reload [--json]                Re-read config.json from disk
        \\  validate [json] [--json]       Validate current or proposed config JSON
        \\
    , .{CONFIG_SUBCOMMANDS}), .{});
}

fn runConfig(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        printConfigUsage();
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "show")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            printConfigUsage();
            std_compat.process.exit(1);
        }

        const config_json = yc.config_mutator.getCurrentConfigJson(allocator) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    if (hasJsonFlag(sub_args[1..])) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
                    std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
                },
                else => {
                    if (hasJsonFlag(sub_args[1..])) writeJsonError("config_read_failed", "Failed to read config.json", null);
                    std.debug.print("Failed to read config.json: {s}\n", .{@errorName(err)});
                },
            }
            std_compat.process.exit(1);
        };
        defer allocator.free(config_json);

        printStdoutBytes(config_json);
        if (config_json.len == 0 or config_json[config_json.len - 1] != '\n') {
            printStdoutBytes("\n");
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "get")) {
        if (sub_args.len < 2 or sub_args.len > 3 or (sub_args.len == 3 and !std.mem.eql(u8, sub_args[2], "--json"))) {
            printConfigUsage();
            std_compat.process.exit(1);
        }

        const path = sub_args[1];
        const value_json = yc.config_mutator.findPathValueJson(allocator, path) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    if (hasJsonFlag(sub_args[2..])) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
                    std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
                },
                error.InvalidJson => {
                    if (hasJsonFlag(sub_args[2..])) writeJsonError("config_invalid_json", "config.json is not valid JSON", null);
                    std.debug.print("config.json is not valid JSON\n", .{});
                },
                error.InvalidPath => {
                    if (hasJsonFlag(sub_args[2..])) writeJsonError("config_invalid_path", "Invalid dotted config path", null);
                    std.debug.print("Invalid dotted config path: {s}\n", .{path});
                },
                else => {
                    if (hasJsonFlag(sub_args[2..])) writeJsonError("config_get_failed", "Failed to read config path", null);
                    std.debug.print("Failed to read config path {s}: {s}\n", .{ path, @errorName(err) });
                },
            }
            std_compat.process.exit(1);
        };
        if (value_json) |value| {
            defer allocator.free(value);
            if (hasJsonFlag(sub_args[2..])) {
                writeConfigValueResult(path, value);
            } else {
                printStdoutBytes(value);
                printStdoutBytes("\n");
            }
            return;
        }

        if (hasJsonFlag(sub_args[2..])) writeJsonError("config_path_not_found", "Config path not found", null);
        std.debug.print("Config path not found: {s}\n", .{path});
        std_compat.process.exit(1);
    }

    if (std.mem.eql(u8, subcmd, "set")) {
        if (sub_args.len < 3 or sub_args.len > 4 or (sub_args.len == 4 and !std.mem.eql(u8, sub_args[3], "--json"))) {
            printConfigUsage();
            std_compat.process.exit(1);
        }

        var result = yc.config_mutator.mutateDefaultConfig(allocator, .set, sub_args[1], sub_args[2], .{ .apply = true }) catch |err| {
            if (hasJsonFlag(sub_args[3..])) writeJsonError("config_set_failed", @errorName(err), null);
            std.debug.print("Failed to update config path {s}: {s}\n", .{ sub_args[1], @errorName(err) });
            std_compat.process.exit(1);
        };
        defer yc.config_mutator.freeMutationResult(allocator, &result);

        if (hasJsonFlag(sub_args[3..])) {
            writeConfigMutationJson(.set, &result);
        } else {
            std.debug.print("Updated {s}\n", .{result.path});
            std.debug.print("  changed:          {}\n", .{result.changed});
            std.debug.print("  applied:          {}\n", .{result.applied});
            std.debug.print("  requires_restart: {}\n", .{result.requires_restart});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "unset")) {
        if (sub_args.len < 2 or sub_args.len > 3 or (sub_args.len == 3 and !std.mem.eql(u8, sub_args[2], "--json"))) {
            printConfigUsage();
            std_compat.process.exit(1);
        }

        var result = yc.config_mutator.mutateDefaultConfig(allocator, .unset, sub_args[1], null, .{ .apply = true }) catch |err| {
            if (hasJsonFlag(sub_args[2..])) writeJsonError("config_unset_failed", @errorName(err), null);
            std.debug.print("Failed to unset config path {s}: {s}\n", .{ sub_args[1], @errorName(err) });
            std_compat.process.exit(1);
        };
        defer yc.config_mutator.freeMutationResult(allocator, &result);

        if (hasJsonFlag(sub_args[2..])) {
            writeConfigMutationJson(.unset, &result);
        } else {
            std.debug.print("Unset {s}\n", .{result.path});
            std.debug.print("  changed:          {}\n", .{result.changed});
            std.debug.print("  applied:          {}\n", .{result.applied});
            std.debug.print("  requires_restart: {}\n", .{result.requires_restart});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "reload")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            printConfigUsage();
            std_compat.process.exit(1);
        }

        yc.config_mutator.validateCurrentConfig(allocator) catch |err| {
            if (hasJsonFlag(sub_args[1..])) writeJsonError("config_reload_failed", @errorName(err), null);
            std.debug.print("Config reload validation failed: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };

        if (hasJsonFlag(sub_args[1..])) {
            writeRenderedJsonLine(appendConfigReloadJson, .{});
        } else {
            std.debug.print("Config re-read from disk. Restart running daemons to apply changes.\n", .{});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "validate")) {
        var payload: ?[]const u8 = null;
        var json_mode = false;
        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--json")) {
                json_mode = true;
            } else if (payload == null) {
                payload = sub_args[i];
            } else {
                printConfigUsage();
                std_compat.process.exit(1);
            }
        }

        if (payload) |candidate| {
            yc.config_mutator.validateProposedConfigJson(allocator, candidate) catch |err| {
                if (json_mode) writeJsonError("config_invalid", @errorName(err), null);
                std.debug.print("Proposed config is invalid: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
        } else {
            yc.config_mutator.validateCurrentConfig(allocator) catch |err| {
                if (json_mode) writeJsonError("config_invalid", @errorName(err), null);
                std.debug.print("Current config is invalid: {s}\n", .{@errorName(err)});
                std_compat.process.exit(1);
            };
        }

        if (json_mode) {
            writeRenderedJsonLine(appendValidationJson, .{true});
        } else {
            std.debug.print("Config validation: OK\n", .{});
        }
        return;
    }

    std.debug.print("Unknown config command: {s}\n\n", .{subcmd});
    printConfigUsage();
    std_compat.process.exit(1);
}

// ── Models ───────────────────────────────────────────────────────

fn runModels(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw models <{s}> [args]
            \\
            \\Commands:
            \\  list                          List available models
            \\  summary [--json]             Show configured provider summary
            \\  info <model>                  Show model details
            \\  benchmark                     Run model latency benchmark
            \\  refresh                       Refresh model catalog
            \\
        , .{MODELS_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        var cfg_opt: ?yc.config.Config = yc.config.Config.load(allocator) catch null;
        defer if (cfg_opt) |*c| c.deinit();

        std.debug.print("Current configuration:\n", .{});
        if (cfg_opt) |c| {
            std.debug.print("  Provider: {s}\n", .{c.default_provider});
            std.debug.print("  Model:    {s}\n", .{c.default_model orelse "(not set)"});
            std.debug.print("  Temp:     {d:.1}\n\n", .{c.default_temperature});
        } else {
            std.debug.print("  (no config -- run `nullclaw onboard` first)\n\n", .{});
        }

        std.debug.print("Known providers and default models:\n", .{});
        for (yc.onboard.known_providers) |p| {
            std.debug.print("  {s:<12} {s:<36} {s}\n", .{ p.key, p.default_model, p.label });
        }
        std.debug.print("\nUse `nullclaw models info <model>` for details.\n", .{});
    } else if (std.mem.eql(u8, subcmd, "summary")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            std.debug.print("Usage: nullclaw models summary [--json]\n", .{});
            std_compat.process.exit(1);
        }

        var cfg = yc.config.Config.load(allocator) catch {
            if (hasJsonFlag(sub_args[1..])) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
            std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
            std_compat.process.exit(1);
        };
        defer cfg.deinit();

        const summary_json = buildModelsSummaryJson(allocator, &cfg) catch |err| {
            if (hasJsonFlag(sub_args[1..])) writeJsonError("models_summary_failed", "Failed to build models summary", null);
            std.debug.print("Failed to build models summary: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        defer allocator.free(summary_json);

        if (hasJsonFlag(sub_args[1..])) {
            printStdoutBytes(summary_json);
            printStdoutBytes("\n");
        } else {
            std.debug.print("Configured provider summary:\n", .{});
            std.debug.print("  Default provider: {s}\n", .{if (cfg.default_provider.len > 0) cfg.default_provider else "(not set)"});
            if (cfg.default_model) |model| {
                if (cfg.default_provider.len > 0) {
                    std.debug.print("  Default model:    {s}/{s}\n", .{ cfg.default_provider, model });
                } else {
                    std.debug.print("  Default model:    {s}\n", .{model});
                }
            } else {
                std.debug.print("  Default model:    (not set)\n", .{});
            }
            if (cfg.providers.len == 0) {
                std.debug.print("  Providers:        (none configured)\n", .{});
            } else {
                std.debug.print("  Providers:\n", .{});
                for (cfg.providers) |provider| {
                    std.debug.print("    - {s} [{s}]\n", .{
                        provider.name,
                        if (provider.api_key != null and std.mem.trim(u8, provider.api_key.?, " \t\r\n").len > 0) "has_key" else "no_key",
                    });
                }
            }
        }
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw models info <model>\n", .{});
            std_compat.process.exit(1);
        }
        if (hasJsonFlag(sub_args[2..])) {
            writeModelInfoJson(sub_args[1]);
        } else {
            std.debug.print("Model: {s}\n", .{sub_args[1]});
            if (modelCanonicalProvider(sub_args[1])) |provider| {
                std.debug.print("  Default provider: {s}\n", .{provider});
            } else {
                std.debug.print("  Default provider: unknown\n", .{});
            }
            std.debug.print("  Context: varies by provider\n", .{});
            std.debug.print("  Pricing: see provider dashboard\n", .{});
        }
    } else if (std.mem.eql(u8, subcmd, "benchmark")) {
        std.debug.print("Running model latency benchmark...\n", .{});
        std.debug.print("Configure a provider first (nullclaw onboard).\n", .{});
    } else if (std.mem.eql(u8, subcmd, "refresh")) {
        try yc.onboard.runModelsRefresh(allocator);
    } else {
        std.debug.print("Unknown models command: {s}\n", .{subcmd});
        std_compat.process.exit(1);
    }
}

fn runMcp(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(std.fmt.comptimePrint(
            \\Usage: nullclaw mcp <{s}> [args]
            \\
            \\Commands:
            \\  list [--json]                List configured MCP servers
            \\  info <name> [--json]         Show details for one MCP server
            \\
        , .{MCP_SUBCOMMANDS}), .{});
        std_compat.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        if (hasJsonFlag(sub_args[1..])) writeJsonError("config_not_found", "No config found -- run `nullclaw onboard` first", null);
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer cfg.deinit();

    const subcmd = sub_args[0];
    if (std.mem.eql(u8, subcmd, "list")) {
        if (sub_args.len > 2 or (sub_args.len == 2 and !std.mem.eql(u8, sub_args[1], "--json"))) {
            std.debug.print("Usage: nullclaw mcp list [--json]\n", .{});
            std_compat.process.exit(1);
        }
        if (hasJsonFlag(sub_args[1..])) {
            const body = yc.mcp_admin.buildServersJson(allocator, cfg.mcp_servers) catch |err| {
                writeJsonError("mcp_list_failed", @errorName(err), null);
                std_compat.process.exit(1);
            };
            defer allocator.free(body);
            printStdoutBytes(body);
            printStdoutBytes("\n");
            return;
        }

        if (cfg.mcp_servers.len == 0) {
            std.debug.print("No MCP servers configured.\n", .{});
            return;
        }

        std.debug.print("Configured MCP servers:\n", .{});
        for (cfg.mcp_servers) |server| {
            std.debug.print("  - {s} [{s}] {s}\n", .{ server.name, server.transport, server.command });
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2 or sub_args.len > 3 or (sub_args.len == 3 and !std.mem.eql(u8, sub_args[2], "--json"))) {
            std.debug.print("Usage: nullclaw mcp info <name> [--json]\n", .{});
            std_compat.process.exit(1);
        }

        const server_json = yc.mcp_admin.buildServerJson(allocator, cfg.mcp_servers, sub_args[1]) catch |err| {
            if (hasJsonFlag(sub_args[2..])) writeJsonError("mcp_info_failed", @errorName(err), null);
            std.debug.print("Failed to inspect MCP server: {s}\n", .{@errorName(err)});
            std_compat.process.exit(1);
        };
        if (server_json) |body| {
            defer allocator.free(body);
            if (hasJsonFlag(sub_args[2..])) {
                printStdoutBytes(body);
                printStdoutBytes("\n");
            } else {
                std.debug.print("{s}\n", .{body});
            }
            return;
        }

        if (hasJsonFlag(sub_args[2..])) writeJsonError("mcp_not_found", "MCP server not found", null);
        std.debug.print("MCP server not found: {s}\n", .{sub_args[1]});
        std_compat.process.exit(1);
    }

    std.debug.print("Unknown mcp command: {s}\n", .{subcmd});
    std_compat.process.exit(1);
}

// ── Onboard ──────────────────────────────────────────────────────

const OnboardMode = enum {
    quick,
    interactive,
    channels_only,
};

const OnboardArgs = struct {
    mode: OnboardMode = .quick,
    api_key: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    memory_backend: ?[]const u8 = null,
};

const OnboardArgParseResult = union(enum) {
    ok: OnboardArgs,
    unknown_option: []const u8,
    missing_value: []const u8,
    unexpected_argument: []const u8,
    invalid_combination: void,
};

fn parseOnboardArgs(sub_args: []const []const u8) OnboardArgParseResult {
    var parsed = OnboardArgs{};

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        const arg = sub_args[i];
        if (std.mem.eql(u8, arg, "--interactive")) {
            if (parsed.mode == .channels_only) return .{ .invalid_combination = {} };
            parsed.mode = .interactive;
            continue;
        }
        if (std.mem.eql(u8, arg, "--channels-only")) {
            if (parsed.mode == .interactive) return .{ .invalid_combination = {} };
            parsed.mode = .channels_only;
            continue;
        }
        if (std.mem.eql(u8, arg, "--api-key")) {
            if (i + 1 >= sub_args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.api_key = sub_args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--provider")) {
            if (i + 1 >= sub_args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.provider = sub_args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--model")) {
            if (i + 1 >= sub_args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.model = sub_args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--memory")) {
            if (i + 1 >= sub_args.len) return .{ .missing_value = arg };
            i += 1;
            parsed.memory_backend = sub_args[i];
            continue;
        }

        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .unknown_option = arg };
        }
        return .{ .unexpected_argument = arg };
    }

    if (parsed.mode != .quick and
        (parsed.api_key != null or parsed.provider != null or parsed.memory_backend != null))
    {
        return .{ .invalid_combination = {} };
    }

    return .{ .ok = parsed };
}

fn printOnboardUsage() void {
    std.debug.print(
        \\Usage: nullclaw onboard [--interactive | --channels-only | [--api-key KEY] [--provider PROV] [--model MODEL] [--memory MEM]]
        \\
        \\Modes:
        \\  (default)         quick setup
        \\  --interactive     run full interactive wizard
        \\  --channels-only   reconfigure channels and allowlists only
        \\
        \\Quick setup options:
        \\  --api-key KEY     provider API key to persist in config
        \\  --provider PROV   default provider key (e.g. openrouter, anthropic, custom:https://...)
        \\  --model MODEL     default model for the provider (e.g. gpt-5.2, claude-opus-4-6)
        \\  --memory MEM      memory backend key (e.g. markdown, sqlite, kg, memory)
        \\
        \\Examples:
        \\  nullclaw onboard --api-key sk-... --provider openrouter
        \\  nullclaw onboard --api-key sk-... --provider custom:https://api.example.com/v1 --model minimaxai/minimax-m2.1
        \\  nullclaw onboard --interactive
        \\
    , .{});
}

fn printKnownOnboardProviders() void {
    std.debug.print("Known providers:", .{});
    for (yc.onboard.known_providers) |p| {
        std.debug.print(" {s}", .{p.key});
    }
    std.debug.print("\n", .{});
}

fn printEnabledMemoryBackends(allocator: std.mem.Allocator) void {
    const enabled = yc.memory.registry.formatEnabledBackends(allocator) catch null;
    defer if (enabled) |names| allocator.free(names);

    if (enabled) |names| {
        std.debug.print("Enabled memory backends in this build: {s}\n", .{names});
    }
}

fn runOnboard(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len == 1 and
        (std.mem.eql(u8, sub_args[0], "--help") or std.mem.eql(u8, sub_args[0], "-h")))
    {
        printOnboardUsage();
        return;
    }

    const parsed = switch (parseOnboardArgs(sub_args)) {
        .ok => |args| args,
        .unknown_option => |opt| {
            std.debug.print("Unknown onboard option: {s}\n\n", .{opt});
            printOnboardUsage();
            std_compat.process.exit(1);
        },
        .missing_value => |opt| {
            std.debug.print("Missing value for onboard option: {s}\n\n", .{opt});
            printOnboardUsage();
            std_compat.process.exit(1);
        },
        .unexpected_argument => |arg| {
            std.debug.print("Unexpected positional argument for onboard: {s}\n\n", .{arg});
            printOnboardUsage();
            std_compat.process.exit(1);
        },
        .invalid_combination => {
            std.debug.print("Invalid onboard option combination.\n", .{});
            std.debug.print("Use either --interactive, --channels-only, or quick-setup flags.\n\n", .{});
            printOnboardUsage();
            std_compat.process.exit(1);
        },
    };

    switch (parsed.mode) {
        .channels_only => yc.onboard.runChannelsOnly(allocator) catch |err| switch (err) {
            error.InsecurePlaintextSecrets => {
                yc.config.Config.printValidationError(error.InsecurePlaintextSecrets);
                std_compat.process.exit(1);
            },
            else => return err,
        },
        .interactive => yc.onboard.runWizard(allocator) catch |err| switch (err) {
            error.InsecurePlaintextSecrets => {
                yc.config.Config.printValidationError(error.InsecurePlaintextSecrets);
                std_compat.process.exit(1);
            },
            else => return err,
        },
        .quick => yc.onboard.runQuickSetup(allocator, parsed.api_key, parsed.provider, parsed.model, parsed.memory_backend) catch |err| switch (err) {
            error.InsecurePlaintextSecrets => {
                yc.config.Config.printValidationError(error.InsecurePlaintextSecrets);
                std_compat.process.exit(1);
            },
            error.UnknownProvider => {
                const requested = parsed.provider orelse "(missing)";
                std.debug.print("Unknown provider '{s}' for quick setup.\n", .{requested});
                printKnownOnboardProviders();
                std_compat.process.exit(1);
            },
            error.UnknownMemoryBackend => {
                const requested = parsed.memory_backend orelse "(missing)";
                std.debug.print("Unknown memory backend '{s}' for quick setup.\n", .{requested});
                std.debug.print("Known memory backends: {s}\n", .{yc.memory.registry.known_backends_csv});
                printEnabledMemoryBackends(allocator);
                std_compat.process.exit(1);
            },
            error.MemoryBackendDisabledInBuild => {
                const requested = parsed.memory_backend orelse "(missing)";
                const engine_token = yc.memory.registry.engineTokenForBackend(requested) orelse requested;
                std.debug.print("Memory backend '{s}' is disabled in this build.\n", .{requested});
                std.debug.print("Rebuild with -Dengines={s} (or include it in -Dengines=... list).\n", .{engine_token});
                printEnabledMemoryBackends(allocator);
                std_compat.process.exit(1);
            },
            else => return err,
        },
    }
}

// ── Channel Start ────────────────────────────────────────────────
// Usage: nullclaw channel start [channel]
// If a channel name is given, start that specific channel.
// Otherwise, start the first available (Telegram first, then Signal).
// To run all configured channels/accounts together, use `nullclaw gateway`.

fn canStartFromChannelCommand(channel_id: yc.channel_catalog.ChannelId) bool {
    if (!yc.channel_catalog.isBuildEnabled(channel_id)) return false;
    return switch (channel_id) {
        .cli, .webhook => false,
        else => true,
    };
}

const ResolvedRuntimeChannel = struct {
    adapter_key: []const u8,
    start_name: []const u8,
};

fn resolveConfiguredRuntimeChannel(config: *const yc.config.Config, requested: []const u8) ?ResolvedRuntimeChannel {
    for (config.channels.external) |external_cfg| {
        if (std.mem.eql(u8, external_cfg.runtime_name, requested)) {
            return .{
                .adapter_key = "external",
                .start_name = external_cfg.runtime_name,
            };
        }
    }

    for (config.channels.maixcam) |maixcam_cfg| {
        if (std.mem.eql(u8, maixcam_cfg.name, requested)) {
            return .{
                .adapter_key = "maixcam",
                .start_name = maixcam_cfg.name,
            };
        }
    }

    return null;
}

fn printConfiguredRuntimeChannelNames(config: *const yc.config.Config) void {
    var first = true;

    for (config.channels.external) |external_cfg| {
        if (external_cfg.runtime_name.len == 0) continue;
        if (first) {
            std.debug.print("Configured runtime channel names: {s}", .{external_cfg.runtime_name});
        } else {
            std.debug.print(", {s}", .{external_cfg.runtime_name});
        }
        first = false;
    }

    for (config.channels.maixcam) |maixcam_cfg| {
        if (maixcam_cfg.name.len == 0 or std.mem.eql(u8, maixcam_cfg.name, "maixcam")) continue;
        if (first) {
            std.debug.print("Configured runtime channel names: {s}", .{maixcam_cfg.name});
        } else {
            std.debug.print(", {s}", .{maixcam_cfg.name});
        }
        first = false;
    }

    if (!first) {
        std.debug.print("\n", .{});
    }
}

fn printChannelStartSupported() void {
    std.debug.print("Supported:", .{});
    for (yc.channel_catalog.known_channels) |meta| {
        if (!canStartFromChannelCommand(meta.id)) continue;
        std.debug.print(" {s}", .{meta.key});
    }
    std.debug.print("\n", .{});
}

fn dispatchChannelStart(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    config: *const yc.config.Config,
    meta: yc.channel_catalog.ChannelMeta,
) !void {
    if (!yc.channel_catalog.isBuildEnabled(meta.id)) {
        std.debug.print("{s} channel is disabled in this build.\n", .{meta.label});
        std.debug.print("Rebuild with -Dchannels={s} (or -Dchannels=all).\n", .{meta.key});
        std_compat.process.exit(1);
    }

    switch (meta.id) {
        .telegram => {
            if (config.channels.telegramPrimary()) |tg_config| {
                return runTelegramChannel(allocator, args, config.*, tg_config);
            }
            std.debug.print("Telegram channel is not configured.\n", .{});
            std_compat.process.exit(1);
        },
        .signal => {
            if (config.channels.signalPrimary()) |sig_config| {
                return runSignalChannel(allocator, args, config, sig_config);
            }
            std.debug.print("Signal channel is not configured.\n", .{});
            std_compat.process.exit(1);
        },
        .matrix => {
            if (config.channels.matrixPrimary()) |mx_config| {
                return runMatrixChannel(allocator, args, config, mx_config);
            }
            std.debug.print("Matrix channel is not configured.\n", .{});
            std_compat.process.exit(1);
        },
        .max => {
            if (config.channels.maxPrimary()) |max_config| {
                return runMaxChannel(allocator, args, config, max_config);
            }
            std.debug.print("Max channel is not configured.\n", .{});
            std_compat.process.exit(1);
        },
        else => return runGatewayChannel(allocator, config, meta.key),
    }
}

fn hasConfiguredStartableChannels(config: *const yc.config.Config) bool {
    for (yc.channel_catalog.known_channels) |meta| {
        if (!canStartFromChannelCommand(meta.id)) continue;
        if (yc.channel_catalog.isConfigured(config, meta.id)) return true;
    }
    return false;
}

fn hasConfiguredButBuildDisabledStartableChannels(config: *const yc.config.Config) bool {
    for (yc.channel_catalog.known_channels) |meta| {
        if (meta.id == .cli or meta.id == .webhook) continue;
        if (yc.channel_catalog.isBuildEnabled(meta.id)) continue;
        if (yc.channel_catalog.configuredCount(config, meta.id) > 0) return true;
    }
    return false;
}

fn printConfiguredButBuildDisabledChannelsHint(config: *const yc.config.Config) void {
    std.debug.print("Configured channels are disabled in this build:", .{});
    var first: bool = true;
    for (yc.channel_catalog.known_channels) |meta| {
        if (meta.id == .cli or meta.id == .webhook) continue;
        if (yc.channel_catalog.isBuildEnabled(meta.id)) continue;
        if (yc.channel_catalog.configuredCount(config, meta.id) == 0) continue;
        if (first) {
            std.debug.print(" {s}", .{meta.key});
            first = false;
        } else {
            std.debug.print(", {s}", .{meta.key});
        }
    }
    std.debug.print("\n", .{});
    std.debug.print("Rebuild with -Dchannels=all or -Dchannels=", .{});
    first = true;
    for (yc.channel_catalog.known_channels) |meta| {
        if (meta.id == .cli or meta.id == .webhook) continue;
        if (yc.channel_catalog.isBuildEnabled(meta.id)) continue;
        if (yc.channel_catalog.configuredCount(config, meta.id) == 0) continue;
        if (first) {
            std.debug.print("{s}", .{meta.key});
            first = false;
        } else {
            std.debug.print(",{s}", .{meta.key});
        }
    }
    std.debug.print("\n", .{});
}

fn printNoMessagingChannelConfiguredHint() void {
    std.debug.print("No messaging channel configured. Add to config.json:\n", .{});
    std.debug.print("  Telegram: {{\"channels\": {{\"telegram\": {{\"accounts\": {{\"main\": {{\"bot_token\": \"...\"}}}}}}}}\n", .{});
    std.debug.print("  Signal:   {{\"channels\": {{\"signal\": {{\"accounts\": {{\"main\": {{\"http_url\": \"http://127.0.0.1:8080\", \"account\": \"+1234567890\"}}}}}}}}\n", .{});
}

const ChannelStartBusDrainCtx = struct {
    allocator: std.mem.Allocator,
    bus: *yc.bus.Bus,
};

fn drainChannelStartBus(ctx: *const ChannelStartBusDrainCtx) void {
    while (ctx.bus.consumeInbound()) |msg| {
        msg.deinit(ctx.allocator);
    }
}

fn runChannelStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len > 0 and std.mem.eql(u8, args[0], "--all")) {
        std.debug.print("Use `nullclaw gateway` to start all configured channels/accounts.\n", .{});
        std_compat.process.exit(1);
    }

    // Load config
    var config = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std_compat.process.exit(1);
    };
    defer config.deinit();

    config.validate() catch |err| {
        yc.config.Config.printValidationError(err);
        std_compat.process.exit(1);
    };
    applyRuntimeProviderOverrides(&config);

    if (!hasConfiguredStartableChannels(&config)) {
        if (hasConfiguredButBuildDisabledStartableChannels(&config)) {
            printConfiguredButBuildDisabledChannelsHint(&config);
        } else {
            printNoMessagingChannelConfiguredHint();
        }
        std_compat.process.exit(1);
    }

    // Check if user specified a channel name
    const requested: ?[]const u8 = if (args.len > 0) args[0] else null;

    if (requested) |ch_name| {
        if (yc.channel_catalog.findByKey(ch_name)) |meta| {
            if (!yc.channel_catalog.isBuildEnabled(meta.id)) {
                const configured = yc.channel_catalog.configuredCount(&config, meta.id);
                if (configured > 0) {
                    std.debug.print("Channel {s} is configured ({d} account(s)) but disabled in this build.\n", .{ meta.key, configured });
                } else {
                    std.debug.print("Channel {s} is disabled in this build.\n", .{meta.key});
                }
                std.debug.print("Rebuild with -Dchannels={s} (or -Dchannels=all).\n", .{meta.key});
                printChannelStartSupported();
                std_compat.process.exit(1);
            }
            if (!canStartFromChannelCommand(meta.id)) {
                std.debug.print("Channel {s} cannot be started via `channel start`.\n", .{ch_name});
                printChannelStartSupported();
                std_compat.process.exit(1);
            }
            if (!yc.channel_catalog.isConfigured(&config, meta.id)) {
                std.debug.print("{s} channel is not configured.\n", .{meta.label});
                std_compat.process.exit(1);
            }

            const child_args: []const []const u8 = if (args.len > 1) args[1..] else &.{};
            return dispatchChannelStart(allocator, child_args, &config, meta);
        }

        if (resolveConfiguredRuntimeChannel(&config, ch_name)) |resolved| {
            const meta = yc.channel_catalog.findByKey(resolved.adapter_key) orelse unreachable;
            if (!yc.channel_catalog.isBuildEnabled(meta.id)) {
                std.debug.print("Channel {s} is configured via {s} but disabled in this build.\n", .{ ch_name, meta.key });
                std.debug.print("Rebuild with -Dchannels={s} (or -Dchannels=all).\n", .{meta.key});
                printChannelStartSupported();
                std_compat.process.exit(1);
            }
            if (!canStartFromChannelCommand(meta.id)) {
                std.debug.print("Channel {s} cannot be started via `channel start`.\n", .{ch_name});
                printChannelStartSupported();
                std_compat.process.exit(1);
            }

            return runGatewayChannel(allocator, &config, resolved.start_name);
        }

        std.debug.print("Unknown channel: {s}\n", .{ch_name});
        printChannelStartSupported();
        printConfiguredRuntimeChannelNames(&config);
        std_compat.process.exit(1);
    }

    // No channel specified -- keep historical preference:
    // Telegram first, then Signal, then any other configured channel.
    if (yc.channel_catalog.findByKey("telegram")) |meta| {
        if (yc.channel_catalog.isConfigured(&config, meta.id)) {
            return dispatchChannelStart(allocator, args, &config, meta);
        }
    }
    if (yc.channel_catalog.findByKey("signal")) |meta| {
        if (yc.channel_catalog.isConfigured(&config, meta.id)) {
            return dispatchChannelStart(allocator, args, &config, meta);
        }
    }

    for (yc.channel_catalog.known_channels) |meta| {
        if (!canStartFromChannelCommand(meta.id)) continue;
        if (meta.id == .telegram or meta.id == .signal) continue;
        if (!yc.channel_catalog.isConfigured(&config, meta.id)) continue;
        return dispatchChannelStart(allocator, args, &config, meta);
    }
}

/// Start a single configured non-polling channel using ChannelManager.
fn runGatewayChannel(allocator: std.mem.Allocator, config: *const yc.config.Config, ch_name: []const u8) !void {
    var registry = yc.channels.dispatch.ChannelRegistry.init(allocator);
    defer registry.deinit();

    // Use a drain-only bus so `channel start` can exercise inbound wiring
    // without leaking or stalling if the user sends test messages.
    var event_bus = yc.bus.Bus.init();
    var drain_ctx = ChannelStartBusDrainCtx{
        .allocator = allocator,
        .bus = &event_bus,
    };
    const drain_thread = try std.Thread.spawn(.{}, drainChannelStartBus, .{&drain_ctx});
    defer drain_thread.join();
    defer event_bus.close();

    const mgr = try yc.channel_manager.ChannelManager.init(allocator, config, &registry);
    defer mgr.deinit();

    mgr.setEventBus(&event_bus);

    try mgr.collectConfiguredChannels();

    // Find and start only the requested channel
    var found = false;
    var started_name = ch_name;
    for (mgr.channelEntries()) |entry| {
        if (std.mem.eql(u8, entry.name, ch_name) or std.mem.eql(u8, entry.adapter_key, ch_name)) {
            entry.channel.start() catch |err| {
                std.debug.print("{s} channel failed to start: {}\n", .{ entry.name, err });
                std_compat.process.exit(1);
            };
            found = true;
            started_name = entry.name;
            break;
        }
    }

    if (!found) {
        std.debug.print("{s} channel is not configured.\n", .{ch_name});
        std_compat.process.exit(1);
    }

    std.debug.print("{s} channel started. Press Ctrl+C to stop.\n", .{started_name});

    // Block until Ctrl+C
    while (!yc.daemon.isShutdownRequested()) {
        std_compat.thread.sleep(1 * std.time.ns_per_s);
    }
}

// ── Signal Channel ─────────────────────────────────────────────────

fn ensureChannelStartupCredentials(
    allocator: std.mem.Allocator,
    config: *const yc.config.Config,
) void {
    if (yc.channel_loop.hasStartupProviderCredentials(allocator, config)) return;

    if (std.mem.eql(u8, config.default_provider, "openai-codex")) {
        std.debug.print("No OpenAI Codex credentials configured.\n", .{});
        std.debug.print("  Run `nullclaw auth login openai-codex` or `nullclaw auth login openai-codex --import-codex`.\n", .{});
        std_compat.process.exit(1);
    }

    if (yc.provider_probe.providerRequiresApiKey(config.default_provider, config.getProviderBaseUrl(config.default_provider))) {
        std.debug.print("No usable provider credentials configured for {s}. Set env var or add to ~/.nullclaw/config.json:\n", .{config.default_provider});
        std.debug.print("  \"providers\": {{ \"{s}\": {{ \"api_key\": \"...\" }} }}\n", .{config.default_provider});
        std_compat.process.exit(1);
    }

    std.debug.print("No usable startup credentials configured for provider {s}.\n", .{config.default_provider});
    std.debug.print("Authenticate the provider locally or configure a reliability fallback provider.\n", .{});
    std_compat.process.exit(1);
}

fn runSignalChannel(allocator: std.mem.Allocator, args: []const []const u8, config: *const yc.config.Config, signal_config: yc.config.SignalConfig) !void {
    _ = args;
    if (!build_options.enable_channel_signal) {
        std.debug.print("Signal channel is disabled in this build.\n", .{});
        std_compat.process.exit(1);
    }

    ensureChannelStartupCredentials(allocator, config);

    const temperature = config.default_temperature;

    std.debug.print("nullclaw Signal bot starting...\n", .{});
    config.printModelConfig();
    std.debug.print("  Temperature: {d:.1}\n", .{temperature});
    std.debug.print("  Signal URL: {s}\n", .{signal_config.http_url});
    std.debug.print("  Account: {s}\n", .{signal_config.account});
    if (signal_config.allow_from.len == 0) {
        std.debug.print("  Allowed users: (none — all messages will be denied)\n", .{});
    } else if (signal_config.allow_from.len == 1 and std.mem.eql(u8, signal_config.allow_from[0], "*")) {
        std.debug.print("  Allowed users: *\n", .{});
    } else {
        std.debug.print("  Allowed users:", .{});
        for (signal_config.allow_from) |u| {
            std.debug.print(" {s}", .{u});
        }
        std.debug.print("\n", .{});
    }
    std.debug.print("  Group policy: {s}\n", .{signal_config.group_policy});
    if (signal_config.group_allow_from.len == 0) {
        std.debug.print("  Group allowed senders: (fallback to allow_from)\n", .{});
    } else if (signal_config.group_allow_from.len == 1 and std.mem.eql(u8, signal_config.group_allow_from[0], "*")) {
        std.debug.print("  Group allowed senders: *\n", .{});
    } else {
        std.debug.print("  Group allowed senders:", .{});
        for (signal_config.group_allow_from) |g| {
            std.debug.print(" {s}", .{g});
        }
        std.debug.print("\n", .{});
    }

    // Env overrides for Signal
    const env_http_url = std_compat.process.getEnvVarOwned(allocator, "SIGNAL_HTTP_URL") catch null;
    defer if (env_http_url) |v| allocator.free(v);
    const env_account = std_compat.process.getEnvVarOwned(allocator, "SIGNAL_ACCOUNT") catch null;
    defer if (env_account) |v| allocator.free(v);
    const effective_http_url = env_http_url orelse signal_config.http_url;
    const effective_account = env_account orelse signal_config.account;

    var sg = yc.channels.signal.SignalChannel.init(
        allocator,
        effective_http_url,
        effective_account,
        signal_config.allow_from,
        signal_config.group_allow_from,
        signal_config.ignore_attachments,
        signal_config.ignore_stories,
    );
    sg.group_policy = signal_config.group_policy;
    sg.account_id = signal_config.account_id;

    // Verify health
    if (!sg.healthCheck()) {
        std.debug.print("Signal health check failed. Is signal-cli daemon running?\n", .{});
        std.debug.print("  Run: signal-cli --account {s} daemon --http 127.0.0.1:8080\n", .{signal_config.account});
        std_compat.process.exit(1);
    }

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});
    const runtime = yc.channel_loop.ChannelRuntime.init(allocator, config) catch |err| {
        std.debug.print("Runtime init failed: {}\n", .{err});
        std_compat.process.exit(1);
    };
    defer runtime.deinit();
    var loop_state = yc.channel_loop.SignalLoopState.init();
    yc.channel_loop.runSignalLoop(allocator, config, runtime, &loop_state, &sg);
}

// ── Matrix Channel ────────────────────────────────────────────────

fn runMatrixChannel(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    config: *const yc.config.Config,
    matrix_config: yc.config.MatrixConfig,
) !void {
    _ = args;
    if (!build_options.enable_channel_matrix) {
        std.debug.print("Matrix channel is disabled in this build.\n", .{});
        std_compat.process.exit(1);
    }

    ensureChannelStartupCredentials(allocator, config);

    var mx = yc.channels.matrix.MatrixChannel.initFromConfig(allocator, matrix_config);

    std.debug.print("nullclaw Matrix bot starting...\n", .{});
    std.debug.print("  Provider: {s}\n", .{config.default_provider});
    std.debug.print("  Homeserver: {s}\n", .{mx.homeserver});
    std.debug.print("  Account ID: {s}\n", .{mx.account_id});
    std.debug.print("  Room: {s}\n", .{mx.room_id});
    std.debug.print("  Group policy: {s}\n", .{mx.group_policy});
    if (mx.group_allow_from.len == 0) {
        std.debug.print("  Group allowed senders: (fallback to allow_from)\n", .{});
    } else if (mx.group_allow_from.len == 1 and std.mem.eql(u8, mx.group_allow_from[0], "*")) {
        std.debug.print("  Group allowed senders: *\n", .{});
    } else {
        std.debug.print("  Group allowed senders:", .{});
        for (mx.group_allow_from) |entry| {
            std.debug.print(" {s}", .{entry});
        }
        std.debug.print("\n", .{});
    }

    if (!mx.healthCheck()) {
        std.debug.print("Matrix health check failed. Verify homeserver/access_token.\n", .{});
        std_compat.process.exit(1);
    }

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    const runtime = yc.channel_loop.ChannelRuntime.init(allocator, config) catch |err| {
        std.debug.print("Runtime init failed: {}\n", .{err});
        std_compat.process.exit(1);
    };
    defer runtime.deinit();

    var loop_state = yc.channel_loop.MatrixLoopState.init();
    yc.channel_loop.runMatrixLoop(allocator, config, runtime, &loop_state, &mx);
}

// ── Max Channel ───────────────────────────────────────────────────

fn runMaxChannel(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    config: *const yc.config.Config,
    max_config: yc.config.MaxConfig,
) !void {
    _ = args;
    if (!build_options.enable_channel_max) {
        std.debug.print("Max channel is disabled in this build.\n", .{});
        std_compat.process.exit(1);
    }

    ensureChannelStartupCredentials(allocator, config);

    var mx = yc.channels.max.MaxChannel.initFromConfig(allocator, max_config);

    if (mx.mode == .webhook) {
        std.debug.print("nullclaw Max channel configured for webhook delivery.\n", .{});
        return runGatewayChannel(allocator, config, "max");
    }

    std.debug.print("nullclaw Max bot starting...\n", .{});
    std.debug.print("  Provider: {s}\n", .{config.default_provider});
    std.debug.print("  Account ID: {s}\n", .{mx.account_id});
    std.debug.print("  Mode: {s}\n", .{@tagName(mx.mode)});
    std.debug.print("  Group policy: {s}\n", .{mx.group_policy});
    if (mx.allow_from.len == 0) {
        std.debug.print("  Allowed users: (none — all messages will be denied)\n", .{});
    } else if (mx.allow_from.len == 1 and std.mem.eql(u8, mx.allow_from[0], "*")) {
        std.debug.print("  Allowed users: *\n", .{});
    } else {
        std.debug.print("  Allowed users:", .{});
        for (mx.allow_from) |u| {
            std.debug.print(" {s}", .{u});
        }
        std.debug.print("\n", .{});
    }

    if (!mx.healthCheck()) {
        std.debug.print("Max health check failed. Verify bot_token.\n", .{});
        std_compat.process.exit(1);
    }

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    const runtime = yc.channel_loop.ChannelRuntime.init(allocator, config) catch |err| {
        std.debug.print("Runtime init failed: {}\n", .{err});
        std_compat.process.exit(1);
    };
    defer runtime.deinit();

    var loop_state = yc.channel_loop.MaxLoopState.init();
    yc.channel_loop.runMaxLoop(allocator, config, runtime, &loop_state, &mx);
}

// ── Telegram Channel ───────────────────────────────────────────────-

fn runTelegramChannel(allocator: std.mem.Allocator, args: []const []const u8, config: yc.config.Config, telegram_config: yc.config.TelegramConfig) !void {
    if (!build_options.enable_channel_telegram) {
        std.debug.print("Telegram channel is disabled in this build.\n", .{});
        std_compat.process.exit(1);
    }

    // Determine allowed users: --user CLI args override config allow_from
    var user_list: std.ArrayList([]const u8) = .empty;
    defer user_list.deinit(allocator);
    {
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--user") and i + 1 < args.len) {
                i += 1;
                user_list.append(allocator, args[i]) catch |err| log.err("failed to append user: {}", .{err});
            }
        }
    }
    const allowed: []const []const u8 = if (user_list.items.len > 0)
        user_list.items
    else
        telegram_config.allow_from;

    ensureChannelStartupCredentials(allocator, &config);
    std.debug.print("nullclaw telegram bot starting...\n", .{});
    config.printModelConfig();
    std.debug.print("  Temperature: {d:.1}\n", .{config.default_temperature});
    if (allowed.len == 0) {
        std.debug.print("  Allowed users: (none — all messages will be denied)\n", .{});
    } else if (allowed.len == 1 and std.mem.eql(u8, allowed[0], "*")) {
        std.debug.print("  Allowed users: *\n", .{});
    } else {
        std.debug.print("  Allowed users:", .{});
        for (allowed) |u| {
            std.debug.print(" {s}", .{u});
        }
        std.debug.print("\n", .{});
    }

    var runtime_telegram_config = telegram_config;
    runtime_telegram_config.allow_from = allowed;
    var tg = yc.channels.telegram.TelegramChannel.initFromConfig(allocator, runtime_telegram_config);
    tg.text_debounce_secs = yc.channels.telegram.TelegramChannel.textDebounceSecsFromMs(
        config.messages.inbound.debounce_ms,
    );
    const runtime = yc.channel_loop.ChannelRuntime.init(allocator, &config) catch |err| {
        std.debug.print("Runtime init failed: {}\n", .{err});
        std_compat.process.exit(1);
    };
    defer runtime.deinit();
    std.debug.print("  Tools: {d} loaded\n", .{runtime.tools.len});
    std.debug.print("  Memory: {s}\n", .{if (runtime.mem_rt != null) "enabled" else "disabled"});
    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    var loop_state = yc.channel_loop.TelegramLoopState.init();
    yc.channel_loop.runTelegramLoop(allocator, &config, runtime, &loop_state, &tg);
}

// ── Auth ─────────────────────────────────────────────────────────

fn runAuth(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 2) {
        printAuthUsage();
        std_compat.process.exit(1);
    }

    const subcmd = sub_args[0];
    const provider_name = sub_args[1];
    const rest = sub_args[2..];

    // Resolve provider-specific constants
    const codex = yc.providers.openai_codex;
    const auth_mod = yc.auth;

    if (std.mem.eql(u8, provider_name, "weixin")) {
        runAuthWeixin(allocator, subcmd, rest);
        return;
    }

    if (!std.mem.eql(u8, provider_name, "openai-codex")) {
        std.debug.print("Unknown auth provider: {s}\n\n", .{provider_name});
        std.debug.print("Available providers:\n", .{});
        std.debug.print("  openai-codex    ChatGPT Plus/Pro subscription (OAuth)\n", .{});
        std.debug.print("  weixin          WeChat personal account (QR code scan)\n", .{});
        std_compat.process.exit(1);
    }

    if (std.mem.eql(u8, subcmd, "login")) {
        var import_codex = false;
        for (rest) |arg| {
            if (std.mem.eql(u8, arg, "--import-codex")) import_codex = true;
        }

        if (import_codex) {
            runAuthImportCodex(allocator, codex, auth_mod);
        } else {
            runAuthDeviceCodeLogin(allocator, codex, auth_mod);
        }
    } else if (std.mem.eql(u8, subcmd, "status")) {
        if (auth_mod.loadCredential(allocator, codex.CREDENTIAL_KEY) catch null) |token| {
            defer token.deinit(allocator);
            std.debug.print("openai-codex: authenticated\n", .{});
            if (token.expires_at != 0) {
                const remaining = token.expires_at - std_compat.time.timestamp();
                if (remaining > 0) {
                    std.debug.print("  Token expires in: {d}h {d}m\n", .{
                        @divTrunc(remaining, 3600),
                        @divTrunc(@mod(remaining, 3600), 60),
                    });
                } else {
                    std.debug.print("  Token: expired (will auto-refresh)\n", .{});
                }
            }
            if (token.refresh_token != null) {
                std.debug.print("  Refresh token: present\n", .{});
            }
            const account_id = codex.extractAccountIdFromJwt(allocator, token.access_token) catch null;
            defer if (account_id) |id| allocator.free(id);
            if (account_id) |id| {
                std.debug.print("  Account: {s}\n", .{id});
            }
        } else if (yc.codex_support.hasOpenAiCodexCredential(allocator)) {
            std.debug.print("openai-codex: authenticated via Codex CLI\n", .{});
            std.debug.print("  Tokens found in ~/.codex/auth.json\n", .{});
            std.debug.print("  Run `nullclaw auth login openai-codex --import-codex` to persist them in auth.json in your nullclaw config directory.\n", .{});
        } else {
            std.debug.print("openai-codex: not authenticated\n", .{});
            std.debug.print("  Run `nullclaw auth login openai-codex` to authenticate.\n", .{});
        }
    } else if (std.mem.eql(u8, subcmd, "logout")) {
        if (auth_mod.deleteCredential(allocator, codex.CREDENTIAL_KEY) catch false) {
            std.debug.print("openai-codex: credentials removed.\n", .{});
        } else {
            std.debug.print("openai-codex: no credentials found.\n", .{});
        }
    } else {
        std.debug.print("Unknown auth command: {s}\n\n", .{subcmd});
        printAuthUsage();
        std_compat.process.exit(1);
    }
}

// ── Update ─────────────────────────────────────────────────────────

fn runUpdate(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var opts = yc.update.Options{ .check_only = false, .yes = false };

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        if (std.mem.eql(u8, sub_args[i], "--check")) {
            opts.check_only = true;
        } else if (std.mem.eql(u8, sub_args[i], "--yes")) {
            opts.yes = true;
        } else {
            std.debug.print("Unknown option: {s}\n", .{sub_args[i]});
            std.debug.print("Usage: nullclaw update [--check] [--yes]\n", .{});
            std_compat.process.exit(1);
        }
    }

    yc.update.run(allocator, opts) catch |err| {
        std.debug.print("Update failed: {s}\n", .{@errorName(err)});
        std_compat.process.exit(1);
    };
}

fn printAuthUsage() void {
    std.debug.print(std.fmt.comptimePrint(
        \\Usage: nullclaw auth <{s}> <provider> [options]
        \\
        \\Commands:
        \\  login <provider>                    Authenticate with provider
        \\  login <provider> --import-codex     Import from Codex CLI (~/.codex/auth.json)
        \\  status <provider>                   Show authentication status
        \\  logout <provider>                   Remove stored credentials
        \\
        \\Providers:
        \\  openai-codex    ChatGPT Plus/Pro subscription (OAuth)
        \\  weixin          WeChat personal account (QR code scan)
        \\
        \\Weixin options:
        \\  --base-url <url>    iLink API base URL (default: https://ilinkai.weixin.qq.com/)
        \\  --proxy <url>       HTTP proxy URL (e.g. http://localhost:7890)
        \\  --timeout <secs>    Login timeout in seconds (default: 300)
        \\
        \\Examples:
        \\  nullclaw auth login openai-codex
        \\  nullclaw auth login openai-codex --import-codex
        \\  nullclaw auth login weixin
        \\  nullclaw auth login weixin --proxy http://localhost:7890
        \\  nullclaw auth status openai-codex
        \\  nullclaw auth status weixin
        \\  nullclaw auth logout openai-codex
        \\
    , .{AUTH_SUBCOMMANDS}), .{});
}

fn runAuthWeixin(allocator: std.mem.Allocator, subcmd: []const u8, args: []const []const u8) void {
    const weixin_mod = yc.channels.weixin;
    const config_mutator = yc.config_mutator;

    if (std.mem.eql(u8, subcmd, "login")) {
        var opts = weixin_mod.LoginOptions{};

        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--base-url") and i + 1 < args.len) {
                i += 1;
                opts.base_url = args[i];
            } else if (std.mem.eql(u8, args[i], "--proxy") and i + 1 < args.len) {
                i += 1;
                opts.proxy = args[i];
            } else if (std.mem.eql(u8, args[i], "--timeout") and i + 1 < args.len) {
                i += 1;
                const secs = std.fmt.parseInt(u64, args[i], 10) catch {
                    std.debug.print("Invalid timeout value: {s}\n", .{args[i]});
                    std.process.exit(1);
                };
                opts.timeout_ns = secs * std.time.ns_per_s;
            } else {
                std.debug.print("Unknown option: {s}\n", .{args[i]});
                printAuthUsage();
                std.process.exit(1);
            }
        }

        std.debug.print("Starting Weixin (WeChat personal) login...\n\n", .{});

        var result = weixin_mod.performLogin(allocator, opts) catch |err| {
            std.debug.print("Weixin login failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer result.deinit(allocator);

        std.debug.print("\nLogin successful!\n", .{});
        std.debug.print("  Account ID: {s}\n", .{result.account_id});
        if (result.user_id.len > 0) {
            std.debug.print("  User ID: {s}\n", .{result.user_id});
        }

        // Persist token to config
        const token_json = std.fmt.allocPrint(allocator, "\"{s}\"", .{result.bot_token}) catch {
            std.debug.print("\nCould not format token for config. Add manually:\n", .{});
            printManualWeixinConfig(result.bot_token, result.base_url);
            return;
        };
        defer allocator.free(token_json);

        _ = config_mutator.mutateDefaultConfig(
            allocator,
            .set,
            "channels.weixin.token",
            token_json,
            .{ .apply = true },
        ) catch {
            std.debug.print("\nCould not auto-save config. Add manually:\n", .{});
            printManualWeixinConfig(result.bot_token, result.base_url);
            return;
        };

        // Save base_url if it differs from default
        if (!std.mem.eql(u8, result.base_url, "https://ilinkai.weixin.qq.com/")) {
            const base_url_json = std.fmt.allocPrint(allocator, "\"{s}\"", .{result.base_url}) catch return;
            defer allocator.free(base_url_json);
            _ = config_mutator.mutateDefaultConfig(
                allocator,
                .set,
                "channels.weixin.base_url",
                base_url_json,
                .{ .apply = true },
            ) catch {};
        }

        std.debug.print("\nConfig updated. Start the gateway with:\n", .{});
        std.debug.print("  nullclaw gateway\n\n", .{});
        std.debug.print("To restrict which WeChat users can send messages, add their user IDs\n", .{});
        std.debug.print("to channels.weixin.allow_from in your config.\n", .{});
    } else if (std.mem.eql(u8, subcmd, "status")) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        var cfg = yc.config.Config.load(arena.allocator()) catch {
            std.debug.print("weixin: could not load config\n", .{});
            return;
        };
        defer cfg.deinit();

        if (cfg.channels.weixinPrimary()) |weixin_cfg| {
            if (weixin_cfg.token.len > 0) {
                std.debug.print("weixin: authenticated\n", .{});
                std.debug.print("  Token: {s}...{s}\n", .{
                    weixin_cfg.token[0..@min(8, weixin_cfg.token.len)],
                    if (weixin_cfg.token.len > 8) weixin_cfg.token[weixin_cfg.token.len - 4 ..] else "",
                });
                std.debug.print("  Base URL: {s}\n", .{weixin_cfg.base_url});
            } else {
                std.debug.print("weixin: not authenticated (token empty)\n", .{});
                std.debug.print("  Run `nullclaw auth login weixin` to authenticate.\n", .{});
            }
        } else {
            std.debug.print("weixin: not configured\n", .{});
            std.debug.print("  Run `nullclaw auth login weixin` to authenticate.\n", .{});
        }
    } else if (std.mem.eql(u8, subcmd, "logout")) {
        _ = config_mutator.mutateDefaultConfig(
            allocator,
            .unset,
            "channels.weixin.token",
            null,
            .{ .apply = true },
        ) catch |err| {
            std.debug.print("Failed to remove weixin credentials: {s}\n", .{@errorName(err)});
            return;
        };
        std.debug.print("weixin: credentials removed.\n", .{});
    } else {
        std.debug.print("Unknown auth command: {s}\n\n", .{subcmd});
        printAuthUsage();
        std.process.exit(1);
    }
}

fn printManualWeixinConfig(token: []const u8, base_url: []const u8) void {
    std.debug.print("\nAdd the following to the channels section of your nullclaw config:\n\n", .{});
    std.debug.print("  \"weixin\": [{{\n", .{});
    std.debug.print("    \"token\": \"{s}\",\n", .{token});
    if (!std.mem.eql(u8, base_url, "https://ilinkai.weixin.qq.com/")) {
        std.debug.print("    \"base_url\": \"{s}\",\n", .{base_url});
    }
    std.debug.print("    \"allow_from\": []\n", .{});
    std.debug.print("  }}]\n", .{});
}

fn runAuthDeviceCodeLogin(
    allocator: std.mem.Allocator,
    codex: type,
    auth_mod: type,
) void {
    std.debug.print("Starting OpenAI Codex authentication...\n\n", .{});

    const dc = auth_mod.startDeviceCodeFlow(
        allocator,
        codex.OAUTH_CLIENT_ID,
        codex.OAUTH_DEVICE_URL,
        codex.OAUTH_SCOPE,
    ) catch {
        std.debug.print("Failed to start device code flow (likely Cloudflare block).\n", .{});
        std.debug.print("Alternative:\n", .{});
        std.debug.print("  nullclaw auth login openai-codex --import-codex   (import from Codex CLI)\n", .{});
        std_compat.process.exit(1);
    };
    defer dc.deinit(allocator);

    std.debug.print("Open this URL in your browser:\n", .{});
    std.debug.print("  {s}\n\n", .{dc.verification_uri});
    std.debug.print("Enter code: {s}\n\n", .{dc.user_code});
    std.debug.print("Waiting for authorization...\n", .{});

    const token = auth_mod.pollDeviceCode(
        allocator,
        codex.OAUTH_TOKEN_URL,
        codex.OAUTH_CLIENT_ID,
        dc.device_code,
        dc.interval,
    ) catch |err| {
        switch (err) {
            error.DeviceCodeDenied => std.debug.print("Authorization denied.\n", .{}),
            error.DeviceCodeTimeout => std.debug.print("Authorization timed out.\n", .{}),
            else => std.debug.print("Authorization failed: {}\n", .{err}),
        }
        std_compat.process.exit(1);
    };
    defer token.deinit(allocator);

    saveAndPrintResult(allocator, codex, auth_mod, token);
}

fn runAuthImportCodex(
    allocator: std.mem.Allocator,
    codex: type,
    auth_mod: type,
) void {
    const home = yc.platform.getHomeDir(allocator) catch {
        std.debug.print("HOME not set.\n", .{});
        std_compat.process.exit(1);
    };
    defer allocator.free(home);

    const path = std_compat.fs.path.join(allocator, &.{ home, ".codex", "auth.json" }) catch {
        std.debug.print("Out of memory.\n", .{});
        std_compat.process.exit(1);
    };
    defer allocator.free(path);

    const file = std_compat.fs.openFileAbsolute(path, .{}) catch {
        std.debug.print("Could not open {s}\n", .{path});
        std.debug.print("Install and authenticate with Codex CLI first.\n", .{});
        std_compat.process.exit(1);
    };
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch {
        std.debug.print("Failed to read {s}\n", .{path});
        std_compat.process.exit(1);
    };
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch {
        std.debug.print("Failed to parse {s}\n", .{path});
        std_compat.process.exit(1);
    };
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => {
            std.debug.print("Invalid format in {s}\n", .{path});
            std_compat.process.exit(1);
        },
    };

    // Extract tokens object
    const tokens_val = root_obj.get("tokens") orelse {
        std.debug.print("No \"tokens\" field in {s}\n", .{path});
        std_compat.process.exit(1);
    };
    const tokens_obj = switch (tokens_val) {
        .object => |o| o,
        else => {
            std.debug.print("Invalid \"tokens\" field in {s}\n", .{path});
            std_compat.process.exit(1);
        },
    };

    const access_token_str = switch (tokens_obj.get("access_token") orelse {
        std.debug.print("No access_token in Codex CLI credentials.\n", .{});
        std_compat.process.exit(1);
    }) {
        .string => |s| s,
        else => {
            std.debug.print("Invalid access_token in Codex CLI credentials.\n", .{});
            std_compat.process.exit(1);
        },
    };

    if (access_token_str.len == 0) {
        std.debug.print("Empty access_token in Codex CLI credentials.\n", .{});
        std_compat.process.exit(1);
    }

    const refresh_token_str: ?[]const u8 = if (tokens_obj.get("refresh_token")) |rt_val| switch (rt_val) {
        .string => |s| if (s.len > 0) s else null,
        else => null,
    } else null;

    // Decode JWT exp from access_token
    const expires_at = decodeJwtExp(allocator, access_token_str);

    const token = auth_mod.OAuthToken{
        .access_token = access_token_str,
        .refresh_token = refresh_token_str,
        .expires_at = expires_at,
        .token_type = "Bearer",
    };

    auth_mod.saveCredential(allocator, codex.CREDENTIAL_KEY, token) catch {
        std.debug.print("Failed to save credential.\n", .{});
        std_compat.process.exit(1);
    };

    const account_id = codex.extractAccountIdFromJwt(allocator, access_token_str) catch null;
    defer if (account_id) |id| allocator.free(id);

    std.debug.print("Imported from Codex CLI ({s})\n", .{path});
    if (account_id) |id| {
        std.debug.print("  Account: {s}\n", .{id});
    }
    std.debug.print("  Access token: {d} bytes\n", .{access_token_str.len});
    if (refresh_token_str != null) {
        std.debug.print("  Refresh token: present\n", .{});
    } else {
        std.debug.print("  Refresh token: absent\n", .{});
    }
    if (expires_at != 0) {
        const remaining = expires_at - std_compat.time.timestamp();
        if (remaining > 0) {
            std.debug.print("  Expires in: {d}h {d}m\n", .{
                @divTrunc(remaining, 3600),
                @divTrunc(@mod(remaining, 3600), 60),
            });
        } else {
            std.debug.print("  Token: expired (will auto-refresh)\n", .{});
        }
    }
    std.debug.print("\nTo use: set \"agents.defaults.model.primary\": \"openai-codex/{s}\" in config.json in your nullclaw config directory\n", .{yc.codex_support.DEFAULT_CODEX_MODEL});
}

/// Decode the "exp" claim from a JWT, returning the Unix timestamp or 0 if not decodable.
fn decodeJwtExp(allocator: std.mem.Allocator, token: []const u8) i64 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return 0;
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return 0;
    const payload_b64 = rest[0..second_dot];
    if (payload_b64.len == 0) return 0;

    const Decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(payload_b64) catch return 0;
    const decoded = allocator.alloc(u8, decoded_len) catch return 0;
    defer allocator.free(decoded);
    Decoder.decode(decoded, payload_b64) catch return 0;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded, .{}) catch return 0;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return 0,
    };

    if (obj.get("exp")) |exp_val| {
        switch (exp_val) {
            .integer => |i| return i,
            .float => |f| return @intFromFloat(f),
            else => {},
        }
    }
    return 0;
}

fn saveAndPrintResult(
    allocator: std.mem.Allocator,
    codex: type,
    auth_mod: type,
    token: auth_mod.OAuthToken,
) void {
    auth_mod.saveCredential(allocator, codex.CREDENTIAL_KEY, token) catch {
        std.debug.print("Failed to save credential.\n", .{});
        std_compat.process.exit(1);
    };

    const account_id = codex.extractAccountIdFromJwt(allocator, token.access_token) catch null;
    defer if (account_id) |id| allocator.free(id);

    if (account_id) |id| {
        std.debug.print("Authenticated (account: {s})\n", .{id});
    } else {
        std.debug.print("Authenticated successfully.\n", .{});
    }
    std.debug.print("\nTo use: set \"agents.defaults.model.primary\": \"openai-codex/{s}\" in config.json in your nullclaw config directory\n", .{yc.codex_support.DEFAULT_CODEX_MODEL});
}

fn printUsage() void {
    std.debug.print("{s}", .{TOP_LEVEL_USAGE});
}

test "parse known commands" {
    try std.testing.expectEqual(.agent, parseCommand("agent").?);
    try std.testing.expectEqual(.config, parseCommand("config").?);
    try std.testing.expectEqual(.status, parseCommand("status").?);
    try std.testing.expectEqual(.version, parseCommand("version").?);
    try std.testing.expectEqual(.version, parseCommand("--version").?);
    try std.testing.expectEqual(.version, parseCommand("-V").?);
    try std.testing.expectEqual(.service, parseCommand("service").?);
    try std.testing.expectEqual(.migrate, parseCommand("migrate").?);
    try std.testing.expectEqual(.memory, parseCommand("memory").?);
    try std.testing.expectEqual(.history, parseCommand("history").?);
    try std.testing.expectEqual(.workspace, parseCommand("workspace").?);
    try std.testing.expectEqual(.capabilities, parseCommand("capabilities").?);
    try std.testing.expectEqual(.models, parseCommand("models").?);
    try std.testing.expectEqual(.auth, parseCommand("auth").?);
    try std.testing.expectEqual(.update, parseCommand("update").?);
    try std.testing.expect(parseCommand("daemon") == null);
    try std.testing.expect(parseCommand("unknown") == null);
}

test "top level usage stays aligned with current subcommand synopses" {
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "service <" ++ SERVICE_SUBCOMMANDS ++ ">"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "config <" ++ CONFIG_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "cron <" ++ CRON_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "channel <" ++ CHANNEL_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "skills <" ++ SKILLS_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "hardware <" ++ HARDWARE_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "memory <" ++ MEMORY_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "history <" ++ HISTORY_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "workspace <" ++ WORKSPACE_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "models <" ++ MODELS_SUBCOMMANDS ++ "> [ARGS]"));
    try std.testing.expect(std.mem.containsAtLeast(u8, TOP_LEVEL_USAGE, 1, "auth <" ++ AUTH_SUBCOMMANDS ++ "> <provider> [--import-codex]"));
}

test "allocDefaultModelRef reconstructs provider-prefixed model ref" {
    const allocator = std.testing.allocator;
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = allocator,
        .default_provider = "custom:https://gateway.example.com/api",
        .default_model = "qianfan/custom-model",
    };

    const value = (try allocDefaultModelRef(allocator, &cfg)).?;
    defer allocator.free(value);

    try std.testing.expectEqualStrings("custom:https://gateway.example.com/api/qianfan/custom-model", value);
}

test "buildModelsSummaryJson emits sorted provider summaries without key contents" {
    const allocator = std.testing.allocator;
    const providers = [_]yc.config.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-test" },
        .{ .name = "ollama", .api_key = null },
    };
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = allocator,
        .default_provider = "openrouter",
        .default_model = "anthropic/claude-sonnet-4.6",
        .providers = &providers,
    };

    const json = try buildModelsSummaryJson(allocator, &cfg);
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"default_provider\":\"openrouter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"default_model\":\"openrouter/anthropic/claude-sonnet-4.6\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"ollama\",\"has_key\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"openrouter\",\"has_key\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "sk-test") == null);
}

test "resolveWorkspaceAuditTriageApiKey uses configured provider key" {
    const allocator = std.testing.allocator;
    const providers_cfg = [_]yc.config.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-test" },
    };
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = allocator,
        .providers = &providers_cfg,
    };

    const key = (try resolveWorkspaceAuditTriageApiKey(allocator, &cfg, "openrouter")).?;
    defer allocator.free(key);
    try std.testing.expectEqualStrings("sk-test", key);
}

test "resolveWorkspaceAuditTriageApiKey allows keyless local provider" {
    const allocator = std.testing.allocator;
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = allocator,
    };

    const key = try resolveWorkspaceAuditTriageApiKey(allocator, &cfg, "ollama");
    try std.testing.expect(key == null);
}

test "workspace audit triage provider holder uses full provider config" {
    const allocator = std.testing.allocator;
    const providers_cfg = [_]yc.config.ProviderEntry{.{
        .name = "custom-local",
        .base_url = "http://localhost:4321/v1",
        .native_tools = false,
        .user_agent = "nullclaw-test",
        .api_mode = .responses,
        .chat_template_enable_thinking_param = true,
        .max_streaming_prompt_bytes = 123,
        .extra_body_params = "{\"seed\":1}",
    }};
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = allocator,
        .providers = &providers_cfg,
    };

    var holder = workspaceAuditTriageProviderHolder(allocator, &cfg, "custom-local", null);
    defer holder.deinit();

    switch (holder) {
        .compatible => |*provider| {
            try std.testing.expectEqualStrings("http://localhost:4321/v1", provider.base_url);
            try std.testing.expect(!provider.native_tools);
            try std.testing.expectEqualStrings("nullclaw-test", provider.user_agent.?);
            try std.testing.expectEqual(yc.providers.compatible.CompatibleApiMode.responses, provider.api_mode);
            try std.testing.expect(provider.chat_template_enable_thinking_param);
            try std.testing.expectEqual(@as(?usize, 123), provider.max_streaming_prompt_bytes);
            try std.testing.expectEqualStrings("{\"seed\":1}", provider.extra_body_params.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "workspace audit triage config selects provider model and budget before defaults" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = std.testing.allocator,
        .default_provider = "openrouter",
        .default_model = "anthropic/claude-sonnet-4.6",
        .workspace_audit = .{
            .llm_triage = .{
                .provider = "ollama",
                .model = "qwen2.5-coder:7b",
                .max_calls = 12,
            },
        },
    };

    try std.testing.expectEqualStrings("ollama", workspaceAuditTriageProviderName(null, &cfg));
    try std.testing.expectEqualStrings("qwen2.5-coder:7b", workspaceAuditTriageModelName(null, &cfg).?);
    try std.testing.expectEqual(@as(usize, 12), workspaceAuditTriageMaxLlmCalls(&cfg));
    try std.testing.expectEqualStrings("openai", workspaceAuditTriageProviderName("openai", &cfg));
    try std.testing.expectEqualStrings("gpt-5.4", workspaceAuditTriageModelName("gpt-5.4", &cfg).?);
}

test "workspace audit triage rejects unknown provider without explicit base url" {
    const providers_cfg = [_]yc.config.ProviderEntry{
        .{
            .name = "custom-compat",
            .base_url = "https://llm.example.com/v1",
        },
        .{
            .name = "bad-compat",
            .base_url = "http://api.example.com/v1",
        },
    };
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = std.testing.allocator,
        .providers = &providers_cfg,
    };

    try std.testing.expect(workspaceAuditTriageProviderIsAllowed(&cfg, "ollama"));
    try std.testing.expect(workspaceAuditTriageProviderIsAllowed(&cfg, "custom-compat"));
    try std.testing.expect(!workspaceAuditTriageProviderIsAllowed(&cfg, "olama"));
    try std.testing.expect(!workspaceAuditTriageProviderIsAllowed(&cfg, "bad-compat"));
}

test "workspace audit log path follows config directory" {
    const allocator = std.testing.allocator;
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-home/config.json",
        .allocator = allocator,
    };

    const path = try defaultWorkspaceAuditLogPath(allocator, &cfg);
    defer allocator.free(path);
    const expected = try std_compat.fs.path.join(allocator, &.{ "/tmp/nullclaw-home", "audit-log.jsonl" });
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, path);
}

test "configureWindowsConsoleUtf8 is safe to call" {
    configureWindowsConsoleUtf8();
    try std.testing.expect(true);
}

test "parsePositiveUsize accepts only positive integers" {
    try std.testing.expectEqual(@as(?usize, 1), parsePositiveUsize("1"));
    try std.testing.expectEqual(@as(?usize, 42), parsePositiveUsize("42"));
    try std.testing.expect(parsePositiveUsize("0") == null);
    try std.testing.expect(parsePositiveUsize("-1") == null);
    try std.testing.expect(parsePositiveUsize("bad") == null);
}

test "parseNonNegativeUsize accepts zero and positive integers" {
    try std.testing.expectEqual(@as(?usize, 0), parseNonNegativeUsize("0"));
    try std.testing.expectEqual(@as(?usize, 1), parseNonNegativeUsize("1"));
    try std.testing.expectEqual(@as(?usize, 42), parseNonNegativeUsize("42"));
    try std.testing.expect(parseNonNegativeUsize("-1") == null);
    try std.testing.expect(parseNonNegativeUsize("bad") == null);
}

test "buildHistoryMemoryConfig disables side-effectful runtime features" {
    var cfg = yc.config.config_types.MemoryConfig{};
    cfg.search.enabled = true;
    cfg.qmd.enabled = true;
    cfg.lifecycle.hygiene_enabled = true;
    cfg.lifecycle.snapshot_on_hygiene = true;
    cfg.lifecycle.auto_hydrate = true;
    cfg.response_cache.enabled = true;

    const history_cfg = buildHistoryMemoryConfig(cfg);
    try std.testing.expect(!history_cfg.search.enabled);
    try std.testing.expect(!history_cfg.qmd.enabled);
    try std.testing.expect(!history_cfg.lifecycle.hygiene_enabled);
    try std.testing.expect(!history_cfg.lifecycle.snapshot_on_hygiene);
    try std.testing.expect(!history_cfg.lifecycle.auto_hydrate);
    try std.testing.expect(!history_cfg.response_cache.enabled);
}

test "hasJsonFlag detects --json" {
    const with_json = [_][]const u8{ "--limit", "10", "--json" };
    try std.testing.expect(hasJsonFlag(&with_json));

    const without_json = [_][]const u8{ "--limit", "10" };
    try std.testing.expect(!hasJsonFlag(&without_json));
}

test "agentHelpRequested detects standalone help flag" {
    const args = [_][]const u8{ "--provider", "openrouter", "--help" };
    try std.testing.expect(agentHelpRequested(&args));
}

test "agentHelpRequested ignores message value that matches help flag" {
    const args = [_][]const u8{ "--message", "--help" };
    try std.testing.expect(!agentHelpRequested(&args));
}

test "agentHelpRequested ignores session value that matches short help flag" {
    const args = [_][]const u8{ "--session", "-h" };
    try std.testing.expect(!agentHelpRequested(&args));
}

test "agentHelpRequested ignores workspace value that matches help flag" {
    const args = [_][]const u8{ "--workspace", "--help" };
    try std.testing.expect(!agentHelpRequested(&args));
}

test "agentHelpRequested ignores agent value that matches help flag" {
    const args = [_][]const u8{ "--agent", "--help" };
    try std.testing.expect(!agentHelpRequested(&args));
}

test "agentHelpRequested ignores skill value that matches help flag" {
    const args = [_][]const u8{ "--skill", "-h" };
    try std.testing.expect(!agentHelpRequested(&args));
}

test "appendAgentInvokeForwardArgs forwards skill option" {
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);

    try appendAgentInvokeForwardArgs(std.testing.allocator, &argv, "hello", "api:default", .{
        .skill_name = "news-digest",
    });

    const expected = [_][]const u8{ "agent", "-m", "hello", "-s", "api:default", "--skill", "news-digest" };
    try std.testing.expectEqual(expected.len, argv.items.len);
    for (expected, argv.items) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "appendAgentInvokeForwardArgs forwards workspace option" {
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);

    try appendAgentInvokeForwardArgs(std.testing.allocator, &argv, "hello", "api:default", .{
        .workspace = "/tmp/acp-workspace",
    });

    const expected = [_][]const u8{ "agent", "-m", "hello", "-s", "api:default", "--workspace", "/tmp/acp-workspace" };
    try std.testing.expectEqual(expected.len, argv.items.len);
    for (expected, argv.items) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "applyHistoryWorkspaceOverride uses ACP workspace for history reads" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-default",
        .config_path = "/tmp/nullclaw-default/config.json",
        .allocator = std.testing.allocator,
    };

    applyHistoryWorkspaceOverride(&cfg, "/tmp/nullclaw-acp");
    try std.testing.expectEqualStrings("/tmp/nullclaw-acp", cfg.workspace_dir);
}

test "gatewayHelpRequested detects standalone help flag" {
    const args = [_][]const u8{ "--port", "8080", "--help" };
    try std.testing.expect(gatewayHelpRequested(&args));
}

test "gatewayHelpRequested ignores host value that matches help flag" {
    const args = [_][]const u8{ "--host", "--help" };
    try std.testing.expect(!gatewayHelpRequested(&args));
}

test "writeJsonString wraps and escapes special characters" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try writeJsonString(&aw.writer, "line \"one\"\nline two\\");
    const written = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expectEqualStrings("\"line \\\"one\\\"\\nline two\\\\\"", written);
}

test "skillSource distinguishes workspace and community skills" {
    const workspace_dir = "/tmp/ws";
    const community_base = "/tmp/home/.nullclaw/skills";

    const workspace_skill = yc.skills.Skill{
        .name = "local",
        .version = "1.0.0",
        .path = "/tmp/ws/skills/local",
        .instructions = "",
    };
    try std.testing.expectEqualStrings("workspace", skillSource(workspace_dir, community_base, workspace_skill));

    const community_skill = yc.skills.Skill{
        .name = "shared",
        .version = "1.0.0",
        .path = "/tmp/home/.nullclaw/skills/shared",
        .instructions = "",
    };
    try std.testing.expectEqualStrings("community", skillSource(workspace_dir, community_base, community_skill));
}

test "parseOnboardArgs parses quick setup flags" {
    const args = [_][]const u8{ "--api-key", "sk-test", "--provider", "openrouter", "--memory", "markdown" };
    switch (parseOnboardArgs(&args)) {
        .ok => |parsed| {
            try std.testing.expectEqual(OnboardMode.quick, parsed.mode);
            try std.testing.expectEqualStrings("sk-test", parsed.api_key.?);
            try std.testing.expectEqualStrings("openrouter", parsed.provider.?);
            try std.testing.expectEqualStrings("markdown", parsed.memory_backend.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseOnboardArgs parses interactive mode" {
    const args = [_][]const u8{"--interactive"};
    switch (parseOnboardArgs(&args)) {
        .ok => |parsed| {
            try std.testing.expectEqual(OnboardMode.interactive, parsed.mode);
            try std.testing.expect(parsed.api_key == null);
            try std.testing.expect(parsed.provider == null);
            try std.testing.expect(parsed.memory_backend == null);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseOnboardArgs reports unknown option" {
    const args = [_][]const u8{"--not-real"};
    switch (parseOnboardArgs(&args)) {
        .unknown_option => |opt| try std.testing.expectEqualStrings("--not-real", opt),
        else => return error.TestUnexpectedResult,
    }
}

test "parseOnboardArgs reports missing option value" {
    const args = [_][]const u8{"--provider"};
    switch (parseOnboardArgs(&args)) {
        .missing_value => |opt| try std.testing.expectEqualStrings("--provider", opt),
        else => return error.TestUnexpectedResult,
    }
}

test "parseOnboardArgs rejects mixed interactive and quick flags" {
    const args = [_][]const u8{ "--interactive", "--provider", "openrouter" };
    switch (parseOnboardArgs(&args)) {
        .invalid_combination => {},
        else => return error.TestUnexpectedResult,
    }
}

test "parseOnboardArgs rejects positional arguments" {
    const args = [_][]const u8{"extra"};
    switch (parseOnboardArgs(&args)) {
        .unexpected_argument => |arg| try std.testing.expectEqualStrings("extra", arg),
        else => return error.TestUnexpectedResult,
    }
}

test "applyGatewayDaemonOverrides applies CLI port before validation" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
    };
    cfg.gateway.port = 0;

    const args = [_][]const u8{ "--port", "8080" };
    try applyGatewayDaemonOverrides(&cfg, &args);

    try std.testing.expectEqual(@as(u16, 8080), cfg.gateway.port);
    try cfg.validate();
}

test "applyGatewayDaemonOverrides applies host override" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
    };
    const args = [_][]const u8{ "--host", "0.0.0.0" };
    try applyGatewayDaemonOverrides(&cfg, &args);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.gateway.host);
}

test "applyGatewayDaemonOverrides rejects invalid port" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
    };
    const args = [_][]const u8{ "--port", "bad" };
    try std.testing.expectError(error.InvalidPort, applyGatewayDaemonOverrides(&cfg, &args));
}

test "applyGatewayDaemonOverrides applies workspace override" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
    };
    const args = [_][]const u8{ "--workspace", "/custom/workspace" };
    try applyGatewayDaemonOverrides(&cfg, &args);
    try std.testing.expectEqualStrings("/custom/workspace", cfg.workspace_dir);
}

test "gatewayHelpRequested skips workspace value" {
    // --help here is the value of --workspace, not a real flag — should not trigger help
    const args = [_][]const u8{ "--workspace", "--help" };
    try std.testing.expect(!gatewayHelpRequested(&args));
}

test "hasConfiguredStartableChannels ignores cli and webhook-only defaults" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
        .channels = .{
            .cli = true,
            .webhook = .{ .port = 8080 },
        },
    };

    try std.testing.expect(!hasConfiguredStartableChannels(&cfg));
}

test "hasConfiguredStartableChannels returns true when telegram configured" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
        .channels = .{
            .telegram = &[_]yc.config.TelegramConfig{
                .{ .account_id = "main", .bot_token = "123:abc" },
            },
        },
    };

    if (!yc.channel_catalog.isBuildEnabled(.telegram)) return error.SkipZigTest;
    try std.testing.expect(hasConfiguredStartableChannels(&cfg));
}

test "resolveConfiguredRuntimeChannel matches external plugin name" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
        .channels = .{
            .external = &[_]yc.config.ExternalChannelConfig{
                .{
                    .account_id = "main",
                    .runtime_name = "whatsapp_web",
                    .transport = .{
                        .command = "nullclaw-plugin-whatsapp-web",
                    },
                },
            },
        },
    };

    const resolved = resolveConfiguredRuntimeChannel(&cfg, "whatsapp_web") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("external", resolved.adapter_key);
    try std.testing.expectEqualStrings("whatsapp_web", resolved.start_name);
}

test "resolveConfiguredRuntimeChannel matches custom maixcam name" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
        .channels = .{
            .maixcam = &[_]yc.config.MaixCamConfig{
                .{
                    .account_id = "cam-main",
                    .name = "vision-lab",
                },
            },
        },
    };

    const resolved = resolveConfiguredRuntimeChannel(&cfg, "vision-lab") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("maixcam", resolved.adapter_key);
    try std.testing.expectEqualStrings("vision-lab", resolved.start_name);
}

test "hasConfiguredButBuildDisabledStartableChannels detects configured disabled channel" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_model = "openrouter/auto",
        .allocator = std.testing.allocator,
        .channels = .{
            .telegram = &[_]yc.config.TelegramConfig{
                .{ .account_id = "main", .bot_token = "123:abc" },
            },
        },
    };

    try std.testing.expectEqual(!yc.channel_catalog.isBuildEnabled(.telegram), hasConfiguredButBuildDisabledStartableChannels(&cfg));
}

test "hasStartupProviderCredentials accepts configured primary key" {
    const providers_cfg = [_]yc.config.ProviderEntry{
        .{ .name = "anthropic", .api_key = "sk-test" },
    };
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "anthropic",
        .default_model = "anthropic/claude-3-7-sonnet",
        .allocator = std.testing.allocator,
        .providers = &providers_cfg,
    };

    try std.testing.expect(yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "hasStartupProviderCredentials accepts local compatible provider without api key" {
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "custom:http://127.0.0.1:8080/v1",
        .default_model = "custom/local-model",
        .allocator = std.testing.allocator,
    };

    try std.testing.expect(yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "hasStartupProviderCredentials accepts gemini oauth env token" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    const env_name = try std.testing.allocator.dupeZ(u8, "GEMINI_OAUTH_TOKEN");
    defer std.testing.allocator.free(env_name);
    const env_value = try std.testing.allocator.dupeZ(u8, "ya29.test-oauth-token");
    defer std.testing.allocator.free(env_value);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(env_name.ptr, env_value.ptr, 1));
    defer _ = c.unsetenv(env_name.ptr);

    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "gemini",
        .default_model = "gemini/gemini-2.5-pro",
        .allocator = std.testing.allocator,
    };

    try std.testing.expect(yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "hasStartupProviderCredentials accepts reliability fallback credentials" {
    var cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "anthropic",
        .default_model = "anthropic/claude-3-7-sonnet",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.api_keys = &.{"rotating-key"};

    try std.testing.expect(yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "hasStartupProviderCredentials rejects blank configured key" {
    // Regression: blank API keys must not bypass channel startup credential checks.
    const providers_cfg = [_]yc.config.ProviderEntry{
        .{ .name = "anthropic", .api_key = "   " },
    };
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "anthropic",
        .default_model = "anthropic/claude-3-7-sonnet",
        .allocator = std.testing.allocator,
        .providers = &providers_cfg,
    };

    try std.testing.expect(!yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "hasStartupProviderCredentials rejects missing provider and fallback credentials" {
    // Regression: channel startup must still fail fast when neither the primary provider nor fallbacks can authenticate.
    const cfg = yc.config.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "anthropic",
        .default_model = "anthropic/claude-3-7-sonnet",
        .allocator = std.testing.allocator,
    };

    try std.testing.expect(!yc.channel_loop.hasStartupProviderCredentials(std.testing.allocator, &cfg));
}

test "parseCronAddAgentOptions preserves delivery account flag" {
    // Regression: cron add-agent ignored --account and dropped delivery account routing.
    const args = [_][]const u8{
        "add-agent",
        "0 7 * * 1,2,4",
        "Check traffic",
        "--model",
        "glm-cn/glm-5-turbo",
        "--session-target",
        "main",
        "--announce",
        "--channel",
        "telegram",
        "--account",
        "main",
        "--to",
        "chat-42",
    };

    const options = try parseCronAddAgentOptions(&args);
    try std.testing.expectEqualStrings("glm-cn/glm-5-turbo", options.model.?);
    try std.testing.expectEqual(yc.cron.SessionTarget.main, options.session_target);
    try std.testing.expectEqual(yc.cron.DeliveryMode.always, options.delivery.mode);
    try std.testing.expectEqualStrings("telegram", options.delivery.channel.?);
    try std.testing.expectEqualStrings("main", options.delivery.account_id.?);
    try std.testing.expectEqualStrings("chat-42", options.delivery.to.?);
    try std.testing.expect(!options.delivery.channel_owned);
    try std.testing.expect(!options.delivery.account_id_owned);
    try std.testing.expect(!options.delivery.to_owned);
}

test "parseCronAgentOptions rejects missing option values" {
    // Regression: malformed cron agent flags must fail fast instead of being ignored.
    const flags = [_][]const u8{ "--model", "--session-target", "--channel", "--account", "--to" };
    for (flags) |flag| {
        const args = [_][]const u8{ "once-agent", "30s", "Summarize status", flag };
        try std.testing.expectError(error.MissingCronOptionValue, parseCronAgentOptions(&args, 3));

        const followed_by_flag = [_][]const u8{ "once-agent", "30s", "Summarize status", flag, "--announce" };
        try std.testing.expectError(error.MissingCronOptionValue, parseCronAgentOptions(&followed_by_flag, 3));
    }
}

test "parseCronAgentOptions rejects unknown options" {
    // Regression: cron agent CLI typos must not be silently ignored.
    const args = [_][]const u8{ "once-agent", "30s", "Summarize status", "--unknown" };
    try std.testing.expectError(error.UnknownCronOption, parseCronAgentOptions(&args, 3));
}

test "appendAgentInvokeResponseJson renders machine-readable turn payload" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendAgentInvokeResponseJson(&writer, "api:default", "hello", 3);
    try std.testing.expectEqualStrings(
        "{\"session\":\"api:default\",\"response\":\"hello\",\"turn_count\":3}",
        writer.buffered(),
    );
}

test "appendAgentSessionListJson renders persisted session metadata" {
    const sessions = [_]yc.memory.SessionInfo{
        .{
            .session_id = "s-1",
            .message_count = 4,
            .first_message_at = "2026-04-17T00:00:00Z",
            .last_message_at = "2026-04-17T00:05:00Z",
        },
        .{
            .session_id = "s-2",
            .message_count = 2,
            .first_message_at = "2026-04-17T00:10:00Z",
            .last_message_at = "2026-04-17T00:11:00Z",
        },
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendAgentSessionListJson(&writer, &sessions, 2);
    try std.testing.expectEqualStrings(
        "{\"sessions\":[{\"session_key\":\"s-1\",\"created_at\":\"2026-04-17T00:00:00Z\",\"last_active\":\"2026-04-17T00:05:00Z\",\"turn_count\":2,\"turn_running\":false},{\"session_key\":\"s-2\",\"created_at\":\"2026-04-17T00:10:00Z\",\"last_active\":\"2026-04-17T00:11:00Z\",\"turn_count\":1,\"turn_running\":false}],\"total\":2}",
        writer.buffered(),
    );
}

test "appendAgentSessionDetailJson renders one persisted session" {
    const session: yc.memory.SessionInfo = .{
        .session_id = "s-1",
        .message_count = 6,
        .first_message_at = "2026-04-17T00:00:00Z",
        .last_message_at = "2026-04-17T00:12:00Z",
    };
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendAgentSessionDetailJson(&writer, session);
    try std.testing.expectEqualStrings(
        "{\"session_key\":\"s-1\",\"created_at\":\"2026-04-17T00:00:00Z\",\"last_active\":\"2026-04-17T00:12:00Z\",\"turn_count\":3,\"turn_running\":false}",
        writer.buffered(),
    );
}

test "appendHistoryListJson renders paginated session history metadata" {
    const sessions = [_]yc.memory.SessionInfo{
        .{
            .session_id = "s-1",
            .message_count = 3,
            .first_message_at = "2026-04-17T00:00:00Z",
            .last_message_at = "2026-04-17T00:03:00Z",
        },
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendHistoryListJson(&writer, &sessions, 9, 50, 0);
    try std.testing.expectEqualStrings(
        "{\"total\":9,\"limit\":50,\"offset\":0,\"sessions\":[{\"session_id\":\"s-1\",\"message_count\":3,\"first_message_at\":\"2026-04-17T00:00:00Z\",\"last_message_at\":\"2026-04-17T00:03:00Z\"}]}",
        writer.buffered(),
    );
}

test "appendHistoryShowJson renders paginated message history" {
    const messages = [_]yc.memory.DetailedMessageEntry{
        .{
            .role = "user",
            .content = "hi",
            .created_at = "2026-04-17T00:00:00Z",
        },
        .{
            .role = "assistant",
            .content = "hello",
            .created_at = "2026-04-17T00:00:01Z",
        },
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendHistoryShowJson(&writer, "s-1", &messages, 2, 100, 0);
    try std.testing.expectEqualStrings(
        "{\"session_id\":\"s-1\",\"total\":2,\"limit\":100,\"offset\":0,\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"created_at\":\"2026-04-17T00:00:00Z\"},{\"role\":\"assistant\",\"content\":\"hello\",\"created_at\":\"2026-04-17T00:00:01Z\"}]}",
        writer.buffered(),
    );
}

test "admin output renders large history payloads without truncation" {
    const allocator = std.testing.allocator;
    const large_content = try allocator.alloc(u8, 80_000);
    defer allocator.free(large_content);
    @memset(large_content, 'x');

    const messages = [_]yc.memory.DetailedMessageEntry{
        .{
            .role = "assistant",
            .content = large_content,
            .created_at = "2026-04-17T00:00:01Z",
        },
    };

    const rendered = try yc.admin_output.renderBytes(allocator, appendHistoryShowJson, .{
        "s-large",
        &messages,
        @as(u64, 1),
        @as(usize, 100),
        @as(usize, 0),
    });
    defer allocator.free(rendered);

    try std.testing.expect(rendered.len > 80_000);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"session_id\":\"s-large\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"role\":\"assistant\"") != null);
}

test "appendConfigMutationJson renders persisted config mutation result" {
    const result: yc.config_mutator.MutationResult = .{
        .path = "gateway.port",
        .changed = true,
        .applied = true,
        .requires_restart = false,
        .old_value_json = "3000",
        .new_value_json = "43123",
        .backup_path = "/tmp/config.json.bak",
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendConfigMutationJson(&writer, .set, &result);
    try std.testing.expectEqualStrings(
        "{\"action\":\"set\",\"path\":\"gateway.port\",\"changed\":true,\"applied\":true,\"requires_restart\":false,\"old_value\":3000,\"new_value\":43123,\"backup_path\":\"/tmp/config.json.bak\"}",
        writer.buffered(),
    );
}

test "appendConfigValueResult renders dotted path lookup payload" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendConfigValueResult(&writer, "gateway.port", "43123");
    try std.testing.expectEqualStrings(
        "{\"path\":\"gateway.port\",\"value\":43123}",
        writer.buffered(),
    );
}

test "appendConfigReloadJson renders reload acknowledgment payload" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendConfigReloadJson(&writer);
    try std.testing.expectEqualStrings(
        "{\"reloaded\":true,\"live_applied\":false,\"message\":\"config.json re-read from disk; restart running daemons to apply changes\"}",
        writer.buffered(),
    );
}

test "appendValidationJson renders validation result payload" {
    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendValidationJson(&writer, true);
    try std.testing.expectEqualStrings("{\"valid\":true}", writer.buffered());
}

test "appendModelInfoJson canonicalizes provider-prefixed models" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendModelInfoJson(&writer, "openai/gpt-5");
    try std.testing.expectEqualStrings(
        "{\"name\":\"openai/gpt-5\",\"provider\":\"openai\",\"canonical_name\":\"openai/gpt-5\",\"context_window\":null}",
        writer.buffered(),
    );
}

test "appendCronJobJson renders full cron job detail payload" {
    const job: yc.cron.CronJob = .{
        .id = "job-1",
        .expression = "*/5 * * * *",
        .command = "echo hello",
        .next_run_secs = 123,
        .last_run_secs = 100,
        .last_status = "ok",
        .paused = false,
        .one_shot = false,
        .job_type = .agent,
        .session_target = .main,
        .prompt = "Check status",
        .name = "health-check",
        .model = "openai/gpt-5",
        .enabled = true,
        .delete_after_run = false,
        .created_at_s = 42,
        .last_output = "done",
    };
    var buf: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendCronJobJson(&writer, &job);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"job_type\":\"agent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"session_target\":\"main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"model\":\"openai/gpt-5\"") != null);
}

test "appendCronRunsJson renders paginated cron run history" {
    const runs = [_]yc.cron.CronRun{
        .{
            .id = 1,
            .job_id = "job-1",
            .started_at_s = 100,
            .finished_at_s = 101,
            .status = "ok",
            .output = "done",
            .duration_ms = 321,
        },
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendCronRunsJson(&writer, &runs);
    try std.testing.expectEqualStrings(
        "{\"runs\":[{\"id\":1,\"job_id\":\"job-1\",\"started_at_s\":100,\"finished_at_s\":101,\"status\":\"ok\",\"output\":\"done\",\"duration_ms\":321}],\"total\":1}",
        writer.buffered(),
    );
}

test "writeSkillJson renders public skill detail without leaking extra fields" {
    const skill: yc.skills.Skill = .{
        .name = "checks",
        .version = "1.0.0",
        .description = "Checks",
        .author = "nullclaw",
        .instructions = "Use checks",
        .always = true,
        .available = true,
        .path = "/tmp/workspace/skills/checks",
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try writeSkillJson(&writer, "/tmp/workspace", null, skill);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"name\":\"checks\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"source\":\"workspace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"instructions_bytes\":10") != null);
}

test "writeMemoryEntryJson renders nullable session ids" {
    const entry = yc.memory.MemoryEntry{
        .id = "entry-1",
        .key = "fact",
        .category = .conversation,
        .timestamp = "2026-04-17T00:00:00Z",
        .content = "hello",
        .session_id = null,
    };
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try writeMemoryEntryJson(&writer, entry);
    try std.testing.expectEqualStrings(
        "{\"key\":\"fact\",\"category\":\"conversation\",\"timestamp\":\"2026-04-17T00:00:00Z\",\"content\":\"hello\",\"session_id\":null}",
        writer.buffered(),
    );
}

test "writeMemoryExportEntryJson renders stable JSONL schema" {
    const entry = yc.memory.MemoryEntry{
        .id = "entry-1",
        .key = "fact",
        .category = .conversation,
        .timestamp = "2026-04-17T00:00:00Z",
        .content = "hello",
        .session_id = null,
    };
    var buf: [320]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try writeMemoryExportEntryJson(&writer, entry, entry.key, entry.content, entry.session_id);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"key\":\"fact\",\"category\":\"conversation\",\"timestamp\":\"2026-04-17T00:00:00Z\",\"session_id\":null,\"content\":\"hello\"}",
        writer.buffered(),
    );
}

test "loadMemoryListPage skips internal entries before applying visible offset" {
    const TestMemory = struct {
        fn makeEntry(allocator: std.mem.Allocator, key: []const u8, content: []const u8) !yc.memory.MemoryEntry {
            return .{
                .id = try allocator.dupe(u8, key),
                .key = try allocator.dupe(u8, key),
                .category = .core,
                .timestamp = try allocator.dupe(u8, "2026-04-17T00:00:00Z"),
                .content = try allocator.dupe(u8, content),
                .session_id = null,
            };
        }

        fn implName(_: *anyopaque) []const u8 {
            return "paged";
        }

        fn implStore(_: *anyopaque, _: []const u8, _: []const u8, _: yc.memory.MemoryCategory, _: ?[]const u8) anyerror!void {}

        fn implRecall(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize, _: ?[]const u8) anyerror![]yc.memory.MemoryEntry {
            return allocator.alloc(yc.memory.MemoryEntry, 0);
        }

        fn implGet(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!?yc.memory.MemoryEntry {
            return null;
        }

        fn implList(_: *anyopaque, allocator: std.mem.Allocator, _: ?yc.memory.MemoryCategory, _: ?[]const u8) anyerror![]yc.memory.MemoryEntry {
            return allocator.alloc(yc.memory.MemoryEntry, 0);
        }

        fn implListPaged(_: *anyopaque, allocator: std.mem.Allocator, _: ?yc.memory.MemoryCategory, _: ?[]const u8, limit: usize, offset: usize) anyerror![]yc.memory.MemoryEntry {
            const all = [_][2][]const u8{
                .{ "__bootstrap.prompt.AGENTS.md", "bootstrap" },
                .{ "visible-1", "first visible" },
                .{ "visible-2", "second visible" },
            };
            if (offset >= all.len) return allocator.alloc(yc.memory.MemoryEntry, 0);
            const end = @min(all.len, offset + limit);
            var entries = try allocator.alloc(yc.memory.MemoryEntry, end - offset);
            for (all[offset..end], 0..) |pair, idx| {
                entries[idx] = try makeEntry(allocator, pair[0], pair[1]);
            }
            return entries;
        }

        fn implForget(_: *anyopaque, _: []const u8) anyerror!bool {
            return false;
        }

        fn implCount(_: *anyopaque) anyerror!usize {
            return 3;
        }

        fn implHealthCheck(_: *anyopaque) bool {
            return true;
        }

        fn implDeinit(_: *anyopaque) void {}

        const vtable = yc.memory.Memory.VTable{
            .name = &implName,
            .store = &implStore,
            .recall = &implRecall,
            .get = &implGet,
            .list = &implList,
            .listPaged = &implListPaged,
            .forget = &implForget,
            .count = &implCount,
            .healthCheck = &implHealthCheck,
            .deinit = &implDeinit,
        };
    };

    const mem = yc.memory.Memory{ .ptr = undefined, .vtable = &TestMemory.vtable };
    const page = try loadMemoryListPage(std.testing.allocator, mem, null, null, 1, 1, false);
    defer yc.memory.freeEntries(std.testing.allocator, page);

    try std.testing.expectEqual(@as(usize, 1), page.len);
    try std.testing.expectEqualStrings("visible-2", page[0].key);
}

test "writeMemoryExportJsonlStream uses bounded pages" {
    const StreamMemory = struct {
        count: usize = 70,
        calls: usize = 0,
        max_limit_seen: usize = 0,

        fn makeEntry(allocator: std.mem.Allocator, idx: usize) !yc.memory.MemoryEntry {
            const key = try std.fmt.allocPrint(allocator, "visible-{d}", .{idx});
            errdefer allocator.free(key);
            const id = try allocator.dupe(u8, key);
            errdefer allocator.free(id);
            const content = try std.fmt.allocPrint(allocator, "content-{d}", .{idx});
            errdefer allocator.free(content);
            const timestamp = try allocator.dupe(u8, "2026-04-17T00:00:00Z");
            errdefer allocator.free(timestamp);
            return .{
                .id = id,
                .key = key,
                .category = .conversation,
                .timestamp = timestamp,
                .content = content,
                .session_id = null,
            };
        }

        fn implName(_: *anyopaque) []const u8 {
            return "stream-paged";
        }

        fn implStore(_: *anyopaque, _: []const u8, _: []const u8, _: yc.memory.MemoryCategory, _: ?[]const u8) anyerror!void {}

        fn implRecall(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize, _: ?[]const u8) anyerror![]yc.memory.MemoryEntry {
            return allocator.alloc(yc.memory.MemoryEntry, 0);
        }

        fn implGet(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!?yc.memory.MemoryEntry {
            return null;
        }

        fn implList(_: *anyopaque, allocator: std.mem.Allocator, _: ?yc.memory.MemoryCategory, _: ?[]const u8) anyerror![]yc.memory.MemoryEntry {
            return allocator.alloc(yc.memory.MemoryEntry, 0);
        }

        fn implListPaged(ptr: *anyopaque, allocator: std.mem.Allocator, _: ?yc.memory.MemoryCategory, _: ?[]const u8, limit: usize, offset: usize) anyerror![]yc.memory.MemoryEntry {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            self.max_limit_seen = @max(self.max_limit_seen, limit);

            if (offset >= self.count) return allocator.alloc(yc.memory.MemoryEntry, 0);
            const end = @min(self.count, offset + limit);
            var entries = try allocator.alloc(yc.memory.MemoryEntry, end - offset);
            var init_count: usize = 0;
            errdefer {
                for (entries[0..init_count]) |*entry| entry.deinit(allocator);
                allocator.free(entries);
            }
            for (entries, 0..) |*entry, idx| {
                entry.* = try makeEntry(allocator, offset + idx);
                init_count += 1;
            }
            return entries;
        }

        fn implForget(_: *anyopaque, _: []const u8) anyerror!bool {
            return false;
        }

        fn implCount(ptr: *anyopaque) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.count;
        }

        fn implHealthCheck(_: *anyopaque) bool {
            return true;
        }

        fn implDeinit(_: *anyopaque) void {}

        const vtable = yc.memory.Memory.VTable{
            .name = &implName,
            .store = &implStore,
            .recall = &implRecall,
            .get = &implGet,
            .list = &implList,
            .listPaged = &implListPaged,
            .forget = &implForget,
            .count = &implCount,
            .healthCheck = &implHealthCheck,
            .deinit = &implDeinit,
        };
    };

    var state = StreamMemory{};
    const mem = yc.memory.Memory{ .ptr = @ptrCast(&state), .vtable = &StreamMemory.vtable };

    var buf: [16_384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeMemoryExportJsonlStream(std.testing.allocator, &writer, mem, .{
        .limit = 70,
        .include_pii = true,
    });

    try std.testing.expect(state.calls >= 2);
    try std.testing.expect(state.max_limit_seen <= MEMORY_EXPORT_STREAM_CHUNK_SIZE);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\"key\":\"visible-69\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, writer.buffered(), "\n"));
}

test "buildMemoryExportJsonl redacts PII and excludes internal entries by default" {
    var impl_ = yc.memory.InMemoryLruMemory.init(std.testing.allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("profile", "Email user@example.com", .conversation, "s-1");
    try mem.store("__bootstrap.prompt.AGENTS.md", "Internal user@example.com", .core, null);

    const jsonl = try buildMemoryExportJsonl(std.testing.allocator, mem, .{
        .limit = 10,
    });
    defer std.testing.allocator.free(jsonl);

    // Regression: governed exports must not leak PII or bootstrap/autosave internals by default.
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "__bootstrap.prompt.AGENTS.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "\"content\":\"Email [EMAIL_1]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "\"session_id\":\"s-1\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, jsonl, "\n"));
}

test "buildMemoryExportJsonl include_pii returns raw content only when explicit" {
    var impl_ = yc.memory.InMemoryLruMemory.init(std.testing.allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("profile", "Email user@example.com", .conversation, "s-1");

    const jsonl = try buildMemoryExportJsonl(std.testing.allocator, mem, .{
        .limit = 10,
        .include_pii = true,
    });
    defer std.testing.allocator.free(jsonl);

    try std.testing.expect(std.mem.indexOf(u8, jsonl, "user@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "[EMAIL_1]") == null);
}

fn memoryExportAllocationTest(allocator: std.mem.Allocator) !void {
    var impl_ = yc.memory.InMemoryLruMemory.init(allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("profile", "Email user@example.com", .conversation, "s-1");
    try mem.store("profile-copy", "Email user@example.com", .conversation, "s-1");

    const jsonl = buildMemoryExportJsonl(allocator, mem, .{ .limit = 10 }) catch |err| switch (err) {
        // std.Io.Writer.Allocating wraps allocation failures as WriteFailed.
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer allocator.free(jsonl);
}

test "buildMemoryExportJsonl handles allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, memoryExportAllocationTest, .{});
}

test "buildMemoryExportJsonl can include internal entries when requested" {
    var impl_ = yc.memory.InMemoryLruMemory.init(std.testing.allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("__bootstrap.prompt.AGENTS.md", "Bootstrap prompt", .core, null);

    const jsonl = try buildMemoryExportJsonl(std.testing.allocator, mem, .{
        .limit = 10,
        .include_internal = true,
    });
    defer std.testing.allocator.free(jsonl);

    try std.testing.expect(std.mem.indexOf(u8, jsonl, "__bootstrap.prompt.AGENTS.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, jsonl, "\"content\":\"Bootstrap prompt\"") != null);
}

fn memoryHygieneAllocationTest(allocator: std.mem.Allocator) !void {
    var impl_ = yc.memory.InMemoryLruMemory.init(allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("exact-a", "duplicate fact", .conversation, "s-1");
    try mem.store("exact-b", "duplicate fact", .conversation, "s-1");
    try mem.store("near-a", "  Case   Folded Fact  ", .conversation, "s-1");
    try mem.store("near-b", "case folded fact", .conversation, "s-1");

    const report = try buildMemoryHygieneDryRunReport(allocator, mem, .{ .limit = 10 });
    _ = report;
}

test "buildMemoryHygieneDryRunReport handles allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, memoryHygieneAllocationTest, .{});
}

test "buildMemoryHygieneDryRunReport counts exact and normalized duplicates without mutation" {
    var impl_ = yc.memory.InMemoryLruMemory.init(std.testing.allocator, 100);
    defer impl_.deinit();
    const mem = impl_.memory();

    try mem.store("exact-a", "duplicate fact", .conversation, "s-1");
    try mem.store("exact-b", "duplicate fact", .conversation, "s-1");
    try mem.store("near-a", "  Case   Folded Fact  ", .conversation, "s-1");
    try mem.store("near-b", "case folded fact", .conversation, "s-1");
    try mem.store("__bootstrap.prompt.AGENTS.md", "duplicate fact", .core, null);

    const report = try buildMemoryHygieneDryRunReport(std.testing.allocator, mem, .{ .limit = 10 });

    // Regression: hygiene-report is dry-run and excludes internal memory by default.
    try std.testing.expectEqual(@as(usize, 4), report.scanned_entries);
    try std.testing.expectEqual(@as(usize, 1), report.exact_duplicates.groups);
    try std.testing.expectEqual(@as(usize, 1), report.exact_duplicates.extra_entries);
    try std.testing.expectEqual(@as(usize, 2), report.normalized_duplicates.groups);
    try std.testing.expectEqual(@as(usize, 2), report.normalized_duplicates.extra_entries);
    try std.testing.expectEqual(@as(usize, 5), try mem.count());
}

test "appendMemoryStatsJson renders runtime memory stats payload" {
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendMemoryStatsJson(&writer, .{
        .backend = "sqlite",
        .retrieval = "hybrid",
        .vector = "sqlite",
        .embedding = "disabled",
        .rollout = "primary",
        .sync = "inline",
        .sources = 1,
        .fallback = "none",
        .entries = 5,
        .vector_entries = 2,
        .outbox_pending = 0,
    });
    try std.testing.expectEqualStrings(
        "{\"backend\":\"sqlite\",\"retrieval\":\"hybrid\",\"vector\":\"sqlite\",\"embedding\":\"disabled\",\"rollout\":\"primary\",\"sync\":\"inline\",\"sources\":1,\"fallback\":\"none\",\"entries\":5,\"vector_entries\":2,\"outbox_pending\":0}",
        writer.buffered(),
    );
}

test "appendMemoryMaintenanceJson renders reindex and drain payloads" {
    var reindex_buf: [128]u8 = undefined;
    var reindex_writer: std.Io.Writer = .fixed(&reindex_buf);
    try appendMemoryMaintenanceJson(&reindex_writer, "reindexed", 3, true);
    try std.testing.expectEqualStrings("{\"reindexed\":3,\"skipped\":true}", reindex_writer.buffered());

    var drain_buf: [128]u8 = undefined;
    var drain_writer: std.Io.Writer = .fixed(&drain_buf);
    try appendMemoryMaintenanceJson(&drain_writer, "drained", 7, null);
    try std.testing.expectEqualStrings("{\"drained\":7}", drain_writer.buffered());
}

test "appendMemoryMutationJson renders store and update payloads" {
    const entry = yc.memory.MemoryEntry{
        .id = "entry-1",
        .key = "fact",
        .category = .conversation,
        .timestamp = "2026-04-17T00:00:00Z",
        .content = "hello",
        .session_id = "s-1",
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendMemoryMutationJson(&writer, "store", entry);
    try std.testing.expectEqualStrings(
        "{\"action\":\"store\",\"entry\":{\"key\":\"fact\",\"category\":\"conversation\",\"timestamp\":\"2026-04-17T00:00:00Z\",\"content\":\"hello\",\"session_id\":\"s-1\"}}",
        writer.buffered(),
    );
}

test "admin output renders large memory entries without truncation" {
    const allocator = std.testing.allocator;
    const large_content = try allocator.alloc(u8, 90_000);
    defer allocator.free(large_content);
    @memset(large_content, 'm');

    const entry = yc.memory.MemoryEntry{
        .id = "entry-large",
        .key = "fact",
        .category = .conversation,
        .timestamp = "2026-04-17T00:00:00Z",
        .content = large_content,
        .session_id = "s-large",
    };

    const rendered = try yc.admin_output.renderBytes(allocator, writeMemoryEntryJson, .{entry});
    defer allocator.free(rendered);

    try std.testing.expect(rendered.len > 90_000);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"key\":\"fact\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"session_id\":\"s-large\"") != null);
}

test "appendMemoryDeleteJson renders delete outcome payload" {
    var buf: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendMemoryDeleteJson(&writer, "fact", "s-1", true);
    try std.testing.expectEqualStrings(
        "{\"key\":\"fact\",\"session_id\":\"s-1\",\"deleted\":true}",
        writer.buffered(),
    );
}

test "appendMemorySearchResultsJson renders retrieval candidates" {
    const results = [_]yc.memory.RetrievalCandidate{
        .{
            .id = "row-1",
            .key = "fact",
            .content = "hello world",
            .snippet = "hello",
            .category = .conversation,
            .keyword_rank = 1,
            .vector_score = null,
            .final_score = 0.9,
            .source = "primary",
            .source_path = "memory://fact",
            .start_line = 1,
            .end_line = 1,
            .created_at = 42,
        },
    };
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendMemorySearchResultsJson(&writer, &results);
    try std.testing.expectEqualStrings(
        "[{\"key\":\"fact\",\"category\":\"conversation\",\"snippet\":\"hello\",\"source\":\"primary\",\"source_path\":\"memory://fact\",\"final_score\":0.9,\"start_line\":1,\"end_line\":1,\"created_at\":42,\"keyword_rank\":1,\"vector_score\":null}]",
        writer.buffered(),
    );
}

test "appendAgentSessionTerminationJson renders terminated session payload" {
    var buf: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try appendAgentSessionTerminationJson(&writer, "s-1");
    try std.testing.expectEqualStrings("{\"session_key\":\"s-1\",\"terminated\":true}", writer.buffered());
}
