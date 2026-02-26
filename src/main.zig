const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const yc = @import("nullclaw");

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    std.fs.File.stderr().writeAll("panic: ") catch {};
    std.fs.File.stderr().writeAll(msg) catch {};
    std.fs.File.stderr().writeAll("\n") catch {};
    std.process.exit(1);
}

const log = std.log.scoped(.main);

const Command = enum {
    agent,
    gateway,
    service,
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
    capabilities,
    models,
    auth,
    update,
    help,
};

fn parseCommand(arg: []const u8) ?Command {
    const command_map = std.StaticStringMap(Command).initComptime(.{
        .{ "agent", .agent },
        .{ "gateway", .gateway },
        .{ "service", .service },
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
        .{ "capabilities", .capabilities },
        .{ "models", .models },
        .{ "auth", .auth },
        .{ "update", .update },
        .{ "help", .help },
        .{ "--help", .help },
        .{ "-h", .help },
    });
    return command_map.get(arg);
}

pub fn main() !void {
    // Enable UTF-8 output on Windows console (fixes Cyrillic/Unicode garbling)
    if (comptime builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleOutputCP(65001);
    }

    const allocator = std.heap.smp_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const cmd = parseCommand(args[1]) orelse {
        std.debug.print("Unknown command: {s}\n\n", .{args[1]});
        printUsage();
        std.process.exit(1);
    };

    const sub_args = args[2..];

    switch (cmd) {
        .version => printVersion(),
        .status => try yc.status.run(allocator),
        .agent => try yc.agent.run(allocator, sub_args),
        .onboard => try runOnboard(allocator, sub_args),
        .doctor => try yc.doctor.run(allocator),
        .help => printUsage(),
        .gateway => try runGateway(allocator, sub_args),
        .service => try runService(allocator, sub_args),
        .cron => try runCron(allocator, sub_args),
        .channel => try runChannel(allocator, sub_args),
        .skills => try runSkills(allocator, sub_args),
        .hardware => try runHardware(allocator, sub_args),
        .migrate => try runMigrate(allocator, sub_args),
        .memory => try runMemory(allocator, sub_args),
        .capabilities => try runCapabilities(allocator, sub_args),
        .models => try runModels(allocator, sub_args),
        .auth => try runAuth(allocator, sub_args),
        .update => try runUpdate(allocator, sub_args),
    }
}

fn printVersion() void {
    var buf: [256]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    bw.interface.print("nullclaw {s}\n", .{yc.version.string}) catch return;
    bw.interface.flush() catch return;
}

const GatewayDaemonOverrideError = error{InvalidPort};

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
        }
    }

    cfg.gateway.port = port;
    cfg.gateway.host = host;
}

// ── Gateway ──────────────────────────────────────────────────────

fn runGateway(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer cfg.deinit();

    applyGatewayDaemonOverrides(&cfg, sub_args) catch {
        std.debug.print("Invalid port in CLI args.\n", .{});
        std.process.exit(1);
    };

    cfg.validate() catch |err| {
        yc.config.Config.printValidationError(err);
        std.process.exit(1);
    };

    try yc.daemon.run(allocator, &cfg, cfg.gateway.host, cfg.gateway.port);
}

// ── Service ──────────────────────────────────────────────────────

fn runService(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print("Usage: nullclaw service <install|start|stop|status|uninstall>\n", .{});
        std.process.exit(1);
    }

    const subcmd = sub_args[0];
    const service_cmd: yc.service.ServiceCommand = blk: {
        const map = .{
            .{ "install", yc.service.ServiceCommand.install },
            .{ "start", yc.service.ServiceCommand.start },
            .{ "stop", yc.service.ServiceCommand.stop },
            .{ "status", yc.service.ServiceCommand.status },
            .{ "uninstall", yc.service.ServiceCommand.uninstall },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, subcmd, entry[0])) break :blk entry[1];
        }
        std.debug.print("Unknown service command: {s}\n", .{subcmd});
        std.debug.print("Usage: nullclaw service <install|start|stop|status|uninstall>\n", .{});
        std.process.exit(1);
    };

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer cfg.deinit();

    yc.service.handleCommand(allocator, service_cmd, cfg.config_path) catch |err| {
        const any_err: anyerror = err;
        switch (any_err) {
            error.UnsupportedPlatform => {
                std.debug.print("Service management is not supported on this platform.\n", .{});
            },
            error.NoHomeDir => {
                std.debug.print("Could not resolve home directory for service files.\n", .{});
            },
            error.SystemctlUnavailable => {
                std.debug.print("`systemctl` is not available; Linux service commands require systemd user services.\n", .{});
                std.debug.print("Run `nullclaw gateway` in the foreground or use another supervisor.\n", .{});
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
        std.process.exit(1);
    };
}

// ── Cron ─────────────────────────────────────────────────────────

fn runCron(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw cron <command> [args]
            \\
            \\Commands:
            \\  list                          List all scheduled tasks
            \\  add <expression> <command>    Add a recurring cron job
            \\  once <delay> <command>        Add a one-shot delayed task
            \\  remove <id>                   Remove a scheduled task
            \\  pause <id>                    Pause a scheduled task
            \\  resume <id>                   Resume a paused task
            \\  run <id>                      Run a scheduled task immediately
            \\  update <id> [options]         Update a cron job
            \\  runs <id>                     List recent run history for a job
            \\
        , .{});
        std.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        try yc.cron.cliListJobs(allocator);
    } else if (std.mem.eql(u8, subcmd, "add")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron add <expression> <command>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliAddJob(allocator, sub_args[1], sub_args[2]);
    } else if (std.mem.eql(u8, subcmd, "once")) {
        if (sub_args.len < 3) {
            std.debug.print("Usage: nullclaw cron once <delay> <command>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliAddOnce(allocator, sub_args[1], sub_args[2]);
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron remove <id>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliRemoveJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "pause")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron pause <id>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliPauseJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "resume")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron resume <id>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliResumeJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "run")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron run <id>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliRunJob(allocator, sub_args[1]);
    } else if (std.mem.eql(u8, subcmd, "update")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron update <id> [--expression <expr>] [--command <cmd>] [--enable] [--disable]\n", .{});
            std.process.exit(1);
        }
        const id = sub_args[1];
        var expression: ?[]const u8 = null;
        var command: ?[]const u8 = null;
        var enabled: ?bool = null;
        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--expression") and i + 1 < sub_args.len) {
                i += 1;
                expression = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--command") and i + 1 < sub_args.len) {
                i += 1;
                command = sub_args[i];
            } else if (std.mem.eql(u8, sub_args[i], "--enable")) {
                enabled = true;
            } else if (std.mem.eql(u8, sub_args[i], "--disable")) {
                enabled = false;
            }
        }
        try yc.cron.cliUpdateJob(allocator, id, expression, command, enabled);
    } else if (std.mem.eql(u8, subcmd, "runs")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw cron runs <id>\n", .{});
            std.process.exit(1);
        }
        try yc.cron.cliListRuns(allocator, sub_args[1]);
    } else {
        std.debug.print("Unknown cron command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

// ── Channel ──────────────────────────────────────────────────────

fn runChannel(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw channel <command> [args]
            \\
            \\Commands:
            \\  list                          List configured channels
            \\  start [channel]               Start a channel (default: first available)
            \\  status                        Show channel health/status
            \\  add <type> <config_json>      Add a channel
            \\  remove <name>                 Remove a channel
            \\
        , .{});
        std.process.exit(1);
    }

    const subcmd = sub_args[0];

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer cfg.deinit();

    if (std.mem.eql(u8, subcmd, "list")) {
        std.debug.print("Configured channels:\n", .{});
        for (yc.channel_catalog.known_channels) |meta| {
            var status_buf: [64]u8 = undefined;
            const status_text = yc.channel_catalog.statusText(&cfg, meta, &status_buf);
            std.debug.print("  {s}: {s}\n", .{ meta.label, status_text });
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
            std.process.exit(1);
        }
        std.debug.print("To add a '{s}' channel, edit your config file:\n  {s}\n", .{ sub_args[1], cfg.config_path });
        std.debug.print("Add a \"{s}\" object under \"channels\" with the required fields.\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw channel remove <name>\n", .{});
            std.process.exit(1);
        }
        std.debug.print("To remove the '{s}' channel, edit your config file:\n  {s}\n", .{ sub_args[1], cfg.config_path });
        std.debug.print("Remove or set the \"{s}\" object to null under \"channels\".\n", .{sub_args[1]});
    } else {
        std.debug.print("Unknown channel command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

// ── Skills ───────────────────────────────────────────────────────

fn runSkills(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw skills <command> [args]
            \\
            \\Commands:
            \\  list                          List installed skills
            \\  install <source>              Install from GitHub URL or path
            \\  remove <name>                 Remove a skill
            \\  info <name>                   Show skill details
            \\
        , .{});
        std.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer cfg.deinit();

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "list")) {
        const skills_list = yc.skills.listSkills(allocator, cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to list skills: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer yc.skills.freeSkills(allocator, skills_list);

        if (skills_list.len == 0) {
            std.debug.print("No skills installed.\n", .{});
        } else {
            std.debug.print("Installed skills ({d}):\n", .{skills_list.len});
            for (skills_list) |skill| {
                std.debug.print("  {s} v{s}", .{ skill.name, skill.version });
                if (skill.description.len > 0) {
                    std.debug.print(" -- {s}", .{skill.description});
                }
                std.debug.print("\n", .{});
            }
        }
    } else if (std.mem.eql(u8, subcmd, "install")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills install <source>\n", .{});
            std.process.exit(1);
        }
        yc.skills.installSkillFromPath(allocator, sub_args[1], cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to install skill: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        std.debug.print("Skill installed from: {s}\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "remove")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills remove <name>\n", .{});
            std.process.exit(1);
        }
        yc.skills.removeSkill(allocator, sub_args[1], cfg.workspace_dir) catch |err| {
            std.debug.print("Failed to remove skill '{s}': {s}\n", .{ sub_args[1], @errorName(err) });
            std.process.exit(1);
        };
        std.debug.print("Removed skill: {s}\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw skills info <name>\n", .{});
            std.process.exit(1);
        }
        const skill_path = std.fmt.allocPrint(allocator, "{s}/skills/{s}", .{ cfg.workspace_dir, sub_args[1] }) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        defer allocator.free(skill_path);

        const skill = yc.skills.loadSkill(allocator, skill_path) catch {
            std.debug.print("Skill '{s}' not found or invalid.\n", .{sub_args[1]});
            std.process.exit(1);
        };
        defer yc.skills.freeSkill(allocator, &skill);

        std.debug.print("Skill: {s}\n", .{skill.name});
        std.debug.print("  Version:     {s}\n", .{skill.version});
        if (skill.description.len > 0) {
            std.debug.print("  Description: {s}\n", .{skill.description});
        }
        if (skill.author.len > 0) {
            std.debug.print("  Author:      {s}\n", .{skill.author});
        }
        std.debug.print("  Enabled:     {}\n", .{skill.enabled});
        if (skill.instructions.len > 0) {
            std.debug.print("  Instructions: {d} bytes\n", .{skill.instructions.len});
        }
    } else {
        std.debug.print("Unknown skills command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

// ── Hardware ─────────────────────────────────────────────────────

fn runHardware(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw hardware <command> [args]
            \\
            \\Commands:
            \\  scan                          Scan for connected hardware
            \\  flash                         Flash firmware to a device
            \\  monitor                       Monitor connected devices
            \\
        , .{});
        std.process.exit(1);
    }

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "scan")) {
        std.debug.print("Scanning for hardware devices...\n", .{});
        std.debug.print("Known board registry: {d} entries\n", .{yc.hardware.knownBoards().len});

        const devices = yc.hardware.discoverHardware(allocator) catch |err| {
            std.debug.print("Discovery failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
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
            std.process.exit(1);
        }
        std.debug.print("Flash not yet implemented. Firmware file: {s}\n", .{sub_args[1]});
    } else if (std.mem.eql(u8, subcmd, "monitor")) {
        std.debug.print("Monitor not yet implemented. Use `nullclaw hardware scan` to discover devices first.\n", .{});
    } else {
        std.debug.print("Unknown hardware command: {s}\n", .{subcmd});
        std.process.exit(1);
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
        std.process.exit(1);
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
            std.process.exit(1);
        };
        defer cfg.deinit();

        const stats = yc.migration.migrateOpenclaw(allocator, &cfg, source_path, dry_run) catch |err| {
            std.debug.print("Migration failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
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
        std.process.exit(1);
    }
}

// ── Memory ───────────────────────────────────────────────────────

fn printMemoryUsage() void {
    std.debug.print(
        \\Usage: nullclaw memory <command> [args]
        \\
        \\Commands:
        \\  stats                         Show resolved memory config and key counters
        \\  count                         Show total number of memory entries
        \\  reindex                       Rebuild vector index from primary memory
        \\  search <query> [--limit N]    Run runtime retrieval (keyword/hybrid)
        \\  get <key>                     Show a single memory entry by key
        \\  list [--category C] [--limit N]
        \\                                List memory entries (default limit: 20)
        \\  drain-outbox                  Drain durable vector outbox queue
        \\  forget <key>                  Delete entry from primary memory (if backend supports)
        \\
    , .{});
}

fn parsePositiveUsize(arg: []const u8) ?usize {
    const n = std.fmt.parseInt(usize, arg, 10) catch return null;
    if (n == 0) return null;
    return n;
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

fn runMemory(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        printMemoryUsage();
        std.process.exit(1);
    }

    var cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer cfg.deinit();

    var mem_rt = yc.memory.initRuntime(allocator, &cfg.memory, cfg.workspace_dir) orelse {
        printMemoryRuntimeInitFailure(allocator, cfg.memory.backend);
        std.process.exit(1);
    };
    defer mem_rt.deinit();

    const subcmd = sub_args[0];

    if (std.mem.eql(u8, subcmd, "stats")) {
        const r = mem_rt.resolved;
        const report = mem_rt.diagnose();
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
        return;
    }

    if (std.mem.eql(u8, subcmd, "count")) {
        const count = mem_rt.memory.count() catch |err| {
            std.debug.print("memory count failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        std.debug.print("{d}\n", .{count});
        return;
    }

    if (std.mem.eql(u8, subcmd, "reindex")) {
        const count = mem_rt.reindex(allocator);
        if (std.mem.eql(u8, mem_rt.resolved.vector_mode, "none")) {
            std.debug.print("Vector plane is disabled; reindex skipped (0 entries).\n", .{});
        } else {
            std.debug.print("Reindex complete: {d} entries reindexed.\n", .{count});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "drain-outbox")) {
        const drained = mem_rt.drainOutbox(allocator);
        std.debug.print("Outbox drain complete: {d} operation(s) processed.\n", .{drained});
        return;
    }

    if (std.mem.eql(u8, subcmd, "forget")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory forget <key>\n", .{});
            std.process.exit(1);
        }
        const key = sub_args[1];
        const deleted = mem_rt.memory.forget(key) catch |err| {
            std.debug.print("memory forget failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        if (deleted) {
            mem_rt.deleteFromVectorStore(key);
            std.debug.print("Deleted memory entry: {s}\n", .{key});
        } else {
            std.debug.print("Entry not deleted (missing or backend is append-only): {s}\n", .{key});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "get")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory get <key>\n", .{});
            std.process.exit(1);
        }
        const key = sub_args[1];
        const entry = mem_rt.memory.get(allocator, key) catch |err| {
            std.debug.print("memory get failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        if (entry) |e| {
            defer e.deinit(allocator);
            std.debug.print("key: {s}\ncategory: {s}\ntimestamp: {s}\ncontent:\n{s}\n", .{
                e.key,
                e.category.toString(),
                e.timestamp,
                e.content,
            });
        } else {
            std.debug.print("Not found: {s}\n", .{key});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "list")) {
        var limit: usize = 20;
        var category_opt: ?yc.memory.MemoryCategory = null;

        var i: usize = 1;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N]\n", .{});
                    std.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, sub_args[i], "--category")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory list [--category C] [--limit N]\n", .{});
                    std.process.exit(1);
                }
                i += 1;
                category_opt = yc.memory.MemoryCategory.fromString(sub_args[i]);
            } else {
                std.debug.print("Unknown option for memory list: {s}\n", .{sub_args[i]});
                std.process.exit(1);
            }
        }

        const entries = mem_rt.memory.list(allocator, category_opt, null) catch |err| {
            std.debug.print("memory list failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer yc.memory.freeEntries(allocator, entries);

        const shown = @min(limit, entries.len);
        std.debug.print("Memory entries: showing {d}/{d}\n", .{ shown, entries.len });
        for (entries[0..shown], 0..) |e, idx| {
            const preview_len = @min(@as(usize, 120), e.content.len);
            const preview = e.content[0..preview_len];
            std.debug.print("  {d}. {s} [{s}] {s}\n     {s}{s}\n", .{
                idx + 1,
                e.key,
                e.category.toString(),
                e.timestamp,
                preview,
                if (e.content.len > preview_len) "..." else "",
            });
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "search")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw memory search <query> [--limit N]\n", .{});
            std.process.exit(1);
        }
        const query = sub_args[1];
        var limit: usize = 6;

        var i: usize = 2;
        while (i < sub_args.len) : (i += 1) {
            if (std.mem.eql(u8, sub_args[i], "--limit")) {
                if (i + 1 >= sub_args.len) {
                    std.debug.print("Usage: nullclaw memory search <query> [--limit N]\n", .{});
                    std.process.exit(1);
                }
                i += 1;
                limit = parsePositiveUsize(sub_args[i]) orelse {
                    std.debug.print("Invalid --limit value: {s}\n", .{sub_args[i]});
                    std.process.exit(1);
                };
            } else {
                std.debug.print("Unknown option for memory search: {s}\n", .{sub_args[i]});
                std.process.exit(1);
            }
        }

        const results = mem_rt.search(allocator, query, limit, null) catch |err| {
            std.debug.print("memory search failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer yc.memory.retrieval.freeCandidates(allocator, results);

        std.debug.print("Search results: {d}\n", .{results.len});
        for (results, 0..) |c, idx| {
            std.debug.print("  {d}. {s} [{s}]\n", .{ idx + 1, c.key, c.category.toString() });
            printRetrievalScoreLine(c);
            const preview_len = @min(@as(usize, 140), c.snippet.len);
            const preview = c.snippet[0..preview_len];
            std.debug.print("     {s}{s}\n", .{ preview, if (c.snippet.len > preview_len) "..." else "" });
        }
        return;
    }

    std.debug.print("Unknown memory command: {s}\n\n", .{subcmd});
    printMemoryUsage();
    std.process.exit(1);
}

fn runCapabilities(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var as_json = false;
    if (sub_args.len > 0) {
        if (sub_args.len == 1 and (std.mem.eql(u8, sub_args[0], "--json") or std.mem.eql(u8, sub_args[0], "json"))) {
            as_json = true;
        } else {
            std.debug.print("Usage: nullclaw capabilities [--json]\n", .{});
            std.process.exit(1);
        }
    }

    var cfg_opt: ?yc.config.Config = yc.config.Config.load(allocator) catch null;
    defer if (cfg_opt) |*cfg| cfg.deinit();
    const cfg_ptr: ?*const yc.config.Config = if (cfg_opt) |*cfg| cfg else null;

    const output = if (as_json)
        try yc.capabilities.buildManifestJson(allocator, cfg_ptr, null)
    else
        try yc.capabilities.buildSummaryText(allocator, cfg_ptr, null);
    defer allocator.free(output);

    std.debug.print("{s}", .{output});
}

// ── Models ───────────────────────────────────────────────────────

fn runModels(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 1) {
        std.debug.print(
            \\Usage: nullclaw models <command>
            \\
            \\Commands:
            \\  list                          List available models
            \\  info <model>                  Show model details
            \\  benchmark                     Run model latency benchmark
            \\  refresh                       Refresh model catalog
            \\
        , .{});
        std.process.exit(1);
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
    } else if (std.mem.eql(u8, subcmd, "info")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw models info <model>\n", .{});
            std.process.exit(1);
        }
        std.debug.print("Model: {s}\n", .{sub_args[1]});
        std.debug.print("  Default provider: {s}\n", .{yc.onboard.canonicalProviderName(sub_args[1])});
        std.debug.print("  Context: varies by provider\n", .{});
        std.debug.print("  Pricing: see provider dashboard\n", .{});
    } else if (std.mem.eql(u8, subcmd, "benchmark")) {
        std.debug.print("Running model latency benchmark...\n", .{});
        std.debug.print("Configure a provider first (nullclaw onboard).\n", .{});
    } else if (std.mem.eql(u8, subcmd, "refresh")) {
        try yc.onboard.runModelsRefresh(allocator);
    } else {
        std.debug.print("Unknown models command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
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
        \\Usage: nullclaw onboard [--interactive | --channels-only | [--api-key KEY] [--provider PROV] [--memory MEM]]
        \\
        \\Modes:
        \\  (default)         quick setup
        \\  --interactive     run full interactive wizard
        \\  --channels-only   reconfigure channels and allowlists only
        \\
        \\Quick setup options:
        \\  --api-key KEY     provider API key to persist in config
        \\  --provider PROV   default provider key (e.g. openrouter, anthropic)
        \\  --memory MEM      memory backend key (e.g. markdown, sqlite, memory)
        \\
        \\Examples:
        \\  nullclaw onboard --api-key sk-... --provider openrouter
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
            std.process.exit(1);
        },
        .missing_value => |opt| {
            std.debug.print("Missing value for onboard option: {s}\n\n", .{opt});
            printOnboardUsage();
            std.process.exit(1);
        },
        .unexpected_argument => |arg| {
            std.debug.print("Unexpected positional argument for onboard: {s}\n\n", .{arg});
            printOnboardUsage();
            std.process.exit(1);
        },
        .invalid_combination => {
            std.debug.print("Invalid onboard option combination.\n", .{});
            std.debug.print("Use either --interactive, --channels-only, or quick-setup flags.\n\n", .{});
            printOnboardUsage();
            std.process.exit(1);
        },
    };

    switch (parsed.mode) {
        .channels_only => try yc.onboard.runChannelsOnly(allocator),
        .interactive => try yc.onboard.runWizard(allocator),
        .quick => yc.onboard.runQuickSetup(allocator, parsed.api_key, parsed.provider, parsed.memory_backend) catch |err| switch (err) {
            error.UnknownProvider => {
                const requested = parsed.provider orelse "(missing)";
                std.debug.print("Unknown provider '{s}' for quick setup.\n", .{requested});
                printKnownOnboardProviders();
                std.process.exit(1);
            },
            error.UnknownMemoryBackend => {
                const requested = parsed.memory_backend orelse "(missing)";
                std.debug.print("Unknown memory backend '{s}' for quick setup.\n", .{requested});
                std.debug.print("Known memory backends: {s}\n", .{yc.memory.registry.known_backends_csv});
                printEnabledMemoryBackends(allocator);
                std.process.exit(1);
            },
            error.MemoryBackendDisabledInBuild => {
                const requested = parsed.memory_backend orelse "(missing)";
                const engine_token = yc.memory.registry.engineTokenForBackend(requested) orelse requested;
                std.debug.print("Memory backend '{s}' is disabled in this build.\n", .{requested});
                std.debug.print("Rebuild with -Dengines={s} (or include it in -Dengines=... list).\n", .{engine_token});
                printEnabledMemoryBackends(allocator);
                std.process.exit(1);
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
        std.process.exit(1);
    }

    switch (meta.id) {
        .telegram => {
            if (config.channels.telegramPrimary()) |tg_config| {
                return runTelegramChannel(allocator, args, config.*, tg_config);
            }
            std.debug.print("Telegram channel is not configured.\n", .{});
            std.process.exit(1);
        },
        .signal => {
            if (config.channels.signalPrimary()) |sig_config| {
                return runSignalChannel(allocator, args, config, sig_config);
            }
            std.debug.print("Signal channel is not configured.\n", .{});
            std.process.exit(1);
        },
        .matrix => {
            if (config.channels.matrixPrimary()) |mx_config| {
                return runMatrixChannel(allocator, args, config, mx_config);
            }
            std.debug.print("Matrix channel is not configured.\n", .{});
            std.process.exit(1);
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

fn runChannelStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len > 0 and std.mem.eql(u8, args[0], "--all")) {
        std.debug.print("Use `nullclaw gateway` to start all configured channels/accounts.\n", .{});
        std.process.exit(1);
    }

    // Load config
    var config = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };
    defer config.deinit();

    config.validate() catch |err| {
        yc.config.Config.printValidationError(err);
        std.process.exit(1);
    };

    if (!hasConfiguredStartableChannels(&config)) {
        if (hasConfiguredButBuildDisabledStartableChannels(&config)) {
            printConfiguredButBuildDisabledChannelsHint(&config);
        } else {
            printNoMessagingChannelConfiguredHint();
        }
        std.process.exit(1);
    }

    // Check if user specified a channel name
    const requested: ?[]const u8 = if (args.len > 0) args[0] else null;

    if (requested) |ch_name| {
        const meta = yc.channel_catalog.findByKey(ch_name) orelse {
            std.debug.print("Unknown channel: {s}\n", .{ch_name});
            printChannelStartSupported();
            std.process.exit(1);
        };
        if (!yc.channel_catalog.isBuildEnabled(meta.id)) {
            const configured = yc.channel_catalog.configuredCount(&config, meta.id);
            if (configured > 0) {
                std.debug.print("Channel {s} is configured ({d} account(s)) but disabled in this build.\n", .{ meta.key, configured });
            } else {
                std.debug.print("Channel {s} is disabled in this build.\n", .{meta.key});
            }
            std.debug.print("Rebuild with -Dchannels={s} (or -Dchannels=all).\n", .{meta.key});
            printChannelStartSupported();
            std.process.exit(1);
        }
        if (!canStartFromChannelCommand(meta.id)) {
            std.debug.print("Channel {s} cannot be started via `channel start`.\n", .{ch_name});
            printChannelStartSupported();
            std.process.exit(1);
        }
        if (!yc.channel_catalog.isConfigured(&config, meta.id)) {
            std.debug.print("{s} channel is not configured.\n", .{meta.label});
            std.process.exit(1);
        }

        const child_args: []const []const u8 = if (args.len > 1) args[1..] else &.{};
        return dispatchChannelStart(allocator, child_args, &config, meta);
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

    const mgr = try yc.channel_manager.ChannelManager.init(allocator, config, &registry);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();

    // Find and start only the requested channel
    var found = false;
    for (mgr.channelEntries()) |entry| {
        if (std.mem.eql(u8, entry.name, ch_name)) {
            entry.channel.start() catch |err| {
                std.debug.print("{s} channel failed to start: {}\n", .{ ch_name, err });
                std.process.exit(1);
            };
            found = true;
            break;
        }
    }

    if (!found) {
        std.debug.print("{s} channel is not configured.\n", .{ch_name});
        std.process.exit(1);
    }

    std.debug.print("{s} channel started. Press Ctrl+C to stop.\n", .{ch_name});

    // Block until Ctrl+C
    while (!yc.daemon.isShutdownRequested()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}

// ── Signal Channel ─────────────────────────────────────────────────

fn hasReliabilityCredentialFallback(allocator: std.mem.Allocator, config: *const yc.config.Config) bool {
    for (config.reliability.api_keys) |raw_key| {
        if (std.mem.trim(u8, raw_key, " \t\r\n").len > 0) return true;
    }

    for (config.reliability.fallback_providers) |provider_name| {
        if (yc.providers.classifyProvider(provider_name) == .openai_codex_provider) return true;

        const resolved = yc.providers.resolveApiKeyFromConfig(
            allocator,
            provider_name,
            config.providers,
        ) catch null;
        defer if (resolved) |k| allocator.free(k);

        if (resolved) |key| {
            if (std.mem.trim(u8, key, " \t\r\n").len > 0) return true;
        }
    }

    return false;
}

fn runSignalChannel(allocator: std.mem.Allocator, args: []const []const u8, config: *const yc.config.Config, signal_config: yc.config.SignalConfig) !void {
    _ = args;
    if (!build_options.enable_channel_signal) {
        std.debug.print("Signal channel is disabled in this build.\n", .{});
        std.process.exit(1);
    }

    // Resolve API key: config providers first, then env vars (ANTHROPIC_API_KEY, etc.)
    const resolved_api_key = yc.providers.resolveApiKeyFromConfig(
        allocator,
        config.default_provider,
        config.providers,
    ) catch null;
    defer if (resolved_api_key) |k| allocator.free(k);

    // OAuth providers (openai-codex) don't need an API key
    const provider_kind = yc.providers.classifyProvider(config.default_provider);
    const has_fallback_credentials = hasReliabilityCredentialFallback(allocator, config);
    if (resolved_api_key == null and provider_kind != .openai_codex_provider and !has_fallback_credentials) {
        std.debug.print("No API key configured. Set env var or add to ~/.nullclaw/config.json:\n", .{});
        std.debug.print("  \"providers\": {{ \"{s}\": {{ \"api_key\": \"...\" }} }}\n", .{config.default_provider});
        std.process.exit(1);
    }

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
    const env_http_url = std.process.getEnvVarOwned(allocator, "SIGNAL_HTTP_URL") catch null;
    defer if (env_http_url) |v| allocator.free(v);
    const env_account = std.process.getEnvVarOwned(allocator, "SIGNAL_ACCOUNT") catch null;
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
        std.process.exit(1);
    }

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    // Initialize MCP tools from config
    const mcp_tools: ?[]const yc.tools.Tool = if (config.mcp_servers.len > 0)
        yc.mcp.initMcpTools(allocator, config.mcp_servers) catch |err| blk: {
            std.debug.print("  MCP: init failed: {}\n", .{err});
            break :blk null;
        }
    else
        null;
    defer if (mcp_tools) |mt| allocator.free(mt);

    // Build security policy from config
    const security = @import("nullclaw").security.policy;
    var tracker = security.RateTracker.init(allocator, config.autonomy.max_actions_per_hour);
    defer tracker.deinit();

    var sec_policy = security.SecurityPolicy{
        .autonomy = config.autonomy.level,
        .workspace_dir = config.workspace_dir,
        .workspace_only = config.autonomy.workspace_only,
        .allowed_commands = if (config.autonomy.allowed_commands.len > 0) config.autonomy.allowed_commands else &security.default_allowed_commands,
        .max_actions_per_hour = config.autonomy.max_actions_per_hour,
        .require_approval_for_medium_risk = config.autonomy.require_approval_for_medium_risk,
        .block_high_risk_commands = config.autonomy.block_high_risk_commands,
        .tracker = &tracker,
    };

    var subagent_manager = yc.subagent.SubagentManager.init(allocator, config, null, .{});
    defer subagent_manager.deinit();

    // Create tools (for system prompt and tool calling)
    const tools = yc.tools.allTools(allocator, config.workspace_dir, .{
        .http_enabled = config.http_request.enabled,
        .browser_enabled = config.browser.enabled,
        .screenshot_enabled = true,
        .mcp_tools = mcp_tools,
        .agents = config.agents,
        .fallback_api_key = resolved_api_key,
        .tools_config = config.tools,
        .allowed_paths = config.autonomy.allowed_paths,
        .policy = &sec_policy,
        .subagent_manager = &subagent_manager,
    }) catch &.{};
    defer if (tools.len > 0) yc.tools.deinitTools(allocator, tools);

    if (mcp_tools) |mt| {
        std.debug.print("  MCP tools: {d}\n", .{mt.len});
    }

    // Create optional memory backend (don't fail if unavailable)
    var mem_rt = yc.memory.initRuntime(allocator, &config.memory, config.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?yc.memory.Memory = if (mem_rt) |rt| rt.memory else null;

    // Wire MemoryRuntime into tools for retrieval pipeline + vector sync
    if (mem_rt) |*rt| {
        yc.tools.bindMemoryRuntime(tools, rt);
    }

    // Create provider with reliability wrapper (retry + fallback chains).
    var runtime_provider = try yc.providers.runtime_bundle.RuntimeProviderBundle.init(allocator, config);
    defer runtime_provider.deinit();
    const provider_i = runtime_provider.provider();

    // Create noop observer
    var noop_obs = yc.observability.NoopObserver{};
    const obs = noop_obs.observer();

    // Initialize session manager
    var session_mgr = yc.session.SessionManager.init(allocator, config, provider_i, tools, mem_opt, obs, if (mem_rt) |rt| rt.session_store else null, if (mem_rt) |*rt| rt.response_cache else null);
    session_mgr.policy = &sec_policy;
    if (mem_rt) |*rt| {
        session_mgr.mem_rt = rt;
    }
    defer session_mgr.deinit();

    // Session key buffer
    var key_buf: [128]u8 = undefined;

    // Message loop: poll → full agent loop (tool calling) → reply
    while (true) {
        const messages = sg.pollMessages(allocator) catch |err| {
            std.debug.print("Signal poll error: {}\n", .{err});
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        for (messages) |msg| {
            std.debug.print("[{s}] {s}: {s}\n", .{ msg.channel, msg.id, msg.content });

            // Session key — resolve through route engine, fallback to legacy key.
            const group_peer_id = yc.channels.signal.signalGroupPeerId(msg.reply_target);
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);
            const session_key = blk: {
                const route = yc.agent_routing.resolveRouteWithSession(
                    allocator,
                    .{
                        .channel = "signal",
                        .account_id = sg.account_id,
                        .peer = .{
                            .kind = if (msg.is_group) .group else .direct,
                            .id = if (msg.is_group) group_peer_id else msg.sender,
                        },
                    },
                    config.agent_bindings,
                    config.agents,
                    config.session,
                ) catch break :blk if (msg.is_group)
                    std.fmt.bufPrint(&key_buf, "signal:{s}:group:{s}:{s}", .{
                        sg.account_id,
                        group_peer_id,
                        msg.sender,
                    }) catch msg.sender
                else
                    std.fmt.bufPrint(&key_buf, "signal:{s}:{s}", .{ sg.account_id, msg.sender }) catch msg.sender;
                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            // Build conversation context for Signal (includes sender UUID and group ID)
            const conversation_context: ?yc.agent.ConversationContext = if (std.mem.eql(u8, msg.channel, "signal")) blk: {
                break :blk .{
                    .channel = "signal",
                    .sender_number = if (msg.sender.len > 0 and msg.sender[0] == '+') msg.sender else null,
                    .sender_uuid = msg.sender_uuid,
                    .group_id = msg.group_id,
                    .is_group = msg.is_group,
                };
            } else null;

            const reply = session_mgr.processMessage(session_key, msg.content, conversation_context) catch |err| {
                std.debug.print("  Agent error: {}\n", .{err});
                const err_msg = switch (err) {
                    error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "Network error. Please try again.",
                    error.ProviderDoesNotSupportVision => "The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.",
                    error.NoResponseContent => "Model returned an empty response. Please retry or /new for a fresh session.",
                    error.AllProvidersFailed => "All configured providers failed for this request. Check model/provider compatibility and credentials.",
                    error.OutOfMemory => "Out of memory.",
                    else => "An error occurred. Try again or /new for a fresh session.",
                };
                if (msg.reply_target) |target| {
                    sg.sendMessage(target, err_msg, &.{}) catch |send_err| std.debug.print("  Send error: {}\n", .{send_err});
                }
                continue;
            };
            defer allocator.free(reply);

            std.debug.print("  -> {s}\n", .{reply});

            // Reply on Signal; handles split
            if (msg.reply_target) |target| {
                sg.sendMessage(target, reply, &.{}) catch |err| {
                    std.debug.print("  Send error: {}\n", .{err});
                };
            }
        }

        if (messages.len > 0) {
            // Free message memory
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        // Small delay between polls
        std.Thread.sleep(500 * std.time.ns_per_ms);
    }
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
        std.process.exit(1);
    }

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
        std.process.exit(1);
    }

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    const runtime = yc.channel_loop.ChannelRuntime.init(allocator, config) catch |err| {
        std.debug.print("Runtime init failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer runtime.deinit();

    var loop_state = yc.channel_loop.MatrixLoopState.init();
    yc.channel_loop.runMatrixLoop(allocator, config, runtime, &loop_state, &mx);
}

// ── Telegram Channel ───────────────────────────────────────────────-

fn runTelegramChannel(allocator: std.mem.Allocator, args: []const []const u8, config: yc.config.Config, telegram_config: yc.config.TelegramConfig) !void {
    if (!build_options.enable_channel_telegram) {
        std.debug.print("Telegram channel is disabled in this build.\n", .{});
        std.process.exit(1);
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

    // Resolve API key: config providers first, then env vars (ANTHROPIC_API_KEY, etc.)
    const resolved_api_key = yc.providers.resolveApiKeyFromConfig(
        allocator,
        config.default_provider,
        config.providers,
    ) catch null;
    defer if (resolved_api_key) |k| allocator.free(k);

    // OAuth providers (openai-codex) don't need an API key
    const provider_kind = yc.providers.classifyProvider(config.default_provider);
    const has_fallback_credentials = hasReliabilityCredentialFallback(allocator, &config);
    if (resolved_api_key == null and provider_kind != .openai_codex_provider and !has_fallback_credentials) {
        std.debug.print("No API key configured. Set env var or add to ~/.nullclaw/config.json:\n", .{});
        std.debug.print("  \"providers\": {{ \"{s}\": {{ \"api_key\": \"...\" }} }}\n", .{config.default_provider});
        std.process.exit(1);
    }

    const model = config.default_model.?;
    const temperature = config.default_temperature;

    std.debug.print("nullclaw telegram bot starting...\n", .{});
    std.debug.print("  Provider: {s}\n", .{config.default_provider});
    std.debug.print("  Model: {s}\n", .{model});
    std.debug.print("  Temperature: {d:.1}\n", .{temperature});
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

    var tg = yc.channels.telegram.TelegramChannel.init(allocator, telegram_config.bot_token, allowed, telegram_config.group_allow_from, telegram_config.group_policy);
    tg.proxy = telegram_config.proxy;
    tg.account_id = telegram_config.account_id;

    // Set up transcription — key comes from providers.{audio_media.provider}
    const trans = config.audio_media;
    const whisper_ptr: ?*yc.voice.WhisperTranscriber = if (config.getProviderKey(trans.provider)) |key| blk: {
        const wt = try allocator.create(yc.voice.WhisperTranscriber);
        wt.* = .{
            .endpoint = yc.voice.resolveTranscriptionEndpoint(trans.provider, trans.base_url),
            .api_key = key,
            .model = trans.model,
            .language = trans.language,
        };
        break :blk wt;
    } else null;
    defer if (whisper_ptr) |wt| allocator.destroy(wt);
    if (whisper_ptr) |wt| tg.transcriber = wt.transcriber();

    // Initialize MCP tools from config
    const mcp_tools: ?[]const yc.tools.Tool = if (config.mcp_servers.len > 0)
        yc.mcp.initMcpTools(allocator, config.mcp_servers) catch |err| blk: {
            std.debug.print("  MCP: init failed: {}\n", .{err});
            break :blk null;
        }
    else
        null;
    defer if (mcp_tools) |mt| allocator.free(mt);

    // Build security policy from config
    const security = @import("nullclaw").security.policy;
    var tracker = security.RateTracker.init(allocator, config.autonomy.max_actions_per_hour);
    defer tracker.deinit();

    var sec_policy = security.SecurityPolicy{
        .autonomy = config.autonomy.level,
        .workspace_dir = config.workspace_dir,
        .workspace_only = config.autonomy.workspace_only,
        .allowed_commands = if (config.autonomy.allowed_commands.len > 0) config.autonomy.allowed_commands else &security.default_allowed_commands,
        .max_actions_per_hour = config.autonomy.max_actions_per_hour,
        .require_approval_for_medium_risk = config.autonomy.require_approval_for_medium_risk,
        .block_high_risk_commands = config.autonomy.block_high_risk_commands,
        .tracker = &tracker,
    };

    var subagent_manager = yc.subagent.SubagentManager.init(allocator, &config, null, .{});
    defer subagent_manager.deinit();

    // Create tools (for system prompt and tool calling)
    const tools = yc.tools.allTools(allocator, config.workspace_dir, .{
        .http_enabled = config.http_request.enabled,
        .browser_enabled = config.browser.enabled,
        .screenshot_enabled = true,
        .mcp_tools = mcp_tools,
        .agents = config.agents,
        .fallback_api_key = resolved_api_key,
        .tools_config = config.tools,
        .allowed_paths = config.autonomy.allowed_paths,
        .policy = &sec_policy,
        .subagent_manager = &subagent_manager,
    }) catch &.{};
    defer if (tools.len > 0) yc.tools.deinitTools(allocator, tools);

    if (mcp_tools) |mt| {
        std.debug.print("  MCP tools: {d}\n", .{mt.len});
    }

    // Create optional memory backend (don't fail if unavailable)
    var mem_rt = yc.memory.initRuntime(allocator, &config.memory, config.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?yc.memory.Memory = if (mem_rt) |rt| rt.memory else null;

    // Wire MemoryRuntime into tools for retrieval pipeline + vector sync
    if (mem_rt) |*rt| {
        yc.tools.bindMemoryRuntime(tools, rt);
    }

    // Create noop observer
    var noop_obs = yc.observability.NoopObserver{};
    const obs = noop_obs.observer();

    // Create provider with reliability wrapper (retry + fallback chains).
    var runtime_provider = try yc.providers.runtime_bundle.RuntimeProviderBundle.init(allocator, &config);
    defer runtime_provider.deinit();
    const provider_i: yc.providers.Provider = runtime_provider.provider();

    std.debug.print("  Tools: {d} loaded\n", .{tools.len});
    std.debug.print("  Memory: {s}\n", .{if (mem_opt != null) "enabled" else "disabled"});

    // Register bot commands in Telegram's "/" menu
    tg.setMyCommands();

    // Skip messages accumulated while bot was offline
    tg.dropPendingUpdates();

    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    var session_mgr = yc.session.SessionManager.init(allocator, &config, provider_i, tools, mem_opt, obs, if (mem_rt) |rt| rt.session_store else null, if (mem_rt) |*rt| rt.response_cache else null);
    session_mgr.policy = &sec_policy;
    if (mem_rt) |*rt| {
        session_mgr.mem_rt = rt;
    }
    defer session_mgr.deinit();

    var evict_counter: u32 = 0;

    // Bot loop: poll → full agent loop (tool calling) → reply
    while (true) {
        const messages = tg.pollUpdates(allocator) catch |err| {
            std.debug.print("Poll error: {}\n", .{err});
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        for (messages) |msg| {
            std.debug.print("[{s}] {s}: {s}\n", .{ msg.channel, msg.id, msg.content });

            // Handle /start command (Telegram-specific greeting, not sent to LLM)
            const trimmed_content = std.mem.trim(u8, msg.content, " \t\r\n");
            if (std.mem.eql(u8, trimmed_content, "/start")) {
                var greeting_buf: [512]u8 = undefined;
                const name = msg.first_name orelse msg.id;
                const greeting = std.fmt.bufPrint(&greeting_buf, "Hello, {s}! I'm nullClaw.\n\nModel: {s}\nType /help for available commands.", .{ name, model }) catch "Hello! I'm nullClaw. Type /help for commands.";
                tg.sendMessageWithReply(msg.sender, greeting, msg.message_id) catch |err| log.err("failed to send /start reply: {}", .{err});
                continue;
            }

            // Determine reply-to: always in groups, configurable in private chats
            const use_reply_to = msg.is_group or telegram_config.reply_in_private;
            const reply_to_id: ?i64 = if (use_reply_to) msg.message_id else null;

            // Session key — resolve through route engine, fallback to legacy key.
            var key_buf: [128]u8 = undefined;
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);
            const session_key = blk: {
                const route = yc.agent_routing.resolveRouteWithSession(
                    allocator,
                    .{
                        .channel = "telegram",
                        .account_id = tg.account_id,
                        .peer = .{
                            .kind = if (msg.is_group) .group else .direct,
                            .id = msg.sender,
                        },
                    },
                    config.agent_bindings,
                    config.agents,
                    config.session,
                ) catch break :blk std.fmt.bufPrint(&key_buf, "telegram:{s}:{s}", .{ tg.account_id, msg.sender }) catch msg.sender;
                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            // Start periodic typing indicator while the model is processing
            const typing_target = msg.sender;
            tg.startTyping(typing_target) catch {};
            defer tg.stopTyping(typing_target) catch {};

            const reply = session_mgr.processMessage(session_key, msg.content, null) catch |err| {
                std.debug.print("  Agent error: {}\n", .{err});
                const err_msg = switch (err) {
                    error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "Network error. Please try again.",
                    error.ProviderDoesNotSupportVision => "The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.",
                    error.NoResponseContent => "Model returned an empty response. Please retry or /new for a fresh session.",
                    error.AllProvidersFailed => "All configured providers failed for this request. Check model/provider compatibility and credentials.",
                    error.OutOfMemory => "Out of memory.",
                    else => "An error occurred. Try again or /new for a fresh session.",
                };
                tg.sendMessageWithReply(msg.sender, err_msg, reply_to_id) catch |send_err| log.err("failed to send error reply: {}", .{send_err});
                continue;
            };
            defer allocator.free(reply);

            std.debug.print("  -> {s}\n", .{reply});

            // Reply on telegram; handles [IMAGE:path] markers + split
            tg.sendMessageWithReply(msg.sender, reply, reply_to_id) catch |err| {
                std.debug.print("  Send error: {}\n", .{err});
            };
        }

        if (messages.len > 0) {
            // Free message memory
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        // Periodically evict sessions idle longer than the configured timeout
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }
    }
}

// ── Auth ─────────────────────────────────────────────────────────

fn runAuth(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    if (sub_args.len < 2) {
        printAuthUsage();
        std.process.exit(1);
    }

    const subcmd = sub_args[0];
    const provider_name = sub_args[1];
    const rest = sub_args[2..];

    // Resolve provider-specific constants
    const codex = yc.providers.openai_codex;
    const auth_mod = yc.auth;

    if (!std.mem.eql(u8, provider_name, "openai-codex")) {
        std.debug.print("Unknown auth provider: {s}\n\n", .{provider_name});
        std.debug.print("Available providers:\n", .{});
        std.debug.print("  openai-codex    ChatGPT Plus/Pro subscription (OAuth)\n", .{});
        std.process.exit(1);
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
                const remaining = token.expires_at - std.time.timestamp();
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
        std.process.exit(1);
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
            std.process.exit(1);
        }
    }

    yc.update.run(allocator, opts) catch |err| {
        std.debug.print("Update failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn printAuthUsage() void {
    std.debug.print(
        \\Usage: nullclaw auth <command> <provider> [options]
        \\
        \\Commands:
        \\  login <provider>                    Authenticate via device code flow
        \\  login <provider> --import-codex     Import from Codex CLI (~/.codex/auth.json)
        \\  status <provider>                   Show authentication status
        \\  logout <provider>                   Remove stored credentials
        \\
        \\Providers:
        \\  openai-codex    ChatGPT Plus/Pro subscription (OAuth)
        \\
        \\Examples:
        \\  nullclaw auth login openai-codex
        \\  nullclaw auth login openai-codex --import-codex
        \\  nullclaw auth status openai-codex
        \\  nullclaw auth logout openai-codex
        \\
    , .{});
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
        std.process.exit(1);
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
        std.process.exit(1);
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
        std.process.exit(1);
    };
    defer allocator.free(home);

    const path = std.fs.path.join(allocator, &.{ home, ".codex", "auth.json" }) catch {
        std.debug.print("Out of memory.\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(path);

    const file = std.fs.cwd().openFile(path, .{}) catch {
        std.debug.print("Could not open {s}\n", .{path});
        std.debug.print("Install and authenticate with Codex CLI first.\n", .{});
        std.process.exit(1);
    };
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch {
        std.debug.print("Failed to read {s}\n", .{path});
        std.process.exit(1);
    };
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch {
        std.debug.print("Failed to parse {s}\n", .{path});
        std.process.exit(1);
    };
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => {
            std.debug.print("Invalid format in {s}\n", .{path});
            std.process.exit(1);
        },
    };

    // Extract tokens object
    const tokens_val = root_obj.get("tokens") orelse {
        std.debug.print("No \"tokens\" field in {s}\n", .{path});
        std.process.exit(1);
    };
    const tokens_obj = switch (tokens_val) {
        .object => |o| o,
        else => {
            std.debug.print("Invalid \"tokens\" field in {s}\n", .{path});
            std.process.exit(1);
        },
    };

    const access_token_str = switch (tokens_obj.get("access_token") orelse {
        std.debug.print("No access_token in Codex CLI credentials.\n", .{});
        std.process.exit(1);
    }) {
        .string => |s| s,
        else => {
            std.debug.print("Invalid access_token in Codex CLI credentials.\n", .{});
            std.process.exit(1);
        },
    };

    if (access_token_str.len == 0) {
        std.debug.print("Empty access_token in Codex CLI credentials.\n", .{});
        std.process.exit(1);
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
        std.process.exit(1);
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
        const remaining = expires_at - std.time.timestamp();
        if (remaining > 0) {
            std.debug.print("  Expires in: {d}h {d}m\n", .{
                @divTrunc(remaining, 3600),
                @divTrunc(@mod(remaining, 3600), 60),
            });
        } else {
            std.debug.print("  Token: expired (will auto-refresh)\n", .{});
        }
    }
    std.debug.print("\nTo use: set \"agents.defaults.model.primary\": \"openai-codex/gpt-5.3-codex\" in ~/.nullclaw/config.json\n", .{});
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
        std.process.exit(1);
    };

    const account_id = codex.extractAccountIdFromJwt(allocator, token.access_token) catch null;
    defer if (account_id) |id| allocator.free(id);

    if (account_id) |id| {
        std.debug.print("Authenticated (account: {s})\n", .{id});
    } else {
        std.debug.print("Authenticated successfully.\n", .{});
    }
    std.debug.print("\nTo use: set \"agents.defaults.model.primary\": \"openai-codex/gpt-5.3-codex\" in ~/.nullclaw/config.json\n", .{});
}

fn printUsage() void {
    const usage =
        \\nullclaw -- The smallest AI assistant. Zig-powered.
        \\
        \\USAGE:
        \\  nullclaw <command> [options]
        \\
        \\COMMANDS:
        \\  onboard     Initialize workspace and configuration
        \\  agent       Start the AI agent loop
        \\  gateway     Start the gateway server (HTTP/WebSocket)
        \\  service     Manage OS service lifecycle (install/start/stop/status/uninstall)
        \\  status      Show system status
        \\  version     Show CLI version
        \\  doctor      Run diagnostics
        \\  cron        Manage scheduled tasks
        \\  channel     Manage channels (Telegram, Discord, Slack, ...)
        \\  skills      Manage skills
        \\  hardware    Discover and manage hardware
        \\  migrate     Migrate data from other agent runtimes
        \\  memory      Inspect and maintain memory subsystem
        \\  capabilities Show runtime capabilities manifest
        \\  models      Manage provider model catalogs
        \\  auth        Manage OAuth authentication (OpenAI Codex)
        \\  update      Check for and install updates
        \\  help        Show this help
        \\
        \\OPTIONS:
        \\  onboard [--interactive] [--api-key KEY] [--provider PROV] [--memory MEM]
        \\  agent [-m MESSAGE] [-s SESSION] [--provider PROVIDER] [--model MODEL] [--temperature TEMP]
        \\  gateway [--port PORT] [--host HOST]
        \\  version | --version | -V
        \\  service <install|start|stop|status|uninstall>
        \\  cron <list|add|once|remove|pause|resume> [ARGS]
        \\  channel <list|start|status|add|remove> [ARGS]
        \\  skills <list|install|remove> [ARGS]
        \\  hardware <discover|introspect|info> [ARGS]
        \\  migrate openclaw [--dry-run] [--source PATH]
        \\  memory <stats|count|reindex|search|get|list|drain-outbox|forget> [ARGS]
        \\  capabilities [--json]
        \\  models refresh
        \\  auth <login|status|logout> <provider> [--import-codex]
        \\  update [--check] [--yes]
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "parse known commands" {
    try std.testing.expectEqual(.agent, parseCommand("agent").?);
    try std.testing.expectEqual(.status, parseCommand("status").?);
    try std.testing.expectEqual(.version, parseCommand("version").?);
    try std.testing.expectEqual(.version, parseCommand("--version").?);
    try std.testing.expectEqual(.version, parseCommand("-V").?);
    try std.testing.expectEqual(.service, parseCommand("service").?);
    try std.testing.expectEqual(.migrate, parseCommand("migrate").?);
    try std.testing.expectEqual(.memory, parseCommand("memory").?);
    try std.testing.expectEqual(.capabilities, parseCommand("capabilities").?);
    try std.testing.expectEqual(.models, parseCommand("models").?);
    try std.testing.expectEqual(.auth, parseCommand("auth").?);
    try std.testing.expectEqual(.update, parseCommand("update").?);
    try std.testing.expect(parseCommand("daemon") == null);
    try std.testing.expect(parseCommand("unknown") == null);
}

test "parsePositiveUsize accepts only positive integers" {
    try std.testing.expectEqual(@as(?usize, 1), parsePositiveUsize("1"));
    try std.testing.expectEqual(@as(?usize, 42), parsePositiveUsize("42"));
    try std.testing.expect(parsePositiveUsize("0") == null);
    try std.testing.expect(parsePositiveUsize("-1") == null);
    try std.testing.expect(parsePositiveUsize("bad") == null);
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
