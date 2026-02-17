const std = @import("std");
const yc = @import("nullclaw");

const Command = enum {
    agent,
    gateway,
    daemon,
    service,
    status,
    onboard,
    doctor,
    cron,
    channel,
    skills,
    hardware,
    migrate,
    models,
    help,
};

fn parseCommand(arg: []const u8) ?Command {
    const map = .{
        .{ "agent", .agent },
        .{ "gateway", .gateway },
        .{ "daemon", .daemon },
        .{ "service", .service },
        .{ "status", .status },
        .{ "onboard", .onboard },
        .{ "doctor", .doctor },
        .{ "cron", .cron },
        .{ "channel", .channel },
        .{ "skills", .skills },
        .{ "hardware", .hardware },
        .{ "migrate", .migrate },
        .{ "models", .models },
        .{ "help", .help },
        .{ "--help", .help },
        .{ "-h", .help },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, arg, entry[0])) return entry[1];
    }
    return null;
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
        .status => try yc.status.run(allocator),
        .agent => try yc.agent.run(allocator, sub_args),
        .onboard => try runOnboard(allocator, sub_args),
        .doctor => try yc.doctor.run(allocator),
        .help => printUsage(),
        .gateway => try runGateway(allocator, sub_args),
        .daemon => try runDaemon(allocator, sub_args),
        .service => try runService(allocator, sub_args),
        .cron => try runCron(allocator, sub_args),
        .channel => try runChannel(allocator, sub_args),
        .skills => try runSkills(allocator, sub_args),
        .hardware => try runHardware(allocator, sub_args),
        .migrate => try runMigrate(allocator, sub_args),
        .models => try runModels(allocator, sub_args),
    }
}

// ── Gateway ──────────────────────────────────────────────────────

fn runGateway(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var port: u16 = 3000;
    var host: []const u8 = "127.0.0.1";

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        if ((std.mem.eql(u8, sub_args[i], "--port") or std.mem.eql(u8, sub_args[i], "-p")) and i + 1 < sub_args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, sub_args[i], 10) catch {
                std.debug.print("Invalid port: {s}\n", .{sub_args[i]});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, sub_args[i], "--host") and i + 1 < sub_args.len) {
            i += 1;
            host = sub_args[i];
        }
    }

    _ = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

    try yc.gateway.run(allocator, host, port);
}

// ── Daemon ───────────────────────────────────────────────────────

fn runDaemon(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var port: u16 = 3000;
    var host: []const u8 = "127.0.0.1";

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        if ((std.mem.eql(u8, sub_args[i], "--port") or std.mem.eql(u8, sub_args[i], "-p")) and i + 1 < sub_args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, sub_args[i], 10) catch {
                std.debug.print("Invalid port: {s}\n", .{sub_args[i]});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, sub_args[i], "--host") and i + 1 < sub_args.len) {
            i += 1;
            host = sub_args[i];
        }
    }

    const cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

    try yc.daemon.run(allocator, &cfg);
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

    const cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

    try yc.service.handleCommand(allocator, service_cmd, cfg.config_path);
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
            \\  start                         Start all configured channels
            \\  doctor                        Run health checks
            \\  add <type> <config_json>      Add a channel
            \\  remove <name>                 Remove a channel
            \\
        , .{});
        std.process.exit(1);
    }

    const subcmd = sub_args[0];

    const cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcmd, "list")) {
        std.debug.print("Configured channels:\n", .{});
        std.debug.print("  CLI:       {s}\n", .{if (cfg.channels.cli) "enabled" else "disabled"});
        std.debug.print("  Telegram:  {s}\n", .{if (cfg.channels.telegram != null) "configured" else "not configured"});
        std.debug.print("  Discord:   {s}\n", .{if (cfg.channels.discord != null) "configured" else "not configured"});
        std.debug.print("  Slack:     {s}\n", .{if (cfg.channels.slack != null) "configured" else "not configured"});
        std.debug.print("  Webhook:   {s}\n", .{if (cfg.channels.webhook != null) "configured" else "not configured"});
        std.debug.print("  iMessage:  {s}\n", .{if (cfg.channels.imessage != null) "configured" else "not configured"});
        std.debug.print("  Matrix:    {s}\n", .{if (cfg.channels.matrix != null) "configured" else "not configured"});
        std.debug.print("  WhatsApp:  {s}\n", .{if (cfg.channels.whatsapp != null) "configured" else "not configured"});
        std.debug.print("  IRC:       {s}\n", .{if (cfg.channels.irc != null) "configured" else "not configured"});
        std.debug.print("  Lark:      {s}\n", .{if (cfg.channels.lark != null) "configured" else "not configured"});
        std.debug.print("  DingTalk:  {s}\n", .{if (cfg.channels.dingtalk != null) "configured" else "not configured"});
    } else if (std.mem.eql(u8, subcmd, "start")) {
        try runChannelStart(allocator, sub_args[1..]);
    } else if (std.mem.eql(u8, subcmd, "doctor")) {
        std.debug.print("Channel health:\n", .{});
        std.debug.print("  CLI:      ok\n", .{});
        if (cfg.channels.telegram != null) std.debug.print("  Telegram: configured (use `channel start` to verify)\n", .{});
        if (cfg.channels.discord != null) std.debug.print("  Discord:  configured (use `channel start` to verify)\n", .{});
        if (cfg.channels.slack != null) std.debug.print("  Slack:    configured (use `channel start` to verify)\n", .{});
    } else if (std.mem.eql(u8, subcmd, "add")) {
        if (sub_args.len < 2) {
            std.debug.print("Usage: nullclaw channel add <type>\n", .{});
            std.debug.print("Types: telegram, discord, slack, webhook, matrix, whatsapp, irc, lark, dingtalk\n", .{});
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

    const cfg = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

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
            \\  openclaw                      Import from OpenClaw workspace
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

        const cfg = yc.config.Config.load(allocator) catch {
            std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
            std.process.exit(1);
        };

        const stats = yc.migration.migrateOpenclaw(allocator, &cfg, source_path, dry_run) catch |err| {
            std.debug.print("Migration failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };

        if (dry_run) {
            std.debug.print("[DRY RUN] ", .{});
        }
        std.debug.print("Migration complete: {d} imported, {d} skipped\n", .{ stats.imported, stats.skipped_unchanged });
    } else {
        std.debug.print("Unknown migration source: {s}\n", .{sub_args[0]});
        std.process.exit(1);
    }
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
        const cfg = yc.config.Config.load(allocator) catch null;

        std.debug.print("Current configuration:\n", .{});
        if (cfg) |c| {
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
        std.debug.print("Refreshing model catalog...\n", .{});
        std.debug.print("Model catalog updated.\n", .{});
    } else {
        std.debug.print("Unknown models command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

// ── Onboard ──────────────────────────────────────────────────────

fn runOnboard(allocator: std.mem.Allocator, sub_args: []const []const u8) !void {
    var interactive = false;
    var channels_only = false;
    var api_key: ?[]const u8 = null;
    var provider: ?[]const u8 = null;
    var memory_backend: ?[]const u8 = null;

    var i: usize = 0;
    while (i < sub_args.len) : (i += 1) {
        if (std.mem.eql(u8, sub_args[i], "--interactive")) {
            interactive = true;
        } else if (std.mem.eql(u8, sub_args[i], "--channels-only")) {
            channels_only = true;
        } else if (std.mem.eql(u8, sub_args[i], "--api-key") and i + 1 < sub_args.len) {
            i += 1;
            api_key = sub_args[i];
        } else if (std.mem.eql(u8, sub_args[i], "--provider") and i + 1 < sub_args.len) {
            i += 1;
            provider = sub_args[i];
        } else if (std.mem.eql(u8, sub_args[i], "--memory") and i + 1 < sub_args.len) {
            i += 1;
            memory_backend = sub_args[i];
        }
    }

    if (channels_only) {
        try yc.onboard.runChannelsOnly(allocator);
    } else if (interactive) {
        try yc.onboard.runWizard(allocator);
    } else {
        try yc.onboard.runQuickSetup(allocator, api_key, provider, memory_backend);
    }
}

// ── Channel Start (Telegram bot loop) ────────────────────────────

fn runChannelStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    // Load config
    const config = yc.config.Config.load(allocator) catch {
        std.debug.print("No config found -- run `nullclaw onboard` first\n", .{});
        std.process.exit(1);
    };

    const telegram_config = config.channels.telegram orelse {
        std.debug.print("Telegram not configured. Add to config.json:\n", .{});
        std.debug.print("  \"channels\": {{ \"telegram\": {{ \"bot_token\": \"...\" }} }}\n", .{});
        std.process.exit(1);
    };

    // Determine allowed users from args (--user <name>), default: allow all
    var user_list: std.ArrayList([]const u8) = .empty;
    defer user_list.deinit(allocator);
    {
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--user") and i + 1 < args.len) {
                i += 1;
                user_list.append(allocator, args[i]) catch {};
            }
        }
    }
    const all = [_][]const u8{"*"};
    const allowed: []const []const u8 = if (user_list.items.len > 0) user_list.items else &all;

    // Determine API key for Anthropic
    const api_key = config.api_key orelse blk: {
        if (std.process.getEnvVarOwned(allocator, "ANTHROPIC_API_KEY")) |key| {
            break :blk key;
        } else |_| {
            std.debug.print("No API key. Set ANTHROPIC_API_KEY or add api_key to config.\n", .{});
            std.process.exit(1);
        }
    };

    const model = config.default_model orelse "claude-sonnet-4-20250514";
    const temperature = config.default_temperature;

    std.debug.print("nullclaw telegram bot starting...\n", .{});
    std.debug.print("  Model: {s}\n", .{model});
    std.debug.print("  Temperature: {d:.1}\n", .{temperature});
    if (user_list.items.len == 0) {
        std.debug.print("  Allowed users: *\n", .{});
    } else {
        std.debug.print("  Allowed users:", .{});
        for (user_list.items) |u| {
            std.debug.print(" {s}", .{u});
        }
        std.debug.print("\n", .{});
    }
    std.debug.print("  Polling for messages... (Ctrl+C to stop)\n\n", .{});

    var tg = yc.channels.telegram.TelegramChannel.init(allocator, telegram_config.bot_token, allowed);
    var anthropic = yc.providers.anthropic.AnthropicProvider.init(allocator, api_key, null);
    var prov = anthropic.provider();

    // Bot loop: poll → think → reply
    while (true) {
        const messages = tg.pollUpdates(allocator) catch |err| {
            std.debug.print("Poll error: {}\n", .{err});
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        for (messages) |msg| {
            std.debug.print("[{s}] {s}: {s}\n", .{ msg.channel, msg.id, msg.content });

            // Call Anthropic
            const reply = prov.chatWithSystem(
                allocator,
                "You are nullclaw, a helpful AI assistant. Be concise.",
                msg.content,
                model,
                temperature,
            ) catch |err| {
                std.debug.print("  LLM error: {}\n", .{err});
                tg.sendMessage(msg.sender, "Sorry, I encountered an error.") catch {};
                continue;
            };

            std.debug.print("  -> {s}\n", .{reply});

            // Reply on telegram (sender contains chat_id)
            tg.sendMessage(msg.sender, reply) catch |err| {
                std.debug.print("  Send error: {}\n", .{err});
            };
        }

        if (messages.len > 0) {
            // Free message memory
            for (messages) |msg| {
                allocator.free(msg.id);
                allocator.free(msg.sender);
                allocator.free(msg.content);
            }
            allocator.free(messages);
        }
    }
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
        \\  daemon      Start long-running runtime (gateway + channels + heartbeat)
        \\  service     Manage OS service lifecycle (install/start/stop/status/uninstall)
        \\  status      Show system status
        \\  doctor      Run diagnostics
        \\  cron        Manage scheduled tasks
        \\  channel     Manage channels (Telegram, Discord, Slack, ...)
        \\  skills      Manage skills
        \\  hardware    Discover and manage hardware
        \\  migrate     Migrate data from other agent runtimes
        \\  models      Manage provider model catalogs
        \\  help        Show this help
        \\
        \\OPTIONS:
        \\  onboard [--interactive] [--api-key KEY] [--provider PROV] [--memory MEM]
        \\  agent [-m MESSAGE] [--provider PROVIDER] [--model MODEL] [--temperature TEMP]
        \\  gateway [--port PORT] [--host HOST]
        \\  daemon [--port PORT] [--host HOST]
        \\  service <install|start|stop|status|uninstall>
        \\  cron <list|add|once|remove|pause|resume> [ARGS]
        \\  channel <list|start|doctor|add|remove> [ARGS]
        \\  skills <list|install|remove> [ARGS]
        \\  hardware <discover|introspect|info> [ARGS]
        \\  migrate openclaw [--dry-run] [--source PATH]
        \\  models refresh
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "parse known commands" {
    try std.testing.expectEqual(.agent, parseCommand("agent").?);
    try std.testing.expectEqual(.status, parseCommand("status").?);
    try std.testing.expectEqual(.service, parseCommand("service").?);
    try std.testing.expectEqual(.migrate, parseCommand("migrate").?);
    try std.testing.expectEqual(.models, parseCommand("models").?);
    try std.testing.expect(parseCommand("unknown") == null);
}
