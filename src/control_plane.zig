const std = @import("std");

pub const SlashCommand = struct {
    name: []const u8,
    arg: []const u8,
};

pub const TelegramBotCommandScope = enum {
    default,
    all_private_chats,
    all_group_chats,
};

pub const TelegramBotCommandOptions = struct {
    scope: TelegramBotCommandScope = .default,
    include_bind_command: bool = true,
    include_topic_command: bool = true,
    include_topics_command: bool = true,
};

pub const HELP_TEXT =
    \\Available commands:
    \\
    \\Session:
    \\  /menu, /help, /commands
    \\  /new, /reset [model], /restart [model]
    \\  /status, /whoami, /id, /compact
    \\  /stop, /abort
    \\
    \\Model and output:
    \\  /model, /models, /model <name>, /model auto
    \\  /think, /verbose, /reasoning
    \\  /exec, /queue, /usage, /tts, /voice
    \\
    \\Memory and diagnostics:
    \\  /doctor — memory subsystem diagnostics
    \\  /memory <stats|status|reindex|count|search|get|list|drain-outbox>
    \\  /export-session, /export
    \\  /session ttl <duration|off>
    \\  /config, /capabilities, /debug
    \\
    \\Tasks and agents:
    \\  /subagents, /tasks, /agents, /poll, /focus, /unfocus, /kill, /steer, /tell
    \\  /bind <agent|clear|status>
    \\
    \\Access and integrations:
    \\  /allowlist, /approve, /context
    \\  /dock-telegram, /dock-discord, /dock-slack
    \\  /activation, /send, /elevated, /bash, /skill
    \\
    \\Telegram forums (if enabled):
    \\  /topic <name>, /topics, /topic-map
    \\
    \\  exit, quit
;

const TelegramBotCommand = struct {
    command: []const u8,
    description: []const u8,
};

const PRIMARY_TELEGRAM_BOT_COMMANDS = [_]TelegramBotCommand{
    .{ .command = "start", .description = "Start a conversation" },
    .{ .command = "menu", .description = "Show grouped command menu" },
    .{ .command = "new", .description = "Clear history, start fresh" },
    .{ .command = "status", .description = "Show model and stats" },
    .{ .command = "whoami", .description = "Show current session id" },
    .{ .command = "model", .description = "Switch model" },
    .{ .command = "think", .description = "Set thinking level" },
    .{ .command = "verbose", .description = "Set verbose level" },
    .{ .command = "reasoning", .description = "Set reasoning output" },
    .{ .command = "exec", .description = "Set exec policy" },
    .{ .command = "allowlist", .description = "Show allowlist" },
    .{ .command = "queue", .description = "Set queue policy" },
    .{ .command = "usage", .description = "Set usage footer mode" },
    .{ .command = "tts", .description = "Set TTS mode" },
    .{ .command = "memory", .description = "Memory tools and diagnostics" },
    .{ .command = "skill", .description = "List skills" },
    .{ .command = "doctor", .description = "Memory diagnostics quick check" },
    .{ .command = "tasks", .description = "List background tasks" },
    .{ .command = "agents", .description = "Show active agents" },
    .{ .command = "bind", .description = "Bind current chat to an agent" },
    .{ .command = "poll", .description = "Show pending tasks and approvals" },
    .{ .command = "stop", .description = "Stop active background task" },
    .{ .command = "restart", .description = "Restart current session" },
    .{ .command = "compact", .description = "Compact context now" },
};

const TOPIC_TELEGRAM_BOT_COMMAND = TelegramBotCommand{
    .command = "topic",
    .description = "Create forum topic",
};

const TOPICS_TELEGRAM_BOT_COMMAND = TelegramBotCommand{
    .command = "topics",
    .description = "Show topic session map",
};

fn appendTelegramBotCommand(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    cmd: TelegramBotCommand,
    first: bool,
) !void {
    if (!first) try out.appendSlice(allocator, ",");
    try out.appendSlice(allocator, "{\"command\":\"");
    try out.appendSlice(allocator, cmd.command);
    try out.appendSlice(allocator, "\",\"description\":\"");
    try out.appendSlice(allocator, cmd.description);
    try out.appendSlice(allocator, "\"}");
}

fn appendTelegramBotCommandScope(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    scope: TelegramBotCommandScope,
) !void {
    switch (scope) {
        .default => try out.appendSlice(allocator, "{\"type\":\"default\"}"),
        .all_private_chats => try out.appendSlice(allocator, "{\"type\":\"all_private_chats\"}"),
        .all_group_chats => try out.appendSlice(allocator, "{\"type\":\"all_group_chats\"}"),
    }
}

pub fn buildTelegramBotCommandsJson(
    allocator: std.mem.Allocator,
    opts: TelegramBotCommandOptions,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"commands\":[");
    var first = true;
    for (PRIMARY_TELEGRAM_BOT_COMMANDS) |cmd| {
        if (!opts.include_bind_command and std.mem.eql(u8, cmd.command, "bind")) continue;
        try appendTelegramBotCommand(&out, allocator, cmd, first);
        first = false;
    }
    const include_topic_command = opts.scope != .all_private_chats and opts.include_topic_command;
    const include_topics_command = opts.scope != .all_private_chats and opts.include_topics_command;
    if (include_topic_command) {
        try appendTelegramBotCommand(&out, allocator, TOPIC_TELEGRAM_BOT_COMMAND, first);
        first = false;
    }
    if (include_topics_command) {
        try appendTelegramBotCommand(&out, allocator, TOPICS_TELEGRAM_BOT_COMMAND, first);
    }
    try out.appendSlice(allocator, "],\"scope\":");
    try appendTelegramBotCommandScope(&out, allocator, opts.scope);
    try out.appendSlice(allocator, "}");
    return try out.toOwnedSlice(allocator);
}

pub fn buildTelegramDeleteBotCommandsJson(
    allocator: std.mem.Allocator,
    scope: TelegramBotCommandScope,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"scope\":");
    try appendTelegramBotCommandScope(&out, allocator, scope);
    try out.appendSlice(allocator, "}");
    return try out.toOwnedSlice(allocator);
}

pub fn parseSlashCommand(message: []const u8) ?SlashCommand {
    const trimmed = std.mem.trim(u8, message, " \t\r\n");
    if (trimmed.len <= 1 or trimmed[0] != '/') return null;

    const body = trimmed[1..];
    var split_idx: usize = 0;
    while (split_idx < body.len) : (split_idx += 1) {
        const ch = body[split_idx];
        if (ch == ':' or ch == ' ' or ch == '\t') break;
    }
    if (split_idx == 0) return null;

    const raw_name = body[0..split_idx];
    const name = slashCommandName(raw_name);
    if (name.len == 0) return null;

    var rest = body[split_idx..];
    if (rest.len > 0 and rest[0] == ':') {
        rest = rest[1..];
    }

    return .{
        .name = name,
        .arg = std.mem.trim(u8, rest, " \t"),
    };
}

pub fn isSlashName(cmd: SlashCommand, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(cmd.name, expected);
}

pub fn isStopCommandName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "stop") or std.ascii.eqlIgnoreCase(name, "abort");
}

pub fn isStopLikeCommand(content: []const u8) bool {
    const cmd = parseSlashCommand(content) orelse return false;
    return isStopCommandName(cmd.name);
}

fn slashCommandName(raw_name: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, raw_name, '@')) |mention_sep|
        raw_name[0..mention_sep]
    else
        raw_name;
}

test "parseSlashCommand strips bot mention from command name" {
    const parsed = parseSlashCommand("/model@nullclaw_bot openrouter/inception/mercury") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("model", parsed.name);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", parsed.arg);
}

test "parseSlashCommand strips bot mention with colon separator" {
    const parsed = parseSlashCommand("/model@nullclaw_bot: gpt-5.2") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("model", parsed.name);
    try std.testing.expectEqualStrings("gpt-5.2", parsed.arg);
}

test "isStopLikeCommand matches stop and abort variants" {
    try std.testing.expect(isStopLikeCommand("/stop"));
    try std.testing.expect(isStopLikeCommand("  /stop  "));
    try std.testing.expect(isStopLikeCommand("/abort"));
    try std.testing.expect(isStopLikeCommand("/STOP"));
    try std.testing.expect(isStopLikeCommand("/abort@nullclaw_bot"));
    try std.testing.expect(isStopLikeCommand("/stop: now"));
    try std.testing.expect(isStopLikeCommand("/abort please"));
}

test "isStopLikeCommand rejects non-control commands" {
    try std.testing.expect(!isStopLikeCommand("stop"));
    try std.testing.expect(!isStopLikeCommand("/stopping"));
    try std.testing.expect(!isStopLikeCommand("/aborted"));
    try std.testing.expect(!isStopLikeCommand("/help"));
    try std.testing.expect(!isStopLikeCommand(""));
}

test "telegram bot command payload includes grouped menu commands" {
    const json = try buildTelegramBotCommandsJson(std.testing.allocator, .{});
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"allowlist\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"skill\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"doctor\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"tasks\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"bind\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"poll\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topic\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topics\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"scope\":{\"type\":\"default\"}") != null);
}

test "buildTelegramBotCommandsJson omits topic commands when disabled" {
    const json = try buildTelegramBotCommandsJson(std.testing.allocator, .{
        .include_topic_command = false,
        .include_topics_command = false,
    });
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topic\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topics\"") == null);
}

test "buildTelegramBotCommandsJson omits bind command when disabled" {
    const json = try buildTelegramBotCommandsJson(std.testing.allocator, .{
        .include_bind_command = false,
    });
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"bind\"") == null);
}

test "buildTelegramBotCommandsJson omits topic commands in private scope" {
    const json = try buildTelegramBotCommandsJson(std.testing.allocator, .{
        .scope = .all_private_chats,
        .include_topic_command = true,
        .include_topics_command = true,
    });
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"scope\":{\"type\":\"all_private_chats\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topic\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"topics\"") == null);
}

test "buildTelegramDeleteBotCommandsJson includes scope" {
    const json = try buildTelegramDeleteBotCommandsJson(std.testing.allocator, .all_group_chats);
    defer std.testing.allocator.free(json);

    try std.testing.expectEqualStrings("{\"scope\":{\"type\":\"all_group_chats\"}}", json);
}
