const std = @import("std");

pub const SlashCommand = struct {
    name: []const u8,
    arg: []const u8,
};

pub const HELP_TEXT =
    \\Available commands:
    \\  /new, /reset [model], /restart [model]
    \\  /help, /commands, /status, /whoami, /id
    \\  /model, /models, /model <name>, /model auto
    \\  /think, /verbose, /reasoning
    \\  /exec, /queue, /usage, /tts, /voice
    \\  /stop, /abort, /compact
    \\  /allowlist, /approve, /context
    \\  /export-session, /export
    \\  /session ttl <duration|off>
    \\  /subagents, /agents, /focus, /unfocus, /kill, /steer, /tell
    \\  /config, /capabilities, /debug
    \\  /dock-telegram, /dock-discord, /dock-slack
    \\  /activation, /send, /elevated, /bash, /poll, /skill
    \\  /doctor — memory subsystem diagnostics
    \\  /memory <stats|status|reindex|count|search|get|list|drain-outbox>
    \\  /tool-customizations, /tools — show tool customizations (read-only)
    \\  exit, quit
;

pub const TELEGRAM_BOT_COMMANDS_JSON =
    \\{"commands":[
    \\{"command":"start","description":"Start a conversation"},
    \\{"command":"new","description":"Clear history, start fresh"},
    \\{"command":"reset","description":"Alias for /new"},
    \\{"command":"help","description":"Show available commands"},
    \\{"command":"commands","description":"Alias for /help"},
    \\{"command":"status","description":"Show model and stats"},
    \\{"command":"whoami","description":"Show current session id"},
    \\{"command":"model","description":"Switch model"},
    \\{"command":"models","description":"Alias for /model"},
    \\{"command":"think","description":"Set thinking level"},
    \\{"command":"verbose","description":"Set verbose level"},
    \\{"command":"reasoning","description":"Set reasoning output"},
    \\{"command":"exec","description":"Set exec policy"},
    \\{"command":"queue","description":"Set queue policy"},
    \\{"command":"usage","description":"Set usage footer mode"},
    \\{"command":"tts","description":"Set TTS mode"},
    \\{"command":"memory","description":"Memory tools and diagnostics"},
    \\{"command":"doctor","description":"Memory diagnostics quick check"},
    \\{"command":"tool-customizations","description":"Show tool customizations (read-only)"},
    \\{"command":"tools","description":"Alias for /tool-customizations"},
    \\{"command":"stop","description":"Stop active background task"},
    \\{"command":"restart","description":"Restart current session"},
    \\{"command":"compact","description":"Compact context now"}
    \\]}
;

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

test "telegram bot command payload includes memory and doctor commands" {
    try std.testing.expect(std.mem.indexOf(u8, TELEGRAM_BOT_COMMANDS_JSON, "\"command\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, TELEGRAM_BOT_COMMANDS_JSON, "\"command\":\"doctor\"") != null);
}
