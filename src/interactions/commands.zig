const std = @import("std");

const TelegramCommand = struct {
    command: []const u8,
    description: []const u8,
};

pub const TelegramCommandCatalogOptions = struct {
    include_bind_command: bool = true,
    include_topic_command: bool = true,
    include_topics_command: bool = true,
};

const primary_telegram_commands = [_]TelegramCommand{
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

const topic_telegram_command = TelegramCommand{
    .command = "topic",
    .description = "Create forum topic",
};

const topics_telegram_command = TelegramCommand{
    .command = "topics",
    .description = "Show topic session map",
};

fn appendTelegramCommandJson(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    cmd: TelegramCommand,
    first: *bool,
) !void {
    if (!first.*) try out.appendSlice(allocator, ",");
    first.* = false;
    try out.appendSlice(allocator, "{\"command\":\"");
    try out.appendSlice(allocator, cmd.command);
    try out.appendSlice(allocator, "\",\"description\":\"");
    try out.appendSlice(allocator, cmd.description);
    try out.appendSlice(allocator, "\"}");
}

pub fn appendTelegramCommandCatalogJson(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    opts: TelegramCommandCatalogOptions,
) !void {
    var first = true;
    for (primary_telegram_commands) |cmd| {
        if (!opts.include_bind_command and std.mem.eql(u8, cmd.command, "bind")) continue;
        try appendTelegramCommandJson(out, allocator, cmd, &first);
    }
    if (opts.include_topic_command) {
        try appendTelegramCommandJson(out, allocator, topic_telegram_command, &first);
    }
    if (opts.include_topics_command) {
        try appendTelegramCommandJson(out, allocator, topics_telegram_command, &first);
    }
}

test "telegram command catalog appends grouped commands" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try appendTelegramCommandCatalogJson(&out, std.testing.allocator, .{});

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"bind\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"topic\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"topics\"") != null);
}

test "telegram command catalog filters optional commands" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try appendTelegramCommandCatalogJson(&out, std.testing.allocator, .{
        .include_bind_command = false,
        .include_topic_command = false,
        .include_topics_command = false,
    });

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"menu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"bind\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"topic\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"command\":\"topics\"") == null);
}

test "telegram command catalog command names stay unique" {
    for (primary_telegram_commands, 0..) |cmd, i| {
        for (primary_telegram_commands[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, cmd.command, other.command));
        }
        try std.testing.expect(!std.mem.eql(u8, cmd.command, topic_telegram_command.command));
        try std.testing.expect(!std.mem.eql(u8, cmd.command, topics_telegram_command.command));
    }
    try std.testing.expect(!std.mem.eql(u8, topic_telegram_command.command, topics_telegram_command.command));
}
