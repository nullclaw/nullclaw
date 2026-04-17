const std = @import("std");
const cron = @import("../cron.zig");
const json_util = @import("../json_util.zig");

pub fn buildIdBody(allocator: std.mem.Allocator, id: []const u8) ![]u8 {
    var body_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_buf.deinit(allocator);

    try body_buf.appendSlice(allocator, "{");
    try json_util.appendJsonKeyValue(&body_buf, allocator, "id", id);
    try body_buf.appendSlice(allocator, "}");
    return try body_buf.toOwnedSlice(allocator);
}

pub fn buildAddBody(
    allocator: std.mem.Allocator,
    expression: ?[]const u8,
    delay: ?[]const u8,
    command: ?[]const u8,
    prompt: ?[]const u8,
    model: ?[]const u8,
    delivery: ?cron.DeliveryConfig,
    session_target: ?cron.SessionTarget,
) ![]u8 {
    var body_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_buf.deinit(allocator);

    try body_buf.appendSlice(allocator, "{");
    var wrote_field = false;

    if (expression) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "expression", value);
    }
    if (delay) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "delay", value);
    }
    if (command) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "command", value);
    }
    if (prompt) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "prompt", value);
    }
    if (model) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "model", value);
    }
    if (session_target) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "session_target", value.asStr());
    }
    if (delivery) |cfg| {
        if (cfg.mode != .none) {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_mode", cfg.mode.asStr());
        }
        if (cfg.channel) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_channel", value);
        }
        if (cfg.account_id) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_account_id", value);
        }
        if (cfg.to) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_to", value);
        }
        if (cfg.peer_kind) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_peer_kind", switch (value) {
                .direct => "direct",
                .group => "group",
                .channel => "channel",
            });
        }
        if (cfg.peer_id) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_peer_id", value);
        }
        if (cfg.thread_id) |value| {
            try appendBodyField(&body_buf, allocator, &wrote_field, "delivery_thread_id", value);
        }
        if (!cfg.best_effort) {
            try appendBodyLiteral(&body_buf, allocator, &wrote_field, "\"delivery_best_effort\":false");
        }
    }

    try body_buf.appendSlice(allocator, "}");
    return try body_buf.toOwnedSlice(allocator);
}

pub fn buildUpdateBody(
    allocator: std.mem.Allocator,
    id: []const u8,
    expression: ?[]const u8,
    command: ?[]const u8,
    prompt: ?[]const u8,
    model: ?[]const u8,
    enabled: ?bool,
    session_target: ?cron.SessionTarget,
) ![]u8 {
    var body_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body_buf.deinit(allocator);

    try body_buf.appendSlice(allocator, "{");
    var wrote_field = false;

    try appendBodyField(&body_buf, allocator, &wrote_field, "id", id);
    if (expression) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "expression", value);
    }
    if (command) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "command", value);
    }
    if (prompt) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "prompt", value);
    }
    if (model) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "model", value);
    }
    if (enabled) |value| {
        try appendBodyLiteral(&body_buf, allocator, &wrote_field, if (value) "\"enabled\":true" else "\"enabled\":false");
    }
    if (session_target) |value| {
        try appendBodyField(&body_buf, allocator, &wrote_field, "session_target", value.asStr());
    }

    try body_buf.appendSlice(allocator, "}");
    return try body_buf.toOwnedSlice(allocator);
}

pub fn findJobByIdJson(allocator: std.mem.Allocator, body: []const u8, id: []const u8) !?[]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidGatewayResponse;

    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const job_id_val = item.object.get("id") orelse continue;
        if (job_id_val != .string) continue;
        if (!std.mem.eql(u8, job_id_val.string, id)) continue;
        return try std.json.Stringify.valueAlloc(allocator, item, .{});
    }

    return null;
}

fn appendBodyField(
    body_buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    wrote_field: *bool,
    key: []const u8,
    value: []const u8,
) !void {
    if (wrote_field.*) try body_buf.appendSlice(allocator, ",");
    wrote_field.* = true;
    try json_util.appendJsonKeyValue(body_buf, allocator, key, value);
}

fn appendBodyLiteral(
    body_buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    wrote_field: *bool,
    literal: []const u8,
) !void {
    if (wrote_field.*) try body_buf.appendSlice(allocator, ",");
    wrote_field.* = true;
    try body_buf.appendSlice(allocator, literal);
}

test "buildAddBody includes delivery fields" {
    const body = try buildAddBody(
        std.testing.allocator,
        "*/15 * * * *",
        null,
        "echo hello",
        null,
        null,
        .{
            .mode = .always,
            .channel = "telegram",
            .account_id = "backup",
            .to = "chat-7",
            .peer_kind = .group,
            .peer_id = "-100123",
            .thread_id = "77",
            .best_effort = false,
        },
        .main,
    );
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("*/15 * * * *", parsed.value.object.get("expression").?.string);
    try std.testing.expectEqualStrings("echo hello", parsed.value.object.get("command").?.string);
    try std.testing.expectEqualStrings("main", parsed.value.object.get("session_target").?.string);
    try std.testing.expectEqualStrings("always", parsed.value.object.get("delivery_mode").?.string);
    try std.testing.expectEqualStrings("telegram", parsed.value.object.get("delivery_channel").?.string);
    try std.testing.expectEqualStrings("backup", parsed.value.object.get("delivery_account_id").?.string);
    try std.testing.expectEqualStrings("chat-7", parsed.value.object.get("delivery_to").?.string);
    try std.testing.expectEqualStrings("group", parsed.value.object.get("delivery_peer_kind").?.string);
    try std.testing.expectEqualStrings("-100123", parsed.value.object.get("delivery_peer_id").?.string);
    try std.testing.expectEqualStrings("77", parsed.value.object.get("delivery_thread_id").?.string);
    try std.testing.expect(!parsed.value.object.get("delivery_best_effort").?.bool);
}

test "buildUpdateBody includes enabled flag" {
    const body = try buildUpdateBody(std.testing.allocator, "job-9", "*/5 * * * *", "echo updated", null, null, false, .main);
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("job-9", parsed.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("*/5 * * * *", parsed.value.object.get("expression").?.string);
    try std.testing.expectEqualStrings("echo updated", parsed.value.object.get("command").?.string);
    try std.testing.expect(!parsed.value.object.get("enabled").?.bool);
    try std.testing.expectEqualStrings("main", parsed.value.object.get("session_target").?.string);
}

test "findJobByIdJson returns matching job object" {
    const body =
        \\[
        \\  {"id":"job-1","command":"echo first"},
        \\  {"id":"job-2","command":"echo second"}
        \\]
    ;
    const job_json = (try findJobByIdJson(std.testing.allocator, body, "job-2")).?;
    defer std.testing.allocator.free(job_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, job_json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("job-2", parsed.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("echo second", parsed.value.object.get("command").?.string);
}
