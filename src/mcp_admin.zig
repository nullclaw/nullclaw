const std = @import("std");
const builtin = @import("builtin");
const config_types = @import("config_types.zig");
const json_util = @import("json_util.zig");
const mcp = @import("mcp.zig");

const McpServerConfig = config_types.McpServerConfig;

fn appendStringArray(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, items: []const []const u8) !void {
    try buf.appendSlice(allocator, "[");
    for (items, 0..) |item, idx| {
        if (idx > 0) try buf.appendSlice(allocator, ",");
        try json_util.appendJsonString(buf, allocator, item);
    }
    try buf.appendSlice(allocator, "]");
}

fn appendServerSummary(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    server: McpServerConfig,
    tool_count: ?usize,
) !void {
    try buf.appendSlice(allocator, "{");
    try json_util.appendJsonKeyValue(buf, allocator, "name", server.name);
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKeyValue(buf, allocator, "transport", server.transport);
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKeyValue(buf, allocator, "command", server.command);
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(buf, allocator, "url");
    if (server.url) |url| {
        try json_util.appendJsonString(buf, allocator, url);
    } else {
        try buf.appendSlice(allocator, "null");
    }
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonInt(buf, allocator, "args_count", @intCast(server.args.len));
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(buf, allocator, "env_keys");
    if (server.env.len == 0) {
        try buf.appendSlice(allocator, "[]");
    } else {
        var env_keys = try allocator.alloc([]const u8, server.env.len);
        defer allocator.free(env_keys);
        for (server.env, 0..) |entry, idx| env_keys[idx] = entry.key;
        try appendStringArray(buf, allocator, env_keys);
    }
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(buf, allocator, "header_names");
    if (server.headers.len == 0) {
        try buf.appendSlice(allocator, "[]");
    } else {
        var header_names = try allocator.alloc([]const u8, server.headers.len);
        defer allocator.free(header_names);
        for (server.headers, 0..) |entry, idx| header_names[idx] = entry.key;
        try appendStringArray(buf, allocator, header_names);
    }
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonInt(buf, allocator, "timeout_ms", server.timeout_ms);
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(buf, allocator, "tool_count");
    if (tool_count) |count| {
        var int_buf: [24]u8 = undefined;
        const count_text = std.fmt.bufPrint(&int_buf, "{d}", .{count}) catch unreachable;
        try buf.appendSlice(allocator, count_text);
    } else {
        try buf.appendSlice(allocator, "null");
    }
    try buf.appendSlice(allocator, "}");
}

fn freeToolDefs(allocator: std.mem.Allocator, defs: []const mcp.McpToolDef) void {
    for (defs) |tool| {
        allocator.free(tool.name);
        allocator.free(tool.description);
        allocator.free(tool.input_schema);
    }
    allocator.free(defs);
}

fn inspectToolCount(allocator: std.mem.Allocator, server_cfg: McpServerConfig) ?usize {
    if (builtin.is_test) return null;

    var client = mcp.McpServer.init(allocator, server_cfg);
    defer client.deinit();

    client.connect() catch return null;
    const defs = client.listTools() catch return null;
    defer freeToolDefs(allocator, defs);
    return defs.len;
}

pub fn buildServersJson(allocator: std.mem.Allocator, servers: []const McpServerConfig) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[");
    for (servers, 0..) |server, idx| {
        if (idx > 0) try buf.appendSlice(allocator, ",");
        try appendServerSummary(&buf, allocator, server, null);
    }
    try buf.appendSlice(allocator, "]");
    return try buf.toOwnedSlice(allocator);
}

pub fn buildServerJson(allocator: std.mem.Allocator, servers: []const McpServerConfig, name: []const u8) !?[]u8 {
    for (servers) |server| {
        if (!std.mem.eql(u8, server.name, name)) continue;

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try appendServerSummary(&buf, allocator, server, inspectToolCount(allocator, server));
        if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '}') {
            buf.items.len -= 1;
        }
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKey(&buf, allocator, "args");
        try appendStringArray(&buf, allocator, server.args);
        try buf.appendSlice(allocator, "}");
        return try buf.toOwnedSlice(allocator);
    }
    return null;
}

test "buildServersJson redacts env values and preserves names" {
    const allocator = std.testing.allocator;
    const env = [_]McpServerConfig.McpEnvEntry{
        .{ .key = "OPENROUTER_API_KEY", .value = "secret" },
    };
    const headers = [_]McpServerConfig.McpHeaderEntry{
        .{ .key = "Authorization", .value = "Bearer secret" },
    };
    const servers = [_]McpServerConfig{
        .{
            .name = "context7",
            .transport = "stdio",
            .command = "npx",
            .args = &.{ "-y", "@upstash/context7-mcp" },
            .env = &env,
            .headers = &headers,
            .timeout_ms = 12_000,
        },
    };

    const json = try buildServersJson(allocator, &servers);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"context7\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"env_keys\":[\"OPENROUTER_API_KEY\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"header_names\":[\"Authorization\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "secret") == null);
}

test "buildServerJson includes full args for one server" {
    const allocator = std.testing.allocator;
    const servers = [_]McpServerConfig{
        .{
            .name = "context7",
            .transport = "stdio",
            .command = "npx",
            .args = &.{ "-y", "@upstash/context7-mcp" },
        },
    };

    const json = (try buildServerJson(allocator, &servers, "context7")).?;
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"args\":[\"-y\",\"@upstash/context7-mcp\"]") != null);
}

test "appendServerSummary serializes tool_count when known" {
    const allocator = std.testing.allocator;
    const server = McpServerConfig{
        .name = "context7",
        .transport = "stdio",
        .command = "npx",
        .args = &.{ "-y", "@upstash/context7-mcp" },
    };

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try appendServerSummary(&buf, allocator, server, 3);

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"tool_count\":3") != null);
}
