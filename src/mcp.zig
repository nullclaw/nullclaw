//! MCP (Model Context Protocol) — stdio transport client.
//!
//! Spawns external tool servers as child processes, communicates via
//! JSON-RPC 2.0 over newline-delimited stdio. Wraps discovered tools
//! into the standard Tool vtable so the agent can call them like any
//! built-in tool.

const std = @import("std");
const tools_mod = @import("tools/root.zig");
const config_mod = @import("config.zig");
const yc = @import("root.zig");
const ver = @import("version.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.mcp);

pub const McpServerConfig = config_mod.McpServerConfig;

// ── Tool definition from server ─────────────────────────────────

pub const McpToolDef = struct {
    name: []const u8,
    description: []const u8,
    input_schema: []const u8,
};

// ── McpServer — child process lifecycle ─────────────────────────

pub const McpServer = struct {
    allocator: Allocator,
    name: []const u8,
    config: McpServerConfig,
    child: ?std.process.Child,
    next_id: u32,

    pub fn init(allocator: Allocator, config: McpServerConfig) McpServer {
        return .{
            .allocator = allocator,
            .name = config.name,
            .config = config,
            .child = null,
            .next_id = 1,
        };
    }

    /// Spawn child process and perform the MCP initialize handshake.
    pub fn connect(self: *McpServer) !void {
        // Build argv: command + args
        var argv_list: std.ArrayList([]const u8) = .{};
        defer argv_list.deinit(self.allocator);
        try argv_list.append(self.allocator, self.config.command);
        for (self.config.args) |a| {
            try argv_list.append(self.allocator, a);
        }

        var child = std.process.Child.init(argv_list.items, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        // Build environment: inherit parent + config overrides
        var env = std.process.EnvMap.init(self.allocator);
        // Add PATH, HOME, etc. from parent
        const inherit_vars = [_][]const u8{
            "PATH", "HOME",  "TERM",   "LANG",      "LC_ALL",            "LC_CTYPE",
            "USER", "SHELL", "TMPDIR", "NODE_PATH", "NPM_CONFIG_PREFIX",
        };
        for (&inherit_vars) |key| {
            if (std.posix.getenv(key)) |val| {
                try env.put(key, val);
            }
        }
        // Config env overrides
        for (self.config.env) |entry| {
            try env.put(entry.key, entry.value);
        }
        child.env_map = &env;

        try child.spawn();
        self.child = child;

        // Send initialize request
        const init_params = try std.fmt.allocPrint(
            self.allocator,
            "{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"nullclaw\",\"version\":\"{s}\"}}}}",
            .{ver.string},
        );
        defer self.allocator.free(init_params);

        const init_resp = try self.sendRequest(self.allocator, "initialize", init_params);
        defer self.allocator.free(init_resp);

        // Verify we got a valid response (has protocolVersion in result)
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, init_resp, .{}) catch
            return error.InvalidHandshake;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidHandshake;
        const result = parsed.value.object.get("result") orelse return error.InvalidHandshake;
        if (result != .object) return error.InvalidHandshake;
        _ = result.object.get("protocolVersion") orelse return error.InvalidHandshake;

        // Send initialized notification (no id, no response expected)
        try self.sendNotification("notifications/initialized", null);
    }

    /// Request the list of tools from the MCP server.
    pub fn listTools(self: *McpServer) ![]McpToolDef {
        const resp = try self.sendRequest(self.allocator, "tools/list", "{}");
        defer self.allocator.free(resp);
        return try parseToolsListResponse(self.allocator, resp);
    }

    /// Call a specific tool on the MCP server.
    pub fn callTool(self: *McpServer, tool_name: []const u8, args_json: []const u8) ![]const u8 {
        // Build params: {"name": "...", "arguments": ...}
        // Use proper JSON escaping for tool_name to prevent injection.
        var params_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer params_buf.deinit(self.allocator);
        try params_buf.appendSlice(self.allocator, "{\"name\":");
        try yc.json_util.appendJsonString(&params_buf, self.allocator, tool_name);
        try params_buf.appendSlice(self.allocator, ",\"arguments\":");
        try params_buf.appendSlice(self.allocator, args_json);
        try params_buf.append(self.allocator, '}');

        const resp = try self.sendRequest(self.allocator, "tools/call", params_buf.items);
        defer self.allocator.free(resp);
        return try parseCallToolResponse(self.allocator, resp);
    }

    pub fn deinit(self: *McpServer) void {
        if (self.child) |*child| {
            // Close stdin to signal the server to exit
            if (child.stdin) |stdin| {
                stdin.close();
                child.stdin = null;
            }
            _ = child.kill() catch {};
            _ = child.wait() catch {};
        }
        self.child = null;
    }

    // ── Internal I/O ────────────────────────────────────────────

    fn sendRequest(self: *McpServer, allocator: Allocator, method: []const u8, params: ?[]const u8) ![]const u8 {
        const id = self.next_id;
        self.next_id += 1;

        const msg = if (params) |p|
            try std.fmt.allocPrint(allocator,
                \\{{"jsonrpc":"2.0","id":{d},"method":"{s}","params":{s}}}
            ++ "\n", .{ id, method, p })
        else
            try std.fmt.allocPrint(allocator,
                \\{{"jsonrpc":"2.0","id":{d},"method":"{s}"}}
            ++ "\n", .{ id, method });
        defer allocator.free(msg);

        const stdin = self.child.?.stdin orelse return error.NoStdin;
        try stdin.writeAll(msg);

        return try self.readLine(allocator);
    }

    fn sendNotification(self: *McpServer, method: []const u8, params: ?[]const u8) !void {
        const msg = if (params) |p|
            try std.fmt.allocPrint(self.allocator,
                \\{{"jsonrpc":"2.0","method":"{s}","params":{s}}}
            ++ "\n", .{ method, p })
        else
            try std.fmt.allocPrint(self.allocator,
                \\{{"jsonrpc":"2.0","method":"{s}"}}
            ++ "\n", .{method});
        defer self.allocator.free(msg);

        const stdin = self.child.?.stdin orelse return error.NoStdin;
        try stdin.writeAll(msg);
    }

    fn readLine(self: *McpServer, allocator: Allocator) ![]const u8 {
        var line_buf: std.ArrayList(u8) = .{};
        errdefer line_buf.deinit(allocator);
        var byte: [1]u8 = undefined;
        const stdout = self.child.?.stdout orelse return error.NoStdout;
        while (true) {
            const n = stdout.read(&byte) catch return error.ReadFailed;
            if (n == 0) return error.EndOfStream;
            if (byte[0] == '\n') break;
            if (byte[0] != '\r') { // skip CR
                try line_buf.append(allocator, byte[0]);
            }
        }
        if (line_buf.items.len == 0) return error.EmptyLine;
        return line_buf.toOwnedSlice(allocator);
    }
};

// ── Response parsers ────────────────────────────────────────────

pub fn parseToolsListResponse(allocator: Allocator, resp: []const u8) ![]McpToolDef {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch
        return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;

    // Check for JSON-RPC error
    if (parsed.value.object.get("error")) |_| return error.JsonRpcError;

    const result = parsed.value.object.get("result") orelse return error.MissingResult;
    if (result != .object) return error.InvalidJson;

    const tools_val = result.object.get("tools") orelse return error.MissingResult;
    if (tools_val != .array) return error.InvalidJson;

    var list: std.ArrayList(McpToolDef) = .{};
    errdefer list.deinit(allocator);

    for (tools_val.array.items) |item| {
        if (item != .object) continue;
        const name_val = item.object.get("name") orelse continue;
        if (name_val != .string) continue;

        const desc_val = item.object.get("description");
        const desc = if (desc_val) |d| (if (d == .string) d.string else "") else "";

        // Serialize inputSchema back to JSON string
        const schema_val = item.object.get("inputSchema");
        const schema_str = if (schema_val) |s| blk: {
            break :blk try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(s, .{})});
        } else "{}";

        try list.append(allocator, .{
            .name = try allocator.dupe(u8, name_val.string),
            .description = try allocator.dupe(u8, desc),
            .input_schema = schema_str,
        });
    }

    return list.toOwnedSlice(allocator);
}

pub fn parseCallToolResponse(allocator: Allocator, resp: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch
        return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;

    // Check for JSON-RPC error
    if (parsed.value.object.get("error")) |err_val| {
        if (err_val == .object) {
            if (err_val.object.get("message")) |msg| {
                if (msg == .string) return error.JsonRpcError;
            }
        }
        return error.JsonRpcError;
    }

    const result = parsed.value.object.get("result") orelse return error.MissingResult;
    if (result != .object) return error.InvalidJson;

    const content = result.object.get("content") orelse return error.MissingResult;
    if (content != .array) return error.InvalidJson;

    // Collect all text content
    var output: std.ArrayList(u8) = .{};
    errdefer output.deinit(allocator);

    for (content.array.items) |item| {
        if (item != .object) continue;
        const text_val = item.object.get("text") orelse continue;
        if (text_val != .string) continue;
        if (output.items.len > 0) {
            try output.append(allocator, '\n');
        }
        try output.appendSlice(allocator, text_val.string);
    }

    return output.toOwnedSlice(allocator);
}

// ── McpToolWrapper — adapts MCP tool to Tool vtable ─────────────

pub const McpToolWrapper = struct {
    server: *McpServer,
    original_name: []const u8,
    prefixed_name: []const u8,
    desc: []const u8,
    params_json: []const u8,

    const vtable = tools_mod.Tool.VTable{
        .execute = &executeImpl,
        .name = &nameImpl,
        .description = &descImpl,
        .parameters_json = &paramsImpl,
    };

    pub fn tool(self: *McpToolWrapper) tools_mod.Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn executeImpl(ptr: *anyopaque, allocator: Allocator, args: tools_mod.JsonObjectMap) anyerror!tools_mod.ToolResult {
        const self: *McpToolWrapper = @ptrCast(@alignCast(ptr));
        // Re-serialize ObjectMap to JSON string for MCP protocol
        const json_val = std.json.Value{ .object = args };
        const args_json = std.json.Stringify.valueAlloc(allocator, json_val, .{}) catch
            return tools_mod.ToolResult.fail("Failed to serialize tool arguments");
        defer allocator.free(args_json);
        const output = self.server.callTool(self.original_name, args_json) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "MCP tool '{s}' failed: {}", .{ self.original_name, err }) catch
                return tools_mod.ToolResult.fail("MCP tool call failed");
            return tools_mod.ToolResult.fail(msg);
        };
        return tools_mod.ToolResult.ok(output);
    }

    fn nameImpl(ptr: *anyopaque) []const u8 {
        const self: *McpToolWrapper = @ptrCast(@alignCast(ptr));
        return self.prefixed_name;
    }

    fn descImpl(ptr: *anyopaque) []const u8 {
        const self: *McpToolWrapper = @ptrCast(@alignCast(ptr));
        return self.desc;
    }

    fn paramsImpl(ptr: *anyopaque) []const u8 {
        const self: *McpToolWrapper = @ptrCast(@alignCast(ptr));
        return self.params_json;
    }
};

// ── Top-level init ──────────────────────────────────────────────

/// Initialize MCP tools from config. Connects to each server, discovers
/// tools, and returns them wrapped in the standard Tool vtable.
/// Errors from individual servers are logged and skipped.
pub fn initMcpTools(allocator: Allocator, configs: []const McpServerConfig) ![]tools_mod.Tool {
    var all_tools: std.ArrayList(tools_mod.Tool) = .{};
    errdefer all_tools.deinit(allocator);

    for (configs) |cfg| {
        var server = try allocator.create(McpServer);
        server.* = McpServer.init(allocator, cfg);

        server.connect() catch |err| {
            log.err("MCP server '{s}': connect failed: {}", .{ cfg.name, err });
            allocator.destroy(server);
            continue;
        };

        const tool_defs = server.listTools() catch |err| {
            log.err("MCP server '{s}': tools/list failed: {}", .{ cfg.name, err });
            server.deinit();
            allocator.destroy(server);
            continue;
        };

        for (tool_defs) |td| {
            var wrapper = try allocator.create(McpToolWrapper);
            errdefer allocator.destroy(wrapper);
            const prefixed_name = try std.fmt.allocPrint(allocator, "mcp_{s}_{s}", .{ cfg.name, td.name });
            errdefer allocator.free(prefixed_name);
            wrapper.* = .{
                .server = server,
                .original_name = td.name,
                .prefixed_name = prefixed_name,
                .desc = td.description,
                .params_json = td.input_schema,
            };
            try all_tools.append(allocator, wrapper.tool());
        }

        log.info("MCP server '{s}': {d} tools registered", .{ cfg.name, tool_defs.len });
    }

    return all_tools.toOwnedSlice(allocator);
}

// ── Tests ───────────────────────────────────────────────────────

test "McpServer init fields" {
    const cfg = McpServerConfig{
        .name = "test-server",
        .command = "/usr/bin/echo",
        .args = &.{"hello"},
        .env = &.{.{ .key = "FOO", .value = "bar" }},
    };
    const server = McpServer.init(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("test-server", server.name);
    try std.testing.expectEqual(@as(u32, 1), server.next_id);
    try std.testing.expect(server.child == null);
    try std.testing.expectEqualStrings("/usr/bin/echo", server.config.command);
}

test "parseToolsListResponse valid" {
    const resp =
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[
        \\  {"name":"read_file","description":"Read a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}
        \\]}}
    ;
    const defs = try parseToolsListResponse(std.testing.allocator, resp);
    defer {
        for (defs) |d| {
            std.testing.allocator.free(d.name);
            std.testing.allocator.free(d.description);
            std.testing.allocator.free(d.input_schema);
        }
        std.testing.allocator.free(defs);
    }
    try std.testing.expectEqual(@as(usize, 1), defs.len);
    try std.testing.expectEqualStrings("read_file", defs[0].name);
    try std.testing.expectEqualStrings("Read a file", defs[0].description);
    try std.testing.expect(defs[0].input_schema.len > 0);
}

test "parseToolsListResponse empty tools" {
    const resp =
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}
    ;
    const defs = try parseToolsListResponse(std.testing.allocator, resp);
    defer std.testing.allocator.free(defs);
    try std.testing.expectEqual(@as(usize, 0), defs.len);
}

test "parseToolsListResponse error" {
    const resp =
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Invalid request"}}
    ;
    try std.testing.expectError(error.JsonRpcError, parseToolsListResponse(std.testing.allocator, resp));
}

test "parseCallToolResponse valid" {
    const resp =
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello world"}]}}
    ;
    const output = try parseCallToolResponse(std.testing.allocator, resp);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings("hello world", output);
}

test "parseCallToolResponse multiple content" {
    const resp =
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"line1"},{"type":"text","text":"line2"}]}}
    ;
    const output = try parseCallToolResponse(std.testing.allocator, resp);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings("line1\nline2", output);
}

test "parseCallToolResponse error" {
    const resp =
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}
    ;
    try std.testing.expectError(error.JsonRpcError, parseCallToolResponse(std.testing.allocator, resp));
}

test "parseCallToolResponse invalid json" {
    try std.testing.expectError(error.InvalidJson, parseCallToolResponse(std.testing.allocator, "not json"));
}

test "McpToolWrapper vtable name" {
    var server = McpServer.init(std.testing.allocator, .{
        .name = "fs",
        .command = "echo",
    });
    var wrapper = McpToolWrapper{
        .server = &server,
        .original_name = "read_file",
        .prefixed_name = "mcp_fs_read_file",
        .desc = "Read a file from disk",
        .params_json = "{}",
    };
    const t = wrapper.tool();
    try std.testing.expectEqualStrings("mcp_fs_read_file", t.name());
}

test "McpToolWrapper vtable description" {
    var server = McpServer.init(std.testing.allocator, .{
        .name = "fs",
        .command = "echo",
    });
    var wrapper = McpToolWrapper{
        .server = &server,
        .original_name = "read_file",
        .prefixed_name = "mcp_fs_read_file",
        .desc = "Read a file from disk",
        .params_json = "{}",
    };
    const t = wrapper.tool();
    try std.testing.expectEqualStrings("Read a file from disk", t.description());
}

test "McpToolWrapper vtable parameters_json" {
    var server = McpServer.init(std.testing.allocator, .{
        .name = "fs",
        .command = "echo",
    });
    var wrapper = McpToolWrapper{
        .server = &server,
        .original_name = "read_file",
        .prefixed_name = "mcp_fs_read_file",
        .desc = "Read a file",
        .params_json = "{\"type\":\"object\"}",
    };
    const t = wrapper.tool();
    try std.testing.expectEqualStrings("{\"type\":\"object\"}", t.parametersJson());
}

test "initMcpTools empty configs" {
    const tools = try initMcpTools(std.testing.allocator, &.{});
    defer std.testing.allocator.free(tools);
    try std.testing.expectEqual(@as(usize, 0), tools.len);
}

test "buildJsonRpcRequest format" {
    // Verify the JSON-RPC message format by testing the string building logic
    const id: u32 = 42;
    const method = "tools/list";
    const params = "{}";
    const msg = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"jsonrpc":"2.0","id":{d},"method":"{s}","params":{s}}}
    ++ "\n", .{ id, method, params });
    defer std.testing.allocator.free(msg);

    // Parse to verify it's valid JSON (minus the trailing newline)
    const json_part = msg[0 .. msg.len - 1];
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_part, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    const jsonrpc = parsed.value.object.get("jsonrpc").?;
    try std.testing.expectEqualStrings("2.0", jsonrpc.string);
    const id_val = parsed.value.object.get("id").?;
    try std.testing.expectEqual(@as(i64, 42), id_val.integer);
}
