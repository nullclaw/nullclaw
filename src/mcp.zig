//! MCP (Model Context Protocol) client.
//!
//! Supports stdio and HTTP JSON-RPC transports. Wraps discovered tools into
//! the standard Tool vtable so the agent can call them like any built-in tool.

const std = @import("std");
const tools_mod = @import("tools/root.zig");
const config_mod = @import("config.zig");
const json_util = @import("json_util.zig");
const version = @import("version.zig");
const platform = @import("platform.zig");
const http_util = @import("http_util.zig");
const verbose = @import("verbose.zig");
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
    http_client: ?std.http.Client,
    next_id: u32,
    mcp_session_id: ?[]u8,

    pub fn init(allocator: Allocator, config: McpServerConfig) McpServer {
        return .{
            .allocator = allocator,
            .name = config.name,
            .config = config,
            .child = null,
            .http_client = null,
            .next_id = 1,
            .mcp_session_id = null,
        };
    }

    /// Connect transport and perform the MCP initialize handshake.
    pub fn connect(self: *McpServer) !void {
        if (McpServerConfig.isHttpTransport(self.config.transport)) {
            try self.connectHttp();
        } else {
            try self.connectStdio();
        }

        // Send initialize request
        const init_params = try std.fmt.allocPrint(
            self.allocator,
            "{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"nullclaw\",\"version\":\"{s}\"}}}}",
            .{version.string},
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

    fn connectStdio(self: *McpServer) !void {
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
            "PATH",              "HOME",        "TERM",    "LANG",         "LC_ALL",
            "LC_CTYPE",          "USER",        "SHELL",   "TMPDIR",       "NODE_PATH",
            "NPM_CONFIG_PREFIX",
            // Windows-specific
            "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP",
            "TMP",               "SYSTEMROOT",  "COMSPEC", "PROGRAMFILES", "WINDIR",
        };
        for (&inherit_vars) |key| {
            if (platform.getEnvOrNull(self.allocator, key)) |val| {
                defer self.allocator.free(val);
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
    }

    fn connectHttp(self: *McpServer) !void {
        const url = self.config.url orelse return error.MissingHttpUrl;
        _ = std.Uri.parse(url) catch return error.InvalidHttpUrl;
        if (!McpServerConfig.isValidHttpUrl(url)) return error.InvalidHttpUrl;

        self.http_client = std.http.Client{ .allocator = self.allocator };
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
        try json_util.appendJsonString(&params_buf, self.allocator, tool_name);
        try params_buf.appendSlice(self.allocator, ",\"arguments\":");
        try params_buf.appendSlice(self.allocator, args_json);
        try params_buf.append(self.allocator, '}');

        const resp = try self.sendRequest(self.allocator, "tools/call", params_buf.items);
        defer self.allocator.free(resp);
        return try parseCallToolResponse(self.allocator, resp);
    }

    pub fn deinit(self: *McpServer) void {
        if (self.http_client) |*client| {
            client.deinit();
            self.http_client = null;
        }
        if (self.mcp_session_id) |sid| {
            self.allocator.free(sid);
            self.mcp_session_id = null;
        }
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
        if (McpServerConfig.isHttpTransport(self.config.transport)) {
            const resp = try self.sendHttpRequest(allocator, msg);
            defer allocator.free(resp.headers);
            if (resp.status_code < 200 or resp.status_code >= 300) {
                const max_body: usize = 4096;
                const body_truncated = if (resp.body.len > max_body) resp.body[0..max_body] else resp.body;
                if (verbose.isVerbose()) {
                    log.err("MCP server '{s}': HTTP {d}: {s}", .{ self.name, resp.status_code, body_truncated });
                } else {
                    log.err("MCP server '{s}': HTTP {d}", .{ self.name, resp.status_code });
                }
                allocator.free(resp.body);
                return error.HttpBadStatus;
            }
            return resp.body;
        }

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
        if (McpServerConfig.isHttpTransport(self.config.transport)) {
            const resp = try self.sendHttpRequest(self.allocator, msg);
            defer {
                self.allocator.free(resp.headers);
                self.allocator.free(resp.body);
            }
            if (resp.status_code < 200 or resp.status_code >= 300) {
                return error.HttpBadStatus;
            }
            return;
        }

        const stdin = self.child.?.stdin orelse return error.NoStdin;
        try stdin.writeAll(msg);
    }

    fn extractMcpSessionIdFromHeaders(headers: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, headers, '\n');
        while (it.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r\n");
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trim(u8, line[0..colon], " \t");
            if (!std.ascii.eqlIgnoreCase(name, "mcp-session-id")) continue;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (value.len == 0) return null;
            return value;
        }
        return null;
    }

    fn sendHttpRequest(self: *McpServer, allocator: Allocator, msg: []const u8) !http_util.HttpResponseWithHeaders {
        if (self.http_client == null) return error.NoHttpClient;
        const url = self.config.url orelse return error.MissingHttpUrl;

        var headers_buf: [24]std.http.Header = undefined;
        var header_count: usize = 0;

        headers_buf[header_count] = .{ .name = "Content-Type", .value = "application/json" };
        header_count += 1;

        if (self.mcp_session_id) |sid| {
            if (header_count >= headers_buf.len) return error.TooManyHeaders;
            headers_buf[header_count] = .{ .name = "mcp-session-id", .value = sid };
            header_count += 1;
        }

        for (self.config.headers) |entry| {
            if (header_count >= headers_buf.len) return error.TooManyHeaders;
            headers_buf[header_count] = .{ .name = entry.key, .value = entry.value };
            header_count += 1;
        }

        const timeout_ms = self.config.timeout_ms;
        const timeout_secs: u32 = @max(@as(u32, 1), (timeout_ms + 999) / 1000);
        var timeout_buf: [16]u8 = undefined;
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch unreachable;

        // std.http.Client.fetch has no request timeout control in Zig 0.15.
        // Use curl so timeouts are enforced.
        var header_lines: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (header_lines.items) |line| allocator.free(line);
            header_lines.deinit(allocator);
        }

        for (headers_buf[0..header_count]) |h| {
            try header_lines.append(allocator, try std.fmt.allocPrint(allocator, "{s}: {s}", .{ h.name, h.value }));
        }
        const resp = http_util.curlPostWithStatusHeadersAndTimeout(
            allocator,
            url,
            msg,
            header_lines.items,
            timeout_str,
        ) catch |err| switch (err) {
            error.CurlInterrupted => return error.HttpRequestInterrupted,
            error.CurlFailed, error.CurlReadError, error.CurlWriteError, error.CurlWaitError, error.CurlParseError => return error.HttpRequestFailed,
            else => return err,
        };
        errdefer {
            allocator.free(resp.headers);
            allocator.free(resp.body);
        }
        if (extractMcpSessionIdFromHeaders(resp.headers)) |sid| {
            const owned = try self.allocator.dupe(u8, sid);
            if (self.mcp_session_id) |old| self.allocator.free(old);
            self.mcp_session_id = owned;
        }

        return resp;
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
    allocator: Allocator,
    server: *McpServer,
    owns_server: bool,
    original_name: []const u8,
    prefixed_name: []const u8,
    desc: []const u8,
    params_json: []const u8,

    const vtable = tools_mod.Tool.VTable{
        .execute = &executeImpl,
        .name = &nameImpl,
        .description = &descImpl,
        .parameters_json = &paramsImpl,
        .deinit = &deinitImpl,
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
            return tools_mod.ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        return tools_mod.ToolResult{ .success = true, .output = output };
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

    fn deinitImpl(ptr: *anyopaque, allocator: Allocator) void {
        _ = allocator;
        const self: *McpToolWrapper = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;
        if (self.owns_server) {
            self.server.deinit();
            alloc.destroy(self.server);
        }
        alloc.free(self.original_name);
        alloc.free(self.prefixed_name);
        alloc.free(self.desc);
        alloc.free(self.params_json);
        alloc.destroy(self);
    }
};

// ── Top-level init ──────────────────────────────────────────────

/// Initialize MCP tools from config. Connects to each server, discovers
/// tools, and returns them wrapped in the standard Tool vtable.
/// Errors from individual servers are logged and skipped.
pub fn initMcpTools(allocator: Allocator, configs: []const McpServerConfig) ![]tools_mod.Tool {
    var all_tools: std.ArrayList(tools_mod.Tool) = .{};
    errdefer {
        for (all_tools.items) |t| {
            t.deinit(allocator);
        }
        all_tools.deinit(allocator);
    }

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
        defer allocator.free(tool_defs);

        var transferred_count: usize = 0;
        errdefer {
            var i: usize = transferred_count;
            while (i < tool_defs.len) : (i += 1) {
                allocator.free(tool_defs[i].name);
                allocator.free(tool_defs[i].description);
                allocator.free(tool_defs[i].input_schema);
            }
            if (transferred_count == 0) {
                server.deinit();
                allocator.destroy(server);
            }
        }

        for (tool_defs, 0..) |td, idx| {
            var wrapper = try allocator.create(McpToolWrapper);
            errdefer allocator.destroy(wrapper);
            const prefixed_name = try std.fmt.allocPrint(allocator, "mcp_{s}_{s}", .{ cfg.name, td.name });
            errdefer allocator.free(prefixed_name);
            wrapper.* = .{
                .allocator = allocator,
                .server = server,
                .owns_server = idx == 0,
                .original_name = td.name,
                .prefixed_name = prefixed_name,
                .desc = td.description,
                .params_json = td.input_schema,
            };
            try all_tools.append(allocator, wrapper.tool());
            transferred_count += 1;
        }

        if (transferred_count == 0) {
            server.deinit();
            allocator.destroy(server);
        }

        log.info("MCP server '{s}': {d} tools registered", .{ cfg.name, tool_defs.len });
    }

    return all_tools.toOwnedSlice(allocator);
}

// ── Tests ───────────────────────────────────────────────────────

test "McpServer init fields" {
    const cfg = McpServerConfig{
        .name = "test-server",
        .transport = "stdio",
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

test "McpServer sendRequest requires http client for http transport" {
    var server = McpServer.init(std.testing.allocator, .{
        .name = "remote",
        .transport = "http",
        .url = "https://mcp.example.com/rpc",
    });
    try std.testing.expectError(error.NoHttpClient, server.sendRequest(std.testing.allocator, "tools/list", "{}"));
}

test "McpServer sendNotification propagates http transport setup errors" {
    var server = McpServer.init(std.testing.allocator, .{
        .name = "remote",
        .transport = "http",
        .url = "https://mcp.example.com/rpc",
    });
    try std.testing.expectError(error.NoHttpClient, server.sendNotification("notifications/initialized", null));
}

test "McpServer init http fields" {
    const cfg = McpServerConfig{
        .name = "remote",
        .transport = "http",
        .url = "https://mcp.example.com/rpc",
    };
    const server = McpServer.init(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("remote", server.name);
    try std.testing.expectEqualStrings("http", server.config.transport);
    try std.testing.expectEqualStrings("", server.config.command);
    try std.testing.expectEqualStrings("https://mcp.example.com/rpc", server.config.url.?);
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
        .allocator = std.testing.allocator,
        .server = &server,
        .owns_server = false,
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
        .allocator = std.testing.allocator,
        .server = &server,
        .owns_server = false,
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
        .allocator = std.testing.allocator,
        .server = &server,
        .owns_server = false,
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

test "extractMcpSessionIdFromHeaders parses CRLF headers" {
    const hdr = "HTTP/2 200\r\ncontent-type: application/json\r\nmcp-session-id: abc123\r\ncache-control: no-cache\r\n";
    const got = McpServer.extractMcpSessionIdFromHeaders(hdr) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("abc123", got);
}

test "extractMcpSessionIdFromHeaders parses LF headers" {
    const hdr = "HTTP/1.1 200 OK\nMCP-Session-Id: zzz\nX: y\n";
    const got = McpServer.extractMcpSessionIdFromHeaders(hdr) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("zzz", got);
}
