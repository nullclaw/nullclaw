const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Composio tool — proxy actions to the Composio managed tool platform.
/// Supports 1000+ OAuth integrations (Gmail, Notion, GitHub, Slack, etc.).
/// Operations: list (available actions), execute (run an action), connect (get OAuth URL).
pub const ComposioTool = struct {
    api_key: []const u8,
    entity_id: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ComposioTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ComposioTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "composio";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Execute actions on 1000+ apps via Composio (Gmail, Notion, GitHub, Slack, etc.). " ++
            "Use action='list' to see available actions, action='execute' with action_name and params, " ++
            "or action='connect' with app to get OAuth URL.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"action":{"type":"string","enum":["list","execute","connect"],"description":"Operation: list, execute, or connect"},"app":{"type":"string","description":"App/toolkit filter for list, or app for connect"},"action_name":{"type":"string","description":"Action identifier to execute"},"params":{"type":"object","description":"Parameters for the action"},"entity_id":{"type":"string","description":"Entity/user ID for multi-user setups"}},"required":["action"]}
        ;
    }

    fn execute(self: *ComposioTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const action = parseStringField(args_json, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (self.api_key.len == 0) {
            return ToolResult.fail("Composio API key not configured. Set composio.api_key in config.");
        }

        if (std.mem.eql(u8, action, "list")) {
            return self.listActions(allocator, args_json);
        } else if (std.mem.eql(u8, action, "execute")) {
            return self.executeAction(allocator, args_json);
        } else if (std.mem.eql(u8, action, "connect")) {
            return self.connectAction(allocator, args_json);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'. Use 'list', 'execute', or 'connect'.", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }

    fn listActions(self: *ComposioTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const app = parseStringField(args_json, "app");

        // Build URL
        var url_buf: [512]u8 = undefined;
        const url = if (app) |a|
            std.fmt.bufPrint(&url_buf, "https://backend.composio.dev/api/v2/actions?appNames={s}", .{a}) catch
                return ToolResult.fail("URL too long")
        else
            std.fmt.bufPrint(&url_buf, "https://backend.composio.dev/api/v2/actions", .{}) catch
                return ToolResult.fail("URL too long");

        return self.httpGet(allocator, url);
    }

    fn executeAction(self: *ComposioTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const action_name = parseStringField(args_json, "action_name") orelse
            return ToolResult.fail("Missing 'action_name' for execute");

        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://backend.composio.dev/api/v2/actions/{s}/execute", .{action_name}) catch
            return ToolResult.fail("URL too long");

        return self.httpPost(allocator, url, args_json);
    }

    fn connectAction(self: *ComposioTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const app = parseStringField(args_json, "app") orelse
            return ToolResult.fail("Missing 'app' for connect");

        const entity = if (parseStringField(args_json, "entity_id")) |e| e else self.entity_id;

        const auth_header = try std.fmt.allocPrint(allocator, "X-API-Key: {s}", .{self.api_key});
        defer allocator.free(auth_header);

        const body = try std.fmt.allocPrint(allocator, "{{\"entity_id\":\"{s}\",\"appName\":\"{s}\"}}", .{ entity, app });
        defer allocator.free(body);

        var argv_buf: [20][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-sL";
        argc += 1;
        argv_buf[argc] = "-m";
        argc += 1;
        argv_buf[argc] = "15";
        argc += 1;
        argv_buf[argc] = "-X";
        argc += 1;
        argv_buf[argc] = "POST";
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = auth_header;
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = "Content-Type: application/json";
        argc += 1;
        argv_buf[argc] = "-d";
        argc += 1;
        argv_buf[argc] = body;
        argc += 1;
        argv_buf[argc] = "https://backend.composio.dev/api/v1/connectedAccounts";
        argc += 1;

        return self.runCurl(allocator, argv_buf[0..argc]);
    }

    fn httpGet(self: *ComposioTool, allocator: std.mem.Allocator, url: []const u8) !ToolResult {
        const auth_header = try std.fmt.allocPrint(allocator, "X-API-Key: {s}", .{self.api_key});
        defer allocator.free(auth_header);

        var argv_buf: [20][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-sL";
        argc += 1;
        argv_buf[argc] = "-m";
        argc += 1;
        argv_buf[argc] = "15";
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = auth_header;
        argc += 1;
        argv_buf[argc] = url;
        argc += 1;

        return self.runCurl(allocator, argv_buf[0..argc]);
    }

    fn httpPost(self: *ComposioTool, allocator: std.mem.Allocator, url: []const u8, body: []const u8) !ToolResult {
        const auth_header = try std.fmt.allocPrint(allocator, "X-API-Key: {s}", .{self.api_key});
        defer allocator.free(auth_header);

        var argv_buf: [20][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-sL";
        argc += 1;
        argv_buf[argc] = "-m";
        argc += 1;
        argv_buf[argc] = "15";
        argc += 1;
        argv_buf[argc] = "-X";
        argc += 1;
        argv_buf[argc] = "POST";
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = auth_header;
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = "Content-Type: application/json";
        argc += 1;
        argv_buf[argc] = "-d";
        argc += 1;
        argv_buf[argc] = body;
        argc += 1;
        argv_buf[argc] = url;
        argc += 1;

        return self.runCurl(allocator, argv_buf[0..argc]);
    }

    /// Run curl as a child process and return stdout on success, stderr on failure.
    fn runCurl(_: *ComposioTool, allocator: std.mem.Allocator, argv: []const []const u8) !ToolResult {
        const max_output: usize = 1_048_576;

        var child = std.process.Child.init(argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout = try child.stdout.?.readToEndAlloc(allocator, max_output);
        defer allocator.free(stdout);
        const stderr = try child.stderr.?.readToEndAlloc(allocator, max_output);
        defer allocator.free(stderr);

        const term = try child.wait();
        const success = term.Exited == 0;

        if (success) {
            const out = try allocator.dupe(u8, if (stdout.len > 0) stdout else "(empty response)");
            return ToolResult{ .success = true, .output = out };
        } else {
            const err_out = try allocator.dupe(u8, if (stderr.len > 0) stderr else "curl failed with non-zero exit code");
            return ToolResult{ .success = false, .output = "", .error_msg = err_out };
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "composio tool name" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    try std.testing.expectEqualStrings("composio", t.name());
}

test "composio tool description mentions 1000+" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const desc = t.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "1000+") != null);
}

test "composio tool schema has action" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "action_name") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "app") != null);
}

test "composio missing action returns error" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "composio unknown action returns error" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"unknown\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "composio no api key returns error" {
    var ct = ComposioTool{ .api_key = "", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"list\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "API key") != null);
}

test "composio list action invokes curl" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"list\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    // curl actually runs — may succeed with API error JSON or fail with network error
    // Either way, we get a result (not a Zig error)
    try std.testing.expect(result.output.len > 0 or result.error_msg != null);
}

test "composio list with app filter invokes curl" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"list\", \"app\": \"gmail\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.output.len > 0 or result.error_msg != null);
}

test "composio execute missing action_name" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"execute\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action_name") != null);
}

test "composio execute with action_name invokes curl" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"execute\", \"action_name\": \"GMAIL_SEND\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    // curl runs against real API — may return error JSON or network failure
    try std.testing.expect(result.output.len > 0 or result.error_msg != null);
}

test "composio connect missing app" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"connect\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "app") != null);
}

test "composio connect with app invokes curl" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"connect\", \"app\": \"gmail\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    // curl runs — result depends on network, but should not crash
    try std.testing.expect(result.output.len > 0 or result.error_msg != null);
}

test "composio tool spec" {
    var ct = ComposioTool{ .api_key = "test-key", .entity_id = "default" };
    const t = ct.tool();
    const s = t.spec();
    try std.testing.expectEqualStrings("composio", s.name);
    try std.testing.expect(s.parameters_json.len > 0);
}
