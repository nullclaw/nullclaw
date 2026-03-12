const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;

/// CronAdd tool — creates a new cron job with either a cron expression or a delay.
pub const CronAddTool = struct {
    pub const tool_name = "cron_add";
    pub const tool_description = "Create a scheduled cron job. Provide either 'expression' (cron syntax) or 'delay' (e.g. '30m', '2h') plus 'command'. Set type='agent' for autonomous agent tasks.";
    pub const tool_params =
        \\{"type":"object","properties":{"expression":{"type":"string","description":"Cron expression (e.g. '*/5 * * * *')"},"delay":{"type":"string","description":"Delay for one-shot tasks (e.g. '30m', '2h')"},"command":{"type":"string","description":"Shell command or agent prompt"},"type":{"type":"string","enum":["shell","agent"],"description":"Job type: 'shell' (default) or 'agent'"},"prompt":{"type":"string","description":"Agent prompt (for type=agent; falls back to command)"},"model":{"type":"string","description":"Model override for agent jobs"},"name":{"type":"string","description":"Optional job name"}},"required":["command"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *CronAddTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *CronAddTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const command = root.getString(args, "command") orelse
            return ToolResult.fail("Missing required 'command' parameter");

        const expression = root.getString(args, "expression");
        const delay = root.getString(args, "delay");

        if (expression == null and delay == null)
            return ToolResult.fail("Missing schedule: provide either 'expression' (cron syntax) or 'delay' (e.g. '30m')");

        // Validate expression if provided
        if (expression) |expr| {
            _ = cron.normalizeExpression(expr) catch
                return ToolResult.fail("Invalid cron expression");
        }

        // Validate delay if provided
        if (delay) |d| {
            _ = cron.parseDuration(d) catch
                return ToolResult.fail("Invalid delay format");
        }

        var scheduler = loadScheduler(allocator) catch {
            return ToolResult.fail("Failed to load scheduler state");
        };
        defer scheduler.deinit();

        const is_agent = if (root.getString(args, "type")) |t| std.ascii.eqlIgnoreCase(t, "agent") else false;
        const prompt = root.getString(args, "prompt") orelse command;
        const model = root.getString(args, "model");

        // Prefer expression (recurring) over delay (one-shot)
        if (expression) |expr| {
            const job = if (is_agent)
                scheduler.addAgentJob(expr, prompt, model, .{}) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create agent job: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                }
            else
                scheduler.addJob(expr, command) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create job: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };

            cron.saveJobs(&scheduler) catch {};

            const type_label: []const u8 = if (is_agent) "agent " else "";
            const msg = try std.fmt.allocPrint(allocator, "Created {s}cron job {s}: {s} \u{2192} {s}", .{
                type_label,
                job.id,
                job.expression,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        if (delay) |d| {
            const job = if (is_agent)
                scheduler.addAgentOnce(d, prompt, model) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create one-shot agent task: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                }
            else
                scheduler.addOnce(d, command) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create one-shot task: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };

            cron.saveJobs(&scheduler) catch {};

            const type_label: []const u8 = if (is_agent) "agent " else "";
            const msg = try std.fmt.allocPrint(allocator, "Created {s}cron job {s}: {s} \u{2192} {s}", .{
                type_label,
                job.id,
                job.expression,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        return ToolResult.fail("Unexpected state: no expression or delay");
    }
};

/// Load the CronScheduler from persisted state (~/.nullclaw/cron.json).
/// Shared by cron_add, cron_list, cron_remove, and schedule tools.
pub fn loadScheduler(allocator: std.mem.Allocator) !CronScheduler {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    cron.loadJobs(&scheduler) catch {};
    return scheduler;
}

// ── Tests ───────────────────────────────────────────────────────────

test "cron_add_requires_command" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const parsed = try root.parseTestArgs("{\"expression\": \"*/5 * * * *\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "command") != null);
}

test "cron_add_requires_schedule" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "expression") != null or
        std.mem.indexOf(u8, result.error_msg.?, "delay") != null);
}

test "cron_add_with_expression" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const parsed = try root.parseTestArgs("{\"expression\": \"*/5 * * * *\", \"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created cron job") != null);
    }
}

test "cron_add_with_delay" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const parsed = try root.parseTestArgs("{\"delay\": \"30m\", \"command\": \"echo later\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created cron job") != null);
    }
}

test "cron_add_rejects_invalid_expression" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const parsed = try root.parseTestArgs("{\"expression\": \"bad cron\", \"command\": \"echo fail\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Invalid cron expression") != null);
}

test "cron_add tool name" {
    var cat = CronAddTool{};
    const t = cat.tool();
    try std.testing.expectEqualStrings("cron_add", t.name());
}

test "cron_add schema has command" {
    var cat = CronAddTool{};
    const t = cat.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "command") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "expression") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "delay") != null);
}
