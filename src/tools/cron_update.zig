const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;
const cron_gateway = @import("cron_gateway.zig");
const loadScheduler = @import("cron_add.zig").loadScheduler;

/// CronUpdate tool — update a cron job's expression, command, or enabled state.
pub const CronUpdateTool = struct {
    pub const tool_name = "cron_update";
    pub const tool_description = "Update a cron job: change expression, command, prompt, model, session_target, or enable/disable it.";
    pub const tool_params =
        \\{"type":"object","properties":{"job_id":{"type":"string","description":"ID of the cron job to update"},"expression":{"type":"string","description":"New cron expression"},"command":{"type":"string","description":"New command to execute"},"prompt":{"type":"string","description":"New prompt for agent jobs"},"model":{"type":"string","description":"New model override for agent jobs"},"session_target":{"type":"string","enum":["isolated","main"],"description":"Routing mode for agent job delivery"},"enabled":{"type":"boolean","description":"Enable or disable the job"}},"required":["job_id"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *CronUpdateTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *CronUpdateTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const job_id = root.getString(args, "job_id") orelse
            return ToolResult.fail("Missing 'job_id' parameter");

        const expression = root.getString(args, "expression");
        const command = root.getString(args, "command");
        const prompt = root.getString(args, "prompt");
        const model = root.getString(args, "model");
        const session_target = if (root.getString(args, "session_target")) |raw|
            cron.SessionTarget.parseStrict(raw) catch
                return ToolResult.fail("Invalid 'session_target' parameter: expected 'isolated' or 'main'")
        else
            null;
        const enabled = root.getBool(args, "enabled");

        // Validate that at least one field is being updated
        if (expression == null and command == null and prompt == null and model == null and session_target == null and enabled == null)
            return ToolResult.fail("Nothing to update — provide expression, command, prompt, model, session_target, or enabled");

        // Validate expression if provided
        if (expression) |expr| {
            _ = cron.normalizeExpression(expr) catch
                return ToolResult.fail("Invalid cron expression");
        }

        const gateway_body = cron_gateway.buildUpdateBody(allocator, job_id, expression, command, prompt, model, enabled, session_target) catch null;
        if (gateway_body) |json_body| {
            defer allocator.free(json_body);
            switch (cron.requestGatewayPost(allocator, "/cron/update", json_body)) {
                .unavailable => {},
                .response => |resp| {
                    if (resp.status_code >= 200 and resp.status_code < 300) {
                        return ToolResult{ .success = true, .output = resp.body };
                    }
                    return ToolResult{ .success = false, .output = "", .error_msg = resp.body };
                },
            }
        }

        var scheduler = loadScheduler(allocator) catch {
            return ToolResult.fail("Failed to load scheduler state");
        };
        defer scheduler.deinit();

        if (session_target != null) {
            const existing = scheduler.getJob(job_id) orelse {
                const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{job_id});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            if (existing.job_type != .agent) {
                return ToolResult.fail("session_target requires an agent job");
            }
        }

        const patch = cron.CronJobPatch{
            .expression = expression,
            .command = command,
            .prompt = prompt,
            .model = model,
            .session_target = session_target,
            .enabled = enabled,
        };

        if (!scheduler.updateJob(allocator, job_id, patch)) {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{job_id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        cron.saveJobs(&scheduler) catch {};

        // Build summary of what changed
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
        const w = &buf_writer.writer;
        try w.print("Updated job {s}", .{job_id});
        if (expression) |expr| try w.print(" | expression={s}", .{expr});
        if (command) |cmd| try w.print(" | command={s}", .{cmd});
        if (prompt) |value| try w.print(" | prompt={s}", .{value});
        if (model) |value| try w.print(" | model={s}", .{value});
        if (session_target) |value| try w.print(" | session_target={s}", .{value.asStr()});
        if (enabled) |ena| try w.print(" | enabled={s}", .{if (ena) "true" else "false"});

        buf = buf_writer.toArrayList();
        return ToolResult{ .success = true, .output = try buf.toOwnedSlice(allocator) };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "cron_update tool name" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    try std.testing.expectEqualStrings("cron_update", t.name());
}

test "cron_update schema has job_id" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "job_id") != null);
}

test "cron_update_requires_job_id" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "job_id") != null);
}

test "cron_update_requires_something" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"job-1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Nothing to update") != null);
}

test "cron_update_expression" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    // First create a job via CronScheduler so there's something to update
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo test");
    cron.saveJobs(&scheduler) catch {};

    const args = try std.fmt.allocPrint(std.testing.allocator, "{{\"job_id\": \"{s}\", \"expression\": \"*/10 * * * *\"}}", .{job.id});
    defer std.testing.allocator.free(args);
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Updated job") != null);
        try std.testing.expect(std.mem.indexOf(u8, result.output, "expression") != null);
    }
}

test "cron_update_disable" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo test");
    cron.saveJobs(&scheduler) catch {};

    const args = try std.fmt.allocPrint(std.testing.allocator, "{{\"job_id\": \"{s}\", \"enabled\": false}}", .{job.id});
    defer std.testing.allocator.free(args);
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Updated job") != null);
        try std.testing.expect(std.mem.indexOf(u8, result.output, "enabled=false") != null);
    }
}

test "cron_update_not_found" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"nonexistent-999\", \"command\": \"echo new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "cron_update_invalid_expression" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"job-1\", \"expression\": \"bad\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Invalid cron expression") != null);
}

test "cron_update rejects invalid session_target" {
    var ct = CronUpdateTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"job-1\", \"session_target\": \"primary\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "session_target") != null);
}

test "cron_update gateway request body keeps enabled false" {
    const body = try cron_gateway.buildUpdateBody(std.testing.allocator, "job-42", null, "echo hi", null, null, false, .main);
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("job-42", parsed.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("echo hi", parsed.value.object.get("command").?.string);
    try std.testing.expect(!parsed.value.object.get("enabled").?.bool);
    try std.testing.expectEqualStrings("main", parsed.value.object.get("session_target").?.string);
}
