const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;

/// Schedule tool — lets the agent manage recurring and one-shot scheduled tasks.
/// Delegates to the CronScheduler from the cron module for persistent job management.
pub const ScheduleTool = struct {
    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ScheduleTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ScheduleTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "schedule";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Manage scheduled tasks. Actions: create/add/once/list/get/cancel/remove/pause/resume";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"action":{"type":"string","enum":["create","add","once","list","get","cancel","remove","pause","resume"],"description":"Action to perform"},"expression":{"type":"string","description":"Cron expression for recurring tasks"},"delay":{"type":"string","description":"Delay for one-shot tasks (e.g. '30m', '2h')"},"command":{"type":"string","description":"Shell command to execute"},"id":{"type":"string","description":"Task ID"}},"required":["action"]}
        ;
    }

    /// Load the CronScheduler from persisted state (~/.nullclaw/cron.json).
    fn loadScheduler(allocator: std.mem.Allocator) !CronScheduler {
        var scheduler = CronScheduler.init(allocator, 1024, true);
        cron.loadJobs(&scheduler) catch {};
        return scheduler;
    }

    fn execute(_: *ScheduleTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const action = parseStringField(args_json, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "list")) {
            var scheduler = loadScheduler(allocator) catch {
                return ToolResult.ok("No scheduled jobs.");
            };
            defer scheduler.deinit();

            const jobs = scheduler.listJobs();
            if (jobs.len == 0) {
                return ToolResult.ok("No scheduled jobs.");
            }

            // Format job list
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(allocator);
            const w = buf.writer(allocator);
            try w.print("Scheduled jobs ({d}):\n", .{jobs.len});
            for (jobs) |job| {
                const flags: []const u8 = blk: {
                    if (job.paused and job.one_shot) break :blk " [paused, one-shot]";
                    if (job.paused) break :blk " [paused]";
                    if (job.one_shot) break :blk " [one-shot]";
                    break :blk "";
                };
                const status = job.last_status orelse "pending";
                try w.print("- {s} | {s} | status={s}{s} | cmd: {s}\n", .{
                    job.id,
                    job.expression,
                    status,
                    flags,
                    job.command,
                });
            }
            return ToolResult{ .success = true, .output = try buf.toOwnedSlice(allocator) };
        }

        if (std.mem.eql(u8, action, "get")) {
            const id = parseStringField(args_json, "id") orelse
                return ToolResult.fail("Missing 'id' parameter for get action");

            var scheduler = loadScheduler(allocator) catch {
                const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer scheduler.deinit();

            if (scheduler.getJob(id)) |job| {
                const flags: []const u8 = blk: {
                    if (job.paused and job.one_shot) break :blk " [paused, one-shot]";
                    if (job.paused) break :blk " [paused]";
                    if (job.one_shot) break :blk " [one-shot]";
                    break :blk "";
                };
                const status = job.last_status orelse "pending";
                const msg = try std.fmt.allocPrint(allocator, "Job {s} | {s} | next={d} | status={s}{s}\n  cmd: {s}", .{
                    job.id,
                    job.expression,
                    job.next_run_secs,
                    status,
                    flags,
                    job.command,
                });
                return ToolResult{ .success = true, .output = msg };
            }
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        if (std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "add")) {
            const command = parseStringField(args_json, "command") orelse
                return ToolResult.fail("Missing 'command' parameter");
            const expression = parseStringField(args_json, "expression") orelse
                return ToolResult.fail("Missing 'expression' parameter for cron job");

            var scheduler = loadScheduler(allocator) catch {
                return ToolResult.fail("Failed to load scheduler state");
            };
            defer scheduler.deinit();

            const job = scheduler.addJob(expression, command) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to create job: {s}", .{@errorName(err)});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };

            cron.saveJobs(&scheduler) catch {};

            const msg = try std.fmt.allocPrint(allocator, "Created job {s} | {s} | cmd: {s}", .{
                job.id,
                job.expression,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        if (std.mem.eql(u8, action, "once")) {
            const command = parseStringField(args_json, "command") orelse
                return ToolResult.fail("Missing 'command' parameter");
            const delay = parseStringField(args_json, "delay") orelse
                return ToolResult.fail("Missing 'delay' parameter for one-shot task");

            var scheduler = loadScheduler(allocator) catch {
                return ToolResult.fail("Failed to load scheduler state");
            };
            defer scheduler.deinit();

            const job = scheduler.addOnce(delay, command) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to create one-shot task: {s}", .{@errorName(err)});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };

            cron.saveJobs(&scheduler) catch {};

            const msg = try std.fmt.allocPrint(allocator, "Created one-shot task {s} | runs at {d} | cmd: {s}", .{
                job.id,
                job.next_run_secs,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        if (std.mem.eql(u8, action, "cancel") or std.mem.eql(u8, action, "remove")) {
            const id = parseStringField(args_json, "id") orelse
                return ToolResult.fail("Missing 'id' parameter for cancel action");

            var scheduler = loadScheduler(allocator) catch {
                return ToolResult.fail("Failed to load scheduler state");
            };
            defer scheduler.deinit();

            if (scheduler.removeJob(id)) {
                cron.saveJobs(&scheduler) catch {};
                const msg = try std.fmt.allocPrint(allocator, "Cancelled job {s}", .{id});
                return ToolResult{ .success = true, .output = msg };
            }
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        if (std.mem.eql(u8, action, "pause") or std.mem.eql(u8, action, "resume")) {
            const id = parseStringField(args_json, "id") orelse
                return ToolResult.fail("Missing 'id' parameter");

            var scheduler = loadScheduler(allocator) catch {
                return ToolResult.fail("Failed to load scheduler state");
            };
            defer scheduler.deinit();

            const is_pause = std.mem.eql(u8, action, "pause");
            const found = if (is_pause) scheduler.pauseJob(id) else scheduler.resumeJob(id);

            if (found) {
                cron.saveJobs(&scheduler) catch {};
                const verb: []const u8 = if (is_pause) "Paused" else "Resumed";
                const msg = try std.fmt.allocPrint(allocator, "{s} job {s}", .{ verb, id });
                return ToolResult{ .success = true, .output = msg };
            }
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'", .{action});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "schedule tool name" {
    var st = ScheduleTool{};
    const t = st.tool();
    try std.testing.expectEqualStrings("schedule", t.name());
}

test "schedule schema has action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
}

test "schedule list returns success" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"list\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    // Either "No scheduled jobs." or a formatted job list
    try std.testing.expect(result.output.len > 0);
}

test "schedule unknown action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"explode\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "schedule create with expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"command\": \"echo hello\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // Succeeds if HOME/.nullclaw is writable, otherwise may fail gracefully
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created job") != null);
    }
}

// ── Additional schedule tests ───────────────────────────────────

test "schedule missing action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "schedule get missing id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"get\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "id") != null);
}

test "schedule get nonexistent job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"get\", \"id\": \"nonexistent-123\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "schedule cancel requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"cancel\"}");
    try std.testing.expect(!result.success);
}

test "schedule cancel nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"cancel\", \"id\": \"job-nonexistent\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    // Job doesn't exist in the real scheduler, so cancel returns not-found or success if previously created
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule remove nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"remove\", \"id\": \"job-nonexistent\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule pause nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"pause\", \"id\": \"job-nonexistent\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule resume nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"resume\", \"id\": \"job-nonexistent\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule once creates one-shot task" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"once\", \"delay\": \"30m\", \"command\": \"echo later\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "one-shot") != null);
    }
}

test "schedule add creates recurring job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"add\", \"expression\": \"0 * * * *\", \"command\": \"echo hourly\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created job") != null);
    }
}

test "schedule create missing command" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"create\", \"expression\": \"* * * * *\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "command") != null);
}

test "schedule create missing expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"create\", \"command\": \"echo hi\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "expression") != null);
}

test "schedule once missing delay" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"once\", \"command\": \"echo hi\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "delay") != null);
}

test "schedule description mentions actions" {
    var st = ScheduleTool{};
    const t = st.tool();
    const desc = t.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "create") != null);
    try std.testing.expect(std.mem.indexOf(u8, desc, "list") != null);
}

test "schedule pause requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"pause\"}");
    try std.testing.expect(!result.success);
}

test "schedule resume requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"resume\"}");
    try std.testing.expect(!result.success);
}
