const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;
const cron_gateway = @import("cron_gateway.zig");
const loadScheduler = @import("cron_add.zig").loadScheduler;

threadlocal var tls_schedule_channel: ?[]const u8 = null;
threadlocal var tls_schedule_account_id: ?[]const u8 = null;
threadlocal var tls_schedule_chat_id: ?[]const u8 = null;

/// Schedule tool — lets the agent manage recurring and one-shot scheduled tasks.
/// Delegates to the CronScheduler from the cron module for persistent job management.
pub const ScheduleTool = struct {
    pub const tool_name = "schedule";
    pub const tool_description = "Manage scheduled tasks. Actions: create/add/once/list/get/cancel/remove/pause/resume. Set type='agent' to run as autonomous agent task (default: shell). Always provide a descriptive 'name' — it is used as the email subject when delivering results. Set session_target to 'main' to route results through the main agent for contextualised delivery.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["create","add","once","list","get","cancel","remove","pause","resume"],"description":"Action to perform"},"expression":{"type":"string","description":"Cron expression for recurring tasks"},"delay":{"type":"string","description":"Delay for one-shot tasks (e.g. '30m', '2h')"},"command":{"type":"string","description":"Shell command or agent prompt"},"type":{"type":"string","enum":["shell","agent"],"description":"Job type: 'shell' (default) or 'agent' (autonomous agent task)"},"prompt":{"type":"string","description":"Agent prompt (for type=agent; falls back to command)"},"model":{"type":"string","description":"Model override for agent jobs (default: config primary model)"},"name":{"type":"string","description":"Descriptive job name, used as email subject for delivery notifications"},"id":{"type":"string","description":"Task ID"},"channel":{"type":"string","description":"Delivery channel for notifications (e.g. telegram, signal, matrix)"},"account_id":{"type":"string","description":"Optional channel account ID for multi-account routing"},"chat_id":{"type":"string","description":"Chat ID for delivery notification"},"session_target":{"type":"string","enum":["isolated","main"],"description":"Routing mode: 'isolated' (default) delivers raw output directly; 'main' routes through the main agent session for contextualised responses"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    /// Set the context for the current turn (called before agent.turn).
    pub fn setContext(self: *ScheduleTool, channel: ?[]const u8, account_id: ?[]const u8, chat_id: ?[]const u8) void {
        _ = self;
        tls_schedule_channel = channel;
        tls_schedule_account_id = account_id;
        tls_schedule_chat_id = chat_id;
    }

    pub fn tool(self: *ScheduleTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *ScheduleTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        _ = self;
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        const explicit_channel = root.getString(args, "channel");
        const explicit_account_id = root.getString(args, "account_id");
        const explicit_chat_id = root.getString(args, "chat_id");
        const session_target = if (root.getString(args, "session_target")) |st|
            cron.SessionTarget.parse(st)
        else
            cron.SessionTarget.isolated;

        // Prefer explicit args; otherwise use per-thread context injected by channel_loop.
        const chat_id = explicit_chat_id orelse tls_schedule_chat_id;
        const delivery_channel = explicit_channel orelse tls_schedule_channel orelse "telegram";
        const delivery_account_id = explicit_account_id orelse tls_schedule_account_id;

        if (explicit_channel) |channel| {
            if (explicit_chat_id == null and tls_schedule_chat_id != null) {
                if (tls_schedule_channel) |current_channel| {
                    if (!std.mem.eql(u8, channel, current_channel)) {
                        return ToolResult.fail("When overriding 'channel', also provide 'chat_id' for the target conversation");
                    }
                }
            }
        }

        if (std.mem.eql(u8, action, "list")) {
            switch (cron.requestGatewayGet(allocator, "/cron")) {
                .unavailable => {},
                .response => |resp| {
                    if (resp.status_code >= 200 and resp.status_code < 300) {
                        return ToolResult{ .success = true, .output = resp.body };
                    }
                    return ToolResult{ .success = false, .output = "", .error_msg = resp.body };
                },
            }

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
            const id = root.getString(args, "id") orelse
                return ToolResult.fail("Missing 'id' parameter for get action");

            switch (cron.requestGatewayGet(allocator, "/cron")) {
                .unavailable => {},
                .response => |resp| {
                    if (resp.status_code < 200 or resp.status_code >= 300) {
                        return ToolResult{ .success = false, .output = "", .error_msg = resp.body };
                    }
                    defer allocator.free(resp.body);

                    const job_json = cron_gateway.findJobByIdJson(allocator, resp.body, id) catch {
                        return ToolResult.fail("Invalid gateway response");
                    };
                    if (job_json) |json| {
                        return ToolResult{ .success = true, .output = json };
                    }

                    const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            }

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
            const command = root.getString(args, "command") orelse
                return ToolResult.fail("Missing 'command' parameter");
            const expression = root.getString(args, "expression") orelse
                return ToolResult.fail("Missing 'expression' parameter for cron job");

            const gateway_delivery = if (chat_id) |cid|
                cron.DeliveryConfig{
                    .mode = .always,
                    .channel = delivery_channel,
                    .account_id = delivery_account_id,
                    .to = cid,
                    .best_effort = true,
                }
            else
                null;
            const gateway_body = cron_gateway.buildAddBody(allocator, expression, null, command, null, null, gateway_delivery) catch null;
            if (gateway_body) |json_body| {
                defer allocator.free(json_body);
                switch (cron.requestGatewayPost(allocator, "/cron/add", json_body)) {
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

            const is_agent = if (root.getString(args, "type")) |t| std.ascii.eqlIgnoreCase(t, "agent") else false;
            const job_name = root.getString(args, "name");

            const delivery_cfg: cron.DeliveryConfig = if (chat_id) |cid| .{
                .mode = .always,
                .channel = delivery_channel,
                .account_id = delivery_account_id,
                .to = cid,
            } else .{};

            const job = if (is_agent) blk: {
                const prompt = root.getString(args, "prompt") orelse command;
                const model = root.getString(args, "model");
                break :blk scheduler.addAgentJob(expression, prompt, model, delivery_cfg) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create agent job: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };
            } else blk: {
                break :blk scheduler.addJob(expression, command) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create job: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };
            };

            if (job_name) |n| job.name = try scheduler.allocator.dupe(u8, n);
            job.session_target = session_target;

            // Set delivery config if chat_id is provided (agent jobs get delivery via addAgentJob)
            if (!is_agent) {
                if (chat_id) |cid| {
                    job.delivery = .{
                        .mode = .always,
                        .channel = try allocator.dupe(u8, delivery_channel),
                        .account_id = if (delivery_account_id) |aid| try allocator.dupe(u8, aid) else null,
                        .to = try allocator.dupe(u8, cid),
                        .channel_owned = true,
                        .account_id_owned = delivery_account_id != null,
                        .to_owned = true,
                    };
                }
            }

            cron.saveJobs(&scheduler) catch {};

            const type_label: []const u8 = if (is_agent) "agent" else "shell";
            const msg = try std.fmt.allocPrint(allocator, "Created {s} job {s} | {s} | cmd: {s}", .{
                type_label,
                job.id,
                job.expression,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        if (std.mem.eql(u8, action, "once")) {
            const command = root.getString(args, "command") orelse
                return ToolResult.fail("Missing 'command' parameter");
            const delay = root.getString(args, "delay") orelse
                return ToolResult.fail("Missing 'delay' parameter for one-shot task");

            const gateway_delivery = if (chat_id) |cid|
                cron.DeliveryConfig{
                    .mode = .always,
                    .channel = delivery_channel,
                    .account_id = delivery_account_id,
                    .to = cid,
                    .best_effort = true,
                }
            else
                null;
            const gateway_body = cron_gateway.buildAddBody(allocator, null, delay, command, null, null, gateway_delivery) catch null;
            if (gateway_body) |json_body| {
                defer allocator.free(json_body);
                switch (cron.requestGatewayPost(allocator, "/cron/add", json_body)) {
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

            const is_agent = if (root.getString(args, "type")) |t| std.ascii.eqlIgnoreCase(t, "agent") else false;
            const job_name = root.getString(args, "name");

            const job = if (is_agent) blk: {
                const prompt = root.getString(args, "prompt") orelse command;
                const model = root.getString(args, "model");
                break :blk scheduler.addAgentOnce(delay, prompt, model) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create one-shot agent task: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };
            } else blk: {
                break :blk scheduler.addOnce(delay, command) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create one-shot task: {s}", .{@errorName(err)});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                };
            };

            if (job_name) |n| job.name = try scheduler.allocator.dupe(u8, n);
            job.session_target = session_target;

            // Set delivery config if chat_id is provided
            if (chat_id) |cid| {
                job.delivery = .{
                    .mode = .always,
                    .channel = try allocator.dupe(u8, delivery_channel),
                    .account_id = if (delivery_account_id) |aid| try allocator.dupe(u8, aid) else null,
                    .to = try allocator.dupe(u8, cid),
                    .channel_owned = true,
                    .account_id_owned = delivery_account_id != null,
                    .to_owned = true,
                };
            }

            cron.saveJobs(&scheduler) catch {};

            const type_label: []const u8 = if (is_agent) "agent" else "shell";
            const msg = try std.fmt.allocPrint(allocator, "Created one-shot {s} task {s} | runs at {d} | cmd: {s}", .{
                type_label,
                job.id,
                job.next_run_secs,
                job.command,
            });
            return ToolResult{ .success = true, .output = msg };
        }

        if (std.mem.eql(u8, action, "cancel") or std.mem.eql(u8, action, "remove")) {
            const id = root.getString(args, "id") orelse
                return ToolResult.fail("Missing 'id' parameter for cancel action");

            const gateway_body = cron_gateway.buildIdBody(allocator, id) catch null;
            if (gateway_body) |json_body| {
                defer allocator.free(json_body);
                switch (cron.requestGatewayPost(allocator, "/cron/remove", json_body)) {
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

            if (scheduler.removeJob(id)) {
                cron.saveJobs(&scheduler) catch {};
                const msg = try std.fmt.allocPrint(allocator, "Cancelled job {s}", .{id});
                return ToolResult{ .success = true, .output = msg };
            }
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        if (std.mem.eql(u8, action, "pause") or std.mem.eql(u8, action, "resume")) {
            const id = root.getString(args, "id") orelse
                return ToolResult.fail("Missing 'id' parameter");

            const gateway_body = cron_gateway.buildIdBody(allocator, id) catch null;
            if (gateway_body) |json_body| {
                defer allocator.free(json_body);
                const path = if (std.mem.eql(u8, action, "pause")) "/cron/pause" else "/cron/resume";
                switch (cron.requestGatewayPost(allocator, path, json_body)) {
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
    const parsed = try root.parseTestArgs("{\"action\": \"list\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    // Either "No scheduled jobs." or a formatted job list
    try std.testing.expect(result.output.len > 0);
}

test "schedule unknown action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"explode\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "schedule create with expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // Succeeds if HOME/.nullclaw is writable, otherwise may fail gracefully
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created shell job") != null);
    }
}

test "schedule create rejects cross-channel override without explicit chat_id" {
    var st = ScheduleTool{};
    st.setContext("telegram", "main", "chat-123");
    defer st.setContext(null, null, null);

    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"command\": \"echo hello\", \"channel\": \"signal\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "chat_id") != null);
}

// ── Additional schedule tests ───────────────────────────────────

test "schedule missing action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "schedule get missing id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"get\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "id") != null);
}

test "schedule get nonexistent job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"get\", \"id\": \"nonexistent-123\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "schedule cancel requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"cancel\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule cancel nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"cancel\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
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
    const parsed = try root.parseTestArgs("{\"action\": \"remove\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule pause nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"pause\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule resume nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"resume\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule once creates one-shot task" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"once\", \"delay\": \"30m\", \"command\": \"echo later\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "one-shot") != null);
    }
}

test "schedule add creates recurring job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"add\", \"expression\": \"0 * * * *\", \"command\": \"echo hourly\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created shell job") != null);
    }
}

test "schedule create missing command" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"* * * * *\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "command") != null);
}

test "schedule create missing expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"command\": \"echo hi\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "expression") != null);
}

test "schedule once missing delay" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"once\", \"command\": \"echo hi\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "delay") != null);
}

test "schedule pause requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"pause\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule resume requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"resume\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule gateway get extracts matching job json" {
    const body =
        \\[
        \\  {"id":"job-a","command":"echo a"},
        \\  {"id":"job-b","command":"echo b"}
        \\]
    ;
    const job_json = (try cron_gateway.findJobByIdJson(std.testing.allocator, body, "job-b")).?;
    defer std.testing.allocator.free(job_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, job_json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("job-b", parsed.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("echo b", parsed.value.object.get("command").?.string);
}
