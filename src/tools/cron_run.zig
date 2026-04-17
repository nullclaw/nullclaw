const std = @import("std");
const std_compat = @import("compat");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;
const loadScheduler = @import("cron_add.zig").loadScheduler;

/// CronRun tool — force-runs a cron job immediately by its ID, regardless of schedule.
pub const CronRunTool = struct {
    pub const tool_name = "cron_run";
    pub const tool_description = "Force-run a cron job immediately by its ID, regardless of schedule.";
    pub const tool_params =
        \\{"type":"object","properties":{"job_id":{"type":"string","description":"The ID of the cron job to run"}},"required":["job_id"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *CronRunTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *CronRunTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const job_id = root.getString(args, "job_id") orelse
            return ToolResult.fail("Missing 'job_id' parameter");

        var scheduler = loadScheduler(allocator) catch {
            return ToolResult.fail("Failed to load scheduler state");
        };
        defer scheduler.deinit();

        // Check that the job exists
        if (scheduler.getJob(job_id) == null) {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{job_id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        // Get the command from the job
        const command = blk: {
            const job = scheduler.getJob(job_id).?;
            break :blk job.command;
        };

        // Execute the command
        const result = std_compat.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ platform.getShell(), platform.getShellFlag(), command },
            .max_output_bytes = 65536,
        }) catch |err| {
            // Update last_status to error
            if (scheduler.getMutableJob(job_id)) |job| {
                job.last_status = "error";
                job.last_run_secs = std_compat.time.timestamp();
            }
            cron.saveJobs(&scheduler) catch {};

            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' execution failed: {s}", .{ job_id, @errorName(err) });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        const exit_code: u8 = switch (result.term) {
            .exited => |code| code,
            else => 1,
        };
        const success = exit_code == 0;
        const status_str: []const u8 = if (success) "ok" else "error";

        // Update job last_run and last_status
        if (scheduler.getMutableJob(job_id)) |job| {
            job.last_status = status_str;
            job.last_run_secs = std_compat.time.timestamp();
        }
        cron.saveJobs(&scheduler) catch {};

        const status_label: []const u8 = if (success) "ok" else "error";
        const output = if (result.stdout.len > 0) result.stdout else result.stderr;
        const msg = try std.fmt.allocPrint(allocator, "Job {s} ran: {s} (exit {d})\n{s}", .{
            job_id,
            status_label,
            exit_code,
            output,
        });
        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "cron_run tool name" {
    var crt = CronRunTool{};
    const t = crt.tool();
    try std.testing.expectEqualStrings("cron_run", t.name());
}

test "cron_run schema has job_id" {
    var crt = CronRunTool{};
    const t = crt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "job_id") != null);
}

test "cron_run_requires_job_id" {
    var crt = CronRunTool{};
    const t = crt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "job_id") != null);
}

test "cron_run_not_found" {
    var crt = CronRunTool{};
    const t = crt.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"nonexistent-xyz\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "cron_run_executes_command" {
    // Create a scheduler with a job, save it, then run via tool
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();
    cron.loadJobs(&scheduler) catch {};

    const job = try scheduler.addJob("*/5 * * * *", "echo hello");
    const job_id = try std.testing.allocator.dupe(u8, job.id);
    defer std.testing.allocator.free(job_id);

    try cron.saveJobs(&scheduler);

    // Now execute the cron_run tool
    var crt = CronRunTool{};
    const t = crt.tool();
    const args = try std.fmt.allocPrint(std.testing.allocator, "{{\"job_id\": \"{s}\"}}", .{job_id});
    defer std.testing.allocator.free(args);
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "hello") != null);

    var loaded = CronScheduler.init(std.testing.allocator, 10, true);
    defer loaded.deinit();
    try cron.loadJobsStrict(&loaded);
    const loaded_job = loaded.getJob(job_id) orelse return error.TestUnexpectedResult;
    try std.testing.expect(loaded_job.last_run_secs != null);
    try std.testing.expect(loaded_job.last_status != null);
    try std.testing.expectEqualStrings("ok", loaded_job.last_status.?);
}
