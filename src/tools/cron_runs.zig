const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;
const loadScheduler = @import("cron_add.zig").loadScheduler;

/// Cron runs tool — shows execution history for a cron job.
pub const CronRunsTool = struct {
    pub const tool_name = "cron_runs";
    pub const tool_description = "List recent execution history for a cron job.";
    pub const tool_params =
        \\{"type":"object","properties":{"job_id":{"type":"string","description":"ID of the cron job"},"limit":{"type":"integer","description":"Max runs to show (default 10)"}},"required":["job_id"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *CronRunsTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *CronRunsTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const job_id = root.getString(args, "job_id") orelse
            return ToolResult.fail("Missing 'job_id' parameter");

        const limit: usize = blk: {
            const raw = root.getInt(args, "limit") orelse 10;
            break :blk if (raw > 0) @intCast(raw) else 10;
        };

        var scheduler = loadScheduler(allocator) catch {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{job_id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer scheduler.deinit();

        const job = scheduler.getJob(job_id) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{job_id});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const runs = scheduler.listRuns(allocator, job_id, limit) catch {
            return ToolResult.fail("Failed to load run history");
        };
        defer allocator.free(runs);

        if (runs.len == 0) {
            const msg = try std.fmt.allocPrint(allocator, "No run history for job {s}. Use 'cron run {s}' to execute manually.", .{ job_id, job_id });
            return ToolResult{ .success = true, .output = msg };
        }

        // Format output
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
        defer buf = buf_writer.toArrayList();
        const w = &buf_writer.writer;

        // Header with job info
        const last_run_str: []const u8 = if (job.last_run_secs) |lrs| blk: {
            break :blk try std.fmt.allocPrint(allocator, "{d}", .{lrs});
        } else "never";
        defer if (job.last_run_secs != null) allocator.free(last_run_str);

        const last_status = job.last_status orelse "pending";
        try w.print("Job {s} | last_run: {s} | last_status: {s}\n", .{ job_id, last_run_str, last_status });
        try w.print("Recent runs ({d}):\n", .{runs.len});

        for (runs) |run| {
            const output_str = if (run.output) |o|
                if (o.len > 80) o[0..80] else o
            else
                "(none)";
            const duration = run.duration_ms orelse 0;
            try w.print("- Run #{d}: {s} | started: {d} | duration: {d}ms | output: {s}\n", .{
                run.id,
                run.status,
                run.started_at_s,
                duration,
                output_str,
            });
        }

        return ToolResult{ .success = true, .output = try buf.toOwnedSlice(allocator) };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "cron_runs_requires_job_id" {
    var crt = CronRunsTool{};
    const t = crt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "job_id") != null);
}

test "cron_runs_not_found" {
    var crt = CronRunsTool{};
    const t = crt.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"nonexistent-xyz\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "cron_runs_no_history" {
    const allocator = std.testing.allocator;
    // Create a scheduler with a job but no runs (no file I/O)
    var scheduler = CronScheduler.init(allocator, 10, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("* * * * *", "echo test");
    const job_id = job.id;

    // Verify no runs exist
    const runs = try scheduler.listRuns(allocator, job_id, 10);
    defer allocator.free(runs);
    try std.testing.expectEqual(@as(usize, 0), runs.len);

    // Also verify via tool with a nonexistent job (since tool loads from disk)
    var crt = CronRunsTool{};
    const t = crt.tool();
    const parsed = try root.parseTestArgs("{\"job_id\": \"no-such-job-abc\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.error_msg) |e| allocator.free(e);
    try std.testing.expect(!result.success);
}

test "cron_runs_shows_history" {
    const allocator = std.testing.allocator;
    // Create a scheduler with a job and add runs directly (no file I/O)
    var scheduler = CronScheduler.init(allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addJob("*/5 * * * *", "echo hello");
    const job_id = job.id;

    try scheduler.addRun(allocator, job_id, 1000, 1001, "success", "hello world", 10);
    try scheduler.addRun(allocator, job_id, 2000, 2002, "error", null, 10);

    // Verify runs are stored
    const runs = try scheduler.listRuns(allocator, job_id, 10);
    defer allocator.free(runs);
    try std.testing.expectEqual(@as(usize, 2), runs.len);
    try std.testing.expectEqualStrings("success", runs[0].status);
    try std.testing.expectEqualStrings("error", runs[1].status);
    try std.testing.expectEqual(@as(u64, 1), runs[0].id);
    try std.testing.expectEqual(@as(u64, 2), runs[1].id);
    try std.testing.expectEqual(@as(i64, 1000), runs[0].started_at_s);
    try std.testing.expectEqual(@as(?i64, 1000), runs[0].duration_ms);
    try std.testing.expectEqualStrings("hello world", runs[0].output.?);
    try std.testing.expect(runs[1].output == null);
}

test "cron_runs tool name" {
    var crt = CronRunsTool{};
    const t = crt.tool();
    try std.testing.expectEqualStrings("cron_runs", t.name());
}

test "cron_runs schema has job_id" {
    var crt = CronRunsTool{};
    const t = crt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "job_id") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "limit") != null);
}
