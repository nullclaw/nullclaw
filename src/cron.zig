const std = @import("std");

/// A scheduled cron job.
pub const CronJob = struct {
    id: []const u8,
    expression: []const u8,
    command: []const u8,
    next_run_secs: i64 = 0,
    last_run_secs: ?i64 = null,
    last_status: ?[]const u8 = null,
    paused: bool = false,
    one_shot: bool = false,
};

/// Duration unit for "once" delay parsing.
pub const DurationUnit = enum {
    seconds,
    minutes,
    hours,
    days,
    weeks,
};

/// Parse a human delay string like "30m", "2h", "1d" into seconds.
pub fn parseDuration(input: []const u8) !i64 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyDelay;

    // Check if last char is a unit letter
    const last = trimmed[trimmed.len - 1];
    var num_str: []const u8 = undefined;
    var multiplier: i64 = undefined;

    if (std.ascii.isAlphabetic(last)) {
        num_str = trimmed[0 .. trimmed.len - 1];
        multiplier = switch (last) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 604800,
            else => return error.UnknownDurationUnit,
        };
    } else {
        num_str = trimmed;
        multiplier = 60; // default to minutes
    }

    const n = std.fmt.parseInt(i64, std.mem.trim(u8, num_str, " "), 10) catch return error.InvalidDurationNumber;
    if (n <= 0) return error.InvalidDurationNumber;

    const secs = std.math.mul(i64, n, multiplier) catch return error.DurationTooLarge;
    return secs;
}

/// Normalize a cron expression (5 fields -> prepend "0" for seconds).
pub fn normalizeExpression(expression: []const u8) !CronNormalized {
    const trimmed = std.mem.trim(u8, expression, " \t\r\n");
    var field_count: usize = 0;
    var in_field = false;

    for (trimmed) |c| {
        if (c == ' ' or c == '\t') {
            if (in_field) {
                in_field = false;
            }
        } else {
            if (!in_field) {
                field_count += 1;
                in_field = true;
            }
        }
    }

    return switch (field_count) {
        5 => .{ .expression = trimmed, .needs_second_prefix = true },
        6, 7 => .{ .expression = trimmed, .needs_second_prefix = false },
        else => error.InvalidCronExpression,
    };
}

pub const CronNormalized = struct {
    expression: []const u8,
    needs_second_prefix: bool,
};

/// In-memory cron job store (no SQLite dependency for the minimal Zig port).
pub const CronScheduler = struct {
    jobs: std.ArrayListUnmanaged(CronJob),
    max_tasks: usize,
    enabled: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, max_tasks: usize, enabled: bool) CronScheduler {
        return .{
            .jobs = .empty,
            .max_tasks = max_tasks,
            .enabled = enabled,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CronScheduler) void {
        for (self.jobs.items) |job| {
            self.allocator.free(job.id);
            self.allocator.free(job.expression);
            self.allocator.free(job.command);
        }
        self.jobs.deinit(self.allocator);
    }

    /// Add a recurring cron job.
    pub fn addJob(self: *CronScheduler, expression: []const u8, command: []const u8) !*CronJob {
        if (self.jobs.items.len >= self.max_tasks) return error.MaxTasksReached;

        // Validate expression
        _ = try normalizeExpression(expression);

        // Generate a simple numeric ID
        var id_buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "job-{d}", .{self.jobs.items.len + 1}) catch "job-?";

        try self.jobs.append(self.allocator, .{
            .id = try self.allocator.dupe(u8, id),
            .expression = try self.allocator.dupe(u8, expression),
            .command = try self.allocator.dupe(u8, command),
            .next_run_secs = std.time.timestamp() + 60, // placeholder
        });

        return &self.jobs.items[self.jobs.items.len - 1];
    }

    /// Add a one-shot delayed task.
    pub fn addOnce(self: *CronScheduler, delay: []const u8, command: []const u8) !*CronJob {
        if (self.jobs.items.len >= self.max_tasks) return error.MaxTasksReached;

        const delay_secs = try parseDuration(delay);
        const now = std.time.timestamp();

        var id_buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "once-{d}", .{self.jobs.items.len + 1}) catch "once-?";

        var expr_buf: [64]u8 = undefined;
        const expr = std.fmt.bufPrint(&expr_buf, "@once:{s}", .{delay}) catch "@once";

        try self.jobs.append(self.allocator, .{
            .id = try self.allocator.dupe(u8, id),
            .expression = try self.allocator.dupe(u8, expr),
            .command = try self.allocator.dupe(u8, command),
            .next_run_secs = now + delay_secs,
            .one_shot = true,
        });

        return &self.jobs.items[self.jobs.items.len - 1];
    }

    /// List all jobs.
    pub fn listJobs(self: *const CronScheduler) []const CronJob {
        return self.jobs.items;
    }

    /// Get a job by ID.
    pub fn getJob(self: *const CronScheduler, id: []const u8) ?*const CronJob {
        for (self.jobs.items) |*job| {
            if (std.mem.eql(u8, job.id, id)) return job;
        }
        return null;
    }

    /// Remove a job by ID, freeing its owned strings.
    pub fn removeJob(self: *CronScheduler, id: []const u8) bool {
        for (self.jobs.items, 0..) |job, i| {
            if (std.mem.eql(u8, job.id, id)) {
                self.allocator.free(job.id);
                self.allocator.free(job.expression);
                self.allocator.free(job.command);
                _ = self.jobs.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Pause a job.
    pub fn pauseJob(self: *CronScheduler, id: []const u8) bool {
        for (self.jobs.items) |*job| {
            if (std.mem.eql(u8, job.id, id)) {
                job.paused = true;
                return true;
            }
        }
        return false;
    }

    /// Resume a job.
    pub fn resumeJob(self: *CronScheduler, id: []const u8) bool {
        for (self.jobs.items) |*job| {
            if (std.mem.eql(u8, job.id, id)) {
                job.paused = false;
                return true;
            }
        }
        return false;
    }

    /// Get due (non-paused) jobs whose next_run <= now.
    pub fn dueJobs(self: *const CronScheduler, allocator: std.mem.Allocator, now_secs: i64) ![]const CronJob {
        var result: std.ArrayListUnmanaged(CronJob) = .empty;
        for (self.jobs.items) |job| {
            if (!job.paused and job.next_run_secs <= now_secs) {
                try result.append(allocator, job);
            }
        }
        return result.items;
    }

    /// Main scheduler loop: check all jobs, execute due ones, sleep until next.
    pub fn run(self: *CronScheduler, poll_secs: u64) void {
        if (!self.enabled) return;

        const poll_ns: u64 = poll_secs * std.time.ns_per_s;

        while (true) {
            const now = std.time.timestamp();
            for (self.jobs.items) |*job| {
                if (!job.paused and job.next_run_secs <= now) {
                    // Execute the job command via child process
                    const result = std.process.Child.run(.{
                        .allocator = self.allocator,
                        .argv = &.{ "sh", "-c", job.command },
                    }) catch {
                        job.last_status = "error";
                        job.last_run_secs = now;
                        continue;
                    };
                    self.allocator.free(result.stdout);
                    self.allocator.free(result.stderr);

                    job.last_run_secs = now;
                    job.last_status = if (result.term.code == 0) "ok" else "error";

                    if (job.one_shot) {
                        // Mark for removal (set next_run far in the future; actual removal in next sweep)
                        job.paused = true;
                    } else {
                        // Reschedule: advance by 60s (simple approximation without full cron parser)
                        job.next_run_secs = now + 60;
                    }
                }
            }

            std.time.sleep(poll_ns);
        }
    }
};

// ── JSON Persistence ─────────────────────────────────────────────

/// Serializable representation of a cron job for JSON persistence.
const JsonCronJob = struct {
    id: []const u8,
    expression: []const u8,
    command: []const u8,
    next_run_secs: i64,
    last_run_secs: ?i64,
    last_status: ?[]const u8,
    paused: bool,
    one_shot: bool,
};

/// Get the default cron.json path: ~/.nullclaw/cron.json
fn cronJsonPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.nullclaw/cron.json", .{home});
}

/// Ensure the ~/.nullclaw directory exists.
fn ensureCronDir(allocator: std.mem.Allocator) !void {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    const dir = try std.fmt.allocPrint(allocator, "{s}/.nullclaw", .{home});
    defer allocator.free(dir);
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// Save scheduler jobs to ~/.nullclaw/cron.json.
pub fn saveJobs(scheduler: *const CronScheduler) !void {
    try ensureCronDir(scheduler.allocator);
    const path = try cronJsonPath(scheduler.allocator);
    defer scheduler.allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();

    var buf: [8192]u8 = undefined;
    var bw = file.writer(&buf);
    const w = &bw.interface;

    try w.writeAll("[\n");
    for (scheduler.jobs.items, 0..) |job, i| {
        try w.writeAll("  {");
        try w.print("\"id\":\"{s}\",", .{job.id});
        try w.print("\"expression\":\"{s}\",", .{job.expression});
        try w.print("\"command\":\"{s}\",", .{job.command});
        try w.print("\"next_run_secs\":{d},", .{job.next_run_secs});
        if (job.last_run_secs) |lrs| {
            try w.print("\"last_run_secs\":{d},", .{lrs});
        } else {
            try w.writeAll("\"last_run_secs\":null,");
        }
        if (job.last_status) |ls| {
            try w.print("\"last_status\":\"{s}\",", .{ls});
        } else {
            try w.writeAll("\"last_status\":null,");
        }
        try w.print("\"paused\":{s},", .{if (job.paused) "true" else "false"});
        try w.print("\"one_shot\":{s}", .{if (job.one_shot) "true" else "false"});
        try w.writeAll("}");
        if (i + 1 < scheduler.jobs.items.len) {
            try w.writeAll(",");
        }
        try w.writeAll("\n");
    }
    try w.writeAll("]\n");
    try w.flush();
}

/// Load jobs from ~/.nullclaw/cron.json into the scheduler.
pub fn loadJobs(scheduler: *CronScheduler) !void {
    const path = try cronJsonPath(scheduler.allocator);
    defer scheduler.allocator.free(path);

    const content = std.fs.cwd().readFileAlloc(scheduler.allocator, path, 1024 * 1024) catch return;
    defer scheduler.allocator.free(content);

    const parsed = std.json.parseFromSlice(std.json.Value, scheduler.allocator, content, .{}) catch return;
    defer parsed.deinit();

    if (parsed.value != .array) return;

    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;

        const id = blk: {
            if (obj.get("id")) |v| {
                if (v == .string) break :blk v.string;
            }
            continue;
        };
        const expression = blk: {
            if (obj.get("expression")) |v| {
                if (v == .string) break :blk v.string;
            }
            continue;
        };
        const command = blk: {
            if (obj.get("command")) |v| {
                if (v == .string) break :blk v.string;
            }
            continue;
        };

        const next_run_secs: i64 = blk: {
            if (obj.get("next_run_secs")) |v| {
                if (v == .integer) break :blk v.integer;
            }
            break :blk std.time.timestamp() + 60;
        };

        const paused = blk: {
            if (obj.get("paused")) |v| {
                if (v == .bool) break :blk v.bool;
            }
            break :blk false;
        };

        const one_shot = blk: {
            if (obj.get("one_shot")) |v| {
                if (v == .bool) break :blk v.bool;
            }
            break :blk false;
        };

        try scheduler.jobs.append(scheduler.allocator, .{
            .id = try scheduler.allocator.dupe(u8, id),
            .expression = try scheduler.allocator.dupe(u8, expression),
            .command = try scheduler.allocator.dupe(u8, command),
            .next_run_secs = next_run_secs,
            .paused = paused,
            .one_shot = one_shot,
        });
    }
}

// ── CLI entry points (called from main.zig) ──────────────────────

/// CLI: list all cron jobs.
pub fn cliListJobs(allocator: std.mem.Allocator) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    const jobs = scheduler.listJobs();
    if (jobs.len == 0) {
        std.debug.print("No scheduled tasks yet.\n\n", .{});
        std.debug.print("Usage:\n", .{});
        std.debug.print("  nullclaw cron add '*/10 * * * *' 'echo hello'\n", .{});
        std.debug.print("  nullclaw cron once 30m 'echo reminder'\n", .{});
        return;
    }

    std.debug.print("Scheduled jobs ({d}):\n", .{jobs.len});
    for (jobs) |job| {
        const flags: []const u8 = blk: {
            if (job.paused and job.one_shot) break :blk " [paused, one-shot]";
            if (job.paused) break :blk " [paused]";
            if (job.one_shot) break :blk " [one-shot]";
            break :blk "";
        };
        const status = job.last_status orelse "n/a";
        std.debug.print("- {s} | {s} | next={d} | status={s}{s}\n    cmd: {s}\n", .{
            job.id,
            job.expression,
            job.next_run_secs,
            status,
            flags,
            job.command,
        });
    }
}

/// CLI: add a recurring cron job.
pub fn cliAddJob(allocator: std.mem.Allocator, expression: []const u8, command: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    const job = try scheduler.addJob(expression, command);
    try saveJobs(&scheduler);

    std.debug.print("Added cron job {s}\n", .{job.id});
    std.debug.print("  Expr: {s}\n", .{job.expression});
    std.debug.print("  Next: {d}\n", .{job.next_run_secs});
    std.debug.print("  Cmd : {s}\n", .{job.command});
}

/// CLI: add a one-shot delayed task.
pub fn cliAddOnce(allocator: std.mem.Allocator, delay: []const u8, command: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    const job = try scheduler.addOnce(delay, command);
    try saveJobs(&scheduler);

    std.debug.print("Added one-shot task {s}\n", .{job.id});
    std.debug.print("  Runs at: {d}\n", .{job.next_run_secs});
    std.debug.print("  Cmd    : {s}\n", .{job.command});
}

/// CLI: remove a cron job by ID.
pub fn cliRemoveJob(allocator: std.mem.Allocator, id: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    if (scheduler.removeJob(id)) {
        try saveJobs(&scheduler);
        std.debug.print("Removed cron job {s}\n", .{id});
    } else {
        std.debug.print("Cron job '{s}' not found\n", .{id});
    }
}

/// CLI: pause a cron job by ID.
pub fn cliPauseJob(allocator: std.mem.Allocator, id: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    if (scheduler.pauseJob(id)) {
        try saveJobs(&scheduler);
        std.debug.print("Paused job {s}\n", .{id});
    } else {
        std.debug.print("Cron job '{s}' not found\n", .{id});
    }
}

/// CLI: resume a paused cron job by ID.
pub fn cliResumeJob(allocator: std.mem.Allocator, id: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    if (scheduler.resumeJob(id)) {
        try saveJobs(&scheduler);
        std.debug.print("Resumed job {s}\n", .{id});
    } else {
        std.debug.print("Cron job '{s}' not found\n", .{id});
    }
}

pub fn cliRunJob(allocator: std.mem.Allocator, id: []const u8) !void {
    var scheduler = CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    try loadJobs(&scheduler);

    if (scheduler.getJob(id)) |job| {
        std.debug.print("Running job '{s}': {s}\n", .{ id, job.command });
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "sh", "-c", job.command },
        }) catch |err| {
            std.debug.print("Job '{s}' failed: {s}\n", .{ id, @errorName(err) });
            return;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.stdout.len > 0) std.debug.print("{s}", .{result.stdout});
        const exit_code: u8 = if (result.term == .Exited) result.term.Exited else 1;
        std.debug.print("Job '{s}' completed (exit {d}).\n", .{ id, exit_code });
    } else {
        std.debug.print("Cron job '{s}' not found\n", .{id});
    }
}

// ── Backwards-compatible type alias ──────────────────────────────────

pub const Task = CronJob;

// ── Tests ────────────────────────────────────────────────────────────

test "parseDuration minutes" {
    try std.testing.expectEqual(@as(i64, 1800), try parseDuration("30m"));
}

test "parseDuration hours" {
    try std.testing.expectEqual(@as(i64, 7200), try parseDuration("2h"));
}

test "parseDuration days" {
    try std.testing.expectEqual(@as(i64, 86400), try parseDuration("1d"));
}

test "parseDuration weeks" {
    try std.testing.expectEqual(@as(i64, 604800), try parseDuration("1w"));
}

test "parseDuration seconds" {
    try std.testing.expectEqual(@as(i64, 30), try parseDuration("30s"));
}

test "parseDuration default unit is minutes" {
    try std.testing.expectEqual(@as(i64, 300), try parseDuration("5"));
}

test "parseDuration empty returns error" {
    try std.testing.expectError(error.EmptyDelay, parseDuration(""));
}

test "parseDuration unknown unit" {
    try std.testing.expectError(error.UnknownDurationUnit, parseDuration("5x"));
}

test "normalizeExpression 5 fields" {
    const result = try normalizeExpression("*/5 * * * *");
    try std.testing.expect(result.needs_second_prefix);
}

test "normalizeExpression 6 fields" {
    const result = try normalizeExpression("0 */5 * * * *");
    try std.testing.expect(!result.needs_second_prefix);
}

test "normalizeExpression 4 fields invalid" {
    try std.testing.expectError(error.InvalidCronExpression, normalizeExpression("* * * *"));
}

test "CronScheduler add and list" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addJob("*/10 * * * *", "echo roundtrip");
    try std.testing.expectEqualStrings("*/10 * * * *", job.expression);
    try std.testing.expectEqualStrings("echo roundtrip", job.command);
    try std.testing.expect(!job.one_shot);
    try std.testing.expect(!job.paused);

    const listed = scheduler.listJobs();
    try std.testing.expectEqual(@as(usize, 1), listed.len);
}

test "CronScheduler addOnce creates one-shot" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addOnce("30m", "echo once");
    try std.testing.expect(job.one_shot);
}

test "CronScheduler remove" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addJob("*/10 * * * *", "echo test");
    try std.testing.expect(scheduler.removeJob(job.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.listJobs().len);
}

test "CronScheduler pause and resume" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addJob("*/5 * * * *", "echo pause");
    try std.testing.expect(scheduler.pauseJob(job.id));
    try std.testing.expect(scheduler.getJob(job.id).?.paused);
    try std.testing.expect(scheduler.resumeJob(job.id));
    try std.testing.expect(!scheduler.getJob(job.id).?.paused);
}

test "CronScheduler max tasks enforced" {
    var scheduler = CronScheduler.init(std.testing.allocator, 1, true);
    defer scheduler.deinit();

    _ = try scheduler.addJob("*/10 * * * *", "echo first");
    try std.testing.expectError(error.MaxTasksReached, scheduler.addJob("*/11 * * * *", "echo second"));
}

test "CronScheduler getJob found and missing" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    const job = try scheduler.addJob("*/5 * * * *", "echo found");
    try std.testing.expect(scheduler.getJob(job.id) != null);
    try std.testing.expect(scheduler.getJob("nonexistent") == null);
}

test "save and load roundtrip" {
    var scheduler = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler.deinit();

    _ = try scheduler.addJob("*/10 * * * *", "echo roundtrip");
    _ = try scheduler.addOnce("5m", "echo oneshot");

    // Save to disk
    try saveJobs(&scheduler);

    // Load into a new scheduler
    var scheduler2 = CronScheduler.init(std.testing.allocator, 10, true);
    defer scheduler2.deinit();
    try loadJobs(&scheduler2);

    try std.testing.expectEqual(@as(usize, 2), scheduler2.listJobs().len);

    const loaded = scheduler2.listJobs();
    try std.testing.expectEqualStrings("*/10 * * * *", loaded[0].expression);
    try std.testing.expectEqualStrings("echo roundtrip", loaded[0].command);
    try std.testing.expect(loaded[1].one_shot);
}

test "cron module compiles" {}
