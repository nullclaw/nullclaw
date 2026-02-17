const std = @import("std");
const util = @import("util.zig");

/// Token usage information from a single API call.
pub const TokenUsage = struct {
    model: []const u8,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    cost_usd: f64,
    timestamp_secs: i64,

    fn sanitizePrice(value: f64) f64 {
        if (std.math.isFinite(value) and value > 0.0) return value;
        return 0.0;
    }

    pub fn init(model: []const u8, input_tokens: u64, output_tokens: u64, input_price_per_million: f64, output_price_per_million: f64) TokenUsage {
        const safe_input_price = sanitizePrice(input_price_per_million);
        const safe_output_price = sanitizePrice(output_price_per_million);
        const total = input_tokens +| output_tokens;
        const input_cost = @as(f64, @floatFromInt(input_tokens)) / 1_000_000.0 * safe_input_price;
        const output_cost = @as(f64, @floatFromInt(output_tokens)) / 1_000_000.0 * safe_output_price;
        return .{
            .model = model,
            .input_tokens = input_tokens,
            .output_tokens = output_tokens,
            .total_tokens = total,
            .cost_usd = input_cost + output_cost,
            .timestamp_secs = std.time.timestamp(),
        };
    }

    pub fn cost(self: *const TokenUsage) f64 {
        return self.cost_usd;
    }
};

/// Time period for cost aggregation.
pub const UsagePeriod = enum {
    session,
    day,
    month,
};

/// Budget enforcement result.
pub const BudgetCheck = union(enum) {
    allowed: void,
    warning: BudgetInfo,
    exceeded: BudgetInfo,
};

pub const BudgetInfo = struct {
    current_usd: f64,
    limit_usd: f64,
    period: UsagePeriod,
};

/// Per-model statistics.
pub const ModelStats = struct {
    model: []const u8,
    cost_usd: f64,
    total_tokens: u64,
    request_count: usize,
};

/// Cost summary for reporting.
pub const CostSummary = struct {
    session_cost_usd: f64 = 0.0,
    daily_cost_usd: f64 = 0.0,
    monthly_cost_usd: f64 = 0.0,
    total_tokens: u64 = 0,
    request_count: usize = 0,
};

/// A single cost record for persistent storage.
pub const CostRecord = struct {
    usage: TokenUsage,
    session_id: []const u8,
};

/// Cost tracker for API usage monitoring and budget enforcement.
/// Uses an in-memory list for session tracking plus JSONL file for persistence.
pub const CostTracker = struct {
    enabled: bool,
    daily_limit_usd: f64,
    monthly_limit_usd: f64,
    warn_at_percent: u32,
    session_records: std.ArrayListUnmanaged(CostRecord),
    storage_path: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, workspace_dir: []const u8, enabled: bool, daily_limit: f64, monthly_limit: f64, warn_pct: u32) CostTracker {
        // Build storage path: workspace_dir/state/costs.jsonl
        const path = std.fs.path.join(allocator, &.{ workspace_dir, "state", "costs.jsonl" }) catch "";
        return .{
            .enabled = enabled,
            .daily_limit_usd = daily_limit,
            .monthly_limit_usd = monthly_limit,
            .warn_at_percent = warn_pct,
            .session_records = .empty,
            .storage_path = path,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CostTracker) void {
        self.session_records.deinit(self.allocator);
        if (self.storage_path.len > 0) {
            self.allocator.free(self.storage_path);
        }
    }

    /// Check if a request is within budget.
    pub fn checkBudget(self: *const CostTracker, estimated_cost_usd: f64) BudgetCheck {
        if (!self.enabled) return .{ .allowed = {} };
        if (!std.math.isFinite(estimated_cost_usd) or estimated_cost_usd < 0.0) return .{ .allowed = {} };

        const session_cost = self.sessionCost();
        const projected = session_cost + estimated_cost_usd;

        // Check daily limit
        if (projected > self.daily_limit_usd) {
            return .{ .exceeded = .{
                .current_usd = session_cost,
                .limit_usd = self.daily_limit_usd,
                .period = .day,
            } };
        }

        // Check monthly limit
        if (projected > self.monthly_limit_usd) {
            return .{ .exceeded = .{
                .current_usd = session_cost,
                .limit_usd = self.monthly_limit_usd,
                .period = .month,
            } };
        }

        // Check warning threshold
        const warn_threshold = @as(f64, @floatFromInt(@min(self.warn_at_percent, 100))) / 100.0;
        const daily_warn = self.daily_limit_usd * warn_threshold;
        if (projected >= daily_warn) {
            return .{ .warning = .{
                .current_usd = session_cost,
                .limit_usd = self.daily_limit_usd,
                .period = .day,
            } };
        }

        return .{ .allowed = {} };
    }

    /// Record a usage event and persist to JSONL file.
    pub fn recordUsage(self: *CostTracker, usage: TokenUsage) !void {
        if (!self.enabled) return;
        if (!std.math.isFinite(usage.cost_usd) or usage.cost_usd < 0.0) return;

        const record = CostRecord{
            .usage = usage,
            .session_id = "current",
        };
        try self.session_records.append(self.allocator, record);

        // Persist to JSONL file
        self.appendToJsonl(&record) catch {};
    }

    /// Append a cost record to the JSONL file.
    fn appendToJsonl(self: *CostTracker, record: *const CostRecord) !void {
        if (self.storage_path.len == 0) return;

        // Ensure parent directory exists
        if (std.fs.path.dirnamePosix(self.storage_path) orelse std.fs.path.dirnameWindows(self.storage_path)) |dir| {
            std.fs.cwd().makePath(dir) catch {};
        }

        const file = std.fs.cwd().createFile(self.storage_path, .{ .truncate = false }) catch return;
        defer file.close();

        // Seek to end for append
        file.seekFromEnd(0) catch {};

        // Write JSON line
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\"model\":\"");
        try buf.appendSlice(self.allocator, record.usage.model);
        try buf.appendSlice(self.allocator, "\",\"input_tokens\":");
        var num_buf: [20]u8 = undefined;
        const in_str = std.fmt.bufPrint(&num_buf, "{d}", .{record.usage.input_tokens}) catch "0";
        try buf.appendSlice(self.allocator, in_str);
        try buf.appendSlice(self.allocator, ",\"output_tokens\":");
        const out_str = std.fmt.bufPrint(&num_buf, "{d}", .{record.usage.output_tokens}) catch "0";
        try buf.appendSlice(self.allocator, out_str);
        try buf.appendSlice(self.allocator, ",\"cost_usd\":");
        var cost_buf_arr: [32]u8 = undefined;
        const cost_str = std.fmt.bufPrint(&cost_buf_arr, "{d:.8}", .{record.usage.cost_usd}) catch "0.0";
        try buf.appendSlice(self.allocator, cost_str);
        try buf.appendSlice(self.allocator, ",\"timestamp\":");
        const ts_str = std.fmt.bufPrint(&num_buf, "{d}", .{record.usage.timestamp_secs}) catch "0";
        try buf.appendSlice(self.allocator, ts_str);
        try buf.appendSlice(self.allocator, ",\"session\":\"");
        try buf.appendSlice(self.allocator, record.session_id);
        try buf.appendSlice(self.allocator, "\"}\n");

        file.writeAll(buf.items) catch {};
    }

    /// Get total session cost.
    pub fn sessionCost(self: *const CostTracker) f64 {
        var total: f64 = 0.0;
        for (self.session_records.items) |record| {
            total += record.usage.cost_usd;
        }
        return total;
    }

    /// Get session token count.
    pub fn sessionTokens(self: *const CostTracker) u64 {
        var total: u64 = 0;
        for (self.session_records.items) |record| {
            total +|= record.usage.total_tokens;
        }
        return total;
    }

    /// Get request count for this session.
    pub fn requestCount(self: *const CostTracker) usize {
        return self.session_records.items.len;
    }

    /// Get daily cost by reading from the JSONL file.
    /// Sums all records with timestamps in the same day (UTC) as the given timestamp.
    pub fn getDailyCost(self: *const CostTracker, target_day_secs: i64) f64 {
        return self.sumCostsForPeriod(target_day_secs, .day);
    }

    /// Get monthly cost by reading from the JSONL file.
    /// Sums all records with timestamps in the same month as the given timestamp.
    pub fn getMonthlyCost(self: *const CostTracker, target_day_secs: i64) f64 {
        return self.sumCostsForPeriod(target_day_secs, .month);
    }

    const Period = enum { day, month };

    fn sumCostsForPeriod(self: *const CostTracker, target_secs: i64, period: Period) f64 {
        if (self.storage_path.len == 0) return self.sessionCost();

        const file = std.fs.cwd().openFile(self.storage_path, .{}) catch return self.sessionCost();
        defer file.close();

        const target_day = @divFloor(target_secs, 86400);
        // For month comparison: compute year*12 + month of target
        const target_epoch_day: i64 = target_day;
        // Approximate month: days since epoch / 30.44
        const target_month_approx: i64 = @divFloor(target_epoch_day, 30);

        var total: f64 = 0.0;
        var line_buf: [4096]u8 = undefined;
        var pos: usize = 0;

        while (true) {
            const n = file.read(line_buf[pos..]) catch break;
            if (n == 0 and pos == 0) break;
            const filled = pos + n;

            var start: usize = 0;
            while (std.mem.indexOfScalar(u8, line_buf[start..filled], '\n')) |nl| {
                const line = line_buf[start .. start + nl];
                start += nl + 1;

                // Parse timestamp from JSON line
                if (parseTimestampFromJsonl(line)) |ts| {
                    const record_day = @divFloor(ts, 86400);
                    switch (period) {
                        .day => {
                            if (record_day == target_day) {
                                total += parseCostFromJsonl(line);
                            }
                        },
                        .month => {
                            const record_month_approx: i64 = @divFloor(record_day, 30);
                            if (record_month_approx == target_month_approx) {
                                total += parseCostFromJsonl(line);
                            }
                        },
                    }
                }
            }

            // Move remaining bytes to beginning
            if (start < filled) {
                std.mem.copyForwards(u8, &line_buf, line_buf[start..filled]);
                pos = filled - start;
            } else {
                pos = 0;
            }

            if (n == 0) break;
        }

        return total;
    }

    /// Get cost summary including daily/monthly from JSONL.
    pub fn getSummary(self: *const CostTracker) CostSummary {
        const now = std.time.timestamp();
        return .{
            .session_cost_usd = self.sessionCost(),
            .daily_cost_usd = self.getDailyCost(now),
            .monthly_cost_usd = self.getMonthlyCost(now),
            .total_tokens = self.sessionTokens(),
            .request_count = self.requestCount(),
        };
    }
};

/// Parse the "timestamp" field from a JSONL cost record line.
fn parseTimestampFromJsonl(line: []const u8) ?i64 {
    const marker = "\"timestamp\":";
    const idx = std.mem.indexOf(u8, line, marker) orelse return null;
    const after = line[idx + marker.len ..];
    // Find the end of the number
    var end: usize = 0;
    for (after) |ch| {
        if (ch >= '0' and ch <= '9') {
            end += 1;
        } else if (ch == '-' and end == 0) {
            end += 1;
        } else break;
    }
    if (end == 0) return null;
    return std.fmt.parseInt(i64, after[0..end], 10) catch null;
}

/// Parse the "cost_usd" field from a JSONL cost record line.
fn parseCostFromJsonl(line: []const u8) f64 {
    const marker = "\"cost_usd\":";
    const idx = std.mem.indexOf(u8, line, marker) orelse return 0.0;
    const after = line[idx + marker.len ..];
    // Find the end of the number
    var end: usize = 0;
    for (after) |ch| {
        if ((ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == 'e' or ch == 'E' or ch == '+') {
            end += 1;
        } else break;
    }
    if (end == 0) return 0.0;
    return std.fmt.parseFloat(f64, after[0..end]) catch 0.0;
}

// ── Tests ────────────────────────────────────────────────────────────

test "TokenUsage cost calculation" {
    const usage = TokenUsage.init("test/model", 1000, 500, 3.0, 15.0);
    // Expected: (1000/1M)*3 + (500/1M)*15 = 0.003 + 0.0075 = 0.0105
    try std.testing.expect(@abs(usage.cost_usd - 0.0105) < 0.0001);
    try std.testing.expectEqual(@as(u64, 1000), usage.input_tokens);
    try std.testing.expectEqual(@as(u64, 500), usage.output_tokens);
    try std.testing.expectEqual(@as(u64, 1500), usage.total_tokens);
}

test "TokenUsage zero tokens" {
    const usage = TokenUsage.init("test/model", 0, 0, 3.0, 15.0);
    try std.testing.expect(@abs(usage.cost_usd) < std.math.floatEps(f64));
    try std.testing.expectEqual(@as(u64, 0), usage.total_tokens);
}

test "TokenUsage negative prices clamped to zero" {
    const usage = TokenUsage.init("test/model", 1000, 1000, -3.0, std.math.nan(f64));
    try std.testing.expect(@abs(usage.cost_usd) < std.math.floatEps(f64));
    try std.testing.expectEqual(@as(u64, 2000), usage.total_tokens);
}

test "CostTracker init and record" {
    var tracker = CostTracker.init(std.testing.allocator, "/tmp", true, 10.0, 100.0, 80);
    defer tracker.deinit();

    const usage = TokenUsage.init("test/model", 1000, 500, 1.0, 2.0);
    try tracker.recordUsage(usage);

    try std.testing.expectEqual(@as(usize, 1), tracker.requestCount());
    try std.testing.expect(tracker.sessionCost() > 0.0);
}

test "CostTracker budget check when disabled" {
    var tracker = CostTracker.init(std.testing.allocator, "/tmp", false, 10.0, 100.0, 80);
    defer tracker.deinit();

    const check = tracker.checkBudget(1000.0);
    try std.testing.expect(check == .allowed);
}

test "CostTracker budget exceeded" {
    var tracker = CostTracker.init(std.testing.allocator, "/tmp", true, 0.01, 100.0, 80);
    defer tracker.deinit();

    const usage = TokenUsage.init("test/model", 10000, 5000, 1.0, 2.0);
    try tracker.recordUsage(usage);

    const check = tracker.checkBudget(0.01);
    try std.testing.expect(check == .exceeded);
}

test "CostTracker summary" {
    var tracker = CostTracker.init(std.testing.allocator, "/tmp", true, 10.0, 100.0, 80);
    defer tracker.deinit();

    try tracker.recordUsage(TokenUsage.init("model-a", 100, 50, 1.0, 2.0));
    try tracker.recordUsage(TokenUsage.init("model-b", 200, 100, 1.0, 2.0));

    const summary = tracker.getSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.request_count);
    try std.testing.expect(summary.session_cost_usd > 0.0);
    try std.testing.expect(summary.total_tokens > 0);
}
