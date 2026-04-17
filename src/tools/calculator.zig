const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const JsonValue = root.JsonValue;

pub const CalculatorTool = struct {
    const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;
    const MAX_FIXED_NOTATION_ABS: f64 = 1_000_000_000_000.0;
    const MIN_FIXED_NOTATION_ABS: f64 = 0.000001;

    pub const tool_name = "calculator";
    pub const tool_description = "Perform mathematical calculations accurately. Supports arithmetic (add, subtract, multiply, divide, mod, pow, sqrt), logarithms (log, log_base, ln, exp), rounding (abs, floor, ceil, round), and statistics (average, median, variance as population variance, stdev_population, stdev_sample, min, max, count, percentile).";
    pub const tool_params =
        \\{"type":"object","properties":{"operation":{"type":"string","enum":["add","subtract","multiply","divide","mod","pow","sqrt","log","log_base","ln","exp","average","median","variance","stdev_population","stdev_sample","min","max","count","percentile","abs","floor","ceil","round"],"description":"Calculation operation to perform"},"values":{"type":"array","items":{"type":"number"},"description":"Numeric values for the calculation. For ordered operations use left-to-right input order; log_base expects [value, base]."},"percentile_rank":{"type":"integer","description":"Percentile rank 0-100, required for percentile operation"}},"required":["operation","values"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *CalculatorTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *CalculatorTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const operation = root.getString(args, "operation") orelse {
            return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, "missing required parameter: operation", .{}) };
        };

        const values_arr = root.getStringArray(args, "values") orelse {
            return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, "missing required parameter: values", .{}) };
        };

        if (values_arr.len == 0) {
            return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, "values array must not be empty", .{}) };
        }

        const values = extractValues(allocator, values_arr) catch |err| switch (err) {
            error.InvalidNumber, error.IntegerPrecisionLoss => {
                return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, "{s}", .{@errorName(err)}) };
            },
            else => return err,
        };
        defer allocator.free(values);

        const result = compute(allocator, operation, values, args) catch |err| {
            return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, "{s}", .{@errorName(err)}) };
        };

        return ToolResult{ .success = true, .output = result };
    }

    fn extractValues(allocator: std.mem.Allocator, arr: []const JsonValue) ![]f64 {
        const values = try allocator.alloc(f64, arr.len);
        errdefer allocator.free(values);
        for (arr, 0..) |item, i| {
            values[i] = try jsonToFloat(item);
        }
        return values;
    }

    fn jsonToFloat(val: JsonValue) !f64 {
        return switch (val) {
            .integer => |i| integerToExactFloat(i),
            .float => |f| f,
            else => error.InvalidNumber,
        };
    }

    fn integerToExactFloat(value: i64) !f64 {
        if (value > MAX_EXACT_INTEGER or value < -MAX_EXACT_INTEGER) {
            return error.IntegerPrecisionLoss;
        }
        return @floatFromInt(value);
    }

    fn compute(allocator: std.mem.Allocator, operation: []const u8, values: []f64, args: JsonObjectMap) ![]const u8 {
        if (std.mem.eql(u8, operation, "add")) {
            if (values.len < 1) return error.AddRequiresValues;
            var sum: f64 = 0.0;
            for (values) |v| sum += v;
            return formatResult(allocator, sum);
        }
        if (std.mem.eql(u8, operation, "subtract")) {
            if (values.len != 2) return error.SubtractRequiresTwoValues;
            return formatResult(allocator, values[0] - values[1]);
        }
        if (std.mem.eql(u8, operation, "multiply")) {
            if (values.len < 1) return error.MultiplyRequiresValues;
            var product: f64 = 1.0;
            for (values) |v| product *= v;
            return formatResult(allocator, product);
        }
        if (std.mem.eql(u8, operation, "divide")) {
            if (values.len != 2) return error.DivideRequiresTwoValues;
            if (values[1] == 0.0) return error.DivisionByZero;
            return formatResult(allocator, values[0] / values[1]);
        }
        if (std.mem.eql(u8, operation, "mod")) {
            if (values.len != 2) return error.ModRequiresTwoValues;
            if (values[1] == 0.0) return error.ModuloByZero;
            return formatResult(allocator, @mod(values[0], values[1]));
        }
        if (std.mem.eql(u8, operation, "pow")) {
            if (values.len != 2) return error.PowRequiresTwoValues;
            return formatResult(allocator, std.math.pow(f64, values[0], values[1]));
        }
        if (std.mem.eql(u8, operation, "sqrt")) {
            if (values.len != 1) return error.SqrtRequiresOneValue;
            if (values[0] < 0.0) return error.SqrtNegativeValue;
            return formatResult(allocator, @sqrt(values[0]));
        }
        if (std.mem.eql(u8, operation, "log")) {
            if (values.len != 1) return error.LogRequiresOneValue;
            if (values[0] <= 0.0) return error.LogRequiresPositiveValue;
            return formatResult(allocator, std.math.log10(values[0]));
        }
        if (std.mem.eql(u8, operation, "log_base")) {
            if (values.len != 2) return error.LogBaseRequiresTwoValues;
            if (values[0] <= 0.0) return error.LogBaseRequiresPositiveValue;
            if (values[1] <= 0.0) return error.LogBaseInvalidBase;
            if (values[1] == 1.0) return error.LogBaseInvalidBase;
            return formatResult(allocator, @log(values[0]) / @log(values[1]));
        }
        if (std.mem.eql(u8, operation, "ln")) {
            if (values.len != 1) return error.LnRequiresOneValue;
            if (values[0] <= 0.0) return error.LnRequiresPositiveValue;
            return formatResult(allocator, @log(values[0]));
        }
        if (std.mem.eql(u8, operation, "exp")) {
            if (values.len != 1) return error.ExpRequiresOneValue;
            return formatResult(allocator, @exp(values[0]));
        }
        if (std.mem.eql(u8, operation, "average")) {
            if (values.len < 1) return error.AverageRequiresValues;
            var sum: f64 = 0.0;
            for (values) |v| sum += v;
            return formatResult(allocator, sum / @as(f64, @floatFromInt(values.len)));
        }
        if (std.mem.eql(u8, operation, "median")) {
            if (values.len < 1) return error.MedianRequiresValues;
            return formatResult(allocator, median(values));
        }
        if (std.mem.eql(u8, operation, "variance")) {
            if (values.len < 1) return error.VarianceRequiresValues;
            return formatResult(allocator, populationVariance(values));
        }
        if (std.mem.eql(u8, operation, "stdev_population")) {
            if (values.len < 1) return error.StdevPopulationRequiresValues;
            return formatResult(allocator, populationStdev(values));
        }
        if (std.mem.eql(u8, operation, "stdev_sample")) {
            if (values.len < 2) return error.StdevSampleRequiresTwoValues;
            return formatResult(allocator, sampleStdev(values));
        }
        if (std.mem.eql(u8, operation, "min")) {
            if (values.len < 1) return error.MinRequiresValues;
            var m = values[0];
            for (values[1..]) |v| {
                if (v < m) m = v;
            }
            return formatResult(allocator, m);
        }
        if (std.mem.eql(u8, operation, "max")) {
            if (values.len < 1) return error.MaxRequiresValues;
            var m = values[0];
            for (values[1..]) |v| {
                if (v > m) m = v;
            }
            return formatResult(allocator, m);
        }
        if (std.mem.eql(u8, operation, "count")) {
            if (values.len < 1) return error.CountRequiresValues;
            return formatResult(allocator, @floatFromInt(values.len));
        }
        if (std.mem.eql(u8, operation, "percentile")) {
            if (values.len < 1) return error.PercentileRequiresValues;
            const rank_raw = root.getInt(args, "percentile_rank") orelse {
                return error.PercentileRequiresRank;
            };
            const rank: i64 = if (rank_raw >= 0 and rank_raw <= 100) rank_raw else {
                return error.PercentileRankOutOfRange;
            };
            return formatResult(allocator, percentile(values, @floatFromInt(rank)));
        }
        if (std.mem.eql(u8, operation, "abs")) {
            if (values.len != 1) return error.AbsRequiresOneValue;
            return formatResult(allocator, @abs(values[0]));
        }
        if (std.mem.eql(u8, operation, "floor")) {
            if (values.len != 1) return error.FloorRequiresOneValue;
            return formatResult(allocator, @floor(values[0]));
        }
        if (std.mem.eql(u8, operation, "ceil")) {
            if (values.len != 1) return error.CeilRequiresOneValue;
            return formatResult(allocator, @ceil(values[0]));
        }
        if (std.mem.eql(u8, operation, "round")) {
            if (values.len != 1) return error.RoundRequiresOneValue;
            return formatResult(allocator, @round(values[0]));
        }

        return error.UnknownOperation;
    }

    fn median(values: []f64) f64 {
        sortValues(values);
        const n = values.len;
        if (n % 2 == 1) {
            return values[n / 2];
        }
        return (values[n / 2 - 1] + values[n / 2]) / 2.0;
    }

    fn populationVariance(values: []const f64) f64 {
        const n: f64 = @floatFromInt(values.len);
        const mean = averageValue(values);
        var sq_diff_sum: f64 = 0.0;
        for (values) |v| {
            const diff = v - mean;
            sq_diff_sum += diff * diff;
        }
        return sq_diff_sum / n;
    }

    fn sampleVariance(values: []const f64) f64 {
        const n: f64 = @floatFromInt(values.len);
        const mean = averageValue(values);
        var sq_diff_sum: f64 = 0.0;
        for (values) |v| {
            const diff = v - mean;
            sq_diff_sum += diff * diff;
        }
        return sq_diff_sum / (n - 1.0);
    }

    fn populationStdev(values: []const f64) f64 {
        return @sqrt(populationVariance(values));
    }

    fn sampleStdev(values: []const f64) f64 {
        return @sqrt(sampleVariance(values));
    }

    fn averageValue(values: []const f64) f64 {
        var sum: f64 = 0.0;
        for (values) |v| sum += v;
        return sum / @as(f64, @floatFromInt(values.len));
    }

    fn percentile(values: []f64, rank: f64) f64 {
        sortValues(values);
        const n = values.len;
        if (n == 1) return values[0];
        const idx = (rank / 100.0) * (@as(f64, @floatFromInt(n)) - 1.0);
        const lower: usize = @intFromFloat(@floor(idx));
        const upper: usize = @min(lower + 1, n - 1);
        const frac = idx - @as(f64, @floatFromInt(lower));
        return values[lower] + frac * (values[upper] - values[lower]);
    }

    fn sortValues(values: []f64) void {
        if (values.len > 1) {
            std.mem.sort(f64, values, {}, struct {
                fn lessThan(_: void, a: f64, b: f64) bool {
                    return a < b;
                }
            }.lessThan);
        }
    }

    fn formatResult(allocator: std.mem.Allocator, value: f64) ![]const u8 {
        if (!std.math.isFinite(value)) return error.ResultNotFinite;

        const normalized = if (value == 0.0) 0.0 else value;
        const raw = if (shouldUseScientificNotation(normalized))
            try std.fmt.allocPrint(allocator, "{e:.6}", .{normalized})
        else
            try std.fmt.allocPrint(allocator, "{d:.6}", .{normalized});
        errdefer allocator.free(raw);

        const trimmed = try trimFormattedFloat(allocator, raw);
        if (trimmed.len == raw.len) return raw;

        allocator.free(raw);
        return trimmed;
    }

    fn shouldUseScientificNotation(value: f64) bool {
        const abs_value = @abs(value);
        return abs_value >= MAX_FIXED_NOTATION_ABS or (abs_value > 0.0 and abs_value < MIN_FIXED_NOTATION_ABS);
    }

    fn trimFormattedFloat(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
        const exp_index = std.mem.indexOfScalar(u8, raw, 'e') orelse {
            const trimmed = trimFixedFloatStr(raw);
            return if (trimmed.len == raw.len) raw else try allocator.dupe(u8, trimmed);
        };

        const trimmed_mantissa = trimFixedFloatStr(raw[0..exp_index]);
        if (trimmed_mantissa.len == exp_index) return raw;

        var result = std.ArrayList(u8).empty;
        errdefer result.deinit(allocator);
        try result.ensureTotalCapacity(allocator, trimmed_mantissa.len + raw.len - exp_index);
        try result.appendSlice(allocator, trimmed_mantissa);
        try result.appendSlice(allocator, raw[exp_index..]);
        return result.toOwnedSlice(allocator);
    }

    fn trimFixedFloatStr(s: []const u8) []const u8 {
        const dot = std.mem.indexOfScalar(u8, s, '.') orelse return s;
        var end = s.len;
        while (end > dot + 1 and s[end - 1] == '0') : (end -= 1) {}
        return if (s[end - 1] == '.') s[0 .. end - 1] else s[0..end];
    }
};

test "calculator tool name and description" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    try std.testing.expectEqualStrings("calculator", t.name());
    try std.testing.expect(t.description().len > 0);
    try std.testing.expect(t.parametersJson().len > 0);
}

test "calculator add two numbers" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[3,5]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("8", result.output);
}

test "calculator add multiple numbers" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[1,2,3,4,5]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("15", result.output);
}

test "calculator add with float values" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[1.5,2.5]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("4", result.output);
}

test "calculator subtract" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"subtract\",\"values\":[10,3]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("7", result.output);
}

test "calculator subtract negative result" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"subtract\",\"values\":[3,10]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("-7", result.output);
}

test "calculator multiply" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"multiply\",\"values\":[3,4,5]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("60", result.output);
}

test "calculator divide" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"divide\",\"values\":[22,7]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("3.142857", result.output);
}

test "calculator divide by zero" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"divide\",\"values\":[10,0]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "DivisionByZero") != null);
}

test "calculator mod" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"mod\",\"values\":[10,3]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("1", result.output);
}

test "calculator mod by zero" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"mod\",\"values\":[10,0]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "ModuloByZero") != null);
}

test "calculator pow" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"pow\",\"values\":[2,10]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("1024", result.output);
}

test "calculator sqrt" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"sqrt\",\"values\":[144]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("12", result.output);
}

test "calculator sqrt negative" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"sqrt\",\"values\":[-4]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator log" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"log\",\"values\":[1000]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("3", result.output);
}

test "calculator log base" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"log_base\",\"values\":[64,2]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("6", result.output);
}

test "calculator log base rejects invalid base" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"log_base\",\"values\":[64,1]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "LogBaseInvalidBase") != null);
}

test "calculator ln" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"ln\",\"values\":[2.718281828]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "1") != null);
}

test "calculator exp" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"exp\",\"values\":[0]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "1") != null);
}

test "calculator average" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"average\",\"values\":[10,20,30]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("20", result.output);
}

test "calculator median odd count" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"median\",\"values\":[5,2,8,1,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("5", result.output);
}

test "calculator median even count" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"median\",\"values\":[4,1,3,2]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("2.5", result.output);
}

test "calculator variance" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"variance\",\"values\":[2,4,4,4,5,5,7,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("4", result.output);
}

test "calculator stdev population" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"stdev_population\",\"values\":[2,4,4,4,5,5,7,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("2", result.output);
}

test "calculator stdev population single value" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"stdev_population\",\"values\":[42]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("0", result.output);
}

test "calculator stdev sample" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"stdev_sample\",\"values\":[2,4,4,4,5,5,7,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("2.13809", result.output);
}

test "calculator stdev sample single value rejected" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"stdev_sample\",\"values\":[42]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator min" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"min\",\"values\":[5,3,8,1,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("1", result.output);
}

test "calculator max" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"max\",\"values\":[5,3,8,1,9]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("9", result.output);
}

test "calculator count" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"count\",\"values\":[1,2,3,4,5,6,7]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("7", result.output);
}

test "calculator percentile" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"percentile\",\"values\":[1,2,3,4,5,6,7,8,9,10],\"percentile_rank\":50}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("5.5", result.output);
}

test "calculator percentile p25" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"percentile\",\"values\":[10,20,30,40,50],\"percentile_rank\":25}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("20", result.output);
}

test "calculator percentile missing rank" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"percentile\",\"values\":[1,2,3]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator abs" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"abs\",\"values\":[-42]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("42", result.output);
}

test "calculator floor" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"floor\",\"values\":[3.7]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("3", result.output);
}

test "calculator ceil" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"ceil\",\"values\":[3.2]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("4", result.output);
}

test "calculator round" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"round\",\"values\":[3.5]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("4", result.output);
}

test "calculator round normalizes negative zero" {
    // Regression: round(-0.4) used to return the confusing string "-0".
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"round\",\"values\":[-0.4]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("0", result.output);
}

test "calculator missing operation" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"values\":[1,2]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator missing values" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator unknown operation" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"fibonacci\",\"values\":[10]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator subtract wrong arg count" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"subtract\",\"values\":[10]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator empty values array" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator log zero" {
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"log\",\"values\":[0]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "calculator invalid values return failed tool result" {
    // Regression: non-numeric values used to escape as a raw error and double-free the values buffer.
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[1,\"oops\"]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("InvalidNumber", result.output);
}

test "calculator rejects integers beyond exact float precision" {
    // Regression: large JSON integers used to be rounded silently when converted to f64.
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"add\",\"values\":[9007199254740993,1]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("IntegerPrecisionLoss", result.output);
}

test "calculator median handles values beyond 1024 items" {
    // Regression: median used to sort only the first 1024 values and ignore later entries.
    const values = try std.testing.allocator.alloc(f64, 1026);
    defer std.testing.allocator.free(values);

    for (values[0..1024], 0..) |*value, i| {
        value.* = @floatFromInt(i + 1);
    }
    values[1024] = -1001.0;
    values[1025] = -1000.0;

    try std.testing.expectEqual(@as(f64, 511.5), CalculatorTool.median(values));
}

test "calculator percentile handles values beyond 1024 items" {
    // Regression: percentile used to index past the fixed 1024-item scratch buffer.
    const values = try std.testing.allocator.alloc(f64, 1025);
    defer std.testing.allocator.free(values);

    for (values, 0..) |*value, i| {
        value.* = @floatFromInt(i);
    }

    try std.testing.expectEqual(@as(f64, 1024.0), CalculatorTool.percentile(values, 100.0));
}

test "calculator formats large finite results with scientific notation" {
    // Regression: large finite outputs used to allocate huge fixed-point strings and could degrade into "0".
    const result = try CalculatorTool.formatResult(std.testing.allocator, std.math.pow(f64, 10.0, 100.0));
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings("1e100", result);
}

test "calculator preserves tiny non-zero results" {
    // Regression: tiny finite outputs used to round down to the literal string "0".
    const result = try CalculatorTool.formatResult(std.testing.allocator, 0.0000004);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings("4e-7", result);
}

test "calculator rejects non-finite results" {
    // Regression: overflow paths used to surface "inf" instead of a failed tool result.
    var ct = CalculatorTool{};
    const t = ct.tool();
    const parsed = try root.parseTestArgs("{\"operation\":\"exp\",\"values\":[1000]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("ResultNotFinite", result.output);
}
