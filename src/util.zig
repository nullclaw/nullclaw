const std = @import("std");

/// Format bytes as human-readable string (e.g. "3.4 MB")
pub fn formatBytes(bytes: u64) struct { value: f64, unit: []const u8 } {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var size: f64 = @floatFromInt(bytes);
    var idx: usize = 0;
    while (size >= 1024.0 and idx < units.len - 1) : (idx += 1) {
        size /= 1024.0;
    }
    return .{ .value = size, .unit = units[idx] };
}

/// Get current timestamp as ISO 8601 string
pub fn timestamp(buf: []u8) []const u8 {
    const epoch = std.time.timestamp();
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(epoch) };
    const day = epoch_seconds.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    const result = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch "0000-00-00T00:00:00Z";

    return result;
}

test "formatBytes" {
    const result = formatBytes(3_500_000);
    try std.testing.expect(result.value > 3.3 and result.value < 3.4);
    try std.testing.expectEqualStrings("MB", result.unit);
}

test "timestamp produces valid length" {
    var buf: [32]u8 = undefined;
    const ts = timestamp(&buf);
    try std.testing.expectEqual(@as(usize, 20), ts.len);
}

// ── Additional util tests ───────────────────────────────────────

test "formatBytes zero" {
    const result = formatBytes(0);
    try std.testing.expect(result.value == 0.0);
    try std.testing.expectEqualStrings("B", result.unit);
}

test "formatBytes exact KB" {
    const result = formatBytes(1024);
    try std.testing.expect(result.value == 1.0);
    try std.testing.expectEqualStrings("KB", result.unit);
}

test "formatBytes exact MB" {
    const result = formatBytes(1024 * 1024);
    try std.testing.expect(result.value == 1.0);
    try std.testing.expectEqualStrings("MB", result.unit);
}

test "formatBytes exact GB" {
    const result = formatBytes(1024 * 1024 * 1024);
    try std.testing.expect(result.value == 1.0);
    try std.testing.expectEqualStrings("GB", result.unit);
}

test "formatBytes exact TB" {
    const result = formatBytes(1024 * 1024 * 1024 * 1024);
    try std.testing.expect(result.value == 1.0);
    try std.testing.expectEqualStrings("TB", result.unit);
}

test "formatBytes small value stays in bytes" {
    const result = formatBytes(500);
    try std.testing.expect(result.value == 500.0);
    try std.testing.expectEqualStrings("B", result.unit);
}

test "formatBytes 1 byte" {
    const result = formatBytes(1);
    try std.testing.expect(result.value == 1.0);
    try std.testing.expectEqualStrings("B", result.unit);
}

test "formatBytes large value" {
    const result = formatBytes(5 * 1024 * 1024 * 1024 * 1024);
    try std.testing.expect(result.value > 4.9 and result.value < 5.1);
    try std.testing.expectEqualStrings("TB", result.unit);
}

test "timestamp ends with Z" {
    var buf: [32]u8 = undefined;
    const ts = timestamp(&buf);
    try std.testing.expect(ts[ts.len - 1] == 'Z');
}

test "timestamp contains T separator" {
    var buf: [32]u8 = undefined;
    const ts = timestamp(&buf);
    try std.testing.expect(std.mem.indexOf(u8, ts, "T") != null);
}
