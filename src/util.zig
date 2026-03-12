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

// ── JSON helpers ────────────────────────────────────────────────

/// Append a string to an ArrayList with JSON escaping (quotes, backslashes, control chars).
/// Used by embedding providers, vector stores, and API backends when building JSON payloads.
pub fn appendJsonEscaped(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    for (text) |ch| {
        switch (ch) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    var hex_buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{ch}) catch continue;
                    try buf.appendSlice(allocator, hex);
                } else {
                    try buf.append(allocator, ch);
                }
            },
        }
    }
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

test "appendJsonEscaped basic text" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonEscaped(&buf, std.testing.allocator, "hello world");
    try std.testing.expectEqualStrings("hello world", buf.items);
}

test "appendJsonEscaped escapes special chars" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonEscaped(&buf, std.testing.allocator, "say \"hello\"\nnewline\\backslash");
    try std.testing.expectEqualStrings("say \\\"hello\\\"\\nnewline\\\\backslash", buf.items);
}

test "appendJsonEscaped escapes control chars" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonEscaped(&buf, std.testing.allocator, "tab\there\rreturn");
    try std.testing.expectEqualStrings("tab\\there\\rreturn", buf.items);
}

test "appendJsonEscaped empty string" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendJsonEscaped(&buf, std.testing.allocator, "");
    try std.testing.expectEqual(@as(usize, 0), buf.items.len);
}

// ── Python module check ─────────────────────────────────────────

/// Check if a Python module is available by attempting to import it.
/// Returns true if the module can be imported successfully.
pub fn checkPythonModule(allocator: std.mem.Allocator, module_name: []const u8) bool {
    const code = std.fmt.allocPrint(allocator, "import {s}", .{module_name}) catch return false;
    defer allocator.free(code);
    const argv = &[_][]const u8{ "python3", "-c", code };
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    switch (term) {
        .Exited => |code_val| return code_val == 0,
        else => return false,
    }
}

test "checkPythonModule detects available module" {
    // sys is always available
    try std.testing.expect(checkPythonModule(std.testing.allocator, "sys"));
}

test "checkPythonModule returns false for nonexistent module" {
    // this_module_definitely_does_not_exist_12345 should not exist
    try std.testing.expect(!checkPythonModule(std.testing.allocator, "this_module_definitely_does_not_exist_12345"));
}
