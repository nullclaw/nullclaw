const std = @import("std");
const std_compat = @import("compat");

const MAX_PROVIDER_BYTES: usize = 64;
const MAX_DETAIL_BYTES: usize = 2048;

var mutex: std_compat.sync.Mutex = .{};
var last_provider_buf: [MAX_PROVIDER_BYTES]u8 = undefined;
var last_provider_len: usize = 0;
var last_detail_buf: [MAX_DETAIL_BYTES]u8 = undefined;
var last_detail_len: usize = 0;

fn copyTrimmedBounded(dst: []u8, src: []const u8) usize {
    const trimmed = std.mem.trim(u8, src, " \t\r\n");
    const n = @min(dst.len, trimmed.len);
    if (n == 0) return 0;
    @memcpy(dst[0..n], trimmed[0..n]);
    return n;
}

/// Clear the process-global last provider API error detail.
pub fn clear() void {
    mutex.lock();
    defer mutex.unlock();
    last_provider_len = 0;
    last_detail_len = 0;
}

/// Record the last provider API error detail (best-effort, truncated).
pub fn set(provider_name: []const u8, detail: []const u8) void {
    mutex.lock();
    defer mutex.unlock();

    last_provider_len = copyTrimmedBounded(&last_provider_buf, provider_name);
    last_detail_len = copyTrimmedBounded(&last_detail_buf, detail);
}

/// Return a heap-owned snapshot of the last recorded provider API error.
/// Format: "<provider>: <detail>" or just "<detail>" when provider is empty.
pub fn snapshot(allocator: std.mem.Allocator) !?[]u8 {
    mutex.lock();
    defer mutex.unlock();

    if (last_detail_len == 0) return null;

    const detail = last_detail_buf[0..last_detail_len];
    if (last_provider_len == 0) {
        return try allocator.dupe(u8, detail);
    }

    const provider = last_provider_buf[0..last_provider_len];
    return try std.fmt.allocPrint(allocator, "{s}: {s}", .{ provider, detail });
}

test "api error detail set snapshot clear" {
    clear();
    try std.testing.expect((try snapshot(std.testing.allocator)) == null);

    set("gemini", "status=503 message=high demand");
    const snap = (try snapshot(std.testing.allocator)).?;
    defer std.testing.allocator.free(snap);
    try std.testing.expectEqualStrings("gemini: status=503 message=high demand", snap);

    clear();
    try std.testing.expect((try snapshot(std.testing.allocator)) == null);
}

test "api error detail truncates oversized provider and detail" {
    clear();

    var provider_buf: [MAX_PROVIDER_BYTES + 20]u8 = undefined;
    @memset(&provider_buf, 'p');
    var detail_buf: [MAX_DETAIL_BYTES + 50]u8 = undefined;
    @memset(&detail_buf, 'd');

    set(&provider_buf, &detail_buf);
    const snap = (try snapshot(std.testing.allocator)).?;
    defer std.testing.allocator.free(snap);

    try std.testing.expect(snap.len > 0);
    try std.testing.expect(snap.len <= MAX_PROVIDER_BYTES + 2 + MAX_DETAIL_BYTES);
}
