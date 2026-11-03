const std = @import("std");
const common = @import("common.zig");

/// Free public endpoint; no API key required.
pub const PUBLIC_ENDPOINT = "https://api.keenable.ai/v1/search/public";
/// Keyed endpoint (higher limits), authenticated with `X-API-Key`.
pub const KEYED_ENDPOINT = "https://api.keenable.ai/v1/search";
/// Maximum bytes kept from `snippet` when a result has no `description`.
const MAX_SNIPPET_BYTES: usize = 1000;

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: ?[]const u8,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const payload = .{
        .query = query,
        .max_results = count,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    var key_header: ?[]u8 = null;
    defer if (key_header) |h| allocator.free(h);
    if (api_key) |key| key_header = try std.fmt.allocPrint(allocator, "X-API-Key: {s}", .{key});

    const base_headers = [_][]const u8{
        "Content-Type: application/json",
        "Accept: application/json",
        "X-Keenable-Title: nullclaw",
    };
    var headers_buf: [base_headers.len + 1][]const u8 = undefined;
    @memcpy(headers_buf[0..base_headers.len], &base_headers);
    var header_count: usize = base_headers.len;
    if (key_header) |h| {
        headers_buf[header_count] = h;
        header_count += 1;
    }

    const endpoint = if (api_key != null) KEYED_ENDPOINT else PUBLIC_ENDPOINT;
    const body = common.curlPostJson(allocator, endpoint, body_json, headers_buf[0..header_count], timeout_str) catch |err| {
        common.logRequestError("keenable", query, err);
        return err;
    };
    defer allocator.free(body);

    var parsed = try common.parseJsonObject(allocator, body);
    defer parsed.deinit();

    const results_arr = try common.requireArrayField(parsed.object, "results");
    return formatResults(allocator, results_arr, query, count);
}

/// Format Keenable results: skip entries without a URL, prefer the short
/// `description`, and fall back to a truncated `snippet`.
pub fn formatResults(
    allocator: std.mem.Allocator,
    items: []const std.json.Value,
    query: []const u8,
    count: usize,
) !common.ToolResult {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.print(allocator, "Results for: {s}\n\n", .{query});

    var out_idx: usize = 0;
    for (items) |item| {
        if (out_idx >= count) break;
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const url = common.extractString(obj, "url") orelse continue;
        if (url.len == 0) continue;
        const title = common.extractString(obj, "title") orelse "(no title)";
        const desc = blk: {
            if (common.extractString(obj, "description")) |d| {
                if (d.len > 0) break :blk d;
            }
            if (common.extractString(obj, "snippet")) |s| break :blk truncateUtf8(s, MAX_SNIPPET_BYTES);
            break :blk "";
        };

        out_idx += 1;
        try buf.print(allocator, "{d}. {s}\n   {s}\n", .{ out_idx, title, url });
        if (desc.len > 0) try buf.print(allocator, "   {s}\n", .{desc});
        try buf.append(allocator, '\n');
    }

    if (out_idx == 0) {
        buf.deinit(allocator);
        return common.noWebResults(allocator);
    }

    return common.ToolResult.ok(try buf.toOwnedSlice(allocator));
}

/// Truncate to at most `max` bytes without splitting a UTF-8 code point.
fn truncateUtf8(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and (text[end] & 0xC0) == 0x80) end -= 1;
    return text[0..end];
}

test "formatResults prefers description, truncates snippet and skips missing urls" {
    const allocator = std.testing.allocator;
    const long_snippet = "x" ** 1500;
    const json_text =
        \\{"results":[
        \\  {"title":"A","url":"https://a.example","description":"short","snippet":"long"},
        \\  {"title":"No URL","description":"dropped"},
        \\  {"title":"B","url":"https://b.example","snippet":"
    ++ long_snippet ++
        \\"}
        \\]}
    ;
    var parsed = try common.parseJsonObject(allocator, json_text);
    defer parsed.deinit();
    const items = try common.requireArrayField(parsed.object, "results");

    const result = try formatResults(allocator, items, "q", 5);
    defer allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "1. A\n   https://a.example\n   short\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "dropped") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "2. B") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "x" ** 1001) == null);
}

test "formatResults respects count" {
    const allocator = std.testing.allocator;
    var parsed = try common.parseJsonObject(allocator,
        \\{"results":[{"title":"A","url":"https://a.example"},{"title":"B","url":"https://b.example"}]}
    );
    defer parsed.deinit();
    const items = try common.requireArrayField(parsed.object, "results");

    const result = try formatResults(allocator, items, "q", 1);
    defer allocator.free(result.output);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "2. B") == null);
}

test "truncateUtf8 does not split code points" {
    try std.testing.expectEqualStrings("ab", truncateUtf8("ab\xc3\xa9", 3));
    try std.testing.expectEqualStrings("abc", truncateUtf8("abc", 10));
}
