const std = @import("std");
const common = @import("common.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const encoded_query = try common.urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(
        allocator,
        "https://api.serply.io/v1/search?q={s}&num={d}",
        .{ encoded_query, count },
    );
    defer allocator.free(url_str);

    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const auth_header = try std.fmt.allocPrint(allocator, "X-Api-Key: {s}", .{api_key});
    defer allocator.free(auth_header);
    const headers = [_][]const u8{
        auth_header,
        "User-Agent: nullclaw/0.1 (web_search)",
        "Accept: application/json",
    };

    const body = common.curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        common.logRequestError("serply", query, err);
        return err;
    };
    defer allocator.free(body);

    const result = try formatResults(allocator, body, query, count);
    if (!result.success) return error.InvalidResponse;
    return result;
}

pub fn formatResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8, count: usize) !common.ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch
        return common.ToolResult.fail("Failed to parse search response JSON");
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return common.ToolResult.fail("Unexpected search response format"),
    };

    // Serply reports auth and quota problems as {"detail": ...}; fail so fallbacks run.
    if (root_val.get("detail") != null)
        return common.ToolResult.fail("Serply returned an error response");

    const results = root_val.get("results") orelse
        return common.noWebResults(allocator);

    const results_arr = switch (results) {
        .array => |a| a,
        else => return common.noWebResults(allocator),
    };

    if (results_arr.items.len == 0)
        return common.noWebResults(allocator);

    // The API caps num at 10 but may return more rows than asked for.
    const limit = @min(count, results_arr.items.len);
    return common.formatResultsArray(allocator, results_arr.items[0..limit], query, "description", null);
}

test "formatResults parses link and description" {
    const json =
        \\{"results":[
        \\  {"title":"Zig Language","link":"https://ziglang.org","description":"Zig is a systems language.","result_type":"organic"},
        \\  {"title":"Zig GitHub","link":"https://github.com/ziglang/zig","description":"Source code."}
        \\]}
    ;
    const result = try formatResults(std.testing.allocator, json, "zig programming", 5);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Results for: zig programming") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "1. Zig Language") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "https://ziglang.org") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Zig is a systems language.") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "2. Zig GitHub") != null);
}

test "formatResults trims rows to requested count" {
    const json =
        \\{"results":[
        \\  {"title":"A","link":"https://a.example","description":"a"},
        \\  {"title":"B","link":"https://b.example","description":"b"},
        \\  {"title":"C","link":"https://c.example","description":"c"}
        \\]}
    ;
    const result = try formatResults(std.testing.allocator, json, "q", 2);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "2. B") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "3. C") == null);
}

test "formatResults empty or missing results" {
    const empty = try formatResults(std.testing.allocator, "{\"results\":[]}", "nothing", 5);
    defer std.testing.allocator.free(empty.output);
    try std.testing.expect(empty.success);
    try std.testing.expectEqualStrings("No web results found.", empty.output);

    const missing = try formatResults(std.testing.allocator, "{\"ads\":[]}", "nothing", 5);
    defer std.testing.allocator.free(missing.output);
    try std.testing.expect(missing.success);
    try std.testing.expectEqualStrings("No web results found.", missing.output);
}

test "formatResults fails on error payload" {
    const result = try formatResults(std.testing.allocator, "{\"detail\":\"Invalid API key\"}", "q", 5);
    try std.testing.expect(!result.success);
}

test "formatResults invalid JSON" {
    const result = try formatResults(std.testing.allocator, "not json", "q", 5);
    try std.testing.expect(!result.success);
}
