const std = @import("std");
const common = @import("common.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const endpoint = "https://api.tavily.com/search";
    const payload = .{
        .api_key = api_key,
        .query = query,
        .max_results = count,
        .search_depth = "basic",
        .include_answer = false,
        .include_raw_content = false,
        .include_images = false,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = common.curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        common.logRequestError("tavily", query, err);
        return err;
    };
    defer allocator.free(body);

    var parsed = try common.parseJsonObject(allocator, body);
    defer parsed.deinit();

    if (parsed.object.get("error")) |_| return error.RequestFailed;

    const results_arr = try common.requireArrayField(parsed.object, "results");
    return common.formatResultsArray(allocator, results_arr, query, "content", null);
}
