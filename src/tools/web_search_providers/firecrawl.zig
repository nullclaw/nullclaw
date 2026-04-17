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

    const endpoint = "https://api.firecrawl.dev/v1/search";
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
    defer allocator.free(auth_header);

    const payload = .{
        .query = query,
        .limit = count,
        .timeout = timeout_secs * 1000,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        auth_header,
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = common.curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        common.logRequestError("firecrawl", query, err);
        return err;
    };
    defer allocator.free(body);

    var parsed = try common.parseJsonObject(allocator, body);
    defer parsed.deinit();

    if (parsed.object.get("success")) |success_val| {
        if (success_val != .bool or !success_val.bool) return error.RequestFailed;
    }

    const results_arr = try common.requireArrayField(parsed.object, "data");
    return common.formatResultsArray(allocator, results_arr, query, "description", null);
}
