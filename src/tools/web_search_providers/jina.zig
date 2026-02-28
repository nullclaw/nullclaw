const std = @import("std");
const common = @import("common.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    api_key: []const u8,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const encoded_query = try common.urlEncodePath(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(allocator, "https://s.jina.ai/{s}", .{encoded_query});
    defer allocator.free(url_str);

    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
    defer allocator.free(auth_header);
    const x_key_header = try std.fmt.allocPrint(allocator, "x-api-key: {s}", .{api_key});
    defer allocator.free(x_key_header);

    const headers = [_][]const u8{
        "Accept: text/plain",
        auth_header,
        x_key_header,
    };

    const body = common.curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        common.logRequestError("jina", query, err);
        return err;
    };
    defer allocator.free(body);

    // Jina returns structured JSON on auth/API errors; avoid surfacing that as
    // successful plain-text search content.
    if (isApiErrorPayload(allocator, body)) return error.RequestFailed;

    return common.formatJinaPlainText(allocator, body, query);
}

fn isApiErrorPayload(allocator: std.mem.Allocator, body: []const u8) bool {
    const trimmed = std.mem.trim(u8, body, " \t\n\r");
    if (trimmed.len == 0 or trimmed[0] != '{') return false;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch return false;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return false,
    };

    if (obj.get("code")) |code| {
        if (code == .integer and code.integer >= 400) {
            if (obj.get("name") != null and obj.get("message") != null) {
                return true;
            }
        }
    }

    if (obj.get("status")) |status| {
        if (status == .integer and status.integer >= 400 and obj.get("message") != null) {
            return true;
        }
    }

    return false;
}

const testing = std.testing;

test "isApiErrorPayload detects jina auth error JSON" {
    const body =
        \\{"data":null,"code":401,"name":"AuthenticationRequiredError","status":40103,"message":"Authentication is required to use this endpoint. Please provide a valid API key via Authorization header.","readableMessage":"AuthenticationRequiredError: Authentication is required to use this endpoint. Please provide a valid API key via Authorization header."}
    ;
    try testing.expect(isApiErrorPayload(testing.allocator, body));
}

test "isApiErrorPayload ignores plain text content" {
    try testing.expect(!isApiErrorPayload(testing.allocator, "# Search Result\n\nZig language"));
}

test "isApiErrorPayload ignores non-error JSON object" {
    const body = "{\"title\":\"Some doc\",\"url\":\"https://example.com\"}";
    try testing.expect(!isApiErrorPayload(testing.allocator, body));
}
