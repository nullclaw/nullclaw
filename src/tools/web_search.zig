//! Web Search Tool — internet search via Brave Search API.
//!
//! Provides web search capability for the agent. Requires BRAVE_API_KEY
//! environment variable (free tier available at https://brave.com/search/api/).

const std = @import("std");
const root = @import("root.zig");
const platform = @import("../platform.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

const log = std.log.scoped(.web_search);

/// Maximum number of search results.
const MAX_RESULTS: usize = 10;
/// Default number of search results.
const DEFAULT_COUNT: usize = 5;

/// Web search tool using Brave Search API.
pub const WebSearchTool = struct {
    pub const tool_name = "web_search";
    pub const tool_description = "Search the web using Brave Search API. Returns titles, URLs, and descriptions. Requires BRAVE_API_KEY env var.";
    pub const tool_params =
        \\{"type":"object","properties":{"query":{"type":"string","minLength":1,"description":"Search query"},"count":{"type":"integer","minimum":1,"maximum":10,"default":5,"description":"Number of results (1-10)"}},"required":["query"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *WebSearchTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *WebSearchTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const query = root.getString(args, "query") orelse
            return ToolResult.fail("Missing required 'query' parameter");

        if (std.mem.trim(u8, query, " \t\n\r").len == 0)
            return ToolResult.fail("'query' must not be empty");

        const count = parseCount(args);

        // Get API key from environment
        const api_key = platform.getEnvOrNull(allocator, "BRAVE_API_KEY") orelse
            return ToolResult.fail("BRAVE_API_KEY environment variable not set. Get a free key at https://brave.com/search/api/");
        defer allocator.free(api_key);

        if (api_key.len == 0)
            return ToolResult.fail("BRAVE_API_KEY is empty");

        // URL-encode query
        const encoded_query = try urlEncode(allocator, query);
        defer allocator.free(encoded_query);

        // Build URL
        const url_str = try std.fmt.allocPrint(
            allocator,
            "https://api.search.brave.com/res/v1/web/search?q={s}&count={d}",
            .{ encoded_query, count },
        );
        defer allocator.free(url_str);

        // Make HTTP request via curl subprocess
        const auth_header = try std.fmt.allocPrint(allocator, "X-Subscription-Token: {s}", .{api_key});
        defer allocator.free(auth_header);
        const headers = [_][]const u8{
            auth_header,
            "Accept: application/json",
        };

        const body = @import("../http_util.zig").curlGet(
            allocator,
            url_str,
            &headers,
            "30",
        ) catch |err| {
            log.err("web_search request failed for '{s}': {}", .{ query, err });
            const msg = try std.fmt.allocPrint(allocator, "Search request failed: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(body);

        // Parse JSON response and format results
        return formatBraveResults(allocator, body, query);
    }
};

/// Parse count from args ObjectMap. Returns DEFAULT_COUNT if not found or invalid.
fn parseCount(args: JsonObjectMap) usize {
    const val_i64 = root.getInt(args, "count") orelse return DEFAULT_COUNT;
    if (val_i64 < 1) return 1;
    const val: usize = if (val_i64 > @as(i64, @intCast(MAX_RESULTS))) MAX_RESULTS else @intCast(val_i64);
    return val;
}

/// URL-encode a string (percent-encoding).
pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try buf.append(allocator, c);
        } else if (c == ' ') {
            try buf.append(allocator, '+');
        } else {
            try buf.appendSlice(allocator, &.{ '%', hexDigit(c >> 4), hexDigit(c & 0x0f) });
        }
    }
    return buf.toOwnedSlice(allocator);
}

fn hexDigit(v: u8) u8 {
    return "0123456789ABCDEF"[v & 0x0f];
}

/// Parse Brave Search JSON and format as text results.
pub fn formatBraveResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8) !ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch
        return ToolResult.fail("Failed to parse search response JSON");
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return ToolResult.fail("Unexpected search response format"),
    };

    // Extract web results
    const web = root_val.get("web") orelse
        return ToolResult.ok("No web results found.");

    const web_obj = switch (web) {
        .object => |o| o,
        else => return ToolResult.ok("No web results found."),
    };

    const results = web_obj.get("results") orelse
        return ToolResult.ok("No web results found.");

    const results_arr = switch (results) {
        .array => |a| a,
        else => return ToolResult.ok("No web results found."),
    };

    if (results_arr.items.len == 0)
        return ToolResult.ok("No web results found.");

    // Format results
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try std.fmt.format(buf.writer(allocator), "Results for: {s}\n\n", .{query});

    for (results_arr.items, 0..) |item, i| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const title = extractString(obj, "title") orelse "(no title)";
        const url = extractString(obj, "url") orelse "(no url)";
        const desc = extractString(obj, "description") orelse "";

        try std.fmt.format(buf.writer(allocator), "{d}. {s}\n   {s}\n", .{ i + 1, title, url });
        if (desc.len > 0) {
            try std.fmt.format(buf.writer(allocator), "   {s}\n", .{desc});
        }
        try buf.append(allocator, '\n');
    }

    return ToolResult.ok(try buf.toOwnedSlice(allocator));
}

fn extractString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

const testing = std.testing;

test "WebSearchTool name and description" {
    var wst = WebSearchTool{};
    const t = wst.tool();
    try testing.expectEqualStrings("web_search", t.name());
    try testing.expect(t.description().len > 0);
    try testing.expect(t.parametersJson()[0] == '{');
}

test "WebSearchTool missing query fails" {
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"count\":5}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Missing required 'query' parameter", result.error_msg.?);
}

test "WebSearchTool empty query fails" {
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"query\":\"  \"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("'query' must not be empty", result.error_msg.?);
}

test "WebSearchTool no API key fails with helpful message" {
    // This test relies on BRAVE_API_KEY not being set in test env
    // If it is set, the test would try to make a real request
    if (platform.getEnvOrNull(testing.allocator, "BRAVE_API_KEY")) |k| {
        testing.allocator.free(k);
        return;
    }
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"query\":\"zig programming\"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "BRAVE_API_KEY") != null);
}

test "parseCount defaults to 5" {
    const p1 = try root.parseTestArgs("{}");
    defer p1.deinit();
    try testing.expectEqual(@as(usize, DEFAULT_COUNT), parseCount(p1.value.object));
    const p2 = try root.parseTestArgs("{\"query\":\"test\"}");
    defer p2.deinit();
    try testing.expectEqual(@as(usize, DEFAULT_COUNT), parseCount(p2.value.object));
}

test "parseCount clamps to range" {
    const p1 = try root.parseTestArgs("{\"count\":0}");
    defer p1.deinit();
    try testing.expectEqual(@as(usize, 1), parseCount(p1.value.object));
    const p2 = try root.parseTestArgs("{\"count\":100}");
    defer p2.deinit();
    try testing.expectEqual(@as(usize, MAX_RESULTS), parseCount(p2.value.object));
    const p3 = try root.parseTestArgs("{\"count\":3}");
    defer p3.deinit();
    try testing.expectEqual(@as(usize, 3), parseCount(p3.value.object));
}

test "urlEncode basic" {
    const encoded = try urlEncode(testing.allocator, "hello world");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("hello+world", encoded);
}

test "urlEncode special chars" {
    const encoded = try urlEncode(testing.allocator, "a&b=c");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("a%26b%3Dc", encoded);
}

test "urlEncode passthrough" {
    const encoded = try urlEncode(testing.allocator, "simple-test_123.txt~");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("simple-test_123.txt~", encoded);
}

test "formatBraveResults parses valid JSON" {
    const json =
        \\{"web":{"results":[
        \\  {"title":"Zig Language","url":"https://ziglang.org","description":"Zig is a systems language."},
        \\  {"title":"Zig GitHub","url":"https://github.com/ziglang/zig","description":"Source code."}
        \\]}}
    ;
    const result = try formatBraveResults(testing.allocator, json, "zig programming");
    defer testing.allocator.free(result.output);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "Results for: zig programming") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "1. Zig Language") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "https://ziglang.org") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "2. Zig GitHub") != null);
}

test "formatBraveResults empty results" {
    const json = "{\"web\":{\"results\":[]}}";
    const result = try formatBraveResults(testing.allocator, json, "nothing");
    try testing.expect(result.success);
    try testing.expectEqualStrings("No web results found.", result.output);
}

test "formatBraveResults no web key" {
    const json = "{\"query\":{\"original\":\"test\"}}";
    const result = try formatBraveResults(testing.allocator, json, "test");
    try testing.expect(result.success);
    try testing.expectEqualStrings("No web results found.", result.output);
}

test "formatBraveResults invalid JSON" {
    const result = try formatBraveResults(testing.allocator, "not json", "q");
    try testing.expect(!result.success);
}
