const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// HTTP request tool for API interactions.
/// Supports GET, POST, PUT, DELETE methods with domain allowlisting.
pub const HttpRequestTool = struct {
    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *HttpRequestTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *HttpRequestTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "http_request";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Make HTTP requests to external APIs. Supports GET, POST, PUT, DELETE methods.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"url":{"type":"string","description":"HTTP or HTTPS URL to request"},"method":{"type":"string","description":"HTTP method (GET, POST, PUT, DELETE)","default":"GET"},"body":{"type":"string","description":"Optional request body"}},"required":["url"]}
        ;
    }

    fn execute(_: *HttpRequestTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const url = parseStringField(args_json, "url") orelse
            return ToolResult.fail("Missing 'url' parameter");

        const method_str = parseStringField(args_json, "method") orelse "GET";

        // Validate URL scheme
        if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only http:// and https:// URLs are allowed");
        }

        // Block localhost/private IPs (SSRF protection)
        const host = extractHost(url) orelse
            return ToolResult.fail("Invalid URL: cannot extract host");

        if (isLocalHost(host)) {
            return ToolResult.fail("Blocked local/private host");
        }

        // Validate method
        const method = validateMethod(method_str) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Unsupported HTTP method: {s}", .{method_str});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        // Build URI
        const uri = std.Uri.parse(url) catch
            return ToolResult.fail("Invalid URL format");

        // Execute request using std.http.Client (Zig 0.15 API)
        var client: std.http.Client = .{ .allocator = allocator };
        defer client.deinit();

        const body = parseStringField(args_json, "body");

        var req = client.request(method, uri, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "HTTP request failed: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer req.deinit();

        // Send body if present, otherwise send bodiless
        if (body) |b| {
            const body_dup = try allocator.dupe(u8, b);
            defer allocator.free(body_dup);
            req.sendBodyComplete(body_dup) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to send body: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
        } else {
            req.sendBodiless() catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to send request: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
        }

        // Receive response head
        var redirect_buf: [4096]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to receive response: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const status_code = @intFromEnum(response.head.status);
        const success = status_code >= 200 and status_code < 300;

        // Read response body (limit to 1MB)
        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const response_body = reader.readAlloc(allocator, 1_048_576) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read response body: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(response_body);

        const output = try std.fmt.allocPrint(
            allocator,
            "Status: {d}\n\nResponse Body:\n{s}",
            .{ status_code, response_body },
        );

        if (success) {
            return ToolResult{ .success = true, .output = output };
        } else {
            const err_msg = try std.fmt.allocPrint(allocator, "HTTP {d}", .{status_code});
            return ToolResult{ .success = false, .output = output, .error_msg = err_msg };
        }
    }
};

fn validateMethod(method: []const u8) ?std.http.Method {
    if (std.ascii.eqlIgnoreCase(method, "GET")) return .GET;
    if (std.ascii.eqlIgnoreCase(method, "POST")) return .POST;
    if (std.ascii.eqlIgnoreCase(method, "PUT")) return .PUT;
    if (std.ascii.eqlIgnoreCase(method, "DELETE")) return .DELETE;
    if (std.ascii.eqlIgnoreCase(method, "PATCH")) return .PATCH;
    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return .HEAD;
    if (std.ascii.eqlIgnoreCase(method, "OPTIONS")) return .OPTIONS;
    return null;
}

fn extractHost(url: []const u8) ?[]const u8 {
    const rest = if (std.mem.startsWith(u8, url, "https://"))
        url[8..]
    else if (std.mem.startsWith(u8, url, "http://"))
        url[7..]
    else
        return null;

    // Find end of authority (first / or ? or #)
    var end: usize = rest.len;
    for (rest, 0..) |c, i| {
        if (c == '/' or c == '?' or c == '#') {
            end = i;
            break;
        }
    }
    const authority = rest[0..end];
    if (authority.len == 0) return null;

    // Strip port
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        return authority[0..colon];
    }
    return authority;
}

fn isLocalHost(host: []const u8) bool {
    if (std.mem.eql(u8, host, "localhost")) return true;
    if (std.mem.endsWith(u8, host, ".localhost")) return true;
    if (std.mem.startsWith(u8, host, "127.")) return true;
    if (std.mem.eql(u8, host, "0.0.0.0")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;
    if (std.mem.eql(u8, host, "[::1]")) return true;
    // Private ranges
    if (std.mem.startsWith(u8, host, "10.")) return true;
    if (std.mem.startsWith(u8, host, "192.168.")) return true;
    if (std.mem.startsWith(u8, host, "172.")) {
        // 172.16.0.0 - 172.31.255.255
        if (host.len > 4) {
            const second_octet = std.fmt.parseInt(u8, blk: {
                const dot = std.mem.indexOfScalar(u8, host[4..], '.') orelse break :blk host[4..];
                break :blk host[4..][0..dot];
            }, 10) catch return false;
            if (second_octet >= 16 and second_octet <= 31) return true;
        }
    }
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

test "http_request tool name" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    try std.testing.expectEqualStrings("http_request", t.name());
}

test "http_request tool description not empty" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    try std.testing.expect(t.description().len > 0);
}

test "http_request schema has url" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "url") != null);
}

test "validateMethod accepts valid methods" {
    try std.testing.expect(validateMethod("GET") != null);
    try std.testing.expect(validateMethod("POST") != null);
    try std.testing.expect(validateMethod("PUT") != null);
    try std.testing.expect(validateMethod("DELETE") != null);
    try std.testing.expect(validateMethod("PATCH") != null);
    try std.testing.expect(validateMethod("HEAD") != null);
    try std.testing.expect(validateMethod("OPTIONS") != null);
    try std.testing.expect(validateMethod("get") != null); // case insensitive
}

test "validateMethod rejects invalid" {
    try std.testing.expect(validateMethod("INVALID") == null);
}

test "extractHost basic" {
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com/path").?);
    try std.testing.expectEqualStrings("example.com", extractHost("http://example.com").?);
    try std.testing.expectEqualStrings("api.example.com", extractHost("https://api.example.com/v1").?);
}

test "extractHost with port" {
    try std.testing.expectEqualStrings("localhost", extractHost("http://localhost:8080/api").?);
}

test "isLocalHost detects localhost" {
    try std.testing.expect(isLocalHost("localhost"));
    try std.testing.expect(isLocalHost("foo.localhost"));
    try std.testing.expect(isLocalHost("127.0.0.1"));
    try std.testing.expect(isLocalHost("0.0.0.0"));
    try std.testing.expect(isLocalHost("::1"));
}

test "isLocalHost detects private ranges" {
    try std.testing.expect(isLocalHost("10.0.0.1"));
    try std.testing.expect(isLocalHost("192.168.1.1"));
    try std.testing.expect(isLocalHost("172.16.0.1"));
}

test "isLocalHost allows public" {
    try std.testing.expect(!isLocalHost("8.8.8.8"));
    try std.testing.expect(!isLocalHost("example.com"));
    try std.testing.expect(!isLocalHost("1.1.1.1"));
}

// ── Additional SSRF and validation tests ────────────────────────

test "extractHost returns null for non-http scheme" {
    try std.testing.expect(extractHost("ftp://example.com") == null);
    try std.testing.expect(extractHost("file:///etc/passwd") == null);
}

test "extractHost returns null for empty host" {
    try std.testing.expect(extractHost("http:///path") == null);
    try std.testing.expect(extractHost("https:///") == null);
}

test "extractHost handles query and fragment" {
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com?q=1").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com#frag").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com/path?q=1#frag").?);
}

test "isLocalHost detects [::1] bracketed" {
    try std.testing.expect(isLocalHost("[::1]"));
}

test "isLocalHost detects 172.16-31 range" {
    try std.testing.expect(isLocalHost("172.16.0.1"));
    try std.testing.expect(isLocalHost("172.31.255.255"));
    // 172.15 should not be blocked
    try std.testing.expect(!isLocalHost("172.15.0.1"));
    // 172.32 should not be blocked
    try std.testing.expect(!isLocalHost("172.32.0.1"));
}

test "isLocalHost detects 127.x.x.x range" {
    try std.testing.expect(isLocalHost("127.0.0.1"));
    try std.testing.expect(isLocalHost("127.0.0.2"));
    try std.testing.expect(isLocalHost("127.255.255.255"));
}

test "validateMethod case insensitive" {
    try std.testing.expect(validateMethod("get") != null);
    try std.testing.expect(validateMethod("Post") != null);
    try std.testing.expect(validateMethod("pUt") != null);
    try std.testing.expect(validateMethod("delete") != null);
    try std.testing.expect(validateMethod("patch") != null);
    try std.testing.expect(validateMethod("head") != null);
    try std.testing.expect(validateMethod("options") != null);
}

test "validateMethod rejects empty string" {
    try std.testing.expect(validateMethod("") == null);
}

test "validateMethod rejects CONNECT TRACE" {
    try std.testing.expect(validateMethod("CONNECT") == null);
    try std.testing.expect(validateMethod("TRACE") == null);
}

test "execute rejects missing url parameter" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "execute rejects non-http scheme" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"ftp://example.com\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "http") != null);
}

test "execute rejects localhost SSRF" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"http://127.0.0.1:8080/admin\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null);
}

test "execute rejects private IP SSRF" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"http://192.168.1.1/admin\"}");
    try std.testing.expect(!result.success);
}

test "execute rejects 10.x private range" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"http://10.0.0.1/secret\"}");
    try std.testing.expect(!result.success);
}

test "execute rejects unsupported method" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"https://example.com\", \"method\": \"INVALID\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsupported") != null);
}

test "execute rejects invalid URL format" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"http://\"}");
    try std.testing.expect(!result.success);
}

test "http_request parameters JSON is valid" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const schema = t.parametersJson();
    try std.testing.expect(schema[0] == '{');
    try std.testing.expect(std.mem.indexOf(u8, schema, "method") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "body") != null);
}
