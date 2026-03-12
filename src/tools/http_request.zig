const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const net_security = @import("../root.zig").net_security;
const http_util = @import("../http_util.zig");

const log = std.log.scoped(.http_request);

/// HTTP request tool for API interactions.
/// Supports GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS methods with
/// domain allowlisting, SSRF protection, and header redaction.
pub const HttpRequestTool = struct {
    allowed_domains: []const []const u8 = &.{}, // empty = allow all
    max_response_size: u32 = 1_000_000,

    pub const tool_name = "http_request";
    pub const tool_description = "Make HTTP requests to external APIs. Supports GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS methods. " ++
        "Security: allowlist-only domains, no local/private hosts, SSRF protection.";
    pub const tool_params =
        \\{"type":"object","properties":{"url":{"type":"string","description":"HTTP or HTTPS URL to request"},"method":{"type":"string","description":"HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)","default":"GET"},"headers":{"type":"object","description":"Optional HTTP headers as key-value pairs"},"body":{"type":"string","description":"Optional request body"}},"required":["url"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *HttpRequestTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *HttpRequestTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const url = root.getString(args, "url") orelse
            return ToolResult.fail("Missing 'url' parameter");

        const method_str = root.getString(args, "method") orelse "GET";

        // Validate URL scheme
        if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only http:// and https:// URLs are allowed");
        }

        // Build URI
        const uri = std.Uri.parse(url) catch
            return ToolResult.fail("Invalid URL format");

        const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
        const resolved_port: u16 = uri.port orelse default_port;

        // SSRF protection and DNS-rebinding hardening:
        // resolve once, validate global address, and connect directly to it.
        const host = net_security.extractHost(url) orelse
            return ToolResult.fail("Invalid URL: cannot extract host");
        const connect_host = net_security.resolveConnectHost(allocator, host, resolved_port) catch |err| switch (err) {
            error.LocalAddressBlocked => return ToolResult.fail("Blocked local/private host"),
            else => return ToolResult.fail("Unable to verify host safety"),
        };
        defer allocator.free(connect_host);

        // Check domain allowlist
        if (self.allowed_domains.len > 0) {
            if (!net_security.hostMatchesAllowlist(host, self.allowed_domains)) {
                return ToolResult.fail("Host is not in http_request.allowed_domains");
            }
        }

        // Validate method
        const method = validateMethod(method_str) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Unsupported HTTP method: {s}", .{method_str});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        // Parse custom headers from ObjectMap
        const headers_val = root.getValue(args, "headers");
        var header_list: std.ArrayList([2][]const u8) = .{};
        errdefer {
            for (header_list.items) |h| {
                allocator.free(h[0]);
                allocator.free(h[1]);
            }
            header_list.deinit(allocator);
        }
        if (headers_val) |hv| {
            if (hv == .object) {
                var it = hv.object.iterator();
                while (it.next()) |entry| {
                    const val_str = switch (entry.value_ptr.*) {
                        .string => |s| s,
                        else => continue,
                    };
                    try header_list.append(allocator, .{
                        try allocator.dupe(u8, entry.key_ptr.*),
                        try allocator.dupe(u8, val_str),
                    });
                }
            }
        }
        const custom_headers = header_list.items;
        defer {
            for (custom_headers) |h| {
                allocator.free(h[0]);
                allocator.free(h[1]);
            }
            header_list.deinit(allocator);
        }

        const body: ?[]const u8 = root.getString(args, "body");

        const status_result = runCurlRequestWithStatus(
            allocator,
            methodToSlice(method),
            url,
            host,
            resolved_port,
            connect_host,
            custom_headers,
            body,
            @intCast(self.max_response_size),
        ) catch |err| {
            if (err == error.CurlInterrupted) {
                return ToolResult.fail("Interrupted by /stop");
            }
            const msg = try std.fmt.allocPrint(allocator, "HTTP request failed: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(status_result.body);

        const status_code = status_result.status_code;
        const success = status_code >= 200 and status_code < 300;

        // Build redacted headers display for custom request headers
        const redacted = redactHeadersForDisplay(allocator, custom_headers) catch "";
        defer if (redacted.len > 0) allocator.free(redacted);

        const output = if (redacted.len > 0)
            try std.fmt.allocPrint(
                allocator,
                "Status: {d}\nRequest Headers: {s}\n\nResponse Body:\n{s}",
                .{ status_code, redacted, status_result.body },
            )
        else
            try std.fmt.allocPrint(
                allocator,
                "Status: {d}\n\nResponse Body:\n{s}",
                .{ status_code, status_result.body },
            );

        if (success) {
            return ToolResult{ .success = true, .output = output };
        } else {
            const err_msg = try std.fmt.allocPrint(allocator, "HTTP {d}", .{status_code});
            return ToolResult{ .success = false, .output = output, .error_msg = err_msg };
        }
    }
};

fn methodToSlice(method: std.http.Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
        .PATCH => "PATCH",
        .HEAD => "HEAD",
        .OPTIONS => "OPTIONS",
        else => "GET",
    };
}

fn shouldUseCurlResolve(host: []const u8) bool {
    return std.mem.indexOfScalar(u8, net_security.stripHostBrackets(host), ':') == null;
}

fn buildCurlResolveEntry(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    connect_host: []const u8,
) ![]u8 {
    const host_for_resolve = net_security.stripHostBrackets(host);
    const connect_target = if (std.mem.indexOfScalar(u8, connect_host, ':') != null)
        try std.fmt.allocPrint(allocator, "[{s}]", .{connect_host})
    else
        try allocator.dupe(u8, connect_host);
    defer allocator.free(connect_target);

    return std.fmt.allocPrint(allocator, "{s}:{d}:{s}", .{ host_for_resolve, port, connect_target });
}

fn runCurlRequestWithStatus(
    allocator: std.mem.Allocator,
    method: []const u8,
    url: []const u8,
    host: []const u8,
    resolved_port: u16,
    connect_host: []const u8,
    headers: []const [2][]const u8,
    body: ?[]const u8,
    max_response_size: usize,
) !http_util.HttpResponse {
    var argv_buf: [64][]const u8 = undefined;
    var argc: usize = 0;
    const reserved_tail_args: usize = if (body != null) 5 else 3;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-sS";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = method;
    argc += 1;
    argv_buf[argc] = "--max-time";
    argc += 1;
    argv_buf[argc] = "60";
    argc += 1;

    var resolve_entry: ?[]u8 = null;
    defer if (resolve_entry) |entry| allocator.free(entry);
    if (shouldUseCurlResolve(host)) {
        resolve_entry = try buildCurlResolveEntry(allocator, host, resolved_port, connect_host);
        argv_buf[argc] = "--resolve";
        argc += 1;
        argv_buf[argc] = resolve_entry.?;
        argc += 1;
    }

    var header_lines: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (header_lines.items) |line| allocator.free(line);
        header_lines.deinit(allocator);
    }

    for (headers) |h| {
        // Reserve room for trailing args:
        // -w "\n%{http_code}" <url> and optional --data-binary @-
        if (argc + 2 + reserved_tail_args > argv_buf.len) break;
        const line = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ h[0], h[1] });
        try header_lines.append(allocator, line);
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = line;
        argc += 1;
    }

    if (body != null) {
        if (argc + 2 + 3 > argv_buf.len) return error.CurlArgsOverflow;
        argv_buf[argc] = "--data-binary";
        argc += 1;
        argv_buf[argc] = "@-";
        argc += 1;
    }

    if (argc + 3 > argv_buf.len) return error.CurlArgsOverflow;
    argv_buf[argc] = "-w";
    argc += 1;
    argv_buf[argc] = "\n%{http_code}";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = if (body != null) .Pipe else .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const cancel_flag = http_util.currentThreadInterruptFlag();
    const AtomicBool = std.atomic.Value(bool);
    const CancelCtx = struct {
        child: *std.process.Child,
        cancel_flag: *const AtomicBool,
        done: *AtomicBool,
    };
    const watcherFn = struct {
        fn run(ctx: *CancelCtx) void {
            while (!ctx.done.load(.acquire)) {
                if (ctx.cancel_flag.load(.acquire)) {
                    if (comptime @import("builtin").os.tag == .windows) {
                        std.os.windows.TerminateProcess(ctx.child.id, 1) catch {};
                    } else {
                        std.posix.kill(ctx.child.id, std.posix.SIG.TERM) catch {};
                    }
                    break;
                }
                std.Thread.sleep(20 * std.time.ns_per_ms);
            }
        }
    }.run;
    var done = AtomicBool.init(false);
    var watcher: ?std.Thread = null;
    var cancel_ctx: CancelCtx = undefined;
    if (cancel_flag) |flag| {
        cancel_ctx = .{ .child = &child, .cancel_flag = flag, .done = &done };
        watcher = std.Thread.spawn(.{}, watcherFn, .{&cancel_ctx}) catch null;
    }
    defer {
        done.store(true, .release);
        if (watcher) |t| t.join();
    }

    if (body) |b| {
        if (child.stdin) |stdin_file| {
            stdin_file.writeAll(b) catch {
                stdin_file.close();
                child.stdin = null;
                _ = child.kill() catch {};
                _ = child.wait() catch {};
                return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWriteError;
            };
            stdin_file.close();
            child.stdin = null;
        } else {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWriteError;
        }
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, max_response_size + 64) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };
    errdefer allocator.free(stdout);

    const term = child.wait() catch return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    switch (term) {
        .Exited => |code| if (code != 0 and !(cancel_flag != null and cancel_flag.?.load(.acquire))) return error.CurlFailed,
        else => return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed,
    }

    if (cancel_flag != null and cancel_flag.?.load(.acquire)) return error.CurlInterrupted;

    const status_sep = std.mem.lastIndexOfScalar(u8, stdout, '\n') orelse return error.CurlParseError;
    const status_raw = std.mem.trim(u8, stdout[status_sep + 1 ..], " \t\r\n");
    if (status_raw.len != 3) return error.CurlParseError;
    const status_code = std.fmt.parseInt(u16, status_raw, 10) catch return error.CurlParseError;
    const body_slice = stdout[0..status_sep];
    const response_body = try allocator.dupe(u8, body_slice);
    allocator.free(stdout);

    return .{
        .status_code = status_code,
        .body = response_body,
    };
}

fn ensureTlsCaBundleLoaded(client: *std.http.Client) !void {
    if (@atomicLoad(bool, &client.next_https_rescan_certs, .acquire)) {
        client.ca_bundle_mutex.lock();
        defer client.ca_bundle_mutex.unlock();

        if (client.next_https_rescan_certs) {
            client.ca_bundle.rescan(client.allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.CertificateBundleLoadFailure,
            };
            @atomicStore(bool, &client.next_https_rescan_certs, false, .release);
        }
    }
}

fn isTlsSetupError(err: anyerror) bool {
    return err == error.TlsInitializationFailed or err == error.CertificateBundleLoadFailure;
}

fn buildHttpRequestErrorMessage(allocator: std.mem.Allocator, prefix: []const u8, err: anyerror) ![]u8 {
    if (isTlsSetupError(err)) {
        return std.fmt.allocPrint(
            allocator,
            "{s}: {s}. Ensure system CA certificates are available in the runtime, or use an endpoint with a publicly trusted certificate chain.",
            .{ prefix, @errorName(err) },
        );
    }
    return std.fmt.allocPrint(allocator, "{s}: {}", .{ prefix, err });
}

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

/// Disable auto-follow redirects so every hop can be explicitly validated.
fn buildRequestOptions(
    extra_headers: []const std.http.Header,
    connection: ?*std.http.Client.Connection,
) std.http.Client.RequestOptions {
    return .{
        .extra_headers = extra_headers,
        .redirect_behavior = .unhandled,
        .connection = connection,
    };
}

/// Parse headers from a JSON object string: {"Key": "Value", ...}
/// Returns array of [2][]const u8 pairs. Caller owns memory.
fn parseHeaders(allocator: std.mem.Allocator, headers_json: ?[]const u8) ![]const [2][]const u8 {
    const json = headers_json orelse return &.{};
    if (json.len < 2) return &.{};

    var list: std.ArrayList([2][]const u8) = .{};
    errdefer {
        for (list.items) |h| {
            allocator.free(h[0]);
            allocator.free(h[1]);
        }
        list.deinit(allocator);
    }

    // Simple JSON object parser: find "key": "value" pairs
    var pos: usize = 0;
    while (pos < json.len) {
        // Find next key (quoted string)
        const key_start = std.mem.indexOfScalarPos(u8, json, pos, '"') orelse break;
        const key_end = std.mem.indexOfScalarPos(u8, json, key_start + 1, '"') orelse break;
        const key = json[key_start + 1 .. key_end];

        // Skip to colon and value
        pos = key_end + 1;
        const colon = std.mem.indexOfScalarPos(u8, json, pos, ':') orelse break;
        pos = colon + 1;

        // Skip whitespace
        while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n')) : (pos += 1) {}

        if (pos >= json.len or json[pos] != '"') {
            pos += 1;
            continue;
        }
        const val_start = pos;
        const val_end = std.mem.indexOfScalarPos(u8, json, val_start + 1, '"') orelse break;
        const value = json[val_start + 1 .. val_end];
        pos = val_end + 1;

        try list.append(allocator, .{
            try allocator.dupe(u8, key),
            try allocator.dupe(u8, value),
        });
    }

    return list.toOwnedSlice(allocator);
}

/// Redact sensitive headers for display output.
/// Headers with names containing authorization, api-key, apikey, token, secret,
/// or password (case-insensitive) get their values replaced with "***REDACTED***".
fn redactHeadersForDisplay(allocator: std.mem.Allocator, headers: []const [2][]const u8) ![]const u8 {
    if (headers.len == 0) return "";

    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    for (headers, 0..) |h, i| {
        if (i > 0) try buf.appendSlice(allocator, ", ");
        try buf.appendSlice(allocator, h[0]);
        try buf.appendSlice(allocator, ": ");
        if (isSensitiveHeader(h[0])) {
            try buf.appendSlice(allocator, "***REDACTED***");
        } else {
            try buf.appendSlice(allocator, h[1]);
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Check if a header name is sensitive (case-insensitive substring check).
fn isSensitiveHeader(name: []const u8) bool {
    // Convert to lowercase for comparison
    var lower_buf: [256]u8 = undefined;
    if (name.len > lower_buf.len) return false;
    const lower = lower_buf[0..name.len];
    for (name, 0..) |c, i| {
        lower[i] = std.ascii.toLower(c);
    }
    if (std.mem.indexOf(u8, lower, "authorization") != null) return true;
    if (std.mem.indexOf(u8, lower, "api-key") != null) return true;
    if (std.mem.indexOf(u8, lower, "apikey") != null) return true;
    if (std.mem.indexOf(u8, lower, "token") != null) return true;
    if (std.mem.indexOf(u8, lower, "secret") != null) return true;
    if (std.mem.indexOf(u8, lower, "password") != null) return true;
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

test "http_request schema has headers" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "headers") != null);
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

// ── redactHeadersForDisplay tests ──────────────────────────

test "redactHeadersForDisplay redacts Authorization" {
    const headers = [_][2][]const u8{
        .{ "Authorization", "Bearer secret-token" },
    };
    const result = try redactHeadersForDisplay(std.testing.allocator, &headers);
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "***REDACTED***") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "secret-token") == null);
}

test "redactHeadersForDisplay preserves Content-Type" {
    const headers = [_][2][]const u8{
        .{ "Content-Type", "application/json" },
    };
    const result = try redactHeadersForDisplay(std.testing.allocator, &headers);
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "application/json") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "REDACTED") == null);
}

test "redactHeadersForDisplay redacts api-key and token" {
    const headers = [_][2][]const u8{
        .{ "X-API-Key", "my-key" },
        .{ "X-Secret-Token", "tok-123" },
    };
    const result = try redactHeadersForDisplay(std.testing.allocator, &headers);
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "my-key") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "tok-123") == null);
}

test "redactHeadersForDisplay empty returns empty" {
    const result = try redactHeadersForDisplay(std.testing.allocator, &.{});
    try std.testing.expectEqualStrings("", result);
}

test "isSensitiveHeader checks" {
    try std.testing.expect(isSensitiveHeader("Authorization"));
    try std.testing.expect(isSensitiveHeader("X-API-Key"));
    try std.testing.expect(isSensitiveHeader("X-Secret-Token"));
    try std.testing.expect(isSensitiveHeader("password-header"));
    try std.testing.expect(!isSensitiveHeader("Content-Type"));
    try std.testing.expect(!isSensitiveHeader("Accept"));
}

test "http_request disables automatic redirects" {
    const opts = buildRequestOptions(&.{}, null);
    try std.testing.expect(opts.redirect_behavior == .unhandled);
    try std.testing.expect(opts.connection == null);
}

test "http_request request options keep provided connection" {
    const fake_ptr_value = @as(usize, @alignOf(std.http.Client.Connection));
    const fake_connection: *std.http.Client.Connection = @ptrFromInt(fake_ptr_value);
    const opts = buildRequestOptions(&.{}, fake_connection);
    try std.testing.expect(opts.connection != null);
    try std.testing.expectEqual(@intFromPtr(fake_connection), @intFromPtr(opts.connection.?));
}

// ── execute-level tests ──────────────────────────────────────

test "execute rejects missing url parameter" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "execute rejects non-http scheme" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"ftp://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "http") != null);
}

test "execute rejects localhost SSRF" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://127.0.0.1:8080/admin\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null);
}

test "execute rejects localhost SSRF with URL userinfo" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://user:pass@127.0.0.1:8080/admin\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null);
}

test "execute rejects localhost SSRF with unbracketed ipv6 authority" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://::1:8080/admin\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null);
}

test "execute rejects private IP SSRF" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://192.168.1.1/admin\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "execute rejects 10.x private range" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://10.0.0.1/secret\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "execute rejects loopback decimal alias SSRF" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://2130706433/admin\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null);
}

test "execute rejects unsupported method" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://example.com\", \"method\": \"INVALID\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsupported") != null);
}

test "execute rejects invalid URL format" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "execute rejects non-allowlisted domain" {
    const domains = [_][]const u8{"example.com"};
    var ht = HttpRequestTool{ .allowed_domains = &domains };
    const t = ht.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://evil.com/path\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "allowed_domains") != null);
}

test "http_request parameters JSON is valid" {
    var ht = HttpRequestTool{};
    const t = ht.tool();
    const schema = t.parametersJson();
    try std.testing.expect(schema[0] == '{');
    try std.testing.expect(std.mem.indexOf(u8, schema, "method") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "body") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "headers") != null);
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

test "isTlsSetupError detects TLS setup failures" {
    try std.testing.expect(isTlsSetupError(error.TlsInitializationFailed));
    try std.testing.expect(isTlsSetupError(error.CertificateBundleLoadFailure));
    try std.testing.expect(!isTlsSetupError(error.EndOfStream));
}

test "buildHttpRequestErrorMessage includes TLS hint" {
    const msg = try buildHttpRequestErrorMessage(std.testing.allocator, "HTTP request failed", error.TlsInitializationFailed);
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "system CA certificates") != null);
}

// ── parseHeaders tests ──────────────────────────────────────

test "parseHeaders basic" {
    const headers = try parseHeaders(std.testing.allocator, "{\"Content-Type\": \"application/json\"}");
    defer {
        for (headers) |h| {
            std.testing.allocator.free(h[0]);
            std.testing.allocator.free(h[1]);
        }
        std.testing.allocator.free(headers);
    }
    try std.testing.expectEqual(@as(usize, 1), headers.len);
    try std.testing.expectEqualStrings("Content-Type", headers[0][0]);
    try std.testing.expectEqualStrings("application/json", headers[0][1]);
}

test "parseHeaders null returns empty" {
    const headers = try parseHeaders(std.testing.allocator, null);
    try std.testing.expectEqual(@as(usize, 0), headers.len);
}
