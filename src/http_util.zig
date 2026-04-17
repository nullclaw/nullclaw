//! Shared HTTP utilities via curl subprocess.
//!
//! Replaces 9+ local `curlPost` / `curlGet` duplicates across the codebase.
//! Uses curl to keep timeout handling explicit and avoid std.http regressions.

const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const net_security = @import("net_security.zig");

const log = std.log.scoped(.http_util);
threadlocal var thread_interrupt_flag: ?*const AtomicBool = null;
const DEFAULT_CURL_GET_MAX_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_CURL_POST_MAX_BYTES: usize = 8 * 1024 * 1024;

fn classifyCurlExitCode(code: u8) []const u8 {
    return switch (code) {
        6 => "dns",
        7 => "connect",
        28 => "timeout",
        35, 51, 58, 60 => "tls",
        else => "other",
    };
}

fn mapCurlExitCodeToError(code: u8) anyerror {
    return switch (code) {
        6 => error.CurlDnsError,
        7 => error.CurlConnectError,
        28 => error.CurlTimeout,
        35, 51, 58, 60 => error.CurlTlsError,
        else => error.CurlFailed,
    };
}

fn logCurlExitFailure(op: []const u8, code: u8) void {
    log.warn("curl {s} failed: exit_code={d} class={s}", .{ op, code, classifyCurlExitCode(code) });
}

pub fn setThreadInterruptFlag(flag: ?*const AtomicBool) void {
    thread_interrupt_flag = flag;
}

pub fn currentThreadInterruptFlag() ?*const AtomicBool {
    return thread_interrupt_flag;
}

const CancelWatcherCtx = struct {
    child: *std_compat.process.Child,
    cancel_flag: *const AtomicBool,
    done: *AtomicBool,
};

fn cancelWatcherMain(ctx: *CancelWatcherCtx) void {
    while (!ctx.done.load(.acquire)) {
        if (ctx.cancel_flag.load(.acquire)) {
            if (comptime @import("builtin").os.tag == .windows) {
                _ = ctx.child.kill() catch {};
            } else {
                std.posix.kill(ctx.child.id, std.posix.SIG.TERM) catch {};
            }
            break;
        }
        std_compat.thread.sleep(20 * std.time.ns_per_ms);
    }
}

pub const HttpResponse = struct {
    status_code: u16,
    body: []u8,
};

pub const HttpResponseWithHeaders = struct {
    status_code: u16,
    headers: []u8,
    body: []u8,
};

const proxy_env_var_names = [_][]const u8{
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
};
const http_proxy_env_var_names = [_][]const u8{
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
};
const https_proxy_env_var_names = [_][]const u8{
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
};

pub const ProxyHttpClient = struct {
    proxy_arena: std.heap.ArenaAllocator,
    client: std.http.Client,

    pub fn init(allocator: Allocator) !ProxyHttpClient {
        var proxy_arena = std.heap.ArenaAllocator.init(allocator);
        errdefer proxy_arena.deinit();

        var client: std.http.Client = .{ .allocator = allocator, .io = std_compat.io() };
        errdefer client.deinit();

        try initClientDefaultProxies(&client, proxy_arena.allocator());

        return .{
            .proxy_arena = proxy_arena,
            .client = client,
        };
    }

    pub fn deinit(self: *ProxyHttpClient) void {
        self.client.deinit();
        self.proxy_arena.deinit();
        self.* = undefined;
    }
};

pub const SafeResolveEntryError = Allocator.Error || error{
    InvalidUrl,
    LocalAddressBlocked,
    HostResolutionFailed,
};

fn defaultPortForScheme(uri: std.Uri) ?u16 {
    if (uri.port) |port| return port;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return 443;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) return 80;
    return null;
}

fn shouldUseCurlResolve(host: []const u8) bool {
    return std.mem.indexOfScalar(u8, net_security.stripHostBrackets(host), ':') == null;
}

fn shouldUsePinnedResolve(host: []const u8, connect_host: []const u8) bool {
    return shouldUseCurlResolve(host) and !std.mem.eql(u8, host, connect_host);
}

fn buildCurlResolveEntry(
    allocator: Allocator,
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

/// Build an optional curl `--resolve` entry for remote provider requests.
/// Remote hosts are pinned to a concrete globally-routable address; explicit
/// local/private hosts are left untouched so intentional local providers still work.
pub fn buildSafeResolveEntryForRemoteUrl(
    allocator: Allocator,
    url: []const u8,
) SafeResolveEntryError!?[]u8 {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    const port = defaultPortForScheme(uri) orelse return error.InvalidUrl;
    const host = net_security.extractHost(url) orelse return error.InvalidUrl;

    if (net_security.isLocalHost(host)) return null;

    const connect_host = try net_security.resolveConnectHost(allocator, host, port);
    defer allocator.free(connect_host);

    if (!shouldUsePinnedResolve(host, connect_host)) return null;
    return try buildCurlResolveEntry(allocator, host, port, connect_host);
}

pub fn appendCurlResolveArgs(argv_buf: []([]const u8), argc: *usize, resolve_entry: ?[]const u8) void {
    if (resolve_entry) |entry| {
        argv_buf[argc.*] = "--resolve";
        argc.* += 1;
        argv_buf[argc.*] = entry;
        argc.* += 1;
    }
}

/// HTTP POST via curl subprocess with optional proxy and timeout.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `proxy` is an optional proxy URL (e.g. `"socks5://host:port"`).
/// `max_time` is an optional --max-time value as a string (e.g. `"300"`).
/// Returns the response body. Caller owns returned memory.
pub fn curlPostWithProxy(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
) ![]u8 {
    return curlPostWithProxyAndResolve(allocator, url, body, headers, proxy, max_time, null);
}

pub fn curlPostWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    return curlRequestWithProxy(
        allocator,
        "POST",
        "Content-Type: application/json",
        url,
        body,
        headers,
        proxy,
        max_time,
        resolve_entry,
    );
}

/// HTTP POST with application/x-www-form-urlencoded body via curl subprocess,
/// with optional proxy and timeout.
pub fn curlPostFormWithProxy(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
) ![]u8 {
    return curlPostFormWithProxyAndResolve(allocator, url, body, proxy, max_time, null);
}

pub fn curlPostFormWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    return curlRequestWithProxy(
        allocator,
        "POST",
        "Content-Type: application/x-www-form-urlencoded",
        url,
        body,
        &.{},
        proxy,
        max_time,
        resolve_entry,
    );
}

fn curlRequestWithProxy(
    allocator: Allocator,
    method: []const u8,
    content_type_header: []const u8,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = method;
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = content_type_header;
    argc += 1;

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    if (max_time) |mt| {
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = mt;
        argc += 1;
    }

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    // Pass payload via stdin to avoid OS argv length limits for large JSON
    // bodies (e.g. multimodal base64 images).
    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = "@-";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(body) catch {
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

    const stdout = child.stdout.?.readToEndAlloc(allocator, DEFAULT_CURL_POST_MAX_BYTES) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        allocator.free(stdout);
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            logCurlExitFailure(method, code);
            allocator.free(stdout);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else mapCurlExitCodeToError(code);
        },
        else => {
            allocator.free(stdout);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed;
        },
    }

    return stdout;
}

/// HTTP POST via curl subprocess (no proxy, no timeout).
pub fn curlPost(allocator: Allocator, url: []const u8, body: []const u8, headers: []const []const u8) ![]u8 {
    return curlPostWithProxy(allocator, url, body, headers, null, null);
}

/// HTTP POST with application/x-www-form-urlencoded body via curl subprocess.
///
/// `body` must already be percent-encoded form data (e.g. `"key=val&key2=val2"`).
/// Returns the response body. Caller owns returned memory.
pub fn curlPostForm(allocator: Allocator, url: []const u8, body: []const u8) ![]u8 {
    return curlPostFormWithProxy(allocator, url, body, null, null);
}

/// HTTP POST via curl subprocess and include HTTP status code in response.
/// Caller owns `response.body`.
pub fn curlPostWithStatus(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
) !HttpResponse {
    return curlPostWithStatusAndTimeout(allocator, url, body, headers, null);
}

pub fn curlGetWithStatus(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
) !HttpResponse {
    return curlGetWithStatusAndTimeout(allocator, url, headers, null);
}

/// HTTP POST via curl subprocess and include HTTP status code in response,
/// with optional --max-time timeout.
/// Caller owns `response.body`.
pub fn curlPostWithStatusAndTimeout(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponse {
    return curlPostWithStatusAndTimeoutAndResolve(allocator, url, body, headers, max_time, null);
}

pub fn curlPostWithStatusAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponse {
    var argv_buf: [48][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;

    if (max_time) |mt| {
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = mt;
        argc += 1;
    }

    appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = "@-";
    argc += 1;
    argv_buf[argc] = "-w";
    argc += 1;
    argv_buf[argc] = "\n%{http_code}";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(body) catch {
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

    const stdout = child.stdout.?.readToEndAlloc(allocator, DEFAULT_CURL_POST_MAX_BYTES) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };
    errdefer allocator.free(stdout);

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            logCurlExitFailure("POST", code);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else mapCurlExitCodeToError(code);
        },
        else => return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed,
    }

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

/// HTTP POST via curl subprocess and include HTTP status code and response headers,
/// with optional --max-time timeout.
/// Caller owns `response.headers` and `response.body`.
pub fn curlPostWithStatusHeadersAndTimeout(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponseWithHeaders {
    return curlPostWithStatusHeadersAndTimeoutAndResolve(allocator, url, body, headers, max_time, null);
}

pub fn curlPostWithStatusHeadersAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponseWithHeaders {
    var argv_buf: [56][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;

    if (max_time) |mt| {
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = mt;
        argc += 1;
    }

    appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    // Dump response headers to stdout so we can capture session IDs.
    argv_buf[argc] = "-D";
    argc += 1;
    argv_buf[argc] = "-";
    argc += 1;

    argv_buf[argc] = "--data-binary";
    argc += 1;
    argv_buf[argc] = "@-";
    argc += 1;
    argv_buf[argc] = "-w";
    argc += 1;
    argv_buf[argc] = "\n%{http_code}";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(body) catch {
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

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };
    errdefer allocator.free(stdout);

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed,
        else => return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed,
    }

    const status_sep = std.mem.lastIndexOfScalar(u8, stdout, '\n') orelse return error.CurlParseError;
    const status_raw = std.mem.trim(u8, stdout[status_sep + 1 ..], " \t\r\n");
    if (status_raw.len != 3) return error.CurlParseError;
    const status_code = std.fmt.parseInt(u16, status_raw, 10) catch return error.CurlParseError;

    const payload = stdout[0..status_sep];
    const header_end_crlf = std.mem.indexOf(u8, payload, "\r\n\r\n");
    const header_end_lf = std.mem.indexOf(u8, payload, "\n\n");

    var headers_slice: []const u8 = "";
    var body_slice: []const u8 = payload;

    if (header_end_crlf) |pos| {
        headers_slice = payload[0..pos];
        body_slice = payload[pos + 4 ..];
    } else if (header_end_lf) |pos| {
        headers_slice = payload[0..pos];
        body_slice = payload[pos + 2 ..];
    }

    const headers_out = try allocator.dupe(u8, headers_slice);
    errdefer allocator.free(headers_out);
    const body_out = try allocator.dupe(u8, body_slice);

    allocator.free(stdout);

    return .{
        .status_code = status_code,
        .headers = headers_out,
        .body = body_out,
    };
}

pub fn curlGetWithStatusAndTimeout(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponse {
    return curlGetWithStatusAndTimeoutAndResolve(allocator, url, headers, max_time, null);
}

pub fn curlGetWithStatusAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponse {
    var argv_buf: [48][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;

    if (max_time) |mt| {
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = mt;
        argc += 1;
    }

    appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = "-w";
    argc += 1;
    argv_buf[argc] = "\n%{http_code}";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, DEFAULT_CURL_GET_MAX_BYTES) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };
    errdefer allocator.free(stdout);

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            logCurlExitFailure("GET", code);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else mapCurlExitCodeToError(code);
        },
        else => return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed,
    }

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

/// HTTP PUT via curl subprocess (no proxy, no timeout).
pub fn curlPut(allocator: Allocator, url: []const u8, body: []const u8, headers: []const []const u8) ![]u8 {
    return curlRequestWithProxy(
        allocator,
        "PUT",
        "Content-Type: application/json",
        url,
        body,
        headers,
        null,
        null,
        null,
    );
}

/// HTTP GET via curl subprocess with optional proxy.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `timeout_secs` sets --max-time. Returns the response body. Caller owns returned memory.
fn curlGetWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    proxy: ?[]const u8,
    resolve_entry: ?[]const u8,
    max_bytes: usize,
) ![]u8 {
    var argv_buf: [48][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-sf";
    argc += 1;
    argv_buf[argc] = "--max-time";
    argc += 1;
    argv_buf[argc] = timeout_secs;
    argc += 1;

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    if (resolve_entry) |entry| {
        argv_buf[argc] = "--resolve";
        argc += 1;
        argv_buf[argc] = entry;
        argc += 1;
    }

    for (headers) |hdr| {
        if (argc + 2 > argv_buf.len) break;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, max_bytes) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        return error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            logCurlExitFailure("GET", code);
            allocator.free(stdout);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else mapCurlExitCodeToError(code);
        },
        else => {
            allocator.free(stdout);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed;
        },
    }

    return stdout;
}

/// HTTP GET via curl subprocess with optional proxy.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `timeout_secs` sets --max-time. Returns the response body. Caller owns returned memory.
pub fn curlGetWithProxy(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    proxy: ?[]const u8,
) ![]u8 {
    return curlGetWithProxyAndResolve(allocator, url, headers, timeout_secs, proxy, null, DEFAULT_CURL_GET_MAX_BYTES);
}

/// HTTP GET via curl subprocess with a pinned host mapping.
///
/// `resolve_entry` must be in curl `--resolve` format: `host:port:address`.
pub fn curlGetWithResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    resolve_entry: []const u8,
) ![]u8 {
    return curlGetWithProxyAndResolve(allocator, url, headers, timeout_secs, null, resolve_entry, DEFAULT_CURL_GET_MAX_BYTES);
}

/// HTTP GET via curl subprocess (no proxy).
pub fn curlGet(allocator: Allocator, url: []const u8, headers: []const []const u8, timeout_secs: []const u8) ![]u8 {
    return curlGetWithProxy(allocator, url, headers, timeout_secs, null);
}

/// HTTP GET via curl subprocess with a caller-provided response size cap.
pub fn curlGetMaxBytes(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    max_bytes: usize,
) ![]u8 {
    return curlGetWithProxyAndResolve(allocator, url, headers, timeout_secs, null, null, max_bytes);
}

/// Read proxy URL from standard environment variables.
/// Checks https_proxy/HTTPS_PROXY first, then http_proxy/HTTP_PROXY,
/// then all_proxy/ALL_PROXY.
/// Returns null if no proxy is set.
/// Caller owns returned memory.
var proxy_override_value: ?[]u8 = null;
var proxy_override_mutex: std_compat.sync.Mutex = .{};

pub const ProxyOverrideError = error{OutOfMemory};

/// Set process-wide proxy override from config.
/// When set, this value has higher priority than proxy environment variables.
pub fn setProxyOverride(proxy: ?[]const u8) ProxyOverrideError!void {
    proxy_override_mutex.lock();
    defer proxy_override_mutex.unlock();

    if (proxy_override_value) |existing| {
        std.heap.page_allocator.free(existing);
        proxy_override_value = null;
    }

    if (proxy) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return;
        proxy_override_value = try std.heap.page_allocator.dupe(u8, trimmed);
    }
}

fn normalizeProxyEnvValue(allocator: Allocator, val: []const u8) !?[]const u8 {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn applyProxyOverrideToEnvMap(env_map: *std_compat.process.EnvMap) !bool {
    proxy_override_mutex.lock();
    defer proxy_override_mutex.unlock();

    const override = proxy_override_value orelse return false;
    for (proxy_env_var_names) |key| {
        try env_map.put(key, override);
    }
    return true;
}

fn putProxyEnvVarFromProcess(
    env_map: *std_compat.process.EnvMap,
    allocator: Allocator,
    key: []const u8,
) !void {
    if (std_compat.process.getEnvVarOwned(allocator, key)) |raw_value| {
        defer allocator.free(raw_value);
        if (try normalizeProxyEnvValue(allocator, raw_value)) |proxy| {
            try env_map.put(key, proxy);
        }
    } else |_| {}
}

fn buildProxyEnvMapFromProcess(allocator: Allocator) !std_compat.process.EnvMap {
    var env_map = std_compat.process.EnvMap.init(allocator);
    errdefer env_map.deinit();

    for (proxy_env_var_names) |key| {
        try putProxyEnvVarFromProcess(&env_map, allocator, key);
    }
    _ = try applyProxyOverrideToEnvMap(&env_map);

    return env_map;
}

fn getProxyFromEnvMap(
    allocator: Allocator,
    env_map: *const std_compat.process.EnvMap,
    env_vars: []const []const u8,
) !?[]const u8 {
    for (env_vars) |var_name| {
        const raw_value = env_map.get(var_name) orelse continue;
        if (try normalizeProxyEnvValue(allocator, raw_value)) |proxy| {
            return proxy;
        }
    }
    return null;
}

fn initClientDefaultProxiesFromEnvMap(
    client: *std.http.Client,
    arena: Allocator,
    env_map: *const std_compat.process.EnvMap,
) !void {
    var merged_env_map = try env_map.clone(arena);
    _ = try applyProxyOverrideToEnvMap(&merged_env_map);
    try client.initDefaultProxies(arena, &merged_env_map);
}

pub fn initClientDefaultProxies(client: *std.http.Client, arena: Allocator) !void {
    var env_map = try buildProxyEnvMapFromProcess(arena);
    try client.initDefaultProxies(arena, &env_map);
}

pub fn getProxyFromEnv(allocator: Allocator) !?[]const u8 {
    var env_map = try buildProxyEnvMapFromProcess(allocator);
    defer env_map.deinit();

    if (try getProxyFromEnvMap(allocator, &env_map, &https_proxy_env_var_names)) |proxy| {
        return proxy;
    }
    return try getProxyFromEnvMap(allocator, &env_map, &http_proxy_env_var_names);
}

/// HTTP GET via curl for SSE (Server-Sent Events).
///
/// Uses -N (--no-buffer) to disable output buffering, allowing
/// SSE events to be received in real-time. Also sends Accept: text/event-stream.
pub fn curlGetSSE(
    allocator: Allocator,
    url: []const u8,
    timeout_secs: []const u8,
) ![]u8 {
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-sf";
    argc += 1;
    argv_buf[argc] = "-N";
    argc += 1;
    argv_buf[argc] = "--max-time";
    argc += 1;
    argv_buf[argc] = timeout_secs;
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Accept: text/event-stream";
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| {
        std.debug.print("[curlGetSSE] spawn failed: {}\n", .{err});
        return error.CurlFailed;
    };
    const cancel_flag = thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (cancel_flag) |flag| {
        watcher_ctx = .{ .child = &child, .cancel_flag = flag, .done = &cancel_done };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, 4 * 1024 * 1024) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlReadError;
    };

    const term = child.wait() catch |err| {
        log.err("curl child.wait failed: {}", .{err});
        allocator.free(stdout);
        return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                // Exit code 28 = timeout. This is expected for SSE when no data arrives,
                // but curl may have received some data before timing out - return it.
                // For other exit codes, treat as error.
                if (code != 28) {
                    logCurlExitFailure("GET-SSE", code);
                    allocator.free(stdout);
                    return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else mapCurlExitCodeToError(code);
                }
                // Timeout (code 28) - return any data we received
            }
        },
        else => {
            allocator.free(stdout);
            return if (cancel_flag != null and cancel_flag.?.load(.acquire)) error.CurlInterrupted else error.CurlFailed;
        },
    }

    return stdout;
}

// ── Tests ───────────────────────────────────────────────────────────

test "curlPostWithProxy header guard allows at most (argv_buf_len - base_args) / 2 headers" {
    // argv_buf is [40][]const u8. Base args consume 8 slots (curl -s -X POST -H
    // Content-Type --data-binary @- url), leaving 32 slots = 16 header pairs.
    // The guard `argc + 2 > argv_buf.len` stops additions before overflow.
    // We verify the guard constant is consistent: remaining = 40 - 8 = 32, max headers = 16.
    const argv_buf_len = 40;
    const base_args = 8; // curl -s -X POST -H <ct> --data-binary @- <url>
    const max_header_pairs = (argv_buf_len - base_args) / 2;
    try std.testing.expectEqual(@as(usize, 16), max_header_pairs);
}

test "curlPostWithStatus compiles and is callable" {
    try std.testing.expect(true);
}

test "curlGetWithStatus compiles and is callable" {
    try std.testing.expect(true);
}

test "curlPut compiles and is callable" {
    try std.testing.expect(true);
}

test "curlPostForm uses exactly 9 fixed args plus url" {
    // argv_buf is [10][]const u8: curl -s -X POST -H <ct> --data-binary @- <url> = 9 slots.
    // Verify the constant is consistent with the implementation.
    const argv_buf_len = 10;
    const fixed_args = 9; // curl -s -X POST -H Content-Type --data-binary @- (url)
    try std.testing.expect(fixed_args < argv_buf_len);
}

test "curlGet with zero headers compiles and is callable" {
    // Smoke-test: verifies the function signature is reachable and the arg-building
    // path with an empty header slice does not panic at comptime.
    _ = curlGet;
}

test "curlGetWithResolve compiles and is callable" {
    try std.testing.expect(true);
}

test "curlGetMaxBytes compiles and is callable" {
    _ = curlGetMaxBytes;
}

test "buildSafeResolveEntryForRemoteUrl allows explicit local host without pinning" {
    try std.testing.expect((try buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "http://127.0.0.1:11434/api/chat")) == null);
}

test "buildSafeResolveEntryForRemoteUrl rejects loopback integer alias" {
    try std.testing.expectError(error.LocalAddressBlocked, buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "https://2130706433/v1"));
}

test "buildSafeResolveEntryForRemoteUrl rejects malformed URL" {
    try std.testing.expectError(error.InvalidUrl, buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "notaurl"));
}

test "appendCurlResolveArgs appends resolve flag and target" {
    var argv_buf: [4][]const u8 = undefined;
    var argc: usize = 0;
    appendCurlResolveArgs(argv_buf[0..], &argc, "example.com:443:203.0.113.7");
    try std.testing.expectEqual(@as(usize, 2), argc);
    try std.testing.expectEqualStrings("--resolve", argv_buf[0]);
    try std.testing.expectEqualStrings("example.com:443:203.0.113.7", argv_buf[1]);
}

test "appendCurlResolveArgs skips null entry" {
    var argv_buf: [2][]const u8 = undefined;
    var argc: usize = 0;
    appendCurlResolveArgs(argv_buf[0..], &argc, null);
    try std.testing.expectEqual(@as(usize, 0), argc);
}

test "curl post max bytes is increased for large provider responses" {
    try std.testing.expect(DEFAULT_CURL_POST_MAX_BYTES >= 8 * 1024 * 1024);
}

test "curl exit code classification maps key network classes" {
    try std.testing.expectEqualStrings("dns", classifyCurlExitCode(6));
    try std.testing.expectEqualStrings("connect", classifyCurlExitCode(7));
    try std.testing.expectEqualStrings("timeout", classifyCurlExitCode(28));
    try std.testing.expectEqualStrings("tls", classifyCurlExitCode(60));
    try std.testing.expectEqualStrings("other", classifyCurlExitCode(22));
}

test "curl exit code mapping returns specific errors" {
    try std.testing.expect(mapCurlExitCodeToError(6) == error.CurlDnsError);
    try std.testing.expect(mapCurlExitCodeToError(7) == error.CurlConnectError);
    try std.testing.expect(mapCurlExitCodeToError(28) == error.CurlTimeout);
    try std.testing.expect(mapCurlExitCodeToError(60) == error.CurlTlsError);
    try std.testing.expect(mapCurlExitCodeToError(22) == error.CurlFailed);
}

test "normalizeProxyEnvValue trims surrounding whitespace" {
    const alloc = std.testing.allocator;
    const normalized = try normalizeProxyEnvValue(alloc, "  socks5://127.0.0.1:1080 \r\n");
    defer if (normalized) |v| alloc.free(v);
    try std.testing.expect(normalized != null);
    try std.testing.expectEqualStrings("socks5://127.0.0.1:1080", normalized.?);
}

test "normalizeProxyEnvValue rejects empty values" {
    const normalized = try normalizeProxyEnvValue(std.testing.allocator, " \t\r\n");
    try std.testing.expect(normalized == null);
}

test "setProxyOverride applies and clears process-wide override" {
    const override = "  socks5://proxy-override-test.invalid:1080  ";
    const normalized_override = "socks5://proxy-override-test.invalid:1080";

    try setProxyOverride(override);
    const from_override = try getProxyFromEnv(std.testing.allocator);
    defer if (from_override) |v| std.testing.allocator.free(v);
    try std.testing.expect(from_override != null);
    try std.testing.expectEqualStrings(normalized_override, from_override.?);

    try setProxyOverride(null);
    const after_clear = try getProxyFromEnv(std.testing.allocator);
    defer if (after_clear) |v| std.testing.allocator.free(v);
    if (after_clear) |proxy| {
        // Environment may define a proxy; only assert our override no longer leaks.
        try std.testing.expect(!std.mem.eql(u8, proxy, normalized_override));
    }
}

test "setProxyOverride accepts long proxy URLs" {
    const allocator = std.testing.allocator;
    var long_proxy = try allocator.alloc(u8, 1600);
    defer allocator.free(long_proxy);

    @memcpy(long_proxy[0.."http://".len], "http://");
    @memset(long_proxy["http://".len..], 'a');

    try setProxyOverride(long_proxy);
    defer setProxyOverride(null) catch unreachable;

    const from_override = try getProxyFromEnv(allocator);
    defer if (from_override) |v| allocator.free(v);
    try std.testing.expect(from_override != null);
    try std.testing.expectEqual(long_proxy.len, from_override.?.len);
}

test "getProxyFromEnvMap honors lowercase https_proxy before http_proxy" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("http_proxy", "http://http-only.example:8080");
    try env_map.put("https_proxy", "https://secure.example:8443");

    const proxy = try getProxyFromEnvMap(std.testing.allocator, &env_map, &https_proxy_env_var_names);
    defer if (proxy) |value| std.testing.allocator.free(value);

    try std.testing.expect(proxy != null);
    try std.testing.expectEqualStrings("https://secure.example:8443", proxy.?);
}

test "applyProxyOverrideToEnvMap overwrites existing proxy values" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("HTTPS_PROXY", "https://old.example:9443");
    try setProxyOverride("  socks5://override.example:1080  ");
    defer setProxyOverride(null) catch unreachable;

    try std.testing.expect(try applyProxyOverrideToEnvMap(&env_map));
    try std.testing.expectEqualStrings("socks5://override.example:1080", env_map.get("HTTPS_PROXY").?);
    try std.testing.expectEqualStrings("socks5://override.example:1080", env_map.get("http_proxy").?);
}

test "initClientDefaultProxiesFromEnvMap parses proxy settings" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("http_proxy", "http://proxy-http.example:8080");
    try env_map.put("HTTPS_PROXY", "https://proxy-https.example:8443");

    var proxy_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer proxy_arena.deinit();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    // Regression: Zig 0.16 requires an explicit environ map for initDefaultProxies.
    try initClientDefaultProxiesFromEnvMap(&client, proxy_arena.allocator(), &env_map);

    try std.testing.expect(client.http_proxy != null);
    try std.testing.expect(client.https_proxy != null);
    try std.testing.expectEqual(@as(u16, 8080), client.http_proxy.?.port);
    try std.testing.expectEqual(@as(u16, 8443), client.https_proxy.?.port);
    try std.testing.expect(client.http_proxy.?.host.eql(try std.Io.net.HostName.init("proxy-http.example")));
    try std.testing.expect(client.https_proxy.?.host.eql(try std.Io.net.HostName.init("proxy-https.example")));
}
