//! Desktop UI server — serves the embedded single-page app at http://localhost:PORT
//! and provides a local JSON API for the setup wizard and chat interface.
//!
//! API surface:
//!   GET  /              → embedded HTML app
//!   GET  /api/status    → {"configured":bool,"provider":"...","model":"..."}
//!   GET  /api/providers → {"providers":[{"key":"...","label":"...","needs_api_key":bool,"default_model":"..."}]}
//!   POST /api/setup     → {"provider":"...","api_key":"...","model":"..."} → {"ok":true}
//!   POST /api/chat      → {"message":"...","history":[...]} → {"response":"..."}

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("config.zig").Config;
const onboard = @import("onboard.zig");
const providers_mod = @import("providers/root.zig");
const tools_mod = @import("tools/root.zig");
const memory_mod = @import("memory/root.zig");
const bootstrap_mod = @import("bootstrap/root.zig");
const observability_mod = @import("observability.zig");
const security_mod = @import("security/policy.zig");
const subagent_mod = @import("subagent.zig");
const subagent_runner_mod = @import("subagent_runner.zig");
const Agent = @import("agent/root.zig").Agent;

const HTML = @embedFile("assets/app.html");

const DEFAULT_PORT: u16 = 7280;
const MAX_REQUEST_SIZE: usize = 1_048_576; // 1 MB
const CONTENT_TYPE_HTML = "text/html; charset=utf-8";
const CONTENT_TYPE_JSON = "application/json; charset=utf-8";

// ── HTTP helpers ────────────────────────────────────────────────

fn writeResponse(stream: *std.net.Stream, status: []const u8, content_type: []const u8, body: []const u8) void {
    var buf: [512]u8 = undefined;
    const header = std.fmt.bufPrint(
        &buf,
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    ) catch return;
    _ = stream.write(header) catch return;
    if (body.len > 0) _ = stream.write(body) catch {};
}

fn writeJson(stream: *std.net.Stream, status: []const u8, body: []const u8) void {
    writeResponse(stream, status, CONTENT_TYPE_JSON, body);
}

fn extractHeader(raw: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    // Skip request line
    while (pos + 1 < raw.len) {
        if (raw[pos] == '\r' and raw[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        pos += 1;
    }
    while (pos < raw.len) {
        const line_end = std.mem.indexOf(u8, raw[pos..], "\r\n") orelse break;
        const line = raw[pos .. pos + line_end];
        if (line.len == 0) break;
        if (line.len > name.len and line[name.len] == ':') {
            if (std.ascii.eqlIgnoreCase(line[0..name.len], name)) {
                var val_start: usize = name.len + 1;
                while (val_start < line.len and line[val_start] == ' ') val_start += 1;
                return line[val_start..];
            }
        }
        pos += line_end + 2;
    }
    return null;
}

fn extractBody(raw: []const u8) ?[]const u8 {
    const sep = "\r\n\r\n";
    const pos = std.mem.indexOf(u8, raw, sep) orelse return null;
    const body = raw[pos + sep.len ..];
    return if (body.len > 0) body else null;
}

/// On Windows, std.net.Stream.read() calls ReadFile() which fails with
/// ERROR_INVALID_PARAMETER (87) on overlapped sockets created by accept().
/// Use recv() via std.posix instead, which maps to WSARecv on Windows.
fn socketRecv(stream: *std.net.Stream, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        return std.posix.recv(stream.handle, buf, 0);
    }
    return stream.read(buf);
}

fn readRequest(allocator: std.mem.Allocator, stream: *std.net.Stream) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = socketRecv(stream, &chunk) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        try buf.appendSlice(allocator, chunk[0..n]);
        if (buf.items.len > MAX_REQUEST_SIZE) return error.RequestTooLarge;

        // Check if we have the full request
        const raw = buf.items;
        const sep = "\r\n\r\n";
        const header_end = std.mem.indexOf(u8, raw, sep) orelse continue;
        const body_start = header_end + sep.len;

        const cl_raw = extractHeader(raw[0..body_start], "Content-Length") orelse {
            // No content-length → headers-only request is complete
            break;
        };
        const cl = std.fmt.parseInt(usize, std.mem.trim(u8, cl_raw, " \t"), 10) catch break;
        if (raw.len >= body_start + cl) break;
    }
    return buf.toOwnedSlice(allocator);
}

// ── JSON escape helper ──────────────────────────────────────────

fn appendJsonString(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            // Other ASCII control characters (excluding the ones handled above)
            0x00...0x08, 0x0b...0x0c, 0x0e...0x1f => {
                var esc: [6]u8 = undefined;
                _ = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch {};
                try out.appendSlice(allocator, &esc);
            },
            else => try out.append(allocator, c),
        }
    }
    try out.append(allocator, '"');
}

// ── API handlers ────────────────────────────────────────────────

fn handleStatus(allocator: std.mem.Allocator) ![]u8 {
    var cfg = Config.load(allocator) catch {
        return allocator.dupe(u8, "{\"configured\":false,\"first_time\":true}");
    };
    defer cfg.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"configured\":true,\"first_time\":false,\"provider\":");
    try appendJsonString(&out, allocator, cfg.default_provider);
    if (cfg.default_model) |m| {
        try out.appendSlice(allocator, ",\"model\":");
        try appendJsonString(&out, allocator, m);
    }
    if (cfg.agent_name) |name| {
        try out.appendSlice(allocator, ",\"agent_name\":");
        try appendJsonString(&out, allocator, name);
    }
    if (cfg.user_name) |name| {
        try out.appendSlice(allocator, ",\"user_name\":");
        try appendJsonString(&out, allocator, name);
    }
    try out.append(allocator, '}');
    return out.toOwnedSlice(allocator);
}

fn handleProviders(allocator: std.mem.Allocator) ![]u8 {
    const no_key_providers = [_][]const u8{
        "ollama", "lm-studio", "lmstudio", "claude-cli", "codex-cli", "gemini-cli", "openai-codex",
    };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"providers\":[");
    var first = true;
    for (onboard.known_providers) |p| {
        if (!first) try out.append(allocator, ',');
        first = false;
        const needs_key = blk: {
            for (no_key_providers) |np| {
                if (std.mem.eql(u8, p.key, np)) break :blk false;
            }
            break :blk true;
        };
        try out.appendSlice(allocator, "{\"key\":");
        try appendJsonString(&out, allocator, p.key);
        try out.appendSlice(allocator, ",\"label\":");
        try appendJsonString(&out, allocator, p.label);
        try out.appendSlice(allocator, ",\"needs_api_key\":");
        try out.appendSlice(allocator, if (needs_key) "true" else "false");
        try out.appendSlice(allocator, ",\"default_model\":");
        try appendJsonString(&out, allocator, p.default_model);
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn handleSetup(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const SetupReq = struct {
        provider: []const u8 = "anthropic",
        api_key: ?[]const u8 = null,
        model: ?[]const u8 = null,
        user_name: ?[]const u8 = null,
        agent_name: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(SetupReq, allocator, body, .{
        .ignore_unknown_fields = true,
    }) catch {
        return allocator.dupe(u8, "{\"error\":\"invalid JSON\"}");
    };
    defer parsed.deinit();
    const req = parsed.value;

    onboard.runQuickSetup(allocator, req.api_key, req.provider, req.model, null, req.user_name, req.agent_name) catch |err| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "{\"error\":");
        const msg = @errorName(err);
        try appendJsonString(&out, allocator, msg);
        try out.append(allocator, '}');
        return out.toOwnedSlice(allocator);
    };

    return allocator.dupe(u8, "{\"ok\":true}");
}

// ── Agent invocation ────────────────────────────────────────────

const HistoryEntry = struct {
    role: []const u8,
    content: []const u8,
};

const ChatReq = struct {
    message: []const u8,
    history: []const HistoryEntry = &.{},
};

fn runAgentTurn(
    allocator: std.mem.Allocator,
    message: []const u8,
    hist: []const HistoryEntry,
) ![]u8 {
    var cfg = try Config.load(allocator);
    defer cfg.deinit();

    var noop_obs = observability_mod.NoopObserver{};
    const obs = noop_obs.observer();

    var tracker = security_mod.RateTracker.init(allocator, cfg.autonomy.max_actions_per_hour);
    defer tracker.deinit();

    var policy = security_mod.SecurityPolicy{
        .autonomy = cfg.autonomy.level,
        .workspace_dir = cfg.workspace_dir,
        .workspace_only = cfg.autonomy.workspace_only,
        .allowed_commands = security_mod.resolveAllowedCommands(
            cfg.autonomy.level,
            cfg.autonomy.allowed_commands,
        ),
        .max_actions_per_hour = cfg.autonomy.max_actions_per_hour,
        .require_approval_for_medium_risk = cfg.autonomy.require_approval_for_medium_risk,
        .block_high_risk_commands = cfg.autonomy.block_high_risk_commands,
        .allow_raw_url_chars = cfg.autonomy.allow_raw_url_chars,
        .tracker = &tracker,
    };

    var runtime_provider = try providers_mod.runtime_bundle.RuntimeProviderBundle.init(allocator, &cfg);
    defer runtime_provider.deinit();

    var subagent_manager = subagent_mod.SubagentManager.init(allocator, &cfg, null, .{});
    subagent_manager.task_runner = subagent_runner_mod.runTaskWithTools;
    defer subagent_manager.deinit();

    var mem_rt = memory_mod.initRuntime(allocator, &cfg.memory, cfg.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?memory_mod.Memory = if (mem_rt) |rt| rt.memory else null;

    const bootstrap_provider: ?bootstrap_mod.BootstrapProvider =
        bootstrap_mod.createProvider(allocator, cfg.memory.backend, mem_opt, cfg.workspace_dir) catch null;
    defer if (bootstrap_provider) |bp| bp.deinit();

    try onboard.scaffoldWorkspace(allocator, cfg.workspace_dir, &onboard.ProjectContext{
        .user_name = cfg.user_name orelse "User",
        .agent_name = cfg.agent_name orelse "krustyklaw",
    }, bootstrap_provider);

    const tools = try tools_mod.allTools(allocator, cfg.workspace_dir, .{
        .http_enabled = cfg.http_request.enabled,
        .http_allowed_domains = cfg.http_request.allowed_domains,
        .http_max_response_size = cfg.http_request.max_response_size,
        .http_timeout_secs = cfg.http_request.timeout_secs,
        .web_search_base_url = cfg.http_request.search_base_url,
        .web_search_provider = cfg.http_request.search_provider,
        .web_search_fallback_providers = cfg.http_request.search_fallback_providers,
        .browser_enabled = cfg.browser.enabled,
        .mcp_server_configs = cfg.mcp_servers,
        .agents = cfg.agents,
        .configured_providers = cfg.providers,
        .fallback_api_key = runtime_provider.primaryApiKey(),
        .tools_config = cfg.tools,
        .allowed_paths = cfg.autonomy.allowed_paths,
        .policy = &policy,
        .subagent_manager = &subagent_manager,
        .bootstrap_provider = bootstrap_provider,
        .backend_name = cfg.memory.backend,
    });
    defer tools_mod.deinitTools(allocator, tools);
    tools_mod.bindMemoryTools(tools, mem_opt);
    if (mem_rt) |*rt| tools_mod.bindMemoryRuntime(tools, rt);

    var agent = try Agent.fromConfigWithProfile(allocator, &cfg, runtime_provider.provider(), tools, mem_opt, obs, null);
    defer agent.deinit();
    agent.policy = &policy;
    if (mem_rt) |rt| agent.session_store = rt.session_store;
    if (mem_rt) |*rt| {
        agent.response_cache = rt.response_cache;
        agent.mem_rt = rt;
    }

    // Restore conversation history from frontend
    try agent.loadHistory(hist);

    const response = try agent.turn(message);
    defer allocator.free(response);

    return allocator.dupe(u8, response);
}

fn handleChat(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(ChatReq, allocator, body, .{
        .ignore_unknown_fields = true,
    }) catch {
        return allocator.dupe(u8, "{\"error\":\"invalid JSON\"}");
    };
    defer parsed.deinit();

    const response = runAgentTurn(allocator, parsed.value.message, parsed.value.history) catch |err| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "{\"error\":");
        const msg = @errorName(err);
        try appendJsonString(&out, allocator, msg);
        try out.append(allocator, '}');
        return out.toOwnedSlice(allocator);
    };
    defer allocator.free(response);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"response\":");
    try appendJsonString(&out, allocator, response);
    try out.append(allocator, '}');
    return out.toOwnedSlice(allocator);
}

// ── Request dispatch ────────────────────────────────────────────

fn dispatch(allocator: std.mem.Allocator, stream: *std.net.Stream, raw: []const u8) void {
    const first_line_end = std.mem.indexOf(u8, raw, "\r\n") orelse return;
    const first_line = raw[0..first_line_end];
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    const method = parts.next() orelse return;
    const target = parts.next() orelse return;
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |qi| target[0..qi] else target;

    // Handle CORS preflight
    if (std.mem.eql(u8, method, "OPTIONS")) {
        writeJson(stream, "204 No Content", "");
        return;
    }

    const is_get = std.mem.eql(u8, method, "GET");
    const is_post = std.mem.eql(u8, method, "POST");

    if (is_get and std.mem.eql(u8, path, "/")) {
        writeResponse(stream, "200 OK", CONTENT_TYPE_HTML, HTML);
        return;
    }

    if (is_get and std.mem.eql(u8, path, "/api/status")) {
        const body = handleStatus(allocator) catch return writeJson(stream, "500 Internal Server Error", "{\"error\":\"internal\"}");
        defer allocator.free(body);
        writeJson(stream, "200 OK", body);
        return;
    }

    if (is_get and std.mem.eql(u8, path, "/api/providers")) {
        const body = handleProviders(allocator) catch return writeJson(stream, "500 Internal Server Error", "{\"error\":\"internal\"}");
        defer allocator.free(body);
        writeJson(stream, "200 OK", body);
        return;
    }

    if (is_post and std.mem.eql(u8, path, "/api/setup")) {
        const req_body = extractBody(raw) orelse "";
        const resp = handleSetup(allocator, req_body) catch return writeJson(stream, "500 Internal Server Error", "{\"error\":\"internal\"}");
        defer allocator.free(resp);
        writeJson(stream, "200 OK", resp);
        return;
    }

    if (is_post and std.mem.eql(u8, path, "/api/chat")) {
        const req_body = extractBody(raw) orelse "";
        const resp = handleChat(allocator, req_body) catch return writeJson(stream, "500 Internal Server Error", "{\"error\":\"internal\"}");
        defer allocator.free(resp);
        writeJson(stream, "200 OK", resp);
        return;
    }

    writeJson(stream, "404 Not Found", "{\"error\":\"not found\"}");
}

// ── Browser launch ──────────────────────────────────────────────

fn openBrowser(allocator: std.mem.Allocator, url: []const u8) void {
    if (comptime builtin.os.tag == .windows) {
        // "cmd /c start "" <url>" opens the default browser
        var child = std.process.Child.init(
            &.{ "cmd", "/c", "start", "", url },
            allocator,
        );
        child.spawn() catch return;
        _ = child.wait() catch {};
    } else if (comptime builtin.os.tag == .macos) {
        var child = std.process.Child.init(&.{ "open", url }, allocator);
        child.spawn() catch return;
        _ = child.wait() catch {};
    } else {
        // Linux: try xdg-open
        var child = std.process.Child.init(&.{ "xdg-open", url }, allocator);
        child.spawn() catch return;
        _ = child.wait() catch {};
    }
}

// ── Entry point ─────────────────────────────────────────────────

pub fn run(allocator: std.mem.Allocator) !void {
    // Find an available port starting at DEFAULT_PORT
    var port: u16 = DEFAULT_PORT;
    var server: std.net.Server = blk: {
        var attempts: u8 = 0;
        while (attempts < 10) : (attempts += 1) {
            const addr = std.net.Address.parseIp4("127.0.0.1", port) catch return error.AddressParseFailed;
            const s = addr.listen(.{ .reuse_address = true }) catch {
                port += 1;
                continue;
            };
            break :blk s;
        }
        return error.NoPortAvailable;
    };
    defer server.deinit();

    var url_buf: [32]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port}) catch "http://127.0.0.1:7280";

    var stdout_buf: [256]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const w = &bw.interface;
    w.print("KrustyKlaw desktop UI starting at {s}\n", .{url}) catch {};
    w.flush() catch {};

    // Small delay so the server is ready before the browser hits it
    std.Thread.sleep(80 * std.time.ns_per_ms);
    openBrowser(allocator, url);

    // Accept loop
    while (true) {
        var conn = server.accept() catch continue;
        defer conn.stream.close();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const req_alloc = arena.allocator();

        const raw = readRequest(req_alloc, &conn.stream) catch continue;
        dispatch(req_alloc, &conn.stream, raw);
    }
}
