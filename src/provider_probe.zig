const std = @import("std");
const std_compat = @import("compat");
const config_mod = @import("config.zig");
const codex_support = @import("codex_support.zig");
const net_security = @import("net_security.zig");
const onboard = @import("onboard.zig");
const providers = @import("providers/root.zig");

const ProbeResult = struct {
    provider: []const u8,
    model: []const u8,
    live_ok: bool,
    reason: []const u8,
    status_code: ?u16 = null,
};

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var matched = true;
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

fn isLocalEndpoint(url: []const u8) bool {
    const host = net_security.extractHost(url) orelse return false;
    return net_security.isLocalHost(host);
}

pub fn providerRequiresApiKey(provider_name: []const u8, base_url: ?[]const u8) bool {
    return switch (providers.classifyProvider(provider_name)) {
        .ollama_provider, .claude_cli_provider, .codex_cli_provider, .gemini_cli_provider, .openai_codex_provider => false,
        .compatible_provider => blk: {
            if (base_url) |configured| {
                break :blk !isLocalEndpoint(configured);
            }
            if (std.mem.startsWith(u8, provider_name, "custom:")) {
                break :blk !isLocalEndpoint(provider_name["custom:".len..]);
            }
            if (providers.compatibleProviderUrl(provider_name)) |known_url| {
                break :blk !isLocalEndpoint(known_url);
            }
            break :blk true;
        },
        .unknown => blk: {
            if (base_url) |configured| break :blk !isLocalEndpoint(configured);
            break :blk true;
        },
        else => true,
    };
}

fn runCommandProbe(allocator: std.mem.Allocator, argv: []const []const u8, timeout_secs: u64) !void {
    var child = std_compat.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    var finished = std.atomic.Value(bool).init(false);
    var timed_out = std.atomic.Value(bool).init(false);

    const WatchdogCtx = struct {
        finished: *std.atomic.Value(bool),
        timed_out: *std.atomic.Value(bool),
        child: *std_compat.process.Child,
        timeout_secs: u64,
    };
    const watchdog = struct {
        fn run(ctx: WatchdogCtx) void {
            if (ctx.timeout_secs == 0) return;
            const timeout_ns = ctx.timeout_secs * std.time.ns_per_s;
            const tick_ns: u64 = 100 * std.time.ns_per_ms;
            var elapsed_ns: u64 = 0;
            while (elapsed_ns < timeout_ns) {
                if (ctx.finished.load(.acquire)) return;
                const remaining = timeout_ns - elapsed_ns;
                const step = if (remaining < tick_ns) remaining else tick_ns;
                std_compat.thread.sleep(step);
                elapsed_ns += step;
            }
            if (ctx.finished.load(.acquire)) return;
            ctx.timed_out.store(true, .release);
            _ = ctx.child.kill() catch {};
        }
    };

    const watchdog_thread: ?std.Thread = if (timeout_secs > 0)
        (std.Thread.spawn(.{}, watchdog.run, .{WatchdogCtx{
            .finished = &finished,
            .timed_out = &timed_out,
            .child = &child,
            .timeout_secs = timeout_secs,
        }}) catch null)
    else
        null;
    defer if (watchdog_thread) |t| t.join();

    const term = child.wait() catch |err| {
        finished.store(true, .release);
        return err;
    };
    finished.store(true, .release);
    if (timed_out.load(.acquire)) return error.ComponentProbeTimeout;
    switch (term) {
        .exited => |code| if (code != 0) return error.CliProcessFailed,
        else => return error.CliProcessFailed,
    }
}

fn classifyProbeError(err: anyerror) struct { reason: []const u8, status_code: ?u16 } {
    if (err == error.FileNotFound) return .{ .reason = "component_binary_missing", .status_code = 404 };
    if (err == error.ComponentProbeTimeout) return .{ .reason = "probe_timeout", .status_code = 504 };
    if (err == error.CliProcessFailed) return .{ .reason = "component_probe_failed", .status_code = null };
    if (err == error.RateLimited) return .{ .reason = "rate_limited", .status_code = 429 };
    if (err == error.ApiError or err == error.ProviderError) {
        return .{ .reason = "provider_rejected", .status_code = null };
    }

    const name = @errorName(err);
    if (containsIgnoreCase(name, "Unauthorized") or containsIgnoreCase(name, "Authentication")) {
        return .{ .reason = "invalid_api_key", .status_code = 401 };
    }
    if (containsIgnoreCase(name, "Forbidden")) {
        return .{ .reason = "forbidden", .status_code = 403 };
    }
    if (containsIgnoreCase(name, "Timeout") or
        containsIgnoreCase(name, "Network") or
        containsIgnoreCase(name, "Connection") or
        containsIgnoreCase(name, "Curl"))
    {
        return .{ .reason = "network_error", .status_code = null };
    }
    if (containsIgnoreCase(name, "Unavailable") or containsIgnoreCase(name, "Service")) {
        return .{ .reason = "provider_unavailable", .status_code = 503 };
    }
    return .{ .reason = "auth_check_failed", .status_code = null };
}

fn probeCliProvider(
    allocator: std.mem.Allocator,
    kind: providers.ProviderKind,
    provider: []const u8,
    model: []const u8,
    timeout_secs: u64,
) ProbeResult {
    if (kind == .codex_cli_provider) {
        const result = codex_support.probeCodexCli(allocator);
        return .{
            .provider = provider,
            .model = model,
            .live_ok = result.live_ok,
            .reason = result.reason,
            .status_code = if (result.live_ok)
                200
            else if (std.mem.eql(u8, result.reason, "codex_cli_missing"))
                404
            else if (std.mem.eql(u8, result.reason, "codex_cli_not_authenticated"))
                401
            else
                null,
        };
    }

    const argv = switch (kind) {
        .claude_cli_provider => &[_][]const u8{
            "claude",
            "-p",
            "health",
            "--output-format",
            "stream-json",
            "--model",
            model,
            "--verbose",
        },
        .codex_cli_provider => &[_][]const u8{
            "codex",
            "--quiet",
            "health",
        },
        .gemini_cli_provider => &[_][]const u8{
            "gemini",
            "--version",
        },
        else => unreachable,
    };

    runCommandProbe(allocator, argv, timeout_secs) catch |err| {
        const classified = classifyProbeError(err);
        return .{
            .provider = provider,
            .model = model,
            .live_ok = false,
            .reason = classified.reason,
            .status_code = classified.status_code,
        };
    };

    return .{
        .provider = provider,
        .model = model,
        .live_ok = true,
        .reason = "ok",
        .status_code = 200,
    };
}

fn writeProbeResult(result: ProbeResult) !void {
    var stdout_buf: [2048]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&stdout_buf);
    const out = &bw.interface;

    try out.writeAll("{\"provider\":");
    try out.print("{f}", .{std.json.fmt(result.provider, .{})});
    try out.writeAll(",\"model\":");
    try out.print("{f}", .{std.json.fmt(result.model, .{})});
    try out.print(",\"live_ok\":{}", .{result.live_ok});
    try out.writeAll(",\"status\":\"");
    try out.writeAll(if (result.live_ok) "ok" else "error");
    try out.writeAll("\",\"reason\":\"");
    try out.writeAll(result.reason);
    try out.writeAll("\"");
    if (result.status_code) |code| {
        try out.print(",\"status_code\":{d}", .{code});
    }
    try out.writeAll("}\n");
    try bw.interface.flush();
}

fn freeChatResponse(allocator: std.mem.Allocator, response: providers.ChatResponse) void {
    if (response.content) |c| {
        if (c.len > 0) allocator.free(c);
    }
    for (response.tool_calls) |tc| {
        if (tc.id.len > 0) allocator.free(tc.id);
        if (tc.name.len > 0) allocator.free(tc.name);
        if (tc.arguments.len > 0) allocator.free(tc.arguments);
    }
    if (response.tool_calls.len > 0) allocator.free(response.tool_calls);
    if (response.provider.len > 0) allocator.free(response.provider);
    if (response.model.len > 0) allocator.free(response.model);
    if (response.reasoning_content) |rc| {
        if (rc.len > 0) allocator.free(rc);
    }
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var provider_arg: ?[]const u8 = null;
    var model_arg: ?[]const u8 = null;
    var timeout_secs: u64 = 10;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--provider")) {
            if (i + 1 >= args.len) return error.InvalidArguments;
            provider_arg = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--model")) {
            if (i + 1 >= args.len) return error.InvalidArguments;
            model_arg = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--timeout-secs")) {
            if (i + 1 >= args.len) return error.InvalidArguments;
            timeout_secs = std.fmt.parseInt(u64, args[i + 1], 10) catch return error.InvalidArguments;
            i += 1;
            continue;
        }
    }

    var cfg = config_mod.Config.load(allocator) catch {
        try writeProbeResult(.{
            .provider = provider_arg orelse "",
            .model = model_arg orelse "",
            .live_ok = false,
            .reason = "config_load_failed",
        });
        return;
    };
    defer cfg.deinit();

    const provider = blk: {
        if (provider_arg) |p| {
            if (p.len > 0) break :blk p;
        }
        if (cfg.default_provider.len > 0) break :blk cfg.default_provider;
        try writeProbeResult(.{
            .provider = "",
            .model = model_arg orelse "",
            .live_ok = false,
            .reason = "provider_not_detected",
        });
        return;
    };

    const model = blk: {
        if (model_arg) |m| {
            if (m.len > 0) break :blk m;
        }
        if (std.mem.eql(u8, provider, cfg.default_provider)) {
            if (cfg.default_model) |m| {
                if (m.len > 0) break :blk m;
            }
        }
        break :blk onboard.defaultModelForProvider(provider);
    };

    const provider_kind = providers.classifyProvider(provider);
    const provider_base_url = cfg.getProviderBaseUrl(provider);
    const api_key = cfg.getProviderKey(provider);
    if (providerRequiresApiKey(provider, provider_base_url)) {
        const key = api_key orelse "";
        if (key.len == 0) {
            try writeProbeResult(.{
                .provider = provider,
                .model = model,
                .live_ok = false,
                .reason = "missing_api_key",
            });
            return;
        }
    }

    if (provider_kind == .claude_cli_provider or provider_kind == .codex_cli_provider or provider_kind == .gemini_cli_provider) {
        try writeProbeResult(probeCliProvider(allocator, provider_kind, provider, model, timeout_secs));
        return;
    }

    if (provider_kind == .openai_codex_provider) {
        const result = codex_support.probeOpenAiCodex(allocator);
        try writeProbeResult(.{
            .provider = provider,
            .model = model,
            .live_ok = result.live_ok,
            .reason = result.reason,
            .status_code = if (result.live_ok)
                200
            else if (std.mem.eql(u8, result.reason, "codex_auth_missing"))
                401
            else
                null,
        });
        return;
    }

    var holder = providers.ProviderHolder.fromConfigWithApiMode(
        allocator,
        provider,
        api_key,
        provider_base_url,
        cfg.getProviderNativeTools(provider),
        cfg.getProviderUserAgent(provider),
        cfg.getProviderApiMode(provider),
        cfg.getProviderMaxStreamingPromptBytes(provider),
        cfg.getProviderChatTemplateEnableThinkingParam(provider),
        cfg.getProviderExtraBodyParams(provider),
    );
    defer holder.deinit();

    const messages = [_]providers.ChatMessage{
        providers.ChatMessage.user("health"),
    };
    const request = providers.ChatRequest{
        .messages = &messages,
        .model = model,
        .temperature = 0.0,
        .max_tokens = 1,
        .timeout_secs = timeout_secs,
    };

    const response = holder.provider().chat(allocator, request, model, 0.0) catch |err| {
        const classified = classifyProbeError(err);
        try writeProbeResult(.{
            .provider = provider,
            .model = model,
            .live_ok = false,
            .reason = classified.reason,
            .status_code = classified.status_code,
        });
        return;
    };
    defer freeChatResponse(allocator, response);

    const effective_provider = if (response.provider.len > 0) response.provider else provider;
    const effective_model = if (response.model.len > 0) response.model else model;
    try writeProbeResult(.{
        .provider = effective_provider,
        .model = effective_model,
        .live_ok = true,
        .reason = "ok",
        .status_code = 200,
    });
}

test "providerRequiresApiKey marks local providers as keyless" {
    try std.testing.expect(!providerRequiresApiKey("ollama", null));
    try std.testing.expect(!providerRequiresApiKey("claude-cli", null));
    try std.testing.expect(!providerRequiresApiKey("codex-cli", null));
    try std.testing.expect(!providerRequiresApiKey("openai-codex", null));
    try std.testing.expect(!providerRequiresApiKey("gemini-cli", null));
    try std.testing.expect(providerRequiresApiKey("openai", null));
    try std.testing.expect(!providerRequiresApiKey("lmstudio", null));
    // Regression: local-network compatible endpoints should not require API keys.
    try std.testing.expect(!providerRequiresApiKey("custom:http://127.0.0.1:8080/v1", null));
    try std.testing.expect(!providerRequiresApiKey("custom:http://100.64.0.1:8080/v1", null));
    try std.testing.expect(!providerRequiresApiKey("custom:http://model.local:8080/v1", null));
    try std.testing.expect(!providerRequiresApiKey("custom:http://[fd00::1]:8080/v1", null));
    try std.testing.expect(providerRequiresApiKey("custom:https://example.com/v1", null));
}

test "classifyProbeError maps rate limits" {
    const classified = classifyProbeError(error.RateLimited);
    try std.testing.expectEqualStrings("rate_limited", classified.reason);
    try std.testing.expectEqual(@as(?u16, 429), classified.status_code);
}

test "classifyProbeError maps missing binary" {
    const classified = classifyProbeError(error.FileNotFound);
    try std.testing.expectEqualStrings("component_binary_missing", classified.reason);
    try std.testing.expectEqual(@as(?u16, 404), classified.status_code);
}

test "classifyProbeError maps probe timeout" {
    const classified = classifyProbeError(error.ComponentProbeTimeout);
    try std.testing.expectEqualStrings("probe_timeout", classified.reason);
    try std.testing.expectEqual(@as(?u16, 504), classified.status_code);
}
