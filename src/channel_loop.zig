//! Channel Loop — extracted polling loops for daemon-supervised channels.
//!
//! Contains `ChannelRuntime` (shared dependencies for message processing)
//! and `runTelegramLoop` (the polling thread function spawned by the
//! daemon supervisor).

const std = @import("std");
const Config = @import("config.zig").Config;
const config_types = @import("config_types.zig");
const telegram = @import("channels/telegram.zig");
const session_mod = @import("session.zig");
const ConversationContext = @import("agent/prompt.zig").ConversationContext;
const buildConversationContext = @import("agent/prompt.zig").buildConversationContext;
const providers = @import("providers/root.zig");
const memory_mod = @import("memory/root.zig");
const bootstrap_mod = @import("bootstrap/root.zig");
const observability = @import("observability.zig");
const tools_mod = @import("tools/root.zig");
const voice = @import("voice.zig");
const health = @import("health.zig");
const daemon = @import("daemon.zig");
const security = @import("security/policy.zig");
const subagent_mod = @import("subagent.zig");
const subagent_runner = @import("subagent_runner.zig");
const agent_routing = @import("agent_routing.zig");
const provider_runtime = @import("providers/runtime_bundle.zig");
const thread_stacks = @import("thread_stacks.zig");
const control_plane = @import("control_plane.zig");
const agent_bindings_config = @import("agent_bindings_config.zig");
const fs_compat = @import("fs_compat.zig");
const provider_probe = @import("provider_probe.zig");

const signal = @import("channels/signal.zig");
const matrix = @import("channels/matrix.zig");
const email = @import("channels/email.zig");
const max_mod = @import("channels/max.zig");
const channels_mod = @import("channels/root.zig");
const Atomic = @import("portable_atomic.zig").Atomic;

const log = std.log.scoped(.channel_loop);

fn hasNonEmptyCredential(value: ?[]const u8) bool {
    const credential = value orelse return false;
    return std.mem.trim(u8, credential, " \t\r\n").len > 0;
}

fn providerHasStartupCredentials(
    allocator: std.mem.Allocator,
    config: *const Config,
    provider_name: []const u8,
) bool {
    const resolved_key = providers.resolveApiKeyFromConfig(
        allocator,
        provider_name,
        config.providers,
    ) catch null;
    defer if (resolved_key) |key| allocator.free(key);

    if (hasNonEmptyCredential(resolved_key)) return true;

    var holder = providers.ProviderHolder.fromConfigWithApiMode(
        allocator,
        provider_name,
        null,
        config.getProviderBaseUrl(provider_name),
        config.getProviderNativeTools(provider_name),
        config.getProviderUserAgent(provider_name),
        config.getProviderApiMode(provider_name),
        config.getProviderMaxStreamingPromptBytes(provider_name),
        config.getProviderChatTemplateEnableThinkingParam(provider_name),
    );
    defer holder.deinit();

    return switch (holder) {
        .ollama => true,
        .claude_cli, .codex_cli, .gemini_cli => true,
        .openai_codex => |provider| provider.access_token != null,
        .gemini => |provider| provider.auth != null,
        .vertex => |provider| provider.auth != null and provider.base != null,
        .compatible => !provider_probe.providerRequiresApiKey(provider_name, config.getProviderBaseUrl(provider_name)),
        else => false,
    };
}

fn hasReliabilityCredentialFallback(
    allocator: std.mem.Allocator,
    config: *const Config,
) bool {
    for (config.reliability.api_keys) |key| {
        if (std.mem.trim(u8, key, " \t\r\n").len > 0) return true;
    }

    for (config.reliability.fallback_providers) |provider_name| {
        if (providerHasStartupCredentials(allocator, config, provider_name)) return true;
    }

    return false;
}

pub fn hasStartupProviderCredentials(
    allocator: std.mem.Allocator,
    config: *const Config,
) bool {
    if (providerHasStartupCredentials(allocator, config, config.default_provider)) return true;
    return hasReliabilityCredentialFallback(allocator, config);
}

/// Set ScheduleTool's default chat_id for delivery context.
fn setScheduleToolContext(
    tools: []const tools_mod.Tool,
    channel: ?[]const u8,
    account_id: ?[]const u8,
    chat_id: ?[]const u8,
    peer_kind: ?agent_routing.ChatType,
    peer_id: ?[]const u8,
    thread_id: ?[]const u8,
) void {
    for (tools) |tool| {
        if (std.mem.eql(u8, tool.name(), "schedule")) {
            const schedule_tool: *tools_mod.schedule.ScheduleTool = @ptrCast(@alignCast(tool.ptr));
            schedule_tool.setContext(channel, account_id, chat_id, peer_kind, peer_id, thread_id);
            break;
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Parallel Message Processing
// ════════════════════════════════════════════════════════════════════════════

fn shouldSuppressGroupReply(is_group: bool, reply: []const u8) bool {
    return is_group and std.mem.indexOf(u8, reply, "[NO_REPLY]") != null;
}

fn shouldSuppressEmailReply(reply: []const u8) bool {
    return std.mem.startsWith(u8, std.mem.trimLeft(u8, reply, " \t\n"), "[NO_REPLY]");
}

fn resolvePiiRedactorPath(allocator: std.mem.Allocator, workspace_dir: []const u8) ?[]u8 {
    if (workspace_dir.len == 0) {
        return std.fs.path.join(allocator, &.{ "scripts", "pii_redactor.py" }) catch null;
    }
    return std.fs.path.join(allocator, &.{ workspace_dir, "scripts", "pii_redactor.py" }) catch null;
}

fn detailedProviderErrorForDisplay(
    allocator: std.mem.Allocator,
    err: anyerror,
) !?[]u8 {
    switch (err) {
        error.ApiError, error.ProviderError, error.AllProvidersFailed => {},
        else => return null,
    }

    const detail = try providers.snapshotLastApiErrorDetail(allocator);
    if (detail) |owned| {
        defer allocator.free(owned);
        if (owned.len == 0) return null;
        const formatted = try std.fmt.allocPrint(allocator, "Provider API error: {s}", .{owned});
        return formatted;
    }
    return null;
}

fn logAgentProcessingError(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    err: anyerror,
) void {
    const detail = providers.snapshotLastApiErrorDetail(allocator) catch null;
    if (detail) |owned| {
        defer allocator.free(owned);
        if (owned.len > 0) {
            log.err("{s}: {} ({s})", .{ prefix, err, owned });
            return;
        }
    }
    log.err("{s}: {}", .{ prefix, err });
}

fn defaultAgentErrorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError, error.CurlDnsError, error.CurlConnectError, error.CurlTimeout, error.CurlTlsError => "Network error contacting provider. Check base_url, DNS, proxy, and TLS certificates, then try again.",
        error.ProviderDoesNotSupportVision => "The current provider does not support image input. Switch to a vision-capable provider or remove [IMAGE:] attachments.",
        error.NoResponseContent => "Model returned an empty response. Please retry or /new for a fresh session.",
        error.AllProvidersFailed => "All configured providers failed for this request. Check model/provider compatibility and credentials.",
        error.OutOfMemory => "Out of memory.",
        else => "An error occurred. Try again or /new for a fresh session.",
    };
}

fn compactAgentErrorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
        error.NoResponseContent => "Model returned an empty response. Please try again.",
        error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError, error.CurlDnsError, error.CurlConnectError, error.CurlTimeout, error.CurlTlsError, error.AllProvidersFailed, error.OutOfMemory => defaultAgentErrorMessage(err),
        else => "An error occurred. Try again.",
    };
}

const TelegramSessionTarget = struct {
    base_chat_id: []const u8,
    thread_id: ?i64,
};

const TelegramSessionMapEntry = struct {
    session_key: []const u8,
    thread_id: ?i64,
    last_active: i64,
    turn_count: u64,
    turn_running: bool,
};

const TELEGRAM_BINDING_COMMENT = "Managed by Telegram /bind";

fn currentTelegramSessionTarget(sender: []const u8) TelegramSessionTarget {
    return .{
        .base_chat_id = telegram.targetChatId(sender),
        .thread_id = telegram.targetThreadId(sender),
    };
}

fn currentTelegramBindingPeerId(
    allocator: std.mem.Allocator,
    sender: []const u8,
    is_group: bool,
) ![]u8 {
    if (!is_group) return allocator.dupe(u8, sender);

    const base_chat_id = telegram.targetChatId(sender);
    if (telegram.targetThreadId(sender)) |thread_id| {
        return std.fmt.allocPrint(allocator, "{s}:thread:{d}", .{ base_chat_id, thread_id });
    }
    return allocator.dupe(u8, base_chat_id);
}

fn currentTelegramBindingKind(is_group: bool) agent_routing.ChatType {
    return if (is_group) .group else .direct;
}

fn telegramBindingTargetLabel(is_group: bool, thread_id: ?i64) []const u8 {
    if (!is_group) return "direct chat";
    if (thread_id != null) return "forum topic";
    return "group chat";
}

fn matchedByLabel(matched_by: agent_routing.MatchedBy) []const u8 {
    return switch (matched_by) {
        .peer => "peer",
        .parent_peer => "parent_peer",
        .guild_roles => "guild_roles",
        .guild => "guild",
        .team => "team",
        .account => "account",
        .channel_only => "channel_only",
        .default => "default",
    };
}

pub fn buildTelegramBindingStatusReply(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    sender: []const u8,
    is_group: bool,
) ![]u8 {
    const base_chat_id = if (is_group) telegram.targetChatId(sender) else sender;
    const thread_id = if (is_group) telegram.targetThreadId(sender) else null;
    const peer_kind = currentTelegramBindingKind(is_group);
    const binding_label = telegramBindingTargetLabel(is_group, thread_id);
    const peer_id = try currentTelegramBindingPeerId(allocator, sender, is_group);
    defer allocator.free(peer_id);

    const current_target = agent_bindings_config.BindingTarget{
        .channel = "telegram",
        .account_id = account_id,
        .peer = .{
            .kind = peer_kind,
            .id = peer_id,
        },
    };
    const exact_binding = agent_bindings_config.findExactPeerBinding(config.agent_bindings, current_target);
    const inherited_binding = agent_bindings_config.findInheritedPeerBinding(config.agent_bindings, current_target);

    const route = try agent_routing.resolveRouteWithSession(allocator, .{
        .channel = "telegram",
        .account_id = account_id,
        .peer = .{
            .kind = peer_kind,
            .id = peer_id,
        },
        .parent_peer = if (is_group and thread_id != null)
            .{
                .kind = peer_kind,
                .id = base_chat_id,
            }
        else
            null,
    }, config.agent_bindings, config.agents, config.session);
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("Telegram binding status\n");
    try writer.print("Account: {s}\n", .{account_id});
    try writer.print("Target: {s} {s}\n", .{ binding_label, peer_id });
    if (thread_id) |tid| {
        try writer.print("Thread: {d}\n", .{tid});
    }
    try writer.print("Effective agent: {s}", .{route.agent_id});
    if (agent_bindings_config.agentDisplayNameForId(config.agents, route.agent_id)) |display_name| {
        try writer.print(" ({s})", .{display_name});
    }
    try writer.writeAll("\n");
    try writer.print("Matched by: {s}\n", .{matchedByLabel(route.matched_by)});
    if (exact_binding) |binding| {
        try writer.print("Exact binding: {s}\n", .{binding.binding.agent_id});
    } else {
        try writer.writeAll("Exact binding: none\n");
    }
    if (inherited_binding) |binding| {
        try writer.print("Inherited peer binding: {s}\n", .{binding.binding.agent_id});
    } else {
        try writer.writeAll("Inherited peer binding: none\n");
    }

    if (config.agents.len == 0) {
        try writer.print("Named agents: none configured in {s}\n", .{config.config_path});
    } else {
        try writer.writeAll("Available named agents:\n");
        for (config.agents) |agent_profile| {
            var agent_buf: [64]u8 = undefined;
            const agent_id = agent_routing.normalizeId(&agent_buf, agent_profile.name);
            try writer.print("- {s} (id: {s}, model: {s}/{s})\n", .{
                agent_profile.name,
                agent_id,
                agent_profile.provider,
                agent_profile.model,
            });
        }
    }
    try writer.writeAll("Usage: /bind <agent>, /bind clear, /bind status");

    return try out.toOwnedSlice(allocator);
}

pub fn applyTelegramBindingCommand(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    sender: []const u8,
    is_group: bool,
    arg: []const u8,
) ![]u8 {
    const trimmed = std.mem.trim(u8, arg, " \t\r\n");
    if (trimmed.len == 0 or std.ascii.eqlIgnoreCase(trimmed, "status") or std.ascii.eqlIgnoreCase(trimmed, "help")) {
        return buildTelegramBindingStatusReply(allocator, config, account_id, sender, is_group);
    }

    const thread_id = if (is_group) telegram.targetThreadId(sender) else null;
    const binding_label = telegramBindingTargetLabel(is_group, thread_id);
    const peer_id = try currentTelegramBindingPeerId(allocator, sender, is_group);
    defer allocator.free(peer_id);

    const binding_target = agent_bindings_config.BindingTarget{
        .channel = "telegram",
        .account_id = account_id,
        .peer = .{
            .kind = currentTelegramBindingKind(is_group),
            .id = peer_id,
        },
        .comment = TELEGRAM_BINDING_COMMENT,
    };

    if (std.ascii.eqlIgnoreCase(trimmed, "clear")) {
        const persisted = try agent_bindings_config.persistBindingUpdate(allocator, config.config_path, binding_target, null);
        const live_applied = blk: {
            const live_cfg = @constCast(config);
            _ = agent_bindings_config.applyBindingUpdate(live_cfg.allocator, live_cfg, binding_target, null) catch break :blk false;
            break :blk true;
        };

        return switch (persisted.status) {
            .removed => std.fmt.allocPrint(
                allocator,
                "Cleared the exact binding for this {s}. {s}",
                .{
                    binding_label,
                    if (live_applied)
                        "Next message here will use the fallback route."
                    else
                        "Saved to config; restart is required for this runtime to pick it up.",
                },
            ),
            .unchanged => std.fmt.allocPrint(allocator, "No exact binding is stored for this {s}.", .{binding_label}),
            else => std.fmt.allocPrint(allocator, "Cleared the exact binding for this {s}.", .{binding_label}),
        };
    }

    if (config.agents.len == 0) {
        return std.fmt.allocPrint(
            allocator,
            "No named agents are configured yet. Add them under agents.list in {s} first.",
            .{config.config_path},
        );
    }

    const selected_agent = agent_bindings_config.findNamedAgent(config.agents, trimmed) orelse {
        const status = try buildTelegramBindingStatusReply(allocator, config, account_id, sender, is_group);
        defer allocator.free(status);
        return std.fmt.allocPrint(
            allocator,
            "Unknown agent '{s}'.\n\n{s}",
            .{ trimmed, status },
        );
    };

    var agent_buf: [64]u8 = undefined;
    const selected_agent_id = agent_routing.normalizeId(&agent_buf, selected_agent.name);

    const persisted = try agent_bindings_config.persistBindingUpdate(allocator, config.config_path, binding_target, selected_agent.name);
    const live_applied = blk: {
        const live_cfg = @constCast(config);
        _ = agent_bindings_config.applyBindingUpdate(live_cfg.allocator, live_cfg, binding_target, selected_agent.name) catch break :blk false;
        break :blk true;
    };

    return switch (persisted.status) {
        .added => std.fmt.allocPrint(
            allocator,
            "Bound this {s} to agent \"{s}\" (id: {s}). {s}",
            .{
                binding_label,
                selected_agent.name,
                selected_agent_id,
                if (live_applied)
                    "Next message here will start or resume that routed session."
                else
                    "Saved to config; restart is required for this runtime to pick it up.",
            },
        ),
        .updated => std.fmt.allocPrint(
            allocator,
            "Updated this {s} binding to agent \"{s}\" (id: {s}). {s}",
            .{
                binding_label,
                selected_agent.name,
                selected_agent_id,
                if (live_applied)
                    "Next message here will start or resume that routed session."
                else
                    "Saved to config; restart is required for this runtime to pick it up.",
            },
        ),
        .unchanged => std.fmt.allocPrint(
            allocator,
            "This {s} is already bound to agent \"{s}\" (id: {s}).",
            .{ binding_label, selected_agent.name, selected_agent_id },
        ),
        .removed => std.fmt.allocPrint(
            allocator,
            "Updated this {s} binding to agent \"{s}\" (id: {s}).",
            .{ binding_label, selected_agent.name, selected_agent_id },
        ),
    };
}

fn parsePositiveI64(raw: []const u8) ?i64 {
    const value = std.fmt.parseInt(i64, raw, 10) catch return null;
    return if (value > 0) value else null;
}

fn parseTelegramTargetRef(target: []const u8) ?TelegramSessionTarget {
    const thread_marker = ":thread:";
    if (std.mem.lastIndexOf(u8, target, thread_marker)) |thread_idx| {
        const base_chat_id = target[0..thread_idx];
        const thread_raw = target[thread_idx + thread_marker.len ..];
        const thread_id = parsePositiveI64(thread_raw) orelse return null;
        if (base_chat_id.len == 0) return null;
        return .{
            .base_chat_id = base_chat_id,
            .thread_id = thread_id,
        };
    }

    return .{
        .base_chat_id = telegram.targetChatId(target),
        .thread_id = telegram.targetThreadId(target),
    };
}

fn parseTelegramSessionTargetFromKey(session_key: []const u8) ?TelegramSessionTarget {
    const group_marker = ":telegram:group:";
    if (std.mem.indexOf(u8, session_key, group_marker)) |idx| {
        const peer = session_key[idx + group_marker.len ..];
        return parseTelegramTargetRef(peer);
    }

    if (std.mem.startsWith(u8, session_key, "telegram:")) {
        const remainder = session_key["telegram:".len..];
        const account_sep = std.mem.indexOfScalar(u8, remainder, ':') orelse return null;
        const target = remainder[account_sep + 1 ..];
        if (target.len == 0) return null;
        return parseTelegramTargetRef(target);
    }

    return null;
}

fn resolveTelegramBaseRouteKey(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    peer_id: []const u8,
    thread_id: ?i64,
    is_group: bool,
) ![]const u8 {
    const peer_kind: agent_routing.ChatType = if (is_group) .group else .direct;
    var topic_peer_id: ?[]u8 = null;
    defer if (topic_peer_id) |owned| allocator.free(owned);

    const route = try agent_routing.resolveRouteWithSession(allocator, .{
        .channel = "telegram",
        .account_id = account_id,
        .peer = .{
            .kind = peer_kind,
            .id = if (is_group and thread_id != null) blk: {
                topic_peer_id = try std.fmt.allocPrint(allocator, "{s}:thread:{d}", .{ peer_id, thread_id.? });
                break :blk topic_peer_id.?;
            } else peer_id,
        },
        .parent_peer = if (is_group and thread_id != null)
            .{
                .kind = peer_kind,
                .id = peer_id,
            }
        else
            null,
    }, config.agent_bindings, config.agents, config.session);
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    return agent_routing.buildSessionKeyWithScope(
        allocator,
        route.agent_id,
        "telegram",
        .{
            .kind = peer_kind,
            .id = peer_id,
        },
        config.session.dm_scope,
        account_id,
        config.session.identity_links,
    );
}

fn buildTelegramFallbackSessionKey(
    allocator: std.mem.Allocator,
    account_id: []const u8,
    peer_id: []const u8,
    thread_id: ?i64,
) ![]const u8 {
    const base_key = try std.fmt.allocPrint(allocator, "telegram:{s}:{s}", .{ account_id, peer_id });
    errdefer allocator.free(base_key);

    if (thread_id) |tid| {
        var thread_buf: [32]u8 = undefined;
        const thread_key = std.fmt.bufPrint(&thread_buf, "{d}", .{tid}) catch return base_key;
        const threaded = try agent_routing.buildThreadSessionKey(allocator, base_key, thread_key);
        allocator.free(base_key);
        return threaded;
    }

    return base_key;
}

fn buildThreadedSessionKeyIfNeeded(
    allocator: std.mem.Allocator,
    base_key: []const u8,
    thread_id: ?i64,
) ![]const u8 {
    if (thread_id) |tid| {
        var thread_buf: [32]u8 = undefined;
        const thread_key = std.fmt.bufPrint(&thread_buf, "{d}", .{tid}) catch return base_key;
        const threaded = try agent_routing.buildThreadSessionKey(allocator, base_key, thread_key);
        allocator.free(base_key);
        return threaded;
    }
    return base_key;
}

fn buildLegacyTelegramTopicSessionKey(
    allocator: std.mem.Allocator,
    base_key: []const u8,
    thread_id: i64,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}#topic:{d}", .{ base_key, thread_id });
}

pub fn resolveTelegramSessionKey(
    allocator: std.mem.Allocator,
    session_mgr: *session_mod.SessionManager,
    config: *const Config,
    account_id: []const u8,
    sender: []const u8,
    is_group: bool,
) ![]const u8 {
    const base_peer_id = if (is_group) telegram.targetChatId(sender) else sender;
    const thread_id = if (is_group) telegram.targetThreadId(sender) else null;

    const canonical_base = resolveTelegramBaseRouteKey(allocator, config, account_id, base_peer_id, thread_id, is_group) catch
        try buildTelegramFallbackSessionKey(allocator, account_id, base_peer_id, null);
    const legacy_key: ?[]u8 = if (thread_id) |tid|
        try buildLegacyTelegramTopicSessionKey(allocator, canonical_base, tid)
    else
        null;
    defer if (legacy_key) |key| allocator.free(key);

    const canonical_key = try buildThreadedSessionKeyIfNeeded(allocator, canonical_base, thread_id);

    if (legacy_key) |key| session_mgr.migrateLegacySessionKey(canonical_key, key);

    return canonical_key;
}

pub fn buildTelegramTopicMapReply(
    allocator: std.mem.Allocator,
    session_mgr: *session_mod.SessionManager,
    sender: []const u8,
) ![]u8 {
    const current_target = currentTelegramSessionTarget(sender);
    const snapshots = try session_mgr.snapshotSessions(allocator);
    defer session_mod.SessionManager.freeSessionSnapshots(allocator, snapshots);

    var entries: std.ArrayListUnmanaged(TelegramSessionMapEntry) = .empty;
    defer entries.deinit(allocator);

    for (snapshots) |snapshot| {
        const target = parseTelegramSessionTargetFromKey(snapshot.session_key) orelse continue;
        if (!std.mem.eql(u8, target.base_chat_id, current_target.base_chat_id)) continue;
        try entries.append(allocator, .{
            .session_key = snapshot.session_key,
            .thread_id = target.thread_id,
            .last_active = snapshot.last_active,
            .turn_count = snapshot.turn_count,
            .turn_running = snapshot.turn_running,
        });
    }

    std.mem.sort(TelegramSessionMapEntry, entries.items, {}, struct {
        fn cmp(_: void, a: TelegramSessionMapEntry, b: TelegramSessionMapEntry) bool {
            if (a.thread_id == null and b.thread_id != null) return true;
            if (a.thread_id != null and b.thread_id == null) return false;
            if (a.thread_id != null and b.thread_id != null and a.thread_id.? != b.thread_id.?) {
                return a.thread_id.? < b.thread_id.?;
            }
            return std.mem.order(u8, a.session_key, b.session_key) == .lt;
        }
    }.cmp);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    const now_ts = std.time.timestamp();

    try writer.print("Telegram topic/session map for chat {s}\n", .{current_target.base_chat_id});
    if (current_target.thread_id) |thread_id| {
        try writer.print("Current topic: {d}\n", .{thread_id});
    } else {
        try writer.writeAll("Current topic: general chat\n");
    }

    if (entries.items.len == 0) {
        try writer.writeAll("No active in-memory sessions for this chat yet.");
        return try out.toOwnedSlice(allocator);
    }

    try writer.print("Active in-memory sessions: {d}\n", .{entries.items.len});
    for (entries.items) |entry| {
        const idle_secs: i64 = @intCast(@max(0, now_ts - entry.last_active));
        const status = if (entry.turn_running) "running" else "idle";
        const is_current = entry.thread_id == current_target.thread_id;

        if (entry.thread_id) |thread_id| {
            try writer.print(
                "- topic {d}{s} [{s}] turns={d} last_active={d}s session={s}\n",
                .{
                    thread_id,
                    if (is_current) " current" else "",
                    status,
                    entry.turn_count,
                    idle_secs,
                    entry.session_key,
                },
            );
        } else {
            try writer.print(
                "- general{s} [{s}] turns={d} last_active={d}s session={s}\n",
                .{
                    if (is_current) " current" else "",
                    status,
                    entry.turn_count,
                    idle_secs,
                    entry.session_key,
                },
            );
        }
    }

    return try out.toOwnedSlice(allocator);
}

fn sendTelegramStartGreeting(
    tg_ptr: *telegram.TelegramChannel,
    sender: []const u8,
    first_name: ?[]const u8,
    fallback_name: []const u8,
    model: []const u8,
    reply_to_id: ?i64,
) void {
    var greeting_buf: [512]u8 = undefined;
    const name = first_name orelse fallback_name;
    const greeting = std.fmt.bufPrint(
        &greeting_buf,
        "Hello, {s}! I'm nullClaw.\n\nModel: {s}\nType /help for available commands.",
        .{ name, model },
    ) catch "Hello! I'm nullClaw. Type /help for commands.";
    tg_ptr.sendMessageWithReply(sender, greeting, reply_to_id) catch |err| {
        log.err("failed to send /start reply: {}", .{err});
    };
}

fn handleTelegramBuiltinCommand(
    allocator: std.mem.Allocator,
    session_mgr: *session_mod.SessionManager,
    config: *const Config,
    tg_ptr: *telegram.TelegramChannel,
    content: []const u8,
    sender: []const u8,
    sender_identity: []const u8,
    first_name: ?[]const u8,
    model: []const u8,
    is_group: bool,
    reply_to_id: ?i64,
    message_id: ?i64,
) bool {
    const cmd = control_plane.parseSlashCommand(content) orelse return false;

    if (control_plane.isSlashName(cmd, "start")) {
        sendTelegramStartGreeting(tg_ptr, sender, first_name, sender_identity, model, reply_to_id);
        return true;
    }

    if (control_plane.isSlashName(cmd, "bind")) {
        tg_ptr.setTaskReaction(sender, message_id, .accepted);

        if (!tg_ptr.binding_commands_enabled) {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            tg_ptr.sendMessageWithReply(sender, "Binding commands are disabled for this Telegram account.", reply_to_id) catch |err| {
                log.err("failed to send /bind disabled reply: {}", .{err});
            };
            return true;
        }

        tg_ptr.setTaskReaction(sender, message_id, .running);
        const reply = applyTelegramBindingCommand(allocator, config, tg_ptr.account_id, sender, is_group, cmd.arg) catch |err| {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            log.err("failed to handle /bind command: {}", .{err});
            tg_ptr.sendMessageWithReply(sender, "Failed to update Telegram binding.", reply_to_id) catch |send_err| {
                log.err("failed to send /bind error reply: {}", .{send_err});
            };
            return true;
        };
        defer allocator.free(reply);

        tg_ptr.sendMessageWithReply(sender, reply, reply_to_id) catch |err| {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            log.err("failed to send /bind reply: {}", .{err});
            return true;
        };
        tg_ptr.setTaskReaction(sender, message_id, .done);
        return true;
    }

    if (control_plane.isSlashName(cmd, "topics") or control_plane.isSlashName(cmd, "topic-map")) {
        tg_ptr.setTaskReaction(sender, message_id, .accepted);

        if (!tg_ptr.topic_map_command_enabled) {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            tg_ptr.sendMessageWithReply(sender, "Topic map command is disabled for this Telegram account.", reply_to_id) catch |err| {
                log.err("failed to send /topics disabled reply: {}", .{err});
            };
            return true;
        }

        tg_ptr.setTaskReaction(sender, message_id, .running);
        const report = buildTelegramTopicMapReply(allocator, session_mgr, sender) catch |err| {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            log.err("failed to build /topics reply: {}", .{err});
            tg_ptr.sendMessageWithReply(sender, "Failed to build topic/session map.", reply_to_id) catch |send_err| {
                log.err("failed to send /topics error reply: {}", .{send_err});
            };
            return true;
        };
        defer allocator.free(report);

        tg_ptr.sendMessageWithReply(sender, report, reply_to_id) catch |err| {
            tg_ptr.setTaskReaction(sender, message_id, .failed);
            log.err("failed to send /topics reply: {}", .{err});
            return true;
        };
        tg_ptr.setTaskReaction(sender, message_id, .done);
        return true;
    }

    if (!control_plane.isSlashName(cmd, "topic")) return false;

    tg_ptr.setTaskReaction(sender, message_id, .accepted);

    if (!tg_ptr.topic_commands_enabled) {
        tg_ptr.setTaskReaction(sender, message_id, .failed);
        tg_ptr.sendMessageWithReply(sender, "Topic commands are disabled for this Telegram account.", reply_to_id) catch |err| {
            log.err("failed to send /topic disabled reply: {}", .{err});
        };
        return true;
    }

    const topic_name = std.mem.trim(u8, cmd.arg, " \t\r\n");
    if (topic_name.len == 0) {
        tg_ptr.setTaskReaction(sender, message_id, .failed);
        tg_ptr.sendMessageWithReply(sender, "Usage: /topic <name>", reply_to_id) catch |err| {
            log.err("failed to send /topic usage reply: {}", .{err});
        };
        return true;
    }

    tg_ptr.setTaskReaction(sender, message_id, .running);
    const thread_id = tg_ptr.createForumTopicFromTarget(sender, topic_name) catch |err| {
        tg_ptr.setTaskReaction(sender, message_id, .failed);
        const err_msg: []const u8 = switch (err) {
            error.InvalidTopicName => "Topic name must be 1-128 characters.",
            else => "Failed to create topic. This works only in forum-enabled supergroups where the bot can manage topics.",
        };
        tg_ptr.sendMessageWithReply(sender, err_msg, reply_to_id) catch |send_err| {
            log.err("failed to send /topic error reply: {}", .{send_err});
        };
        return true;
    };

    const confirmation = std.fmt.allocPrint(
        allocator,
        "Created topic \"{s}\" (thread {d}). Messages in that topic will use an isolated nullclaw session.",
        .{ topic_name, thread_id },
    ) catch null;
    defer if (confirmation) |msg| allocator.free(msg);

    tg_ptr.sendMessageWithReply(sender, confirmation orelse "Topic created.", reply_to_id) catch |err| {
        log.err("failed to send /topic confirmation: {}", .{err});
    };
    tg_ptr.setTaskReaction(sender, message_id, .done);
    return true;
}

fn processTelegramMessage(
    allocator: std.mem.Allocator,
    runtime: *ChannelRuntime,
    tg_ptr: *telegram.TelegramChannel,
    session_key: []const u8,
    content: []const u8,
    sender: []const u8,
    message_id: ?i64,
    is_group: bool,
    reply_to_id: ?i64,
    message_sender_id: []const u8,
) void {
    const typing_target = sender;
    const draft_turn_id = tg_ptr.startTypingTurn(typing_target) catch 0;
    defer {
        tg_ptr.stopTyping(typing_target) catch {};
        if (draft_turn_id != 0) tg_ptr.finishDraftTurn(typing_target, draft_turn_id) catch {};
    }

    // Set ScheduleTool context for delivery.
    var schedule_thread_buf: [32]u8 = undefined;
    const schedule_thread_id = if (is_group)
        if (telegram.targetThreadId(sender)) |thread_id|
            std.fmt.bufPrint(&schedule_thread_buf, "{d}", .{thread_id}) catch null
        else
            null
    else
        null;
    setScheduleToolContext(
        runtime.tools,
        "telegram",
        tg_ptr.account_id,
        sender,
        if (is_group) .group else .direct,
        if (is_group) telegram.targetChatId(sender) else sender,
        schedule_thread_id,
    );
    defer setScheduleToolContext(runtime.tools, null, null, null, null, null, null);

    // Build conversation context for Telegram
    const conversation_context = buildConversationContext(.{
        .channel = "telegram",
        .account_id = tg_ptr.account_id,
        .delivery_chat_id = sender,
        .peer_id = sender,
        .is_group = is_group,
        .group_id = if (is_group) sender else null,
    });

    var stream_ctx = telegram.TelegramChannel.StreamCtx{
        .tg_ptr = tg_ptr,
        .chat_id = sender,
        .draft_id = draft_turn_id,
    };
    const sink = tg_ptr.makeSink(&stream_ctx);

    tg_ptr.setTaskReaction(sender, message_id, .running);
    const reply = runtime.session_mgr.processMessageStreaming(session_key, content, conversation_context, sink) catch |err| {
        logAgentProcessingError(allocator, "Agent error", err);
        tg_ptr.setTaskReaction(sender, message_id, .failed);
        const owned_err_msg = detailedProviderErrorForDisplay(allocator, err) catch null;
        defer if (owned_err_msg) |owned_msg| allocator.free(owned_msg);
        const err_msg = owned_err_msg orelse defaultAgentErrorMessage(err);
        tg_ptr.sendMessageWithReply(sender, err_msg, reply_to_id) catch |send_err| log.err("failed to send error reply: {}", .{send_err});
        return;
    };
    defer allocator.free(reply);

    if (shouldSuppressGroupReply(is_group, reply)) {
        log.info("Smart reply: skipping non-essential message", .{});
        tg_ptr.setTaskReaction(sender, message_id, .done);
        return;
    }

    tg_ptr.sendAssistantMessageWithReply(sender, message_sender_id, is_group, reply, reply_to_id) catch |err| {
        tg_ptr.setTaskReaction(sender, message_id, .failed);
        log.warn("Send error: {}", .{err});
        return;
    };
    tg_ptr.setTaskReaction(sender, message_id, .done);
}

/// Task context for processing a message in a worker thread.
const MessageTask = struct {
    allocator: std.mem.Allocator,
    runtime: *ChannelRuntime,
    tg_ptr: *telegram.TelegramChannel,
    session_key: []const u8,
    content: []const u8,
    sender: []const u8,
    message_id: ?i64,
    is_group: bool,
    reply_to_id: ?i64,
    message_sender_id: []const u8,

    fn run(task: *MessageTask) void {
        processTelegramMessage(
            task.allocator,
            task.runtime,
            task.tg_ptr,
            task.session_key,
            task.content,
            task.sender,
            task.message_id,
            task.is_group,
            task.reply_to_id,
            task.message_sender_id,
        );
    }

    fn deinit(self: *MessageTask) void {
        self.allocator.free(self.session_key);
        self.allocator.free(self.content);
        self.allocator.free(self.sender);
        self.allocator.free(self.message_sender_id);
    }
};

/// Wrapper for thread spawn compatibility
fn messageTaskWorker(task_ptr: *MessageTask) void {
    defer {
        task_ptr.deinit();
        task_ptr.allocator.destroy(task_ptr);
    }
    task_ptr.run();
}

const TELEGRAM_OFFSET_STORE_VERSION: i64 = 1;

fn extractTelegramBotId(bot_token: []const u8) ?[]const u8 {
    const colon_pos = std.mem.indexOfScalar(u8, bot_token, ':') orelse return null;
    if (colon_pos == 0) return null;
    const raw = std.mem.trim(u8, bot_token[0..colon_pos], " \t\r\n");
    if (raw.len == 0) return null;
    for (raw) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    return raw;
}

fn normalizeTelegramAccountId(allocator: std.mem.Allocator, account_id: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, account_id, " \t\r\n");
    const source = if (trimmed.len == 0) "default" else trimmed;
    var normalized = try allocator.alloc(u8, source.len);
    for (source, 0..) |c, i| {
        normalized[i] = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-') c else '_';
    }
    return normalized;
}

fn telegramUpdateOffsetPath(allocator: std.mem.Allocator, config: *const Config, account_id: []const u8) ![]u8 {
    const config_dir = std.fs.path.dirname(config.config_path) orelse ".";
    const normalized_account_id = try normalizeTelegramAccountId(allocator, account_id);
    defer allocator.free(normalized_account_id);

    const file_name = try std.fmt.allocPrint(allocator, "update-offset-{s}.json", .{normalized_account_id});
    defer allocator.free(file_name);

    const relative_path = try std.fs.path.join(allocator, &.{ config_dir, "state", "telegram", file_name });
    defer allocator.free(relative_path);

    if (std.fs.path.isAbsolute(relative_path)) {
        return std.fs.path.resolve(allocator, &.{relative_path});
    }

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fs.path.resolve(allocator, &.{ cwd, relative_path });
}

/// Load persisted Telegram update offset. Returns null when missing/invalid/stale.
pub fn loadTelegramUpdateOffset(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    bot_token: []const u8,
) ?i64 {
    const path = telegramUpdateOffsetPath(allocator, config, account_id) catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const content = file.readToEndAlloc(allocator, 16 * 1024) catch return null;
    defer allocator.free(content);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    if (obj.get("version")) |version_val| {
        if (version_val != .integer or version_val.integer != TELEGRAM_OFFSET_STORE_VERSION) return null;
    }

    const last_update_id_val = obj.get("last_update_id") orelse return null;
    if (last_update_id_val != .integer) return null;

    const expected_bot_id = extractTelegramBotId(bot_token);
    if (expected_bot_id) |expected| {
        const stored_bot_id_val = obj.get("bot_id") orelse return null;
        if (stored_bot_id_val != .string) return null;
        if (!std.mem.eql(u8, stored_bot_id_val.string, expected)) return null;
    } else if (obj.get("bot_id")) |stored_bot_id_val| {
        if (stored_bot_id_val != .null and stored_bot_id_val != .string) return null;
    }

    return last_update_id_val.integer;
}

/// Persist Telegram update offset with bot identity (atomic write).
pub fn saveTelegramUpdateOffset(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    bot_token: []const u8,
    update_id: i64,
) !void {
    const path = try telegramUpdateOffsetPath(allocator, config, account_id);
    defer allocator.free(path);

    if (std.fs.path.dirname(path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => try fs_compat.makePath(dir),
        };
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\n");
    try std.fmt.format(buf.writer(allocator), "  \"version\": {d},\n", .{TELEGRAM_OFFSET_STORE_VERSION});
    try std.fmt.format(buf.writer(allocator), "  \"last_update_id\": {d},\n", .{update_id});
    if (extractTelegramBotId(bot_token)) |bot_id| {
        try std.fmt.format(buf.writer(allocator), "  \"bot_id\": \"{s}\"\n", .{bot_id});
    } else {
        try buf.appendSlice(allocator, "  \"bot_id\": null\n");
    }
    try buf.appendSlice(allocator, "}\n");

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    {
        var tmp_file = try std.fs.createFileAbsolute(tmp_path, .{});
        defer tmp_file.close();
        try tmp_file.writeAll(buf.items);
    }

    std.fs.renameAbsolute(tmp_path, path) catch {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(buf.items);
    };
}

/// Persist candidate Telegram offset only when it advanced beyond the last
/// persisted value. On write failure, keeps watermark unchanged so the caller
/// retries on the next loop iteration.
pub fn persistTelegramUpdateOffsetIfAdvanced(
    allocator: std.mem.Allocator,
    config: *const Config,
    account_id: []const u8,
    bot_token: []const u8,
    persisted_update_id: *i64,
    candidate_update_id: i64,
) void {
    if (candidate_update_id <= persisted_update_id.*) return;
    saveTelegramUpdateOffset(allocator, config, account_id, bot_token, candidate_update_id) catch |err| {
        log.warn("failed to persist telegram update offset: {}", .{err});
        return;
    };
    persisted_update_id.* = candidate_update_id;
}

fn signalGroupPeerId(reply_target: ?[]const u8) []const u8 {
    const target = reply_target orelse "unknown";
    if (std.mem.startsWith(u8, target, signal.GROUP_TARGET_PREFIX)) {
        const raw = target[signal.GROUP_TARGET_PREFIX.len..];
        if (raw.len > 0) return raw;
    }
    return target;
}

fn matrixRoomPeerId(reply_target: ?[]const u8) []const u8 {
    return reply_target orelse "unknown";
}

// ════════════════════════════════════════════════════════════════════════════
// TelegramLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const TelegramLoopState = struct {
    /// Updated after each pollUpdates() — epoch seconds.
    last_activity: Atomic(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: Atomic(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() TelegramLoopState {
        return .{
            .last_activity = Atomic(i64).init(std.time.timestamp()),
            .stop_requested = Atomic(bool).init(false),
        };
    }
};

// Re-export centralized ProviderHolder from providers module.
pub const ProviderHolder = providers.ProviderHolder;

// ════════════════════════════════════════════════════════════════════════════
// ChannelRuntime — container for polling-thread dependencies
// ════════════════════════════════════════════════════════════════════════════

pub const ChannelRuntime = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    session_mgr: session_mod.SessionManager,
    provider_bundle: provider_runtime.RuntimeProviderBundle,
    tools: []const tools_mod.Tool,
    mem_rt: ?memory_mod.MemoryRuntime,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider,
    runtime_observer: *observability.RuntimeObserver,
    subagent_manager: ?*subagent_mod.SubagentManager,
    policy_tracker: *security.RateTracker,
    security_policy: *security.SecurityPolicy,

    /// Initialize the runtime from config — mirrors main.zig:702-786 setup.
    pub fn init(allocator: std.mem.Allocator, config: *const Config) !*ChannelRuntime {
        var runtime_provider = try provider_runtime.RuntimeProviderBundle.init(allocator, config);
        errdefer runtime_provider.deinit();

        const provider_i = runtime_provider.provider();
        const resolved_key = runtime_provider.primaryApiKey();

        const subagent_manager = allocator.create(subagent_mod.SubagentManager) catch null;
        errdefer if (subagent_manager) |mgr| allocator.destroy(mgr);
        if (subagent_manager) |mgr| {
            mgr.* = subagent_mod.SubagentManager.init(allocator, config, null, .{});
            mgr.task_runner = subagent_runner.runTaskWithTools;
            errdefer {
                mgr.deinit();
            }
        }

        // Security policy (same behavior as direct channel loops in main.zig).
        const policy_tracker = try allocator.create(security.RateTracker);
        errdefer allocator.destroy(policy_tracker);
        policy_tracker.* = security.RateTracker.init(allocator, config.autonomy.max_actions_per_hour);
        errdefer policy_tracker.deinit();

        const security_policy = try allocator.create(security.SecurityPolicy);
        errdefer allocator.destroy(security_policy);
        security_policy.* = .{
            .autonomy = config.autonomy.level,
            .workspace_dir = config.workspace_dir,
            .workspace_only = config.autonomy.workspace_only,
            .allowed_commands = security.resolveAllowedCommands(config.autonomy.level, config.autonomy.allowed_commands),
            .max_actions_per_hour = config.autonomy.max_actions_per_hour,
            .require_approval_for_medium_risk = config.autonomy.require_approval_for_medium_risk,
            .block_high_risk_commands = config.autonomy.block_high_risk_commands,
            .allow_raw_url_chars = config.autonomy.allow_raw_url_chars,
            .tracker = policy_tracker,
        };

        // Optional memory backend
        var mem_rt = memory_mod.initRuntime(allocator, &config.memory, config.workspace_dir);
        errdefer if (mem_rt) |*rt| rt.deinit();
        const mem_opt: ?memory_mod.Memory = if (mem_rt) |rt| rt.memory else null;

        const bootstrap_provider: ?bootstrap_mod.BootstrapProvider = bootstrap_mod.createProvider(
            allocator,
            config.memory.backend,
            mem_opt,
            config.workspace_dir,
        ) catch null;
        errdefer if (bootstrap_provider) |bp| bp.deinit();

        // Tools
        const tools = tools_mod.allTools(allocator, config.workspace_dir, .{
            .http_enabled = config.http_request.enabled,
            .http_allowed_domains = config.http_request.allowed_domains,
            .http_max_response_size = config.http_request.max_response_size,
            .http_timeout_secs = config.http_request.timeout_secs,
            .web_search_base_url = config.http_request.search_base_url,
            .web_search_provider = config.http_request.search_provider,
            .web_search_fallback_providers = config.http_request.search_fallback_providers,
            .browser_enabled = config.browser.enabled,
            .screenshot_enabled = true,
            .mcp_server_configs = config.mcp_servers,
            .agents = config.agents,
            .configured_providers = config.providers,
            .fallback_api_key = resolved_key,
            .tools_config = config.tools,
            .allowed_paths = config.autonomy.allowed_paths,
            .policy = security_policy,
            .subagent_manager = subagent_manager,
            .bootstrap_provider = bootstrap_provider,
            .backend_name = config.memory.backend,
            .sandbox_backend = config.security.sandbox.backend,
            .sandbox_enabled = config.sandboxEnabled(),
        }) catch &.{};
        errdefer if (tools.len > 0) tools_mod.deinitTools(allocator, tools);

        const runtime_observer = try observability.RuntimeObserver.create(
            allocator,
            .{
                .workspace_dir = config.workspace_dir,
                .backend = config.diagnostics.backend,
                .otel_endpoint = config.diagnostics.otel_endpoint,
                .otel_service_name = config.diagnostics.otel_service_name,
            },
            config.diagnostics.otel_headers,
            &.{},
        );
        errdefer runtime_observer.destroy();
        const obs = runtime_observer.observer();
        if (subagent_manager) |mgr| {
            mgr.observer = runtime_observer.backendObserver();
        }

        // Session manager
        var session_mgr = session_mod.SessionManager.init(allocator, config, provider_i, tools, mem_opt, obs, if (mem_rt) |rt| rt.session_store else null, if (mem_rt) |*rt| rt.response_cache else null);
        session_mgr.policy = security_policy;

        // Self — heap-allocated so pointers remain stable
        const self = try allocator.create(ChannelRuntime);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .session_mgr = session_mgr,
            .provider_bundle = runtime_provider,
            .tools = tools,
            .mem_rt = mem_rt,
            .bootstrap_provider = bootstrap_provider,
            .runtime_observer = runtime_observer,
            .subagent_manager = subagent_manager,
            .policy_tracker = policy_tracker,
            .security_policy = security_policy,
        };
        // Wire MemoryRuntime pointer into SessionManager for /doctor diagnostics
        // and into memory tools for retrieval pipeline + vector sync.
        // self is heap-allocated so the pointer is stable.
        if (self.mem_rt) |*rt| {
            self.session_mgr.mem_rt = rt;
            tools_mod.bindMemoryRuntime(tools, rt);
        }
        return self;
    }

    pub fn deinit(self: *ChannelRuntime) void {
        const alloc = self.allocator;
        self.session_mgr.deinit();
        if (self.tools.len > 0) tools_mod.deinitTools(alloc, self.tools);
        if (self.bootstrap_provider) |bp| bp.deinit();
        if (self.subagent_manager) |mgr| {
            mgr.deinit();
            alloc.destroy(mgr);
        }
        if (self.mem_rt) |*rt| rt.deinit();
        self.provider_bundle.deinit();
        self.policy_tracker.deinit();
        alloc.destroy(self.security_policy);
        alloc.destroy(self.policy_tracker);
        self.runtime_observer.destroy();
        alloc.destroy(self);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// runTelegramLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for the Telegram polling loop.
/// Mirrors main.zig:793-866 but checks `loop_state.stop_requested` and
/// `daemon.isShutdownRequested()` for graceful shutdown.
///
/// `tg_ptr` is the channel instance owned by the supervisor (ChannelManager).
/// The polling loop uses it directly instead of creating a second
/// TelegramChannel, so health checks and polling operate on the same object.
pub fn runTelegramLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *TelegramLoopState,
    tg_ptr: *telegram.TelegramChannel,
) void {
    // Set up transcription — key comes from providers.{audio_media.provider}
    const trans = config.audio_media;
    if (config.getProviderKey(trans.provider)) |key| {
        const wt = allocator.create(voice.WhisperTranscriber) catch {
            log.warn("Failed to allocate WhisperTranscriber", .{});
            return;
        };
        wt.* = .{
            .endpoint = voice.resolveTranscriptionEndpoint(trans.provider, trans.base_url),
            .api_key = key,
            .model = trans.model,
            .language = trans.language,
        };
        tg_ptr.transcriber = wt.transcriber();
    }
    defer if (tg_ptr.transcriber) |t| {
        allocator.destroy(@as(*voice.WhisperTranscriber, @ptrCast(@alignCast(t.ptr))));
        tg_ptr.transcriber = null;
    };

    // Restore persisted Telegram offset (OpenClaw parity).
    if (loadTelegramUpdateOffset(allocator, config, tg_ptr.account_id, tg_ptr.bot_token)) |saved_update_id| {
        tg_ptr.last_update_id = saved_update_id;
    }

    // Ensure polling mode is active without dropping queued updates.
    tg_ptr.deleteWebhookKeepPending();

    // Register bot commands
    tg_ptr.syncCommandsMenu();
    var persisted_update_id: i64 = tg_ptr.last_update_id;

    var evict_counter: u32 = 0;

    const model = config.default_model orelse {
        log.err("No default model configured. Set agents.defaults.model.primary in config.json in your nullclaw config directory or run `nullclaw onboard`.", .{});
        return;
    };

    // Update activity timestamp at start
    loop_state.last_activity.store(std.time.timestamp(), .release);

    // Parallel worker bookkeeping.
    // Keep at most one in-flight worker per session_key to preserve order.
    var active_worker_threads: std.StringHashMapUnmanaged(std.Thread) = .empty;
    var active_worker_order: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        while (active_worker_order.items.len > 0) {
            const key = active_worker_order.orderedRemove(0);
            if (active_worker_threads.fetchRemove(key)) |entry| {
                entry.value.join();
                allocator.free(@constCast(entry.key));
            }
        }
        active_worker_order.deinit(allocator);
        active_worker_threads.deinit(allocator);
    }

    const max_parallel_tasks: usize = if (config.session.max_concurrent_tasks > 1)
        @intCast(config.session.max_concurrent_tasks)
    else
        1;
    const enable_parallel = max_parallel_tasks > 1;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        const messages = tg_ptr.pollUpdates(allocator) catch |err| {
            log.warn("Telegram poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        // Update activity after each poll (even if no messages)
        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            // Reply-to logic
            const use_reply_to = msg.is_group or tg_ptr.reply_in_private;
            const reply_to_id: ?i64 = if (use_reply_to) msg.message_id else null;

            if (handleTelegramBuiltinCommand(
                allocator,
                &runtime.session_mgr,
                config,
                tg_ptr,
                msg.content,
                msg.sender,
                msg.id,
                msg.first_name,
                model,
                msg.is_group,
                reply_to_id,
                msg.message_id,
            )) {
                continue;
            }

            tg_ptr.setTaskReaction(msg.sender, msg.message_id, .accepted);

            const session_key = resolveTelegramSessionKey(
                allocator,
                &runtime.session_mgr,
                config,
                tg_ptr.account_id,
                msg.sender,
                msg.is_group,
            ) catch |err| {
                tg_ptr.setTaskReaction(msg.sender, msg.message_id, .failed);
                log.err("failed to resolve telegram session key: {}", .{err});
                tg_ptr.sendMessageWithReply(msg.sender, "Failed to resolve session for this Telegram topic.", reply_to_id) catch |send_err| {
                    log.err("failed to send telegram session-key error reply: {}", .{send_err});
                };
                continue;
            };
            defer allocator.free(session_key);

            if (enable_parallel) {
                var handled_in_worker = false;
                parallel_attempt: {
                    if (control_plane.isStopLikeCommand(msg.content) and active_worker_threads.get(session_key) != null) {
                        var interrupt = runtime.session_mgr.requestTurnInterrupt(session_key);
                        defer interrupt.deinit(allocator);
                        var dynamic_notice: ?[]u8 = null;
                        defer if (dynamic_notice) |msg_alloc| allocator.free(msg_alloc);
                        const immediate_notice: []const u8 = blk_notice: {
                            if (interrupt.requested and interrupt.active_tool != null) {
                                dynamic_notice = std.fmt.allocPrint(
                                    allocator,
                                    "Stop requested. Sent hard-stop signal to running tool: {s}.",
                                    .{interrupt.active_tool.?},
                                ) catch null;
                                break :blk_notice dynamic_notice orelse "Stop requested. Sent hard-stop signal.";
                            }
                            if (interrupt.requested) break :blk_notice "Stop requested. Sent hard-stop signal to in-flight execution.";
                            break :blk_notice "Stop requested, but no in-flight turn was found for interruption.";
                        };
                        tg_ptr.sendMessageWithReply(
                            msg.sender,
                            immediate_notice,
                            reply_to_id,
                        ) catch |err| {
                            log.warn("failed to send immediate stop notice: {}", .{err});
                        };
                        tg_ptr.setTaskReaction(msg.sender, msg.message_id, .done);
                        handled_in_worker = true;
                        break :parallel_attempt;
                    }

                    // Preserve message order per session_key.
                    if (active_worker_threads.fetchRemove(session_key)) |entry| {
                        var idx: usize = 0;
                        while (idx < active_worker_order.items.len) : (idx += 1) {
                            if (std.mem.eql(u8, active_worker_order.items[idx], session_key)) {
                                _ = active_worker_order.orderedRemove(idx);
                                break;
                            }
                        }
                        entry.value.join();
                        allocator.free(@constCast(entry.key));
                    }

                    // Bound total parallelism per channel loop instance.
                    while (active_worker_order.items.len >= max_parallel_tasks) {
                        const oldest_key = active_worker_order.orderedRemove(0);
                        if (active_worker_threads.fetchRemove(oldest_key)) |entry| {
                            entry.value.join();
                            allocator.free(@constCast(entry.key));
                        }
                    }

                    // Spawn a worker thread for this message.
                    const task = allocator.create(MessageTask) catch |err| {
                        log.err("Failed to allocate task: {}, falling back to synchronous", .{err});
                        break :parallel_attempt;
                    };

                    const task_session_key = allocator.dupe(u8, session_key) catch |err| {
                        log.err("Failed to duplicate session key: {}, falling back to synchronous", .{err});
                        allocator.destroy(task);
                        break :parallel_attempt;
                    };
                    const task_content = allocator.dupe(u8, msg.content) catch |err| {
                        log.err("Failed to duplicate content: {}, falling back to synchronous", .{err});
                        allocator.free(task_session_key);
                        allocator.destroy(task);
                        break :parallel_attempt;
                    };
                    const task_sender = allocator.dupe(u8, msg.sender) catch |err| {
                        log.err("Failed to duplicate sender: {}, falling back to synchronous", .{err});
                        allocator.free(task_session_key);
                        allocator.free(task_content);
                        allocator.destroy(task);
                        break :parallel_attempt;
                    };
                    const task_message_sender_id = allocator.dupe(u8, msg.id) catch |err| {
                        log.err("Failed to duplicate message id: {}, falling back to synchronous", .{err});
                        allocator.free(task_session_key);
                        allocator.free(task_content);
                        allocator.free(task_sender);
                        allocator.destroy(task);
                        break :parallel_attempt;
                    };

                    task.* = .{
                        .allocator = allocator,
                        .runtime = runtime,
                        .tg_ptr = tg_ptr,
                        .session_key = task_session_key,
                        .content = task_content,
                        .sender = task_sender,
                        .message_id = msg.message_id,
                        .is_group = msg.is_group,
                        .reply_to_id = reply_to_id,
                        .message_sender_id = task_message_sender_id,
                    };

                    const thread = std.Thread.spawn(.{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE }, messageTaskWorker, .{task}) catch |err| {
                        log.err("Failed to spawn worker thread: {}, falling back to synchronous", .{err});
                        task.deinit();
                        allocator.destroy(task);
                        break :parallel_attempt;
                    };

                    const tracked_session_key = allocator.dupe(u8, session_key) catch |err| {
                        log.err("Failed to duplicate tracking session key: {}", .{err});
                        thread.join();
                        handled_in_worker = true;
                        break :parallel_attempt;
                    };

                    active_worker_threads.put(allocator, tracked_session_key, thread) catch |err| {
                        log.err("Failed to register worker thread: {}", .{err});
                        thread.join();
                        allocator.free(tracked_session_key);
                        handled_in_worker = true;
                        break :parallel_attempt;
                    };

                    active_worker_order.append(allocator, tracked_session_key) catch |err| {
                        log.err("Failed to enqueue worker thread: {}", .{err});
                        if (active_worker_threads.fetchRemove(tracked_session_key)) |entry| {
                            entry.value.join();
                            allocator.free(@constCast(entry.key));
                        } else {
                            thread.join();
                            allocator.free(tracked_session_key);
                        }
                        handled_in_worker = true;
                        break :parallel_attempt;
                    };

                    handled_in_worker = true;
                }

                if (handled_in_worker) continue;
            }

            // Synchronous processing
            processTelegramMessage(
                allocator,
                runtime,
                tg_ptr,
                session_key,
                msg.content,
                msg.sender,
                msg.message_id,
                msg.is_group,
                reply_to_id,
                msg.id,
            );
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        if (tg_ptr.persistableUpdateOffset()) |persistable_update_id| {
            persistTelegramUpdateOffsetIfAdvanced(
                allocator,
                config,
                tg_ptr.account_id,
                tg_ptr.bot_token,
                &persisted_update_id,
                persistable_update_id,
            );
        }

        // Periodic session eviction
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("telegram");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SignalLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const SignalLoopState = struct {
    /// Updated after each pollMessages() — epoch seconds.
    last_activity: Atomic(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: Atomic(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() SignalLoopState {
        return .{
            .last_activity = Atomic(i64).init(std.time.timestamp()),
            .stop_requested = Atomic(bool).init(false),
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// runSignalLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for the Signal SSE polling loop.
/// Mirrors runTelegramLoop but uses signal-cli's SSE/JSON-RPC API.
/// Checks `loop_state.stop_requested` and `daemon.isShutdownRequested()`
/// for graceful shutdown.
pub fn runSignalLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *SignalLoopState,
    sg_ptr: *signal.SignalChannel,
) void {
    // Update activity timestamp at start
    loop_state.last_activity.store(std.time.timestamp(), .release);

    var evict_counter: u32 = 0;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        const messages = sg_ptr.pollMessages(allocator) catch |err| {
            log.warn("Signal poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        // Update activity after each poll (even if no messages)
        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            const schedule_chat_id = msg.reply_target orelse msg.sender;
            setScheduleToolContext(
                runtime.tools,
                "signal",
                sg_ptr.account_id,
                schedule_chat_id,
                if (msg.is_group) .group else .direct,
                if (msg.is_group) signalGroupPeerId(msg.reply_target) else msg.sender,
                null,
            );
            defer setScheduleToolContext(runtime.tools, null, null, null, null, null, null);

            // Session key — always resolve through agent routing (falls back on errors)
            var key_buf: [128]u8 = undefined;
            const group_peer_id = signalGroupPeerId(msg.reply_target);
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);
            const session_key = blk: {
                const route = agent_routing.resolveRouteWithSession(allocator, .{
                    .channel = "signal",
                    .account_id = sg_ptr.account_id,
                    .peer = .{
                        .kind = if (msg.is_group) .group else .direct,
                        .id = if (msg.is_group) group_peer_id else msg.sender,
                    },
                }, config.agent_bindings, config.agents, config.session) catch break :blk if (msg.is_group)
                    std.fmt.bufPrint(&key_buf, "signal:{s}:group:{s}:{s}", .{
                        sg_ptr.account_id,
                        group_peer_id,
                        msg.sender,
                    }) catch msg.sender
                else
                    std.fmt.bufPrint(&key_buf, "signal:{s}:{s}", .{ sg_ptr.account_id, msg.sender }) catch msg.sender;
                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            const typing_target = msg.reply_target;
            if (typing_target) |target| sg_ptr.startTyping(target) catch {};
            defer if (typing_target) |target| sg_ptr.stopTyping(target) catch {};

            // Build conversation context for Signal
            const conversation_context = buildConversationContext(.{
                .channel = "signal",
                .account_id = sg_ptr.account_id,
                .sender_number = if (msg.sender.len > 0 and msg.sender[0] == '+') msg.sender else null,
                .sender_uuid = msg.sender_uuid,
                .delivery_chat_id = msg.reply_target orelse msg.sender,
                .peer_id = if (msg.is_group) msg.group_id else msg.sender,
                .group_id = msg.group_id,
                .is_group = msg.is_group,
            });

            const reply = runtime.session_mgr.processMessage(session_key, msg.content, conversation_context) catch |err| {
                logAgentProcessingError(allocator, "Signal agent error", err);
                const owned_err_msg = detailedProviderErrorForDisplay(allocator, err) catch null;
                defer if (owned_err_msg) |owned_msg| allocator.free(owned_msg);
                const err_msg = owned_err_msg orelse compactAgentErrorMessage(err);
                if (msg.reply_target) |target| {
                    sg_ptr.sendMessage(target, err_msg, &.{}) catch |send_err| log.err("failed to send signal error reply: {}", .{send_err});
                }
                continue;
            };
            defer allocator.free(reply);

            // Reply on Signal
            if (msg.reply_target) |target| {
                sg_ptr.sendMessage(target, reply, &.{}) catch |err| {
                    log.warn("Signal send error: {}", .{err});
                };
            }
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        // Periodic session eviction
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("signal");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MatrixLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const MatrixLoopState = struct {
    /// Updated after each pollMessages() — epoch seconds.
    last_activity: Atomic(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: Atomic(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() MatrixLoopState {
        return .{
            .last_activity = Atomic(i64).init(std.time.timestamp()),
            .stop_requested = Atomic(bool).init(false),
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// EmailLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const EmailLoopState = struct {
    /// Updated after each pollMessages() — epoch seconds.
    last_activity: Atomic(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: Atomic(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() EmailLoopState {
        return .{
            .last_activity = Atomic(i64).init(std.time.timestamp()),
            .stop_requested = Atomic(bool).init(false),
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// MaxLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const MaxLoopState = struct {
    /// Updated after each pollUpdates() — epoch seconds.
    last_activity: Atomic(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: Atomic(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() MaxLoopState {
        return .{
            .last_activity = Atomic(i64).init(std.time.timestamp()),
            .stop_requested = Atomic(bool).init(false),
        };
    }
};

pub const PollingState = union(enum) {
    telegram: *TelegramLoopState,
    signal: *SignalLoopState,
    matrix: *MatrixLoopState,
    email: *EmailLoopState,
    max: *MaxLoopState,
};

pub const PollingSpawnResult = struct {
    thread: std.Thread,
    state: PollingState,
};

pub fn spawnTelegramPolling(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    channel: channels_mod.Channel,
) !PollingSpawnResult {
    const tg_ls = try allocator.create(TelegramLoopState);
    errdefer allocator.destroy(tg_ls);
    tg_ls.* = TelegramLoopState.init();

    const tg_ptr: *telegram.TelegramChannel = @ptrCast(@alignCast(channel.ptr));
    const thread = try std.Thread.spawn(
        .{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE },
        runTelegramLoop,
        .{ allocator, config, runtime, tg_ls, tg_ptr },
    );
    tg_ls.thread = thread;

    return .{
        .thread = thread,
        .state = .{ .telegram = tg_ls },
    };
}

pub fn spawnSignalPolling(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    channel: channels_mod.Channel,
) !PollingSpawnResult {
    const sg_ls = try allocator.create(SignalLoopState);
    errdefer allocator.destroy(sg_ls);
    sg_ls.* = SignalLoopState.init();

    const sg_ptr: *signal.SignalChannel = @ptrCast(@alignCast(channel.ptr));
    const thread = try std.Thread.spawn(
        .{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE },
        runSignalLoop,
        .{ allocator, config, runtime, sg_ls, sg_ptr },
    );
    sg_ls.thread = thread;

    return .{
        .thread = thread,
        .state = .{ .signal = sg_ls },
    };
}

pub fn spawnMatrixPolling(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    channel: channels_mod.Channel,
) !PollingSpawnResult {
    const mx_ls = try allocator.create(MatrixLoopState);
    errdefer allocator.destroy(mx_ls);
    mx_ls.* = MatrixLoopState.init();

    const mx_ptr: *matrix.MatrixChannel = @ptrCast(@alignCast(channel.ptr));
    const thread = try std.Thread.spawn(
        .{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE },
        runMatrixLoop,
        .{ allocator, config, runtime, mx_ls, mx_ptr },
    );
    mx_ls.thread = thread;

    return .{
        .thread = thread,
        .state = .{ .matrix = mx_ls },
    };
}

pub fn spawnEmailPolling(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    channel: channels_mod.Channel,
) !PollingSpawnResult {
    const em_ls = try allocator.create(EmailLoopState);
    errdefer allocator.destroy(em_ls);
    em_ls.* = EmailLoopState.init();

    const em_ptr: *email.EmailChannel = @ptrCast(@alignCast(channel.ptr));
    const thread = try std.Thread.spawn(
        .{ .stack_size = 2 * 1024 * 1024 },
        runEmailLoop,
        .{ allocator, config, runtime, em_ls, em_ptr },
    );
    em_ls.thread = thread;

    return .{
        .thread = thread,
        .state = .{ .email = em_ls },
    };
}

// ════════════════════════════════════════════════════════════════════════════
/// Split an email reply_target ("addr\x00subject") into address and subject parts.
fn splitEmailTarget(target: []const u8) struct { addr: []const u8, subject: []const u8 } {
    if (std.mem.indexOfScalar(u8, target, 0)) |sep| {
        return .{ .addr = target[0..sep], .subject = target[sep + 1 ..] };
    }
    return .{ .addr = target, .subject = "" };
}

// ── PII redaction helpers ─────────────────────────────────────────────────
// Spawn the Python pii_redactor.py script, piping content via stdin.
// On any error, returns null so the caller can fall back to the original text.

fn redactPii(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    content: []const u8,
    msg_id: []const u8,
    sender: []const u8,
    use_spacy: bool,
) ?[]u8 {
    const script = resolvePiiRedactorPath(allocator, workspace_dir) orelse return null;
    defer allocator.free(script);

    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "python3";
    argc += 1;
    argv_buf[argc] = script;
    argc += 1;
    argv_buf[argc] = "redact";
    argc += 1;

    // Build --id=<msg_id> string
    const id_arg = std.fmt.allocPrint(allocator, "--id={s}", .{msg_id}) catch return null;
    defer allocator.free(id_arg);
    argv_buf[argc] = id_arg;
    argc += 1;

    // Build --sender=<sender>
    var sender_arg: ?[]u8 = null;
    defer if (sender_arg) |s| allocator.free(s);
    if (sender.len > 0) {
        sender_arg = std.fmt.allocPrint(allocator, "--sender={s}", .{sender}) catch return null;
        argv_buf[argc] = sender_arg.?;
        argc += 1;
    }

    if (use_spacy) {
        argv_buf[argc] = "--spacy";
        argc += 1;
    }

    const argv = argv_buf[0..argc];

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch |err| {
        log.warn("PII redact spawn error: {}", .{err});
        return null;
    };

    // Write content to stdin, then close
    if (child.stdin) |*stdin_stream| {
        stdin_stream.writeAll(content) catch {};
        stdin_stream.close();
        child.stdin = null;
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1_048_576) catch |err| {
        log.warn("PII redact stdout read error: {}", .{err});
        _ = child.wait() catch {};
        return null;
    };
    // Read stderr but discard
    const stderr = child.stderr.?.readToEndAlloc(allocator, 65_536) catch "";
    defer if (stderr.len > 0) allocator.free(stderr);

    const term = child.wait() catch |err| {
        log.warn("PII redact wait error: {}", .{err});
        allocator.free(stdout);
        return null;
    };

    const exit_ok = switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };

    if (!exit_ok) {
        log.warn("PII redact exited with error", .{});
        if (stderr.len > 0) log.warn("PII redact stderr: {s}", .{stderr});
        allocator.free(stdout);
        return null;
    }

    return stdout;
}

fn deredactPii(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    text: []const u8,
    msg_id: []const u8,
) ?[]u8 {
    const script = resolvePiiRedactorPath(allocator, workspace_dir) orelse return null;
    defer allocator.free(script);

    const id_arg = std.fmt.allocPrint(allocator, "--id={s}", .{msg_id}) catch return null;
    defer allocator.free(id_arg);

    const argv = [_][]const u8{ "python3", script, "deredact", id_arg };

    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch |err| {
        log.warn("PII deredact spawn error: {}", .{err});
        return null;
    };

    if (child.stdin) |*stdin_stream| {
        stdin_stream.writeAll(text) catch {};
        stdin_stream.close();
        child.stdin = null;
    }

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1_048_576) catch |err| {
        log.warn("PII deredact stdout read error: {}", .{err});
        _ = child.wait() catch {};
        return null;
    };
    const stderr = child.stderr.?.readToEndAlloc(allocator, 65_536) catch "";
    defer if (stderr.len > 0) allocator.free(stderr);

    const term = child.wait() catch |err| {
        log.warn("PII deredact wait error: {}", .{err});
        allocator.free(stdout);
        return null;
    };

    const exit_ok = switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };

    if (!exit_ok) {
        log.warn("PII deredact exited with error", .{});
        if (stderr.len > 0) log.warn("PII deredact stderr: {s}", .{stderr});
        allocator.free(stdout);
        return null;
    }

    return stdout;
}

// runEmailLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for Email IMAP.
/// Dispatches to IDLE mode (persistent connection) or polling (curl) based on config.
pub fn runEmailLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *EmailLoopState,
    em_ptr: *email.EmailChannel,
) void {
    loop_state.last_activity.store(std.time.timestamp(), .release);

    if (em_ptr.config.imap_idle) {
        runEmailIdleLoop(allocator, config, runtime, loop_state, em_ptr);
    } else {
        runEmailPollLoop(allocator, config, runtime, loop_state, em_ptr);
    }
}

/// IDLE-based email loop — persistent TLS+IMAP connection with push notifications.
fn runEmailIdleLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *EmailLoopState,
    em_ptr: *email.EmailChannel,
) void {
    var imap = email.ImapClient.init(allocator, em_ptr.config);
    defer imap.disconnect();

    var evict_counter: u32 = 0;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        // ── Connect phase ────────────────────────────────────────────
        imap.connect() catch {
            imap.backoff();
            if (imap.shouldFallbackToPoll()) {
                log.warn("IMAP IDLE: too many connect failures, falling back to poll mode", .{});
                runEmailPollLoop(allocator, config, runtime, loop_state, em_ptr);
                return;
            }
            continue;
        };

        imap.login() catch {
            imap.disconnect();
            imap.backoff();
            if (imap.shouldFallbackToPoll()) {
                log.warn("IMAP IDLE: login failures, falling back to poll mode", .{});
                runEmailPollLoop(allocator, config, runtime, loop_state, em_ptr);
                return;
            }
            continue;
        };

        imap.capability() catch {
            imap.disconnect();
            imap.backoff();
            continue;
        };

        if (!imap.server_supports_idle) {
            log.info("IMAP server lacks IDLE capability, using poll mode", .{});
            imap.logout();
            runEmailPollLoop(allocator, config, runtime, loop_state, em_ptr);
            return;
        }

        imap.selectFolder() catch {
            imap.disconnect();
            imap.backoff();
            continue;
        };

        // Connected successfully
        imap.resetBackoff();
        log.info("IMAP IDLE mode active", .{});

        // ── Main IDLE loop ───────────────────────────────────────────
        inner: while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
            // Check for unseen messages before entering IDLE
            const uids = imap.searchUnseen(allocator) catch break :inner;
            defer {
                for (uids) |uid| allocator.free(uid);
                allocator.free(uids);
            }

            // Process new messages
            for (uids) |uid| {
                if (em_ptr.seen_uids.contains(uid)) continue;

                // Fetch raw email via native IMAP
                const raw_email = imap.fetchMessage(allocator, uid) catch |err| {
                    log.warn("IMAP IDLE: failed to fetch UID {s}: {}", .{ uid, err });
                    continue;
                };
                defer allocator.free(raw_email);

                // Reuse existing email processing pipeline
                processIncomingEmail(allocator, config, runtime, em_ptr, uid, raw_email);

                // Mark seen on the server
                imap.storeSeen(uid) catch {};
            }

            loop_state.last_activity.store(std.time.timestamp(), .release);
            health.markComponentOk("email");

            evict_counter += 1;
            if (evict_counter >= 100) {
                evict_counter = 0;
                _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
            }

            // Enter IDLE — blocks until new mail, timeout renewal, or shutdown
            const result = imap.idle(&loop_state.stop_requested, &loop_state.last_activity) catch break :inner;
            switch (result) {
                .new_mail => continue :inner, // loop back to searchUnseen
                .renewal => continue :inner, // 25-min renewal
                .shutdown => {
                    imap.logout();
                    return;
                },
            }
        }

        // Broke out of inner loop — reconnect
        imap.disconnect();
        imap.backoff();
    }

    // Clean shutdown
    imap.logout();
}

/// Process a single incoming email — extracted from the poll loop for reuse.
/// Handles parsing, allowlist check, PII, agent dispatch, and reply.
fn processIncomingEmail(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    em_ptr: *email.EmailChannel,
    uid: []const u8,
    raw_email_data: []const u8,
) void {
    const parsed = email.parseRawEmail(raw_email_data);
    const sender_addr = email.extractEmailAddress(parsed.from);

    const is_known_sender = em_ptr.isSenderAllowed(sender_addr);
    if (!is_known_sender) {
        log.info("Email from unknown sender: {s} — forwarding to agent for triage", .{sender_addr});
    }

    var body_text = email.extractTextBody(allocator, raw_email_data) catch return;
    defer allocator.free(body_text);

    const max_bytes = em_ptr.config.max_body_bytes;
    var final_content: []u8 = undefined;

    if (body_text.len > max_bytes) {
        final_content = std.fmt.allocPrint(allocator, "{s}\n[TRUNCATED - original was {d} bytes]", .{
            body_text[0..max_bytes], body_text.len,
        }) catch return;
    } else {
        final_content = allocator.dupe(u8, body_text) catch return;
    }

    // Injection check
    if (email.basicInjectionCheck(final_content)) {
        log.warn("Injection pattern detected in email from {s}", .{sender_addr});
        allocator.free(final_content);
        _ = em_ptr.seen_uids.insert(uid) catch {};
        return;
    }

    // Extract and save attachments
    var saved_attachments: []channels_mod.Attachment = &.{};
    if (em_ptr.config.attachment_save_enabled) {
        saved_attachments = email.extractAndSaveAttachments(
            allocator,
            raw_email_data,
            em_ptr.config.attachment_save_dir,
            em_ptr.config.attachment_extensions,
            em_ptr.config.attachment_max_bytes,
            uid,
        ) catch &.{};
    }

    // Build attachment info text
    var attachment_info: []u8 = &.{};
    defer if (attachment_info.len > 0) allocator.free(attachment_info);

    if (saved_attachments.len > 0) {
        var info_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer info_buf.deinit(allocator);
        const writer = info_buf.writer(allocator);
        writer.writeAll("\n\n[ATTACHMENTS]\n") catch {};
        for (saved_attachments) |att| {
            writer.print("- {s} (saved to: {s})\n", .{ att.filename, att.path }) catch {};
        }
        writer.writeAll("[/ATTACHMENTS]") catch {};
        attachment_info = info_buf.toOwnedSlice(allocator) catch &.{};
    }

    // Wrap with security markers
    const tag_start: []const u8 = if (is_known_sender) "[UNTRUSTED_EMAIL_START]" else "[UNKNOWN_SENDER_START]";
    const tag_end: []const u8 = if (is_known_sender) "[UNTRUSTED_EMAIL_END]" else "[UNKNOWN_SENDER_END]";
    const wrapped = if (attachment_info.len > 0)
        std.fmt.allocPrint(allocator, "{s}\nFrom: {s}\nSubject: {s}\n\n{s}{s}\n{s}", .{
            tag_start, sender_addr, parsed.subject, final_content, attachment_info, tag_end,
        }) catch {
            allocator.free(final_content);
            return;
        }
    else
        std.fmt.allocPrint(allocator, "{s}\nFrom: {s}\nSubject: {s}\n\n{s}\n{s}", .{
            tag_start, sender_addr, parsed.subject, final_content, tag_end,
        }) catch {
            allocator.free(final_content);
            return;
        };
    allocator.free(final_content);
    defer allocator.free(wrapped);

    // Track Message-ID for threading
    if (parsed.message_id.len > 0) {
        em_ptr.trackMessageId(sender_addr, parsed.message_id) catch {};
    }

    // Mark as seen in dedup set
    _ = em_ptr.seen_uids.insert(uid) catch {};

    // ── Agent dispatch ───────────────────────────────────────────
    var key_buf: [192]u8 = undefined;
    var routed_session_key: ?[]const u8 = null;
    defer if (routed_session_key) |key| allocator.free(key);

    const session_key = blk: {
        const route = agent_routing.resolveRouteWithSession(allocator, .{
            .channel = "email",
            .account_id = em_ptr.config.account_id,
            .peer = .{
                .kind = .direct,
                .id = sender_addr,
            },
        }, config.agent_bindings, config.agents, config.session) catch break :blk std.fmt.bufPrint(&key_buf, "email:{s}:{s}", .{ em_ptr.config.account_id, sender_addr }) catch sender_addr;

        allocator.free(route.main_session_key);
        routed_session_key = route.session_key;
        break :blk route.session_key;
    };

    // PII redaction (pre-LLM)
    const pii_enabled = em_ptr.config.pii_redaction;
    var redacted_content: ?[]u8 = null;
    defer if (redacted_content) |rc| allocator.free(rc);

    const content_for_llm = if (pii_enabled) pii_blk: {
        redacted_content = redactPii(allocator, config.workspace_dir, wrapped, uid, sender_addr, em_ptr.config.pii_spacy);
        if (redacted_content) |rc| {
            break :pii_blk rc;
        } else {
            log.warn("PII redaction failed, using original content", .{});
            break :pii_blk wrapped;
        }
    } else wrapped;

    // Set ScheduleTool context so subagents know the originating channel.
    setScheduleToolContext(runtime.tools, "email", em_ptr.config.account_id, sender_addr);
    defer setScheduleToolContext(runtime.tools, null, null, null);

    const reply = runtime.session_mgr.processMessage(session_key, content_for_llm, null) catch |err| {
        log.err("Email agent error: {}", .{err});
        const err_msg: []const u8 = switch (err) {
            error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "Network error. Please try again.",
            error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
            error.NoResponseContent => "Model returned an empty response. Please try again.",
            error.AllProvidersFailed => "All configured providers failed for this request.",
            error.OutOfMemory => "Out of memory.",
            else => "An error occurred. Try again.",
        };
        em_ptr.sendReply(sender_addr, parsed.subject, err_msg) catch |send_err| log.err("failed to send email error reply: {}", .{send_err});
        return;
    };
    defer allocator.free(reply);

    // PII de-redaction (post-LLM)
    var deredacted_reply: ?[]u8 = null;
    defer if (deredacted_reply) |dr| allocator.free(dr);

    const final_reply = if (pii_enabled) deredact_blk: {
        deredacted_reply = deredactPii(allocator, config.workspace_dir, reply, uid);
        if (deredacted_reply) |dr| {
            break :deredact_blk dr;
        } else {
            log.warn("PII de-redaction failed, using redacted reply", .{});
            break :deredact_blk reply;
        }
    } else reply;

    // If the agent prefixes its reply with [NO_REPLY], suppress the email reply.
    // Used for unknown sender triage where the agent handles routing via tools.
    if (shouldSuppressEmailReply(final_reply)) {
        log.info("Email reply suppressed by [NO_REPLY] marker for {s}", .{sender_addr});
        return;
    }

    em_ptr.sendReply(sender_addr, parsed.subject, final_reply) catch |err| {
        log.warn("Email send error: {}", .{err});
    };
}

/// Curl-based polling loop (fallback when IDLE is unavailable or disabled).
fn runEmailPollLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *EmailLoopState,
    em_ptr: *email.EmailChannel,
) void {
    var evict_counter: u32 = 0;
    var consecutive_net_failures: u32 = 0;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        // Skip polling when the network is unreachable (e.g. wifi off at night).
        // Uses exponential backoff: 30s, 60s, 120s, ... up to 5 minutes.
        if (!em_ptr.isImapReachable(allocator)) {
            consecutive_net_failures +|= 1;
            if (consecutive_net_failures == 1) {
                log.info("Email: IMAP server unreachable, pausing poll until network returns", .{});
            }
            const shift: u6 = @intCast(@min(consecutive_net_failures, 3));
            const backoff: u64 = @min(@as(u64, 30) << shift, 300);
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(backoff * std.time.ns_per_s);
            continue;
        }
        if (consecutive_net_failures > 0) {
            log.info("Email: network restored after {d} failed probes, resuming poll", .{consecutive_net_failures});
            consecutive_net_failures = 0;
        }

        const messages = em_ptr.pollMessages(allocator) catch |err| {
            log.warn("Email poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            var key_buf: [192]u8 = undefined;
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);

            const session_key = blk: {
                const route = agent_routing.resolveRouteWithSession(allocator, .{
                    .channel = "email",
                    .account_id = em_ptr.config.account_id,
                    .peer = .{
                        .kind = .direct,
                        .id = msg.sender,
                    },
                }, config.agent_bindings, config.agents, config.session) catch break :blk std.fmt.bufPrint(&key_buf, "email:{s}:{s}", .{ em_ptr.config.account_id, msg.sender }) catch msg.sender;

                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            // PII redaction (pre-LLM)
            const pii_enabled = em_ptr.config.pii_redaction;
            var redacted_content: ?[]u8 = null;
            defer if (redacted_content) |rc| allocator.free(rc);

            const content_for_llm = if (pii_enabled) blk: {
                redacted_content = redactPii(allocator, config.workspace_dir, msg.content, msg.id, msg.sender, em_ptr.config.pii_spacy);
                if (redacted_content) |rc| {
                    break :blk rc;
                } else {
                    log.warn("PII redaction failed, using original content", .{});
                    break :blk msg.content;
                }
            } else msg.content;

            setScheduleToolContext(runtime.tools, "email", em_ptr.config.account_id, msg.sender);
            defer setScheduleToolContext(runtime.tools, null, null, null);

            const reply = runtime.session_mgr.processMessage(session_key, content_for_llm, null) catch |err| {
                log.err("Email agent error: {}", .{err});
                const err_msg: []const u8 = switch (err) {
                    error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "Network error. Please try again.",
                    error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
                    error.NoResponseContent => "Model returned an empty response. Please try again.",
                    error.AllProvidersFailed => "All configured providers failed for this request.",
                    error.OutOfMemory => "Out of memory.",
                    else => "An error occurred. Try again.",
                };
                if (msg.reply_target) |target| {
                    const recipient = splitEmailTarget(target);
                    em_ptr.sendReply(recipient.addr, recipient.subject, err_msg) catch |send_err| log.err("failed to send email error reply: {}", .{send_err});
                }
                continue;
            };
            defer allocator.free(reply);

            // PII de-redaction (post-LLM)
            var deredacted_reply: ?[]u8 = null;
            defer if (deredacted_reply) |dr| allocator.free(dr);

            const final_reply = if (pii_enabled) blk: {
                deredacted_reply = deredactPii(allocator, config.workspace_dir, reply, msg.id);
                if (deredacted_reply) |dr| {
                    break :blk dr;
                } else {
                    log.warn("PII de-redaction failed, using redacted reply", .{});
                    break :blk reply;
                }
            } else reply;

            if (shouldSuppressEmailReply(final_reply)) {
                log.info("Email reply suppressed by [NO_REPLY] marker for {s}", .{msg.sender});
                continue;
            }

            if (msg.reply_target) |target| {
                const recipient = splitEmailTarget(target);
                em_ptr.sendReply(recipient.addr, recipient.subject, final_reply) catch |err| {
                    log.warn("Email send error: {}", .{err});
                };
            }
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("email");

        // Sleep for poll interval
        const sleep_ns = @as(u64, em_ptr.config.poll_interval_secs) * std.time.ns_per_s;
        std.Thread.sleep(sleep_ns);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// runMatrixLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for Matrix /sync polling.
/// Uses account-aware route resolution and per-room reply targets.
pub fn runMatrixLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *MatrixLoopState,
    mx_ptr: *matrix.MatrixChannel,
) void {
    loop_state.last_activity.store(std.time.timestamp(), .release);

    var evict_counter: u32 = 0;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        const messages = mx_ptr.pollMessages(allocator) catch |err| {
            log.warn("Matrix poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            const schedule_chat_id = msg.reply_target orelse msg.sender;
            setScheduleToolContext(
                runtime.tools,
                "matrix",
                mx_ptr.account_id,
                schedule_chat_id,
                if (msg.is_group) .group else .direct,
                if (msg.is_group) matrixRoomPeerId(msg.reply_target) else msg.sender,
                null,
            );
            defer setScheduleToolContext(runtime.tools, null, null, null, null, null, null);

            var key_buf: [192]u8 = undefined;
            const room_peer_id = matrixRoomPeerId(msg.reply_target);
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);

            const session_key = blk: {
                const route = agent_routing.resolveRouteWithSession(allocator, .{
                    .channel = "matrix",
                    .account_id = mx_ptr.account_id,
                    .peer = .{
                        .kind = if (msg.is_group) .group else .direct,
                        .id = if (msg.is_group) room_peer_id else msg.sender,
                    },
                }, config.agent_bindings, config.agents, config.session) catch break :blk if (msg.is_group)
                    std.fmt.bufPrint(&key_buf, "matrix:{s}:room:{s}", .{ mx_ptr.account_id, room_peer_id }) catch msg.sender
                else
                    std.fmt.bufPrint(&key_buf, "matrix:{s}:{s}", .{ mx_ptr.account_id, msg.sender }) catch msg.sender;

                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            const typing_target = msg.reply_target orelse msg.sender;
            mx_ptr.startTyping(typing_target) catch {};
            defer mx_ptr.stopTyping(typing_target) catch {};

            const conversation_context = buildConversationContext(.{
                .channel = "matrix",
                .account_id = mx_ptr.account_id,
                .delivery_chat_id = typing_target,
                .peer_id = if (msg.is_group) room_peer_id else msg.sender,
                .is_group = msg.is_group,
                .group_id = if (msg.is_group) room_peer_id else null,
            });

            const reply = runtime.session_mgr.processMessage(session_key, msg.content, conversation_context) catch |err| {
                logAgentProcessingError(allocator, "Matrix agent error", err);
                const owned_err_msg = detailedProviderErrorForDisplay(allocator, err) catch null;
                defer if (owned_err_msg) |owned_msg| allocator.free(owned_msg);
                const err_msg = owned_err_msg orelse compactAgentErrorMessage(err);
                mx_ptr.sendMessage(typing_target, err_msg) catch |send_err| log.err("failed to send matrix error reply: {}", .{send_err});
                continue;
            };
            defer allocator.free(reply);

            mx_ptr.sendMessage(typing_target, reply) catch |err| {
                log.warn("Matrix send error: {}", .{err});
            };
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("matrix");
    }
}

pub fn spawnMaxPolling(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    channel: channels_mod.Channel,
) !PollingSpawnResult {
    const mx_ls = try allocator.create(MaxLoopState);
    errdefer allocator.destroy(mx_ls);
    mx_ls.* = MaxLoopState.init();

    const mx_ptr: *max_mod.MaxChannel = @ptrCast(@alignCast(channel.ptr));
    const thread = try std.Thread.spawn(
        .{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE },
        runMaxLoop,
        .{ allocator, config, runtime, mx_ls, mx_ptr },
    );
    mx_ls.thread = thread;

    return .{
        .thread = thread,
        .state = .{ .max = mx_ls },
    };
}

// ════════════════════════════════════════════════════════════════════════════
// runMaxLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for Max Bot API long-polling.
/// Uses account-aware route resolution and per-chat reply targets.
pub fn runMaxLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *MaxLoopState,
    mx_ptr: *max_mod.MaxChannel,
) void {
    // 1. Fetch bot identity
    mx_ptr.channel().start() catch |err| {
        log.err("Max channel start failed: {}", .{err});
        return;
    };
    defer mx_ptr.channel().stop();

    loop_state.last_activity.store(std.time.timestamp(), .release);

    var evict_counter: u32 = 0;
    var backoff_ns: u64 = std.time.ns_per_s;
    const max_backoff_ns: u64 = 30 * std.time.ns_per_s;

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        const messages = mx_ptr.pollUpdates(allocator) catch |err| {
            log.warn("Max poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(backoff_ns);
            backoff_ns = @min(backoff_ns * 2, max_backoff_ns);
            continue;
        };

        // Reset backoff on success
        backoff_ns = std.time.ns_per_s;
        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            const reply_target = msg.reply_target orelse msg.sender;
            setScheduleToolContext(
                runtime.tools,
                "max",
                mx_ptr.account_id,
                reply_target,
                if (msg.is_group) .group else .direct,
                if (msg.is_group) reply_target else msg.sender,
                null,
            );
            defer setScheduleToolContext(runtime.tools, null, null, null, null, null, null);
            max_mod.setInteractiveOwnerContext(msg.sender);
            defer max_mod.setInteractiveOwnerContext(null);

            var key_buf: [192]u8 = undefined;
            var routed_session_key: ?[]const u8 = null;
            defer if (routed_session_key) |key| allocator.free(key);

            const session_key = blk: {
                const peer_id = if (msg.is_group) reply_target else msg.sender;
                const route = agent_routing.resolveRouteWithSession(allocator, .{
                    .channel = "max",
                    .account_id = mx_ptr.account_id,
                    .peer = .{
                        .kind = if (msg.is_group) .group else .direct,
                        .id = peer_id,
                    },
                }, config.agent_bindings, config.agents, config.session) catch break :blk if (msg.is_group)
                    std.fmt.bufPrint(&key_buf, "max:{s}:chat:{s}", .{ mx_ptr.account_id, peer_id }) catch msg.sender
                else
                    std.fmt.bufPrint(&key_buf, "max:{s}:{s}", .{ mx_ptr.account_id, msg.sender }) catch msg.sender;

                allocator.free(route.main_session_key);
                routed_session_key = route.session_key;
                break :blk route.session_key;
            };

            mx_ptr.startTyping(reply_target) catch {};
            defer mx_ptr.stopTyping(reply_target) catch {};

            const conversation_context = buildConversationContext(.{
                .channel = "max",
                .account_id = mx_ptr.account_id,
                .delivery_chat_id = reply_target,
                .peer_id = if (msg.is_group) reply_target else msg.sender,
                .is_group = msg.is_group,
                .group_id = if (msg.is_group) reply_target else null,
            });

            var stream_ctx = max_mod.MaxChannel.StreamCtx{
                .max_ptr = mx_ptr,
                .chat_id = reply_target,
            };
            const sink = mx_ptr.makeSink(&stream_ctx);

            const reply = runtime.session_mgr.processMessageStreaming(session_key, msg.content, conversation_context, sink) catch |err| {
                logAgentProcessingError(allocator, "Max agent error", err);
                const owned_err_msg = detailedProviderErrorForDisplay(allocator, err) catch null;
                defer if (owned_err_msg) |owned_msg| allocator.free(owned_msg);
                const err_msg = owned_err_msg orelse compactAgentErrorMessage(err);
                mx_ptr.sendMessage(reply_target, err_msg) catch |send_err| log.err("failed to send max error reply: {}", .{send_err});
                continue;
            };
            defer allocator.free(reply);

            if (shouldSuppressGroupReply(msg.is_group, reply)) {
                log.info("Smart reply: skipping non-essential message", .{});
                continue;
            }

            mx_ptr.sendMessage(reply_target, reply) catch |err| {
                log.warn("Max send error: {}", .{err});
            };
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("max");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "TelegramLoopState init defaults" {
    const state = TelegramLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "TelegramLoopState stop_requested toggle" {
    var state = TelegramLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "TelegramLoopState last_activity update" {
    var state = TelegramLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "shouldSuppressGroupReply suppresses only group replies with marker" {
    try std.testing.expect(shouldSuppressGroupReply(true, "ok [NO_REPLY]"));
    try std.testing.expect(!shouldSuppressGroupReply(false, "ok [NO_REPLY]"));
    try std.testing.expect(!shouldSuppressGroupReply(true, "regular reply"));
}

test "shouldSuppressEmailReply requires NO_REPLY prefix after optional whitespace" {
    // Regression: email poll fallback must honor the same [NO_REPLY] contract as IDLE mode.
    try std.testing.expect(shouldSuppressEmailReply("[NO_REPLY] skip"));
    try std.testing.expect(shouldSuppressEmailReply(" \n\t[NO_REPLY] skip"));
    try std.testing.expect(!shouldSuppressEmailReply("ok [NO_REPLY]"));
}

test "resolvePiiRedactorPath uses workspace scripts directory" {
    // Regression: email PII redaction must not hardcode /home/nullclaw on macOS/Windows.
    const allocator = std.testing.allocator;
    const path = resolvePiiRedactorPath(allocator, "/tmp/nullclaw-workspace") orelse return error.TestUnexpectedResult;
    defer allocator.free(path);

    const expected = try std.fs.path.join(allocator, &.{ "/tmp/nullclaw-workspace", "scripts", "pii_redactor.py" });
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, path);
}

test "isStopLikeCommand matches stop and abort variants" {
    try std.testing.expect(control_plane.isStopLikeCommand("/stop"));
    try std.testing.expect(control_plane.isStopLikeCommand("  /stop  "));
    try std.testing.expect(control_plane.isStopLikeCommand("/abort"));
    try std.testing.expect(control_plane.isStopLikeCommand("/STOP"));
    try std.testing.expect(control_plane.isStopLikeCommand("/abort@nullclaw_bot"));
    try std.testing.expect(control_plane.isStopLikeCommand("/stop: now"));
    try std.testing.expect(control_plane.isStopLikeCommand("/abort please"));
}

test "isStopLikeCommand rejects non-control commands" {
    try std.testing.expect(!control_plane.isStopLikeCommand("stop"));
    try std.testing.expect(!control_plane.isStopLikeCommand("/stopping"));
    try std.testing.expect(!control_plane.isStopLikeCommand("/aborted"));
    try std.testing.expect(!control_plane.isStopLikeCommand("/help"));
    try std.testing.expect(!control_plane.isStopLikeCommand(""));
}

test "ProviderHolder tagged union fields" {
    // Compile-time check that ProviderHolder has expected variants
    try std.testing.expect(@hasField(ProviderHolder, "openrouter"));
    try std.testing.expect(@hasField(ProviderHolder, "anthropic"));
    try std.testing.expect(@hasField(ProviderHolder, "openai"));
    try std.testing.expect(@hasField(ProviderHolder, "gemini"));
    try std.testing.expect(@hasField(ProviderHolder, "ollama"));
    try std.testing.expect(@hasField(ProviderHolder, "compatible"));
    try std.testing.expect(@hasField(ProviderHolder, "openai_codex"));
}

test "channel runtime wires security policy into session manager and shell tool" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);
    const config_path = try std.fs.path.join(allocator, &.{ workspace, "config.json" });
    defer allocator.free(config_path);

    var allowed_paths = [_][]const u8{workspace};
    const cfg = Config{
        .workspace_dir = workspace,
        .config_path = config_path,
        .allocator = allocator,
        .autonomy = .{
            .allowed_paths = &allowed_paths,
        },
    };

    var runtime = try ChannelRuntime.init(allocator, &cfg);
    defer runtime.deinit();

    try std.testing.expect(runtime.session_mgr.policy != null);
    try std.testing.expect(runtime.session_mgr.policy.? == runtime.security_policy);

    var found_shell = false;
    for (runtime.tools) |tool| {
        if (!std.mem.eql(u8, tool.name(), "shell")) continue;
        found_shell = true;

        const shell_tool: *tools_mod.shell.ShellTool = @ptrCast(@alignCast(tool.ptr));
        try std.testing.expect(shell_tool.policy != null);
        try std.testing.expect(shell_tool.policy.? == runtime.security_policy);
        try std.testing.expectEqual(@as(usize, 1), shell_tool.allowed_paths.len);
        try std.testing.expectEqualStrings(workspace, shell_tool.allowed_paths[0]);
        break;
    }
    try std.testing.expect(found_shell);
}

test "SignalLoopState init defaults" {
    const state = SignalLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "SignalLoopState stop_requested toggle" {
    var state = SignalLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "SignalLoopState last_activity update" {
    var state = SignalLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "MatrixLoopState init defaults" {
    const state = MatrixLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "MatrixLoopState stop_requested toggle" {
    var state = MatrixLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "MatrixLoopState last_activity update" {
    var state = MatrixLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "EmailLoopState init defaults" {
    const state = EmailLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "EmailLoopState stop_requested toggle" {
    var state = EmailLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "EmailLoopState last_activity update" {
    var state = EmailLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "MaxLoopState init defaults" {
    const state = MaxLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "MaxLoopState stop_requested toggle" {
    var state = MaxLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "MaxLoopState last_activity update" {
    var state = MaxLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "signalGroupPeerId extracts group id from reply target" {
    const peer_id = signalGroupPeerId("group:1203630@g.us");
    try std.testing.expectEqualStrings("1203630@g.us", peer_id);
}

test "signalGroupPeerId falls back when reply target is missing or malformed" {
    try std.testing.expectEqualStrings("unknown", signalGroupPeerId(null));
    try std.testing.expectEqualStrings("group:", signalGroupPeerId("group:"));
    try std.testing.expectEqualStrings("direct:+15550001111", signalGroupPeerId("direct:+15550001111"));
}

test "matrixRoomPeerId falls back when reply target is missing" {
    try std.testing.expectEqualStrings("unknown", matrixRoomPeerId(null));
    try std.testing.expectEqualStrings("!room:example", matrixRoomPeerId("!room:example"));
}

test "parseTelegramSessionTargetFromKey handles encoded telegram topic peers" {
    const parsed = parseTelegramSessionTargetFromKey("agent:main:telegram:group:-100123#topic:77") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("-100123", parsed.base_chat_id);
    try std.testing.expectEqual(@as(?i64, 77), parsed.thread_id);
}

test "parseTelegramSessionTargetFromKey handles thread suffix session keys" {
    const parsed = parseTelegramSessionTargetFromKey("agent:main:telegram:group:-100123:thread:77") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("-100123", parsed.base_chat_id);
    try std.testing.expectEqual(@as(?i64, 77), parsed.thread_id);
}

test "parseTelegramSessionTargetFromKey handles legacy telegram fallback keys" {
    const parsed = parseTelegramSessionTargetFromKey("telegram:main:-100123#topic:77") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("-100123", parsed.base_chat_id);
    try std.testing.expectEqual(@as(?i64, 77), parsed.thread_id);
}

test "parseTelegramSessionTargetFromKey handles canonical telegram fallback thread keys" {
    const parsed = parseTelegramSessionTargetFromKey("telegram:main:-100123:thread:77") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("-100123", parsed.base_chat_id);
    try std.testing.expectEqual(@as(?i64, 77), parsed.thread_id);
}

test "resolveTelegramBaseRouteKey matches topic-specific telegram binding before group fallback" {
    const allocator = std.testing.allocator;
    const agents = [_]config_types.NamedAgentConfig{
        .{ .name = "default", .provider = "openai", .model = "gpt-4" },
        .{ .name = "group-agent", .provider = "openai", .model = "gpt-4" },
        .{ .name = "topic-agent", .provider = "openai", .model = "gpt-4" },
    };
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "group-agent",
            .match = .{
                .channel = "telegram",
                .account_id = "main",
                .peer = .{ .kind = .group, .id = "-100123" },
            },
        },
        .{
            .agent_id = "topic-agent",
            .match = .{
                .channel = "telegram",
                .account_id = "main",
                .peer = .{ .kind = .group, .id = "-100123:thread:77" },
            },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agents = &agents,
        .agent_bindings = &bindings,
    };

    const key = try resolveTelegramBaseRouteKey(allocator, &cfg, "main", "-100123", 77, true);
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:topic-agent:telegram:group:-100123", key);
}

test "resolveTelegramBaseRouteKey falls back to base telegram group binding for unmatched topic" {
    const allocator = std.testing.allocator;
    const agents = [_]config_types.NamedAgentConfig{
        .{ .name = "default", .provider = "openai", .model = "gpt-4" },
        .{ .name = "group-agent", .provider = "openai", .model = "gpt-4" },
    };
    const bindings = [_]agent_routing.AgentBinding{.{
        .agent_id = "group-agent",
        .match = .{
            .channel = "telegram",
            .account_id = "main",
            .peer = .{ .kind = .group, .id = "-100123" },
        },
    }};
    const cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agents = &agents,
        .agent_bindings = &bindings,
    };

    const key = try resolveTelegramBaseRouteKey(allocator, &cfg, "main", "-100123", 77, true);
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:group-agent:telegram:group:-100123", key);
}

test "resolveTelegramBaseRouteKey auto-provisions direct telegram peers" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .session = .{
            .auto_provision_direct_agents = true,
        },
    };

    const key = try resolveTelegramBaseRouteKey(allocator, &cfg, "main", "123456", null, false);
    defer allocator.free(key);

    try std.testing.expect(std.mem.startsWith(u8, key, "agent:peer-"));
    try std.testing.expect(std.mem.endsWith(u8, key, ":telegram:direct:123456"));
}

test "buildTelegramBindingStatusReply distinguishes exact and inherited peer bindings" {
    const allocator = std.testing.allocator;
    const agents = [_]config_types.NamedAgentConfig{
        .{ .name = "default", .provider = "openai", .model = "gpt-4" },
        .{ .name = "reviewer", .provider = "openai", .model = "gpt-4" },
        .{ .name = "coder", .provider = "openai", .model = "gpt-4" },
    };
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "reviewer",
            .match = .{
                .channel = "telegram",
                .peer = .{ .kind = .group, .id = "-100123:thread:77" },
            },
        },
        .{
            .agent_id = "coder",
            .match = .{
                .channel = "telegram",
                .account_id = "main",
                .peer = .{ .kind = .group, .id = "-100123:thread:77" },
            },
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agents = &agents,
        .agent_bindings = &bindings,
    };

    const reply = try buildTelegramBindingStatusReply(allocator, &cfg, "main", "-100123#topic:77", true);
    defer allocator.free(reply);

    try std.testing.expect(std.mem.indexOf(u8, reply, "Effective agent: coder") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "Exact binding: coder") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "Inherited peer binding: reviewer") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "Matched by: peer") != null);
}

test "buildTelegramBindingStatusReply shows synthetic peer agent for auto-provisioned dm" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .session = .{
            .auto_provision_direct_agents = true,
        },
    };

    const reply = try buildTelegramBindingStatusReply(allocator, &cfg, "main", "123456", false);
    defer allocator.free(reply);

    try std.testing.expect(std.mem.indexOf(u8, reply, "Effective agent: peer-") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "Matched by: default") != null);
}

test "telegram update offset store roundtrip" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };

    try saveTelegramUpdateOffset(allocator, &cfg, "main", "12345:test-token", 777);
    const restored = loadTelegramUpdateOffset(allocator, &cfg, "main", "12345:test-token");
    try std.testing.expectEqual(@as(?i64, 777), restored);
}

test "telegram update offset path resolves relative config path" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const relative_base = try std.fs.path.relative(allocator, cwd, base);
    defer allocator.free(relative_base);
    const config_path = try std.fs.path.join(allocator, &.{ relative_base, "config.json" });
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };

    const resolved = try telegramUpdateOffsetPath(allocator, &cfg, "default");
    defer allocator.free(resolved);
    const expected = try std.fs.path.join(allocator, &.{ base, "state", "telegram", "update-offset-default.json" });
    defer allocator.free(expected);

    try std.testing.expect(std.fs.path.isAbsolute(resolved));
    try std.testing.expectEqualStrings(expected, resolved);
}

test "detailedProviderErrorForDisplay surfaces sanitized provider detail" {
    const allocator = std.testing.allocator;
    providers.clearLastApiErrorDetail();
    defer providers.clearLastApiErrorDetail();

    providers.setLastApiErrorDetail("compatible", "status=429 message=Rate limit exceeded");
    const msg = (try detailedProviderErrorForDisplay(allocator, error.ApiError)).?;
    defer allocator.free(msg);

    try std.testing.expectEqualStrings("Provider API error: compatible: status=429 message=Rate limit exceeded", msg);
}

test "detailedProviderErrorForDisplay ignores non-provider errors" {
    const allocator = std.testing.allocator;
    providers.clearLastApiErrorDetail();
    defer providers.clearLastApiErrorDetail();

    providers.setLastApiErrorDetail("compatible", "status=429 message=Rate limit exceeded");
    try std.testing.expect((try detailedProviderErrorForDisplay(allocator, error.OutOfMemory)) == null);
}

test "compactAgentErrorMessage keeps non-telegram fallback concise" {
    // Regression: Signal/Matrix/Max should not inherit Telegram's `/new` guidance for generic failures.
    try std.testing.expectEqualStrings("An error occurred. Try again.", compactAgentErrorMessage(error.Unexpected));
}

test "telegram update offset store returns null for mismatched bot id" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };

    try saveTelegramUpdateOffset(allocator, &cfg, "main", "11111:test-token-a", 123);
    const restored = loadTelegramUpdateOffset(allocator, &cfg, "main", "22222:test-token-b");
    try std.testing.expect(restored == null);
}

test "telegram update offset store treats legacy payload without bot_id as stale" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };

    const offset_path = try telegramUpdateOffsetPath(allocator, &cfg, "default");
    defer allocator.free(offset_path);
    const offset_dir = std.fs.path.dirname(offset_path).?;
    std.fs.makeDirAbsolute(offset_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => try fs_compat.makePath(offset_dir),
    };
    const file = try std.fs.createFileAbsolute(offset_path, .{});
    defer file.close();
    try file.writeAll(
        \\{
        \\  "version": 1,
        \\  "last_update_id": 456
        \\}
        \\
    );

    const restored = loadTelegramUpdateOffset(allocator, &cfg, "default", "33333:test-token-c");
    try std.testing.expect(restored == null);
}

test "telegram offset persistence helper retries after write failure" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    const cfg = Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = allocator,
    };

    const blocked_state_path = try std.fs.path.join(allocator, &.{ base, "state" });
    defer allocator.free(blocked_state_path);

    {
        const blocked_state_file = try std.fs.createFileAbsolute(blocked_state_path, .{});
        blocked_state_file.close();
    }

    var persisted_update_id: i64 = 100;
    persistTelegramUpdateOffsetIfAdvanced(
        allocator,
        &cfg,
        "main",
        "12345:test-token",
        &persisted_update_id,
        101,
    );
    try std.testing.expectEqual(@as(i64, 100), persisted_update_id);
    try std.testing.expect(loadTelegramUpdateOffset(allocator, &cfg, "main", "12345:test-token") == null);

    try std.fs.deleteFileAbsolute(blocked_state_path);

    persistTelegramUpdateOffsetIfAdvanced(
        allocator,
        &cfg,
        "main",
        "12345:test-token",
        &persisted_update_id,
        101,
    );
    try std.testing.expectEqual(@as(i64, 101), persisted_update_id);
    const restored = loadTelegramUpdateOffset(allocator, &cfg, "main", "12345:test-token");
    try std.testing.expectEqual(@as(?i64, 101), restored);
}
