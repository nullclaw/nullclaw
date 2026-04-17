const std = @import("std");
const std_compat = @import("compat");
const Config = @import("config.zig").Config;
const config_paths = @import("config_paths.zig");
const config_types = @import("config_types.zig");
const agent_routing = @import("agent_routing.zig");

pub const Error = error{
    InvalidConfigPath,
    UnknownAgent,
};

pub const BindingTarget = struct {
    channel: []const u8,
    account_id: ?[]const u8 = null,
    peer: agent_routing.PeerRef,
    comment: ?[]const u8 = null,
};

pub const BindingLookupScope = enum {
    exact_account,
    unscoped_account,
};

pub const BindingLookup = struct {
    index: usize,
    scope: BindingLookupScope,
    binding: agent_routing.AgentBinding,
};

pub const BindingUpdateStatus = enum {
    added,
    updated,
    removed,
    unchanged,
};

pub const BindingUpdateResult = struct {
    status: BindingUpdateStatus,
};

fn dupOptionalString(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |s| return try allocator.dupe(u8, s);
    return null;
}

fn dupStringSlice(allocator: std.mem.Allocator, src: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, src.len);
    errdefer allocator.free(out);

    var i: usize = 0;
    errdefer {
        while (i > 0) {
            i -= 1;
            allocator.free(out[i]);
        }
    }

    while (i < src.len) : (i += 1) {
        out[i] = try allocator.dupe(u8, src[i]);
    }

    return out;
}

fn freeStringSlice(allocator: std.mem.Allocator, src: []const []const u8) void {
    if (src.len == 0) return;
    for (src) |item| allocator.free(item);
    allocator.free(src);
}

pub fn freeBinding(allocator: std.mem.Allocator, binding: *const agent_routing.AgentBinding) void {
    allocator.free(binding.agent_id);
    if (binding.comment) |comment| allocator.free(comment);
    if (binding.match.channel) |channel| allocator.free(channel);
    if (binding.match.account_id) |account_id| allocator.free(account_id);
    if (binding.match.guild_id) |guild_id| allocator.free(guild_id);
    if (binding.match.team_id) |team_id| allocator.free(team_id);
    if (binding.match.peer) |peer| allocator.free(peer.id);
    freeStringSlice(allocator, binding.match.roles);
}

pub fn freeBindingSlice(allocator: std.mem.Allocator, bindings: []const agent_routing.AgentBinding) void {
    if (bindings.len == 0) return;
    for (bindings) |binding| freeBinding(allocator, &binding);
    allocator.free(bindings);
}

fn freeBindingList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(agent_routing.AgentBinding),
) void {
    for (list.items) |binding| freeBinding(allocator, &binding);
    list.deinit(allocator);
}

fn dupBinding(allocator: std.mem.Allocator, binding: agent_routing.AgentBinding) !agent_routing.AgentBinding {
    var copied = agent_routing.AgentBinding{
        .agent_id = try allocator.dupe(u8, binding.agent_id),
        .comment = try dupOptionalString(allocator, binding.comment),
        .match = .{
            .channel = try dupOptionalString(allocator, binding.match.channel),
            .account_id = try dupOptionalString(allocator, binding.match.account_id),
            .guild_id = try dupOptionalString(allocator, binding.match.guild_id),
            .team_id = try dupOptionalString(allocator, binding.match.team_id),
            .roles = try dupStringSlice(allocator, binding.match.roles),
        },
    };
    errdefer freeBinding(allocator, &copied);

    if (binding.match.peer) |peer| {
        copied.match.peer = .{
            .kind = peer.kind,
            .id = try allocator.dupe(u8, peer.id),
        };
    }

    return copied;
}

fn buildManagedBinding(
    allocator: std.mem.Allocator,
    target: BindingTarget,
    agent_id: []const u8,
) !agent_routing.AgentBinding {
    var binding = agent_routing.AgentBinding{
        .agent_id = try allocator.dupe(u8, agent_id),
        .comment = try dupOptionalString(allocator, target.comment),
        .match = .{
            .channel = try allocator.dupe(u8, target.channel),
            .account_id = try dupOptionalString(allocator, target.account_id),
            .peer = .{
                .kind = target.peer.kind,
                .id = try allocator.dupe(u8, target.peer.id),
            },
            .roles = &.{},
        },
    };
    errdefer freeBinding(allocator, &binding);
    return binding;
}

fn bindingHasOnlyPeerScope(binding: agent_routing.AgentBinding) bool {
    return binding.match.peer != null and
        binding.match.guild_id == null and
        binding.match.team_id == null and
        binding.match.roles.len == 0;
}

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |left| {
        if (b) |right| return std.mem.eql(u8, left, right);
        return false;
    }
    return b == null;
}

fn bindingMatchesTarget(binding: agent_routing.AgentBinding, target: BindingTarget, scope: BindingLookupScope) bool {
    if (!bindingHasOnlyPeerScope(binding)) return false;
    if (!optionalEql(binding.match.channel, target.channel)) return false;
    if (!agent_routing.peerMatches(binding.match.peer, target.peer)) return false;

    return switch (scope) {
        .exact_account => optionalEql(binding.match.account_id, target.account_id),
        .unscoped_account => binding.match.account_id == null,
    };
}

pub fn findExactPeerBinding(
    bindings: []const agent_routing.AgentBinding,
    target: BindingTarget,
) ?BindingLookup {
    for (bindings, 0..) |binding, idx| {
        if (bindingMatchesTarget(binding, target, .exact_account)) {
            return .{
                .index = idx,
                .scope = .exact_account,
                .binding = binding,
            };
        }
    }

    return null;
}

pub fn findInheritedPeerBinding(
    bindings: []const agent_routing.AgentBinding,
    target: BindingTarget,
) ?BindingLookup {
    if (target.account_id != null) {
        for (bindings, 0..) |binding, idx| {
            if (bindingMatchesTarget(binding, target, .unscoped_account)) {
                return .{
                    .index = idx,
                    .scope = .unscoped_account,
                    .binding = binding,
                };
            }
        }
    }

    return null;
}

fn replaceOwnedBindings(
    allocator: std.mem.Allocator,
    cfg: *Config,
    next_bindings: []const agent_routing.AgentBinding,
) void {
    const previous_bindings = cfg.agent_bindings;
    const previous_owned = cfg.agent_bindings_runtime_owned;
    cfg.agent_bindings = next_bindings;
    cfg.agent_bindings_runtime_owned = true;
    if (previous_owned) freeBindingSlice(allocator, previous_bindings);
}

pub fn releaseRuntimeOwnedBindings(
    allocator: std.mem.Allocator,
    cfg: *Config,
) void {
    if (!cfg.agent_bindings_runtime_owned) return;
    const owned = cfg.agent_bindings;
    cfg.agent_bindings = &.{};
    cfg.agent_bindings_runtime_owned = false;
    freeBindingSlice(allocator, owned);
}

pub fn findNamedAgent(
    agents: []const config_types.NamedAgentConfig,
    requested: []const u8,
) ?config_types.NamedAgentConfig {
    const trimmed = std.mem.trim(u8, requested, " \t\r\n");
    if (trimmed.len == 0) return null;

    for (agents) |agent| {
        if (std.ascii.eqlIgnoreCase(agent.name, trimmed)) return agent;
    }

    var req_buf: [64]u8 = undefined;
    const normalized_requested = agent_routing.normalizeId(&req_buf, trimmed);
    for (agents) |agent| {
        var agent_buf: [64]u8 = undefined;
        const normalized_agent = agent_routing.normalizeId(&agent_buf, agent.name);
        if (std.mem.eql(u8, normalized_requested, normalized_agent)) return agent;
    }

    return null;
}

pub fn agentDisplayNameForId(
    agents: []const config_types.NamedAgentConfig,
    agent_id: []const u8,
) ?[]const u8 {
    for (agents) |agent| {
        var agent_buf: [64]u8 = undefined;
        const normalized_agent = agent_routing.normalizeId(&agent_buf, agent.name);
        if (std.mem.eql(u8, normalized_agent, agent_id)) return agent.name;
    }
    return null;
}

pub fn applyBindingUpdate(
    allocator: std.mem.Allocator,
    cfg: *Config,
    target: BindingTarget,
    requested_agent: ?[]const u8,
) !BindingUpdateResult {
    const existing = findExactPeerBinding(cfg.agent_bindings, target);

    if (requested_agent) |raw_agent| {
        const profile = findNamedAgent(cfg.agents, raw_agent) orelse return error.UnknownAgent;
        var agent_buf: [64]u8 = undefined;
        const normalized_agent_id = agent_routing.normalizeId(&agent_buf, profile.name);

        if (existing) |current| {
            if (std.mem.eql(u8, current.binding.agent_id, normalized_agent_id) and
                current.scope == .exact_account and
                optionalEql(current.binding.comment, target.comment))
            {
                return .{ .status = .unchanged };
            }
        }

        var desired = try buildManagedBinding(allocator, target, normalized_agent_id);
        var desired_owned = true;
        errdefer if (desired_owned) freeBinding(allocator, &desired);

        var next: std.ArrayListUnmanaged(agent_routing.AgentBinding) = .empty;
        errdefer freeBindingList(allocator, &next);
        try next.ensureTotalCapacity(allocator, if (existing == null) cfg.agent_bindings.len + 1 else cfg.agent_bindings.len);

        for (cfg.agent_bindings, 0..) |binding, idx| {
            if (existing != null and idx == existing.?.index) {
                try next.append(allocator, desired);
                desired_owned = false;
                continue;
            }
            try next.append(allocator, try dupBinding(allocator, binding));
        }
        if (existing == null) {
            try next.append(allocator, desired);
            desired_owned = false;
        }

        replaceOwnedBindings(allocator, cfg, try next.toOwnedSlice(allocator));
        return .{ .status = if (existing == null) .added else .updated };
    }

    const current = existing orelse return .{ .status = .unchanged };

    var next: std.ArrayListUnmanaged(agent_routing.AgentBinding) = .empty;
    errdefer freeBindingList(allocator, &next);
    try next.ensureTotalCapacity(allocator, cfg.agent_bindings.len - 1);

    for (cfg.agent_bindings, 0..) |binding, idx| {
        if (idx == current.index) continue;
        try next.append(allocator, try dupBinding(allocator, binding));
    }

    replaceOwnedBindings(allocator, cfg, try next.toOwnedSlice(allocator));
    return .{ .status = .removed };
}

fn loadConfigFromPath(allocator: std.mem.Allocator, config_path: []const u8) !Config {
    const config_dir = std_compat.fs.path.dirname(config_path) orelse return error.InvalidConfigPath;
    const workspace_dir = try config_paths.defaultWorkspaceDirFromConfigDir(allocator, config_dir);

    var cfg = Config{
        .workspace_dir = workspace_dir,
        .config_path = config_path,
        .allocator = allocator,
    };

    const file = try std_compat.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 2 * 1024 * 1024);
    try cfg.parseJson(content);
    cfg.syncFlatFields();
    try cfg.validate();
    return cfg;
}

pub fn persistBindingUpdate(
    allocator: std.mem.Allocator,
    config_path: []const u8,
    target: BindingTarget,
    requested_agent: ?[]const u8,
) !BindingUpdateResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = try loadConfigFromPath(arena, config_path);
    const result = try applyBindingUpdate(arena, &cfg, target, requested_agent);
    if (result.status != .unchanged) {
        try cfg.save();
    }
    return result;
}

test "findNamedAgent accepts normalized id alias" {
    const agents = [_]config_types.NamedAgentConfig{
        .{ .name = "Coder Agent", .provider = "ollama", .model = "qwen2.5-coder:14b" },
        .{ .name = "Reviewer", .provider = "openrouter", .model = "anthropic/claude-sonnet-4" },
    };

    const found = findNamedAgent(&agents, "coder-agent") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("Coder Agent", found.name);
}

test "applyBindingUpdate adds account-scoped peer binding" {
    var cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = std.testing.allocator,
        .agents = &.{
            .{ .name = "Coder Agent", .provider = "ollama", .model = "qwen2.5-coder:14b" },
        },
    };

    const result = try applyBindingUpdate(std.testing.allocator, &cfg, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
        .comment = "Managed by Telegram /bind",
    }, "Coder Agent");
    defer releaseRuntimeOwnedBindings(std.testing.allocator, &cfg);

    try std.testing.expect(result.status == .added);
    try std.testing.expectEqual(@as(usize, 1), cfg.agent_bindings.len);
    try std.testing.expectEqualStrings("coder-agent", cfg.agent_bindings[0].agent_id);
    try std.testing.expectEqualStrings("telegram", cfg.agent_bindings[0].match.channel.?);
    try std.testing.expectEqualStrings("main", cfg.agent_bindings[0].match.account_id.?);
    try std.testing.expect(cfg.agent_bindings[0].match.peer != null);
    try std.testing.expectEqualStrings("-100123:thread:42", cfg.agent_bindings[0].match.peer.?.id);
    try std.testing.expect(cfg.agent_bindings_runtime_owned);
}

test "applyBindingUpdate adds exact binding without replacing inherited peer fallback" {
    const allocator = std.testing.allocator;
    const existing = try allocator.alloc(agent_routing.AgentBinding, 1);
    errdefer allocator.free(existing);
    existing[0] = .{
        .agent_id = try allocator.dupe(u8, "reviewer"),
        .comment = null,
        .match = .{
            .channel = try allocator.dupe(u8, "telegram"),
            .account_id = null,
            .peer = .{ .kind = .group, .id = try allocator.dupe(u8, "-100123:thread:42") },
            .roles = &.{},
        },
    };

    var cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agents = &.{
            .{ .name = "Coder Agent", .provider = "ollama", .model = "qwen2.5-coder:14b" },
        },
        .agent_bindings = existing,
    };
    defer releaseRuntimeOwnedBindings(allocator, &cfg);
    defer {
        freeBinding(allocator, &existing[0]);
        allocator.free(existing);
    }

    const add_result = try applyBindingUpdate(allocator, &cfg, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
        .comment = "Managed by Telegram /bind",
    }, "Coder Agent");

    try std.testing.expect(add_result.status == .added);
    try std.testing.expectEqual(@as(usize, 2), cfg.agent_bindings.len);

    const exact = findExactPeerBinding(cfg.agent_bindings, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
    }) orelse return error.TestExpectedEqual;
    const inherited = findInheritedPeerBinding(cfg.agent_bindings, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
    }) orelse return error.TestExpectedEqual;

    try std.testing.expectEqualStrings("coder-agent", exact.binding.agent_id);
    try std.testing.expectEqualStrings("reviewer", inherited.binding.agent_id);
}

test "applyBindingUpdate clear removes exact binding only" {
    const allocator = std.testing.allocator;
    const existing = try allocator.alloc(agent_routing.AgentBinding, 1);
    errdefer allocator.free(existing);
    existing[0] = .{
        .agent_id = try allocator.dupe(u8, "coder-agent"),
        .comment = null,
        .match = .{
            .channel = try allocator.dupe(u8, "telegram"),
            .account_id = try allocator.dupe(u8, "main"),
            .peer = .{ .kind = .group, .id = try allocator.dupe(u8, "-100123:thread:42") },
            .roles = &.{},
        },
    };

    var cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agent_bindings = existing,
    };

    const result = try applyBindingUpdate(allocator, &cfg, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
    }, null);
    defer releaseRuntimeOwnedBindings(allocator, &cfg);
    defer {
        freeBinding(allocator, &existing[0]);
        allocator.free(existing);
    }

    try std.testing.expect(result.status == .removed);
    try std.testing.expectEqual(@as(usize, 0), cfg.agent_bindings.len);
}

test "applyBindingUpdate clear keeps inherited unscoped peer binding" {
    const allocator = std.testing.allocator;
    const existing = try allocator.alloc(agent_routing.AgentBinding, 1);
    errdefer allocator.free(existing);
    existing[0] = .{
        .agent_id = try allocator.dupe(u8, "coder-agent"),
        .comment = null,
        .match = .{
            .channel = try allocator.dupe(u8, "telegram"),
            .account_id = null,
            .peer = .{ .kind = .group, .id = try allocator.dupe(u8, "-100123:thread:42") },
            .roles = &.{},
        },
    };

    var cfg = Config{
        .workspace_dir = "/tmp/nullclaw",
        .config_path = "/tmp/nullclaw/config.json",
        .allocator = allocator,
        .agent_bindings = existing,
    };
    defer {
        freeBinding(allocator, &existing[0]);
        allocator.free(existing);
    }

    const result = try applyBindingUpdate(allocator, &cfg, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
    }, null);

    try std.testing.expect(result.status == .unchanged);
    try std.testing.expectEqual(@as(usize, 1), cfg.agent_bindings.len);
    try std.testing.expectEqualStrings("coder-agent", cfg.agent_bindings[0].agent_id);
    try std.testing.expect(!cfg.agent_bindings_runtime_owned);
}

test "persistBindingUpdate skips rewriting config when binding is unchanged" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{base});
    defer allocator.free(config_path);

    const initial_content =
        \\{
        \\  "agents": {
        \\    "defaults": {
        \\      "model": {
        \\        "primary": "ollama/qwen2.5-coder:14b"
        \\      }
        \\    },
        \\    "list": [
        \\      {
        \\        "id": "Coder Agent",
        \\        "provider": "ollama",
        \\        "model": "qwen2.5-coder:14b"
        \\      }
        \\    ]
        \\  },
        \\  "bindings": [
        \\    {
        \\      "agent_id": "coder-agent",
        \\      "comment": "Managed by Telegram /bind",
        \\      "match": {
        \\        "channel": "telegram",
        \\        "account_id": "main",
        \\        "peer": {
        \\          "kind": "group",
        \\          "id": "-100123:thread:42"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    {
        const file = try std_compat.fs.createFileAbsolute(config_path, .{});
        defer file.close();
        try file.writeAll(initial_content);
    }

    const result = try persistBindingUpdate(allocator, config_path, .{
        .channel = "telegram",
        .account_id = "main",
        .peer = .{ .kind = .group, .id = "-100123:thread:42" },
        .comment = "Managed by Telegram /bind",
    }, "Coder Agent");

    try std.testing.expect(result.status == .unchanged);

    const file = try std_compat.fs.openFileAbsolute(config_path, .{});
    defer file.close();
    const persisted = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(persisted);

    try std.testing.expectEqualStrings(initial_content, persisted);
}
