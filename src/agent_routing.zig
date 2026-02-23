//! Agent Routing — OpenClaw-compatible agent bindings routing system.
//!
//! Routes incoming messages to the correct agent based on a tiered matching
//! system. Bindings are checked against the input in priority order:
//!   1. peer        — exact peer (kind + id) match
//!   2. parent_peer — peer matches the parent (e.g. thread starter)
//!   3. guild_roles — guild_id + at least one matching role
//!   4. guild       — guild_id only (no roles)
//!   5. team        — team_id match
//!   6. account     — channel + account_id only
//!   7. channel_only— channel only (no account_id/peer/guild/team/roles)
//!
//! If no binding matches, the default agent is used (first in agents list,
//! or "main" if the list is empty).

const std = @import("std");
const config_types = @import("config_types.zig");
const NamedAgentConfig = config_types.NamedAgentConfig;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

pub const ChatType = enum {
    direct,
    group,
    channel,
};

pub const PeerRef = struct {
    kind: ChatType,
    id: []const u8,
};

pub const BindingMatch = struct {
    channel: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
    peer: ?PeerRef = null,
    guild_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    roles: []const []const u8 = &.{},
};

pub const AgentBinding = struct {
    agent_id: []const u8,
    comment: ?[]const u8 = null,
    match: BindingMatch = .{},
};

pub const MatchedBy = enum {
    peer,
    parent_peer,
    guild_roles,
    guild,
    team,
    account,
    channel_only,
    default,
};

pub const ResolvedRoute = struct {
    agent_id: []const u8,
    channel: []const u8,
    account_id: []const u8,
    session_key: []const u8,
    main_session_key: []const u8,
    matched_by: MatchedBy,
};

pub const RouteInput = struct {
    channel: []const u8,
    account_id: []const u8,
    peer: ?PeerRef = null,
    parent_peer: ?PeerRef = null,
    guild_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    member_role_ids: []const []const u8 = &.{},
};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Normalize an ID: lowercase, replace non-alphanumeric with '-',
/// strip leading/trailing dashes, cap at 64 chars.
/// Returns "default" for empty or all-dash input.
pub fn normalizeId(buf: *[64]u8, input: []const u8) []const u8 {
    if (input.len == 0) return "default";
    var len: usize = 0;
    for (input) |c| {
        if (len >= 64) break;
        if (std.ascii.isAlphanumeric(c)) {
            buf[len] = std.ascii.toLower(c);
            len += 1;
        } else {
            buf[len] = '-';
            len += 1;
        }
    }
    // Strip leading and trailing dashes
    var start: usize = 0;
    while (start < len and buf[start] == '-') start += 1;
    while (len > start and buf[len - 1] == '-') len -= 1;
    if (start >= len) return "default";
    return buf[start..len];
}

/// Resolve a peer ID through identity links. If the peer matches any
/// link's peers list, return the canonical name instead.
pub fn resolveLinkedPeerId(
    peer_id: []const u8,
    identity_links: []const config_types.IdentityLink,
) []const u8 {
    for (identity_links) |link| {
        for (link.peers) |linked_peer| {
            if (std.mem.eql(u8, linked_peer, peer_id)) return link.canonical;
        }
    }
    return peer_id;
}

/// Build a DM-scope-aware session key.
/// Returns owned slice; caller must free with the same allocator.
pub fn buildSessionKey(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    channel: []const u8,
    peer: ?PeerRef,
) ![]u8 {
    return buildSessionKeyWithScope(allocator, agent_id, channel, peer, .per_channel_peer, null, &.{});
}

/// Build a session key respecting DmScope and identity links.
pub fn buildSessionKeyWithScope(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    channel: []const u8,
    peer: ?PeerRef,
    dm_scope: config_types.DmScope,
    account_id: ?[]const u8,
    identity_links: []const config_types.IdentityLink,
) ![]u8 {
    var norm_buf: [64]u8 = undefined;
    const norm_agent = normalizeId(&norm_buf, agent_id);

    if (peer) |p| {
        const kind_str = switch (p.kind) {
            .direct => "direct",
            .group => "group",
            .channel => "channel",
        };

        // Groups and channels always use per-channel-peer scope
        if (p.kind != .direct) {
            return std.fmt.allocPrint(allocator, "agent:{s}:{s}:{s}:{s}", .{
                norm_agent, channel, kind_str, p.id,
            });
        }

        // Resolve identity links for DM peers
        const resolved_peer = resolveLinkedPeerId(p.id, identity_links);

        return switch (dm_scope) {
            .main => std.fmt.allocPrint(allocator, "agent:{s}:main", .{norm_agent}),
            .per_peer => std.fmt.allocPrint(allocator, "agent:{s}:direct:{s}", .{
                norm_agent, resolved_peer,
            }),
            .per_channel_peer => std.fmt.allocPrint(allocator, "agent:{s}:{s}:direct:{s}", .{
                norm_agent, channel, resolved_peer,
            }),
            .per_account_channel_peer => std.fmt.allocPrint(allocator, "agent:{s}:{s}:{s}:direct:{s}", .{
                norm_agent, channel, account_id orelse "default", resolved_peer,
            }),
        };
    }
    return std.fmt.allocPrint(allocator, "agent:{s}:{s}:none:none", .{
        norm_agent, channel,
    });
}

/// Build the main session key for an agent: `agent:{id}:main`.
pub fn buildMainSessionKey(allocator: std.mem.Allocator, agent_id: []const u8) ![]u8 {
    var norm_buf: [64]u8 = undefined;
    const norm_agent = normalizeId(&norm_buf, agent_id);
    return std.fmt.allocPrint(allocator, "agent:{s}:main", .{norm_agent});
}

/// Append `:thread:{threadId}` to a base session key.
pub fn buildThreadSessionKey(allocator: std.mem.Allocator, base_key: []const u8, thread_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}:thread:{s}", .{ base_key, thread_id });
}

/// Strip `:thread:{threadId}` suffix to get the parent session key.
/// Returns null if the key doesn't contain a thread suffix.
pub fn resolveThreadParentSessionKey(key: []const u8) ?[]const u8 {
    const marker = ":thread:";
    if (std.mem.lastIndexOf(u8, key, marker)) |idx| {
        return key[0..idx];
    }
    return null;
}

/// Find the default agent from a named agents list.
/// Returns the first agent's name, or "main" if the list is empty.
pub fn findDefaultAgent(agents: []const NamedAgentConfig) []const u8 {
    if (agents.len > 0) return agents[0].name;
    return "main";
}

/// Check if two PeerRef values match (same kind and id).
pub fn peerMatches(binding_peer: ?PeerRef, input_peer: ?PeerRef) bool {
    const bp = binding_peer orelse return false;
    const ip = input_peer orelse return false;
    return bp.kind == ip.kind and std.mem.eql(u8, bp.id, ip.id);
}

/// Pre-filter: check that a binding's channel and account_id constraints
/// match the input. A null constraint means "any" (matches everything).
pub fn bindingMatchesScope(binding: AgentBinding, input: RouteInput) bool {
    if (binding.match.channel) |bc| {
        if (!std.mem.eql(u8, bc, input.channel)) return false;
    }
    if (binding.match.account_id) |ba| {
        if (!std.mem.eql(u8, ba, input.account_id)) return false;
    }
    return true;
}

/// Returns true if the binding has no peer, guild_id, team_id, or roles set
/// (only channel and/or account_id).
fn isAccountOnly(b: AgentBinding) bool {
    return b.match.peer == null and
        b.match.guild_id == null and
        b.match.team_id == null and
        b.match.roles.len == 0;
}

/// Returns true if the binding has only a channel constraint (no account_id,
/// peer, guild_id, team_id, or roles).
fn isChannelOnly(b: AgentBinding) bool {
    return b.match.account_id == null and
        b.match.peer == null and
        b.match.guild_id == null and
        b.match.team_id == null and
        b.match.roles.len == 0;
}

/// Check ALL constraints on a binding against input. Each constraint on the
/// binding must match the corresponding input field. Null constraints match
/// anything (they impose no restriction).
fn allConstraintsMatch(b: AgentBinding, input: RouteInput, check_peer: ?PeerRef) bool {
    // Channel + account_id already checked in pre-filter.
    // Peer constraint: if binding has a peer, it must match the given check_peer.
    if (b.match.peer) |bp| {
        const ip = check_peer orelse return false;
        if (bp.kind != ip.kind or !std.mem.eql(u8, bp.id, ip.id)) return false;
    }
    // Guild constraint
    if (b.match.guild_id) |bg| {
        const ig = input.guild_id orelse return false;
        if (!std.mem.eql(u8, bg, ig)) return false;
    }
    // Team constraint
    if (b.match.team_id) |bt| {
        const it = input.team_id orelse return false;
        if (!std.mem.eql(u8, bt, it)) return false;
    }
    // Roles constraint
    if (b.match.roles.len > 0) {
        if (!hasMatchingRole(b.match.roles, input.member_role_ids)) return false;
    }
    return true;
}

/// Check if any role in `binding_roles` appears in `member_roles`.
fn hasMatchingRole(binding_roles: []const []const u8, member_roles: []const []const u8) bool {
    for (binding_roles) |br| {
        for (member_roles) |mr| {
            if (std.mem.eql(u8, br, mr)) return true;
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Route resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Resolve the agent route for a given input.
///
/// Walks 7 tiers of binding matches in priority order and returns the
/// first match found. Falls back to the default agent if none match.
/// The returned `session_key` is allocated; caller must free it.
pub fn resolveRoute(
    allocator: std.mem.Allocator,
    input: RouteInput,
    bindings: []const AgentBinding,
    agents: []const NamedAgentConfig,
) !ResolvedRoute {
    // Pre-filter bindings by channel + account_id scope.
    var candidates: std.ArrayListUnmanaged(AgentBinding) = .empty;
    defer candidates.deinit(allocator);

    for (bindings) |b| {
        if (bindingMatchesScope(b, input)) {
            try candidates.append(allocator, b);
        }
    }

    // Tier 1: peer match — binding has a peer constraint that matches input.peer
    if (input.peer) |ip| {
        for (candidates.items) |b| {
            if (b.match.peer != null and allConstraintsMatch(b, input, ip)) {
                return buildRoute(allocator, b.agent_id, input, .peer);
            }
        }
    }

    // Tier 2: parent_peer match — binding peer matches input.parent_peer
    if (input.parent_peer) |pp| {
        if (pp.id.len > 0) {
            for (candidates.items) |b| {
                if (b.match.peer != null and allConstraintsMatch(b, input, pp)) {
                    return buildRoute(allocator, b.agent_id, input, .parent_peer);
                }
            }
        }
    }

    // Tier 3: guild_id + roles match
    if (input.guild_id != null and input.member_role_ids.len > 0) {
        for (candidates.items) |b| {
            if (b.match.guild_id != null and b.match.roles.len > 0 and
                allConstraintsMatch(b, input, input.peer))
            {
                return buildRoute(allocator, b.agent_id, input, .guild_roles);
            }
        }
    }

    // Tier 4: guild_id only (no roles on binding)
    if (input.guild_id != null) {
        for (candidates.items) |b| {
            if (b.match.guild_id != null and b.match.roles.len == 0 and
                allConstraintsMatch(b, input, input.peer))
            {
                return buildRoute(allocator, b.agent_id, input, .guild);
            }
        }
    }

    // Tier 5: team_id match
    if (input.team_id != null) {
        for (candidates.items) |b| {
            if (b.match.team_id != null and allConstraintsMatch(b, input, input.peer)) {
                return buildRoute(allocator, b.agent_id, input, .team);
            }
        }
    }

    // Tier 6: account only (channel + account_id, no peer/guild/team/roles)
    for (candidates.items) |b| {
        if (b.match.account_id != null and isAccountOnly(b)) {
            return buildRoute(allocator, b.agent_id, input, .account);
        }
    }

    // Tier 7: channel only (no account_id/peer/guild/team/roles)
    for (candidates.items) |b| {
        if (isChannelOnly(b)) {
            return buildRoute(allocator, b.agent_id, input, .channel_only);
        }
    }

    // No match — use default agent.
    const default_id = findDefaultAgent(agents);
    return buildRoute(allocator, default_id, input, .default);
}

/// Resolve a route and build session keys using configured session scope settings.
/// Applies dm_scope and identity_links to the returned session_key.
pub fn resolveRouteWithSession(
    allocator: std.mem.Allocator,
    input: RouteInput,
    bindings: []const AgentBinding,
    agents: []const NamedAgentConfig,
    session: config_types.SessionConfig,
) !ResolvedRoute {
    var route = try resolveRoute(allocator, input, bindings, agents);
    errdefer allocator.free(route.main_session_key);

    allocator.free(route.session_key);
    route.session_key = try buildSessionKeyWithScope(
        allocator,
        route.agent_id,
        input.channel,
        input.peer,
        session.dm_scope,
        input.account_id,
        session.identity_links,
    );
    return route;
}

/// Internal helper to construct a ResolvedRoute with allocated session keys.
fn buildRoute(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    input: RouteInput,
    matched_by: MatchedBy,
) !ResolvedRoute {
    const session_key = try buildSessionKey(allocator, agent_id, input.channel, input.peer);
    errdefer allocator.free(session_key);
    const main_key = try buildMainSessionKey(allocator, agent_id);
    return .{
        .agent_id = agent_id,
        .channel = input.channel,
        .account_id = input.account_id,
        .session_key = session_key,
        .main_session_key = main_key,
        .matched_by = matched_by,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test {
    std.testing.refAllDecls(@This());
}

test "resolveRoute — no bindings returns default agent" {
    const allocator = std.testing.allocator;
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
    };
    const agents = [_]NamedAgentConfig{.{
        .name = "helper",
        .provider = "openai",
        .model = "gpt-4",
    }};
    const route = try resolveRoute(allocator, input, &.{}, &agents);
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("helper", route.agent_id);
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
    try std.testing.expectEqualStrings("discord", route.channel);
    try std.testing.expectEqualStrings("acct1", route.account_id);
}

test "resolveRoute — peer match returns correct agent" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "support-bot",
            .match = .{
                .peer = .{ .kind = .direct, .id = "user42" },
            },
        },
        .{
            .agent_id = "general-bot",
        },
    };
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user42" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("support-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — guild+roles match (tier 3)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "mod-bot",
        .match = .{
            .guild_id = "guild1",
            .roles = &.{ "moderator", "admin" },
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
        .member_role_ids = &.{"moderator"},
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("mod-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild_roles, route.matched_by);
}

test "resolveRoute — guild-only match (tier 4)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "guild-bot",
        .match = .{
            .guild_id = "guild1",
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("guild-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "resolveRoute — channel-only match (tier 7)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "catch-all",
        .match = .{
            .channel = "slack",
        },
    }};
    const input = RouteInput{
        .channel = "slack",
        .account_id = "acct99",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("catch-all", route.agent_id);
    try std.testing.expectEqual(MatchedBy.channel_only, route.matched_by);
}

test "resolveRoute — tier priority: peer wins over guild" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "guild-bot",
            .match = .{ .guild_id = "guild1" },
        },
        .{
            .agent_id = "peer-bot",
            .match = .{
                .peer = .{ .kind = .direct, .id = "user1" },
            },
        },
    };
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user1" },
        .guild_id = "guild1",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("peer-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — parent_peer match (tier 2)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "thread-bot",
        .match = .{
            .peer = .{ .kind = .group, .id = "thread99" },
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user5" },
        .parent_peer = .{ .kind = .group, .id = "thread99" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("thread-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.parent_peer, route.matched_by);
}

test "resolveRoute — team match (tier 5)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "team-bot",
        .match = .{ .team_id = "T123" },
    }};
    const input = RouteInput{
        .channel = "slack",
        .account_id = "acct1",
        .team_id = "T123",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("team-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.team, route.matched_by);
}

test "resolveRoute — account match (tier 6)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "acct-bot",
        .match = .{
            .channel = "telegram",
            .account_id = "acct7",
        },
    }};
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct7",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("acct-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.account, route.matched_by);
}

test "resolveRoute — scope pre-filter excludes mismatched channel" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "discord-only",
        .match = .{
            .channel = "discord",
            .peer = .{ .kind = .direct, .id = "user1" },
        },
    }};
    // Input is on "telegram", not "discord" — binding should be excluded.
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user1" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    // No match — falls through to default.
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
    try std.testing.expectEqualStrings("main", route.agent_id);
}

test "resolveRoute — guild_roles no matching role falls to guild tier" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "role-bot",
            .match = .{
                .guild_id = "guild1",
                .roles = &.{"admin"},
            },
        },
        .{
            .agent_id = "guild-fallback",
            .match = .{
                .guild_id = "guild1",
            },
        },
    };
    // User has "member" role, not "admin" — role binding should NOT match,
    // but guild-only binding should.
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
        .member_role_ids = &.{"member"},
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);

    try std.testing.expectEqualStrings("guild-fallback", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "buildSessionKey — with peer" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "bot1", "discord", .{
        .kind = .direct,
        .id = "user42",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:bot1:discord:direct:user42", key);
}

test "buildSessionKey — without peer" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "bot1", "telegram", null);
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:bot1:telegram:none:none", key);
}

test "buildSessionKey — group peer kind" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "agent-x", "slack", .{
        .kind = .group,
        .id = "G1234",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:agent-x:slack:group:G1234", key);
}

test "buildSessionKey — channel peer kind" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "mybot", "irc", .{
        .kind = .channel,
        .id = "#general",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:mybot:irc:channel:#general", key);
}

test "findDefaultAgent — empty list returns main" {
    const result = findDefaultAgent(&.{});
    try std.testing.expectEqualStrings("main", result);
}

test "findDefaultAgent — returns first agent name" {
    const agents = [_]NamedAgentConfig{
        .{ .name = "alpha", .provider = "openai", .model = "gpt-4" },
        .{ .name = "beta", .provider = "anthropic", .model = "claude-3" },
    };
    const result = findDefaultAgent(&agents);
    try std.testing.expectEqualStrings("alpha", result);
}

test "peerMatches — both present and equal" {
    try std.testing.expect(peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .direct, .id = "u1" },
    ));
}

test "peerMatches — different kind" {
    try std.testing.expect(!peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .group, .id = "u1" },
    ));
}

test "peerMatches — different id" {
    try std.testing.expect(!peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .direct, .id = "u2" },
    ));
}

test "peerMatches — binding null" {
    try std.testing.expect(!peerMatches(null, .{ .kind = .direct, .id = "u1" }));
}

test "peerMatches — input null" {
    try std.testing.expect(!peerMatches(.{ .kind = .direct, .id = "u1" }, null));
}

test "peerMatches — both null" {
    try std.testing.expect(!peerMatches(null, null));
}

test "bindingMatchesScope — null constraints match anything" {
    const b = AgentBinding{ .agent_id = "x" };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}

test "bindingMatchesScope — matching channel and account" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "discord", .account_id = "acct1" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}

test "bindingMatchesScope — mismatched channel" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "slack" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(!bindingMatchesScope(b, input));
}

test "bindingMatchesScope — mismatched account_id" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .account_id = "acct2" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(!bindingMatchesScope(b, input));
}

test "bindingMatchesScope — channel matches, account null (any)" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "discord" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2 tests: normalizeId, identity links, DM scope, thread keys
// ═══════════════════════════════════════════════════════════════════════════

test "normalizeId — basic lowercase" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello", normalizeId(&buf, "Hello"));
}

test "normalizeId — special chars become dashes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("my-bot-1", normalizeId(&buf, "My Bot!1"));
}

test "normalizeId — empty returns default" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("default", normalizeId(&buf, ""));
}

test "normalizeId — all-dash returns default" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("default", normalizeId(&buf, "---"));
}

test "normalizeId — strips leading/trailing dashes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("abc", normalizeId(&buf, "  abc  "));
}

test "resolveLinkedPeerId — no links returns original" {
    try std.testing.expectEqualStrings("user42", resolveLinkedPeerId("user42", &.{}));
}

test "resolveLinkedPeerId — matched link returns canonical" {
    const links = [_]config_types.IdentityLink{.{
        .canonical = "alice",
        .peers = &.{ "telegram:123", "discord:456" },
    }};
    try std.testing.expectEqualStrings("alice", resolveLinkedPeerId("discord:456", &links));
}

test "resolveLinkedPeerId — unmatched returns original" {
    const links = [_]config_types.IdentityLink{.{
        .canonical = "alice",
        .peers = &.{"telegram:123"},
    }};
    try std.testing.expectEqualStrings("discord:789", resolveLinkedPeerId("discord:789", &links));
}

test "buildSessionKeyWithScope — per_channel_peer (default)" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(allocator, "bot1", "discord", .{
        .kind = .direct, .id = "user42",
    }, .per_channel_peer, null, &.{});
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:discord:direct:user42", key);
}

test "buildSessionKeyWithScope — main scope" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(allocator, "bot1", "discord", .{
        .kind = .direct, .id = "user42",
    }, .main, null, &.{});
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:main", key);
}

test "buildSessionKeyWithScope — per_peer scope" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(allocator, "bot1", "discord", .{
        .kind = .direct, .id = "user42",
    }, .per_peer, null, &.{});
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:direct:user42", key);
}

test "buildSessionKeyWithScope — per_account_channel_peer scope" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(allocator, "bot1", "discord", .{
        .kind = .direct, .id = "user42",
    }, .per_account_channel_peer, "work", &.{});
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:discord:work:direct:user42", key);
}

test "buildSessionKeyWithScope — group always per-channel" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(allocator, "bot1", "discord", .{
        .kind = .group, .id = "G123",
    }, .main, null, &.{});
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:discord:group:G123", key);
}

test "buildSessionKeyWithScope — identity link resolves peer" {
    const allocator = std.testing.allocator;
    const links = [_]config_types.IdentityLink{.{
        .canonical = "alice",
        .peers = &.{"telegram:123"},
    }};
    const key = try buildSessionKeyWithScope(allocator, "bot1", "telegram", .{
        .kind = .direct, .id = "telegram:123",
    }, .per_channel_peer, null, &links);
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:telegram:direct:alice", key);
}

test "buildMainSessionKey" {
    const allocator = std.testing.allocator;
    const key = try buildMainSessionKey(allocator, "My Bot");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:my-bot:main", key);
}

test "buildThreadSessionKey" {
    const allocator = std.testing.allocator;
    const key = try buildThreadSessionKey(allocator, "agent:bot1:discord:direct:user42", "thread99");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:bot1:discord:direct:user42:thread:thread99", key);
}

test "resolveThreadParentSessionKey — has thread suffix" {
    const parent = resolveThreadParentSessionKey("agent:bot1:discord:direct:user42:thread:t99");
    try std.testing.expect(parent != null);
    try std.testing.expectEqualStrings("agent:bot1:discord:direct:user42", parent.?);
}

test "resolveThreadParentSessionKey — no thread suffix" {
    const parent = resolveThreadParentSessionKey("agent:bot1:discord:direct:user42");
    try std.testing.expect(parent == null);
}

test "resolveRoute — main_session_key is always set" {
    const allocator = std.testing.allocator;
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    const route = try resolveRoute(allocator, input, &.{}, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("agent:main:main", route.main_session_key);
}

// ═══════════════════════════════════════════════════════════════════════════
// Parity tests: route resolution, session keys, multi-account, normalization
// ═══════════════════════════════════════════════════════════════════════════

test "resolveRoute — defaults to main/default when no bindings" {
    const allocator = std.testing.allocator;
    const route = try resolveRoute(allocator, .{
        .channel = "whatsapp",
        .account_id = "default",
    }, &.{}, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("main", route.agent_id);
    try std.testing.expectEqualStrings("default", route.account_id);
    try std.testing.expectEqualStrings("agent:main:main", route.main_session_key);
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
}

test "resolveRoute — peer binding wins over account binding" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "a",
            .match = .{
                .channel = "whatsapp",
                .account_id = "biz",
                .peer = .{ .kind = .direct, .id = "+1000" },
            },
        },
        .{
            .agent_id = "b",
            .match = .{
                .channel = "whatsapp",
                .account_id = "biz",
            },
        },
    };
    const route = try resolveRoute(allocator, .{
        .channel = "whatsapp",
        .account_id = "biz",
        .peer = .{ .kind = .direct, .id = "+1000" },
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("a", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — missing accountId in binding matches only that account" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "default-acct",
        .match = .{ .channel = "whatsapp", .account_id = "default" },
    }};
    // default account: matches
    const r1 = try resolveRoute(allocator, .{
        .channel = "whatsapp",
        .account_id = "default",
        .peer = .{ .kind = .direct, .id = "+1000" },
    }, &bindings, &.{});
    defer allocator.free(r1.session_key);
    defer allocator.free(r1.main_session_key);
    try std.testing.expectEqualStrings("default-acct", r1.agent_id);
    try std.testing.expectEqual(MatchedBy.account, r1.matched_by);

    // different account: no match, falls to default
    const r2 = try resolveRoute(allocator, .{
        .channel = "whatsapp",
        .account_id = "biz",
        .peer = .{ .kind = .direct, .id = "+1000" },
    }, &bindings, &.{});
    defer allocator.free(r2.session_key);
    defer allocator.free(r2.main_session_key);
    try std.testing.expectEqualStrings("main", r2.agent_id);
    try std.testing.expectEqual(MatchedBy.default, r2.matched_by);
}

test "resolveRoute — defaultAgentId used when no binding matches" {
    const allocator = std.testing.allocator;
    const agents = [_]NamedAgentConfig{.{
        .name = "home",
        .provider = "openai",
        .model = "gpt-4",
    }};
    const route = try resolveRoute(allocator, .{
        .channel = "whatsapp",
        .account_id = "biz",
        .peer = .{ .kind = .direct, .id = "+1000" },
    }, &.{}, &agents);
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("home", route.agent_id);
    try std.testing.expectEqualStrings("agent:home:main", route.main_session_key);
}

test "resolveRoute — peer+guild binding requires guild match" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "bot",
        .match = .{
            .channel = "discord",
            .peer = .{ .kind = .direct, .id = "user1" },
            .guild_id = "guild1",
        },
    }};
    // guild matches: peer wins
    const r1 = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .peer = .{ .kind = .direct, .id = "user1" },
        .guild_id = "guild1",
    }, &bindings, &.{});
    defer allocator.free(r1.session_key);
    defer allocator.free(r1.main_session_key);
    try std.testing.expectEqualStrings("bot", r1.agent_id);

    // guild mismatch: no match
    const r2 = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .peer = .{ .kind = .direct, .id = "user1" },
        .guild_id = "guild2",
    }, &bindings, &.{});
    defer allocator.free(r2.session_key);
    defer allocator.free(r2.main_session_key);
    try std.testing.expectEqual(MatchedBy.default, r2.matched_by);
}

test "resolveRoute — guild binding wins over account when peer not bound" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "guild-bot",
            .match = .{ .channel = "discord", .guild_id = "guild1" },
        },
        .{
            .agent_id = "acct-bot",
            .match = .{ .channel = "discord", .account_id = "default" },
        },
    };
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .guild_id = "guild1",
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("guild-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "resolveRoute — peer binding still beats guild+roles" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "role-bot",
            .match = .{ .channel = "discord", .guild_id = "g1", .roles = &.{"admin"} },
        },
        .{
            .agent_id = "peer-bot",
            .match = .{ .channel = "discord", .peer = .{ .kind = .direct, .id = "u1" } },
        },
    };
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .peer = .{ .kind = .direct, .id = "u1" },
        .guild_id = "g1",
        .member_role_ids = &.{"admin"},
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("peer-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — no member_role_ids means guild+roles doesn't match" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "role-bot",
        .match = .{ .channel = "discord", .guild_id = "g1", .roles = &.{"admin"} },
    }};
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .guild_id = "g1",
        // no member_role_ids
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
}

test "resolveRoute — empty roles treated as no role restriction (guild tier)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "guild-bot",
        .match = .{ .channel = "discord", .guild_id = "g1", .roles = &.{} },
    }};
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .guild_id = "g1",
        .member_role_ids = &.{"admin"},
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    // Empty roles = guild-only binding (tier 4), not guild+roles (tier 3)
    try std.testing.expectEqualStrings("guild-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "resolveRoute — first matching binding wins with multiple role bindings" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "first-bot",
            .match = .{ .channel = "discord", .guild_id = "g1", .roles = &.{"mod"} },
        },
        .{
            .agent_id = "second-bot",
            .match = .{ .channel = "discord", .guild_id = "g1", .roles = &.{"admin"} },
        },
    };
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .guild_id = "g1",
        .member_role_ids = &.{ "mod", "admin" },
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("first-bot", route.agent_id);
}

test "resolveRoute — parent_peer binding wins over guild binding" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "guild-bot",
            .match = .{ .channel = "discord", .guild_id = "g1" },
        },
        .{
            .agent_id = "parent-bot",
            .match = .{
                .channel = "discord",
                .peer = .{ .kind = .channel, .id = "ch99" },
            },
        },
    };
    const route = try resolveRoute(allocator, .{
        .channel = "discord",
        .account_id = "default",
        .peer = .{ .kind = .direct, .id = "user1" },
        .parent_peer = .{ .kind = .channel, .id = "ch99" },
        .guild_id = "g1",
    }, &bindings, &.{});
    defer allocator.free(route.session_key);
    defer allocator.free(route.main_session_key);
    try std.testing.expectEqualStrings("parent-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.parent_peer, route.matched_by);
}

// ── dmScope session key tests ───────────────────────────────────────────

test "dmScope controls direct-message session key isolation" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ config_types.DmScope.per_peer, "agent:bot:direct:+15551234567" },
        .{ config_types.DmScope.per_channel_peer, "agent:bot:whatsapp:direct:+15551234567" },
        .{ config_types.DmScope.main, "agent:bot:main" },
        .{ config_types.DmScope.per_account_channel_peer, "agent:bot:whatsapp:default:direct:+15551234567" },
    };
    inline for (cases) |c| {
        const key = try buildSessionKeyWithScope(
            allocator,
            "bot",
            "whatsapp",
            .{ .kind = .direct, .id = "+15551234567" },
            c[0],
            null,
            &.{},
        );
        defer allocator.free(key);
        try std.testing.expectEqualStrings(c[1], key);
    }
}

test "per_account_channel_peer isolates per account, channel, sender" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(
        allocator, "main", "telegram",
        .{ .kind = .direct, .id = "7550356539" },
        .per_account_channel_peer, "tasks", &.{},
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:main:telegram:tasks:direct:7550356539", key);
}

test "per_account_channel_peer uses default when account not provided" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKeyWithScope(
        allocator, "main", "telegram",
        .{ .kind = .direct, .id = "7550356539" },
        .per_account_channel_peer, null, &.{},
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:main:telegram:default:direct:7550356539", key);
}

test "identityLinks applies to per_peer scope" {
    const allocator = std.testing.allocator;
    const links = [_]config_types.IdentityLink{.{
        .canonical = "alice",
        .peers = &.{ "telegram:111111111", "discord:222222222222222222" },
    }};
    const key = try buildSessionKeyWithScope(
        allocator, "main", "telegram",
        .{ .kind = .direct, .id = "telegram:111111111" },
        .per_peer, null, &links,
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:main:direct:alice", key);
}

test "identityLinks applies to per_channel_peer scope" {
    const allocator = std.testing.allocator;
    const links = [_]config_types.IdentityLink{.{
        .canonical = "alice",
        .peers = &.{ "telegram:111111111", "discord:222222222222222222" },
    }};
    const key = try buildSessionKeyWithScope(
        allocator, "main", "discord",
        .{ .kind = .direct, .id = "discord:222222222222222222" },
        .per_channel_peer, null, &links,
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:main:discord:direct:alice", key);
}

// ── Session key continuity (DM vs group produce distinct keys) ──────────

test "distinct keys for DM vs channel — main scope" {
    const allocator = std.testing.allocator;
    const dm_key = try buildSessionKeyWithScope(
        allocator, "main", "discord",
        .{ .kind = .direct, .id = "user123" },
        .main, "default", &.{},
    );
    defer allocator.free(dm_key);
    const group_key = try buildSessionKeyWithScope(
        allocator, "main", "discord",
        .{ .kind = .channel, .id = "channel456" },
        .main, "default", &.{},
    );
    defer allocator.free(group_key);
    try std.testing.expectEqualStrings("agent:main:main", dm_key);
    try std.testing.expectEqualStrings("agent:main:discord:channel:channel456", group_key);
    try std.testing.expect(!std.mem.eql(u8, dm_key, group_key));
}

test "distinct keys for DM vs channel — per_peer scope" {
    const allocator = std.testing.allocator;
    const dm_key = try buildSessionKeyWithScope(
        allocator, "main", "discord",
        .{ .kind = .direct, .id = "user123" },
        .per_peer, "default", &.{},
    );
    defer allocator.free(dm_key);
    const group_key = try buildSessionKeyWithScope(
        allocator, "main", "discord",
        .{ .kind = .channel, .id = "channel456" },
        .per_peer, "default", &.{},
    );
    defer allocator.free(group_key);
    try std.testing.expectEqualStrings("agent:main:direct:user123", dm_key);
    try std.testing.expectEqualStrings("agent:main:discord:channel:channel456", group_key);
    try std.testing.expect(!std.mem.eql(u8, dm_key, group_key));
}

// ── normalizeId parity tests ────────────────────────────────────────────

test "normalizeId — defaults missing/empty values to default" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("default", normalizeId(&buf, ""));
    try std.testing.expectEqualStrings("default", normalizeId(&buf, "   "));
}

test "normalizeId — normalizes valid ids to lowercase" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("business-1", normalizeId(&buf, "  Business_1  "));
}

test "normalizeId — sanitizes invalid characters" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("prod-us-east", normalizeId(&buf, " Prod/US East "));
}

test "normalizeId — truncates at 64 chars" {
    var buf: [64]u8 = undefined;
    const long_input = "a" ** 100;
    const result = normalizeId(&buf, long_input);
    try std.testing.expectEqual(@as(usize, 64), result.len);
}

// ── Thread session key parity tests ─────────────────────────────────────

test "buildThreadSessionKey — topic suffix for telegram groups" {
    const allocator = std.testing.allocator;
    const base = "agent:main:telegram:group:1";
    const key = try buildThreadSessionKey(allocator, base, "55");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:main:telegram:group:1:thread:55", key);
}

test "resolveThreadParentSessionKey — parses thread suffix" {
    const parent = resolveThreadParentSessionKey("agent:main:slack:channel:C1:thread:123.456");
    try std.testing.expect(parent != null);
    try std.testing.expectEqualStrings("agent:main:slack:channel:C1", parent.?);
}

test "resolveThreadParentSessionKey — DM without thread returns null" {
    const parent = resolveThreadParentSessionKey("agent:main:telegram:direct:user-1");
    try std.testing.expect(parent == null);
}

// ── buildMainSessionKey normalizes agent id ─────────────────────────────

test "buildMainSessionKey — normalizes agent id" {
    const allocator = std.testing.allocator;
    const key = try buildMainSessionKey(allocator, "  Research Bot  ");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:research-bot:main", key);
}

test "buildMainSessionKey — empty agent id defaults to main" {
    const allocator = std.testing.allocator;
    const key = try buildMainSessionKey(allocator, "");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("agent:default:main", key);
}

// ── resolveLinkedPeerId parity ──────────────────────────────────────────

test "resolveLinkedPeerId — multiple links, first match wins" {
    const links = [_]config_types.IdentityLink{
        .{ .canonical = "alice", .peers = &.{ "telegram:111", "discord:222" } },
        .{ .canonical = "bob", .peers = &.{"telegram:333"} },
    };
    try std.testing.expectEqualStrings("alice", resolveLinkedPeerId("discord:222", &links));
    try std.testing.expectEqualStrings("bob", resolveLinkedPeerId("telegram:333", &links));
}

test "resolveLinkedPeerId — empty links returns original" {
    try std.testing.expectEqualStrings("user42", resolveLinkedPeerId("user42", &.{}));
}
