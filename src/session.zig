//! Session Manager — persistent in-process Agent sessions.
//!
//! Replaces subprocess spawning with reusable Agent instances keyed by
//! session_key (e.g. "telegram:chat123"). Each session maintains its own
//! conversation history across turns.
//!
//! Thread safety: SessionManager.mutex guards the sessions map (short hold),
//! Session.mutex serializes turn() per session (may be long). Different
//! sessions are processed in parallel.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Config = @import("config.zig").Config;
const fs_compat = @import("fs_compat.zig");
const agent_routing = @import("agent_routing.zig");
const agent_mod = @import("agent/root.zig");
const Agent = agent_mod.Agent;
const NamedAgentConfig = @import("config_types.zig").NamedAgentConfig;
const ConversationContext = @import("agent/prompt.zig").ConversationContext;
const config_types = @import("config_types.zig");
const providers = @import("providers/root.zig");
const Provider = providers.Provider;
const memory_mod = @import("memory/root.zig");
const Memory = memory_mod.Memory;
const onboard = @import("onboard.zig");
const bootstrap_mod = @import("bootstrap/root.zig");
const observability = @import("observability.zig");
const Observer = observability.Observer;
const tools_mod = @import("tools/root.zig");
const Tool = tools_mod.Tool;
const SecurityPolicy = @import("security/policy.zig").SecurityPolicy;
const streaming = @import("streaming.zig");
const thread_stacks = @import("thread_stacks.zig");
const log = std.log.scoped(.session);
const MESSAGE_LOG_MAX_BYTES: usize = 4096;
const TOKEN_USAGE_LEDGER_FILENAME = "llm_token_usage.jsonl";
const NS_PER_SEC: i128 = std.time.ns_per_s;
const RUNTIME_COMMAND_ROLE = memory_mod.RUNTIME_COMMAND_ROLE;
const CLAIM_STATE_FILENAME = "identity_claims.json";
const CLAIM_STATE_VERSION: u32 = 1;

const ClaimDirectContext = struct {
    channel: []const u8,
    account_id: []const u8,
    peer_id: []const u8,
};

const VerifiedBinding = struct {
    canonical_user_id: []u8,
    verified_at: i64,
};

const ClaimAttempt = struct {
    failures: u32 = 0,
    locked_until: i64 = 0,
};

const ClaimToken = struct {
    expires_at: i64,
    canonical_user_id: []const u8,
    nonce: []const u8,
    signature_hex: []const u8,
};

const ClaimStateSnapshot = struct {
    generation: u64,
    content: []u8,
};

fn messageLogPreview(text: []const u8) struct { slice: []const u8, truncated: bool } {
    if (text.len <= MESSAGE_LOG_MAX_BYTES) {
        return .{ .slice = text, .truncated = false };
    }
    return .{ .slice = text[0..MESSAGE_LOG_MAX_BYTES], .truncated = true };
}

fn estimateRestoredSessionTokens(entries: []const memory_mod.MessageEntry) u64 {
    var total: u64 = 0;
    for (entries) |entry| {
        if (!std.mem.eql(u8, entry.role, "assistant")) continue;
        total += agent_mod.estimate_text_tokens(entry.content);
    }
    return total;
}

fn persistedAssistantReply(agent: *const Agent, response: []const u8) []const u8 {
    if (agent.history.items.len == 0) return response;
    const last = agent.history.items[agent.history.items.len - 1];
    if (last.role != .assistant) return response;
    return last.content;
}

fn restorePersistedSessionState(session: *Session, entries: []const memory_mod.MessageEntry) void {
    for (entries) |entry| {
        if (memory_mod.isRuntimeCommandRole(entry.role)) {
            const maybe_response = session.agent.handleSlashCommand(entry.content) catch null;
            if (maybe_response) |response| session.agent.allocator.free(response);
            continue;
        }

        const role: providers.Role = if (std.mem.eql(u8, entry.role, "assistant"))
            .assistant
        else if (std.mem.eql(u8, entry.role, "system"))
            .system
        else
            .user;

        const content = session.agent.allocator.dupe(u8, entry.content) catch continue;
        session.agent.history.append(session.agent.allocator, .{
            .role = role,
            .content = content,
        }) catch {
            session.agent.allocator.free(content);
            continue;
        };
    }
}

fn sessionAgentId(session_key: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, session_key, "agent:")) return null;
    const rest = session_key["agent:".len..];
    const sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    if (sep == 0) return null;
    return rest[0..sep];
}

fn findProfileForSessionKey(config: *const Config, session_key: []const u8) ?config_types.NamedAgentConfig {
    const normalized_agent_id = sessionAgentId(session_key) orelse return null;

    for (config.agents) |agent_profile| {
        var norm_buf: [64]u8 = undefined;
        const normalized_name = agent_routing.normalizeId(&norm_buf, agent_profile.name);
        if (std.mem.eql(u8, normalized_name, normalized_agent_id)) return agent_profile;
    }

    return null;
}

const SessionProviderContext = struct {
    provider: Provider,
    holder: ?providers.ProviderHolder = null,
    owned_api_key: ?[]u8 = null,

    fn deinit(self: *SessionProviderContext, allocator: Allocator) void {
        if (self.holder) |*holder| {
            holder.deinit();
            self.holder = null;
        }
        if (self.owned_api_key) |key| {
            allocator.free(key);
            self.owned_api_key = null;
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Session
// ═══════════════════════════════════════════════════════════════════════════

pub const Session = struct {
    agent: Agent,
    provider_holder: ?providers.ProviderHolder = null,
    owned_provider_api_key: ?[]u8 = null,
    owned_memory_session_id: ?[]u8 = null,
    created_at: i64,
    last_active: i64,
    last_consolidated: u64 = 0,
    session_key: []const u8, // owned copy
    turn_count: u64,
    turn_running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,

    pub fn deinit(self: *Session, allocator: Allocator) void {
        self.agent.deinit();
        if (self.provider_holder) |*holder| holder.deinit();
        if (self.owned_provider_api_key) |key| allocator.free(key);
        if (self.owned_memory_session_id) |sid| allocator.free(sid);
        allocator.free(self.session_key);
    }
};

const AgentRuntime = struct {
    agent_id: []const u8,
    workspace_dir: []const u8,
    config: Config,
    provider: Provider,
    tools: []const Tool,
    mem: ?Memory,
    mem_rt: ?memory_mod.MemoryRuntime,
    session_store: ?memory_mod.SessionStore,
    response_cache: ?*memory_mod.cache.ResponseCache,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider,

    fn deinit(self: *AgentRuntime, allocator: Allocator) void {
        if (self.tools.len > 0) tools_mod.deinitTools(allocator, self.tools);
        if (self.bootstrap_provider) |bp| bp.deinit();
        if (self.mem_rt) |*rt| rt.deinit();
        allocator.free(self.workspace_dir);
        allocator.free(self.agent_id);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// SessionManager
// ═══════════════════════════════════════════════════════════════════════════

pub const SessionManager = struct {
    allocator: Allocator,
    config: *const Config,
    provider: Provider,
    tools: []const Tool,
    mem: ?Memory,
    session_store: ?memory_mod.SessionStore = null,
    response_cache: ?*memory_mod.cache.ResponseCache = null,
    mem_rt: ?*memory_mod.MemoryRuntime = null,
    observer: Observer,
    policy: ?*const SecurityPolicy = null,
    subagent_manager: ?*@import("subagent.zig").SubagentManager = null,

    mutex: std.Thread.Mutex,
    usage_log_mutex: std.Thread.Mutex,
    claim_state_io_mutex: std.Thread.Mutex,
    usage_ledger_state_initialized: bool,
    usage_ledger_window_started_at: i64,
    usage_ledger_line_count: u64,
    sessions: std.StringHashMapUnmanaged(*Session),
    agent_runtimes: std.StringHashMapUnmanaged(*AgentRuntime),
    claim_state_path: ?[]u8 = null,
    claim_state_loaded: bool = false,
    claim_state_generation: u64 = 0,
    claim_state_persisted_generation: u64 = 0,
    verified_bindings: std.StringHashMapUnmanaged(VerifiedBinding),
    used_claim_nonces: std.StringHashMapUnmanaged(i64),
    claim_attempts: std.StringHashMapUnmanaged(ClaimAttempt),

    pub fn init(
        allocator: Allocator,
        config: *const Config,
        provider: Provider,
        tools: []const Tool,
        mem: ?Memory,
        observer_i: Observer,
        session_store: ?memory_mod.SessionStore,
        response_cache: ?*memory_mod.cache.ResponseCache,
    ) SessionManager {
        tools_mod.bindMemoryTools(tools, mem);

        const claim_state_path = blk: {
            const secret = config.session.claim_secret orelse break :blk null;
            if (std.mem.trim(u8, secret, " \t\r\n").len == 0) break :blk null;
            const config_dir = std.fs.path.dirname(config.config_path) orelse ".";
            break :blk std.fs.path.join(allocator, &.{ config_dir, "state", CLAIM_STATE_FILENAME }) catch null;
        };

        var manager: SessionManager = .{
            .allocator = allocator,
            .config = config,
            .provider = provider,
            .tools = tools,
            .mem = mem,
            .session_store = session_store,
            .response_cache = response_cache,
            .observer = observer_i,
            .subagent_manager = detectSubagentManager(tools),
            .mutex = .{},
            .usage_log_mutex = .{},
            .claim_state_io_mutex = .{},
            .usage_ledger_state_initialized = false,
            .usage_ledger_window_started_at = 0,
            .usage_ledger_line_count = 0,
            .sessions = .{},
            .agent_runtimes = .{},
            .claim_state_path = claim_state_path,
            .claim_state_loaded = false,
            .claim_state_generation = 0,
            .claim_state_persisted_generation = 0,
            .verified_bindings = .{},
            .used_claim_nonces = .{},
            .claim_attempts = .{},
        };
        manager.loadClaimState();
        return manager;
    }

    pub fn deinit(self: *SessionManager) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit(self.allocator);

        var rt_it = self.agent_runtimes.iterator();
        while (rt_it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.agent_runtimes.deinit(self.allocator);

        var bindings_it = self.verified_bindings.iterator();
        while (bindings_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.canonical_user_id);
        }
        self.verified_bindings.deinit(self.allocator);

        var nonces_it = self.used_claim_nonces.iterator();
        while (nonces_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.used_claim_nonces.deinit(self.allocator);

        var attempts_it = self.claim_attempts.iterator();
        while (attempts_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.claim_attempts.deinit(self.allocator);

        if (self.claim_state_path) |path| self.allocator.free(path);
    }

    fn detectSubagentManager(tools: []const Tool) ?*@import("subagent.zig").SubagentManager {
        for (tools) |tool| {
            if (!std.mem.eql(u8, tool.name(), "spawn")) continue;
            const spawn_tool: *tools_mod.spawn.SpawnTool = @ptrCast(@alignCast(tool.ptr));
            return spawn_tool.manager;
        }
        return null;
    }

    fn secureEql(a: []const u8, b: []const u8) bool {
        const max_len = @max(a.len, b.len);
        var diff: u8 = @intFromBool(a.len != b.len);
        var i: usize = 0;
        while (i < max_len) : (i += 1) {
            const av: u8 = if (i < a.len) a[i] else 0;
            const bv: u8 = if (i < b.len) b[i] else 0;
            diff |= av ^ bv;
        }
        return diff == 0;
    }

    fn parseClaimToken(token: []const u8) ?ClaimToken {
        var parts = std.mem.splitScalar(u8, token, ':');
        const version = parts.next() orelse return null;
        const expires_raw = parts.next() orelse return null;
        const canonical = parts.next() orelse return null;
        const nonce = parts.next() orelse return null;
        const sig_hex = parts.next() orelse return null;
        if (parts.next() != null) return null;

        if (!std.mem.eql(u8, version, "v1")) return null;
        if (canonical.len == 0 or nonce.len == 0 or sig_hex.len != 64) return null;

        for (canonical) |ch| {
            if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.')) return null;
        }
        for (nonce) |ch| {
            if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.')) return null;
        }
        for (sig_hex) |ch| {
            if (!std.ascii.isHex(ch)) return null;
        }

        const expires_at = std.fmt.parseInt(i64, expires_raw, 10) catch return null;
        return .{
            .expires_at = expires_at,
            .canonical_user_id = canonical,
            .nonce = nonce,
            .signature_hex = sig_hex,
        };
    }

    fn decodeHex32(hex: []const u8) ?[32]u8 {
        if (hex.len != 64) return null;
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            const off = i * 2;
            out[i] = std.fmt.parseInt(u8, hex[off .. off + 2], 16) catch return null;
        }
        return out;
    }

    fn claimSecret(self: *const SessionManager) ?[]const u8 {
        const secret = self.config.session.claim_secret orelse return null;
        const trimmed = std.mem.trim(u8, secret, " \t\r\n");
        if (trimmed.len == 0) return null;
        return trimmed;
    }

    fn claimAdminSecret(self: *const SessionManager) ?[]const u8 {
        const secret = self.config.session.claim_admin_secret orelse return null;
        const trimmed = std.mem.trim(u8, secret, " \t\r\n");
        if (trimmed.len == 0) return null;
        return trimmed;
    }

    fn claimGateEnabled(self: *const SessionManager) bool {
        return self.config.session.auto_provision_direct_agents and self.claimSecret() != null;
    }

    fn claimBindingKeyOwned(self: *SessionManager, channel: []const u8, account_id: []const u8, peer_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}\x1f{s}\x1f{s}", .{ channel, account_id, peer_id });
    }

    fn splitClaimBindingKey(key: []const u8) ?struct { channel: []const u8, account_id: []const u8, peer_id: []const u8 } {
        const first_sep = std.mem.indexOfScalar(u8, key, 0x1f) orelse return null;
        if (first_sep == 0 or first_sep + 1 >= key.len) return null;
        const rest = key[first_sep + 1 ..];
        const second_rel = std.mem.indexOfScalar(u8, rest, 0x1f) orelse {
            return .{
                .channel = key[0..first_sep],
                .account_id = "default",
                .peer_id = rest,
            };
        };
        if (second_rel == 0 or second_rel + 1 >= rest.len) return null;
        return .{
            .channel = key[0..first_sep],
            .account_id = rest[0..second_rel],
            .peer_id = rest[second_rel + 1 ..],
        };
    }

    fn parseAgentIdFromSessionKey(session_key: []const u8) []const u8 {
        return sessionAgentId(session_key) orelse "main";
    }

    fn parseChannelFromSessionKey(session_key: []const u8) ?[]const u8 {
        if (std.mem.startsWith(u8, session_key, "agent:")) {
            var rest = session_key["agent:".len..];
            const agent_sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
            rest = rest[agent_sep + 1 ..];
            const seg_sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
            const candidate = rest[0..seg_sep];
            if (std.mem.eql(u8, candidate, "main") or
                std.mem.eql(u8, candidate, "direct") or
                std.mem.eql(u8, candidate, "group") or
                std.mem.eql(u8, candidate, "channel") or
                std.mem.eql(u8, candidate, "room"))
            {
                return null;
            }
            return candidate;
        }
        const sep = std.mem.indexOfScalar(u8, session_key, ':') orelse return null;
        if (sep == 0) return null;
        return session_key[0..sep];
    }

    fn parseAccountIdFromSessionKey(session_key: []const u8) ?[]const u8 {
        if (!std.mem.startsWith(u8, session_key, "agent:")) return null;
        var rest = session_key["agent:".len..];
        const agent_sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        rest = rest[agent_sep + 1 ..];

        const first_sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        const first = rest[0..first_sep];
        if (std.mem.eql(u8, first, "main") or
            std.mem.eql(u8, first, "direct") or
            std.mem.eql(u8, first, "group") or
            std.mem.eql(u8, first, "channel") or
            std.mem.eql(u8, first, "room"))
        {
            return null;
        }

        rest = rest[first_sep + 1 ..];
        const second_sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        const second = rest[0..second_sep];
        if (std.mem.eql(u8, second, "direct") or
            std.mem.eql(u8, second, "group") or
            std.mem.eql(u8, second, "channel") or
            std.mem.eql(u8, second, "room"))
        {
            return null;
        }
        return second;
    }

    fn parsePeerIdFromSessionKey(session_key: []const u8) ?[]const u8 {
        const markers = [_][]const u8{
            ":direct:",
            ":group:",
            ":channel:",
            ":room:",
        };
        for (markers) |marker| {
            const marker_idx = std.mem.indexOf(u8, session_key, marker) orelse continue;
            const start = marker_idx + marker.len;
            if (start >= session_key.len) continue;
            var end = session_key.len;
            if (std.mem.indexOfPos(u8, session_key, start, ":thread:")) |thread_idx| {
                end = thread_idx;
            }
            if (end > start) return session_key[start..end];
        }
        return null;
    }

    fn directContextForClaims(session_key: []const u8, conversation_context: ?ConversationContext) ?ClaimDirectContext {
        const is_direct = if (conversation_context) |ctx|
            if (ctx.is_group) |is_group| !is_group else std.mem.indexOf(u8, session_key, ":direct:") != null
        else
            std.mem.indexOf(u8, session_key, ":direct:") != null;
        if (!is_direct) return null;

        const peer_id = (if (conversation_context) |ctx|
            (ctx.peer_id orelse parsePeerIdFromSessionKey(session_key))
        else
            parsePeerIdFromSessionKey(session_key)) orelse return null;
        const channel = if (conversation_context) |ctx|
            (ctx.channel orelse parseChannelFromSessionKey(session_key) orelse "unknown")
        else
            parseChannelFromSessionKey(session_key) orelse "unknown";
        const account_id = if (conversation_context) |ctx|
            (ctx.account_id orelse parseAccountIdFromSessionKey(session_key) orelse "default")
        else
            parseAccountIdFromSessionKey(session_key) orelse "default";
        return .{ .channel = channel, .account_id = account_id, .peer_id = peer_id };
    }

    fn clearExpiredClaimNoncesLocked(self: *SessionManager, now_ts: i64) void {
        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.used_claim_nonces.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* <= now_ts) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.used_claim_nonces.fetchRemove(key)) |entry| {
                self.allocator.free(entry.key);
            }
        }
    }

    fn evictClaimAttemptLocked(self: *SessionManager, binding_key: []const u8) bool {
        if (self.claim_attempts.fetchRemove(binding_key)) |entry| {
            self.allocator.free(entry.key);
            return true;
        }
        return false;
    }

    fn claimAttemptStatusLocked(self: *SessionManager, binding_key: []const u8, now_ts: i64) ?ClaimAttempt {
        const attempt = self.claim_attempts.getPtr(binding_key) orelse return null;
        if (attempt.locked_until > now_ts) return attempt.*;
        if (attempt.failures == 0) {
            _ = self.evictClaimAttemptLocked(binding_key);
            return null;
        }
        return attempt.*;
    }

    fn registerClaimFailureLocked(self: *SessionManager, binding_key: []const u8, now_ts: i64) void {
        const max_attempts: u32 = @max(1, self.config.session.claim_max_attempts);
        const lockout_secs: i64 = @intCast(@max(1, self.config.session.claim_lockout_secs));

        if (self.claim_attempts.getPtr(binding_key)) |attempt| {
            if (attempt.locked_until > now_ts) return;
            attempt.failures += 1;
            if (attempt.failures >= max_attempts) {
                attempt.failures = 0;
                attempt.locked_until = now_ts + lockout_secs;
            }
            return;
        }

        const owned_key = self.allocator.dupe(u8, binding_key) catch return;
        var attempt = ClaimAttempt{ .failures = 1, .locked_until = 0 };
        if (attempt.failures >= max_attempts) {
            attempt.failures = 0;
            attempt.locked_until = now_ts + lockout_secs;
        }
        self.claim_attempts.put(self.allocator, owned_key, attempt) catch {
            self.allocator.free(owned_key);
        };
    }

    fn putClaimNonceLocked(self: *SessionManager, nonce: []const u8, expires_at: i64) void {
        if (self.used_claim_nonces.getPtr(nonce)) |existing| {
            existing.* = expires_at;
            return;
        }
        const owned_nonce = self.allocator.dupe(u8, nonce) catch return;
        self.used_claim_nonces.put(self.allocator, owned_nonce, expires_at) catch {
            self.allocator.free(owned_nonce);
        };
    }

    fn setVerifiedBindingLocked(self: *SessionManager, channel: []const u8, account_id: []const u8, peer_id: []const u8, canonical_user_id: []const u8, verified_at: i64) void {
        const key = self.claimBindingKeyOwned(channel, account_id, peer_id) catch return;
        if (self.verified_bindings.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value.canonical_user_id);
        }

        const canonical_owned = self.allocator.dupe(u8, canonical_user_id) catch {
            self.allocator.free(key);
            return;
        };
        self.verified_bindings.put(self.allocator, key, .{
            .canonical_user_id = canonical_owned,
            .verified_at = verified_at,
        }) catch {
            self.allocator.free(canonical_owned);
            self.allocator.free(key);
        };
    }

    fn removeVerifiedBindingLocked(self: *SessionManager, channel: []const u8, account_id: []const u8, peer_id: []const u8) bool {
        const key = self.claimBindingKeyOwned(channel, account_id, peer_id) catch return false;
        defer self.allocator.free(key);
        if (self.verified_bindings.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value.canonical_user_id);
            return true;
        }
        return false;
    }

    fn hmacClaimPayload(self: *SessionManager, expires_at: i64, canonical_user_id: []const u8, nonce: []const u8) ?[32]u8 {
        const secret = self.claimSecret() orelse return null;
        const payload = std.fmt.allocPrint(self.allocator, "v1:{d}:{s}:{s}", .{ expires_at, canonical_user_id, nonce }) catch return null;
        defer self.allocator.free(payload);

        var mac: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(mac[0..], payload, secret);
        return mac;
    }

    fn verifyClaimTokenLocked(self: *SessionManager, token_raw: []const u8, now_ts: i64) ?ClaimToken {
        const token = parseClaimToken(token_raw) orelse return null;
        if (token.expires_at <= now_ts) return null;

        self.clearExpiredClaimNoncesLocked(now_ts);
        if (self.used_claim_nonces.get(token.nonce)) |_| {
            return null;
        }

        const provided_sig = decodeHex32(token.signature_hex) orelse return null;
        const expected_sig = self.hmacClaimPayload(token.expires_at, token.canonical_user_id, token.nonce) orelse return null;
        if (!std.crypto.timing_safe.eql([32]u8, expected_sig, provided_sig)) return null;
        return token;
    }

    fn loadClaimState(self: *SessionManager) void {
        if (self.claim_state_loaded) return;
        self.claim_state_loaded = true;
        const path = self.claim_state_path orelse return;

        const file = std.fs.openFileAbsolute(path, .{}) catch return;
        defer file.close();
        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const root = parsed.value.object;

        const now_ts = std.time.timestamp();

        if (root.get("bindings")) |bindings_val| {
            if (bindings_val == .array) {
                for (bindings_val.array.items) |item| {
                    if (item != .object) continue;
                    const channel_v = item.object.get("channel") orelse continue;
                    const peer_v = item.object.get("peer_id") orelse continue;
                    const canonical_v = item.object.get("canonical_user_id") orelse continue;
                    if (channel_v != .string or peer_v != .string or canonical_v != .string) continue;
                    const verified_at: i64 = blk: {
                        const ts_v = item.object.get("verified_at") orelse break :blk now_ts;
                        if (ts_v == .integer) break :blk ts_v.integer;
                        break :blk now_ts;
                    };
                    const account_id = if (item.object.get("account_id")) |account_v|
                        if (account_v == .string and account_v.string.len > 0) account_v.string else "default"
                    else
                        "default";
                    self.setVerifiedBindingLocked(channel_v.string, account_id, peer_v.string, canonical_v.string, verified_at);
                }
            }
        }

        if (root.get("used_nonces")) |nonces_val| {
            if (nonces_val == .array) {
                for (nonces_val.array.items) |item| {
                    if (item != .object) continue;
                    const nonce_v = item.object.get("nonce") orelse continue;
                    const expires_v = item.object.get("expires_at") orelse continue;
                    if (nonce_v != .string or expires_v != .integer) continue;
                    if (expires_v.integer <= now_ts) continue;
                    self.putClaimNonceLocked(nonce_v.string, expires_v.integer);
                }
            }
        }

        if (root.get("attempts")) |attempts_val| {
            if (attempts_val == .array) {
                for (attempts_val.array.items) |item| {
                    if (item != .object) continue;
                    const channel_v = item.object.get("channel") orelse continue;
                    const peer_v = item.object.get("peer_id") orelse continue;
                    if (channel_v != .string or peer_v != .string) continue;
                    const account_id = if (item.object.get("account_id")) |account_v|
                        if (account_v == .string and account_v.string.len > 0) account_v.string else "default"
                    else
                        "default";
                    const key = self.claimBindingKeyOwned(channel_v.string, account_id, peer_v.string) catch continue;
                    const failures: u32 = blk: {
                        const fv = item.object.get("failures") orelse break :blk 0;
                        if (fv == .integer and fv.integer > 0) break :blk @intCast(fv.integer);
                        break :blk 0;
                    };
                    const locked_until: i64 = blk: {
                        const lv = item.object.get("locked_until") orelse break :blk 0;
                        if (lv == .integer and lv.integer > now_ts) break :blk lv.integer;
                        break :blk 0;
                    };
                    if (failures == 0 and locked_until == 0) {
                        self.allocator.free(key);
                        continue;
                    }
                    self.claim_attempts.put(self.allocator, key, .{
                        .failures = failures,
                        .locked_until = locked_until,
                    }) catch self.allocator.free(key);
                }
            }
        }
    }

    fn markClaimStateDirtyLocked(self: *SessionManager) void {
        self.claim_state_generation += 1;
    }

    fn captureClaimStateSnapshotLocked(self: *SessionManager) ?ClaimStateSnapshot {
        if (self.claim_state_path == null) return null;
        if (self.claim_state_generation <= self.claim_state_persisted_generation) return null;

        const now_ts = std.time.timestamp();
        self.clearExpiredClaimNoncesLocked(now_ts);

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        w.print("{{\"version\":{d},\"bindings\":[", .{CLAIM_STATE_VERSION}) catch return null;

        var wrote_binding = false;
        var binding_it = self.verified_bindings.iterator();
        while (binding_it.next()) |entry| {
            const split = splitClaimBindingKey(entry.key_ptr.*) orelse continue;
            if (wrote_binding) w.writeAll(",") catch return null;
            w.print(
                "{{\"channel\":{f},\"account_id\":{f},\"peer_id\":{f},\"canonical_user_id\":{f},\"verified_at\":{d}}}",
                .{
                    std.json.fmt(split.channel, .{}),
                    std.json.fmt(split.account_id, .{}),
                    std.json.fmt(split.peer_id, .{}),
                    std.json.fmt(entry.value_ptr.canonical_user_id, .{}),
                    entry.value_ptr.verified_at,
                },
            ) catch return null;
            wrote_binding = true;
        }

        w.writeAll("],\"used_nonces\":[") catch return null;
        var wrote_nonce = false;
        var nonce_it = self.used_claim_nonces.iterator();
        while (nonce_it.next()) |entry| {
            if (entry.value_ptr.* <= now_ts) continue;
            if (wrote_nonce) w.writeAll(",") catch return null;
            w.print(
                "{{\"nonce\":{f},\"expires_at\":{d}}}",
                .{
                    std.json.fmt(entry.key_ptr.*, .{}),
                    entry.value_ptr.*,
                },
            ) catch return null;
            wrote_nonce = true;
        }

        w.writeAll("],\"attempts\":[") catch return null;
        var wrote_attempt = false;
        var attempt_it = self.claim_attempts.iterator();
        while (attempt_it.next()) |entry| {
            const attempt = entry.value_ptr.*;
            if (attempt.failures == 0 and attempt.locked_until <= now_ts) continue;
            const split = splitClaimBindingKey(entry.key_ptr.*) orelse continue;
            if (wrote_attempt) w.writeAll(",") catch return null;
            w.print(
                "{{\"channel\":{f},\"account_id\":{f},\"peer_id\":{f},\"failures\":{d},\"locked_until\":{d}}}",
                .{
                    std.json.fmt(split.channel, .{}),
                    std.json.fmt(split.account_id, .{}),
                    std.json.fmt(split.peer_id, .{}),
                    attempt.failures,
                    attempt.locked_until,
                },
            ) catch return null;
            wrote_attempt = true;
        }

        w.writeAll("]}") catch return null;
        const content = buf.toOwnedSlice(self.allocator) catch return null;
        return .{
            .generation = self.claim_state_generation,
            .content = content,
        };
    }

    fn persistClaimStateSnapshot(self: *SessionManager, snapshot: ?ClaimStateSnapshot) void {
        const claim_snapshot = snapshot orelse return;
        defer self.allocator.free(claim_snapshot.content);

        const path = self.claim_state_path orelse return;

        self.claim_state_io_mutex.lock();
        defer self.claim_state_io_mutex.unlock();

        self.mutex.lock();
        const is_stale = claim_snapshot.generation <= self.claim_state_persisted_generation;
        self.mutex.unlock();
        if (is_stale) return;

        if (std.fs.path.dirname(path)) |parent| {
            std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    std.fs.cwd().makePath(parent) catch return;
                },
            };
        }

        const tmp_path = std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path}) catch return;
        defer self.allocator.free(tmp_path);

        var tmp_file = std.fs.createFileAbsolute(tmp_path, .{}) catch return;
        tmp_file.writeAll(claim_snapshot.content) catch {
            tmp_file.close();
            std.fs.deleteFileAbsolute(tmp_path) catch {};
            return;
        };
        tmp_file.close();

        std.fs.renameAbsolute(tmp_path, path) catch {
            std.fs.deleteFileAbsolute(tmp_path) catch {};
            const file = std.fs.createFileAbsolute(path, .{ .truncate = true }) catch return;
            defer file.close();
            file.writeAll(claim_snapshot.content) catch return;
        };

        self.mutex.lock();
        if (claim_snapshot.generation > self.claim_state_persisted_generation) {
            self.claim_state_persisted_generation = claim_snapshot.generation;
        }
        self.mutex.unlock();
    }

    fn claimTokenArg(message: []const u8) ?[]const u8 {
        const trimmed = std.mem.trim(u8, message, " \t\r\n");
        if (!std.mem.startsWith(u8, trimmed, "/claim")) return null;
        if (trimmed.len == "/claim".len) return null;
        if (trimmed["/claim".len] != ' ' and trimmed["/claim".len] != '\t') return null;
        const arg = std.mem.trim(u8, trimmed["/claim".len + 1 ..], " \t\r\n");
        if (arg.len == 0) return null;
        return arg;
    }

    fn revokeSecretArg(message: []const u8) ?[]const u8 {
        const trimmed = std.mem.trim(u8, message, " \t\r\n");
        if (!std.mem.startsWith(u8, trimmed, "/revoke")) return null;
        if (trimmed.len == "/revoke".len) return null;
        if (trimmed["/revoke".len] != ' ' and trimmed["/revoke".len] != '\t') return null;
        const arg = std.mem.trim(u8, trimmed["/revoke".len + 1 ..], " \t\r\n");
        if (arg.len == 0) return null;
        return arg;
    }

    fn maybeHandleClaimGate(
        self: *SessionManager,
        session_key: []const u8,
        content: []const u8,
        conversation_context: ?ConversationContext,
    ) ?[]const u8 {
        if (!self.claimGateEnabled()) return null;
        if (!std.mem.startsWith(u8, parseAgentIdFromSessionKey(session_key), "peer-")) return null;

        const direct_ctx = directContextForClaims(session_key, conversation_context) orelse return null;
        const now_ts = std.time.timestamp();

        if (revokeSecretArg(content)) |provided_revoke_secret| {
            const admin_secret = self.claimAdminSecret() orelse {
                return self.allocator.dupe(
                    u8,
                    "Revocation is disabled. Configure session.claim_admin_secret to enable /revoke.",
                ) catch null;
            };
            if (!secureEql(provided_revoke_secret, admin_secret)) {
                return self.allocator.dupe(u8, "Invalid revoke secret.") catch null;
            }

            var removed = false;
            var snapshot: ?ClaimStateSnapshot = null;
            self.mutex.lock();
            removed = self.removeVerifiedBindingLocked(direct_ctx.channel, direct_ctx.account_id, direct_ctx.peer_id);
            const attempt_key = self.claimBindingKeyOwned(direct_ctx.channel, direct_ctx.account_id, direct_ctx.peer_id) catch null;
            var cleared_attempts = false;
            if (attempt_key) |k| {
                cleared_attempts = self.evictClaimAttemptLocked(k);
                self.allocator.free(k);
            }
            if (removed or cleared_attempts) {
                self.markClaimStateDirtyLocked();
                snapshot = self.captureClaimStateSnapshotLocked();
            }
            self.mutex.unlock();
            self.persistClaimStateSnapshot(snapshot);

            if (removed) {
                return self.allocator.dupe(u8, "Identity link revoked. This peer is back in gatekeeper mode.") catch null;
            }
            return self.allocator.dupe(u8, "No active identity link was found for this peer.") catch null;
        }

        const claim_token = claimTokenArg(content);
        const binding_key = self.claimBindingKeyOwned(direct_ctx.channel, direct_ctx.account_id, direct_ctx.peer_id) catch return null;
        defer self.allocator.free(binding_key);

        self.mutex.lock();
        if (self.verified_bindings.get(binding_key)) |_| {
            self.mutex.unlock();
            if (claim_token != null) {
                return self.allocator.dupe(u8, "This peer is already verified.") catch null;
            }
            return null;
        }

        if (self.claimAttemptStatusLocked(binding_key, now_ts)) |attempt| {
            if (attempt.locked_until > now_ts) {
                self.mutex.unlock();
                const remaining = @as(u64, @intCast(attempt.locked_until - now_ts));
                return std.fmt.allocPrint(
                    self.allocator,
                    "Too many failed claim attempts. Try again in {d} seconds.",
                    .{remaining},
                ) catch null;
            }
        }

        if (claim_token) |raw_token| {
            const verified = self.verifyClaimTokenLocked(raw_token, now_ts);
            if (verified) |token| {
                self.setVerifiedBindingLocked(
                    direct_ctx.channel,
                    direct_ctx.account_id,
                    direct_ctx.peer_id,
                    token.canonical_user_id,
                    now_ts,
                );
                self.putClaimNonceLocked(token.nonce, token.expires_at);
                _ = self.evictClaimAttemptLocked(binding_key);
                self.markClaimStateDirtyLocked();
                const snapshot = self.captureClaimStateSnapshotLocked();
                self.mutex.unlock();
                self.persistClaimStateSnapshot(snapshot);
                return std.fmt.allocPrint(
                    self.allocator,
                    "Identity verified as '{s}'. Dedicated agent runtime unlocked.",
                    .{token.canonical_user_id},
                ) catch null;
            }

            self.registerClaimFailureLocked(binding_key, now_ts);
            self.markClaimStateDirtyLocked();
            const snapshot = self.captureClaimStateSnapshotLocked();
            self.mutex.unlock();
            self.persistClaimStateSnapshot(snapshot);
            return self.allocator.dupe(
                u8,
                "Invalid or expired claim token. Use `/claim v1:<exp>:<canonical>:<nonce>:<hmac_sha256_hex>`.",
            ) catch null;
        }

        self.mutex.unlock();
        return self.allocator.dupe(
            u8,
            "Identity verification required before agent provisioning. Send `/claim <token>` to continue.",
        ) catch null;
    }

    fn setTurnToolContext(
        tools: []const Tool,
        session_key: []const u8,
        conversation_context: ?ConversationContext,
    ) void {
        const channel = if (conversation_context) |ctx| (ctx.channel orelse parseChannelFromSessionKey(session_key)) else parseChannelFromSessionKey(session_key);
        const chat_id = parsePeerIdFromSessionKey(session_key);
        const account_id = if (conversation_context) |ctx| ctx.account_id else null;

        for (tools) |tool| {
            if (std.mem.eql(u8, tool.name(), "schedule")) {
                const schedule_tool: *tools_mod.schedule.ScheduleTool = @ptrCast(@alignCast(tool.ptr));
                schedule_tool.setContext(channel, account_id, chat_id);
            }
        }
    }

    fn shouldUseDedicatedRuntime(self: *SessionManager, agent_id: []const u8, named_agent: ?NamedAgentConfig) bool {
        if (named_agent) |cfg| {
            if (cfg.workspace_path != null) return true;
        }
        return self.config.session.auto_provision_direct_agents and std.mem.startsWith(u8, agent_id, "peer-");
    }

    fn sanitizePathComponent(allocator: Allocator, value: []const u8) ![]u8 {
        var trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len == 0) trimmed = "default";
        var out = try allocator.alloc(u8, trimmed.len);
        for (trimmed, 0..) |ch, idx| {
            out[idx] = if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.') ch else '_';
        }
        return out;
    }

    fn resolveAgentWorkspaceDir(self: *SessionManager, agent_id: []const u8, named_agent: ?NamedAgentConfig) ![]const u8 {
        if (named_agent) |cfg| {
            if (cfg.workspace_path) |workspace_path| {
                return self.config.resolveAgentWorkspacePath(self.allocator, workspace_path);
            }
        }

        const config_dir = std.fs.path.dirname(self.config.config_path) orelse ".";
        const normalized = try sanitizePathComponent(self.allocator, agent_id);
        defer self.allocator.free(normalized);
        return std.fs.path.join(self.allocator, &.{ config_dir, "agents", normalized, "workspace" });
    }

    fn makeAgentConfig(base: *const Config, workspace_dir: []const u8, named_agent: ?NamedAgentConfig) Config {
        var cfg = base.*;
        cfg.workspace_dir = workspace_dir;
        if (named_agent) |agent_cfg| {
            cfg.default_provider = agent_cfg.provider;
            cfg.default_model = agent_cfg.model;
            if (agent_cfg.temperature) |t| cfg.default_temperature = t;
        }
        cfg.syncFlatFields();
        return cfg;
    }

    fn createAgentRuntime(
        self: *SessionManager,
        agent_id: []const u8,
        named_agent: ?NamedAgentConfig,
    ) !*AgentRuntime {
        const runtime = try self.allocator.create(AgentRuntime);
        errdefer self.allocator.destroy(runtime);

        const owned_agent_id = try self.allocator.dupe(u8, agent_id);
        errdefer self.allocator.free(owned_agent_id);

        const workspace_dir = try self.resolveAgentWorkspaceDir(agent_id, named_agent);
        errdefer self.allocator.free(workspace_dir);

        var mem_rt = memory_mod.initRuntime(self.allocator, &self.config.memory, workspace_dir);
        errdefer if (mem_rt) |*rt| rt.deinit();

        const mem_opt: ?Memory = if (mem_rt) |rt| rt.memory else null;
        const session_store: ?memory_mod.SessionStore = if (mem_rt) |rt| rt.session_store else null;
        const response_cache: ?*memory_mod.cache.ResponseCache = if (mem_rt) |*rt| rt.response_cache else null;

        const bootstrap_provider = bootstrap_mod.createProvider(
            self.allocator,
            self.config.memory.backend,
            mem_opt,
            workspace_dir,
        ) catch null;
        errdefer if (bootstrap_provider) |bp| bp.deinit();

        var project_ctx = onboard.ProjectContext{};
        onboard.scaffoldWorkspace(self.allocator, workspace_dir, &project_ctx, bootstrap_provider) catch {};

        const runtime_tools = tools_mod.allTools(self.allocator, workspace_dir, .{
            .http_enabled = self.config.http_request.enabled,
            .http_allowed_domains = self.config.http_request.allowed_domains,
            .http_max_response_size = self.config.http_request.max_response_size,
            .http_timeout_secs = self.config.http_request.timeout_secs,
            .web_search_base_url = self.config.http_request.search_base_url,
            .web_search_provider = self.config.http_request.search_provider,
            .web_search_fallback_providers = self.config.http_request.search_fallback_providers,
            .browser_enabled = self.config.browser.enabled,
            .screenshot_enabled = true,
            .mcp_server_configs = self.config.mcp_servers,
            .agents = self.config.agents,
            .configured_providers = self.config.providers,
            .fallback_api_key = self.config.defaultProviderKey(),
            .tools_config = self.config.tools,
            .allowed_paths = self.config.autonomy.allowed_paths,
            .policy = self.policy,
            .subagent_manager = self.subagent_manager,
            .bootstrap_provider = bootstrap_provider,
            .backend_name = self.config.memory.backend,
        }) catch &.{};
        errdefer if (runtime_tools.len > 0) tools_mod.deinitTools(self.allocator, runtime_tools);

        runtime.* = .{
            .agent_id = owned_agent_id,
            .workspace_dir = workspace_dir,
            .config = makeAgentConfig(self.config, workspace_dir, named_agent),
            .provider = self.provider,
            .tools = runtime_tools,
            .mem = mem_opt,
            .mem_rt = mem_rt,
            .session_store = session_store,
            .response_cache = response_cache,
            .bootstrap_provider = bootstrap_provider,
        };

        tools_mod.bindMemoryTools(runtime.tools, runtime.mem);
        if (runtime.mem_rt) |*rt| {
            tools_mod.bindMemoryRuntime(runtime.tools, rt);
        }

        return runtime;
    }

    fn getOrCreateAgentRuntimeLocked(self: *SessionManager, agent_id: []const u8, named_agent: ?NamedAgentConfig) !*AgentRuntime {
        if (self.agent_runtimes.get(agent_id)) |runtime| return runtime;

        const runtime = try self.createAgentRuntime(agent_id, named_agent);
        errdefer {
            runtime.deinit(self.allocator);
            self.allocator.destroy(runtime);
        }
        try self.agent_runtimes.put(self.allocator, runtime.agent_id, runtime);
        return runtime;
    }

    fn pruneUnusedAgentRuntimesLocked(self: *SessionManager) void {
        if (self.agent_runtimes.count() == 0) return;

        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var runtime_it = self.agent_runtimes.iterator();
        while (runtime_it.next()) |entry| {
            const runtime_agent_id = entry.key_ptr.*;
            var in_use = false;

            var session_it = self.sessions.iterator();
            while (session_it.next()) |session_entry| {
                const session_agent_id = parseAgentIdFromSessionKey(session_entry.key_ptr.*);
                if (std.mem.eql(u8, session_agent_id, runtime_agent_id)) {
                    in_use = true;
                    break;
                }
            }

            if (!in_use) {
                to_remove.append(self.allocator, runtime_agent_id) catch continue;
            }
        }

        for (to_remove.items) |agent_id| {
            if (self.agent_runtimes.fetchRemove(agent_id)) |entry| {
                entry.value.deinit(self.allocator);
                self.allocator.destroy(entry.value);
            }
        }
    }

    /// Find or create a session for the given key. Thread-safe.
    pub fn getOrCreate(self: *SessionManager, session_key: []const u8) !*Session {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.get(session_key)) |session| {
            session.last_active = std.time.timestamp();
            return session;
        }

        // Create new session
        const owned_key = try self.allocator.dupe(u8, session_key);
        var key_owned_by_session = false;
        errdefer if (!key_owned_by_session) self.allocator.free(owned_key);

        const session = try self.allocator.create(Session);
        session.provider_holder = null;
        session.owned_provider_api_key = null;
        var session_initialized = false;
        errdefer {
            if (session_initialized) session.deinit(self.allocator);
            self.allocator.destroy(session);
        }
        errdefer if (!session_initialized) {
            if (session.provider_holder) |*holder| holder.deinit();
            if (session.owned_provider_api_key) |key| self.allocator.free(key);
        };

        const agent_profile = findProfileForSessionKey(self.config, session_key);
        const parsed_agent_id = parseAgentIdFromSessionKey(session_key);
        const dedicated_runtime = if (self.shouldUseDedicatedRuntime(parsed_agent_id, agent_profile))
            try self.getOrCreateAgentRuntimeLocked(parsed_agent_id, agent_profile)
        else
            null;

        const selected_config: *const Config = if (dedicated_runtime) |rt| &rt.config else self.config;
        const selected_tools: []const Tool = if (dedicated_runtime) |rt| rt.tools else self.tools;
        const selected_mem: ?Memory = if (dedicated_runtime) |rt| rt.mem else self.mem;
        const selected_session_store: ?memory_mod.SessionStore = if (dedicated_runtime) |rt| rt.session_store else self.session_store;
        const selected_response_cache: ?*memory_mod.cache.ResponseCache = if (dedicated_runtime) |rt| rt.response_cache else self.response_cache;
        const selected_mem_rt: ?*memory_mod.MemoryRuntime = if (dedicated_runtime) |rt|
            (if (rt.mem_rt) |*v| v else null)
        else
            self.mem_rt;

        var provider_ctx = try self.resolveProviderForSession(agent_profile);
        errdefer provider_ctx.deinit(self.allocator);

        session.* = undefined;
        session.provider_holder = provider_ctx.holder;
        session.owned_provider_api_key = provider_ctx.owned_api_key;
        provider_ctx.holder = null;
        provider_ctx.owned_api_key = null;

        const session_provider = if (session.provider_holder) |*holder|
            holder.provider()
        else
            provider_ctx.provider;

        var agent = try Agent.fromConfigWithProfile(
            self.allocator,
            selected_config,
            session_provider,
            selected_tools,
            selected_mem,
            self.observer,
            agent_profile,
        );
        agent.policy = self.policy;
        agent.session_store = selected_session_store;
        agent.response_cache = selected_response_cache;
        agent.mem_rt = selected_mem_rt;
        agent.memory_session_id = owned_key;
        var owned_memory_session_id: ?[]u8 = null;
        errdefer if (owned_memory_session_id) |sid| self.allocator.free(sid);
        if (agent_profile) |profile| {
            if (profile.workspace_path != null) {
                if (sessionAgentId(session_key)) |agent_id| {
                    owned_memory_session_id = try std.fmt.allocPrint(self.allocator, "agent:{s}", .{agent_id});
                    agent.memory_session_id = owned_memory_session_id.?;
                }
            }
        }
        if (self.config.diagnostics.token_usage_ledger_enabled) {
            agent.usage_record_callback = usageRecordForwarder;
            agent.usage_record_ctx = @ptrCast(self);
        }

        const session_provider_holder = session.provider_holder;
        const session_owned_provider_api_key = session.owned_provider_api_key;
        session.* = .{
            .agent = agent,
            .provider_holder = session_provider_holder,
            .owned_provider_api_key = session_owned_provider_api_key,
            .owned_memory_session_id = owned_memory_session_id,
            .created_at = std.time.timestamp(),
            .last_active = std.time.timestamp(),
            .last_consolidated = 0,
            .session_key = owned_key,
            .turn_count = 0,
            .turn_running = std.atomic.Value(bool).init(false),
            .mutex = .{},
        };
        key_owned_by_session = true;
        session_initialized = true;

        // Restore persisted conversation history from session store
        if (selected_session_store) |store| {
            const maybe_entries = store.loadMessages(self.allocator, session_key) catch null;
            if (maybe_entries) |entries| {
                defer memory_mod.freeMessages(self.allocator, entries);
                if (entries.len > 0) {
                    restorePersistedSessionState(session, entries);
                }
                if (try store.loadUsage(session_key)) |total_tokens| {
                    session.agent.total_tokens = total_tokens;
                } else if (entries.len > 0) {
                    session.agent.total_tokens = estimateRestoredSessionTokens(entries);
                }
            }
        }

        try self.sessions.put(self.allocator, owned_key, session);
        return session;
    }

    fn resolveProviderForSession(
        self: *SessionManager,
        agent_profile: ?config_types.NamedAgentConfig,
    ) !SessionProviderContext {
        const profile = agent_profile orelse return .{ .provider = self.provider };

        var owned_api_key: ?[]u8 = null;
        errdefer if (owned_api_key) |key| self.allocator.free(key);

        const provider_api_key = profile.api_key orelse blk: {
            owned_api_key = providers.resolveApiKeyFromConfig(
                self.allocator,
                profile.provider,
                self.config.providers,
            ) catch null;
            break :blk owned_api_key;
        };

        var holder = providers.ProviderHolder.fromConfig(
            self.allocator,
            profile.provider,
            provider_api_key,
            self.config.getProviderBaseUrl(profile.provider),
            self.config.getProviderNativeTools(profile.provider),
            self.config.getProviderUserAgent(profile.provider),
        );
        return .{
            .provider = holder.provider(),
            .holder = holder,
            .owned_api_key = owned_api_key,
        };
    }

    const StreamAdapterCtx = struct {
        sink: streaming.Sink,
    };

    fn streamChunkForwarder(ctx_ptr: *anyopaque, chunk: providers.StreamChunk) void {
        const adapter: *StreamAdapterCtx = @ptrCast(@alignCast(ctx_ptr));
        streaming.forwardProviderChunk(adapter.sink, chunk);
    }

    fn usageRecordForwarder(ctx_ptr: *anyopaque, record: Agent.UsageRecord) void {
        const self: *SessionManager = @ptrCast(@alignCast(ctx_ptr));
        self.appendUsageRecord(record);
    }

    fn usageLedgerPath(self: *SessionManager) ?[]u8 {
        if (!self.config.diagnostics.token_usage_ledger_enabled) return null;
        const config_dir = std.fs.path.dirname(self.config.config_path) orelse return null;
        return std.fs.path.join(self.allocator, &.{ config_dir, TOKEN_USAGE_LEDGER_FILENAME }) catch null;
    }

    fn usageWindowSeconds(self: *SessionManager) i64 {
        const hours = self.config.diagnostics.token_usage_ledger_window_hours;
        if (hours == 0) return 0;
        return @as(i64, @intCast(hours)) * 60 * 60;
    }

    fn countLedgerLines(file: *std.fs.File) !u64 {
        try file.seekTo(0);
        var lines: u64 = 0;
        var saw_data = false;
        var last_byte: u8 = '\n';
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try file.read(&buf);
            if (n == 0) break;
            saw_data = true;
            last_byte = buf[n - 1];
            lines += @intCast(std.mem.count(u8, buf[0..n], "\n"));
        }
        if (saw_data and last_byte != '\n') lines += 1;
        return lines;
    }

    fn initializeUsageLedgerState(
        self: *SessionManager,
        file: *std.fs.File,
        stat: std.fs.File.Stat,
        now_ts: i64,
    ) void {
        if (self.usage_ledger_state_initialized) return;
        self.usage_ledger_state_initialized = true;
        if (stat.size > 0) {
            const mtime_secs: i64 = @intCast(@divFloor(stat.mtime, NS_PER_SEC));
            self.usage_ledger_window_started_at = if (mtime_secs > 0) mtime_secs else now_ts;
            if (self.config.diagnostics.token_usage_ledger_max_lines > 0) {
                self.usage_ledger_line_count = countLedgerLines(file) catch 0;
            } else {
                self.usage_ledger_line_count = 0;
            }
        } else {
            self.usage_ledger_window_started_at = now_ts;
            self.usage_ledger_line_count = 0;
        }
    }

    fn shouldResetUsageLedger(
        self: *SessionManager,
        stat: std.fs.File.Stat,
        now_ts: i64,
        pending_bytes: usize,
        pending_lines: u64,
    ) bool {
        const window_secs = self.usageWindowSeconds();
        if (window_secs > 0) {
            const started_at = self.usage_ledger_window_started_at;
            if (started_at > 0 and now_ts - started_at >= window_secs) return true;
        }

        const max_bytes = self.config.diagnostics.token_usage_ledger_max_bytes;
        if (max_bytes > 0) {
            const projected = @as(u64, @intCast(stat.size)) + @as(u64, @intCast(pending_bytes));
            if (projected > max_bytes) return true;
        }

        const max_lines = self.config.diagnostics.token_usage_ledger_max_lines;
        if (max_lines > 0 and self.usage_ledger_line_count + pending_lines > max_lines) return true;

        return false;
    }

    fn appendUsageRecord(self: *SessionManager, record: Agent.UsageRecord) void {
        self.usage_log_mutex.lock();
        defer self.usage_log_mutex.unlock();

        const ledger_path = self.usageLedgerPath() orelse return;
        defer self.allocator.free(ledger_path);

        var file = std.fs.openFileAbsolute(ledger_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => std.fs.createFileAbsolute(ledger_path, .{ .truncate = false, .read = true }) catch return,
            else => return,
        };
        var file_needs_close = true;
        defer if (file_needs_close) file.close();

        const now_ts = std.time.timestamp();
        const stat = fs_compat.stat(file) catch return;
        self.initializeUsageLedgerState(&file, stat, now_ts);

        const record_line = std.fmt.allocPrint(
            self.allocator,
            "{{\"ts\":{d},\"provider\":{f},\"model\":{f},\"prompt_tokens\":{d},\"completion_tokens\":{d},\"total_tokens\":{d},\"success\":{}}}\n",
            .{
                record.ts,
                std.json.fmt(record.provider, .{}),
                std.json.fmt(record.model, .{}),
                record.usage.prompt_tokens,
                record.usage.completion_tokens,
                record.usage.total_tokens,
                record.success,
            },
        ) catch return;
        defer self.allocator.free(record_line);

        const pending_bytes: usize = record_line.len;
        if (self.shouldResetUsageLedger(stat, now_ts, pending_bytes, 1)) {
            file.close();
            file_needs_close = false;
            file = std.fs.createFileAbsolute(ledger_path, .{ .truncate = true, .read = true }) catch return;
            file_needs_close = true;
            self.usage_ledger_state_initialized = true;
            self.usage_ledger_window_started_at = now_ts;
            self.usage_ledger_line_count = 0;
        }

        // Zig 0.15 buffered File.writer ignores manual seek position for append-style writes.
        // Use direct file.writeAll after seek to guarantee true append semantics.
        file.seekFromEnd(0) catch return;
        file.writeAll(record_line) catch return;

        if (self.usage_ledger_window_started_at == 0) {
            self.usage_ledger_window_started_at = now_ts;
        }
        if (self.config.diagnostics.token_usage_ledger_max_lines > 0) {
            self.usage_ledger_line_count += 1;
        }
    }

    /// Process a message within a session context.
    /// Finds or creates the session, locks it, runs agent.turn(), returns owned response.
    pub fn processMessage(self: *SessionManager, session_key: []const u8, content: []const u8, conversation_context: ?ConversationContext) ![]const u8 {
        return self.processMessageStreaming(session_key, content, conversation_context, null);
    }

    /// Process a message within a session context and optionally forward text deltas.
    /// Deltas are only emitted when provider streaming is active.
    pub fn processMessageStreaming(
        self: *SessionManager,
        session_key: []const u8,
        content: []const u8,
        conversation_context: ?ConversationContext,
        stream_sink: ?streaming.Sink,
    ) ![]const u8 {
        const channel = if (conversation_context) |ctx| (ctx.channel orelse "unknown") else "unknown";
        const session_hash = std.hash.Wyhash.hash(0, session_key);

        if (self.config.diagnostics.log_message_receipts) {
            log.info("message receipt channel={s} session=0x{x} bytes={d}", .{ channel, session_hash, content.len });
        }
        if (self.config.diagnostics.log_message_payloads) {
            const preview = messageLogPreview(content);
            log.info(
                "message inbound channel={s} session=0x{x} bytes={d} content={f}{s}",
                .{
                    channel,
                    session_hash,
                    content.len,
                    std.json.fmt(preview.slice, .{}),
                    if (preview.truncated) " [log preview truncated]" else "",
                },
            );
        }

        if (self.maybeHandleClaimGate(session_key, content, conversation_context)) |gate_reply| {
            if (self.config.diagnostics.log_message_payloads) {
                const preview = messageLogPreview(gate_reply);
                log.info(
                    "message outbound channel={s} session=0x{x} bytes={d} content={f}{s}",
                    .{
                        channel,
                        session_hash,
                        gate_reply.len,
                        std.json.fmt(preview.slice, .{}),
                        if (preview.truncated) " [truncated]" else "",
                    },
                );
            }
            return gate_reply;
        }

        const session = try self.getOrCreate(session_key);

        session.mutex.lock();
        defer session.mutex.unlock();
        session.turn_running.store(true, .release);
        defer {
            session.turn_running.store(false, .release);
            session.agent.clearInterruptRequest();
        }

        // Set conversation context for this turn.
        session.agent.conversation_context = conversation_context;
        defer session.agent.conversation_context = null;
        setTurnToolContext(session.agent.tools, session_key, conversation_context);

        const prev_stream_callback = session.agent.stream_callback;
        const prev_stream_ctx = session.agent.stream_ctx;
        defer {
            session.agent.stream_callback = prev_stream_callback;
            session.agent.stream_ctx = prev_stream_ctx;
        }

        var stream_adapter: StreamAdapterCtx = undefined;
        if (stream_sink) |sink| {
            stream_adapter = .{ .sink = sink };
            session.agent.stream_callback = streamChunkForwarder;
            session.agent.stream_ctx = @ptrCast(&stream_adapter);
        } else {
            session.agent.stream_callback = null;
            session.agent.stream_ctx = null;
        }

        const turn_input = agent_mod.commands.planTurnInput(content);
        const response = try session.agent.turn(content);
        session.turn_count += 1;
        session.last_active = std.time.timestamp();

        // Track consolidation timestamp
        if (session.agent.last_turn_compacted) {
            session.last_consolidated = @intCast(@max(0, std.time.timestamp()));
        }

        // Persist messages via session store
        if (session.agent.session_store) |store| {
            if (turn_input.clear_session) {
                // Clear persisted messages on session reset
                store.clearMessages(session_key) catch {};
                // Clear stale auto-saved memories
                store.clearAutoSaved(session_key) catch {};
            }

            if (agent_mod.commands.persistedRuntimeCommand(content)) |runtime_command| {
                store.saveMessage(session_key, RUNTIME_COMMAND_ROLE, runtime_command) catch {};
            }

            if (turn_input.llm_user_message) |persisted_user| {
                // Persist canonical conversation history.
                // Local-only slash commands are skipped, but any input that
                // reached the LLM must persist with the exact same routing
                // decision used by Agent.turn().
                // When the turn ends with an assistant history message, prefer
                // that canonical text over the rendered reply so restored
                // sessions do not replay /usage footers or reasoning blocks.
                // Some degraded turns return a fallback response without
                // appending a final assistant history entry; in that case we
                // must persist the actual response instead of stale tool-step
                // assistant text from earlier in the turn.
                const persisted_assistant = persistedAssistantReply(&session.agent, response);
                store.saveMessage(session_key, "user", persisted_user) catch {};
                store.saveMessage(session_key, "assistant", persisted_assistant) catch {};
                store.saveUsage(session_key, session.agent.total_tokens) catch {};
            }
        }

        if (self.config.diagnostics.log_message_payloads) {
            const preview = messageLogPreview(response);
            log.info(
                "message outbound channel={s} session=0x{x} bytes={d} content={f}{s}",
                .{
                    channel,
                    session_hash,
                    response.len,
                    std.json.fmt(preview.slice, .{}),
                    if (preview.truncated) " [log preview truncated]" else "",
                },
            );
        }

        return response;
    }

    pub const InterruptRequestResult = struct {
        requested: bool = false,
        active_tool: ?[]u8 = null,

        pub fn deinit(self: *InterruptRequestResult, allocator: Allocator) void {
            if (self.active_tool) |name| allocator.free(name);
            self.active_tool = null;
        }
    };

    pub const SessionSnapshot = struct {
        session_key: []u8,
        last_active: i64,
        turn_count: u64,
        turn_running: bool,

        pub fn deinit(self: *SessionSnapshot, allocator: Allocator) void {
            allocator.free(self.session_key);
        }
    };

    /// Request interruption of a currently running turn for a session.
    /// Returns whether it was signaled and the active tool snapshot (if any).
    pub fn requestTurnInterrupt(self: *SessionManager, session_key: []const u8) InterruptRequestResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const session = self.sessions.get(session_key) orelse return .{};
        if (!session.turn_running.load(.acquire)) return .{};
        session.agent.requestInterrupt();
        return .{
            .requested = true,
            .active_tool = session.agent.snapshotActiveToolName(self.allocator) catch null,
        };
    }

    pub fn freeSessionSnapshots(allocator: Allocator, snapshots: []SessionSnapshot) void {
        for (snapshots) |*snapshot| snapshot.deinit(allocator);
        allocator.free(snapshots);
    }

    /// Snapshot active sessions for read-only status/reporting surfaces.
    /// The returned slice owns duplicated session keys and must be freed with
    /// `freeSessionSnapshots`.
    pub fn snapshotSessions(self: *SessionManager, allocator: Allocator) ![]SessionSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const count = self.sessions.count();
        const snapshots = try allocator.alloc(SessionSnapshot, count);
        errdefer allocator.free(snapshots);

        var idx: usize = 0;
        errdefer {
            for (snapshots[0..idx]) |*snapshot| snapshot.deinit(allocator);
        }

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const session = entry.value_ptr.*;
            session.mutex.lock();
            const last_active = session.last_active;
            const turn_count = session.turn_count;
            session.mutex.unlock();

            snapshots[idx] = .{
                .session_key = try allocator.dupe(u8, session.session_key),
                .last_active = last_active,
                .turn_count = turn_count,
                .turn_running = session.turn_running.load(.acquire),
            };
            idx += 1;
        }

        return snapshots;
    }

    /// Best-effort migration from a legacy session key to a new canonical key.
    /// Used for wire-format changes where we want future turns to land on the
    /// canonical key without dropping persisted transcript or session-scoped memory.
    pub fn migrateLegacySessionKey(self: *SessionManager, canonical_session_key: []const u8, legacy_session_key: ?[]const u8) void {
        const legacy = legacy_session_key orelse return;
        if (std.mem.eql(u8, canonical_session_key, legacy)) return;

        self.migrateLiveSessionKey(canonical_session_key, legacy);
        self.migrateStoredSessionTranscript(canonical_session_key, legacy);
        self.migrateScopedMemoryEntries(canonical_session_key, legacy);
    }

    fn migrateLiveSessionKey(self: *SessionManager, canonical_session_key: []const u8, legacy_session_key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.contains(canonical_session_key)) return;
        const legacy_session = self.sessions.get(legacy_session_key) orelse return;
        if (legacy_session.turn_running.load(.acquire)) return;

        const new_key = self.allocator.dupe(u8, canonical_session_key) catch return;
        if (self.sessions.fetchRemove(legacy_session_key)) |entry| {
            const session = entry.value;
            const old_key = session.session_key;

            session.session_key = new_key;
            if (session.owned_memory_session_id == null) {
                session.agent.memory_session_id = session.session_key;
            }

            self.sessions.put(self.allocator, session.session_key, session) catch {
                session.session_key = old_key;
                if (session.owned_memory_session_id == null) {
                    session.agent.memory_session_id = session.session_key;
                }
                self.sessions.put(self.allocator, old_key, session) catch {
                    log.err("failed to restore live session after canonical key migration rollback", .{});
                };
                self.allocator.free(new_key);
                return;
            };

            self.allocator.free(old_key);
        } else {
            self.allocator.free(new_key);
        }
    }

    fn migrateStoredSessionTranscript(self: *SessionManager, canonical_session_key: []const u8, legacy_session_key: []const u8) void {
        const store = self.session_store orelse return;

        const legacy_messages = store.loadMessages(self.allocator, legacy_session_key) catch return;
        defer memory_mod.freeMessages(self.allocator, legacy_messages);
        const legacy_usage = store.loadUsage(legacy_session_key) catch null;

        if (legacy_messages.len == 0 and legacy_usage == null) return;

        const canonical_messages = store.loadMessages(self.allocator, canonical_session_key) catch return;
        defer memory_mod.freeMessages(self.allocator, canonical_messages);
        const canonical_usage = store.loadUsage(canonical_session_key) catch null;

        if (canonical_messages.len > 0 or canonical_usage != null) return;

        for (legacy_messages) |entry| {
            store.saveMessage(canonical_session_key, entry.role, entry.content) catch return;
        }
        if (legacy_usage) |usage| {
            store.saveUsage(canonical_session_key, usage) catch return;
        }
        store.clearMessages(legacy_session_key) catch return;
    }

    fn migrateScopedMemoryEntries(self: *SessionManager, canonical_session_key: []const u8, legacy_session_key: []const u8) void {
        const mem = self.mem orelse return;
        if (std.mem.eql(u8, mem.name(), "markdown")) return;

        const legacy_entries = mem.list(self.allocator, null, legacy_session_key) catch return;
        defer memory_mod.freeEntries(self.allocator, legacy_entries);
        if (legacy_entries.len == 0) return;

        for (legacy_entries) |entry| {
            mem.store(entry.key, entry.content, entry.category, canonical_session_key) catch return;
            _ = mem.forgetScoped(self.allocator, entry.key, legacy_session_key) catch return;
        }
    }

    /// Number of active sessions.
    pub fn sessionCount(self: *SessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }

    pub const ReloadSkillsResult = struct {
        sessions_seen: usize = 0,
        sessions_reloaded: usize = 0,
        failures: usize = 0,
    };

    /// Reload skill-backed system prompts for all active sessions.
    /// Each session is reloaded under its own lock to avoid in-flight turn races.
    pub fn reloadSkillsAll(self: *SessionManager) ReloadSkillsResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = ReloadSkillsResult{};

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const session = entry.value_ptr.*;
            result.sessions_seen += 1;
            session.mutex.lock();
            session.agent.has_system_prompt = false;
            session.mutex.unlock();
            result.sessions_reloaded += 1;
        }

        return result;
    }

    /// Evict sessions idle longer than max_idle_secs. Returns number evicted.
    pub fn evictIdle(self: *SessionManager, max_idle_secs: u64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var evicted: usize = 0;

        // Collect keys to remove (can't modify map while iterating).
        // Active turns keep stale last_active until the turn finishes, so skip
        // any session that is currently executing.
        var to_remove: std.ArrayListUnmanaged([]const u8) = .{};
        defer to_remove.deinit(self.allocator);

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const session = entry.value_ptr.*;
            const idle_secs: u64 = @intCast(@max(0, now - session.last_active));
            if (idle_secs > max_idle_secs and !session.turn_running.load(.acquire)) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.sessions.fetchRemove(key)) |kv| {
                const session = kv.value;
                session.deinit(self.allocator);
                self.allocator.destroy(session);
                evicted += 1;
            }
        }

        if (evicted > 0) {
            self.pruneUnusedAgentRuntimesLocked();
        }

        return evicted;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// ---------------------------------------------------------------------------
// MockProvider — returns a fixed response, no network calls
// ---------------------------------------------------------------------------

const MockProvider = struct {
    response: []const u8,

    const vtable = Provider.VTable{
        .chatWithSystem = mockChatWithSystem,
        .chat = mockChat,
        .supportsNativeTools = mockSupportsNativeTools,
        .getName = mockGetName,
        .deinit = mockDeinit,
    };

    fn provider(self: *MockProvider) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn mockChatWithSystem(
        ptr: *anyopaque,
        _: Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        return self.response;
    }

    fn mockChat(
        ptr: *anyopaque,
        allocator: Allocator,
        _: providers.ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!providers.ChatResponse {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        return .{ .content = try allocator.dupe(u8, self.response) };
    }

    fn mockSupportsNativeTools(_: *anyopaque) bool {
        return false;
    }

    fn mockGetName(_: *anyopaque) []const u8 {
        return "mock";
    }

    fn mockDeinit(_: *anyopaque) void {}
};

const MockStreamingProvider = struct {
    response: []const u8,

    const vtable = Provider.VTable{
        .chatWithSystem = mockChatWithSystem,
        .chat = mockChat,
        .supportsNativeTools = mockSupportsNativeTools,
        .getName = mockGetName,
        .deinit = mockDeinit,
        .supports_streaming = mockSupportsStreaming,
        .stream_chat = mockStreamChat,
    };

    fn provider(self: *MockStreamingProvider) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn mockChatWithSystem(
        ptr: *anyopaque,
        _: Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *MockStreamingProvider = @ptrCast(@alignCast(ptr));
        return self.response;
    }

    fn mockChat(
        ptr: *anyopaque,
        allocator: Allocator,
        _: providers.ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!providers.ChatResponse {
        const self: *MockStreamingProvider = @ptrCast(@alignCast(ptr));
        return .{ .content = try allocator.dupe(u8, self.response) };
    }

    fn mockSupportsNativeTools(_: *anyopaque) bool {
        return false;
    }

    fn mockGetName(_: *anyopaque) []const u8 {
        return "mock_stream";
    }

    fn mockDeinit(_: *anyopaque) void {}

    fn mockSupportsStreaming(_: *anyopaque) bool {
        return true;
    }

    fn mockStreamChat(
        ptr: *anyopaque,
        allocator: Allocator,
        _: providers.ChatRequest,
        model: []const u8,
        _: f64,
        callback: providers.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!providers.StreamChatResult {
        const self: *MockStreamingProvider = @ptrCast(@alignCast(ptr));
        const mid = self.response.len / 2;
        if (mid > 0) callback(callback_ctx, providers.StreamChunk.textDelta(self.response[0..mid]));
        callback(callback_ctx, providers.StreamChunk.textDelta(self.response[mid..]));
        callback(callback_ctx, providers.StreamChunk.finalChunk());
        return .{
            .content = try allocator.dupe(u8, self.response),
            .model = try allocator.dupe(u8, model),
        };
    }
};

const DeltaCollector = struct {
    allocator: Allocator,
    data: std.ArrayListUnmanaged(u8) = .empty,

    fn onEvent(ctx_ptr: *anyopaque, event: streaming.Event) void {
        if (event.stage != .chunk or event.text.len == 0) return;
        const self: *DeltaCollector = @ptrCast(@alignCast(ctx_ptr));
        self.data.appendSlice(self.allocator, event.text) catch {};
    }

    fn deinit(self: *DeltaCollector) void {
        self.data.deinit(self.allocator);
    }
};

const ProbeTool = struct {
    pub const tool_name = "probe";
    pub const tool_description = "Test probe tool";
    pub const tool_params = "{}";
    const vtable = tools_mod.ToolVTable(@This());

    fn tool(self: *@This()) Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn execute(_: *@This(), allocator: Allocator, _: tools_mod.JsonObjectMap) !tools_mod.ToolResult {
        return .{ .success = true, .output = try allocator.dupe(u8, "probe ok") };
    }
};

const SummaryFailureProvider = struct {
    call_count: usize = 0,

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystem,
        .chat = chat,
        .supportsNativeTools = supportsNativeTools,
        .getName = getName,
        .deinit = deinitFn,
    };

    fn provider(self: *SummaryFailureProvider) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn chatWithSystem(
        _: *anyopaque,
        allocator: Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        return allocator.dupe(u8, "");
    }

    fn chat(
        ptr: *anyopaque,
        allocator: Allocator,
        _: providers.ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!providers.ChatResponse {
        const self: *SummaryFailureProvider = @ptrCast(@alignCast(ptr));
        self.call_count += 1;

        if (self.call_count == 1) {
            const tool_calls = try allocator.alloc(providers.ToolCall, 1);
            tool_calls[0] = .{
                .id = try allocator.dupe(u8, "call-probe"),
                .name = try allocator.dupe(u8, "probe"),
                .arguments = try allocator.dupe(u8, "{}"),
            };
            return .{
                .content = try allocator.dupe(u8, "running"),
                .tool_calls = tool_calls,
                .usage = .{},
                .model = try allocator.dupe(u8, "test-model"),
            };
        }

        return error.ProviderError;
    }

    fn supportsNativeTools(_: *anyopaque) bool {
        return true;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "summary_failure";
    }

    fn deinitFn(_: *anyopaque) void {}
};

/// Create a test SessionManager with mock provider.
fn testSessionManager(allocator: Allocator, mock: *MockProvider, cfg: *const Config) SessionManager {
    return testSessionManagerWithMemory(allocator, mock, cfg, null, null);
}

fn testSessionManagerWithMemory(allocator: Allocator, mock: *MockProvider, cfg: *const Config, mem: ?Memory, session_store: ?memory_mod.SessionStore) SessionManager {
    var noop = observability.NoopObserver{};
    return SessionManager.init(
        allocator,
        cfg,
        mock.provider(),
        &.{},
        mem,
        noop.observer(),
        session_store,
        null,
    );
}

fn testConfig() Config {
    return .{
        .workspace_dir = "/tmp/yc_test",
        .config_path = "/tmp/yc_test/config.json",
        .default_model = "test/mock-model",
        .allocator = testing.allocator,
    };
}

fn testBuildClaimToken(
    allocator: Allocator,
    secret: []const u8,
    expires_at: i64,
    canonical_user_id: []const u8,
    nonce: []const u8,
) ![]u8 {
    const payload = try std.fmt.allocPrint(allocator, "v1:{d}:{s}:{s}", .{ expires_at, canonical_user_id, nonce });
    defer allocator.free(payload);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, payload, secret);

    var sig_hex: [64]u8 = undefined;
    for (mac, 0..) |byte, i| {
        sig_hex[i * 2] = "0123456789abcdef"[byte >> 4];
        sig_hex[i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }

    return std.fmt.allocPrint(
        allocator,
        "v1:{d}:{s}:{s}:{s}",
        .{ expires_at, canonical_user_id, nonce, sig_hex[0..] },
    );
}

fn testClaimCommand(allocator: Allocator, token: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/claim {s}", .{token});
}

fn toNativePathFragment(allocator: Allocator, unix_path_fragment: []const u8) ![]u8 {
    const native = try allocator.dupe(u8, unix_path_fragment);
    if (std.fs.path.sep == '\\') {
        for (native) |*ch| {
            if (ch.* == '/') ch.* = '\\';
        }
    }
    return native;
}

fn expectPathContains(path: []const u8, unix_path_fragment: []const u8) !void {
    const native_fragment = try toNativePathFragment(testing.allocator, unix_path_fragment);
    defer testing.allocator.free(native_fragment);
    const has_unix = std.mem.indexOf(u8, path, unix_path_fragment) != null;
    const has_native = std.mem.indexOf(u8, path, native_fragment) != null;
    try testing.expect(has_unix or has_native);
}

fn expectPathEndsWith(path: []const u8, unix_path_suffix: []const u8) !void {
    const native_suffix = try toNativePathFragment(testing.allocator, unix_path_suffix);
    defer testing.allocator.free(native_suffix);
    const ends_unix = std.mem.endsWith(u8, path, unix_path_suffix);
    const ends_native = std.mem.endsWith(u8, path, native_suffix);
    try testing.expect(ends_unix or ends_native);
}

// ---------------------------------------------------------------------------
// 1. Struct tests
// ---------------------------------------------------------------------------

test "SessionManager init/deinit — no leaks" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    sm.deinit();
}

test "usage ledger appends records when retention limits are disabled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);
    const ledger_path = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ base, TOKEN_USAGE_LEDGER_FILENAME });
    defer testing.allocator.free(ledger_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.diagnostics.token_usage_ledger_enabled = true;
    cfg.diagnostics.token_usage_ledger_window_hours = 0;
    cfg.diagnostics.token_usage_ledger_max_lines = 0;
    cfg.diagnostics.token_usage_ledger_max_bytes = 0;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    sm.appendUsageRecord(.{
        .ts = 101,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 1, .completion_tokens = 1, .total_tokens = 2 },
        .success = true,
    });
    sm.appendUsageRecord(.{
        .ts = 102,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 2, .completion_tokens = 2, .total_tokens = 4 },
        .success = true,
    });

    const file = try std.fs.openFileAbsolute(ledger_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(content);

    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, content, "\n"));
    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":101") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":102") != null);
}

test "usage ledger resets when max line limit is reached" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);
    const ledger_path = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ base, TOKEN_USAGE_LEDGER_FILENAME });
    defer testing.allocator.free(ledger_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.diagnostics.token_usage_ledger_enabled = true;
    cfg.diagnostics.token_usage_ledger_window_hours = 0;
    cfg.diagnostics.token_usage_ledger_max_lines = 2;
    cfg.diagnostics.token_usage_ledger_max_bytes = 0;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    sm.appendUsageRecord(.{
        .ts = 1,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 1, .completion_tokens = 2, .total_tokens = 3 },
        .success = true,
    });
    sm.appendUsageRecord(.{
        .ts = 2,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 2, .completion_tokens = 3, .total_tokens = 5 },
        .success = true,
    });
    sm.appendUsageRecord(.{
        .ts = 3,
        .provider = "p2",
        .model = "m2",
        .usage = .{ .prompt_tokens = 3, .completion_tokens = 4, .total_tokens = 7 },
        .success = true,
    });

    const file = try std.fs.openFileAbsolute(ledger_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(content);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, content, "\n"));
    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":3") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"total_tokens\":7") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"success\":true") != null);
}

test "usage ledger resets when window expires" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);
    const ledger_path = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ base, TOKEN_USAGE_LEDGER_FILENAME });
    defer testing.allocator.free(ledger_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.diagnostics.token_usage_ledger_enabled = true;
    cfg.diagnostics.token_usage_ledger_window_hours = 1;
    cfg.diagnostics.token_usage_ledger_max_lines = 0;
    cfg.diagnostics.token_usage_ledger_max_bytes = 0;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    sm.appendUsageRecord(.{
        .ts = 10,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 1, .completion_tokens = 1, .total_tokens = 2 },
        .success = true,
    });

    sm.usage_ledger_state_initialized = true;
    sm.usage_ledger_window_started_at = std.time.timestamp() - 2 * 60 * 60;

    sm.appendUsageRecord(.{
        .ts = 11,
        .provider = "p2",
        .model = "m2",
        .usage = .{ .prompt_tokens = 2, .completion_tokens = 2, .total_tokens = 4 },
        .success = true,
    });

    const file = try std.fs.openFileAbsolute(ledger_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(content);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, content, "\n"));
    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":11") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"total_tokens\":4") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"success\":true") != null);
}

test "usage ledger resets when byte limit would be exceeded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);
    const ledger_path = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ base, TOKEN_USAGE_LEDGER_FILENAME });
    defer testing.allocator.free(ledger_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.diagnostics.token_usage_ledger_enabled = true;
    cfg.diagnostics.token_usage_ledger_window_hours = 0;
    cfg.diagnostics.token_usage_ledger_max_lines = 0;
    cfg.diagnostics.token_usage_ledger_max_bytes = 140;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    sm.appendUsageRecord(.{
        .ts = 21,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 1, .completion_tokens = 2, .total_tokens = 3 },
        .success = true,
    });
    sm.appendUsageRecord(.{
        .ts = 22,
        .provider = "p2",
        .model = "m2",
        .usage = .{ .prompt_tokens = 2, .completion_tokens = 3, .total_tokens = 5 },
        .success = true,
    });

    const file = try std.fs.openFileAbsolute(ledger_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(content);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, content, "\n"));
    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":22") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"total_tokens\":5") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"success\":true") != null);
}

test "usage ledger records failed response flag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);
    const ledger_path = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ base, TOKEN_USAGE_LEDGER_FILENAME });
    defer testing.allocator.free(ledger_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.diagnostics.token_usage_ledger_enabled = true;
    cfg.diagnostics.token_usage_ledger_window_hours = 0;
    cfg.diagnostics.token_usage_ledger_max_lines = 0;
    cfg.diagnostics.token_usage_ledger_max_bytes = 0;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    sm.appendUsageRecord(.{
        .ts = 31,
        .provider = "p1",
        .model = "m1",
        .usage = .{ .prompt_tokens = 0, .completion_tokens = 0, .total_tokens = 0 },
        .success = false,
    });

    const file = try std.fs.openFileAbsolute(ledger_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(content);

    try testing.expect(std.mem.indexOf(u8, content, "\"ts\":31") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"success\":false") != null);
}

test "getOrCreate creates new session for unknown key" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("telegram:chat1");
    try testing.expect(session.turn_count == 0);
    try testing.expectEqualStrings("telegram:chat1", session.session_key);
}

test "getOrCreate returns same session for same key" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s1 = try sm.getOrCreate("key1");
    const s2 = try sm.getOrCreate("key1");
    try testing.expect(s1 == s2); // pointer equality
}

test "getOrCreate creates separate sessions for different keys" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s1 = try sm.getOrCreate("telegram:a");
    const s2 = try sm.getOrCreate("discord:b");
    try testing.expect(s1 != s2);
}

test "getOrCreate applies named agent profile from routed session key" {
    var mock = MockProvider{ .response = "ok" };
    var cfg = testConfig();
    cfg.default_provider = "openrouter";
    cfg.agents = &.{
        .{
            .name = "Coder Agent",
            .provider = "ollama",
            .model = "qwen2.5-coder:14b",
            .system_prompt = "You are a coding specialist.",
            .temperature = 0.25,
        },
    };

    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:coder-agent:telegram:group:-100123");
    try testing.expect(session.provider_holder != null);
    try testing.expectEqualStrings("Coder Agent", session.agent.profile_name.?);
    try testing.expectEqualStrings("qwen2.5-coder:14b", session.agent.model_name);
    try testing.expectEqualStrings("ollama", session.agent.default_provider);
    try testing.expectApproxEqAbs(@as(f64, 0.25), session.agent.temperature, 0.000001);
    try testing.expectEqual(@as(usize, 0), session.agent.model_routes.len);
}

test "getOrCreate stores named agent provider interface from session-owned holder" {
    var mock = MockProvider{ .response = "ok" };
    var cfg = testConfig();
    cfg.default_provider = "openrouter";
    cfg.agents = &.{
        .{
            .name = "Coder Agent",
            .provider = "ollama",
            .model = "qwen2.5-coder:14b",
        },
    };

    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:coder-agent:telegram:group:-100123");
    try testing.expect(session.provider_holder != null);

    var holder = &session.provider_holder.?;
    const holder_provider = holder.provider();
    try testing.expect(session.agent.provider.ptr == holder_provider.ptr);
    try testing.expect(session.agent.provider.vtable == holder_provider.vtable);
}

test "getOrCreate uses named agent workspace namespace when workspace_path is set" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fs.path.join(testing.allocator, &.{ base, "config.json" });
    defer testing.allocator.free(config_path);
    const expected_workspace = try std.fs.path.join(testing.allocator, &.{ base, "agents", "coder-agent" });
    defer testing.allocator.free(expected_workspace);

    var mock = MockProvider{ .response = "ok" };
    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.agents = &.{
        .{
            .name = "Coder Agent",
            .provider = "ollama",
            .model = "qwen2.5-coder:14b",
            .workspace_path = "agents/coder-agent",
        },
    };

    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:coder-agent:telegram:group:-100123");
    try testing.expect(session.owned_memory_session_id != null);
    try testing.expectEqualStrings("agent:coder-agent", session.agent.memory_session_id.?);
    try testing.expectEqualStrings(expected_workspace, session.agent.workspace_dir);
}

test "getOrCreate auto-provisioned peer uses dedicated runtime workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const auto_session = try sm.getOrCreate("agent:peer-deadbeefcafebabe:whatsapp_web:direct:5511987654321");
    try expectPathContains(auto_session.agent.workspace_dir, "/agents/peer-deadbeefcafebabe/workspace");
    try testing.expectEqual(@as(usize, 1), sm.agent_runtimes.count());

    const default_session = try sm.getOrCreate("agent:main:whatsapp_web:direct:5511987654321");
    try testing.expectEqualStrings(base, default_session.agent.workspace_dir);
    try testing.expectEqual(@as(usize, 1), sm.agent_runtimes.count());
}

test "getOrCreate named agent workspace override creates dedicated runtime" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    const agents = [_]NamedAgentConfig{
        .{
            .name = "Helper Bot",
            .provider = "openrouter",
            .model = "test/mock-model",
            .workspace_path = "agents/helper-workspace",
        },
    };

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.agents = &agents;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:helper-bot:telegram:direct:42");
    try expectPathEndsWith(session.agent.workspace_dir, "agents/helper-workspace");
    try testing.expectEqual(@as(usize, 1), sm.agent_runtimes.count());
}

test "claim gate blocks unverified peer when dm_scope is main" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.dm_scope = .main;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const resp = try sm.processMessage("agent:peer-0011223344556677:main", "hello", .{
        .channel = "whatsapp_web",
        .account_id = "default",
        .peer_id = "5511",
        .is_group = false,
    });
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "Identity verification required") != null);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
}

test "claim gate attempts are scoped by account_id" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.dm_scope = .per_account_channel_peer;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";
    cfg.session.claim_max_attempts = 1;
    cfg.session.claim_lockout_secs = 120;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const bad_claim = "/claim v1:9999999999:void:nonce-bad:0000000000000000000000000000000000000000000000000000000000000000";
    const account_a = try sm.processMessage("agent:peer-aaaaaaaaaaaaaaaa:whatsapp_web:acct-a:direct:55118888", bad_claim, .{
        .channel = "whatsapp_web",
        .account_id = "acct-a",
        .peer_id = "55118888",
        .is_group = false,
    });
    defer testing.allocator.free(account_a);
    try testing.expect(std.mem.indexOf(u8, account_a, "Invalid or expired claim token") != null);

    const locked_a = try sm.processMessage("agent:peer-aaaaaaaaaaaaaaaa:whatsapp_web:acct-a:direct:55118888", "hello", .{
        .channel = "whatsapp_web",
        .account_id = "acct-a",
        .peer_id = "55118888",
        .is_group = false,
    });
    defer testing.allocator.free(locked_a);
    try testing.expect(std.mem.indexOf(u8, locked_a, "Too many failed claim attempts") != null);

    const account_b = try sm.processMessage("agent:peer-bbbbbbbbbbbbbbbb:whatsapp_web:acct-b:direct:55118888", "hello", .{
        .channel = "whatsapp_web",
        .account_id = "acct-b",
        .peer_id = "55118888",
        .is_group = false,
    });
    defer testing.allocator.free(account_b);
    try testing.expect(std.mem.indexOf(u8, account_b, "Identity verification required") != null);
}

test "claim gate blocks unverified peer before session provisioning" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session_key = "agent:peer-0011223344556677:whatsapp_web:direct:5511";
    const resp = try sm.processMessage(session_key, "hello", null);
    defer testing.allocator.free(resp);

    try testing.expect(std.mem.indexOf(u8, resp, "Identity verification required") != null);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
    try testing.expectEqual(@as(usize, 0), sm.agent_runtimes.count());
}

test "claim gate unlocks peer runtime after valid signed token" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session_key = "agent:peer-deadbeefcafebabe:whatsapp_web:direct:5511987654321";
    const token = try testBuildClaimToken(
        testing.allocator,
        cfg.session.claim_secret.?,
        std.time.timestamp() + 600,
        "void",
        "nonce-001",
    );
    defer testing.allocator.free(token);
    const claim_cmd = try testClaimCommand(testing.allocator, token);
    defer testing.allocator.free(claim_cmd);

    const claim_resp = try sm.processMessage(session_key, claim_cmd, null);
    defer testing.allocator.free(claim_resp);
    try testing.expect(std.mem.indexOf(u8, claim_resp, "Identity verified as 'void'") != null);

    const resp = try sm.processMessage(session_key, "hello after claim", null);
    defer testing.allocator.free(resp);
    try testing.expectEqualStrings("ok", resp);
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
    try testing.expectEqual(@as(usize, 1), sm.agent_runtimes.count());
}

test "claim gate persists verified identity across manager restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";

    var mock = MockProvider{ .response = "ok" };
    const session_key = "agent:peer-a1b2c3d4e5f60718:whatsapp_web:direct:55115555";

    {
        var sm = testSessionManager(testing.allocator, &mock, &cfg);
        defer sm.deinit();

        const token = try testBuildClaimToken(
            testing.allocator,
            cfg.session.claim_secret.?,
            std.time.timestamp() + 600,
            "void",
            "nonce-persist",
        );
        defer testing.allocator.free(token);
        const claim_cmd = try testClaimCommand(testing.allocator, token);
        defer testing.allocator.free(claim_cmd);

        const claim_resp = try sm.processMessage(session_key, claim_cmd, null);
        defer testing.allocator.free(claim_resp);
        try testing.expect(std.mem.indexOf(u8, claim_resp, "Identity verified as 'void'") != null);
    }

    {
        var sm = testSessionManager(testing.allocator, &mock, &cfg);
        defer sm.deinit();

        const resp = try sm.processMessage(session_key, "hello after restart", null);
        defer testing.allocator.free(resp);
        try testing.expectEqualStrings("ok", resp);
    }
}

test "claim gate rejects replayed nonce across peers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const token = try testBuildClaimToken(
        testing.allocator,
        cfg.session.claim_secret.?,
        std.time.timestamp() + 600,
        "void",
        "nonce-replay",
    );
    defer testing.allocator.free(token);
    const claim_cmd = try testClaimCommand(testing.allocator, token);
    defer testing.allocator.free(claim_cmd);

    const first_key = "agent:peer-aaaaaaaaaaaaaaaa:whatsapp_web:direct:551100000001";
    const second_key = "agent:peer-bbbbbbbbbbbbbbbb:whatsapp_web:direct:551100000002";

    const first_resp = try sm.processMessage(first_key, claim_cmd, null);
    defer testing.allocator.free(first_resp);
    try testing.expect(std.mem.indexOf(u8, first_resp, "Identity verified as 'void'") != null);

    const replay_resp = try sm.processMessage(second_key, claim_cmd, null);
    defer testing.allocator.free(replay_resp);
    try testing.expect(std.mem.indexOf(u8, replay_resp, "Invalid or expired claim token") != null);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
}

test "claim gate locks out after max failed attempts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";
    cfg.session.claim_max_attempts = 2;
    cfg.session.claim_lockout_secs = 120;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session_key = "agent:peer-feedfacefeedface:whatsapp_web:direct:55118888";
    const bad_claim = "/claim v1:9999999999:void:nonce-bad:0000000000000000000000000000000000000000000000000000000000000000";

    const first = try sm.processMessage(session_key, bad_claim, null);
    defer testing.allocator.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "Invalid or expired claim token") != null);

    const second = try sm.processMessage(session_key, bad_claim, null);
    defer testing.allocator.free(second);
    try testing.expect(std.mem.indexOf(u8, second, "Invalid or expired claim token") != null);

    const third = try sm.processMessage(session_key, "hello", null);
    defer testing.allocator.free(third);
    try testing.expect(std.mem.indexOf(u8, third, "Too many failed claim attempts") != null);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
}

test "claim gate supports revoke and returns peer to quarantine mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;
    cfg.session.claim_secret = "claim-secret";
    cfg.session.claim_admin_secret = "admin-secret";

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session_key = "agent:peer-1234567890abcdef:whatsapp_web:direct:55119999";
    const token = try testBuildClaimToken(
        testing.allocator,
        cfg.session.claim_secret.?,
        std.time.timestamp() + 600,
        "void",
        "nonce-revoke",
    );
    defer testing.allocator.free(token);
    const claim_cmd = try testClaimCommand(testing.allocator, token);
    defer testing.allocator.free(claim_cmd);

    const claim_resp = try sm.processMessage(session_key, claim_cmd, null);
    defer testing.allocator.free(claim_resp);
    try testing.expect(std.mem.indexOf(u8, claim_resp, "Identity verified as 'void'") != null);

    const unlocked = try sm.processMessage(session_key, "hello", null);
    defer testing.allocator.free(unlocked);
    try testing.expectEqualStrings("ok", unlocked);
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());

    const bad_revoke = try sm.processMessage(session_key, "/revoke nope", null);
    defer testing.allocator.free(bad_revoke);
    try testing.expectEqualStrings("Invalid revoke secret.", bad_revoke);

    const revoked = try sm.processMessage(session_key, "/revoke admin-secret", null);
    defer testing.allocator.free(revoked);
    try testing.expect(std.mem.indexOf(u8, revoked, "Identity link revoked") != null);

    const gated_again = try sm.processMessage(session_key, "hello again", null);
    defer testing.allocator.free(gated_again);
    try testing.expect(std.mem.indexOf(u8, gated_again, "Identity verification required") != null);
}

test "getOrCreate falls back to default config for unknown routed agent id" {
    var mock = MockProvider{ .response = "ok" };
    var cfg = testConfig();
    cfg.default_provider = "openrouter";
    cfg.agents = &.{
        .{
            .name = "coder",
            .provider = "ollama",
            .model = "qwen2.5-coder:14b",
        },
    };

    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:missing:telegram:group:-100123");
    try testing.expect(session.provider_holder == null);
    try testing.expect(session.agent.profile_name == null);
    try testing.expectEqualStrings("test/mock-model", session.agent.model_name);
    try testing.expectEqualStrings("openrouter", session.agent.default_provider);
}

test "sessionCount reflects active sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
    _ = try sm.getOrCreate("a");
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
    _ = try sm.getOrCreate("b");
    try testing.expectEqual(@as(usize, 2), sm.sessionCount());
    _ = try sm.getOrCreate("a"); // existing
    try testing.expectEqual(@as(usize, 2), sm.sessionCount());
}

test "snapshotSessions captures live session metadata" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("telegram:main:-100123#topic:77");
    session.mutex.lock();
    session.last_active = 1234;
    session.turn_count = 9;
    session.mutex.unlock();
    session.turn_running.store(true, .release);
    defer session.turn_running.store(false, .release);

    const snapshots = try sm.snapshotSessions(testing.allocator);
    defer SessionManager.freeSessionSnapshots(testing.allocator, snapshots);

    try testing.expectEqual(@as(usize, 1), snapshots.len);
    try testing.expectEqualStrings("telegram:main:-100123#topic:77", snapshots[0].session_key);
    try testing.expectEqual(@as(i64, 1234), snapshots[0].last_active);
    try testing.expectEqual(@as(u64, 9), snapshots[0].turn_count);
    try testing.expect(snapshots[0].turn_running);
}

test "migrateLegacySessionKey renames in-memory session to canonical key" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const legacy = try sm.getOrCreate("agent:main:telegram:group:-100123#topic:77");
    legacy.turn_count = 3;

    sm.migrateLegacySessionKey("agent:main:telegram:group:-100123:thread:77", "agent:main:telegram:group:-100123#topic:77");

    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
    try testing.expect(sm.sessions.get("agent:main:telegram:group:-100123#topic:77") == null);

    const canonical = sm.sessions.get("agent:main:telegram:group:-100123:thread:77") orelse return error.TestExpectedEqual;
    try testing.expect(canonical == legacy);
    try testing.expectEqualStrings("agent:main:telegram:group:-100123:thread:77", canonical.session_key);
    try testing.expect(canonical.agent.memory_session_id != null);
    try testing.expectEqualStrings("agent:main:telegram:group:-100123:thread:77", canonical.agent.memory_session_id.?);
    try testing.expectEqual(@as(u64, 3), canonical.turn_count);
}

test "migrateLegacySessionKey copies persisted transcript and usage to canonical key" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var sm = testSessionManagerWithMemory(testing.allocator, &mock, &cfg, null, sqlite_mem.sessionStore());
    defer sm.deinit();

    const store = sqlite_mem.sessionStore();
    try store.saveMessage("agent:main:telegram:group:-100123#topic:77", "user", "hello");
    try store.saveMessage("agent:main:telegram:group:-100123#topic:77", "assistant", "world");
    try store.saveUsage("agent:main:telegram:group:-100123#topic:77", 42);

    sm.migrateLegacySessionKey("agent:main:telegram:group:-100123:thread:77", "agent:main:telegram:group:-100123#topic:77");

    const canonical_msgs = try store.loadMessages(testing.allocator, "agent:main:telegram:group:-100123:thread:77");
    defer memory_mod.freeMessages(testing.allocator, canonical_msgs);
    try testing.expectEqual(@as(usize, 2), canonical_msgs.len);
    try testing.expectEqualStrings("hello", canonical_msgs[0].content);
    try testing.expectEqualStrings("world", canonical_msgs[1].content);
    try testing.expectEqual(@as(?u64, 42), try store.loadUsage("agent:main:telegram:group:-100123:thread:77"));

    const legacy_msgs = try store.loadMessages(testing.allocator, "agent:main:telegram:group:-100123#topic:77");
    defer memory_mod.freeMessages(testing.allocator, legacy_msgs);
    try testing.expectEqual(@as(usize, 0), legacy_msgs.len);
    try testing.expectEqual(@as(?u64, null), try store.loadUsage("agent:main:telegram:group:-100123#topic:77"));
}

test "migrateLegacySessionKey reattaches session-scoped memory to canonical key" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var sm = testSessionManagerWithMemory(testing.allocator, &mock, &cfg, mem, sqlite_mem.sessionStore());
    defer sm.deinit();

    try mem.store("autosave_user_1", "legacy memory", .conversation, "agent:main:telegram:group:-100123#topic:77");

    sm.migrateLegacySessionKey("agent:main:telegram:group:-100123:thread:77", "agent:main:telegram:group:-100123#topic:77");

    const migrated = try mem.get(testing.allocator, "autosave_user_1");
    defer if (migrated) |entry| entry.deinit(testing.allocator);
    try testing.expect(migrated != null);
    try testing.expect(migrated.?.session_id != null);
    try testing.expectEqualStrings("agent:main:telegram:group:-100123:thread:77", migrated.?.session_id.?);

    const legacy_entries = try mem.list(testing.allocator, null, "agent:main:telegram:group:-100123#topic:77");
    defer memory_mod.freeEntries(testing.allocator, legacy_entries);
    try testing.expectEqual(@as(usize, 0), legacy_entries.len);
}

test "session has correct initial state" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s = try sm.getOrCreate("test:init");
    try testing.expectEqual(@as(u64, 0), s.turn_count);
    try testing.expect(!s.turn_running.load(.acquire));
    try testing.expect(!s.agent.has_system_prompt);
    try testing.expectEqual(@as(usize, 0), s.agent.historyLen());
}

test "requestTurnInterrupt signals only active sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("interrupt:1");
    var none = sm.requestTurnInterrupt("interrupt:1");
    defer none.deinit(testing.allocator);
    try testing.expect(!none.requested);

    session.turn_running.store(true, .release);
    defer session.turn_running.store(false, .release);
    var yes = sm.requestTurnInterrupt("interrupt:1");
    defer yes.deinit(testing.allocator);
    try testing.expect(yes.requested);
    try testing.expect(session.agent.interrupt_requested.load(.acquire));
}

test "requestTurnInterrupt returns active tool snapshot when available" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("interrupt:tool");
    session.turn_running.store(true, .release);
    defer session.turn_running.store(false, .release);

    session.agent.tool_state_mu.lock();
    if (session.agent.active_tool_name) |old| testing.allocator.free(old);
    session.agent.active_tool_name = try testing.allocator.dupe(u8, "shell");
    session.agent.tool_state_mu.unlock();

    var res = sm.requestTurnInterrupt("interrupt:tool");
    defer res.deinit(testing.allocator);
    try testing.expect(res.requested);
    try testing.expect(res.active_tool != null);
    try testing.expectEqualStrings("shell", res.active_tool.?);
}

// ---------------------------------------------------------------------------
// 2. processMessage tests
// ---------------------------------------------------------------------------

test "processMessage returns mock response" {
    var mock = MockProvider{ .response = "Hello from mock" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const resp = try sm.processMessage("user:1", "hi", null);
    defer testing.allocator.free(resp);
    try testing.expectEqualStrings("Hello from mock", resp);
}

test "processMessageStreaming forwards provider deltas" {
    var mock = MockStreamingProvider{ .response = "streaming reply" };
    const cfg = testConfig();
    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        null,
        noop.observer(),
        null,
        null,
    );
    defer sm.deinit();

    var collector = DeltaCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const resp = try sm.processMessageStreaming(
        "stream:1",
        "hi",
        null,
        .{
            .callback = DeltaCollector.onEvent,
            .ctx = @ptrCast(&collector),
        },
    );
    defer testing.allocator.free(resp);

    try testing.expectEqualStrings("streaming reply", resp);
    try testing.expectEqualStrings("streaming reply", collector.data.items);
}

test "processMessage refreshes system prompt when conversation context is cleared" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const sender_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const with_context: ?ConversationContext = .{
        .channel = "signal",
        .sender_number = "+15551234567",
        .sender_uuid = sender_uuid,
        .group_id = null,
        .is_group = false,
    };

    const resp1 = try sm.processMessage("ctx:user", "first", with_context);
    defer testing.allocator.free(resp1);

    const session = try sm.getOrCreate("ctx:user");
    try testing.expect(session.agent.history.items.len > 0);
    const sys1 = session.agent.history.items[0].content;
    try testing.expect(std.mem.indexOf(u8, sys1, "## Conversation Context") != null);
    try testing.expect(std.mem.indexOf(u8, sys1, sender_uuid) != null);

    const resp2 = try sm.processMessage("ctx:user", "second", null);
    defer testing.allocator.free(resp2);

    try testing.expect(session.agent.history.items.len > 0);
    const sys2 = session.agent.history.items[0].content;
    try testing.expect(std.mem.indexOf(u8, sys2, "## Conversation Context") == null);
    try testing.expect(std.mem.indexOf(u8, sys2, sender_uuid) == null);
}

test "processMessage updates last_active" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("user:2");
    const before = session.last_active;

    // Small sleep so timestamp changes
    std.Thread.sleep(10 * std.time.ns_per_ms);

    const resp = try sm.processMessage("user:2", "hello", null);
    defer testing.allocator.free(resp);

    try testing.expect(session.last_active >= before);
}

test "processMessage increments turn_count" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const resp1 = try sm.processMessage("user:3", "msg1", null);
    defer testing.allocator.free(resp1);

    const session = try sm.getOrCreate("user:3");
    try testing.expectEqual(@as(u64, 1), session.turn_count);

    const resp2 = try sm.processMessage("user:3", "msg2", null);
    defer testing.allocator.free(resp2);
    try testing.expectEqual(@as(u64, 2), session.turn_count);
}

test "processMessage preserves session across calls" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const resp1 = try sm.processMessage("persist:1", "first", null);
    defer testing.allocator.free(resp1);

    const session = try sm.getOrCreate("persist:1");
    // After first processMessage: system prompt + user msg + assistant response
    try testing.expect(session.agent.historyLen() > 0);

    const history_before = session.agent.historyLen();

    const resp2 = try sm.processMessage("persist:1", "second", null);
    defer testing.allocator.free(resp2);

    // History should have grown (user msg + assistant response added)
    try testing.expect(session.agent.historyLen() > history_before);
}

test "restored session reconstructs token count from persisted assistant replies" {
    var mock = MockProvider{ .response = "assistant reply" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:chat-1";
    const reply = try sm.processMessage(session_key, "hello", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(reply);

    const expected_tokens = agent_mod.estimate_text_tokens("assistant reply");
    const first_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(@as(u64, expected_tokens), first_session.agent.total_tokens);

    first_session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(@as(u64, expected_tokens), restored_session.agent.total_tokens);

    const status = try restored_session.agent.handleSlashCommand("/status");
    defer {
        if (status) |resp| testing.allocator.free(resp);
    }
    try testing.expect(status != null);

    var expected_line_buf: [64]u8 = undefined;
    const expected_line = try std.fmt.bufPrint(&expected_line_buf, "Tokens used: {d}", .{expected_tokens});
    try testing.expect(std.mem.indexOf(u8, status.?, expected_line) != null);
}

test "restored session token reconstruction ignores usage footer decorations" {
    var mock = MockProvider{ .response = "assistant reply" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:chat-usage";
    const session = try sm.getOrCreate(session_key);
    session.agent.usage_mode = .tokens;

    const reply = try sm.processMessage(session_key, "hello", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(reply);
    try testing.expect(std.mem.indexOf(u8, reply, "[usage] total_tokens=") != null);

    const entries = try sqlite_mem.loadMessages(testing.allocator, session_key);
    defer memory_mod.freeMessages(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("assistant", entries[1].role);
    try testing.expectEqualStrings("assistant reply", entries[1].content);

    const expected_tokens = agent_mod.estimate_text_tokens("assistant reply");
    session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(@as(u64, expected_tokens), restored_session.agent.total_tokens);
}

test "persisted session falls back to rendered response when degraded turn has no final assistant history entry" {
    var provider = SummaryFailureProvider{};
    var probe_tool = ProbeTool{};
    const tools = [_]Tool{probe_tool.tool()};
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        provider.provider(),
        &tools,
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:chat-fallback";
    const session = try sm.getOrCreate(session_key);
    session.agent.max_tool_iterations = 1;

    const response = try sm.processMessage(session_key, "hello", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(response);

    try testing.expect(std.mem.indexOf(u8, response, "Could not produce a summary") != null);
    try testing.expect(session.agent.history.items.len > 0);
    try testing.expect(session.agent.history.items[session.agent.history.items.len - 1].role != .assistant);

    const entries = try sqlite_mem.loadMessages(testing.allocator, session_key);
    defer memory_mod.freeMessages(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("assistant", entries[1].role);
    try testing.expectEqualStrings(response, entries[1].content);
    try testing.expect(!std.mem.eql(u8, entries[1].content, "running"));

    const live_total_tokens = session.agent.total_tokens;
    try testing.expect(live_total_tokens > 0);
    session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(live_total_tokens, restored_session.agent.total_tokens);
}

test "restored session token reconstruction stays aligned across response cache hits" {
    var mock = MockProvider{ .response = "assistant reply" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var response_cache = try memory_mod.ResponseCache.init(":memory:", 60, 1000);
    defer response_cache.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        &response_cache,
    );
    defer sm.deinit();

    const session_key = "telegram:main:chat-cache";
    const first = try sm.processMessage(session_key, "hello", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(first);

    const second = try sm.processMessage(session_key, "hello", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(second);
    try testing.expectEqualStrings(first, second);

    const expected_tokens = agent_mod.estimate_text_tokens("assistant reply");
    const live_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(@as(u64, expected_tokens), live_session.agent.total_tokens);
    try testing.expectEqual(@as(u32, 0), live_session.agent.last_turn_usage.total_tokens);

    live_session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(@as(u64, expected_tokens), restored_session.agent.total_tokens);
}

fn expectResetTurnPersistsFreshSession(command: []const u8) !void {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:chat-reset-usage";
    const store = sqlite_mem.sessionStore();

    const first = try sm.processMessage(session_key, "before reset", .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(first);

    const token_cost = @as(u64, agent_mod.estimate_text_tokens("ok"));
    const session = try sm.getOrCreate(session_key);
    try testing.expectEqual(token_cost, session.agent.total_tokens);

    const reset_reply = try sm.processMessage(session_key, command, .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(reset_reply);
    try testing.expectEqual(token_cost, session.agent.total_tokens);

    const entries = try store.loadMessages(testing.allocator, session_key);
    defer memory_mod.freeMessages(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("user", entries[0].role);
    try testing.expectEqualStrings(agent_mod.commands.bareSessionResetPrompt(command).?, entries[0].content);
    try testing.expectEqualStrings("assistant", entries[1].role);
    try testing.expectEqualStrings("ok", entries[1].content);
    try testing.expectEqual(@as(?u64, token_cost), try store.loadUsage(session_key));

    session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored = try sm.getOrCreate(session_key);
    try testing.expectEqual(token_cost, restored.agent.total_tokens);
    try testing.expectEqual(@as(usize, 2), restored.agent.historyLen());
    try testing.expectEqualStrings(entries[0].content, restored.agent.history.items[0].content);
    try testing.expectEqualStrings("ok", restored.agent.history.items[1].content);
}

test "processMessage bare /new persists fresh-session turn across reload" {
    try expectResetTurnPersistsFreshSession("/new");
}

test "processMessage bare /reset with mention persists fresh-session turn across reload" {
    try expectResetTurnPersistsFreshSession("/reset@nullclaw_bot:");
}

test "processMessage slash-prefixed prompt that is not a local command persists across reload" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:slash-path";
    const slash_prompt = "/etc/hosts";
    const response = try sm.processMessage(session_key, slash_prompt, .{
        .channel = "telegram",
        .is_group = false,
        .group_id = null,
    });
    defer testing.allocator.free(response);

    const expected_tokens = @as(u64, agent_mod.estimate_text_tokens("ok"));
    const store = sqlite_mem.sessionStore();
    const entries = try store.loadMessages(testing.allocator, session_key);
    defer memory_mod.freeMessages(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("user", entries[0].role);
    try testing.expectEqualStrings(slash_prompt, entries[0].content);
    try testing.expectEqualStrings("assistant", entries[1].role);
    try testing.expectEqualStrings("ok", entries[1].content);
    try testing.expectEqual(@as(?u64, expected_tokens), try store.loadUsage(session_key));

    const live_session = try sm.getOrCreate(session_key);
    try testing.expectEqual(expected_tokens, live_session.agent.total_tokens);
    live_session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored = try sm.getOrCreate(session_key);
    try testing.expectEqual(expected_tokens, restored.agent.total_tokens);
    try testing.expectEqual(@as(usize, 2), restored.agent.historyLen());
    try testing.expectEqualStrings(slash_prompt, restored.agent.history.items[0].content);
    try testing.expectEqualStrings("ok", restored.agent.history.items[1].content);
}

test "processMessage runtime slash commands persist across reload" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        sqlite_mem.memory(),
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    const session_key = "telegram:main:runtime-state";
    const commands = [_][]const u8{
        "/think high",
        "/verbose full",
        "/reasoning stream",
        "/usage full",
        "/exec host=node security=full ask=always node=worker-a",
        "/queue debounce debounce:2s cap:3 drop:oldest",
        "/tts always provider test-provider limit 120 summary on audio on",
        "/session ttl 5m",
        "/focus incident-123",
        "/dock-telegram",
        "/activation always",
        "/send on",
        "/debug reset",
        "/usage cost",
        "/exec host=sandbox security=allowlist ask=on-miss",
        "/queue serial cap:4 drop:newest",
        "/tts tagged provider replay-provider limit 77 summary off audio off",
        "/session ttl 30s",
        "/unfocus",
        "/dock-slack",
        "/activation mention",
        "/send inherit",
        "/elevated full",
    };

    for (commands) |command| {
        const reply = try sm.processMessage(session_key, command, .{
            .channel = "telegram",
            .is_group = false,
            .group_id = null,
        });
        defer testing.allocator.free(reply);
    }

    const live_session = try sm.getOrCreate(session_key);
    try testing.expect(live_session.agent.reasoning_effort == null);
    try testing.expect(live_session.agent.verbose_level == .off);
    try testing.expect(live_session.agent.reasoning_mode == .off);
    try testing.expect(live_session.agent.usage_mode == .cost);
    try testing.expect(live_session.agent.exec_host == .sandbox);
    try testing.expect(live_session.agent.exec_security == .full);
    try testing.expect(live_session.agent.exec_ask == .off);
    try testing.expect(live_session.agent.exec_node_id == null);
    try testing.expect(live_session.agent.queue_mode == .serial);
    try testing.expectEqual(@as(u32, 4), live_session.agent.queue_cap);
    try testing.expect(live_session.agent.queue_drop == .newest);
    try testing.expect(live_session.agent.tts_mode == .tagged);
    try testing.expectEqualStrings("replay-provider", live_session.agent.tts_provider.?);
    try testing.expectEqual(@as(u32, 77), live_session.agent.tts_limit_chars);
    try testing.expect(!live_session.agent.tts_summary);
    try testing.expect(!live_session.agent.tts_audio);
    try testing.expectEqual(@as(?u64, 30), live_session.agent.session_ttl_secs);
    try testing.expect(live_session.agent.focus_target == null);
    try testing.expectEqualStrings("slack", live_session.agent.dock_target.?);
    try testing.expect(live_session.agent.activation_mode == .mention);
    try testing.expect(live_session.agent.send_mode == .inherit);
    try testing.expectEqual(@as(usize, 0), live_session.agent.historyLen());

    const store = sqlite_mem.sessionStore();
    const entries = try store.loadMessages(testing.allocator, session_key);
    defer memory_mod.freeMessages(testing.allocator, entries);
    try testing.expectEqual(@as(usize, commands.len), entries.len);
    for (entries, commands) |entry, command| {
        try testing.expectEqualStrings(RUNTIME_COMMAND_ROLE, entry.role);
        try testing.expectEqualStrings(command, entry.content);
    }

    live_session.last_active = 0;
    try testing.expectEqual(@as(usize, 1), sm.evictIdle(1));

    const restored = try sm.getOrCreate(session_key);
    try testing.expect(restored.agent.reasoning_effort == null);
    try testing.expect(restored.agent.verbose_level == .off);
    try testing.expect(restored.agent.reasoning_mode == .off);
    try testing.expect(restored.agent.usage_mode == .cost);
    try testing.expect(restored.agent.exec_host == .sandbox);
    try testing.expect(restored.agent.exec_security == .full);
    try testing.expect(restored.agent.exec_ask == .off);
    try testing.expect(restored.agent.exec_node_id == null);
    try testing.expect(restored.agent.queue_mode == .serial);
    try testing.expectEqual(@as(u32, 4), restored.agent.queue_cap);
    try testing.expect(restored.agent.queue_drop == .newest);
    try testing.expect(restored.agent.tts_mode == .tagged);
    try testing.expectEqualStrings("replay-provider", restored.agent.tts_provider.?);
    try testing.expectEqual(@as(u32, 77), restored.agent.tts_limit_chars);
    try testing.expect(!restored.agent.tts_summary);
    try testing.expect(!restored.agent.tts_audio);
    try testing.expectEqual(@as(?u64, 30), restored.agent.session_ttl_secs);
    try testing.expect(restored.agent.focus_target == null);
    try testing.expectEqualStrings("slack", restored.agent.dock_target.?);
    try testing.expect(restored.agent.activation_mode == .mention);
    try testing.expect(restored.agent.send_mode == .inherit);
    try testing.expectEqual(@as(usize, 0), restored.agent.historyLen());
}

test "processMessage different keys — independent sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const resp_a = try sm.processMessage("user:a", "hello a", null);
    defer testing.allocator.free(resp_a);

    const resp_b = try sm.processMessage("user:b", "hello b", null);
    defer testing.allocator.free(resp_b);

    const sa = try sm.getOrCreate("user:a");
    const sb = try sm.getOrCreate("user:b");
    try testing.expect(sa != sb);
    try testing.expectEqual(@as(u64, 1), sa.turn_count);
    try testing.expectEqual(@as(u64, 1), sb.turn_count);
}

test "processMessage /new clears autosave only for current session" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        mem,
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    // Seed autosave entries for two different sessions.
    try mem.store("autosave_user_a", "session a", .conversation, "sess-a");
    try mem.store("autosave_user_b", "session b", .conversation, "sess-b");
    try testing.expectEqual(@as(usize, 2), try mem.count());

    const response = try sm.processMessage("sess-a", "/new", null);
    defer testing.allocator.free(response);

    const a_entry = try mem.get(testing.allocator, "autosave_user_a");
    defer if (a_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(a_entry == null);

    const b_entry = try mem.get(testing.allocator, "autosave_user_b");
    defer if (b_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(b_entry != null);
    try testing.expectEqualStrings("session b", b_entry.?.content);
}

test "processMessage /new with model clears autosave only for current session" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        mem,
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    try mem.store("autosave_user_a", "session a", .conversation, "sess-a");
    try mem.store("autosave_user_b", "session b", .conversation, "sess-b");
    try testing.expectEqual(@as(usize, 2), try mem.count());

    const response = try sm.processMessage("sess-a", "/new gpt-4o-mini", null);
    defer testing.allocator.free(response);

    const a_entry = try mem.get(testing.allocator, "autosave_user_a");
    defer if (a_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(a_entry == null);

    const b_entry = try mem.get(testing.allocator, "autosave_user_b");
    defer if (b_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(b_entry != null);
    try testing.expectEqualStrings("session b", b_entry.?.content);
}

test "processMessage /reset clears autosave only for current session" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        mem,
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    try mem.store("autosave_user_a", "session a", .conversation, "sess-a");
    try mem.store("autosave_user_b", "session b", .conversation, "sess-b");
    try testing.expectEqual(@as(usize, 2), try mem.count());

    const response = try sm.processMessage("sess-a", "/reset", null);
    defer testing.allocator.free(response);

    const a_entry = try mem.get(testing.allocator, "autosave_user_a");
    defer if (a_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(a_entry == null);

    const b_entry = try mem.get(testing.allocator, "autosave_user_b");
    defer if (b_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(b_entry != null);
    try testing.expectEqualStrings("session b", b_entry.?.content);
}

test "processMessage /restart clears autosave only for current session" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var noop = observability.NoopObserver{};
    var sm = SessionManager.init(
        testing.allocator,
        &cfg,
        mock.provider(),
        &.{},
        mem,
        noop.observer(),
        sqlite_mem.sessionStore(),
        null,
    );
    defer sm.deinit();

    try mem.store("autosave_user_a", "session a", .conversation, "sess-a");
    try mem.store("autosave_user_b", "session b", .conversation, "sess-b");
    try testing.expectEqual(@as(usize, 2), try mem.count());

    const response = try sm.processMessage("sess-a", "/restart", null);
    defer testing.allocator.free(response);

    const a_entry = try mem.get(testing.allocator, "autosave_user_a");
    defer if (a_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(a_entry == null);

    const b_entry = try mem.get(testing.allocator, "autosave_user_b");
    defer if (b_entry) |entry| entry.deinit(testing.allocator);
    try testing.expect(b_entry != null);
    try testing.expectEqualStrings("session b", b_entry.?.content);
}

test "processMessage with sqlite memory first turn does not panic" {
    var mock = MockProvider{ .response = "ok" };
    var cfg = testConfig();
    cfg.memory.auto_save = true;
    cfg.memory.backend = "sqlite";

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var sm = testSessionManagerWithMemory(testing.allocator, &mock, &cfg, mem, sqlite_mem.sessionStore());
    defer sm.deinit();

    const resp = try sm.processMessage("signal:session:1", "hello", null);
    defer testing.allocator.free(resp);
    try testing.expectEqualStrings("ok", resp);

    const entries = try sqlite_mem.loadMessages(testing.allocator, "signal:session:1");
    defer {
        for (entries) |entry| {
            testing.allocator.free(entry.role);
            testing.allocator.free(entry.content);
        }
        testing.allocator.free(entries);
    }
    // One user + one assistant message should be persisted.
    try testing.expect(entries.len >= 2);
}

// ---------------------------------------------------------------------------
// 3. evictIdle tests
// ---------------------------------------------------------------------------

test "evictIdle removes old sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("old:1");
    // Force last_active to the past
    session.last_active = std.time.timestamp() - 1000;

    const evicted = sm.evictIdle(500);
    try testing.expectEqual(@as(usize, 1), evicted);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
}

test "evictIdle prunes unused dedicated agent runtimes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{base});
    defer testing.allocator.free(config_path);

    var cfg = testConfig();
    cfg.workspace_dir = base;
    cfg.config_path = config_path;
    cfg.session.auto_provision_direct_agents = true;

    var mock = MockProvider{ .response = "ok" };
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("agent:peer-0011223344556677:whatsapp_web:direct:5511");
    try testing.expectEqual(@as(usize, 1), sm.agent_runtimes.count());

    session.last_active = std.time.timestamp() - 1000;
    const evicted = sm.evictIdle(1);
    try testing.expectEqual(@as(usize, 1), evicted);
    try testing.expectEqual(@as(usize, 0), sm.sessionCount());
    try testing.expectEqual(@as(usize, 0), sm.agent_runtimes.count());
}

test "evictIdle preserves recent sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    _ = try sm.getOrCreate("recent:1");
    // This session was just created, last_active is now

    const evicted = sm.evictIdle(3600); // 1 hour threshold
    try testing.expectEqual(@as(usize, 0), evicted);
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
}

test "evictIdle returns correct count" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    // Create 3 sessions, make 2 old
    const s1 = try sm.getOrCreate("s1");
    const s2 = try sm.getOrCreate("s2");
    _ = try sm.getOrCreate("s3");

    s1.last_active = std.time.timestamp() - 2000;
    s2.last_active = std.time.timestamp() - 2000;
    // s3 stays recent

    const evicted = sm.evictIdle(1000);
    try testing.expectEqual(@as(usize, 2), evicted);
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
}

test "evictIdle with no sessions returns 0" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    try testing.expectEqual(@as(usize, 0), sm.evictIdle(60));
}

test "evictIdle preserves sessions with active turns" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const session = try sm.getOrCreate("busy:1");
    session.last_active = std.time.timestamp() - 1000;
    session.turn_running.store(true, .release);
    defer session.turn_running.store(false, .release);

    const evicted = sm.evictIdle(5);
    try testing.expectEqual(@as(usize, 0), evicted);
    try testing.expect(sm.sessions.contains("busy:1"));
}

// ---------------------------------------------------------------------------
// 4. Thread safety tests
// ---------------------------------------------------------------------------

test "concurrent getOrCreate same key — single Session created" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const num_threads = 8;
    var sessions: [num_threads]*Session = undefined;
    var handles: [num_threads]std.Thread = undefined;

    for (0..num_threads) |t| {
        handles[t] = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, struct {
            fn run(mgr: *SessionManager, out: **Session) void {
                out.* = mgr.getOrCreate("shared:key") catch unreachable;
            }
        }.run, .{ &sm, &sessions[t] });
    }

    for (handles) |h| h.join();

    // All threads should have gotten the same session pointer
    for (1..num_threads) |i| {
        try testing.expect(sessions[0] == sessions[i]);
    }
    try testing.expectEqual(@as(usize, 1), sm.sessionCount());
}

test "concurrent getOrCreate different keys — separate Sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const num_threads = 8;
    var sessions: [num_threads]*Session = undefined;
    var handles: [num_threads]std.Thread = undefined;
    var key_bufs: [num_threads][16]u8 = undefined;
    var keys: [num_threads][]const u8 = undefined;

    for (0..num_threads) |t| {
        keys[t] = std.fmt.bufPrint(&key_bufs[t], "key:{d}", .{t}) catch "?";
        handles[t] = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, struct {
            fn run(mgr: *SessionManager, key: []const u8, out: **Session) void {
                out.* = mgr.getOrCreate(key) catch unreachable;
            }
        }.run, .{ &sm, keys[t], &sessions[t] });
    }

    for (handles) |h| h.join();

    // All sessions should be distinct
    for (0..num_threads) |i| {
        for (i + 1..num_threads) |j| {
            try testing.expect(sessions[i] != sessions[j]);
        }
    }
    try testing.expectEqual(@as(usize, num_threads), sm.sessionCount());
}

test "concurrent processMessage different keys — no crash" {
    var mock = MockProvider{ .response = "concurrent ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const num_threads = 4;
    var handles: [num_threads]std.Thread = undefined;
    var key_bufs: [num_threads][16]u8 = undefined;
    var keys: [num_threads][]const u8 = undefined;

    for (0..num_threads) |t| {
        keys[t] = std.fmt.bufPrint(&key_bufs[t], "conc:{d}", .{t}) catch "?";
        // Match the runtime worker stack budget used for threaded session
        // turns so this test exercises concurrency rather than a tiny stack.
        handles[t] = try std.Thread.spawn(.{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE }, struct {
            fn run(mgr: *SessionManager, key: []const u8, alloc: Allocator) void {
                for (0..3) |_| {
                    const resp = mgr.processMessage(key, "hello", null) catch return;
                    alloc.free(resp);
                }
            }
        }.run, .{ &sm, keys[t], testing.allocator });
    }

    for (handles) |h| h.join();
    try testing.expectEqual(@as(usize, num_threads), sm.sessionCount());
}

test "concurrent processMessage with sqlite memory does not panic" {
    var mock = MockProvider{ .response = "concurrent sqlite ok" };
    var cfg = testConfig();
    cfg.memory.auto_save = true;
    cfg.memory.backend = "sqlite";

    var sqlite_mem = try memory_mod.SqliteMemory.init(testing.allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    var sm = testSessionManagerWithMemory(testing.allocator, &mock, &cfg, mem, sqlite_mem.sessionStore());
    defer sm.deinit();

    const num_threads = 4;
    var handles: [num_threads]std.Thread = undefined;
    var key_bufs: [num_threads][24]u8 = undefined;
    var keys: [num_threads][]const u8 = undefined;
    var failed = std.atomic.Value(bool).init(false);

    for (0..num_threads) |t| {
        keys[t] = std.fmt.bufPrint(&key_bufs[t], "sqlite-conc:{d}", .{t}) catch "?";
        // This path still executes a full session turn, so keep it aligned
        // with the runtime stack budget for threaded message processing.
        handles[t] = try std.Thread.spawn(.{ .stack_size = thread_stacks.SESSION_TURN_STACK_SIZE }, struct {
            fn run(mgr: *SessionManager, key: []const u8, alloc: Allocator, failed_flag: *std.atomic.Value(bool)) void {
                for (0..5) |_| {
                    const resp = mgr.processMessage(key, "hello sqlite", null) catch {
                        failed_flag.store(true, .release);
                        return;
                    };
                    alloc.free(resp);
                }
            }
        }.run, .{ &sm, keys[t], testing.allocator, &failed });
    }

    for (handles) |h| h.join();
    try testing.expect(!failed.load(.acquire));
    try testing.expectEqual(@as(usize, num_threads), sm.sessionCount());

    const count = try mem.count();
    try testing.expect(count > 0);
}

// ---------------------------------------------------------------------------
// 5. Session consolidation tests
// ---------------------------------------------------------------------------

test "session last_consolidated defaults to zero" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s = try sm.getOrCreate("test:consolidation");
    try testing.expectEqual(@as(u64, 0), s.last_consolidated);
}

test "session initial state includes last_consolidated" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s = try sm.getOrCreate("test:fields");
    try testing.expectEqual(@as(u64, 0), s.last_consolidated);
    try testing.expectEqual(@as(u64, 0), s.turn_count);
    try testing.expect(s.created_at > 0);
    try testing.expect(s.last_active > 0);
}

// ---------------------------------------------------------------------------
// 6. reloadSkillsAll tests
// ---------------------------------------------------------------------------

test "reloadSkillsAll with no sessions returns zero counts" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const result = sm.reloadSkillsAll();
    try testing.expectEqual(@as(usize, 0), result.sessions_seen);
    try testing.expectEqual(@as(usize, 0), result.sessions_reloaded);
    try testing.expectEqual(@as(usize, 0), result.failures);
}

test "reloadSkillsAll invalidates system prompt on all sessions" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    const s1 = try sm.getOrCreate("reload:a");
    const s2 = try sm.getOrCreate("reload:b");
    s1.agent.has_system_prompt = true;
    s2.agent.has_system_prompt = true;

    const result = sm.reloadSkillsAll();
    try testing.expectEqual(@as(usize, 2), result.sessions_seen);
    try testing.expectEqual(@as(usize, 2), result.sessions_reloaded);
    try testing.expect(!s1.agent.has_system_prompt);
    try testing.expect(!s2.agent.has_system_prompt);
}

test "reloadSkillsAll does not affect session count" {
    var mock = MockProvider{ .response = "ok" };
    const cfg = testConfig();
    var sm = testSessionManager(testing.allocator, &mock, &cfg);
    defer sm.deinit();

    _ = try sm.getOrCreate("reload:c");
    _ = try sm.getOrCreate("reload:d");
    try testing.expectEqual(@as(usize, 2), sm.sessionCount());

    _ = sm.reloadSkillsAll();
    try testing.expectEqual(@as(usize, 2), sm.sessionCount());
}
