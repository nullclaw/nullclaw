const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const ws_client = @import("../websocket.zig");
const config_types = @import("../config_types.zig");
const auth = @import("../auth.zig");
const pairing_mod = @import("../security/pairing.zig");
const secret_crypto = @import("../security/secrets.zig");
const websocket = @import("websocket");

const log = std.log.scoped(.web);

pub const WebChannel = struct {
    const MAX_E2E_PAYLOAD_BYTES: usize = 65_536;
    const MAX_APPROVAL_ACTION_BYTES: usize = 4096;
    const MAX_APPROVAL_REASON_BYTES: usize = 512;
    const MAX_REQUEST_ID_BYTES: usize = 128;
    const MAX_CLIENT_SUB_BYTES: usize = 128;
    const MAX_SESSION_ID_BYTES: usize = 64;
    const MAX_SESSION_CLIENT_BINDINGS: usize = 1024;
    const E2E_ALG: []const u8 = "x25519-chacha20poly1305-v1";
    const RelayTokenSource = enum {
        config,
        env,
        stored,
        generated,
    };

    const LocalTokenSource = enum {
        config,
        env,
        ephemeral,
    };

    const RelayTokenResolution = struct {
        token: []u8,
        source: RelayTokenSource,
    };

    const VerifiedJwt = struct {
        sub: []u8,
        exp: i64,

        fn deinit(self: *VerifiedJwt, allocator: std.mem.Allocator) void {
            allocator.free(self.sub);
        }
    };

    const E2eSession = struct {
        key: [32]u8,
    };

    const SessionClientBinding = struct {
        client_sub: []const u8,
        expires_at: i64,
    };

    const WebTransport = enum {
        local,
        relay,
    };

    const MessageAuthMode = enum {
        pairing,
        token,
        invalid,
    };

    allocator: std.mem.Allocator,
    transport: WebTransport,
    port: u16,
    listen_address: []const u8,
    ws_path: []const u8,
    max_connections: u16,
    max_handshake_size: u16,
    account_id: []const u8,
    configured_auth_token: ?[]const u8,
    allowed_origins: []const []const u8,
    relay_url: ?[]const u8,
    relay_agent_id: []const u8,
    configured_relay_token: ?[]const u8,
    relay_token_ttl_secs: u32,
    relay_pairing_code_ttl_secs: u32,
    relay_ui_token_ttl_secs: u32,
    relay_e2e_required: bool,
    message_auth_mode: MessageAuthMode,
    bus: ?*bus_mod.Bus = null,

    // Active auth token (configured/env/generate).
    token: [128]u8 = [_]u8{0} ** 128,
    token_len: u8 = 0,
    token_initialized: bool = false,

    // Runtime state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    server: ?WsServer = null,
    server_thread: ?std.Thread = null,
    relay_thread: ?std.Thread = null,

    // Connection tracking
    connections: ConnectionList = .{},

    // Relay state
    relay_client_mu: std_compat.sync.Mutex = .{},
    relay_client: ?*ws_client.WsClient = null,
    relay_connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    relay_socket_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    relay_pairing_guard: ?pairing_mod.PairingGuard = null,
    relay_pairing_issued_at: i64 = 0,
    jwt_signing_key: [32]u8 = [_]u8{0} ** 32,
    jwt_ready: bool = false,
    relay_security_mu: std_compat.sync.Mutex = .{},
    session_client_bindings: std.StringHashMapUnmanaged(SessionClientBinding) = .empty,
    e2e_sessions: std.StringHashMapUnmanaged(E2eSession) = .empty,

    const SocketFd = std_compat.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std_compat.net.invalidHandle(SocketFd),
        else => -1,
    };

    const WsServer = websocket.Server(WsHandler);

    fn publicBindTokenRequiredLogMessage(message_auth_mode: MessageAuthMode) []const u8 {
        return switch (message_auth_mode) {
            .pairing => "WS connection rejected: token required for non-loopback bind; local pairing_request is loopback-only. Use /ws?token=<auth_token> (or Authorization header), keep listen=127.0.0.1, or use an SSH tunnel/reverse proxy.",
            .token => "WS connection rejected: token required for non-loopback bind; use /ws?token=<auth_token> (or Authorization header).",
            .invalid => "WS connection rejected: token required for non-loopback bind.",
        };
    }

    fn loopbackTokenRequiredLogMessage() []const u8 {
        return "WS connection rejected: token required on loopback when message_auth_mode=token; use /ws?token=<auth_token> (or Authorization header).";
    }

    fn allowsUnauthenticatedLoopbackUpgrade(message_auth_mode: MessageAuthMode) bool {
        return message_auth_mode == .pairing;
    }

    fn requiresOriginAllowlistWarning(self: *const WebChannel) bool {
        if (self.transport != .local) return false;
        if (self.allowed_origins.len != 0) return false;
        if (pairing_mod.isPublicBind(self.listen_address)) return true;
        return self.message_auth_mode == .token;
    }

    fn warnIfOriginAllowlistBroad(self: *const WebChannel) void {
        if (!self.requiresOriginAllowlistWarning()) return;
        if (pairing_mod.isPublicBind(self.listen_address)) {
            log.warn("Web channel allowed_origins is empty on non-loopback bind; browser origins are unrestricted. Set channels.web.allowed_origins explicitly before exposing this listener.", .{});
            return;
        }
        log.warn("Web channel allowed_origins is empty while message_auth_mode=token; browser origins are unrestricted on loopback. Set channels.web.allowed_origins to limit trusted UI origins.", .{});
    }

    const vtable = root.Channel.VTable{
        .start = wsStart,
        .stop = wsStop,
        .send = wsSend,
        .sendEvent = wsSendEvent,
        .sendApprovalRequest = wsSendApprovalRequest,
        .name = wsName,
        .healthCheck = wsHealthCheck,
        .supportsStreamingOutbound = wsSupportsStreamingOutbound,
    };

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WebConfig) WebChannel {
        const clamped_max_connections: u16 = if (@as(usize, cfg.max_connections) > ConnectionList.MAX_TRACKED)
            @intCast(ConnectionList.MAX_TRACKED)
        else
            cfg.max_connections;
        const normalized_path = config_types.WebConfig.normalizePath(cfg.path);
        const normalized_max_handshake_size: u16 = if (cfg.max_handshake_size == 0)
            config_types.WebConfig.DEFAULT_MAX_HANDSHAKE_SIZE
        else
            cfg.max_handshake_size;
        return .{
            .allocator = allocator,
            .transport = parseTransport(cfg.transport),
            .port = cfg.port,
            .listen_address = cfg.listen,
            .ws_path = normalized_path,
            .max_connections = clamped_max_connections,
            .max_handshake_size = normalized_max_handshake_size,
            .account_id = cfg.account_id,
            .configured_auth_token = cfg.auth_token,
            .allowed_origins = cfg.allowed_origins,
            .relay_url = cfg.relay_url,
            .relay_agent_id = cfg.relay_agent_id,
            .configured_relay_token = cfg.relay_token,
            .relay_token_ttl_secs = cfg.relay_token_ttl_secs,
            .relay_pairing_code_ttl_secs = cfg.relay_pairing_code_ttl_secs,
            .relay_ui_token_ttl_secs = cfg.relay_ui_token_ttl_secs,
            .relay_e2e_required = cfg.relay_e2e_required,
            .message_auth_mode = parseMessageAuthMode(cfg.message_auth_mode),
        };
    }

    fn parseTransport(raw: []const u8) WebTransport {
        if (config_types.WebConfig.isRelayTransport(raw)) return .relay;
        return .local;
    }

    fn parseMessageAuthMode(raw: []const u8) MessageAuthMode {
        if (config_types.WebConfig.isTokenMessageAuthMode(raw)) return .token;
        if (config_types.WebConfig.isValidMessageAuthMode(raw)) return .pairing;
        return .invalid;
    }

    pub fn channel(self: *WebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setBus(self: *WebChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    fn setActiveToken(self: *WebChannel, raw: []const u8) !void {
        if (!config_types.WebConfig.isValidAuthToken(raw)) return error.InvalidAuthToken;
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        @memset(self.token[0..], 0);
        @memcpy(self.token[0..trimmed.len], trimmed);
        self.token_len = @intCast(trimmed.len);
        self.token_initialized = true;
    }

    fn loadTokenFromEnvCandidates(self: *WebChannel, env_candidates: []const []const u8) !bool {
        for (env_candidates) |name| {
            if (std_compat.process.getEnvVarOwned(self.allocator, name)) |raw| {
                defer self.allocator.free(raw);
                self.setActiveToken(raw) catch |err| {
                    if (err == error.InvalidAuthToken) {
                        log.warn("Ignoring invalid Web channel auth token from env {s}", .{name});
                        continue;
                    }
                    return err;
                };
                log.info("Web channel auth token loaded from env {s}", .{name});
                return true;
            } else |_| {}
        }
        return false;
    }

    fn loadLocalTokenFromEnv(self: *WebChannel) !bool {
        return self.loadTokenFromEnvCandidates(&.{
            "NULLCLAW_WEB_TOKEN",
            "NULLCLAW_GATEWAY_TOKEN",
            "OPENCLAW_GATEWAY_TOKEN",
        });
    }

    fn loadDedicatedRelayTokenFromEnv(self: *WebChannel) !?[]u8 {
        if (std_compat.process.getEnvVarOwned(self.allocator, "NULLCLAW_RELAY_TOKEN")) |raw| {
            if (!config_types.WebConfig.isValidAuthToken(raw)) {
                log.warn("Ignoring invalid relay token from env NULLCLAW_RELAY_TOKEN", .{});
                self.allocator.free(raw);
                return null;
            }
            return raw;
        } else |_| {}
        return null;
    }

    fn relayCredentialProviderKey(self: *const WebChannel) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "web-relay-{s}", .{self.account_id});
    }

    fn uiJwtCredentialProviderKey(self: *const WebChannel) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "web-ui-jwt-{s}", .{self.account_id});
    }

    fn uiE2eCredentialProviderKey(self: *const WebChannel, client_sub: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "web-ui-e2e-{s}-{s}", .{ self.account_id, client_sub });
    }

    fn persistUiJwtSigningKey(self: *WebChannel) void {
        const provider_key = self.uiJwtCredentialProviderKey() catch |err| {
            log.warn("Web UI JWT key persistence skipped (provider key): {}", .{err});
            return;
        };
        defer self.allocator.free(provider_key);

        const encoded = self.base64UrlEncodeAlloc(&self.jwt_signing_key) catch |err| {
            log.warn("Web UI JWT key persistence skipped (encode): {}", .{err});
            return;
        };
        defer self.allocator.free(encoded);

        auth.saveCredential(self.allocator, provider_key, .{
            .access_token = encoded,
            .refresh_token = null,
            .expires_at = 0,
            .token_type = "Bearer",
        }) catch |err| {
            log.warn("Web UI JWT key persistence failed: {}", .{err});
        };
    }

    fn loadPersistedUiJwtSigningKey(self: *WebChannel) !bool {
        const provider_key = try self.uiJwtCredentialProviderKey();
        defer self.allocator.free(provider_key);

        const stored = try auth.loadCredential(self.allocator, provider_key);
        if (stored == null) return false;

        const token = stored.?;
        defer token.deinit(self.allocator);

        const decoded = self.base64UrlDecodeAlloc(token.access_token) catch {
            log.warn("Ignoring invalid persisted Web UI JWT key (decode failed)", .{});
            return false;
        };
        defer self.allocator.free(decoded);
        if (decoded.len != self.jwt_signing_key.len) {
            log.warn("Ignoring invalid persisted Web UI JWT key (len={d})", .{decoded.len});
            return false;
        }

        @memcpy(self.jwt_signing_key[0..], decoded[0..self.jwt_signing_key.len]);
        return true;
    }

    fn persistE2eSession(self: *WebChannel, client_sub: []const u8, e2e: E2eSession) void {
        const provider_key = self.uiE2eCredentialProviderKey(client_sub) catch |err| {
            log.warn("Web UI e2e session persistence skipped (provider key): {}", .{err});
            return;
        };
        defer self.allocator.free(provider_key);

        const encoded = self.base64UrlEncodeAlloc(&e2e.key) catch |err| {
            log.warn("Web UI e2e session persistence skipped (encode): {}", .{err});
            return;
        };
        defer self.allocator.free(encoded);

        const expires_at: i64 = std_compat.time.timestamp() + @as(i64, @intCast(self.relay_ui_token_ttl_secs));
        auth.saveCredential(self.allocator, provider_key, .{
            .access_token = encoded,
            .refresh_token = null,
            .expires_at = expires_at,
            .token_type = "Bearer",
        }) catch |err| {
            log.warn("Web UI e2e session persistence failed: {}", .{err});
        };
    }

    fn loadPersistedE2eSession(self: *WebChannel, client_sub: []const u8) ?E2eSession {
        const provider_key = self.uiE2eCredentialProviderKey(client_sub) catch return null;
        defer self.allocator.free(provider_key);

        const stored = auth.loadCredential(self.allocator, provider_key) catch return null;
        if (stored == null) return null;

        const token = stored.?;
        defer token.deinit(self.allocator);

        const decoded = self.base64UrlDecodeAlloc(token.access_token) catch return null;
        defer self.allocator.free(decoded);
        if (decoded.len != 32) return null;

        var key: [32]u8 = undefined;
        @memcpy(key[0..], decoded[0..32]);
        return .{ .key = key };
    }

    fn generateRelayLifecycleToken(self: *WebChannel) ![]u8 {
        var random_bytes: [32]u8 = undefined;
        std_compat.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        return std.fmt.allocPrint(self.allocator, "zcr_{s}", .{hex});
    }

    fn persistRelayLifecycleToken(self: *WebChannel, token: []const u8) void {
        const provider_key = self.relayCredentialProviderKey() catch |err| {
            log.warn("Web relay token persistence skipped (provider key): {}", .{err});
            return;
        };
        defer self.allocator.free(provider_key);

        const expires_at: i64 = std_compat.time.timestamp() + @as(i64, @intCast(self.relay_token_ttl_secs));
        auth.saveCredential(self.allocator, provider_key, .{
            .access_token = token,
            .refresh_token = null,
            .expires_at = expires_at,
            .token_type = "Bearer",
        }) catch |err| {
            log.warn("Web relay token persistence failed: {}", .{err});
        };
    }

    fn resolveRelayToken(self: *WebChannel) !RelayTokenResolution {
        if (self.configured_relay_token) |token| {
            if (!config_types.WebConfig.isValidAuthToken(token)) return error.InvalidAuthToken;
            return .{
                .token = try self.allocator.dupe(u8, std.mem.trim(u8, token, " \t\r\n")),
                .source = .config,
            };
        }

        if (try self.loadDedicatedRelayTokenFromEnv()) |env_token| {
            errdefer self.allocator.free(env_token);
            self.persistRelayLifecycleToken(env_token);
            return .{
                .token = env_token,
                .source = .env,
            };
        }

        const provider_key = try self.relayCredentialProviderKey();
        defer self.allocator.free(provider_key);
        if (try auth.loadCredential(self.allocator, provider_key)) |stored| {
            defer stored.deinit(self.allocator);
            if (config_types.WebConfig.isValidAuthToken(stored.access_token)) {
                return .{
                    .token = try self.allocator.dupe(u8, stored.access_token),
                    .source = .stored,
                };
            }
            log.warn("Stored relay token is invalid, generating a new lifecycle token", .{});
        }

        const generated = try self.generateRelayLifecycleToken();
        errdefer self.allocator.free(generated);
        self.persistRelayLifecycleToken(generated);
        return .{
            .token = generated,
            .source = .generated,
        };
    }

    fn clearSessionBindingsUnlocked(self: *WebChannel) void {
        var it = self.session_client_bindings.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.client_sub);
        }
        self.session_client_bindings.deinit(self.allocator);
        self.session_client_bindings = .empty;
    }

    fn clearE2eSessionsUnlocked(self: *WebChannel) void {
        var it = self.e2e_sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.e2e_sessions.deinit(self.allocator);
        self.e2e_sessions = .empty;
    }

    fn deinitRelaySecurityState(self: *WebChannel) void {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        if (self.relay_pairing_guard) |*guard| {
            guard.deinit();
        }
        self.relay_pairing_guard = null;
        self.relay_pairing_issued_at = 0;
        self.jwt_ready = false;
        @memset(self.jwt_signing_key[0..], 0);
        self.clearSessionBindingsUnlocked();
        self.clearE2eSessionsUnlocked();
    }

    fn initRelaySecurityState(self: *WebChannel) !void {
        self.deinitRelaySecurityState();
        const pairing_enabled = !(self.transport == .local and self.message_auth_mode == .token);
        if (pairing_enabled) {
            if (try self.loadPersistedUiJwtSigningKey()) {
                log.info("Web UI JWT signing key loaded from persisted store", .{});
            } else {
                std_compat.crypto.random.bytes(&self.jwt_signing_key);
                self.persistUiJwtSigningKey();
                log.info("Web UI JWT signing key generated and persisted", .{});
            }
            self.jwt_ready = true;
        } else {
            self.jwt_ready = false;
            @memset(self.jwt_signing_key[0..], 0);
        }
        self.relay_pairing_guard = try pairing_mod.PairingGuard.init(self.allocator, pairing_enabled, &.{});
        self.relay_pairing_issued_at = if (pairing_enabled) std_compat.time.timestamp() else 0;

        if (self.transport == .local) {
            if (self.relay_pairing_guard) |*guard| {
                if (guard.pairingCode()) |code| {
                    var pairing_log_buf: [160]u8 = undefined;
                    self.relay_pairing_issued_at = std_compat.time.timestamp();
                    log.info("{s}", .{localPairingLogMessage(&pairing_log_buf, self.relay_pairing_code_ttl_secs, null, code)});
                }
            }
        } else if (self.relay_pairing_guard) |*guard| {
            if (guard.pairingCode()) |code| {
                var pairing_log_buf: [160]u8 = undefined;
                log.info("{s}", .{relayPairingLogMessage(&pairing_log_buf, self.relay_pairing_code_ttl_secs, null, code)});
            }
        }
    }

    fn relayPairingCodeExpiredLocked(self: *const WebChannel) bool {
        if (self.transport == .local) return false;
        if (self.relay_pairing_issued_at == 0) return true;
        const age = std_compat.time.timestamp() - self.relay_pairing_issued_at;
        return age > @as(i64, @intCast(self.relay_pairing_code_ttl_secs));
    }

    fn relayPairingCodeExpired(self: *WebChannel) bool {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();
        return self.relayPairingCodeExpiredLocked();
    }

    fn relayPairingLogMessage(buf: []u8, ttl_secs: u32, reason: ?[]const u8, code: []const u8) []const u8 {
        _ = code;
        if (reason) |why| {
            return std.fmt.bufPrint(buf, "Web relay pairing code rotated ({s}, one-time, {d}s TTL, value hidden)", .{
                why,
                ttl_secs,
            }) catch "Web relay pairing code rotated (value hidden)";
        }
        return std.fmt.bufPrint(buf, "Web relay pairing code generated (one-time, {d}s TTL, value hidden)", .{
            ttl_secs,
        }) catch "Web relay pairing code generated (value hidden)";
    }

    fn localPairingLogMessage(buf: []u8, ttl_secs: u32, reason: ?[]const u8, code: []const u8) []const u8 {
        _ = ttl_secs;
        _ = code;
        if (reason) |why| {
            return std.fmt.bufPrint(buf, "Web local pairing code rotated ({s}, loopback-only, one-time, value hidden)", .{
                why,
            }) catch "Web local pairing code rotated (value hidden)";
        }
        return std.fmt.bufPrint(buf, "Web local pairing code ready (loopback-only, one-time, value hidden)", .{}) catch "Web local pairing code ready (value hidden)";
    }

    fn rotateRelayPairingCodeLocked(self: *WebChannel, reason: []const u8) void {
        if (self.transport == .local) {
            if (self.relay_pairing_guard) |*guard| {
                if (guard.regeneratePairingCode()) |code| {
                    self.relay_pairing_issued_at = std_compat.time.timestamp();
                    if (!std.mem.eql(u8, reason, "consumed")) {
                        var pairing_log_buf: [160]u8 = undefined;
                        log.info("{s}", .{localPairingLogMessage(&pairing_log_buf, self.relay_pairing_code_ttl_secs, reason, code)});
                    }
                }
            }
            return;
        }

        if (self.relay_pairing_guard) |*guard| {
            if (guard.regeneratePairingCode()) |code| {
                var pairing_log_buf: [160]u8 = undefined;
                self.relay_pairing_issued_at = std_compat.time.timestamp();
                log.info("{s}", .{relayPairingLogMessage(&pairing_log_buf, self.relay_pairing_code_ttl_secs, reason, code)});
            }
        }
    }

    fn rotateRelayPairingCode(self: *WebChannel, reason: []const u8) void {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();
        self.rotateRelayPairingCodeLocked(reason);
    }

    /// Generate a random auth token (64 hex chars from 32 random bytes).
    pub fn generateToken(self: *WebChannel) void {
        var random_bytes: [32]u8 = undefined;
        std_compat.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        @memset(self.token[0..], 0);
        @memcpy(self.token[0..hex.len], &hex);
        self.token_len = @intCast(hex.len);
        self.token_initialized = true;
    }

    /// Validate a token string against the stored token.
    pub fn validateToken(self: *const WebChannel, candidate: []const u8) bool {
        if (!self.token_initialized) return false;
        const active = self.token[0..self.token_len];
        if (candidate.len != active.len) return false;
        var diff: u8 = 0;
        for (candidate, active) |a, b| diff |= a ^ b;
        return diff == 0;
    }

    fn activeToken(self: *const WebChannel) []const u8 {
        if (!self.token_initialized) return "";
        return self.token[0..self.token_len];
    }

    fn base64UrlEncodeAlloc(self: *const WebChannel, input: []const u8) ![]u8 {
        const Encoder = std.base64.url_safe_no_pad.Encoder;
        const out_len = Encoder.calcSize(input.len);
        const out = try self.allocator.alloc(u8, out_len);
        _ = Encoder.encode(out, input);
        return out;
    }

    fn base64UrlDecodeAlloc(self: *const WebChannel, input: []const u8) ![]u8 {
        const Decoder = std.base64.url_safe_no_pad.Decoder;
        const out_len = try Decoder.calcSizeForSlice(input);
        const out = try self.allocator.alloc(u8, out_len);
        errdefer self.allocator.free(out);
        try Decoder.decode(out, input);
        return out;
    }

    fn deriveClientSubjectFromPairToken(self: *WebChannel, pair_token: []const u8) ![]u8 {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(pair_token, &hash, .{});
        const hex = std.fmt.bytesToHex(hash, .lower);
        return std.fmt.allocPrint(self.allocator, "ui-{s}", .{hex[0..16]});
    }

    fn issueUiAccessToken(self: *WebChannel, client_sub: []const u8) ![]u8 {
        if (!self.jwt_ready) return error.InvalidState;

        const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const now = std_compat.time.timestamp();
        const exp = now + @as(i64, @intCast(self.relay_ui_token_ttl_secs));

        var payload_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer payload_buf.deinit(self.allocator);
        var payload_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &payload_buf);
        const pw = &payload_writer.writer;
        try pw.writeAll("{\"sub\":");
        try root.appendJsonStringW(pw, client_sub);
        try pw.writeAll(",\"aid\":");
        try root.appendJsonStringW(pw, self.account_id);
        try pw.print(",\"iat\":{d},\"exp\":{d}", .{ now, exp });
        try pw.writeByte('}');
        payload_buf = payload_writer.toArrayList();

        const header_b64 = try self.base64UrlEncodeAlloc(header_json);
        defer self.allocator.free(header_b64);
        const payload_b64 = try self.base64UrlEncodeAlloc(payload_buf.items);
        defer self.allocator.free(payload_b64);

        const signing_input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ header_b64, payload_b64 });
        defer self.allocator.free(signing_input);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var sig: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&sig, signing_input, &self.jwt_signing_key);
        const sig_b64 = try self.base64UrlEncodeAlloc(&sig);
        defer self.allocator.free(sig_b64);

        return std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ signing_input, sig_b64 });
    }

    fn verifyUiAccessToken(self: *WebChannel, token: []const u8) ?VerifiedJwt {
        if (!self.jwt_ready) return null;

        const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return null;
        const rest = token[first_dot + 1 ..];
        const second_dot_rel = std.mem.indexOfScalar(u8, rest, '.') orelse return null;
        const second_dot = first_dot + 1 + second_dot_rel;
        const header_b64 = token[0..first_dot];
        const payload_b64 = token[first_dot + 1 .. second_dot];
        const sig_b64 = token[second_dot + 1 ..];
        if (header_b64.len == 0 or payload_b64.len == 0 or sig_b64.len == 0) return null;

        const signing_input = token[0..second_dot];
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var expected_sig: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&expected_sig, signing_input, &self.jwt_signing_key);

        const provided_sig = self.base64UrlDecodeAlloc(sig_b64) catch return null;
        defer self.allocator.free(provided_sig);
        if (provided_sig.len != HmacSha256.mac_length) return null;

        var sig_diff: u8 = 0;
        for (provided_sig, expected_sig) |a, b| sig_diff |= a ^ b;
        if (sig_diff != 0) return null;

        const payload = self.base64UrlDecodeAlloc(payload_b64) catch return null;
        defer self.allocator.free(payload);
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return null;
        defer parsed.deinit();
        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return null,
        };

        const sub_val = obj.get("sub") orelse return null;
        if (sub_val != .string or sub_val.string.len == 0) return null;
        const aid_val = obj.get("aid") orelse return null;
        if (aid_val != .string or !std.mem.eql(u8, aid_val.string, self.account_id)) return null;
        const exp_val = obj.get("exp") orelse return null;
        const exp: i64 = switch (exp_val) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            else => return null,
        };
        if (std_compat.time.timestamp() >= exp) return null;

        return .{
            .sub = self.allocator.dupe(u8, sub_val.string) catch return null,
            .exp = exp,
        };
    }

    /// Bind a conversation to its first authenticated UI principal for the
    /// lifetime of that principal's JWT. A newly paired client may reclaim the
    /// session only after the old binding has expired.
    fn bindSessionToClient(self: *WebChannel, session_id: []const u8, client_sub: []const u8, expires_at: i64) !bool {
        if (session_id.len == 0 or session_id.len > MAX_SESSION_ID_BYTES) return error.InvalidSessionId;
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        const now = std_compat.time.timestamp();
        self.evictExpiredSessionBindingsLocked(now);
        if (self.session_client_bindings.getPtr(session_id)) |existing| {
            if (std.mem.eql(u8, existing.client_sub, client_sub)) {
                existing.expires_at = expires_at;
                return true;
            }
            if (now < existing.expires_at) return false;

            const replacement = try self.allocator.dupe(u8, client_sub);
            self.allocator.free(existing.client_sub);
            existing.* = .{
                .client_sub = replacement,
                .expires_at = expires_at,
            };
            return true;
        }
        if (self.session_client_bindings.count() >= MAX_SESSION_CLIENT_BINDINGS) {
            return error.TooManySessionBindings;
        }

        const key_copy = try self.allocator.dupe(u8, session_id);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, client_sub);
        errdefer self.allocator.free(value_copy);
        try self.session_client_bindings.put(self.allocator, key_copy, .{
            .client_sub = value_copy,
            .expires_at = expires_at,
        });
        return true;
    }

    fn evictExpiredSessionBindingsLocked(self: *WebChannel, now: i64) void {
        var it = self.session_client_bindings.iterator();
        while (it.next()) |entry| {
            if (now < entry.value_ptr.expires_at) continue;
            const owned_session_id = entry.key_ptr.*;
            const owned_client_sub = entry.value_ptr.client_sub;
            self.session_client_bindings.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_session_id);
            self.allocator.free(owned_client_sub);
        }
    }

    fn sessionBindingMatches(self: *WebChannel, session_id: []const u8, client_sub: []const u8) bool {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        const existing = self.session_client_bindings.get(session_id) orelse return false;
        return std_compat.time.timestamp() < existing.expires_at and
            std.mem.eql(u8, existing.client_sub, client_sub);
    }

    fn upsertE2eSession(self: *WebChannel, client_sub: []const u8, e2e: E2eSession) !void {
        {
            self.relay_security_mu.lock();
            defer self.relay_security_mu.unlock();

            if (self.e2e_sessions.getPtr(client_sub)) |existing| {
                existing.* = e2e;
            } else {
                const key_copy = try self.allocator.dupe(u8, client_sub);
                errdefer self.allocator.free(key_copy);
                try self.e2e_sessions.put(self.allocator, key_copy, e2e);
            }
        }

        self.persistE2eSession(client_sub, e2e);
    }

    fn e2eSessionByClient(self: *WebChannel, client_sub: []const u8) ?E2eSession {
        {
            self.relay_security_mu.lock();
            defer self.relay_security_mu.unlock();
            if (self.e2e_sessions.get(client_sub)) |session| return session;
        }

        if (self.loadPersistedE2eSession(client_sub)) |persisted| {
            self.upsertE2eSession(client_sub, persisted) catch {};
            return persisted;
        }
        return null;
    }

    fn e2eSessionByChat(self: *WebChannel, session_id: []const u8) ?E2eSession {
        const client_sub_copy = blk: {
            self.relay_security_mu.lock();
            defer self.relay_security_mu.unlock();

            const binding = self.session_client_bindings.get(session_id) orelse break :blk null;
            if (std_compat.time.timestamp() >= binding.expires_at) break :blk null;
            if (self.e2e_sessions.get(binding.client_sub)) |session| return session;
            break :blk self.allocator.dupe(u8, binding.client_sub) catch null;
        };
        if (client_sub_copy) |client_sub| {
            defer self.allocator.free(client_sub);
            return self.e2eSessionByClient(client_sub);
        }
        return null;
    }

    fn deriveE2eSession(self: *WebChannel, client_pub_b64: []const u8) !struct { session: E2eSession, agent_public_b64: []u8 } {
        const expected_public_key_len = std.base64.url_safe_no_pad.Encoder.calcSize(std.crypto.dh.X25519.public_length);
        if (client_pub_b64.len != expected_public_key_len) return error.InvalidClientPublicKey;
        const client_pub_raw = try self.base64UrlDecodeAlloc(client_pub_b64);
        defer self.allocator.free(client_pub_raw);
        if (client_pub_raw.len != std.crypto.dh.X25519.public_length) return error.InvalidClientPublicKey;

        const kp = std.crypto.dh.X25519.KeyPair.generate(std_compat.io());
        const client_pub: [std.crypto.dh.X25519.public_length]u8 = client_pub_raw[0..std.crypto.dh.X25519.public_length].*;
        const shared = try std.crypto.dh.X25519.scalarmult(kp.secret_key, client_pub);

        var key: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("webchannel-e2e-v1");
        hasher.update(&shared);
        hasher.final(&key);

        return .{
            .session = .{ .key = key },
            .agent_public_b64 = try self.base64UrlEncodeAlloc(&kp.public_key),
        };
    }

    fn encryptE2ePayload(self: *WebChannel, key: [32]u8, plaintext: []const u8) !struct { nonce_b64: []u8, ciphertext_b64: []u8 } {
        var nonce: [12]u8 = undefined;
        std_compat.crypto.random.bytes(&nonce);

        const cipher = try self.allocator.alloc(u8, plaintext.len + secret_crypto.TAG_LEN);
        defer self.allocator.free(cipher);
        const encrypted = try secret_crypto.encrypt(key, nonce, plaintext, cipher);

        const nonce_b64 = try self.base64UrlEncodeAlloc(&nonce);
        errdefer self.allocator.free(nonce_b64);
        const ciphertext_b64 = try self.base64UrlEncodeAlloc(encrypted);
        return .{
            .nonce_b64 = nonce_b64,
            .ciphertext_b64 = ciphertext_b64,
        };
    }

    fn decryptE2ePayload(self: *WebChannel, key: [32]u8, nonce_b64: []const u8, ciphertext_b64: []const u8) ![]u8 {
        const Encoder = std.base64.url_safe_no_pad.Encoder;
        if (nonce_b64.len != Encoder.calcSize(12)) return error.InvalidNonce;
        if (ciphertext_b64.len > Encoder.calcSize(MAX_E2E_PAYLOAD_BYTES + secret_crypto.TAG_LEN)) {
            return error.CiphertextTooLarge;
        }
        const nonce_raw = try self.base64UrlDecodeAlloc(nonce_b64);
        defer self.allocator.free(nonce_raw);
        if (nonce_raw.len != 12) return error.InvalidNonce;
        const nonce: [12]u8 = nonce_raw[0..12].*;

        const ciphertext = try self.base64UrlDecodeAlloc(ciphertext_b64);
        defer self.allocator.free(ciphertext);
        if (ciphertext.len < secret_crypto.TAG_LEN) return error.InvalidCiphertext;
        if (ciphertext.len > MAX_E2E_PAYLOAD_BYTES + secret_crypto.TAG_LEN) return error.CiphertextTooLarge;

        var plain_buf: [MAX_E2E_PAYLOAD_BYTES]u8 = undefined;
        const plain = try secret_crypto.decrypt(key, nonce, ciphertext, plain_buf[0..]);
        return try self.allocator.dupe(u8, plain);
    }

    fn sendOutboundEvent(self: *WebChannel, session_id: []const u8, message: []const u8) void {
        switch (self.transport) {
            .local => self.connections.broadcast(session_id, message),
            .relay => {
                self.relay_client_mu.lock();
                defer self.relay_client_mu.unlock();
                if (self.relay_client) |ws| {
                    ws.writeText(message) catch |err| {
                        log.warn("Web relay write failed: {}", .{err});
                    };
                }
            },
        }
    }

    /// Approval requests are security-sensitive control messages. Unlike
    /// ordinary assistant output, their delivery must be confirmed so the
    /// agent does not retain an unreachable pending approval indefinitely.
    fn sendApprovalOutboundEvent(self: *WebChannel, session_id: []const u8, message: []const u8) !void {
        switch (self.transport) {
            .local => {
                self.relay_security_mu.lock();
                defer self.relay_security_mu.unlock();
                const owner: ?[]const u8 = switch (self.message_auth_mode) {
                    .pairing => blk: {
                        const binding = self.session_client_bindings.get(session_id) orelse
                            return error.ApprovalDeliveryUnavailable;
                        if (std_compat.time.timestamp() >= binding.expires_at) {
                            return error.ApprovalDeliveryUnavailable;
                        }
                        break :blk binding.client_sub;
                    },
                    .token => null,
                    .invalid => return error.ApprovalDeliveryUnavailable,
                };
                try self.connections.broadcastApprovalChecked(session_id, owner, message);
            },
            .relay => {
                // WebChannel v1 relay envelopes do not carry an authenticated
                // recipient or delivery acknowledgement. A successful write
                // to the shared agent socket therefore cannot prove that the
                // session owner received this capability. Fail closed until
                // the relay protocol supports owner-addressed, acknowledged
                // control delivery.
                return error.ApprovalDeliveryUnavailable;
            },
        }
    }

    fn eventStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
        if (obj.get(key)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
        return null;
    }

    fn payloadStringField(payload_obj: ?std.json.ObjectMap, key: []const u8) ?[]const u8 {
        if (payload_obj) |obj| {
            return eventStringField(obj, key);
        }
        return null;
    }

    fn requestIdFromEvent(obj: std.json.ObjectMap) ?[]const u8 {
        if (obj.get("request_id")) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
        return null;
    }

    fn sendRelayError(self: *WebChannel, session_id: []const u8, request_id: ?[]const u8, code: []const u8, message: []const u8) void {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        var buf_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &buf);
        const w = &buf_writer.writer;
        w.writeAll("{\"v\":1,\"type\":\"error\",\"session_id\":") catch return;
        root.appendJsonStringW(w, session_id) catch return;
        w.writeAll(",\"agent_id\":") catch return;
        root.appendJsonStringW(w, self.account_id) catch return;
        if (request_id) |rid| {
            w.writeAll(",\"request_id\":") catch return;
            root.appendJsonStringW(w, rid) catch return;
        }
        w.writeAll(",\"payload\":{\"code\":") catch return;
        root.appendJsonStringW(w, code) catch return;
        w.writeAll(",\"message\":") catch return;
        root.appendJsonStringW(w, message) catch return;
        w.writeAll("}}") catch return;
        buf = buf_writer.toArrayList();
        self.sendOutboundEvent(session_id, buf.items);
    }

    fn buildEncryptedRelayPairingResult(
        self: *WebChannel,
        session_id: []const u8,
        request_id: ?[]const u8,
        client_sub: []const u8,
        access_token: []const u8,
        cookie: []const u8,
        agent_public_b64: []const u8,
        e2e_session: E2eSession,
    ) ![]u8 {
        var sensitive_writer: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer sensitive_writer.deinit();
        const sw = &sensitive_writer.writer;
        try sw.writeAll("{\"client_id\":");
        try root.appendJsonStringW(sw, client_sub);
        try sw.writeAll(",\"access_token\":");
        try root.appendJsonStringW(sw, access_token);
        try sw.writeAll(",\"token_type\":\"Bearer\",\"expires_in\":");
        try sw.print("{d}", .{self.relay_ui_token_ttl_secs});
        try sw.writeAll(",\"set_cookie\":");
        try root.appendJsonStringW(sw, cookie);
        try sw.writeAll(",\"e2e_required\":");
        try sw.writeAll(if (self.relay_e2e_required) "true" else "false");
        try sw.writeByte('}');
        var sensitive = sensitive_writer.toArrayList();
        defer {
            @memset(sensitive.items, 0);
            sensitive.deinit(self.allocator);
        }

        const encrypted = try self.encryptE2ePayload(e2e_session.key, sensitive.items);
        defer self.allocator.free(encrypted.nonce_b64);
        defer self.allocator.free(encrypted.ciphertext_b64);

        var response_writer: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer response_writer.deinit();
        const w = &response_writer.writer;
        try w.writeAll("{\"v\":1,\"type\":\"pairing_result\",\"session_id\":");
        try root.appendJsonStringW(w, session_id);
        try w.writeAll(",\"agent_id\":");
        try root.appendJsonStringW(w, self.account_id);
        if (request_id) |rid| {
            try w.writeAll(",\"request_id\":");
            try root.appendJsonStringW(w, rid);
        }
        try w.writeAll(",\"payload\":{\"ok\":true,\"e2e\":{\"alg\":");
        try root.appendJsonStringW(w, E2E_ALG);
        try w.writeAll(",\"agent_pub\":");
        try root.appendJsonStringW(w, agent_public_b64);
        try w.writeAll(",\"nonce\":");
        try root.appendJsonStringW(w, encrypted.nonce_b64);
        try w.writeAll(",\"ciphertext\":");
        try root.appendJsonStringW(w, encrypted.ciphertext_b64);
        try w.writeAll("}}}");
        var response = response_writer.toArrayList();
        defer response.deinit(self.allocator);
        return try response.toOwnedSlice(self.allocator);
    }

    fn handleRelayPairingRequest(
        self: *WebChannel,
        session_id: []const u8,
        request_id: ?[]const u8,
        payload_obj: ?std.json.ObjectMap,
        source_conn: ?*websocket.Conn,
    ) void {
        const pairing_code = payloadStringField(payload_obj, "pairing_code");
        const client_pub = payloadStringField(payload_obj, "client_pub") orelse
            payloadStringField(payload_obj, "client_public_key");

        // Validate and derive the client key before consuming the one-time
        // pairing code. A missing or malformed key must not burn a valid code.
        var agent_public_b64: ?[]u8 = null;
        defer if (agent_public_b64) |value| self.allocator.free(value);
        var pairing_e2e_session: ?E2eSession = null;
        if (client_pub) |public_key| {
            const derived = self.deriveE2eSession(public_key) catch {
                self.sendRelayError(session_id, request_id, "pairing_invalid_client_pub", "client_pub must be a base64url X25519 public key");
                return;
            };
            pairing_e2e_session = derived.session;
            agent_public_b64 = derived.agent_public_b64;
        } else if (self.transport == .relay) {
            // Relay pairing results contain a bearer token but the v1 relay
            // route has no authenticated recipient.
            self.sendRelayError(session_id, request_id, "pairing_client_pub_required", "client_pub is required for secure relay pairing");
            return;
        }

        const PairingAttempt = union(enum) {
            paired: []const u8,
            failed: struct {
                code: []const u8,
                message: []const u8,
            },
        };

        const pair_attempt = blk: {
            self.relay_security_mu.lock();
            defer self.relay_security_mu.unlock();

            if (self.relay_pairing_guard == null) {
                break :blk PairingAttempt{
                    .failed = .{
                        .code = "pairing_unavailable",
                        .message = "pairing flow is not initialized",
                    },
                };
            }
            if (self.relayPairingCodeExpiredLocked()) {
                self.rotateRelayPairingCodeLocked("expired");
                break :blk PairingAttempt{
                    .failed = .{
                        .code = "pairing_code_expired",
                        .message = "pairing code expired; a new code was issued",
                    },
                };
            }

            if (self.relay_pairing_guard) |*guard| {
                const attempt = if (self.transport == .local)
                    guard.attemptPair(guard.pairingCode())
                else
                    guard.attemptPair(pairing_code);
                switch (attempt) {
                    .paired => |token| {
                        self.rotateRelayPairingCodeLocked("consumed");
                        break :blk PairingAttempt{ .paired = token };
                    },
                    .missing_code => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_missing_code",
                            .message = "pairing_code is required",
                        },
                    },
                    .invalid_code => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_invalid_code",
                            .message = "pairing code is invalid",
                        },
                    },
                    .already_paired => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_already_used",
                            .message = "pairing code already consumed",
                        },
                    },
                    .disabled => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_disabled",
                            .message = "pairing is disabled",
                        },
                    },
                    .locked_out => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_locked_out",
                            .message = "too many failed pairing attempts; retry later",
                        },
                    },
                    .internal_error => break :blk PairingAttempt{
                        .failed = .{
                            .code = "pairing_internal_error",
                            .message = "pairing failed",
                        },
                    },
                }
            }

            break :blk PairingAttempt{
                .failed = .{
                    .code = "pairing_internal_error",
                    .message = "pairing flow is not initialized",
                },
            };
        };
        const pair_token = switch (pair_attempt) {
            .paired => |token| token,
            .failed => |failure| {
                self.sendRelayError(session_id, request_id, failure.code, failure.message);
                return;
            },
        };
        defer self.allocator.free(pair_token);

        const client_sub = self.deriveClientSubjectFromPairToken(pair_token) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to derive client identity");
            return;
        };
        defer self.allocator.free(client_sub);

        if (pairing_e2e_session) |session| {
            self.upsertE2eSession(client_sub, session) catch {
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to persist e2e session");
                return;
            };
        }

        const access_token = self.issueUiAccessToken(client_sub) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to issue UI access token");
            return;
        };
        defer {
            @memset(access_token, 0);
            self.allocator.free(access_token);
        }

        const cookie = std.fmt.allocPrint(
            self.allocator,
            "nullclaw_ui_token={s}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={d}",
            .{ access_token, self.relay_ui_token_ttl_secs },
        ) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to build UI cookie");
            return;
        };
        defer {
            @memset(cookie, 0);
            self.allocator.free(cookie);
        }

        if (self.transport == .relay) {
            const pairing_session = pairing_e2e_session orelse {
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "secure relay pairing session is unavailable");
                return;
            };
            const agent_pub = agent_public_b64 orelse {
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "secure relay pairing key is unavailable");
                return;
            };
            const encrypted_response = self.buildEncryptedRelayPairingResult(
                session_id,
                request_id,
                client_sub,
                access_token,
                cookie,
                agent_pub,
                pairing_session,
            ) catch {
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to encrypt UI access token");
                return;
            };
            defer self.allocator.free(encrypted_response);
            self.sendOutboundEvent(session_id, encrypted_response);
            return;
        }

        var response: std.ArrayListUnmanaged(u8) = .empty;
        defer response.deinit(self.allocator);
        var response_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &response);
        const w = &response_writer.writer;
        w.writeAll("{\"v\":1,\"type\":\"pairing_result\",\"session_id\":") catch return;
        root.appendJsonStringW(w, session_id) catch return;
        w.writeAll(",\"agent_id\":") catch return;
        root.appendJsonStringW(w, self.account_id) catch return;
        if (request_id) |rid| {
            w.writeAll(",\"request_id\":") catch return;
            root.appendJsonStringW(w, rid) catch return;
        }
        w.writeAll(",\"payload\":{\"ok\":true,\"client_id\":") catch return;
        root.appendJsonStringW(w, client_sub) catch return;
        w.writeAll(",\"access_token\":") catch return;
        root.appendJsonStringW(w, access_token) catch return;
        w.writeAll(",\"token_type\":\"Bearer\",\"expires_in\":") catch return;
        w.print("{d}", .{self.relay_ui_token_ttl_secs}) catch return;
        w.writeAll(",\"set_cookie\":") catch return;
        root.appendJsonStringW(w, cookie) catch return;
        w.writeAll(",\"e2e_required\":") catch return;
        w.writeAll(if (self.transport == .relay and self.relay_e2e_required) "true" else "false") catch return;
        if (agent_public_b64) |agent_pub| {
            w.writeAll(",\"e2e\":{\"alg\":") catch return;
            root.appendJsonStringW(w, E2E_ALG) catch return;
            w.writeAll(",\"agent_pub\":") catch return;
            root.appendJsonStringW(w, agent_pub) catch return;
            w.writeByte('}') catch return;
        }
        w.writeAll("}}") catch return;
        response = response_writer.toArrayList();
        sendLocalPairingResult(source_conn, response.items) catch |err| {
            log.warn("failed to send local WebChannel pairing result: {}", .{err});
        };
    }

    // ── vtable implementations ──

    fn wsStart(ctx: *anyopaque) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        if (self.message_auth_mode == .invalid) {
            log.warn("Web channel start failed: channels.web.message_auth_mode must be 'pairing' or 'token'", .{});
            return error.InvalidConfiguration;
        }
        if (self.transport == .relay and self.message_auth_mode == .token) {
            log.warn("Web channel start failed: message_auth_mode=token is supported only for local transport", .{});
            return error.InvalidConfiguration;
        }
        switch (self.transport) {
            .local => try self.startLocalTransport(),
            .relay => try self.startRelayTransport(),
        }
    }

    fn ensureLocalTokenSourceCompatible(self: *const WebChannel, token_source: LocalTokenSource) !void {
        if (self.message_auth_mode == .token and token_source == .ephemeral) {
            log.warn("Web channel message_auth_mode=token requires stable auth token from config (channels.web.auth_token) or env (NULLCLAW_WEB_TOKEN/NULLCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_TOKEN)", .{});
            return error.InvalidConfiguration;
        }
    }

    fn startLocalTransport(self: *WebChannel) !void {
        var token_source: LocalTokenSource = .ephemeral;
        if (self.configured_auth_token) |token| {
            try self.setActiveToken(token);
            token_source = .config;
            log.info("Web channel auth token loaded from channels.web auth_token", .{});
        } else if (try self.loadLocalTokenFromEnv()) {
            token_source = .env;
        } else {
            self.generateToken();
            token_source = .ephemeral;
            log.warn("Web channel using ephemeral auth token for this run", .{});
        }

        try self.ensureLocalTokenSourceCompatible(token_source);

        try self.initRelaySecurityState();
        errdefer self.deinitRelaySecurityState();

        self.server = WsServer.init(self.allocator, .{
            .port = self.port,
            .address = self.listen_address,
            .max_conn = @intCast(self.max_connections),
            .handshake = .{
                .max_size = self.max_handshake_size,
            },
        }) catch |err| {
            log.err("Failed to init WebSocket server: {}", .{err});
            return err;
        };

        self.running.store(true, .release);

        self.server_thread = std.Thread.spawn(.{}, serverListenThread, .{self}) catch |err| {
            log.err("Failed to spawn WS server thread: {}", .{err});
            self.running.store(false, .release);
            if (self.server) |*s| s.deinit();
            self.server = null;
            return err;
        };

        log.info("Web channel ready on ws://{s}:{d}{s}", .{ self.listen_address, self.port, self.ws_path });
        switch (token_source) {
            .ephemeral => log.warn("Web channel generated an optional upgrade token for this run (hidden in logs); set channels.web.auth_token or NULLCLAW_WEB_TOKEN/NULLCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_TOKEN for stable automation", .{}),
            .config, .env => log.info("Web channel optional upgrade auth token active (hidden in logs)", .{}),
        }
        self.warnIfOriginAllowlistBroad();
        if (self.message_auth_mode == .token) {
            log.info("Web channel user_message auth mode: token", .{});
        }
    }

    fn startRelayTransport(self: *WebChannel) !void {
        const resolved = try self.resolveRelayToken();
        defer self.allocator.free(resolved.token);
        try self.setActiveToken(resolved.token);
        switch (resolved.source) {
            .config => log.info("Web relay token loaded from channels.web relay_token", .{}),
            .env => log.info("Web relay token loaded from env NULLCLAW_RELAY_TOKEN and persisted", .{}),
            .stored => log.info("Web relay token loaded from persisted lifecycle store", .{}),
            .generated => log.warn("Web relay generated a new lifecycle token and persisted it", .{}),
        }

        try self.initRelaySecurityState();
        errdefer self.deinitRelaySecurityState();

        const relay_url = self.relay_url orelse return error.InvalidConfiguration;
        const endpoint = try parseRelayEndpoint(relay_url);

        var auth_header_buf: [256]u8 = undefined;
        const auth_header = try std.fmt.bufPrint(&auth_header_buf, "Authorization: Bearer {s}", .{self.activeToken()});
        var agent_header_buf: [128]u8 = undefined;
        const agent_header = try std.fmt.bufPrint(&agent_header_buf, "X-NullClaw-Agent: {s}", .{self.relay_agent_id});

        const ws_ptr = try self.allocator.create(ws_client.WsClient);
        errdefer self.allocator.destroy(ws_ptr);
        ws_ptr.* = try ws_client.WsClient.connect(
            self.allocator,
            endpoint.host,
            endpoint.port,
            endpoint.path,
            &.{ auth_header, agent_header, "X-WebChannel-Version: 1" },
        );
        errdefer ws_ptr.deinit();

        self.relay_client_mu.lock();
        self.relay_client = ws_ptr;
        self.relay_client_mu.unlock();
        self.relay_socket_fd.store(ws_ptr.stream.handle, .release);
        self.relay_connected.store(true, .release);
        self.running.store(true, .release);

        self.relay_thread = std.Thread.spawn(.{}, relayReadThread, .{self}) catch |err| {
            self.relay_client_mu.lock();
            self.relay_client = null;
            self.relay_client_mu.unlock();
            self.relay_connected.store(false, .release);
            self.relay_socket_fd.store(invalid_socket, .release);
            self.running.store(false, .release);
            ws_ptr.deinit();
            self.allocator.destroy(ws_ptr);
            self.deinitRelaySecurityState();
            return err;
        };

        log.info("Web relay connected to {s}", .{relay_url});
    }

    fn serverListenThread(self: *WebChannel) void {
        if (self.server) |*s| {
            s.listen(self) catch |err| {
                if (self.running.load(.acquire)) {
                    log.err("WebSocket server listen error: {}", .{err});
                    self.running.store(false, .release);
                }
                return;
            };
            if (self.running.load(.acquire)) {
                log.err("WebSocket server stopped unexpectedly", .{});
                self.running.store(false, .release);
            }
        } else {
            self.running.store(false, .release);
        }
    }

    fn relayReadThread(self: *WebChannel) void {
        while (self.running.load(.acquire)) {
            self.relay_client_mu.lock();
            const ws_ptr = self.relay_client;
            self.relay_client_mu.unlock();
            if (ws_ptr == null) break;

            const message_opt = ws_ptr.?.readTextMessage() catch |err| {
                if (self.running.load(.acquire)) {
                    log.warn("Web relay read failed: {}", .{err});
                }
                break;
            };
            const message = message_opt orelse break;
            defer self.allocator.free(message);

            self.handleInboundEvent(message, null);
        }

        self.relay_connected.store(false, .release);
        self.relay_socket_fd.store(invalid_socket, .release);
        if (self.running.load(.acquire)) {
            self.running.store(false, .release);
            log.warn("Web relay disconnected", .{});
        }
    }

    fn wsStop(ctx: *anyopaque) void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        switch (self.transport) {
            .local => self.stopLocalTransport(),
            .relay => self.stopRelayTransport(),
        }
    }

    fn stopLocalTransport(self: *WebChannel) void {
        self.running.store(false, .release);

        // Stop the server (closes listening socket, triggers listen loop exit)
        if (self.server) |*s| {
            if (comptime builtin.os.tag == .windows) {
                // websocket.zig 0.1.0 on Zig 0.15.2 has a Windows type mismatch in
                // Server.stop(); mimic its logic without posix.shutdown().
                s._mut.lock();
                defer s._mut.unlock();
                for (s._signals) |fd| {
                    std.Io.Threaded.closeFd(fd);
                }
                s._cond.wait(&s._mut);
            } else {
                s.stop();
            }
        }

        if (self.server_thread) |t| {
            t.join();
            self.server_thread = null;
        }

        self.connections.closeAll();

        if (self.server) |*s| {
            s.deinit();
            self.server = null;
        }
        self.deinitRelaySecurityState();
    }

    fn stopRelayTransport(self: *WebChannel) void {
        self.running.store(false, .release);
        self.relay_connected.store(false, .release);

        self.relay_client_mu.lock();
        const ws_ptr = self.relay_client;
        self.relay_client_mu.unlock();
        if (ws_ptr) |ws| {
            ws.writeClose();
        }

        // Unblock blocking read when relay does not answer close.
        // Use shutdown (not close) so WsClient.deinit() performs the final close once.
        const fd = self.relay_socket_fd.load(.acquire);
        if (fd != invalid_socket) {
            (std_compat.net.Stream{ .handle = fd }).shutdown(.recv) catch {};
            self.relay_socket_fd.store(invalid_socket, .release);
        }

        if (self.relay_thread) |t| {
            t.join();
            self.relay_thread = null;
        }

        self.relay_client_mu.lock();
        const client = self.relay_client;
        self.relay_client = null;
        self.relay_client_mu.unlock();
        if (client) |ws| {
            ws.deinit();
            self.allocator.destroy(ws);
        }
        self.deinitRelaySecurityState();
    }

    fn sendAssistantEvent(
        self: *WebChannel,
        target: []const u8,
        message: []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        if (stage == .chunk and message.len == 0) return;

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        var buf_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &buf);
        const w = &buf_writer.writer;

        const session_e2e = self.e2eSessionByChat(target);
        if (self.transport == .relay and session_e2e == null and self.relay_e2e_required) {
            return error.E2eRequired;
        }

        const event_type = switch (stage) {
            .chunk => "assistant_chunk",
            .final => "assistant_final",
        };

        try w.writeAll("{\"v\":1,\"type\":");
        try root.appendJsonStringW(w, event_type);
        try w.writeAll(",\"session_id\":");
        try root.appendJsonStringW(w, target);
        try w.writeAll(",\"agent_id\":");
        try root.appendJsonStringW(w, self.account_id);
        try w.writeAll(",\"payload\":");

        if (session_e2e) |session| {
            var plain_payload: std.ArrayListUnmanaged(u8) = .empty;
            defer plain_payload.deinit(self.allocator);
            var plain_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &plain_payload);
            const pw = &plain_writer.writer;
            try pw.writeAll("{\"content\":");
            try root.appendJsonStringW(pw, message);
            try pw.writeByte('}');
            plain_payload = plain_writer.toArrayList();

            const encrypted = try self.encryptE2ePayload(session.key, plain_payload.items);
            defer self.allocator.free(encrypted.nonce_b64);
            defer self.allocator.free(encrypted.ciphertext_b64);

            try w.writeAll("{\"e2e\":{\"alg\":");
            try root.appendJsonStringW(w, E2E_ALG);
            try w.writeAll(",\"nonce\":");
            try root.appendJsonStringW(w, encrypted.nonce_b64);
            try w.writeAll(",\"ciphertext\":");
            try root.appendJsonStringW(w, encrypted.ciphertext_b64);
            try w.writeAll("}}");
        } else {
            try w.writeAll("{\"content\":");
            try root.appendJsonStringW(w, message);
            try w.writeByte('}');
            try w.writeAll(",\"content\":");
            try root.appendJsonStringW(w, message);
        }

        try w.writeByte('}');
        buf = buf_writer.toArrayList();
        self.sendOutboundEvent(target, buf.items);
    }

    fn buildApprovalRequestEvent(
        self: *WebChannel,
        target: []const u8,
        request: root.Channel.ApprovalRequest,
    ) ![]u8 {
        if (request.request_id.len == 0 or request.request_id.len > MAX_REQUEST_ID_BYTES) {
            return error.InvalidRequestId;
        }
        if (request.action.len == 0 or request.action.len > MAX_APPROVAL_ACTION_BYTES) {
            return error.InvalidApprovalAction;
        }
        if (request.reason.len > MAX_APPROVAL_REASON_BYTES) return error.ApprovalReasonTooLong;

        // The current UI E2E codec only supports message `content`. Local
        // transport may use the authenticated plaintext control envelope so
        // the standard UI remains usable; relay transport crosses an
        // intermediary and therefore stays fail-closed while E2E is active or
        // required.
        const plaintext_with_message_e2e_allowed = self.transport == .local and
            !pairing_mod.isPublicBind(self.listen_address);
        if (!plaintext_with_message_e2e_allowed and
            (self.e2eSessionByChat(target) != null or
                (self.transport == .relay and self.relay_e2e_required)))
        {
            return error.ApprovalE2eUnsupported;
        }

        var buf_writer: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf_writer.deinit();
        const w = &buf_writer.writer;

        try w.writeAll("{\"v\":1,\"type\":\"approval_request\",\"session_id\":");
        try root.appendJsonStringW(w, target);
        try w.writeAll(",\"agent_id\":");
        try root.appendJsonStringW(w, self.account_id);
        try w.writeAll(",\"request_id\":");
        try root.appendJsonStringW(w, request.request_id);
        try w.writeAll(",\"payload\":");

        try w.writeAll("{\"action\":");
        try root.appendJsonStringW(w, request.action);
        if (request.reason.len > 0) {
            try w.writeAll(",\"reason\":");
            try root.appendJsonStringW(w, request.reason);
        }
        try w.writeByte('}');

        try w.writeByte('}');
        var buf = buf_writer.toArrayList();
        defer buf.deinit(self.allocator);
        return try buf.toOwnedSlice(self.allocator);
    }

    fn wsSend(ctx: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        return self.sendAssistantEvent(target, message, .final);
    }

    fn wsSendEvent(
        ctx: *anyopaque,
        target: []const u8,
        message: []const u8,
        _: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        return self.sendAssistantEvent(target, message, stage);
    }

    fn wsSendApprovalRequest(
        ctx: *anyopaque,
        target: []const u8,
        request: root.Channel.ApprovalRequest,
    ) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        const event = try self.buildApprovalRequestEvent(target, request);
        defer self.allocator.free(event);
        try self.sendApprovalOutboundEvent(target, event);
    }

    fn wsName(_: *anyopaque) []const u8 {
        return "web";
    }

    fn wsHealthCheck(ctx: *anyopaque) bool {
        const self: *const WebChannel = @ptrCast(@alignCast(ctx));
        return switch (self.transport) {
            .local => self.running.load(.acquire),
            .relay => self.running.load(.acquire) and self.relay_connected.load(.acquire),
        };
    }

    fn wsSupportsStreamingOutbound(_: *anyopaque) bool {
        return true;
    }

    fn handleInboundEvent(self: *WebChannel, data: []const u8, forced_session_id: ?[]const u8) void {
        self.handleInboundEventFromConnection(data, forced_session_id, null);
    }

    fn handleInboundEventFromConnection(
        self: *WebChannel,
        data: []const u8,
        forced_session_id: ?[]const u8,
        source_conn: ?*websocket.Conn,
    ) void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch {
            log.warn("WS: invalid JSON from client", .{});
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                log.warn("WS: expected JSON object", .{});
                return;
            },
        };

        const event_type = blk: {
            if (obj.get("type")) |type_val| {
                if (type_val != .string or type_val.string.len == 0) return;
                break :blk type_val.string;
            }
            break :blk "user_message";
        };

        var payload_obj: ?std.json.ObjectMap = null;
        if (obj.get("payload")) |payload_val| {
            if (payload_val == .object) payload_obj = payload_val.object;
        }
        const request_id = requestIdFromEvent(obj);

        const session_id = blk: {
            if (forced_session_id) |sid| break :blk sid;
            if (eventStringField(obj, "session_id")) |sid| break :blk sid;
            break :blk "default";
        };
        if (session_id.len == 0 or session_id.len > MAX_SESSION_ID_BYTES) {
            self.sendRelayError("default", request_id, "invalid_session_id", "session_id must be 1..64 bytes");
            return;
        }

        if (forced_session_id) |bound_sid| {
            if (eventStringField(obj, "session_id")) |sid| {
                if (!std.mem.eql(u8, sid, bound_sid)) {
                    log.warn("WS: ignoring session_id override for established connection", .{});
                }
            }
        }

        if (std.mem.eql(u8, event_type, "pairing_request")) {
            if (self.message_auth_mode == .token and self.transport == .local) {
                self.sendRelayError(session_id, request_id, "pairing_disabled", "pairing_request is disabled when message_auth_mode=token");
                return;
            }
            self.handleRelayPairingRequest(session_id, request_id, payload_obj, source_conn);
            return;
        }

        const is_user_message = std.mem.eql(u8, event_type, "user_message");
        const is_approval_response = std.mem.eql(u8, event_type, "approval_response");
        if (!is_user_message and !is_approval_response) return;

        const access_token = payloadStringField(payload_obj, "access_token") orelse eventStringField(obj, "access_token");
        const auth_token = payloadStringField(payload_obj, "auth_token") orelse eventStringField(obj, "auth_token");

        var verified_opt: ?VerifiedJwt = null;
        defer if (verified_opt) |*verified| verified.deinit(self.allocator);

        switch (self.message_auth_mode) {
            .pairing => {
                const ui_access_token = access_token orelse {
                    self.sendRelayError(session_id, request_id, "unauthorized", "access_token is required");
                    return;
                };
                verified_opt = self.verifyUiAccessToken(ui_access_token) orelse {
                    self.sendRelayError(session_id, request_id, "unauthorized", "access_token is invalid or expired");
                    return;
                };

                if (is_approval_response) {
                    if (!self.sessionBindingMatches(session_id, verified_opt.?.sub)) {
                        self.sendRelayError(session_id, request_id, "session_owner_mismatch", "approval_response principal does not own this session");
                        return;
                    }
                } else {
                    const bound = self.bindSessionToClient(session_id, verified_opt.?.sub, verified_opt.?.exp) catch {
                        self.sendRelayError(session_id, request_id, "internal_error", "failed to bind session to UI client");
                        return;
                    };
                    if (!bound) {
                        self.sendRelayError(session_id, request_id, "session_owner_mismatch", "session is bound to another UI client");
                        return;
                    }
                }
            },
            .token => {
                const inbound_token = auth_token orelse access_token orelse {
                    self.sendRelayError(session_id, request_id, "unauthorized", "auth_token is required");
                    return;
                };
                if (!self.validateToken(inbound_token)) {
                    self.sendRelayError(session_id, request_id, "unauthorized", "auth_token is invalid");
                    return;
                }
            },
            .invalid => {
                self.sendRelayError(session_id, request_id, "invalid_configuration", "message_auth_mode is invalid");
                return;
            },
        }

        if (self.transport == .local) {
            if (source_conn) |conn| {
                const principal = if (verified_opt) |verified| verified.sub else null;
                const expires_at = if (verified_opt) |verified| verified.exp else 0;
                if (!self.connections.markAuthenticated(conn, principal, expires_at)) {
                    self.sendRelayError(session_id, request_id, "connection_auth_failed", "failed to bind authenticated WebSocket connection");
                    return;
                }
            }
        }

        if (is_approval_response) {
            const version = obj.get("v") orelse {
                self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response protocol version is required");
                return;
            };
            if (version != .integer or version.integer != 1) {
                self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response protocol version is unsupported");
                return;
            }
            const approval_request_id = request_id orelse {
                self.sendRelayError(session_id, null, "invalid_payload", "approval_response request_id is required");
                return;
            };
            if (approval_request_id.len > MAX_REQUEST_ID_BYTES) {
                self.sendRelayError(session_id, null, "invalid_payload", "approval_response request_id is too long");
                return;
            }
        }
        const authenticated_sub: ?[]const u8 = if (verified_opt) |verified_jwt| verified_jwt.sub else null;

        const e2e_obj = blk: {
            if (payload_obj) |p| {
                if (p.get("e2e")) |value| {
                    if (value == .object) break :blk value.object;
                }
            }
            break :blk null;
        };
        const approval_e2e_active = if (is_approval_response) blk: {
            const verified = verified_opt orelse break :blk false;
            break :blk self.e2eSessionByClient(verified.sub) != null;
        } else false;

        // WebChannel v1 does not define authenticated encryption for the
        // approval envelope fields (type/session/request_id). Accepting an
        // encrypted decision body would allow relay replay/substitution. The
        // outbound side likewise fails closed while any E2E session is active.
        const plaintext_with_message_e2e_allowed = self.transport == .local and
            !pairing_mod.isPublicBind(self.listen_address);
        if (is_approval_response and
            (e2e_obj != null or (approval_e2e_active and !plaintext_with_message_e2e_allowed)))
        {
            self.sendRelayError(session_id, request_id, "approval_e2e_unsupported", "approval_response is unavailable while WebChannel E2E is active");
            return;
        }

        var decrypted_payload_owned: ?[]u8 = null;
        defer if (decrypted_payload_owned) |owned| self.allocator.free(owned);

        if (e2e_obj) |encrypted_obj| {
            if (eventStringField(encrypted_obj, "alg")) |alg| {
                if (!std.mem.eql(u8, alg, E2E_ALG)) {
                    self.sendRelayError(session_id, request_id, "unsupported_e2e_alg", "payload.e2e.alg is not supported");
                    return;
                }
            }
            const verified = verified_opt orelse {
                self.sendRelayError(session_id, request_id, "e2e_requires_pairing", "payload.e2e requires pairing access_token auth");
                return;
            };
            const e2e_session = self.e2eSessionByClient(verified.sub) orelse {
                self.sendRelayError(session_id, request_id, "e2e_not_initialized", "no e2e session is bound to this UI token");
                return;
            };
            const nonce_b64 = eventStringField(encrypted_obj, "nonce") orelse {
                self.sendRelayError(session_id, request_id, "invalid_e2e_payload", "payload.e2e.nonce is required");
                return;
            };
            const ciphertext_b64 = eventStringField(encrypted_obj, "ciphertext") orelse {
                self.sendRelayError(session_id, request_id, "invalid_e2e_payload", "payload.e2e.ciphertext is required");
                return;
            };
            const decrypted_payload = self.decryptE2ePayload(e2e_session.key, nonce_b64, ciphertext_b64) catch {
                self.sendRelayError(session_id, request_id, "e2e_decrypt_failed", "failed to decrypt payload");
                return;
            };
            decrypted_payload_owned = decrypted_payload;

            const decrypted_json = std.json.parseFromSlice(std.json.Value, self.allocator, decrypted_payload, .{}) catch {
                self.sendRelayError(session_id, request_id, "invalid_e2e_payload", "decrypted payload must be valid JSON");
                return;
            };
            defer decrypted_json.deinit();
            const decrypted_obj = switch (decrypted_json.value) {
                .object => |map| map,
                else => {
                    self.sendRelayError(session_id, request_id, "invalid_e2e_payload", "decrypted payload must be an object");
                    return;
                },
            };
            self.handleAuthenticatedPayload(event_type, obj, decrypted_obj, session_id, request_id, authenticated_sub);
            return;
        } else {
            if (self.transport == .relay and self.relay_e2e_required) {
                self.sendRelayError(session_id, request_id, "e2e_required", "web channel requires encrypted payloads");
                return;
            }
            const plain_payload = payload_obj orelse {
                if (is_approval_response) {
                    self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response payload object is required");
                    return;
                }
                self.handleAuthenticatedPayload(event_type, obj, obj, session_id, request_id, authenticated_sub);
                return;
            };
            self.handleAuthenticatedPayload(event_type, obj, plain_payload, session_id, request_id, authenticated_sub);
            return;
        }
    }

    fn handleAuthenticatedPayload(
        self: *WebChannel,
        event_type: []const u8,
        envelope_obj: std.json.ObjectMap,
        payload_obj: std.json.ObjectMap,
        session_id: []const u8,
        request_id: ?[]const u8,
        authenticated_sub: ?[]const u8,
    ) void {
        if (std.mem.eql(u8, event_type, "user_message")) {
            const content = eventStringField(payload_obj, "content") orelse eventStringField(envelope_obj, "content") orelse {
                self.sendRelayError(session_id, request_id, "invalid_payload", "content is required");
                return;
            };
            // Pairing mode is keyed by the verified JWT subject. Token mode has
            // one shared authenticated principal, regardless of sender_id.
            const sender = authenticated_sub orelse "web-token";
            self.publishInboundMessage(sender, session_id, content, request_id);
            return;
        }

        const approval_request_id = request_id orelse {
            self.sendRelayError(session_id, null, "invalid_payload", "approval_response request_id is required");
            return;
        };
        const approved_value = payload_obj.get("approved") orelse {
            self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response payload.approved is required");
            return;
        };
        if (approved_value != .bool) {
            self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response payload.approved must be a boolean");
            return;
        }

        const reason: ?[]const u8 = blk: {
            const reason_value = payload_obj.get("reason") orelse break :blk null;
            if (reason_value != .string) {
                self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response payload.reason must be a string");
                return;
            }
            if (reason_value.string.len > MAX_APPROVAL_REASON_BYTES) {
                self.sendRelayError(session_id, request_id, "invalid_payload", "approval_response payload.reason is too long");
                return;
            }
            if (reason_value.string.len == 0) break :blk null;
            break :blk reason_value.string;
        };

        // Approval decisions are attributed to the authenticated JWT subject.
        // Token mode authenticates every request as the same shared principal;
        // never let an untrusted sender_id split or spoof that identity.
        const sender = authenticated_sub orelse "web-token";
        self.publishInboundApprovalResponse(sender, session_id, approval_request_id, approved_value.bool, reason);
    }

    fn publishInboundMessage(self: *WebChannel, sender_id: []const u8, session_id: []const u8, content: []const u8, request_id: ?[]const u8) void {
        const allocator = self.allocator;
        const session_key = std.fmt.allocPrint(allocator, "web:{s}:direct:{s}", .{
            self.account_id,
            session_id,
        }) catch return;
        defer allocator.free(session_key);

        var metadata_writer: std.Io.Writer.Allocating = .init(allocator);
        defer metadata_writer.deinit();
        const mw = &metadata_writer.writer;
        mw.writeAll("{\"is_dm\":true,\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        if (request_id) |rid| {
            mw.writeAll(",\"request_id\":") catch return;
            root.appendJsonStringW(mw, rid) catch return;
        }
        mw.writeByte('}') catch return;
        var metadata_buf = metadata_writer.toArrayList();
        defer metadata_buf.deinit(allocator);

        const msg = bus_mod.makeInboundFull(
            allocator,
            "web",
            sender_id,
            session_id,
            content,
            session_key,
            &.{},
            metadata_buf.items,
        ) catch |err| {
            log.warn("WS: failed to create inbound message: {}", .{err});
            return;
        };

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("WS: failed to publish inbound: {}", .{err});
                msg.deinit(allocator);
            };
        } else {
            msg.deinit(allocator);
        }
    }

    fn publishInboundApprovalResponse(
        self: *WebChannel,
        sender_id: []const u8,
        session_id: []const u8,
        request_id: []const u8,
        approved: bool,
        reason: ?[]const u8,
    ) void {
        const allocator = self.allocator;
        const session_key = std.fmt.allocPrint(allocator, "web:{s}:direct:{s}", .{
            self.account_id,
            session_id,
        }) catch return;
        defer allocator.free(session_key);

        var metadata_writer: std.Io.Writer.Allocating = .init(allocator);
        defer metadata_writer.deinit();
        const mw = &metadata_writer.writer;
        mw.writeAll("{\"is_dm\":true,\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        mw.writeAll(",\"event_type\":\"approval_response\",\"request_id\":") catch return;
        root.appendJsonStringW(mw, request_id) catch return;
        mw.writeAll(",\"approval_approved\":") catch return;
        mw.writeAll(if (approved) "true" else "false") catch return;
        if (reason) |value| {
            mw.writeAll(",\"approval_reason\":") catch return;
            root.appendJsonStringW(mw, value) catch return;
        }
        mw.writeByte('}') catch return;
        var metadata_buf = metadata_writer.toArrayList();
        defer metadata_buf.deinit(allocator);

        const msg = bus_mod.makeInboundFull(
            allocator,
            "web",
            sender_id,
            session_id,
            "",
            session_key,
            &.{},
            metadata_buf.items,
        ) catch |err| {
            log.warn("WS: failed to create inbound approval response: {}", .{err});
            return;
        };

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("WS: failed to publish inbound approval response: {}", .{err});
                msg.deinit(allocator);
            };
        } else {
            msg.deinit(allocator);
        }
    }

    // ── Connection tracking ──

    pub const ConnectionList = struct {
        mutex: std_compat.sync.Mutex = .{},
        entries: [MAX_TRACKED]?ConnEntry = [_]?ConnEntry{null} ** MAX_TRACKED,

        const MAX_TRACKED = 64;

        const ConnEntry = struct {
            conn: *websocket.Conn,
            session_id: [64]u8 = [_]u8{0} ** 64,
            session_len: u8 = 0,
            authenticated: bool = false,
            client_sub: [MAX_CLIENT_SUB_BYTES]u8 = [_]u8{0} ** MAX_CLIENT_SUB_BYTES,
            client_sub_len: u8 = 0,
            auth_expires_at: i64 = 0,

            fn matchesApprovalRecipient(
                self: *const ConnEntry,
                session_id: []const u8,
                owner: ?[]const u8,
            ) bool {
                if (!self.authenticated) return false;
                if (self.auth_expires_at != 0 and std_compat.time.timestamp() >= self.auth_expires_at) return false;
                if (!std.mem.eql(u8, self.session_id[0..self.session_len], session_id)) return false;
                if (owner) |expected_owner| {
                    return std.mem.eql(u8, self.client_sub[0..self.client_sub_len], expected_owner);
                }
                return true;
            }
        };

        fn add(self: *ConnectionList, conn: *websocket.Conn, session_id: []const u8) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    var entry = ConnEntry{ .conn = conn };
                    const len = @min(session_id.len, 64);
                    @memcpy(entry.session_id[0..len], session_id[0..len]);
                    entry.session_len = @intCast(len);
                    slot.* = entry;
                    return true;
                }
            }
            return false;
        }

        fn remove(self: *ConnectionList, conn: *websocket.Conn) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    if (entry.conn == conn) {
                        slot.* = null;
                        return;
                    }
                }
            }
        }

        fn markAuthenticated(
            self: *ConnectionList,
            conn: *websocket.Conn,
            client_sub: ?[]const u8,
            expires_at: i64,
        ) bool {
            if (client_sub) |sub| {
                if (sub.len == 0 or sub.len > MAX_CLIENT_SUB_BYTES) return false;
            }
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |*entry| {
                    if (entry.conn != conn) continue;
                    entry.authenticated = true;
                    entry.auth_expires_at = expires_at;
                    @memset(entry.client_sub[0..], 0);
                    if (client_sub) |sub| {
                        @memcpy(entry.client_sub[0..sub.len], sub);
                        entry.client_sub_len = @intCast(sub.len);
                    } else {
                        entry.client_sub_len = 0;
                    }
                    return true;
                }
            }
            return false;
        }

        fn broadcast(self: *ConnectionList, session_id: []const u8, data: []const u8) void {
            _ = self.broadcastCount(session_id, data);
        }

        fn broadcastApprovalChecked(
            self: *ConnectionList,
            session_id: []const u8,
            owner: ?[]const u8,
            data: []const u8,
        ) !void {
            if (self.broadcastApprovalCount(session_id, owner, data) == 0) {
                return error.ApprovalDeliveryUnavailable;
            }
        }

        fn broadcastCount(self: *ConnectionList, session_id: []const u8, data: []const u8) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            var delivered: usize = 0;
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    const sid = entry.session_id[0..entry.session_len];
                    if (std.mem.eql(u8, sid, session_id)) {
                        entry.conn.write(data) catch |err| {
                            log.warn("Failed to send to WS client: {}", .{err});
                            slot.* = null;
                            continue;
                        };
                        delivered += 1;
                    }
                }
            }
            return delivered;
        }

        fn broadcastApprovalCount(
            self: *ConnectionList,
            session_id: []const u8,
            owner: ?[]const u8,
            data: []const u8,
        ) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            var delivered: usize = 0;
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    if (!entry.matchesApprovalRecipient(session_id, owner)) continue;
                    entry.conn.write(data) catch |err| {
                        log.warn("Failed to send approval to WS client: {}", .{err});
                        slot.* = null;
                        continue;
                    };
                    delivered += 1;
                }
            }
            return delivered;
        }

        fn closeAll(self: *ConnectionList) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    entry.conn.close(.{ .code = 1001, .reason = "server shutting down" }) catch {};
                    slot.* = null;
                }
            }
        }
    };

    // ── WebSocket Handler (used by websocket.Server) ──

    const WsHandler = struct {
        web_channel: *WebChannel,
        conn: *websocket.Conn,
        session_id: [64]u8 = [_]u8{0} ** 64,
        session_len: u8 = 0,

        pub fn init(h: *websocket.Handshake, conn: *websocket.Conn, web_channel: *WebChannel) !WsHandler {
            const url = h.url;
            const path = trimTrailingSlash(extractPath(url));
            if (!std.mem.eql(u8, path, web_channel.ws_path)) {
                log.warn("WS connection rejected: invalid path '{s}'", .{path});
                return error.Forbidden;
            }

            const auth_header = h.headers.get("authorization");
            const token = extractQueryParam(url, "token") orelse extractBearerToken(auth_header orelse "");
            if (token) |candidate| {
                if (!web_channel.validateToken(candidate)) {
                    log.warn("WS connection rejected: invalid token", .{});
                    return error.Forbidden;
                }
            }

            const origin = h.headers.get("origin");
            if (!isUpgradeOriginAllowed(web_channel.allowed_origins, origin, token != null)) {
                if (origin == null) {
                    log.warn("WS connection rejected: missing origin", .{});
                } else if (web_channel.allowed_origins.len == 0 and token == null) {
                    log.warn("WS connection rejected: browser pairing requires an explicit allowed_origins entry or upgrade token", .{});
                } else {
                    log.warn("WS connection rejected: origin not allowed", .{});
                }
                return error.Forbidden;
            }

            if (token == null) {
                // Pairing-first local UX: allow unauthenticated upgrade only on loopback.
                if (pairing_mod.isPublicBind(web_channel.listen_address)) {
                    log.warn("{s}", .{publicBindTokenRequiredLogMessage(web_channel.message_auth_mode)});
                    return error.Forbidden;
                }
                if (!allowsUnauthenticatedLoopbackUpgrade(web_channel.message_auth_mode)) {
                    log.warn("{s}", .{loopbackTokenRequiredLogMessage()});
                    return error.Forbidden;
                }
                log.info("WS client connected without upgrade token; waiting for pairing_request", .{});
            }

            // Extract session_id from query (optional, default to "default")
            const sid_raw = extractQueryParam(url, "session_id") orelse "default";
            const sid = if (sid_raw.len == 0) "default" else sid_raw;

            var handler = WsHandler{
                .web_channel = web_channel,
                .conn = conn,
            };
            const len = @min(sid.len, 64);
            @memcpy(handler.session_id[0..len], sid[0..len]);
            handler.session_len = @intCast(len);

            if (!web_channel.connections.add(conn, sid)) {
                log.warn("WS connection rejected: connection list full", .{});
                return error.ServiceUnavailable;
            }
            log.info("WS client connected (session={s})", .{sid});

            return handler;
        }

        pub fn clientMessage(self: *WsHandler, data: []const u8) !void {
            const msg_session = self.session_id[0..self.session_len];
            self.web_channel.handleInboundEventFromConnection(data, msg_session, self.conn);
        }

        pub fn close(self: *WsHandler) void {
            self.web_channel.connections.remove(self.conn);
            log.info("WS client disconnected", .{});
        }
    };
};

/// Extract a query parameter value from a URL string.
/// Returns the value slice or null if not found.
fn extractQueryParam(url: []const u8, param_name: []const u8) ?[]const u8 {
    // Find '?' start of query string
    const query_start = std.mem.indexOfScalar(u8, url, '?') orelse return null;
    var remaining = url[query_start + 1 ..];

    while (remaining.len > 0) {
        // Find end of this param (& or end of string)
        const amp = std.mem.indexOfScalar(u8, remaining, '&');
        const pair = if (amp) |i| remaining[0..i] else remaining;

        // Split on '='
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }

        remaining = if (amp) |i| remaining[i + 1 ..] else &.{};
    }

    return null;
}

fn extractPath(url: []const u8) []const u8 {
    const qmark = std.mem.indexOfScalar(u8, url, '?') orelse return url;
    return url[0..qmark];
}

fn trimTrailingSlash(value: []const u8) []const u8 {
    if (value.len <= 1) return value;
    if (value[value.len - 1] == '/') return value[0 .. value.len - 1];
    return value;
}

fn isOriginAllowed(allowed_origins: []const []const u8, origin: []const u8) bool {
    const normalized_origin = trimTrailingSlash(std.mem.trim(u8, origin, " \t\r\n"));
    for (allowed_origins) |entry_raw| {
        const entry = trimTrailingSlash(std.mem.trim(u8, entry_raw, " \t\r\n"));
        if (std.mem.eql(u8, entry, "*")) return true;
        if (std.ascii.eqlIgnoreCase(entry, normalized_origin)) return true;
    }
    return false;
}

/// Browser WebSocket handshakes always carry Origin. With no configured
/// allowlist, possession of a valid upgrade token is the only safe way to
/// accept such a browser connection; native loopback clients without Origin
/// may still use the pairing-first flow.
fn isUpgradeOriginAllowed(
    allowed_origins: []const []const u8,
    origin: ?[]const u8,
    has_valid_upgrade_token: bool,
) bool {
    if (allowed_origins.len > 0) {
        const supplied_origin = origin orelse return false;
        return isOriginAllowed(allowed_origins, supplied_origin);
    }
    if (origin != null and !has_valid_upgrade_token) return false;
    return true;
}

fn sendLocalPairingResult(source_conn: ?*websocket.Conn, response: []const u8) !void {
    // pairing_result contains a bearer token. Never fall back to the ordinary
    // session broadcast when the originating local socket is unavailable.
    const conn = source_conn orelse return error.PairingResponseUnavailable;
    try conn.write(response);
}

fn extractBearerToken(authorization_header: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, authorization_header, " \t\r\n");
    const prefix = "Bearer ";
    if (trimmed.len <= prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(trimmed[0..prefix.len], prefix)) return null;
    const token = std.mem.trim(u8, trimmed[prefix.len..], " \t\r\n");
    if (token.len == 0) return null;
    return token;
}

const RelayEndpoint = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseRelayEndpoint(url: []const u8) !RelayEndpoint {
    const trimmed = std.mem.trim(u8, url, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "wss://")) return error.InvalidRelayUrl;

    const rest = trimmed["wss://".len..];
    if (rest.len == 0) return error.InvalidRelayUrl;

    const path_start = std.mem.indexOfAny(u8, rest, "/?");
    const authority = if (path_start) |idx| rest[0..idx] else rest;
    if (authority.len == 0) return error.InvalidRelayUrl;

    const path = if (path_start) |idx| blk: {
        const p = rest[idx..];
        if (p[0] != '/') return error.InvalidRelayUrl;
        break :blk p;
    } else "/ws";

    var host: []const u8 = authority;
    var port: u16 = 443;

    if (authority[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidRelayUrl;
        host = authority[1..close_idx];
        if (host.len == 0) return error.InvalidRelayUrl;
        const tail = authority[close_idx + 1 ..];
        if (tail.len > 0) {
            if (tail[0] != ':') return error.InvalidRelayUrl;
            if (tail.len == 1) return error.InvalidRelayUrl;
            port = std.fmt.parseInt(u16, tail[1..], 10) catch return error.InvalidRelayUrl;
        }
        return .{ .host = host, .port = port, .path = path };
    }

    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon_idx| {
        const host_part = authority[0..colon_idx];
        const port_part = authority[colon_idx + 1 ..];
        if (host_part.len == 0 or port_part.len == 0) return error.InvalidRelayUrl;
        if (std.mem.indexOfScalar(u8, host_part, ':') != null) return error.InvalidRelayUrl;
        host = host_part;
        port = std.fmt.parseInt(u16, port_part, 10) catch return error.InvalidRelayUrl;
    }

    if (host.len == 0 or std.mem.indexOfAny(u8, host, " \t\r\n") != null) {
        return error.InvalidRelayUrl;
    }
    return .{ .host = host, .port = port, .path = path };
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

fn putTestE2eSession(ch: *WebChannel, client_sub: []const u8, key: [32]u8) !void {
    // Test-only in-memory setup: production upsert persists credentials, which
    // would make unit tests mutate the caller's real auth.json.
    const owned_sub = try ch.allocator.dupe(u8, client_sub);
    errdefer ch.allocator.free(owned_sub);
    try ch.e2e_sessions.put(ch.allocator, owned_sub, .{ .key = key });
}

fn buildApprovalRequestEventAllocationHarness(allocator: std.mem.Allocator) !void {
    var ch = WebChannel.initFromConfig(allocator, .{ .account_id = "web-main" });
    const event = ch.buildApprovalRequestEvent("sess-approval", .{
        .request_id = "0123456789abcdef0123456789abcdef",
        .action = "run guarded command",
        .reason = "policy requires approval",
    }) catch |err| switch (err) {
        // Allocating Writer deliberately erases allocator errors behind its
        // Writer interface; normalize that signal for the std test harness.
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer allocator.free(event);
}

test "WebChannel initFromConfig uses defaults" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectEqual(WebChannel.WebTransport.local, ch.transport);
    try std.testing.expectEqual(@as(u16, 32123), ch.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.listen_address);
    try std.testing.expectEqualStrings(config_types.WebConfig.DEFAULT_PATH, ch.ws_path);
    try std.testing.expectEqual(@as(u16, 10), ch.max_connections);
    try std.testing.expectEqual(config_types.WebConfig.DEFAULT_MAX_HANDSHAKE_SIZE, ch.max_handshake_size);
    try std.testing.expectEqualStrings("default", ch.account_id);
    try std.testing.expect(ch.configured_auth_token == null);
    try std.testing.expectEqual(@as(usize, 0), ch.allowed_origins.len);
    try std.testing.expect(ch.relay_url == null);
    try std.testing.expectEqualStrings("default", ch.relay_agent_id);
    try std.testing.expect(ch.configured_relay_token == null);
    try std.testing.expectEqual(WebChannel.MessageAuthMode.pairing, ch.message_auth_mode);
    try std.testing.expect(ch.bus == null);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "WebChannel initFromConfig uses custom values" {
    const origins = [_][]const u8{
        "http://localhost:5173",
        "chrome-extension://testid",
    };
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .port = 8080,
        .listen = "0.0.0.0",
        .path = "/relay/",
        .max_connections = 5,
        .max_handshake_size = 12_288,
        .account_id = "web-main",
        .auth_token = "test-token-123456",
        .message_auth_mode = "token",
        .allowed_origins = &origins,
    });
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqualStrings("0.0.0.0", ch.listen_address);
    try std.testing.expectEqualStrings("/relay", ch.ws_path);
    try std.testing.expectEqual(@as(u16, 5), ch.max_connections);
    try std.testing.expectEqual(@as(u16, 12_288), ch.max_handshake_size);
    try std.testing.expectEqualStrings("web-main", ch.account_id);
    try std.testing.expectEqualStrings("test-token-123456", ch.configured_auth_token.?);
    try std.testing.expectEqual(WebChannel.MessageAuthMode.token, ch.message_auth_mode);
    try std.testing.expectEqual(@as(usize, 2), ch.allowed_origins.len);
}

test "WebChannel parseMessageAuthMode marks unsupported mode as invalid" {
    try std.testing.expectEqual(WebChannel.MessageAuthMode.pairing, WebChannel.parseMessageAuthMode("pairing"));
    try std.testing.expectEqual(WebChannel.MessageAuthMode.token, WebChannel.parseMessageAuthMode("token"));
    try std.testing.expectEqual(WebChannel.MessageAuthMode.invalid, WebChannel.parseMessageAuthMode("jwt"));
}

test "WebChannel loopback upgrade policy allows pairing mode only" {
    try std.testing.expect(WebChannel.allowsUnauthenticatedLoopbackUpgrade(.pairing));
    try std.testing.expect(!WebChannel.allowsUnauthenticatedLoopbackUpgrade(.token));
    try std.testing.expect(!WebChannel.allowsUnauthenticatedLoopbackUpgrade(.invalid));
}

test "WebChannel requires origin allowlist warning on public bind with empty allowlist" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .listen = "0.0.0.0",
    });
    try std.testing.expect(ch.requiresOriginAllowlistWarning());
}

test "WebChannel requires origin allowlist warning for token mode on loopback" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .message_auth_mode = "token",
    });
    try std.testing.expect(ch.requiresOriginAllowlistWarning());
}

test "WebChannel skips origin allowlist warning when allowlist is configured" {
    const origins = [_][]const u8{"http://localhost:5173"};
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .message_auth_mode = "token",
        .allowed_origins = &origins,
    });
    try std.testing.expect(!ch.requiresOriginAllowlistWarning());
}

test "WebChannel wsStart fails fast for invalid message auth mode" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "jwt",
    });
    try std.testing.expectError(error.InvalidConfiguration, ch.channel().vtable.start(ch.channel().ptr));
}

test "WebChannel wsStart rejects token mode for relay transport" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .message_auth_mode = "token",
        .relay_url = "wss://relay.nullclaw.io/ws/agent",
    });
    try std.testing.expectError(error.InvalidConfiguration, ch.channel().vtable.start(ch.channel().ptr));
}

test "WebChannel initFromConfig maps relay transport settings" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .relay_url = "wss://relay.nullclaw.io/ws/agent",
        .relay_agent_id = "edge-1",
        .relay_token = "relay-token-123456",
    });
    try std.testing.expectEqual(WebChannel.WebTransport.relay, ch.transport);
    try std.testing.expectEqualStrings("wss://relay.nullclaw.io/ws/agent", ch.relay_url.?);
    try std.testing.expectEqualStrings("edge-1", ch.relay_agent_id);
    try std.testing.expectEqualStrings("relay-token-123456", ch.configured_relay_token.?);
}

test "WebChannel initFromConfig falls back to default path for invalid value" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .path = "relay",
    });
    try std.testing.expectEqualStrings(config_types.WebConfig.DEFAULT_PATH, ch.ws_path);
}

test "WebChannel initFromConfig clamps max_connections to tracked limit" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .max_connections = 500,
    });
    try std.testing.expectEqual(@as(u16, 64), ch.max_connections);
}

test "WebChannel initFromConfig normalizes zero handshake size to default" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .max_handshake_size = 0,
    });
    try std.testing.expectEqual(config_types.WebConfig.DEFAULT_MAX_HANDSHAKE_SIZE, ch.max_handshake_size);
}

test "WebChannel vtable name returns web" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("web", iface.name());
}

test "WebChannel builds protocol approval_request envelope" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .account_id = "web-main",
    });
    const event = try ch.buildApprovalRequestEvent("sess-approval", .{
        .request_id = "0123456789abcdef0123456789abcdef",
        .action = "delete \"report\"",
        .reason = "destructive operation",
    });
    defer std.testing.allocator.free(event);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, event, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 1), obj.get("v").?.integer);
    try std.testing.expectEqualStrings("approval_request", obj.get("type").?.string);
    try std.testing.expectEqualStrings("sess-approval", obj.get("session_id").?.string);
    try std.testing.expectEqualStrings("web-main", obj.get("agent_id").?.string);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", obj.get("request_id").?.string);
    const payload = obj.get("payload").?.object;
    try std.testing.expectEqualStrings("delete \"report\"", payload.get("action").?.string);
    try std.testing.expectEqualStrings("destructive operation", payload.get("reason").?.string);

    const oversized_action = "x" ** (WebChannel.MAX_APPROVAL_ACTION_BYTES + 1);
    try std.testing.expectError(error.InvalidApprovalAction, ch.buildApprovalRequestEvent("sess-approval", .{
        .request_id = "0123456789abcdef0123456789abcdef",
        .action = oversized_action,
        .reason = "requires approval",
    }));
}

test "WebChannel approval_request builder releases allocations on failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildApprovalRequestEventAllocationHarness,
        .{},
    );
}

// Regression: pending approval state must not be retained when no WebChannel
// client can receive the corresponding approval_request.
test "WebChannel approval_request fails when target is unavailable" {
    var local = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
    });
    try std.testing.expectError(error.ApprovalDeliveryUnavailable, local.channel().sendApprovalRequest("missing-session", .{
        .request_id = "0123456789abcdef0123456789abcdef",
        .action = "run command",
        .reason = "requires approval",
    }));

    var relay = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
    });
    defer relay.deinitRelaySecurityState();
    // Regression: an active session binding is not a delivery receipt. The
    // v1 relay envelope has no authenticated recipient or UI acknowledgement.
    try std.testing.expect(try relay.bindSessionToClient(
        "bound-session",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));
    try std.testing.expectError(error.ApprovalDeliveryUnavailable, relay.channel().sendApprovalRequest("missing-session", .{
        .request_id = "fedcba9876543210fedcba9876543210",
        .action = "run command",
        .reason = "requires approval",
    }));
    try std.testing.expectError(error.ApprovalDeliveryUnavailable, relay.channel().sendApprovalRequest("bound-session", .{
        .request_id = "00112233445566778899aabbccddeeff",
        .action = "run command",
        .reason = "requires approval",
    }));
}

test "WebChannel approval_request fails closed when an E2E session is active" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    defer ch.deinitRelaySecurityState();
    try std.testing.expect(try ch.bindSessionToClient(
        "sess-e2e-approval",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));
    const key = [_]u8{0x5a} ** 32;
    try putTestE2eSession(&ch, "ui-owner", key);

    try std.testing.expectError(error.ApprovalE2eUnsupported, ch.buildApprovalRequestEvent("sess-e2e-approval", .{
        .request_id = "fedcba9876543210fedcba9876543210",
        .action = "restart gateway",
        .reason = "interrupts active sessions",
    }));
    var required = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .relay_e2e_required = true,
    });
    try std.testing.expectError(error.ApprovalE2eUnsupported, required.buildApprovalRequestEvent("unbound", .{
        .request_id = "00112233445566778899aabbccddeeff",
        .action = "run command",
        .reason = "",
    }));
}

test "WebChannel loopback approval controls remain usable with message E2E" {
    // Regression: the standard local UI negotiates message E2E, but its typed
    // approval controls are authenticated plaintext envelopes in protocol v1.
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .listen = "127.0.0.1",
        .account_id = "local-main",
        // Relay policy must not alter local transport behavior.
        .relay_e2e_required = true,
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();
    ch.jwt_signing_key = [_]u8{0x6b} ** 32;
    ch.jwt_ready = true;
    try std.testing.expect(try ch.bindSessionToClient(
        "sess-local-e2e-approval",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));
    try putTestE2eSession(&ch, "ui-owner", [_]u8{0x44} ** 32);

    const outbound = try ch.buildApprovalRequestEvent("sess-local-e2e-approval", .{
        .request_id = "fedcba9876543210fedcba9876543210",
        .action = "restart gateway",
        .reason = "interrupts active sessions",
    });
    defer std.testing.allocator.free(outbound);
    try std.testing.expect(std.mem.indexOf(u8, outbound, "\"type\":\"approval_request\"") != null);

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    const access_token = try ch.issueUiAccessToken("ui-owner");
    defer std.testing.allocator.free(access_token);
    const inbound = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-local-e2e-approval\",\"request_id\":\"fedcba9876543210fedcba9876543210\",\"payload\":{{\"access_token\":\"{s}\",\"approved\":true}}}}",
        .{access_token},
    );
    defer std.testing.allocator.free(inbound);
    ch.handleInboundEvent(inbound, null);
    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const message = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer message.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, message.metadata_json.?, "\"event_type\":\"approval_response\"") != null);
}

test "WebChannel public local bind rejects approval controls with message E2E" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .listen = "0.0.0.0",
    });
    defer ch.deinitRelaySecurityState();
    try std.testing.expect(try ch.bindSessionToClient(
        "sess-public-e2e-approval",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));
    try putTestE2eSession(&ch, "ui-owner", [_]u8{0x55} ** 32);

    try std.testing.expectError(error.ApprovalE2eUnsupported, ch.buildApprovalRequestEvent("sess-public-e2e-approval", .{
        .request_id = "00112233445566778899aabbccddeeff",
        .action = "run command",
        .reason = "requires approval",
    }));
}

test "WebChannel generateToken produces 64 hex chars" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.token_initialized);
    ch.generateToken();
    try std.testing.expect(ch.token_initialized);
    try std.testing.expectEqual(@as(usize, 64), ch.token_len);
    for (ch.token[0..ch.token_len]) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "WebChannel validateToken accepts correct token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(ch.validateToken(ch.token[0..ch.token_len]));
}

test "WebChannel validateToken rejects wrong token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    var bad_token: [64]u8 = undefined;
    @memset(&bad_token, 'x');
    try std.testing.expect(!ch.validateToken(bad_token[0..]));
}

test "WebChannel validateToken rejects wrong length" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(!ch.validateToken("short"));
    try std.testing.expect(!ch.validateToken(""));
}

test "WebChannel validateToken rejects before init" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.validateToken("a" ** 64));
}

test "WebChannel setBus stores bus reference" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    try std.testing.expect(ch.bus == &bus);
}

test "WebChannel two instances have different tokens" {
    var ch1 = WebChannel.initFromConfig(std.testing.allocator, .{});
    var ch2 = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch1.generateToken();
    ch2.generateToken();
    try std.testing.expect(!std.mem.eql(u8, ch1.token[0..ch1.token_len], ch2.token[0..ch2.token_len]));
}

test "extractQueryParam finds token" {
    try std.testing.expectEqualStrings("abc123", extractQueryParam("/ws?token=abc123", "token").?);
}

test "extractQueryParam finds param among multiple" {
    try std.testing.expectEqualStrings("hello", extractQueryParam("/ws?token=abc&session_id=hello", "session_id").?);
    try std.testing.expectEqualStrings("abc", extractQueryParam("/ws?token=abc&session_id=hello", "token").?);
}

test "extractQueryParam returns null for missing param" {
    try std.testing.expect(extractQueryParam("/ws?token=abc", "session_id") == null);
    try std.testing.expect(extractQueryParam("/ws", "token") == null);
    try std.testing.expect(extractQueryParam("/ws?", "token") == null);
}

test "extractPath strips query" {
    try std.testing.expectEqualStrings("/ws", extractPath("/ws?token=abc"));
    try std.testing.expectEqualStrings("/relay", extractPath("/relay"));
}

test "isOriginAllowed handles exact wildcard and slash normalization" {
    const allowed = [_][]const u8{
        "http://localhost:5173/",
        "chrome-extension://abc",
    };
    try std.testing.expect(isOriginAllowed(&allowed, "http://localhost:5173"));
    try std.testing.expect(isOriginAllowed(&allowed, "chrome-extension://abc/"));
    try std.testing.expect(!isOriginAllowed(&allowed, "https://example.com"));

    const wildcard = [_][]const u8{"*"};
    try std.testing.expect(isOriginAllowed(&wildcard, "https://anything.example"));
}

test "WebChannel upgrade origin policy blocks cross-site unauthenticated pairing" {
    // Regression: a browser page must not use code-less loopback pairing when
    // the operator has not explicitly trusted its Origin.
    try std.testing.expect(!isUpgradeOriginAllowed(&.{}, "https://attacker.example", false));
    try std.testing.expect(isUpgradeOriginAllowed(&.{}, null, false));
    try std.testing.expect(isUpgradeOriginAllowed(&.{}, "https://ui.example", true));

    const allowed = [_][]const u8{"https://ui.example"};
    try std.testing.expect(isUpgradeOriginAllowed(&allowed, "https://ui.example", false));
    try std.testing.expect(!isUpgradeOriginAllowed(&allowed, "https://attacker.example", true));
    try std.testing.expect(!isUpgradeOriginAllowed(&allowed, null, true));
}

test "WebChannel local pairing result never broadcasts without source connection" {
    // Regression: pairing_result carries the UI bearer token and must not fall
    // back to a session-wide broadcast when the requesting socket is missing.
    try std.testing.expectError(
        error.PairingResponseUnavailable,
        sendLocalPairingResult(null, "{\"type\":\"pairing_result\"}"),
    );
}

test "extractBearerToken parses bearer auth header" {
    try std.testing.expectEqualStrings("tok123", extractBearerToken("Bearer tok123").?);
    try std.testing.expectEqualStrings("tok123", extractBearerToken("bearer tok123").?);
    try std.testing.expect(extractBearerToken("Basic abc") == null);
    try std.testing.expect(extractBearerToken("") == null);
}

test "parseRelayEndpoint parses host path and default port" {
    const ep = try parseRelayEndpoint("wss://relay.nullclaw.io/ws/agent");
    try std.testing.expectEqualStrings("relay.nullclaw.io", ep.host);
    try std.testing.expectEqual(@as(u16, 443), ep.port);
    try std.testing.expectEqualStrings("/ws/agent", ep.path);
}

test "parseRelayEndpoint parses explicit port" {
    const ep = try parseRelayEndpoint("wss://relay.nullclaw.io:9443/ws");
    try std.testing.expectEqualStrings("relay.nullclaw.io", ep.host);
    try std.testing.expectEqual(@as(u16, 9443), ep.port);
    try std.testing.expectEqualStrings("/ws", ep.path);
}

test "parseRelayEndpoint rejects non-wss URL" {
    try std.testing.expectError(error.InvalidRelayUrl, parseRelayEndpoint("https://relay.nullclaw.io/ws"));
    try std.testing.expectError(error.InvalidRelayUrl, parseRelayEndpoint("ws://relay.nullclaw.io/ws"));
}

test "WebChannel setActiveToken rejects non url-safe tokens" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectError(error.InvalidAuthToken, ch.setActiveToken("bad token with spaces"));
}

test "ConnectionList add and remove" {
    const list = WebChannel.ConnectionList{};
    // We can't create real websocket.Conn in tests, but we can verify the structure compiles
    try std.testing.expectEqual(@as(usize, 64), list.entries.len);
}

test "ConnectionList approval recipients require matching authenticated principal" {
    var list = WebChannel.ConnectionList{};
    var conn: websocket.Conn = undefined;
    try std.testing.expect(list.add(&conn, "session-a"));

    if (list.entries[0]) |*entry| {
        try std.testing.expect(!entry.matchesApprovalRecipient("session-a", "owner-a"));
    } else return error.TestUnexpectedResult;

    try std.testing.expect(list.markAuthenticated(&conn, "owner-a", std_compat.time.timestamp() + 3600));
    if (list.entries[0]) |*entry| {
        try std.testing.expect(entry.matchesApprovalRecipient("session-a", "owner-a"));
        try std.testing.expect(entry.matchesApprovalRecipient("session-a", null));
        try std.testing.expect(!entry.matchesApprovalRecipient("session-a", "owner-b"));
        try std.testing.expect(!entry.matchesApprovalRecipient("session-b", "owner-a"));
        entry.auth_expires_at = std_compat.time.timestamp();
        try std.testing.expect(!entry.matchesApprovalRecipient("session-a", "owner-a"));
    } else return error.TestUnexpectedResult;
}

test "WebChannel pairing session binding can be reclaimed only after JWT expiry" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    defer ch.deinitRelaySecurityState();

    const now = std_compat.time.timestamp();
    try std.testing.expect(try ch.bindSessionToClient("session-a", "owner-a", now + 3600));
    try std.testing.expect(!try ch.bindSessionToClient("session-a", "owner-b", now + 3600));
    try std.testing.expect(ch.sessionBindingMatches("session-a", "owner-a"));

    ch.session_client_bindings.getPtr("session-a").?.expires_at = now;
    try std.testing.expect(!ch.sessionBindingMatches("session-a", "owner-a"));
    try std.testing.expect(try ch.bindSessionToClient("session-a", "owner-b", now + 3600));
    try std.testing.expect(!ch.sessionBindingMatches("session-a", "owner-a"));
    try std.testing.expect(ch.sessionBindingMatches("session-a", "owner-b"));
    try std.testing.expectEqual(@as(u32, 1), ch.session_client_bindings.count());

    const oversized_session_id = "s" ** (WebChannel.MAX_SESSION_ID_BYTES + 1);
    try std.testing.expectError(
        error.InvalidSessionId,
        ch.bindSessionToClient(oversized_session_id, "owner-c", now + 3600),
    );
}

test "WsHandler clientMessage uses connection session id" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .account_id = "web-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    const access_token = try ch.issueUiAccessToken("ui-conn");
    defer std.testing.allocator.free(access_token);

    var fake_conn: websocket.Conn = undefined;
    var handler = WebChannel.WsHandler{
        .web_channel = &ch,
        .conn = &fake_conn,
    };
    const connection_sid = "conn-session";
    @memcpy(handler.session_id[0..connection_sid.len], connection_sid);
    handler.session_len = @intCast(connection_sid.len);
    try std.testing.expect(ch.connections.add(&fake_conn, connection_sid));
    defer ch.connections.remove(&fake_conn);

    var event_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer event_writer.deinit();
    const w = &event_writer.writer;
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"other-session\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"content\":\"hello\",\"sender_id\":\"user-1\"}}");
    var event_buf = event_writer.toArrayList();
    defer event_buf.deinit(std.testing.allocator);

    try handler.clientMessage(event_buf.items);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("conn-session", msg.chat_id);
    try std.testing.expectEqualStrings("web:web-main:direct:conn-session", msg.session_key);
}

test "WebChannel handleInboundEvent parses v1 envelope payload" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .account_id = "web-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    const access_token = try ch.issueUiAccessToken("ui-1");
    defer std.testing.allocator.free(access_token);

    var event_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer event_buf.deinit(std.testing.allocator);
    var event_writer: std.Io.Writer.Allocating = .fromArrayList(std.testing.allocator, &event_buf);
    const w = &event_writer.writer;
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-42\",\"request_id\":\"req-7\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"content\":\"hello from ui\",\"sender_id\":\"ui-1\"}}");
    event_buf = event_writer.toArrayList();

    const event = event_buf.items;
    ch.handleInboundEvent(event, null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("sess-42", msg.chat_id);
    try std.testing.expectEqualStrings("ui-1", msg.sender_id);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"request_id\":\"req-7\"") != null);
}

test "WebChannel local token mode accepts user_message with auth_token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "web-main",
        .message_auth_mode = "token",
        // Regression: this setting is scoped to relay transport.
        .relay_e2e_required = true,
    });
    try ch.setActiveToken("token-mode-1234567890");

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-token\",\"payload\":{\"auth_token\":\"token-mode-1234567890\",\"content\":\"hello token\",\"sender_id\":\"orchestrator\"}}", null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("sess-token", msg.chat_id);
    // Regression: token-mode sender_id is attacker-controlled and must not
    // become a distinct approval principal.
    try std.testing.expectEqualStrings("web-token", msg.sender_id);
    try std.testing.expectEqualStrings("hello token", msg.content);
}

test "WebChannel local token mode accepts token in access_token field for compatibility" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "web-main",
        .message_auth_mode = "token",
    });
    try ch.setActiveToken("token-mode-1234567890");

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-token\",\"payload\":{\"access_token\":\"token-mode-1234567890\",\"content\":\"hello token\"}}", null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("hello token", msg.content);
}

test "WebChannel local token mode rejects user_message without token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    try ch.setActiveToken("token-mode-1234567890");

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-token\",\"payload\":{\"content\":\"hello\"}}", null);

    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
}

test "WebChannel local token mode rejects user_message with invalid token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    try ch.setActiveToken("token-mode-1234567890");

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-token\",\"payload\":{\"auth_token\":\"wrong-token-xxxxxxxx\",\"content\":\"hello\"}}", null);

    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
}

test "WebChannel approval_response requires token auth and publishes control metadata" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "web-main",
        .message_auth_mode = "token",
    });
    try ch.setActiveToken("approval-token-1234567890");

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-missing-token\",\"payload\":{\"approved\":true}}", null);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-invalid-token\",\"payload\":{\"auth_token\":\"wrong-token-xxxxxxxx\",\"approved\":true}}", null);
    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());

    ch.handleInboundEvent("{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"0123456789abcdef0123456789abcdef\",\"payload\":{\"auth_token\":\"approval-token-1234567890\",\"approved\":false,\"reason\":\"needs review\"}}", null);
    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());

    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("sess-token", msg.chat_id);
    // Regression: a valid response may omit sender_id and still matches the
    // canonical token-mode principal used by the original user message.
    try std.testing.expectEqualStrings("web-token", msg.sender_id);
    try std.testing.expectEqualStrings("", msg.content);
    const metadata = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg.metadata_json.?, .{});
    defer metadata.deinit();
    const metadata_obj = metadata.value.object;
    try std.testing.expectEqualStrings("approval_response", metadata_obj.get("event_type").?.string);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", metadata_obj.get("request_id").?.string);
    try std.testing.expect(!metadata_obj.get("approval_approved").?.bool);
    try std.testing.expectEqualStrings("needs review", metadata_obj.get("approval_reason").?.string);
}

test "WebChannel approval_response rejects malformed protocol fields" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    try ch.setActiveToken("approval-token-1234567890");
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    const malformed = [_][]const u8{
        "{\"v\":2,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"wrong-version\",\"payload\":{\"auth_token\":\"approval-token-1234567890\",\"approved\":true}}",
        "{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"payload\":{\"auth_token\":\"approval-token-1234567890\",\"approved\":true}}",
        "{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-1\",\"payload\":{\"auth_token\":\"approval-token-1234567890\"}}",
        "{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-2\",\"payload\":{\"auth_token\":\"approval-token-1234567890\",\"approved\":\"yes\"}}",
        "{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-3\",\"payload\":{\"auth_token\":\"approval-token-1234567890\",\"approved\":true,\"reason\":7}}",
    };
    for (malformed) |event| ch.handleInboundEvent(event, null);

    const too_long_reason = "x" ** (WebChannel.MAX_APPROVAL_REASON_BYTES + 1);
    const oversized = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-token\",\"request_id\":\"req-4\",\"payload\":{{\"auth_token\":\"approval-token-1234567890\",\"approved\":true,\"reason\":\"{s}\"}}}}",
        .{too_long_reason},
    );
    defer std.testing.allocator.free(oversized);
    ch.handleInboundEvent(oversized, null);

    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
}

test "WebChannel approval_response pairing principal must own session" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    defer ch.deinitRelaySecurityState();
    ch.jwt_signing_key = [_]u8{0x2a} ** 32;
    ch.jwt_ready = true;
    try std.testing.expect(try ch.bindSessionToClient(
        "sess-owner",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));

    const owner_token = try ch.issueUiAccessToken("ui-owner");
    defer std.testing.allocator.free(owner_token);
    const attacker_token = try ch.issueUiAccessToken("ui-attacker");
    defer std.testing.allocator.free(attacker_token);

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    const owner_event = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-owner\",\"request_id\":\"owner-request\",\"payload\":{{\"access_token\":\"{s}\",\"approved\":true}}}}",
        .{owner_token},
    );
    defer std.testing.allocator.free(owner_event);
    ch.handleInboundEvent(owner_event, null);
    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());

    const attacker_event = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-owner\",\"request_id\":\"attacker-request\",\"payload\":{{\"access_token\":\"{s}\",\"approved\":true}}}}",
        .{attacker_token},
    );
    defer std.testing.allocator.free(attacker_event);
    ch.handleInboundEvent(attacker_event, null);
    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());

    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ui-owner", msg.sender_id);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"request_id\":\"owner-request\"") != null);
}

test "WebChannel local token mode requires stable token source before start" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    try std.testing.expectError(error.InvalidConfiguration, ch.ensureLocalTokenSourceCompatible(.ephemeral));
    try ch.ensureLocalTokenSourceCompatible(.config);
    try ch.ensureLocalTokenSourceCompatible(.env);
}

test "WebChannel local token mode ignores pairing_request events" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-token\",\"payload\":{\"pairing_code\":\"123456\"}}", null);

    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
    try std.testing.expect(!ch.relay_pairing_guard.?.isPaired());
}

test "WebChannel relay UI access token verify and tamper detect" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    const token = try ch.issueUiAccessToken("ui-test");
    defer std.testing.allocator.free(token);

    var verified = ch.verifyUiAccessToken(token) orelse return error.TestUnexpectedResult;
    defer verified.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ui-test", verified.sub);

    const tampered = try std.testing.allocator.dupe(u8, token);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] = if (tampered[tampered.len - 1] == 'a') 'b' else 'a';
    try std.testing.expect(ch.verifyUiAccessToken(tampered) == null);
}

test "WebChannel token mode does not initialize JWT signing state" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .message_auth_mode = "token",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    try std.testing.expect(!ch.jwt_ready);
    try std.testing.expect(ch.relay_pairing_guard != null);
    try std.testing.expect(!ch.relay_pairing_guard.?.requirePairing());
    try std.testing.expect(ch.relay_pairing_guard.?.pairingCode() == null);
    for (ch.jwt_signing_key) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "WebChannel relay e2e payload helpers roundtrip" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
    });
    const key = [_]u8{0x31} ** 32;
    const plain = "{\"content\":\"hello\"}";

    const encrypted = try ch.encryptE2ePayload(key, plain);
    defer std.testing.allocator.free(encrypted.nonce_b64);
    defer std.testing.allocator.free(encrypted.ciphertext_b64);

    const decrypted = try ch.decryptE2ePayload(key, encrypted.nonce_b64, encrypted.ciphertext_b64);
    defer std.testing.allocator.free(decrypted);
    try std.testing.expectEqualStrings(plain, decrypted);
}

test "WebChannel relay e2e helpers reject oversized encoded fields before decode" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{ .transport = "relay" });
    try std.testing.expectError(
        error.InvalidClientPublicKey,
        ch.deriveE2eSession("A" ** 128),
    );
    try std.testing.expectError(
        error.InvalidNonce,
        ch.decryptE2ePayload([_]u8{0x31} ** 32, "A" ** 128, "AAAA"),
    );

    const nonce = [_]u8{0} ** 12;
    const nonce_b64 = try ch.base64UrlEncodeAlloc(&nonce);
    defer std.testing.allocator.free(nonce_b64);
    const max_ciphertext_b64 = std.base64.url_safe_no_pad.Encoder.calcSize(
        WebChannel.MAX_E2E_PAYLOAD_BYTES + secret_crypto.TAG_LEN,
    );
    const oversized_ciphertext = try std.testing.allocator.alloc(u8, max_ciphertext_b64 + 1);
    defer std.testing.allocator.free(oversized_ciphertext);
    @memset(oversized_ciphertext, 'A');
    try std.testing.expectError(
        error.CiphertextTooLarge,
        ch.decryptE2ePayload([_]u8{0x31} ** 32, nonce_b64, oversized_ciphertext),
    );
}

fn encryptE2ePayloadAllocationHarness(allocator: std.mem.Allocator) !void {
    var ch = WebChannel.initFromConfig(allocator, .{ .transport = "relay" });
    const encrypted = try ch.encryptE2ePayload([_]u8{0x31} ** 32, "{\"content\":\"hello\"}");
    defer allocator.free(encrypted.nonce_b64);
    defer allocator.free(encrypted.ciphertext_b64);
}

test "WebChannel relay e2e encryption releases partial output on allocation failure" {
    // Regression: a ciphertext encoding failure after nonce encoding must not
    // leak the already allocated nonce string.
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        encryptE2ePayloadAllocationHarness,
        .{},
    );
}

test "WebChannel relay pairing result encrypts bearer credentials" {
    // Regression: the relay route is not owner-addressed, so a pairing bearer
    // token must never appear in its plaintext pairing_result envelope.
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    const key = [_]u8{0x42} ** 32;
    const response = try ch.buildEncryptedRelayPairingResult(
        "sess-pair",
        "pair-request",
        "ui-client",
        "secret-ui-bearer",
        "nullclaw_ui_token=secret-ui-bearer",
        "agent-public-key",
        .{ .key = key },
    );
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "secret-ui-bearer") == null);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response, .{});
    defer parsed.deinit();
    const payload = parsed.value.object.get("payload") orelse return error.TestUnexpectedResult;
    const encrypted_value = payload.object.get("e2e") orelse return error.TestUnexpectedResult;
    const nonce = WebChannel.eventStringField(encrypted_value.object, "nonce") orelse return error.TestUnexpectedResult;
    const ciphertext = WebChannel.eventStringField(encrypted_value.object, "ciphertext") orelse return error.TestUnexpectedResult;
    const decrypted = try ch.decryptE2ePayload(key, nonce, ciphertext);
    defer std.testing.allocator.free(decrypted);
    try std.testing.expect(std.mem.indexOf(u8, decrypted, "\"access_token\":\"secret-ui-bearer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, decrypted, "\"set_cookie\":\"nullclaw_ui_token=secret-ui-bearer\"") != null);
}

test "WebChannel relay pairing request rotates one-time code and initializes e2e" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    const code = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    const code_copy = try std.testing.allocator.dupe(u8, code);
    defer std.testing.allocator.free(code_copy);

    const client_kp = std.crypto.dh.X25519.KeyPair.generate(std_compat.io());
    const client_pub_b64 = try ch.base64UrlEncodeAlloc(&client_kp.public_key);
    defer std.testing.allocator.free(client_pub_b64);

    var event_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer event_buf.deinit(std.testing.allocator);
    var event_writer: std.Io.Writer.Allocating = .fromArrayList(std.testing.allocator, &event_buf);
    const w = &event_writer.writer;
    try w.writeAll("{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-pair\",\"payload\":{\"pairing_code\":");
    try root.appendJsonStringW(w, code_copy);
    try w.writeAll(",\"client_pub\":");
    try root.appendJsonStringW(w, client_pub_b64);
    try w.writeAll("}}");
    event_buf = event_writer.toArrayList();

    ch.handleInboundEvent(event_buf.items, null);
    try std.testing.expect(ch.relay_pairing_guard.?.isPaired());
    const next_code = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expect(!std.mem.eql(u8, code_copy, next_code));
    try std.testing.expectEqual(@as(usize, 1), ch.e2e_sessions.count());
}

test "WebChannel relay pairing rejects invalid client key without consuming code" {
    // Regression: the mandatory credential-encryption key is validated before
    // the one-time pairing capability is consumed.
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    const code = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    const code_copy = try std.testing.allocator.dupe(u8, code);
    defer std.testing.allocator.free(code_copy);
    const missing_key_event = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-pair\",\"payload\":{{\"pairing_code\":\"{s}\"}}}}",
        .{code_copy},
    );
    defer std.testing.allocator.free(missing_key_event);
    ch.handleInboundEvent(missing_key_event, null);
    try std.testing.expect(!ch.relay_pairing_guard.?.isPaired());
    try std.testing.expectEqualStrings(code_copy, ch.relay_pairing_guard.?.pairingCode().?);

    const invalid_key_event = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-pair\",\"payload\":{{\"pairing_code\":\"{s}\",\"client_pub\":\"invalid\"}}}}",
        .{code_copy},
    );
    defer std.testing.allocator.free(invalid_key_event);
    ch.handleInboundEvent(invalid_key_event, null);
    try std.testing.expect(!ch.relay_pairing_guard.?.isPaired());
    try std.testing.expectEqualStrings(code_copy, ch.relay_pairing_guard.?.pairingCode().?);
}

test "WebChannel local pairing code is random and rotates" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "local-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    const first = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 6), first.len);
    for (first) |c| {
        try std.testing.expect(std.ascii.isDigit(c));
    }

    ch.relay_pairing_guard.?.failed_count = 4;
    ch.relay_pairing_guard.?.lockout_time = std_compat.time.nanoTimestamp();
    ch.rotateRelayPairingCode("test-rotate");
    const second = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 6), second.len);
    for (second) |c| {
        try std.testing.expect(std.ascii.isDigit(c));
    }
    try std.testing.expectEqual(@as(u32, 0), ch.relay_pairing_guard.?.failed_count);
    try std.testing.expect(ch.relay_pairing_guard.?.lockout_time == null);
}

// Regression: local loopback pairing must not depend on a fixed shared secret.
test "WebChannel local pairing request accepts legacy client code and rotates hidden state" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "local-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    const first = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    const first_copy = try std.testing.allocator.dupe(u8, first);
    defer std.testing.allocator.free(first_copy);

    ch.handleInboundEvent("{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-local\",\"payload\":{\"pairing_code\":\"123456\"}}", null);
    try std.testing.expect(ch.relay_pairing_guard.?.isPaired());
    const second = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expect(second.len == 6);
    try std.testing.expect(!std.mem.eql(u8, first_copy, second));
}

// Regression: local loopback pairing should remain usable without exposing a fixed code.
test "WebChannel local pairing request succeeds without pairing_code payload" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "local-main",
        // Regression: relay-only E2E policy must not require client_pub here.
        .relay_e2e_required = true,
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    ch.handleInboundEvent("{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-local\",\"payload\":{}}", null);
    try std.testing.expect(ch.relay_pairing_guard.?.isPaired());
    try std.testing.expect(ch.relay_pairing_guard.?.pairingCode() != null);
}

test "WebChannel local pairing code never expires" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
        .account_id = "local-main",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    ch.relay_pairing_issued_at = std_compat.time.timestamp() - 86_400;
    try std.testing.expect(!ch.relayPairingCodeExpired());
}

test "WebChannel public bind token guidance mentions loopback-only pairing" {
    try std.testing.expect(std.mem.indexOf(u8, WebChannel.publicBindTokenRequiredLogMessage(.pairing), "loopback-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, WebChannel.publicBindTokenRequiredLogMessage(.pairing), "/ws?token=<auth_token>") != null);
    try std.testing.expect(std.mem.indexOf(u8, WebChannel.publicBindTokenRequiredLogMessage(.token), "Authorization header") != null);
}

test "WebChannel relay pairing log message hides code" {
    var buf: [160]u8 = undefined;
    const msg = WebChannel.relayPairingLogMessage(&buf, 300, "expired", "654321");
    try std.testing.expect(std.mem.indexOf(u8, msg, "654321") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "expired") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "value hidden") != null);
}

test "WebChannel local pairing log message hides pairing code" {
    var buf: [160]u8 = undefined;
    const msg = WebChannel.localPairingLogMessage(&buf, 300, null, "123456");
    try std.testing.expect(std.mem.indexOf(u8, msg, "123456") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "value hidden") != null);
}

test "WebChannel relay encrypted user_message is published to bus" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
        .relay_e2e_required = true,
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    const key = [_]u8{0x44} ** 32;
    try putTestE2eSession(&ch, "ui-42", key);

    const access_token = try ch.issueUiAccessToken("ui-42");
    defer std.testing.allocator.free(access_token);

    const plaintext_payload = "{\"content\":\"secret hello\",\"sender_id\":\"ui-42\"}";
    const encrypted = try ch.encryptE2ePayload(key, plaintext_payload);
    defer std.testing.allocator.free(encrypted.nonce_b64);
    defer std.testing.allocator.free(encrypted.ciphertext_b64);

    var event_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer event_writer.deinit();
    const w = &event_writer.writer;
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-e2e\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"e2e\":{\"nonce\":");
    try root.appendJsonStringW(w, encrypted.nonce_b64);
    try w.writeAll(",\"ciphertext\":");
    try root.appendJsonStringW(w, encrypted.ciphertext_b64);
    try w.writeAll("}}}");
    var event_buf = event_writer.toArrayList();
    defer event_buf.deinit(std.testing.allocator);

    ch.handleInboundEvent(event_buf.items, null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ui-42", msg.sender_id);
    try std.testing.expectEqualStrings("sess-e2e", msg.chat_id);
    try std.testing.expectEqualStrings("secret hello", msg.content);
}

test "WebChannel relay rejects plaintext and replayable encrypted approval responses when E2E is active" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .account_id = "relay-main",
        .relay_e2e_required = false,
    });
    defer ch.deinitRelaySecurityState();
    ch.jwt_signing_key = [_]u8{0x6b} ** 32;
    ch.jwt_ready = true;
    try std.testing.expect(try ch.bindSessionToClient(
        "sess-approval-e2e",
        "ui-owner",
        std_compat.time.timestamp() + 3600,
    ));

    const key = [_]u8{0x44} ** 32;
    try putTestE2eSession(&ch, "ui-owner", key);
    const access_token = try ch.issueUiAccessToken("ui-owner");
    defer std.testing.allocator.free(access_token);

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    const plaintext_event = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-approval-e2e\",\"request_id\":\"plain-request\",\"payload\":{{\"access_token\":\"{s}\",\"approved\":true}}}}",
        .{access_token},
    );
    defer std.testing.allocator.free(plaintext_event);
    ch.handleInboundEvent(plaintext_event, null);
    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());

    const encrypted = try ch.encryptE2ePayload(key, "{\"approved\":false,\"reason\":\"review incomplete\"}");
    defer std.testing.allocator.free(encrypted.nonce_b64);
    defer std.testing.allocator.free(encrypted.ciphertext_b64);
    var event_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer event_writer.deinit();
    const w = &event_writer.writer;
    try w.writeAll("{\"v\":1,\"type\":\"approval_response\",\"session_id\":\"sess-approval-e2e\",\"request_id\":\"encrypted-request\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"e2e\":{\"alg\":");
    try root.appendJsonStringW(w, WebChannel.E2E_ALG);
    try w.writeAll(",\"nonce\":");
    try root.appendJsonStringW(w, encrypted.nonce_b64);
    try w.writeAll(",\"ciphertext\":");
    try root.appendJsonStringW(w, encrypted.ciphertext_b64);
    try w.writeAll("}}}");
    var event_buf = event_writer.toArrayList();
    defer event_buf.deinit(std.testing.allocator);
    ch.handleInboundEvent(event_buf.items, null);

    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());

    // Regression: the same authenticated ciphertext cannot be substituted
    // under another top-level request id because v1 encrypted approvals are
    // rejected until envelope fields are cryptographically bound.
    const replay_event = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        event_buf.items,
        "encrypted-request",
        "substitute-request",
    );
    defer std.testing.allocator.free(replay_event);
    ch.handleInboundEvent(replay_event, null);
    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
}

test "WebChannel relay user_message without access token is rejected" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
    });
    defer ch.deinitRelaySecurityState();
    try ch.initRelaySecurityState();

    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    ch.handleInboundEvent("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-1\",\"payload\":{\"content\":\"hello\"}}", null);
    try std.testing.expectEqual(@as(usize, 0), bus.inboundDepth());
}

test "WebChannel create + healthCheck + stop leaks zero bytes" {
    // WebChannel (local transport) holds no heap allocations at init-time.  No deinit needed.
    var ch_struct = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "local",
    });

    const ch = ch_struct.channel();
    _ = ch.healthCheck();
    ch.stop();
}

test {
    @import("std").testing.refAllDecls(@This());
}
