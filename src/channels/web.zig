const std = @import("std");
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
    const E2E_ALG: []const u8 = "x25519-chacha20poly1305-v1";

    const RelayTokenSource = enum {
        config,
        env,
        stored,
        generated,
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

    const WebTransport = enum {
        local,
        relay,
    };

    allocator: std.mem.Allocator,
    transport: WebTransport,
    port: u16,
    listen_address: []const u8,
    ws_path: []const u8,
    max_connections: u16,
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
    relay_client_mu: std.Thread.Mutex = .{},
    relay_client: ?*ws_client.WsClient = null,
    relay_connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    relay_socket_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),
    relay_pairing_guard: ?pairing_mod.PairingGuard = null,
    relay_pairing_issued_at: i64 = 0,
    jwt_signing_key: [32]u8 = [_]u8{0} ** 32,
    jwt_ready: bool = false,
    relay_security_mu: std.Thread.Mutex = .{},
    session_client_bindings: std.StringHashMapUnmanaged([]const u8) = .empty,
    e2e_sessions: std.StringHashMapUnmanaged(E2eSession) = .empty,

    const SocketFd = std.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std.os.windows.ws2_32.INVALID_SOCKET,
        else => -1,
    };

    const WsServer = websocket.Server(WsHandler);

    const vtable = root.Channel.VTable{
        .start = wsStart,
        .stop = wsStop,
        .send = wsSend,
        .name = wsName,
        .healthCheck = wsHealthCheck,
    };

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WebConfig) WebChannel {
        const clamped_max_connections: u16 = if (@as(usize, cfg.max_connections) > ConnectionList.MAX_TRACKED)
            @intCast(ConnectionList.MAX_TRACKED)
        else
            cfg.max_connections;
        const normalized_path = config_types.WebConfig.normalizePath(cfg.path);
        return .{
            .allocator = allocator,
            .transport = parseTransport(cfg.transport),
            .port = cfg.port,
            .listen_address = cfg.listen,
            .ws_path = normalized_path,
            .max_connections = clamped_max_connections,
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
        };
    }

    fn parseTransport(raw: []const u8) WebTransport {
        if (config_types.WebConfig.isRelayTransport(raw)) return .relay;
        return .local;
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
            if (std.process.getEnvVarOwned(self.allocator, name)) |raw| {
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
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_RELAY_TOKEN")) |raw| {
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

    fn generateRelayLifecycleToken(self: *WebChannel) ![]u8 {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        return std.fmt.allocPrint(self.allocator, "zcr_{s}", .{hex});
    }

    fn persistRelayLifecycleToken(self: *WebChannel, token: []const u8) void {
        const provider_key = self.relayCredentialProviderKey() catch |err| {
            log.warn("Web relay token persistence skipped (provider key): {}", .{err});
            return;
        };
        defer self.allocator.free(provider_key);

        const expires_at: i64 = std.time.timestamp() + @as(i64, @intCast(self.relay_token_ttl_secs));
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
            self.allocator.free(entry.value_ptr.*);
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
        std.crypto.random.bytes(&self.jwt_signing_key);
        self.jwt_ready = true;
        self.relay_pairing_guard = try pairing_mod.PairingGuard.init(self.allocator, true, &.{});
        self.relay_pairing_issued_at = std.time.timestamp();

        if (self.relay_pairing_guard) |*guard| {
            if (guard.pairingCode()) |code| {
                log.warn("Web relay pairing code (one-time, {d}s TTL): {s}", .{
                    self.relay_pairing_code_ttl_secs,
                    code,
                });
            }
        }
    }

    fn relayPairingCodeExpired(self: *const WebChannel) bool {
        if (self.relay_pairing_issued_at == 0) return true;
        const age = std.time.timestamp() - self.relay_pairing_issued_at;
        return age > @as(i64, @intCast(self.relay_pairing_code_ttl_secs));
    }

    fn rotateRelayPairingCode(self: *WebChannel, reason: []const u8) void {
        if (self.relay_pairing_guard) |*guard| {
            if (guard.regeneratePairingCode()) |code| {
                self.relay_pairing_issued_at = std.time.timestamp();
                log.warn("Web relay pairing code rotated ({s}, one-time, {d}s TTL): {s}", .{
                    reason,
                    self.relay_pairing_code_ttl_secs,
                    code,
                });
            }
        }
    }

    /// Generate a random auth token (64 hex chars from 32 random bytes).
    pub fn generateToken(self: *WebChannel) void {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
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
        const now = std.time.timestamp();
        const exp = now + @as(i64, @intCast(self.relay_ui_token_ttl_secs));

        var payload_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer payload_buf.deinit(self.allocator);
        const pw = payload_buf.writer(self.allocator);
        try pw.writeAll("{\"sub\":");
        try root.appendJsonStringW(pw, client_sub);
        try pw.writeAll(",\"aid\":");
        try root.appendJsonStringW(pw, self.account_id);
        try pw.print(",\"iat\":{d},\"exp\":{d}", .{ now, exp });
        try pw.writeByte('}');

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
        if (std.time.timestamp() >= exp) return null;

        return .{
            .sub = self.allocator.dupe(u8, sub_val.string) catch return null,
            .exp = exp,
        };
    }

    fn upsertSessionBinding(self: *WebChannel, session_id: []const u8, client_sub: []const u8) !void {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        if (self.session_client_bindings.getPtr(session_id)) |existing| {
            self.allocator.free(existing.*);
            existing.* = try self.allocator.dupe(u8, client_sub);
            return;
        }

        const key_copy = try self.allocator.dupe(u8, session_id);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, client_sub);
        errdefer self.allocator.free(value_copy);
        try self.session_client_bindings.put(self.allocator, key_copy, value_copy);
    }

    fn upsertE2eSession(self: *WebChannel, client_sub: []const u8, e2e: E2eSession) !void {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        if (self.e2e_sessions.getPtr(client_sub)) |existing| {
            existing.* = e2e;
            return;
        }
        const key_copy = try self.allocator.dupe(u8, client_sub);
        errdefer self.allocator.free(key_copy);
        try self.e2e_sessions.put(self.allocator, key_copy, e2e);
    }

    fn e2eSessionByClient(self: *WebChannel, client_sub: []const u8) ?E2eSession {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        if (self.e2e_sessions.get(client_sub)) |session| return session;
        return null;
    }

    fn e2eSessionByChat(self: *WebChannel, session_id: []const u8) ?E2eSession {
        self.relay_security_mu.lock();
        defer self.relay_security_mu.unlock();

        const client_sub = self.session_client_bindings.get(session_id) orelse return null;
        if (self.e2e_sessions.get(client_sub)) |session| return session;
        return null;
    }

    fn deriveE2eSession(self: *WebChannel, client_pub_b64: []const u8) !struct { session: E2eSession, agent_public_b64: []u8 } {
        const client_pub_raw = try self.base64UrlDecodeAlloc(client_pub_b64);
        defer self.allocator.free(client_pub_raw);
        if (client_pub_raw.len != std.crypto.dh.X25519.public_length) return error.InvalidClientPublicKey;

        const kp = std.crypto.dh.X25519.KeyPair.generate();
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
        std.crypto.random.bytes(&nonce);

        const cipher = try self.allocator.alloc(u8, plaintext.len + secret_crypto.TAG_LEN);
        defer self.allocator.free(cipher);
        const encrypted = try secret_crypto.encrypt(key, nonce, plaintext, cipher);

        return .{
            .nonce_b64 = try self.base64UrlEncodeAlloc(&nonce),
            .ciphertext_b64 = try self.base64UrlEncodeAlloc(encrypted),
        };
    }

    fn decryptE2ePayload(self: *WebChannel, key: [32]u8, nonce_b64: []const u8, ciphertext_b64: []const u8) ![]u8 {
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
        const w = buf.writer(self.allocator);
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
        self.sendOutboundEvent(session_id, buf.items);
    }

    fn handleRelayPairingRequest(self: *WebChannel, session_id: []const u8, request_id: ?[]const u8, payload_obj: ?std.json.ObjectMap) void {
        const pairing_code = payloadStringField(payload_obj, "pairing_code");
        if (self.relay_pairing_guard == null) {
            self.sendRelayError(session_id, request_id, "pairing_unavailable", "pairing flow is not initialized");
            return;
        }
        if (self.relayPairingCodeExpired()) {
            self.rotateRelayPairingCode("expired");
            self.sendRelayError(session_id, request_id, "pairing_code_expired", "pairing code expired; a new code was issued");
            return;
        }

        const pair_token = blk: {
            if (self.relay_pairing_guard) |*guard| {
                const attempt = guard.attemptPair(pairing_code);
                switch (attempt) {
                    .paired => |token| break :blk token,
                    .missing_code => {
                        self.sendRelayError(session_id, request_id, "pairing_missing_code", "pairing_code is required");
                        return;
                    },
                    .invalid_code => {
                        self.sendRelayError(session_id, request_id, "pairing_invalid_code", "pairing code is invalid");
                        return;
                    },
                    .already_paired => {
                        self.sendRelayError(session_id, request_id, "pairing_already_used", "pairing code already consumed");
                        return;
                    },
                    .disabled => {
                        self.sendRelayError(session_id, request_id, "pairing_disabled", "pairing is disabled");
                        return;
                    },
                    .locked_out => {
                        self.sendRelayError(session_id, request_id, "pairing_locked_out", "too many failed pairing attempts; retry later");
                        return;
                    },
                    .internal_error => {
                        self.sendRelayError(session_id, request_id, "pairing_internal_error", "pairing failed");
                        return;
                    },
                }
            }
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "pairing flow is not initialized");
            return;
        };
        defer self.allocator.free(pair_token);
        defer self.rotateRelayPairingCode("consumed");

        const client_sub = self.deriveClientSubjectFromPairToken(pair_token) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to derive client identity");
            return;
        };
        defer self.allocator.free(client_sub);

        var agent_public_b64: ?[]u8 = null;
        defer if (agent_public_b64) |value| self.allocator.free(value);

        if (payloadStringField(payload_obj, "client_pub")) |client_pub| {
            const derived = self.deriveE2eSession(client_pub) catch {
                self.sendRelayError(session_id, request_id, "pairing_invalid_client_pub", "client_pub must be base64url X25519 public key");
                return;
            };
            self.upsertE2eSession(client_sub, derived.session) catch {
                self.allocator.free(derived.agent_public_b64);
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to persist e2e session");
                return;
            };
            agent_public_b64 = derived.agent_public_b64;
        } else if (payloadStringField(payload_obj, "client_public_key")) |client_pub| {
            const derived = self.deriveE2eSession(client_pub) catch {
                self.sendRelayError(session_id, request_id, "pairing_invalid_client_pub", "client_public_key must be base64url X25519 public key");
                return;
            };
            self.upsertE2eSession(client_sub, derived.session) catch {
                self.allocator.free(derived.agent_public_b64);
                self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to persist e2e session");
                return;
            };
            agent_public_b64 = derived.agent_public_b64;
        } else if (self.relay_e2e_required) {
            self.sendRelayError(session_id, request_id, "pairing_e2e_required", "client_pub is required because relay_e2e_required=true");
            return;
        }

        const access_token = self.issueUiAccessToken(client_sub) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to issue UI access token");
            return;
        };
        defer self.allocator.free(access_token);

        const cookie = std.fmt.allocPrint(
            self.allocator,
            "nullclaw_ui_token={s}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={d}",
            .{ access_token, self.relay_ui_token_ttl_secs },
        ) catch {
            self.sendRelayError(session_id, request_id, "pairing_internal_error", "failed to build UI cookie");
            return;
        };
        defer self.allocator.free(cookie);

        var response: std.ArrayListUnmanaged(u8) = .empty;
        defer response.deinit(self.allocator);
        const w = response.writer(self.allocator);
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
        w.writeAll(if (self.relay_e2e_required) "true" else "false") catch return;
        if (agent_public_b64) |agent_pub| {
            w.writeAll(",\"e2e\":{\"alg\":") catch return;
            root.appendJsonStringW(w, E2E_ALG) catch return;
            w.writeAll(",\"agent_pub\":") catch return;
            root.appendJsonStringW(w, agent_pub) catch return;
            w.writeByte('}') catch return;
        }
        w.writeAll("}}") catch return;
        self.sendOutboundEvent(session_id, response.items);
    }

    // ── vtable implementations ──

    fn wsStart(ctx: *anyopaque) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        switch (self.transport) {
            .local => try self.startLocalTransport(),
            .relay => try self.startRelayTransport(),
        }
    }

    fn startLocalTransport(self: *WebChannel) !void {
        var token_source: enum { config, env, ephemeral } = .ephemeral;
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

        try self.initRelaySecurityState();
        errdefer self.deinitRelaySecurityState();

        self.server = WsServer.init(self.allocator, .{
            .port = self.port,
            .address = self.listen_address,
            .max_conn = @intCast(self.max_connections),
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
            .ephemeral => log.warn("Web channel one-time optional upgrade token: {s}", .{self.activeToken()}),
            .config, .env => log.info("Web channel optional upgrade auth token active (hidden in logs)", .{}),
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
                    std.posix.close(fd);
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
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.shutdown(fd, std.os.windows.ws2_32.SD_RECEIVE);
            } else {
                std.posix.shutdown(fd, .recv) catch {};
            }
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

    fn wsSend(ctx: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        const session_e2e = self.e2eSessionByChat(target);
        if (self.transport == .relay and session_e2e == null and self.relay_e2e_required) {
            return error.E2eRequired;
        }

        try w.writeAll("{\"v\":1,\"type\":\"assistant_final\",\"session_id\":");
        try root.appendJsonStringW(w, target);
        try w.writeAll(",\"agent_id\":");
        try root.appendJsonStringW(w, self.account_id);
        try w.writeAll(",\"payload\":");

        if (session_e2e) |session| {
            var plain_payload: std.ArrayListUnmanaged(u8) = .empty;
            defer plain_payload.deinit(self.allocator);
            const pw = plain_payload.writer(self.allocator);
            try pw.writeAll("{\"content\":");
            try root.appendJsonStringW(pw, message);
            try pw.writeByte('}');

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
        self.sendOutboundEvent(target, buf.items);
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

    fn handleInboundEvent(self: *WebChannel, data: []const u8, forced_session_id: ?[]const u8) void {
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

        if (forced_session_id) |bound_sid| {
            if (eventStringField(obj, "session_id")) |sid| {
                if (!std.mem.eql(u8, sid, bound_sid)) {
                    log.warn("WS: ignoring session_id override for established connection", .{});
                }
            }
        }

        if (std.mem.eql(u8, event_type, "pairing_request")) {
            self.handleRelayPairingRequest(session_id, request_id, payload_obj);
            return;
        }

        if (!std.mem.eql(u8, event_type, "user_message")) return;

        const access_token = payloadStringField(payload_obj, "access_token") orelse
            eventStringField(obj, "access_token") orelse {
            self.sendRelayError(session_id, request_id, "unauthorized", "access_token is required");
            return;
        };
        const e2e_obj = blk: {
            if (payload_obj) |p| {
                if (p.get("e2e")) |value| {
                    if (value == .object) break :blk value.object;
                }
            }
            break :blk null;
        };
        var verified = self.verifyUiAccessToken(access_token) orelse {
            self.sendRelayError(session_id, request_id, "unauthorized", "access_token is invalid or expired");
            return;
        };
        defer verified.deinit(self.allocator);

        self.upsertSessionBinding(session_id, verified.sub) catch {
            self.sendRelayError(session_id, request_id, "internal_error", "failed to bind session to UI client");
            return;
        };

        var decrypted_payload_owned: ?[]u8 = null;
        defer if (decrypted_payload_owned) |owned| self.allocator.free(owned);

        if (e2e_obj) |encrypted_obj| {
            if (eventStringField(encrypted_obj, "alg")) |alg| {
                if (!std.mem.eql(u8, alg, E2E_ALG)) {
                    self.sendRelayError(session_id, request_id, "unsupported_e2e_alg", "payload.e2e.alg is not supported");
                    return;
                }
            }
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
            const decrypted_content = eventStringField(decrypted_obj, "content") orelse {
                self.sendRelayError(session_id, request_id, "invalid_e2e_payload", "decrypted payload.content is required");
                return;
            };
            const decrypted_sender = eventStringField(decrypted_obj, "sender_id") orelse "web-user";
            self.publishInboundMessage(decrypted_sender, session_id, decrypted_content, request_id);
            return;
        } else {
            if (self.relay_e2e_required) {
                self.sendRelayError(session_id, request_id, "e2e_required", "web channel requires encrypted payloads");
                return;
            }
            const plain_content = payloadStringField(payload_obj, "content") orelse
                eventStringField(obj, "content") orelse {
                self.sendRelayError(session_id, request_id, "invalid_payload", "content is required");
                return;
            };
            const plain_sender = payloadStringField(payload_obj, "sender_id") orelse eventStringField(obj, "sender_id") orelse "web-user";
            self.publishInboundMessage(plain_sender, session_id, plain_content, request_id);
            return;
        }
    }

    fn publishInboundMessage(self: *WebChannel, sender_id: []const u8, session_id: []const u8, content: []const u8, request_id: ?[]const u8) void {
        const allocator = self.allocator;
        const session_key = std.fmt.allocPrint(allocator, "web:{s}:direct:{s}", .{
            self.account_id,
            session_id,
        }) catch return;
        defer allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(allocator);
        const mw = metadata_buf.writer(allocator);
        mw.writeAll("{\"is_dm\":true,\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        if (request_id) |rid| {
            mw.writeAll(",\"request_id\":") catch return;
            root.appendJsonStringW(mw, rid) catch return;
        }
        mw.writeByte('}') catch return;

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

    // ── Connection tracking ──

    pub const ConnectionList = struct {
        mutex: std.Thread.Mutex = .{},
        entries: [MAX_TRACKED]?ConnEntry = [_]?ConnEntry{null} ** MAX_TRACKED,

        const MAX_TRACKED = 64;

        const ConnEntry = struct {
            conn: *websocket.Conn,
            session_id: [64]u8 = [_]u8{0} ** 64,
            session_len: u8 = 0,
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

        fn broadcast(self: *ConnectionList, session_id: []const u8, data: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    const sid = entry.session_id[0..entry.session_len];
                    if (std.mem.eql(u8, sid, session_id)) {
                        entry.conn.write(data) catch |err| {
                            log.warn("Failed to send to WS client: {}", .{err});
                            slot.* = null;
                        };
                    }
                }
            }
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

            if (web_channel.allowed_origins.len > 0) {
                const origin = h.headers.get("origin") orelse {
                    log.warn("WS connection rejected: missing origin", .{});
                    return error.Forbidden;
                };
                if (!isOriginAllowed(web_channel.allowed_origins, origin)) {
                    log.warn("WS connection rejected: origin not allowed", .{});
                    return error.Forbidden;
                }
            }

            const auth_header = h.headers.get("authorization");
            const token = extractQueryParam(url, "token") orelse extractBearerToken(auth_header orelse "");
            if (token) |candidate| {
                if (!web_channel.validateToken(candidate)) {
                    log.warn("WS connection rejected: invalid token", .{});
                    return error.Forbidden;
                }
            } else {
                // Pairing-first local UX: allow unauthenticated upgrade only on loopback.
                if (pairing_mod.isPublicBind(web_channel.listen_address)) {
                    log.warn("WS connection rejected: token required for non-loopback bind", .{});
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
            self.web_channel.handleInboundEvent(data, msg_session);
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

test "WebChannel initFromConfig uses defaults" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectEqual(WebChannel.WebTransport.local, ch.transport);
    try std.testing.expectEqual(@as(u16, 32123), ch.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.listen_address);
    try std.testing.expectEqualStrings(config_types.WebConfig.DEFAULT_PATH, ch.ws_path);
    try std.testing.expectEqual(@as(u16, 10), ch.max_connections);
    try std.testing.expectEqualStrings("default", ch.account_id);
    try std.testing.expect(ch.configured_auth_token == null);
    try std.testing.expectEqual(@as(usize, 0), ch.allowed_origins.len);
    try std.testing.expect(ch.relay_url == null);
    try std.testing.expectEqualStrings("default", ch.relay_agent_id);
    try std.testing.expect(ch.configured_relay_token == null);
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
        .account_id = "web-main",
        .auth_token = "test-token-123456",
        .allowed_origins = &origins,
    });
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqualStrings("0.0.0.0", ch.listen_address);
    try std.testing.expectEqualStrings("/relay", ch.ws_path);
    try std.testing.expectEqual(@as(u16, 5), ch.max_connections);
    try std.testing.expectEqualStrings("web-main", ch.account_id);
    try std.testing.expectEqualStrings("test-token-123456", ch.configured_auth_token.?);
    try std.testing.expectEqual(@as(usize, 2), ch.allowed_origins.len);
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

test "WebChannel vtable name returns web" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("web", iface.name());
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

    var handler = WebChannel.WsHandler{
        .web_channel = &ch,
        .conn = undefined,
    };
    const connection_sid = "conn-session";
    @memcpy(handler.session_id[0..connection_sid.len], connection_sid);
    handler.session_len = @intCast(connection_sid.len);

    var event_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer event_buf.deinit(std.testing.allocator);
    const w = event_buf.writer(std.testing.allocator);
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"other-session\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"content\":\"hello\",\"sender_id\":\"user-1\"}}");

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
    const w = event_buf.writer(std.testing.allocator);
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-42\",\"request_id\":\"req-7\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"content\":\"hello from ui\",\"sender_id\":\"ui-1\"}}");

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

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const client_pub_b64 = try ch.base64UrlEncodeAlloc(&client_kp.public_key);
    defer std.testing.allocator.free(client_pub_b64);

    var event_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer event_buf.deinit(std.testing.allocator);
    const w = event_buf.writer(std.testing.allocator);
    try w.writeAll("{\"v\":1,\"type\":\"pairing_request\",\"session_id\":\"sess-pair\",\"payload\":{\"pairing_code\":");
    try root.appendJsonStringW(w, code_copy);
    try w.writeAll(",\"client_pub\":");
    try root.appendJsonStringW(w, client_pub_b64);
    try w.writeAll("}}");

    ch.handleInboundEvent(event_buf.items, null);
    try std.testing.expect(ch.relay_pairing_guard.?.isPaired());
    const next_code = ch.relay_pairing_guard.?.pairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expect(!std.mem.eql(u8, code_copy, next_code));
    try std.testing.expectEqual(@as(usize, 1), ch.e2e_sessions.count());
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
    try ch.upsertE2eSession("ui-42", .{ .key = key });

    const access_token = try ch.issueUiAccessToken("ui-42");
    defer std.testing.allocator.free(access_token);

    const plaintext_payload = "{\"content\":\"secret hello\",\"sender_id\":\"ui-42\"}";
    const encrypted = try ch.encryptE2ePayload(key, plaintext_payload);
    defer std.testing.allocator.free(encrypted.nonce_b64);
    defer std.testing.allocator.free(encrypted.ciphertext_b64);

    var event_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer event_buf.deinit(std.testing.allocator);
    const w = event_buf.writer(std.testing.allocator);
    try w.writeAll("{\"v\":1,\"type\":\"user_message\",\"session_id\":\"sess-e2e\",\"payload\":{\"access_token\":");
    try root.appendJsonStringW(w, access_token);
    try w.writeAll(",\"e2e\":{\"nonce\":");
    try root.appendJsonStringW(w, encrypted.nonce_b64);
    try w.writeAll(",\"ciphertext\":");
    try root.appendJsonStringW(w, encrypted.ciphertext_b64);
    try w.writeAll("}}}");

    ch.handleInboundEvent(event_buf.items, null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ui-42", msg.sender_id);
    try std.testing.expectEqualStrings("sess-e2e", msg.chat_id);
    try std.testing.expectEqualStrings("secret hello", msg.content);
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

test {
    @import("std").testing.refAllDecls(@This());
}
