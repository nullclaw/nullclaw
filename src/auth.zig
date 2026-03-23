//! Unified OAuth 2.0 module — PKCE, browser auth, device code flow, credential store.
//!
//! Provides reusable OAuth primitives for all providers:
//! - PKCE challenge generation (RFC 7636)
//! - Authorization code flow with localhost callback
//! - Token storage with filesystem-based credential store (~/.nullclaw/auth.json)
//! - Device Authorization Grant flow (RFC 8628)

const std = @import("std");
const fs_compat = @import("fs_compat.zig");
const platform = @import("platform.zig");
const json_util = @import("json_util.zig");
const url_percent = @import("url_percent.zig");

// ── PKCE (RFC 7636) ────────────────────────────────────────────────────

pub const PkceChallenge = struct {
    verifier: []u8,
    challenge: []u8,
    method: []const u8 = "S256",

    pub fn deinit(self: PkceChallenge, allocator: std.mem.Allocator) void {
        allocator.free(self.verifier);
        allocator.free(self.challenge);
    }
};

/// Generate a PKCE challenge pair (RFC 7636).
/// 64 random bytes → base64url (no padding) verifier.
/// SHA-256(verifier) → base64url (no padding) challenge.
pub fn generatePkce(allocator: std.mem.Allocator) !PkceChallenge {
    var random_bytes: [64]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    // base64url-encode the random bytes → verifier (86 chars for 64 bytes, no padding)
    const verifier = try base64UrlEncodeAlloc(allocator, &random_bytes);
    errdefer allocator.free(verifier);

    // SHA-256(verifier) → challenge
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});
    const challenge = try base64UrlEncodeAlloc(allocator, &hash);

    return .{
        .verifier = verifier,
        .challenge = challenge,
    };
}

/// Base64url-encode without padding, returning an allocated slice.
fn base64UrlEncodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const Encoder = std.base64.url_safe_no_pad.Encoder;
    const len = Encoder.calcSize(input.len);
    const buf = try allocator.alloc(u8, len);
    _ = Encoder.encode(buf, input);
    return buf;
}

// ── OAuth Token ────────────────────────────────────────────────────────

pub const OAuthToken = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_at: i64 = 0,
    token_type: []const u8 = "Bearer",

    /// Returns true if the token is expired or within 300s of expiring.
    pub fn isExpired(self: OAuthToken) bool {
        if (self.expires_at == 0) return false;
        return std.time.timestamp() + 300 >= self.expires_at;
    }

    /// Free all heap-allocated fields. Only call on tokens returned by
    /// parseTokenResponse / loadCredential / startDeviceCodeFlow (i.e. tokens
    /// whose string fields were produced by allocator.dupe).
    pub fn deinit(self: OAuthToken, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |rt| allocator.free(rt);
        // token_type is heap-allocated when parsed from JSON responses
        allocator.free(self.token_type);
    }
};

// ── Credential Store ───────────────────────────────────────────────────

const CRED_DIR = ".nullclaw";
const CRED_FILE = "auth.json";

fn writeCredentialsFileAtomic(allocator: std.mem.Allocator, file_path: []const u8, contents: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{file_path});
    defer allocator.free(tmp_path);

    const tmp_file = std.fs.createFileAbsolute(tmp_path, .{}) catch return error.CredentialWriteFailed;
    tmp_file.writeAll(contents) catch {
        tmp_file.close();
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return error.CredentialWriteFailed;
    };

    if (@import("builtin").os.tag != .windows) {
        tmp_file.chmod(0o600) catch {};
    }
    tmp_file.close();

    std.fs.renameAbsolute(tmp_path, file_path) catch {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return error.CredentialWriteFailed;
    };
}

/// Save a credential for the given provider to ~/.nullclaw/auth.json.
/// Merges with existing credentials (other providers are preserved).
/// File permissions are set to 0o600.
pub fn saveCredential(allocator: std.mem.Allocator, provider: []const u8, token: OAuthToken) !void {
    const home = platform.getHomeDir(allocator) catch return error.HomeNotSet;
    defer allocator.free(home);

    const dir_path = try std.fs.path.join(allocator, &.{ home, CRED_DIR });
    defer allocator.free(dir_path);

    // Ensure directory exists
    fs_compat.makePath(dir_path) catch return error.CredentialWriteFailed;

    const file_path = try std.fs.path.join(allocator, &.{ dir_path, CRED_FILE });
    defer allocator.free(file_path);

    // Read existing credentials (if any)
    var existing = loadAllCredentials(allocator, file_path) orelse std.StringArrayHashMap(StoredToken).init(allocator);
    defer {
        var it = existing.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            freeStoredToken(allocator, entry.value_ptr.*);
        }
        existing.deinit();
    }

    // Upsert provider entry.
    // After put() succeeds, the map owns these allocations and the defer
    // block above handles cleanup.  The flag prevents errdefer double-frees
    // if a subsequent try (serialization / file I/O) fails.
    var put_succeeded = false;
    const key_owned = try allocator.dupe(u8, provider);
    errdefer if (!put_succeeded) allocator.free(key_owned);
    if (existing.fetchSwapRemove(key_owned)) |old| {
        allocator.free(old.key);
        freeStoredToken(allocator, old.value);
    }
    const at_owned = try allocator.dupe(u8, token.access_token);
    errdefer if (!put_succeeded) allocator.free(at_owned);
    const rt_owned: ?[]const u8 = if (token.refresh_token) |rt| try allocator.dupe(u8, rt) else null;
    errdefer {
        if (!put_succeeded) {
            if (rt_owned) |rt| allocator.free(rt);
        }
    }
    const tt_owned = try allocator.dupe(u8, token.token_type);
    errdefer if (!put_succeeded) allocator.free(tt_owned);
    try existing.put(key_owned, .{
        .access_token = at_owned,
        .refresh_token = rt_owned,
        .expires_at = token.expires_at,
        .token_type = tt_owned,
    });
    put_succeeded = true;

    // Serialize
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.append(allocator, '{');
    var first = true;
    var iter = existing.iterator();
    while (iter.next()) |entry| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try json_util.appendJsonKey(&buf, allocator, entry.key_ptr.*);
        try buf.append(allocator, '{');
        try json_util.appendJsonKeyValue(&buf, allocator, "access_token", entry.value_ptr.*.access_token);
        if (entry.value_ptr.*.refresh_token) |rt| {
            try buf.append(allocator, ',');
            try json_util.appendJsonKeyValue(&buf, allocator, "refresh_token", rt);
        }
        try buf.append(allocator, ',');
        try json_util.appendJsonInt(&buf, allocator, "expires_at", entry.value_ptr.*.expires_at);
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(&buf, allocator, "token_type", entry.value_ptr.*.token_type);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, '}');

    try writeCredentialsFileAtomic(allocator, file_path, buf.items);
}

/// Load a credential for the given provider from ~/.nullclaw/auth.json.
/// Returns null if the file is missing, the provider is not found, or the token
/// is expired and cannot be refreshed.
pub fn loadCredential(allocator: std.mem.Allocator, provider: []const u8) !?OAuthToken {
    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);

    const file_path = try std.fs.path.join(allocator, &.{ home, CRED_DIR, CRED_FILE });
    defer allocator.free(file_path);

    const file = std.fs.cwd().openFile(file_path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    const provider_val = root_obj.get(provider) orelse return null;
    const prov_obj = switch (provider_val) {
        .object => |obj| obj,
        else => return null,
    };

    const access_token_val = prov_obj.get("access_token") orelse return null;
    const access_token_str = switch (access_token_val) {
        .string => |s| s,
        else => return null,
    };
    if (access_token_str.len == 0) return null;

    const access_token = try allocator.dupe(u8, access_token_str);
    errdefer allocator.free(access_token);

    const refresh_token: ?[]const u8 = if (prov_obj.get("refresh_token")) |rt_val| blk: {
        switch (rt_val) {
            .string => |s| break :blk if (s.len > 0) try allocator.dupe(u8, s) else null,
            else => break :blk null,
        }
    } else null;
    errdefer if (refresh_token) |rt| allocator.free(rt);

    const expires_at: i64 = if (prov_obj.get("expires_at")) |ea_val| blk: {
        switch (ea_val) {
            .integer => |i| break :blk i,
            .float => |f| break :blk @intFromFloat(f),
            else => break :blk 0,
        }
    } else 0;

    const token_type_raw: []const u8 = if (prov_obj.get("token_type")) |tt_val| blk: {
        switch (tt_val) {
            .string => |s| break :blk s,
            else => break :blk "Bearer",
        }
    } else "Bearer";
    const token_type = try allocator.dupe(u8, token_type_raw);
    errdefer allocator.free(token_type);

    if (expires_at != 0 and std.time.timestamp() + 300 >= expires_at and refresh_token == null) {
        allocator.free(access_token);
        if (refresh_token) |rt| allocator.free(rt);
        allocator.free(token_type);
        return null;
    }

    return OAuthToken{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
        .token_type = token_type,
    };
}

const StoredToken = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    expires_at: i64,
    token_type: []const u8,
};

fn freeStoredToken(allocator: std.mem.Allocator, tok: StoredToken) void {
    allocator.free(tok.access_token);
    if (tok.refresh_token) |rt| allocator.free(rt);
    allocator.free(tok.token_type);
}

fn loadAllCredentials(allocator: std.mem.Allocator, file_path: []const u8) ?std.StringArrayHashMap(StoredToken) {
    const file = std.fs.cwd().openFile(file_path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    var map = std.StringArrayHashMap(StoredToken).init(allocator);
    var it = root_obj.iterator();
    while (it.next()) |entry| {
        const prov_obj = switch (entry.value_ptr.*) {
            .object => |obj| obj,
            else => continue,
        };
        const at = switch (prov_obj.get("access_token") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        const rt: ?[]const u8 = if (prov_obj.get("refresh_token")) |v| switch (v) {
            .string => |s| if (s.len > 0) s else null,
            else => null,
        } else null;
        const ea: i64 = if (prov_obj.get("expires_at")) |v| switch (v) {
            .integer => |i| i,
            .float => |f| @as(i64, @intFromFloat(f)),
            else => 0,
        } else 0;
        const tt: []const u8 = if (prov_obj.get("token_type")) |v| switch (v) {
            .string => |s| s,
            else => "Bearer",
        } else "Bearer";

        const key = allocator.dupe(u8, entry.key_ptr.*) catch continue;
        const access_token = allocator.dupe(u8, at) catch {
            allocator.free(key);
            continue;
        };
        const refresh_token = if (rt) |r| allocator.dupe(u8, r) catch null else null;
        const token_type = allocator.dupe(u8, tt) catch {
            allocator.free(key);
            allocator.free(access_token);
            if (refresh_token) |owned_rt| allocator.free(owned_rt);
            continue;
        };

        map.put(key, .{
            .access_token = access_token,
            .refresh_token = refresh_token,
            .expires_at = ea,
            .token_type = token_type,
        }) catch {
            allocator.free(token_type);
            if (refresh_token) |owned_rt| allocator.free(owned_rt);
            allocator.free(access_token);
            allocator.free(key);
            continue;
        };
    }
    return map;
}

// ── Token Refresh ─────────────────────────────────────────────────────

/// Refresh an OAuth access token using a refresh_token grant.
/// Preserves the old refresh_token if the response omits a new one.
pub fn refreshAccessToken(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    refresh_token: []const u8,
) !OAuthToken {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const payload = try std.fmt.allocPrint(
        allocator,
        "grant_type=refresh_token&refresh_token={s}&client_id={s}",
        .{ refresh_token, client_id },
    );
    defer allocator.free(payload);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = token_url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "User-Agent", .value = "nullClaw/1.0" },
        },
        .response_writer = &aw.writer,
    });
    if (result.status != .ok) return error.TokenRefreshFailed;

    const resp_body = aw.writer.buffer[0..aw.writer.end];

    var token = try parseTokenResponse(allocator, resp_body);

    // Preserve old refresh_token if response omits a new one
    if (token.refresh_token == null) {
        token.refresh_token = try allocator.dupe(u8, refresh_token);
    }

    return token;
}

// ── Credential Deletion ───────────────────────────────────────────────

/// Delete a credential for the given provider from ~/.nullclaw/auth.json.
/// Returns true if the credential was found and removed.
pub fn deleteCredential(allocator: std.mem.Allocator, provider: []const u8) !bool {
    const home = platform.getHomeDir(allocator) catch return error.HomeNotSet;
    defer allocator.free(home);

    const file_path = try std.fs.path.join(allocator, &.{ home, CRED_DIR, CRED_FILE });
    defer allocator.free(file_path);

    var existing = loadAllCredentials(allocator, file_path) orelse return false;
    defer {
        var it = existing.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            freeStoredToken(allocator, entry.value_ptr.*);
        }
        existing.deinit();
    }

    // Check if provider exists
    var found = false;
    var remove_it = existing.iterator();
    while (remove_it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, provider)) {
            found = true;
            break;
        }
    }
    if (!found) return false;

    // Remove and re-serialize
    if (existing.fetchSwapRemove(provider)) |old| {
        allocator.free(old.key);
        freeStoredToken(allocator, old.value);
    }

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.append(allocator, '{');
    var first = true;
    var iter = existing.iterator();
    while (iter.next()) |entry| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try json_util.appendJsonKey(&buf, allocator, entry.key_ptr.*);
        try buf.append(allocator, '{');
        try json_util.appendJsonKeyValue(&buf, allocator, "access_token", entry.value_ptr.*.access_token);
        if (entry.value_ptr.*.refresh_token) |rt| {
            try buf.append(allocator, ',');
            try json_util.appendJsonKeyValue(&buf, allocator, "refresh_token", rt);
        }
        try buf.append(allocator, ',');
        try json_util.appendJsonInt(&buf, allocator, "expires_at", entry.value_ptr.*.expires_at);
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(&buf, allocator, "token_type", entry.value_ptr.*.token_type);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, '}');

    try writeCredentialsFileAtomic(allocator, file_path, buf.items);

    return true;
}

// ── Device Code Flow (RFC 8628) ────────────────────────────────────────

pub const DeviceCode = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: []const u8,
    interval: u32,
    expires_in: u32,

    pub fn deinit(self: DeviceCode, allocator: std.mem.Allocator) void {
        allocator.free(self.device_code);
        allocator.free(self.user_code);
        allocator.free(self.verification_uri);
    }
};

/// Initiate a device code flow by POSTing to the device authorization URL.
pub fn startDeviceCodeFlow(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    device_auth_url: []const u8,
    scope: []const u8,
) !DeviceCode {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const payload = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&scope={s}",
        .{ client_id, scope },
    );
    defer allocator.free(payload);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = device_auth_url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "User-Agent", .value = "nullClaw/1.0" },
        },
        .response_writer = &aw.writer,
    });
    if (result.status != .ok) return error.DeviceCodeRequestFailed;

    const resp_body = aw.writer.buffer[0..aw.writer.end];

    return parseDeviceCodeResponse(allocator, resp_body);
}

fn parseDeviceCodeResponse(allocator: std.mem.Allocator, body: []const u8) !DeviceCode {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch
        return error.DeviceCodeParseFailed;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.DeviceCodeParseFailed,
    };

    const dc = switch (obj.get("device_code") orelse return error.DeviceCodeParseFailed) {
        .string => |s| s,
        else => return error.DeviceCodeParseFailed,
    };
    const uc = switch (obj.get("user_code") orelse return error.DeviceCodeParseFailed) {
        .string => |s| s,
        else => return error.DeviceCodeParseFailed,
    };
    const vu = switch (obj.get("verification_uri") orelse
        obj.get("verification_url") orelse return error.DeviceCodeParseFailed) {
        .string => |s| s,
        else => return error.DeviceCodeParseFailed,
    };

    const interval: u32 = if (obj.get("interval")) |v| switch (v) {
        .integer => |i| @intCast(i),
        else => 5,
    } else 5;

    const expires_in: u32 = if (obj.get("expires_in")) |v| switch (v) {
        .integer => |i| @intCast(i),
        else => 900,
    } else 900;

    const dc_owned = try allocator.dupe(u8, dc);
    errdefer allocator.free(dc_owned);
    const uc_owned = try allocator.dupe(u8, uc);
    errdefer allocator.free(uc_owned);
    const vu_owned = try allocator.dupe(u8, vu);

    return .{
        .device_code = dc_owned,
        .user_code = uc_owned,
        .verification_uri = vu_owned,
        .interval = interval,
        .expires_in = expires_in,
    };
}

/// Poll the token endpoint until the user authorizes the device.
/// Returns the OAuthToken on success or error on timeout / denied.
pub fn pollDeviceCode(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    device_code: []const u8,
    interval_s: u32,
) !OAuthToken {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const payload = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&device_code={s}&grant_type=urn:ietf:params:oauth:grant-type:device_code",
        .{ client_id, device_code },
    );
    defer allocator.free(payload);

    const interval_ns: u64 = @as(u64, interval_s) * std.time.ns_per_s;
    const max_attempts: u32 = 120;

    for (0..max_attempts) |_| {
        std.Thread.sleep(interval_ns);

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();
        const result = client.fetch(.{
            .location = .{ .url = token_url },
            .method = .POST,
            .payload = payload,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                .{ .name = "User-Agent", .value = "nullClaw/1.0" },
            },
            .response_writer = &aw.writer,
        }) catch continue;

        const resp_body = aw.writer.buffer[0..aw.writer.end];

        if (result.status == .ok) {
            return parseTokenResponse(allocator, resp_body) catch continue;
        }

        // Check for terminal errors
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch continue;
        defer parsed.deinit();
        const obj = switch (parsed.value) {
            .object => |o| o,
            else => continue,
        };
        const err_str = switch (obj.get("error") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        if (std.mem.eql(u8, err_str, "authorization_pending") or
            std.mem.eql(u8, err_str, "slow_down"))
        {
            continue;
        }
        // access_denied, expired_token, etc.
        return error.DeviceCodeDenied;
    }

    return error.DeviceCodeTimeout;
}

fn parseTokenResponse(allocator: std.mem.Allocator, body: []const u8) !OAuthToken {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.TokenParseFailed,
    };

    const at = switch (obj.get("access_token") orelse return error.TokenParseFailed) {
        .string => |s| s,
        else => return error.TokenParseFailed,
    };

    const rt: ?[]const u8 = if (obj.get("refresh_token")) |v| switch (v) {
        .string => |s| if (s.len > 0) s else null,
        else => null,
    } else null;

    const expires_in: i64 = if (obj.get("expires_in")) |v| switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => 3600,
    } else 3600;

    const tt: []const u8 = if (obj.get("token_type")) |v| switch (v) {
        .string => |s| s,
        else => "Bearer",
    } else "Bearer";

    const at_owned = try allocator.dupe(u8, at);
    errdefer allocator.free(at_owned);
    const rt_owned: ?[]const u8 = if (rt) |r| try allocator.dupe(u8, r) else null;
    errdefer if (rt_owned) |r| allocator.free(r);
    const tt_owned = try allocator.dupe(u8, tt);

    return .{
        .access_token = at_owned,
        .refresh_token = rt_owned,
        .expires_at = std.time.timestamp() + expires_in,
        .token_type = tt_owned,
    };
}

// ── Browser Authorization Code Flow ────────────────────────────────────

const MAX_HTTP_REQUEST_BYTES: usize = 8192;
const CALLBACK_ACCEPT_POLL_MS: u64 = 50;
const CALLBACK_READ_TIMEOUT_SECS: i64 = 5;

pub const BrowserAuthOptions = struct {
    client_id: []const u8,
    authorize_url: []const u8,
    scope: []const u8,
    listen_host: []const u8 = "127.0.0.1",
    redirect_host: []const u8 = "localhost",
    listen_port: u16 = 0,
};

pub const BrowserAuthSession = struct {
    server: std.net.Server,
    auth_url: []u8,
    redirect_uri: []u8,
    state: []u8,
    pkce: PkceChallenge,
    listen_port: u16,

    pub fn deinit(self: *BrowserAuthSession, allocator: std.mem.Allocator) void {
        self.server.deinit();
        allocator.free(self.auth_url);
        allocator.free(self.redirect_uri);
        allocator.free(self.state);
        self.pkce.deinit(allocator);
    }

    pub fn waitForCallback(
        self: *BrowserAuthSession,
        allocator: std.mem.Allocator,
        token_url: []const u8,
        client_id: []const u8,
        timeout_s: u32,
    ) !OAuthToken {
        const deadline_ms = std.time.milliTimestamp() + (@as(i64, timeout_s) * std.time.ms_per_s);

        while (std.time.milliTimestamp() < deadline_ms) {
            var conn = self.server.accept() catch |err| switch (err) {
                error.WouldBlock => {
                    std.Thread.sleep(CALLBACK_ACCEPT_POLL_MS * std.time.ns_per_ms);
                    continue;
                },
                else => return error.CallbackListenFailed,
            };
            defer conn.stream.close();

            configureReadTimeout(&conn.stream, CALLBACK_READ_TIMEOUT_SECS);

            var request_buf: [MAX_HTTP_REQUEST_BYTES]u8 = undefined;
            const request = readHttpRequest(&conn.stream, &request_buf) catch {
                writeTextResponse(&conn.stream, "400 Bad Request", "Invalid OAuth callback request") catch {};
                continue;
            };

            var callback = parseCallbackRequest(allocator, request) catch {
                writeTextResponse(&conn.stream, "400 Bad Request", "Invalid OAuth callback request") catch {};
                continue;
            };
            defer callback.deinit(allocator);

            if (!std.mem.eql(u8, callback.path, "/auth/callback")) {
                writeTextResponse(&conn.stream, "404 Not Found", "Not Found") catch {};
                continue;
            }

            if (callback.params.state) |state| {
                if (!std.mem.eql(u8, state, self.state)) {
                    writeTextResponse(&conn.stream, "400 Bad Request", "OAuth state mismatch") catch {};
                    continue;
                }
            } else {
                writeTextResponse(&conn.stream, "400 Bad Request", "Missing OAuth state") catch {};
                continue;
            }

            if (callback.params.error_code) |_| {
                writeTextResponse(&conn.stream, "403 Forbidden", "Authorization was denied") catch {};
                return error.AuthorizationDenied;
            }

            const code = callback.params.code orelse {
                writeTextResponse(&conn.stream, "400 Bad Request", "Missing authorization code") catch {};
                return error.AuthorizationFailed;
            };

            const token = exchangeAuthorizationCode(
                allocator,
                token_url,
                client_id,
                self.redirect_uri,
                self.pkce.verifier,
                code,
            ) catch {
                writeTextResponse(&conn.stream, "502 Bad Gateway", "Failed to exchange authorization code") catch {};
                return error.AuthorizationCodeExchangeFailed;
            };

            writeHtmlResponse(&conn.stream, "200 OK", successHtml) catch {};
            return token;
        }

        return error.AuthorizationTimeout;
    }
};

pub fn startBrowserAuthSession(
    allocator: std.mem.Allocator,
    opts: BrowserAuthOptions,
) !BrowserAuthSession {
    const pkce = try generatePkce(allocator);
    errdefer pkce.deinit(allocator);

    const state = try generateStateToken(allocator);
    errdefer allocator.free(state);

    const addr = try std.net.Address.resolveIp(opts.listen_host, opts.listen_port);
    var server = try addr.listen(.{
        .reuse_address = true,
        .force_nonblocking = true,
    });
    errdefer server.deinit();

    const actual_port = server.listen_address.in.getPort();
    const redirect_uri = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d}/auth/callback",
        .{ opts.redirect_host, actual_port },
    );
    errdefer allocator.free(redirect_uri);

    const auth_url = try buildAuthorizationUrl(
        allocator,
        opts.authorize_url,
        opts.client_id,
        redirect_uri,
        opts.scope,
        pkce.challenge,
        state,
    );
    errdefer allocator.free(auth_url);

    return .{
        .server = server,
        .auth_url = auth_url,
        .redirect_uri = redirect_uri,
        .state = state,
        .pkce = pkce,
        .listen_port = actual_port,
    };
}

pub fn exchangeAuthorizationCode(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    code_verifier: []const u8,
    code: []const u8,
) !OAuthToken {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const encoded_code = try url_percent.encode(allocator, code);
    defer allocator.free(encoded_code);
    const encoded_redirect_uri = try url_percent.encode(allocator, redirect_uri);
    defer allocator.free(encoded_redirect_uri);
    const encoded_client_id = try url_percent.encode(allocator, client_id);
    defer allocator.free(encoded_client_id);
    const encoded_code_verifier = try url_percent.encode(allocator, code_verifier);
    defer allocator.free(encoded_code_verifier);

    const payload = try std.fmt.allocPrint(
        allocator,
        "grant_type=authorization_code&code={s}&redirect_uri={s}&client_id={s}&code_verifier={s}",
        .{ encoded_code, encoded_redirect_uri, encoded_client_id, encoded_code_verifier },
    );
    defer allocator.free(payload);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = token_url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "User-Agent", .value = "nullClaw/1.0" },
        },
        .response_writer = &aw.writer,
    });
    if (result.status != .ok) return error.AuthorizationCodeExchangeFailed;

    const resp_body = aw.writer.buffer[0..aw.writer.end];
    return parseTokenResponse(allocator, resp_body) catch error.AuthorizationCodeExchangeFailed;
}

fn generateStateToken(allocator: std.mem.Allocator) ![]u8 {
    var random_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    return base64UrlEncodeAlloc(allocator, &random_bytes);
}

fn buildAuthorizationUrl(
    allocator: std.mem.Allocator,
    authorize_url: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    scope: []const u8,
    code_challenge: []const u8,
    state: []const u8,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, authorize_url);
    try buf.append(allocator, '?');

    var first = true;
    try appendQueryParam(&buf, allocator, &first, "response_type", "code");
    try appendQueryParam(&buf, allocator, &first, "client_id", client_id);
    try appendQueryParam(&buf, allocator, &first, "redirect_uri", redirect_uri);
    try appendQueryParam(&buf, allocator, &first, "scope", scope);
    try appendQueryParam(&buf, allocator, &first, "code_challenge", code_challenge);
    try appendQueryParam(&buf, allocator, &first, "code_challenge_method", "S256");
    try appendQueryParam(&buf, allocator, &first, "state", state);

    return buf.toOwnedSlice(allocator);
}

fn appendQueryParam(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    first: *bool,
    key: []const u8,
    value: []const u8,
) !void {
    if (!first.*) try buf.append(allocator, '&');
    first.* = false;
    try buf.appendSlice(allocator, key);
    try buf.append(allocator, '=');
    try url_percent.appendPercentEncodedList(buf, allocator, value);
}

const CallbackRequest = struct {
    path: []const u8,
    params: CallbackParams,

    fn deinit(self: *CallbackRequest, allocator: std.mem.Allocator) void {
        self.params.deinit(allocator);
    }
};

const CallbackParams = struct {
    code: ?[]u8 = null,
    state: ?[]u8 = null,
    error_code: ?[]u8 = null,
    error_description: ?[]u8 = null,

    fn deinit(self: *CallbackParams, allocator: std.mem.Allocator) void {
        if (self.code) |value| allocator.free(value);
        if (self.state) |value| allocator.free(value);
        if (self.error_code) |value| allocator.free(value);
        if (self.error_description) |value| allocator.free(value);
    }
};

fn parseCallbackRequest(allocator: std.mem.Allocator, request: []const u8) !CallbackRequest {
    const first_line_end = std.mem.indexOf(u8, request, "\r\n") orelse return error.InvalidCallbackRequest;
    const first_line = request[0..first_line_end];
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    const method = parts.next() orelse return error.InvalidCallbackRequest;
    const target = parts.next() orelse return error.InvalidCallbackRequest;
    _ = parts.next() orelse return error.InvalidCallbackRequest;

    if (!std.mem.eql(u8, method, "GET")) return error.InvalidCallbackRequest;
    if (target.len == 0 or target[0] != '/') return error.InvalidCallbackRequest;

    const query_idx = std.mem.indexOfScalar(u8, target, '?');
    const path = if (query_idx) |idx| target[0..idx] else target;
    const query = if (query_idx) |idx| target[idx + 1 ..] else "";

    return .{
        .path = path,
        .params = try parseCallbackParams(allocator, query),
    };
}

fn parseCallbackParams(allocator: std.mem.Allocator, query: []const u8) !CallbackParams {
    var params = CallbackParams{};
    errdefer params.deinit(allocator);

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq_idx = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const key = pair[0..eq_idx];
        const value = if (eq_idx < pair.len) pair[eq_idx + 1 ..] else "";
        const decoded = try urlDecodeAlloc(allocator, value);
        errdefer allocator.free(decoded);

        if (std.mem.eql(u8, key, "code")) {
            if (params.code == null) {
                params.code = decoded;
                continue;
            }
        } else if (std.mem.eql(u8, key, "state")) {
            if (params.state == null) {
                params.state = decoded;
                continue;
            }
        } else if (std.mem.eql(u8, key, "error")) {
            if (params.error_code == null) {
                params.error_code = decoded;
                continue;
            }
        } else if (std.mem.eql(u8, key, "error_description")) {
            if (params.error_description == null) {
                params.error_description = decoded;
                continue;
            }
        }

        allocator.free(decoded);
    }

    return params;
}

fn urlDecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '+') {
            try buf.append(allocator, ' ');
            i += 1;
            continue;
        }

        if (c == '%' and i + 2 < input.len) {
            const hi = std.fmt.charToDigit(input[i + 1], 16) catch {
                try buf.append(allocator, c);
                i += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(input[i + 2], 16) catch {
                try buf.append(allocator, c);
                i += 1;
                continue;
            };
            try buf.append(allocator, @as(u8, hi * 16 + lo));
            i += 3;
            continue;
        }

        try buf.append(allocator, c);
        i += 1;
    }

    return buf.toOwnedSlice(allocator);
}

fn parseContentLength(request: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, request, "\r\n");
    _ = lines.next() orelse return null;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_idx = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon_idx], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
        const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

fn readHttpRequest(stream: *std.net.Stream, buf: []u8) ![]const u8 {
    var used: usize = 0;
    var expected_total: ?usize = null;

    while (used < buf.len) {
        const n = stream.read(buf[used..]) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionTimedOut => return error.CallbackReadFailed,
            else => return err,
        };
        if (n == 0) return error.CallbackReadFailed;
        used += n;

        if (expected_total == null) {
            if (std.mem.indexOf(u8, buf[0..used], "\r\n\r\n")) |header_end_idx| {
                const header_end = header_end_idx + 4;
                const content_length = parseContentLength(buf[0..header_end]) orelse 0;
                expected_total = header_end + content_length;
                if (expected_total.? > buf.len) return error.CallbackRequestTooLarge;
            }
        }

        if (expected_total) |total| {
            if (used >= total) return buf[0..used];
        }
    }

    return error.CallbackRequestTooLarge;
}

fn configureReadTimeout(stream: *std.net.Stream, timeout_s: i64) void {
    if (!@hasDecl(std.posix.SO, "RCVTIMEO")) return;

    const timeout = std.posix.timeval{
        .sec = @intCast(timeout_s),
        .usec = 0,
    };
    std.posix.setsockopt(
        stream.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        &std.mem.toBytes(timeout),
    ) catch {};
}

fn writeTextResponse(stream: *std.net.Stream, status: []const u8, body: []const u8) !void {
    try writeHttpResponse(stream, status, "text/plain; charset=utf-8", body);
}

fn writeHtmlResponse(stream: *std.net.Stream, status: []const u8, body: []const u8) !void {
    try writeHttpResponse(stream, status, "text/html; charset=utf-8", body);
}

fn writeHttpResponse(
    stream: *std.net.Stream,
    status: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    );
    try stream.writeAll(header);
    try stream.writeAll(body);
}

const successHtml =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>nullClaw Login</title></head>" ++
    "<body><h1>Authentication complete</h1><p>You can close this browser window and return to nullClaw.</p></body></html>";

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "PKCE verifier length is 86 chars (64 bytes base64url no-pad)" {
    const pkce = try generatePkce(std.testing.allocator);
    defer pkce.deinit(std.testing.allocator);

    // 64 bytes → base64url no-pad = ceil(64*4/3) = 86 chars
    try std.testing.expectEqual(@as(usize, 86), pkce.verifier.len);
}

test "PKCE challenge is 43 chars (32 bytes SHA-256 base64url no-pad)" {
    const pkce = try generatePkce(std.testing.allocator);
    defer pkce.deinit(std.testing.allocator);

    // SHA-256 = 32 bytes → base64url no-pad = ceil(32*4/3) = 43 chars
    try std.testing.expectEqual(@as(usize, 43), pkce.challenge.len);
}

test "PKCE challenge is valid base64url" {
    const pkce = try generatePkce(std.testing.allocator);
    defer pkce.deinit(std.testing.allocator);

    for (pkce.challenge) |c| {
        try std.testing.expect(
            (c >= 'A' and c <= 'Z') or
                (c >= 'a' and c <= 'z') or
                (c >= '0' and c <= '9') or
                c == '-' or c == '_',
        );
    }
}

test "PKCE method is S256" {
    const pkce = try generatePkce(std.testing.allocator);
    defer pkce.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("S256", pkce.method);
}

test "PKCE challenge matches SHA-256 of verifier" {
    const pkce = try generatePkce(std.testing.allocator);
    defer pkce.deinit(std.testing.allocator);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(pkce.verifier, &hash, .{});
    const expected = try base64UrlEncodeAlloc(std.testing.allocator, &hash);
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, pkce.challenge);
}

test "OAuthToken isExpired returns true for past expiry" {
    const token = OAuthToken{
        .access_token = "tok",
        .expires_at = std.time.timestamp() - 3600,
    };
    try std.testing.expect(token.isExpired());
}

test "OAuthToken isExpired returns false for far-future expiry" {
    const token = OAuthToken{
        .access_token = "tok",
        .expires_at = std.time.timestamp() + 3600,
    };
    try std.testing.expect(!token.isExpired());
}

test "OAuthToken isExpired returns false when expires_at is zero" {
    const token = OAuthToken{
        .access_token = "tok",
        .expires_at = 0,
    };
    try std.testing.expect(!token.isExpired());
}

test "OAuthToken isExpired buffer: token expiring in 200s is expired" {
    const token = OAuthToken{
        .access_token = "tok",
        .expires_at = std.time.timestamp() + 200,
    };
    // 200s < 300s buffer → should be expired
    try std.testing.expect(token.isExpired());
}

test "OAuthToken isExpired buffer: token expiring in 400s is NOT expired" {
    const token = OAuthToken{
        .access_token = "tok",
        .expires_at = std.time.timestamp() + 400,
    };
    // 400s > 300s buffer → not expired
    try std.testing.expect(!token.isExpired());
}

test "parseDeviceCodeResponse parses valid response" {
    const body =
        \\{"device_code":"dev123","user_code":"ABCD-1234","verification_uri":"https://example.com/activate","interval":5,"expires_in":600}
    ;
    const dc = try parseDeviceCodeResponse(std.testing.allocator, body);
    defer dc.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("dev123", dc.device_code);
    try std.testing.expectEqualStrings("ABCD-1234", dc.user_code);
    try std.testing.expectEqualStrings("https://example.com/activate", dc.verification_uri);
    try std.testing.expectEqual(@as(u32, 5), dc.interval);
    try std.testing.expectEqual(@as(u32, 600), dc.expires_in);
}

test "parseDeviceCodeResponse handles verification_url alias" {
    const body =
        \\{"device_code":"dc","user_code":"UC","verification_url":"https://ex.com/v","interval":10,"expires_in":300}
    ;
    const dc = try parseDeviceCodeResponse(std.testing.allocator, body);
    defer dc.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("https://ex.com/v", dc.verification_uri);
}

test "parseDeviceCodeResponse defaults for missing interval/expires_in" {
    const body =
        \\{"device_code":"dc","user_code":"UC","verification_uri":"https://ex.com"}
    ;
    const dc = try parseDeviceCodeResponse(std.testing.allocator, body);
    defer dc.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 5), dc.interval);
    try std.testing.expectEqual(@as(u32, 900), dc.expires_in);
}

test "parseDeviceCodeResponse fails on missing device_code" {
    const body =
        \\{"user_code":"UC","verification_uri":"https://ex.com"}
    ;
    try std.testing.expectError(error.DeviceCodeParseFailed, parseDeviceCodeResponse(std.testing.allocator, body));
}

test "parseTokenResponse parses valid token" {
    const body =
        \\{"access_token":"ya29.xyz","refresh_token":"1//abc","expires_in":3600,"token_type":"Bearer"}
    ;
    const token = try parseTokenResponse(std.testing.allocator, body);
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("ya29.xyz", token.access_token);
    try std.testing.expectEqualStrings("1//abc", token.refresh_token.?);
    try std.testing.expect(token.expires_at > std.time.timestamp());
}

test "parseTokenResponse fails on missing access_token" {
    const body =
        \\{"refresh_token":"rt","expires_in":3600}
    ;
    try std.testing.expectError(error.TokenParseFailed, parseTokenResponse(std.testing.allocator, body));
}

test "base64UrlEncodeAlloc produces correct output" {
    const input = "hello";
    const encoded = try base64UrlEncodeAlloc(std.testing.allocator, input);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("aGVsbG8", encoded);
}

test "parseTokenResponse preserves refresh_token in refresh response" {
    // Simulates a refresh response that includes a new refresh_token
    const body =
        \\{"access_token":"new_access","refresh_token":"new_refresh","expires_in":7200,"token_type":"Bearer"}
    ;
    const token = try parseTokenResponse(std.testing.allocator, body);
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("new_access", token.access_token);
    try std.testing.expectEqualStrings("new_refresh", token.refresh_token.?);
    try std.testing.expectEqualStrings("Bearer", token.token_type);
    try std.testing.expect(token.expires_at > std.time.timestamp());
}

test "parseTokenResponse handles missing refresh_token in response" {
    const body =
        \\{"access_token":"refreshed_access","expires_in":3600,"token_type":"Bearer"}
    ;
    const token = try parseTokenResponse(std.testing.allocator, body);
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("refreshed_access", token.access_token);
    try std.testing.expect(token.refresh_token == null);
}

test "buildAuthorizationUrl includes required authorization-code parameters" {
    const url = try buildAuthorizationUrl(
        std.testing.allocator,
        "https://auth.example.com/oauth/authorize",
        "client-123",
        "http://localhost:1455/auth/callback",
        "openid profile email offline_access",
        "challenge-xyz",
        "state-abc",
    );
    defer std.testing.allocator.free(url);

    try std.testing.expect(std.mem.indexOf(u8, url, "response_type=code") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "client_id=client-123") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=openid%20profile%20email%20offline_access") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge=challenge-xyz") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "state=state-abc") != null);
}

test "parseCallbackParams decodes percent-encoded query values" {
    var params = try parseCallbackParams(
        std.testing.allocator,
        "code=abc%20123&state=state-1&error_description=access+denied",
    );
    defer params.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc 123", params.code.?);
    try std.testing.expectEqualStrings("state-1", params.state.?);
    try std.testing.expectEqualStrings("access denied", params.error_description.?);
}

test "browser auth session exchanges authorization code via localhost callback" {
    const TestTokenServer = struct {
        const Ctx = struct {
            ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
            port: u16 = 0,
            saw_grant_type: bool = false,
            saw_code: bool = false,
            saw_client_id: bool = false,
            saw_redirect_uri: bool = false,
            saw_code_verifier: bool = false,
        };

        fn run(ctx: *Ctx) void {
            const addr = std.net.Address.resolveIp("127.0.0.1", 0) catch return;
            var server = addr.listen(.{ .reuse_address = true }) catch return;
            defer server.deinit();

            ctx.port = server.listen_address.in.getPort();
            ctx.ready.store(true, .release);

            var conn = server.accept() catch return;
            defer conn.stream.close();

            configureReadTimeout(&conn.stream, CALLBACK_READ_TIMEOUT_SECS);

            var request_buf: [MAX_HTTP_REQUEST_BYTES]u8 = undefined;
            const request = readHttpRequest(&conn.stream, &request_buf) catch return;

            ctx.saw_grant_type = std.mem.indexOf(u8, request, "grant_type=authorization_code") != null;
            ctx.saw_code = std.mem.indexOf(u8, request, "code=browser-code-123") != null;
            ctx.saw_client_id = std.mem.indexOf(u8, request, "client_id=client-browser") != null;
            ctx.saw_redirect_uri = std.mem.indexOf(u8, request, "redirect_uri=http%3A%2F%2Flocalhost%3A") != null;
            ctx.saw_code_verifier = std.mem.indexOf(u8, request, "code_verifier=") != null;

            writeHttpResponse(
                &conn.stream,
                "200 OK",
                "application/json",
                "{\"access_token\":\"browser-at\",\"refresh_token\":\"browser-rt\",\"expires_in\":3600,\"token_type\":\"Bearer\"}",
            ) catch {};
        }
    };

    const CallbackClient = struct {
        const Ctx = struct {
            port: u16,
            state: []const u8,
        };

        fn run(ctx: *const Ctx) void {
            std.Thread.sleep(100 * std.time.ns_per_ms);

            const addr = std.net.Address.resolveIp("127.0.0.1", ctx.port) catch return;
            var stream = std.net.tcpConnectToAddress(addr) catch return;
            defer stream.close();

            var req_buf: [2048]u8 = undefined;
            const request = std.fmt.bufPrint(
                &req_buf,
                "GET /auth/callback?code=browser-code-123&state={s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
                .{ ctx.state, ctx.port },
            ) catch return;
            stream.writeAll(request) catch return;

            var resp_buf: [512]u8 = undefined;
            _ = stream.read(&resp_buf) catch {};
        }
    };

    var token_ctx = TestTokenServer.Ctx{};
    const token_thread = try std.Thread.spawn(.{}, TestTokenServer.run, .{&token_ctx});
    defer token_thread.join();

    while (!token_ctx.ready.load(.acquire)) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    const token_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/oauth/token",
        .{token_ctx.port},
    );
    defer std.testing.allocator.free(token_url);

    var session = try startBrowserAuthSession(std.testing.allocator, .{
        .client_id = "client-browser",
        .authorize_url = "https://auth.example.com/oauth/authorize",
        .scope = "openid profile email offline_access",
    });
    defer session.deinit(std.testing.allocator);

    const callback_ctx = CallbackClient.Ctx{
        .port = session.listen_port,
        .state = session.state,
    };
    const callback_thread = try std.Thread.spawn(.{}, CallbackClient.run, .{&callback_ctx});
    defer callback_thread.join();

    const token = try session.waitForCallback(
        std.testing.allocator,
        token_url,
        "client-browser",
        3,
    );
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("browser-at", token.access_token);
    try std.testing.expectEqualStrings("browser-rt", token.refresh_token.?);
    try std.testing.expect(token_ctx.saw_grant_type);
    try std.testing.expect(token_ctx.saw_code);
    try std.testing.expect(token_ctx.saw_client_id);
    try std.testing.expect(token_ctx.saw_redirect_uri);
    try std.testing.expect(token_ctx.saw_code_verifier);
}

test "Allocating writer deinit frees full buffer — no invalid free on sub-slice (issue #42)" {
    const allocator = std.testing.allocator;

    // Simulate the pattern from refreshAccessToken / pollDeviceCode:
    // Io.Writer.Allocating grows geometrically, so capacity > written length.
    // The old code did allocator.free(buffer[0..end]) — a sub-slice free
    // that is UB (length mismatch). The fix uses aw.deinit() instead.
    {
        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        try aw.writer.writeAll(
            \\{"access_token":"test_tok","refresh_token":"test_rt","expires_in":7200,"token_type":"Bearer"}
        );

        // Confirm geometric growth: capacity > written
        try std.testing.expect(aw.writer.buffer.len > aw.writer.end);

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        const token = try parseTokenResponse(allocator, resp_body);
        defer token.deinit(allocator);

        try std.testing.expectEqualStrings("test_tok", token.access_token);
        try std.testing.expectEqualStrings("test_rt", token.refresh_token.?);
        try std.testing.expectEqualStrings("Bearer", token.token_type);
    }

    // Same pattern for parseDeviceCodeResponse (startDeviceCodeFlow path)
    {
        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        try aw.writer.writeAll(
            \\{"device_code":"dev123","user_code":"ABCD-1234","verification_uri":"https://example.com/verify","interval":5,"expires_in":900}
        );

        try std.testing.expect(aw.writer.buffer.len > aw.writer.end);

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        const dc = try parseDeviceCodeResponse(allocator, resp_body);
        defer dc.deinit(allocator);

        try std.testing.expectEqualStrings("dev123", dc.device_code);
        try std.testing.expectEqualStrings("ABCD-1234", dc.user_code);
        try std.testing.expectEqualStrings("https://example.com/verify", dc.verification_uri);
        try std.testing.expectEqual(@as(u32, 5), dc.interval);
    }
    // If we reach here without panic, DebugAllocator confirmed:
    // 1. No invalid free (sub-slice length mismatch)
    // 2. No memory leak (all allocations freed)
}
