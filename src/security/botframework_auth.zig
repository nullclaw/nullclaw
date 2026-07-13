const builtin = @import("builtin");
const std = @import("std");
const std_compat = @import("compat");
const http_util = @import("../http_util.zig");

const log = std.log.scoped(.botframework_auth);
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;

pub const OPENID_CONFIG_URL = "https://login.botframework.com/v1/.well-known/openidconfiguration";
pub const OPENID_KEYS_URL = "https://login.botframework.com/v1/.well-known/keys";
pub const EXPECTED_ISSUER = "https://api.botframework.com";
pub const CACHE_TTL_SECS: i64 = 24 * 60 * 60;
pub const CLOCK_SKEW_SECS: i64 = 5 * 60;
const FETCH_TIMEOUT_SECS = "10";
const MAX_OPENID_BYTES: usize = 64 * 1024;
const MAX_KEYS_BYTES: usize = 2 * 1024 * 1024;
const KEY_REFRESH_COOLDOWN_SECS: i64 = 5 * 60;
const STALE_KEY_GRACE_SECS: i64 = 60 * 60;

pub const VerifyError = error{
    MissingKeyId,
    MissingRequiredClaim,
    MissingRequiredMetadata,
    TokenMalformed,
    TokenHeaderMalformed,
    TokenPayloadMalformed,
    UnsupportedTokenAlgorithm,
    InvalidIssuer,
    InvalidAudience,
    TokenNotYetValid,
    TokenExpired,
    ServiceUrlMismatch,
    MissingChannelEndorsement,
    InvalidSignature,
    SigningKeyUnsupported,
    OpenIdMetadataFetchFailed,
    OpenIdKeysFetchFailed,
    OpenIdMetadataInvalid,
    OpenIdKeysInvalid,
} || Allocator.Error;

pub const JwksKey = struct {
    kid: []u8,
    x5t: ?[]u8,
    cert_der: []u8,
    endorsements: []const []const u8,

    fn deinit(self: *JwksKey, allocator: Allocator) void {
        allocator.free(self.kid);
        if (self.x5t) |value| allocator.free(value);
        allocator.free(self.cert_der);
        for (self.endorsements) |endorsement| allocator.free(endorsement);
        allocator.free(self.endorsements);
    }

    fn matches(self: JwksKey, key_id: []const u8) bool {
        if (std.mem.eql(u8, self.kid, key_id)) return true;
        if (self.x5t) |x5t| return std.mem.eql(u8, x5t, key_id);
        return false;
    }

    fn hasEndorsement(self: JwksKey, channel_id: []const u8) bool {
        for (self.endorsements) |endorsement| {
            if (std.mem.eql(u8, endorsement, channel_id)) return true;
        }
        return false;
    }
};

pub const KeyCache = struct {
    mutex: std_compat.sync.Mutex = .{},
    fetched_at: i64 = 0,
    last_refresh_attempt: i64 = 0,
    keys: std.ArrayListUnmanaged(JwksKey) = .empty,

    const RefreshDecision = enum {
        use_cached,
        refresh,
        reject,
    };

    pub fn deinit(self: *KeyCache, allocator: Allocator) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.clearLocked(allocator);
    }

    pub fn verifyConnectorToken(
        self: *KeyCache,
        allocator: Allocator,
        token: []const u8,
        app_id: []const u8,
        service_url: []const u8,
        channel_id: []const u8,
    ) VerifyError!void {
        return self.verifyConnectorTokenAt(allocator, token, app_id, service_url, channel_id, std_compat.time.timestamp());
    }

    fn verifyConnectorTokenAt(
        self: *KeyCache,
        allocator: Allocator,
        token: []const u8,
        app_id: []const u8,
        service_url: []const u8,
        channel_id: []const u8,
        now_sec: i64,
    ) VerifyError!void {
        const parsed = try parseJwt(allocator, token);
        defer parsed.deinit(allocator);

        if (!std.mem.eql(u8, parsed.header.alg, "RS256")) {
            return error.UnsupportedTokenAlgorithm;
        }
        const key_id = parsed.header.kid orelse parsed.header.x5t orelse return error.MissingKeyId;

        try validateClaims(parsed.claims, app_id, service_url, now_sec);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.ensureFreshLocked(allocator, key_id, now_sec);
        const key = self.findKeyLocked(key_id) orelse return error.OpenIdKeysInvalid;
        if (!key.hasEndorsement(channel_id)) return error.MissingChannelEndorsement;

        try verifyRs256Signature(key.cert_der, parsed.signing_input, parsed.signature);
    }

    fn ensureFreshLocked(self: *KeyCache, allocator: Allocator, key_id: []const u8, now_sec: i64) VerifyError!void {
        switch (self.refreshDecisionLocked(key_id, now_sec)) {
            .use_cached => return,
            .refresh => {},
            .reject => return error.OpenIdKeysInvalid,
        }

        const had_cached_keys = self.keys.items.len > 0;
        self.last_refresh_attempt = now_sec;
        self.refreshLocked(allocator, now_sec) catch |err| {
            if (had_cached_keys and
                self.findKeyLocked(key_id) != null and
                timestampWithin(now_sec, self.fetched_at, CACHE_TTL_SECS + STALE_KEY_GRACE_SECS))
            {
                log.warn("Bot Framework key refresh failed, using cached keys: {}", .{err});
                return;
            }
            return err;
        };
    }

    fn refreshDecisionLocked(self: *const KeyCache, key_id: []const u8, now_sec: i64) RefreshDecision {
        const has_key = self.findKeyLocked(key_id) != null;
        const is_fresh = self.keys.items.len > 0 and timestampWithin(now_sec, self.fetched_at, CACHE_TTL_SECS);
        if (is_fresh and has_key) return .use_cached;

        if (timestampWithin(now_sec, self.last_refresh_attempt, KEY_REFRESH_COOLDOWN_SECS)) {
            const within_stale_grace = timestampWithin(
                now_sec,
                self.fetched_at,
                CACHE_TTL_SECS + STALE_KEY_GRACE_SECS,
            );
            return if (has_key and within_stale_grace) .use_cached else .reject;
        }
        return .refresh;
    }

    fn refreshLocked(self: *KeyCache, allocator: Allocator, now_sec: i64) VerifyError!void {
        const openid = http_util.curlGetMaxBytes(allocator, OPENID_CONFIG_URL, &.{}, FETCH_TIMEOUT_SECS, MAX_OPENID_BYTES) catch {
            return error.OpenIdMetadataFetchFailed;
        };
        defer allocator.free(openid);

        const metadata = try parseOpenIdMetadata(allocator, openid);
        defer metadata.deinit(allocator);

        const raw_keys = http_util.curlGetMaxBytes(allocator, metadata.jwks_uri, &.{}, FETCH_TIMEOUT_SECS, MAX_KEYS_BYTES) catch {
            return error.OpenIdKeysFetchFailed;
        };
        defer allocator.free(raw_keys);

        var new_keys = try parseJwksKeys(allocator, raw_keys);
        errdefer {
            for (new_keys.items) |*key| key.deinit(allocator);
            new_keys.deinit(allocator);
        }

        self.clearLocked(allocator);
        self.keys = new_keys;
        self.fetched_at = now_sec;
        self.last_refresh_attempt = now_sec;
    }

    fn clearLocked(self: *KeyCache, allocator: Allocator) void {
        for (self.keys.items) |*key| key.deinit(allocator);
        self.keys.deinit(allocator);
        self.keys = .empty;
        self.fetched_at = 0;
        self.last_refresh_attempt = 0;
    }

    fn findKeyLocked(self: *const KeyCache, key_id: []const u8) ?JwksKey {
        for (self.keys.items) |key| {
            if (key.matches(key_id)) return key;
        }
        return null;
    }

    pub fn seedFixtureForTest(self: *KeyCache, allocator: Allocator) !void {
        if (!builtin.is_test) unreachable;
        return self.seedFixtureForTestAt(allocator, std_compat.time.timestamp());
    }

    fn seedFixtureForTestAt(self: *KeyCache, allocator: Allocator, fetched_at: i64) !void {
        if (!builtin.is_test) unreachable;
        self.mutex.lock();
        defer self.mutex.unlock();

        self.clearLocked(allocator);
        self.keys = try parseJwksKeys(allocator, TEST_JWKS_JSON);
        self.fetched_at = fetched_at;
    }
};

fn timestampWithin(now_sec: i64, timestamp_sec: i64, window_sec: i64) bool {
    if (timestamp_sec == 0) return false;
    if (now_sec < timestamp_sec) return false;
    return now_sec - timestamp_sec < window_sec;
}

pub fn fixtureTokenForTest() []const u8 {
    if (!builtin.is_test) unreachable;
    return TEST_JWT;
}

const OpenIdMetadata = struct {
    jwks_uri: []u8,

    fn deinit(self: OpenIdMetadata, allocator: Allocator) void {
        allocator.free(self.jwks_uri);
    }
};

const JwtHeader = struct {
    alg: []u8,
    kid: ?[]u8,
    x5t: ?[]u8,
};

const JwtClaims = struct {
    iss: []u8,
    service_url: []u8,
    nbf: i64,
    exp: i64,
    audience: Audience,

    const Audience = union(enum) {
        single: []u8,
        multiple: []const []const u8,

        fn deinit(self: Audience, allocator: Allocator) void {
            switch (self) {
                .single => |value| allocator.free(value),
                .multiple => |values| {
                    for (values) |value| allocator.free(value);
                    allocator.free(values);
                },
            }
        }

        fn contains(self: Audience, expected: []const u8) bool {
            return switch (self) {
                .single => |value| std.mem.eql(u8, value, expected),
                .multiple => |values| blk: {
                    for (values) |value| {
                        if (std.mem.eql(u8, value, expected)) break :blk true;
                    }
                    break :blk false;
                },
            };
        }
    };

    fn deinit(self: JwtClaims, allocator: Allocator) void {
        allocator.free(self.iss);
        allocator.free(self.service_url);
        self.audience.deinit(allocator);
    }
};

const ParsedJwt = struct {
    signing_input: []u8,
    signature: []u8,
    header: JwtHeader,
    claims: JwtClaims,

    fn deinit(self: ParsedJwt, allocator: Allocator) void {
        allocator.free(self.signing_input);
        allocator.free(self.signature);
        allocator.free(self.header.alg);
        if (self.header.kid) |value| allocator.free(value);
        if (self.header.x5t) |value| allocator.free(value);
        self.claims.deinit(allocator);
    }
};

fn parseOpenIdMetadata(allocator: Allocator, json_bytes: []const u8) VerifyError!OpenIdMetadata {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.OpenIdMetadataInvalid;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return error.OpenIdMetadataInvalid,
    };

    const issuer = jsonObjectString(obj, "issuer") orelse return error.MissingRequiredMetadata;
    if (!std.mem.eql(u8, issuer, EXPECTED_ISSUER)) return error.OpenIdMetadataInvalid;

    const jwks_uri = jsonObjectString(obj, "jwks_uri") orelse return error.MissingRequiredMetadata;
    if (!std.mem.eql(u8, jwks_uri, OPENID_KEYS_URL)) return error.OpenIdMetadataInvalid;

    return .{
        .jwks_uri = try allocator.dupe(u8, jwks_uri),
    };
}

fn parseJwksKeys(allocator: Allocator, json_bytes: []const u8) VerifyError!std.ArrayListUnmanaged(JwksKey) {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.OpenIdKeysInvalid,
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return error.OpenIdKeysInvalid,
    };
    const keys_value = obj.get("keys") orelse return error.MissingRequiredMetadata;
    if (keys_value != .array) return error.OpenIdKeysInvalid;

    var keys: std.ArrayListUnmanaged(JwksKey) = .empty;
    errdefer {
        for (keys.items) |*key| key.deinit(allocator);
        keys.deinit(allocator);
    }

    for (keys_value.array.items) |key_value| {
        if (key_value != .object) continue;
        const key_obj = key_value.object;
        const kty = jsonObjectString(key_obj, "kty") orelse continue;
        if (!std.mem.eql(u8, kty, "RSA")) continue;

        const kid = jsonObjectString(key_obj, "kid") orelse continue;
        const x5c_val = key_obj.get("x5c") orelse continue;
        if (x5c_val != .array or x5c_val.array.items.len == 0) continue;
        const cert_b64_val = x5c_val.array.items[0];
        if (cert_b64_val != .string) continue;

        const cert_der = try base64DecodeAlloc(allocator, cert_b64_val.string);
        errdefer allocator.free(cert_der);

        const x5t = if (jsonObjectString(key_obj, "x5t")) |value| try allocator.dupe(u8, value) else null;
        errdefer if (x5t) |value| allocator.free(value);

        const endorsements = try parseEndorsements(allocator, key_obj.get("endorsements"));
        errdefer {
            for (endorsements) |endorsement| allocator.free(endorsement);
            allocator.free(endorsements);
        }

        const kid_owned = try allocator.dupe(u8, kid);
        errdefer allocator.free(kid_owned);

        try keys.append(allocator, .{
            .kid = kid_owned,
            .x5t = x5t,
            .cert_der = cert_der,
            .endorsements = endorsements,
        });
    }

    if (keys.items.len == 0) return error.OpenIdKeysInvalid;
    return keys;
}

fn parseEndorsements(allocator: Allocator, value_opt: ?std.json.Value) ![]const []const u8 {
    const value = value_opt orelse return allocator.alloc([]const u8, 0);
    if (value != .array) return allocator.alloc([]const u8, 0);

    var list = try allocator.alloc([]const u8, value.array.items.len);
    var count: usize = 0;
    errdefer {
        for (list[0..count]) |entry| allocator.free(entry);
        allocator.free(list);
    }

    for (value.array.items) |item| {
        if (item != .string or item.string.len == 0) continue;
        list[count] = try allocator.dupe(u8, item.string);
        count += 1;
    }

    if (count == list.len) return list;
    if (count == 0) {
        allocator.free(list);
        return allocator.alloc([]const u8, 0);
    }
    return allocator.realloc(list, count);
}

fn parseJwt(allocator: Allocator, token: []const u8) VerifyError!ParsedJwt {
    var it = std.mem.splitScalar(u8, token, '.');
    const header_b64 = it.next() orelse return error.TokenMalformed;
    const payload_b64 = it.next() orelse return error.TokenMalformed;
    const sig_b64 = it.next() orelse return error.TokenMalformed;
    if (it.next() != null or header_b64.len == 0 or payload_b64.len == 0 or sig_b64.len == 0) {
        return error.TokenMalformed;
    }

    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    errdefer allocator.free(signing_input);

    const header_bytes = try base64UrlDecodeAlloc(allocator, header_b64);
    defer allocator.free(header_bytes);
    const payload_bytes = try base64UrlDecodeAlloc(allocator, payload_b64);
    defer allocator.free(payload_bytes);
    const signature = try base64UrlDecodeAlloc(allocator, sig_b64);
    errdefer allocator.free(signature);

    const header = try parseJwtHeader(allocator, header_bytes);
    errdefer {
        allocator.free(header.alg);
        if (header.kid) |value| allocator.free(value);
        if (header.x5t) |value| allocator.free(value);
    }
    const claims = try parseJwtClaims(allocator, payload_bytes);
    errdefer claims.deinit(allocator);

    return .{
        .signing_input = signing_input,
        .signature = signature,
        .header = header,
        .claims = claims,
    };
}

fn parseJwtHeader(allocator: Allocator, json_bytes: []const u8) VerifyError!JwtHeader {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.TokenHeaderMalformed;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return error.TokenHeaderMalformed,
    };

    const alg = jsonObjectString(obj, "alg") orelse return error.MissingRequiredClaim;
    const kid = if (jsonObjectString(obj, "kid")) |value| try allocator.dupe(u8, value) else null;
    errdefer if (kid) |value| allocator.free(value);
    const x5t = if (jsonObjectString(obj, "x5t")) |value| try allocator.dupe(u8, value) else null;
    errdefer if (x5t) |value| allocator.free(value);

    return .{
        .alg = try allocator.dupe(u8, alg),
        .kid = kid,
        .x5t = x5t,
    };
}

fn parseJwtClaims(allocator: Allocator, json_bytes: []const u8) VerifyError!JwtClaims {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.TokenPayloadMalformed;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return error.TokenPayloadMalformed,
    };

    const iss = jsonObjectString(obj, "iss") orelse return error.MissingRequiredClaim;
    const service_url = jsonObjectString(obj, "serviceurl") orelse jsonObjectString(obj, "serviceUrl") orelse return error.MissingRequiredClaim;
    const nbf = jsonObjectInt(obj, "nbf") orelse return error.MissingRequiredClaim;
    const exp = jsonObjectInt(obj, "exp") orelse return error.MissingRequiredClaim;
    const aud_value = obj.get("aud") orelse return error.MissingRequiredClaim;

    const iss_owned = try allocator.dupe(u8, iss);
    errdefer allocator.free(iss_owned);
    const service_url_owned = try allocator.dupe(u8, service_url);
    errdefer allocator.free(service_url_owned);
    const audience = try parseAudience(allocator, aud_value);
    errdefer audience.deinit(allocator);

    return .{
        .iss = iss_owned,
        .service_url = service_url_owned,
        .nbf = nbf,
        .exp = exp,
        .audience = audience,
    };
}

fn parseAudience(allocator: Allocator, value: std.json.Value) VerifyError!JwtClaims.Audience {
    return switch (value) {
        .string => |single| .{ .single = try allocator.dupe(u8, single) },
        .array => |array| blk: {
            var values = try allocator.alloc([]const u8, array.items.len);
            var count: usize = 0;
            errdefer {
                for (values[0..count]) |entry| allocator.free(entry);
                allocator.free(values);
            }
            for (array.items) |item| {
                if (item != .string or item.string.len == 0) continue;
                values[count] = try allocator.dupe(u8, item.string);
                count += 1;
            }
            if (count == 0) return error.InvalidAudience;
            if (count != values.len) values = try allocator.realloc(values, count);
            break :blk .{ .multiple = values };
        },
        else => error.InvalidAudience,
    };
}

fn validateClaims(claims: JwtClaims, app_id: []const u8, service_url: []const u8, now_sec: i64) VerifyError!void {
    if (!std.mem.eql(u8, claims.iss, EXPECTED_ISSUER)) return error.InvalidIssuer;
    if (!claims.audience.contains(app_id)) return error.InvalidAudience;
    if (claims.nbf > now_sec + CLOCK_SKEW_SECS) return error.TokenNotYetValid;
    if (claims.exp < now_sec - CLOCK_SKEW_SECS) return error.TokenExpired;
    if (!std.mem.eql(u8, claims.service_url, service_url)) return error.ServiceUrlMismatch;
}

fn verifyRs256Signature(cert_der: []const u8, signing_input: []const u8, signature: []const u8) VerifyError!void {
    const parsed_cert = Certificate.parse(.{
        .buffer = cert_der,
        .index = 0,
    }) catch return error.SigningKeyUnsupported;

    switch (parsed_cert.pub_key_algo) {
        .rsaEncryption, .rsassa_pss => {},
        else => return error.SigningKeyUnsupported,
    }

    const components = Certificate.rsa.PublicKey.parseDer(parsed_cert.pubKey()) catch return error.SigningKeyUnsupported;
    const key = Certificate.rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch return error.SigningKeyUnsupported;

    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature.len != modulus_len) return error.InvalidSignature;
            const sig = Certificate.rsa.PKCS1v1_5Signature.fromBytes(modulus_len, signature);
            Certificate.rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                sig,
                signing_input,
                key,
                std.crypto.hash.sha2.Sha256,
            ) catch return error.InvalidSignature;
        },
        else => return error.SigningKeyUnsupported,
    }
}

fn jsonObjectString(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |string| if (string.len > 0) string else null,
        else => null,
    };
}

fn jsonObjectInt(object: std.json.ObjectMap, key: []const u8) ?i64 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .integer => |integer| integer,
        else => null,
    };
}

fn base64UrlDecodeAlloc(allocator: Allocator, encoded: []const u8) VerifyError![]u8 {
    const Decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(encoded) catch return error.TokenMalformed;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    Decoder.decode(decoded, encoded) catch return error.TokenMalformed;
    return decoded;
}

fn base64DecodeAlloc(allocator: Allocator, encoded: []const u8) VerifyError![]u8 {
    const Decoder = std.base64.standard.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(encoded) catch return error.OpenIdKeysInvalid;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    Decoder.decode(decoded, encoded) catch return error.OpenIdKeysInvalid;
    return decoded;
}

test "verifyConnectorTokenAt accepts valid Teams token" {
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);

    try seedTestKey(&cache, std.testing.allocator);
    try cache.verifyConnectorTokenAt(
        std.testing.allocator,
        TEST_JWT,
        "test-app-id",
        "https://smba.trafficmanager.net/amer/",
        "msteams",
        1_800_000_000,
    );
}

test "verifyConnectorTokenAt rejects missing endorsement" {
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);

    try seedTestKey(&cache, std.testing.allocator);
    try std.testing.expectError(
        error.MissingChannelEndorsement,
        cache.verifyConnectorTokenAt(
            std.testing.allocator,
            TEST_JWT,
            "test-app-id",
            "https://smba.trafficmanager.net/amer/",
            "telegram",
            1_800_000_000,
        ),
    );
}

test "verifyConnectorTokenAt rejects serviceUrl mismatch" {
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);

    try seedTestKey(&cache, std.testing.allocator);
    try std.testing.expectError(
        error.ServiceUrlMismatch,
        cache.verifyConnectorTokenAt(
            std.testing.allocator,
            TEST_JWT,
            "test-app-id",
            "https://smba.trafficmanager.net/emea/",
            "msteams",
            1_800_000_000,
        ),
    );
}

test "verifyConnectorTokenAt rejects invalid audience" {
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);

    try seedTestKey(&cache, std.testing.allocator);
    try std.testing.expectError(
        error.InvalidAudience,
        cache.verifyConnectorTokenAt(
            std.testing.allocator,
            TEST_JWT,
            "wrong-app-id",
            "https://smba.trafficmanager.net/amer/",
            "msteams",
            1_800_000_000,
        ),
    );
}

test "verifyConnectorTokenAt rejects expired token" {
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);

    try seedTestKey(&cache, std.testing.allocator);
    try std.testing.expectError(
        error.TokenExpired,
        cache.verifyConnectorTokenAt(
            std.testing.allocator,
            TEST_JWT,
            "test-app-id",
            "https://smba.trafficmanager.net/amer/",
            "msteams",
            1_900_000_301,
        ),
    );
}

test "Bot Framework JWKS fetch cap is two mebibytes" {
    // Regression: the previous expression claimed 2 MiB but evaluated to 1 MiB,
    // leaving too little headroom above Microsoft's live JWKS response.
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), MAX_KEYS_BYTES);
}

test "KeyCache throttles repeated refreshes for unknown key ids" {
    // Regression: arbitrary unknown kid values could each force a metadata and
    // JWKS download while the global key-cache mutex remained locked.
    var cache = KeyCache{};
    defer cache.deinit(std.testing.allocator);
    try seedTestKey(&cache, std.testing.allocator);

    const now_sec: i64 = 1_800_000_100;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.use_cached,
        cache.refreshDecisionLocked("test-kid", now_sec),
    );
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.refresh,
        cache.refreshDecisionLocked("unknown-kid", now_sec),
    );

    cache.last_refresh_attempt = now_sec;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.reject,
        cache.refreshDecisionLocked("unknown-kid", now_sec + 1),
    );

    cache.fetched_at = now_sec - CACHE_TTL_SECS - 1;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.use_cached,
        cache.refreshDecisionLocked("test-kid", now_sec + 1),
    );

    cache.fetched_at = now_sec - CACHE_TTL_SECS - STALE_KEY_GRACE_SECS;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.reject,
        cache.refreshDecisionLocked("test-kid", now_sec + 1),
    );

    cache.last_refresh_attempt = now_sec - KEY_REFRESH_COOLDOWN_SECS;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.refresh,
        cache.refreshDecisionLocked("unknown-kid", now_sec),
    );

    cache.fetched_at = now_sec + 1;
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.refresh,
        cache.refreshDecisionLocked("test-kid", now_sec),
    );

    var empty_cache = KeyCache{ .last_refresh_attempt = now_sec };
    defer empty_cache.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        KeyCache.RefreshDecision.reject,
        empty_cache.refreshDecisionLocked("unknown-kid", now_sec + 1),
    );
}

test "parseJwtClaims rejects floating numeric dates" {
    try std.testing.expectError(
        error.MissingRequiredClaim,
        parseJwtClaims(
            std.testing.allocator,
            "{\"iss\":\"https://api.botframework.com\",\"aud\":\"test-app-id\",\"serviceUrl\":\"https://smba.trafficmanager.net/amer/\",\"nbf\":1700000000.5,\"exp\":1900000000}",
        ),
    );
}

test "parseJwtClaims accepts lowercase serviceurl claim" {
    // Bot Framework connector tokens emit the service URL as the lowercase
    // claim "serviceurl" (AuthenticationConstants.ServiceUrlClaim), not camelCase.
    var claims = try parseJwtClaims(
        std.testing.allocator,
        "{\"iss\":\"https://api.botframework.com\",\"aud\":\"test-app-id\",\"serviceurl\":\"https://smba.trafficmanager.net/amer/\",\"nbf\":1700000000,\"exp\":1900000000}",
    );
    defer claims.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("https://smba.trafficmanager.net/amer/", claims.service_url);
}

test "parseJwtClaims still accepts camelCase serviceUrl claim" {
    // Backward compatibility: the camelCase spelling continues to parse.
    var claims = try parseJwtClaims(
        std.testing.allocator,
        "{\"iss\":\"https://api.botframework.com\",\"aud\":\"test-app-id\",\"serviceUrl\":\"https://smba.trafficmanager.net/amer/\",\"nbf\":1700000000,\"exp\":1900000000}",
    );
    defer claims.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("https://smba.trafficmanager.net/amer/", claims.service_url);
}

test "parseJwtClaims prefers canonical lowercase serviceurl claim" {
    // Regression: when both signed spellings are present, the SDK-defined
    // lowercase serviceurl claim must take precedence over the legacy fallback.
    var claims = try parseJwtClaims(
        std.testing.allocator,
        "{\"iss\":\"https://api.botframework.com\",\"aud\":\"test-app-id\",\"serviceurl\":\"https://canonical.example.com/\",\"serviceUrl\":\"https://legacy.example.com/\",\"nbf\":1700000000,\"exp\":1900000000}",
    );
    defer claims.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("https://canonical.example.com/", claims.service_url);
}

fn parseJwksKeysAllocationTest(allocator: Allocator) !void {
    var keys = try parseJwksKeys(allocator, TEST_JWKS_JSON);
    defer {
        for (keys.items) |*key| key.deinit(allocator);
        keys.deinit(allocator);
    }
}

test "parseJwksKeys frees partial key on out-of-memory" {
    // Regression: an allocation failure while growing the key list must free
    // the already-owned kid, certificate, thumbprint, and endorsements.
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        parseJwksKeysAllocationTest,
        .{},
    );
}

fn seedTestKey(cache: *KeyCache, allocator: Allocator) !void {
    try cache.seedFixtureForTestAt(allocator, 1_800_000_000);
}

const TEST_JWT =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0." ++
    "eyJpc3MiOiJodHRwczovL2FwaS5ib3RmcmFtZXdvcmsuY29tIiwiYXVkIjoidGVzdC1hcHAtaWQiLCJzZXJ2aWNlVXJsIjoiaHR0cHM6Ly9zbWJhLnRyYWZmaWNtYW5hZ2VyLm5ldC9hbWVyLyIsIm5iZiI6MTcwMDAwMDAwMCwiZXhwIjoxOTAwMDAwMDAwfQ." ++
    "Wn9lWzZEMYHkGC7uB9J420vble2Ht5VGESrlNj-AUEykHlZ46nB-T3AYMyIofdMYsrXHZ3nALTvup0YfEMG_bLv0rM4jNmE2qbIviXYYSbiTHDD4sBbj6As61d9kn5Ce_U6-mOmuzgfu1kJLgAZ-1qafBRyIVFtQisV0uOE0a564hivmCzgIoGnV-T-IN_4sN2Ai7NOohEgjdla6QFb638OTdFL35bBeuySr7HCX73tSp0g8irUyl3YyuorM5wXBKWrpmhjdmfywtMhZEywEJuv88XCBXs9-EqmCiOgwGq6Eva2uBjaM76KWPBA3JZW7GqkYajkAqXD03xd_sRRAHg";

const TEST_JWKS_JSON =
    "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test-kid\",\"x5t\":\"test-kid\",\"x5c\":[\"" ++
    "MIIDJTCCAg2gAwIBAgIUbcaJBh62776RqwQVmgAhFDz3W0MwDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAwwXdGVzdC5ib3RmcmFtZXdvcmsubG9jYWwwHhcNMjYwNDA5MDIzNTUwWhcNMzYwNDA2MDIzNTUwWjAiMSAwHgYDVQQDDBd0ZXN0LmJvdGZyYW1ld29yay5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALjdpaA+cRjaYDm0TvSnH3N2Ar9zBOcqMf+jmZ+UDzyy/RngnSpz9bbTdfeiHBQWY+iB3Y3650Ma9aAUj8id4HLTp0PJ9Z3Ry7DP/rHwCd2usn6wHi/YJ16GFdBInFIh8NEkDvemBpbDKgDDAdEzgv3XBOnvDKf6net41ZMyPUk0C8yKQoLSjS2+PeZpo+FzJquBvOUpf/R3HulIrzJB5G6IYK1EtHW4OXWlPFxnao3oJawRKbgbqKYSlfQ6j6spC60VfON+ZGareKKIdUhsAaiAtB/rE1V0pXqK4+bskPMT0KXnFYi5JLrVl8qQDuWSIILInkimjEgF6+AHE2FsCq8CAwEAAaNTMFEwHQYDVR0OBBYEFBXdj2hpNsv6tPGH87uea32v6OaTMB8GA1UdIwQYMBaAFBXdj2hpNsv6tPGH87uea32v6OaTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGCA2juDDaCqae/V8R54aiwlenJIAO+lwXuDwTmCv8OI60kySuEMFO/AKTQ/Iy47fukgLoYn8BzNg1gUYxwB4/7SGUSoEtQak5jqlAmvPorjJ6pv9O4VBCKUgCB1jWyHBM0WZ/fQe0EnqaUCmrh+EZp0fU+XObFsk5HzclOBOLqg3GzRiujBx9It93U13FVW+DkuYjV0opFMYsrHKPeCP8tvW826hMVtxexwmRPp78JGof0/9fM4CGutYo6yZAAXkgtJpejIjstIWDFSqGDnp13Tgg03tnoyuzr7h/zCdO2dTTBncfh76947obKIGHi01LXACyHNCgPVwlAs/ypXVcg=" ++
    "\"],\"endorsements\":[\"msteams\",\"skype\"]}]}";
