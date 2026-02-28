const std = @import("std");
const crypto = @import("../security/secrets.zig");

/// Maximum failed pairing attempts before lockout.
const MAX_PAIR_ATTEMPTS: u32 = 5;
/// Lockout duration after too many failed pairing attempts (5 minutes).
const PAIR_LOCKOUT_NS: i128 = 300 * std.time.ns_per_s;

/// Manages pairing state for the gateway.
///
/// Bearer tokens are stored as SHA-256 hashes to prevent plaintext exposure
/// in config files. When a new token is generated, the plaintext is returned
/// to the client once, and only the hash is retained.
pub const PairingGuard = struct {
    /// Whether pairing is required at all.
    require_pairing_flag: bool,
    /// One-time pairing code (generated on startup, consumed on first pair).
    pairing_code: ?[6]u8,
    /// Set of SHA-256 hashed bearer tokens (hex strings).
    paired_tokens: std.StringHashMap(void),
    /// Brute-force protection
    failed_count: u32,
    lockout_time: ?i128, // nanoTimestamp when locked out
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, require_pairing: bool, existing_tokens: []const []const u8) !PairingGuard {
        var tokens = std.StringHashMap(void).init(allocator);

        for (existing_tokens) |t| {
            if (isTokenHash(t)) {
                const duped = try allocator.dupe(u8, t);
                try tokens.put(duped, {});
            } else {
                const hashed = try hashTokenAlloc(allocator, t);
                try tokens.put(hashed, {});
            }
        }

        const code: ?[6]u8 = if (require_pairing and tokens.count() == 0) generateCode() else null;

        return .{
            .require_pairing_flag = require_pairing,
            .pairing_code = code,
            .paired_tokens = tokens,
            .failed_count = 0,
            .lockout_time = null,
            .allocator = allocator,
        };
    }

    pub const PairAttemptResult = union(enum) {
        paired: []const u8,
        missing_code,
        invalid_code,
        already_paired,
        disabled,
        locked_out,
        internal_error,
    };

    pub fn attemptPair(self: *PairingGuard, pairing_code: ?[]const u8) PairAttemptResult {
        if (!self.require_pairing_flag) return .disabled;
        if (self.pairingCode() == null) return .already_paired;
        const code = pairing_code orelse return .missing_code;
        const token_opt = self.tryPair(code) catch |err| switch (err) {
            error.LockedOut => return .locked_out,
            else => return .internal_error,
        };
        if (token_opt) |token| return .{ .paired = token };
        return .invalid_code;
    }

    pub fn deinit(self: *PairingGuard) void {
        var it = self.paired_tokens.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.paired_tokens.deinit();
    }

    /// The one-time pairing code (only set when no tokens exist yet).
    pub fn pairingCode(self: *const PairingGuard) ?[]const u8 {
        if (self.pairing_code) |*code| {
            return code;
        }
        return null;
    }

    /// Regenerate one-time pairing code for the next pairing attempt.
    pub fn regeneratePairingCode(self: *PairingGuard) ?[]const u8 {
        if (!self.require_pairing_flag) {
            self.pairing_code = null;
            return null;
        }
        self.pairing_code = generateCode();
        self.failed_count = 0;
        self.lockout_time = null;
        return self.pairingCode();
    }

    /// Whether pairing is required at all.
    pub fn requirePairing(self: *const PairingGuard) bool {
        return self.require_pairing_flag;
    }

    /// Attempt to pair with the given code. Returns a bearer token on success.
    /// Returns error.LockedOut if locked out due to brute force.
    /// Returns null if code is incorrect.
    pub fn tryPair(self: *PairingGuard, code: []const u8) !?[]const u8 {
        // Check brute force lockout
        if (self.failed_count >= MAX_PAIR_ATTEMPTS) {
            if (self.lockout_time) |locked_at| {
                const elapsed = std.time.nanoTimestamp() - locked_at;
                if (elapsed < PAIR_LOCKOUT_NS) {
                    return error.LockedOut;
                }
                // Lockout expired, reset
                self.failed_count = 0;
                self.lockout_time = null;
            }
        }

        if (self.pairing_code) |expected| {
            const trimmed_code = std.mem.trim(u8, code, " \t\r\n");
            const trimmed_expected = std.mem.trim(u8, &expected, " \t\r\n");
            if (constantTimeEq(trimmed_code, trimmed_expected)) {
                // Reset failed attempts on success
                self.failed_count = 0;
                self.lockout_time = null;

                // Generate token
                const token = generateToken();
                const hashed = try hashTokenAlloc(self.allocator, &token);
                try self.paired_tokens.put(hashed, {});

                // Consume pairing code
                self.pairing_code = null;

                return try self.allocator.dupe(u8, &token);
            }
        }

        // Increment failed attempts
        self.failed_count += 1;
        if (self.failed_count >= MAX_PAIR_ATTEMPTS) {
            self.lockout_time = std.time.nanoTimestamp();
        }

        return null;
    }

    /// Check if a bearer token is valid (compares against stored hashes).
    pub fn isAuthenticated(self: *const PairingGuard, token: []const u8) bool {
        if (!self.require_pairing_flag) return true;

        var hash_buf: [64]u8 = undefined;
        const hashed = hashToken(token, &hash_buf);
        return self.paired_tokens.contains(hashed);
    }

    /// Returns true if the gateway is already paired (has at least one token).
    pub fn isPaired(self: *const PairingGuard) bool {
        return self.paired_tokens.count() > 0;
    }

    /// Get count of paired tokens
    pub fn tokenCount(self: *const PairingGuard) usize {
        return self.paired_tokens.count();
    }
};

/// Generate a 6-digit numeric pairing code using cryptographic randomness.
fn generateCode() [6]u8 {
    var bytes: [4]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const raw = std.mem.readInt(u32, &bytes, .little);
    // Rejection sampling to avoid modulo bias
    const upper_bound: u32 = 1_000_000;
    const reject_threshold: u32 = (std.math.maxInt(u32) / upper_bound) * upper_bound;
    const val = if (raw < reject_threshold) raw % upper_bound else blk: {
        // Extremely rare case; just re-draw
        var retry_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&retry_bytes);
        break :blk std.mem.readInt(u32, &retry_bytes, .little) % upper_bound;
    };
    var buf: [6]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>6}", .{val}) catch unreachable;
    return buf;
}

/// Generate a bearer token with 256-bit entropy.
fn generateToken() [67]u8 {
    var random_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var buf: [67]u8 = undefined; // "zc_" (3) + 64 hex chars
    @memcpy(buf[0..3], "zc_");
    const hex = std.fmt.bytesToHex(random_bytes, .lower);
    @memcpy(buf[3..67], &hex);
    return buf;
}

/// SHA-256 hash a bearer token. Returns lowercase hex in the provided buffer.
fn hashToken(token: []const u8, buf: *[64]u8) []const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    @memcpy(buf, &hex);
    return buf;
}

/// SHA-256 hash a token, returning an allocated hex string
fn hashTokenAlloc(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &hash, .{});
    const result = try allocator.alloc(u8, 64);
    const hex = std.fmt.bytesToHex(hash, .lower);
    @memcpy(result, &hex);
    return result;
}

/// Check if a stored value looks like a SHA-256 hash (64 hex chars)
fn isTokenHash(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

/// Constant-time string comparison to prevent timing attacks.
pub fn constantTimeEq(a: []const u8, b: []const u8) bool {
    const len_diff = a.len ^ b.len;
    const max_len = @max(a.len, b.len);
    var byte_diff: u8 = 0;
    for (0..max_len) |i| {
        const x = if (i < a.len) a[i] else 0;
        const y = if (i < b.len) b[i] else 0;
        byte_diff |= x ^ y;
    }
    return (len_diff == 0) and (byte_diff == 0);
}

/// Check if a host string represents a non-localhost bind address.
pub fn isPublicBind(host: []const u8) bool {
    if (std.mem.eql(u8, host, "127.0.0.1")) return false;
    if (std.mem.eql(u8, host, "localhost")) return false;
    if (std.mem.eql(u8, host, "::1")) return false;
    if (std.mem.eql(u8, host, "[::1]")) return false;
    if (std.mem.eql(u8, host, "0:0:0:0:0:0:0:1")) return false;
    return true;
}

// ── Tests ──────────────────────────────────────────────────────────────

test "new guard generates code when no tokens" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();
    try std.testing.expect(guard.pairingCode() != null);
    try std.testing.expect(!guard.isPaired());
}

test "new guard no code when tokens exist" {
    const tokens = [_][]const u8{"zc_existing"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expect(guard.pairingCode() == null);
    try std.testing.expect(guard.isPaired());
}

test "new guard no code when pairing disabled" {
    var guard = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard.deinit();
    try std.testing.expect(guard.pairingCode() == null);
}

test "is authenticated when pairing disabled" {
    var guard = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard.deinit();
    try std.testing.expect(guard.isAuthenticated("anything"));
    try std.testing.expect(guard.isAuthenticated(""));
}

test "is authenticated with valid token" {
    const tokens = [_][]const u8{"zc_valid"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expect(guard.isAuthenticated("zc_valid"));
}

test "is authenticated with prehashed token" {
    var hash_buf: [64]u8 = undefined;
    const hashed = hashToken("zc_valid", &hash_buf);
    var hashed_copy: [64]u8 = undefined;
    @memcpy(&hashed_copy, hashed);
    const tokens = [_][]const u8{&hashed_copy};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expect(guard.isAuthenticated("zc_valid"));
}

test "is authenticated with invalid token" {
    const tokens = [_][]const u8{"zc_valid"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expect(!guard.isAuthenticated("zc_invalid"));
}

test "tokens stored as hashes" {
    const tokens = [_][]const u8{ "zc_a", "zc_b" };
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expectEqual(@as(usize, 2), guard.tokenCount());
}

test "constant time eq same" {
    try std.testing.expect(constantTimeEq("abc", "abc"));
    try std.testing.expect(constantTimeEq("", ""));
}

test "constant time eq different" {
    try std.testing.expect(!constantTimeEq("abc", "abd"));
    try std.testing.expect(!constantTimeEq("abc", "ab"));
    try std.testing.expect(!constantTimeEq("a", ""));
}

test "generate code is 6 digits" {
    const code = generateCode();
    try std.testing.expectEqual(@as(usize, 6), code.len);
    for (&code) |c| {
        try std.testing.expect(std.ascii.isDigit(c));
    }
}

test "generate code is not deterministic" {
    // Two codes should differ with overwhelming probability
    var found_different = false;
    for (0..10) |_| {
        const c1 = generateCode();
        const c2 = generateCode();
        if (!std.mem.eql(u8, &c1, &c2)) {
            found_different = true;
            break;
        }
    }
    try std.testing.expect(found_different);
}

test "generate token has prefix" {
    const token = generateToken();
    try std.testing.expect(std.mem.startsWith(u8, &token, "zc_"));
    try std.testing.expect(token.len > 10);
}

test "hash token produces 64 hex chars" {
    var buf: [64]u8 = undefined;
    const hash = hashToken("zc_test_token", &buf);
    try std.testing.expectEqual(@as(usize, 64), hash.len);
    for (hash) |c| {
        try std.testing.expect(std.ascii.isHex(c));
    }
}

test "hash token is deterministic" {
    var buf1: [64]u8 = undefined;
    var buf2: [64]u8 = undefined;
    const h1 = hashToken("zc_abc", &buf1);
    const h2 = hashToken("zc_abc", &buf2);
    try std.testing.expectEqualStrings(h1, h2);
}

test "hash token differs for different inputs" {
    var buf1: [64]u8 = undefined;
    var buf2: [64]u8 = undefined;
    const h1 = hashToken("zc_a", &buf1);
    const h2 = hashToken("zc_b", &buf2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "is token hash detects hash vs plaintext" {
    var buf: [64]u8 = undefined;
    const hash = hashToken("zc_test", &buf);
    var hash_arr: [64]u8 = undefined;
    @memcpy(&hash_arr, hash);
    try std.testing.expect(isTokenHash(&hash_arr));
    try std.testing.expect(!isTokenHash("zc_test_token"));
    try std.testing.expect(!isTokenHash("too_short"));
    try std.testing.expect(!isTokenHash(""));
}

test "localhost variants not public" {
    try std.testing.expect(!isPublicBind("127.0.0.1"));
    try std.testing.expect(!isPublicBind("localhost"));
    try std.testing.expect(!isPublicBind("::1"));
    try std.testing.expect(!isPublicBind("[::1]"));
}

test "zero zero is public" {
    try std.testing.expect(isPublicBind("0.0.0.0"));
}

test "real ip is public" {
    try std.testing.expect(isPublicBind("192.168.1.100"));
    try std.testing.expect(isPublicBind("10.0.0.1"));
}

// ── Additional pairing tests ────────────────────────────────────

test "brute force lockout after max attempts" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    // Exhaust all attempts with wrong code
    for (0..5) |_| {
        const result = try guard.tryPair("000000");
        try std.testing.expect(result == null);
    }

    // Next attempt should return LockedOut error
    const locked_result = guard.tryPair("000000");
    try std.testing.expectError(error.LockedOut, locked_result);
}

test "failed attempts increment" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    // Wrong code should return null
    const result = try guard.tryPair("wrong");
    try std.testing.expect(result == null);

    // failed_count should be 1
    try std.testing.expectEqual(@as(u32, 1), guard.failed_count);
}

test "lockout time set after max attempts" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    try std.testing.expect(guard.lockout_time == null);

    for (0..5) |_| {
        _ = try guard.tryPair("wrong");
    }

    try std.testing.expect(guard.lockout_time != null);
}

test "multiple tokens can be added" {
    const tokens = [_][]const u8{ "zc_a", "zc_b", "zc_c" };
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expectEqual(@as(usize, 3), guard.tokenCount());
    try std.testing.expect(guard.isAuthenticated("zc_a"));
    try std.testing.expect(guard.isAuthenticated("zc_b"));
    try std.testing.expect(guard.isAuthenticated("zc_c"));
    try std.testing.expect(!guard.isAuthenticated("zc_d"));
}

test "require pairing getter" {
    var guard1 = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard1.deinit();
    try std.testing.expect(guard1.requirePairing());

    var guard2 = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard2.deinit();
    try std.testing.expect(!guard2.requirePairing());
}

test "pairing code is 6 chars" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();
    const code = guard.pairingCode().?;
    try std.testing.expectEqual(@as(usize, 6), code.len);
}

test "regenerate pairing code creates new code and resets lockout counters" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    const first = guard.pairingCode() orelse return error.TestUnexpectedResult;
    var first_copy: [6]u8 = undefined;
    @memcpy(&first_copy, first);

    guard.failed_count = 5;
    guard.lockout_time = std.time.nanoTimestamp();

    const second = guard.regeneratePairingCode() orelse return error.TestUnexpectedResult;
    try std.testing.expect(second.len == 6);
    try std.testing.expect(!std.mem.eql(u8, &first_copy, second));
    try std.testing.expectEqual(@as(u32, 0), guard.failed_count);
    try std.testing.expect(guard.lockout_time == null);
}

test "is public bind empty string" {
    try std.testing.expect(isPublicBind(""));
}

test "is public bind ipv6 full form not public" {
    try std.testing.expect(!isPublicBind("0:0:0:0:0:0:0:1"));
}

test "constant time eq handles unicode bytes" {
    try std.testing.expect(constantTimeEq("\xc3\xa9", "\xc3\xa9"));
    try std.testing.expect(!constantTimeEq("\xc3\xa9", "\xc3\xa8"));
}

test "constant time eq single char" {
    try std.testing.expect(constantTimeEq("a", "a"));
    try std.testing.expect(!constantTimeEq("a", "b"));
}

test "constant time eq long strings" {
    const a = "abcdefghijklmnopqrstuvwxyz0123456789";
    const b = "abcdefghijklmnopqrstuvwxyz0123456789";
    try std.testing.expect(constantTimeEq(a, b));
}

test "generate token length is 67" {
    const token = generateToken();
    try std.testing.expectEqual(@as(usize, 67), token.len);
}

test "generate token is not deterministic" {
    var found_different = false;
    for (0..10) |_| {
        const t1 = generateToken();
        const t2 = generateToken();
        if (!std.mem.eql(u8, &t1, &t2)) {
            found_different = true;
            break;
        }
    }
    try std.testing.expect(found_different);
}

test "is public bind various addresses" {
    // Private IP ranges that are still "public bind"
    try std.testing.expect(isPublicBind("172.16.0.1"));
    try std.testing.expect(isPublicBind("8.8.8.8"));
    // Hostname
    try std.testing.expect(isPublicBind("example.com"));
}

test "token count starts at zero" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();
    try std.testing.expectEqual(@as(usize, 0), guard.tokenCount());
}

test "is paired returns false when no tokens" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();
    try std.testing.expect(!guard.isPaired());
}

test "is paired returns true with tokens" {
    const tokens = [_][]const u8{"zc_test"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();
    try std.testing.expect(guard.isPaired());
}

// ── attemptPair tests ───────────────────────────────────────────

test "attemptPair returns missing_code when header absent" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    const result = guard.attemptPair(null);
    try std.testing.expect(result == .missing_code);
}

test "attemptPair succeeds with valid one-time code" {
    var guard = try PairingGuard.init(std.testing.allocator, true, &.{});
    defer guard.deinit();

    const code = guard.pairingCode().?;
    const result = guard.attemptPair(code);
    switch (result) {
        .paired => |token| {
            defer std.testing.allocator.free(token);
            try std.testing.expect(std.mem.startsWith(u8, token, "zc_"));
        },
        else => try std.testing.expect(false),
    }
}

test "attemptPair reports already_paired when no code is available" {
    const tokens = [_][]const u8{"zc_existing"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();

    const result = guard.attemptPair("123456");
    try std.testing.expect(result == .already_paired);
}

test "attemptPair reports disabled when pairing is off" {
    var guard = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard.deinit();

    const result = guard.attemptPair("123456");
    try std.testing.expect(result == .disabled);
}
