const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Length of the random encryption key in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Tag length
pub const TAG_LEN: usize = ChaCha20Poly1305.tag_length;

/// Encrypt data using ChaCha20-Poly1305 (Zig stdlib).
pub fn encrypt(key: [32]u8, nonce: [12]u8, plaintext: []const u8, buf: []u8) ![]const u8 {
    if (buf.len < plaintext.len + ChaCha20Poly1305.tag_length) return error.BufferTooSmall;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        buf[0..plaintext.len],
        &tag,
        plaintext,
        "",
        nonce,
        key,
    );
    @memcpy(buf[plaintext.len..][0..ChaCha20Poly1305.tag_length], &tag);
    return buf[0 .. plaintext.len + ChaCha20Poly1305.tag_length];
}

/// Decrypt data using ChaCha20-Poly1305.
pub fn decrypt(key: [32]u8, nonce: [12]u8, ciphertext: []const u8, buf: []u8) ![]const u8 {
    if (ciphertext.len < ChaCha20Poly1305.tag_length) return error.CiphertextTooShort;
    const data_len = ciphertext.len - ChaCha20Poly1305.tag_length;
    const tag: [ChaCha20Poly1305.tag_length]u8 = ciphertext[data_len..][0..ChaCha20Poly1305.tag_length].*;
    ChaCha20Poly1305.decrypt(
        buf[0..data_len],
        ciphertext[0..data_len],
        tag,
        "",
        nonce,
        key,
    ) catch return error.DecryptionFailed;
    return buf[0..data_len];
}

/// HMAC-SHA256 for webhook signature verification.
pub fn hmacSha256(key: []const u8, message: []const u8) [HmacSha256.mac_length]u8 {
    var out: [HmacSha256.mac_length]u8 = undefined;
    var h = HmacSha256.init(key);
    h.update(message);
    h.final(&out);
    return out;
}

/// Hex-encode bytes to a lowercase hex string.
pub fn hexEncode(data: []const u8, buf: []u8) []const u8 {
    const charset = "0123456789abcdef";
    const len = @min(data.len * 2, buf.len);
    var i: usize = 0;
    while (i < data.len and i * 2 + 1 < buf.len) : (i += 1) {
        buf[i * 2] = charset[data[i] >> 4];
        buf[i * 2 + 1] = charset[data[i] & 0x0f];
    }
    return buf[0..len];
}

/// Hex-decode a hex string to bytes.
pub fn hexDecode(hex: []const u8, buf: []u8) ![]const u8 {
    if (hex.len & 1 != 0) return error.OddHexLength;
    const byte_len = hex.len / 2;
    if (buf.len < byte_len) return error.BufferTooSmall;
    for (0..byte_len) |i| {
        const hi: u8 = hexVal(hex[i * 2]) orelse return error.InvalidHex;
        const lo: u8 = hexVal(hex[i * 2 + 1]) orelse return error.InvalidHex;
        buf[i] = (hi << 4) | lo;
    }
    return buf[0..byte_len];
}

fn hexVal(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    return null;
}

/// Manages encrypted storage of secrets (API keys, tokens, etc.)
/// Secrets are encrypted using ChaCha20-Poly1305 AEAD with a random key
/// stored on disk with restrictive file permissions.
pub const SecretStore = struct {
    /// Path to the key file
    key_path_buf: [std.fs.max_path_bytes]u8 = undefined,
    key_path_len: usize,
    /// Whether encryption is enabled
    enabled: bool,

    /// Create a new secret store rooted at the given directory.
    pub fn init(dir: []const u8, enabled: bool) SecretStore {
        var store = SecretStore{
            .key_path_len = 0,
            .enabled = enabled,
        };
        const key_name = "/.secret_key";
        const total = @min(dir.len + key_name.len, store.key_path_buf.len);
        const dir_len = @min(dir.len, store.key_path_buf.len);
        @memcpy(store.key_path_buf[0..dir_len], dir[0..dir_len]);
        if (total > dir_len) {
            const rest_len = total - dir_len;
            @memcpy(store.key_path_buf[dir_len..][0..rest_len], key_name[0..rest_len]);
        }
        store.key_path_len = total;
        return store;
    }

    fn keyPath(self: *const SecretStore) []const u8 {
        return self.key_path_buf[0..self.key_path_len];
    }

    /// Encrypt a plaintext secret. Returns hex-encoded ciphertext prefixed with "enc2:".
    /// Format: enc2:<hex(nonce || ciphertext || tag)> (12 + N + 16 bytes).
    /// If encryption is disabled, returns the plaintext as-is.
    pub fn encryptSecret(self: *const SecretStore, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        if (!self.enabled or plaintext.len == 0) {
            return try allocator.dupe(u8, plaintext);
        }

        const key = try self.loadOrCreateKey();

        // Generate random nonce
        var nonce: [NONCE_LEN]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        // Encrypt
        const ct_len = plaintext.len + TAG_LEN;
        var ct_buf = try allocator.alloc(u8, ct_len);
        defer allocator.free(ct_buf);

        var tag: [TAG_LEN]u8 = undefined;
        ChaCha20Poly1305.encrypt(
            ct_buf[0..plaintext.len],
            &tag,
            plaintext,
            "",
            nonce,
            key,
        );
        @memcpy(ct_buf[plaintext.len..][0..TAG_LEN], &tag);

        // Build blob: nonce || ciphertext || tag
        const blob_len = NONCE_LEN + ct_len;
        var blob = try allocator.alloc(u8, blob_len);
        defer allocator.free(blob);
        @memcpy(blob[0..NONCE_LEN], &nonce);
        @memcpy(blob[NONCE_LEN..][0..ct_len], ct_buf);

        // Hex encode and prepend "enc2:"
        const hex_len = blob_len * 2;
        const result = try allocator.alloc(u8, 5 + hex_len); // "enc2:" + hex
        @memcpy(result[0..5], "enc2:");
        _ = hexEncode(blob, result[5..]);

        return result;
    }

    /// Decrypt a secret.
    /// - "enc2:" prefix -> ChaCha20-Poly1305
    /// - No prefix -> returned as-is (plaintext)
    pub fn decryptSecret(self: *const SecretStore, allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        if (value.len > 5 and std.mem.eql(u8, value[0..5], "enc2:")) {
            return self.decryptChacha20(allocator, value[5..]);
        }
        return try allocator.dupe(u8, value);
    }

    fn decryptChacha20(self: *const SecretStore, allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
        // Decode hex
        var decode_buf: [8192]u8 = undefined;
        const blob = hexDecode(hex_str, &decode_buf) catch return error.CorruptHex;
        if (blob.len <= NONCE_LEN) return error.CiphertextTooShort;

        const nonce: [NONCE_LEN]u8 = blob[0..NONCE_LEN].*;
        const ciphertext = blob[NONCE_LEN..];

        const key = try self.loadOrCreateKey();

        // Use the top-level decrypt with a stack buffer (avoids segfault
        // in ChaCha20Poly1305.decrypt when tag verification fails with
        // heap-allocated output on Zig 0.15/macOS).
        var plain_buf: [8192]u8 = undefined;
        const decrypted = decrypt(key, nonce, ciphertext, &plain_buf) catch return error.DecryptionFailed;

        return try allocator.dupe(u8, decrypted);
    }

    /// Check if a value is encrypted
    pub fn isEncrypted(value: []const u8) bool {
        return value.len >= 5 and std.mem.eql(u8, value[0..5], "enc2:");
    }

    /// Load the encryption key from disk, or create one if it doesn't exist.
    fn loadOrCreateKey(self: *const SecretStore) ![KEY_LEN]u8 {
        const path = self.keyPath();

        // Try to read existing key
        if (std.fs.cwd().openFile(path, .{})) |file| {
            defer file.close();
            var hex_buf: [KEY_LEN * 2 + 16]u8 = undefined; // some slack for whitespace
            const bytes_read = file.readAll(&hex_buf) catch return error.KeyReadFailed;
            const hex_str = std.mem.trim(u8, hex_buf[0..bytes_read], " \t\r\n");
            var key: [KEY_LEN]u8 = undefined;
            _ = hexDecode(hex_str, &key) catch return error.KeyCorrupt;
            return key;
        } else |_| {
            // Generate new key
            var key: [KEY_LEN]u8 = undefined;
            std.crypto.random.bytes(&key);

            // Write hex-encoded key
            var hex_buf: [KEY_LEN * 2]u8 = undefined;
            _ = hexEncode(&key, &hex_buf);

            // Ensure parent dir exists
            if (std.fs.path.dirname(path)) |parent| {
                std.fs.cwd().makePath(parent) catch {};
            }

            const file = std.fs.cwd().createFile(path, .{}) catch return error.KeyWriteFailed;
            defer file.close();
            file.writeAll(&hex_buf) catch return error.KeyWriteFailed;

            // Set restrictive permissions (Unix: 0600, owner-only)
            if (@import("builtin").os.tag != .windows) {
                file.chmod(0o600) catch {};
            }

            return key;
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "encrypt then decrypt roundtrip" {
    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = "hello nullclaw";

    var enc_buf: [256]u8 = undefined;
    const encrypted = try encrypt(key, nonce, plaintext, &enc_buf);

    var dec_buf: [256]u8 = undefined;
    const decrypted = try decrypt(key, nonce, encrypted, &dec_buf);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "hmac produces correct length" {
    const result = hmacSha256("secret", "message");
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "hex encode decode roundtrip" {
    const data = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0xab, 0xcd };
    var enc_buf: [12]u8 = undefined;
    const encoded = hexEncode(&data, &enc_buf);
    try std.testing.expectEqualStrings("0001feffabcd", encoded);

    var dec_buf: [6]u8 = undefined;
    const decoded = try hexDecode(encoded, &dec_buf);
    try std.testing.expectEqualSlices(u8, &data, decoded);
}

test "hex decode odd length fails" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.OddHexLength, hexDecode("abc", &buf));
}

test "hex decode invalid chars fails" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.InvalidHex, hexDecode("zzzz", &buf));
}

test "secret store encrypt decrypt roundtrip" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const secret = "sk-my-secret-api-key-12345";

    const encrypted = try store.encryptSecret(std.testing.allocator, secret);
    defer std.testing.allocator.free(encrypted);

    try std.testing.expect(std.mem.startsWith(u8, encrypted, "enc2:"));
    try std.testing.expect(!std.mem.eql(u8, encrypted, secret));

    const decrypted = try store.decryptSecret(std.testing.allocator, encrypted);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(secret, decrypted);
}

test "secret store encrypt empty returns empty" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const result = try store.encryptSecret(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "secret store decrypt plaintext passthrough" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const result = try store.decryptSecret(std.testing.allocator, "sk-plaintext-key");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("sk-plaintext-key", result);
}

test "secret store disabled returns plaintext" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, false);
    const result = try store.encryptSecret(std.testing.allocator, "sk-secret");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("sk-secret", result);
}

test "secret store is encrypted detects prefix" {
    try std.testing.expect(SecretStore.isEncrypted("enc2:aabbcc"));
    try std.testing.expect(!SecretStore.isEncrypted("sk-plaintext"));
    try std.testing.expect(!SecretStore.isEncrypted(""));
}

test "secret store encrypting same value produces different ciphertext" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const e1 = try store.encryptSecret(std.testing.allocator, "secret");
    defer std.testing.allocator.free(e1);
    const e2 = try store.encryptSecret(std.testing.allocator, "secret");
    defer std.testing.allocator.free(e2);

    try std.testing.expect(!std.mem.eql(u8, e1, e2));

    // Both should decrypt to same value
    const d1 = try store.decryptSecret(std.testing.allocator, e1);
    defer std.testing.allocator.free(d1);
    const d2 = try store.decryptSecret(std.testing.allocator, e2);
    defer std.testing.allocator.free(d2);
    try std.testing.expectEqualStrings("secret", d1);
    try std.testing.expectEqualStrings("secret", d2);
}

test "secret store different dirs cannot decrypt each other" {
    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    const path1 = try tmp1.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path1);

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    const path2 = try tmp2.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path2);

    const store1 = SecretStore.init(path1, true);
    const store2 = SecretStore.init(path2, true);

    const encrypted = try store1.encryptSecret(std.testing.allocator, "secret-for-store1");
    defer std.testing.allocator.free(encrypted);

    const result = store2.decryptSecret(std.testing.allocator, encrypted);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "secret store same dir interop" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store1 = SecretStore.init(tmp_path, true);
    const store2 = SecretStore.init(tmp_path, true);

    const encrypted = try store1.encryptSecret(std.testing.allocator, "cross-store-secret");
    defer std.testing.allocator.free(encrypted);

    const decrypted = try store2.decryptSecret(std.testing.allocator, encrypted);
    defer std.testing.allocator.free(decrypted);
    try std.testing.expectEqualStrings("cross-store-secret", decrypted);
}

// ── Additional encryption tests ──────────────────────────────────

test "secret store unicode roundtrip" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const secret = "sk-\xc3\xa9mojis-\xf0\x9f\xa6\x80-test";

    const encrypted = try store.encryptSecret(std.testing.allocator, secret);
    defer std.testing.allocator.free(encrypted);

    const decrypted = try store.decryptSecret(std.testing.allocator, encrypted);
    defer std.testing.allocator.free(decrypted);
    try std.testing.expectEqualStrings(secret, decrypted);
}

test "secret store key file created on first encrypt" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);

    const encrypted = try store.encryptSecret(std.testing.allocator, "trigger-key-creation");
    defer std.testing.allocator.free(encrypted);

    // Key file should exist now
    const key_path = store.keyPath();
    const file = try std.fs.cwd().openFile(key_path, .{});
    defer file.close();
    var buf: [128]u8 = undefined;
    const bytes_read = try file.readAll(&buf);
    // Key is hex-encoded 32 bytes = 64 hex chars
    try std.testing.expectEqual(@as(usize, KEY_LEN * 2), bytes_read);
}

test "secret store tampered ciphertext detected" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    const encrypted = try store.encryptSecret(std.testing.allocator, "sensitive-data");
    defer std.testing.allocator.free(encrypted);

    // Flip a byte in the hex ciphertext (after "enc2:" prefix)
    // We need to decode hex, tamper, then re-encode
    const hex_str = encrypted[5..];
    var decode_buf: [8192]u8 = undefined;
    const blob = try hexDecode(hex_str, &decode_buf);

    // Tamper with a byte after the nonce
    var tampered_blob: [8192]u8 = undefined;
    @memcpy(tampered_blob[0..blob.len], blob);
    if (blob.len > NONCE_LEN) {
        tampered_blob[NONCE_LEN] ^= 0xff;
    }

    // Re-encode to hex
    var hex_out: [16384]u8 = undefined;
    const tampered_hex = hexEncode(tampered_blob[0..blob.len], &hex_out);

    // Build tampered string: "enc2:" + tampered_hex
    var tampered_full: [16400]u8 = undefined;
    @memcpy(tampered_full[0..5], "enc2:");
    @memcpy(tampered_full[5..][0..tampered_hex.len], tampered_hex);
    const tampered_str = tampered_full[0 .. 5 + tampered_hex.len];

    const result = store.decryptSecret(std.testing.allocator, tampered_str);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "secret store truncated ciphertext returns error" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    // Trigger key creation first
    const setup = try store.encryptSecret(std.testing.allocator, "setup");
    defer std.testing.allocator.free(setup);

    // Only a few bytes — shorter than nonce
    const result = store.decryptSecret(std.testing.allocator, "enc2:aabbccdd");
    try std.testing.expectError(error.CiphertextTooShort, result);
}

test "secret store corrupt hex returns error" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);
    // Trigger key creation
    const setup = try store.encryptSecret(std.testing.allocator, "setup");
    defer std.testing.allocator.free(setup);

    const result = store.decryptSecret(std.testing.allocator, "enc2:not-valid-hex!!");
    try std.testing.expectError(error.CorruptHex, result);
}

test "encrypt with different nonce produces different output" {
    const key = [_]u8{0x42} ** 32;
    const nonce1 = [_]u8{0x01} ** 12;
    const nonce2 = [_]u8{0x02} ** 12;
    const plaintext = "same input";

    var enc1_buf: [256]u8 = undefined;
    const e1 = try encrypt(key, nonce1, plaintext, &enc1_buf);

    var enc2_buf: [256]u8 = undefined;
    const e2 = try encrypt(key, nonce2, plaintext, &enc2_buf);

    // Different nonces -> different ciphertext
    try std.testing.expect(!std.mem.eql(u8, e1, e2));

    // Both decrypt to same value
    var dec1_buf: [256]u8 = undefined;
    const d1 = try decrypt(key, nonce1, e1, &dec1_buf);
    try std.testing.expectEqualStrings(plaintext, d1);

    var dec2_buf: [256]u8 = undefined;
    const d2 = try decrypt(key, nonce2, e2, &dec2_buf);
    try std.testing.expectEqualStrings(plaintext, d2);
}

test "decrypt with wrong key fails" {
    const key1 = [_]u8{0x01} ** 32;
    const key2 = [_]u8{0x02} ** 32;
    const nonce = [_]u8{0xAB} ** 12;
    const plaintext = "secret message";

    var enc_buf: [256]u8 = undefined;
    const encrypted = try encrypt(key1, nonce, plaintext, &enc_buf);

    var dec_buf: [256]u8 = undefined;
    const result = decrypt(key2, nonce, encrypted, &dec_buf);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "encrypt buffer too small fails" {
    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = "hello";

    var tiny_buf: [5]u8 = undefined; // Too small (needs plaintext.len + 16 for tag)
    const result = encrypt(key, nonce, plaintext, &tiny_buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "decrypt ciphertext too short fails" {
    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x01} ** 12;

    // Less than tag length
    var dec_buf: [256]u8 = undefined;
    const result = decrypt(key, nonce, "short", &dec_buf);
    try std.testing.expectError(error.CiphertextTooShort, result);
}

test "hmac same input same output" {
    const r1 = hmacSha256("key", "message");
    const r2 = hmacSha256("key", "message");
    try std.testing.expectEqualSlices(u8, &r1, &r2);
}

test "hmac different keys different output" {
    const r1 = hmacSha256("key1", "message");
    const r2 = hmacSha256("key2", "message");
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "hmac different messages different output" {
    const r1 = hmacSha256("key", "message1");
    const r2 = hmacSha256("key", "message2");
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "hex encode empty" {
    var buf: [4]u8 = undefined;
    const result = hexEncode(&[_]u8{}, &buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "hex decode empty" {
    var buf: [4]u8 = undefined;
    const result = try hexDecode("", &buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "hex encode all bytes" {
    const data = [_]u8{ 0x00, 0xff };
    var buf: [4]u8 = undefined;
    const result = hexEncode(&data, &buf);
    try std.testing.expectEqualStrings("00ff", result);
}

test "hex decode uppercase" {
    var buf: [2]u8 = undefined;
    const result = try hexDecode("AABB", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, result);
}

test "hex decode mixed case" {
    var buf: [2]u8 = undefined;
    const result = try hexDecode("aAbB", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, result);
}

test "secret store is encrypted short strings" {
    try std.testing.expect(!SecretStore.isEncrypted("enc"));
    try std.testing.expect(!SecretStore.isEncrypted("enc2"));
    try std.testing.expect(SecretStore.isEncrypted("enc2:x"));
    try std.testing.expect(!SecretStore.isEncrypted("ENC2:x"));
}

test "secret store encrypt decrypt multiple values same store" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const store = SecretStore.init(tmp_path, true);

    const secrets = [_][]const u8{ "secret-1", "secret-2", "secret-3" };
    var encrypted: [3][]u8 = undefined;

    for (secrets, 0..) |s, i| {
        encrypted[i] = try store.encryptSecret(std.testing.allocator, s);
    }
    defer for (&encrypted) |e| std.testing.allocator.free(e);

    for (secrets, 0..) |expected, i| {
        const dec = try store.decryptSecret(std.testing.allocator, encrypted[i]);
        defer std.testing.allocator.free(dec);
        try std.testing.expectEqualStrings(expected, dec);
    }
}
