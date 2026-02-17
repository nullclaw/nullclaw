const std = @import("std");

// Security — encryption, workspace sandboxing, pairing.
// Canonical implementations live in security/secrets.zig; re-exported here for convenience.

const secrets = @import("security/secrets.zig");

/// Encrypt data using ChaCha20-Poly1305.
pub const encrypt = secrets.encrypt;

/// Decrypt data using ChaCha20-Poly1305.
pub const decrypt = secrets.decrypt;

/// HMAC-SHA256 for webhook signature verification.
pub const hmacSha256 = secrets.hmacSha256;

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
