//! Tencent platform cryptographic helpers shared by WeChat, WeCom, and Tencent Cloud.

const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha1 = std.crypto.hash.Sha1;

/// AES block size in bytes.
pub const AES_BLOCK: usize = 16;

/// WeChat and WeCom secure callbacks use PKCS#7 padding up to 32 bytes.
pub const WECHAT_PKCS7_BLOCK: u8 = 32;

/// Tencent EncodingAESKey values are 43 base64 characters without trailing '='.
pub const ENCODING_AES_KEY_LEN: usize = 43;

/// Apply PKCS#7 padding so the result length is a multiple of `block_multiple`.
/// Allocates; caller must free.
pub fn pkcs7Pad(
    allocator: std.mem.Allocator,
    data: []const u8,
    block_multiple: u8,
) ![]u8 {
    if (block_multiple == 0) return error.InvalidBlockSize;

    const rem = data.len % block_multiple;
    const pad_len: u8 = @intCast(if (rem == 0) block_multiple else (block_multiple - rem));
    const out = try allocator.alloc(u8, data.len + pad_len);
    @memcpy(out[0..data.len], data);
    @memset(out[data.len..], pad_len);
    return out;
}

/// Validate and strip PKCS#7 padding. Returns a sub-slice of `data` (no allocation).
pub fn pkcs7Unpad(data: []const u8, max_pad: u8) ![]const u8 {
    if (data.len == 0 or data.len % AES_BLOCK != 0) return error.InvalidPadding;
    const pad_len = data[data.len - 1];
    if (pad_len == 0 or pad_len > max_pad or pad_len > data.len) return error.InvalidPadding;
    for (data[data.len - pad_len ..]) |b| {
        if (b != pad_len) return error.InvalidPadding;
    }
    return data[0 .. data.len - pad_len];
}

/// AES-256-CBC encrypt with PKCS#7 padding.
/// Returns heap-allocated ciphertext. Caller must free.
pub fn aesCbcEncrypt(
    allocator: std.mem.Allocator,
    key: [32]u8,
    iv: [16]u8,
    plaintext: []const u8,
    padding_block: u8,
) ![]u8 {
    const padded = try pkcs7Pad(allocator, plaintext, padding_block);
    defer allocator.free(padded);

    const out = try allocator.alloc(u8, padded.len);
    const enc = Aes256.initEnc(key);
    var prev = iv;

    var offset: usize = 0;
    while (offset < padded.len) : (offset += AES_BLOCK) {
        var block: [AES_BLOCK]u8 = undefined;
        @memcpy(block[0..], padded[offset .. offset + AES_BLOCK]);

        var i: usize = 0;
        while (i < AES_BLOCK) : (i += 1) {
            block[i] ^= prev[i];
        }

        var out_block: [AES_BLOCK]u8 = undefined;
        enc.encrypt(&out_block, &block);
        @memcpy(out[offset .. offset + AES_BLOCK], out_block[0..]);
        prev = out_block;
    }

    return out;
}

/// AES-256-CBC decrypt in place.
pub fn aes256CbcDecryptInPlace(buf: []u8, key: [32]u8, iv: [16]u8) !void {
    if (buf.len == 0 or (buf.len % AES_BLOCK) != 0) return error.InvalidCiphertext;

    const dec = Aes256.initDec(key);
    var prev = iv;
    var offset: usize = 0;
    while (offset < buf.len) : (offset += AES_BLOCK) {
        var src_block: [AES_BLOCK]u8 = undefined;
        @memcpy(src_block[0..], buf[offset .. offset + AES_BLOCK]);

        var dst_block: [AES_BLOCK]u8 = undefined;
        dec.decrypt(&dst_block, &src_block);

        var i: usize = 0;
        while (i < AES_BLOCK) : (i += 1) {
            dst_block[i] ^= prev[i];
        }

        @memcpy(buf[offset .. offset + AES_BLOCK], dst_block[0..]);
        prev = src_block;
    }
}

/// AES-256-CBC decrypt with PKCS#7 unpadding.
/// Returns heap-allocated plaintext. Caller must free.
pub fn aesCbcDecrypt(
    allocator: std.mem.Allocator,
    key: [32]u8,
    iv: [16]u8,
    ciphertext: []const u8,
    max_pad: u8,
) ![]u8 {
    const buf = try allocator.dupe(u8, ciphertext);
    defer allocator.free(buf);

    try aes256CbcDecryptInPlace(buf, key, iv);
    const unpadded = try pkcs7Unpad(buf, max_pad);
    return try allocator.dupe(u8, unpadded);
}

/// Decode a Tencent EncodingAESKey (43 chars, base64 without trailing '=').
pub fn decodeEncodingAesKey(encoding_aes_key: []const u8) ![32]u8 {
    if (encoding_aes_key.len != ENCODING_AES_KEY_LEN) return error.InvalidEncodingAesKey;

    var with_padding: [ENCODING_AES_KEY_LEN + 1]u8 = undefined;
    @memcpy(with_padding[0..ENCODING_AES_KEY_LEN], encoding_aes_key);
    with_padding[ENCODING_AES_KEY_LEN] = '=';

    var decoded: [32]u8 = undefined;
    _ = std.base64.standard.Decoder.decode(&decoded, &with_padding) catch return error.InvalidEncodingAesKey;
    return decoded;
}

/// SHA-1(sort(token, timestamp, nonce)) as lowercase hex.
pub fn wechatSha1Signature(
    token: []const u8,
    timestamp: []const u8,
    nonce: []const u8,
) [40]u8 {
    var parts = [_][]const u8{ token, timestamp, nonce };
    return sortedSha1Hex(parts[0..]);
}

/// SHA-1(sort(token, timestamp, nonce, encrypted)) as lowercase hex.
pub fn wechatMessageSha1Signature(
    token: []const u8,
    timestamp: []const u8,
    nonce: []const u8,
    encrypted: []const u8,
) [40]u8 {
    var parts = [_][]const u8{ token, timestamp, nonce, encrypted };
    return sortedSha1Hex(parts[0..]);
}

fn sortedSha1Hex(parts: [][]const u8) [40]u8 {
    sortLexParts(parts);

    var sha1 = Sha1.init(.{});
    for (parts) |part| sha1.update(part);

    var digest: [Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn sortLexParts(parts: [][]const u8) void {
    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < parts.len) : (j += 1) {
            if (std.mem.lessThan(u8, parts[j], parts[i])) {
                const tmp = parts[i];
                parts[i] = parts[j];
                parts[j] = tmp;
            }
        }
    }
}

/// Tencent Cloud TC3-HMAC-SHA256 signing algorithm.
///
/// Signature = Hex(HMAC-SHA256(SecretSigning, StringToSign))
/// where:
///   SecretDate    = HMAC-SHA256("TC3" + secret_key, date)
///   SecretService = HMAC-SHA256(SecretDate, service)
///   SecretSigning = HMAC-SHA256(SecretService, "tc3_request")
pub fn tc3Sign(
    secret_key: []const u8,
    date: []const u8,
    service: []const u8,
    string_to_sign: []const u8,
) error{KeyTooLong}![64]u8 {
    var key_buf: [224]u8 = undefined;
    if (3 + secret_key.len > key_buf.len) return error.KeyTooLong;

    @memcpy(key_buf[0..3], "TC3");
    @memcpy(key_buf[3..][0..secret_key.len], secret_key);
    const tc3_key = key_buf[0 .. 3 + secret_key.len];

    var secret_date: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_date, date, tc3_key);

    var secret_service: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_service, service, &secret_date);

    var secret_signing: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_signing, "tc3_request", &secret_service);

    var signature: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&signature, string_to_sign, &secret_signing);

    return std.fmt.bytesToHex(signature, .lower);
}

test "pkcs7Pad respects requested block multiple" {
    const padded = try pkcs7Pad(std.testing.allocator, "abc", WECHAT_PKCS7_BLOCK);
    defer std.testing.allocator.free(padded);

    try std.testing.expectEqual(@as(usize, 32), padded.len);
    for (padded[3..]) |b| try std.testing.expectEqual(@as(u8, 29), b);
}

test "pkcs7Pad on block boundary adds a full block" {
    const padded = try pkcs7Pad(std.testing.allocator, "12345678901234567890123456789012", WECHAT_PKCS7_BLOCK);
    defer std.testing.allocator.free(padded);

    try std.testing.expectEqual(@as(usize, 64), padded.len);
    for (padded[32..]) |b| try std.testing.expectEqual(WECHAT_PKCS7_BLOCK, b);
}

test "pkcs7Unpad strips valid 32-byte padding" {
    var buf = [_]u8{ 'a', 'b', 'c' } ++ [_]u8{29} ** 29;
    const result = try pkcs7Unpad(&buf, WECHAT_PKCS7_BLOCK);
    try std.testing.expectEqualStrings("abc", result);
}

test "pkcs7Unpad rejects padding longer than configured maximum" {
    var buf = [_]u8{0} ** 16 ++ [_]u8{17} ** 16;
    try std.testing.expectError(error.InvalidPadding, pkcs7Unpad(&buf, 16));
}

test "decodeEncodingAesKey decodes 43-char base64 key" {
    var raw: [32]u8 = undefined;
    for (&raw, 0..) |*byte, idx| byte.* = @as(u8, @intCast(idx));

    var encoded: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &raw);

    const decoded = try decodeEncodingAesKey(encoded[0..43]);
    try std.testing.expectEqualSlices(u8, &raw, &decoded);
}

test "aesCbcEncrypt decrypt roundtrip with WeChat padding" {
    const key = [_]u8{0x2b} ** 32;
    const iv = [_]u8{0x00} ** 16;
    const plaintext = "wechat secure callback payload";

    const ciphertext = try aesCbcEncrypt(
        std.testing.allocator,
        key,
        iv,
        plaintext,
        WECHAT_PKCS7_BLOCK,
    );
    defer std.testing.allocator.free(ciphertext);

    const decrypted = try aesCbcDecrypt(
        std.testing.allocator,
        key,
        iv,
        ciphertext,
        WECHAT_PKCS7_BLOCK,
    );
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "aes256CbcDecryptInPlace rejects non-block-aligned ciphertext" {
    var buf = [_]u8{0} ** 15;
    try std.testing.expectError(
        error.InvalidCiphertext,
        aes256CbcDecryptInPlace(&buf, [_]u8{0} ** 32, [_]u8{0} ** 16),
    );
}

test "wechatSha1Signature is deterministic" {
    const sig1 = wechatSha1Signature("mytoken", "1234567890", "abc123");
    const sig2 = wechatSha1Signature("mytoken", "1234567890", "abc123");
    try std.testing.expectEqualSlices(u8, &sig1, &sig2);
}

test "wechatMessageSha1Signature matches official WeCom example" {
    const encrypted =
        "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5" ++
        "L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qh" ++
        "xchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLx" ++
        "AUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s" ++
        "4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8" ++
        "V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/u" ++
        "h9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGH" ++
        "BZZIs2pDBS8R07+qN+E7Q==";

    const sig = wechatMessageSha1Signature("QDG6eK", "1409659813", "1372623149", encrypted);
    try std.testing.expectEqualStrings("477715d11cdb4164915debcba66cb864d751f3e6", sig[0..]);
}

test "tc3Sign matches official Tencent Cloud example" {
    const string_to_sign =
        "TC3-HMAC-SHA256\n" ++
        "1551113065\n" ++
        "2019-02-25/cvm/tc3_request\n" ++
        "5ffe6a04c0664d6b969fab9a13bdab201d63ee709638e2749d62a09ca18d7031";

    const signature = try tc3Sign(
        "Gu5t9xGARNpq86cd98joQYCN3EXAMPLE",
        "2019-02-25",
        "cvm",
        string_to_sign,
    );
    try std.testing.expectEqualStrings(
        "72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168",
        signature[0..],
    );
}

test "tc3Sign key too long returns error" {
    const long_key = "x" ** 222;
    try std.testing.expectError(
        error.KeyTooLong,
        tc3Sign(long_key, "2026-03-16", "hunyuan", "payload"),
    );
}
