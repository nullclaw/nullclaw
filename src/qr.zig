const std = @import("std");
const testing = std.testing;

/// Minimal QR Code encoder (Model 2, Version 1–6, Error correction level L).
/// Designed for encoding short URLs into terminal-renderable QR codes.
const MAX_VERSION = 6;
const MAX_MODULES = 17 + MAX_VERSION * 4; // Version 6 = 41 modules

pub const QrCode = struct {
    modules: [MAX_MODULES][MAX_MODULES]bool,
    size: u8,

    pub fn get(self: *const QrCode, row: usize, col: usize) bool {
        return self.modules[row][col];
    }
};

const VersionInfo = struct {
    version: u8,
    size: u8,
    data_codewords: u16,
    ec_codewords: u8,
    num_blocks: u8,
    alignment_center: ?u8,
};

const version_table = [6]VersionInfo{
    .{ .version = 1, .size = 21, .data_codewords = 19, .ec_codewords = 7, .num_blocks = 1, .alignment_center = null },
    .{ .version = 2, .size = 25, .data_codewords = 34, .ec_codewords = 10, .num_blocks = 1, .alignment_center = 18 },
    .{ .version = 3, .size = 29, .data_codewords = 55, .ec_codewords = 15, .num_blocks = 1, .alignment_center = 22 },
    .{ .version = 4, .size = 33, .data_codewords = 80, .ec_codewords = 20, .num_blocks = 1, .alignment_center = 26 },
    .{ .version = 5, .size = 37, .data_codewords = 108, .ec_codewords = 26, .num_blocks = 1, .alignment_center = 30 },
    .{ .version = 6, .size = 41, .data_codewords = 136, .ec_codewords = 18, .num_blocks = 2, .alignment_center = 34 },
};

fn selectVersion(data_len: usize) !VersionInfo {
    for (version_table) |v| {
        const capacity = v.data_codewords - 3;
        if (data_len <= capacity) return v;
    }
    return error.DataTooLong;
}

pub fn encode(data: []const u8) !QrCode {
    const ver = try selectVersion(data.len);
    var qr = QrCode{ .modules = std.mem.zeroes([MAX_MODULES][MAX_MODULES]bool), .size = ver.size };
    var reserved = std.mem.zeroes([MAX_MODULES][MAX_MODULES]bool);

    placeFunctionPatterns(&qr, &reserved, ver);
    placeTimingPatterns(&qr, &reserved, ver);
    reserveFormatArea(&reserved, ver);

    const total_codewords = ver.data_codewords + @as(u16, ver.ec_codewords) * @as(u16, ver.num_blocks);
    var codewords: [256]u8 = undefined;
    const data_cw = buildDataCodewords(data, ver, &codewords);
    buildEcCodewords(data_cw, ver, &codewords);

    placeDataBits(&qr, &reserved, codewords[0..total_codewords], ver.size);

    const best_mask = selectBestMask(&qr, &reserved, ver);
    applyMask(&qr, &reserved, best_mask, ver.size);
    placeFormatBits(&qr, best_mask, ver.size);

    return qr;
}

fn placeFunctionPatterns(qr: *QrCode, reserved: *[MAX_MODULES][MAX_MODULES]bool, ver: VersionInfo) void {
    placeFinderPattern(qr, reserved, 0, 0, ver.size);
    placeFinderPattern(qr, reserved, 0, ver.size - 7, ver.size);
    placeFinderPattern(qr, reserved, ver.size - 7, 0, ver.size);

    if (ver.alignment_center) |center| {
        placeAlignmentPattern(qr, reserved, center, center);
    }
}

fn placeFinderPattern(qr: *QrCode, reserved: *[MAX_MODULES][MAX_MODULES]bool, row: u8, col: u8, size: u8) void {
    const finder = [7][7]bool{
        .{ true, true, true, true, true, true, true },
        .{ true, false, false, false, false, false, true },
        .{ true, false, true, true, true, false, true },
        .{ true, false, true, true, true, false, true },
        .{ true, false, true, true, true, false, true },
        .{ true, false, false, false, false, false, true },
        .{ true, true, true, true, true, true, true },
    };

    for (0..7) |r| {
        for (0..7) |c| {
            const rr = row + @as(u8, @intCast(r));
            const cc = col + @as(u8, @intCast(c));
            qr.modules[rr][cc] = finder[r][c];
            reserved[rr][cc] = true;
        }
    }

    // Separators
    for (0..8) |i| {
        const ii = @as(u8, @intCast(i));
        // Horizontal
        if (row == 0) {
            if (col + 7 < size) {
                setReserved(reserved, 7, col + ii);
            }
            if (col >= 1) {
                setReserved(reserved, 7, col -| 1);
            } else if (col == 0 and ii < 8) {
                setReserved(reserved, 7, ii);
            }
        } else {
            if (col + 7 < size) {
                setReserved(reserved, row -| 1, col + ii);
            }
            if (col == 0) {
                setReserved(reserved, row -| 1, ii);
            }
        }
        // Vertical
        if (col == 0) {
            if (row == 0 and ii < 8) {
                setReserved(reserved, ii, 7);
            } else if (row > 0) {
                setReserved(reserved, row + ii, 7);
                if (row >= 1 and ii == 0) setReserved(reserved, row -| 1, 7);
            }
        }
        if (col + 7 < size) {
            // already handled
        }
    }

    // Simpler approach: mark 8x8 area + separators as reserved
    const r_start = if (row == 0) 0 else row -| 1;
    const r_end: u8 = @min(row + 8, size);
    const c_start = if (col == 0) 0 else col -| 1;
    const c_end: u8 = @min(col + 8, size);

    var r: u8 = r_start;
    while (r < r_end) : (r += 1) {
        var c: u8 = c_start;
        while (c < c_end) : (c += 1) {
            reserved[r][c] = true;
        }
    }
}

fn setReserved(reserved: *[MAX_MODULES][MAX_MODULES]bool, r: u8, c: u8) void {
    reserved[r][c] = true;
}

fn placeAlignmentPattern(qr: *QrCode, reserved: *[MAX_MODULES][MAX_MODULES]bool, center_row: u8, center_col: u8) void {
    const pattern = [5][5]bool{
        .{ true, true, true, true, true },
        .{ true, false, false, false, true },
        .{ true, false, true, false, true },
        .{ true, false, false, false, true },
        .{ true, true, true, true, true },
    };

    for (0..5) |r| {
        for (0..5) |c| {
            const rr = center_row - 2 + @as(u8, @intCast(r));
            const cc = center_col - 2 + @as(u8, @intCast(c));
            qr.modules[rr][cc] = pattern[r][c];
            reserved[rr][cc] = true;
        }
    }
}

fn placeTimingPatterns(qr: *QrCode, reserved: *[MAX_MODULES][MAX_MODULES]bool, ver: VersionInfo) void {
    for (8..ver.size - 8) |i| {
        const val = (i % 2 == 0);
        if (!reserved[6][i]) {
            qr.modules[6][i] = val;
            reserved[6][i] = true;
        }
        if (!reserved[i][6]) {
            qr.modules[i][6] = val;
            reserved[i][6] = true;
        }
    }
}

fn reserveFormatArea(reserved: *[MAX_MODULES][MAX_MODULES]bool, ver: VersionInfo) void {
    for (0..9) |i| {
        reserved[8][i] = true;
        reserved[i][8] = true;
    }
    for (0..8) |i| {
        reserved[8][ver.size - 1 - @as(u8, @intCast(i))] = true;
        reserved[ver.size - 1 - @as(u8, @intCast(i))][8] = true;
    }
    // Dark module
    reserved[ver.size - 8][8] = true;
}

fn buildDataCodewords(data: []const u8, ver: VersionInfo, out: *[256]u8) []u8 {
    var bits: BitWriter = .{};

    // Byte mode indicator: 0100
    bits.writeBits(4, 4);

    // Character count (8 bits for v1-9 in byte mode)
    bits.writeBits(@intCast(data.len), 8);

    // Data
    for (data) |byte| {
        bits.writeBits(byte, 8);
    }

    // Terminator (up to 4 zeros)
    const data_bits: u16 = @as(u16, ver.data_codewords) * 8;
    const remaining = data_bits -| bits.bit_count;
    const term_bits: u4 = @intCast(@min(remaining, 4));
    bits.writeBits(0, term_bits);

    // Pad to byte boundary
    while (bits.bit_count % 8 != 0) {
        bits.writeBits(0, 1);
    }

    // Pad codewords: 0xEC, 0x11 alternating
    var pad_toggle: bool = true;
    while (bits.bit_count < data_bits) {
        bits.writeBits(if (pad_toggle) 0xEC else 0x11, 8);
        pad_toggle = !pad_toggle;
    }

    const byte_count = bits.bit_count / 8;
    @memcpy(out[0..byte_count], bits.buffer[0..byte_count]);
    return out[0..byte_count];
}

fn buildEcCodewords(data: []const u8, ver: VersionInfo, out: *[256]u8) void {
    if (ver.num_blocks == 1) {
        const ec = gfPolyDivide(data, ver.ec_codewords);
        @memcpy(out[data.len .. data.len + ver.ec_codewords], ec[0..ver.ec_codewords]);
    } else {
        // Version 6 has 2 blocks. Split data evenly.
        const block_size = data.len / ver.num_blocks;
        const extra = data.len % ver.num_blocks;

        var ec_all: [2][26]u8 = undefined;
        var block_data: [2][]const u8 = undefined;
        var offset: usize = 0;

        for (0..ver.num_blocks) |b| {
            const sz = block_size + (if (b < extra) @as(usize, 1) else 0);
            block_data[b] = data[offset .. offset + sz];
            const ec = gfPolyDivide(block_data[b], ver.ec_codewords);
            @memcpy(ec_all[b][0..ver.ec_codewords], ec[0..ver.ec_codewords]);
            offset += sz;
        }

        // Interleave data codewords
        var write_pos: usize = 0;
        const max_block_sz = block_size + (if (extra > 0) @as(usize, 1) else 0);
        for (0..max_block_sz) |i| {
            for (0..ver.num_blocks) |b| {
                const sz = block_size + (if (b < extra) @as(usize, 1) else 0);
                if (i < sz) {
                    out[write_pos] = block_data[b][i];
                    write_pos += 1;
                }
            }
        }

        // Interleave EC codewords
        for (0..ver.ec_codewords) |i| {
            for (0..ver.num_blocks) |b| {
                out[write_pos] = ec_all[b][i];
                write_pos += 1;
            }
        }
    }
}

fn placeDataBits(qr: *QrCode, reserved: *const [MAX_MODULES][MAX_MODULES]bool, codewords: []const u8, size: u8) void {
    var bit_idx: usize = 0;
    const total_bits = codewords.len * 8;

    var col_: i16 = @as(i16, size) - 1;
    while (col_ >= 1) {
        var col = @as(u8, @intCast(col_));
        if (col == 6) col = 5; // Skip vertical timing column

        const right_col = col;
        const left_col = col - 1;
        if (left_col == 6) {
            col_ -= 1; // handled: skip timing
        }

        const col_group = @divTrunc(@as(i16, size) - 1 - col_, 2);
        var row_: i16 = if (@mod(col_group, 2) == 0) @as(i16, size) - 1 else 0;
        const row_step: i2 = if (@mod(col_group, 2) == 0) -1 else 1;

        while (row_ >= 0 and row_ < size) {
            const row = @as(u8, @intCast(row_));
            // Right column
            if (!reserved[row][right_col]) {
                if (bit_idx < total_bits) {
                    qr.modules[row][right_col] = ((codewords[bit_idx / 8] >> @intCast(7 - (bit_idx % 8))) & 1) == 1;
                    bit_idx += 1;
                }
            }
            // Left column
            const lc = if (right_col > 0) right_col - 1 else break;
            if (lc != 6 and !reserved[row][lc]) {
                if (bit_idx < total_bits) {
                    qr.modules[row][lc] = ((codewords[bit_idx / 8] >> @intCast(7 - (bit_idx % 8))) & 1) == 1;
                    bit_idx += 1;
                }
            }

            row_ += row_step;
        }

        col_ -= 2;
    }
}

fn applyMask(qr: *QrCode, reserved: *const [MAX_MODULES][MAX_MODULES]bool, mask: u3, size: u8) void {
    for (0..size) |r| {
        for (0..size) |c| {
            if (reserved[r][c]) continue;
            if (maskBit(mask, r, c)) {
                qr.modules[r][c] = !qr.modules[r][c];
            }
        }
    }
}

fn maskBit(mask: u3, row: usize, col: usize) bool {
    return switch (mask) {
        0 => (row + col) % 2 == 0,
        1 => row % 2 == 0,
        2 => col % 3 == 0,
        3 => (row + col) % 3 == 0,
        4 => (row / 2 + col / 3) % 2 == 0,
        5 => (row * col) % 2 + (row * col) % 3 == 0,
        6 => ((row * col) % 2 + (row * col) % 3) % 2 == 0,
        7 => ((row + col) % 2 + (row * col) % 3) % 2 == 0,
    };
}

fn selectBestMask(qr: *QrCode, reserved: *const [MAX_MODULES][MAX_MODULES]bool, ver: VersionInfo) u3 {
    var best_mask: u3 = 0;
    var best_penalty: u32 = std.math.maxInt(u32);

    for (0..8) |m| {
        const mask: u3 = @intCast(m);
        var trial = qr.*;
        applyMask(&trial, reserved, mask, ver.size);
        placeFormatBits(&trial, mask, ver.size);
        const penalty = evaluatePenalty(&trial, ver.size);
        if (penalty < best_penalty) {
            best_penalty = penalty;
            best_mask = mask;
        }
    }

    return best_mask;
}

fn evaluatePenalty(qr: *const QrCode, size: u8) u32 {
    var penalty: u32 = 0;

    // Rule 1: runs of same color >= 5
    for (0..size) |r| {
        var run: u32 = 1;
        for (1..size) |c| {
            if (qr.modules[r][c] == qr.modules[r][c - 1]) {
                run += 1;
            } else {
                if (run >= 5) penalty += run - 2;
                run = 1;
            }
        }
        if (run >= 5) penalty += run - 2;
    }
    for (0..size) |c| {
        var run: u32 = 1;
        for (1..size) |r| {
            if (qr.modules[r][c] == qr.modules[r - 1][c]) {
                run += 1;
            } else {
                if (run >= 5) penalty += run - 2;
                run = 1;
            }
        }
        if (run >= 5) penalty += run - 2;
    }

    // Rule 2: 2x2 blocks
    for (0..size - 1) |r| {
        for (0..size - 1) |c| {
            const v = qr.modules[r][c];
            if (v == qr.modules[r][c + 1] and v == qr.modules[r + 1][c] and v == qr.modules[r + 1][c + 1]) {
                penalty += 3;
            }
        }
    }

    // Rule 4: proportion of dark modules
    var dark: u32 = 0;
    const total: u32 = @as(u32, size) * @as(u32, size);
    for (0..size) |r| {
        for (0..size) |c| {
            if (qr.modules[r][c]) dark += 1;
        }
    }
    const pct = (dark * 100) / total;
    const prev5 = (pct / 5) * 5;
    const next5 = prev5 + 5;
    const d1 = if (prev5 >= 50) prev5 - 50 else 50 - prev5;
    const d2 = if (next5 >= 50) next5 - 50 else 50 - next5;
    penalty += @min(d1, d2) * 2;

    return penalty;
}

const FORMAT_BITS_TABLE = [8]u15{
    0x77C4, // mask 0, ECC L
    0x72F3, // mask 1
    0x7DAA, // mask 2
    0x789D, // mask 3
    0x662F, // mask 4
    0x6318, // mask 5
    0x6C41, // mask 6
    0x6976, // mask 7
};

fn placeFormatBits(qr: *QrCode, mask: u3, size: u8) void {
    const fmt_bits = FORMAT_BITS_TABLE[mask];

    // Around top-left finder
    const positions_h = [15]u8{ 0, 1, 2, 3, 4, 5, 7, 8, 8, 8, 8, 8, 8, 8, 8 };
    const positions_v = [15]u8{ 8, 8, 8, 8, 8, 8, 8, 8, 7, 5, 4, 3, 2, 1, 0 };

    for (0..15) |i| {
        const bit = ((fmt_bits >> @intCast(14 - i)) & 1) == 1;
        if (i < 8) {
            qr.modules[positions_v[i]][positions_h[i]] = bit;
        } else {
            qr.modules[positions_v[i]][positions_h[i]] = bit;
        }
    }

    // Along bottom-left and top-right
    for (0..7) |i| {
        const bit = ((fmt_bits >> @intCast(14 - i)) & 1) == 1;
        qr.modules[size - 1 - @as(u8, @intCast(i))][8] = bit;
    }
    for (0..8) |i| {
        const bit = ((fmt_bits >> @intCast(7 - i)) & 1) == 1;
        qr.modules[8][size - 8 + @as(u8, @intCast(i))] = bit;
    }

    // Dark module (always set)
    qr.modules[size - 8][8] = true;
}

// ── GF(2^8) arithmetic for Reed-Solomon ────────────────────────────

const GF_EXP = blk: {
    var table: [512]u8 = undefined;
    var x: u16 = 1;
    for (0..255) |i| {
        table[i] = @intCast(x);
        x <<= 1;
        if (x >= 256) x ^= 0x11D;
    }
    for (255..512) |i| {
        table[i] = table[i - 255];
    }
    break :blk table;
};

const GF_LOG = blk: {
    var table: [256]u8 = undefined;
    table[0] = 0;
    for (0..255) |i| {
        table[GF_EXP[i]] = @intCast(i);
    }
    break :blk table;
};

fn gfMul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    return GF_EXP[@as(u16, GF_LOG[a]) + @as(u16, GF_LOG[b])];
}

fn gfPolyDivide(data: []const u8, ec_len: u8) [26]u8 {
    const gen = generatorPoly(ec_len);
    var remainder: [256]u8 = std.mem.zeroes([256]u8);
    @memcpy(remainder[0..data.len], data);

    for (0..data.len) |i| {
        const coef = remainder[i];
        if (coef != 0) {
            for (0..ec_len) |j| {
                remainder[i + 1 + j] ^= gfMul(gen[j], coef);
            }
        }
    }

    var result: [26]u8 = undefined;
    @memcpy(result[0..ec_len], remainder[data.len .. data.len + ec_len]);
    return result;
}

fn generatorPoly(degree: u8) [26]u8 {
    var poly: [27]u8 = std.mem.zeroes([27]u8);
    poly[0] = 1;
    var poly_len: usize = 1;

    for (0..degree) |i| {
        // Multiply by (x - alpha^i)
        var j: usize = poly_len;
        while (j > 0) : (j -= 1) {
            poly[j] = poly[j - 1] ^ gfMul(poly[j], GF_EXP[i]);
        }
        poly[0] = gfMul(poly[0], GF_EXP[i]);
        poly_len += 1;
    }

    // Return coefficients excluding leading 1
    var result: [26]u8 = undefined;
    @memcpy(result[0..degree], poly[0..degree]);
    return result;
}

// ── Bit Writer ─────────────────────────────────────────────────────

const BitWriter = struct {
    buffer: [256]u8 = std.mem.zeroes([256]u8),
    bit_count: u16 = 0,

    fn writeBits(self: *BitWriter, value: u32, count: u4) void {
        var i: u4 = count;
        while (i > 0) {
            i -= 1;
            const byte_idx = self.bit_count / 8;
            const bit_pos: u3 = @intCast(7 - (self.bit_count % 8));
            if (((value >> i) & 1) == 1) {
                self.buffer[byte_idx] |= @as(u8, 1) << bit_pos;
            }
            self.bit_count += 1;
        }
    }
};

// ── Terminal Rendering ─────────────────────────────────────────────

/// Render QR code to terminal using Unicode half-block characters.
/// Each character cell represents two rows of modules.
/// Uses inverted colors (dark on light) for better scanability on dark terminals.
pub fn renderTerminal(qr: *const QrCode, writer: anytype) !void {
    const size: usize = qr.size;
    const quiet = 1;

    // Top quiet zone
    for (0..quiet) |_| {
        for (0..size + quiet * 2) |_| {
            try writer.writeAll("\u{2588}");
        }
        try writer.writeAll("\n");
    }

    var row: usize = 0;
    while (row < size) {
        // Left quiet zone
        for (0..quiet) |_| {
            try writer.writeAll("\u{2588}");
        }

        for (0..size) |col| {
            const top = qr.get(row, col);
            const bottom = if (row + 1 < size) qr.get(row + 1, col) else false;

            if (top and bottom) {
                try writer.writeAll(" ");
            } else if (top and !bottom) {
                try writer.writeAll("\u{2584}"); // ▄
            } else if (!top and bottom) {
                try writer.writeAll("\u{2580}"); // ▀
            } else {
                try writer.writeAll("\u{2588}"); // █
            }
        }

        // Right quiet zone
        for (0..quiet) |_| {
            try writer.writeAll("\u{2588}");
        }
        try writer.writeAll("\n");

        row += 2;
    }

    // Bottom quiet zone (if odd number of rows, we need the remainder)
    for (0..quiet) |_| {
        for (0..size + quiet * 2) |_| {
            try writer.writeAll("\u{2588}");
        }
        try writer.writeAll("\n");
    }
}

// ── Tests ──────────────────────────────────────────────────────────

test "encode short string selects version 1" {
    const qr = try encode("01234");
    try testing.expectEqual(@as(u8, 21), qr.size);
}

test "encode medium URL selects appropriate version" {
    const qr = try encode("https://example.com/test");
    try testing.expect(qr.size >= 21);
    try testing.expect(qr.size <= 41);
}

test "encode returns error for data too long" {
    const long = "A" ** 200;
    try testing.expectError(error.DataTooLong, encode(long));
}

test "encode produces valid finder patterns" {
    const qr = try encode("test");
    // Top-left finder: 7x7 pattern with specific dark/light pattern
    try testing.expect(qr.modules[0][0] == true);
    try testing.expect(qr.modules[0][6] == true);
    try testing.expect(qr.modules[6][0] == true);
    try testing.expect(qr.modules[6][6] == true);
    // Inner white ring
    try testing.expect(qr.modules[1][1] == false);
    try testing.expect(qr.modules[1][5] == false);
    // Inner black square
    try testing.expect(qr.modules[2][2] == true);
    try testing.expect(qr.modules[4][4] == true);
}

test "renderTerminal produces output" {
    const qr = try encode("hello");
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(testing.allocator, &buf);
    try renderTerminal(&qr, &buf_writer.writer);
    buf = buf_writer.toArrayList();
    try testing.expect(buf.items.len > 0);
    // Should contain newlines
    try testing.expect(std.mem.indexOf(u8, buf.items, "\n") != null);
}

test "GF multiply identity" {
    try testing.expectEqual(@as(u8, 0), gfMul(0, 100));
    try testing.expectEqual(@as(u8, 0), gfMul(100, 0));
    try testing.expectEqual(@as(u8, 1), gfMul(1, 1));
}

test "BitWriter writes correct bits" {
    var bw = BitWriter{};
    bw.writeBits(0b0100, 4);
    bw.writeBits(5, 8);
    try testing.expectEqual(@as(u16, 12), bw.bit_count);
    try testing.expectEqual(@as(u8, 0b0100_0000), bw.buffer[0]);
    try testing.expectEqual(@as(u8, 0b0101_0000), bw.buffer[1]);
}

test "version selection capacity" {
    // Version 1 byte mode: 19 - 3 = 16 bytes
    const v1 = try selectVersion(16);
    try testing.expectEqual(@as(u8, 1), v1.version);

    // Version 2 needed for 17+ bytes
    const v2 = try selectVersion(17);
    try testing.expectEqual(@as(u8, 2), v2.version);
}

test "encode and render weixin-length URL" {
    const url = "https://ilinkai.weixin.qq.com/some/path?token=abcdef1234567890";
    const qr = try encode(url);
    try testing.expect(qr.size >= 25);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(testing.allocator, &buf);
    try renderTerminal(&qr, &buf_writer.writer);
    buf = buf_writer.toArrayList();
    try testing.expect(buf.items.len > 100);
}

test "deterministic encoding" {
    const qr1 = try encode("deterministic");
    const qr2 = try encode("deterministic");
    for (0..qr1.size) |r| {
        for (0..qr1.size) |c| {
            try testing.expectEqual(qr1.modules[r][c], qr2.modules[r][c]);
        }
    }
}
