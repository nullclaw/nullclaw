const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// SPI hardware tool for Linux SPI device interaction.
/// Supports listing SPI devices, full-duplex transfer, and read-only mode.
/// On non-Linux platforms, returns a platform-unsupported error for device operations.
pub const SpiTool = struct {
    allocator: std.mem.Allocator = undefined,

    pub const tool_name = "spi";
    pub const tool_description = "Interact with SPI hardware devices. " ++
        "Supports listing available SPI devices, full-duplex data transfer, and read-only mode. " ++
        "Linux only — uses /dev/spidevX.Y via ioctl.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","description":"Action: list, transfer, or read"},"device":{"type":"string","description":"SPI device path (default /dev/spidev0.0)"},"data":{"type":"string","description":"Hex bytes to send, e.g. 'FF 0A 3B'"},"speed_hz":{"type":"integer","description":"SPI clock speed in Hz (default 1000000)"},"mode":{"type":"integer","description":"SPI mode 0-3 (default 0)"},"bits_per_word":{"type":"integer","description":"Bits per word (default 8)"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *SpiTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *SpiTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        _ = self;
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "list")) {
            return executeList(allocator);
        } else if (std.mem.eql(u8, action, "transfer")) {
            return executeTransfer(allocator, args, false);
        } else if (std.mem.eql(u8, action, "read")) {
            return executeTransfer(allocator, args, true);
        } else {
            return ToolResult.fail("Unknown action. Use 'list', 'transfer', or 'read'");
        }
    }

    fn executeList(allocator: std.mem.Allocator) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            const output = try allocator.dupe(u8, "{\"devices\":[],\"note\":\"SPI device listing only supported on Linux\"}");
            return ToolResult{ .success = true, .output = output };
        }

        // On Linux: glob /dev/spidev*.*
        var devices: std.ArrayList(u8) = .empty;
        errdefer devices.deinit(allocator);

        try devices.appendSlice(allocator, "{\"devices\":[");

        var count: usize = 0;
        var dir = std_compat.fs.openDirAbsolute("/dev", .{ .iterate = true }) catch {
            try devices.appendSlice(allocator, "]}");
            return ToolResult{ .success = true, .output = try devices.toOwnedSlice(allocator) };
        };
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, "spidev")) {
                if (count > 0) try devices.appendSlice(allocator, ",");
                try devices.appendSlice(allocator, "\"/dev/");
                try devices.appendSlice(allocator, entry.name);
                try devices.appendSlice(allocator, "\"");
                count += 1;
            }
        }

        try devices.appendSlice(allocator, "]}");
        return ToolResult{ .success = true, .output = try devices.toOwnedSlice(allocator) };
    }

    fn executeTransfer(allocator: std.mem.Allocator, args: JsonObjectMap, read_only: bool) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            const output = try allocator.dupe(u8, "{\"error\":\"SPI not supported on this platform\"}");
            return ToolResult{ .success = false, .output = output, .error_msg = try allocator.dupe(u8, "SPI not supported on this platform") };
        }

        const device = root.getString(args, "device") orelse "/dev/spidev0.0";
        const speed_hz: u32 = if (root.getInt(args, "speed_hz")) |v| @intCast(@as(u32, @truncate(@as(u64, @bitCast(v))))) else 1_000_000;
        const mode: u8 = if (root.getInt(args, "mode")) |v| @intCast(@as(u8, @truncate(@as(u64, @bitCast(v))))) else 0;
        const bits_per_word: u8 = if (root.getInt(args, "bits_per_word")) |v| @intCast(@as(u8, @truncate(@as(u64, @bitCast(v))))) else 8;

        if (mode > 3) {
            return ToolResult.fail("SPI mode must be 0-3");
        }

        // Parse hex data
        var tx_buf: [256]u8 = undefined;
        var tx_len: usize = 0;

        if (!read_only) {
            const data_str = root.getString(args, "data") orelse
                return ToolResult.fail("Missing 'data' parameter for transfer action");
            tx_len = parseHexBytes(data_str, &tx_buf) catch
                return ToolResult.fail("Invalid hex data format. Use space-separated hex bytes like 'FF 0A 3B'");
            if (tx_len == 0) {
                return ToolResult.fail("No data bytes provided");
            }
        } else {
            // For read-only, use data length or default 1 byte
            if (root.getInt(args, "length")) |len| {
                tx_len = @intCast(@as(usize, @truncate(@as(u64, @bitCast(len)))));
                if (tx_len > tx_buf.len) tx_len = tx_buf.len;
            } else if (root.getString(args, "data")) |data_str| {
                tx_len = parseHexBytes(data_str, &tx_buf) catch 1;
                // Zero out for read-only
                @memset(tx_buf[0..tx_len], 0);
            } else {
                tx_len = 1;
            }
            @memset(tx_buf[0..tx_len], 0);
        }

        // Linux SPI ioctl
        return spiTransferLinux(allocator, device, tx_buf[0..tx_len], speed_hz, mode, bits_per_word);
    }

    fn openSpiDevice(device: []const u8) !std_compat.fs.File {
        return try std_compat.fs.openFileAbsolute(device, .{ .mode = .read_write });
    }

    /// Linux-only SPI transfer via ioctl.
    fn spiTransferLinux(
        allocator: std.mem.Allocator,
        device: []const u8,
        tx_data: []const u8,
        speed_hz: u32,
        mode: u8,
        bits_per_word: u8,
    ) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            return ToolResult.fail("SPI is only supported on Linux");
        }

        // ioctl constants for SPI
        const SPI_IOC_WR_MODE: u32 = 0x40016B01;
        const SPI_IOC_WR_MAX_SPEED_HZ: u32 = 0x40046B04;
        const SPI_IOC_WR_BITS_PER_WORD: u32 = 0x40016B03;
        // SPI_IOC_MESSAGE(1) = _IOW('k', 0, struct spi_ioc_transfer) for 1 transfer
        const SPI_IOC_MESSAGE_1: u32 = 0x40206B00;

        // Open SPI device
        const file = openSpiDevice(device) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open SPI device '{s}': {}", .{ device, err });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();
        const fd = file.handle;

        // Set SPI mode
        var mode_val: u8 = mode;
        if (std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, SPI_IOC_WR_MODE), @intFromPtr(&mode_val)) != 0) {
            return ToolResult.fail("Failed to set SPI mode");
        }

        // Set bits per word
        var bpw: u8 = bits_per_word;
        if (std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, SPI_IOC_WR_BITS_PER_WORD), @intFromPtr(&bpw)) != 0) {
            return ToolResult.fail("Failed to set bits per word");
        }

        // Set speed
        var spd: u32 = speed_hz;
        if (std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, SPI_IOC_WR_MAX_SPEED_HZ), @intFromPtr(&spd)) != 0) {
            return ToolResult.fail("Failed to set SPI speed");
        }

        // Prepare rx buffer
        var rx_buf: [256]u8 = undefined;
        const len = tx_data.len;

        // struct spi_ioc_transfer (packed, 32 bytes on 64-bit)
        const SpiIocTransfer = extern struct {
            tx_buf: u64,
            rx_buf: u64,
            len: u32,
            speed_hz: u32,
            delay_usecs: u16,
            bits_per_word: u8,
            cs_change: u8,
            tx_nbits: u8,
            rx_nbits: u8,
            word_delay_usecs: u8,
            pad: u8,
        };

        var transfer = SpiIocTransfer{
            .tx_buf = @intFromPtr(tx_data.ptr),
            .rx_buf = @intFromPtr(&rx_buf),
            .len = @intCast(len),
            .speed_hz = speed_hz,
            .delay_usecs = 0,
            .bits_per_word = bits_per_word,
            .cs_change = 0,
            .tx_nbits = 0,
            .rx_nbits = 0,
            .word_delay_usecs = 0,
            .pad = 0,
        };

        if (std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, SPI_IOC_MESSAGE_1), @intFromPtr(&transfer)) != 0) {
            return ToolResult.fail("SPI transfer failed");
        }

        // Format response as hex
        return formatSpiResponse(allocator, rx_buf[0..len]);
    }

    fn formatSpiResponse(allocator: std.mem.Allocator, rx_data: []const u8) !ToolResult {
        var output: std.ArrayListUnmanaged(u8) = .empty;
        errdefer output.deinit(allocator);

        try output.appendSlice(allocator, "{\"rx_data\":\"");
        for (rx_data, 0..) |byte, i| {
            if (i > 0) try output.append(allocator, ' ');
            var buf: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&buf, "{X:0>2}", .{byte}) catch unreachable;
            try output.appendSlice(allocator, &buf);
        }
        try output.appendSlice(allocator, "\",\"length\":");
        var len_buf: [16]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{rx_data.len}) catch unreachable;
        try output.appendSlice(allocator, len_str);
        try output.appendSlice(allocator, "}");

        return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }
};

/// Parse space-separated hex bytes ("FF 0A 3B") into a byte buffer.
/// Returns the number of bytes parsed.
pub fn parseHexBytes(hex_str: []const u8, out: []u8) !usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < hex_str.len) {
        // Skip whitespace
        while (i < hex_str.len and (hex_str[i] == ' ' or hex_str[i] == '\t')) : (i += 1) {}
        if (i >= hex_str.len) break;

        // Read 1-2 hex chars
        const start = i;
        while (i < hex_str.len and hex_str[i] != ' ' and hex_str[i] != '\t') : (i += 1) {}
        const token = hex_str[start..i];

        if (token.len == 0) continue;
        if (token.len > 2) return error.InvalidHexByte;
        if (count >= out.len) return error.BufferOverflow;

        out[count] = std.fmt.parseInt(u8, token, 16) catch return error.InvalidHexByte;
        count += 1;
    }
    return count;
}

// ── Tests ───────────────────────────────────────────────────────────

test "spi tool name" {
    var st = SpiTool{};
    const t = st.tool();
    try std.testing.expectEqualStrings("spi", t.name());
}

test "spi tool description not empty" {
    var st = SpiTool{};
    const t = st.tool();
    try std.testing.expect(t.description().len > 0);
}

test "spi tool schema has action" {
    var st = SpiTool{};
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "device") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "speed_hz") != null);
}

test "spi list action on non-linux" {
    var st = SpiTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"list\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expect(result.success);
        try std.testing.expect(std.mem.indexOf(u8, result.output, "devices") != null);
    }
}

test "spi transfer on non-linux returns error" {
    if (comptime builtin.os.tag == .linux) return;
    var st = SpiTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"transfer\", \"data\": \"FF 0A\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not supported") != null);
}

test "spi read on non-linux returns error" {
    if (comptime builtin.os.tag == .linux) return;
    var st = SpiTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not supported") != null);
}

test "spi open helper opens absolute file on linux" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const file = try SpiTool.openSpiDevice("/dev/null");
    file.close();
}

test "spi missing action" {
    var st = SpiTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "spi unknown action" {
    var st = SpiTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"unknown\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "parseHexBytes basic" {
    var buf: [8]u8 = undefined;
    const len = try parseHexBytes("FF 0A", &buf);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqual(@as(u8, 0xFF), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x0A), buf[1]);
}

test "parseHexBytes single byte" {
    var buf: [8]u8 = undefined;
    const len = try parseHexBytes("AB", &buf);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0xAB), buf[0]);
}

test "parseHexBytes multiple spaces" {
    var buf: [8]u8 = undefined;
    const len = try parseHexBytes("  01   02   03  ", &buf);
    try std.testing.expectEqual(@as(usize, 3), len);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x02), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[2]);
}

test "parseHexBytes lowercase" {
    var buf: [8]u8 = undefined;
    const len = try parseHexBytes("ff 0a 3b", &buf);
    try std.testing.expectEqual(@as(usize, 3), len);
    try std.testing.expectEqual(@as(u8, 0xFF), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x0A), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x3B), buf[2]);
}

test "parseHexBytes invalid hex" {
    var buf: [8]u8 = undefined;
    const result = parseHexBytes("GG", &buf);
    try std.testing.expect(result == error.InvalidHexByte);
}

test "parseHexBytes empty" {
    var buf: [8]u8 = undefined;
    const len = try parseHexBytes("", &buf);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "parseHexBytes three digit token fails" {
    var buf: [8]u8 = undefined;
    const result = parseHexBytes("FFF", &buf);
    try std.testing.expect(result == error.InvalidHexByte);
}

test "formatSpiResponse builds json" {
    const data = [_]u8{ 0xFF, 0x0A, 0x00 };
    const result = try SpiTool.formatSpiResponse(std.testing.allocator, &data);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "FF 0A 00") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"length\":3") != null);
}
