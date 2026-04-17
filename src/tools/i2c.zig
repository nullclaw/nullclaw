const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Linux I2C ioctl constants.
const I2C_SLAVE = 0x0703;
const I2C_FUNCS = 0x0705;

/// Valid I2C address range (7-bit addressing, excluding reserved).
const I2C_ADDR_MIN: u7 = 0x03;
const I2C_ADDR_MAX: u7 = 0x77;

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) error{WriteFailed}!usize {
    if (bytes.len == 0) return 0;
    while (true) {
        const rc = std.posix.system.write(fd, bytes.ptr, bytes.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn openLinuxBusFile(path: []const u8) !std_compat.fs.File {
    return try std_compat.fs.openFileAbsolute(path, .{ .mode = .read_write });
}

/// I2C hardware tool — detect buses, scan devices, read/write registers.
/// On non-Linux platforms, all actions return a platform-not-supported error.
pub const I2cTool = struct {
    pub const tool_name = "i2c";
    pub const tool_description = "I2C hardware tool. Actions: detect (list buses), scan (find devices on bus), " ++
        "read (read register bytes), write (write register byte). Linux only.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","description":"Action: detect, scan, read, write"},"bus":{"type":"integer","description":"I2C bus number (e.g. 1 for /dev/i2c-1)"},"address":{"type":"string","description":"Device address in hex (0x03-0x77)"},"register":{"type":"integer","description":"Register number to read/write"},"value":{"type":"integer","description":"Byte value to write (0-255)"},"length":{"type":"integer","description":"Number of bytes to read (default 1)"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *I2cTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *I2cTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "detect")) {
            return actionDetect(allocator);
        } else if (std.mem.eql(u8, action, "scan")) {
            return actionScan(allocator, args);
        } else if (std.mem.eql(u8, action, "read")) {
            return actionRead(allocator, args);
        } else if (std.mem.eql(u8, action, "write")) {
            return actionWrite(allocator, args);
        } else {
            return ToolResult.fail("Unknown action. Use: detect, scan, read, write");
        }
    }

    // ── Actions ─────────────────────────────────────────────────────

    fn actionDetect(allocator: std.mem.Allocator) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            return platformError(allocator);
        }
        return detectLinux(allocator);
    }

    fn actionScan(allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            return platformError(allocator);
        }
        const bus = root.getInt(args, "bus") orelse
            return ToolResult.fail("Missing 'bus' parameter for scan");
        if (bus < 0) return ToolResult.fail("Bus number must be non-negative");
        return scanLinux(allocator, @intCast(bus));
    }

    fn actionRead(allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            return platformError(allocator);
        }
        const bus = root.getInt(args, "bus") orelse
            return ToolResult.fail("Missing 'bus' parameter for read");
        if (bus < 0) return ToolResult.fail("Bus number must be non-negative");
        const addr = parseAddress(args) orelse
            return ToolResult.fail("Missing or invalid 'address' (hex 0x03-0x77)");
        const register = root.getInt(args, "register") orelse
            return ToolResult.fail("Missing 'register' parameter for read");
        if (register < 0 or register > 255) return ToolResult.fail("Register must be 0-255");
        const length = root.getInt(args, "length") orelse 1;
        if (length < 1 or length > 32) return ToolResult.fail("Length must be 1-32");
        return readLinux(allocator, @intCast(bus), addr, @intCast(register), @intCast(length));
    }

    fn actionWrite(allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        if (comptime builtin.os.tag != .linux) {
            return platformError(allocator);
        }
        const bus = root.getInt(args, "bus") orelse
            return ToolResult.fail("Missing 'bus' parameter for write");
        if (bus < 0) return ToolResult.fail("Bus number must be non-negative");
        const addr = parseAddress(args) orelse
            return ToolResult.fail("Missing or invalid 'address' (hex 0x03-0x77)");
        const register = root.getInt(args, "register") orelse
            return ToolResult.fail("Missing 'register' parameter for write");
        if (register < 0 or register > 255) return ToolResult.fail("Register must be 0-255");
        const value = root.getInt(args, "value") orelse
            return ToolResult.fail("Missing 'value' parameter for write");
        if (value < 0 or value > 255) return ToolResult.fail("Value must be 0-255");
        return writeLinux(allocator, @intCast(bus), addr, @intCast(register), @intCast(value));
    }

    // ── Linux implementations ───────────────────────────────────────

    fn detectLinux(allocator: std.mem.Allocator) !ToolResult {
        if (comptime builtin.os.tag != .linux) return ToolResult.fail("I2C is only supported on Linux");
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        try output.appendSlice(allocator, "{\"buses\":[");

        var found: usize = 0;
        for (0..16) |i| {
            var path_buf: [32]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "/dev/i2c-{d}", .{i}) catch continue;
            // Check if device node exists
            if (std_compat.fs.accessAbsolute(path, .{})) {
                if (found > 0) try output.appendSlice(allocator, ",");
                try output.appendSlice(allocator, "\"");
                try output.appendSlice(allocator, path);
                try output.appendSlice(allocator, "\"");
                found += 1;
            } else |_| {}
        }

        try output.appendSlice(allocator, "],\"count\":");
        var count_buf: [8]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{found}) catch "0";
        try output.appendSlice(allocator, count_str);
        try output.appendSlice(allocator, "}");

        return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }

    fn scanLinux(allocator: std.mem.Allocator, bus: u32) !ToolResult {
        if (comptime builtin.os.tag != .linux) return ToolResult.fail("I2C is only supported on Linux");
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/dev/i2c-{d}", .{bus}) catch
            return ToolResult.fail("Invalid bus number");

        const file = openLinuxBusFile(path) catch
            return ToolResult.fail("Cannot open I2C bus (permission denied or bus not found)");
        defer file.close();
        const fd = file.handle;

        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        try output.appendSlice(allocator, "{\"bus\":");
        var bus_str_buf: [8]u8 = undefined;
        const bus_str = std.fmt.bufPrint(&bus_str_buf, "{d}", .{bus}) catch "0";
        try output.appendSlice(allocator, bus_str);
        try output.appendSlice(allocator, ",\"devices\":[");

        var found: usize = 0;
        var addr: u7 = I2C_ADDR_MIN;
        while (addr <= I2C_ADDR_MAX) : (addr += 1) {
            // Set slave address via ioctl
            const rc = std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, I2C_SLAVE), @as(usize, addr));
            const signed_rc: isize = @bitCast(rc);
            if (signed_rc < 0) continue;

            // Quick write probe (send 0 bytes)
            const wrc = writeFd(fd, &.{}) catch continue;
            _ = wrc;

            if (found > 0) try output.appendSlice(allocator, ",");
            var addr_buf: [8]u8 = undefined;
            const addr_str = std.fmt.bufPrint(&addr_buf, "\"0x{x:0>2}\"", .{addr}) catch continue;
            try output.appendSlice(allocator, addr_str);
            found += 1;
        }

        try output.appendSlice(allocator, "],\"count\":");
        var count_buf: [8]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{found}) catch "0";
        try output.appendSlice(allocator, count_str);
        try output.appendSlice(allocator, "}");

        return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }

    fn readLinux(allocator: std.mem.Allocator, bus: u32, addr: u7, register: u8, length: u8) !ToolResult {
        if (comptime builtin.os.tag != .linux) return ToolResult.fail("I2C is only supported on Linux");
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/dev/i2c-{d}", .{bus}) catch
            return ToolResult.fail("Invalid bus number");

        const file = openLinuxBusFile(path) catch
            return ToolResult.fail("Cannot open I2C bus");
        defer file.close();
        const fd = file.handle;

        // Set slave address
        const rc = std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, I2C_SLAVE), @as(usize, addr));
        const signed_rc: isize = @bitCast(rc);
        if (signed_rc < 0)
            return ToolResult.fail("Failed to set I2C slave address");

        // Write register address
        _ = writeFd(fd, &.{register}) catch
            return ToolResult.fail("Failed to write register address");

        // Read data
        var read_buf: [32]u8 = undefined;
        const n = std.posix.read(fd, read_buf[0..length]) catch
            return ToolResult.fail("Failed to read from I2C device");

        // Format output
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        try output.appendSlice(allocator, "{\"bus\":");
        var bus_buf: [8]u8 = undefined;
        try output.appendSlice(allocator, std.fmt.bufPrint(&bus_buf, "{d}", .{bus}) catch "0");
        try output.appendSlice(allocator, ",\"address\":\"0x");
        var addr_hex: [4]u8 = undefined;
        try output.appendSlice(allocator, std.fmt.bufPrint(&addr_hex, "{x:0>2}", .{addr}) catch "??");
        try output.appendSlice(allocator, "\",\"register\":");
        var reg_buf: [8]u8 = undefined;
        try output.appendSlice(allocator, std.fmt.bufPrint(&reg_buf, "{d}", .{register}) catch "0");
        try output.appendSlice(allocator, ",\"data\":[");

        for (read_buf[0..n], 0..) |byte, i| {
            if (i > 0) try output.appendSlice(allocator, ",");
            var byte_buf: [4]u8 = undefined;
            try output.appendSlice(allocator, std.fmt.bufPrint(&byte_buf, "{d}", .{byte}) catch "0");
        }

        try output.appendSlice(allocator, "],\"hex\":\"");
        for (read_buf[0..n]) |byte| {
            var hex_buf: [4]u8 = undefined;
            try output.appendSlice(allocator, std.fmt.bufPrint(&hex_buf, "{x:0>2}", .{byte}) catch "??");
        }
        try output.appendSlice(allocator, "\"}");

        return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }

    fn writeLinux(allocator: std.mem.Allocator, bus: u32, addr: u7, register: u8, value: u8) !ToolResult {
        if (comptime builtin.os.tag != .linux) return ToolResult.fail("I2C is only supported on Linux");
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/dev/i2c-{d}", .{bus}) catch
            return ToolResult.fail("Invalid bus number");

        const file = openLinuxBusFile(path) catch
            return ToolResult.fail("Cannot open I2C bus");
        defer file.close();
        const fd = file.handle;

        // Set slave address
        const rc = std.os.linux.syscall3(.ioctl, @as(usize, @intCast(fd)), @as(usize, I2C_SLAVE), @as(usize, addr));
        const signed_rc: isize = @bitCast(rc);
        if (signed_rc < 0)
            return ToolResult.fail("Failed to set I2C slave address");

        // Write register + value
        _ = writeFd(fd, &.{ register, value }) catch
            return ToolResult.fail("Failed to write to I2C device");

        const output = try std.fmt.allocPrint(allocator,
            \\{{"bus":{d},"address":"0x{x:0>2}","register":{d},"value":{d},"status":"ok"}}
        , .{ bus, addr, register, value });

        return ToolResult{ .success = true, .output = output };
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn platformError(allocator: std.mem.Allocator) !ToolResult {
        const msg = try allocator.dupe(u8, "{\"error\":\"I2C not supported on this platform\"}");
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }
};

/// Parse hex address string (e.g. "0x48") and validate range 0x03-0x77.
pub fn parseAddress(args: JsonObjectMap) ?u7 {
    const addr_str = root.getString(args, "address") orelse return null;
    const hex = if (std.mem.startsWith(u8, addr_str, "0x") or std.mem.startsWith(u8, addr_str, "0X"))
        addr_str[2..]
    else
        addr_str;
    if (hex.len == 0) return null;
    const val = std.fmt.parseInt(u7, hex, 16) catch return null;
    if (val < I2C_ADDR_MIN or val > I2C_ADDR_MAX) return null;
    return val;
}

// ── Tests ───────────────────────────────────────────────────────────

test "i2c tool name" {
    var it: I2cTool = .{};
    const t = it.tool();
    try std.testing.expectEqualStrings("i2c", t.name());
}

test "i2c tool description not empty" {
    var it: I2cTool = .{};
    const t = it.tool();
    try std.testing.expect(t.description().len > 0);
}

test "i2c tool schema has action" {
    var it: I2cTool = .{};
    const t = it.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "bus") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "address") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "register") != null);
}

test "i2c detect on non-linux returns platform error" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"detect\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not supported") != null);
}

test "i2c open bus helper opens absolute file on linux" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const file = try openLinuxBusFile("/dev/null");
    file.close();
}

test "i2c scan on non-linux returns platform error" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"scan\",\"bus\":1}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not supported") != null);
}

test "i2c read on non-linux returns platform error" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"read\",\"bus\":1,\"address\":\"0x48\",\"register\":0}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not supported") != null);
}

test "i2c write on non-linux returns platform error" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"write\",\"bus\":1,\"address\":\"0x48\",\"register\":0,\"value\":42}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not supported") != null);
}

test "i2c missing action parameter" {
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "i2c unknown action" {
    var it: I2cTool = .{};
    const t = it.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"reset\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "parseAddress valid hex" {
    const p1 = try root.parseTestArgs("{\"address\":\"0x48\"}");
    defer p1.deinit();
    try std.testing.expectEqual(@as(?u7, 0x48), parseAddress(p1.value.object));
    const p2 = try root.parseTestArgs("{\"address\":\"0x03\"}");
    defer p2.deinit();
    try std.testing.expectEqual(@as(?u7, 0x03), parseAddress(p2.value.object));
    const p3 = try root.parseTestArgs("{\"address\":\"0x77\"}");
    defer p3.deinit();
    try std.testing.expectEqual(@as(?u7, 0x77), parseAddress(p3.value.object));
    const p4 = try root.parseTestArgs("{\"address\":\"0X50\"}");
    defer p4.deinit();
    try std.testing.expectEqual(@as(?u7, 0x50), parseAddress(p4.value.object));
    const p5 = try root.parseTestArgs("{\"address\":\"20\"}");
    defer p5.deinit();
    try std.testing.expectEqual(@as(?u7, 0x20), parseAddress(p5.value.object)); // no prefix
}

test "parseAddress rejects out of range" {
    const p1 = try root.parseTestArgs("{\"address\":\"0x00\"}");
    defer p1.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p1.value.object));
    const p2 = try root.parseTestArgs("{\"address\":\"0x01\"}");
    defer p2.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p2.value.object));
    const p3 = try root.parseTestArgs("{\"address\":\"0x02\"}");
    defer p3.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p3.value.object));
    const p4 = try root.parseTestArgs("{\"address\":\"0x78\"}");
    defer p4.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p4.value.object));
    const p5 = try root.parseTestArgs("{\"address\":\"0xFF\"}");
    defer p5.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p5.value.object));
}

test "parseAddress rejects invalid" {
    const p1 = try root.parseTestArgs("{\"address\":\"\"}");
    defer p1.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p1.value.object));
    const p2 = try root.parseTestArgs("{\"address\":\"zz\"}");
    defer p2.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p2.value.object));
    const p3 = try root.parseTestArgs("{}");
    defer p3.deinit();
    try std.testing.expectEqual(@as(?u7, null), parseAddress(p3.value.object));
}

test "i2c scan missing bus parameter" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    var it: I2cTool = .{};
    const t = it.tool();
    // On non-Linux, the platform error fires before bus check (comptime).
    // Test that it doesn't crash.
    const parsed = try root.parseTestArgs("{\"action\":\"scan\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
}
