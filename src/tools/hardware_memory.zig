const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const parseIntField = @import("shell.zig").parseIntField;

/// RAM base for STM32F401 Nucleo boards.
const NUCLEO_RAM_BASE: u64 = 0x2000_0000;

/// Maximum output size from probe-rs commands (64 KB).
const MAX_PROBE_OUTPUT: usize = 65_536;

/// Hardware memory read/write tool — read/write memory at addresses via probe-rs or serial.
/// Supports Nucleo boards connected via USB.
pub const HardwareMemoryTool = struct {
    boards: []const []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *HardwareMemoryTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *HardwareMemoryTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "hardware_memory";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Read/write hardware memory maps via probe-rs or serial. " ++
            "Use for: 'read memory', 'read register', 'dump memory', 'write memory'. " ++
            "Params: action (read/write), address (hex), length (bytes), value (for write).";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"action":{"type":"string","enum":["read","write"],"description":"read or write memory"},"address":{"type":"string","description":"Memory address in hex (e.g. 0x20000000)"},"length":{"type":"integer","description":"Bytes to read (default 128, max 256)"},"value":{"type":"string","description":"Hex value to write (for write action)"},"board":{"type":"string","description":"Board name (optional if only one configured)"}},"required":["action"]}
        ;
    }

    fn execute(self: *HardwareMemoryTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        if (self.boards.len == 0) {
            return ToolResult.fail("No peripherals configured. Add boards to config.toml [peripherals.boards].");
        }

        const action = parseStringField(args_json, "action") orelse
            return ToolResult.fail("Missing 'action' parameter (read or write)");

        const board = parseStringField(args_json, "board") orelse
            (if (self.boards.len > 0) self.boards[0] else "unknown");

        // Validate board is a supported type
        const chip = chipForBoard(board) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory operations only support nucleo-f401re, nucleo-f411re. Got: {s}", .{board});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const address_str = parseStringField(args_json, "address") orelse "0x20000000";
        const address = parseHexAddress(address_str) orelse NUCLEO_RAM_BASE;

        if (std.mem.eql(u8, action, "read")) {
            const length_raw = parseIntField(args_json, "length") orelse 128;
            const length: usize = @intCast(@min(@max(length_raw, 1), 256));
            return probeRead(allocator, chip, address, length);
        } else if (std.mem.eql(u8, action, "write")) {
            const value = parseStringField(args_json, "value") orelse
                return ToolResult.fail("Missing 'value' parameter for write action");
            return probeWrite(allocator, chip, address, value);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'. Use 'read' or 'write'.", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }
};

/// Check if probe-rs is available on the system.
fn probeRsAvailable(allocator: std.mem.Allocator) bool {
    var child = std.process.Child.init(
        &.{ "probe-rs", "--version" },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch return false;

    // Drain pipes so the child doesn't block
    _ = child.stdout.?.readToEndAlloc(allocator, 4096) catch "";
    _ = child.stderr.?.readToEndAlloc(allocator, 4096) catch "";
    const term = child.wait() catch return false;
    return term.Exited == 0;
}

/// Execute a probe-rs read command: `probe-rs read --chip CHIP ADDRESS LENGTH`
fn probeRead(allocator: std.mem.Allocator, chip: []const u8, address: u64, length: usize) !ToolResult {
    if (!probeRsAvailable(allocator)) {
        return ToolResult.fail("probe-rs not found. Install with: cargo install probe-rs-tools");
    }

    const addr_str = try std.fmt.allocPrint(allocator, "0x{X:0>8}", .{address});
    defer allocator.free(addr_str);
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{length});
    defer allocator.free(len_str);

    var child = std.process.Child.init(
        &.{ "probe-rs", "read", "--chip", chip, addr_str, len_str },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch {
        return ToolResult.fail("Failed to spawn probe-rs read command");
    };

    const stdout = try child.stdout.?.readToEndAlloc(allocator, MAX_PROBE_OUTPUT);
    defer allocator.free(stdout);
    const stderr = try child.stderr.?.readToEndAlloc(allocator, MAX_PROBE_OUTPUT);
    defer allocator.free(stderr);

    const term = try child.wait();
    const success = term.Exited == 0;

    if (success) {
        const out = try allocator.dupe(u8, if (stdout.len > 0) stdout else "(no output from probe-rs)");
        return ToolResult{ .success = true, .output = out };
    } else {
        const err_msg = try std.fmt.allocPrint(
            allocator,
            "probe-rs read failed (exit {d}): {s}",
            .{ term.Exited, if (stderr.len > 0) stderr else "unknown error" },
        );
        return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
    }
}

/// Execute a probe-rs write command: `probe-rs write --chip CHIP ADDRESS VALUE`
fn probeWrite(allocator: std.mem.Allocator, chip: []const u8, address: u64, value: []const u8) !ToolResult {
    if (!probeRsAvailable(allocator)) {
        return ToolResult.fail("probe-rs not found. Install with: cargo install probe-rs-tools");
    }

    const addr_str = try std.fmt.allocPrint(allocator, "0x{X:0>8}", .{address});
    defer allocator.free(addr_str);

    var child = std.process.Child.init(
        &.{ "probe-rs", "write", "--chip", chip, addr_str, value },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch {
        return ToolResult.fail("Failed to spawn probe-rs write command");
    };

    const stdout = try child.stdout.?.readToEndAlloc(allocator, MAX_PROBE_OUTPUT);
    defer allocator.free(stdout);
    const stderr = try child.stderr.?.readToEndAlloc(allocator, MAX_PROBE_OUTPUT);
    defer allocator.free(stderr);

    const term = try child.wait();
    const success = term.Exited == 0;

    if (success) {
        const out = try std.fmt.allocPrint(
            allocator,
            "Write OK: 0x{X:0>8} <- {s} ({s}){s}",
            .{ address, value, chip, if (stdout.len > 0) stdout else "" },
        );
        return ToolResult{ .success = true, .output = out };
    } else {
        const err_msg = try std.fmt.allocPrint(
            allocator,
            "probe-rs write failed (exit {d}): {s}",
            .{ term.Exited, if (stderr.len > 0) stderr else "unknown error" },
        );
        return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
    }
}

fn chipForBoard(board: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, board, "nucleo-f401re")) return "STM32F401RETx";
    if (std.mem.eql(u8, board, "nucleo-f411re")) return "STM32F411RETx";
    return null;
}

fn parseHexAddress(s: []const u8) ?u64 {
    var trimmed = s;
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        trimmed = trimmed[2..];
    }
    return std.fmt.parseInt(u64, trimmed, 16) catch null;
}

// ── Tests ───────────────────────────────────────────────────────────

test "hardware_memory tool name" {
    var hm = HardwareMemoryTool{ .boards = &.{} };
    const t = hm.tool();
    try std.testing.expectEqualStrings("hardware_memory", t.name());
}

test "hardware_memory tool description not empty" {
    var hm = HardwareMemoryTool{ .boards = &.{} };
    const t = hm.tool();
    try std.testing.expect(t.description().len > 0);
    try std.testing.expect(std.mem.indexOf(u8, t.description(), "memory") != null);
}

test "hardware_memory schema has action" {
    var hm = HardwareMemoryTool{ .boards = &.{} };
    const t = hm.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "address") != null);
}

test "hardware_memory no boards returns error" {
    var hm = HardwareMemoryTool{ .boards = &.{} };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"read\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "peripherals") != null);
}

test "hardware_memory missing action returns error" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "hardware_memory unsupported board" {
    const boards = [_][]const u8{"esp32"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"read\", \"board\": \"esp32\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "nucleo") != null);
}

test "hardware_memory read without probe-rs" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"read\", \"address\": \"0x20000000\", \"length\": 64}");
    // Only free heap-allocated output/error_msg (probe-rs failure returns a
    // heap-allocated error when the command runs but fails, or allocPrint output
    // on success; ToolResult.fail() returns a string literal that must NOT be freed).
    const has_probe = probeRsAvailable(std.testing.allocator);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (has_probe) {
        if (result.error_msg) |e| std.testing.allocator.free(e);
    };
    if (has_probe) {
        // probe-rs is installed — we expect a real result (success or device error)
        // Either way, no crash is the key assertion.
    } else {
        // probe-rs not found — expect helpful error message
        try std.testing.expect(!result.success);
        try std.testing.expect(result.error_msg != null);
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "probe-rs not found") != null);
    }
}

test "hardware_memory write without probe-rs" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"write\", \"address\": \"0x20000000\", \"value\": \"DEADBEEF\"}");
    const has_probe = probeRsAvailable(std.testing.allocator);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (has_probe) {
        if (result.error_msg) |e| std.testing.allocator.free(e);
    };
    if (has_probe) {
        // probe-rs is installed — we expect a real result (success or device error)
    } else {
        // probe-rs not found — expect helpful error message
        try std.testing.expect(!result.success);
        try std.testing.expect(result.error_msg != null);
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "probe-rs not found") != null);
    }
}

test "hardware_memory write missing value" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"write\", \"address\": \"0x20000000\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "value") != null);
}

test "hardware_memory unknown action" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hm = HardwareMemoryTool{ .boards = &boards };
    const t = hm.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"delete\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
}

test "parseHexAddress valid" {
    try std.testing.expectEqual(@as(?u64, 0x20000000), parseHexAddress("0x20000000"));
    try std.testing.expectEqual(@as(?u64, 0x20000000), parseHexAddress("0X20000000"));
    try std.testing.expectEqual(@as(?u64, 0xFF), parseHexAddress("FF"));
    try std.testing.expectEqual(@as(?u64, 0), parseHexAddress("0x0"));
}

test "parseHexAddress invalid" {
    try std.testing.expect(parseHexAddress("not_hex") == null);
    try std.testing.expect(parseHexAddress("") == null);
}

test "chipForBoard known" {
    try std.testing.expectEqualStrings("STM32F401RETx", chipForBoard("nucleo-f401re").?);
    try std.testing.expectEqualStrings("STM32F411RETx", chipForBoard("nucleo-f411re").?);
}

test "chipForBoard unknown" {
    try std.testing.expect(chipForBoard("esp32") == null);
    try std.testing.expect(chipForBoard("unknown") == null);
}

test "hardware_memory tool spec" {
    var hm = HardwareMemoryTool{ .boards = &.{} };
    const t = hm.tool();
    const s = t.spec();
    try std.testing.expectEqualStrings("hardware_memory", s.name);
    try std.testing.expect(s.parameters_json[0] == '{');
}
