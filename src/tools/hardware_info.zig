const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Static board info entries: (board_id, chip, description).
const BoardInfo = struct {
    id: []const u8,
    chip: []const u8,
    desc: []const u8,
};

const BOARD_DB = [_]BoardInfo{
    .{
        .id = "nucleo-f401re",
        .chip = "STM32F401RET6",
        .desc = "ARM Cortex-M4, 84 MHz. Flash: 512 KB, RAM: 128 KB. User LED on PA5 (pin 13).",
    },
    .{
        .id = "nucleo-f411re",
        .chip = "STM32F411RET6",
        .desc = "ARM Cortex-M4, 100 MHz. Flash: 512 KB, RAM: 128 KB. User LED on PA5 (pin 13).",
    },
    .{
        .id = "arduino-uno",
        .chip = "ATmega328P",
        .desc = "8-bit AVR, 16 MHz. Flash: 16 KB, SRAM: 2 KB. Built-in LED on pin 13.",
    },
    .{
        .id = "arduino-uno-q",
        .chip = "STM32U585 + Qualcomm",
        .desc = "Dual-core: STM32 (MCU) + Linux (aarch64). GPIO via Bridge app on port 9999.",
    },
    .{
        .id = "esp32",
        .chip = "ESP32",
        .desc = "Dual-core Xtensa LX6, 240 MHz. Flash: 4 MB typical. Built-in LED on GPIO 2.",
    },
    .{
        .id = "rpi-gpio",
        .chip = "Raspberry Pi",
        .desc = "ARM Linux. Native GPIO via sysfs/rppal. No fixed LED pin.",
    },
};

/// Hardware board info tool — returns chip name, architecture, and memory map.
pub const HardwareBoardInfoTool = struct {
    boards: []const []const u8,

    pub const tool_name = "hardware_board_info";
    pub const tool_description = "Return board info (chip, architecture, memory map) for connected hardware. " ++
        "Use for: 'board info', 'what board', 'connected hardware', 'chip info', 'memory map'.";
    pub const tool_params =
        \\{"type":"object","properties":{"board":{"type":"string","description":"Board name (e.g. nucleo-f401re). If omitted, returns info for first configured board."}}}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *HardwareBoardInfoTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *HardwareBoardInfoTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        if (self.boards.len == 0) {
            return ToolResult.fail("No peripherals configured. Add boards to config.toml [peripherals.boards].");
        }

        const board = root.getString(args, "board") orelse
            (if (self.boards.len > 0) self.boards[0] else "unknown");

        // Look up static info
        for (&BOARD_DB) |*entry| {
            if (std.mem.eql(u8, entry.id, board)) {
                var output: std.ArrayList(u8) = .empty;
                errdefer output.deinit(allocator);

                try output.appendSlice(allocator, "**Board:** ");
                try output.appendSlice(allocator, board);
                try output.appendSlice(allocator, "\n**Chip:** ");
                try output.appendSlice(allocator, entry.chip);
                try output.appendSlice(allocator, "\n**Description:** ");
                try output.appendSlice(allocator, entry.desc);

                // Add memory map for known boards
                if (memoryMapStatic(board)) |mem| {
                    try output.appendSlice(allocator, "\n\n**Memory map:**\n");
                    try output.appendSlice(allocator, mem);
                }

                return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
            }
        }

        const msg = try std.fmt.allocPrint(allocator, "Board '{s}' configured. No static info available.", .{board});
        return ToolResult{ .success = true, .output = msg };
    }
};

fn memoryMapStatic(board: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, board, "nucleo-f401re") or std.mem.eql(u8, board, "nucleo-f411re")) {
        return "Flash: 0x0800_0000 - 0x0807_FFFF (512 KB)\nRAM: 0x2000_0000 - 0x2001_FFFF (128 KB)";
    }
    if (std.mem.eql(u8, board, "arduino-uno")) {
        return "Flash: 16 KB, SRAM: 2 KB, EEPROM: 1 KB";
    }
    if (std.mem.eql(u8, board, "esp32")) {
        return "Flash: 4 MB, IRAM/DRAM per ESP-IDF layout";
    }
    return null;
}

// ── Tests ───────────────────────────────────────────────────────────

test "hardware_board_info tool name" {
    var hi = HardwareBoardInfoTool{ .boards = &.{} };
    const t = hi.tool();
    try std.testing.expectEqualStrings("hardware_board_info", t.name());
}

test "hardware_board_info schema has board" {
    var hi = HardwareBoardInfoTool{ .boards = &.{} };
    const t = hi.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "board") != null);
}

test "hardware_board_info no boards returns error" {
    var hi = HardwareBoardInfoTool{ .boards = &.{} };
    const t = hi.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "peripherals") != null);
}

test "hardware_board_info known board returns info" {
    const boards = [_][]const u8{"nucleo-f401re"};
    var hi = HardwareBoardInfoTool{ .boards = &boards };
    const t = hi.tool();
    const parsed = try root.parseTestArgs("{\"board\": \"nucleo-f401re\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "STM32F401") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Memory map") != null);
}

test "hardware_board_info default board from config" {
    const boards = [_][]const u8{"nucleo-f411re"};
    var hi = HardwareBoardInfoTool{ .boards = &boards };
    const t = hi.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "STM32F411") != null);
}

test "hardware_board_info unknown board returns message" {
    const boards = [_][]const u8{"custom-board"};
    var hi = HardwareBoardInfoTool{ .boards = &boards };
    const t = hi.tool();
    const parsed = try root.parseTestArgs("{\"board\": \"custom-board\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "custom-board") != null);
}

test "hardware_board_info esp32" {
    const boards = [_][]const u8{"esp32"};
    var hi = HardwareBoardInfoTool{ .boards = &boards };
    const t = hi.tool();
    const parsed = try root.parseTestArgs("{\"board\": \"esp32\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "ESP32") != null);
}

test "memoryMapStatic returns for known boards" {
    try std.testing.expect(memoryMapStatic("nucleo-f401re") != null);
    try std.testing.expect(memoryMapStatic("nucleo-f411re") != null);
    try std.testing.expect(memoryMapStatic("arduino-uno") != null);
    try std.testing.expect(memoryMapStatic("esp32") != null);
    try std.testing.expect(memoryMapStatic("unknown") == null);
}
