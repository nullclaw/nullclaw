const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");

// Hardware discovery -- USB device enumeration and introspection.
//
// Mirrors ZeroClaw's hardware module: registry of known USB VID/PID,
// device discovery, introspection, and wizard helpers.

// ── Board Registry ──────────────────────────────────────────────

/// Information about a known board.
pub const BoardInfo = struct {
    vid: u16,
    pid: u16,
    name: []const u8,
    architecture: ?[]const u8,
};

/// Known USB VID/PID to board mappings.
/// VID 0x0483 = STMicroelectronics, 0x2341 = Arduino, 0x10c4 = Silicon Labs.
const known_boards: []const BoardInfo = &.{
    .{ .vid = 0x0483, .pid = 0x374b, .name = "nucleo-f401re", .architecture = "ARM Cortex-M4" },
    .{ .vid = 0x0483, .pid = 0x3748, .name = "nucleo-f411re", .architecture = "ARM Cortex-M4" },
    .{ .vid = 0x2341, .pid = 0x0043, .name = "arduino-uno", .architecture = "AVR ATmega328P" },
    .{ .vid = 0x2341, .pid = 0x0078, .name = "arduino-uno", .architecture = "Arduino Uno Q / ATmega328P" },
    .{ .vid = 0x2341, .pid = 0x0042, .name = "arduino-mega", .architecture = "AVR ATmega2560" },
    .{ .vid = 0x10c4, .pid = 0xea60, .name = "cp2102", .architecture = "USB-UART bridge" },
    .{ .vid = 0x10c4, .pid = 0xea70, .name = "cp2102n", .architecture = "USB-UART bridge" },
    .{ .vid = 0x1a86, .pid = 0x7523, .name = "esp32", .architecture = "ESP32 (CH340)" },
    .{ .vid = 0x1a86, .pid = 0x55d4, .name = "esp32", .architecture = "ESP32 (CH340)" },
};

/// Look up a board by VID and PID.
pub fn lookupBoard(vid: u16, pid: u16) ?*const BoardInfo {
    for (known_boards) |*b| {
        if (b.vid == vid and b.pid == pid) return b;
    }
    return null;
}

/// Return all known board entries.
pub fn knownBoards() []const BoardInfo {
    return known_boards;
}

// ── Discovered Device ───────────────────────────────────────────

/// A hardware device discovered during auto-scan.
pub const DiscoveredDevice = struct {
    name: []const u8,
    detail: ?[]const u8 = null,
    device_path: ?[]const u8 = null,
    transport: config.HardwareTransport = .serial,
};

/// Auto-discover connected hardware devices.
/// On macOS: runs `system_profiler SPUSBDataType` and parses VID/PID.
/// On Linux: reads /sys/bus/usb/devices/ entries for idVendor/idProduct.
/// On other platforms: returns empty.
pub fn discoverHardware(allocator: std.mem.Allocator) ![]DiscoveredDevice {
    return switch (comptime builtin.os.tag) {
        .macos => discoverMacOS(allocator),
        .linux => discoverLinux(allocator),
        else => &.{},
    };
}

/// Parse a hex VID/PID value from a line like "  Vendor ID: 0x0483  (STMicroelectronics)"
/// or "  Product ID: 0x374b". Handles optional "0x" prefix and trailing text.
fn parseHexFromLine(line: []const u8, prefix: []const u8) ?u16 {
    const idx = std.mem.indexOf(u8, line, prefix) orelse return null;
    var rest = line[idx + prefix.len ..];
    // Skip leading whitespace
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
    // Skip optional "0x" or "0X" prefix
    if (rest.len >= 2 and rest[0] == '0' and (rest[1] == 'x' or rest[1] == 'X')) {
        rest = rest[2..];
    }
    // Collect hex digits
    var end: usize = 0;
    while (end < rest.len and end < 4) : (end += 1) {
        const c = rest[end];
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) break;
    }
    if (end == 0) return null;
    return std.fmt.parseInt(u16, rest[0..end], 16) catch null;
}

/// macOS discovery: spawn system_profiler and parse text output.
fn discoverMacOS(allocator: std.mem.Allocator) ![]DiscoveredDevice {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "system_profiler", "SPUSBDataType" },
    }) catch return &.{};
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var devices: std.ArrayListUnmanaged(DiscoveredDevice) = .empty;
    errdefer {
        for (devices.items) |d| {
            allocator.free(d.name);
            if (d.detail) |det| allocator.free(det);
        }
        devices.deinit(allocator);
    }

    // Parse line by line, looking for Vendor ID / Product ID pairs.
    // system_profiler outputs blocks per device; VID appears before PID.
    var current_vid: ?u16 = null;
    var lines_iter = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines_iter.next()) |line| {
        if (parseHexFromLine(line, "Vendor ID:")) |vid| {
            current_vid = vid;
        } else if (parseHexFromLine(line, "Product ID:")) |pid| {
            if (current_vid) |vid| {
                if (lookupBoard(vid, pid)) |board| {
                    const detail = try std.fmt.allocPrint(allocator, "USB VID=0x{x:0>4} PID=0x{x:0>4}", .{ vid, pid });
                    errdefer allocator.free(detail);
                    const name = try allocator.dupe(u8, board.name);
                    try devices.append(allocator, .{
                        .name = name,
                        .detail = detail,
                        .transport = .serial,
                    });
                }
                current_vid = null;
            }
        }
    }

    return devices.toOwnedSlice(allocator);
}

/// Linux discovery: read /sys/bus/usb/devices/*/idVendor and idProduct.
fn discoverLinux(allocator: std.mem.Allocator) ![]DiscoveredDevice {
    var devices: std.ArrayListUnmanaged(DiscoveredDevice) = .empty;
    errdefer {
        for (devices.items) |d| {
            allocator.free(d.name);
            if (d.detail) |det| allocator.free(det);
        }
        devices.deinit(allocator);
    }

    const usb_base = "/sys/bus/usb/devices";
    var dir = std.fs.openDirAbsolute(usb_base, .{ .iterate = true }) catch return &.{};
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const vid = readSysfsHex(dir, entry.name, "idVendor") orelse continue;
        const pid = readSysfsHex(dir, entry.name, "idProduct") orelse continue;
        if (lookupBoard(vid, pid)) |board| {
            const detail = try std.fmt.allocPrint(allocator, "USB VID=0x{x:0>4} PID=0x{x:0>4} ({s})", .{ vid, pid, entry.name });
            errdefer allocator.free(detail);
            const name = try allocator.dupe(u8, board.name);
            try devices.append(allocator, .{
                .name = name,
                .detail = detail,
                .transport = .serial,
            });
        }
    }

    return devices.toOwnedSlice(allocator);
}

/// Read a 4-digit hex value from a sysfs file like /sys/bus/usb/devices/<dev>/<attr>.
fn readSysfsHex(dir: std.fs.Dir, dev_name: []const u8, attr: []const u8) ?u16 {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dev_name, attr }) catch return null;
    var sub_dir = dir.openFile(path, .{}) catch return null;
    defer sub_dir.close();
    var buf: [16]u8 = undefined;
    const n = sub_dir.readAll(&buf) catch return null;
    const content = std.mem.trimRight(u8, buf[0..n], &.{ '\n', '\r', ' ' });
    if (content.len == 0) return null;
    return std.fmt.parseInt(u16, content, 16) catch null;
}

/// Free a slice of DiscoveredDevice that was allocated by discoverHardware.
/// Safe to call with an empty comptime slice (returned on unsupported platforms).
pub fn freeDiscoveredDevices(allocator: std.mem.Allocator, devices: []DiscoveredDevice) void {
    for (devices) |d| {
        allocator.free(d.name);
        if (d.detail) |det| allocator.free(det);
    }
    // Only free the slice if it was heap-allocated (length > 0 guarantees it came
    // from toOwnedSlice). For empty slices from comptime &.{}, skip the free.
    if (devices.len > 0) {
        allocator.free(devices);
    }
}

// ── Wizard Helpers ──────────────────────────────────────────────

/// Return the recommended default wizard choice index based on discovered devices.
/// 0 = Native, 1 = Tethered/Serial, 2 = Debug Probe, 3 = Software Only
pub fn recommendedWizardDefault(devices: []const DiscoveredDevice) usize {
    if (devices.len == 0) {
        return 3; // software only
    }
    return 1; // tethered (most common for detected USB devices)
}

/// Build a HardwareConfig from the wizard menu choice (0-3) and discovered devices.
pub fn configFromWizardChoice(choice: usize, devices: []const DiscoveredDevice) config.HardwareConfig {
    return switch (choice) {
        0 => .{
            .enabled = true,
            .transport = .native,
        },
        1 => blk: {
            var serial_port: ?[]const u8 = null;
            for (devices) |d| {
                if (d.transport == .serial) {
                    serial_port = d.device_path;
                    break;
                }
            }
            break :blk .{
                .enabled = true,
                .transport = .serial,
                .serial_port = serial_port,
            };
        },
        2 => .{
            .enabled = true,
            .transport = .probe,
        },
        else => .{}, // software only (defaults)
    };
}

// ── Introspection ───────────────────────────────────────────────

/// Result of introspecting a device by path.
pub const IntrospectResult = struct {
    path: []const u8,
    vid: ?u16 = null,
    pid: ?u16 = null,
    board_name: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    memory_map_note: []const u8 = "Build with hardware feature for live memory map",
};

/// Introspect a device by its serial path.
/// On macOS: runs system_profiler and matches device info.
/// On Linux: reads sysfs attributes for the device.
/// Returns basic VID/PID and board info if the device is recognized.
pub fn introspectDevice(allocator: std.mem.Allocator, path: []const u8) IntrospectResult {
    return switch (comptime builtin.os.tag) {
        .macos => introspectMacOS(allocator, path),
        .linux => introspectLinux(path),
        else => .{
            .path = path,
            .memory_map_note = "USB introspection not available on this platform",
        },
    };
}

/// macOS introspection: parse system_profiler output to find VID/PID
/// for the first USB device, then look up in known_boards.
fn introspectMacOS(allocator: std.mem.Allocator, path: []const u8) IntrospectResult {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "system_profiler", "SPUSBDataType" },
    }) catch return .{
        .path = path,
        .memory_map_note = "Failed to run system_profiler",
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Parse output for VID/PID pairs and try to match a known board.
    // Since system_profiler doesn't directly map to /dev paths, we return
    // the first recognized board we find as a best-effort match.
    var current_vid: ?u16 = null;
    var lines_iter = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines_iter.next()) |line| {
        if (parseHexFromLine(line, "Vendor ID:")) |vid| {
            current_vid = vid;
        } else if (parseHexFromLine(line, "Product ID:")) |pid| {
            if (current_vid) |vid| {
                if (lookupBoard(vid, pid)) |board| {
                    return .{
                        .path = path,
                        .vid = vid,
                        .pid = pid,
                        .board_name = board.name,
                        .architecture = board.architecture,
                        .memory_map_note = "Identified via system_profiler USB scan",
                    };
                }
                current_vid = null;
            }
        }
    }

    return .{
        .path = path,
        .memory_map_note = "No recognized board found via system_profiler",
    };
}

/// Linux introspection: try to find the sysfs USB device for the given path,
/// then read idVendor/idProduct and look up in known_boards.
fn introspectLinux(path: []const u8) IntrospectResult {
    // Try to resolve a /dev/ttyACM* or /dev/ttyUSB* path to its sysfs USB ancestor.
    // Strategy: iterate /sys/bus/usb/devices/ and check each for matching VID/PID.
    const usb_base = "/sys/bus/usb/devices";
    var dir = std.fs.openDirAbsolute(usb_base, .{ .iterate = true }) catch return .{
        .path = path,
        .memory_map_note = "Cannot access /sys/bus/usb/devices",
    };
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        const vid = readSysfsHex(dir, entry.name, "idVendor") orelse continue;
        const pid = readSysfsHex(dir, entry.name, "idProduct") orelse continue;
        if (lookupBoard(vid, pid)) |board| {
            return .{
                .path = path,
                .vid = vid,
                .pid = pid,
                .board_name = board.name,
                .architecture = board.architecture,
                .memory_map_note = "Identified via sysfs USB scan",
            };
        }
    }

    return .{
        .path = path,
        .memory_map_note = "No recognized board found in sysfs",
    };
}

// ── Tests ───────────────────────────────────────────────────────

test "lookupBoard finds nucleo-f401re" {
    const b = lookupBoard(0x0483, 0x374b);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("nucleo-f401re", b.?.name);
    try std.testing.expectEqualStrings("ARM Cortex-M4", b.?.architecture.?);
}

test "lookupBoard finds nucleo-f411re" {
    const b = lookupBoard(0x0483, 0x3748);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("nucleo-f411re", b.?.name);
}

test "lookupBoard finds arduino-uno" {
    const b = lookupBoard(0x2341, 0x0043);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("arduino-uno", b.?.name);
}

test "lookupBoard finds arduino-mega" {
    const b = lookupBoard(0x2341, 0x0042);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("arduino-mega", b.?.name);
}

test "lookupBoard finds cp2102" {
    const b = lookupBoard(0x10c4, 0xea60);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("cp2102", b.?.name);
}

test "lookupBoard finds esp32" {
    const b = lookupBoard(0x1a86, 0x7523);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("esp32", b.?.name);
}

test "lookupBoard returns null for unknown VID/PID" {
    try std.testing.expect(lookupBoard(0x0000, 0x0000) == null);
}

test "lookupBoard returns null for partial match" {
    // Correct VID but wrong PID
    try std.testing.expect(lookupBoard(0x0483, 0xFFFF) == null);
}

test "knownBoards is not empty" {
    try std.testing.expect(knownBoards().len > 0);
}

test "knownBoards has at least 9 entries" {
    try std.testing.expectEqual(@as(usize, 9), knownBoards().len);
}

test "all known boards have non-empty name" {
    for (knownBoards()) |b| {
        try std.testing.expect(b.name.len > 0);
    }
}

test "all known boards have architecture" {
    for (knownBoards()) |b| {
        try std.testing.expect(b.architecture != null);
    }
}

test "discoverHardware does not error" {
    const devices = try discoverHardware(std.testing.allocator);
    // On CI or machines without USB devices this will be empty;
    // on a dev machine with known boards plugged in it may return results.
    // Either way, verify no error and clean up allocations.
    defer freeDiscoveredDevices(std.testing.allocator, devices);
    // Sanity: each discovered device has a non-empty name.
    for (devices) |d| {
        try std.testing.expect(d.name.len > 0);
    }
}

test "recommendedWizardDefault returns 3 for empty" {
    try std.testing.expectEqual(@as(usize, 3), recommendedWizardDefault(&.{}));
}

test "recommendedWizardDefault returns 1 for non-empty" {
    const devices = [_]DiscoveredDevice{.{ .name = "test" }};
    try std.testing.expectEqual(@as(usize, 1), recommendedWizardDefault(&devices));
}

test "configFromWizardChoice native" {
    const cfg = configFromWizardChoice(0, &.{});
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqual(config.HardwareTransport.native, cfg.transport);
}

test "configFromWizardChoice serial" {
    const devices = [_]DiscoveredDevice{.{
        .name = "nucleo",
        .transport = .serial,
        .device_path = "/dev/ttyACM0",
    }};
    const cfg = configFromWizardChoice(1, &devices);
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqual(config.HardwareTransport.serial, cfg.transport);
    try std.testing.expectEqualStrings("/dev/ttyACM0", cfg.serial_port.?);
}

test "configFromWizardChoice probe" {
    const cfg = configFromWizardChoice(2, &.{});
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqual(config.HardwareTransport.probe, cfg.transport);
}

test "configFromWizardChoice software only" {
    const cfg = configFromWizardChoice(3, &.{});
    try std.testing.expect(!cfg.enabled);
    try std.testing.expectEqual(config.HardwareTransport.none, cfg.transport);
}

test "configFromWizardChoice out of range defaults to software only" {
    const cfg = configFromWizardChoice(99, &.{});
    try std.testing.expect(!cfg.enabled);
}

test "introspectDevice returns path" {
    const result = introspectDevice(std.testing.allocator, "/dev/ttyACM0");
    try std.testing.expectEqualStrings("/dev/ttyACM0", result.path);
    // VID/PID may or may not be populated depending on connected hardware.
    // Just verify the path is preserved.
}

test "introspectDevice has memory map note" {
    const result = introspectDevice(std.testing.allocator, "/dev/ttyUSB0");
    try std.testing.expect(result.memory_map_note.len > 0);
}

test "DiscoveredDevice defaults" {
    const d = DiscoveredDevice{ .name = "test-board" };
    try std.testing.expectEqualStrings("test-board", d.name);
    try std.testing.expect(d.detail == null);
    try std.testing.expect(d.device_path == null);
    try std.testing.expectEqual(config.HardwareTransport.serial, d.transport);
}

test "IntrospectResult defaults" {
    const r = IntrospectResult{ .path = "/dev/test" };
    try std.testing.expectEqualStrings("/dev/test", r.path);
    try std.testing.expect(r.vid == null);
    try std.testing.expect(r.pid == null);
}

// ── parseHexFromLine tests ──────────────────────────────────────

test "parseHexFromLine extracts VID with 0x prefix" {
    const vid = parseHexFromLine("          Vendor ID: 0x0483  (STMicroelectronics)", "Vendor ID:");
    try std.testing.expect(vid != null);
    try std.testing.expectEqual(@as(u16, 0x0483), vid.?);
}

test "parseHexFromLine extracts PID with 0x prefix" {
    const pid = parseHexFromLine("          Product ID: 0x374b", "Product ID:");
    try std.testing.expect(pid != null);
    try std.testing.expectEqual(@as(u16, 0x374b), pid.?);
}

test "parseHexFromLine handles uppercase hex" {
    const val = parseHexFromLine("  Vendor ID: 0xEA60", "Vendor ID:");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(u16, 0xea60), val.?);
}

test "parseHexFromLine handles no 0x prefix" {
    const val = parseHexFromLine("  Vendor ID: 0483", "Vendor ID:");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(u16, 0x0483), val.?);
}

test "parseHexFromLine returns null for missing prefix" {
    try std.testing.expect(parseHexFromLine("  Serial Number: 12345", "Vendor ID:") == null);
}

test "parseHexFromLine returns null for empty value" {
    try std.testing.expect(parseHexFromLine("  Vendor ID:", "Vendor ID:") == null);
}

test "parseHexFromLine handles 0X prefix" {
    const val = parseHexFromLine("  Vendor ID: 0X2341", "Vendor ID:");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(u16, 0x2341), val.?);
}

test "parseHexFromLine with trailing parenthetical" {
    const vid = parseHexFromLine("          Vendor ID: 0x1a86  (QinHeng Electronics)", "Vendor ID:");
    try std.testing.expect(vid != null);
    try std.testing.expectEqual(@as(u16, 0x1a86), vid.?);
}

test "freeDiscoveredDevices with empty slice" {
    // Should not crash when called with an empty comptime slice.
    freeDiscoveredDevices(std.testing.allocator, &.{});
}
