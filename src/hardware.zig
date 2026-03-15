const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const thread_stacks = @import("thread_stacks.zig");

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

// ── USB Hotplug Monitoring ──────────────────────────────────────

/// A USB hotplug event emitted by the monitor.
/// Fields are slices into a temporary buffer — copy if you need to retain them.
pub const DeviceEvent = struct {
    /// Action string: "add", "remove", or "change".
    action: []const u8,
    /// Subsystem/kind of the event (e.g. "usb", "tty").
    kind: []const u8,
    /// Composed device identifier: "VID:PID model" from udevadm properties,
    /// or the raw device path when properties are unavailable.
    device_id: []const u8,
    /// Monotonic timestamp in seconds (from udevadm), or 0 if unavailable.
    timestamp: i64,
};

/// Callback invoked for each hotplug device event.
pub const DeviceEventCallback = *const fn (event: DeviceEvent, context: ?*anyopaque) void;

/// Real-time USB hotplug monitor that watches for device connect/disconnect events.
pub const HotplugMonitor = struct {
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    allocator: std.mem.Allocator,
    callback: ?DeviceEventCallback = null,
    callback_ctx: ?*anyopaque = null,
};

/// Start a hotplug monitor that calls `callback` on USB device events.
/// On Linux: spawns udevadm monitor --property and parses its output.
/// On macOS: logs that hotplug monitoring is not available and returns.
/// On other platforms: no-op (monitor.running stays false).
///
/// Caller must initialize `monitor` fields (allocator, callback/callback_ctx) before calling.
/// The monitor must remain at a stable address until stopHotplugMonitor() returns.
pub fn startHotplugMonitor(monitor: *HotplugMonitor) !void {
    switch (comptime builtin.os.tag) {
        .linux => {
            monitor.running = std.atomic.Value(bool).init(true);
            monitor.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.CONTROL_LOOP_STACK_SIZE }, runLinuxMonitor, .{monitor});
        },
        .macos => {
            std.log.info("hotplug monitoring not available on macOS", .{});
        },
        else => {},
    }
}

/// Stop the hotplug monitor and wait for the thread to finish.
pub fn stopHotplugMonitor(monitor: *HotplugMonitor) void {
    monitor.running.store(false, .release);
    if (monitor.thread) |t| {
        t.join();
        monitor.thread = null;
    }
}

/// Parse a udevadm monitor header line.
/// Expected format: "UDEV  [1234.567890] add      /devices/pci0000:00/... (usb)"
/// Returns a partial DeviceEvent with action, kind (subsystem), device_id (device path),
/// and timestamp. Returns null if the line cannot be parsed.
pub fn parseUdevLine(line: []const u8) ?DeviceEvent {
    // Must start with "UDEV" (skip KERNEL events)
    if (!std.mem.startsWith(u8, line, "UDEV")) return null;

    // Find timestamp in brackets: [timestamp]
    const ts_start = std.mem.indexOf(u8, line, "[") orelse return null;
    const ts_end = std.mem.indexOf(u8, line, "]") orelse return null;
    if (ts_end <= ts_start + 1) return null;

    // Parse the action keyword after the ']'
    var rest = line[ts_end + 1 ..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];

    const action_str = parseActionStr(rest) orelse return null;
    rest = rest[action_str.len..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];

    // Device path is everything up to the parenthesized subsystem
    var device_path: []const u8 = rest;
    var subsystem: []const u8 = "unknown";

    if (std.mem.lastIndexOf(u8, rest, "(")) |paren_start| {
        device_path = std.mem.trimRight(u8, rest[0..paren_start], " ");
        const after_paren = rest[paren_start + 1 ..];
        if (std.mem.indexOf(u8, after_paren, ")")) |paren_end| {
            subsystem = after_paren[0..paren_end];
        }
    }

    // Parse timestamp as integer seconds
    const ts_str = line[ts_start + 1 .. ts_end];
    const timestamp = parseTimestampSecs(ts_str);

    return DeviceEvent{
        .action = action_str,
        .kind = subsystem,
        .device_id = device_path,
        .timestamp = timestamp,
    };
}

/// Extract the action keyword from the beginning of the string.
/// Returns the slice "add", "remove", or "change", or null if unrecognized.
fn parseActionStr(rest: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, rest, "remove")) return rest[0..6];
    if (std.mem.startsWith(u8, rest, "change")) return rest[0..6];
    if (std.mem.startsWith(u8, rest, "add")) return rest[0..3];
    return null;
}

/// Parse a udevadm property line of the form "KEY=value".
/// Returns the key and value slices, or null if the line is not a property.
pub fn parseUdevProperty(line: []const u8) ?struct { key: []const u8, value: []const u8 } {
    if (line.len == 0) return null;
    // Property lines don't start with whitespace in --property mode,
    // but skip leading spaces just in case.
    var trimmed = line;
    while (trimmed.len > 0 and trimmed[0] == ' ') trimmed = trimmed[1..];
    if (trimmed.len == 0) return null;
    // Must contain '=' and not start with special chars
    const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse return null;
    if (eq_pos == 0) return null;
    // Key must be uppercase letters, digits, or underscores
    const key = trimmed[0..eq_pos];
    for (key) |c| {
        if (!((c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_')) return null;
    }
    return .{ .key = key, .value = trimmed[eq_pos + 1 ..] };
}

/// Build a device_id string from collected udevadm properties.
/// Format: "VID:PID model" if properties available, otherwise returns fallback.
pub fn buildDeviceId(
    buf: []u8,
    vendor_id: ?[]const u8,
    product_id: ?[]const u8,
    model: ?[]const u8,
    fallback: []const u8,
) []const u8 {
    const vid = vendor_id orelse {
        // No vendor info — use fallback
        return fallback;
    };
    const pid = product_id orelse "0000";
    if (model) |m| {
        return std.fmt.bufPrint(buf, "{s}:{s} {s}", .{ vid, pid, m }) catch fallback;
    } else {
        return std.fmt.bufPrint(buf, "{s}:{s}", .{ vid, pid }) catch fallback;
    }
}

fn parseTimestampSecs(ts_str: []const u8) i64 {
    const trimmed = std.mem.trim(u8, ts_str, " ");
    // Format: "1234.567890" — take the integer part only
    if (std.mem.indexOf(u8, trimmed, ".")) |dot_pos| {
        return std.fmt.parseInt(i64, trimmed[0..dot_pos], 10) catch 0;
    } else {
        return std.fmt.parseInt(i64, trimmed, 10) catch 0;
    }
}

/// Linux monitor: spawn `udevadm monitor --udev --subsystem-match=usb --property`
/// and parse header + property lines from its stdout.
fn runLinuxMonitor(monitor: *HotplugMonitor) void {
    var child = std.process.Child.init(
        &.{ "udevadm", "monitor", "--udev", "--subsystem-match=usb", "--property" },
        monitor.allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch return;
    defer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    const cb = monitor.callback orelse return;
    const stdout = child.stdout orelse return;

    var buf: [4096]u8 = undefined;
    // State for collecting a multi-line event block
    var pending_event: ?DeviceEvent = null;
    var id_vendor: ?[]const u8 = null;
    var id_product: ?[]const u8 = null;
    var id_model: ?[]const u8 = null;
    var device_id_buf: [256]u8 = undefined;

    while (monitor.running.load(.acquire)) {
        const n = stdout.read(&buf) catch break;
        if (n == 0) break;
        var lines_iter = std.mem.splitScalar(u8, buf[0..n], '\n');
        while (lines_iter.next()) |line| {
            if (line.len == 0) {
                // Blank line = end of event block -> emit
                if (pending_event) |*ev| {
                    ev.device_id = buildDeviceId(
                        &device_id_buf,
                        id_vendor,
                        id_product,
                        id_model,
                        ev.device_id,
                    );
                    cb(ev.*, monitor.callback_ctx);
                }
                pending_event = null;
                id_vendor = null;
                id_product = null;
                id_model = null;
                continue;
            }
            // Try to parse as header line
            if (parseUdevLine(line)) |event| {
                // If there was an un-emitted pending event, emit it first
                if (pending_event) |*ev| {
                    ev.device_id = buildDeviceId(
                        &device_id_buf,
                        id_vendor,
                        id_product,
                        id_model,
                        ev.device_id,
                    );
                    cb(ev.*, monitor.callback_ctx);
                }
                pending_event = event;
                id_vendor = null;
                id_product = null;
                id_model = null;
                continue;
            }
            // Try to parse as property line
            if (pending_event != null) {
                if (parseUdevProperty(line)) |prop| {
                    if (std.mem.eql(u8, prop.key, "ID_VENDOR_ID")) {
                        id_vendor = prop.value;
                    } else if (std.mem.eql(u8, prop.key, "ID_MODEL_ID") or std.mem.eql(u8, prop.key, "ID_PRODUCT_ID")) {
                        id_product = prop.value;
                    } else if (std.mem.eql(u8, prop.key, "ID_MODEL")) {
                        id_model = prop.value;
                    }
                }
            }
        }
    }
    // Emit any trailing event
    if (pending_event) |*ev| {
        ev.device_id = buildDeviceId(
            &device_id_buf,
            id_vendor,
            id_product,
            id_model,
            ev.device_id,
        );
        cb(ev.*, monitor.callback_ctx);
    }
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

// ── Hotplug Monitor Tests ──────────────────────────────────────

test "DeviceEvent struct creation" {
    const event = DeviceEvent{
        .action = "add",
        .kind = "usb",
        .device_id = "/dev/ttyUSB0",
        .timestamp = 1234567890,
    };
    try std.testing.expectEqualStrings("add", event.action);
    try std.testing.expectEqualStrings("/dev/ttyUSB0", event.device_id);
    try std.testing.expectEqualStrings("usb", event.kind);
    try std.testing.expectEqual(@as(i64, 1234567890), event.timestamp);
}

test "DeviceEvent all actions" {
    const added = DeviceEvent{ .action = "add", .kind = "usb", .device_id = "/dev/a", .timestamp = 0 };
    const removed = DeviceEvent{ .action = "remove", .kind = "tty", .device_id = "/dev/b", .timestamp = 1 };
    const changed = DeviceEvent{ .action = "change", .kind = "usb", .device_id = "/dev/c", .timestamp = 2 };
    try std.testing.expectEqualStrings("add", added.action);
    try std.testing.expectEqualStrings("remove", removed.action);
    try std.testing.expectEqualStrings("change", changed.action);
}

test "parseUdevLine parses add event" {
    const line = "UDEV  [1234.567890] add      /devices/pci0000:00/0000:00:14.0/usb1/1-1 (usb)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("add", event.?.action);
    try std.testing.expectEqualStrings("/devices/pci0000:00/0000:00:14.0/usb1/1-1", event.?.device_id);
    try std.testing.expectEqualStrings("usb", event.?.kind);
    try std.testing.expect(event.?.timestamp > 0);
}

test "parseUdevLine parses remove event" {
    const line = "UDEV  [5678.123456] remove   /devices/pci0000:00/0000:00:14.0/usb1/1-1 (usb)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("remove", event.?.action);
}

test "parseUdevLine parses change event" {
    const line = "UDEV  [9999.000000] change   /devices/pci0000:00/usb2/2-1 (tty)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("change", event.?.action);
    try std.testing.expectEqualStrings("tty", event.?.kind);
}

test "parseUdevLine rejects KERNEL line" {
    const line = "KERNEL[1234.567890] add      /devices/pci0000:00/usb1/1-1 (usb)";
    try std.testing.expect(parseUdevLine(line) == null);
}

test "parseUdevLine rejects empty line" {
    try std.testing.expect(parseUdevLine("") == null);
}

test "parseUdevLine rejects malformed line" {
    try std.testing.expect(parseUdevLine("UDEV  no brackets here") == null);
}

test "parseUdevLine rejects unknown action" {
    const line = "UDEV  [1234.567890] bind     /devices/pci0000:00/usb1/1-1 (usb)";
    try std.testing.expect(parseUdevLine(line) == null);
}

test "parseUdevLine timestamp truncates to seconds" {
    const line = "UDEV  [100.500000000] add      /devices/test (usb)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqual(@as(i64, 100), event.?.timestamp);
}

test "parseUdevLine timestamp integer only" {
    const line = "UDEV  [42] add      /devices/test (usb)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqual(@as(i64, 42), event.?.timestamp);
}

test "parseUdevLine tty subsystem" {
    const line = "UDEV  [1000.000] add      /devices/pci0000:00/ttyUSB0 (tty)";
    const event = parseUdevLine(line);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("tty", event.?.kind);
}

// ── Property Parsing Tests ─────────────────────────────────────

test "parseUdevProperty parses key=value" {
    const prop = parseUdevProperty("ID_VENDOR_ID=0483");
    try std.testing.expect(prop != null);
    try std.testing.expectEqualStrings("ID_VENDOR_ID", prop.?.key);
    try std.testing.expectEqualStrings("0483", prop.?.value);
}

test "parseUdevProperty parses ID_MODEL" {
    const prop = parseUdevProperty("ID_MODEL=Arduino_Uno");
    try std.testing.expect(prop != null);
    try std.testing.expectEqualStrings("ID_MODEL", prop.?.key);
    try std.testing.expectEqualStrings("Arduino_Uno", prop.?.value);
}

test "parseUdevProperty parses empty value" {
    const prop = parseUdevProperty("ID_MODEL=");
    try std.testing.expect(prop != null);
    try std.testing.expectEqualStrings("ID_MODEL", prop.?.key);
    try std.testing.expectEqualStrings("", prop.?.value);
}

test "parseUdevProperty rejects empty line" {
    try std.testing.expect(parseUdevProperty("") == null);
}

test "parseUdevProperty rejects line without equals" {
    try std.testing.expect(parseUdevProperty("no_equals_sign") == null);
}

test "parseUdevProperty rejects lowercase key" {
    try std.testing.expect(parseUdevProperty("lowercase=value") == null);
}

test "parseUdevProperty rejects header line" {
    // UDEV header has spaces and brackets, not a valid property
    try std.testing.expect(parseUdevProperty("UDEV  [1234.567890] add /dev (usb)") == null);
}

// ── buildDeviceId Tests ────────────────────────────────────────

test "buildDeviceId with all properties" {
    var buf: [256]u8 = undefined;
    const id = buildDeviceId(&buf, "0483", "374b", "Nucleo_F401RE", "/dev/fallback");
    try std.testing.expectEqualStrings("0483:374b Nucleo_F401RE", id);
}

test "buildDeviceId without model" {
    var buf: [256]u8 = undefined;
    const id = buildDeviceId(&buf, "1a86", "7523", null, "/dev/fallback");
    try std.testing.expectEqualStrings("1a86:7523", id);
}

test "buildDeviceId without vendor returns fallback" {
    var buf: [256]u8 = undefined;
    const id = buildDeviceId(&buf, null, null, null, "/devices/pci/usb1");
    try std.testing.expectEqualStrings("/devices/pci/usb1", id);
}

test "buildDeviceId without product uses 0000" {
    var buf: [256]u8 = undefined;
    const id = buildDeviceId(&buf, "0483", null, null, "/dev/fallback");
    try std.testing.expectEqualStrings("0483:0000", id);
}

// ── DeviceEventCallback Tests ──────────────────────────────────

test "DeviceEventCallback with context" {
    const Ctx = struct {
        count: usize = 0,
        fn handler(_: DeviceEvent, context: ?*anyopaque) void {
            if (context) |ptr| {
                const self: *@This() = @ptrCast(@alignCast(ptr));
                self.count += 1;
            }
        }
    };
    var ctx = Ctx{};
    const cb: DeviceEventCallback = &Ctx.handler;
    const event = DeviceEvent{ .action = "add", .kind = "usb", .device_id = "test", .timestamp = 0 };
    cb(event, @ptrCast(&ctx));
    cb(event, @ptrCast(&ctx));
    try std.testing.expectEqual(@as(usize, 2), ctx.count);
}

test "DeviceEventCallback with null context" {
    const handler = struct {
        fn cb(_: DeviceEvent, context: ?*anyopaque) void {
            std.debug.assert(context == null);
        }
    };
    const event = DeviceEvent{ .action = "remove", .kind = "usb", .device_id = "dev", .timestamp = 5 };
    handler.cb(event, null);
}

// ── HotplugMonitor Tests ───────────────────────────────────────

test "HotplugMonitor initial state" {
    const monitor = HotplugMonitor{
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(monitor.thread == null);
    try std.testing.expect(!monitor.running.raw);
    try std.testing.expect(monitor.callback == null);
    try std.testing.expect(monitor.callback_ctx == null);
}

test "HotplugMonitor with callback" {
    const monitor = HotplugMonitor{
        .allocator = std.testing.allocator,
        .callback = &struct {
            fn cb(_: DeviceEvent, _: ?*anyopaque) void {}
        }.cb,
    };
    try std.testing.expect(monitor.callback != null);
}

test "startHotplugMonitor returns without error" {
    var monitor = HotplugMonitor{
        .allocator = std.testing.allocator,
        .callback = &struct {
            fn cb(_: DeviceEvent, _: ?*anyopaque) void {}
        }.cb,
    };
    try startHotplugMonitor(&monitor);
    // On macOS: logs and returns (no thread). On Linux: udevadm may fail but ok.
    stopHotplugMonitor(&monitor);
    try std.testing.expect(monitor.thread == null);
}

test "stopHotplugMonitor is safe to call twice" {
    var monitor = HotplugMonitor{
        .allocator = std.testing.allocator,
        .callback = &struct {
            fn cb(_: DeviceEvent, _: ?*anyopaque) void {}
        }.cb,
    };
    try startHotplugMonitor(&monitor);
    stopHotplugMonitor(&monitor);
    stopHotplugMonitor(&monitor); // second call should be safe
    try std.testing.expect(monitor.thread == null);
}

test "startHotplugMonitor without callback" {
    var monitor = HotplugMonitor{
        .allocator = std.testing.allocator,
    };
    try startHotplugMonitor(&monitor);
    stopHotplugMonitor(&monitor);
    try std.testing.expect(monitor.thread == null);
}
