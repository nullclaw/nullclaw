const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");

// Peripherals -- hardware peripheral management (STM32, RPi GPIO, Arduino, etc).
//
// Mirrors ZeroClaw's peripherals module: the Peripheral trait/interface,
// board listing, serial/GPIO/flash backends, capabilities, and tool creation.

// ── Peripheral Interface ────────────────────────────────────────

/// Peripheral capabilities reported by a connected device.
pub const PeripheralCapabilities = struct {
    board_name: []const u8 = "",
    board_type: []const u8 = "",
    gpio_pins: []const u8 = "",
    flash_size_kb: u32 = 0,
    has_serial: bool = false,
    has_gpio: bool = false,
    has_flash: bool = false,
    has_adc: bool = false,
};

/// A hardware peripheral that exposes capabilities as tools.
/// Implement this for boards like Nucleo-F401RE (serial), RPi GPIO (native), etc.
pub const Peripheral = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        board_type: *const fn (ptr: *anyopaque) []const u8,
        health_check: *const fn (ptr: *anyopaque) bool,
        init_peripheral: *const fn (ptr: *anyopaque) PeripheralError!void,
        read: *const fn (ptr: *anyopaque, addr: u32) PeripheralError!u8,
        write: *const fn (ptr: *anyopaque, addr: u32, data: u8) PeripheralError!void,
        flash: *const fn (ptr: *anyopaque, firmware_path: []const u8) PeripheralError!void,
        capabilities: *const fn (ptr: *anyopaque) PeripheralCapabilities,
    };

    pub const PeripheralError = error{
        NotConnected,
        IoError,
        FlashFailed,
        Timeout,
        InvalidAddress,
        PermissionDenied,
        DeviceNotFound,
        UnsupportedOperation,
    };

    pub fn name(self: Peripheral) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn boardType(self: Peripheral) []const u8 {
        return self.vtable.board_type(self.ptr);
    }

    pub fn healthCheck(self: Peripheral) bool {
        return self.vtable.health_check(self.ptr);
    }

    pub fn initPeripheral(self: Peripheral) PeripheralError!void {
        return self.vtable.init_peripheral(self.ptr);
    }

    pub fn read(self: Peripheral, addr: u32) PeripheralError!u8 {
        return self.vtable.read(self.ptr, addr);
    }

    pub fn writeByte(self: Peripheral, addr: u32, data: u8) PeripheralError!void {
        return self.vtable.write(self.ptr, addr, data);
    }

    pub fn flashFirmware(self: Peripheral, firmware_path: []const u8) PeripheralError!void {
        return self.vtable.flash(self.ptr, firmware_path);
    }

    pub fn getCapabilities(self: Peripheral) PeripheralCapabilities {
        return self.vtable.capabilities(self.ptr);
    }
};

// ── Allowed Serial Paths (security) ─────────────────────────────

const allowed_serial_prefixes = [_][]const u8{
    "/dev/ttyACM",
    "/dev/ttyUSB",
    "/dev/tty.usbmodem",
    "/dev/cu.usbmodem",
    "/dev/tty.usbserial",
    "/dev/cu.usbserial",
};

pub fn isSerialPathAllowed(path: []const u8) bool {
    for (allowed_serial_prefixes) |prefix| {
        if (path.len >= prefix.len and std.mem.eql(u8, path[0..prefix.len], prefix)) {
            return true;
        }
    }
    return false;
}

// ── SerialPeripheral ────────────────────────────────────────────

/// Serial peripheral for STM32, Arduino, etc. over USB CDC.
/// Protocol: newline-delimited JSON.
pub const SerialPeripheral = struct {
    peripheral_name: []const u8,
    board_type_str: []const u8,
    port_path: []const u8,
    baud_rate: u32,
    connected: bool = false,
    serial_file: ?std.fs.File = null,
    msg_id: u32 = 0,

    const serial_vtable = Peripheral.VTable{
        .name = serialName,
        .board_type = serialBoardType,
        .health_check = serialHealthCheck,
        .init_peripheral = serialInit,
        .read = serialRead,
        .write = serialWrite,
        .flash = serialFlash,
        .capabilities = serialCapabilities,
    };

    pub fn create(port_path: []const u8, board: []const u8, baud: u32) Peripheral.PeripheralError!SerialPeripheral {
        if (!isSerialPathAllowed(port_path)) {
            return Peripheral.PeripheralError.PermissionDenied;
        }
        return SerialPeripheral{
            .peripheral_name = board,
            .board_type_str = board,
            .port_path = port_path,
            .baud_rate = baud,
        };
    }

    pub fn peripheral(self: *SerialPeripheral) Peripheral {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &serial_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *SerialPeripheral {
        return @ptrCast(@alignCast(ptr));
    }

    fn serialName(ptr: *anyopaque) []const u8 {
        return resolve(ptr).peripheral_name;
    }

    fn serialBoardType(ptr: *anyopaque) []const u8 {
        return resolve(ptr).board_type_str;
    }

    fn serialHealthCheck(ptr: *anyopaque) bool {
        return resolve(ptr).connected;
    }

    fn serialInit(ptr: *anyopaque) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (comptime !(builtin.os.tag == .linux or builtin.os.tag == .macos)) {
            return Peripheral.PeripheralError.UnsupportedOperation;
        }
        if (!isSerialPathAllowed(self.port_path)) {
            return Peripheral.PeripheralError.PermissionDenied;
        }
        const file = std.fs.openFileAbsolute(self.port_path, .{ .mode = .read_write }) catch {
            self.connected = false;
            return Peripheral.PeripheralError.IoError;
        };
        self.serial_file = file;
        self.connected = true;
    }

    fn serialRead(ptr: *anyopaque, addr: u32) Peripheral.PeripheralError!u8 {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        const file = self.serial_file orelse return Peripheral.PeripheralError.NotConnected;

        // Build JSON command: {"id":"N","cmd":"gpio_read","args":{"pin":PIN}}
        self.msg_id +%= 1;
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "{{\"id\":\"{d}\",\"cmd\":\"gpio_read\",\"args\":{{\"pin\":{d}}}}}\n", .{ self.msg_id, addr }) catch
            return Peripheral.PeripheralError.IoError;

        // Write command to serial port
        file.writeAll(cmd) catch return Peripheral.PeripheralError.IoError;

        // Read response (newline-delimited JSON)
        var resp_buf: [512]u8 = undefined;
        const n = file.read(&resp_buf) catch return Peripheral.PeripheralError.IoError;
        if (n == 0) return Peripheral.PeripheralError.Timeout;

        // Parse response JSON to extract "result" value
        return parseResultValue(resp_buf[0..n]);
    }

    /// Parse a JSON response like {"id":"N","ok":true,"result":"VALUE"} and
    /// return the "result" field as u8.
    fn parseResultValue(resp: []const u8) Peripheral.PeripheralError!u8 {
        // Find "result":" or "result": in the response
        const key = "\"result\":";
        const idx = std.mem.indexOf(u8, resp, key) orelse return Peripheral.PeripheralError.IoError;
        const after_key = resp[idx + key.len ..];
        // Skip optional whitespace and quotes
        var pos: usize = 0;
        while (pos < after_key.len and (after_key[pos] == ' ' or after_key[pos] == '"')) : (pos += 1) {}
        // Parse digits
        var end = pos;
        while (end < after_key.len and after_key[end] >= '0' and after_key[end] <= '9') : (end += 1) {}
        if (end == pos) {
            // Non-numeric result (e.g. "done") -- not valid for read
            return Peripheral.PeripheralError.IoError;
        }
        return std.fmt.parseInt(u8, after_key[pos..end], 10) catch return Peripheral.PeripheralError.IoError;
    }

    fn serialWrite(ptr: *anyopaque, addr: u32, data: u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        const file = self.serial_file orelse return Peripheral.PeripheralError.NotConnected;

        // Build JSON command: {"id":"N","cmd":"gpio_write","args":{"pin":PIN,"value":VALUE}}
        self.msg_id +%= 1;
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "{{\"id\":\"{d}\",\"cmd\":\"gpio_write\",\"args\":{{\"pin\":{d},\"value\":{d}}}}}\n", .{ self.msg_id, addr, data }) catch
            return Peripheral.PeripheralError.IoError;

        // Write command to serial port
        file.writeAll(cmd) catch return Peripheral.PeripheralError.IoError;

        // Read and verify response
        var resp_buf: [512]u8 = undefined;
        const n = file.read(&resp_buf) catch return Peripheral.PeripheralError.IoError;
        if (n == 0) return Peripheral.PeripheralError.Timeout;

        // Verify "ok":true in response
        if (std.mem.indexOf(u8, resp_buf[0..n], "\"ok\":true") == null) {
            return Peripheral.PeripheralError.IoError;
        }
    }

    fn serialFlash(_: *anyopaque, _: []const u8) Peripheral.PeripheralError!void {
        return Peripheral.PeripheralError.UnsupportedOperation;
    }

    fn serialCapabilities(ptr: *anyopaque) PeripheralCapabilities {
        const self = resolve(ptr);
        return .{
            .board_name = self.peripheral_name,
            .board_type = self.board_type_str,
            .has_serial = true,
            .has_gpio = true,
        };
    }
};

// ── ArduinoPeripheral ───────────────────────────────────────────

/// Arduino peripheral: detect boards via serial, upload sketches via arduino-cli.
pub const ArduinoPeripheral = struct {
    peripheral_name: []const u8,
    port_path: []const u8,
    baud_rate: u32,
    fqbn: []const u8 = "arduino:avr:uno",
    connected: bool = false,
    serial_file: ?std.fs.File = null,
    msg_id: u32 = 0,

    const arduino_vtable = Peripheral.VTable{
        .name = arduinoName,
        .board_type = arduinoBoardType,
        .health_check = arduinoHealthCheck,
        .init_peripheral = arduinoInit,
        .read = arduinoRead,
        .write = arduinoWrite,
        .flash = arduinoFlash,
        .capabilities = arduinoCapabilities,
    };

    pub fn create(port_path: []const u8, baud: u32) ArduinoPeripheral {
        return .{
            .peripheral_name = "arduino-uno",
            .port_path = port_path,
            .baud_rate = baud,
        };
    }

    pub fn peripheral(self: *ArduinoPeripheral) Peripheral {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &arduino_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *ArduinoPeripheral {
        return @ptrCast(@alignCast(ptr));
    }

    fn arduinoName(ptr: *anyopaque) []const u8 {
        return resolve(ptr).peripheral_name;
    }

    fn arduinoBoardType(_: *anyopaque) []const u8 {
        return "arduino-uno";
    }

    fn arduinoHealthCheck(ptr: *anyopaque) bool {
        return resolve(ptr).connected;
    }

    fn arduinoInit(ptr: *anyopaque) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        // Detect Arduino by running arduino-cli board list and checking for the port.
        var child = std.process.Child.init(
            &.{ "arduino-cli", "board", "list" },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch {
            self.connected = false;
            return Peripheral.PeripheralError.DeviceNotFound;
        };
        // Read stdout to check if our port is listed
        const stdout = if (child.stdout) |*out| out.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch null else null;
        defer if (stdout) |s| std.heap.page_allocator.free(s);
        const term = child.wait() catch {
            self.connected = false;
            return Peripheral.PeripheralError.DeviceNotFound;
        };
        const exited_ok = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!exited_ok) {
            self.connected = false;
            return Peripheral.PeripheralError.DeviceNotFound;
        }
        // Check if our port appears in the output
        if (stdout) |s| {
            if (std.mem.indexOf(u8, s, self.port_path) != null) {
                self.connected = true;
                // Open serial port for read/write communication
                if (isSerialPathAllowed(self.port_path)) {
                    const file = std.fs.openFileAbsolute(self.port_path, .{ .mode = .read_write }) catch return;
                    self.serial_file = file;
                }
                return;
            }
        }
        // Port not found in listing but arduino-cli exists; mark connected anyway
        // since the board may not be detected but port may still be valid.
        self.connected = true;

        // Open serial port for read/write communication
        if (isSerialPathAllowed(self.port_path)) {
            const file = std.fs.openFileAbsolute(self.port_path, .{ .mode = .read_write }) catch {
                // Board detected but serial port not accessible — still mark connected
                return;
            };
            self.serial_file = file;
        }
    }

    fn arduinoRead(ptr: *anyopaque, addr: u32) Peripheral.PeripheralError!u8 {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        const file = self.serial_file orelse return Peripheral.PeripheralError.NotConnected;

        // Build JSON command: {"id":"N","cmd":"gpio_read","args":{"pin":PIN}}
        self.msg_id +%= 1;
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "{{\"id\":\"{d}\",\"cmd\":\"gpio_read\",\"args\":{{\"pin\":{d}}}}}\n", .{ self.msg_id, addr }) catch
            return Peripheral.PeripheralError.IoError;

        file.writeAll(cmd) catch return Peripheral.PeripheralError.IoError;

        // Read response (newline-delimited JSON)
        var resp_buf: [512]u8 = undefined;
        const n = file.read(&resp_buf) catch return Peripheral.PeripheralError.IoError;
        if (n == 0) return Peripheral.PeripheralError.Timeout;

        return SerialPeripheral.parseResultValue(resp_buf[0..n]);
    }

    fn arduinoWrite(ptr: *anyopaque, addr: u32, data: u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        const file = self.serial_file orelse return Peripheral.PeripheralError.NotConnected;

        // Build JSON command: {"id":"N","cmd":"gpio_write","args":{"pin":PIN,"value":VALUE}}
        self.msg_id +%= 1;
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "{{\"id\":\"{d}\",\"cmd\":\"gpio_write\",\"args\":{{\"pin\":{d},\"value\":{d}}}}}\n", .{ self.msg_id, addr, data }) catch
            return Peripheral.PeripheralError.IoError;

        file.writeAll(cmd) catch return Peripheral.PeripheralError.IoError;

        // Read and verify response
        var resp_buf: [512]u8 = undefined;
        const n = file.read(&resp_buf) catch return Peripheral.PeripheralError.IoError;
        if (n == 0) return Peripheral.PeripheralError.Timeout;

        // Verify "ok":true in response
        if (std.mem.indexOf(u8, resp_buf[0..n], "\"ok\":true") == null) {
            return Peripheral.PeripheralError.IoError;
        }
    }

    fn arduinoFlash(ptr: *anyopaque, firmware_path: []const u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        if (firmware_path.len == 0) return Peripheral.PeripheralError.FlashFailed;

        // Step 1: Compile the sketch
        var compile_child = std.process.Child.init(
            &.{ "arduino-cli", "compile", "--fqbn", self.fqbn, firmware_path },
            std.heap.page_allocator,
        );
        compile_child.stdout_behavior = .Ignore;
        compile_child.stderr_behavior = .Pipe;
        compile_child.spawn() catch return Peripheral.PeripheralError.FlashFailed;
        // Drain stderr to avoid pipe deadlock
        if (compile_child.stderr) |*err_pipe| {
            _ = err_pipe.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch {};
        }
        const compile_term = compile_child.wait() catch return Peripheral.PeripheralError.FlashFailed;
        const compile_ok = switch (compile_term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!compile_ok) return Peripheral.PeripheralError.FlashFailed;

        // Step 2: Upload to the board
        var upload_child = std.process.Child.init(
            &.{ "arduino-cli", "upload", "-p", self.port_path, "--fqbn", self.fqbn, firmware_path },
            std.heap.page_allocator,
        );
        upload_child.stdout_behavior = .Ignore;
        upload_child.stderr_behavior = .Pipe;
        upload_child.spawn() catch return Peripheral.PeripheralError.FlashFailed;
        if (upload_child.stderr) |*err_pipe| {
            _ = err_pipe.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch {};
        }
        const upload_term = upload_child.wait() catch return Peripheral.PeripheralError.FlashFailed;
        const upload_ok = switch (upload_term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!upload_ok) return Peripheral.PeripheralError.FlashFailed;
    }

    fn arduinoCapabilities(ptr: *anyopaque) PeripheralCapabilities {
        const self = resolve(ptr);
        return .{
            .board_name = self.peripheral_name,
            .board_type = "arduino-uno",
            .has_serial = true,
            .has_gpio = true,
            .has_flash = true,
            .flash_size_kb = 32, // ATmega328P
        };
    }

    /// Check if arduino-cli is available on the system.
    pub fn isArduinoCliAvailable() bool {
        var child = std.process.Child.init(
            &.{ "arduino-cli", "version" },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return false;
        const term = child.wait() catch return false;
        return switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
    }
};

// ── RpiGpioPeripheral ───────────────────────────────────────────

/// Raspberry Pi GPIO peripheral using sysfs interface.
/// Uses /sys/class/gpio/export, direction, value for pin access.
pub const RpiGpioPeripheral = struct {
    connected: bool = false,
    exported_pins: [64]bool = [_]bool{false} ** 64,

    const rpi_vtable = Peripheral.VTable{
        .name = rpiName,
        .board_type = rpiBoardType,
        .health_check = rpiHealthCheck,
        .init_peripheral = rpiInit,
        .read = rpiRead,
        .write = rpiWrite,
        .flash = rpiFlash,
        .capabilities = rpiCapabilities,
    };

    pub fn create() RpiGpioPeripheral {
        return .{};
    }

    pub fn peripheral(self: *RpiGpioPeripheral) Peripheral {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &rpi_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *RpiGpioPeripheral {
        return @ptrCast(@alignCast(ptr));
    }

    fn rpiName(_: *anyopaque) []const u8 {
        return "rpi-gpio";
    }

    fn rpiBoardType(_: *anyopaque) []const u8 {
        return "rpi-gpio";
    }

    fn rpiHealthCheck(ptr: *anyopaque) bool {
        return resolve(ptr).connected;
    }

    fn rpiInit(ptr: *anyopaque) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (comptime builtin.os.tag != .linux) {
            return Peripheral.PeripheralError.UnsupportedOperation;
        }
        // Check that /sys/class/gpio exists (Linux sysfs GPIO interface)
        std.fs.openDirAbsolute("/sys/class/gpio", .{}) catch {
            self.connected = false;
            return Peripheral.PeripheralError.DeviceNotFound;
        };
        self.connected = true;
    }

    fn rpiRead(ptr: *anyopaque, addr: u32) Peripheral.PeripheralError!u8 {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        if (addr >= 64) return Peripheral.PeripheralError.InvalidAddress;

        if (comptime builtin.os.tag == .linux) {
            // 1. Export pin (ignore error if already exported)
            rpiExportPin(addr);
            // 2. Set direction to "in"
            var dir_path_buf: [64]u8 = undefined;
            const dir_path = std.fmt.bufPrint(&dir_path_buf, "/sys/class/gpio/gpio{d}/direction", .{addr}) catch
                return Peripheral.PeripheralError.IoError;
            rpiWriteFile(dir_path, "in") catch return Peripheral.PeripheralError.IoError;
            // 3. Read value from /sys/class/gpio/gpioN/value
            var val_path_buf: [64]u8 = undefined;
            const val_path = std.fmt.bufPrint(&val_path_buf, "/sys/class/gpio/gpio{d}/value", .{addr}) catch
                return Peripheral.PeripheralError.IoError;
            const val = rpiReadFile(val_path) catch return Peripheral.PeripheralError.IoError;
            self.exported_pins[addr] = true;
            return val;
        } else {
            return Peripheral.PeripheralError.UnsupportedOperation;
        }
    }

    fn rpiWrite(ptr: *anyopaque, addr: u32, data: u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;
        if (addr >= 64) return Peripheral.PeripheralError.InvalidAddress;

        if (comptime builtin.os.tag == .linux) {
            // 1. Export pin (ignore error if already exported)
            rpiExportPin(addr);
            // 2. Set direction to "out"
            var dir_path_buf: [64]u8 = undefined;
            const dir_path = std.fmt.bufPrint(&dir_path_buf, "/sys/class/gpio/gpio{d}/direction", .{addr}) catch
                return Peripheral.PeripheralError.IoError;
            rpiWriteFile(dir_path, "out") catch return Peripheral.PeripheralError.IoError;
            // 3. Write value to /sys/class/gpio/gpioN/value
            var val_path_buf: [64]u8 = undefined;
            const val_path = std.fmt.bufPrint(&val_path_buf, "/sys/class/gpio/gpio{d}/value", .{addr}) catch
                return Peripheral.PeripheralError.IoError;
            const val_str: []const u8 = if (data != 0) "1" else "0";
            rpiWriteFile(val_path, val_str) catch return Peripheral.PeripheralError.IoError;
            self.exported_pins[addr] = true;
        } else {
            return Peripheral.PeripheralError.UnsupportedOperation;
        }
    }

    /// Export a GPIO pin via sysfs. Ignores errors (pin may already be exported).
    fn rpiExportPin(pin: u32) void {
        var pin_buf: [8]u8 = undefined;
        const pin_str = std.fmt.bufPrint(&pin_buf, "{d}", .{pin}) catch return;
        const export_file = std.fs.openFileAbsolute("/sys/class/gpio/export", .{ .mode = .write_only }) catch return;
        defer export_file.close();
        export_file.writeAll(pin_str) catch {};
    }

    /// Write a string to a sysfs file.
    fn rpiWriteFile(path: []const u8, value: []const u8) !void {
        const file = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch return error.IoError;
        defer file.close();
        file.writeAll(value) catch return error.IoError;
    }

    /// Read a GPIO value (0 or 1) from a sysfs value file.
    fn rpiReadFile(path: []const u8) !u8 {
        const file = std.fs.openFileAbsolute(path, .{}) catch return error.IoError;
        defer file.close();
        var buf: [4]u8 = undefined;
        const n = file.read(&buf) catch return error.IoError;
        if (n == 0) return error.IoError;
        if (buf[0] == '1') return 1;
        return 0;
    }

    fn rpiFlash(_: *anyopaque, _: []const u8) Peripheral.PeripheralError!void {
        return Peripheral.PeripheralError.UnsupportedOperation;
    }

    fn rpiCapabilities(_: *anyopaque) PeripheralCapabilities {
        return .{
            .board_name = "rpi-gpio",
            .board_type = "rpi-gpio",
            .gpio_pins = "2-27",
            .has_gpio = true,
        };
    }

    /// Format a GPIO pin state as a human-readable string.
    pub fn gpioStateString(value: u8) []const u8 {
        return if (value == 0) "LOW" else "HIGH";
    }
};

// ── NucleoFlash ─────────────────────────────────────────────────

/// STM32 Nucleo board flash utility via probe-rs.
pub const NucleoFlash = struct {
    chip: []const u8,
    target: []const u8,
    connected: bool = false,

    const nucleo_vtable = Peripheral.VTable{
        .name = nucleoName,
        .board_type = nucleoBoardType,
        .health_check = nucleoHealthCheck,
        .init_peripheral = nucleoInit,
        .read = nucleoRead,
        .write = nucleoWrite,
        .flash = nucleoFlash,
        .capabilities = nucleoCapabilities,
    };

    pub fn create(chip: []const u8) NucleoFlash {
        return .{
            .chip = chip,
            .target = "thumbv7em-none-eabihf",
        };
    }

    pub fn createF401() NucleoFlash {
        return create("STM32F401RETx");
    }

    pub fn createF411() NucleoFlash {
        return create("STM32F411RETx");
    }

    pub fn peripheral(self: *NucleoFlash) Peripheral {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &nucleo_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *NucleoFlash {
        return @ptrCast(@alignCast(ptr));
    }

    fn nucleoName(ptr: *anyopaque) []const u8 {
        return resolve(ptr).chip;
    }

    fn nucleoBoardType(_: *anyopaque) []const u8 {
        return "nucleo";
    }

    fn nucleoHealthCheck(ptr: *anyopaque) bool {
        return resolve(ptr).connected;
    }

    fn nucleoInit(ptr: *anyopaque) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        // Verify a debug probe is connected via probe-rs list
        var child = std.process.Child.init(
            &.{ "probe-rs", "list" },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch {
            self.connected = false;
            return Peripheral.PeripheralError.NotConnected;
        };
        const stdout = if (child.stdout) |*out| out.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch null else null;
        defer if (stdout) |s| std.heap.page_allocator.free(s);
        const term = child.wait() catch {
            self.connected = false;
            return Peripheral.PeripheralError.NotConnected;
        };
        const exited_ok = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!exited_ok) {
            self.connected = false;
            return Peripheral.PeripheralError.NotConnected;
        }
        // Check if any probes were found (non-empty output with probe info)
        if (stdout) |s| {
            // probe-rs list outputs nothing or "No probes found" when no probes connected
            if (s.len == 0 or std.mem.indexOf(u8, s, "No probes found") != null) {
                self.connected = false;
                return Peripheral.PeripheralError.NotConnected;
            }
        } else {
            self.connected = false;
            return Peripheral.PeripheralError.NotConnected;
        }
        self.connected = true;
    }

    fn nucleoRead(ptr: *anyopaque, addr: u32) Peripheral.PeripheralError!u8 {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;

        // Format address as hex string for probe-rs
        var addr_buf: [16]u8 = undefined;
        const addr_hex = std.fmt.bufPrint(&addr_buf, "0x{X}", .{addr}) catch
            return Peripheral.PeripheralError.IoError;

        // Run: probe-rs read b8 <addr> --chip CHIP
        var child = std.process.Child.init(
            &.{ "probe-rs", "read", "b8", addr_hex, "--chip", self.chip },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return Peripheral.PeripheralError.IoError;
        const stdout = if (child.stdout) |*out| out.readToEndAlloc(std.heap.page_allocator, 4096) catch null else null;
        defer if (stdout) |s| std.heap.page_allocator.free(s);
        const term = child.wait() catch return Peripheral.PeripheralError.IoError;
        const exited_ok = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!exited_ok) return Peripheral.PeripheralError.IoError;

        // Parse the output — probe-rs read outputs hex bytes
        const output = stdout orelse return Peripheral.PeripheralError.IoError;
        const trimmed = std.mem.trim(u8, output, " \t\r\n");
        if (trimmed.len == 0) return Peripheral.PeripheralError.IoError;
        return std.fmt.parseInt(u8, trimmed, 0) catch return Peripheral.PeripheralError.IoError;
    }

    fn nucleoWrite(ptr: *anyopaque, addr: u32, data: u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (!self.connected) return Peripheral.PeripheralError.NotConnected;

        // Format address and data as hex strings for probe-rs
        var addr_buf: [16]u8 = undefined;
        const addr_hex = std.fmt.bufPrint(&addr_buf, "0x{X}", .{addr}) catch
            return Peripheral.PeripheralError.IoError;
        var data_buf: [8]u8 = undefined;
        const data_str = std.fmt.bufPrint(&data_buf, "0x{X}", .{data}) catch
            return Peripheral.PeripheralError.IoError;

        // Run: probe-rs write b8 <addr> <data> --chip CHIP
        var child = std.process.Child.init(
            &.{ "probe-rs", "write", "b8", addr_hex, data_str, "--chip", self.chip },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Pipe;
        child.spawn() catch return Peripheral.PeripheralError.IoError;
        // Drain stderr to avoid pipe deadlock
        if (child.stderr) |*err_pipe| {
            _ = err_pipe.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch {};
        }
        const term = child.wait() catch return Peripheral.PeripheralError.IoError;
        const exited_ok = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!exited_ok) return Peripheral.PeripheralError.IoError;
    }

    fn nucleoFlash(ptr: *anyopaque, firmware_path: []const u8) Peripheral.PeripheralError!void {
        const self = resolve(ptr);
        if (firmware_path.len == 0) return Peripheral.PeripheralError.FlashFailed;

        // Run: probe-rs run --chip CHIP firmware_path
        var child = std.process.Child.init(
            &.{ "probe-rs", "run", "--chip", self.chip, firmware_path },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.spawn() catch return Peripheral.PeripheralError.FlashFailed;
        // Drain pipes to avoid deadlock
        if (child.stdout) |*out| {
            _ = out.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch {};
        }
        if (child.stderr) |*err_pipe| {
            _ = err_pipe.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch {};
        }
        const term = child.wait() catch return Peripheral.PeripheralError.FlashFailed;
        const ok = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!ok) return Peripheral.PeripheralError.FlashFailed;
    }

    fn nucleoCapabilities(ptr: *anyopaque) PeripheralCapabilities {
        const self = resolve(ptr);
        return .{
            .board_name = self.chip,
            .board_type = "nucleo",
            .has_serial = true,
            .has_gpio = true,
            .has_flash = true,
            .flash_size_kb = 512,
        };
    }

    /// Check if probe-rs is available on the system.
    pub fn isProbeRsAvailable() bool {
        var child = std.process.Child.init(
            &.{ "probe-rs", "--version" },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return false;
        const term = child.wait() catch return false;
        return switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
    }
};

// ── GPIO Tool Helpers ───────────────────────────────────────────

/// Result of a GPIO read operation.
pub const GpioReadResult = struct {
    pin: u32,
    value: u8,

    pub fn stateString(self: GpioReadResult) []const u8 {
        return if (self.value == 0) "LOW" else "HIGH";
    }
};

/// Result of a GPIO write operation.
pub const GpioWriteResult = struct {
    pin: u32,
    value: u8,
    success: bool,
};

/// Read a GPIO pin via a peripheral. Returns "HIGH" or "LOW".
pub fn gpioRead(p: Peripheral, pin: u32) Peripheral.PeripheralError!GpioReadResult {
    const value = try p.read(pin);
    return GpioReadResult{ .pin = pin, .value = value };
}

/// Write a GPIO pin via a peripheral.
pub fn gpioWrite(p: Peripheral, pin: u32, high: bool) Peripheral.PeripheralError!GpioWriteResult {
    const value: u8 = if (high) 1 else 0;
    try p.writeByte(pin, value);
    return GpioWriteResult{ .pin = pin, .value = value, .success = true };
}

// ── Board Listing ───────────────────────────────────────────────

/// Supported board types that can be configured as peripherals.
pub const SupportedBoard = enum {
    nucleo_f401re,
    nucleo_f411re,
    arduino_uno,
    arduino_uno_q,
    arduino_mega,
    esp32,
    rpi_gpio,

    pub fn displayName(self: SupportedBoard) []const u8 {
        return switch (self) {
            .nucleo_f401re => "nucleo-f401re",
            .nucleo_f411re => "nucleo-f411re",
            .arduino_uno => "arduino-uno",
            .arduino_uno_q => "arduino-uno-q",
            .arduino_mega => "arduino-mega",
            .esp32 => "esp32",
            .rpi_gpio => "rpi-gpio",
        };
    }

    pub fn defaultTransport(self: SupportedBoard) []const u8 {
        return switch (self) {
            .rpi_gpio => "native",
            .arduino_uno_q => "bridge",
            else => "serial",
        };
    }

    pub fn fromString(board_name: []const u8) ?SupportedBoard {
        const map = [_]struct { n: []const u8, b: SupportedBoard }{
            .{ .n = "nucleo-f401re", .b = .nucleo_f401re },
            .{ .n = "nucleo-f411re", .b = .nucleo_f411re },
            .{ .n = "arduino-uno", .b = .arduino_uno },
            .{ .n = "arduino-uno-q", .b = .arduino_uno_q },
            .{ .n = "uno-q", .b = .arduino_uno_q },
            .{ .n = "arduino-mega", .b = .arduino_mega },
            .{ .n = "esp32", .b = .esp32 },
            .{ .n = "rpi-gpio", .b = .rpi_gpio },
            .{ .n = "raspberry-pi", .b = .rpi_gpio },
        };
        for (map) |entry| {
            if (std.mem.eql(u8, board_name, entry.n)) return entry.b;
        }
        return null;
    }

    pub fn all() []const SupportedBoard {
        return &.{
            .nucleo_f401re,
            .nucleo_f411re,
            .arduino_uno,
            .arduino_uno_q,
            .arduino_mega,
            .esp32,
            .rpi_gpio,
        };
    }

    /// Get default capabilities for a board type.
    pub fn defaultCapabilities(self: SupportedBoard) PeripheralCapabilities {
        return switch (self) {
            .nucleo_f401re => .{
                .board_name = "nucleo-f401re",
                .board_type = "nucleo",
                .gpio_pins = "PA0-PA15,PB0-PB15,PC0-PC15",
                .flash_size_kb = 512,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
                .has_adc = true,
            },
            .nucleo_f411re => .{
                .board_name = "nucleo-f411re",
                .board_type = "nucleo",
                .gpio_pins = "PA0-PA15,PB0-PB15,PC0-PC15",
                .flash_size_kb = 512,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
                .has_adc = true,
            },
            .arduino_uno => .{
                .board_name = "arduino-uno",
                .board_type = "arduino",
                .gpio_pins = "D0-D13,A0-A5",
                .flash_size_kb = 32,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
                .has_adc = true,
            },
            .arduino_uno_q => .{
                .board_name = "arduino-uno-q",
                .board_type = "arduino",
                .gpio_pins = "D0-D13,A0-A5",
                .flash_size_kb = 32,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
            },
            .arduino_mega => .{
                .board_name = "arduino-mega",
                .board_type = "arduino",
                .gpio_pins = "D0-D53,A0-A15",
                .flash_size_kb = 256,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
                .has_adc = true,
            },
            .esp32 => .{
                .board_name = "esp32",
                .board_type = "esp32",
                .gpio_pins = "GPIO0-GPIO39",
                .flash_size_kb = 4096,
                .has_serial = true,
                .has_gpio = true,
                .has_flash = true,
                .has_adc = true,
            },
            .rpi_gpio => .{
                .board_name = "rpi-gpio",
                .board_type = "rpi-gpio",
                .gpio_pins = "2-27",
                .has_gpio = true,
            },
        };
    }
};

/// List configured boards from config. Returns empty if peripherals disabled.
pub fn listConfiguredBoards(peripherals_config: config.PeripheralsConfig) []const u8 {
    if (!peripherals_config.enabled) {
        return "No peripherals configured";
    }
    return "Peripherals enabled";
}

/// Check if a board name is recognized.
pub fn isKnownBoard(board_name: []const u8) bool {
    return SupportedBoard.fromString(board_name) != null;
}

/// Validate a board transport string.
pub fn isValidTransport(transport: []const u8) bool {
    const valid = [_][]const u8{ "serial", "native", "bridge", "probe" };
    for (valid) |v| {
        if (std.mem.eql(u8, transport, v)) return true;
    }
    return false;
}

/// Validate a baud rate.
pub fn isValidBaudRate(baud: u32) bool {
    const valid_rates = [_]u32{ 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600 };
    for (valid_rates) |rate| {
        if (baud == rate) return true;
    }
    return false;
}

/// Create peripheral tool count from config.
/// Returns 0 when peripherals are disabled (no hardware feature linked).
pub fn createPeripheralToolCount(peripherals_config: config.PeripheralsConfig) usize {
    if (!peripherals_config.enabled) return 0;
    // Each connected board contributes gpio_read + gpio_write tools
    return 2;
}

// ── Tests ───────────────────────────────────────────────────────

test "SupportedBoard.fromString finds nucleo-f401re" {
    const board = SupportedBoard.fromString("nucleo-f401re");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.nucleo_f401re, board.?);
}

test "SupportedBoard.fromString finds nucleo-f411re" {
    const board = SupportedBoard.fromString("nucleo-f411re");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.nucleo_f411re, board.?);
}

test "SupportedBoard.fromString finds arduino-uno" {
    const board = SupportedBoard.fromString("arduino-uno");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.arduino_uno, board.?);
}

test "SupportedBoard.fromString finds arduino-uno-q" {
    const board = SupportedBoard.fromString("arduino-uno-q");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.arduino_uno_q, board.?);
}

test "SupportedBoard.fromString finds uno-q alias" {
    const board = SupportedBoard.fromString("uno-q");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.arduino_uno_q, board.?);
}

test "SupportedBoard.fromString finds esp32" {
    const board = SupportedBoard.fromString("esp32");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.esp32, board.?);
}

test "SupportedBoard.fromString finds rpi-gpio" {
    const board = SupportedBoard.fromString("rpi-gpio");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.rpi_gpio, board.?);
}

test "SupportedBoard.fromString finds raspberry-pi alias" {
    const board = SupportedBoard.fromString("raspberry-pi");
    try std.testing.expect(board != null);
    try std.testing.expectEqual(SupportedBoard.rpi_gpio, board.?);
}

test "SupportedBoard.fromString returns null for unknown" {
    try std.testing.expect(SupportedBoard.fromString("unknown-board") == null);
}

test "SupportedBoard.displayName" {
    try std.testing.expectEqualStrings("nucleo-f401re", SupportedBoard.nucleo_f401re.displayName());
    try std.testing.expectEqualStrings("arduino-uno", SupportedBoard.arduino_uno.displayName());
    try std.testing.expectEqualStrings("rpi-gpio", SupportedBoard.rpi_gpio.displayName());
}

test "SupportedBoard.defaultTransport" {
    try std.testing.expectEqualStrings("serial", SupportedBoard.nucleo_f401re.defaultTransport());
    try std.testing.expectEqualStrings("serial", SupportedBoard.arduino_uno.defaultTransport());
    try std.testing.expectEqualStrings("native", SupportedBoard.rpi_gpio.defaultTransport());
    try std.testing.expectEqualStrings("bridge", SupportedBoard.arduino_uno_q.defaultTransport());
}

test "SupportedBoard.all returns all boards" {
    try std.testing.expectEqual(@as(usize, 7), SupportedBoard.all().len);
}

test "isKnownBoard recognizes valid boards" {
    try std.testing.expect(isKnownBoard("nucleo-f401re"));
    try std.testing.expect(isKnownBoard("arduino-uno"));
    try std.testing.expect(isKnownBoard("esp32"));
    try std.testing.expect(isKnownBoard("rpi-gpio"));
}

test "isKnownBoard rejects unknown" {
    try std.testing.expect(!isKnownBoard("banana-board"));
    try std.testing.expect(!isKnownBoard(""));
}

test "isValidTransport accepts valid transports" {
    try std.testing.expect(isValidTransport("serial"));
    try std.testing.expect(isValidTransport("native"));
    try std.testing.expect(isValidTransport("bridge"));
    try std.testing.expect(isValidTransport("probe"));
}

test "isValidTransport rejects unknown" {
    try std.testing.expect(!isValidTransport("wireless"));
    try std.testing.expect(!isValidTransport(""));
}

test "isValidBaudRate accepts common rates" {
    try std.testing.expect(isValidBaudRate(9600));
    try std.testing.expect(isValidBaudRate(115200));
    try std.testing.expect(isValidBaudRate(921600));
}

test "isValidBaudRate rejects uncommon rates" {
    try std.testing.expect(!isValidBaudRate(0));
    try std.testing.expect(!isValidBaudRate(12345));
}

test "listConfiguredBoards disabled" {
    const cfg = config.PeripheralsConfig{};
    try std.testing.expectEqualStrings("No peripherals configured", listConfiguredBoards(cfg));
}

test "listConfiguredBoards enabled" {
    const cfg = config.PeripheralsConfig{ .enabled = true };
    try std.testing.expectEqualStrings("Peripherals enabled", listConfiguredBoards(cfg));
}

test "createPeripheralToolCount disabled returns 0" {
    const cfg = config.PeripheralsConfig{};
    try std.testing.expectEqual(@as(usize, 0), createPeripheralToolCount(cfg));
}

test "createPeripheralToolCount enabled returns 2" {
    const cfg = config.PeripheralsConfig{ .enabled = true };
    try std.testing.expectEqual(@as(usize, 2), createPeripheralToolCount(cfg));
}

test "PeripheralBoardConfig defaults" {
    const board_cfg = config.PeripheralBoardConfig{};
    try std.testing.expectEqualStrings("", board_cfg.board);
    try std.testing.expectEqualStrings("serial", board_cfg.transport);
    try std.testing.expect(board_cfg.path == null);
    try std.testing.expectEqual(@as(u32, 115200), board_cfg.baud);
}

// ── Peripheral vtable tests ─────────────────────────────────────

test "SerialPeripheral create rejects disallowed path" {
    const result = SerialPeripheral.create("/etc/passwd", "test", 115200);
    try std.testing.expectError(Peripheral.PeripheralError.PermissionDenied, result);
}

test "SerialPeripheral vtable dispatches correctly" {
    var serial = SerialPeripheral{
        .peripheral_name = "test-serial",
        .board_type_str = "nucleo-f401re",
        .port_path = "/dev/ttyACM0",
        .baud_rate = 115200,
        .connected = true,
    };
    const p = serial.peripheral();
    try std.testing.expectEqualStrings("test-serial", p.name());
    try std.testing.expectEqualStrings("nucleo-f401re", p.boardType());
    try std.testing.expect(p.healthCheck());
    const caps = p.getCapabilities();
    try std.testing.expect(caps.has_serial);
    try std.testing.expect(caps.has_gpio);
}

test "SerialPeripheral read fails when not connected" {
    var serial = SerialPeripheral{
        .peripheral_name = "test",
        .board_type_str = "test",
        .port_path = "/dev/ttyACM0",
        .baud_rate = 115200,
        .connected = false,
    };
    const p = serial.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.NotConnected, p.read(0));
}

test "ArduinoPeripheral vtable works" {
    var arduino = ArduinoPeripheral.create("/dev/cu.usbmodem0001", 115200);
    const p = arduino.peripheral();
    try std.testing.expectEqualStrings("arduino-uno", p.name());
    try std.testing.expectEqualStrings("arduino-uno", p.boardType());
    try std.testing.expect(!p.healthCheck());
    const caps = p.getCapabilities();
    try std.testing.expect(caps.has_flash);
    try std.testing.expectEqual(@as(u32, 32), caps.flash_size_kb);
}

test "ArduinoPeripheral flash fails when not connected" {
    var arduino = ArduinoPeripheral.create("/dev/cu.usbmodem0001", 115200);
    const p = arduino.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.NotConnected, p.flashFirmware("test.ino"));
}

test "RpiGpioPeripheral vtable works" {
    var rpi = RpiGpioPeripheral.create();
    const p = rpi.peripheral();
    try std.testing.expectEqualStrings("rpi-gpio", p.name());
    try std.testing.expectEqualStrings("rpi-gpio", p.boardType());
    try std.testing.expect(!p.healthCheck());
    const caps = p.getCapabilities();
    try std.testing.expect(caps.has_gpio);
    try std.testing.expect(!caps.has_flash);
}

test "RpiGpioPeripheral read fails when not connected" {
    var rpi = RpiGpioPeripheral.create();
    const p = rpi.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.NotConnected, p.read(17));
}

test "RpiGpioPeripheral invalid address" {
    var rpi = RpiGpioPeripheral.create();
    rpi.connected = true;
    const p = rpi.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.InvalidAddress, p.read(100));
}

test "RpiGpioPeripheral flash not supported" {
    var rpi = RpiGpioPeripheral.create();
    const p = rpi.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.UnsupportedOperation, p.flashFirmware("test"));
}

test "RpiGpioPeripheral.gpioStateString" {
    try std.testing.expectEqualStrings("LOW", RpiGpioPeripheral.gpioStateString(0));
    try std.testing.expectEqualStrings("HIGH", RpiGpioPeripheral.gpioStateString(1));
    try std.testing.expectEqualStrings("HIGH", RpiGpioPeripheral.gpioStateString(255));
}

test "NucleoFlash vtable works" {
    var nucleo = NucleoFlash.createF401();
    const p = nucleo.peripheral();
    try std.testing.expectEqualStrings("STM32F401RETx", p.name());
    try std.testing.expectEqualStrings("nucleo", p.boardType());
    try std.testing.expect(!p.healthCheck());
    const caps = p.getCapabilities();
    try std.testing.expect(caps.has_flash);
    try std.testing.expectEqual(@as(u32, 512), caps.flash_size_kb);
}

test "NucleoFlash F411 creation" {
    const nucleo = NucleoFlash.createF411();
    try std.testing.expectEqualStrings("STM32F411RETx", nucleo.chip);
}

test "NucleoFlash read fails when not connected" {
    var nucleo = NucleoFlash.createF401();
    const p = nucleo.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.NotConnected, p.read(0));
}

test "NucleoFlash flash with empty path fails" {
    var nucleo = NucleoFlash.createF401();
    nucleo.connected = true;
    const p = nucleo.peripheral();
    try std.testing.expectError(Peripheral.PeripheralError.FlashFailed, p.flashFirmware(""));
}

// ── GPIO tool helper tests ──────────────────────────────────────

test "gpioRead returns result with state" {
    var rpi = RpiGpioPeripheral.create();
    rpi.connected = true;
    const p = rpi.peripheral();
    if (comptime builtin.os.tag == .linux) {
        const result = try gpioRead(p, 17);
        try std.testing.expectEqual(@as(u32, 17), result.pin);
        try std.testing.expectEqualStrings("LOW", result.stateString());
    } else {
        try std.testing.expectError(Peripheral.PeripheralError.UnsupportedOperation, gpioRead(p, 17));
    }
}

test "gpioWrite returns success" {
    var rpi = RpiGpioPeripheral.create();
    rpi.connected = true;
    const p = rpi.peripheral();
    if (comptime builtin.os.tag == .linux) {
        const result = try gpioWrite(p, 17, true);
        try std.testing.expectEqual(@as(u32, 17), result.pin);
        try std.testing.expectEqual(@as(u8, 1), result.value);
        try std.testing.expect(result.success);
    } else {
        try std.testing.expectError(Peripheral.PeripheralError.UnsupportedOperation, gpioWrite(p, 17, true));
    }
}

// ── Serial path security tests ──────────────────────────────────

test "isSerialPathAllowed accepts valid paths" {
    try std.testing.expect(isSerialPathAllowed("/dev/ttyACM0"));
    try std.testing.expect(isSerialPathAllowed("/dev/ttyUSB0"));
    try std.testing.expect(isSerialPathAllowed("/dev/tty.usbmodem1234"));
    try std.testing.expect(isSerialPathAllowed("/dev/cu.usbmodem5678"));
    try std.testing.expect(isSerialPathAllowed("/dev/cu.usbserial-1234"));
}

test "isSerialPathAllowed rejects invalid paths" {
    try std.testing.expect(!isSerialPathAllowed("/etc/passwd"));
    try std.testing.expect(!isSerialPathAllowed("/dev/sda"));
    try std.testing.expect(!isSerialPathAllowed("/tmp/evil"));
    try std.testing.expect(!isSerialPathAllowed(""));
}

// ── Board capabilities tests ────────────────────────────────────

test "SupportedBoard.defaultCapabilities for nucleo" {
    const caps = SupportedBoard.nucleo_f401re.defaultCapabilities();
    try std.testing.expect(caps.has_gpio);
    try std.testing.expect(caps.has_flash);
    try std.testing.expect(caps.has_serial);
    try std.testing.expect(caps.has_adc);
    try std.testing.expectEqual(@as(u32, 512), caps.flash_size_kb);
}

test "SupportedBoard.defaultCapabilities for arduino" {
    const caps = SupportedBoard.arduino_uno.defaultCapabilities();
    try std.testing.expect(caps.has_gpio);
    try std.testing.expect(caps.has_flash);
    try std.testing.expectEqual(@as(u32, 32), caps.flash_size_kb);
}

test "SupportedBoard.defaultCapabilities for rpi" {
    const caps = SupportedBoard.rpi_gpio.defaultCapabilities();
    try std.testing.expect(caps.has_gpio);
    try std.testing.expect(!caps.has_flash);
    try std.testing.expectEqual(@as(u32, 0), caps.flash_size_kb);
}

test "SupportedBoard.defaultCapabilities for esp32" {
    const caps = SupportedBoard.esp32.defaultCapabilities();
    try std.testing.expect(caps.has_gpio);
    try std.testing.expect(caps.has_flash);
    try std.testing.expectEqual(@as(u32, 4096), caps.flash_size_kb);
}

test "PeripheralCapabilities defaults" {
    const caps = PeripheralCapabilities{};
    try std.testing.expect(!caps.has_serial);
    try std.testing.expect(!caps.has_gpio);
    try std.testing.expect(!caps.has_flash);
    try std.testing.expect(!caps.has_adc);
    try std.testing.expectEqual(@as(u32, 0), caps.flash_size_kb);
}
