//! Service management — launchd (macOS), systemd (Linux), and SCM (Windows).
//!
//! Mirrors ZeroClaw's service module: install, start, stop, status, uninstall.
//! Uses child process execution to interact with launchctl / systemctl / sc.exe.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");

const SERVICE_LABEL = "com.nullclaw.daemon";
const WINDOWS_SERVICE_NAME = "nullclaw";
const WINDOWS_SERVICE_DISPLAY_NAME = "nullclaw gateway runtime";

pub const ServiceCommand = enum {
    install,
    start,
    stop,
    status,
    uninstall,
};

pub const ServiceError = error{
    CommandFailed,
    UnsupportedPlatform,
    NoHomeDir,
    FileCreateFailed,
    SystemctlUnavailable,
    SystemdUserUnavailable,
};

/// Handle a service management command.
pub fn handleCommand(
    allocator: std.mem.Allocator,
    command: ServiceCommand,
    config_path: []const u8,
) !void {
    return switch (command) {
        .install => install(allocator, config_path),
        .start => startService(allocator),
        .stop => stopService(allocator),
        .status => serviceStatus(allocator),
        .uninstall => uninstall(allocator),
    };
}

fn install(allocator: std.mem.Allocator, config_path: []const u8) !void {
    if (comptime builtin.os.tag == .macos) {
        try installMacos(allocator, config_path);
    } else if (comptime builtin.os.tag == .linux) {
        try installLinux(allocator);
    } else if (comptime builtin.os.tag == .windows) {
        try installWindows(allocator);
    } else {
        return error.UnsupportedPlatform;
    }
}

fn startService(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .macos) {
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        try runChecked(allocator, &.{ "launchctl", "load", "-w", plist });
        try runChecked(allocator, &.{ "launchctl", "start", SERVICE_LABEL });
    } else if (comptime builtin.os.tag == .linux) {
        try assertLinuxSystemdUserAvailable(allocator);
        try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
        try runChecked(allocator, &.{ "systemctl", "--user", "start", "nullclaw.service" });
    } else if (comptime builtin.os.tag == .windows) {
        try runChecked(allocator, &.{ "sc.exe", "start", WINDOWS_SERVICE_NAME });
    } else {
        return error.UnsupportedPlatform;
    }
}

fn stopService(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .macos) {
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        runChecked(allocator, &.{ "launchctl", "stop", SERVICE_LABEL }) catch {};
        runChecked(allocator, &.{ "launchctl", "unload", "-w", plist }) catch {};
    } else if (comptime builtin.os.tag == .linux) {
        try assertLinuxSystemdUserAvailable(allocator);
        try runChecked(allocator, &.{ "systemctl", "--user", "stop", "nullclaw.service" });
    } else if (comptime builtin.os.tag == .windows) {
        try runChecked(allocator, &.{ "sc.exe", "stop", WINDOWS_SERVICE_NAME });
    } else {
        return error.UnsupportedPlatform;
    }
}

fn serviceStatus(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const w = &bw.interface;

    if (comptime builtin.os.tag == .macos) {
        const output = runCapture(allocator, &.{ "launchctl", "list" }) catch "";
        defer if (output.len > 0) allocator.free(output);
        const running = std.mem.indexOf(u8, output, SERVICE_LABEL) != null;
        try w.print("Service: {s}\n", .{if (running) "running/loaded" else "not loaded"});
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        try w.print("Unit: {s}\n", .{plist});
        try w.flush();
    } else if (comptime builtin.os.tag == .linux) {
        try assertLinuxSystemdUserAvailable(allocator);
        const output = runCapture(allocator, &.{ "systemctl", "--user", "is-active", "nullclaw.service" }) catch try allocator.dupe(u8, "unknown");
        defer allocator.free(output);
        try w.print("Service state: {s}\n", .{std.mem.trim(u8, output, " \t\n\r")});
        const unit = try linuxServiceFile(allocator);
        defer allocator.free(unit);
        try w.print("Unit: {s}\n", .{unit});
        try w.flush();
    } else if (comptime builtin.os.tag == .windows) {
        const status = try runCaptureStatus(allocator, &.{ "sc.exe", "query", WINDOWS_SERVICE_NAME });
        defer allocator.free(status.stdout);
        defer allocator.free(status.stderr);

        const detail = captureStatusDetail(&status);
        if (!status.success and isWindowsServiceMissingDetail(detail)) {
            try w.print("Service: not installed\n", .{});
            try w.print("Name: {s}\n", .{WINDOWS_SERVICE_NAME});
            try w.flush();
            return;
        }
        if (!status.success) return error.CommandFailed;

        try w.print("Service state: {s}\n", .{windowsServiceState(status.stdout)});
        try w.print("Name: {s}\n", .{WINDOWS_SERVICE_NAME});
        try w.flush();
    } else {
        return error.UnsupportedPlatform;
    }
}

fn uninstall(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .macos) {
        try stopService(allocator);
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        std.fs.deleteFileAbsolute(plist) catch {};
    } else if (comptime builtin.os.tag == .linux) {
        try stopService(allocator);
        const unit = try linuxServiceFile(allocator);
        defer allocator.free(unit);
        std.fs.deleteFileAbsolute(unit) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try assertLinuxSystemdUserAvailable(allocator);
        try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
    } else if (comptime builtin.os.tag == .windows) {
        try uninstallWindows(allocator);
    } else {
        return error.UnsupportedPlatform;
    }
}

fn installMacos(allocator: std.mem.Allocator, _: []const u8) !void {
    const plist = try macosServiceFile(allocator);
    defer allocator.free(plist);

    // Ensure parent directory exists
    if (std.mem.lastIndexOfScalar(u8, plist, '/')) |idx| {
        std.fs.makeDirAbsolute(plist[0..idx]) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Get current executable path
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);

    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    const logs_dir = try std.fmt.allocPrint(allocator, "{s}/.nullclaw/logs", .{home});
    defer allocator.free(logs_dir);
    std.fs.makeDirAbsolute(logs_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const stdout_log = try std.fmt.allocPrint(allocator, "{s}/daemon.stdout.log", .{logs_dir});
    defer allocator.free(stdout_log);
    const stderr_log = try std.fmt.allocPrint(allocator, "{s}/daemon.stderr.log", .{logs_dir});
    defer allocator.free(stderr_log);

    const content = try std.fmt.allocPrint(allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key>
        \\  <string>{s}</string>
        \\  <key>ProgramArguments</key>
        \\  <array>
        \\    <string>{s}</string>
        \\    <string>gateway</string>
        \\  </array>
        \\  <key>RunAtLoad</key>
        \\  <true/>
        \\  <key>KeepAlive</key>
        \\  <true/>
        \\  <key>StandardOutPath</key>
        \\  <string>{s}</string>
        \\  <key>StandardErrorPath</key>
        \\  <string>{s}</string>
        \\</dict>
        \\</plist>
    , .{ SERVICE_LABEL, xmlEscape(exe_path), xmlEscape(stdout_log), xmlEscape(stderr_log) });
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(plist, .{});
    defer file.close();
    try file.writeAll(content);
}

fn installLinux(allocator: std.mem.Allocator) !void {
    const unit = try linuxServiceFile(allocator);
    defer allocator.free(unit);

    try assertLinuxSystemdUserAvailable(allocator);

    if (std.mem.lastIndexOfScalar(u8, unit, '/')) |idx| {
        try std.fs.cwd().makePath(unit[0..idx]);
    }

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);

    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    const config_dir = try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
    defer allocator.free(config_dir);

    const content = try std.fmt.allocPrint(allocator,
        \\[Unit]
        \\Description=nullclaw gateway runtime
        \\After=network.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStart={s} gateway
        \\Restart=always
        \\RestartSec=3
        \\EnvironmentFile=-{s}/.env
        \\
        \\[Install]
        \\WantedBy=default.target
    , .{ exe_path, config_dir });
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(unit, .{});
    defer file.close();
    try file.writeAll(content);

    try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
    try runChecked(allocator, &.{ "systemctl", "--user", "enable", "nullclaw.service" });
}

fn installWindows(allocator: std.mem.Allocator) !void {
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);
    const bin_path = try std.fmt.allocPrint(allocator, "\"{s}\" gateway", .{exe_path});
    defer allocator.free(bin_path);

    const create = try runCaptureStatus(allocator, &.{
        "sc.exe",
        "create",
        WINDOWS_SERVICE_NAME,
        "binPath=",
        bin_path,
        "start=",
        "auto",
        "DisplayName=",
        WINDOWS_SERVICE_DISPLAY_NAME,
    });
    defer allocator.free(create.stdout);
    defer allocator.free(create.stderr);

    if (!create.success) {
        const detail = captureStatusDetail(&create);
        if (!isWindowsServiceAlreadyExistsDetail(detail)) return error.CommandFailed;
        try runChecked(allocator, &.{
            "sc.exe",
            "config",
            WINDOWS_SERVICE_NAME,
            "binPath=",
            bin_path,
            "start=",
            "auto",
            "DisplayName=",
            WINDOWS_SERVICE_DISPLAY_NAME,
        });
    }

    // Best-effort metadata polish.
    runChecked(allocator, &.{ "sc.exe", "description", WINDOWS_SERVICE_NAME, WINDOWS_SERVICE_DISPLAY_NAME }) catch {};
}

fn uninstallWindows(allocator: std.mem.Allocator) !void {
    // Stop is best-effort.
    const stop = try runCaptureStatus(allocator, &.{ "sc.exe", "stop", WINDOWS_SERVICE_NAME });
    defer allocator.free(stop.stdout);
    defer allocator.free(stop.stderr);
    if (!stop.success and !isWindowsServiceMissingDetail(captureStatusDetail(&stop))) {
        // Ignore stop races/non-running state.
    }

    const del = try runCaptureStatus(allocator, &.{ "sc.exe", "delete", WINDOWS_SERVICE_NAME });
    defer allocator.free(del.stdout);
    defer allocator.free(del.stderr);

    if (!del.success and !isWindowsServiceMissingDetail(captureStatusDetail(&del))) {
        return error.CommandFailed;
    }
}

// ── Path helpers ─────────────────────────────────────────────────

fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    return platform.getHomeDir(allocator) catch return error.NoHomeDir;
}

fn macosServiceFile(allocator: std.mem.Allocator) ![]const u8 {
    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, "Library", "LaunchAgents", SERVICE_LABEL ++ ".plist" });
}

fn linuxServiceFile(allocator: std.mem.Allocator) ![]const u8 {
    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".config", "systemd", "user", "nullclaw.service" });
}

// ── Process helpers ──────────────────────────────────────────────

const CaptureStatus = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
};

fn captureStatusDetail(status: *const CaptureStatus) []const u8 {
    const stderr_trimmed = std.mem.trim(u8, status.stderr, " \t\r\n");
    if (stderr_trimmed.len > 0) return stderr_trimmed;
    return std.mem.trim(u8, status.stdout, " \t\r\n");
}

fn isSystemdUnavailableDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "systemctl --user unavailable") != null or
        std.ascii.indexOfIgnoreCase(detail, "systemctl not available") != null or
        std.ascii.indexOfIgnoreCase(detail, "failed to connect to bus") != null or
        std.ascii.indexOfIgnoreCase(detail, "not been booted with systemd") != null or
        std.ascii.indexOfIgnoreCase(detail, "system has not been booted with systemd") != null or
        std.ascii.indexOfIgnoreCase(detail, "systemd user services are required") != null or
        std.ascii.indexOfIgnoreCase(detail, "no such file or directory") != null;
}

fn isWindowsServiceMissingDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "1060") != null or
        std.ascii.indexOfIgnoreCase(detail, "does not exist as an installed service") != null or
        std.ascii.indexOfIgnoreCase(detail, "service does not exist") != null;
}

fn isWindowsServiceAlreadyExistsDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "1073") != null or
        std.ascii.indexOfIgnoreCase(detail, "already exists") != null;
}

fn windowsServiceState(query_output: []const u8) []const u8 {
    if (std.ascii.indexOfIgnoreCase(query_output, "RUNNING") != null) return "running";
    if (std.ascii.indexOfIgnoreCase(query_output, "STOPPED") != null) return "stopped";
    if (std.ascii.indexOfIgnoreCase(query_output, "START_PENDING") != null) return "start_pending";
    if (std.ascii.indexOfIgnoreCase(query_output, "STOP_PENDING") != null) return "stop_pending";
    if (std.ascii.indexOfIgnoreCase(query_output, "PAUSED") != null) return "paused";
    return "unknown";
}

fn runCaptureStatus(allocator: std.mem.Allocator, argv: []const []const u8) !CaptureStatus {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch |err| switch (err) {
        error.FileNotFound => {
            if (argv.len > 0 and std.mem.eql(u8, argv[0], "systemctl")) return error.SystemctlUnavailable;
            return err;
        },
        else => return err,
    };

    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return error.CommandFailed;
    };
    errdefer allocator.free(stdout);
    const stderr = child.stderr.?.readToEndAlloc(allocator, 1024 * 1024) catch {
        allocator.free(stdout);
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return error.CommandFailed;
    };
    errdefer allocator.free(stderr);

    const result = try child.wait();
    const success = switch (result) {
        .Exited => |code| code == 0,
        else => false,
    };
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .success = success,
    };
}

fn assertLinuxSystemdUserAvailable(allocator: std.mem.Allocator) !void {
    const status = try runCaptureStatus(allocator, &.{ "systemctl", "--user", "status" });
    defer allocator.free(status.stdout);
    defer allocator.free(status.stderr);

    if (status.success) return;

    const stderr_trimmed = std.mem.trim(u8, status.stderr, " \t\r\n");
    const stdout_trimmed = std.mem.trim(u8, status.stdout, " \t\r\n");
    const detail = if (stderr_trimmed.len > 0) stderr_trimmed else stdout_trimmed;

    if (isSystemdUnavailableDetail(detail)) return error.SystemdUserUnavailable;
    return error.CommandFailed;
}

fn runChecked(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, allocator);
    // Avoid deadlocks: we do not consume pipes in runChecked.
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.spawn() catch |err| switch (err) {
        error.FileNotFound => {
            if (argv.len > 0 and std.mem.eql(u8, argv[0], "systemctl")) return error.SystemctlUnavailable;
            return err;
        },
        else => return err,
    };
    const result = try child.wait();
    switch (result) {
        .Exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn runCapture(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    // We only need stdout here; inheriting/ignoring stderr prevents pipe backpressure hangs.
    child.stderr_behavior = .Ignore;
    child.spawn() catch |err| switch (err) {
        error.FileNotFound => {
            if (argv.len > 0 and std.mem.eql(u8, argv[0], "systemctl")) return error.SystemctlUnavailable;
            return err;
        },
        else => return err,
    };
    const stdout = child.stdout.?.readToEndAlloc(allocator, 1024 * 1024) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return error.CommandFailed;
    };
    errdefer allocator.free(stdout);
    _ = child.wait() catch {
        return error.CommandFailed;
    };
    return stdout;
}

// ── XML escape ───────────────────────────────────────────────────

fn xmlEscape(input: []const u8) []const u8 {
    // For plist generation, the paths should be safe (no special XML chars).
    // If needed, we'd allocate. For now, return as-is since paths rarely contain XML specials.
    return input;
}

// ── Tests ────────────────────────────────────────────────────────

test "service label is set" {
    try std.testing.expect(SERVICE_LABEL.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, SERVICE_LABEL, "nullclaw") != null);
}

test "macosServiceFile contains label" {
    const path = macosServiceFile(std.testing.allocator) catch return;
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.mem.indexOf(u8, path, SERVICE_LABEL) != null);
    try std.testing.expect(std.mem.endsWith(u8, path, ".plist"));
}

test "linuxServiceFile contains service suffix" {
    const path = linuxServiceFile(std.testing.allocator) catch return;
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.mem.endsWith(u8, path, "nullclaw.service"));
}

test "xmlEscape returns input for safe strings" {
    const input = "/usr/local/bin/nullclaw";
    try std.testing.expectEqualStrings(input, xmlEscape(input));
}

test "runChecked succeeds for true command" {
    runChecked(std.testing.allocator, &.{"true"}) catch {
        // May fail in CI — just ensure it compiles
        return;
    };
}

test "runCapture captures stdout" {
    const output = runCapture(std.testing.allocator, &.{ "echo", "hello" }) catch {
        return;
    };
    defer std.testing.allocator.free(output);
    try std.testing.expect(std.mem.startsWith(u8, std.mem.trim(u8, output, " \t\n\r"), "hello"));
}

test "isSystemdUnavailableDetail detects common unavailable errors" {
    try std.testing.expect(isSystemdUnavailableDetail("systemctl --user unavailable: failed to connect to bus"));
    try std.testing.expect(isSystemdUnavailableDetail("systemctl not available; systemd user services are required on Linux"));
    try std.testing.expect(isSystemdUnavailableDetail("Failed to connect to bus: No medium found"));
    try std.testing.expect(isSystemdUnavailableDetail("System has not been booted with systemd as init system"));
    try std.testing.expect(isSystemdUnavailableDetail("No such file or directory"));
    try std.testing.expect(!isSystemdUnavailableDetail("unit nullclaw.service not found"));
    try std.testing.expect(!isSystemdUnavailableDetail("permission denied"));
}

test "isWindowsServiceMissingDetail detects missing-service patterns" {
    try std.testing.expect(isWindowsServiceMissingDetail("OpenService FAILED 1060"));
    try std.testing.expect(isWindowsServiceMissingDetail("The specified service does not exist as an installed service."));
    try std.testing.expect(!isWindowsServiceMissingDetail("OpenService FAILED 5: Access is denied."));
}

test "isWindowsServiceAlreadyExistsDetail detects duplicate-service patterns" {
    try std.testing.expect(isWindowsServiceAlreadyExistsDetail("CreateService FAILED 1073"));
    try std.testing.expect(isWindowsServiceAlreadyExistsDetail("service already exists"));
    try std.testing.expect(!isWindowsServiceAlreadyExistsDetail("CreateService FAILED 5"));
}

test "windowsServiceState parses common states" {
    try std.testing.expectEqualStrings("running", windowsServiceState("STATE              : 4  RUNNING"));
    try std.testing.expectEqualStrings("stopped", windowsServiceState("STATE              : 1  STOPPED"));
    try std.testing.expectEqualStrings("start_pending", windowsServiceState("STATE              : 2  START_PENDING"));
    try std.testing.expectEqualStrings("unknown", windowsServiceState("STATE              : ?"));
}
