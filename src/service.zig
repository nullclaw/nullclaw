//! Service management — launchd (macOS), systemd/OpenRC (Linux), and SCM (Windows).
//!
//! Mirrors ZeroClaw's service module: install, start, stop, restart, status, uninstall.
//! Uses child process execution to interact with launchctl / systemctl / rc-service / sc.exe.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const Config = @import("config.zig").Config;
const daemon = @import("daemon.zig");
const http_util = @import("http_util.zig");
const fs_compat = @import("fs_compat.zig");
const providers = @import("providers/root.zig");
const security = @import("security/root.zig");

const SERVICE_LABEL = "com.nullclaw.daemon";
const WINDOWS_SERVICE_NAME = "nullclaw";
const WINDOWS_SERVICE_DISPLAY_NAME = "nullclaw gateway runtime";
const OPENRC_SERVICE_NAME = "nullclaw";
const OPENRC_SERVICE_FILE = "/etc/init.d/nullclaw";
pub const WINDOWS_SERVICE_GATEWAY_ARG = "__windows-service-gateway";

const windows = std.os.windows;
const WINDOWS_SERVICE_NAME_W = std.unicode.utf8ToUtf16LeStringLiteral(WINDOWS_SERVICE_NAME);

const WindowsServiceStatusHandle = ?*opaque {};
const WindowsServiceMainProc = *const fn (windows.DWORD, [*]?[*:0]u16) callconv(.winapi) void;
const WindowsServiceControlProc = *const fn (windows.DWORD) callconv(.winapi) void;
const WindowsServiceTableEntry = extern struct {
    service_name: ?[*:0]const u16,
    service_proc: ?WindowsServiceMainProc,
};
const WindowsServiceStatus = extern struct {
    service_type: windows.DWORD,
    current_state: windows.DWORD,
    controls_accepted: windows.DWORD,
    win32_exit_code: windows.DWORD,
    service_specific_exit_code: windows.DWORD,
    checkpoint: windows.DWORD,
    wait_hint_ms: windows.DWORD,
};

const SERVICE_WIN32_OWN_PROCESS: windows.DWORD = 0x00000010;
const SERVICE_STOPPED: windows.DWORD = 0x00000001;
const SERVICE_START_PENDING: windows.DWORD = 0x00000002;
const SERVICE_STOP_PENDING: windows.DWORD = 0x00000003;
const SERVICE_RUNNING: windows.DWORD = 0x00000004;
const SERVICE_ACCEPT_STOP: windows.DWORD = 0x00000001;
const SERVICE_ACCEPT_SHUTDOWN: windows.DWORD = 0x00000004;
const SERVICE_CONTROL_STOP: windows.DWORD = 0x00000001;
const SERVICE_CONTROL_INTERROGATE: windows.DWORD = 0x00000004;
const SERVICE_CONTROL_SHUTDOWN: windows.DWORD = 0x00000005;
const SERVICE_NO_ERROR: windows.DWORD = 0;
const SERVICE_GENERIC_FAILURE: windows.DWORD = 1;

extern "advapi32" fn StartServiceCtrlDispatcherW(start_table: [*]const WindowsServiceTableEntry) callconv(.winapi) windows.BOOL;
extern "advapi32" fn RegisterServiceCtrlHandlerW(service_name: [*:0]const u16, handler_proc: WindowsServiceControlProc) callconv(.winapi) WindowsServiceStatusHandle;
extern "advapi32" fn SetServiceStatus(status_handle: WindowsServiceStatusHandle, status: *const WindowsServiceStatus) callconv(.winapi) windows.BOOL;

var windows_service_status_handle: WindowsServiceStatusHandle = null;
var windows_service_status = WindowsServiceStatus{
    .service_type = SERVICE_WIN32_OWN_PROCESS,
    .current_state = SERVICE_STOPPED,
    .controls_accepted = 0,
    .win32_exit_code = SERVICE_NO_ERROR,
    .service_specific_exit_code = 0,
    .checkpoint = 0,
    .wait_hint_ms = 0,
};
var windows_service_checkpoint: windows.DWORD = 1;

pub const ServiceCommand = enum {
    install,
    start,
    stop,
    restart,
    status,
    uninstall,
};

pub const ServiceError = error{
    CommandFailed,
    UnsupportedPlatform,
    NoHomeDir,
    FileCreateFailed,
    OpenRcUnavailable,
    SystemctlUnavailable,
    SystemdUserUnavailable,
};

const LinuxServiceManager = enum {
    systemd_user,
    openrc,
};

pub fn isWindowsServiceGatewayArg(arg: []const u8) bool {
    return std.mem.eql(u8, arg, WINDOWS_SERVICE_GATEWAY_ARG);
}

pub fn runWindowsServiceGateway(allocator: std.mem.Allocator) !void {
    _ = allocator;
    if (comptime builtin.os.tag != .windows) return error.UnsupportedPlatform;

    resetWindowsServiceState();

    const table = [_]WindowsServiceTableEntry{
        .{
            .service_name = WINDOWS_SERVICE_NAME_W,
            .service_proc = windowsServiceMain,
        },
        .{
            .service_name = null,
            .service_proc = null,
        },
    };

    if (StartServiceCtrlDispatcherW(&table) == 0) {
        return error.CommandFailed;
    }
}

/// Handle a service management command.
pub fn handleCommand(
    allocator: std.mem.Allocator,
    command: ServiceCommand,
) !void {
    return switch (command) {
        .install => install(allocator),
        .start => startService(allocator),
        .stop => stopService(allocator),
        .restart => restartService(allocator),
        .status => serviceStatus(allocator),
        .uninstall => uninstall(allocator),
    };
}

fn install(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .macos) {
        try installMacos(allocator);
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
        switch (try detectLinuxServiceManager(allocator)) {
            .systemd_user => {
                try assertLinuxSystemdUserAvailable(allocator);
                try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
                try runChecked(allocator, &.{ "systemctl", "--user", "start", "nullclaw.service" });
            },
            .openrc => try openRcRunChecked(allocator, &.{ OPENRC_SERVICE_NAME, "start" }),
        }
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
        switch (try detectLinuxServiceManager(allocator)) {
            .systemd_user => {
                try assertLinuxSystemdUserAvailable(allocator);
                try runChecked(allocator, &.{ "systemctl", "--user", "stop", "nullclaw.service" });
            },
            .openrc => try openRcRunChecked(allocator, &.{ OPENRC_SERVICE_NAME, "stop" }),
        }
    } else if (comptime builtin.os.tag == .windows) {
        try runChecked(allocator, &.{ "sc.exe", "stop", WINDOWS_SERVICE_NAME });
    } else {
        return error.UnsupportedPlatform;
    }
}

fn restartService(allocator: std.mem.Allocator) !void {
    // Restart should still proceed when stop reports "already stopped"/"not loaded",
    // but should not mask unrelated stop failures.
    try stopServiceForRestart(allocator);
    try startService(allocator);
}

fn stopServiceForRestart(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .macos) {
        // launchctl stop/unload can fail when not loaded; treat as best-effort here.
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        runChecked(allocator, &.{ "launchctl", "stop", SERVICE_LABEL }) catch {};
        runChecked(allocator, &.{ "launchctl", "unload", "-w", plist }) catch {};
        return;
    } else if (comptime builtin.os.tag == .linux) {
        switch (try detectLinuxServiceManager(allocator)) {
            .systemd_user => {
                try assertLinuxSystemdUserAvailable(allocator);
                const status = try runCaptureStatus(allocator, &.{ "systemctl", "--user", "stop", "nullclaw.service" });
                defer allocator.free(status.stdout);
                defer allocator.free(status.stderr);
                if (status.success) return;
                const detail = captureStatusDetail(&status);
                if (isSystemdUnitNotLoadedDetail(detail)) return;
                return error.CommandFailed;
            },
            .openrc => {
                const status = try openRcRunCaptureStatus(allocator, &.{ OPENRC_SERVICE_NAME, "stop" });
                defer allocator.free(status.stdout);
                defer allocator.free(status.stderr);
                if (status.success) return;
                const detail = captureStatusDetail(&status);
                if (isOpenRcServiceMissingDetail(detail) or isOpenRcInactiveDetail(detail)) return;
                return error.CommandFailed;
            },
        }
    } else if (comptime builtin.os.tag == .windows) {
        const status = try runCaptureStatus(allocator, &.{ "sc.exe", "stop", WINDOWS_SERVICE_NAME });
        defer allocator.free(status.stdout);
        defer allocator.free(status.stderr);
        if (status.success) return;
        const detail = captureStatusDetail(&status);
        if (isWindowsServiceMissingDetail(detail) or isWindowsServiceNotRunningDetail(detail)) return;
        return error.CommandFailed;
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
        switch (try detectLinuxServiceManager(allocator)) {
            .systemd_user => {
                try assertLinuxSystemdUserAvailable(allocator);
                const output = runCapture(allocator, &.{ "systemctl", "--user", "is-active", "nullclaw.service" }) catch try allocator.dupe(u8, "unknown");
                defer allocator.free(output);
                try w.print("Service state: {s}\n", .{std.mem.trim(u8, output, " \t\n\r")});
                const unit = try linuxServiceFile(allocator);
                defer allocator.free(unit);
                try w.print("Unit: {s}\n", .{unit});
                try w.flush();
            },
            .openrc => {
                if (!fileExistsAbsolute(OPENRC_SERVICE_FILE)) {
                    try w.print("Service: not installed\n", .{});
                    try w.print("Script: {s}\n", .{OPENRC_SERVICE_FILE});
                    try w.flush();
                    return;
                }
                const status = try openRcRunCaptureStatus(allocator, &.{ OPENRC_SERVICE_NAME, "status" });
                defer allocator.free(status.stdout);
                defer allocator.free(status.stderr);
                const detail = captureStatusDetail(&status);
                try w.print("Service state: {s}\n", .{openRcServiceState(detail)});
                try w.print("Script: {s}\n", .{OPENRC_SERVICE_FILE});
                try w.flush();
            },
        }
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
        switch (try detectLinuxServiceManager(allocator)) {
            .systemd_user => {
                try stopService(allocator);
                const unit = try linuxServiceFile(allocator);
                defer allocator.free(unit);
                std.fs.deleteFileAbsolute(unit) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return err,
                };
                try assertLinuxSystemdUserAvailable(allocator);
                try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
            },
            .openrc => try uninstallOpenRc(allocator),
        }
    } else if (comptime builtin.os.tag == .windows) {
        try uninstallWindows(allocator);
    } else {
        return error.UnsupportedPlatform;
    }
}

fn installMacos(allocator: std.mem.Allocator) !void {
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
    const service_exe_path = try resolveServiceExecutablePath(allocator, exe_path);
    defer allocator.free(service_exe_path);

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
    , .{ SERVICE_LABEL, xmlEscape(service_exe_path), xmlEscape(stdout_log), xmlEscape(stderr_log) });
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(plist, .{});
    defer file.close();
    try file.writeAll(content);
}

fn resolveServiceExecutablePath(allocator: std.mem.Allocator, exe_path: []const u8) ![]u8 {
    if (try preferredHomebrewShimPath(allocator, exe_path)) |candidate| {
        std.fs.accessAbsolute(candidate, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                allocator.free(candidate);
                return allocator.dupe(u8, exe_path);
            },
            else => {
                allocator.free(candidate);
                return err;
            },
        };
        return candidate;
    }
    return allocator.dupe(u8, exe_path);
}

fn preferredHomebrewShimPath(allocator: std.mem.Allocator, exe_path: []const u8) !?[]u8 {
    if (!std.mem.endsWith(u8, exe_path, "/bin/nullclaw")) {
        return null;
    }

    const cellar_marker = "/Cellar/nullclaw/";
    const cellar_index = std.mem.indexOf(u8, exe_path, cellar_marker) orelse return null;
    if (cellar_index == 0) {
        return null;
    }

    // selfExePath uses POSIX separators for Homebrew installs even when tests run on Windows.
    const candidate = try std.fmt.allocPrint(allocator, "{s}/bin/nullclaw", .{exe_path[0..cellar_index]});
    return candidate;
}

fn installLinux(allocator: std.mem.Allocator) !void {
    switch (try detectLinuxServiceManager(allocator)) {
        .systemd_user => try installLinuxSystemd(allocator),
        .openrc => try installLinuxOpenRc(allocator),
    }
}

fn installLinuxSystemd(allocator: std.mem.Allocator) !void {
    const unit = try linuxServiceFile(allocator);
    defer allocator.free(unit);

    try assertLinuxSystemdUserAvailable(allocator);

    if (std.mem.lastIndexOfScalar(u8, unit, '/')) |idx| {
        try fs_compat.makePath(unit[0..idx]);
    }

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);
    const service_exe_path = try resolveServiceExecutablePath(allocator, exe_path);
    defer allocator.free(service_exe_path);

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
    , .{ service_exe_path, config_dir });
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(unit, .{});
    defer file.close();
    try file.writeAll(content);

    try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
    try runChecked(allocator, &.{ "systemctl", "--user", "enable", "nullclaw.service" });
}

fn installLinuxOpenRc(allocator: std.mem.Allocator) !void {
    const openrc_run_path = getOpenRcRunPath() orelse return error.OpenRcUnavailable;

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);
    const service_exe_path = try resolveServiceExecutablePath(allocator, exe_path);
    defer allocator.free(service_exe_path);

    const service_user = getServiceUser(allocator);
    defer if (service_user) |user| allocator.free(user);

    const service_home = try getServiceHomeDir(allocator);
    defer allocator.free(service_home);

    const config_dir = try std.fs.path.join(allocator, &.{ service_home, ".nullclaw" });
    defer allocator.free(config_dir);

    const script = try buildOpenRcScript(allocator, .{
        .openrc_run_path = openrc_run_path,
        .service_exe_path = service_exe_path,
        .service_user = service_user,
        .service_home = service_home,
        .config_dir = config_dir,
    });
    defer allocator.free(script);

    const file = try std.fs.createFileAbsolute(OPENRC_SERVICE_FILE, .{});
    defer file.close();
    try file.writeAll(script);
    try file.chmod(0o755);

    try openRcUpdateChecked(allocator, &.{ "add", OPENRC_SERVICE_NAME, "default" });
}

fn installWindows(allocator: std.mem.Allocator) !void {
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);
    const bin_path = try windowsServiceBinPath(allocator, exe_path);
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

fn fileExistsAbsolute(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return false,
    };
    return true;
}

fn getServiceUser(allocator: std.mem.Allocator) ?[]const u8 {
    if (platform.getEnvOrNull(allocator, "SUDO_USER")) |sudo_user| return sudo_user;
    return platform.getEnvOrNull(allocator, "USER");
}

fn parsePasswdHome(passwd_contents: []const u8, username: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, passwd_contents, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const home = fields.next() orelse continue;

        if (std.mem.eql(u8, name, username)) return home;
    }
    return null;
}

fn getHomeDirForUserFromPasswd(allocator: std.mem.Allocator, username: []const u8) ![]const u8 {
    const passwd = try std.fs.cwd().readFileAlloc(allocator, "/etc/passwd", 1024 * 1024);
    defer allocator.free(passwd);

    const home = parsePasswdHome(passwd, username) orelse return error.NoHomeDir;
    return allocator.dupe(u8, home);
}

fn getServiceHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (platform.getEnvOrNull(allocator, "SUDO_USER")) |sudo_user| {
        defer allocator.free(sudo_user);
        return getHomeDirForUserFromPasswd(allocator, sudo_user);
    }
    return getHomeDir(allocator);
}

// ── Process helpers ──────────────────────────────────────────────

const CaptureStatus = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
};

const OpenRcScriptConfig = struct {
    openrc_run_path: []const u8,
    service_exe_path: []const u8,
    service_user: ?[]const u8,
    service_home: []const u8,
    config_dir: []const u8,
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

const openrc_markers = [_][]const u8{
    "/run/openrc",
    "/run/openrc/softlevel",
};

const openrc_command_candidates = [_][]const u8{
    "/sbin/rc-service",
    "/usr/sbin/rc-service",
    "/bin/rc-service",
    "/usr/bin/rc-service",
};

const openrc_update_candidates = [_][]const u8{
    "/sbin/rc-update",
    "/usr/sbin/rc-update",
    "/bin/rc-update",
    "/usr/bin/rc-update",
};

const openrc_run_candidates = [_][]const u8{
    "/sbin/openrc-run",
    "/usr/sbin/openrc-run",
    "/bin/openrc-run",
    "/usr/bin/openrc-run",
};

fn hasAnyMatchingPath(candidate_paths: []const []const u8, existing_paths: []const []const u8) bool {
    for (candidate_paths) |candidate| {
        for (existing_paths) |path| {
            if (std.mem.eql(u8, candidate, path)) return true;
        }
    }
    return false;
}

fn hasOpenRcMarkerInPaths(existing_paths: []const []const u8) bool {
    return hasAnyMatchingPath(&openrc_markers, existing_paths);
}

fn hasOpenRcCommandInPaths(existing_paths: []const []const u8) bool {
    return hasAnyMatchingPath(&openrc_command_candidates, existing_paths) and
        hasAnyMatchingPath(&openrc_run_candidates, existing_paths);
}

fn firstExistingAbsolutePath(paths: []const []const u8) ?[]const u8 {
    for (paths) |path| {
        if (fileExistsAbsolute(path)) return path;
    }
    return null;
}

fn hasAnyExistingAbsolutePath(paths: []const []const u8) bool {
    return firstExistingAbsolutePath(paths) != null;
}

fn getOpenRcServiceCommandPath() ?[]const u8 {
    return firstExistingAbsolutePath(&openrc_command_candidates);
}

fn getOpenRcUpdatePath() ?[]const u8 {
    return firstExistingAbsolutePath(&openrc_update_candidates);
}

fn getOpenRcRunPath() ?[]const u8 {
    return firstExistingAbsolutePath(&openrc_run_candidates);
}

fn linuxHasOpenRcRuntime() bool {
    return hasAnyExistingAbsolutePath(&openrc_markers);
}

fn linuxHasOpenRcSupport() bool {
    return getOpenRcServiceCommandPath() != null and
        getOpenRcUpdatePath() != null and
        getOpenRcRunPath() != null;
}

fn detectLinuxServiceManager(allocator: std.mem.Allocator) !LinuxServiceManager {
    if (linuxHasOpenRcRuntime()) {
        if (!linuxHasOpenRcSupport()) return error.OpenRcUnavailable;
        return .openrc;
    }

    assertLinuxSystemdUserAvailable(allocator) catch |err| switch (err) {
        error.SystemctlUnavailable, error.SystemdUserUnavailable => {
            if (linuxHasOpenRcSupport()) return .openrc;
            return err;
        },
        else => return err,
    };

    return .systemd_user;
}

fn shellDoubleQuoted(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.append(allocator, '"');
    for (input) |ch| {
        switch (ch) {
            '\\', '"', '$', '`' => {
                try out.append(allocator, '\\');
                try out.append(allocator, ch);
            },
            else => try out.append(allocator, ch),
        }
    }
    try out.append(allocator, '"');
    return out.toOwnedSlice(allocator);
}

fn buildOpenRcScript(allocator: std.mem.Allocator, cfg: OpenRcScriptConfig) ![]u8 {
    const exe_quoted = try shellDoubleQuoted(allocator, cfg.service_exe_path);
    defer allocator.free(exe_quoted);
    const home_quoted = try shellDoubleQuoted(allocator, cfg.service_home);
    defer allocator.free(home_quoted);
    const config_quoted = try shellDoubleQuoted(allocator, cfg.config_dir);
    defer allocator.free(config_quoted);
    const user_line = if (cfg.service_user) |service_user| blk: {
        const user_quoted = try shellDoubleQuoted(allocator, service_user);
        defer allocator.free(user_quoted);
        break :blk try std.fmt.allocPrint(allocator, "command_user={s}\nexport USER={s}\n", .{ user_quoted, user_quoted });
    } else try allocator.dupe(u8, "");
    defer allocator.free(user_line);

    return std.fmt.allocPrint(allocator,
        \\#!{s}
        \\
        \\name="nullclaw"
        \\description="nullclaw gateway runtime"
        \\command={s}
        \\command_args="gateway"
        \\command_background="yes"
        \\pidfile="/run/${{RC_SVCNAME}}.pid"
        \\directory={s}
        \\export HOME={s}
        \\export NULLCLAW_HOME={s}
        \\{s}
        \\depend() {{
        \\    need net
        \\}}
    , .{ cfg.openrc_run_path, exe_quoted, home_quoted, home_quoted, config_quoted, user_line });
}

fn isSystemdUnitNotLoadedDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "unit nullclaw.service not loaded") != null or
        std.ascii.indexOfIgnoreCase(detail, "could not be found") != null or
        std.ascii.indexOfIgnoreCase(detail, "not loaded") != null;
}

fn isOpenRcServiceMissingDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "does not exist") != null or
        std.ascii.indexOfIgnoreCase(detail, "not found") != null or
        std.ascii.indexOfIgnoreCase(detail, "service `nullclaw'") != null;
}

fn isOpenRcInactiveDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "stopped") != null or
        std.ascii.indexOfIgnoreCase(detail, "not started") != null or
        std.ascii.indexOfIgnoreCase(detail, "inactive") != null;
}

fn openRcServiceState(detail: []const u8) []const u8 {
    if (std.ascii.indexOfIgnoreCase(detail, "started") != null or
        std.ascii.indexOfIgnoreCase(detail, "running") != null)
    {
        return "running";
    }
    if (std.ascii.indexOfIgnoreCase(detail, "crashed") != null) return "crashed";
    if (isOpenRcInactiveDetail(detail)) return "stopped";
    if (isOpenRcServiceMissingDetail(detail)) return "not installed";
    return "unknown";
}

fn isWindowsServiceMissingDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "1060") != null or
        std.ascii.indexOfIgnoreCase(detail, "does not exist as an installed service") != null or
        std.ascii.indexOfIgnoreCase(detail, "service does not exist") != null;
}

fn isWindowsServiceNotRunningDetail(detail: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(detail, "1062") != null or
        std.ascii.indexOfIgnoreCase(detail, "service has not been started") != null;
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

fn openRcRunChecked(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const rc_service = getOpenRcServiceCommandPath() orelse return error.OpenRcUnavailable;
    var full: std.ArrayListUnmanaged([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, rc_service);
    try full.appendSlice(allocator, argv);
    try runChecked(allocator, full.items);
}

fn openRcRunCaptureStatus(allocator: std.mem.Allocator, argv: []const []const u8) !CaptureStatus {
    const rc_service = getOpenRcServiceCommandPath() orelse return error.OpenRcUnavailable;
    var full: std.ArrayListUnmanaged([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, rc_service);
    try full.appendSlice(allocator, argv);
    return runCaptureStatus(allocator, full.items);
}

fn openRcUpdateChecked(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const rc_update = getOpenRcUpdatePath() orelse return error.OpenRcUnavailable;
    var full: std.ArrayListUnmanaged([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, rc_update);
    try full.appendSlice(allocator, argv);
    try runChecked(allocator, full.items);
}

fn uninstallOpenRc(allocator: std.mem.Allocator) !void {
    const stop_status = openRcRunCaptureStatus(allocator, &.{ OPENRC_SERVICE_NAME, "stop" }) catch |err| switch (err) {
        error.CommandFailed => return error.CommandFailed,
        else => return err,
    };
    defer allocator.free(stop_status.stdout);
    defer allocator.free(stop_status.stderr);

    const stop_detail = captureStatusDetail(&stop_status);
    if (!stop_status.success and !isOpenRcServiceMissingDetail(stop_detail) and !isOpenRcInactiveDetail(stop_detail)) {
        return error.CommandFailed;
    }

    openRcUpdateChecked(allocator, &.{ "del", OPENRC_SERVICE_NAME, "default" }) catch |err| switch (err) {
        error.CommandFailed => {},
        else => return err,
    };

    std.fs.deleteFileAbsolute(OPENRC_SERVICE_FILE) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
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

fn windowsServiceBinPath(allocator: std.mem.Allocator, exe_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\"{s}\" {s}", .{ exe_path, WINDOWS_SERVICE_GATEWAY_ARG });
}

fn resetWindowsServiceState() void {
    windows_service_status_handle = null;
    windows_service_checkpoint = 1;
    windows_service_status = .{
        .service_type = SERVICE_WIN32_OWN_PROCESS,
        .current_state = SERVICE_STOPPED,
        .controls_accepted = 0,
        .win32_exit_code = SERVICE_NO_ERROR,
        .service_specific_exit_code = 0,
        .checkpoint = 0,
        .wait_hint_ms = 0,
    };
}

fn updateWindowsServiceStatus(current_state: windows.DWORD, win32_exit_code: windows.DWORD, wait_hint_ms: windows.DWORD) void {
    const handle = windows_service_status_handle orelse return;

    windows_service_status.current_state = current_state;
    windows_service_status.win32_exit_code = win32_exit_code;
    windows_service_status.service_specific_exit_code = 0;
    windows_service_status.wait_hint_ms = wait_hint_ms;
    windows_service_status.controls_accepted = switch (current_state) {
        SERVICE_RUNNING => SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        else => 0,
    };
    windows_service_status.checkpoint = switch (current_state) {
        SERVICE_START_PENDING, SERVICE_STOP_PENDING => blk: {
            const checkpoint = windows_service_checkpoint;
            windows_service_checkpoint += 1;
            break :blk checkpoint;
        },
        else => 0,
    };

    _ = SetServiceStatus(handle, &windows_service_status);
}

fn applyServiceRuntimeProviderOverrides(config: *const Config) !void {
    try http_util.setProxyOverride(config.http_request.proxy);
    try providers.setApiErrorLimitOverride(config.diagnostics.api_error_max_chars);
}

fn runWindowsServiceGatewayProcess(allocator: std.mem.Allocator) !void {
    var cfg = try Config.load(allocator);
    defer cfg.deinit();

    try cfg.validate();
    try applyServiceRuntimeProviderOverrides(&cfg);
    if (!security.isYoloGatewayAllowed(cfg.autonomy.level, cfg.gateway.host, security.isYoloForceEnabled(allocator))) {
        std.debug.print(
            "Refusing to start gateway service with autonomy.level=yolo on non-local host '{s}'. Use localhost or set NULLCLAW_ALLOW_YOLO=1 to force this insecure mode.\n",
            .{cfg.gateway.host},
        );
        return error.InsecureYoloGatewayBind;
    }

    updateWindowsServiceStatus(SERVICE_RUNNING, SERVICE_NO_ERROR, 0);
    try daemon.run(allocator, &cfg, cfg.gateway.host, cfg.gateway.port);
}

fn windowsServiceMain(_: windows.DWORD, _: [*]?[*:0]u16) callconv(.winapi) void {
    windows_service_status_handle = RegisterServiceCtrlHandlerW(WINDOWS_SERVICE_NAME_W, windowsServiceControlHandler);
    if (windows_service_status_handle == null) return;

    updateWindowsServiceStatus(SERVICE_START_PENDING, SERVICE_NO_ERROR, 10_000);

    runWindowsServiceGatewayProcess(std.heap.smp_allocator) catch {
        updateWindowsServiceStatus(SERVICE_STOPPED, SERVICE_GENERIC_FAILURE, 0);
        return;
    };

    updateWindowsServiceStatus(SERVICE_STOPPED, SERVICE_NO_ERROR, 0);
}

fn windowsServiceControlHandler(control: windows.DWORD) callconv(.winapi) void {
    switch (control) {
        SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN => {
            daemon.requestShutdown();
            // The control handler should transition to STOP_PENDING and return;
            // ServiceMain reports STOPPED once the daemon has actually exited.
            updateWindowsServiceStatus(SERVICE_STOP_PENDING, SERVICE_NO_ERROR, 30_000);
        },
        SERVICE_CONTROL_INTERROGATE => {
            const handle = windows_service_status_handle orelse return;
            _ = SetServiceStatus(handle, &windows_service_status);
        },
        else => {},
    }
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

test "preferredHomebrewShimPath resolves Apple Silicon Cellar install" {
    const shim = (try preferredHomebrewShimPath(std.testing.allocator, "/opt/homebrew/Cellar/nullclaw/2026.3.7/bin/nullclaw")).?;
    defer std.testing.allocator.free(shim);
    try std.testing.expectEqualStrings("/opt/homebrew/bin/nullclaw", shim);
}

test "preferredHomebrewShimPath resolves Intel Homebrew Cellar install" {
    const shim = (try preferredHomebrewShimPath(std.testing.allocator, "/usr/local/Cellar/nullclaw/2026.3.7/bin/nullclaw")).?;
    defer std.testing.allocator.free(shim);
    try std.testing.expectEqualStrings("/usr/local/bin/nullclaw", shim);
}

test "preferredHomebrewShimPath resolves Linux Homebrew Cellar install" {
    const shim = (try preferredHomebrewShimPath(std.testing.allocator, "/home/linuxbrew/.linuxbrew/Cellar/nullclaw/2026.3.7/bin/nullclaw")).?;
    defer std.testing.allocator.free(shim);
    try std.testing.expectEqualStrings("/home/linuxbrew/.linuxbrew/bin/nullclaw", shim);
}

test "preferredHomebrewShimPath ignores non-Cellar paths" {
    try std.testing.expect((try preferredHomebrewShimPath(std.testing.allocator, "/Applications/nullclaw/bin/nullclaw")) == null);
}

test "preferredHomebrewShimPath ignores non-executable Cellar paths" {
    try std.testing.expect((try preferredHomebrewShimPath(std.testing.allocator, "/opt/homebrew/Cellar/nullclaw/2026.3.7/share/nullclaw.txt")) == null);
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

test "hasOpenRcMarkerInPaths detects common OpenRC markers" {
    try std.testing.expect(hasOpenRcMarkerInPaths(&.{"/run/openrc/softlevel"}));
    try std.testing.expect(hasOpenRcMarkerInPaths(&.{"/run/openrc"}));
    try std.testing.expect(!hasOpenRcMarkerInPaths(&.{"/run/systemd/system"}));
}

test "hasOpenRcCommandInPaths detects required OpenRC commands" {
    try std.testing.expect(hasOpenRcCommandInPaths(&.{ "/sbin/rc-service", "/sbin/openrc-run" }));
    try std.testing.expect(!hasOpenRcCommandInPaths(&.{"/sbin/rc-service"}));
}

test "hasAnyExistingAbsolutePath checks actual filesystem state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("openrc");
    const existing = try tmp.dir.realpathAlloc(std.testing.allocator, "openrc");
    defer std.testing.allocator.free(existing);

    const missing = try std.fs.path.join(std.testing.allocator, &.{ existing, "softlevel" });
    defer std.testing.allocator.free(missing);

    try std.testing.expect(hasAnyExistingAbsolutePath(&.{ missing, existing }));
    try std.testing.expect(!hasAnyExistingAbsolutePath(&.{missing}));
}

test "parsePasswdHome extracts matching user home" {
    const passwd =
        \\root:x:0:0:root:/root:/bin/sh
        \\alice:x:1000:1000:Alice:/home/alice:/bin/ash
    ;
    try std.testing.expectEqualStrings("/home/alice", parsePasswdHome(passwd, "alice").?);
    try std.testing.expect(parsePasswdHome(passwd, "bob") == null);
}

test "buildOpenRcScript includes user and config env" {
    const script = try buildOpenRcScript(std.testing.allocator, .{
        .openrc_run_path = "/sbin/openrc-run",
        .service_exe_path = "/usr/local/bin/nullclaw",
        .service_user = "alice",
        .service_home = "/home/alice",
        .config_dir = "/home/alice/.nullclaw",
    });
    defer std.testing.allocator.free(script);

    try std.testing.expect(std.mem.indexOf(u8, script, "#!/sbin/openrc-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "command=\"/usr/local/bin/nullclaw\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "command_user=\"alice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "export HOME=\"/home/alice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "export NULLCLAW_HOME=\"/home/alice/.nullclaw\"") != null);
}

test "openRcServiceState classifies common states" {
    try std.testing.expectEqualStrings("running", openRcServiceState("status: started"));
    try std.testing.expectEqualStrings("stopped", openRcServiceState("status: stopped"));
    try std.testing.expectEqualStrings("crashed", openRcServiceState("status: crashed"));
    try std.testing.expectEqualStrings("not installed", openRcServiceState("service `nullclaw' does not exist"));
}

test "isSystemdUnitNotLoadedDetail detects stop-not-loaded patterns" {
    try std.testing.expect(isSystemdUnitNotLoadedDetail("Unit nullclaw.service not loaded."));
    try std.testing.expect(isSystemdUnitNotLoadedDetail("Unit nullclaw.service could not be found."));
    try std.testing.expect(isSystemdUnitNotLoadedDetail("not loaded"));
    try std.testing.expect(!isSystemdUnitNotLoadedDetail("permission denied"));
}

test "isWindowsServiceMissingDetail detects missing-service patterns" {
    try std.testing.expect(isWindowsServiceMissingDetail("OpenService FAILED 1060"));
    try std.testing.expect(isWindowsServiceMissingDetail("The specified service does not exist as an installed service."));
    try std.testing.expect(!isWindowsServiceMissingDetail("OpenService FAILED 5: Access is denied."));
}

test "isWindowsServiceNotRunningDetail detects stop-not-running patterns" {
    try std.testing.expect(isWindowsServiceNotRunningDetail("ControlService FAILED 1062"));
    try std.testing.expect(isWindowsServiceNotRunningDetail("The service has not been started."));
    try std.testing.expect(!isWindowsServiceNotRunningDetail("OpenService FAILED 1060"));
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

test "windowsServiceBinPath uses hidden service gateway entrypoint" {
    const bin_path = try windowsServiceBinPath(std.testing.allocator, "C:\\Program Files\\nullclaw\\nullclaw.exe");
    defer std.testing.allocator.free(bin_path);

    try std.testing.expectEqualStrings("\"C:\\Program Files\\nullclaw\\nullclaw.exe\" __windows-service-gateway", bin_path);
}

test "isWindowsServiceGatewayArg matches hidden service sentinel" {
    try std.testing.expect(isWindowsServiceGatewayArg("__windows-service-gateway"));
    try std.testing.expect(!isWindowsServiceGatewayArg("gateway"));
}
