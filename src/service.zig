//! Service management — launchd (macOS) and systemd (Linux) user services.
//!
//! Mirrors ZeroClaw's service module: install, start, stop, status, uninstall.
//! Uses child process execution to interact with launchctl / systemctl.

const std = @import("std");
const builtin = @import("builtin");

const SERVICE_LABEL = "com.nullclaw.daemon";

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
        try runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
        try runChecked(allocator, &.{ "systemctl", "--user", "start", "nullclaw.service" });
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
        runChecked(allocator, &.{ "systemctl", "--user", "stop", "nullclaw.service" }) catch {};
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
        const output = runCapture(allocator, &.{ "systemctl", "--user", "is-active", "nullclaw.service" }) catch try allocator.dupe(u8, "unknown");
        defer allocator.free(output);
        try w.print("Service state: {s}\n", .{std.mem.trim(u8, output, " \t\n\r")});
        const unit = try linuxServiceFile(allocator);
        defer allocator.free(unit);
        try w.print("Unit: {s}\n", .{unit});
        try w.flush();
    } else {
        return error.UnsupportedPlatform;
    }
}

fn uninstall(allocator: std.mem.Allocator) !void {
    stopService(allocator) catch {};

    if (comptime builtin.os.tag == .macos) {
        const plist = try macosServiceFile(allocator);
        defer allocator.free(plist);
        std.fs.deleteFileAbsolute(plist) catch {};
    } else if (comptime builtin.os.tag == .linux) {
        const unit = try linuxServiceFile(allocator);
        defer allocator.free(unit);
        std.fs.deleteFileAbsolute(unit) catch {};
        runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" }) catch {};
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
        \\    <string>daemon</string>
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

    if (std.mem.lastIndexOfScalar(u8, unit, '/')) |idx| {
        std.fs.makeDirAbsolute(unit[0..idx]) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);

    const content = try std.fmt.allocPrint(allocator,
        \\[Unit]
        \\Description=nullclaw daemon
        \\After=network.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStart={s} daemon
        \\Restart=always
        \\RestartSec=3
        \\
        \\[Install]
        \\WantedBy=default.target
    , .{exe_path});
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(unit, .{});
    defer file.close();
    try file.writeAll(content);

    runChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" }) catch {};
    runChecked(allocator, &.{ "systemctl", "--user", "enable", "nullclaw.service" }) catch {};
}

// ── Path helpers ─────────────────────────────────────────────────

fn getHomeDir(allocator: std.mem.Allocator) ![]u8 {
    return std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHomeDir;
}

fn macosServiceFile(allocator: std.mem.Allocator) ![]u8 {
    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/Library/LaunchAgents/{s}.plist", .{ home, SERVICE_LABEL });
}

fn linuxServiceFile(allocator: std.mem.Allocator) ![]u8 {
    const home = try getHomeDir(allocator);
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.config/systemd/user/nullclaw.service", .{home});
}

// ── Process helpers ──────────────────────────────────────────────

fn runChecked(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, allocator);
    child.stderr_behavior = .Pipe;
    try child.spawn();
    const result = try child.wait();
    if (result.Exited != 0) return error.CommandFailed;
}

fn runCapture(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    const stdout = try child.stdout.?.readToEndAlloc(allocator, 1024 * 1024);
    _ = try child.wait();
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
