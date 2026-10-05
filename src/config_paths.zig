const std = @import("std");
const builtin = @import("builtin");
const std_compat = @import("compat");
const platform = @import("platform.zig");

pub fn defaultConfigDirFromInputs(
    allocator: std.mem.Allocator,
    nullclaw_home: ?[]const u8,
    home_dir: ?[]const u8,
) ![]u8 {
    if (nullclaw_home) |config_dir| return allocator.dupe(u8, config_dir);
    const home = home_dir orelse return error.HomeDirNotFound;
    return std_compat.fs.path.join(allocator, &.{ home, ".nullclaw" });
}

pub fn defaultConfigDir(allocator: std.mem.Allocator) ![]u8 {
    const nullclaw_home = std_compat.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    if (nullclaw_home) |config_dir| return config_dir;

    // Resolve HOME even under test: keeping this call reachable preserves the
    // function's error set (callers switch on error.HomeDirNotFound). Only its
    // *result* is discarded for tests.
    const home_dir = try platform.getHomeDir(allocator);
    defer allocator.free(home_dir);

    // Tests must never resolve the developer's real `~/.nullclaw`: the suite has
    // to pass with HOME redirected or with writes to the user config directory
    // blocked (AGENTS.md §3.6 — no dependence on system state). NULLCLAW_HOME
    // above still wins, so tests that exercise that override keep working.
    // Same convention as cronJsonPath's test branch.
    if (comptime builtin.is_test) return testConfigDir(allocator);

    return defaultConfigDirFromInputs(allocator, null, home_dir);
}

/// Process-wide config directory for tests, created on first use.
var test_config_dir: ?[]u8 = null;

fn testConfigDir(allocator: std.mem.Allocator) ![]u8 {
    if (test_config_dir) |dir| return allocator.dupe(u8, dir);

    const tmp = try platform.getTempDir(std.heap.page_allocator);
    defer std.heap.page_allocator.free(tmp);
    // Unique per run: a fixed name would let state left behind by a previous
    // suite (daemon state, cron store) leak into this one.
    var suffix: [4]u8 = undefined;
    std_compat.crypto.random.bytes(&suffix);
    const suffix_hex = std.fmt.bytesToHex(suffix, .lower);
    const leaf = try std.fmt.allocPrint(std.heap.page_allocator, "nullclaw-test-config-{s}", .{&suffix_hex});
    defer std.heap.page_allocator.free(leaf);
    const path = try std_compat.fs.path.join(std.heap.page_allocator, &.{ tmp, leaf });
    errdefer std.heap.page_allocator.free(path);
    std_compat.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    test_config_dir = path;
    return allocator.dupe(u8, path);
}

pub fn pathFromConfigDir(
    allocator: std.mem.Allocator,
    config_dir: []const u8,
    leaf_name: []const u8,
) ![]u8 {
    return std_compat.fs.path.join(allocator, &.{ config_dir, leaf_name });
}

pub fn defaultWorkspaceDirFromInputs(
    allocator: std.mem.Allocator,
    nullclaw_workspace: ?[]const u8,
    config_dir: []const u8,
) ![]u8 {
    if (nullclaw_workspace) |workspace_dir| return allocator.dupe(u8, workspace_dir);
    return pathFromConfigDir(allocator, config_dir, "workspace");
}

pub fn defaultWorkspaceDirFromConfigDir(
    allocator: std.mem.Allocator,
    config_dir: []const u8,
) ![]u8 {
    return defaultWorkspaceDirFromInputs(allocator, null, config_dir);
}

pub fn defaultWorkspaceDir(allocator: std.mem.Allocator) ![]u8 {
    const nullclaw_workspace = std_compat.process.getEnvVarOwned(allocator, "NULLCLAW_WORKSPACE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    if (nullclaw_workspace) |workspace_dir| return workspace_dir;

    const config_dir = try defaultConfigDir(allocator);
    defer allocator.free(config_dir);
    return defaultWorkspaceDirFromConfigDir(allocator, config_dir);
}

test "defaultConfigDirFromInputs prefers NULLCLAW_HOME override" {
    const config_dir = try defaultConfigDirFromInputs(std.testing.allocator, "/tmp/nullclaw-home", "/home/ignored");
    defer std.testing.allocator.free(config_dir);

    try std.testing.expectEqualStrings("/tmp/nullclaw-home", config_dir);
}

test "defaultConfigDir in tests never resolves the real HOME config directory" {
    // Regression for #1029: cron/session tests wrote into the developer's real
    // `~/.nullclaw`, so the suite failed whenever that directory was not
    // writable (sandboxed runners, redirected HOME).
    const allocator = std.testing.allocator;

    const ambient = std_compat.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (ambient) |value| allocator.free(value);

    const dir = try defaultConfigDir(allocator);
    defer allocator.free(dir);

    try std.testing.expect(std.fs.path.isAbsolute(dir));

    if (ambient) |override| {
        // The documented override still wins when it is set.
        try std.testing.expectEqualStrings(override, dir);
        return;
    }

    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    const real_config_dir = try std_compat.fs.path.join(allocator, &.{ home, ".nullclaw" });
    defer allocator.free(real_config_dir);
    try std.testing.expect(!std.mem.eql(u8, dir, real_config_dir));

    // The private directory exists and opens, so writers under it succeed.
    var handle = try std_compat.fs.cwd().openDir(dir, .{});
    handle.close();
}

test "defaultConfigDirFromInputs falls back to HOME/.nullclaw" {
    const config_dir = try defaultConfigDirFromInputs(std.testing.allocator, null, "/home/alice");
    defer std.testing.allocator.free(config_dir);

    const expected = try std_compat.fs.path.join(std.testing.allocator, &.{ "/home/alice", ".nullclaw" });
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, config_dir);
}

test "defaultConfigDirFromInputs reports missing home" {
    try std.testing.expectError(error.HomeDirNotFound, defaultConfigDirFromInputs(std.testing.allocator, null, null));
}

test "pathFromConfigDir appends a leaf name" {
    const path = try pathFromConfigDir(std.testing.allocator, "/tmp/nullclaw-home", "config.json");
    defer std.testing.allocator.free(path);

    const expected = try std_compat.fs.path.join(std.testing.allocator, &.{ "/tmp/nullclaw-home", "config.json" });
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, path);
}

test "defaultWorkspaceDirFromInputs prefers NULLCLAW_WORKSPACE override" {
    const workspace_dir = try defaultWorkspaceDirFromInputs(std.testing.allocator, "/tmp/custom-workspace", "/tmp/nullclaw-home");
    defer std.testing.allocator.free(workspace_dir);

    try std.testing.expectEqualStrings("/tmp/custom-workspace", workspace_dir);
}

test "defaultWorkspaceDirFromConfigDir appends workspace" {
    const workspace_dir = try defaultWorkspaceDirFromConfigDir(std.testing.allocator, "/tmp/nullclaw-home");
    defer std.testing.allocator.free(workspace_dir);

    const expected = try std_compat.fs.path.join(std.testing.allocator, &.{ "/tmp/nullclaw-home", "workspace" });
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, workspace_dir);
}
