const std = @import("std");
const config_mod = @import("config.zig");
const platform = @import("platform.zig");

pub const MutationAction = enum {
    set,
    unset,
};

pub const MutationOptions = struct {
    apply: bool = false,
};

pub const MutationResult = struct {
    path: []const u8,
    changed: bool,
    applied: bool,
    requires_restart: bool,
    old_value_json: []const u8,
    new_value_json: []const u8,
    backup_path: ?[]const u8 = null,
};

pub const Error = error{
    InvalidPath,
    PathNotAllowed,
    MissingValue,
    InvalidJson,
};

const allowed_exact_paths = [_][]const u8{
    "default_temperature",
    "reasoning_effort",
    "memory.backend",
    "memory.profile",
    "memory.auto_save",
    "gateway.host",
    "gateway.port",
    "tunnel.provider",
    "agents.defaults.model.primary",
};

const allowed_prefix_paths = [_][]const u8{
    "agent.",
    "autonomy.",
    "browser.",
    "channels.",
    "diagnostics.",
    "http_request.",
    "memory.",
    "models.providers.",
    "runtime.",
    "scheduler.",
    "security.",
    "session.",
    "tools.",
};

pub fn freeMutationResult(allocator: std.mem.Allocator, result: *MutationResult) void {
    allocator.free(result.path);
    allocator.free(result.old_value_json);
    allocator.free(result.new_value_json);
    if (result.backup_path) |p| allocator.free(p);
}

fn defaultConfigDir(allocator: std.mem.Allocator, nullclaw_home_override: ?[]const u8) ![]u8 {
    if (nullclaw_home_override) |config_dir| {
        return allocator.dupe(u8, config_dir);
    }

    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
}

fn defaultConfigPathFromDir(allocator: std.mem.Allocator, config_dir: []const u8) ![]u8 {
    return try std.fs.path.join(allocator, &.{ config_dir, "config.json" });
}

pub fn defaultConfigPath(allocator: std.mem.Allocator) ![]u8 {
    const nullclaw_home = std.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (nullclaw_home) |config_dir| allocator.free(config_dir);

    const config_dir = try defaultConfigDir(allocator, nullclaw_home);
    defer allocator.free(config_dir);

    return try defaultConfigPathFromDir(allocator, config_dir);
}

fn splitPathTokens(allocator: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    const trimmed = std.mem.trim(u8, path, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;

    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(allocator);

    var it = std.mem.splitScalar(u8, trimmed, '.');
    while (it.next()) |token| {
        if (token.len == 0) return error.InvalidPath;
        try out.append(allocator, token);
    }

    if (out.items.len == 0) return error.InvalidPath;
    return try out.toOwnedSlice(allocator);
}

fn isAllowedPath(path: []const u8) bool {
    for (allowed_exact_paths) |allowed| {
        if (std.mem.eql(u8, path, allowed)) return true;
    }
    for (allowed_prefix_paths) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

pub fn pathRequiresRestart(path: []const u8) bool {
    if (std.mem.startsWith(u8, path, "channels.")) return true;
    if (std.mem.startsWith(u8, path, "runtime.")) return true;
    if (std.mem.eql(u8, path, "memory.backend") or std.mem.eql(u8, path, "memory.profile")) return true;
    return false;
}

fn parseValueInput(allocator: std.mem.Allocator, raw_input: []const u8) !std.json.Value {
    const raw = std.mem.trim(u8, raw_input, " \t\r\n");
    if (raw.len == 0) return error.MissingValue;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return .{ .string = try allocator.dupe(u8, raw) };
    };
    return parsed.value;
}

fn ensureObject(value: *std.json.Value, allocator: std.mem.Allocator) *std.json.ObjectMap {
    switch (value.*) {
        .object => |*obj| return obj,
        else => {
            value.* = .{ .object = std.json.ObjectMap.init(allocator) };
            return &value.object;
        },
    }
}

fn valueAtPath(root: *std.json.Value, tokens: []const []const u8) ?*std.json.Value {
    var current = root;
    for (tokens) |token| {
        switch (current.*) {
            .object => |*obj| {
                current = obj.getPtr(token) orelse return null;
            },
            else => return null,
        }
    }
    return current;
}

fn setAtPath(
    root: *std.json.Value,
    allocator: std.mem.Allocator,
    tokens: []const []const u8,
    value: std.json.Value,
) !void {
    var current = root;

    if (tokens.len == 0) return;

    for (tokens[0 .. tokens.len - 1]) |token| {
        const obj = ensureObject(current, allocator);
        if (obj.getPtr(token)) |next| {
            current = next;
            continue;
        }

        const key_copy = try allocator.dupe(u8, token);
        try obj.put(key_copy, .{ .object = std.json.ObjectMap.init(allocator) });
        current = obj.getPtr(token).?;
    }

    const last = tokens[tokens.len - 1];
    const obj = ensureObject(current, allocator);
    if (obj.getPtr(last)) |slot| {
        slot.* = value;
        return;
    }

    const key_copy = try allocator.dupe(u8, last);
    try obj.put(key_copy, value);
}

fn unsetAtPath(root: *std.json.Value, tokens: []const []const u8) bool {
    if (tokens.len == 0) return false;

    var current = root;
    for (tokens[0 .. tokens.len - 1]) |token| {
        switch (current.*) {
            .object => |*obj| {
                current = obj.getPtr(token) orelse return false;
            },
            else => return false,
        }
    }

    switch (current.*) {
        .object => |*obj| return obj.swapRemove(tokens[tokens.len - 1]),
        else => return false,
    }
}

fn stringifyValue(allocator: std.mem.Allocator, value: ?*std.json.Value) ![]u8 {
    if (value) |v| {
        return try std.json.Stringify.valueAlloc(allocator, v.*, .{});
    }
    return try allocator.dupe(u8, "null");
}

fn readConfigOrDefault(allocator: std.mem.Allocator, config_path: []const u8) !struct { content: []u8, existed: bool } {
    const file = std.fs.openFileAbsolute(config_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            return .{ .content = try allocator.dupe(u8, "{}\n"), .existed = false };
        },
        else => return err,
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    return .{ .content = content, .existed = true };
}

test "defaultConfigDir uses NULLCLAW_HOME override" {
    const allocator = std.testing.allocator;
    const config_dir = try defaultConfigDir(allocator, "/tmp/nullclaw-home");
    defer allocator.free(config_dir);

    try std.testing.expectEqualStrings("/tmp/nullclaw-home", config_dir);
}

test "defaultConfigPath appends config filename to NULLCLAW_HOME override" {
    const allocator = std.testing.allocator;
    const config_path = try defaultConfigPathFromDir(allocator, "/tmp/nullclaw-home");
    defer allocator.free(config_path);

    const expected = try std.fmt.allocPrint(allocator, "/tmp/nullclaw-home{s}config.json", .{std.fs.path.sep_str});
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, config_path);
}

fn writeAtomic(allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    const dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const tmp_file = try std.fs.createFileAbsolute(tmp_path, .{});
    defer tmp_file.close();
    try tmp_file.writeAll(content);

    std.fs.renameAbsolute(tmp_path, path) catch {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(content);
    };
}

fn validateCandidateJson(allocator: std.mem.Allocator, config_path: []const u8, content: []const u8) !void {
    const config_dir = std.fs.path.dirname(config_path) orelse return error.InvalidPath;
    const workspace_dir = try std.fs.path.join(allocator, &.{ config_dir, "workspace" });

    var cfg = config_mod.Config{
        .workspace_dir = workspace_dir,
        .config_path = config_path,
        .allocator = allocator,
    };
    try cfg.parseJson(content);
    cfg.syncFlatFields();
    try cfg.validate();
}

pub fn getPathValueJson(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    const data = try readConfigOrDefault(allocator, config_path);
    defer allocator.free(data.content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, a, data.content, .{}) catch return error.InvalidJson;

    var root = parsed.value;
    if (root != .object) {
        root = .{ .object = std.json.ObjectMap.init(a) };
    }

    const tokens = try splitPathTokens(a, path);
    const value = valueAtPath(&root, tokens);
    return stringifyValue(allocator, value);
}

pub fn validateCurrentConfig(allocator: std.mem.Allocator) !void {
    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    const data = try readConfigOrDefault(allocator, config_path);
    defer allocator.free(data.content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try validateCandidateJson(arena.allocator(), config_path, data.content);
}

pub fn mutateDefaultConfig(
    allocator: std.mem.Allocator,
    action: MutationAction,
    path: []const u8,
    value_raw: ?[]const u8,
    options: MutationOptions,
) !MutationResult {
    const trimmed_path = std.mem.trim(u8, path, " \t\r\n");
    if (!isAllowedPath(trimmed_path)) return error.PathNotAllowed;

    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    const current = try readConfigOrDefault(allocator, config_path);
    defer allocator.free(current.content);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, a, current.content, .{}) catch return error.InvalidJson;
    var root = parsed.value;
    if (root != .object) {
        root = .{ .object = std.json.ObjectMap.init(a) };
    }

    const tokens = try splitPathTokens(a, trimmed_path);

    const old_value_json = try stringifyValue(allocator, valueAtPath(&root, tokens));
    errdefer allocator.free(old_value_json);

    switch (action) {
        .set => {
            const raw = value_raw orelse return error.MissingValue;
            const parsed_value = try parseValueInput(a, raw);
            try setAtPath(&root, a, tokens, parsed_value);
        },
        .unset => {
            _ = unsetAtPath(&root, tokens);
        },
    }

    const new_value_json = try stringifyValue(allocator, valueAtPath(&root, tokens));
    errdefer allocator.free(new_value_json);

    const changed = !std.mem.eql(u8, old_value_json, new_value_json);
    const requires_restart = pathRequiresRestart(trimmed_path);

    var rendered = try std.json.Stringify.valueAlloc(allocator, root, .{ .whitespace = .indent_2 });
    errdefer allocator.free(rendered);

    if (rendered.len == 0 or rendered[rendered.len - 1] != '\n') {
        const with_newline = try std.fmt.allocPrint(allocator, "{s}\n", .{rendered});
        allocator.free(rendered);
        rendered = with_newline;
    }

    try validateCandidateJson(a, config_path, rendered);

    var backup_path_opt: ?[]const u8 = null;

    if (options.apply and changed) {
        if (current.existed) {
            const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{config_path});
            errdefer allocator.free(backup_path);
            const backup_file = try std.fs.createFileAbsolute(backup_path, .{});
            defer backup_file.close();
            try backup_file.writeAll(current.content);
            backup_path_opt = backup_path;
        }

        try writeAtomic(allocator, config_path, rendered);
    }

    allocator.free(rendered);

    return .{
        .path = try allocator.dupe(u8, trimmed_path),
        .changed = changed,
        .applied = options.apply and changed,
        .requires_restart = requires_restart,
        .old_value_json = old_value_json,
        .new_value_json = new_value_json,
        .backup_path = backup_path_opt,
    };
}

test "pathRequiresRestart detects structural paths" {
    try std.testing.expect(pathRequiresRestart("channels.telegram.accounts.default.bot_token"));
    try std.testing.expect(pathRequiresRestart("runtime.kind"));
    try std.testing.expect(pathRequiresRestart("memory.backend"));
    try std.testing.expect(!pathRequiresRestart("default_temperature"));
}

test "isAllowedPath accepts channels and memory path" {
    try std.testing.expect(isAllowedPath("channels.telegram.accounts.default.bot_token"));
    try std.testing.expect(isAllowedPath("memory.backend"));
    try std.testing.expect(!isAllowedPath("identity.format"));
}

test "setAtPath creates nested objects and stores value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var root = std.json.Value{ .object = std.json.ObjectMap.init(a) };
    const tokens = [_][]const u8{ "memory", "backend" };
    const value = std.json.Value{ .string = try a.dupe(u8, "sqlite") };

    try setAtPath(&root, a, &tokens, value);

    const got = valueAtPath(&root, &tokens) orelse return error.TestUnexpectedResult;
    try std.testing.expect(got.* == .string);
    try std.testing.expectEqualStrings("sqlite", got.string);
}

test "unsetAtPath removes existing key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var root = std.json.Value{ .object = std.json.ObjectMap.init(a) };
    const tokens = [_][]const u8{ "gateway", "port" };
    try setAtPath(&root, a, &tokens, .{ .integer = 3000 });

    try std.testing.expect(valueAtPath(&root, &tokens) != null);
    try std.testing.expect(unsetAtPath(&root, &tokens));
    try std.testing.expect(valueAtPath(&root, &tokens) == null);
}
