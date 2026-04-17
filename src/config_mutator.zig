const std = @import("std");
const std_compat = @import("compat");
const config_mod = @import("config.zig");
const config_paths = @import("config_paths.zig");
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

const primary_model_path = "agents.defaults.model.primary";
const primary_model_tokens = [_][]const u8{ "agents", "defaults", "model", "primary" };
const primary_model_provider_tokens = [_][]const u8{ "agents", "defaults", "model", "provider" };

const allowed_exact_paths = [_][]const u8{
    "default_temperature",
    "reasoning_effort",
    "memory.backend",
    "memory.profile",
    "memory.auto_save",
    "gateway.host",
    "gateway.port",
    "tunnel.provider",
    primary_model_path,
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
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return config_paths.defaultConfigDirFromInputs(allocator, nullclaw_home_override, home);
}

fn defaultConfigPathFromDir(allocator: std.mem.Allocator, config_dir: []const u8) ![]u8 {
    return config_paths.pathFromConfigDir(allocator, config_dir, "config.json");
}

pub fn defaultConfigPath(allocator: std.mem.Allocator) ![]u8 {
    const nullclaw_home = std_compat.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch |err| switch (err) {
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
    _ = allocator;
    switch (value.*) {
        .object => |*obj| return obj,
        else => {
            value.* = .{ .object = .empty };
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

fn stringifyPrimaryModelValueJson(allocator: std.mem.Allocator, root: *std.json.Value) ![]u8 {
    const primary_value = valueAtPath(root, &primary_model_tokens) orelse return try allocator.dupe(u8, "null");
    const provider_value = valueAtPath(root, &primary_model_provider_tokens) orelse return stringifyValue(allocator, primary_value);
    if (primary_value.* != .string or provider_value.* != .string) return stringifyValue(allocator, primary_value);

    const combined = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ provider_value.string, primary_value.string });
    defer allocator.free(combined);
    return try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .string = combined }, .{});
}

fn stringifyPathValueJson(
    allocator: std.mem.Allocator,
    root: *std.json.Value,
    path: []const u8,
    tokens: []const []const u8,
) ![]u8 {
    if (std.mem.eql(u8, path, primary_model_path)) {
        return stringifyPrimaryModelValueJson(allocator, root);
    }
    return stringifyValue(allocator, valueAtPath(root, tokens));
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
        try obj.put(allocator, key_copy, .{ .object = .empty });
        current = obj.getPtr(token).?;
    }

    const last = tokens[tokens.len - 1];
    const obj = ensureObject(current, allocator);
    if (obj.getPtr(last)) |slot| {
        slot.* = value;
        return;
    }

    const key_copy = try allocator.dupe(u8, last);
    try obj.put(allocator, key_copy, value);
}

fn setPrimaryModelPathValue(
    root: *std.json.Value,
    allocator: std.mem.Allocator,
    raw_input: []const u8,
) !void {
    const parsed_value = try parseValueInput(allocator, raw_input);
    switch (parsed_value) {
        .string => |primary| {
            if (config_mod.splitPrimaryModelRef(primary)) |parsed_ref| {
                if (config_mod.shouldSerializeDefaultModelProviderField(parsed_ref.provider)) {
                    try setAtPath(root, allocator, &primary_model_provider_tokens, .{ .string = parsed_ref.provider });
                    try setAtPath(root, allocator, &primary_model_tokens, .{ .string = parsed_ref.model });
                    return;
                }
            }
        },
        else => {},
    }

    // Keep the logical provider/model pair in sync for user-facing primary updates.
    _ = unsetAtPath(root, &primary_model_provider_tokens);
    try setAtPath(root, allocator, &primary_model_tokens, parsed_value);
}

fn unsetPrimaryModelPathValue(root: *std.json.Value) void {
    _ = unsetAtPath(root, &primary_model_provider_tokens);
    _ = unsetAtPath(root, &primary_model_tokens);
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
    const file = std_compat.fs.openFileAbsolute(config_path, .{}) catch |err| switch (err) {
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

    const expected = try std.fmt.allocPrint(allocator, "/tmp/nullclaw-home{s}config.json", .{std_compat.fs.path.sep_str});
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, config_path);
}

fn writeAtomic(allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    const dir = std_compat.fs.path.dirname(path) orelse return error.InvalidPath;
    std_compat.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const tmp_file = try std_compat.fs.createFileAbsolute(tmp_path, .{});
    defer tmp_file.close();
    try tmp_file.writeAll(content);

    std_compat.fs.renameAbsolute(tmp_path, path) catch {
        std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
        const file = try std_compat.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(content);
    };
}

fn validateCandidateJson(allocator: std.mem.Allocator, config_path: []const u8, content: []const u8) !void {
    const config_dir = std_compat.fs.path.dirname(config_path) orelse return error.InvalidPath;
    const workspace_dir = try config_paths.defaultWorkspaceDirFromConfigDir(allocator, config_dir);

    var cfg = config_mod.Config{
        .workspace_dir = workspace_dir,
        .config_path = config_path,
        .allocator = allocator,
    };
    try cfg.parseJson(content);
    cfg.syncFlatFields();
    try cfg.validate();
}

pub fn validateProposedConfigJson(allocator: std.mem.Allocator, content: []const u8) !void {
    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try validateCandidateJson(arena.allocator(), config_path, content);
}

pub fn getCurrentConfigJson(allocator: std.mem.Allocator) ![]u8 {
    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    const file = std_compat.fs.openFileAbsolute(config_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer file.close();

    return try file.readToEndAlloc(allocator, 1024 * 1024);
}

pub fn findPathValueJson(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    const config_path = try defaultConfigPath(allocator);
    defer allocator.free(config_path);

    const file = std_compat.fs.openFileAbsolute(config_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, a, data, .{}) catch return error.InvalidJson;

    var root = parsed.value;
    if (root != .object) {
        root = .{ .object = .empty };
    }

    const tokens = try splitPathTokens(a, path);
    if (valueAtPath(&root, tokens) == null) return null;
    return try stringifyPathValueJson(allocator, &root, path, tokens);
}

pub fn getPathValueJson(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (try findPathValueJson(allocator, path)) |value_json| return value_json;
    return try allocator.dupe(u8, "null");
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
        root = .{ .object = .empty };
    }

    const tokens = try splitPathTokens(a, trimmed_path);

    const old_value_json = try stringifyPathValueJson(allocator, &root, trimmed_path, tokens);
    errdefer allocator.free(old_value_json);

    switch (action) {
        .set => {
            const raw = value_raw orelse return error.MissingValue;
            if (std.mem.eql(u8, trimmed_path, primary_model_path)) {
                try setPrimaryModelPathValue(&root, a, raw);
            } else {
                const parsed_value = try parseValueInput(a, raw);
                try setAtPath(&root, a, tokens, parsed_value);
            }
        },
        .unset => {
            if (std.mem.eql(u8, trimmed_path, primary_model_path)) {
                unsetPrimaryModelPathValue(&root);
            } else {
                _ = unsetAtPath(&root, tokens);
            }
        },
    }

    const new_value_json = try stringifyPathValueJson(allocator, &root, trimmed_path, tokens);
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
            const backup_file = try std_compat.fs.createFileAbsolute(backup_path, .{});
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

    var root = std.json.Value{ .object = .empty };
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

    var root = std.json.Value{ .object = .empty };
    const tokens = [_][]const u8{ "gateway", "port" };
    try setAtPath(&root, a, &tokens, .{ .integer = 3000 });

    try std.testing.expect(valueAtPath(&root, &tokens) != null);
    try std.testing.expect(unsetAtPath(&root, &tokens));
    try std.testing.expect(valueAtPath(&root, &tokens) == null);
}

test "stringifyPathValueJson reconstructs logical default model primary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        a,
        \\{"agents":{"defaults":{"model":{"provider":"custom:https://example.com/api","primary":"meta-llama/Llama-4-70B-Instruct"}}}}
    ,
        .{},
    );
    var root = parsed.value;
    const tokens = try splitPathTokens(a, primary_model_path);

    const value_json = try stringifyPathValueJson(std.testing.allocator, &root, primary_model_path, tokens);
    defer std.testing.allocator.free(value_json);

    // Regression: split provider/model storage must still surface the documented provider/model path value.
    try std.testing.expectEqualStrings(
        "\"custom:https://example.com/api/meta-llama/Llama-4-70B-Instruct\"",
        value_json,
    );
}

test "setPrimaryModelPathValue stores split provider field for versionless custom urls" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var root = std.json.Value{ .object = .empty };

    try setPrimaryModelPathValue(&root, a, "custom:https://gateway.example.com/api/qianfan/custom-model");

    const provider_value = valueAtPath(&root, &primary_model_provider_tokens) orelse return error.TestUnexpectedResult;
    const primary_value = valueAtPath(&root, &primary_model_tokens) orelse return error.TestUnexpectedResult;
    try std.testing.expect(provider_value.* == .string);
    try std.testing.expect(primary_value.* == .string);
    try std.testing.expectEqualStrings("custom:https://gateway.example.com/api", provider_value.string);
    try std.testing.expectEqualStrings("qianfan/custom-model", primary_value.string);
}

test "setPrimaryModelPathValue clears stale split provider field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        a,
        \\{"agents":{"defaults":{"model":{"provider":"custom:https://example.com/api","primary":"meta-llama/Llama-4-70B-Instruct"}}}}
    ,
        .{},
    );
    var root = parsed.value;

    try setPrimaryModelPathValue(&root, a, "openai/gpt-5.2");

    try std.testing.expect(valueAtPath(&root, &primary_model_provider_tokens) == null);

    const tokens = try splitPathTokens(a, primary_model_path);
    const value_json = try stringifyPathValueJson(std.testing.allocator, &root, primary_model_path, tokens);
    defer std.testing.allocator.free(value_json);
    try std.testing.expectEqualStrings("\"openai/gpt-5.2\"", value_json);

    const rendered = try std.json.Stringify.valueAlloc(std.testing.allocator, root, .{});
    defer std.testing.allocator.free(rendered);

    var cfg_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer cfg_arena.deinit();
    var cfg = config_mod.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = cfg_arena.allocator(),
    };
    try cfg.parseJson(rendered);

    try std.testing.expectEqualStrings("openai", cfg.default_provider);
    try std.testing.expectEqualStrings("gpt-5.2", cfg.default_model.?);
}
