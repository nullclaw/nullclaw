const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const auth = @import("auth.zig");

pub const ProbeResult = struct {
    live_ok: bool,
    reason: []const u8,
};

pub const codex_model_fallbacks = [_][]const u8{
    "gpt-5.4",
    "gpt-5.3-codex",
    "gpt-5.3-codex-spark",
    "gpt-5.2-codex",
    "gpt-5.2",
    "gpt-5.1-codex-max",
    "gpt-5.1-codex",
    "gpt-5.1",
    "gpt-5-codex",
    "gpt-5",
    "gpt-5.1-codex-mini",
    "gpt-5-codex-mini",
};

pub const DEFAULT_CODEX_MODEL = codex_model_fallbacks[0];
pub const OPENAI_CODEX_CREDENTIAL_KEY = "openai-codex";

const CommandRunResult = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
};

pub fn freeOwnedStrings(allocator: std.mem.Allocator, values: [][]const u8) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

pub fn loadCodexModels(allocator: std.mem.Allocator) ![][]const u8 {
    return loadCodexModelsInner(allocator) catch dupeFallbackModels(allocator);
}

pub fn probeCodexCli(allocator: std.mem.Allocator) ProbeResult {
    const command = resolveCodexCommand(allocator) orelse return .{
        .live_ok = false,
        .reason = "codex_cli_missing",
    };
    defer allocator.free(command);

    const result = runCommand(allocator, command, &.{ "login", "status" }) catch return .{
        .live_ok = false,
        .reason = "codex_cli_probe_failed",
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (!result.success) {
        return .{
            .live_ok = false,
            .reason = "codex_cli_not_authenticated",
        };
    }

    return .{
        .live_ok = true,
        .reason = "ok",
    };
}

pub fn probeOpenAiCodex(allocator: std.mem.Allocator) ProbeResult {
    if (hasOpenAiCodexCredential(allocator)) {
        return .{
            .live_ok = true,
            .reason = "ok",
        };
    }

    return .{
        .live_ok = false,
        .reason = "codex_auth_missing",
    };
}

pub fn hasOpenAiCodexCredential(allocator: std.mem.Allocator) bool {
    if (loadStoredOpenAiCodexCredential(allocator)) |token| {
        token.deinit(allocator);
        return true;
    }

    if (loadCodexCliToken(allocator)) |token| {
        token.deinit(allocator);
        return true;
    }

    return false;
}

pub fn loadStoredOpenAiCodexCredential(allocator: std.mem.Allocator) ?auth.OAuthToken {
    return auth.loadCredential(allocator, OPENAI_CODEX_CREDENTIAL_KEY) catch null;
}

pub fn resolveCodexCommand(allocator: std.mem.Allocator) ?[]u8 {
    const binary_name = if (builtin.os.tag == .windows) "codex.exe" else "codex";

    if (resolveFromPath(allocator, binary_name)) |command| return command;

    const static_candidates = [_][]const u8{
        if (builtin.os.tag == .windows) "C:\\Program Files\\Codex\\codex.exe" else "/opt/homebrew/bin/codex",
        if (builtin.os.tag == .windows) "C:\\Program Files (x86)\\Codex\\codex.exe" else "/usr/local/bin/codex",
        if (builtin.os.tag == .windows) "C:\\codex\\codex.exe" else "/usr/bin/codex",
    };
    for (static_candidates) |candidate| {
        if (fileExists(candidate)) {
            return allocator.dupe(u8, candidate) catch null;
        }
    }

    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);
    const home_candidates = [_][]const u8{
        ".local/bin",
        "bin",
        ".bun/bin",
        ".npm-global/bin",
    };
    for (home_candidates) |candidate_dir| {
        const candidate = std.fs.path.join(allocator, &.{ home, candidate_dir, binary_name }) catch continue;
        if (fileExists(candidate)) {
            return candidate;
        }
        allocator.free(candidate);
    }

    return null;
}

fn dupeFallbackModels(allocator: std.mem.Allocator) ![][]const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    for (codex_model_fallbacks) |model| {
        try result.append(allocator, try allocator.dupe(u8, model));
    }
    return result.toOwnedSlice(allocator);
}

fn loadCodexModelsInner(allocator: std.mem.Allocator) ![][]const u8 {
    const path = try resolveCodexStatePath(allocator, "models_cache.json");
    defer allocator.free(path);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 4 * 1024 * 1024);
    defer allocator.free(bytes);

    return parseCodexModelsFromBytes(allocator, bytes);
}

fn parseCodexModelsFromBytes(allocator: std.mem.Allocator, bytes: []const u8) ![][]const u8 {
    const parsed = try std.json.parseFromSlice(struct {
        models: []const struct {
            slug: []const u8,
            visibility: ?[]const u8 = null,
        } = &.{},
    }, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var models: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (models.items) |item| allocator.free(item);
        models.deinit(allocator);
    }

    for (parsed.value.models) |model| {
        if (model.slug.len == 0) continue;
        if (model.visibility) |visibility| {
            if (!std.mem.eql(u8, visibility, "list")) continue;
        }
        if (containsString(models.items, model.slug)) continue;
        try models.append(allocator, try allocator.dupe(u8, model.slug));
    }

    if (models.items.len == 0) return error.CodexModelsUnavailable;
    return models.toOwnedSlice(allocator);
}

fn containsString(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |entry| {
        if (std.mem.eql(u8, entry, needle)) return true;
    }
    return false;
}

pub fn loadCodexCliToken(allocator: std.mem.Allocator) ?auth.OAuthToken {
    const path = resolveCodexStatePath(allocator, "auth.json") catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(bytes);

    return parseCodexCliTokenFromBytes(allocator, bytes);
}

fn parseCodexCliTokenFromBytes(allocator: std.mem.Allocator, bytes: []const u8) ?auth.OAuthToken {
    const parsed = std.json.parseFromSlice(struct {
        tokens: ?struct {
            access_token: ?[]const u8 = null,
            refresh_token: ?[]const u8 = null,
        } = null,
    }, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();

    const tokens = parsed.value.tokens orelse return null;
    const access_token_str = tokens.access_token orelse return null;
    if (access_token_str.len == 0) return null;

    const access_token = allocator.dupe(u8, access_token_str) catch return null;
    errdefer allocator.free(access_token);

    const refresh_token: ?[]const u8 = if (tokens.refresh_token) |rt|
        if (rt.len > 0) allocator.dupe(u8, rt) catch null else null
    else
        null;
    errdefer if (refresh_token) |rt| allocator.free(rt);

    const expires_at = decodeJwtExp(allocator, access_token);
    if (expires_at != 0 and std.time.timestamp() + 300 >= expires_at and refresh_token == null) {
        allocator.free(access_token);
        if (refresh_token) |rt| allocator.free(rt);
        return null;
    }

    const token_type = allocator.dupe(u8, "Bearer") catch {
        allocator.free(access_token);
        if (refresh_token) |rt| allocator.free(rt);
        return null;
    };

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
        .token_type = token_type,
    };
}

fn resolveCodexStatePath(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    return resolveHomeRelativePath(allocator, ".codex", filename);
}

fn resolveHomeRelativePath(allocator: std.mem.Allocator, dir_name: []const u8, filename: []const u8) ![]u8 {
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, dir_name, filename });
}

fn decodeJwtExp(allocator: std.mem.Allocator, token: []const u8) i64 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return 0;
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return 0;
    const payload_b64 = rest[0..second_dot];
    if (payload_b64.len == 0) return 0;

    const Decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(payload_b64) catch return 0;
    const decoded = allocator.alloc(u8, decoded_len) catch return 0;
    defer allocator.free(decoded);
    Decoder.decode(decoded, payload_b64) catch return 0;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded, .{}) catch return 0;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return 0,
    };

    if (obj.get("exp")) |exp_val| {
        switch (exp_val) {
            .integer => |i| return i,
            .float => |f| return @intFromFloat(f),
            else => {},
        }
    }
    return 0;
}

fn resolveFromPath(allocator: std.mem.Allocator, binary_name: []const u8) ?[]u8 {
    const env_path = std.process.getEnvVarOwned(allocator, "PATH") catch return null;
    defer allocator.free(env_path);

    const separator: u8 = if (builtin.os.tag == .windows) ';' else ':';
    var path_it = std.mem.splitScalar(u8, env_path, separator);
    while (path_it.next()) |entry| {
        if (entry.len == 0) continue;
        const candidate = std.fs.path.join(allocator, &.{ entry, binary_name }) catch continue;
        if (fileExists(candidate)) return candidate;
        allocator.free(candidate);
    }
    return null;
}

fn fileExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        const file = std.fs.openFileAbsolute(path, .{}) catch return false;
        file.close();
        return true;
    }
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn runCommand(allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) !CommandRunResult {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, command);
    try argv.appendSlice(allocator, args);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
    });
    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .success = switch (result.term) {
            .Exited => |code| code == 0,
            else => false,
        },
    };
}

test "parseCodexModelsFromBytes parses visible model slugs" {
    const allocator = std.testing.allocator;
    const models = try parseCodexModelsFromBytes(allocator,
        \\{
        \\  "models": [
        \\    { "slug": "gpt-5.4", "visibility": "list" },
        \\    { "slug": "gpt-5.3-codex", "visibility": "hidden" },
        \\    { "slug": "gpt-5.2-codex", "visibility": "list" },
        \\    { "slug": "gpt-5.4", "visibility": "list" }
        \\  ]
        \\}
    );
    defer freeOwnedStrings(allocator, models);

    try std.testing.expectEqual(@as(usize, 2), models.len);
    try std.testing.expectEqualStrings("gpt-5.4", models[0]);
    try std.testing.expectEqualStrings("gpt-5.2-codex", models[1]);
}

test "parseCodexCliTokenFromBytes accepts access token" {
    const token = parseCodexCliTokenFromBytes(std.testing.allocator,
        \\{
        \\  "tokens": {
        \\    "access_token": "abc",
        \\    "refresh_token": ""
        \\  }
        \\}
    ) orelse return error.TestUnexpectedResult;
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc", token.access_token);
    try std.testing.expect(token.refresh_token == null);
}

test "parseCodexCliTokenFromBytes keeps expired token when refresh token exists" {
    const token = parseCodexCliTokenFromBytes(std.testing.allocator,
        \\{
        \\  "tokens": {
        \\    "access_token": "x.eyJleHAiOjF9.y",
        \\    "refresh_token": "refresh"
        \\  }
        \\}
    ) orelse return error.TestUnexpectedResult;
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("x.eyJleHAiOjF9.y", token.access_token);
    try std.testing.expectEqualStrings("refresh", token.refresh_token.?);
}
