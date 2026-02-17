const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;

/// Maximum shell command execution time (nanoseconds).
const SHELL_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
/// Maximum output size in bytes (1MB).
const MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Environment variables safe to pass to shell commands.
const SAFE_ENV_VARS = [_][]const u8{
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
};

/// Shell command execution tool with workspace scoping.
pub const ShellTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ShellTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ShellTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "shell";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Execute a shell command in the workspace directory";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"command":{"type":"string","description":"The shell command to execute"}},"required":["command"]}
        ;
    }

    fn execute(self: *ShellTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        // Parse the command from JSON
        const command = parseStringField(args_json, "command") orelse
            return ToolResult.fail("Missing 'command' parameter");

        // Execute via /bin/sh -c
        var child = std.process.Child.init(
            &.{ "/bin/sh", "-c", command },
            allocator,
        );
        child.cwd = self.workspace_dir;

        // Clear environment to prevent leaking API keys (CWE-200),
        // then re-add only safe, functional variables.
        child.env_map = null;

        var env = std.process.EnvMap.init(allocator);
        defer env.deinit();
        for (&SAFE_ENV_VARS) |key| {
            if (std.posix.getenv(key)) |val| {
                try env.put(key, val);
            }
        }
        child.env_map = &env;

        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        // Read stdout and stderr
        const stdout = try child.stdout.?.readToEndAlloc(allocator, MAX_OUTPUT_BYTES);
        defer allocator.free(stdout);
        const stderr = try child.stderr.?.readToEndAlloc(allocator, MAX_OUTPUT_BYTES);
        defer allocator.free(stderr);

        const term = try child.wait();
        const success = term.Exited == 0;

        // Build output — allocator-owned copy for the caller
        if (success) {
            const out = try allocator.dupe(u8, if (stdout.len > 0) stdout else "(no output)");
            return ToolResult{ .success = true, .output = out };
        } else {
            const err_out = try allocator.dupe(u8, if (stderr.len > 0) stderr else "Command failed with non-zero exit code");
            return ToolResult{ .success = false, .output = "", .error_msg = err_out };
        }
    }
};

/// Extract a string field value from a JSON blob (minimal parser — no allocations).
pub fn parseStringField(json: []const u8, key: []const u8) ?[]const u8 {
    // Find "key": "value"
    // Build the search pattern: "key":"  or "key" : "
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1) {}

    if (i >= after_key.len or after_key[i] != '"') return null;
    i += 1; // skip opening quote

    // Find closing quote (handle escaped quotes)
    const start = i;
    while (i < after_key.len) : (i += 1) {
        if (after_key[i] == '\\' and i + 1 < after_key.len) {
            i += 1; // skip escaped char
            continue;
        }
        if (after_key[i] == '"') {
            return after_key[start..i];
        }
    }
    return null;
}

/// Extract a boolean field value from a JSON blob.
pub fn parseBoolField(json: []const u8, key: []const u8) ?bool {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1) {}

    if (i + 4 <= after_key.len and std.mem.eql(u8, after_key[i..][0..4], "true")) return true;
    if (i + 5 <= after_key.len and std.mem.eql(u8, after_key[i..][0..5], "false")) return false;
    return null;
}

/// Extract an integer field value from a JSON blob.
pub fn parseIntField(json: []const u8, key: []const u8) ?i64 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1) {}

    const start = i;
    if (i < after_key.len and after_key[i] == '-') i += 1;
    while (i < after_key.len and after_key[i] >= '0' and after_key[i] <= '9') : (i += 1) {}
    if (i == start) return null;

    return std.fmt.parseInt(i64, after_key[start..i], 10) catch null;
}

// ── Tests ───────────────────────────────────────────────────────────

test "shell tool name" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expectEqualStrings("shell", t.name());
}

test "shell tool description not empty" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expect(t.description().len > 0);
}

test "shell tool schema has command" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "command") != null);
}

test "shell executes echo" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"command\": \"echo hello\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "hello") != null);
}

test "shell captures failing command" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{\"command\": \"ls /nonexistent_dir_xyz_42\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
}

test "shell missing command param" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "parseStringField basic" {
    const json = "{\"command\": \"echo hello\", \"other\": \"val\"}";
    const val = parseStringField(json, "command");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("echo hello", val.?);
}

test "parseStringField missing" {
    const json = "{\"other\": \"val\"}";
    try std.testing.expect(parseStringField(json, "command") == null);
}

test "parseBoolField true" {
    const json = "{\"cached\": true}";
    try std.testing.expectEqual(@as(?bool, true), parseBoolField(json, "cached"));
}

test "parseBoolField false" {
    const json = "{\"cached\": false}";
    try std.testing.expectEqual(@as(?bool, false), parseBoolField(json, "cached"));
}

test "parseIntField positive" {
    const json = "{\"limit\": 42}";
    try std.testing.expectEqual(@as(?i64, 42), parseIntField(json, "limit"));
}

test "parseIntField negative" {
    const json = "{\"offset\": -5}";
    try std.testing.expectEqual(@as(?i64, -5), parseIntField(json, "offset"));
}
