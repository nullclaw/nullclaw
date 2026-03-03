const std = @import("std");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const SecurityPolicy = @import("../security/policy.zig").SecurityPolicy;
const audit_mod = @import("../security/audit.zig");
const UNAVAILABLE_WORKSPACE_SENTINEL = "/__nullclaw_workspace_unavailable__";

/// Default maximum shell command execution time (nanoseconds).
const DEFAULT_SHELL_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
/// Default maximum output size in bytes (1MB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Environment variables safe to pass to shell commands.
const SAFE_ENV_VARS = [_][]const u8{
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
};

/// Shell command execution tool with workspace scoping.
pub const ShellTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    timeout_ns: u64 = DEFAULT_SHELL_TIMEOUT_NS,
    max_output_bytes: usize = DEFAULT_MAX_OUTPUT_BYTES,
    policy: ?*const SecurityPolicy = null,
    audit_logger: ?*const audit_mod.AuditLogger = null,
    audit_channel: []const u8 = "runtime",

    pub const tool_name = "shell";
    pub const tool_description = "Execute a shell command in the workspace directory";
    pub const tool_params =
        \\{"type":"object","properties":{"command":{"type":"string","description":"The shell command to execute"},"cwd":{"type":"string","description":"Working directory (absolute path within allowed paths; defaults to workspace)"}},"required":["command"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *ShellTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *ShellTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const started_ms = std.time.milliTimestamp();
        // Parse the command from the pre-parsed JSON object
        const command = root.getString(args, "command") orelse
            return ToolResult.fail("Missing 'command' parameter");

        var risk_level: []const u8 = "none";

        // Validate command against security policy
        if (self.policy) |pol| {
            _ = pol.validateCommandExecution(command, false) catch |err| {
                const elapsed_ms = elapsedMillis(started_ms);
                risk_level = pol.commandRiskLevel(command).toString();
                self.logCommandEvent(command, risk_level, false, false, false, elapsed_ms);
                self.logPolicyViolationEvent(command, risk_level, elapsed_ms, @errorName(err));
                return switch (err) {
                    error.CommandNotAllowed => ToolResult.fail("Command not allowed by security policy"),
                    error.HighRiskBlocked => ToolResult.fail("High-risk command blocked by security policy"),
                    error.ApprovalRequired => blk: {
                        const msg = try std.fmt.allocPrint(allocator, "Command requires approval (medium/high risk): {s}", .{command});
                        break :blk ToolResult{ .success = false, .output = "", .error_msg = msg };
                    },
                };
            };
            risk_level = pol.commandRiskLevel(command).toString();
        }

        // Determine working directory
        const effective_cwd = if (root.getString(args, "cwd")) |cwd| blk: {
            // cwd must be absolute
            if (cwd.len == 0 or !std.fs.path.isAbsolute(cwd))
                return ToolResult.fail("cwd must be an absolute path");
            // Resolve and validate
            const resolved_cwd = std.fs.cwd().realpathAlloc(allocator, cwd) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve cwd: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_cwd);

            const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);
            if (ws_resolved == null and self.allowed_paths.len == 0)
                return ToolResult.fail("cwd not allowed (workspace unavailable and no allowed_paths configured)");

            if (!isResolvedPathAllowed(allocator, resolved_cwd, ws_resolved orelse UNAVAILABLE_WORKSPACE_SENTINEL, self.allowed_paths))
                return ToolResult.fail("cwd is outside allowed areas");

            break :blk cwd;
        } else self.workspace_dir;

        // Clear environment to prevent leaking API keys (CWE-200),
        // then re-add only safe, functional variables.
        var env = std.process.EnvMap.init(allocator);
        defer env.deinit();
        for (&SAFE_ENV_VARS) |key| {
            if (platform.getEnvOrNull(allocator, key)) |val| {
                defer allocator.free(val);
                try env.put(key, val);
            }
        }

        // Execute via platform shell
        const proc = @import("process_util.zig");
        const result = try proc.run(allocator, &.{ platform.getShell(), platform.getShellFlag(), command }, .{
            .cwd = effective_cwd,
            .env_map = &env,
            .max_output_bytes = self.max_output_bytes,
        });
        defer allocator.free(result.stderr);
        const elapsed_ms = elapsedMillis(started_ms);

        if (result.success) {
            self.logCommandEvent(command, risk_level, false, true, true, elapsed_ms);
            if (result.stdout.len > 0) return ToolResult{ .success = true, .output = result.stdout };
            allocator.free(result.stdout);
            return ToolResult{ .success = true, .output = try allocator.dupe(u8, "(no output)") };
        }
        self.logCommandEvent(command, risk_level, false, true, false, elapsed_ms);
        defer allocator.free(result.stdout);
        if (result.exit_code != null) {
            const err_out = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Command failed with non-zero exit code");
            return ToolResult{ .success = false, .output = "", .error_msg = err_out };
        }
        return ToolResult{ .success = false, .output = "", .error_msg = "Command terminated by signal" };
    }

    fn elapsedMillis(started_ms: i64) u64 {
        const now_ms = std.time.milliTimestamp();
        if (now_ms <= started_ms) return 0;
        return @intCast(now_ms - started_ms);
    }

    fn logCommandEvent(
        self: *const ShellTool,
        command: []const u8,
        risk_level: []const u8,
        approved: bool,
        allowed: bool,
        success: bool,
        duration_ms: u64,
    ) void {
        const logger = self.audit_logger orelse return;
        logger.logCommand(.{
            .channel = self.audit_channel,
            .command = command,
            .risk_level = risk_level,
            .approved = approved,
            .allowed = allowed,
            .success = success,
            .duration_ms = duration_ms,
        }) catch {};
    }

    fn logPolicyViolationEvent(
        self: *const ShellTool,
        command: []const u8,
        risk_level: []const u8,
        duration_ms: u64,
        err_msg: []const u8,
    ) void {
        const logger = self.audit_logger orelse return;
        var event = audit_mod.AuditEvent.init(.policy_violation)
            .withActor(self.audit_channel, null, null)
            .withAction(command, risk_level, false, false)
            .withResult(false, null, duration_ms, err_msg);
        event.security.policy_violation = true;
        logger.log(&event) catch {};
    }
};

/// Extract a string field value from a JSON blob (minimal parser — no allocations).
/// NOTE: Prefer root.getString() with pre-parsed ObjectMap for tool implementations.
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

test "shell tool schema has command" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "command") != null);
}

test "shell executes echo" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "hello") != null);
}

test "shell captures failing command" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"ls /nonexistent_dir_xyz_42\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
}

test "shell missing command param" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
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

test "shell cwd inside workspace works without allowed_paths" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var args_buf: [512]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{tmp_path});

    var st = ShellTool{ .workspace_dir = tmp_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, tmp_path) != null);
}

test "shell cwd outside workspace without allowed_paths is rejected" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makeDir("ws");
    try tmp_dir.dir.makeDir("other");
    const root_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const ws_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const other_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "other" });
    defer std.testing.allocator.free(other_path);

    var args_buf: [768]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{other_path});

    var st = ShellTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);
}

test "shell cwd relative path is rejected" {
    var st = ShellTool{ .workspace_dir = "/tmp", .allowed_paths = &.{"/tmp"} };
    const parsed = try root.parseTestArgs("{\"command\": \"pwd\", \"cwd\": \"relative\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "absolute") != null);
}

test "shell cwd with allowed_paths runs in cwd" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var args_buf: [512]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{tmp_path});

    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    var st = ShellTool{ .workspace_dir = ".", .allowed_paths = &.{tmp_path} };
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, tmp_path) != null);
}

test "shell ApprovalRequired error includes command name" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    const allowed = [_][]const u8{ "git", "ls", "cat", "grep", "echo", "touch" };
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .require_approval_for_medium_risk = true,
        .block_high_risk_commands = false,
        .tracker = &tracker,
        .allowed_commands = &allowed,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"touch test.txt\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    defer std.testing.allocator.free(result.error_msg.?);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "touch test.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "approval") != null);
}

test "shell ApprovalRequired propagates oom for error message allocation" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    const allowed = [_][]const u8{ "git", "ls", "cat", "grep", "echo", "touch" };
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .require_approval_for_medium_risk = true,
        .block_high_risk_commands = false,
        .tracker = &tracker,
        .allowed_commands = &allowed,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"touch test.txt\"}");
    defer parsed.deinit();

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        st.execute(failing.allocator(), parsed.value.object),
    );
}

test "shell wildcard policy permits command outside default allowlist" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var restrictive_tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer restrictive_tracker.deinit();
    var restrictive_policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .allowed_commands = &policy_mod.default_allowed_commands,
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &restrictive_tracker,
    };

    var restrictive_tool = ShellTool{ .workspace_dir = "/tmp", .policy = &restrictive_policy };
    const restricted_args = try root.parseTestArgs("{\"command\": \"true\"}");
    defer restricted_args.deinit();
    const restricted = try restrictive_tool.execute(std.testing.allocator, restricted_args.value.object);
    defer if (restricted.output.len > 0) std.testing.allocator.free(restricted.output);
    try std.testing.expect(!restricted.success);
    try std.testing.expect(restricted.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, restricted.error_msg.?, "Command not allowed") != null);

    var wildcard_tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer wildcard_tracker.deinit();
    var wildcard_policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &wildcard_tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &wildcard_policy };

    const parsed = try root.parseTestArgs("{\"command\": \"true\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
}

test "shell without policy executes command" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = null };

    const parsed = try root.parseTestArgs("{\"command\": \"echo no-policy\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
}

test "shell audit logger writes command execution events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "shell_audit.log",
        .max_size_mb = 10,
    }, tmp_path);
    defer logger.deinit();

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .audit_logger = &logger,
        .audit_channel = "runtime",
    };
    const parsed = try root.parseTestArgs("{\"command\": \"echo audit-test\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "shell_audit.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"command_execution\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "audit-test") != null);
}

test "shell audit logger writes policy violation events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "policy_audit.log",
        .max_size_mb = 10,
    }, tmp_path);
    defer logger.deinit();

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = tmp_path,
        .allowed_commands = &policy_mod.default_allowed_commands,
        .block_high_risk_commands = true,
        .require_approval_for_medium_risk = true,
        .tracker = &tracker,
    };

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .policy = &policy,
        .audit_logger = &logger,
        .audit_channel = "runtime",
    };
    const parsed = try root.parseTestArgs("{\"command\": \"rm -rf /tmp/never\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "policy_audit.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"command_execution\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"policy_violation\"") != null);
}
