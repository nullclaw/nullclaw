const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const fs_compat = @import("../fs_compat.zig");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const SecurityPolicy = @import("../security/policy.zig").SecurityPolicy;
const json_miniparse = @import("../json_miniparse.zig");
const command_summary = @import("../command_summary.zig");
const UNAVAILABLE_WORKSPACE_SENTINEL = "/__nullclaw_workspace_unavailable__";
const log = std.log.scoped(.shell);
const Sandbox = @import("../security/sandbox.zig").Sandbox;
const SandboxStorage = @import("../security/sandbox.zig").SandboxStorage;

/// Default maximum shell command execution time (nanoseconds).
const DEFAULT_SHELL_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
/// Default maximum output size in bytes (1MB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Environment variables safe to pass to shell commands.
const SAFE_ENV_VARS: []const []const u8 = if (builtin.os.tag == .windows)
    &.{
        "PATH",
        "HOME",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "USER",
        "SHELL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    }
else
    &.{
        "PATH",
        "HOME",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "USER",
        "SHELL",
        "TMPDIR",
    };

fn safeEnvVarAllowed(key: []const u8) bool {
    for (SAFE_ENV_VARS) |allowed| {
        if (std.mem.eql(u8, allowed, key)) return true;
    }
    return false;
}

/// Validate that a platform path-list value has all components within
/// the sandbox (workspace + allowed_paths). Uses the same validation as
/// file access: system blocklist always rejects, then workspace and
/// allowed_paths are checked via realpath canonicalization.
/// Platform-aware path-list delimiter: `;` on Windows, `:` elsewhere.
const path_list_delimiter: u8 = if (@import("builtin").os.tag == .windows) ';' else ':';

fn validatePathEnvValue(
    allocator: std.mem.Allocator,
    value: []const u8,
    ws_resolved: []const u8,
    allowed_paths: []const []const u8,
) bool {
    if (value.len == 0) return true;
    var iter = std.mem.splitScalar(u8, value, path_list_delimiter);
    while (iter.next()) |component| {
        if (component.len == 0) continue;
        // Must be absolute
        if (!std_compat.fs.path.isAbsolute(component)) return false;
        // Resolve to canonical path (follows symlinks)
        const resolved = fs_compat.realpathAllocPath(allocator, component) catch
            return false; // path doesn't exist or can't be resolved
        defer allocator.free(resolved);
        if (!isResolvedPathAllowed(allocator, resolved, ws_resolved, allowed_paths))
            return false;
    }
    return true;
}

fn wrapCommandArgv(sandbox: ?Sandbox, base_argv: []const []const u8, wrap_buf: [][]const u8) ![]const []const u8 {
    if (sandbox) |sb| {
        return sb.wrapCommand(base_argv, wrap_buf);
    }
    return base_argv;
}

fn sandboxRestrictsToWorkspace(sandbox: ?Sandbox) bool {
    if (sandbox) |sb| {
        return std.mem.eql(u8, sb.name(), "bubblewrap") or
            std.mem.eql(u8, sb.name(), "docker");
    }
    return false;
}

fn normalizeCommandInput(command: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (unwrapMarkdownFence(trimmed)) |unfenced| {
        return std.mem.trim(u8, unfenced, " \t\r\n");
    }
    return trimmed;
}

fn unwrapMarkdownFence(command: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, command, "```")) return null;
    const after_open = command[3..];
    const close_idx = std.mem.lastIndexOf(u8, after_open, "```") orelse return null;
    const trailing = std.mem.trim(u8, after_open[close_idx + 3 ..], " \t\r\n");
    if (trailing.len != 0) return null;

    const fenced_body = after_open[0..close_idx];
    const content = if (std.mem.indexOfScalar(u8, fenced_body, '\n')) |first_newline|
        fenced_body[first_newline + 1 ..]
    else
        fenced_body;
    const trimmed_content = std.mem.trim(u8, content, " \t\r\n");
    if (trimmed_content.len == 0) return null;
    return trimmed_content;
}

/// Shell command execution tool with workspace scoping.
pub const ShellTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    timeout_ns: u64 = DEFAULT_SHELL_TIMEOUT_NS,
    max_output_bytes: usize = DEFAULT_MAX_OUTPUT_BYTES,
    policy: ?*const SecurityPolicy = null,
    /// Env var names whose platform path-list values are validated
    /// against workspace + allowed_paths before passing to child processes.
    path_env_vars: []const []const u8 = &.{},
    sandbox: ?Sandbox = null,
    // Storage for sandbox backends; must outlive the ShellTool.
    // This is part of the vtable ownership pattern: the tool creator owns the storage.
    sandbox_storage: SandboxStorage = .{},
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
        // Parse the command from the pre-parsed JSON object
        const command_input = root.getString(args, "command") orelse
            return ToolResult.fail("Missing 'command' parameter");
        const command = normalizeCommandInput(command_input);

        // Validate command against security policy
        if (self.policy) |pol| {
            _ = pol.validateCommandExecution(command, false) catch |err| {
                return switch (err) {
                    error.CommandNotAllowed => blk: {
                        const summary = command_summary.summarizeBlockedCommand(command);
                        log.warn("command blocked by security policy: head={s} bytes={d} assignments={d}", .{
                            summary.head,
                            summary.byte_len,
                            summary.assignment_count,
                        });
                        break :blk ToolResult.fail("Command not allowed by security policy");
                    },
                    error.HighRiskBlocked => ToolResult.fail("High-risk command blocked by security policy"),
                    error.ApprovalRequired => blk: {
                        const msg = try std.fmt.allocPrint(allocator, "Command requires approval (medium/high risk): {s}", .{command});
                        break :blk ToolResult{ .success = false, .output = "", .error_msg = msg };
                    },
                };
            };
        }

        // Determine working directory
        const effective_cwd = if (root.getString(args, "cwd")) |cwd| blk: {
            // cwd must be absolute
            if (cwd.len == 0 or !std_compat.fs.path.isAbsolute(cwd))
                return ToolResult.fail("cwd must be an absolute path");
            // Resolve and validate
            const resolved_cwd = fs_compat.realpathAllocPath(allocator, cwd) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve cwd: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_cwd);

            const ws_resolved: ?[]const u8 = fs_compat.realpathAllocPath(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);
            if (ws_resolved == null and self.allowed_paths.len == 0)
                return ToolResult.fail("cwd not allowed (workspace unavailable and no allowed_paths configured)");

            if (!isResolvedPathAllowed(allocator, resolved_cwd, ws_resolved orelse UNAVAILABLE_WORKSPACE_SENTINEL, self.allowed_paths))
                return ToolResult.fail("cwd is outside allowed areas");

            break :blk cwd;
        } else self.workspace_dir;

        if (sandboxRestrictsToWorkspace(self.sandbox)) {
            const resolved_cwd = fs_compat.realpathAllocPath(allocator, effective_cwd) catch
                return ToolResult.fail("sandboxed cwd must stay within workspace");
            defer allocator.free(resolved_cwd);
            const ws_resolved = fs_compat.realpathAllocPath(allocator, self.workspace_dir) catch
                return ToolResult.fail("sandboxed cwd must stay within workspace");
            defer allocator.free(ws_resolved);

            if (!isResolvedPathAllowed(allocator, resolved_cwd, ws_resolved, &.{})) {
                return ToolResult.fail("sandboxed cwd must stay within workspace");
            }
        }

        // Clear environment to prevent leaking API keys (CWE-200),
        // then re-add only safe, functional variables.
        var env = std_compat.process.EnvMap.init(allocator);
        defer env.deinit();
        for (SAFE_ENV_VARS) |key| {
            if (platform.getEnvOrNull(allocator, key)) |val| {
                defer allocator.free(val);
                try env.put(key, val);
            }
        }

        // Add path-validated env vars: each delimiter-separated component
        // (`:` on Unix, `;` on Windows) must resolve within workspace or allowed_paths.
        if (self.path_env_vars.len > 0) {
            const ws_resolved: ?[]const u8 = fs_compat.realpathAllocPath(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);
            const ws_for_check = ws_resolved orelse UNAVAILABLE_WORKSPACE_SENTINEL;
            const sandbox_allowed_paths = if (sandboxRestrictsToWorkspace(self.sandbox))
                &.{}
            else
                self.allowed_paths;

            for (self.path_env_vars) |key| {
                if (platform.getEnvOrNull(allocator, key)) |val| {
                    defer allocator.free(val);
                    if (validatePathEnvValue(allocator, val, ws_for_check, sandbox_allowed_paths)) {
                        try env.put(key, val);
                    }
                }
            }
        }

        // Execute via platform shell. On Windows, bypass cmd.exe when the user
        // explicitly invokes PowerShell so pipes stay inside PowerShell instead
        // of being interpreted by cmd.exe first.
        const proc = @import("process_util.zig");
        // Determine base argv and ownership
        var base_argv: []const []const u8 = undefined;
        var maybe_owned_argv: ?[]const []const u8 = null;
        defer {
            if (maybe_owned_argv) |owned| {
                freeOwnedArgv(allocator, owned);
            }
        }

        if (builtin.os.tag == .windows) {
            const parsed = try parseWindowsCommandArgv(allocator, command);
            maybe_owned_argv = parsed;
            if (parsed.len > 0 and isPowerShellExecutable(parsed[0])) {
                base_argv = parsed;
            } else {
                const shell_cmd = platform.getShell();
                const shell_flag = platform.getShellFlag();
                base_argv = &.{ shell_cmd, shell_flag, command };
            }
        } else {
            const shell_cmd = platform.getShell();
            const shell_flag = platform.getShellFlag();
            base_argv = &.{ shell_cmd, shell_flag, command };
        }

        // Apply sandbox wrapper if configured.
        var wrap_buf: [512][]const u8 = undefined;
        const final_argv = try wrapCommandArgv(self.sandbox, base_argv, &wrap_buf);

        // Execute command.
        const result = try proc.run(allocator, final_argv, .{
            .cwd = effective_cwd,
            .env_map = &env,
            .max_output_bytes = self.max_output_bytes,
            .timeout_ns = self.timeout_ns,
        });
        defer allocator.free(result.stderr);

        if (result.success) {
            if (result.stdout.len > 0) return ToolResult{ .success = true, .output = result.stdout };
            allocator.free(result.stdout);
            return ToolResult{ .success = true, .output = try allocator.dupe(u8, "(no output)") };
        }
        defer allocator.free(result.stdout);
        if (result.interrupted) {
            return ToolResult{ .success = false, .output = "", .error_msg = "Interrupted by /stop" };
        }
        if (result.timed_out) {
            const msg = try std.fmt.allocPrint(allocator, "Command timed out after {d}s", .{self.timeout_ns / std.time.ns_per_s});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        if (result.exit_code != null) {
            const err_out = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Command failed with non-zero exit code");
            return ToolResult{ .success = false, .output = "", .error_msg = err_out };
        }
        return ToolResult{ .success = false, .output = "", .error_msg = "Command terminated by signal" };
    }
};

/// Extract a string field value from a JSON blob (minimal parser — no allocations).
/// NOTE: Prefer root.getString() with pre-parsed ObjectMap for tool implementations.
pub fn parseStringField(json: []const u8, key: []const u8) ?[]const u8 {
    return json_miniparse.parseStringField(json, key);
}

/// Extract a boolean field value from a JSON blob.
pub fn parseBoolField(json: []const u8, key: []const u8) ?bool {
    return json_miniparse.parseBoolField(json, key);
}

fn parseWindowsCommandArgv(allocator: std.mem.Allocator, command: []const u8) ![]const []const u8 {
    const command_line_w = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, command);
    defer allocator.free(command_line_w);

    var iter = try std_compat.process.ArgIteratorWindows.init(allocator, command_line_w);
    defer iter.deinit();

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (argv.items) |arg| allocator.free(arg);
        argv.deinit(allocator);
    }

    while (iter.next()) |arg| {
        try argv.append(allocator, try allocator.dupe(u8, arg));
    }

    return try argv.toOwnedSlice(allocator);
}

fn freeOwnedArgv(allocator: std.mem.Allocator, argv: []const []const u8) void {
    for (argv) |arg| allocator.free(arg);
    allocator.free(argv);
}

fn windowsBasename(path: []const u8) []const u8 {
    const sep_idx = std.mem.lastIndexOfAny(u8, path, "\\/") orelse return path;
    return path[sep_idx + 1 ..];
}

fn isPowerShellExecutable(executable: []const u8) bool {
    const base = windowsBasename(executable);
    return std.ascii.eqlIgnoreCase(base, "powershell") or
        std.ascii.eqlIgnoreCase(base, "powershell.exe") or
        std.ascii.eqlIgnoreCase(base, "pwsh") or
        std.ascii.eqlIgnoreCase(base, "pwsh.exe");
}

/// Extract an integer field value from a JSON blob.
pub fn parseIntField(json: []const u8, key: []const u8) ?i64 {
    return json_miniparse.parseIntField(json, key);
}

// ── Tests ───────────────────────────────────────────────────────────

test "parseWindowsCommandArgv preserves PowerShell flags and quoted script" {
    const argv = try parseWindowsCommandArgv(
        std.testing.allocator,
        "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -NoProfile -Command \"Get-Process | Select-Object -First 1\"",
    );
    defer freeOwnedArgv(std.testing.allocator, argv);

    try std.testing.expectEqual(@as(usize, 4), argv.len);
    try std.testing.expectEqualStrings("C:\\Program Files\\PowerShell\\7\\pwsh.exe", argv[0]);
    try std.testing.expectEqualStrings("-NoProfile", argv[1]);
    try std.testing.expectEqualStrings("-Command", argv[2]);
    try std.testing.expectEqualStrings("Get-Process | Select-Object -First 1", argv[3]);
}

test "isPowerShellExecutable requires exact basename match" {
    try std.testing.expect(isPowerShellExecutable("powershell"));
    try std.testing.expect(isPowerShellExecutable("powershell.exe"));
    try std.testing.expect(isPowerShellExecutable("pwsh"));
    try std.testing.expect(isPowerShellExecutable("pwsh.exe"));
    try std.testing.expect(isPowerShellExecutable("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
    try std.testing.expect(isPowerShellExecutable("C:/Program Files/PowerShell/7/pwsh.exe"));

    try std.testing.expect(!isPowerShellExecutable("powershell-preview"));
    try std.testing.expect(!isPowerShellExecutable("powershell_ise.exe"));
    try std.testing.expect(!isPowerShellExecutable("pwsh-script"));
}

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

test "shell reports interruption when cancel flag is set" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"sleep 5\"}");
    defer parsed.deinit();

    var cancel = std.atomic.Value(bool).init(true);
    @import("process_util.zig").setThreadInterruptFlag(&cancel);
    defer @import("process_util.zig").setThreadInterruptFlag(null);

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Interrupted") != null);
}

test "shell reports timeout for long-running command" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = ".", .timeout_ns = 100 * std.time.ns_per_ms };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"sleep 5\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "timed out") != null);
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

test "shell safe env keeps required Windows variables" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;

    try std.testing.expect(safeEnvVarAllowed("SystemRoot"));
    try std.testing.expect(safeEnvVarAllowed("WINDIR"));
    try std.testing.expect(safeEnvVarAllowed("COMSPEC"));
    try std.testing.expect(safeEnvVarAllowed("PATHEXT"));
    try std.testing.expect(safeEnvVarAllowed("TEMP"));
    try std.testing.expect(safeEnvVarAllowed("TMP"));
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
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
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
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("ws");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("other");
    const root_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const ws_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const other_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "other" });
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
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
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

test "shell sandboxed cwd outside workspace is rejected before spawn" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("ws");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("other");
    const root_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const ws_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const other_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "other" });
    defer std.testing.allocator.free(other_path);

    var prefix = PrefixSandbox{};
    var st = ShellTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{other_path},
        .sandbox = prefix.restrictedSandbox(),
    };

    var args_buf: [768]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{other_path});
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "sandboxed cwd must stay within workspace") != null);
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

test "shell wildcard policy allows stderr redirect to dev null" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer tracker.deinit();
    var wildcard_policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &wildcard_policy };
    const parsed = try root.parseTestArgs("{\"command\": \"ls /definitely-missing-file 2>/dev/null || echo missing\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "missing") != null);
}

test "shell accepts markdown-fenced command payload" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 1000);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"```bash\\necho fenced\\n```\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "fenced") != null);
}

test "shell keeps subshell backticks blocked after fenced markdown normalization" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 1000);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"```bash\\necho `whoami`\\n```\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Command not allowed") != null);
}

test "shell without policy executes command" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = null };

    const parsed = try root.parseTestArgs("{\"command\": \"echo no-policy\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
}

test "validatePathEnvValue allows paths within workspace" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("lib");
    const lib_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "lib" });
    defer std.testing.allocator.free(lib_path);

    try std.testing.expect(validatePathEnvValue(
        std.testing.allocator,
        lib_path,
        tmp_path,
        &.{},
    ));
}

test "validatePathEnvValue allows delimiter-separated paths within workspace" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("lib");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("usr");
    const lib_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "lib" });
    defer std.testing.allocator.free(lib_path);
    const usr_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "usr" });
    defer std.testing.allocator.free(usr_path);

    const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}" ++ &[_]u8{path_list_delimiter} ++ "{s}", .{ lib_path, usr_path });
    defer std.testing.allocator.free(combined);

    try std.testing.expect(validatePathEnvValue(
        std.testing.allocator,
        combined,
        tmp_path,
        &.{},
    ));
}

test "validatePathEnvValue rejects paths outside workspace" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("ws");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("outside");
    const ws_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const outside_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "outside" });
    defer std.testing.allocator.free(outside_path);

    try std.testing.expect(!validatePathEnvValue(
        std.testing.allocator,
        outside_path,
        ws_path,
        &.{},
    ));
}

test "validatePathEnvValue rejects system paths" {
    const system_path = if (@import("builtin").os.tag == .windows) "C:\\Windows\\System32" else "/usr/lib";
    const fake_ws = if (@import("builtin").os.tag == .windows) "C:\\Users\\test\\workspace" else "/home/user/workspace";
    try std.testing.expect(!validatePathEnvValue(
        std.testing.allocator,
        system_path,
        fake_ws,
        &.{},
    ));
}

test "validatePathEnvValue allows via allowed_paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("tools");
    const tools_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "tools" });
    defer std.testing.allocator.free(tools_path);

    try std.testing.expect(validatePathEnvValue(
        std.testing.allocator,
        tools_path,
        "/nonexistent-workspace",
        &.{tmp_path},
    ));
}

test "validatePathEnvValue rejects mixed valid and invalid paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("lib");
    const lib_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "lib" });
    defer std.testing.allocator.free(lib_path);

    // Mix a valid path with a system path (blocked)
    const system_path = if (@import("builtin").os.tag == .windows) "C:\\Windows\\System32" else "/etc";
    const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}" ++ &[_]u8{path_list_delimiter} ++ "{s}", .{ lib_path, system_path });
    defer std.testing.allocator.free(combined);

    try std.testing.expect(!validatePathEnvValue(
        std.testing.allocator,
        combined,
        tmp_path,
        &.{},
    ));
}

test "validatePathEnvValue rejects relative paths" {
    const fake_ws = if (@import("builtin").os.tag == .windows) "C:\\Users\\test\\workspace" else "/home/user/workspace";
    try std.testing.expect(!validatePathEnvValue(
        std.testing.allocator,
        "relative/path",
        fake_ws,
        &.{},
    ));
}

test "validatePathEnvValue allows empty value" {
    const fake_ws = if (@import("builtin").os.tag == .windows) "C:\\Users\\test\\workspace" else "/home/user/workspace";
    try std.testing.expect(validatePathEnvValue(
        std.testing.allocator,
        "",
        fake_ws,
        &.{},
    ));
}

test "shell path_env_vars passes validated vars to child" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("mylibs");
    const libs_path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "mylibs" });
    defer std.testing.allocator.free(libs_path);

    const key_z = try std.testing.allocator.dupeZ(u8, "TEST_LIB_PATH");
    defer std.testing.allocator.free(key_z);
    const value_z = try std.testing.allocator.dupeZ(u8, libs_path);
    defer std.testing.allocator.free(value_z);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key_z.ptr, value_z.ptr, 1));
    defer _ = c.unsetenv(key_z.ptr);

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .path_env_vars = &.{"TEST_LIB_PATH"},
    };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"printf '%s' \\\"$TEST_LIB_PATH\\\"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings(libs_path, result.output);
}

test "shell sandboxed path_env_vars ignore allowed_paths outside workspace" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("ws");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("other");
    const root_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const ws_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const other_path = try std_compat.fs.path.join(std.testing.allocator, &.{ root_path, "other" });
    defer std.testing.allocator.free(other_path);

    try std_compat.fs.cwd().makePath(other_path);
    const libs_path = try std_compat.fs.path.join(std.testing.allocator, &.{ other_path, "mylibs" });
    defer std.testing.allocator.free(libs_path);
    try std_compat.fs.cwd().makePath(libs_path);

    const key_z = try std.testing.allocator.dupeZ(u8, "TEST_LIB_PATH");
    defer std.testing.allocator.free(key_z);
    const value_z = try std.testing.allocator.dupeZ(u8, libs_path);
    defer std.testing.allocator.free(value_z);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key_z.ptr, value_z.ptr, 1));
    defer _ = c.unsetenv(key_z.ptr);

    var prefix = PrefixSandbox{};
    var st = ShellTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{other_path},
        .path_env_vars = &.{"TEST_LIB_PATH"},
        .sandbox = prefix.restrictedSandbox(),
    };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"printf '%s' \\\"$TEST_LIB_PATH\\\"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    // Regression: docker/bubblewrap sandboxing only mounts the workspace, so
    // path-like env vars outside it must be dropped before spawn.
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("(no output)", result.output);
}

const PrefixSandbox = struct {
    pub const sandbox_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getName,
        .description = getDescription,
    };

    pub fn sandbox(self: *PrefixSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sandbox_vtable,
        };
    }

    fn wrapCommand(_: *anyopaque, argv: []const []const u8, buf: [][]const u8) ![]const []const u8 {
        if (buf.len < argv.len + 1) return error.BufferTooSmall;

        buf[0] = "env";
        for (argv, 0..) |arg, i| {
            buf[i + 1] = arg;
        }
        return buf[0 .. argv.len + 1];
    }

    fn isAvailable(_: *anyopaque) bool {
        return true;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "prefix";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        return "Test prefix sandbox";
    }

    pub fn restrictedSandbox(self: *PrefixSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &restricted_vtable,
        };
    }

    pub const restricted_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getRestrictedName,
        .description = getDescription,
    };

    fn getRestrictedName(_: *anyopaque) []const u8 {
        return "docker";
    }
};

test "wrapCommandArgv uses caller-owned buffer for sandbox wrappers" {
    var prefix = PrefixSandbox{};
    const base_argv = [_][]const u8{ "sh", "-c", "printf test" };
    var wrap_buf: [8][]const u8 = undefined;

    // Regression: keep wrapper argv storage alive until the child process is spawned.
    const final_argv = try wrapCommandArgv(@as(?Sandbox, prefix.sandbox()), &base_argv, &wrap_buf);
    try std.testing.expectEqual(@as(usize, 4), final_argv.len);
    try std.testing.expectEqualStrings("env", final_argv[0]);
    try std.testing.expectEqualStrings("sh", final_argv[1]);
    try std.testing.expectEqualStrings("-c", final_argv[2]);
    try std.testing.expectEqualStrings("printf test", final_argv[3]);
}

test "shell with sandbox wrapper executes command" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // Sandboxes not currently available on Windows in tests

    var prefix = PrefixSandbox{};

    var st = ShellTool{
        .workspace_dir = "/tmp",
        .sandbox = prefix.sandbox(),
    };
    const t = st.tool();

    const parsed = try root.parseTestArgs("{\"command\": \"printf test\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("test", result.output);
}
