const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const UNAVAILABLE_WORKSPACE_SENTINEL = "/__nullclaw_workspace_unavailable__";

/// Git operations tool for structured repository management.
pub const GitTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},

    pub const tool_name = "git_operations";
    pub const tool_description = "Perform structured Git operations (status, diff, log, branch, commit, add, checkout, stash).";
    pub const tool_params =
        \\{"type":"object","properties":{"operation":{"type":"string","enum":["status","diff","log","branch","commit","add","checkout","stash"],"description":"Git operation to perform"},"message":{"type":"string","description":"Commit message (for commit)"},"paths":{"oneOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}],"description":"File paths (for add). Prefer array for multiple files."},"branch":{"type":"string","description":"Branch name (for checkout)"},"files":{"oneOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}],"description":"Files to diff. Prefer array for multiple files."},"cached":{"type":"boolean","description":"Show staged changes (diff)"},"limit":{"type":"integer","description":"Log entry count (default: 10)"},"cwd":{"type":"string","description":"Repository directory (absolute path within allowed paths; defaults to workspace)"}},"required":["operation"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *GitTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Returns false if the git arguments contain dangerous patterns.
    fn sanitizeGitArgs(args: []const u8) bool {
        // Block dangerous git options that could lead to command injection
        const dangerous_prefixes = [_][]const u8{
            "--exec=",
            "--upload-pack=",
            "--receive-pack=",
            "--pager=",
            "--editor=",
        };
        const dangerous_exact = [_][]const u8{
            "--no-verify",
        };
        const dangerous_substrings = [_][]const u8{
            "$(",
            "`",
        };
        const dangerous_chars = [_]u8{ '|', ';', '>' };

        var it = std.mem.tokenizeScalar(u8, args, ' ');
        while (it.next()) |arg| {
            // Check dangerous prefixes (case-insensitive via lowercase comparison)
            for (dangerous_prefixes) |prefix| {
                if (arg.len >= prefix.len and std.ascii.eqlIgnoreCase(arg[0..prefix.len], prefix))
                    return false;
            }
            // Check exact matches (case-insensitive)
            for (dangerous_exact) |exact| {
                if (arg.len == exact.len and std.ascii.eqlIgnoreCase(arg, exact))
                    return false;
            }
            // Check dangerous substrings
            for (dangerous_substrings) |sub| {
                if (std.mem.indexOf(u8, arg, sub) != null)
                    return false;
            }
            // Check dangerous single characters
            for (arg) |ch| {
                for (dangerous_chars) |dc| {
                    if (ch == dc) return false;
                }
            }
            // Block -c config injection: exact "-c" or "-c=..." (but not "--cached", "-cached", etc.)
            if (arg.len == 2 and arg[0] == '-' and (arg[1] == 'c' or arg[1] == 'C')) {
                return false;
            }
            if (arg.len > 2 and arg[0] == '-' and (arg[1] == 'c' or arg[1] == 'C') and arg[2] == '=') {
                return false;
            }
        }
        return true;
    }

    /// Truncate a commit message to max_bytes, respecting UTF-8 boundaries.
    fn truncateCommitMessage(msg: []const u8, max_bytes: usize) []const u8 {
        if (msg.len <= max_bytes) return msg;
        var i = max_bytes;
        while (i > 0 and (msg[i] & 0xC0) == 0x80) i -= 1;
        return msg[0..i];
    }

    /// Returns true for operations that modify the repository.
    fn requiresWriteAccess(operation: []const u8) bool {
        const write_ops = std.StaticStringMap(void).initComptime(.{
            .{ "commit", {} }, .{ "push", {} },   .{ "merge", {} },
            .{ "rebase", {} }, .{ "reset", {} },  .{ "checkout", {} },
            .{ "add", {} },    .{ "rm", {} },     .{ "mv", {} },
            .{ "tag", {} },    .{ "branch", {} }, .{ "clean", {} },
            // "stash push" is write, but we check at the stash level
            .{ "stash", {} },
        });
        return write_ops.has(operation);
    }

    pub fn execute(self: *GitTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const operation = root.getString(args, "operation") orelse
            return ToolResult.fail("Missing 'operation' parameter");

        // Sanitize all string arguments before execution
        const string_fields = [_][]const u8{ "message", "paths", "branch", "files", "action" };
        for (string_fields) |field| {
            if (root.getString(args, field)) |val| {
                if (!sanitizeGitArgs(val))
                    return ToolResult.fail("Unsafe git arguments detected");
            }
        }
        // Sanitize array arguments (paths, files) element-by-element
        const array_fields = [_][]const u8{ "paths", "files" };
        for (array_fields) |field| {
            if (root.getStringArray(args, field)) |items| {
                for (items) |item| {
                    if (item == .string) {
                        if (!sanitizeGitArgs(item.string))
                            return ToolResult.fail("Unsafe git arguments detected");
                    }
                }
            }
        }

        // Resolve optional cwd override
        const effective_cwd = if (root.getString(args, "cwd")) |cwd| blk: {
            if (cwd.len == 0 or !std_compat.fs.path.isAbsolute(cwd))
                return ToolResult.fail("cwd must be an absolute path");
            const resolved_cwd = fs_compat.realpathAllocPath(allocator, cwd) catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "Failed to resolve cwd: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
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

        const GitOp = enum { status, diff, log, branch, commit, add, checkout, stash };
        const op_map = std.StaticStringMap(GitOp).initComptime(.{
            .{ "status", .status },
            .{ "diff", .diff },
            .{ "log", .log },
            .{ "branch", .branch },
            .{ "commit", .commit },
            .{ "add", .add },
            .{ "checkout", .checkout },
            .{ "stash", .stash },
        });

        if (op_map.get(operation)) |op| return switch (op) {
            .status => self.runGitOp(allocator, effective_cwd, &.{ "status", "--porcelain=2", "--branch" }),
            .diff => self.gitDiff(allocator, effective_cwd, args),
            .log => self.gitLog(allocator, effective_cwd, args),
            .branch => self.runGitOp(allocator, effective_cwd, &.{ "branch", "--format=%(refname:short)|%(HEAD)" }),
            .commit => self.gitCommit(allocator, effective_cwd, args),
            .add => self.gitAdd(allocator, effective_cwd, args),
            .checkout => self.gitCheckout(allocator, effective_cwd, args),
            .stash => self.gitStash(allocator, effective_cwd, args),
        };

        const msg = try std.fmt.allocPrint(allocator, "Unknown operation: {s}", .{operation});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }

    fn runGit(_: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: []const []const u8) !struct { stdout: []u8, stderr: []u8, success: bool } {
        var argv_buf: [32][]const u8 = undefined;
        argv_buf[0] = "git";
        const arg_count = @min(args.len, argv_buf.len - 1);
        for (args[0..arg_count], 1..) |a, i| {
            argv_buf[i] = a;
        }

        const proc = @import("process_util.zig");
        const result = try proc.run(allocator, argv_buf[0 .. arg_count + 1], .{ .cwd = git_cwd });
        return .{ .stdout = result.stdout, .stderr = result.stderr, .success = result.success };
    }

    /// Run a simple git operation and return stdout on success.
    fn runGitOp(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: []const []const u8) !ToolResult {
        const result = try self.runGit(allocator, git_cwd, args);
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git operation failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitDiff(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const cached = root.getBool(args, "cached") orelse false;
        const file_items = root.getStringArray(args, "files");
        const file_string = root.getString(args, "files");

        var argv_buf: [30][]const u8 = undefined;
        var argc: usize = 0;
        var added_files: usize = 0;
        argv_buf[argc] = "diff";
        argc += 1;
        argv_buf[argc] = "--unified=3";
        argc += 1;
        if (cached) {
            argv_buf[argc] = "--cached";
            argc += 1;
        }
        argv_buf[argc] = "--";
        argc += 1;
        if (file_items) |items| {
            for (items) |item| {
                if (argc >= argv_buf.len) break;
                if (item == .string) {
                    argv_buf[argc] = item.string;
                    argc += 1;
                    added_files += 1;
                }
            }
        } else if (file_string) |f| {
            argv_buf[argc] = f;
            argc += 1;
            added_files += 1;
        }
        if (added_files == 0) {
            argv_buf[argc] = ".";
            argc += 1;
        }

        const result = try self.runGit(allocator, git_cwd, argv_buf[0..argc]);
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git diff failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitLog(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const limit_raw = root.getInt(args, "limit") orelse 10;
        const limit: usize = @intCast(@min(@max(limit_raw, 1), 1000));

        var limit_buf: [16]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "-{d}", .{limit});

        const result = try self.runGit(allocator, git_cwd, &.{
            "log",
            limit_str,
            "--pretty=format:%H|%an|%ae|%ad|%s",
            "--date=iso",
        });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git log failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitCommit(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const raw_message = root.getString(args, "message") orelse
            return ToolResult.fail("Missing 'message' parameter for commit");

        if (raw_message.len == 0) return ToolResult.fail("Commit message cannot be empty");

        const message = truncateCommitMessage(raw_message, 2000);

        const result = try self.runGit(allocator, git_cwd, &.{ "commit", "-m", message });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git commit failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        defer allocator.free(result.stdout);
        const out = try std.fmt.allocPrint(allocator, "Committed: {s}", .{message});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitAdd(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const path_items = root.getStringArray(args, "paths");
        const path_string = root.getString(args, "paths");
        if (path_items == null and path_string == null)
            return ToolResult.fail("Missing 'paths' parameter for add");

        var argv_buf: [30][]const u8 = undefined;
        argv_buf[0] = "add";
        argv_buf[1] = "--";
        var argc: usize = 2;
        var added_paths: usize = 0;
        if (path_items) |items| {
            for (items) |item| {
                if (argc >= argv_buf.len) break;
                if (item == .string) {
                    argv_buf[argc] = item.string;
                    argc += 1;
                    added_paths += 1;
                }
            }
        } else if (path_string) |p| {
            if (argc < argv_buf.len) {
                argv_buf[argc] = p;
                argc += 1;
                added_paths += 1;
            }
        }
        if (added_paths == 0)
            return ToolResult.fail("Missing 'paths' parameter for add");

        const result = try self.runGit(allocator, git_cwd, argv_buf[0..argc]);
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git add failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        // Build summary of staged paths
        var summary = std.ArrayListUnmanaged(u8).empty;
        defer summary.deinit(allocator);
        try summary.appendSlice(allocator, "Staged:");
        if (path_items) |items| {
            for (items) |item| {
                if (item == .string) {
                    try summary.appendSlice(allocator, " ");
                    try summary.appendSlice(allocator, item.string);
                }
            }
        } else if (path_string) |p| {
            try summary.appendSlice(allocator, " ");
            try summary.appendSlice(allocator, p);
        }
        const out = try allocator.dupe(u8, summary.items);
        return ToolResult{ .success = true, .output = out };
    }

    fn gitCheckout(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const branch = root.getString(args, "branch") orelse
            return ToolResult.fail("Missing 'branch' parameter for checkout");

        // Block dangerous branch names
        if (std.mem.indexOfScalar(u8, branch, ';') != null or
            std.mem.indexOfScalar(u8, branch, '|') != null or
            std.mem.indexOfScalar(u8, branch, '`') != null or
            std.mem.indexOf(u8, branch, "$(") != null)
        {
            return ToolResult.fail("Branch name contains invalid characters");
        }

        const result = try self.runGit(allocator, git_cwd, &.{ "checkout", branch });
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git checkout failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        const out = try std.fmt.allocPrint(allocator, "Switched to branch: {s}", .{branch});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitStash(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse "push";

        if (std.mem.eql(u8, action, "push") or std.mem.eql(u8, action, "save")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "push", "-m", "auto-stash" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "pop")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "pop" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "list")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "list" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        const msg = try std.fmt.allocPrint(allocator, "Unknown stash action: {s}", .{action});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "git tool name" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    try std.testing.expectEqualStrings("git_operations", t.name());
}

test "git tool schema has operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "operation") != null);
}

test "git rejects missing operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "git rejects unknown operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"push\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown operation") != null);
}

test "git cwd inside workspace works without allowed_paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const args = try std.fmt.allocPrint(std.testing.allocator, "{{\"operation\":\"unknown_op\",\"cwd\":{f}}}", .{std.json.fmt(ws_path, .{})});
    defer std.testing.allocator.free(args);

    var gt = GitTool{ .workspace_dir = ws_path };
    const t = gt.tool();
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown operation") != null);
}

test "git cwd outside workspace without allowed_paths is rejected" {
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

    const args = try std.fmt.allocPrint(std.testing.allocator, "{{\"operation\":\"status\",\"cwd\":{f}}}", .{std.json.fmt(other_path, .{})});
    defer std.testing.allocator.free(args);

    var gt = GitTool{ .workspace_dir = ws_path };
    const t = gt.tool();
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);
}

test "git checkout blocks injection" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"checkout\", \"branch\": \"main; rm -rf /\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    // Caught by sanitizeGitArgs in execute() before reaching gitCheckout
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git commit missing message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git commit empty message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\", \"message\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git add missing paths" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git add empty paths array" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\", \"paths\": []}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "git add accepts string paths parameter" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\", \"paths\": \"file.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    var error_msg_to_free: ?[]const u8 = null;
    if (result.error_msg) |e| {
        if (!std.mem.eql(u8, e, "Missing 'paths' parameter for add"))
            error_msg_to_free = e;
    }
    defer if (error_msg_to_free) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Missing 'paths' parameter") == null);
}

// ── sanitizeGitArgs tests ───────────────────────────────────────────

test "sanitizeGitArgs blocks --exec=cmd" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--exec=rm -rf /"));
}

test "sanitizeGitArgs blocks --upload-pack=evil" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--upload-pack=evil"));
}

test "sanitizeGitArgs blocks --no-verify" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--no-verify"));
}

test "sanitizeGitArgs blocks command substitution $()" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("$(evil)"));
}

test "sanitizeGitArgs blocks backtick" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("`malicious`"));
}

test "sanitizeGitArgs blocks pipe" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("arg | cat /etc/passwd"));
}

test "sanitizeGitArgs blocks semicolon" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("arg; rm -rf /"));
}

test "sanitizeGitArgs blocks redirect" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("file.txt > /tmp/out"));
}

test "sanitizeGitArgs blocks -c config injection" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("-c core.sshCommand=evil"));
    try std.testing.expect(!GitTool.sanitizeGitArgs("-c=core.pager=less"));
}

test "sanitizeGitArgs blocks --pager and --editor" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--pager=less"));
    try std.testing.expect(!GitTool.sanitizeGitArgs("--editor=vim"));
}

test "sanitizeGitArgs blocks --receive-pack" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--receive-pack=evil"));
}

test "sanitizeGitArgs allows --oneline" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--oneline"));
}

test "sanitizeGitArgs allows --stat" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--stat"));
}

test "sanitizeGitArgs allows safe branch names" {
    try std.testing.expect(GitTool.sanitizeGitArgs("main"));
    try std.testing.expect(GitTool.sanitizeGitArgs("feature/test-branch"));
    try std.testing.expect(GitTool.sanitizeGitArgs("src/main.zig"));
    try std.testing.expect(GitTool.sanitizeGitArgs("."));
}

test "sanitizeGitArgs allows --cached (not blocked by -c check)" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--cached"));
    try std.testing.expect(GitTool.sanitizeGitArgs("-cached"));
}

// ── truncateCommitMessage tests ─────────────────────────────────────

test "truncateCommitMessage short message unchanged" {
    const msg = "short message";
    try std.testing.expectEqualStrings(msg, GitTool.truncateCommitMessage(msg, 2000));
}

test "truncateCommitMessage truncates at UTF-8 boundary" {
    // "Éééééé" in UTF-8 is 12 bytes (2 bytes per accented char)
    const msg = "Éééééé ààà!"; // 20 bytes
    const truncated = GitTool.truncateCommitMessage(msg, 10);
    // Should truncate to 10 bytes which is at a clean boundary (5 Cyrillic chars)
    try std.testing.expect(truncated.len <= 10);
    // Must not end in the middle of a multi-byte sequence
    try std.testing.expect(std.unicode.utf8ValidateSlice(truncated));
}

test "truncateCommitMessage exact boundary" {
    const msg = "hello";
    try std.testing.expectEqualStrings("hello", GitTool.truncateCommitMessage(msg, 5));
    try std.testing.expectEqualStrings("hello", GitTool.truncateCommitMessage(msg, 100));
}

// ── requiresWriteAccess tests ───────────────────────────────────────

test "requiresWriteAccess returns true for commit" {
    try std.testing.expect(GitTool.requiresWriteAccess("commit"));
}

test "requiresWriteAccess returns true for push" {
    try std.testing.expect(GitTool.requiresWriteAccess("push"));
}

test "requiresWriteAccess returns true for add" {
    try std.testing.expect(GitTool.requiresWriteAccess("add"));
}

test "requiresWriteAccess returns false for status" {
    try std.testing.expect(!GitTool.requiresWriteAccess("status"));
}

test "requiresWriteAccess returns false for diff" {
    try std.testing.expect(!GitTool.requiresWriteAccess("diff"));
}

test "requiresWriteAccess returns false for log" {
    try std.testing.expect(!GitTool.requiresWriteAccess("log"));
}

// ── Integration: sanitizeGitArgs in execute ─────────────────────────

test "git execute blocks unsafe args in message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\", \"message\": \"$(evil)\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git execute blocks unsafe args in paths" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\", \"paths\": [\"file.txt; rm -rf /\"]}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git execute blocks unsafe args in paths string" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\", \"paths\": \"file.txt; rm -rf /\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git execute blocks unsafe args in files string" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"diff\", \"files\": \"src/main.zig; rm -rf /\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}
