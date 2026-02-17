const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const parseBoolField = @import("shell.zig").parseBoolField;
const parseIntField = @import("shell.zig").parseIntField;

/// Git operations tool for structured repository management.
pub const GitTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *GitTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *GitTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "git_operations";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Perform structured Git operations (status, diff, log, branch, commit, add, checkout, stash).";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"operation":{"type":"string","enum":["status","diff","log","branch","commit","add","checkout","stash"],"description":"Git operation to perform"},"message":{"type":"string","description":"Commit message (for commit)"},"paths":{"type":"string","description":"File paths (for add)"},"branch":{"type":"string","description":"Branch name (for checkout)"},"files":{"type":"string","description":"Files to diff"},"cached":{"type":"boolean","description":"Show staged changes (diff)"},"limit":{"type":"integer","description":"Log entry count (default: 10)"}},"required":["operation"]}
        ;
    }

    fn execute(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const operation = parseStringField(args_json, "operation") orelse
            return ToolResult.fail("Missing 'operation' parameter");

        if (std.mem.eql(u8, operation, "status")) return self.gitStatus(allocator);
        if (std.mem.eql(u8, operation, "diff")) return self.gitDiff(allocator, args_json);
        if (std.mem.eql(u8, operation, "log")) return self.gitLog(allocator, args_json);
        if (std.mem.eql(u8, operation, "branch")) return self.gitBranch(allocator);
        if (std.mem.eql(u8, operation, "commit")) return self.gitCommit(allocator, args_json);
        if (std.mem.eql(u8, operation, "add")) return self.gitAdd(allocator, args_json);
        if (std.mem.eql(u8, operation, "checkout")) return self.gitCheckout(allocator, args_json);
        if (std.mem.eql(u8, operation, "stash")) return self.gitStash(allocator, args_json);

        const msg = try std.fmt.allocPrint(allocator, "Unknown operation: {s}", .{operation});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }

    fn runGit(self: *GitTool, allocator: std.mem.Allocator, args: []const []const u8) !struct { stdout: []u8, stderr: []u8, success: bool } {
        var argv_buf: [32][]const u8 = undefined;
        argv_buf[0] = "git";
        const arg_count = @min(args.len, argv_buf.len - 1);
        for (args[0..arg_count], 1..) |a, i| {
            argv_buf[i] = a;
        }

        var child = std.process.Child.init(argv_buf[0 .. arg_count + 1], allocator);
        child.cwd = self.workspace_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stdout = try child.stdout.?.readToEndAlloc(allocator, 1_048_576);
        const stderr = try child.stderr.?.readToEndAlloc(allocator, 1_048_576);
        const term = try child.wait();

        return .{ .stdout = stdout, .stderr = stderr, .success = term.Exited == 0 };
    }

    fn gitStatus(self: *GitTool, allocator: std.mem.Allocator) !ToolResult {
        const result = try self.runGit(allocator, &.{ "status", "--porcelain=2", "--branch" });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git status failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitDiff(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const cached = parseBoolField(args_json, "cached") orelse false;
        const files = parseStringField(args_json, "files") orelse ".";

        var argv_buf: [8][]const u8 = undefined;
        var argc: usize = 0;
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
        argv_buf[argc] = files;
        argc += 1;

        const result = try self.runGit(allocator, argv_buf[0..argc]);
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git diff failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitLog(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const limit_raw = parseIntField(args_json, "limit") orelse 10;
        const limit: usize = @intCast(@min(@max(limit_raw, 1), 1000));

        var limit_buf: [16]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "-{d}", .{limit});

        const result = try self.runGit(allocator, &.{
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

    fn gitBranch(self: *GitTool, allocator: std.mem.Allocator) !ToolResult {
        const result = try self.runGit(allocator, &.{ "branch", "--format=%(refname:short)|%(HEAD)" });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git branch failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitCommit(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const message = parseStringField(args_json, "message") orelse
            return ToolResult.fail("Missing 'message' parameter for commit");

        if (message.len == 0) return ToolResult.fail("Commit message cannot be empty");

        const result = try self.runGit(allocator, &.{ "commit", "-m", message });
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

    fn gitAdd(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const paths = parseStringField(args_json, "paths") orelse
            return ToolResult.fail("Missing 'paths' parameter for add");

        const result = try self.runGit(allocator, &.{ "add", "--", paths });
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git add failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        const out = try std.fmt.allocPrint(allocator, "Staged: {s}", .{paths});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitCheckout(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const branch = parseStringField(args_json, "branch") orelse
            return ToolResult.fail("Missing 'branch' parameter for checkout");

        // Block dangerous branch names
        if (std.mem.indexOfScalar(u8, branch, ';') != null or
            std.mem.indexOfScalar(u8, branch, '|') != null or
            std.mem.indexOfScalar(u8, branch, '`') != null or
            std.mem.indexOf(u8, branch, "$(") != null)
        {
            return ToolResult.fail("Branch name contains invalid characters");
        }

        const result = try self.runGit(allocator, &.{ "checkout", branch });
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git checkout failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        const out = try std.fmt.allocPrint(allocator, "Switched to branch: {s}", .{branch});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitStash(self: *GitTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const action = parseStringField(args_json, "action") orelse "push";

        if (std.mem.eql(u8, action, "push") or std.mem.eql(u8, action, "save")) {
            const result = try self.runGit(allocator, &.{ "stash", "push", "-m", "auto-stash" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "pop")) {
            const result = try self.runGit(allocator, &.{ "stash", "pop" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "list")) {
            const result = try self.runGit(allocator, &.{ "stash", "list" });
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

test "git tool description not empty" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    try std.testing.expect(t.description().len > 0);
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
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "git rejects unknown operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const result = try t.execute(std.testing.allocator, "{\"operation\": \"push\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown operation") != null);
}

test "git checkout blocks injection" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const result = try t.execute(std.testing.allocator, "{\"operation\": \"checkout\", \"branch\": \"main; rm -rf /\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "invalid characters") != null);
}

test "git commit missing message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const result = try t.execute(std.testing.allocator, "{\"operation\": \"commit\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git commit empty message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const result = try t.execute(std.testing.allocator, "{\"operation\": \"commit\", \"message\": \"\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git add missing paths" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const result = try t.execute(std.testing.allocator, "{\"operation\": \"add\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}
