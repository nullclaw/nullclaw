const std = @import("std");
const builtin = @import("builtin");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Screenshot tool — capture the screen using platform-native commands.
/// macOS: `screencapture -x FILE`
/// Linux: `import FILE` (ImageMagick)
pub const ScreenshotTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *ScreenshotTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *ScreenshotTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "screenshot";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Capture a screenshot of the current screen. Returns the file path.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"filename":{"type":"string","description":"Optional filename (default: screenshot.png). Saved in workspace."}}}
        ;
    }

    fn execute(self: *ScreenshotTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const filename = parseStringField(args_json, "filename") orelse "screenshot.png";

        // Build output path: workspace_dir/filename
        const output_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.workspace_dir, filename });
        defer allocator.free(output_path);

        // Platform-specific screenshot command
        const argv: []const []const u8 = switch (comptime builtin.os.tag) {
            .macos => &.{ "screencapture", "-x", output_path },
            .linux => &.{ "import", "-window", "root", output_path },
            else => {
                return ToolResult.fail("Screenshot not supported on this platform");
            },
        };

        var child = std.process.Child.init(argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            return ToolResult.fail("Failed to spawn screenshot command");
        };

        const stderr = child.stderr.?.readToEndAlloc(allocator, 1_048_576) catch "";
        defer if (stderr.len > 0) allocator.free(stderr);

        const term = child.wait() catch {
            return ToolResult.fail("Failed to wait for screenshot command");
        };

        if (term.Exited == 0) {
            const msg = try std.fmt.allocPrint(allocator, "Screenshot saved to: {s}/{s}", .{ self.workspace_dir, filename });
            return ToolResult{ .success = true, .output = msg };
        } else {
            const err_msg = try std.fmt.allocPrint(allocator, "Screenshot command failed: {s}", .{if (stderr.len > 0) stderr else "unknown error"});
            return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "screenshot tool name" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expectEqualStrings("screenshot", t.name());
}

test "screenshot tool description not empty" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expect(t.description().len > 0);
    try std.testing.expect(std.mem.indexOf(u8, t.description(), "screenshot") != null or std.mem.indexOf(u8, t.description(), "Screenshot") != null);
}

test "screenshot tool schema has filename" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "filename") != null);
}

test "screenshot tool spec" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const s = t.spec();
    try std.testing.expectEqualStrings("screenshot", s.name);
    try std.testing.expect(s.parameters_json.len > 0);
    try std.testing.expect(s.parameters_json[0] == '{');
}

test "screenshot tool vtable consistent" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expect(t.vtable == &ScreenshotTool.vtable);
    try std.testing.expectEqualStrings("screenshot", t.name());
    try std.testing.expectEqualStrings("screenshot", t.name());
}
