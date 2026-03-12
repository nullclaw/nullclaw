const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const verbose = @import("../verbose.zig");
const log = std.log.scoped(.screenshot);

/// Screenshot tool — capture the screen using platform-native commands.
/// macOS: `screencapture -x FILE`
/// Linux: `import FILE` (ImageMagick)
/// Windows: PowerShell-based screen capture
pub const ScreenshotTool = struct {
    workspace_dir: []const u8,

    pub const tool_name = "screenshot";
    pub const tool_description = "Capture a screenshot of the current screen. Returns [IMAGE:path] marker — include it verbatim in your response to send the image to the user.";
    pub const tool_params =
        \\{"type":"object","properties":{"filename":{"type":"string","description":"Optional filename (default: screenshot.png). Saved in workspace."}}}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *ScreenshotTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *ScreenshotTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const log_enabled = verbose.isVerbose();
        if (log_enabled) {
            log.info("OS tag: {}", .{comptime builtin.os.tag});
        }

        const filename = root.getString(args, "filename") orelse "screenshot.png";

        // Build output path: workspace_dir/filename
        const output_path = if (comptime builtin.os.tag == .windows)
            try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ self.workspace_dir, filename })
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.workspace_dir, filename });
        defer allocator.free(output_path);

        // In test mode, return a mock result without spawning a real process
        if (comptime builtin.is_test) {
            const msg = try std.fmt.allocPrint(allocator, "[IMAGE:{s}]", .{output_path});
            return ToolResult{ .success = true, .output = msg };
        }

        // Platform-specific screenshot command
        const argv: []const []const u8 = switch (comptime builtin.os.tag) {
            .macos => &.{ "screencapture", "-x", output_path },
            .linux => &.{ "import", "-window", "root", output_path },
            .windows => blk: {
                const ps_script = try std.fmt.allocPrint(allocator,
                    \\Add-Type -AssemblyName System.Windows.Forms; 
                    \\Add-Type -AssemblyName System.Drawing; 
                    \\$screen = [System.Windows.Forms.Screen]::PrimaryScreen; 
                    \\$bounds = $screen.Bounds; 
                    \\$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; 
                    \\$g = [System.Drawing.Graphics]::FromImage($bmp); 
                    \\$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size); 
                    \\$bmp.Save('{s}', [System.Drawing.Imaging.ImageFormat]::Png); 
                    \\$g.Dispose(); 
                    \\$bmp.Dispose(); 
                    \\exit 0
                , .{output_path});

                if (log_enabled) {
                    log.info("ps_script: {s}", .{ps_script});
                    log.info("output_path: {s}", .{output_path});
                }

                const argv_win = try allocator.alloc([]const u8, 6);
                argv_win[0] = "powershell.exe";
                argv_win[1] = "-NoProfile";
                argv_win[2] = "-ExecutionPolicy";
                argv_win[3] = "Bypass";
                argv_win[4] = "-Command";
                argv_win[5] = ps_script;

                break :blk argv_win;
            },
            else => {
                return ToolResult.fail("Screenshot not supported on this platform");
            },
        };

        const proc = @import("process_util.zig");

        const result = proc.run(allocator, argv, .{}) catch |err| {
            if (comptime builtin.os.tag == .windows) {
                allocator.free(argv[5]);
                allocator.free(argv);
            }
            log.err("Failed to spawn: {s}", .{@errorName(err)});
            return ToolResult.fail("Screenshot failed: cannot execute screenshot command. This may be due to sandbox restrictions in this environment. Try running the screenshot tool in a normal terminal environment.");
        };
        defer result.deinit(allocator);
        if (comptime builtin.os.tag == .windows) {
            allocator.free(argv[5]);
            allocator.free(argv);
        }

        if (log_enabled) {
            log.info("Result: success={}, exit_code={?}, stdout_len={d}, stderr_len={d}", .{ result.success, result.exit_code, result.stdout.len, result.stderr.len });
            if (result.stderr.len > 0) {
                log.info("Stderr: {s}", .{result.stderr});
            }
        }

        if (result.success) {
            const msg = try std.fmt.allocPrint(allocator, "[IMAGE:{s}/{s}]", .{ self.workspace_dir, filename });
            return ToolResult{ .success = true, .output = msg };
        }
        const err_msg = try std.fmt.allocPrint(allocator, "Screenshot command failed: {s}", .{if (result.stderr.len > 0) result.stderr else "unknown error"});
        return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "screenshot tool name" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expectEqualStrings("screenshot", t.name());
}

test "screenshot tool schema has filename" {
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "filename") != null);
}

test "screenshot execute returns mock in test mode" {
    const allocator = std.testing.allocator;
    var st = ScreenshotTool{ .workspace_dir = "/tmp/workspace" };
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try st.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[IMAGE:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "screenshot.png") != null);
}

test "screenshot execute with custom filename" {
    const allocator = std.testing.allocator;
    var st = ScreenshotTool{ .workspace_dir = "/tmp" };
    const parsed = try root.parseTestArgs("{\"filename\":\"capture.png\"}");
    defer parsed.deinit();
    const result = try st.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "capture.png") != null);
}
