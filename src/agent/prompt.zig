const std = @import("std");
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;

// ═══════════════════════════════════════════════════════════════════════════
// System Prompt Builder
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum characters to include from a single workspace identity file.
const BOOTSTRAP_MAX_CHARS: usize = 20_000;

/// Context passed to prompt sections during construction.
pub const PromptContext = struct {
    workspace_dir: []const u8,
    model_name: []const u8,
    tools: []const Tool,
};

/// Build the full system prompt from workspace identity files, tools, and runtime context.
pub fn buildSystemPrompt(
    allocator: std.mem.Allocator,
    ctx: PromptContext,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Identity section — inject workspace MD files
    try buildIdentitySection(allocator, w, ctx.workspace_dir);

    // Tools section
    try buildToolsSection(w, ctx.tools);

    // Safety section
    try w.writeAll("## Safety\n\n");
    try w.writeAll("- Do not exfiltrate private data.\n");
    try w.writeAll("- Do not run destructive commands without asking.\n");
    try w.writeAll("- Do not bypass oversight or approval mechanisms.\n");
    try w.writeAll("- Prefer `trash` over `rm`.\n");
    try w.writeAll("- When in doubt, ask before acting externally.\n\n");

    // Workspace section
    try std.fmt.format(w, "## Workspace\n\nWorking directory: `{s}`\n\n", .{ctx.workspace_dir});

    // Runtime section
    try std.fmt.format(w, "## Runtime\n\nOS: {s} | Model: {s}\n\n", .{
        @tagName(comptime std.Target.Os.Tag.macos),
        ctx.model_name,
    });

    return try buf.toOwnedSlice(allocator);
}

fn buildIdentitySection(
    allocator: std.mem.Allocator,
    w: anytype,
    workspace_dir: []const u8,
) !void {
    try w.writeAll("## Project Context\n\n");
    try w.writeAll("The following workspace files define your identity, behavior, and context.\n\n");

    const identity_files = [_][]const u8{
        "AGENTS.md",
        "SOUL.md",
        "TOOLS.md",
        "IDENTITY.md",
        "USER.md",
        "HEARTBEAT.md",
        "BOOTSTRAP.md",
        "MEMORY.md",
    };

    for (identity_files) |filename| {
        try injectWorkspaceFile(allocator, w, workspace_dir, filename);
    }
}

fn buildToolsSection(w: anytype, tools: []const Tool) !void {
    try w.writeAll("## Tools\n\n");
    for (tools) |t| {
        try std.fmt.format(w, "- **{s}**: {s}\n  Parameters: `{s}`\n", .{
            t.name(),
            t.description(),
            t.parametersJson(),
        });
    }
    try w.writeAll("\n");
}

/// Read a workspace file and append it to the prompt, truncating if too large.
fn injectWorkspaceFile(
    allocator: std.mem.Allocator,
    w: anytype,
    workspace_dir: []const u8,
    filename: []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ workspace_dir, filename });
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch {
        try std.fmt.format(w, "### {s}\n\n[File not found: {s}]\n\n", .{ filename, filename });
        return;
    };
    defer file.close();

    // Read up to BOOTSTRAP_MAX_CHARS + some margin
    const content = file.readToEndAlloc(allocator, BOOTSTRAP_MAX_CHARS + 1024) catch {
        try std.fmt.format(w, "### {s}\n\n[Could not read: {s}]\n\n", .{ filename, filename });
        return;
    };
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, " \t\r\n");
    if (trimmed.len == 0) return;

    try std.fmt.format(w, "### {s}\n\n", .{filename});

    if (trimmed.len > BOOTSTRAP_MAX_CHARS) {
        try w.writeAll(trimmed[0..BOOTSTRAP_MAX_CHARS]);
        try std.fmt.format(w, "\n\n[... truncated at {d} chars -- use `read` for full file]\n\n", .{BOOTSTRAP_MAX_CHARS});
    } else {
        try w.writeAll(trimmed);
        try w.writeAll("\n\n");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "buildSystemPrompt includes core sections" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = "/tmp/nonexistent",
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Project Context") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Tools") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Safety") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Runtime") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "test-model") != null);
}

test "buildSystemPrompt includes workspace dir" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = "/my/workspace",
        .model_name = "claude",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "/my/workspace") != null);
}
