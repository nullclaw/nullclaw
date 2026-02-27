const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../platform.zig");
const tools_mod = @import("../tools/root.zig");
const Tool = tools_mod.Tool;
const skills_mod = @import("../skills.zig");

// ═══════════════════════════════════════════════════════════════════════════
// System Prompt Builder
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum characters to include from a single workspace identity file.
const BOOTSTRAP_MAX_CHARS: usize = 20_000;
/// Maximum bytes allowed for guarded workspace bootstrap file reads.
const MAX_WORKSPACE_BOOTSTRAP_FILE_BYTES: u64 = 2 * 1024 * 1024;

const GuardedWorkspaceFileOpen = struct {
    file: std.fs.File,
    canonical_path: []u8,
    stat: std.fs.File.Stat,
};

fn deinitGuardedWorkspaceFile(allocator: std.mem.Allocator, opened: GuardedWorkspaceFileOpen) void {
    opened.file.close();
    allocator.free(opened.canonical_path);
}

/// Best-effort device id for fingerprint parity with OpenClaw's
/// dev+ino+size+mtime identity tuple.
fn workspaceFileDeviceId(file: *const std.fs.File) ?u64 {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return null;

    const stat = std.posix.fstat(file.handle) catch return null;
    return @as(u64, @intCast(stat.dev));
}

fn pathStartsWith(path: []const u8, prefix: []const u8) bool {
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    if (path.len == prefix.len) return true;
    if (prefix.len > 0 and (prefix[prefix.len - 1] == '/' or prefix[prefix.len - 1] == '\\')) {
        return true;
    }
    const c = path[prefix.len];
    return c == '/' or c == '\\';
}

fn isWorkspaceBootstrapFilenameSafe(filename: []const u8) bool {
    if (std.fs.path.isAbsolute(filename)) return false;
    if (std.mem.indexOfScalar(u8, filename, 0) != null) return false;
    var it = std.mem.splitAny(u8, filename, "/\\");
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn openWorkspaceFileWithGuards(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    filename: []const u8,
) ?GuardedWorkspaceFileOpen {
    if (!isWorkspaceBootstrapFilenameSafe(filename)) return null;

    const workspace_root = std.fs.cwd().realpathAlloc(allocator, workspace_dir) catch return null;
    defer allocator.free(workspace_root);

    const candidate = std.fs.path.join(allocator, &.{ workspace_dir, filename }) catch return null;
    defer allocator.free(candidate);

    const canonical_path = std.fs.cwd().realpathAlloc(allocator, candidate) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return null,
    };

    if (!pathStartsWith(canonical_path, workspace_root)) {
        allocator.free(canonical_path);
        return null;
    }

    const file = std.fs.openFileAbsolute(canonical_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            allocator.free(canonical_path);
            return null;
        },
        else => {
            allocator.free(canonical_path);
            return null;
        },
    };

    const stat = file.stat() catch {
        file.close();
        allocator.free(canonical_path);
        return null;
    };
    if (stat.size > MAX_WORKSPACE_BOOTSTRAP_FILE_BYTES) {
        file.close();
        allocator.free(canonical_path);
        return null;
    }

    return .{
        .file = file,
        .canonical_path = canonical_path,
        .stat = stat,
    };
}

/// Conversation context for the current turn (Signal-specific for now).
pub const ConversationContext = struct {
    channel: ?[]const u8 = null,
    sender_number: ?[]const u8 = null,
    sender_uuid: ?[]const u8 = null,
    group_id: ?[]const u8 = null,
    is_group: ?bool = null,
};

/// Context passed to prompt sections during construction.
pub const PromptContext = struct {
    workspace_dir: []const u8,
    model_name: []const u8,
    tools: []const Tool,
    capabilities_section: ?[]const u8 = null,
    conversation_context: ?ConversationContext = null,
};

/// Build a lightweight fingerprint for workspace prompt files.
/// Used to detect when AGENTS/SOUL/etc changed and system prompt must be rebuilt.
pub fn workspacePromptFingerprint(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
) !u64 {
    var hasher = std.hash.Fnv1a_64.init();
    const tracked_files = [_][]const u8{
        "AGENTS.md",
        "SOUL.md",
        "TOOLS.md",
        "IDENTITY.md",
        "USER.md",
        "HEARTBEAT.md",
        "BOOTSTRAP.md",
        "MEMORY.md",
        "memory.md",
    };

    for (tracked_files) |filename| {
        hasher.update(filename);
        hasher.update("\n");

        const opened = openWorkspaceFileWithGuards(allocator, workspace_dir, filename);
        if (opened == null) {
            hasher.update("missing");
            continue;
        }

        const guarded = opened.?;
        defer deinitGuardedWorkspaceFile(allocator, guarded);

        const stat = guarded.stat;
        hasher.update("present");
        hasher.update(guarded.canonical_path);

        if (workspaceFileDeviceId(&guarded.file)) |device_id| {
            hasher.update(std.mem.asBytes(&device_id));
        } else {
            hasher.update("nodev");
        }

        const inode_id = stat.inode;
        const mtime_ns: i128 = stat.mtime;
        const size_bytes: u64 = @intCast(stat.size);
        hasher.update(std.mem.asBytes(&inode_id));
        hasher.update(std.mem.asBytes(&mtime_ns));
        hasher.update(std.mem.asBytes(&size_bytes));
    }

    return hasher.final();
}

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

    // Attachment marker conventions for channel delivery.
    try appendChannelAttachmentsSection(w);

    // Conversation context section (Signal-specific for now)
    if (ctx.conversation_context) |cc| {
        try w.writeAll("## Conversation Context\n\n");
        if (cc.channel) |ch| {
            try std.fmt.format(w, "- Channel: {s}\n", .{ch});
        }
        if (cc.is_group) |ig| {
            if (ig) {
                if (cc.group_id) |gid| {
                    try std.fmt.format(w, "- Chat type: group\n", .{});
                    try std.fmt.format(w, "- Group ID: {s}\n", .{gid});
                } else {
                    try std.fmt.format(w, "- Chat type: group\n", .{});
                }
            } else {
                try std.fmt.format(w, "- Chat type: direct message\n", .{});
            }
        }
        if (cc.sender_number) |num| {
            try std.fmt.format(w, "- Sender phone: {s}\n", .{num});
        }
        if (cc.sender_uuid) |uuid| {
            try std.fmt.format(w, "- Sender UUID: {s}\n", .{uuid});
        }
        try w.writeAll("\n");
    }

    if (ctx.capabilities_section) |section| {
        try w.writeAll(section);
    }

    // Safety section
    try w.writeAll("## Safety\n\n");
    try w.writeAll("- Do not exfiltrate private data.\n");
    try w.writeAll("- Do not run destructive commands without asking.\n");
    try w.writeAll("- Do not bypass oversight or approval mechanisms.\n");
    try w.writeAll("- Prefer `trash` over `rm`.\n");
    try w.writeAll("- When in doubt, ask before acting externally.\n\n");
    try w.writeAll("- Never expose internal memory implementation keys (for example: `autosave_*`, `last_hygiene_at`) in user-facing replies.\n\n");

    // Skills section
    try appendSkillsSection(allocator, w, ctx.workspace_dir);

    // Workspace section
    try std.fmt.format(w, "## Workspace\n\nWorking directory: `{s}`\n\n", .{ctx.workspace_dir});

    // DateTime section
    try appendDateTimeSection(w);

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
    try w.writeAll("If AGENTS.md is present, follow its operational guidance (including startup routines and red-line constraints) unless higher-priority instructions override it.\n\n");
    try w.writeAll("If SOUL.md is present, embody its persona and tone. Avoid stiff, generic replies; follow its guidance unless higher-priority instructions override it.\n\n");
    try w.writeAll("TOOLS.md does not control tool availability; it is user guidance for how to use external tools.\n\n");

    const identity_files = [_][]const u8{
        "AGENTS.md",
        "SOUL.md",
        "TOOLS.md",
        "IDENTITY.md",
        "USER.md",
        "HEARTBEAT.md",
        "BOOTSTRAP.md",
    };

    for (identity_files) |filename| {
        try injectWorkspaceFile(allocator, w, workspace_dir, filename);
    }

    // Inject MEMORY.md if present, otherwise fallback to memory.md.
    try injectPreferredMemoryFile(allocator, w, workspace_dir);
}

test "buildSystemPrompt includes SOUL persona guidance" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("SOUL.md", .{});
        defer f.close();
        try f.writeAll("Persona baseline");
    }

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "If SOUL.md is present, embody its persona and tone. Avoid stiff, generic replies; follow its guidance unless higher-priority instructions override it.") != null);
}

test "buildSystemPrompt includes AGENTS operational guidance" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("AGENTS.md", .{});
        defer f.close();
        try f.writeAll("Session Startup\n- Read SOUL.md");
    }

    const workspace = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "If AGENTS.md is present, follow its operational guidance (including startup routines and red-line constraints) unless higher-priority instructions override it.") != null);
}

test "buildSystemPrompt includes TOOLS availability guidance" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = "/tmp/nonexistent",
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "TOOLS.md does not control tool availability; it is user guidance for how to use external tools.") != null);
}

test "buildSystemPrompt blocks AGENTS symlink escape outside workspace" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    try outside_tmp.dir.writeFile(.{ .sub_path = "outside-agents.md", .data = "outside-secret-rules" });
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);
    const outside_agents = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "outside-agents.md" });
    defer std.testing.allocator.free(outside_agents);

    try ws_tmp.dir.symLink(outside_agents, "AGENTS.md", .{});

    const workspace = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "[File not found: AGENTS.md]") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "outside-secret-rules") == null);
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

fn appendChannelAttachmentsSection(w: anytype) !void {
    try w.writeAll("## Channel Attachments\n\n");
    try w.writeAll("- On marker-aware channels (for example Telegram), you can send real attachments by emitting markers in your final reply.\n");
    try w.writeAll("- File/document: `[FILE:/absolute/path/to/file.ext]` or `[DOCUMENT:/absolute/path/to/file.ext]`\n");
    try w.writeAll("- Image/video/audio/voice: `[IMAGE:/abs/path]`, `[VIDEO:/abs/path]`, `[AUDIO:/abs/path]`, `[VOICE:/abs/path]`\n");
    try w.writeAll("- If user gives `~/...`, expand it to the absolute home path before sending.\n");
    try w.writeAll("- Do not claim attachment sending is unavailable when these markers are supported.\n\n");
}

fn writeXmlEscapedAttrValue(w: anytype, value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&apos;"),
            else => try w.writeByte(c),
        }
    }
}

/// Append available skills with progressive loading.
/// - always=true skills: full instruction text in the prompt
/// - always=false skills: XML summary only (agent must use read_file to load)
/// - unavailable skills: marked with available="false" and missing deps
fn appendSkillsSection(
    allocator: std.mem.Allocator,
    w: anytype,
    workspace_dir: []const u8,
) !void {
    // Two-source loading: workspace skills + ~/.nullclaw/skills/community/
    const home_dir = platform.getHomeDir(allocator) catch null;
    defer if (home_dir) |h| allocator.free(h);
    const community_base = if (home_dir) |h|
        std.fs.path.join(allocator, &.{ h, ".nullclaw", "skills" }) catch null
    else
        null;
    defer if (community_base) |cb| allocator.free(cb);

    // listSkillsMerged already calls checkRequirements on each skill.
    // The fallback listSkills path needs explicit checkRequirements calls.
    var used_merged = false;
    const skill_list = if (community_base) |cb| blk: {
        const merged = skills_mod.listSkillsMerged(allocator, cb, workspace_dir) catch
            break :blk skills_mod.listSkills(allocator, workspace_dir) catch return;
        used_merged = true;
        break :blk merged;
    } else skills_mod.listSkills(allocator, workspace_dir) catch return;
    defer skills_mod.freeSkills(allocator, skill_list);

    // checkRequirements only needed for the non-merged path
    if (!used_merged) {
        for (skill_list) |*skill| {
            skills_mod.checkRequirements(allocator, skill);
        }
    }

    if (skill_list.len == 0) return;

    // Render always=true skills with full instructions first
    var has_always = false;
    for (skill_list) |skill| {
        if (!skill.always or !skill.available) continue;
        if (!has_always) {
            try w.writeAll("## Skills\n\n");
            has_always = true;
        }
        try std.fmt.format(w, "### Skill: {s}\n\n", .{skill.name});
        if (skill.description.len > 0) {
            try std.fmt.format(w, "{s}\n\n", .{skill.description});
        }
        if (skill.instructions.len > 0) {
            try w.writeAll(skill.instructions);
            try w.writeAll("\n\n");
        }
    }

    // Render summary skills and unavailable skills as XML
    var has_summary = false;
    for (skill_list) |skill| {
        if (skill.always and skill.available) continue; // already rendered above
        if (!has_summary) {
            try w.writeAll("## Available Skills\n\n");
            try w.writeAll("Use the read_file tool to load full skill instructions when needed.\n\n");
            try w.writeAll("<available_skills>\n");
            has_summary = true;
        }
        if (!skill.available) {
            try w.writeAll("  <skill name=\"");
            try writeXmlEscapedAttrValue(w, skill.name);
            try w.writeAll("\" description=\"");
            try writeXmlEscapedAttrValue(w, skill.description);
            try w.writeAll("\" available=\"false\" missing=\"");
            try writeXmlEscapedAttrValue(w, skill.missing_deps);
            try w.writeAll("\"/>\n");
        } else {
            const skill_path = if (skill.path.len > 0) skill.path else workspace_dir;
            try w.writeAll("  <skill name=\"");
            try writeXmlEscapedAttrValue(w, skill.name);
            try w.writeAll("\" description=\"");
            try writeXmlEscapedAttrValue(w, skill.description);
            try w.writeAll("\" path=\"");
            try writeXmlEscapedAttrValue(w, skill_path);
            try w.writeAll("/SKILL.md\"/>\n");
        }
    }
    if (has_summary) {
        try w.writeAll("</available_skills>\n\n");
    }
}

/// Append a human-readable UTC date/time section derived from the system clock.
fn appendDateTimeSection(w: anytype) !void {
    const timestamp = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    const year = year_day.year;
    const month = @intFromEnum(month_day.month);
    const day = month_day.day_index + 1;
    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();

    try std.fmt.format(w, "## Current Date & Time\n\n{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2} UTC\n\n", .{
        year, month, day, hour, minute,
    });
}

/// Read a workspace file and append it to the prompt, truncating if too large.
fn injectWorkspaceFile(
    allocator: std.mem.Allocator,
    w: anytype,
    workspace_dir: []const u8,
    filename: []const u8,
) !void {
    const opened = openWorkspaceFileWithGuards(allocator, workspace_dir, filename);
    if (opened == null) {
        try std.fmt.format(w, "### {s}\n\n[File not found: {s}]\n\n", .{ filename, filename });
        return;
    }
    var guarded = opened.?;
    defer deinitGuardedWorkspaceFile(allocator, guarded);

    try appendWorkspaceFileContent(allocator, w, filename, &guarded.file);
}

fn appendWorkspaceFileContent(
    allocator: std.mem.Allocator,
    w: anytype,
    filename: []const u8,
    file: *std.fs.File,
) !void {
    // Read up to BOOTSTRAP_MAX_CHARS + some margin
    const content = file.readToEndAlloc(allocator, BOOTSTRAP_MAX_CHARS + 1024) catch {
        try std.fmt.format(w, "### {s}\n\n[Could not read: {s}]\n\n", .{ filename, filename });
        return;
    };
    defer allocator.free(content);

    try appendPromptSectionContent(w, filename, content);
}

fn appendPromptSectionContent(
    w: anytype,
    filename: []const u8,
    content: []const u8,
) !void {
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

fn injectPreferredMemoryFile(
    allocator: std.mem.Allocator,
    w: anytype,
    workspace_dir: []const u8,
) !void {
    var seen_memory_paths: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it = seen_memory_paths.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        seen_memory_paths.deinit(allocator);
    }

    const memory_files = [_][]const u8{ "MEMORY.md", "memory.md" };
    for (memory_files) |filename| {
        const opened = openWorkspaceFileWithGuards(allocator, workspace_dir, filename);
        if (opened == null) continue;
        var guarded = opened.?;
        defer deinitGuardedWorkspaceFile(allocator, guarded);

        if (seen_memory_paths.contains(guarded.canonical_path)) {
            continue;
        }
        try seen_memory_paths.put(allocator, try allocator.dupe(u8, guarded.canonical_path), {});

        try appendWorkspaceFileContent(allocator, w, filename, &guarded.file);
    }
}

fn workspaceFileExists(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    filename: []const u8,
) bool {
    const opened = openWorkspaceFileWithGuards(allocator, workspace_dir, filename);
    if (opened) |guarded| {
        deinitGuardedWorkspaceFile(allocator, guarded);
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "pathStartsWith handles root prefixes" {
    try std.testing.expect(pathStartsWith("/tmp/workspace", "/"));
    try std.testing.expect(pathStartsWith("C:\\tmp\\workspace", "C:\\"));
    try std.testing.expect(pathStartsWith("/tmp/workspace", "/tmp"));
    try std.testing.expect(!pathStartsWith("/tmpx/workspace", "/tmp"));
}

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
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Current Date & Time") != null);
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

test "buildSystemPrompt includes channel attachment marker guidance" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = "/my/workspace",
        .model_name = "claude",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Channel Attachments") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "[FILE:/absolute/path/to/file.ext]") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "Do not claim attachment sending is unavailable") != null);
}

test "buildSystemPrompt injects memory.md when MEMORY.md is absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("memory.md", .{});
        defer f.close();
        try f.writeAll("alt-memory");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    const has_memory_header = std.mem.indexOf(u8, prompt, "### memory.md") != null or
        std.mem.indexOf(u8, prompt, "### MEMORY.md") != null;
    try std.testing.expect(has_memory_header);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "alt-memory") != null);
}

test "buildSystemPrompt injects BOOTSTRAP.md when present" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("BOOTSTRAP.md", .{});
        defer f.close();
        try f.writeAll("bootstrap-welcome-line");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "### BOOTSTRAP.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "bootstrap-welcome-line") != null);
}

test "buildSystemPrompt injects HEARTBEAT.md when present" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("HEARTBEAT.md", .{});
        defer f.close();
        try f.writeAll("- heartbeat-check-item");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "### HEARTBEAT.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "heartbeat-check-item") != null);
}

test "buildSystemPrompt injects IDENTITY.md when present" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("IDENTITY.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** identity-test-bot");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "### IDENTITY.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "identity-test-bot") != null);
}

test "buildSystemPrompt injects USER.md when present" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** user-test\n- **Timezone:** UTC");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "### USER.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "**Name:** user-test") != null);
}

test "workspacePromptFingerprint is stable when files are unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("SOUL.md", .{});
        defer f.close();
        try f.writeAll("soul-v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const fp1 = try workspacePromptFingerprint(std.testing.allocator, workspace);
    const fp2 = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expectEqual(fp1, fp2);
}

test "workspacePromptFingerprint changes when tracked file changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("SOUL.md", .{});
        defer f.close();
        try f.writeAll("short");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("SOUL.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("longer-content-after-change");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when MEMORY.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("MEMORY.md", .{});
        defer f.close();
        try f.writeAll("memory-v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("MEMORY.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("memory-v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when memory.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("memory.md", .{});
        defer f.close();
        try f.writeAll("alt-memory-v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("memory.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("alt-memory-v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when BOOTSTRAP.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("BOOTSTRAP.md", .{});
        defer f.close();
        try f.writeAll("bootstrap-v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("BOOTSTRAP.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("bootstrap-v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when HEARTBEAT.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("HEARTBEAT.md", .{});
        defer f.close();
        try f.writeAll("- check-1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("HEARTBEAT.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("- check-2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when IDENTITY.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("IDENTITY.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("IDENTITY.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("- **Name:** v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when AGENTS.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("AGENTS.md", .{});
        defer f.close();
        try f.writeAll("startup-v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("AGENTS.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("startup-v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "workspacePromptFingerprint changes when USER.md changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("- **Name:** v1");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const before = try workspacePromptFingerprint(std.testing.allocator, workspace);

    {
        const f = try tmp.dir.createFile("USER.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("- **Name:** v2-updated");
    }

    const after = try workspacePromptFingerprint(std.testing.allocator, workspace);
    try std.testing.expect(before != after);
}

test "buildSystemPrompt includes both MEMORY.md and memory.md when distinct" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const primary = try tmp.dir.createFile("MEMORY.md", .{});
        defer primary.close();
        try primary.writeAll("primary-memory");
    }

    var has_distinct_case_files = true;
    const alt = tmp.dir.createFile("memory.md", .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => blk: {
            has_distinct_case_files = false;
            break :blk null;
        },
        else => return err,
    };
    if (alt) |f| {
        defer f.close();
        try f.writeAll("alt-memory");
    }

    const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    const prompt = try buildSystemPrompt(std.testing.allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer std.testing.allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "### MEMORY.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "primary-memory") != null);
    if (has_distinct_case_files) {
        try std.testing.expect(std.mem.indexOf(u8, prompt, "### memory.md") != null);
        try std.testing.expect(std.mem.indexOf(u8, prompt, "alt-memory") != null);
    }
}

test "appendDateTimeSection outputs UTC timestamp" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const w = buf.writer(std.testing.allocator);
    try appendDateTimeSection(w);

    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "## Current Date & Time") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "UTC") != null);
    // Verify the year is plausible (2025+)
    try std.testing.expect(std.mem.indexOf(u8, output, "202") != null);
}

test "appendSkillsSection with no skills produces nothing" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, "/tmp/nullclaw-prompt-test-no-skills");

    try std.testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "appendSkillsSection renders summary XML for always=false skill" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Setup
    try tmp.dir.makePath("skills/greeter");

    // always defaults to false — should render as summary XML
    {
        const f = try tmp.dir.createFile("skills/greeter/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"greeter\", \"version\": \"1.0.0\", \"description\": \"Greets the user\", \"author\": \"dev\"}");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    // Summary skills should appear as self-closing XML tags
    try std.testing.expect(std.mem.indexOf(u8, output, "<available_skills>") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "</available_skills>") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"greeter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "description=\"Greets the user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "SKILL.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "read_file") != null);
    // Full instructions should NOT be in the output
    try std.testing.expect(std.mem.indexOf(u8, output, "## Skills") == null);
}

test "appendSkillsSection escapes XML attributes in summary output" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/xml-escape");
    {
        const f = try tmp.dir.createFile("skills/xml-escape/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"xml-escape\", \"description\": \"Use \\\"quotes\\\" & <tags>\"}");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "&quot;") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "&amp;") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "&lt;tags&gt;") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "description=\"Use \"quotes\" & <tags>\"") == null);
}

test "appendSkillsSection supports markdown-only installed skill" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("skills/md-only");
    {
        const f = try tmp.dir.createFile("skills/md-only/SKILL.md", .{});
        defer f.close();
        try f.writeAll("# Markdown only skill");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"md-only\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "path=\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "md-only/SKILL.md") != null);
}

test "appendSkillsSection renders full instructions for always=true skill" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Setup
    try tmp.dir.makePath("skills/commit");

    // always=true skill with instructions
    {
        const f = try tmp.dir.createFile("skills/commit/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"commit\", \"description\": \"Git commit helper\", \"always\": true}");
    }
    {
        const f = try tmp.dir.createFile("skills/commit/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Always stage before committing.");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    // Full instructions should be in the output
    try std.testing.expect(std.mem.indexOf(u8, output, "## Skills") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "### Skill: commit") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Always stage before committing.") != null);
    // Should NOT appear in summary XML
    try std.testing.expect(std.mem.indexOf(u8, output, "<available_skills>") == null);
}

test "appendSkillsSection renders mixed always=true and always=false" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Setup
    try tmp.dir.makePath("skills/full-skill");
    try tmp.dir.makePath("skills/lazy-skill");

    // always=true skill
    {
        const f = try tmp.dir.createFile("skills/full-skill/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"full-skill\", \"description\": \"Full loader\", \"always\": true}");
    }
    {
        const f = try tmp.dir.createFile("skills/full-skill/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Full instructions here.");
    }

    // always=false skill (default)
    {
        const f = try tmp.dir.createFile("skills/lazy-skill/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"lazy-skill\", \"description\": \"Lazy loader\"}");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    // Full skill should be in ## Skills section
    try std.testing.expect(std.mem.indexOf(u8, output, "## Skills") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "### Skill: full-skill") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Full instructions here.") != null);
    // Lazy skill should be in <available_skills> XML
    try std.testing.expect(std.mem.indexOf(u8, output, "<available_skills>") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"lazy-skill\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "SKILL.md") != null);
}

test "appendSkillsSection renders unavailable skill with missing deps" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Setup
    try tmp.dir.makePath("skills/docker-deploy");

    // Skill requiring nonexistent binary and env
    {
        const f = try tmp.dir.createFile("skills/docker-deploy/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"docker-deploy\", \"description\": \"Deploy with docker\", \"requires_bins\": [\"nullclaw_fake_docker_xyz\"], \"requires_env\": [\"NULLCLAW_FAKE_TOKEN_XYZ\"]}");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    // Should render as unavailable in XML
    try std.testing.expect(std.mem.indexOf(u8, output, "<available_skills>") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"docker-deploy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "available=\"false\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "missing=") != null);
    // Should NOT be in the full Skills section
    try std.testing.expect(std.mem.indexOf(u8, output, "## Skills") == null);
}

test "appendSkillsSection unavailable always=true skill renders in XML not full" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Setup
    try tmp.dir.makePath("skills/broken-always");

    // always=true but requires nonexistent binary — should be unavailable
    {
        const f = try tmp.dir.createFile("skills/broken-always/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"broken-always\", \"description\": \"Broken always skill\", \"always\": true, \"requires_bins\": [\"nullclaw_nonexistent_xyz_aaa\"]}");
    }
    {
        const f = try tmp.dir.createFile("skills/broken-always/SKILL.md", .{});
        defer f.close();
        try f.writeAll("These instructions should NOT appear in prompt.");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try appendSkillsSection(allocator, w, base);

    const output = buf.items;
    // Even though always=true, since unavailable it should render as XML summary
    try std.testing.expect(std.mem.indexOf(u8, output, "available=\"false\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"broken-always\"") != null);
    // Full instructions should NOT be in the prompt
    try std.testing.expect(std.mem.indexOf(u8, output, "These instructions should NOT appear in prompt.") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "### Skill: broken-always") == null);
}

test "installSkill end-to-end appears in buildSystemPrompt" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace");
    try tmp.dir.makePath("source");

    {
        const f = try tmp.dir.createFile("source/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"e2e-installed-skill\", \"description\": \"Installed via installSkill\"}");
    }
    {
        const f = try tmp.dir.createFile("source/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Follow the installed skill instructions.");
    }

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const workspace = try std.fs.path.join(allocator, &.{ base, "workspace" });
    defer allocator.free(workspace);
    const source = try std.fs.path.join(allocator, &.{ base, "source" });
    defer allocator.free(source);

    try skills_mod.installSkill(allocator, source, workspace);

    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = workspace,
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Available Skills") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "name=\"e2e-installed-skill\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "path=\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "source/SKILL.md") != null);
}

test "buildSystemPrompt datetime appears before runtime" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, .{
        .workspace_dir = "/tmp/nonexistent",
        .model_name = "test-model",
        .tools = &.{},
    });
    defer allocator.free(prompt);

    const dt_pos = std.mem.indexOf(u8, prompt, "## Current Date & Time") orelse return error.SectionNotFound;
    const rt_pos = std.mem.indexOf(u8, prompt, "## Runtime") orelse return error.SectionNotFound;
    try std.testing.expect(dt_pos < rt_pos);
}
