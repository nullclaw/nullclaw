const std = @import("std");

// Skills — user-defined capabilities loaded from disk.
//
// Each skill lives in ~/.nullclaw/workspace/skills/<name>/ with:
//   - skill.json  — manifest (name, version, description, author)
//   - SKILL.md    — optional instruction text
//
// The skillforge module handles discovery and evaluation;
// this module handles definition, loading, installation, and removal.

// ── Types ───────────────────────────────────────────────────────

pub const Skill = struct {
    name: []const u8,
    version: []const u8 = "0.0.1",
    description: []const u8 = "",
    author: []const u8 = "",
    instructions: []const u8 = "",
    enabled: bool = true,
};

pub const SkillManifest = struct {
    name: []const u8,
    version: []const u8,
    description: []const u8,
    author: []const u8,
};

// ── JSON Parsing (manual, no allocations) ───────────────────────

/// Extract a string field value from a JSON blob (minimal parser — no allocations).
/// Same pattern as tools/shell.zig parseStringField.
fn parseStringField(json: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or
        after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1)
    {}

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

/// Parse a skill.json manifest from raw JSON bytes.
/// Returns slices pointing into the original json_bytes (no allocations needed
/// beyond what the caller already owns for json_bytes).
pub fn parseManifest(json_bytes: []const u8) !SkillManifest {
    const name = parseStringField(json_bytes, "name") orelse return error.MissingField;
    const version = parseStringField(json_bytes, "version") orelse "0.0.1";
    const description = parseStringField(json_bytes, "description") orelse "";
    const author = parseStringField(json_bytes, "author") orelse "";

    return SkillManifest{
        .name = name,
        .version = version,
        .description = description,
        .author = author,
    };
}

// ── Skill Loading ───────────────────────────────────────────────

/// Load a single skill from a directory.
/// Reads skill.json (required) and SKILL.md (optional) from skill_dir_path.
pub fn loadSkill(allocator: std.mem.Allocator, skill_dir_path: []const u8) !Skill {
    // Read skill.json
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/skill.json", .{skill_dir_path});
    defer allocator.free(manifest_path);

    const manifest_bytes = std.fs.cwd().readFileAlloc(allocator, manifest_path, 64 * 1024) catch
        return error.ManifestNotFound;
    defer allocator.free(manifest_bytes);

    const manifest = parseManifest(manifest_bytes) catch return error.InvalidManifest;

    // Dupe all strings so they outlive the manifest_bytes buffer
    const name = try allocator.dupe(u8, manifest.name);
    errdefer allocator.free(name);
    const version = try allocator.dupe(u8, manifest.version);
    errdefer allocator.free(version);
    const description = try allocator.dupe(u8, manifest.description);
    errdefer allocator.free(description);
    const author = try allocator.dupe(u8, manifest.author);
    errdefer allocator.free(author);

    // Try to read SKILL.md (optional)
    const instructions_path = try std.fmt.allocPrint(allocator, "{s}/SKILL.md", .{skill_dir_path});
    defer allocator.free(instructions_path);

    const instructions = std.fs.cwd().readFileAlloc(allocator, instructions_path, 256 * 1024) catch
        try allocator.dupe(u8, "");

    return Skill{
        .name = name,
        .version = version,
        .description = description,
        .author = author,
        .instructions = instructions,
        .enabled = true,
    };
}

/// Free all heap-allocated fields of a Skill.
pub fn freeSkill(allocator: std.mem.Allocator, skill: *const Skill) void {
    if (skill.name.len > 0) allocator.free(skill.name);
    if (skill.version.len > 0) allocator.free(skill.version);
    if (skill.description.len > 0) allocator.free(skill.description);
    if (skill.author.len > 0) allocator.free(skill.author);
    allocator.free(skill.instructions);
}

/// Free a slice of skills and all their contents.
pub fn freeSkills(allocator: std.mem.Allocator, skills_slice: []Skill) void {
    for (skills_slice) |*s| {
        freeSkill(allocator, s);
    }
    allocator.free(skills_slice);
}

// ── Listing ─────────────────────────────────────────────────────

/// Scan workspace_dir/skills/ for subdirectories, loading each as a Skill.
/// Returns owned slice; caller must free with freeSkills().
pub fn listSkills(allocator: std.mem.Allocator, workspace_dir: []const u8) ![]Skill {
    const skills_dir_path = try std.fmt.allocPrint(allocator, "{s}/skills", .{workspace_dir});
    defer allocator.free(skills_dir_path);

    var skills_list: std.ArrayList(Skill) = .empty;
    errdefer {
        for (skills_list.items) |*s| freeSkill(allocator, s);
        skills_list.deinit(allocator);
    }

    const dir = std.fs.cwd().openDir(skills_dir_path, .{ .iterate = true }) catch {
        // Directory doesn't exist or can't be opened — return empty
        return try skills_list.toOwnedSlice(allocator);
    };
    // Note: openDir returns by value in Zig 0.15, no need to dereference
    var dir_mut = dir;
    defer dir_mut.close();

    var it = dir_mut.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;

        const sub_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ skills_dir_path, entry.name });
        defer allocator.free(sub_path);

        if (loadSkill(allocator, sub_path)) |skill| {
            try skills_list.append(allocator, skill);
        } else |_| {
            // Skip directories without valid skill.json
            continue;
        }
    }

    return try skills_list.toOwnedSlice(allocator);
}

// ── Installation ────────────────────────────────────────────────

/// Install a skill by copying its directory into workspace_dir/skills/<name>/.
/// source_path must contain a valid skill.json.
pub fn installSkillFromPath(allocator: std.mem.Allocator, source_path: []const u8, workspace_dir: []const u8) !void {
    // Validate source has a manifest
    const src_manifest_path = try std.fmt.allocPrint(allocator, "{s}/skill.json", .{source_path});
    defer allocator.free(src_manifest_path);

    const manifest_bytes = std.fs.cwd().readFileAlloc(allocator, src_manifest_path, 64 * 1024) catch
        return error.ManifestNotFound;
    defer allocator.free(manifest_bytes);

    const manifest = parseManifest(manifest_bytes) catch return error.InvalidManifest;

    // Sanitize skill name for safe path usage
    for (manifest.name) |c| {
        if (c == '/' or c == '\\' or c == 0) return error.UnsafeName;
    }
    if (manifest.name.len == 0 or std.mem.eql(u8, manifest.name, "..")) return error.UnsafeName;

    // Ensure skills directory exists
    const skills_dir_path = try std.fmt.allocPrint(allocator, "{s}/skills", .{workspace_dir});
    defer allocator.free(skills_dir_path);
    std.fs.makeDirAbsolute(skills_dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Create target directory
    const target_path = try std.fmt.allocPrint(allocator, "{s}/skills/{s}", .{ workspace_dir, manifest.name });
    defer allocator.free(target_path);
    std.fs.makeDirAbsolute(target_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Copy skill.json
    const dst_manifest = try std.fmt.allocPrint(allocator, "{s}/skill.json", .{target_path});
    defer allocator.free(dst_manifest);
    try copyFileAbsolute(src_manifest_path, dst_manifest);

    // Copy SKILL.md if present
    const src_instructions = try std.fmt.allocPrint(allocator, "{s}/SKILL.md", .{source_path});
    defer allocator.free(src_instructions);
    const dst_instructions = try std.fmt.allocPrint(allocator, "{s}/SKILL.md", .{target_path});
    defer allocator.free(dst_instructions);
    copyFileAbsolute(src_instructions, dst_instructions) catch {
        // SKILL.md is optional, ignore if missing
    };
}

/// Copy a file from src to dst using absolute paths.
fn copyFileAbsolute(src: []const u8, dst: []const u8) !void {
    const src_file = try std.fs.openFileAbsolute(src, .{});
    defer src_file.close();

    const dst_file = try std.fs.createFileAbsolute(dst, .{});
    defer dst_file.close();

    // Read and write in chunks
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = src_file.read(&buf) catch return error.ReadError;
        if (n == 0) break;
        dst_file.writeAll(buf[0..n]) catch return error.WriteError;
    }
}

// ── Removal ─────────────────────────────────────────────────────

/// Remove a skill by deleting its directory from workspace_dir/skills/<name>/.
pub fn removeSkill(allocator: std.mem.Allocator, name: []const u8, workspace_dir: []const u8) !void {
    // Sanitize name
    for (name) |c| {
        if (c == '/' or c == '\\' or c == 0) return error.UnsafeName;
    }
    if (name.len == 0 or std.mem.eql(u8, name, "..")) return error.UnsafeName;

    const skill_path = try std.fmt.allocPrint(allocator, "{s}/skills/{s}", .{ workspace_dir, name });
    defer allocator.free(skill_path);

    // Verify the skill directory actually exists before deleting
    std.fs.accessAbsolute(skill_path, .{}) catch return error.SkillNotFound;

    std.fs.deleteTreeAbsolute(skill_path) catch |err| {
        return err;
    };
}

// ── Tests ───────────────────────────────────────────────────────

test "parseManifest full JSON" {
    const json =
        \\{"name": "code-review", "version": "1.2.0", "description": "Automated code review", "author": "nullclaw"}
    ;
    const m = try parseManifest(json);
    try std.testing.expectEqualStrings("code-review", m.name);
    try std.testing.expectEqualStrings("1.2.0", m.version);
    try std.testing.expectEqualStrings("Automated code review", m.description);
    try std.testing.expectEqualStrings("nullclaw", m.author);
}

test "parseManifest minimal JSON (name only)" {
    const json =
        \\{"name": "minimal-skill"}
    ;
    const m = try parseManifest(json);
    try std.testing.expectEqualStrings("minimal-skill", m.name);
    try std.testing.expectEqualStrings("0.0.1", m.version);
    try std.testing.expectEqualStrings("", m.description);
    try std.testing.expectEqualStrings("", m.author);
}

test "parseManifest missing name returns error" {
    const json =
        \\{"version": "1.0.0", "description": "no name"}
    ;
    try std.testing.expectError(error.MissingField, parseManifest(json));
}

test "parseManifest empty JSON object returns error" {
    try std.testing.expectError(error.MissingField, parseManifest("{}"));
}

test "parseManifest handles whitespace in JSON" {
    const json =
        \\{
        \\  "name": "spaced-skill",
        \\  "version": "0.1.0",
        \\  "description": "A skill with whitespace",
        \\  "author": "tester"
        \\}
    ;
    const m = try parseManifest(json);
    try std.testing.expectEqualStrings("spaced-skill", m.name);
    try std.testing.expectEqualStrings("0.1.0", m.version);
    try std.testing.expectEqualStrings("A skill with whitespace", m.description);
    try std.testing.expectEqualStrings("tester", m.author);
}

test "parseManifest handles escaped quotes" {
    const json =
        \\{"name": "escape-test", "description": "says \"hello\""}
    ;
    const m = try parseManifest(json);
    try std.testing.expectEqualStrings("escape-test", m.name);
    try std.testing.expectEqualStrings("says \\\"hello\\\"", m.description);
}

test "parseStringField basic" {
    const json = "{\"command\": \"echo hello\", \"other\": \"val\"}";
    const val = parseStringField(json, "command");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("echo hello", val.?);
}

test "parseStringField missing key" {
    const json = "{\"other\": \"val\"}";
    try std.testing.expect(parseStringField(json, "command") == null);
}

test "parseStringField non-string value" {
    const json = "{\"count\": 42}";
    try std.testing.expect(parseStringField(json, "count") == null);
}

test "Skill struct defaults" {
    const s = Skill{ .name = "test" };
    try std.testing.expectEqualStrings("test", s.name);
    try std.testing.expectEqualStrings("0.0.1", s.version);
    try std.testing.expectEqualStrings("", s.description);
    try std.testing.expectEqualStrings("", s.author);
    try std.testing.expectEqualStrings("", s.instructions);
    try std.testing.expect(s.enabled);
}

test "Skill struct custom values" {
    const s = Skill{
        .name = "custom",
        .version = "2.0.0",
        .description = "A custom skill",
        .author = "dev",
        .instructions = "Do the thing",
        .enabled = false,
    };
    try std.testing.expectEqualStrings("custom", s.name);
    try std.testing.expectEqualStrings("2.0.0", s.version);
    try std.testing.expectEqualStrings("A custom skill", s.description);
    try std.testing.expectEqualStrings("dev", s.author);
    try std.testing.expectEqualStrings("Do the thing", s.instructions);
    try std.testing.expect(!s.enabled);
}

test "SkillManifest fields" {
    const m = SkillManifest{
        .name = "test",
        .version = "1.0.0",
        .description = "desc",
        .author = "author",
    };
    try std.testing.expectEqualStrings("test", m.name);
    try std.testing.expectEqualStrings("1.0.0", m.version);
}

test "listSkills from nonexistent directory" {
    const allocator = std.testing.allocator;
    const skills = try listSkills(allocator, "/tmp/nullclaw-test-skills-nonexistent-dir");
    defer freeSkills(allocator, skills);
    try std.testing.expectEqual(@as(usize, 0), skills.len);
}

test "listSkills from empty directory" {
    const allocator = std.testing.allocator;
    const base = "/tmp/nullclaw-test-skills-empty";
    const skills_dir = "/tmp/nullclaw-test-skills-empty/skills";

    // Create the skills directory
    std.fs.makeDirAbsolute(base) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(base) catch {};
    std.fs.makeDirAbsolute(skills_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const skills = try listSkills(allocator, base);
    defer freeSkills(allocator, skills);
    try std.testing.expectEqual(@as(usize, 0), skills.len);
}

test "loadSkill reads manifest and instructions" {
    const allocator = std.testing.allocator;
    const skill_dir = "/tmp/nullclaw-test-skills-load/skills/test-skill";

    // Setup: create skill directory with manifest and instructions
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-load") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-load/skills") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute(skill_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute("/tmp/nullclaw-test-skills-load") catch {};

    // Write skill.json
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-load/skills/test-skill/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"test-skill\", \"version\": \"1.0.0\", \"description\": \"A test\", \"author\": \"tester\"}");
    }

    // Write SKILL.md
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-load/skills/test-skill/SKILL.md", .{});
        defer f.close();
        try f.writeAll("# Test Skill\nDo the test thing.");
    }

    const skill = try loadSkill(allocator, skill_dir);
    defer freeSkill(allocator, &skill);

    try std.testing.expectEqualStrings("test-skill", skill.name);
    try std.testing.expectEqualStrings("1.0.0", skill.version);
    try std.testing.expectEqualStrings("A test", skill.description);
    try std.testing.expectEqualStrings("tester", skill.author);
    try std.testing.expectEqualStrings("# Test Skill\nDo the test thing.", skill.instructions);
    try std.testing.expect(skill.enabled);
}

test "loadSkill without SKILL.md still works" {
    const allocator = std.testing.allocator;
    const skill_dir = "/tmp/nullclaw-test-skills-nomd/skills/bare-skill";

    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-nomd") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-nomd/skills") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute(skill_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute("/tmp/nullclaw-test-skills-nomd") catch {};

    // Write only skill.json, no SKILL.md
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-nomd/skills/bare-skill/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"bare-skill\", \"version\": \"0.5.0\"}");
    }

    const skill = try loadSkill(allocator, skill_dir);
    defer freeSkill(allocator, &skill);

    try std.testing.expectEqualStrings("bare-skill", skill.name);
    try std.testing.expectEqualStrings("0.5.0", skill.version);
    try std.testing.expectEqualStrings("", skill.instructions);
}

test "loadSkill missing manifest returns error" {
    const allocator = std.testing.allocator;
    const skill_dir = "/tmp/nullclaw-test-skills-nomanifest";

    std.fs.makeDirAbsolute(skill_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(skill_dir) catch {};

    try std.testing.expectError(error.ManifestNotFound, loadSkill(allocator, skill_dir));
}

test "listSkills discovers skills in subdirectories" {
    const allocator = std.testing.allocator;
    const base = "/tmp/nullclaw-test-skills-list";
    const skills_dir = "/tmp/nullclaw-test-skills-list/skills";

    std.fs.makeDirAbsolute(base) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute(skills_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(base) catch {};

    // Create two skill directories
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-list/skills/alpha") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-list/skills/alpha/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"alpha\", \"version\": \"1.0.0\", \"description\": \"First skill\", \"author\": \"dev\"}");
    }

    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-list/skills/beta") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-list/skills/beta/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"beta\", \"version\": \"2.0.0\", \"description\": \"Second skill\", \"author\": \"dev2\"}");
    }

    // Also create a regular file (should be skipped)
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-list/skills/README.md", .{});
        defer f.close();
        try f.writeAll("Not a skill directory");
    }

    const skills = try listSkills(allocator, base);
    defer freeSkills(allocator, skills);

    try std.testing.expectEqual(@as(usize, 2), skills.len);

    // Skills may come in any order from directory iteration
    var found_alpha = false;
    var found_beta = false;
    for (skills) |s| {
        if (std.mem.eql(u8, s.name, "alpha")) found_alpha = true;
        if (std.mem.eql(u8, s.name, "beta")) found_beta = true;
    }
    try std.testing.expect(found_alpha);
    try std.testing.expect(found_beta);
}

test "listSkills skips directories without valid manifest" {
    const allocator = std.testing.allocator;
    const base = "/tmp/nullclaw-test-skills-skip";
    const skills_dir = "/tmp/nullclaw-test-skills-skip/skills";

    std.fs.makeDirAbsolute(base) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute(skills_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(base) catch {};

    // One valid skill
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-skip/skills/valid") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-skip/skills/valid/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"valid\"}");
    }

    // One empty directory (no manifest)
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-skip/skills/broken") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const skills = try listSkills(allocator, base);
    defer freeSkills(allocator, skills);

    try std.testing.expectEqual(@as(usize, 1), skills.len);
    try std.testing.expectEqualStrings("valid", skills[0].name);
}

test "installSkillFromPath and removeSkill roundtrip" {
    const allocator = std.testing.allocator;
    const workspace = "/tmp/nullclaw-test-skills-install";
    const source = "/tmp/nullclaw-test-skills-install-src";

    // Setup workspace
    std.fs.makeDirAbsolute(workspace) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(workspace) catch {};

    // Setup source skill
    std.fs.makeDirAbsolute(source) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(source) catch {};

    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-install-src/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"installable\", \"version\": \"1.0.0\", \"description\": \"Test install\", \"author\": \"dev\"}");
    }
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-install-src/SKILL.md", .{});
        defer f.close();
        try f.writeAll("# Instructions\nInstall me.");
    }

    // Install
    try installSkillFromPath(allocator, source, workspace);

    // Verify installed skill loads
    const skills = try listSkills(allocator, workspace);
    defer freeSkills(allocator, skills);
    try std.testing.expectEqual(@as(usize, 1), skills.len);
    try std.testing.expectEqualStrings("installable", skills[0].name);
    try std.testing.expectEqualStrings("# Instructions\nInstall me.", skills[0].instructions);

    // Remove
    try removeSkill(allocator, "installable", workspace);

    // Verify removal
    const after = try listSkills(allocator, workspace);
    defer freeSkills(allocator, after);
    try std.testing.expectEqual(@as(usize, 0), after.len);
}

test "installSkillFromPath rejects missing manifest" {
    const allocator = std.testing.allocator;
    const source = "/tmp/nullclaw-test-skills-install-bad";

    std.fs.makeDirAbsolute(source) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(source) catch {};

    try std.testing.expectError(error.ManifestNotFound, installSkillFromPath(allocator, source, "/tmp/nullclaw-test-ws"));
}

test "removeSkill nonexistent returns SkillNotFound" {
    const allocator = std.testing.allocator;
    const workspace = "/tmp/nullclaw-test-skills-remove-none";

    std.fs.makeDirAbsolute(workspace) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute("/tmp/nullclaw-test-skills-remove-none/skills") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(workspace) catch {};

    try std.testing.expectError(error.SkillNotFound, removeSkill(allocator, "nonexistent", workspace));
}

test "removeSkill rejects unsafe names" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnsafeName, removeSkill(allocator, "../etc", "/tmp"));
    try std.testing.expectError(error.UnsafeName, removeSkill(allocator, "foo/bar", "/tmp"));
    try std.testing.expectError(error.UnsafeName, removeSkill(allocator, "", "/tmp"));
    try std.testing.expectError(error.UnsafeName, removeSkill(allocator, "..", "/tmp"));
}

test "installSkillFromPath rejects unsafe skill names" {
    const allocator = std.testing.allocator;
    const source = "/tmp/nullclaw-test-skills-unsafe-name";

    std.fs.makeDirAbsolute(source) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(source) catch {};

    // Write a manifest with a malicious name
    {
        const f = try std.fs.createFileAbsolute("/tmp/nullclaw-test-skills-unsafe-name/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"../../../etc/passwd\"}");
    }

    try std.testing.expectError(error.UnsafeName, installSkillFromPath(allocator, source, "/tmp/nullclaw-test-ws"));
}
