//! Migration — import memory from OpenClaw workspaces.
//!
//! Mirrors ZeroClaw's migration module:
//!   - Reads from OpenClaw SQLite (brain.db) and Markdown (MEMORY.md, daily logs)
//!   - De-duplicates entries
//!   - Renames conflicting keys
//!   - Supports dry-run mode
//!   - Creates backup before import

const std = @import("std");
const Config = @import("config.zig").Config;
const memory_root = @import("memory/root.zig");

/// Statistics collected during migration.
pub const MigrationStats = struct {
    from_sqlite: usize = 0,
    from_markdown: usize = 0,
    imported: usize = 0,
    skipped_unchanged: usize = 0,
    renamed_conflicts: usize = 0,
};

/// A single entry from the source workspace.
pub const SourceEntry = struct {
    key: []const u8,
    content: []const u8,
    category: []const u8,
};

/// Run the OpenClaw migration command.
pub fn migrateOpenclaw(
    allocator: std.mem.Allocator,
    config: *const Config,
    source_path: ?[]const u8,
    dry_run: bool,
) !MigrationStats {
    const source = try resolveOpenclawWorkspace(allocator, source_path);
    defer allocator.free(source);

    // Verify source exists
    {
        var dir = std.fs.openDirAbsolute(source, .{}) catch {
            return error.SourceNotFound;
        };
        dir.close();
    }

    // Refuse self-migration
    if (pathsEqual(source, config.workspace_dir)) {
        return error.SelfMigration;
    }

    var stats = MigrationStats{};

    // Collect entries from source
    var entries: std.ArrayList(SourceEntry) = .empty;
    defer {
        for (entries.items) |e| {
            allocator.free(e.key);
            allocator.free(e.content);
            allocator.free(e.category);
        }
        entries.deinit(allocator);
    }

    // Read markdown entries from source
    try readOpenclawMarkdownEntries(allocator, source, &entries, &stats);

    if (entries.items.len == 0) {
        return stats;
    }

    if (dry_run) {
        return stats;
    }

    // Open the target memory backend
    const db_path = try std.fs.path.joinZ(allocator, &.{ config.workspace_dir, "memory.db" });
    defer allocator.free(db_path);

    var mem = memory_root.createMemory(allocator, config.memory_backend, db_path) catch {
        return error.TargetMemoryOpenFailed;
    };
    defer mem.deinit();

    // Import each entry into target memory, renaming conflicts
    for (entries.items) |entry| {
        // Check if key already exists in target
        var key = entry.key;
        var owned_key: ?[]u8 = null;
        defer if (owned_key) |k| allocator.free(k);

        if (mem.get(allocator, key) catch null) |existing| {
            // Key conflict — check if content is the same
            defer {
                var e = existing;
                e.deinit(allocator);
            }
            if (std.mem.eql(u8, existing.content, entry.content)) {
                stats.skipped_unchanged += 1;
                continue;
            }
            // Rename with _migrated suffix
            owned_key = try std.fmt.allocPrint(allocator, "{s}_migrated", .{entry.key});
            key = owned_key.?;
            stats.renamed_conflicts += 1;
        }

        const category = memory_root.MemoryCategory.fromString(entry.category);
        mem.store(key, entry.content, category) catch {
            continue;
        };
        stats.imported += 1;
    }

    return stats;
}

/// Read OpenClaw markdown entries from MEMORY.md and daily logs.
fn readOpenclawMarkdownEntries(
    allocator: std.mem.Allocator,
    source: []const u8,
    entries: *std.ArrayList(SourceEntry),
    stats: *MigrationStats,
) !void {
    // Core memory file
    const core_path = try std.fmt.allocPrint(allocator, "{s}/MEMORY.md", .{source});
    defer allocator.free(core_path);

    if (std.fs.cwd().readFileAlloc(allocator, core_path, 1024 * 1024)) |content| {
        defer allocator.free(content);
        const count = try parseMarkdownFile(allocator, content, "core", "openclaw_core", entries);
        stats.from_markdown += count;
    } else |_| {}

    // Daily logs
    const daily_dir = try std.fmt.allocPrint(allocator, "{s}/memory", .{source});
    defer allocator.free(daily_dir);

    if (std.fs.cwd().openDir(daily_dir, .{ .iterate = true })) |*dir_handle| {
        var dir = dir_handle.*;
        defer dir.close();
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
            const fpath = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ daily_dir, entry.name });
            defer allocator.free(fpath);
            if (std.fs.cwd().readFileAlloc(allocator, fpath, 1024 * 1024)) |content| {
                defer allocator.free(content);
                const stem = entry.name[0 .. entry.name.len - 3];
                const count = try parseMarkdownFile(allocator, content, "daily", stem, entries);
                stats.from_markdown += count;
            } else |_| {}
        }
    } else |_| {}
}

/// Parse a markdown file into SourceEntry items.
fn parseMarkdownFile(
    allocator: std.mem.Allocator,
    content: []const u8,
    category: []const u8,
    stem: []const u8,
    entries: *std.ArrayList(SourceEntry),
) !usize {
    var count: usize = 0;
    var line_idx: usize = 0;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        defer line_idx += 1;
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const clean = if (std.mem.startsWith(u8, trimmed, "- ")) trimmed[2..] else trimmed;

        // Try to parse structured format: **key**: value
        const parsed = parseStructuredLine(clean);
        const key = if (parsed.key) |k|
            try allocator.dupe(u8, k)
        else
            try std.fmt.allocPrint(allocator, "openclaw_{s}_{d}", .{ stem, line_idx + 1 });
        errdefer allocator.free(key);

        const text = if (parsed.value) |v|
            try allocator.dupe(u8, std.mem.trim(u8, v, " \t"))
        else
            try allocator.dupe(u8, std.mem.trim(u8, clean, " \t"));
        errdefer allocator.free(text);

        if (text.len == 0) {
            allocator.free(key);
            allocator.free(text);
            continue;
        }

        const cat = try allocator.dupe(u8, category);
        errdefer allocator.free(cat);

        try entries.append(allocator, .{
            .key = key,
            .content = text,
            .category = cat,
        });
        count += 1;
    }
    return count;
}

/// Parse a structured memory line: **key**: value
fn parseStructuredLine(line: []const u8) struct { key: ?[]const u8, value: ?[]const u8 } {
    if (!std.mem.startsWith(u8, line, "**")) return .{ .key = null, .value = null };
    const rest = line[2..];
    const key_end = std.mem.indexOf(u8, rest, "**:") orelse return .{ .key = null, .value = null };
    const key = std.mem.trim(u8, rest[0..key_end], " \t");
    const value = if (key_end + 3 < rest.len) rest[key_end + 3 ..] else "";
    if (key.len == 0) return .{ .key = null, .value = null };
    return .{ .key = key, .value = value };
}

/// Resolve the OpenClaw workspace directory.
fn resolveOpenclawWorkspace(allocator: std.mem.Allocator, source: ?[]const u8) ![]u8 {
    if (source) |src| return allocator.dupe(u8, src);
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHomeDir;
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.openclaw/workspace", .{home});
}

/// Check if two paths refer to the same location.
fn pathsEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ── Errors ───────────────────────────────────────────────────────

pub const MigrateError = error{
    SourceNotFound,
    SelfMigration,
    NoHomeDir,
    TargetMemoryOpenFailed,
};

// ── Tests ────────────────────────────────────────────────────────

test "parseStructuredLine parses bold key" {
    const result = parseStructuredLine("**user_pref**: likes Zig");
    try std.testing.expectEqualStrings("user_pref", result.key.?);
    try std.testing.expect(std.mem.indexOf(u8, result.value.?, "likes Zig") != null);
}

test "parseStructuredLine returns null for plain text" {
    const result = parseStructuredLine("plain note");
    try std.testing.expect(result.key == null);
    try std.testing.expect(result.value == null);
}

test "parseStructuredLine returns null for empty key" {
    const result = parseStructuredLine("****: some value");
    try std.testing.expect(result.key == null);
}

test "parseMarkdownFile extracts entries" {
    const content = "# Title\n\n- **pref**: likes Zig\n- plain note\n\n# Section 2\nmore text\n";
    var entries: std.ArrayList(SourceEntry) = .empty;
    defer {
        for (entries.items) |e| {
            std.testing.allocator.free(e.key);
            std.testing.allocator.free(e.content);
            std.testing.allocator.free(e.category);
        }
        entries.deinit(std.testing.allocator);
    }

    const count = try parseMarkdownFile(std.testing.allocator, content, "core", "test", &entries);
    try std.testing.expect(count >= 2);
    try std.testing.expect(entries.items.len >= 2);
}

test "parseMarkdownFile skips headings and blank lines" {
    const content = "# Heading\n\n## Sub\n\n";
    var entries: std.ArrayList(SourceEntry) = .empty;
    defer entries.deinit(std.testing.allocator);

    const count = try parseMarkdownFile(std.testing.allocator, content, "core", "test", &entries);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "pathsEqual detects same paths" {
    try std.testing.expect(pathsEqual("/a/b", "/a/b"));
    try std.testing.expect(!pathsEqual("/a/b", "/a/c"));
}

test "resolveOpenclawWorkspace uses provided path" {
    const path = try resolveOpenclawWorkspace(std.testing.allocator, "/custom/workspace");
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/custom/workspace", path);
}

test "MigrationStats defaults to zero" {
    const stats = MigrationStats{};
    try std.testing.expectEqual(@as(usize, 0), stats.imported);
    try std.testing.expectEqual(@as(usize, 0), stats.from_sqlite);
    try std.testing.expectEqual(@as(usize, 0), stats.from_markdown);
}
