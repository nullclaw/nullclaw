//! Migration — import memory from OpenClaw workspaces.
//!
//! Mirrors ZeroClaw's migration module:
//!   - Reads from OpenClaw SQLite (brain.db) and Markdown (MEMORY.md, daily logs)
//!   - De-duplicates entries
//!   - Renames conflicting keys
//!   - Supports dry-run mode
//!   - Creates backup before import

const std = @import("std");
const platform = @import("platform.zig");
const Config = @import("config.zig").Config;
const memory_root = @import("memory/root.zig");
const migrate_mod = @import("memory/lifecycle/migrate.zig");

const log = std.log.scoped(.migration);

/// Policy for handling key conflicts during migration.
pub const MergePolicy = enum {
    /// Skip entries whose key already exists in the target (default safe mode).
    skip_existing,
    /// Overwrite target entry if the source content is different.
    overwrite_newer,
    /// Rename conflicting keys with a `_migrated_<hash>` suffix.
    rename_conflicts,
};

/// Statistics collected during migration.
pub const MigrationStats = struct {
    from_sqlite: usize = 0,
    from_markdown: usize = 0,
    imported: usize = 0,
    skipped_unchanged: usize = 0,
    renamed_conflicts: usize = 0,
    overwritten: usize = 0,
    backup_path: ?[]const u8 = null,
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
    return migrateOpenclawWithPolicy(allocator, config, source_path, dry_run, .rename_conflicts);
}

/// Run the OpenClaw migration command with an explicit merge policy.
pub fn migrateOpenclawWithPolicy(
    allocator: std.mem.Allocator,
    config: *const Config,
    source_path: ?[]const u8,
    dry_run: bool,
    policy: MergePolicy,
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

    // Track markdown keys for dedup against SQLite
    var seen_keys = std.StringHashMap(void).init(allocator);
    defer seen_keys.deinit();
    for (entries.items) |e| {
        seen_keys.put(e.key, {}) catch {};
    }

    // Read brain.db entries (try memory/brain.db and workspace-level brain.db)
    readBrainDbEntries(allocator, source, &entries, &stats, &seen_keys);

    if (entries.items.len == 0) {
        return stats;
    }

    if (dry_run) {
        return stats;
    }

    // Backup before import
    const backup_path: ?[]u8 = createBackup(allocator, config) catch |err| blk: {
        log.warn("backup before migration failed: {}", .{err});
        break :blk null;
    };
    if (backup_path) |bp| {
        stats.backup_path = bp;
        log.info("created backup at {s}", .{bp});
    }

    // Open the target memory backend
    var mem_rt = memory_root.initRuntime(allocator, &.{ .backend = config.memory_backend }, config.workspace_dir) orelse
        return error.TargetMemoryOpenFailed;
    defer mem_rt.deinit();
    var mem = mem_rt.memory;

    // Import each entry into target memory according to merge policy
    for (entries.items) |entry| {
        var key = entry.key;
        var owned_key: ?[]u8 = null;
        defer if (owned_key) |k| allocator.free(k);

        if (mem.get(allocator, key) catch null) |existing| {
            defer {
                var e = existing;
                e.deinit(allocator);
            }

            // Fast content comparison via hash
            if (contentEqual(existing.content, entry.content)) {
                stats.skipped_unchanged += 1;
                continue;
            }

            // Content differs — apply merge policy
            switch (policy) {
                .skip_existing => {
                    stats.skipped_unchanged += 1;
                    continue;
                },
                .overwrite_newer => {
                    // Store will overwrite the existing entry
                    stats.overwritten += 1;
                },
                .rename_conflicts => {
                    const short_hash = contentShortHash(entry.content);
                    owned_key = std.fmt.allocPrint(allocator, "{s}_migrated_{s}", .{ entry.key, short_hash }) catch {
                        log.err("failed to allocate renamed key for '{s}'", .{entry.key});
                        continue;
                    };
                    key = owned_key.?;
                    stats.renamed_conflicts += 1;
                },
            }
        }

        const category = memory_root.MemoryCategory.fromString(entry.category);
        mem.store(key, entry.content, category, null) catch |err| {
            log.err("failed to store migration entry '{s}': {}", .{ key, err });
            continue;
        };
        stats.imported += 1;
    }

    return stats;
}

// ── Content hashing ─────────────────────────────────────────────

/// Compare two content strings for equality.
/// Direct comparison is both faster and correct (no hash collision risk).
fn contentEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Produce a short hex hash (first 8 hex chars of SHA-256) for deterministic
/// conflict key suffixes.
pub fn contentShortHash(content: []const u8) [8]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..4], .lower);
    return hex;
}

// ── Backup ──────────────────────────────────────────────────────

/// Create a backup of the target database before import.
/// For SQLite backends, copies the .db file. For markdown, copies MEMORY.md.
/// Returns the backup file path (caller owns the string).
pub fn createBackup(
    allocator: std.mem.Allocator,
    config: *const Config,
) ![]u8 {
    const timestamp = std.time.timestamp();
    const backend = config.memory_backend;

    if (std.mem.eql(u8, backend, "sqlite") or std.mem.eql(u8, backend, "lucid")) {
        // SQLite-based backends: backup the memory.db file
        const db_file = try std.fs.path.join(allocator, &.{ config.workspace_dir, "memory.db" });
        defer allocator.free(db_file);
        const backup_path = try std.fmt.allocPrint(allocator, "{s}.backup-{d}", .{ db_file, timestamp });
        errdefer allocator.free(backup_path);
        try copyFileAbsolute(db_file, backup_path);
        return backup_path;
    } else if (std.mem.eql(u8, backend, "markdown")) {
        // Markdown backend: backup MEMORY.md
        const md_file = try std.fs.path.join(allocator, &.{ config.workspace_dir, "MEMORY.md" });
        defer allocator.free(md_file);
        const backup_path = try std.fmt.allocPrint(allocator, "{s}.backup-{d}", .{ md_file, timestamp });
        errdefer allocator.free(backup_path);
        try copyFileAbsolute(md_file, backup_path);
        return backup_path;
    }

    return error.UnsupportedBackend;
}

/// Restore from a backup file by copying it over the current target.
/// The `backup_path` should be a path returned from `createBackup` or
/// following the naming convention `<target>.backup-<timestamp>`.
pub fn restoreBackup(backup_path: []const u8, target_path: []const u8) !void {
    try copyFileAbsolute(backup_path, target_path);
}

fn copyFileAbsolute(src: []const u8, dst: []const u8) !void {
    const src_file = try std.fs.openFileAbsolute(src, .{});
    defer src_file.close();
    const dst_file = try std.fs.createFileAbsolute(dst, .{});
    defer dst_file.close();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = src_file.read(&buf) catch return error.ReadError;
        if (n == 0) break;
        dst_file.writeAll(buf[0..n]) catch return error.WriteError;
    }
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
    const home = platform.getHomeDir(allocator) catch return error.NoHomeDir;
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".openclaw", "workspace" });
}

/// Check if two paths refer to the same location.
fn pathsEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Read brain.db entries from known locations, deduplicating against seen keys.
fn readBrainDbEntries(
    allocator: std.mem.Allocator,
    source: []const u8,
    entries: *std.ArrayList(SourceEntry),
    stats: *MigrationStats,
    seen_keys: *std.StringHashMap(void),
) void {
    // Try memory/brain.db (common OpenClaw layout)
    const paths = [_][]const u8{ "memory/brain.db", "brain.db" };
    for (&paths) |rel| {
        const db_path = std.fs.path.joinZ(allocator, &.{ source, rel }) catch continue;
        defer allocator.free(db_path);

        // Check file exists before attempting open
        const abs_path = db_path[0..db_path.len];
        std.fs.cwd().access(abs_path, .{}) catch continue;

        const sqlite_entries = migrate_mod.readBrainDb(allocator, db_path) catch |err| {
            log.warn("brain.db read failed at {s}: {}", .{ abs_path, err });
            continue;
        };
        defer migrate_mod.freeSqliteEntries(allocator, sqlite_entries);

        for (sqlite_entries) |se| {
            // Dedup: prefer markdown (human-edited) over SQLite
            if (seen_keys.contains(se.key)) continue;

            const key = allocator.dupe(u8, se.key) catch continue;
            const content = allocator.dupe(u8, se.content) catch {
                allocator.free(key);
                continue;
            };
            const category = allocator.dupe(u8, se.category) catch {
                allocator.free(key);
                allocator.free(content);
                continue;
            };

            entries.append(allocator, .{
                .key = key,
                .content = content,
                .category = category,
            }) catch {
                allocator.free(key);
                allocator.free(content);
                allocator.free(category);
                continue;
            };

            seen_keys.put(key, {}) catch {};
            stats.from_sqlite += 1;
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────

pub const MigrateError = error{
    SourceNotFound,
    SelfMigration,
    NoHomeDir,
    TargetMemoryOpenFailed,
    UnsupportedBackend,
    ReadError,
    WriteError,
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
    try std.testing.expectEqual(@as(usize, 0), stats.overwritten);
    try std.testing.expect(stats.backup_path == null);
}

// ── P5.2: Content hashing tests ──────────────────────────────────

test "contentEqual: identical short strings" {
    try std.testing.expect(contentEqual("hello", "hello"));
}

test "contentEqual: different short strings" {
    try std.testing.expect(!contentEqual("hello", "world"));
}

test "contentEqual: different lengths" {
    try std.testing.expect(!contentEqual("short", "a much longer string"));
}

test "contentEqual: identical long strings use hash path" {
    const long = "x" ** 128;
    try std.testing.expect(contentEqual(long, long));
}

test "contentEqual: different long strings" {
    const a = "a" ** 128;
    const b = "b" ** 128;
    try std.testing.expect(!contentEqual(a, b));
}

test "contentShortHash: deterministic output" {
    const h1 = contentShortHash("likes Zig");
    const h2 = contentShortHash("likes Zig");
    try std.testing.expectEqualStrings(&h1, &h2);
}

test "contentShortHash: different content yields different hash" {
    const h1 = contentShortHash("likes Zig");
    const h2 = contentShortHash("likes Rust");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "contentShortHash: returns 8 hex chars" {
    const hash = contentShortHash("test content");
    try std.testing.expectEqual(@as(usize, 8), hash.len);
    for (&hash) |ch| {
        try std.testing.expect((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
    }
}

// ── P5.2: MergePolicy tests ─────────────────────────────────────

test "MergePolicy enum values" {
    // Verify all policy variants exist and are distinct
    const skip = MergePolicy.skip_existing;
    const overwrite = MergePolicy.overwrite_newer;
    const rename = MergePolicy.rename_conflicts;
    try std.testing.expect(skip != overwrite);
    try std.testing.expect(overwrite != rename);
    try std.testing.expect(skip != rename);
}

// ── P5.3: Backup tests ──────────────────────────────────────────

test "backup and restore roundtrip" {
    // Create a temp file to act as source
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write a "database" file
    const content = "SQLITE_MAGIC_test_data_12345";
    const src_file = try tmp_dir.dir.createFile("test.db", .{});
    try src_file.writeAll(content);
    src_file.close();

    // Get absolute paths via realpath
    const src_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.db");
    defer std.testing.allocator.free(src_path);

    const backup_name = "test.db.backup-1234";
    const backup_file = try tmp_dir.dir.createFile(backup_name, .{});
    backup_file.close();
    const backup_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, backup_name);
    defer std.testing.allocator.free(backup_path);

    // Copy source to backup
    try copyFileAbsolute(src_path, backup_path);

    // Verify backup content matches
    const backup_content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, backup_name, 4096);
    defer std.testing.allocator.free(backup_content);
    try std.testing.expectEqualStrings(content, backup_content);

    // Corrupt the "database" (simulate modification)
    const mod_file = try tmp_dir.dir.createFile("test.db", .{});
    try mod_file.writeAll("CORRUPTED");
    mod_file.close();

    // Restore from backup
    try restoreBackup(backup_path, src_path);

    // Verify restored content
    const restored = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.db", 4096);
    defer std.testing.allocator.free(restored);
    try std.testing.expectEqualStrings(content, restored);
}

test "copyFileAbsolute fails on non-existent source" {
    const result = copyFileAbsolute("/tmp/nonexistent_migration_test_file_xyz.db", "/tmp/out.db");
    try std.testing.expectError(error.FileNotFound, result);
}

// ── P5.1: Empty source yields zero entries ───────────────────────

test "parseMarkdownFile with empty content returns zero" {
    var entries: std.ArrayList(SourceEntry) = .empty;
    defer entries.deinit(std.testing.allocator);
    const count = try parseMarkdownFile(std.testing.allocator, "", "core", "empty", &entries);
    try std.testing.expectEqual(@as(usize, 0), count);
    try std.testing.expectEqual(@as(usize, 0), entries.items.len);
}

test "parseMarkdownFile with whitespace-only content returns zero" {
    var entries: std.ArrayList(SourceEntry) = .empty;
    defer entries.deinit(std.testing.allocator);
    const count = try parseMarkdownFile(std.testing.allocator, "   \n  \n\t\n", "core", "ws", &entries);
    try std.testing.expectEqual(@as(usize, 0), count);
}
