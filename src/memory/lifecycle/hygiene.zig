//! Memory hygiene — periodic cleanup of old daily memories, archives, and conversation rows.
//!
//! Mirrors ZeroClaw's hygiene module:
//!   - run_if_due: checks last_hygiene_at in kv table, runs if older than interval
//!   - Archives old daily memory files
//!   - Purges expired archives
//!   - Prunes old conversation rows from SQLite

const std = @import("std");
const build_options = @import("build_options");
const root = @import("../root.zig");
const Memory = root.Memory;
const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");

/// Default hygiene interval in seconds (12 hours).
const HYGIENE_INTERVAL_SECS: i64 = 12 * 60 * 60;

/// KV key used to track last hygiene run time.
const LAST_HYGIENE_KEY = "last_hygiene_at";

/// Hygiene report — counts of actions taken during a hygiene pass.
pub const HygieneReport = struct {
    archived_memory_files: u64 = 0,
    purged_memory_archives: u64 = 0,
    pruned_conversation_rows: u64 = 0,

    pub fn totalActions(self: *const HygieneReport) u64 {
        return self.archived_memory_files + self.purged_memory_archives + self.pruned_conversation_rows;
    }
};

/// Hygiene config — mirrors fields from MemoryConfig.
pub const HygieneConfig = struct {
    hygiene_enabled: bool = true,
    archive_after_days: u32 = 7,
    purge_after_days: u32 = 30,
    conversation_retention_days: u32 = 30,
    workspace_dir: []const u8 = "",
};

/// Run memory hygiene if the cadence window has elapsed.
/// This is intentionally best-effort: failures are returned but non-fatal.
pub fn runIfDue(allocator: std.mem.Allocator, config: HygieneConfig, mem: ?Memory) HygieneReport {
    if (!config.hygiene_enabled) return .{};

    if (!shouldRunNow(allocator, config, mem)) return .{};

    var report = HygieneReport{};

    // Archive old daily memory files
    if (config.archive_after_days > 0) {
        report.archived_memory_files = archiveOldFiles(allocator, config) catch 0;
    }

    // Purge expired archives
    if (config.purge_after_days > 0) {
        report.purged_memory_archives = purgeOldArchives(allocator, config) catch 0;
    }

    // Prune old conversation rows
    if (config.conversation_retention_days > 0) {
        if (mem) |m| {
            report.pruned_conversation_rows = pruneConversationRows(allocator, m, config.conversation_retention_days) catch 0;
        }
    }

    // Mark hygiene as completed
    if (mem) |m| {
        const now = std.time.timestamp();
        var buf: [20]u8 = undefined;
        const ts = std.fmt.bufPrint(&buf, "{d}", .{now}) catch return report;
        m.store(LAST_HYGIENE_KEY, ts, .core, null) catch {};
    }

    return report;
}

/// Check if enough time has elapsed since the last hygiene run.
fn shouldRunNow(allocator: std.mem.Allocator, config: HygieneConfig, mem: ?Memory) bool {
    _ = config;

    const m = mem orelse return true;

    // Check if we have a last_hygiene_at record
    const entry = m.get(allocator, LAST_HYGIENE_KEY) catch return true;
    if (entry) |e| {
        defer e.deinit(allocator);
        // Parse raw timestamps (sqlite-like) and markdown-encoded entries
        // (markdown backend stores as "**key**: value").
        const last_ts = parseLastHygieneTimestamp(e.content) orelse return true;
        const now = std.time.timestamp();
        return (now - last_ts) >= HYGIENE_INTERVAL_SECS;
    }

    return true; // Never run before
}

fn parseLastHygieneTimestamp(content: []const u8) ?i64 {
    const trimmed = std.mem.trim(u8, content, " \t\r\n");
    return std.fmt.parseInt(i64, trimmed, 10) catch {
        const marker = "**" ++ LAST_HYGIENE_KEY ++ "**:";
        if (!std.mem.startsWith(u8, trimmed, marker)) return null;
        const value = std.mem.trim(u8, trimmed[marker.len..], " \t");
        return std.fmt.parseInt(i64, value, 10) catch null;
    };
}

/// Archive old daily memory .md files from memory/ to memory/archive/.
fn archiveOldFiles(allocator: std.mem.Allocator, config: HygieneConfig) !u64 {
    const memory_dir_path = try std.fs.path.join(allocator, &.{ config.workspace_dir, "memory" });
    defer allocator.free(memory_dir_path);

    var memory_dir = std.fs.cwd().openDir(memory_dir_path, .{ .iterate = true }) catch return 0;
    defer memory_dir.close();

    const archive_path = try std.fs.path.join(allocator, &.{ config.workspace_dir, "memory", "archive" });
    defer allocator.free(archive_path);

    std.fs.cwd().makePath(archive_path) catch {};

    const cutoff_secs = std.time.timestamp() - @as(i64, @intCast(config.archive_after_days)) * 24 * 60 * 60;
    var moved: u64 = 0;

    var iter = memory_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;

        // Only process .md files
        if (!std.mem.endsWith(u8, name, ".md")) continue;

        // Check file modification time
        const stat = memory_dir.statFile(name) catch continue;
        const mtime_secs: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        if (mtime_secs >= cutoff_secs) continue;

        // Build full source and destination paths, then rename
        const src_path = std.fs.path.join(allocator, &.{ memory_dir_path, name }) catch continue;
        defer allocator.free(src_path);
        const dst_path = std.fs.path.join(allocator, &.{ archive_path, name }) catch continue;
        defer allocator.free(dst_path);

        std.fs.cwd().rename(src_path, dst_path) catch {
            // Fallback: try copy + delete
            var dest_dir = std.fs.cwd().openDir(archive_path, .{}) catch continue;
            defer dest_dir.close();
            memory_dir.copyFile(name, dest_dir, name, .{}) catch continue;
            memory_dir.deleteFile(name) catch {};
        };
        moved += 1;
    }

    return moved;
}

/// Purge archived files older than the retention period.
fn purgeOldArchives(allocator: std.mem.Allocator, config: HygieneConfig) !u64 {
    const archive_path = try std.fs.path.join(allocator, &.{ config.workspace_dir, "memory", "archive" });
    defer allocator.free(archive_path);

    var archive_dir = std.fs.cwd().openDir(archive_path, .{ .iterate = true }) catch return 0;
    defer archive_dir.close();

    const cutoff_secs = std.time.timestamp() - @as(i64, @intCast(config.purge_after_days)) * 24 * 60 * 60;
    var removed: u64 = 0;

    var iter = archive_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;

        const stat = archive_dir.statFile(entry.name) catch continue;
        const mtime_secs: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        if (mtime_secs >= cutoff_secs) continue;

        archive_dir.deleteFile(entry.name) catch continue;
        removed += 1;
    }

    return removed;
}

/// Prune conversation rows older than retention_days via the Memory interface.
/// Searches for conversation-tagged entries and deletes those whose timestamp is old.
pub fn pruneConversationRows(allocator: std.mem.Allocator, mem: Memory, retention_days: u32) !u64 {
    const cutoff_secs = std.time.timestamp() - @as(i64, @intCast(retention_days)) * 24 * 60 * 60;

    // Search for conversation-tagged entries
    const results = mem.search(allocator, "conversation", 1000) catch return 0;
    defer {
        for (results) |r| r.deinit(allocator);
        allocator.free(results);
    }
    if (results.len == 0) return 0;

    var pruned: u64 = 0;
    for (results) |entry| {
        // Parse timestamp from entry key (format: "conv_<timestamp>_<id>")
        const ts = parseConversationTimestamp(entry.key) orelse continue;
        if (ts < cutoff_secs) {
            _ = mem.forget(entry.key) catch continue;
            pruned += 1;
        }
    }

    return pruned;
}

/// Parse a unix timestamp from a conversation key like "conv_1234567890_abc".
fn parseConversationTimestamp(key: []const u8) ?i64 {
    if (!std.mem.startsWith(u8, key, "conv_")) return null;
    const after_prefix = key[5..];
    const underscore_pos = std.mem.indexOfScalar(u8, after_prefix, '_') orelse after_prefix.len;
    return std.fmt.parseInt(i64, after_prefix[0..underscore_pos], 10) catch null;
}

// ── Tests ─────────────────────────────────────────────────────────

test "HygieneReport totalActions" {
    const report = HygieneReport{
        .archived_memory_files = 3,
        .purged_memory_archives = 2,
        .pruned_conversation_rows = 5,
    };
    try std.testing.expectEqual(@as(u64, 10), report.totalActions());
}

test "HygieneReport zero actions" {
    const report = HygieneReport{};
    try std.testing.expectEqual(@as(u64, 0), report.totalActions());
}

test "runIfDue disabled returns empty" {
    const cfg = HygieneConfig{
        .hygiene_enabled = false,
    };
    const report = runIfDue(std.testing.allocator, cfg, null);
    try std.testing.expectEqual(@as(u64, 0), report.totalActions());
}

test "runIfDue no memory first run" {
    const cfg = HygieneConfig{
        .hygiene_enabled = true,
        .archive_after_days = 0,
        .purge_after_days = 0,
        .conversation_retention_days = 0,
        .workspace_dir = "/nonexistent",
    };
    const report = runIfDue(std.testing.allocator, cfg, null);
    // Should run but all operations disabled or paths don't exist
    try std.testing.expectEqual(@as(u64, 0), report.totalActions());
}

test "shouldRunNow returns true with no memory" {
    const config = HygieneConfig{};
    try std.testing.expect(shouldRunNow(std.testing.allocator, config, null));
}

test "parseLastHygieneTimestamp supports markdown format" {
    const ts = parseLastHygieneTimestamp("**last_hygiene_at**: 1772051598") orelse return error.TestFailed;
    try std.testing.expectEqual(@as(i64, 1772051598), ts);
}

test "runIfDue with markdown backend does not append hygiene marker twice inside interval" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var markdown_memory = try root.MarkdownMemory.init(std.testing.allocator, base);
    defer markdown_memory.deinit();
    const mem = markdown_memory.memory();

    try mem.store(LAST_HYGIENE_KEY, "1772051598", .core, null);
    const before = try mem.count();

    const cfg = HygieneConfig{
        .hygiene_enabled = true,
        .archive_after_days = 0,
        .purge_after_days = 0,
        .conversation_retention_days = 0,
        .workspace_dir = base,
    };

    _ = runIfDue(std.testing.allocator, cfg, mem);
    const after_first = try mem.count();
    try std.testing.expectEqual(before + 1, after_first);

    _ = runIfDue(std.testing.allocator, cfg, mem);
    const after_second = try mem.count();
    try std.testing.expectEqual(after_first, after_second);
}

test "parseConversationTimestamp valid key" {
    const ts = parseConversationTimestamp("conv_1700000000_abc123");
    try std.testing.expectEqual(@as(i64, 1700000000), ts.?);
}

test "parseConversationTimestamp invalid prefix" {
    try std.testing.expect(parseConversationTimestamp("msg_1700000000_abc") == null);
}

test "parseConversationTimestamp no timestamp" {
    try std.testing.expect(parseConversationTimestamp("conv_notanumber_abc") == null);
}

// ── R3 Tests ──────────────────────────────────────────────────────

test "R3: pruneConversationRows with empty NoneMemory returns 0" {
    var none_mem = root.NoneMemory.init();
    defer none_mem.deinit();
    const mem = none_mem.memory();

    const pruned = try pruneConversationRows(std.testing.allocator, mem, 30);
    try std.testing.expectEqual(@as(u64, 0), pruned);
}

test "R3: pruneConversationRows with sqlite empty store returns 0" {
    if (!build_options.enable_sqlite) return;

    var mem_impl = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    const pruned = try pruneConversationRows(std.testing.allocator, mem, 30);
    try std.testing.expectEqual(@as(u64, 0), pruned);
}

test "R3: parseConversationTimestamp key with only prefix" {
    try std.testing.expect(parseConversationTimestamp("conv_") == null);
}

test "R3: parseConversationTimestamp key without trailing id" {
    const ts = parseConversationTimestamp("conv_1700000000");
    try std.testing.expectEqual(@as(i64, 1700000000), ts.?);
}
