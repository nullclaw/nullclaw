//! Memory hygiene — periodic cleanup of old daily memories, archives, and conversation rows.
//!
//! Mirrors ZeroClaw's hygiene module:
//!   - run_if_due: checks last_hygiene_at in kv table, runs if older than interval
//!   - Archives old daily memory files
//!   - Purges expired archives
//!   - Prunes old conversation rows from SQLite

const std = @import("std");
const std_compat = @import("compat");
const build_options = @import("build_options");
const fs_compat = @import("../../fs_compat.zig");
const root = @import("../root.zig");
const Memory = root.Memory;
const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const chunker = @import("../vector/chunker.zig");
const log = std.log.scoped(.memory_hygiene);

/// Default hygiene interval in seconds (12 hours).
const HYGIENE_INTERVAL_SECS: i64 = 12 * 60 * 60;
const ARCHIVE_READ_MAX_BYTES: usize = 1024 * 1024;
const ARCHIVE_CHUNK_MAX_TOKENS: usize = 512;
const ARCHIVE_CATEGORY = root.MemoryCategory{ .custom = "archive" };

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
    preserve_before_purge: bool = true,
    workspace_dir: []const u8 = "",
};

/// Optional callback sink used to synchronize preserved chunks into vector storage.
pub const PreserveSyncHook = struct {
    ptr: *anyopaque,
    callback: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8, content: []const u8) void,
};

/// Run memory hygiene if the cadence window has elapsed.
/// This is intentionally best-effort: failures are returned but non-fatal.
pub fn runIfDue(allocator: std.mem.Allocator, config: HygieneConfig, mem: ?Memory, preserve_sync_hook: ?PreserveSyncHook) HygieneReport {
    if (!config.hygiene_enabled) return .{};

    if (!shouldRunNow(allocator, config, mem)) return .{};

    var report = HygieneReport{};

    // Archive old daily memory files
    if (config.archive_after_days > 0) {
        report.archived_memory_files = archiveOldFiles(allocator, config) catch 0;
    }

    // Purge expired archives
    if (config.purge_after_days > 0) {
        report.purged_memory_archives = purgeOldArchives(allocator, config, mem, preserve_sync_hook) catch 0;
    }

    // Prune old conversation rows
    if (config.conversation_retention_days > 0) {
        if (mem) |m| {
            report.pruned_conversation_rows = pruneConversationRowsWithPreserve(
                allocator,
                m,
                config.conversation_retention_days,
                config.preserve_before_purge,
                preserve_sync_hook,
            ) catch 0;
        }
    }

    // Mark hygiene as completed
    if (mem) |m| {
        const now = std_compat.time.timestamp();
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
        const now = std_compat.time.timestamp();
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
    const memory_dir_path = try std_compat.fs.path.join(allocator, &.{ config.workspace_dir, "memory" });
    defer allocator.free(memory_dir_path);

    var memory_dir = fs_compat.openDirPath(memory_dir_path, .{ .iterate = true }) catch return 0;
    defer memory_dir.close();

    const archive_path = try std_compat.fs.path.join(allocator, &.{ config.workspace_dir, "memory", "archive" });
    defer allocator.free(archive_path);

    fs_compat.makePath(archive_path) catch {};

    const cutoff_secs = std_compat.time.timestamp() - @as(i64, @intCast(config.archive_after_days)) * 24 * 60 * 60;
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
        const src_path = std_compat.fs.path.join(allocator, &.{ memory_dir_path, name }) catch continue;
        defer allocator.free(src_path);
        const dst_path = std_compat.fs.path.join(allocator, &.{ archive_path, name }) catch continue;
        defer allocator.free(dst_path);

        fs_compat.renamePath(src_path, dst_path) catch {
            // Fallback: try copy + delete
            var dest_dir = fs_compat.openDirPath(archive_path, .{}) catch continue;
            defer dest_dir.close();
            memory_dir.copyFile(name, dest_dir, name, .{}) catch continue;
            memory_dir.deleteFile(name) catch {};
        };
        moved += 1;
    }

    return moved;
}

/// Purge archived files older than the retention period.
fn purgeOldArchives(
    allocator: std.mem.Allocator,
    config: HygieneConfig,
    mem: ?Memory,
    preserve_sync_hook: ?PreserveSyncHook,
) !u64 {
    const archive_path = try std_compat.fs.path.join(allocator, &.{ config.workspace_dir, "memory", "archive" });
    defer allocator.free(archive_path);

    var archive_dir = fs_compat.openDirPath(archive_path, .{ .iterate = true }) catch return 0;
    defer archive_dir.close();

    const cutoff_secs = std_compat.time.timestamp() - @as(i64, @intCast(config.purge_after_days)) * 24 * 60 * 60;
    var removed: u64 = 0;

    var iter = archive_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;

        const stat = archive_dir.statFile(entry.name) catch continue;
        const mtime_secs: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        if (mtime_secs >= cutoff_secs) continue;

        if (config.preserve_before_purge and mem != null and std.mem.endsWith(u8, entry.name, ".md")) {
            preserveArchiveFile(allocator, archive_dir, entry.name, mem.?, preserve_sync_hook) catch |err| {
                log.warn("skipping purge for '{s}' because preservation failed: {}", .{ entry.name, err });
                continue;
            };
        }

        archive_dir.deleteFile(entry.name) catch continue;
        removed += 1;
    }

    return removed;
}

fn preserveArchiveFile(
    allocator: std.mem.Allocator,
    archive_dir: std_compat.fs.Dir,
    file_name: []const u8,
    mem: Memory,
    preserve_sync_hook: ?PreserveSyncHook,
) !void {
    const content = try fs_compat.readFileAlloc(archive_dir, allocator, file_name, ARCHIVE_READ_MAX_BYTES);
    defer allocator.free(content);
    if (std.mem.trim(u8, content, " \t\r\n").len == 0) return;

    const chunks = try chunker.chunkMarkdown(allocator, content, ARCHIVE_CHUNK_MAX_TOKENS);
    defer chunker.freeChunks(allocator, chunks);
    if (chunks.len == 0) return;

    for (chunks, 0..) |chunk, idx| {
        const key = try std.fmt.allocPrint(allocator, "archive:{s}:chunk:{d}", .{ file_name, idx });
        defer allocator.free(key);
        const wrapped = try std.fmt.allocPrint(
            allocator,
            "Archived source: {s}\nChunk: {d}/{d}\n\n{s}",
            .{ file_name, idx + 1, chunks.len, chunk.content },
        );
        defer allocator.free(wrapped);
        try mem.store(key, wrapped, ARCHIVE_CATEGORY, null);
        if (preserve_sync_hook) |hook| {
            hook.callback(hook.ptr, allocator, key, wrapped);
        }
    }
}

fn preserveConversationEntry(
    allocator: std.mem.Allocator,
    mem: Memory,
    key_prefix: []const u8,
    content: []const u8,
    preserve_sync_hook: ?PreserveSyncHook,
) !void {
    const chunks = try chunker.chunkMarkdown(allocator, content, ARCHIVE_CHUNK_MAX_TOKENS);
    defer chunker.freeChunks(allocator, chunks);
    if (chunks.len == 0) return;

    for (chunks, 0..) |chunk, idx| {
        const archive_key = try std.fmt.allocPrint(allocator, "{s}:chunk:{d}", .{ key_prefix, idx });
        defer allocator.free(archive_key);
        const wrapped = try std.fmt.allocPrint(
            allocator,
            "Archived conversation source: {s}\nChunk: {d}/{d}\n\n{s}",
            .{ key_prefix, idx + 1, chunks.len, chunk.content },
        );
        defer allocator.free(wrapped);
        try mem.store(archive_key, wrapped, ARCHIVE_CATEGORY, null);
        if (preserve_sync_hook) |hook| {
            hook.callback(hook.ptr, allocator, archive_key, wrapped);
        }
    }
}

/// Prune conversation rows older than retention_days via the Memory interface.
/// Lists conversation-tagged entries and deletes those whose timestamp is old.
pub fn pruneConversationRows(allocator: std.mem.Allocator, mem: Memory, retention_days: u32) !u64 {
    return pruneConversationRowsWithPreserve(allocator, mem, retention_days, false, null);
}

fn pruneConversationRowsWithPreserve(
    allocator: std.mem.Allocator,
    mem: Memory,
    retention_days: u32,
    preserve_before_forget: bool,
    preserve_sync_hook: ?PreserveSyncHook,
) !u64 {
    const cutoff_secs = std_compat.time.timestamp() - @as(i64, @intCast(retention_days)) * 24 * 60 * 60;

    // List conversation-tagged entries directly so prune is independent of
    // message text content.
    const results = mem.list(allocator, .conversation, null) catch return 0;
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
            if (preserve_before_forget) {
                const preserve_key_prefix = try std.fmt.allocPrint(allocator, "archive:conversation:{s}", .{entry.key});
                defer allocator.free(preserve_key_prefix);
                preserveConversationEntry(allocator, mem, preserve_key_prefix, entry.content, preserve_sync_hook) catch |err| {
                    log.warn("skipping prune for '{s}' because preservation failed: {}", .{ entry.key, err });
                    continue;
                };
            }
            _ = mem.forget(entry.key) catch continue;
            pruned += 1;
        }
    }

    return pruned;
}

/// Parse a unix timestamp from a conversation key like "conv_1234567890_abc".
fn parseConversationTimestamp(key: []const u8) ?i64 {
    if (std.mem.startsWith(u8, key, "conv_")) {
        const after_prefix = key[5..];
        const underscore_pos = std.mem.indexOfScalar(u8, after_prefix, '_') orelse after_prefix.len;
        const raw = std.fmt.parseInt(u128, after_prefix[0..underscore_pos], 10) catch return null;
        return normalizeTimestampToSeconds(raw);
    }
    if (std.mem.startsWith(u8, key, "autosave_user_")) {
        const raw = std.fmt.parseInt(u128, key["autosave_user_".len..], 10) catch return null;
        return normalizeTimestampToSeconds(raw);
    }
    if (std.mem.startsWith(u8, key, "autosave_assistant_")) {
        const raw = std.fmt.parseInt(u128, key["autosave_assistant_".len..], 10) catch return null;
        return normalizeTimestampToSeconds(raw);
    }
    return null;
}

fn normalizeTimestampToSeconds(raw: u128) ?i64 {
    // Handle legacy second-based keys and newer high-precision autosave keys.
    const ts_secs: u128 = if (raw >= 100_000_000_000_000)
        raw / std.time.ns_per_s
    else if (raw >= 100_000_000_000)
        raw / std.time.ms_per_s
    else
        raw;
    if (ts_secs > std.math.maxInt(i64)) return null;
    return @intCast(ts_secs);
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
    const report = runIfDue(std.testing.allocator, cfg, null, null);
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
    const report = runIfDue(std.testing.allocator, cfg, null, null);
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
    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
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

    _ = runIfDue(std.testing.allocator, cfg, mem, null);
    const after_first = try mem.count();
    try std.testing.expectEqual(before + 1, after_first);

    _ = runIfDue(std.testing.allocator, cfg, mem, null);
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

test "parseConversationTimestamp autosave user key in nanoseconds" {
    const key = "autosave_user_1700000000000000000";
    const ts = parseConversationTimestamp(key) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i64, 1700000000), ts);
}

test "parseConversationTimestamp autosave assistant key in nanoseconds" {
    const key = "autosave_assistant_1700000000123000000";
    const ts = parseConversationTimestamp(key) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i64, 1700000000), ts);
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

test "runIfDue preserves archived markdown chunks before purge" {
    if (!build_options.enable_sqlite) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace_dir);

    const archive_path = try std_compat.fs.path.join(std.testing.allocator, &.{ workspace_dir, "memory", "archive" });
    defer std.testing.allocator.free(archive_path);
    try fs_compat.makePath(archive_path);

    var archive_dir = try fs_compat.openDirPath(archive_path, .{});
    defer archive_dir.close();

    var file = try archive_dir.createFile("old-memory.md", .{});
    try file.writeAll("# Heading\nThis old memory should be preserved before purge.");
    try file.updateTimes(0, 0);
    file.close();

    var mem_impl = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    const report = runIfDue(std.testing.allocator, .{
        .hygiene_enabled = true,
        .archive_after_days = 0,
        .purge_after_days = 1,
        .conversation_retention_days = 0,
        .preserve_before_purge = true,
        .workspace_dir = workspace_dir,
    }, mem, null);

    try std.testing.expectEqual(@as(u64, 1), report.purged_memory_archives);
    try std.testing.expect((archive_dir.statFile("old-memory.md") catch null) == null);

    const preserved = try mem.list(std.testing.allocator, .{ .custom = "archive" }, null);
    defer root.freeEntries(std.testing.allocator, preserved);

    var found = false;
    for (preserved) |entry| {
        if (std.mem.startsWith(u8, entry.key, "archive:old-memory.md:chunk:")) {
            found = true;
            try std.testing.expect(std.mem.indexOf(u8, entry.content, "Archived source: old-memory.md") != null);
        }
    }
    try std.testing.expect(found);
}

test "runIfDue deletes old archives when memory is unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace_dir);

    const archive_path = try std_compat.fs.path.join(std.testing.allocator, &.{ workspace_dir, "memory", "archive" });
    defer std.testing.allocator.free(archive_path);
    try fs_compat.makePath(archive_path);

    var archive_dir = try fs_compat.openDirPath(archive_path, .{});
    defer archive_dir.close();

    var file = try archive_dir.createFile("old-memory.md", .{});
    try file.writeAll("Legacy archive content.");
    try file.updateTimes(0, 0);
    file.close();

    const report = runIfDue(std.testing.allocator, .{
        .hygiene_enabled = true,
        .archive_after_days = 0,
        .purge_after_days = 1,
        .conversation_retention_days = 0,
        .preserve_before_purge = true,
        .workspace_dir = workspace_dir,
    }, null, null);

    try std.testing.expectEqual(@as(u64, 1), report.purged_memory_archives);
    try std.testing.expect((archive_dir.statFile("old-memory.md") catch null) == null);
}

test "runIfDue preserves conversation rows before prune when enabled" {
    if (!build_options.enable_sqlite) return;

    var mem_impl = try sqlite_mod.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    try mem.store("autosave_user_1700000000000000000", "conversation message that should be archived", .conversation, null);

    const report = runIfDue(std.testing.allocator, .{
        .hygiene_enabled = true,
        .archive_after_days = 0,
        .purge_after_days = 0,
        .conversation_retention_days = 1,
        .preserve_before_purge = true,
        .workspace_dir = "/tmp",
    }, mem, null);

    try std.testing.expectEqual(@as(u64, 1), report.pruned_conversation_rows);
    const maybe_old = try mem.get(std.testing.allocator, "autosave_user_1700000000000000000");
    if (maybe_old) |entry| {
        defer entry.deinit(std.testing.allocator);
    }
    try std.testing.expect(maybe_old == null);

    const preserved = try mem.list(std.testing.allocator, .{ .custom = "archive" }, null);
    defer root.freeEntries(std.testing.allocator, preserved);

    var found = false;
    for (preserved) |entry| {
        if (std.mem.startsWith(u8, entry.key, "archive:conversation:autosave_user_1700000000000000000:chunk:")) {
            found = true;
            try std.testing.expect(std.mem.indexOf(u8, entry.content, "Archived conversation source: archive:conversation:autosave_user_1700000000000000000") != null);
        }
    }
    try std.testing.expect(found);
}
