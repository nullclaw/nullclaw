//! QMD retrieval adapter — spawns `qmd` CLI for search, parses JSON results.
//!
//! Follows the pattern in lucid.zig (runLucidCommand) and uses
//! process_util.run() for child process spawning.

const std = @import("std");
const Allocator = std.mem.Allocator;
const retrieval = @import("engine.zig");
const RetrievalCandidate = retrieval.RetrievalCandidate;
const RetrievalSourceAdapter = retrieval.RetrievalSourceAdapter;
const SourceCapabilities = retrieval.SourceCapabilities;
const config_types = @import("../../config_types.zig");
const process_util = @import("../../tools/process_util.zig");
const root = @import("../root.zig");
const log = std.log.scoped(.qmd);

pub const QmdAdapter = struct {
    allocator: Allocator,
    config: config_types.MemoryQmdConfig,
    workspace_dir: []const u8,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, config: config_types.MemoryQmdConfig, workspace_dir: []const u8) QmdAdapter {
        return .{
            .allocator = allocator,
            .config = config,
            .workspace_dir = workspace_dir,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    pub fn adapter(self: *QmdAdapter) RetrievalSourceAdapter {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &qmd_vtable,
        };
    }

    // ── vtable implementations ──────────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "qmd";
    }

    fn implCapabilities(_: *anyopaque) SourceCapabilities {
        return .{
            .has_keyword_rank = true,
            .has_vector_search = false,
            .is_readonly = true,
        };
    }

    fn implKeywordCandidates(ptr: *anyopaque, alloc: Allocator, query: []const u8, limit: u32, _: ?[]const u8) anyerror![]RetrievalCandidate {
        const self = castSelf(ptr);

        const limit_str = std.fmt.allocPrint(alloc, "{d}", .{limit}) catch return alloc.alloc(RetrievalCandidate, 0);
        defer alloc.free(limit_str);

        const argv = &[_][]const u8{ self.config.command, self.config.search_mode, query, "--json", "-n", limit_str };

        var env_map = std.process.EnvMap.init(alloc);
        defer env_map.deinit();
        env_map.put("NO_COLOR", "1") catch {};

        const result = process_util.run(alloc, argv, .{
            .cwd = self.workspace_dir,
            .env_map = &env_map,
        }) catch |err| {
            log.warn("qmd process spawn failed: {}", .{err});
            return alloc.alloc(RetrievalCandidate, 0);
        };
        defer result.deinit(alloc);

        if (!result.success) {
            log.warn("qmd exited non-zero (code={?})", .{result.exit_code});
            return alloc.alloc(RetrievalCandidate, 0);
        }

        return parseQmdJson(alloc, result.stdout, self.config.limits) catch |err| {
            log.warn("qmd JSON parse failed: {}", .{err});
            return alloc.alloc(RetrievalCandidate, 0);
        };
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self = castSelf(ptr);
        const result = process_util.run(self.allocator, &.{ self.config.command, "--version" }, .{}) catch return false;
        defer result.deinit(self.allocator);
        return result.success;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self = castSelf(ptr);
        self.deinit();
    }

    fn castSelf(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }

    const qmd_vtable = RetrievalSourceAdapter.VTable{
        .name = &implName,
        .capabilities = &implCapabilities,
        .keywordCandidates = &implKeywordCandidates,
        .healthCheck = &implHealthCheck,
        .deinit = &implDeinit,
    };

    // ── JSON parsing ────────────────────────────────────────────────

    const QmdResult = struct {
        path: []const u8 = "",
        title: []const u8 = "",
        content: []const u8 = "",
        text: []const u8 = "",
        start_line: u32 = 0,
        end_line: u32 = 0,
    };

    pub fn parseQmdJson(
        allocator: Allocator,
        json_bytes: []const u8,
        limits: config_types.QmdLimitsConfig,
    ) ![]RetrievalCandidate {
        if (json_bytes.len == 0) return allocator.alloc(RetrievalCandidate, 0);

        const parsed = std.json.parseFromSlice([]const QmdResult, allocator, json_bytes, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            return allocator.alloc(RetrievalCandidate, 0);
        };
        defer parsed.deinit();

        var candidates = std.ArrayListUnmanaged(RetrievalCandidate){};
        errdefer {
            for (candidates.items) |*c| c.deinit(allocator);
            candidates.deinit(allocator);
        }

        var total_chars: usize = 0;

        for (parsed.value, 0..) |item, i| {
            // Choose key and content from available fields
            const raw_key = if (item.path.len > 0) item.path else item.title;
            const raw_content = if (item.content.len > 0) item.content else item.text;

            if (raw_key.len == 0 and raw_content.len == 0) continue;

            // Enforce max_injected_chars total
            if (total_chars >= limits.max_injected_chars) break;

            // Truncate snippet to max_snippet_chars
            const snippet_len = @min(raw_content.len, limits.max_snippet_chars);
            const remaining = limits.max_injected_chars -| total_chars;
            const actual_snippet_len = @min(snippet_len, remaining);

            const id = try std.fmt.allocPrint(allocator, "qmd:{d}", .{i});
            errdefer allocator.free(id);
            const key = try allocator.dupe(u8, raw_key);
            errdefer allocator.free(key);
            const content = try allocator.dupe(u8, raw_content);
            errdefer allocator.free(content);
            const snippet = try allocator.dupe(u8, raw_content[0..actual_snippet_len]);
            errdefer allocator.free(snippet);
            const source = try allocator.dupe(u8, "qmd");
            errdefer allocator.free(source);
            const source_path = try allocator.dupe(u8, item.path);
            errdefer allocator.free(source_path);

            try candidates.append(allocator, .{
                .id = id,
                .key = key,
                .content = content,
                .snippet = snippet,
                .category = .core,
                .keyword_rank = @as(u32, @intCast(i + 1)),
                .vector_score = null,
                .final_score = 0.0,
                .source = source,
                .source_path = source_path,
                .start_line = item.start_line,
                .end_line = item.end_line,
            });

            total_chars += actual_snippet_len;
        }

        return candidates.toOwnedSlice(allocator);
    }

    /// Session IDs are used as filenames for exported markdown.
    /// Reject path traversal and unsafe path bytes.
    fn isSafeSessionIdForFileName(session_id: []const u8) bool {
        if (session_id.len == 0) return false;
        if (std.mem.indexOf(u8, session_id, "..") != null) return false;
        for (session_id) |ch| {
            if (ch == '/' or ch == '\\' or ch == ':' or ch < 0x20) return false;
        }
        return true;
    }

    // ── Session export ────────────────────────────────────────────

    /// Export session conversations as markdown files for QMD indexing.
    /// Returns count of files written (skips unchanged via content hash).
    pub fn exportSessions(
        self: *QmdAdapter,
        allocator: Allocator,
        session_store: ?root.SessionStore,
        session_ids: []const []const u8,
    ) !u32 {
        if (!self.config.sessions.enabled) return 0;
        if (session_ids.len == 0) return 0;
        const store = session_store orelse return 0;

        const export_dir = if (self.config.sessions.export_dir.len > 0)
            self.config.sessions.export_dir
        else
            return 0;

        // Ensure export directory exists
        std.fs.cwd().makePath(export_dir) catch |err| {
            log.warn("failed to create session export dir '{s}': {}", .{ export_dir, err });
            return 0;
        };

        var written: u32 = 0;

        for (session_ids) |sid| {
            if (!isSafeSessionIdForFileName(sid)) {
                log.warn("skipping unsafe session id in qmd export: '{s}'", .{sid});
                continue;
            }

            const messages = store.loadMessages(allocator, sid) catch continue;
            defer root.freeMessages(allocator, messages);
            if (messages.len == 0) continue;

            // Build markdown content
            var content: std.ArrayList(u8) = .empty;
            defer content.deinit(allocator);

            content.appendSlice(allocator, "## Session: ") catch continue;
            content.appendSlice(allocator, sid) catch continue;
            content.appendSlice(allocator, "\n\n") catch continue;

            for (messages) |msg| {
                const label: []const u8 = if (std.mem.eql(u8, msg.role, "user"))
                    "**User**"
                else if (std.mem.eql(u8, msg.role, "assistant"))
                    "**Assistant**"
                else
                    msg.role;
                content.appendSlice(allocator, label) catch continue;
                content.appendSlice(allocator, ": ") catch continue;
                content.appendSlice(allocator, msg.content) catch continue;
                content.appendSlice(allocator, "\n\n") catch continue;
            }

            // Compute hash of new content
            const new_hash = std.hash.Fnv1a_32.hash(content.items);

            // Build file path
            const file_name = std.fmt.allocPrint(allocator, "{s}.md", .{sid}) catch continue;
            defer allocator.free(file_name);
            const file_path = std.fs.path.join(allocator, &.{ export_dir, file_name }) catch continue;
            defer allocator.free(file_path);

            // Check if existing file has same content hash (skip redundant writes)
            const skip = blk: {
                const existing = std.fs.cwd().readFileAlloc(allocator, file_path, 1024 * 1024) catch break :blk false;
                defer allocator.free(existing);
                break :blk std.hash.Fnv1a_32.hash(existing) == new_hash;
            };
            if (skip) continue;

            // Write file
            const file = std.fs.cwd().createFile(file_path, .{}) catch |err| {
                log.warn("failed to write session export '{s}': {}", .{ file_path, err });
                continue;
            };
            defer file.close();
            file.writeAll(content.items) catch continue;

            written += 1;
        }

        return written;
    }

    /// Delete exported session files older than retention_days.
    /// Returns count of files deleted.
    pub fn pruneExportedSessions(
        self: *QmdAdapter,
        _: Allocator,
    ) !u32 {
        if (!self.config.sessions.enabled) return 0;
        const export_dir = if (self.config.sessions.export_dir.len > 0)
            self.config.sessions.export_dir
        else
            return 0;

        const retention_ns: i128 = @as(i128, self.config.sessions.retention_days) * 24 * 3600 * std.time.ns_per_s;
        const now_ns: i128 = std.time.nanoTimestamp();

        var dir = std.fs.cwd().openDir(export_dir, .{ .iterate = true }) catch return 0;
        defer dir.close();

        var deleted: u32 = 0;
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".md")) continue;

            const stat = dir.statFile(entry.name) catch continue;
            const mtime_ns: i128 = stat.mtime;
            const age_ns = now_ns - mtime_ns;

            if (age_ns > retention_ns) {
                dir.deleteFile(entry.name) catch continue;
                deleted += 1;
            }
        }

        return deleted;
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "QmdAdapter.init stores config" {
    const allocator = std.testing.allocator;
    const cfg = config_types.MemoryQmdConfig{};
    var qa = QmdAdapter.init(allocator, cfg, "/tmp/ws");
    _ = &qa;
    try std.testing.expectEqualStrings("qmd", qa.config.command);
    try std.testing.expectEqualStrings("/tmp/ws", qa.workspace_dir);
}

test "name() returns qmd" {
    const allocator = std.testing.allocator;
    var qa = QmdAdapter.init(allocator, .{}, "/tmp");
    const a = qa.adapter();
    try std.testing.expectEqualStrings("qmd", a.getName());
}

test "capabilities() correct" {
    const allocator = std.testing.allocator;
    var qa = QmdAdapter.init(allocator, .{}, "/tmp");
    const a = qa.adapter();
    const caps = a.getCapabilities();
    try std.testing.expect(caps.has_keyword_rank);
    try std.testing.expect(!caps.has_vector_search);
    try std.testing.expect(caps.is_readonly);
}

test "parseQmdJson parses valid JSON array" {
    const allocator = std.testing.allocator;
    const json =
        \\[{"path":"docs/a.md","content":"Alpha content","start_line":1,"end_line":5},
        \\ {"path":"docs/b.md","content":"Beta content","start_line":10,"end_line":20}]
    ;
    const results = try QmdAdapter.parseQmdJson(allocator, json, .{});
    defer retrieval.freeCandidates(allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("docs/a.md", results[0].key);
    try std.testing.expectEqualStrings("Alpha content", results[0].content);
    try std.testing.expectEqualStrings("qmd", results[0].source);
    try std.testing.expectEqualStrings("docs/a.md", results[0].source_path);
    try std.testing.expectEqual(@as(u32, 1), results[0].start_line);
    try std.testing.expectEqual(@as(u32, 5), results[0].end_line);
    try std.testing.expectEqual(@as(u32, 1), results[0].keyword_rank.?);
    try std.testing.expectEqual(@as(u32, 2), results[1].keyword_rank.?);
}

test "parseQmdJson handles empty array" {
    const allocator = std.testing.allocator;
    const results = try QmdAdapter.parseQmdJson(allocator, "[]", .{});
    defer allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "parseQmdJson handles malformed JSON" {
    const allocator = std.testing.allocator;
    const results = try QmdAdapter.parseQmdJson(allocator, "not json at all", .{});
    defer allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "parseQmdJson handles empty input" {
    const allocator = std.testing.allocator;
    const results = try QmdAdapter.parseQmdJson(allocator, "", .{});
    defer allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "max_snippet_chars truncation" {
    const allocator = std.testing.allocator;
    const long_content = "A" ** 1000;
    const json = try std.fmt.allocPrint(allocator,
        \\[{{"path":"doc.md","content":"{s}"}}]
    , .{long_content});
    defer allocator.free(json);

    const results = try QmdAdapter.parseQmdJson(allocator, json, .{
        .max_snippet_chars = 50,
        .max_injected_chars = 4000,
    });
    defer retrieval.freeCandidates(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].snippet.len <= 50);
    // content should be full
    try std.testing.expectEqual(@as(usize, 1000), results[0].content.len);
}

test "max_injected_chars total limit" {
    const allocator = std.testing.allocator;
    const content_200 = "B" ** 200;
    const json = try std.fmt.allocPrint(allocator,
        \\[{{"path":"a.md","content":"{s}"}},
        \\ {{"path":"b.md","content":"{s}"}},
        \\ {{"path":"c.md","content":"{s}"}}]
    , .{ content_200, content_200, content_200 });
    defer allocator.free(json);

    const results = try QmdAdapter.parseQmdJson(allocator, json, .{
        .max_snippet_chars = 700,
        .max_injected_chars = 350, // only 1.75 results worth
    });
    defer retrieval.freeCandidates(allocator, results);

    // Should have at most 2 results (200 + 150 = 350)
    try std.testing.expect(results.len <= 2);
}

test "keywordCandidates with non-existent binary returns empty" {
    const allocator = std.testing.allocator;
    var qa = QmdAdapter.init(allocator, .{
        .command = "nonexistent_qmd_binary_xyz",
    }, "/tmp");
    const a = qa.adapter();
    const results = try a.keywordCandidates(allocator, "query", 5, null);
    defer retrieval.freeCandidates(allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "healthCheck with non-existent binary returns false" {
    const allocator = std.testing.allocator;
    var qa = QmdAdapter.init(allocator, .{
        .command = "nonexistent_qmd_binary_xyz",
    }, "/tmp");
    const a = qa.adapter();
    try std.testing.expect(!a.healthCheck());
}

test "keyword_rank is 1-based" {
    const allocator = std.testing.allocator;
    const json =
        \\[{"path":"a.md","content":"A"},{"path":"b.md","content":"B"},{"path":"c.md","content":"C"}]
    ;
    const results = try QmdAdapter.parseQmdJson(allocator, json, .{});
    defer retrieval.freeCandidates(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(@as(u32, 1), results[0].keyword_rank.?);
    try std.testing.expectEqual(@as(u32, 2), results[1].keyword_rank.?);
    try std.testing.expectEqual(@as(u32, 3), results[2].keyword_rank.?);
}

test "parseQmdJson uses title when path is empty" {
    const allocator = std.testing.allocator;
    const json =
        \\[{"title":"My Title","text":"Some text"}]
    ;
    const results = try QmdAdapter.parseQmdJson(allocator, json, .{});
    defer retrieval.freeCandidates(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("My Title", results[0].key);
    try std.testing.expectEqualStrings("Some text", results[0].content);
}

test "parseQmdJson skips entries with no key and no content" {
    const allocator = std.testing.allocator;
    const json =
        \\[{"path":"","content":""},{"path":"valid.md","content":"data"}]
    ;
    const results = try QmdAdapter.parseQmdJson(allocator, json, .{});
    defer retrieval.freeCandidates(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("valid.md", results[0].key);
}

// ── Session export tests ───────────────────────────────────────────

const MockSessionStore = struct {
    call_count: usize = 0,

    fn implSaveMessage(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) anyerror!void {}
    fn implLoadMessages(ptr: *anyopaque, allocator: std.mem.Allocator, _: []const u8) anyerror![]root.MessageEntry {
        const self: *MockSessionStore = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        var msgs = try allocator.alloc(root.MessageEntry, 2);
        msgs[0] = .{ .role = try allocator.dupe(u8, "user"), .content = try allocator.dupe(u8, "Hello") };
        msgs[1] = .{ .role = try allocator.dupe(u8, "assistant"), .content = try allocator.dupe(u8, "Hi there") };
        return msgs;
    }
    fn implClearMessages(_: *anyopaque, _: []const u8) anyerror!void {}
    fn implClearAutoSaved(_: *anyopaque, _: ?[]const u8) anyerror!void {}

    const vtable = root.SessionStore.VTable{
        .saveMessage = &implSaveMessage,
        .loadMessages = &implLoadMessages,
        .clearMessages = &implClearMessages,
        .clearAutoSaved = &implClearAutoSaved,
    };

    fn store(self: *MockSessionStore) root.SessionStore {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

test "exportSessions with mock session store writes files" {
    const allocator = std.testing.allocator;

    // Create temp dir
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var mock = MockSessionStore{};
    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = true, .export_dir = tmp_path },
    }, "/tmp");

    const ids = [_][]const u8{"session-1"};
    const written = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 1), written);
    try std.testing.expect(mock.call_count >= 1);

    // Verify file was created
    const content = try tmp.dir.readFileAlloc(allocator, "session-1.md", 4096);
    defer allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "Session: session-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "**User**: Hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "**Assistant**: Hi there") != null);
}

test "exportSessions skips unchanged files (hash check)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var mock = MockSessionStore{};
    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = true, .export_dir = tmp_path },
    }, "/tmp");

    const ids = [_][]const u8{"session-2"};

    // First write
    const written1 = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 1), written1);

    // Second write with same content — should skip
    const written2 = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 0), written2);
}

test "exportSessions with empty session list returns 0" {
    const allocator = std.testing.allocator;
    var mock = MockSessionStore{};
    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = true, .export_dir = "/tmp" },
    }, "/tmp");

    const ids = [_][]const u8{};
    const written = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 0), written);
}

test "exportSessions with disabled config returns 0" {
    const allocator = std.testing.allocator;
    var mock = MockSessionStore{};
    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = false },
    }, "/tmp");

    const ids = [_][]const u8{"session-x"};
    const written = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 0), written);
}

test "exportSessions skips unsafe session ids" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var mock = MockSessionStore{};
    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = true, .export_dir = tmp_path },
    }, "/tmp");

    const ids = [_][]const u8{"../escape"};
    const written = try qa.exportSessions(allocator, mock.store(), &ids);
    try std.testing.expectEqual(@as(u32, 0), written);
}

test "pruneExportedSessions deletes old files" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create a test file
    {
        const f = try tmp.dir.createFile("old-session.md", .{});
        try f.writeAll("old content");
        f.close();
    }

    var qa = QmdAdapter.init(allocator, .{
        .sessions = .{ .enabled = true, .export_dir = tmp_path, .retention_days = 0 }, // 0 days = delete immediately
    }, "/tmp");

    const deleted = try qa.pruneExportedSessions(allocator);
    try std.testing.expectEqual(@as(u32, 1), deleted);

    // Verify file was deleted
    const result = tmp.dir.statFile("old-session.md");
    try std.testing.expectError(error.FileNotFound, result);
}
