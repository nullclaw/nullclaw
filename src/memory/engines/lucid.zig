//! Lucid memory backend — bridges local SQLite to the external `lucid` CLI
//! for cross-project semantic memory sync.
//!
//! Architecture:
//!   - Local SqliteMemory is authoritative for all CRUD operations
//!   - `lucid store` syncs writes to the external lucid-memory service
//!   - `lucid context` augments recall with cross-project results
//!   - On CLI failure, enters a cooldown period and falls back to local-only
//!
//! Mirrors ZeroClaw's `LucidMemory` (src/memory/lucid.rs).

const std = @import("std");
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;

pub const LucidMemory = struct {
    local: root.SqliteMemory,
    allocator: std.mem.Allocator,
    owns_self: bool = false,
    lucid_cmd: []const u8,
    workspace_dir: []const u8,
    token_budget: usize,
    local_hit_threshold: usize,
    recall_timeout_ms: u64,
    store_timeout_ms: u64,
    failure_cooldown_ms: u64,
    /// Timestamp (ms since epoch) after which we retry lucid.
    /// 0 means no cooldown active.
    cooldown_until_ms: i64,

    const Self = @This();

    const DEFAULT_LUCID_CMD = "lucid";
    const DEFAULT_TOKEN_BUDGET: usize = 200;
    const DEFAULT_RECALL_TIMEOUT_MS: u64 = 500;
    const DEFAULT_STORE_TIMEOUT_MS: u64 = 800;
    const DEFAULT_LOCAL_HIT_THRESHOLD: usize = 3;
    const DEFAULT_FAILURE_COOLDOWN_MS: u64 = 15_000;

    pub fn init(allocator: std.mem.Allocator, db_path: [*:0]const u8, workspace_dir: []const u8) !Self {
        return Self{
            .local = try root.SqliteMemory.init(allocator, db_path),
            .allocator = allocator,
            .lucid_cmd = DEFAULT_LUCID_CMD,
            .workspace_dir = workspace_dir,
            .token_budget = DEFAULT_TOKEN_BUDGET,
            .local_hit_threshold = DEFAULT_LOCAL_HIT_THRESHOLD,
            .recall_timeout_ms = DEFAULT_RECALL_TIMEOUT_MS,
            .store_timeout_ms = DEFAULT_STORE_TIMEOUT_MS,
            .failure_cooldown_ms = DEFAULT_FAILURE_COOLDOWN_MS,
            .cooldown_until_ms = 0,
        };
    }

    /// Test-only constructor with all knobs exposed.
    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        db_path: [*:0]const u8,
        lucid_cmd: []const u8,
        workspace_dir: []const u8,
        token_budget: usize,
        local_hit_threshold: usize,
        failure_cooldown_ms: u64,
    ) !Self {
        return Self{
            .local = try root.SqliteMemory.init(allocator, db_path),
            .allocator = allocator,
            .lucid_cmd = lucid_cmd,
            .workspace_dir = workspace_dir,
            .token_budget = token_budget,
            .local_hit_threshold = @max(local_hit_threshold, 1),
            .recall_timeout_ms = DEFAULT_RECALL_TIMEOUT_MS,
            .store_timeout_ms = DEFAULT_STORE_TIMEOUT_MS,
            .failure_cooldown_ms = failure_cooldown_ms,
            .cooldown_until_ms = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.local.deinit();
    }

    // ── Cooldown ─────────────────────────────────────────────────

    fn nowMs() i64 {
        return std.time.milliTimestamp();
    }

    fn inFailureCooldown(self: *const Self) bool {
        if (self.cooldown_until_ms == 0) return false;
        return nowMs() < self.cooldown_until_ms;
    }

    fn markFailure(self: *Self) void {
        self.cooldown_until_ms = nowMs() + @as(i64, @intCast(self.failure_cooldown_ms));
    }

    fn clearFailure(self: *Self) void {
        self.cooldown_until_ms = 0;
    }

    // ── Category mapping ─────────────────────────────────────────

    fn toLucidType(category: MemoryCategory) []const u8 {
        return switch (category) {
            .core => "decision",
            .daily => "context",
            .conversation => "conversation",
            .custom => "learning",
        };
    }

    fn toMemoryCategory(label: []const u8) MemoryCategory {
        // Check for "visual" substring
        for (0..label.len) |i| {
            if (i + 6 <= label.len and std.mem.eql(u8, label[i..][0..6], "visual")) {
                return .{ .custom = "visual" };
            }
        }

        if (std.mem.eql(u8, label, "decision") or
            std.mem.eql(u8, label, "learning") or
            std.mem.eql(u8, label, "solution"))
        {
            return .core;
        }
        if (std.mem.eql(u8, label, "context") or
            std.mem.eql(u8, label, "conversation"))
        {
            return .conversation;
        }
        if (std.mem.eql(u8, label, "bug")) {
            return .daily;
        }
        return .{ .custom = label };
    }

    // ── Lucid CLI interaction ────────────────────────────────────

    fn runLucidCommand(self: *Self, args: []const []const u8) ?[]u8 {
        const argv_buf = self.allocator.alloc([]const u8, args.len + 1) catch return null;
        defer self.allocator.free(argv_buf);
        argv_buf[0] = self.lucid_cmd;
        for (args, 0..) |arg, i| {
            argv_buf[i + 1] = arg;
        }

        var child = std.process.Child.init(argv_buf, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        child.spawn() catch return null;

        const stdout_raw = child.stdout.?.readToEndAlloc(self.allocator, 1024 * 1024) catch {
            _ = child.wait() catch {};
            return null;
        };

        const term = child.wait() catch {
            self.allocator.free(stdout_raw);
            return null;
        };

        switch (term) {
            .Exited => |code| if (code != 0) {
                self.allocator.free(stdout_raw);
                return null;
            },
            else => {
                self.allocator.free(stdout_raw);
                return null;
            },
        }

        return stdout_raw;
    }

    fn syncToLucid(self: *Self, key: []const u8, content: []const u8, category: MemoryCategory) void {
        if (self.inFailureCooldown()) return;

        const payload = std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ key, content }) catch return;
        defer self.allocator.free(payload);

        const type_flag = std.fmt.allocPrint(self.allocator, "--type={s}", .{toLucidType(category)}) catch return;
        defer self.allocator.free(type_flag);

        const project_flag = std.fmt.allocPrint(self.allocator, "--project={s}", .{self.workspace_dir}) catch return;
        defer self.allocator.free(project_flag);

        const args = [_][]const u8{ "store", payload, type_flag, project_flag };
        if (self.runLucidCommand(&args)) |out| {
            self.allocator.free(out);
            self.clearFailure();
        } else {
            self.markFailure();
        }
    }

    fn recallFromLucid(self: *Self, query: []const u8) ?[]u8 {
        if (self.inFailureCooldown()) return null;

        const budget_flag = std.fmt.allocPrint(self.allocator, "--budget={d}", .{self.token_budget}) catch return null;
        defer self.allocator.free(budget_flag);

        const project_flag = std.fmt.allocPrint(self.allocator, "--project={s}", .{self.workspace_dir}) catch return null;
        defer self.allocator.free(project_flag);

        const args = [_][]const u8{ "context", query, budget_flag, project_flag };
        if (self.runLucidCommand(&args)) |out| {
            self.clearFailure();
            return out;
        } else {
            self.markFailure();
            return null;
        }
    }

    // ── Parse lucid-context output ───────────────────────────────

    pub fn parseLucidContext(allocator: std.mem.Allocator, raw: []const u8) ![]MemoryEntry {
        var entries: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*e| e.deinit(allocator);
            entries.deinit(allocator);
        }

        var in_context_block = false;
        var rank: usize = 0;

        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");

            if (std.mem.eql(u8, line, "<lucid-context>")) {
                in_context_block = true;
                continue;
            }
            if (std.mem.eql(u8, line, "</lucid-context>")) {
                break;
            }
            if (!in_context_block or line.len == 0) continue;

            // Expected format: "- [label] content"
            const rest = stripPrefix(line, "- [") orelse continue;
            const close_bracket = std.mem.indexOfScalar(u8, rest, ']') orelse continue;

            const label = std.mem.trim(u8, rest[0..close_bracket], " \t");
            const content = std.mem.trim(u8, rest[close_bracket + 1 ..], " \t");
            if (content.len == 0) continue;

            const score_val: f64 = @max(1.0 - @as(f64, @floatFromInt(rank)) * 0.05, 0.1);

            const id = try std.fmt.allocPrint(allocator, "lucid:{d}", .{rank});
            errdefer allocator.free(id);
            const key = try std.fmt.allocPrint(allocator, "lucid_{d}", .{rank});
            errdefer allocator.free(key);
            const content_owned = try allocator.dupe(u8, content);
            errdefer allocator.free(content_owned);
            const timestamp = try allocator.dupe(u8, "");
            errdefer allocator.free(timestamp);

            const cat = toMemoryCategory(label);
            // If custom, dupe the label so the entry owns it
            const owned_cat: MemoryCategory = switch (cat) {
                .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
                else => cat,
            };

            try entries.append(allocator, .{
                .id = id,
                .key = key,
                .content = content_owned,
                .category = owned_cat,
                .timestamp = timestamp,
                .session_id = null,
                .score = score_val,
            });

            rank += 1;
        }

        return entries.toOwnedSlice(allocator);
    }

    fn stripPrefix(s: []const u8, prefix: []const u8) ?[]const u8 {
        if (s.len < prefix.len) return null;
        if (std.mem.eql(u8, s[0..prefix.len], prefix)) {
            return s[prefix.len..];
        }
        return null;
    }

    // ── Merge & deduplicate ──────────────────────────────────────

    fn mergeResults(
        allocator: std.mem.Allocator,
        primary: []MemoryEntry,
        secondary: []MemoryEntry,
        limit: usize,
    ) ![]MemoryEntry {
        if (limit == 0) {
            root.freeEntries(allocator, primary);
            root.freeEntries(allocator, secondary);
            return allocator.alloc(MemoryEntry, 0);
        }

        const batches = [2][]MemoryEntry{ primary, secondary };
        var batch_idx: usize = 0;
        var entry_idx: usize = 0;

        var merged: std.ArrayList(MemoryEntry) = .empty;
        errdefer {
            for (merged.items) |*e| e.deinit(allocator);
            merged.deinit(allocator);
            // Free remaining unprocessed entries from current and subsequent batches.
            // On error mid-iteration, entries already appended to `merged` are freed above,
            // but entries not yet visited would leak without this cleanup.
            var bi = batch_idx;
            var ei = entry_idx;
            while (bi < batches.len) {
                while (ei < batches[bi].len) {
                    var e = batches[bi][ei];
                    e.deinit(allocator);
                    ei += 1;
                }
                allocator.free(batches[bi]);
                bi += 1;
                ei = 0;
            }
        }

        // Track seen keys by lowered signature (key + '\0' + content)
        var seen = std.StringHashMap(void).init(allocator);
        defer {
            var it = seen.keyIterator();
            while (it.next()) |k| allocator.free(k.*);
            seen.deinit();
        }

        // Process primary first, then secondary
        while (batch_idx < batches.len) {
            entry_idx = 0;
            while (entry_idx < batches[batch_idx].len) {
                const entry = batches[batch_idx][entry_idx];
                entry_idx += 1; // advance past this entry (now "processed")

                if (merged.items.len >= limit) {
                    // Free remaining entries from this batch that won't be used
                    var e_copy = entry;
                    e_copy.deinit(allocator);
                    continue;
                }

                const sig = try buildSignature(allocator, entry.key, entry.content);

                const gop = try seen.getOrPut(sig);
                if (gop.found_existing) {
                    allocator.free(sig);
                    var e_copy = entry;
                    e_copy.deinit(allocator);
                } else {
                    try merged.append(allocator, entry);
                }
            }
            // Free the batch slice itself (but not entries — they're moved)
            allocator.free(batches[batch_idx]);
            batch_idx += 1;
        }

        return merged.toOwnedSlice(allocator);
    }

    fn buildSignature(allocator: std.mem.Allocator, key: []const u8, content: []const u8) ![]u8 {
        const sig = try allocator.alloc(u8, key.len + 1 + content.len);
        @memcpy(sig[0..key.len], key);
        sig[key.len] = 0;
        @memcpy(sig[key.len + 1 ..], content);
        // Lowercase in-place
        for (sig) |*ch| {
            if (ch.* >= 'A' and ch.* <= 'Z') {
                ch.* = ch.* + ('a' - 'A');
            }
        }
        return sig;
    }

    // ── Memory vtable implementation ─────────────────────────────

    /// Get the local SQLite memory interface. The pointer into self.local
    /// is stable because LucidMemory is not moved after init.
    fn localMemory(self: *Self) Memory {
        return self.local.memory();
    }

    fn implName(_: *anyopaque) []const u8 {
        return "lucid";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self = castSelf(ptr);
        // Store locally first (authoritative)
        const local = self.localMemory();
        try local.store(key, content, category, session_id);
        // Fire-and-forget sync to lucid
        self.syncToLucid(key, content, category);
    }

    fn implRecall(ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self = castSelf(ptr);
        const local = self.localMemory();

        const local_results = try local.recall(allocator, query, limit, session_id);

        // Short-circuit: local results sufficient
        if (limit == 0 or
            local_results.len >= limit or
            local_results.len >= self.local_hit_threshold)
        {
            return local_results;
        }

        // Try lucid augmentation
        if (self.recallFromLucid(query)) |raw_output| {
            defer self.allocator.free(raw_output);
            const lucid_results = parseLucidContext(allocator, raw_output) catch {
                return local_results;
            };
            return mergeResults(allocator, local_results, lucid_results, limit) catch {
                // On merge failure, local results may already be freed
                // Return empty as a safe fallback
                return allocator.alloc(MemoryEntry, 0);
            };
        }

        return local_results;
    }

    fn implGet(ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self = castSelf(ptr);
        return self.localMemory().get(allocator, key);
    }

    fn implList(ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self = castSelf(ptr);
        return self.localMemory().list(allocator, category, session_id);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self = castSelf(ptr);
        return self.localMemory().forget(key);
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self = castSelf(ptr);
        return self.localMemory().count();
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self = castSelf(ptr);
        return self.localMemory().healthCheck();
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self = castSelf(ptr);
        self.deinit();
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn castSelf(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }

    const vtable = Memory.VTable{
        .name = &implName,
        .store = &implStore,
        .recall = &implRecall,
        .get = &implGet,
        .list = &implList,
        .forget = &implForget,
        .count = &implCount,
        .healthCheck = &implHealthCheck,
        .deinit = &implDeinit,
    };

    pub fn memory(self: *Self) Memory {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    // ── SessionStore vtable ────────────────────────────────────────

    fn implSessionSaveMessage(ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void {
        const self = castSelf(ptr);
        return self.local.saveMessage(session_id, role, content);
    }

    fn implSessionLoadMessages(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8) anyerror![]root.MessageEntry {
        const self = castSelf(ptr);
        return self.local.loadMessages(allocator, session_id);
    }

    fn implSessionClearMessages(ptr: *anyopaque, session_id: []const u8) anyerror!void {
        const self = castSelf(ptr);
        return self.local.clearMessages(session_id);
    }

    fn implSessionClearAutoSaved(ptr: *anyopaque, session_id: ?[]const u8) anyerror!void {
        const self = castSelf(ptr);
        return self.local.clearAutoSaved(session_id);
    }

    fn implSessionSaveUsage(ptr: *anyopaque, session_id: []const u8, total_tokens: u64) anyerror!void {
        const self = castSelf(ptr);
        return self.local.saveUsage(session_id, total_tokens);
    }

    fn implSessionLoadUsage(ptr: *anyopaque, session_id: []const u8) anyerror!?u64 {
        const self = castSelf(ptr);
        return self.local.loadUsage(session_id);
    }

    fn implSessionCountSessions(ptr: *anyopaque) anyerror!u64 {
        const self = castSelf(ptr);
        return self.local.countSessions();
    }

    fn implSessionListSessions(ptr: *anyopaque, allocator: std.mem.Allocator, limit: usize, offset: usize) anyerror![]root.SessionInfo {
        const self = castSelf(ptr);
        return self.local.listSessions(allocator, limit, offset);
    }

    fn implSessionCountDetailedMessages(ptr: *anyopaque, session_id: []const u8) anyerror!u64 {
        const self = castSelf(ptr);
        return self.local.countDetailedMessages(session_id);
    }

    fn implSessionLoadMessagesDetailed(ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8, limit: usize, offset: usize) anyerror![]root.DetailedMessageEntry {
        const self = castSelf(ptr);
        return self.local.loadMessagesDetailed(allocator, session_id, limit, offset);
    }

    const session_vtable = root.SessionStore.VTable{
        .saveMessage = &implSessionSaveMessage,
        .loadMessages = &implSessionLoadMessages,
        .clearMessages = &implSessionClearMessages,
        .clearAutoSaved = &implSessionClearAutoSaved,
        .saveUsage = &implSessionSaveUsage,
        .loadUsage = &implSessionLoadUsage,
        .countSessions = &implSessionCountSessions,
        .listSessions = &implSessionListSessions,
        .countDetailedMessages = &implSessionCountDetailedMessages,
        .loadMessagesDetailed = &implSessionLoadMessagesDetailed,
    };

    pub fn sessionStore(self: *Self) root.SessionStore {
        return .{ .ptr = @ptrCast(self), .vtable = &session_vtable };
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "lucid memory name" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expectEqualStrings("lucid", m.name());
}

test "lucid store succeeds when lucid binary missing" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try m.store("lang", "User prefers Zig", .core, null);

    const entry = try m.get(allocator, "lang");
    try std.testing.expect(entry != null);
    var e = entry.?;
    defer e.deinit(allocator);
    try std.testing.expectEqualStrings("User prefers Zig", e.content);
}

test "lucid recall returns local results when lucid unavailable" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try m.store("pref", "Zig is fast", .core, null);

    const results = try m.recall(allocator, "zig", 5, null);
    defer root.freeEntries(allocator, results);
    try std.testing.expect(results.len >= 1);
    try std.testing.expect(std.mem.indexOf(u8, results[0].content, "Zig is fast") != null);
}

test "lucid list delegates to local" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try m.store("a", "alpha", .core, null);
    try m.store("b", "beta", .daily, null);

    const all = try m.list(allocator, null, null);
    defer root.freeEntries(allocator, all);
    try std.testing.expectEqual(@as(usize, 2), all.len);

    const core_only = try m.list(allocator, .core, null);
    defer root.freeEntries(allocator, core_only);
    try std.testing.expectEqual(@as(usize, 1), core_only.len);
}

test "lucid forget delegates to local" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try m.store("temp", "temporary data", .core, null);
    const forgotten = try m.forget("temp");
    try std.testing.expect(forgotten);

    const entry = try m.get(allocator, "temp");
    try std.testing.expect(entry == null);
}

test "lucid count delegates to local" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try std.testing.expectEqual(@as(usize, 0), try m.count());
    try m.store("x", "data", .core, null);
    try std.testing.expectEqual(@as(usize, 1), try m.count());
}

test "lucid health check delegates to local" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expect(m.healthCheck());
}

test "lucid failure cooldown is set on lucid failure" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        99, // high threshold to force lucid attempt
        5000,
    );
    defer mem.deinit();

    // Initial state: no cooldown
    try std.testing.expect(!mem.inFailureCooldown());

    // Attempt recall — lucid binary missing, should set cooldown
    const m = mem.memory();
    const results = try m.recall(allocator, "test", 5, null);
    defer root.freeEntries(allocator, results);

    // After failed lucid attempt, cooldown should be active
    try std.testing.expect(mem.cooldown_until_ms > 0);
    try std.testing.expect(mem.inFailureCooldown());
}

test "lucid clearFailure resets cooldown" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        5000,
    );
    defer mem.deinit();

    mem.markFailure();
    try std.testing.expect(mem.inFailureCooldown());
    mem.clearFailure();
    try std.testing.expect(!mem.inFailureCooldown());
}

test "parseLucidContext parses valid output" {
    const allocator = std.testing.allocator;
    const raw =
        \\<lucid-context>
        \\Auth context snapshot
        \\- [decision] Use token refresh middleware
        \\- [context] Working in src/auth.rs
        \\</lucid-context>
    ;

    const entries = try LucidMemory.parseLucidContext(allocator, raw);
    defer root.freeEntries(allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("lucid:0", entries[0].id);
    try std.testing.expectEqualStrings("Use token refresh middleware", entries[0].content);
    try std.testing.expect(entries[0].category.eql(.core)); // decision -> core
    try std.testing.expectEqualStrings("Working in src/auth.rs", entries[1].content);
    try std.testing.expect(entries[1].category.eql(.conversation)); // context -> conversation

    // Check scores descend
    try std.testing.expect(entries[0].score.? > entries[1].score.?);
}

test "parseLucidContext handles empty output" {
    const allocator = std.testing.allocator;
    const entries = try LucidMemory.parseLucidContext(allocator, "");
    defer root.freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseLucidContext handles no context block" {
    const allocator = std.testing.allocator;
    const raw = "Some random output without any context block";
    const entries = try LucidMemory.parseLucidContext(allocator, raw);
    defer root.freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseLucidContext skips empty content" {
    const allocator = std.testing.allocator;
    const raw =
        \\<lucid-context>
        \\- [decision]
        \\- [context] Valid entry
        \\- [bug]
        \\</lucid-context>
    ;
    const entries = try LucidMemory.parseLucidContext(allocator, raw);
    defer root.freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("Valid entry", entries[0].content);
}

test "toLucidType maps categories correctly" {
    try std.testing.expectEqualStrings("decision", LucidMemory.toLucidType(.core));
    try std.testing.expectEqualStrings("context", LucidMemory.toLucidType(.daily));
    try std.testing.expectEqualStrings("conversation", LucidMemory.toLucidType(.conversation));
    try std.testing.expectEqualStrings("learning", LucidMemory.toLucidType(.{ .custom = "anything" }));
}

test "toMemoryCategory maps labels correctly" {
    try std.testing.expect(LucidMemory.toMemoryCategory("decision").eql(.core));
    try std.testing.expect(LucidMemory.toMemoryCategory("learning").eql(.core));
    try std.testing.expect(LucidMemory.toMemoryCategory("solution").eql(.core));
    try std.testing.expect(LucidMemory.toMemoryCategory("context").eql(.conversation));
    try std.testing.expect(LucidMemory.toMemoryCategory("conversation").eql(.conversation));
    try std.testing.expect(LucidMemory.toMemoryCategory("bug").eql(.daily));

    const visual = LucidMemory.toMemoryCategory("visual");
    try std.testing.expectEqualStrings("visual", visual.custom);
}

test "buildSignature creates lowercased key-content pair" {
    const allocator = std.testing.allocator;
    const sig = try LucidMemory.buildSignature(allocator, "Hello", "World");
    defer allocator.free(sig);
    try std.testing.expectEqualStrings("hello\x00world", sig);
}

test "stripPrefix works correctly" {
    const result = LucidMemory.stripPrefix("- [decision] Use tokens", "- [");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("decision] Use tokens", result.?);

    const no_match = LucidMemory.stripPrefix("hello", "- [");
    try std.testing.expect(no_match == null);

    const short = LucidMemory.stripPrefix("- ", "- [");
    try std.testing.expect(short == null);
}

test "lucid recall skips lucid when local hits meet threshold" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        1, // threshold = 1, so even 1 local hit skips lucid
        5000,
    );
    defer mem.deinit();
    const m = mem.memory();

    try m.store("pref", "Zig stays local-first", .core, null);

    // Store may have triggered cooldown from failed lucid sync — reset it
    // so we can verify recall itself doesn't set it again.
    mem.clearFailure();
    try std.testing.expect(!mem.inFailureCooldown());

    const results = try m.recall(allocator, "zig", 5, null);
    defer root.freeEntries(allocator, results);
    try std.testing.expect(results.len >= 1);

    // Cooldown should still NOT be set because recall short-circuited
    // (local hits >= threshold), so lucid was never attempted during recall.
    try std.testing.expect(!mem.inFailureCooldown());
}

test "lucid recall timeout is 500ms" {
    try std.testing.expectEqual(@as(u64, 500), LucidMemory.DEFAULT_RECALL_TIMEOUT_MS);
}

test "lucid store accepts session_id" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    // Store with explicit session_id
    try m.store("sess_key", "session data", .core, "session-abc");

    const entry = try m.get(allocator, "sess_key");
    try std.testing.expect(entry != null);
    var e = entry.?;
    defer e.deinit(allocator);
    try std.testing.expectEqualStrings("session data", e.content);
}

test "lucid recall accepts session_id" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    // Store with same session_id so it's retrievable by that session
    try m.store("data", "searchable content", .core, "session-abc");

    const results = try m.recall(allocator, "searchable", 5, "session-abc");
    defer root.freeEntries(allocator, results);
    try std.testing.expect(results.len >= 1);
}

test "lucid list accepts session_id" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();
    const m = mem.memory();

    // Store with same session_id so it's listable by that session
    try m.store("a", "alpha", .core, "session-abc");

    const results = try m.list(allocator, null, "session-abc");
    defer root.freeEntries(allocator, results);
    try std.testing.expect(results.len >= 1);
}

// ── SessionStore vtable tests ─────────────────────────────────────

test "lucid sessionStore returns valid vtable" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();

    const store = mem.sessionStore();
    try std.testing.expect(store.vtable == &LucidMemory.session_vtable);
}

test "lucid sessionStore saveMessage + loadMessages roundtrip" {
    const allocator = std.testing.allocator;
    var mem = try LucidMemory.initWithOptions(
        allocator,
        ":memory:",
        "nonexistent-lucid-binary",
        "/tmp/test",
        200,
        3,
        2000,
    );
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("s1", "user", "hello from lucid");
    try store.saveMessage("s1", "assistant", "hi back");

    const msgs = try store.loadMessages(allocator, "s1");
    defer root.freeMessages(allocator, msgs);

    try std.testing.expectEqual(@as(usize, 2), msgs.len);
    try std.testing.expectEqualStrings("user", msgs[0].role);
    try std.testing.expectEqualStrings("hello from lucid", msgs[0].content);
    try std.testing.expectEqualStrings("assistant", msgs[1].role);
    try std.testing.expectEqualStrings("hi back", msgs[1].content);
}
