//! Skill Evolution Pipeline — detect and track skill improvement opportunities.
//!
//! Monitors turn scores per skill and detects patterns that indicate a skill
//! needs improvement. When a trigger fires, an evolution event is recorded
//! in the memory system for later processing (LLM analysis via nullclaw-rag).
//!
//! Current implementation: detection + tracking only (no LLM calls).
//! LLM-based analysis and SKILL.md patching deferred to Fase 7 / nullclaw-rag.

const std = @import("std");
const builtin = @import("builtin");
const memory_mod = @import("memory/root.zig");
const Memory = memory_mod.Memory;

pub const log = std.log.scoped(.skill_evolution);

// ── Configuration ────────────────────────────────────────────────────

pub const EvolutionConfig = struct {
    /// Enable evolution trigger detection.
    enabled: bool = false,
    /// Max evolution triggers per skill per day.
    max_per_skill_per_day: u32 = 3,
    /// Cooldown between triggers for the same skill (minutes).
    cooldown_minutes: u32 = 30,
    /// Score threshold for single-failure trigger.
    single_failure_threshold: f32 = -0.5,
    /// Score threshold for pattern trigger.
    pattern_threshold: f32 = -0.2,
    /// Number of low-scoring turns needed for pattern trigger.
    pattern_count: u32 = 3,
    /// Window for pattern detection (hours).
    pattern_window_hours: u32 = 24,
};

// ── Types ────────────────────────────────────────────────────────────

pub const TriggerType = enum {
    /// Single turn: score < threshold AND tool_failure signal set.
    single_failure,
    /// Pattern: N+ turns below threshold within time window.
    pattern,
    /// User gave explicit negative feedback tied to a skill.
    explicit_feedback,

    pub fn toSlice(self: TriggerType) []const u8 {
        return switch (self) {
            .single_failure => "single_failure",
            .pattern => "pattern",
            .explicit_feedback => "explicit_feedback",
        };
    }
};

/// A detected evolution trigger — something went wrong with a skill.
pub const EvolutionTrigger = struct {
    skill_name: []const u8,
    trigger_type: TriggerType,
    score: f32,
    tool_failures: u16,
    timestamp: i64,

    /// Format trigger as a human-readable summary for memory storage.
    pub fn format(self: *const EvolutionTrigger, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(
            allocator,
            "trigger={s} skill={s} score={d:.2} failures={d} ts={d}",
            .{ self.trigger_type.toSlice(), self.skill_name, self.score, self.tool_failures, self.timestamp },
        );
    }
};

/// A recorded score for a skill at a point in time.
const SkillScoreEntry = struct {
    score: f32,
    tool_failures: u16,
    has_tool_failure_signal: bool,
    has_explicit_negative: bool,
    timestamp: i64,
};

/// Per-skill tracking state.
const SkillState = struct {
    /// Recent score entries (ring buffer, max 16).
    entries: [MAX_ENTRIES]SkillScoreEntry = undefined,
    count: u8 = 0,
    /// Number of triggers fired today.
    triggers_today: u32 = 0,
    /// Day number for trigger counting (days since epoch).
    trigger_day: i64 = 0,
    /// Timestamp of last trigger (for cooldown).
    last_trigger_ts: i64 = 0,

    const MAX_ENTRIES: u8 = 16;

    fn addEntry(self: *SkillState, entry: SkillScoreEntry) void {
        if (self.count < MAX_ENTRIES) {
            self.entries[self.count] = entry;
            self.count += 1;
        } else {
            // Shift left (drop oldest)
            var i: u8 = 0;
            while (i < MAX_ENTRIES - 1) : (i += 1) {
                self.entries[i] = self.entries[i + 1];
            }
            self.entries[MAX_ENTRIES - 1] = entry;
        }
    }

    /// Count entries below threshold within a time window.
    fn countBelowThreshold(self: *const SkillState, threshold: f32, min_ts: i64) u32 {
        var n: u32 = 0;
        for (self.entries[0..self.count]) |e| {
            if (e.score < threshold and e.timestamp >= min_ts) n += 1;
        }
        return n;
    }

    /// Check and update rate limit. Returns true if allowed to trigger.
    fn checkRateLimit(self: *SkillState, config: EvolutionConfig, now: i64) bool {
        const day = @divFloor(now, 86400);

        // Reset daily counter if new day
        if (day != self.trigger_day) {
            self.triggers_today = 0;
            self.trigger_day = day;
        }

        // Check daily limit
        if (self.triggers_today >= config.max_per_skill_per_day) return false;

        // Check cooldown (skip if no trigger has fired yet)
        if (self.last_trigger_ts > 0) {
            const cooldown_secs = @as(i64, @intCast(config.cooldown_minutes)) * 60;
            if (now - self.last_trigger_ts < cooldown_secs) return false;
        }

        return true;
    }

    fn recordTrigger(self: *SkillState, now: i64) void {
        self.triggers_today += 1;
        self.last_trigger_ts = now;
    }
};

// ── Performance Tracker ──────────────────────────────────────────────

/// Tracks per-skill turn scores and detects evolution triggers.
/// Designed for in-process use — no heap allocations for tracking state.
/// Max 32 skills tracked simultaneously (oldest evicted on overflow).
pub const SkillPerformanceTracker = struct {
    skills: [MAX_SKILLS]TrackedSkill = undefined,
    skill_count: u8 = 0,
    config: EvolutionConfig,

    const MAX_SKILLS: u8 = 32;

    const TrackedSkill = struct {
        name_buf: [64]u8 = undefined,
        name_len: u8 = 0,
        state: SkillState = .{},

        fn getName(self: *const TrackedSkill) []const u8 {
            return self.name_buf[0..self.name_len];
        }

        fn setName(self: *TrackedSkill, name: []const u8) void {
            const len = @min(name.len, 64);
            @memcpy(self.name_buf[0..len], name[0..len]);
            self.name_len = @intCast(len);
        }
    };

    pub fn init(config: EvolutionConfig) SkillPerformanceTracker {
        return .{ .config = config };
    }

    /// Record a turn score for a skill. Returns an EvolutionTrigger if one fires.
    pub fn recordScore(
        self: *SkillPerformanceTracker,
        skill_name: []const u8,
        score: f32,
        tool_failures: u16,
        has_tool_failure_signal: bool,
        has_explicit_negative: bool,
        now: i64,
    ) ?EvolutionTrigger {
        if (!self.config.enabled) return null;
        if (skill_name.len == 0) return null;

        const slot = self.getOrCreateSlot(skill_name);
        const entry = SkillScoreEntry{
            .score = score,
            .tool_failures = tool_failures,
            .has_tool_failure_signal = has_tool_failure_signal,
            .has_explicit_negative = has_explicit_negative,
            .timestamp = now,
        };
        slot.state.addEntry(entry);

        // Check triggers (priority order)
        return self.checkTriggers(slot, entry, now);
    }

    fn checkTriggers(
        self: *SkillPerformanceTracker,
        slot: *TrackedSkill,
        entry: SkillScoreEntry,
        now: i64,
    ) ?EvolutionTrigger {
        if (!slot.state.checkRateLimit(self.config, now)) return null;

        // 1. Single failure: score below threshold AND tool failure
        if (entry.score < self.config.single_failure_threshold and entry.has_tool_failure_signal) {
            slot.state.recordTrigger(now);
            return EvolutionTrigger{
                .skill_name = slot.getName(),
                .trigger_type = .single_failure,
                .score = entry.score,
                .tool_failures = entry.tool_failures,
                .timestamp = now,
            };
        }

        // 2. Explicit negative feedback
        if (entry.has_explicit_negative) {
            slot.state.recordTrigger(now);
            return EvolutionTrigger{
                .skill_name = slot.getName(),
                .trigger_type = .explicit_feedback,
                .score = entry.score,
                .tool_failures = entry.tool_failures,
                .timestamp = now,
            };
        }

        // 3. Pattern: N+ low scores within window
        const window_secs = @as(i64, @intCast(self.config.pattern_window_hours)) * 3600;
        const min_ts = now - window_secs;
        const count = slot.state.countBelowThreshold(self.config.pattern_threshold, min_ts);
        if (count >= self.config.pattern_count) {
            slot.state.recordTrigger(now);
            return EvolutionTrigger{
                .skill_name = slot.getName(),
                .trigger_type = .pattern,
                .score = entry.score,
                .tool_failures = entry.tool_failures,
                .timestamp = now,
            };
        }

        return null;
    }

    fn getOrCreateSlot(self: *SkillPerformanceTracker, name: []const u8) *TrackedSkill {
        // Find existing
        for (self.skills[0..self.skill_count]) |*s| {
            if (std.mem.eql(u8, s.getName(), name[0..@min(name.len, 64)])) {
                return s;
            }
        }

        // Create new slot
        if (self.skill_count < MAX_SKILLS) {
            const slot = &self.skills[self.skill_count];
            slot.* = .{};
            slot.setName(name);
            self.skill_count += 1;
            return slot;
        }

        // Evict oldest (slot 0) and shift
        var i: u8 = 0;
        while (i < MAX_SKILLS - 1) : (i += 1) {
            self.skills[i] = self.skills[i + 1];
        }
        const slot = &self.skills[MAX_SKILLS - 1];
        slot.* = .{};
        slot.setName(name);
        return slot;
    }

    /// Get score history for a skill (for diagnostics / /skill status command).
    pub fn getScoreHistory(self: *const SkillPerformanceTracker, skill_name: []const u8) ?[]const SkillScoreEntry {
        for (self.skills[0..self.skill_count]) |*s| {
            if (std.mem.eql(u8, s.getName(), skill_name[0..@min(skill_name.len, 64)])) {
                return s.state.entries[0..s.state.count];
            }
        }
        return null;
    }
};

// ── Memory persistence ───────────────────────────────────────────────

/// Store an evolution trigger in the memory system.
pub fn storeTrigger(
    mem: Memory,
    trigger: *const EvolutionTrigger,
    allocator: std.mem.Allocator,
) void {
    var key_buf: [128]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "__evolution.{s}.{d}", .{
        trigger.skill_name, trigger.timestamp,
    }) catch return;

    const content = trigger.format(allocator) catch return;
    defer allocator.free(content);

    mem.store(key, content, .core, null) catch |err| {
        log.warn("failed to store evolution trigger: {s}", .{@errorName(err)});
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "SkillPerformanceTracker init" {
    const tracker = SkillPerformanceTracker.init(.{ .enabled = true });
    try std.testing.expectEqual(@as(u8, 0), tracker.skill_count);
}

test "recordScore with disabled config returns null" {
    var tracker = SkillPerformanceTracker.init(.{ .enabled = false });
    const result = tracker.recordScore("my-skill", -0.8, 2, true, false, 1000);
    try std.testing.expect(result == null);
}

test "recordScore with empty skill name returns null" {
    var tracker = SkillPerformanceTracker.init(.{ .enabled = true });
    const result = tracker.recordScore("", -0.8, 2, true, false, 1000);
    try std.testing.expect(result == null);
}

test "single_failure trigger fires on low score with tool failure" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .single_failure_threshold = -0.5,
    });
    const result = tracker.recordScore("coding-agent", -0.7, 1, true, false, 1000);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(TriggerType.single_failure, result.?.trigger_type);
    try std.testing.expectEqualStrings("coding-agent", result.?.skill_name);
}

test "single_failure does NOT fire without tool_failure signal" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .single_failure_threshold = -0.5,
    });
    const result = tracker.recordScore("coding-agent", -0.7, 0, false, false, 1000);
    try std.testing.expect(result == null);
}

test "explicit_feedback trigger fires on negative feedback" {
    var tracker = SkillPerformanceTracker.init(.{ .enabled = true });
    const result = tracker.recordScore("writing-agent", -0.2, 0, false, true, 1000);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(TriggerType.explicit_feedback, result.?.trigger_type);
}

test "pattern trigger fires after N low scores" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .pattern_threshold = -0.2,
        .pattern_count = 3,
        .pattern_window_hours = 24,
    });
    // Three low scores within window
    _ = tracker.recordScore("data-agent", -0.3, 0, false, false, 1000);
    _ = tracker.recordScore("data-agent", -0.25, 0, false, false, 2000);
    const result = tracker.recordScore("data-agent", -0.4, 0, false, false, 3000);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(TriggerType.pattern, result.?.trigger_type);
}

test "pattern trigger does NOT fire if scores outside window" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .pattern_threshold = -0.2,
        .pattern_count = 3,
        .pattern_window_hours = 1,
    });
    // Two scores outside 1-hour window
    _ = tracker.recordScore("data-agent", -0.3, 0, false, false, 0);
    _ = tracker.recordScore("data-agent", -0.25, 0, false, false, 100);
    // Third score 2 hours later — only this one is in window
    const result = tracker.recordScore("data-agent", -0.4, 0, false, false, 7200);
    try std.testing.expect(result == null);
}

test "rate limit: daily max prevents trigger" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .max_per_skill_per_day = 2,
        .cooldown_minutes = 0,
    });
    // Fire twice
    const r1 = tracker.recordScore("agent-a", -0.8, 1, true, false, 86400);
    try std.testing.expect(r1 != null);
    const r2 = tracker.recordScore("agent-a", -0.8, 1, true, false, 86401);
    try std.testing.expect(r2 != null);
    // Third should be blocked
    const r3 = tracker.recordScore("agent-a", -0.8, 1, true, false, 86402);
    try std.testing.expect(r3 == null);
}

test "rate limit: cooldown prevents trigger" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .max_per_skill_per_day = 10,
        .cooldown_minutes = 30,
    });
    const r1 = tracker.recordScore("agent-b", -0.8, 1, true, false, 1000);
    try std.testing.expect(r1 != null);
    // 10 minutes later — within cooldown
    const r2 = tracker.recordScore("agent-b", -0.8, 1, true, false, 1600);
    try std.testing.expect(r2 == null);
    // 31 minutes later — past cooldown
    const r3 = tracker.recordScore("agent-b", -0.8, 1, true, false, 2860);
    try std.testing.expect(r3 != null);
}

test "slot eviction when max skills reached" {
    var tracker = SkillPerformanceTracker.init(.{
        .enabled = true,
        .cooldown_minutes = 0,
    });
    // Fill all 32 slots
    var i: u8 = 0;
    while (i < 32) : (i += 1) {
        var name_buf: [8]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "sk-{d:0>3}", .{i}) catch unreachable;
        _ = tracker.recordScore(name, 0.5, 0, false, false, @intCast(i));
    }
    try std.testing.expectEqual(@as(u8, 32), tracker.skill_count);

    // 33rd skill should evict the oldest
    _ = tracker.recordScore("sk-new", 0.5, 0, false, false, 100);
    try std.testing.expectEqual(@as(u8, 32), tracker.skill_count);

    // First slot should now be "sk-001" (sk-000 evicted)
    try std.testing.expectEqualStrings("sk-001", tracker.skills[0].getName());
}

test "getScoreHistory returns entries for tracked skill" {
    var tracker = SkillPerformanceTracker.init(.{ .enabled = true });
    _ = tracker.recordScore("my-skill", 0.5, 0, false, false, 100);
    _ = tracker.recordScore("my-skill", -0.3, 1, true, false, 200);

    const history = tracker.getScoreHistory("my-skill");
    try std.testing.expect(history != null);
    try std.testing.expectEqual(@as(usize, 2), history.?.len);
}

test "getScoreHistory returns null for unknown skill" {
    const tracker = SkillPerformanceTracker.init(.{ .enabled = true });
    try std.testing.expect(tracker.getScoreHistory("unknown") == null);
}

test "EvolutionTrigger format" {
    const allocator = std.testing.allocator;
    const trigger = EvolutionTrigger{
        .skill_name = "coding-agent",
        .trigger_type = .single_failure,
        .score = -0.7,
        .tool_failures = 2,
        .timestamp = 1234,
    };
    const formatted = try trigger.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "single_failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "coding-agent") != null);
}

test "storeTrigger persists to memory" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    const trigger = EvolutionTrigger{
        .skill_name = "test-skill",
        .trigger_type = .pattern,
        .score = -0.35,
        .tool_failures = 0,
        .timestamp = 5000,
    };
    storeTrigger(mem, &trigger, allocator);

    const entry = try mem.get(allocator, "__evolution.test-skill.5000");
    try std.testing.expect(entry != null);
    if (entry) |e| {
        defer e.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, e.content, "pattern") != null);
    }
}

test "SkillScoreEntry ring buffer overflow" {
    var state = SkillState{};
    // Fill 16 entries
    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        state.addEntry(.{
            .score = 0.1,
            .tool_failures = 0,
            .has_tool_failure_signal = false,
            .has_explicit_negative = false,
            .timestamp = @intCast(i),
        });
    }
    try std.testing.expectEqual(@as(u8, 16), state.count);

    // 17th entry should shift and replace
    state.addEntry(.{
        .score = -0.9,
        .tool_failures = 1,
        .has_tool_failure_signal = true,
        .has_explicit_negative = false,
        .timestamp = 99,
    });
    try std.testing.expectEqual(@as(u8, 16), state.count);
    // Oldest (ts=0) should be gone, newest (ts=99) at end
    try std.testing.expectEqual(@as(i64, 1), state.entries[0].timestamp);
    try std.testing.expectEqual(@as(i64, 99), state.entries[15].timestamp);
}
