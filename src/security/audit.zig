const std = @import("std");
const Allocator = std.mem.Allocator;

/// Audit event types
pub const AuditEventType = enum {
    command_execution,
    file_access,
    config_change,
    auth_success,
    auth_failure,
    policy_violation,
    security_event,

    pub fn toString(self: AuditEventType) []const u8 {
        return switch (self) {
            .command_execution => "command_execution",
            .file_access => "file_access",
            .config_change => "config_change",
            .auth_success => "auth_success",
            .auth_failure => "auth_failure",
            .policy_violation => "policy_violation",
            .security_event => "security_event",
        };
    }
};

/// Actor information (who performed the action)
pub const Actor = struct {
    channel: []const u8,
    user_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
};

/// Action information (what was done)
pub const Action = struct {
    command: ?[]const u8 = null,
    risk_level: ?[]const u8 = null,
    approved: bool,
    allowed: bool,
};

/// Execution result
pub const ExecutionResult = struct {
    success: bool,
    exit_code: ?i32 = null,
    duration_ms: ?u64 = null,
    err_msg: ?[]const u8 = null,
};

/// Security context
pub const SecurityContext = struct {
    policy_violation: bool = false,
    rate_limit_remaining: ?u32 = null,
    sandbox_backend: ?[]const u8 = null,
};

/// Complete audit event
pub const AuditEvent = struct {
    /// Timestamp in seconds since epoch (UTC)
    timestamp_s: i64,
    /// Unique event identifier (counter-based for simplicity)
    event_id: u64,
    event_type: AuditEventType,
    actor: ?Actor = null,
    action: ?Action = null,
    result: ?ExecutionResult = null,
    security: SecurityContext = .{},

    /// Global counter for unique event IDs
    var next_id: u64 = 0;

    /// Create a new audit event with current timestamp and unique ID
    pub fn init(event_type: AuditEventType) AuditEvent {
        const id = @atomicRmw(u64, &next_id, .Add, 1, .monotonic);
        return .{
            .timestamp_s = std.time.timestamp(),
            .event_id = id,
            .event_type = event_type,
        };
    }

    /// Set the actor
    pub fn withActor(self: AuditEvent, channel: []const u8, user_id: ?[]const u8, username: ?[]const u8) AuditEvent {
        var ev = self;
        ev.actor = .{
            .channel = channel,
            .user_id = user_id,
            .username = username,
        };
        return ev;
    }

    /// Set the action
    pub fn withAction(self: AuditEvent, command: []const u8, risk_level: []const u8, approved: bool, allowed: bool) AuditEvent {
        var ev = self;
        ev.action = .{
            .command = command,
            .risk_level = risk_level,
            .approved = approved,
            .allowed = allowed,
        };
        return ev;
    }

    /// Set the result
    pub fn withResult(self: AuditEvent, success: bool, exit_code: ?i32, duration_ms: u64, err_msg: ?[]const u8) AuditEvent {
        var ev = self;
        ev.result = .{
            .success = success,
            .exit_code = exit_code,
            .duration_ms = duration_ms,
            .err_msg = err_msg,
        };
        return ev;
    }

    /// Set security context sandbox backend
    pub fn withSecurity(self: AuditEvent, sandbox_backend: ?[]const u8) AuditEvent {
        var ev = self;
        ev.security.sandbox_backend = sandbox_backend;
        return ev;
    }

    /// Write a JSON representation of the event into a buffer.
    /// Returns the slice of the buffer that was written.
    pub fn writeJson(self: *const AuditEvent, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.print(
            "{{\"timestamp_s\":{d},\"event_id\":{d},\"event_type\":\"{s}\"",
            .{ self.timestamp_s, self.event_id, self.event_type.toString() },
        );

        if (self.actor) |a| {
            try writer.print(",\"actor\":{{\"channel\":\"{s}\"", .{a.channel});
            if (a.user_id) |uid| try writer.print(",\"user_id\":\"{s}\"", .{uid});
            if (a.username) |uname| try writer.print(",\"username\":\"{s}\"", .{uname});
            try writer.writeAll("}");
        }

        if (self.action) |act| {
            try writer.writeAll(",\"action\":{");
            var need_comma = false;
            if (act.command) |cmd| {
                try writer.print("\"command\":\"{s}\"", .{cmd});
                need_comma = true;
            }
            if (act.risk_level) |rl| {
                if (need_comma) try writer.writeAll(",");
                try writer.print("\"risk_level\":\"{s}\"", .{rl});
                need_comma = true;
            }
            if (need_comma) try writer.writeAll(",");
            try writer.print("\"approved\":{},\"allowed\":{}", .{ act.approved, act.allowed });
            try writer.writeAll("}");
        }

        if (self.result) |res| {
            try writer.print(",\"result\":{{\"success\":{}", .{res.success});
            if (res.exit_code) |ec| try writer.print(",\"exit_code\":{d}", .{ec});
            if (res.duration_ms) |ms| try writer.print(",\"duration_ms\":{d}", .{ms});
            if (res.err_msg) |em| try writer.print(",\"error\":\"{s}\"", .{em});
            try writer.writeAll("}");
        }

        try writer.print(",\"security\":{{\"policy_violation\":{}", .{self.security.policy_violation});
        if (self.security.rate_limit_remaining) |rlr| try writer.print(",\"rate_limit_remaining\":{d}", .{rlr});
        if (self.security.sandbox_backend) |sb| try writer.print(",\"sandbox_backend\":\"{s}\"", .{sb});
        try writer.writeAll("}}");
        return fbs.getWritten();
    }
};

/// Structured command execution details for audit logging.
pub const CommandExecutionLog = struct {
    channel: []const u8,
    command: []const u8,
    risk_level: []const u8,
    approved: bool,
    allowed: bool,
    success: bool,
    duration_ms: u64,
};

/// Audit logger configuration
pub const AuditConfig = struct {
    enabled: bool = true,
    log_path: []const u8 = "audit.log",
    max_size_mb: u32 = 10,
};

/// Audit logger — writes JSON audit events to a log file.
pub const AuditLogger = struct {
    log_path: []const u8,
    config: AuditConfig,
    allocator: Allocator,

    /// Create a new audit logger
    pub fn init(allocator: Allocator, config: AuditConfig, base_dir: []const u8) !AuditLogger {
        const path = try std.fs.path.join(allocator, &.{ base_dir, config.log_path });
        return .{
            .log_path = path,
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AuditLogger) void {
        self.allocator.free(self.log_path);
    }

    /// Log an event
    pub fn log(self: *const AuditLogger, event: *const AuditEvent) !void {
        if (!self.config.enabled) return;

        try self.rotateIfNeeded();

        // Write JSON line to file
        const file = try std.fs.cwd().createFile(self.log_path, .{
            .truncate = false,
        });
        defer file.close();

        try file.seekFromEnd(0);
        var json_buf: [4096]u8 = undefined;
        const json = try event.writeJson(&json_buf);
        try file.writeAll(json);
        try file.writeAll("\n");
        try file.sync();
    }

    /// Log a command execution event.
    pub fn logCommand(self: *const AuditLogger, entry: CommandExecutionLog) !void {
        var event = AuditEvent.init(.command_execution)
            .withActor(entry.channel, null, null)
            .withAction(entry.command, entry.risk_level, entry.approved, entry.allowed)
            .withResult(entry.success, null, entry.duration_ms, null);
        try self.log(&event);
    }

    /// Rotate log if it exceeds max size
    fn rotateIfNeeded(self: *const AuditLogger) !void {
        const stat = std.fs.cwd().statFile(self.log_path) catch return;
        const size_mb = stat.size / (1024 * 1024);
        if (size_mb >= self.config.max_size_mb) {
            try self.rotate();
        }
    }

    /// Rotate the log file
    fn rotate(self: *const AuditLogger) !void {
        var buf_old: [1024]u8 = undefined;
        var buf_new: [1024]u8 = undefined;

        // Shift existing rotated logs: .9 -> .10, .8 -> .9, ... .1 -> .2
        var i: u32 = 9;
        while (i >= 1) : (i -= 1) {
            const old_name = std.fmt.bufPrint(&buf_old, "{s}.{d}.log", .{ self.log_path, i }) catch continue;
            const new_name = std.fmt.bufPrint(&buf_new, "{s}.{d}.log", .{ self.log_path, i + 1 }) catch continue;
            std.fs.cwd().rename(old_name, new_name) catch {};
        }

        // Rename current log to .1
        const rotated = std.fmt.bufPrint(&buf_old, "{s}.1.log", .{self.log_path}) catch return;
        std.fs.cwd().rename(self.log_path, rotated) catch {};
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "audit event init creates unique ids" {
    const e1 = AuditEvent.init(.command_execution);
    const e2 = AuditEvent.init(.command_execution);
    try std.testing.expect(e1.event_id != e2.event_id);
}

test "audit event with actor" {
    const event = AuditEvent.init(.command_execution)
        .withActor("telegram", "123", "@alice");
    try std.testing.expect(event.actor != null);
    const actor = event.actor.?;
    try std.testing.expectEqualStrings("telegram", actor.channel);
    try std.testing.expectEqualStrings("123", actor.user_id.?);
    try std.testing.expectEqualStrings("@alice", actor.username.?);
}

test "audit event with action" {
    const event = AuditEvent.init(.command_execution)
        .withAction("ls -la", "low", false, true);
    try std.testing.expect(event.action != null);
    const action = event.action.?;
    try std.testing.expectEqualStrings("ls -la", action.command.?);
    try std.testing.expectEqualStrings("low", action.risk_level.?);
}

test "audit event serializes to json" {
    var event = AuditEvent.init(.command_execution)
        .withActor("telegram", null, null)
        .withAction("ls", "low", false, true)
        .withResult(true, 0, 15, null);

    var buf: [1024]u8 = undefined;
    const json = try event.writeJson(&buf);
    // Should contain key fields
    try std.testing.expect(std.mem.indexOf(u8, json, "command_execution") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "telegram") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"success\":true") != null);
}

test "audit event type toString" {
    try std.testing.expectEqualStrings("command_execution", AuditEventType.command_execution.toString());
    try std.testing.expectEqualStrings("policy_violation", AuditEventType.policy_violation.toString());
    try std.testing.expectEqualStrings("auth_success", AuditEventType.auth_success.toString());
}

test "audit logger disabled does not create file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = false };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var event = AuditEvent.init(.command_execution);
    try logger.log(&event);

    // File should not exist since logging is disabled
    const result = tmp_dir.dir.statFile("audit.log");
    try std.testing.expectError(error.FileNotFound, result);
}

// ── Additional audit tests ──────────────────────────────────────

test "audit event types all have string representations" {
    const types = [_]AuditEventType{
        .command_execution, .file_access,  .config_change,
        .auth_success,      .auth_failure, .policy_violation,
        .security_event,
    };
    for (types) |t| {
        const s = t.toString();
        try std.testing.expect(s.len > 0);
    }
}

test "audit event with result" {
    const event = AuditEvent.init(.command_execution)
        .withResult(true, 0, 42, null);
    try std.testing.expect(event.result != null);
    const r = event.result.?;
    try std.testing.expect(r.success);
    try std.testing.expectEqual(@as(?i32, 0), r.exit_code);
    try std.testing.expectEqual(@as(?u64, 42), r.duration_ms);
    try std.testing.expect(r.err_msg == null);
}

test "audit event with result error message" {
    const event = AuditEvent.init(.command_execution)
        .withResult(false, 1, 100, "command failed");
    const r = event.result.?;
    try std.testing.expect(!r.success);
    try std.testing.expectEqual(@as(?i32, 1), r.exit_code);
    try std.testing.expectEqualStrings("command failed", r.err_msg.?);
}

test "audit event with security context" {
    const event = AuditEvent.init(.security_event)
        .withSecurity("firejail");
    try std.testing.expectEqualStrings("firejail", event.security.sandbox_backend.?);
    try std.testing.expect(!event.security.policy_violation);
}

test "audit event chained builder" {
    const event = AuditEvent.init(.command_execution)
        .withActor("cli", "user1", "alice")
        .withAction("ls -la", "low", false, true)
        .withResult(true, 0, 5, null)
        .withSecurity("none");

    try std.testing.expect(event.actor != null);
    try std.testing.expect(event.action != null);
    try std.testing.expect(event.result != null);
    try std.testing.expectEqualStrings("none", event.security.sandbox_backend.?);
}

test "audit event json contains event type" {
    var event = AuditEvent.init(.auth_failure)
        .withActor("gateway", null, null);
    var buf: [2048]u8 = undefined;
    const json = try event.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "auth_failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "gateway") != null);
}

test "audit event json contains security context" {
    var event = AuditEvent.init(.policy_violation);
    event.security.policy_violation = true;
    event.security.rate_limit_remaining = 5;
    var buf: [2048]u8 = undefined;
    const json = try event.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "policy_violation") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "rate_limit_remaining") != null);
}

test "audit event default security context" {
    const event = AuditEvent.init(.command_execution);
    try std.testing.expect(!event.security.policy_violation);
    try std.testing.expect(event.security.rate_limit_remaining == null);
    try std.testing.expect(event.security.sandbox_backend == null);
}

test "audit config defaults" {
    const cfg = AuditConfig{};
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqualStrings("audit.log", cfg.log_path);
    try std.testing.expectEqual(@as(u32, 10), cfg.max_size_mb);
}

test "audit config custom" {
    const cfg = AuditConfig{
        .enabled = false,
        .log_path = "custom.log",
        .max_size_mb = 50,
    };
    try std.testing.expect(!cfg.enabled);
    try std.testing.expectEqualStrings("custom.log", cfg.log_path);
    try std.testing.expectEqual(@as(u32, 50), cfg.max_size_mb);
}

test "audit logger enabled writes to file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "test_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var event = AuditEvent.init(.command_execution)
        .withAction("ls", "low", false, true);
    try logger.log(&event);

    // File should exist
    const stat = try tmp_dir.dir.statFile("test_audit.log");
    try std.testing.expect(stat.size > 0);
}

test "audit logger multiple events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "multi_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var e1 = AuditEvent.init(.command_execution);
    try logger.log(&e1);
    var e2 = AuditEvent.init(.auth_success);
    try logger.log(&e2);

    const stat = try tmp_dir.dir.statFile("multi_audit.log");
    try std.testing.expect(stat.size > 10); // more than one event
}

test "audit command execution log" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "cmd_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    try logger.logCommand(.{
        .channel = "cli",
        .command = "git status",
        .risk_level = "low",
        .approved = false,
        .allowed = true,
        .success = true,
        .duration_ms = 15,
    });

    const stat = try tmp_dir.dir.statFile("cmd_audit.log");
    try std.testing.expect(stat.size > 0);
}

test "audit event ids are sequential" {
    const e1 = AuditEvent.init(.command_execution);
    const e2 = AuditEvent.init(.command_execution);
    const e3 = AuditEvent.init(.command_execution);
    try std.testing.expect(e2.event_id > e1.event_id);
    try std.testing.expect(e3.event_id > e2.event_id);
}

test "audit event timestamp is reasonable" {
    const event = AuditEvent.init(.command_execution);
    // Timestamp should be a positive number (after Unix epoch)
    try std.testing.expect(event.timestamp_s > 0);
    // And before year 2100 (reasonable upper bound)
    try std.testing.expect(event.timestamp_s < 4_102_444_800);
}
