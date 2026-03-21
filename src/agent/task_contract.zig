//! Task Contract — pre/post verification for agent turns.
//!
//! Before executing a task the agent generates a lightweight contract:
//! "What is being asked?" with verifiable checkpoints.  After the turn
//! completes, checkpoints are verified rule-based (zero LLM cost) using
//! the TurnContext.  Results are appended to a JSONL ledger for later
//! analysis by the daily evaluation cron job (layer 2).

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.task_contract);
const providers = @import("../providers/root.zig");
const Provider = providers.Provider;
const turn_scorer = @import("turn_scorer.zig");
const TurnContext = turn_scorer.TurnContext;
const json_util = @import("../json_util.zig");
const platform = @import("../platform.zig");

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

pub const CheckType = enum {
    tool_success, // All tool calls succeeded
    no_errors, // No failures, no max_iterations
    response_contains, // Final response contains a keyword

    pub fn asStr(self: CheckType) []const u8 {
        return switch (self) {
            .tool_success => "tool_success",
            .no_errors => "no_errors",
            .response_contains => "response_contains",
        };
    }

    pub fn fromStr(s: []const u8) ?CheckType {
        if (std.mem.eql(u8, s, "tool_success")) return .tool_success;
        if (std.mem.eql(u8, s, "no_errors")) return .no_errors;
        if (std.mem.eql(u8, s, "response_contains")) return .response_contains;
        return null;
    }
};

pub const Checkpoint = struct {
    description: []const u8,
    check_type: CheckType,
    /// For response_contains: expected substring in final response.
    expected: ?[]const u8 = null,
    /// Verification result (filled in after verification).
    passed: bool = false,
};

pub const TaskContract = struct {
    session_id: []const u8,
    timestamp: i64,
    task_summary: []const u8,
    checkpoints: []Checkpoint,
    model: []const u8,
    skill: []const u8,
};

pub const ContractResult = struct {
    session_id: []const u8,
    timestamp: i64,
    task_summary: []const u8,
    model: []const u8,
    skill: []const u8,
    checkpoints_passed: u8,
    checkpoints_total: u8,
    duration_ms: u64,
    verified_at: i64,
};

// ═══════════════════════════════════════════════════════════════════════════
// Contract generation
// ═══════════════════════════════════════════════════════════════════════════

const CONTRACT_SYSTEM_PROMPT =
    \\You are a task contract generator. Given a user request, output a JSON object with:
    \\- "task_summary": one sentence describing what is being asked (max 20 words)
    \\- "checkpoints": array of 1-5 objects, each with:
    \\  - "description": what should happen (max 15 words)
    \\  - "check_type": one of "tool_success", "no_errors", "response_contains"
    \\  - "expected": (only for response_contains) substring to look for in the response
    \\Output ONLY valid JSON. No explanation, no markdown fences, no extra text.
;

/// Generate a task contract by calling a cheap LLM.
/// Returns null on any failure (best-effort, never blocks the main turn).
pub fn generateContract(
    allocator: std.mem.Allocator,
    provider: Provider,
    contract_model: []const u8,
    user_message: []const u8,
    session_id: []const u8,
    turn_model: []const u8,
    skill: []const u8,
    max_checkpoints: u8,
) ?TaskContract {
    if (builtin.is_test) {
        // Return a mock contract in tests
        return TaskContract{
            .session_id = session_id,
            .timestamp = std.time.timestamp(),
            .task_summary = "Test task",
            .checkpoints = allocator.alloc(Checkpoint, 1) catch return null,
            .model = turn_model,
            .skill = skill,
        };
    }

    // Use the configured contract model, fall back to the turn model
    const model = if (contract_model.len > 0) contract_model else turn_model;

    const response_text = provider.chatWithSystem(
        allocator,
        CONTRACT_SYSTEM_PROMPT,
        user_message,
        model,
        0.0,
    ) catch |err| {
        log.warn("contract generation failed: {s}", .{@errorName(err)});
        return null;
    };
    defer allocator.free(response_text);

    return parseContractJson(allocator, response_text, session_id, turn_model, skill, max_checkpoints);
}

/// Parse the LLM's JSON response into a TaskContract.
fn parseContractJson(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    session_id: []const u8,
    model: []const u8,
    skill: []const u8,
    max_checkpoints: u8,
) ?TaskContract {
    // Strip markdown fences if present
    const clean = stripJsonFences(json_text);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, clean, .{}) catch {
        log.warn("contract JSON parse failed", .{});
        return null;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return null;
    const obj = root.object;

    const summary = if (obj.get("task_summary")) |v| switch (v) {
        .string => |s| s,
        else => null,
    } else null;
    if (summary == null) return null;

    const checkpoints_val = obj.get("checkpoints") orelse return null;
    if (checkpoints_val != .array) return null;
    const arr = checkpoints_val.array;

    const count = @min(arr.items.len, max_checkpoints);
    if (count == 0) return null;

    var checkpoints = allocator.alloc(Checkpoint, count) catch return null;
    var valid: usize = 0;

    for (arr.items[0..count]) |item| {
        if (item != .object) continue;
        const cp_obj = item.object;

        const desc = if (cp_obj.get("description")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        if (desc == null) continue;

        const ct_str = if (cp_obj.get("check_type")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        const ct = if (ct_str) |s| CheckType.fromStr(s) orelse CheckType.no_errors else CheckType.no_errors;

        const expected = if (cp_obj.get("expected")) |v| switch (v) {
            .string => |s| allocator.dupe(u8, s) catch null,
            else => null,
        } else null;

        checkpoints[valid] = .{
            .description = allocator.dupe(u8, desc.?) catch continue,
            .check_type = ct,
            .expected = expected,
        };
        valid += 1;
    }

    if (valid == 0) {
        allocator.free(checkpoints);
        return null;
    }

    // Shrink if fewer valid checkpoints than allocated
    if (valid < count) {
        checkpoints = allocator.realloc(checkpoints, valid) catch checkpoints;
    }

    return TaskContract{
        .session_id = allocator.dupe(u8, session_id) catch return null,
        .timestamp = std.time.timestamp(),
        .task_summary = allocator.dupe(u8, summary.?) catch return null,
        .checkpoints = checkpoints[0..valid],
        .model = allocator.dupe(u8, model) catch return null,
        .skill = allocator.dupe(u8, skill) catch return null,
    };
}

/// Strip ```json ... ``` fences if present.
fn stripJsonFences(text: []const u8) []const u8 {
    var s = std.mem.trim(u8, text, " \t\r\n");
    if (std.mem.startsWith(u8, s, "```json")) {
        s = s[7..];
    } else if (std.mem.startsWith(u8, s, "```")) {
        s = s[3..];
    }
    if (std.mem.endsWith(u8, s, "```")) {
        s = s[0 .. s.len - 3];
    }
    return std.mem.trim(u8, s, " \t\r\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Verification (rule-based, zero LLM cost)
// ═══════════════════════════════════════════════════════════════════════════

/// Verify a contract against the turn context and final response.
pub fn verifyContract(contract: *TaskContract, turn_ctx: TurnContext, final_response: []const u8) ContractResult {
    var passed: u8 = 0;
    const total: u8 = @intCast(@min(contract.checkpoints.len, 255));

    for (contract.checkpoints) |*cp| {
        cp.passed = switch (cp.check_type) {
            .tool_success => turn_ctx.has_tool_calls and turn_ctx.tools_failed == 0,
            .no_errors => turn_ctx.tools_failed == 0 and !turn_ctx.max_iterations_hit,
            .response_contains => if (cp.expected) |needle|
                std.ascii.indexOfIgnoreCase(final_response, needle) != null
            else
                true,
        };
        if (cp.passed) passed += 1;
    }

    return .{
        .session_id = contract.session_id,
        .timestamp = contract.timestamp,
        .task_summary = contract.task_summary,
        .model = contract.model,
        .skill = contract.skill,
        .checkpoints_passed = passed,
        .checkpoints_total = total,
        .duration_ms = 0, // filled in by caller
        .verified_at = std.time.timestamp(),
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Persistence (JSONL append)
// ═══════════════════════════════════════════════════════════════════════════

/// Append a contract result to the JSONL ledger file.
pub fn persistResult(allocator: std.mem.Allocator, result: ContractResult) !void {
    const home = platform.getHomeDir(allocator) catch return error.HomeDirNotFound;
    defer allocator.free(home);
    const path = try std.fmt.allocPrint(allocator, "{s}/.nullclaw/contracts.jsonl", .{home});
    defer allocator.free(path);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.print(
        \\{{"session_id":"{s}","timestamp":{d},"task_summary":
    , .{ result.session_id, result.timestamp });
    try json_util.appendJsonString(&buf, allocator, result.task_summary);
    try w.print(
        \\,"model":"{s}","skill":"{s}","checkpoints_passed":{d},"checkpoints_total":{d},"duration_ms":{d},"verified_at":{d}}}
    , .{
        result.model,
        result.skill,
        result.checkpoints_passed,
        result.checkpoints_total,
        result.duration_ms,
        result.verified_at,
    });
    try w.writeByte('\n');

    const file = try std.fs.cwd().createFile(path, .{ .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll(buf.items);
}

/// Free all allocations in a TaskContract.
pub fn deinitContract(allocator: std.mem.Allocator, contract: *TaskContract) void {
    for (contract.checkpoints) |cp| {
        allocator.free(cp.description);
        if (cp.expected) |e| allocator.free(e);
    }
    allocator.free(contract.checkpoints);
    allocator.free(contract.task_summary);
    allocator.free(contract.session_id);
    allocator.free(contract.model);
    allocator.free(contract.skill);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "stripJsonFences removes markdown code fences" {
    try std.testing.expectEqualStrings("{}", stripJsonFences("```json\n{}\n```"));
    try std.testing.expectEqualStrings("{}", stripJsonFences("```\n{}\n```"));
    try std.testing.expectEqualStrings("{}", stripJsonFences("{}"));
    try std.testing.expectEqualStrings("{\"a\":1}", stripJsonFences("  ```json\n{\"a\":1}\n```  "));
}

test "parseContractJson valid input" {
    const allocator = std.testing.allocator;
    const json =
        \\{"task_summary":"Write a report","checkpoints":[{"description":"File created","check_type":"tool_success"},{"description":"No errors","check_type":"no_errors"}]}
    ;

    const contract = parseContractJson(allocator, json, "sess-1", "gpt-4o-mini", "general", 5) orelse {
        return error.TestUnexpectedResult;
    };
    var c = contract;
    defer deinitContract(allocator, &c);

    try std.testing.expectEqualStrings("Write a report", c.task_summary);
    try std.testing.expectEqual(@as(usize, 2), c.checkpoints.len);
    try std.testing.expectEqual(CheckType.tool_success, c.checkpoints[0].check_type);
    try std.testing.expectEqual(CheckType.no_errors, c.checkpoints[1].check_type);
}

test "parseContractJson with fences" {
    const allocator = std.testing.allocator;
    const json =
        \\```json
        \\{"task_summary":"Do X","checkpoints":[{"description":"Done","check_type":"no_errors"}]}
        \\```
    ;

    const contract = parseContractJson(allocator, json, "s1", "m1", "sk1", 5) orelse {
        return error.TestUnexpectedResult;
    };
    var c = contract;
    defer deinitContract(allocator, &c);

    try std.testing.expectEqualStrings("Do X", c.task_summary);
}

test "parseContractJson rejects invalid" {
    const allocator = std.testing.allocator;
    try std.testing.expect(parseContractJson(allocator, "not json", "s", "m", "sk", 5) == null);
    try std.testing.expect(parseContractJson(allocator, "{}", "s", "m", "sk", 5) == null);
    try std.testing.expect(parseContractJson(allocator, "{\"task_summary\":\"x\"}", "s", "m", "sk", 5) == null);
}

test "parseContractJson respects max_checkpoints" {
    const allocator = std.testing.allocator;
    const json =
        \\{"task_summary":"Big task","checkpoints":[
        \\{"description":"A","check_type":"no_errors"},
        \\{"description":"B","check_type":"no_errors"},
        \\{"description":"C","check_type":"no_errors"},
        \\{"description":"D","check_type":"no_errors"}
        \\]}
    ;

    const contract = parseContractJson(allocator, json, "s", "m", "sk", 2) orelse {
        return error.TestUnexpectedResult;
    };
    var c = contract;
    defer deinitContract(allocator, &c);

    try std.testing.expectEqual(@as(usize, 2), c.checkpoints.len);
}

test "verifyContract all passing" {
    const allocator = std.testing.allocator;
    var checkpoints = try allocator.alloc(Checkpoint, 2);
    defer allocator.free(checkpoints);
    checkpoints[0] = .{ .description = "tools ok", .check_type = .tool_success };
    checkpoints[1] = .{ .description = "no errs", .check_type = .no_errors };

    var contract = TaskContract{
        .session_id = "s1",
        .timestamp = 0,
        .task_summary = "test",
        .checkpoints = checkpoints,
        .model = "m1",
        .skill = "sk1",
    };

    const ctx = TurnContext{
        .tools_called = 3,
        .tools_failed = 0,
        .has_tool_calls = true,
        .max_iterations_hit = false,
    };

    const result = verifyContract(&contract, ctx, "done");
    try std.testing.expectEqual(@as(u8, 2), result.checkpoints_passed);
    try std.testing.expectEqual(@as(u8, 2), result.checkpoints_total);
}

test "verifyContract with failures" {
    const allocator = std.testing.allocator;
    var checkpoints = try allocator.alloc(Checkpoint, 2);
    defer allocator.free(checkpoints);
    checkpoints[0] = .{ .description = "tools ok", .check_type = .tool_success };
    checkpoints[1] = .{ .description = "no errs", .check_type = .no_errors };

    var contract = TaskContract{
        .session_id = "s1",
        .timestamp = 0,
        .task_summary = "test",
        .checkpoints = checkpoints,
        .model = "m1",
        .skill = "sk1",
    };

    const ctx = TurnContext{
        .tools_called = 3,
        .tools_failed = 1,
        .has_tool_calls = true,
        .max_iterations_hit = false,
    };

    const result = verifyContract(&contract, ctx, "error occurred");
    try std.testing.expectEqual(@as(u8, 0), result.checkpoints_passed);
}

test "verifyContract response_contains" {
    const allocator = std.testing.allocator;
    var checkpoints = try allocator.alloc(Checkpoint, 1);
    defer allocator.free(checkpoints);
    const expected = try allocator.dupe(u8, "opgeslagen");
    checkpoints[0] = .{ .description = "confirms save", .check_type = .response_contains, .expected = expected };
    defer allocator.free(expected);

    var contract = TaskContract{
        .session_id = "s1",
        .timestamp = 0,
        .task_summary = "test",
        .checkpoints = checkpoints,
        .model = "m1",
        .skill = "sk1",
    };

    const ctx = TurnContext{};

    const result_pass = verifyContract(&contract, ctx, "Bestand opgeslagen op NAS");
    try std.testing.expectEqual(@as(u8, 1), result_pass.checkpoints_passed);

    // Reset
    checkpoints[0].passed = false;
    const result_fail = verifyContract(&contract, ctx, "Klaar met de taak");
    try std.testing.expectEqual(@as(u8, 0), result_fail.checkpoints_passed);
}
