//! Tools module — agent tool integrations for LLM function calling.
//!
//! Provides a common Tool vtable, ToolResult/ToolSpec types, and implementations
//! for shell execution, file I/O, HTTP requests, git operations, memory tools,
//! scheduling, delegation, browser, and image tools.

const std = @import("std");
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;

// ── JSON arg extraction helpers ─────────────────────────────────
// Used by all tool implementations to extract typed fields from
// the pre-parsed ObjectMap passed by the dispatcher.

pub const JsonObjectMap = std.json.ObjectMap;
pub const JsonValue = std.json.Value;

pub fn getString(args: JsonObjectMap, key: []const u8) ?[]const u8 {
    const val = args.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

pub fn getBool(args: JsonObjectMap, key: []const u8) ?bool {
    const val = args.get(key) orelse return null;
    return switch (val) {
        .bool => |b| b,
        else => null,
    };
}

pub fn getInt(args: JsonObjectMap, key: []const u8) ?i64 {
    const val = args.get(key) orelse return null;
    return switch (val) {
        .integer => |i| i,
        else => null,
    };
}

pub fn getValue(args: JsonObjectMap, key: []const u8) ?JsonValue {
    return args.get(key);
}

/// Test helper: parse a JSON string into a Parsed(Value) for use in tool tests.
/// The caller must `defer parsed.deinit()` and extract `.value.object` for the ObjectMap.
pub fn parseTestArgs(json_str: []const u8) !std.json.Parsed(JsonValue) {
    return std.json.parseFromSlice(JsonValue, std.testing.allocator, json_str, .{});
}

// Sub-modules
pub const shell = @import("shell.zig");
pub const file_read = @import("file_read.zig");
pub const file_write = @import("file_write.zig");
pub const file_edit = @import("file_edit.zig");
pub const http_request = @import("http_request.zig");
pub const git = @import("git.zig");
pub const memory_store = @import("memory_store.zig");
pub const memory_recall = @import("memory_recall.zig");
pub const memory_list = @import("memory_list.zig");
pub const memory_forget = @import("memory_forget.zig");
pub const schedule = @import("schedule.zig");
pub const delegate = @import("delegate.zig");
pub const browser = @import("browser.zig");
pub const image = @import("image.zig");
pub const composio = @import("composio.zig");
pub const screenshot = @import("screenshot.zig");
pub const browser_open = @import("browser_open.zig");
pub const hardware_info = @import("hardware_info.zig");
pub const hardware_memory = @import("hardware_memory.zig");
pub const cron_add = @import("cron_add.zig");
pub const cron_list = @import("cron_list.zig");
pub const cron_remove = @import("cron_remove.zig");
pub const cron_runs = @import("cron_runs.zig");
pub const cron_run = @import("cron_run.zig");
pub const cron_update = @import("cron_update.zig");
pub const message = @import("message.zig");
pub const pushover = @import("pushover.zig");
pub const schema = @import("schema.zig");
pub const web_search = @import("web_search.zig");
pub const web_fetch = @import("web_fetch.zig");
pub const file_append = @import("file_append.zig");
pub const spawn = @import("spawn.zig");
pub const i2c = @import("i2c.zig");
pub const spi = @import("spi.zig");
pub const path_security = @import("path_security.zig");
pub const process_util = @import("process_util.zig");

// ── Core types ──────────────────────────────────────────────────────

/// Result of a tool execution.
///
/// Ownership: both `output` and `error_msg` are owned by the tool that produced them.
/// The caller (agent/dispatcher) must free them with `allocator.free()` after use.
/// Exception: static string literals (e.g. `""`, compile-time constants) must NOT be freed —
/// use `ToolResult.ok("")` or `ToolResult.fail("literal")` for those.
pub const ToolResult = struct {
    success: bool,
    /// Heap-allocated output string owned by caller. Free with allocator.free().
    /// May be an empty literal "" for void results — do NOT free in that case.
    output: []const u8,
    /// Heap-allocated error message owned by caller if non-null. Free with allocator.free().
    error_msg: ?[]const u8 = null,

    /// Create a success result with a static/literal output (do NOT free).
    pub fn ok(output: []const u8) ToolResult {
        return .{ .success = true, .output = output };
    }

    /// Create a failure result with a static/literal error message (do NOT free).
    pub fn fail(err: []const u8) ToolResult {
        return .{ .success = false, .output = "", .error_msg = err };
    }
};

/// Description of a tool for the LLM (function calling schema)
pub const ToolSpec = struct {
    name: []const u8,
    description: []const u8,
    parameters_json: []const u8,
};

/// Tool vtable — implement for any capability.
/// Uses Zig's type-erased interface pattern.
pub const Tool = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        execute: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, args: JsonObjectMap) anyerror!ToolResult,
        name: *const fn (ptr: *anyopaque) []const u8,
        description: *const fn (ptr: *anyopaque) []const u8,
        parameters_json: *const fn (ptr: *anyopaque) []const u8,
        deinit: ?*const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void = null,
    };

    pub fn execute(self: Tool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        return self.vtable.execute(self.ptr, allocator, args);
    }

    pub fn name(self: Tool) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn description(self: Tool) []const u8 {
        return self.vtable.description(self.ptr);
    }

    pub fn parametersJson(self: Tool) []const u8 {
        return self.vtable.parameters_json(self.ptr);
    }

    pub fn spec(self: Tool) ToolSpec {
        return .{
            .name = self.name(),
            .description = self.description(),
            .parameters_json = self.parametersJson(),
        };
    }

    /// Free the heap-allocated backing struct. Safe to call even if
    /// the tool was not heap-allocated (deinit will be null).
    pub fn deinit(self: Tool, allocator: std.mem.Allocator) void {
        if (self.vtable.deinit) |deinit_fn| {
            deinit_fn(self.ptr, allocator);
        }
    }
};

/// Generate a Tool.VTable from a tool struct type at comptime.
///
/// The type T must declare:
///   - `pub const tool_name: []const u8`
///   - `pub const tool_description: []const u8`
///   - `pub const tool_params: []const u8`
///   - `fn execute(self: *T, allocator: Allocator, args: JsonObjectMap) anyerror!ToolResult`
pub fn ToolVTable(comptime T: type) Tool.VTable {
    return .{
        .execute = &struct {
            fn f(ptr: *anyopaque, allocator: std.mem.Allocator, args: JsonObjectMap) anyerror!ToolResult {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.execute(allocator, args);
            }
        }.f,
        .name = &struct {
            fn f(_: *anyopaque) []const u8 {
                return T.tool_name;
            }
        }.f,
        .description = &struct {
            fn f(_: *anyopaque) []const u8 {
                return T.tool_description;
            }
        }.f,
        .parameters_json = &struct {
            fn f(_: *anyopaque) []const u8 {
                return T.tool_params;
            }
        }.f,
        .deinit = &struct {
            fn f(ptr: *anyopaque, allocator: std.mem.Allocator) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                allocator.destroy(self);
            }
        }.f,
    };
}

/// Comptime check that a type correctly implements the Tool interface.
pub fn assertToolInterface(comptime T: type) void {
    if (!@hasDecl(T, "tool")) @compileError(@typeName(T) ++ " missing tool() method");
    if (!@hasDecl(T, "vtable")) @compileError(@typeName(T) ++ " missing vtable constant");
    const vt = T.vtable;
    _ = vt.execute;
    _ = vt.name;
    _ = vt.description;
    _ = vt.parameters_json;
}

/// Create the default tool set (shell, file_read, file_write).
pub fn defaultTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
) ![]Tool {
    return defaultToolsWithPaths(allocator, workspace_dir, &.{});
}

/// Create the default tool set with additional allowed paths.
pub fn defaultToolsWithPaths(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    allowed_paths: []const []const u8,
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer {
        for (list.items) |t| {
            t.deinit(allocator);
        }
        list.deinit(allocator);
    }

    const st = try allocator.create(shell.ShellTool);
    st.* = .{ .workspace_dir = workspace_dir, .allowed_paths = allowed_paths };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir, .allowed_paths = allowed_paths };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir, .allowed_paths = allowed_paths };
    try list.append(allocator, wt.tool());

    const et = try allocator.create(file_edit.FileEditTool);
    et.* = .{ .workspace_dir = workspace_dir, .allowed_paths = allowed_paths };
    try list.append(allocator, et.tool());

    return list.toOwnedSlice(allocator);
}

/// Create all tools including optional ones.
pub fn allTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    opts: struct {
        http_enabled: bool = false,
        http_allowed_domains: []const []const u8 = &.{},
        http_max_response_size: u32 = 1_000_000,
        http_timeout_secs: u64 = 30,
        web_search_base_url: ?[]const u8 = null,
        web_search_provider: []const u8 = "auto",
        web_search_fallback_providers: []const []const u8 = &.{},
        browser_enabled: bool = false,
        screenshot_enabled: bool = false,
        composio_api_key: ?[]const u8 = null,
        browser_open_domains: ?[]const []const u8 = null,
        hardware_boards: ?[]const []const u8 = null,
        mcp_tools: ?[]const Tool = null,
        agents: ?[]const @import("../config.zig").NamedAgentConfig = null,
        fallback_api_key: ?[]const u8 = null,
        delegate_depth: u32 = 0,
        subagent_manager: ?*@import("../subagent.zig").SubagentManager = null,
        allowed_paths: []const []const u8 = &.{},
        tools_config: @import("../config.zig").ToolsConfig = .{},
        policy: ?*const @import("../security/policy.zig").SecurityPolicy = null,
    },
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer {
        for (list.items) |t| {
            t.deinit(allocator);
        }
        list.deinit(allocator);
    }

    // Core tools with workspace_dir + allowed_paths + tools_config limits
    const tc = opts.tools_config;

    const st = try allocator.create(shell.ShellTool);
    st.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .timeout_ns = tc.shell_timeout_secs * std.time.ns_per_s,
        .max_output_bytes = tc.shell_max_output_bytes,
        .policy = opts.policy,
    };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths, .max_file_size = tc.max_file_size_bytes };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths };
    try list.append(allocator, wt.tool());

    const et2 = try allocator.create(file_edit.FileEditTool);
    et2.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths, .max_file_size = tc.max_file_size_bytes };
    try list.append(allocator, et2.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    // Tools without workspace_dir
    const it = try allocator.create(image.ImageInfoTool);
    it.* = .{};
    try list.append(allocator, it.tool());

    // Memory tools (work gracefully without a backend)
    const mst = try allocator.create(memory_store.MemoryStoreTool);
    mst.* = .{};
    try list.append(allocator, mst.tool());

    const mrt = try allocator.create(memory_recall.MemoryRecallTool);
    mrt.* = .{};
    try list.append(allocator, mrt.tool());

    const mlt = try allocator.create(memory_list.MemoryListTool);
    mlt.* = .{};
    try list.append(allocator, mlt.tool());

    const mft = try allocator.create(memory_forget.MemoryForgetTool);
    mft.* = .{};
    try list.append(allocator, mft.tool());

    // Delegate and schedule tools
    const dlt = try allocator.create(delegate.DelegateTool);
    dlt.* = .{
        .agents = opts.agents orelse &.{},
        .fallback_api_key = opts.fallback_api_key,
        .depth = opts.delegate_depth,
    };
    try list.append(allocator, dlt.tool());

    const scht = try allocator.create(schedule.ScheduleTool);
    scht.* = .{};
    try list.append(allocator, scht.tool());

    // Spawn tool (async subagent)
    const sp = try allocator.create(spawn.SpawnTool);
    sp.* = .{ .manager = opts.subagent_manager };
    try list.append(allocator, sp.tool());

    if (opts.http_enabled) {
        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{
            .allowed_domains = opts.http_allowed_domains,
            .max_response_size = opts.http_max_response_size,
        };
        try list.append(allocator, ht.tool());

        const wst = try allocator.create(web_search.WebSearchTool);
        wst.* = .{
            .searxng_base_url = opts.web_search_base_url,
            .provider = opts.web_search_provider,
            .fallback_providers = opts.web_search_fallback_providers,
            .timeout_secs = opts.http_timeout_secs,
        };
        try list.append(allocator, wst.tool());

        const wft = try allocator.create(web_fetch.WebFetchTool);
        wft.* = .{ .default_max_chars = tc.web_fetch_max_chars };
        try list.append(allocator, wft.tool());
    }

    if (opts.browser_enabled) {
        const bt = try allocator.create(browser.BrowserTool);
        bt.* = .{};
        try list.append(allocator, bt.tool());
    }

    if (opts.screenshot_enabled) {
        const sst = try allocator.create(screenshot.ScreenshotTool);
        sst.* = .{ .workspace_dir = workspace_dir };
        try list.append(allocator, sst.tool());
    }

    if (opts.composio_api_key) |api_key| {
        const ct = try allocator.create(composio.ComposioTool);
        ct.* = .{ .api_key = api_key, .entity_id = "default" };
        try list.append(allocator, ct.tool());
    }

    if (opts.browser_open_domains) |domains| {
        const bot = try allocator.create(browser_open.BrowserOpenTool);
        bot.* = .{ .allowed_domains = domains };
        try list.append(allocator, bot.tool());
    }

    if (opts.hardware_boards) |boards| {
        const hbi = try allocator.create(hardware_info.HardwareBoardInfoTool);
        hbi.* = .{ .boards = boards };
        try list.append(allocator, hbi.tool());

        const hmt = try allocator.create(hardware_memory.HardwareMemoryTool);
        hmt.* = .{ .boards = boards };
        try list.append(allocator, hmt.tool());

        const i2ct = try allocator.create(i2c.I2cTool);
        i2ct.* = .{};
        try list.append(allocator, i2ct.tool());
    }

    // MCP tools (pre-initialized externally)
    if (opts.mcp_tools) |mt| {
        for (mt) |t| {
            try list.append(allocator, t);
        }
    }

    return list.toOwnedSlice(allocator);
}

/// Bind a memory backend to memory tools in a pre-built tool list.
pub fn bindMemoryTools(tools: []const Tool, memory: ?Memory) void {
    for (tools) |t| {
        if (t.vtable == &memory_store.MemoryStoreTool.vtable) {
            const mt: *memory_store.MemoryStoreTool = @ptrCast(@alignCast(t.ptr));
            mt.memory = memory;
        } else if (t.vtable == &memory_recall.MemoryRecallTool.vtable) {
            const mt: *memory_recall.MemoryRecallTool = @ptrCast(@alignCast(t.ptr));
            mt.memory = memory;
        } else if (t.vtable == &memory_list.MemoryListTool.vtable) {
            const mt: *memory_list.MemoryListTool = @ptrCast(@alignCast(t.ptr));
            mt.memory = memory;
        } else if (t.vtable == &memory_forget.MemoryForgetTool.vtable) {
            const mt: *memory_forget.MemoryForgetTool = @ptrCast(@alignCast(t.ptr));
            mt.memory = memory;
        }
    }
}

/// Bind a MemoryRuntime to memory tools for retrieval pipeline and vector sync.
/// Call after bindMemoryTools to enable hybrid search and vector sync.
pub fn bindMemoryRuntime(tools: []const Tool, mem_rt: ?*memory_mod.MemoryRuntime) void {
    for (tools) |t| {
        if (t.vtable == &memory_store.MemoryStoreTool.vtable) {
            const mt: *memory_store.MemoryStoreTool = @ptrCast(@alignCast(t.ptr));
            mt.mem_rt = mem_rt;
        } else if (t.vtable == &memory_recall.MemoryRecallTool.vtable) {
            const mt: *memory_recall.MemoryRecallTool = @ptrCast(@alignCast(t.ptr));
            mt.mem_rt = mem_rt;
        } else if (t.vtable == &memory_forget.MemoryForgetTool.vtable) {
            const mt: *memory_forget.MemoryForgetTool = @ptrCast(@alignCast(t.ptr));
            mt.mem_rt = mem_rt;
        }
    }
}

/// Free all heap-allocated tool structs and the tools slice itself.
/// Pairs with `allTools` / `defaultTools` / `subagentTools`.
pub fn deinitTools(allocator: std.mem.Allocator, tools: []const Tool) void {
    for (tools) |t| {
        t.deinit(allocator);
    }
    allocator.free(tools);
}

/// Create restricted tool set for subagents.
/// Includes: shell, file_read, file_write, file_edit, git, http (if enabled).
/// Excludes: message, spawn, delegate, schedule, memory, composio, browser —
/// to prevent infinite loops and cross-channel side effects.
pub fn subagentTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    opts: struct {
        http_enabled: bool = false,
        allowed_paths: []const []const u8 = &.{},
        policy: ?*const @import("../security/policy.zig").SecurityPolicy = null,
    },
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer {
        for (list.items) |t| {
            t.deinit(allocator);
        }
        list.deinit(allocator);
    }

    const st = try allocator.create(shell.ShellTool);
    st.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths, .policy = opts.policy };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths };
    try list.append(allocator, wt.tool());

    const et = try allocator.create(file_edit.FileEditTool);
    et.* = .{ .workspace_dir = workspace_dir, .allowed_paths = opts.allowed_paths };
    try list.append(allocator, et.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    if (opts.http_enabled) {
        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{};
        try list.append(allocator, ht.tool());
    }

    return list.toOwnedSlice(allocator);
}

// ── Tests ───────────────────────────────────────────────────────────

test "getString returns unescaped newlines and tabs" {
    const parsed = try parseTestArgs("{\"content\":\"line1\\nline2\\ttab\"}");
    defer parsed.deinit();
    const val = getString(parsed.value.object, "content").?;
    try std.testing.expectEqualStrings("line1\nline2\ttab", val);
}

test "getString returns unescaped quotes and backslashes" {
    const parsed = try parseTestArgs("{\"s\":\"say \\\"hello\\\" path\\\\dir\"}");
    defer parsed.deinit();
    const val = getString(parsed.value.object, "s").?;
    try std.testing.expectEqualStrings("say \"hello\" path\\dir", val);
}

test "getString returns unescaped unicode" {
    // \u0041 = A, \u00c9 = É
    const parsed = try parseTestArgs("{\"s\":\"\\u0041BC \\u00c9\\u00f6\\u00fc\\u00e4\\u00e8\"}");
    defer parsed.deinit();
    const val = getString(parsed.value.object, "s").?;
    try std.testing.expectEqualStrings("ABC Éöüäè", val);
}

test "getString returns unescaped shell script content" {
    const parsed = try parseTestArgs("{\"content\":\"#!/bin/bash\\necho \\\"hello\\\"\\nexit 0\"}");
    defer parsed.deinit();
    const val = getString(parsed.value.object, "content").?;
    try std.testing.expectEqualStrings("#!/bin/bash\necho \"hello\"\nexit 0", val);
}

test "getString returns null for missing key" {
    const parsed = try parseTestArgs("{\"other\":\"val\"}");
    defer parsed.deinit();
    try std.testing.expect(getString(parsed.value.object, "content") == null);
}

test "getString returns null for non-string value" {
    const parsed = try parseTestArgs("{\"count\":42}");
    defer parsed.deinit();
    try std.testing.expect(getString(parsed.value.object, "count") == null);
}

test "getBool extracts boolean values" {
    const parsed = try parseTestArgs("{\"a\":true,\"b\":false}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?bool, true), getBool(parsed.value.object, "a"));
    try std.testing.expectEqual(@as(?bool, false), getBool(parsed.value.object, "b"));
    try std.testing.expect(getBool(parsed.value.object, "missing") == null);
}

test "getInt extracts integer values" {
    const parsed = try parseTestArgs("{\"n\":42,\"neg\":-5}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?i64, 42), getInt(parsed.value.object, "n"));
    try std.testing.expectEqual(@as(?i64, -5), getInt(parsed.value.object, "neg"));
    try std.testing.expect(getInt(parsed.value.object, "missing") == null);
}

test "tool result ok" {
    const r = ToolResult.ok("hello");
    try std.testing.expect(r.success);
    try std.testing.expectEqualStrings("hello", r.output);
    try std.testing.expect(r.error_msg == null);
}

test "tool result fail" {
    const r = ToolResult.fail("boom");
    try std.testing.expect(!r.success);
    try std.testing.expectEqualStrings("", r.output);
    try std.testing.expectEqualStrings("boom", r.error_msg.?);
}

test "default tools returns four" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        // Free the heap-allocated tool structs
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    try std.testing.expectEqual(@as(usize, 4), tools.len);

    // Verify names
    try std.testing.expectEqualStrings("shell", tools[0].name());
    try std.testing.expectEqualStrings("file_read", tools[1].name());
    try std.testing.expectEqualStrings("file_write", tools[2].name());
    try std.testing.expectEqualStrings("file_edit", tools[3].name());
}

test "all tools has descriptions" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        try std.testing.expect(t.description().len > 0);
    }
}

test "all tools have parameter schemas" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        const json = t.parametersJson();
        try std.testing.expect(json.len > 0);
        // Should be valid JSON object
        try std.testing.expect(json[0] == '{');
    }
}

test "tool spec generation" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        const s = t.spec();
        try std.testing.expectEqualStrings(t.name(), s.name);
        try std.testing.expectEqualStrings(t.description(), s.description);
        try std.testing.expect(s.parameters_json.len > 0);
    }
}

test "all tools includes extras when enabled" {
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{
        .http_enabled = true,
        .browser_enabled = true,
    });
    defer deinitTools(std.testing.allocator, tools);

    // Order: shell, file_read, file_write, file_edit, git, image_info,
    //        memory_store, memory_recall, memory_list, memory_forget,
    //        delegate, schedule, spawn, http_request, web_search, web_fetch,
    //        browser = 17
    try std.testing.expectEqual(@as(usize, 17), tools.len);
}

test "all tools excludes extras when disabled" {
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{});
    defer deinitTools(std.testing.allocator, tools);

    // Order: shell, file_read, file_write, file_edit, git, image_info,
    //        memory_store, memory_recall, memory_list, memory_forget,
    //        delegate, schedule, spawn = 13
    try std.testing.expectEqual(@as(usize, 13), tools.len);
}

test "all tools wires http and web_search config into tool instances" {
    const domains = [_][]const u8{ "example.com", "api.example.com" };
    const search_url = "https://searx.example.com";
    const search_fallbacks = [_][]const u8{ "jina", "duckduckgo" };

    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{
        .http_enabled = true,
        .http_allowed_domains = &domains,
        .http_max_response_size = 321_000,
        .http_timeout_secs = 12,
        .web_search_base_url = search_url,
        .web_search_provider = "brave",
        .web_search_fallback_providers = &search_fallbacks,
    });
    defer deinitTools(std.testing.allocator, tools);

    var saw_http = false;
    var saw_search = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "http_request")) {
            const ht: *http_request.HttpRequestTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(usize, 2), ht.allowed_domains.len);
            try std.testing.expectEqualStrings("example.com", ht.allowed_domains[0]);
            try std.testing.expectEqual(@as(u32, 321_000), ht.max_response_size);
            saw_http = true;
            continue;
        }
        if (std.mem.eql(u8, t.name(), "web_search")) {
            const wst: *web_search.WebSearchTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqualStrings(search_url, wst.searxng_base_url.?);
            try std.testing.expectEqualStrings("brave", wst.provider);
            try std.testing.expectEqual(@as(usize, 2), wst.fallback_providers.len);
            try std.testing.expectEqualStrings("jina", wst.fallback_providers[0]);
            try std.testing.expectEqual(@as(u64, 12), wst.timeout_secs);
            saw_search = true;
        }
    }

    try std.testing.expect(saw_http);
    try std.testing.expect(saw_search);
}

test "all tools wires subagent manager into spawn tool" {
    const Config = @import("../config.zig").Config;
    const subagent_mod = @import("../subagent.zig");

    var cfg = Config{
        .workspace_dir = "/tmp/yc_test",
        .config_path = "/tmp/yc_test/config.json",
        .allocator = std.testing.allocator,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer manager.deinit();

    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{
        .subagent_manager = &manager,
    });
    defer deinitTools(std.testing.allocator, tools);

    var checked_spawn = false;
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name(), "spawn")) continue;
        const spawn_tool: *spawn.SpawnTool = @ptrCast(@alignCast(t.ptr));
        try std.testing.expect(spawn_tool.manager == &manager);
        checked_spawn = true;
        break;
    }
    try std.testing.expect(checked_spawn);
}

test "bindMemoryTools matches by vtable, not by colliding tool name" {
    const FakeCollidingTool = struct {
        sentinel: usize = 0xDEADBEEF,

        pub const tool_name = "memory_store";
        pub const tool_description = "fake";
        pub const tool_params = "{}";
        pub const vtable = ToolVTable(@This());

        pub fn tool(self: *@This()) Tool {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        pub fn execute(_: *@This(), _: std.mem.Allocator, _: JsonObjectMap) anyerror!ToolResult {
            return ToolResult.ok("");
        }
    };

    const NoneMemory = @import("../memory/root.zig").NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var real_memory_store = memory_store.MemoryStoreTool{};
    var fake_memory_store_name = FakeCollidingTool{};
    const tools = [_]Tool{
        real_memory_store.tool(),
        fake_memory_store_name.tool(),
    };

    bindMemoryTools(&tools, backend.memory());

    try std.testing.expect(real_memory_store.memory != null);
    try std.testing.expectEqual(@as(usize, 0xDEADBEEF), fake_memory_store_name.sentinel);
}

test {
    @import("std").testing.refAllDecls(@This());
}
