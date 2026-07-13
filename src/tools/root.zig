//! Tools module — agent tool integrations for LLM function calling.
//!
//! Provides a common Tool vtable, ToolResult/ToolSpec types, and implementations
//! for shell execution, file I/O, HTTP requests, git operations, memory tools,
//! scheduling, delegation, browser, and image tools.

const std = @import("std");
const builtin = @import("builtin");
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const bootstrap_mod = @import("../bootstrap/root.zig");
const config_types = @import("../config_types.zig");
const mcp_mod = @import("../mcp.zig");
const SandboxBackend = @import("../security/sandbox.zig").SandboxBackend;
const ConfigSandboxBackend = @import("../config.zig").SandboxBackend;

fn mapConfigSandboxBackend(backend: ConfigSandboxBackend) SandboxBackend {
    return switch (backend) {
        .auto => .auto,
        .landlock => .landlock,
        .firejail => .firejail,
        .bubblewrap => .bubblewrap,
        .docker => .docker,
        .none => .none,
    };
}

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

pub fn getStringArray(args: JsonObjectMap, key: []const u8) ?[]const JsonValue {
    const val = args.get(key) orelse return null;
    return switch (val) {
        .array => |a| a.items,
        else => null,
    };
}

/// Test helper: parse a JSON string into a Parsed(Value) for use in tool tests.
/// The caller must `defer parsed.deinit()` and extract `.value.object` for the ObjectMap.
pub fn parseTestArgs(json_str: []const u8) !std.json.Parsed(JsonValue) {
    return std.json.parseFromSlice(JsonValue, std.testing.allocator, json_str, .{});
}

threadlocal var tls_memory_session_id: ?[]const u8 = null;

pub fn setThreadMemorySessionId(session_id: ?[]const u8) ?[]const u8 {
    const previous = tls_memory_session_id;
    tls_memory_session_id = session_id;
    return previous;
}

pub fn threadMemorySessionId() ?[]const u8 {
    return tls_memory_session_id;
}

/// Exact tool invocation authorized by a one-shot user approval.
///
/// The slices are borrowed for the duration of the synchronous `Tool.execute`
/// call. Keeping every security-relevant shell input in the grant prevents a
/// broad ambient boolean from authorizing another invocation on the thread.
pub const ApprovalGrant = struct {
    tool_name: []const u8,
    command: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
};

threadlocal var tls_approval_grant: ?ApprovalGrant = null;

pub fn setThreadApprovalGrant(grant: ?ApprovalGrant) ?ApprovalGrant {
    const previous = tls_approval_grant;
    tls_approval_grant = grant;
    return previous;
}

pub fn threadCommandApproved(tool_name: []const u8, command: []const u8, cwd: ?[]const u8) bool {
    const grant = tls_approval_grant orelse return false;
    if (!std.ascii.eqlIgnoreCase(grant.tool_name, tool_name)) return false;
    const approved_command = grant.command orelse return false;
    if (!std.mem.eql(u8, approved_command, command)) return false;
    if (grant.cwd) |approved_cwd| {
        const requested_cwd = cwd orelse return false;
        return std.mem.eql(u8, approved_cwd, requested_cwd);
    }
    return cwd == null;
}

// Sub-modules
pub const shell = @import("shell.zig");
pub const file_read = @import("file_read.zig");
pub const file_write = @import("file_write.zig");
pub const file_edit = @import("file_edit.zig");
pub const file_delete = @import("file_delete.zig");
pub const file_read_hashed = @import("file_read_hashed.zig");
pub const file_edit_hashed = @import("file_edit_hashed.zig");
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
pub const calculator = @import("calculator.zig");
pub const sqlite_query = @import("sqlite_query.zig");
pub const anonymize_text = @import("anonymize_text.zig");

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
    custom_description: ?[]const u8 = null,

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
        if (self.custom_description) |desc| return desc;
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

fn findToolCustomization(customizations: []const config_types.ToolCustomization, tool_name: []const u8) ?config_types.ToolCustomization {
    for (customizations) |cust| {
        if (std.mem.eql(u8, tool_name, cust.name)) return cust;
    }
    return null;
}

fn applyToolCustomizations(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Tool),
    customizations: []const config_types.ToolCustomization,
) void {
    if (customizations.len == 0) return;

    var write_idx: usize = 0;
    for (list.items) |*tool_item| {
        if (findToolCustomization(customizations, tool_item.name())) |cust| {
            if (!cust.enabled) {
                tool_item.deinit(allocator);
                continue;
            }
            if (cust.system_prompt) |prompt| {
                tool_item.custom_description = prompt;
            }
        }

        list.items[write_idx] = tool_item.*;
        write_idx += 1;
    }
    list.shrinkRetainingCapacity(write_idx);
}

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

/// Create the default tool set (shell, file_read, file_write, file_edit, file_append).
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
    var list: std.ArrayList(Tool) = .empty;
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

    const fa = try allocator.create(file_append.FileAppendTool);
    fa.* = .{ .workspace_dir = workspace_dir, .allowed_paths = allowed_paths };
    try list.append(allocator, fa.tool());

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
        mcp_server_configs: []const @import("../config_types.zig").McpServerConfig = &.{},
        agents: ?[]const @import("../config.zig").NamedAgentConfig = null,
        configured_providers: []const @import("../config_types.zig").ProviderEntry = &.{},
        fallback_api_key: ?[]const u8 = null,
        delegate_depth: u32 = 0,
        subagent_manager: ?*@import("../subagent.zig").SubagentManager = null,
        allowed_paths: []const []const u8 = &.{},
        tools_config: @import("../config.zig").ToolsConfig = .{},
        policy: ?*const @import("../security/policy.zig").SecurityPolicy = null,
        bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
        backend_name: []const u8 = "hybrid",
        sandbox_backend: ConfigSandboxBackend = .auto,
        sandbox_enabled: bool = true,
    },
) ![]Tool {
    var list: std.ArrayList(Tool) = .empty;
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
        .path_env_vars = tc.path_env_vars,
    };
    if (opts.sandbox_enabled and comptime builtin.os.tag != .windows) {
        // Windows shells use cmd.exe/PowerShell, which Unix-oriented sandboxes
        // cannot wrap without breaking command execution semantics.
        // Delay sandbox auto-detection until the shell tool is actually used so
        // channel/runtime startup does not spawn probe children preemptively.
        st.sandbox_backend = mapConfigSandboxBackend(opts.sandbox_backend);
        st.sandbox_allocator = allocator;
    }
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, wt.tool());

    const et2 = try allocator.create(file_edit.FileEditTool);
    et2.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, et2.tool());

    const fa = try allocator.create(file_append.FileAppendTool);
    fa.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, fa.tool());

    const dt = try allocator.create(file_delete.FileDeleteTool);
    dt.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, dt.tool());

    const frh = try allocator.create(file_read_hashed.FileReadHashedTool);
    frh.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
    };
    try list.append(allocator, frh.tool());

    const feh = try allocator.create(file_edit_hashed.FileEditHashedTool);
    feh.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
    };
    try list.append(allocator, feh.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    // Tools without workspace_dir
    const it = try allocator.create(image.ImageInfoTool);
    it.* = .{};
    try list.append(allocator, it.tool());

    const calt = try allocator.create(calculator.CalculatorTool);
    calt.* = .{};
    try list.append(allocator, calt.tool());

    const sqt = try allocator.create(sqlite_query.SqliteQueryTool);
    sqt.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
    };
    try list.append(allocator, sqt.tool());

    const ant = try allocator.create(anonymize_text.AnonymizeTextTool);
    ant.* = .{};
    try list.append(allocator, ant.tool());

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
        .configured_providers = opts.configured_providers,
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
        // Pushover notification tool (network egress, gated with HTTP tools).
        const pt = try allocator.create(pushover.PushoverTool);
        pt.* = .{ .workspace_dir = workspace_dir };
        try list.append(allocator, pt.tool());

        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{
            .allowed_domains = opts.http_allowed_domains,
            .max_response_size = opts.http_max_response_size,
            .timeout_secs = opts.http_timeout_secs,
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
        wft.* = .{
            .default_max_chars = tc.web_fetch_max_chars,
            .allowed_domains = opts.http_allowed_domains,
        };
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

    // MCP tools — connect to configured servers and register their tools.
    if (opts.mcp_server_configs.len > 0) {
        const mcp_tools = mcp_mod.initMcpTools(allocator, opts.mcp_server_configs) catch |err| blk: {
            std.log.warn("allTools: MCP init failed: {}", .{err});
            break :blk &[_]Tool{};
        };
        // mcp_tools backing slice is a temporary; append each Tool then free it.
        defer allocator.free(mcp_tools);
        for (mcp_tools) |t| {
            try list.append(allocator, t);
        }
    }

    applyToolCustomizations(allocator, &list, opts.tools_config.tool_customizations);

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
/// Includes: shell, file_read, file_write, file_edit, file_append, file_delete,
/// file_read_hashed, file_edit_hashed, git, http (if enabled).
/// Excludes: message, spawn, delegate, schedule, memory, composio, browser —
/// to prevent infinite loops and cross-channel side effects.
pub fn subagentTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    opts: struct {
        http_enabled: bool = false,
        http_allowed_domains: []const []const u8 = &.{},
        http_max_response_size: u32 = 1_000_000,
        http_timeout_secs: u64 = 30,
        allowed_paths: []const []const u8 = &.{},
        policy: ?*const @import("../security/policy.zig").SecurityPolicy = null,
        tools_config: @import("../config.zig").ToolsConfig = .{},
        bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
        backend_name: []const u8 = "hybrid",
    },
) ![]Tool {
    var list: std.ArrayList(Tool) = .empty;
    errdefer {
        for (list.items) |t| {
            t.deinit(allocator);
        }
        list.deinit(allocator);
    }

    const tc = opts.tools_config;

    const st = try allocator.create(shell.ShellTool);
    st.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .timeout_ns = tc.shell_timeout_secs * std.time.ns_per_s,
        .max_output_bytes = tc.shell_max_output_bytes,
        .policy = opts.policy,
        .path_env_vars = tc.path_env_vars,
    };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, wt.tool());

    const et = try allocator.create(file_edit.FileEditTool);
    et.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, et.tool());

    const fa = try allocator.create(file_append.FileAppendTool);
    fa.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, fa.tool());

    const dt = try allocator.create(file_delete.FileDeleteTool);
    dt.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .bootstrap_provider = opts.bootstrap_provider,
        .backend_name = opts.backend_name,
    };
    try list.append(allocator, dt.tool());

    const frh = try allocator.create(file_read_hashed.FileReadHashedTool);
    frh.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
    };
    try list.append(allocator, frh.tool());

    const feh = try allocator.create(file_edit_hashed.FileEditHashedTool);
    feh.* = .{
        .workspace_dir = workspace_dir,
        .allowed_paths = opts.allowed_paths,
        .max_file_size = tc.max_file_size_bytes,
    };
    try list.append(allocator, feh.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    if (opts.http_enabled) {
        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{
            .allowed_domains = opts.http_allowed_domains,
            .max_response_size = opts.http_max_response_size,
            .timeout_secs = opts.http_timeout_secs,
        };
        try list.append(allocator, ht.tool());
    }

    applyToolCustomizations(allocator, &list, opts.tools_config.tool_customizations);

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

test "default tools returns five" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        // Free the heap-allocated tool structs
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.destroy(@as(*file_append.FileAppendTool, @ptrCast(@alignCast(tools[4].ptr))));
        std.testing.allocator.free(tools);
    }
    try std.testing.expectEqual(@as(usize, 5), tools.len);

    // Verify names
    try std.testing.expectEqualStrings("shell", tools[0].name());
    try std.testing.expectEqualStrings("file_read", tools[1].name());
    try std.testing.expectEqualStrings("file_write", tools[2].name());
    try std.testing.expectEqualStrings("file_edit", tools[3].name());
    try std.testing.expectEqualStrings("file_append", tools[4].name());
}

test "all tools has descriptions" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.destroy(@as(*file_append.FileAppendTool, @ptrCast(@alignCast(tools[4].ptr))));
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
        std.testing.allocator.destroy(@as(*file_append.FileAppendTool, @ptrCast(@alignCast(tools[4].ptr))));
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
        std.testing.allocator.destroy(@as(*file_append.FileAppendTool, @ptrCast(@alignCast(tools[4].ptr))));
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

    // Order: shell, file_read, file_write, file_edit, file_append, file_delete,
    //        file_read_hashed, file_edit_hashed, git, image_info, calculator,
    //        sqlite_query, anonymize_text, memory_store, memory_recall,
    //        memory_list, memory_forget, delegate, schedule, spawn, pushover,
    //        http_request, web_search, web_fetch, browser = 25
    try std.testing.expectEqual(@as(usize, 25), tools.len);
}

test "all tools excludes extras when disabled" {
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{});
    defer deinitTools(std.testing.allocator, tools);

    // Order: shell, file_read, file_write, file_edit, file_append, file_delete,
    //        file_read_hashed, file_edit_hashed, git, image_info, calculator,
    //        sqlite_query, anonymize_text, memory_store, memory_recall,
    //        memory_list, memory_forget, delegate, schedule, spawn = 20
    try std.testing.expectEqual(@as(usize, 20), tools.len);
}

test "all tools apply configured descriptions and enabled filters" {
    const customizations = [_]config_types.ToolCustomization{
        .{ .name = "shell", .enabled = false },
        .{ .name = "file_read", .system_prompt = "Read only small files" },
    };

    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{
        .tools_config = .{ .tool_customizations = &customizations },
    });
    defer deinitTools(std.testing.allocator, tools);

    var saw_shell = false;
    var saw_file_read = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "shell")) saw_shell = true;
        if (std.mem.eql(u8, t.name(), "file_read")) {
            saw_file_read = true;
            try std.testing.expectEqualStrings("Read only small files", t.description());
        }
    }

    try std.testing.expect(!saw_shell);
    try std.testing.expect(saw_file_read);
    try std.testing.expectEqual(@as(usize, 19), tools.len);
}

test "all tools defers shell sandbox initialization by default" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{});
    defer deinitTools(std.testing.allocator, tools);

    var saw_shell = false;
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name(), "shell")) continue;
        const st: *shell.ShellTool = @ptrCast(@alignCast(t.ptr));
        try std.testing.expect(st.sandbox == null);
        try std.testing.expectEqual(SandboxBackend.auto, st.sandbox_backend.?);
        try std.testing.expect(st.sandbox_allocator != null);
        saw_shell = true;
        break;
    }

    try std.testing.expect(saw_shell);
}

test "all tools skips shell sandbox wiring on windows" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;

    const tools = try allTools(std.testing.allocator, "C:\\tmp\\yc_test", .{
        .sandbox_enabled = true,
        .sandbox_backend = .docker,
    });
    defer deinitTools(std.testing.allocator, tools);

    for (tools) |t| {
        if (!std.mem.eql(u8, t.name(), "shell")) continue;
        const st: *shell.ShellTool = @ptrCast(@alignCast(t.ptr));
        try std.testing.expect(st.sandbox == null);
        return;
    }

    return error.TestUnexpectedResult;
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
    var saw_fetch = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "http_request")) {
            const ht: *http_request.HttpRequestTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(usize, 2), ht.allowed_domains.len);
            try std.testing.expectEqualStrings("example.com", ht.allowed_domains[0]);
            try std.testing.expectEqual(@as(u32, 321_000), ht.max_response_size);
            try std.testing.expectEqual(@as(u64, 12), ht.timeout_secs);
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
            continue;
        }
        if (std.mem.eql(u8, t.name(), "web_fetch")) {
            const wft: *web_fetch.WebFetchTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(usize, 2), wft.allowed_domains.len);
            try std.testing.expectEqualStrings("example.com", wft.allowed_domains[0]);
            saw_fetch = true;
        }
    }

    try std.testing.expect(saw_http);
    try std.testing.expect(saw_search);
    try std.testing.expect(saw_fetch);
}

test "all tools wire bootstrap provider into bootstrap-aware file tools for sqlite backends" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var lru = memory_mod.InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    const provider = bp_impl.provider();
    try provider.store("USER.md", "name: Igor");

    const tools = try allTools(std.testing.allocator, ws_path, .{
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = provider,
        .backend_name = "sqlite",
    });
    defer deinitTools(std.testing.allocator, tools);

    var checked_read = false;
    var checked_append = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "file_read")) {
            const ft: *file_read.FileReadTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expect(ft.bootstrap_provider != null);
            try std.testing.expectEqualStrings("sqlite", ft.backend_name);

            const parsed = try parseTestArgs("{\"path\": \"USER.md\"}");
            defer parsed.deinit();
            const result = try t.execute(std.testing.allocator, parsed.value.object);
            defer if (result.output.len > 0) std.testing.allocator.free(result.output);
            defer if (result.error_msg) |e| std.testing.allocator.free(e);

            try std.testing.expect(result.success);
            try std.testing.expectEqualStrings("name: Igor", result.output);
            checked_read = true;
            continue;
        }

        if (std.mem.eql(u8, t.name(), "file_append")) {
            const fa: *file_append.FileAppendTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expect(fa.bootstrap_provider != null);
            try std.testing.expectEqualStrings("sqlite", fa.backend_name);

            const parsed = try parseTestArgs("{\"path\": \"USER.md\", \"content\": \"\\nrole: coder\"}");
            defer parsed.deinit();
            const result = try t.execute(std.testing.allocator, parsed.value.object);
            defer if (result.output.len > 0) std.testing.allocator.free(result.output);
            defer if (result.error_msg) |e| std.testing.allocator.free(e);

            try std.testing.expect(result.success);
            checked_append = true;
        }
    }

    const appended = try provider.load(std.testing.allocator, "USER.md") orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(appended);
    try std.testing.expectEqualStrings("name: Igor\nrole: coder", appended);
    try std.testing.expect(checked_read);
    try std.testing.expect(checked_append);
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

test "subagent tools use configured shell and file limits" {
    const tools = try subagentTools(std.testing.allocator, "/tmp/yc_test", .{
        .tools_config = .{
            .shell_timeout_secs = 7,
            .shell_max_output_bytes = 2048,
            .max_file_size_bytes = 4096,
        },
    });
    defer deinitTools(std.testing.allocator, tools);

    var saw_shell = false;
    var saw_file_read = false;
    var saw_file_edit = false;
    var saw_file_read_hashed = false;
    var saw_file_edit_hashed = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "shell")) {
            const st: *shell.ShellTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(u64, 7 * std.time.ns_per_s), st.timeout_ns);
            try std.testing.expectEqual(@as(usize, 2048), st.max_output_bytes);
            saw_shell = true;
            continue;
        }
        if (std.mem.eql(u8, t.name(), "file_read")) {
            const ft: *file_read.FileReadTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(u64, 4096), ft.max_file_size);
            saw_file_read = true;
            continue;
        }
        if (std.mem.eql(u8, t.name(), "file_edit")) {
            const et: *file_edit.FileEditTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(usize, 4096), et.max_file_size);
            saw_file_edit = true;
            continue;
        }
        if (std.mem.eql(u8, t.name(), "file_read_hashed")) {
            const ft: *file_read_hashed.FileReadHashedTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(u64, 4096), ft.max_file_size);
            saw_file_read_hashed = true;
            continue;
        }
        if (std.mem.eql(u8, t.name(), "file_edit_hashed")) {
            const et: *file_edit_hashed.FileEditHashedTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expectEqual(@as(usize, 4096), et.max_file_size);
            saw_file_edit_hashed = true;
        }
    }

    try std.testing.expect(saw_shell);
    try std.testing.expect(saw_file_read);
    try std.testing.expect(saw_file_edit);
    try std.testing.expect(saw_file_read_hashed);
    try std.testing.expect(saw_file_edit_hashed);
}

test "subagent tools wire bootstrap provider into bootstrap-aware file tools for sqlite backends" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var lru = memory_mod.InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    const provider = bp_impl.provider();
    try provider.store("SOUL.md", "## Soul");

    const tools = try subagentTools(std.testing.allocator, ws_path, .{
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = provider,
        .backend_name = "sqlite",
    });
    defer deinitTools(std.testing.allocator, tools);

    var checked_read = false;
    var checked_append = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "file_read")) {
            const ft: *file_read.FileReadTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expect(ft.bootstrap_provider != null);
            try std.testing.expectEqualStrings("sqlite", ft.backend_name);
            checked_read = true;
            continue;
        }

        if (std.mem.eql(u8, t.name(), "file_append")) {
            const fa: *file_append.FileAppendTool = @ptrCast(@alignCast(t.ptr));
            try std.testing.expect(fa.bootstrap_provider != null);
            try std.testing.expectEqualStrings("sqlite", fa.backend_name);

            const parsed = try parseTestArgs("{\"path\": \"SOUL.md\", \"content\": \"\\nMore\"}");
            defer parsed.deinit();
            const result = try t.execute(std.testing.allocator, parsed.value.object);
            defer if (result.output.len > 0) std.testing.allocator.free(result.output);
            defer if (result.error_msg) |e| std.testing.allocator.free(e);

            try std.testing.expect(result.success);
            checked_append = true;
        }
    }

    const appended = try provider.load(std.testing.allocator, "SOUL.md") orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(appended);
    try std.testing.expectEqualStrings("## Soul\nMore", appended);
    try std.testing.expect(checked_read);
    try std.testing.expect(checked_append);
}

test "mapConfigSandboxBackend preserves configured backend values" {
    // Regression: config and runtime sandbox enums do not share the same ordinal order.
    const cases = [_]struct {
        config: ConfigSandboxBackend,
        runtime: SandboxBackend,
    }{
        .{ .config = .auto, .runtime = .auto },
        .{ .config = .landlock, .runtime = .landlock },
        .{ .config = .firejail, .runtime = .firejail },
        .{ .config = .bubblewrap, .runtime = .bubblewrap },
        .{ .config = .docker, .runtime = .docker },
        .{ .config = .none, .runtime = .none },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.runtime, mapConfigSandboxBackend(case.config));
    }
}

test "subagent tools wire http allowlist, response limit, and timeout" {
    const domains = [_][]const u8{"example.com"};
    const tools = try subagentTools(std.testing.allocator, "/tmp/yc_test", .{
        .http_enabled = true,
        .http_allowed_domains = &domains,
        .http_max_response_size = 2222,
        .http_timeout_secs = 17,
    });
    defer deinitTools(std.testing.allocator, tools);

    var saw_http = false;
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name(), "http_request")) continue;
        const ht: *http_request.HttpRequestTool = @ptrCast(@alignCast(t.ptr));
        try std.testing.expectEqual(@as(usize, 1), ht.allowed_domains.len);
        try std.testing.expectEqualStrings("example.com", ht.allowed_domains[0]);
        try std.testing.expectEqual(@as(u32, 2222), ht.max_response_size);
        try std.testing.expectEqual(@as(u64, 17), ht.timeout_secs);
        saw_http = true;
        break;
    }

    try std.testing.expect(saw_http);
}

test "subagent tools apply configured descriptions and enabled filters" {
    // Regression: subagentTools receives ToolsConfig and must honor tool customizations
    // the same way allTools does.
    const customizations = [_]config_types.ToolCustomization{
        .{ .name = "git_operations", .enabled = false },
        .{ .name = "shell", .system_prompt = "Use shell only for deterministic commands" },
    };

    const tools = try subagentTools(std.testing.allocator, "/tmp/yc_test", .{
        .tools_config = .{ .tool_customizations = &customizations },
    });
    defer deinitTools(std.testing.allocator, tools);

    var saw_git = false;
    var saw_shell = false;
    for (tools) |t| {
        if (std.mem.eql(u8, t.name(), "git_operations")) saw_git = true;
        if (std.mem.eql(u8, t.name(), "shell")) {
            saw_shell = true;
            try std.testing.expectEqualStrings("Use shell only for deterministic commands", t.description());
        }
    }

    try std.testing.expect(!saw_git);
    try std.testing.expect(saw_shell);
    try std.testing.expectEqual(@as(usize, 8), tools.len);
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

test "every tool from allTools exposes non-empty metadata and survives lifecycle" {
    const alloc = std.testing.allocator;

    // Use a tmp workspace to satisfy path-touching tools.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(alloc, ".");
    defer alloc.free(ws_path);

    const tools = try allTools(alloc, ws_path, .{});
    defer deinitTools(alloc, tools);

    // The ToolVTable name/description/parameters_json slots take an
    // anyopaque ptr but never dereference it — they return compile-time
    // T.tool_name / T.tool_description / T.tool_params constants. So this
    // loop verifies metadata-presence only; the ptr itself is exercised
    // by `every tool from allTools has useful schema semantics` below
    // (which calls execute() through the vtable). The leak-free lifecycle
    // is enforced by std.testing.allocator at scope exit.
    for (tools) |tool| {
        const n = tool.name();
        try std.testing.expect(n.len > 0);
        const desc = tool.description();
        try std.testing.expect(desc.len > 0);
        const params = tool.parametersJson();
        try std.testing.expect(params.len > 0);
    }
}

fn toolSchemaHasRequiredFields(schema_value: JsonValue) !bool {
    try std.testing.expect(schema_value == .object);

    const type_field = schema_value.object.get("type") orelse return error.TestUnexpectedResult;
    try std.testing.expect(type_field == .string);
    try std.testing.expectEqualStrings("object", type_field.string);

    const properties = schema_value.object.get("properties") orelse return error.TestUnexpectedResult;
    try std.testing.expect(properties == .object);

    const required = schema_value.object.get("required") orelse return false;
    try std.testing.expect(required == .array);

    var has_required = false;
    for (required.array.items) |field| {
        try std.testing.expect(field == .string);
        has_required = true;
        try std.testing.expect(properties.object.contains(field.string));
    }

    return has_required;
}

test "every tool from allTools has useful schema semantics" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(alloc, ".");
    defer alloc.free(ws_path);

    const browser_domains = [_][]const u8{"example.com"};
    const tools = try allTools(alloc, ws_path, .{
        .http_enabled = true,
        .browser_enabled = true,
        .screenshot_enabled = true,
        .browser_open_domains = &browser_domains,
    });
    defer deinitTools(alloc, tools);

    var seen_names = std.StringHashMap(void).init(alloc);
    defer seen_names.deinit();

    for (tools) |tool| {
        const name = tool.name();
        try std.testing.expect(name.len > 0);
        const gop = try seen_names.getOrPut(name);
        try std.testing.expect(!gop.found_existing);

        const description = tool.description();
        try std.testing.expect(description.len > 0);
        try std.testing.expectEqualStrings(description, std.mem.trim(u8, description, " \t\r\n"));

        const params = tool.parametersJson();
        try std.testing.expect(params.len > 0);

        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, params, .{});
        defer parsed.deinit();

        if (try toolSchemaHasRequiredFields(parsed.value)) {
            const empty_args = try parseTestArgs("{}");
            defer empty_args.deinit();

            var result_arena = std.heap.ArenaAllocator.init(alloc);
            defer result_arena.deinit();

            const result = try tool.execute(result_arena.allocator(), empty_args.value.object);
            try std.testing.expect(!result.success);
            try std.testing.expect(result.output.len > 0 or (result.error_msg != null and result.error_msg.?.len > 0));
        }
    }
}

test "all tools wires anonymize_text and end-to-end redacts an email" {
    // Ensure the tool is registered in the default set and that calling it
    // through the vtable produces a redacted output.
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{});
    defer deinitTools(std.testing.allocator, tools);

    var saw_anonymize = false;
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name(), "anonymize_text")) continue;
        saw_anonymize = true;
        const parsed = try parseTestArgs("{\"text\":\"reach me at user@example.com\"}");
        defer parsed.deinit();
        const result = try t.execute(std.testing.allocator, parsed.value.object);
        defer std.testing.allocator.free(result.output);
        try std.testing.expect(result.success);
        try std.testing.expectEqualStrings("reach me at [EMAIL_1]", result.output);
        try std.testing.expect(std.mem.indexOf(u8, result.output, "user@example.com") == null);
        break;
    }
    try std.testing.expect(saw_anonymize);
}

test "approval grant is scoped to exact tool invocation" {
    const prev = setThreadApprovalGrant(.{
        .tool_name = "shell",
        .command = "printf ok",
        .cwd = "/tmp/work-a",
    });
    defer _ = setThreadApprovalGrant(prev);

    try std.testing.expect(threadCommandApproved("shell", "printf ok", "/tmp/work-a"));
    try std.testing.expect(!threadCommandApproved("other", "printf ok", "/tmp/work-a"));
    try std.testing.expect(!threadCommandApproved("shell", "rm -rf tmp", "/tmp/work-a"));
    try std.testing.expect(!threadCommandApproved("shell", "printf ok", "/tmp/work-b"));
    try std.testing.expect(!threadCommandApproved("shell", "printf ok", null));
}

test {
    @import("std").testing.refAllDecls(@This());
}
