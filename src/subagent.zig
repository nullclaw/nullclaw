//! SubagentManager — background task execution via isolated agent instances.
//!
//! Spawns subagents in separate OS threads with restricted tool sets
//! (no message, spawn, delegate — to prevent infinite loops).
//! Task results are routed via the event bus as system InboundMessages.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bus_mod = @import("bus.zig");
const config_mod = @import("config.zig");
const config_types = @import("config_types.zig");
const observability = @import("observability.zig");
const providers = @import("providers/root.zig");
const thread_stacks = @import("thread_stacks.zig");

const log = std.log.scoped(.subagent);

// ── Task types ──────────────────────────────────────────────────

pub const TaskStatus = enum {
    running,
    completed,
    failed,
};

pub const TaskState = struct {
    status: TaskStatus,
    label: []const u8,
    session_key: ?[]const u8 = null,
    result: ?[]const u8 = null,
    error_msg: ?[]const u8 = null,
    started_at: i64,
    completed_at: ?i64 = null,
    thread: ?std.Thread = null,
};

pub const SubagentConfig = struct {
    max_iterations: u32 = 15,
    max_concurrent: u32 = 4,
};

pub const TaskRunRequest = struct {
    task: []const u8,
    system_prompt: []const u8,
    api_key: ?[]const u8,
    default_provider: []const u8,
    default_model: ?[]const u8,
    temperature: f64,
    workspace_dir: []const u8,
    allowed_paths: []const []const u8,
    http_enabled: bool,
    http_allowed_domains: []const []const u8,
    http_max_response_size: u32,
    http_timeout_secs: u64,
    tools_config: config_types.ToolsConfig,
    memory_config: config_types.MemoryConfig,
    max_tool_iterations: u32,
    autonomy: config_types.AutonomyLevel,
    workspace_only: bool,
    allowed_commands: []const []const u8,
    max_actions_per_hour: u32,
    require_approval_for_medium_risk: bool,
    block_high_risk_commands: bool,
    allow_raw_url_chars: bool,
    configured_providers: []const config_types.ProviderEntry,
    observer: ?observability.Observer = null,
};

pub const TaskRunnerFn = *const fn (allocator: Allocator, request: TaskRunRequest) anyerror![]const u8;

// ── ThreadContext — passed to each spawned thread ────────────────

const ThreadContext = struct {
    manager: *SubagentManager,
    task_id: u64,
    task: []const u8,
    label: []const u8,
    origin_channel: []const u8,
    origin_chat_id: []const u8,
    agent_name: ?[]const u8 = null,
};

// ── SubagentManager ─────────────────────────────────────────────

pub const SubagentManager = struct {
    allocator: Allocator,
    tasks: std.AutoHashMapUnmanaged(u64, *TaskState),
    next_id: u64,
    mutex: std.Thread.Mutex,
    config: SubagentConfig,
    bus: ?*bus_mod.Bus,

    // Context needed for creating providers in subagent threads
    api_key: ?[]const u8,
    default_provider: []const u8,
    default_model: ?[]const u8,
    workspace_dir: []const u8,
    config_path: []const u8,
    allowed_paths: []const []const u8,
    agents: []const config_mod.NamedAgentConfig,
    autonomy: config_types.AutonomyLevel,
    workspace_only: bool,
    allowed_commands: []const []const u8,
    max_actions_per_hour: u32,
    require_approval_for_medium_risk: bool,
    block_high_risk_commands: bool,
    allow_raw_url_chars: bool,
    configured_providers: []const config_types.ProviderEntry,
    http_enabled: bool,
    http_allowed_domains: []const []const u8,
    http_max_response_size: u32,
    http_timeout_secs: u64,
    tools_config: config_types.ToolsConfig,
    memory_config: config_types.MemoryConfig,
    observer: ?observability.Observer = null,
    task_runner: ?TaskRunnerFn = null,

    pub fn init(
        allocator: Allocator,
        cfg: *const config_mod.Config,
        bus: ?*bus_mod.Bus,
        subagent_config: SubagentConfig,
    ) SubagentManager {
        return .{
            .allocator = allocator,
            .tasks = .{},
            .next_id = 1,
            .mutex = .{},
            .config = subagent_config,
            .bus = bus,
            .api_key = cfg.defaultProviderKey(),
            .default_provider = cfg.default_provider,
            .default_model = cfg.default_model,
            .workspace_dir = cfg.workspace_dir,
            .config_path = cfg.config_path,
            .allowed_paths = cfg.autonomy.allowed_paths,
            .agents = cfg.agents,
            .autonomy = cfg.autonomy.level,
            .workspace_only = cfg.autonomy.workspace_only,
            .allowed_commands = cfg.autonomy.allowed_commands,
            .max_actions_per_hour = cfg.autonomy.max_actions_per_hour,
            .require_approval_for_medium_risk = cfg.autonomy.require_approval_for_medium_risk,
            .block_high_risk_commands = cfg.autonomy.block_high_risk_commands,
            .allow_raw_url_chars = cfg.autonomy.allow_raw_url_chars,
            .configured_providers = cfg.providers,
            .http_enabled = cfg.http_request.enabled,
            .http_allowed_domains = cfg.http_request.allowed_domains,
            .http_max_response_size = cfg.http_request.max_response_size,
            .http_timeout_secs = cfg.http_request.timeout_secs,
            .tools_config = cfg.tools,
            .memory_config = cfg.memory,
        };
    }

    pub fn deinit(self: *SubagentManager) void {
        // Join all running threads and free task states
        var it = self.tasks.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.thread) |thread| {
                thread.join();
            }
            if (state.result) |r| self.allocator.free(r);
            if (state.error_msg) |e| self.allocator.free(e);
            if (state.session_key) |sk| self.allocator.free(sk);
            self.allocator.free(state.label);
            self.allocator.destroy(state);
        }
        self.tasks.deinit(self.allocator);
    }

    /// Spawn a background subagent. Returns task_id immediately.
    pub fn spawn(
        self: *SubagentManager,
        task: []const u8,
        label: []const u8,
        origin_channel: []const u8,
        origin_chat_id: []const u8,
    ) !u64 {
        return self.spawnWithAgent(task, label, origin_channel, origin_chat_id, null);
    }

    /// Spawn a background subagent using an optional named agent profile.
    /// When `agent_name` is set, provider/model/prompt are resolved from `agents.list`.
    pub fn spawnWithAgent(
        self: *SubagentManager,
        task: []const u8,
        label: []const u8,
        origin_channel: []const u8,
        origin_chat_id: []const u8,
        agent_name: ?[]const u8,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (agent_name) |name| {
            if (self.findAgent(name) == null) return error.UnknownAgent;
        }

        if (self.getRunningCountLocked() >= self.config.max_concurrent)
            return error.TooManyConcurrentSubagents;

        const task_id = self.next_id;
        self.next_id += 1;

        const state = try self.allocator.create(TaskState);
        errdefer self.allocator.destroy(state);
        const state_label = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(state_label);
        const state_session = try self.allocator.dupe(u8, origin_chat_id);
        errdefer self.allocator.free(state_session);
        state.* = .{
            .status = .running,
            .label = state_label,
            .session_key = state_session,
            .started_at = std.time.milliTimestamp(),
        };

        try self.tasks.put(self.allocator, task_id, state);
        errdefer _ = self.tasks.remove(task_id);

        const task_copy = try self.allocator.dupe(u8, task);
        errdefer self.allocator.free(task_copy);
        const label_copy = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(label_copy);
        const origin_channel_copy = try self.allocator.dupe(u8, origin_channel);
        errdefer self.allocator.free(origin_channel_copy);
        const origin_chat_copy = try self.allocator.dupe(u8, origin_chat_id);
        errdefer self.allocator.free(origin_chat_copy);
        const agent_name_copy = if (agent_name) |name| try self.allocator.dupe(u8, name) else null;
        errdefer if (agent_name_copy) |name| self.allocator.free(name);

        // Build thread context
        const ctx = try self.allocator.create(ThreadContext);
        errdefer self.allocator.destroy(ctx);
        ctx.* = .{
            .manager = self,
            .task_id = task_id,
            .task = task_copy,
            .label = label_copy,
            .origin_channel = origin_channel_copy,
            .origin_chat_id = origin_chat_copy,
            .agent_name = agent_name_copy,
        };

        state.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, subagentThreadFn, .{ctx});

        return task_id;
    }

    fn findAgent(self: *const SubagentManager, name: []const u8) ?config_mod.NamedAgentConfig {
        for (self.agents) |agent| {
            if (std.mem.eql(u8, agent.name, name)) return agent;
        }
        return null;
    }

    pub fn getTaskStatus(self: *SubagentManager, task_id: u64) ?TaskStatus {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.tasks.get(task_id)) |state| {
            return state.status;
        }
        return null;
    }

    pub fn getTaskResult(self: *SubagentManager, task_id: u64) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.tasks.get(task_id)) |state| {
            return state.result;
        }
        return null;
    }

    pub fn getRunningCount(self: *SubagentManager) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getRunningCountLocked();
    }

    fn getRunningCountLocked(self: *SubagentManager) u32 {
        var count: u32 = 0;
        var it = self.tasks.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.status == .running) count += 1;
        }
        return count;
    }

    /// Mark a task as completed or failed. Thread-safe.
    fn completeTask(self: *SubagentManager, task_id: u64, result: ?[]const u8, err_msg: ?[]const u8) void {
        // Dupe result/error into manager's allocator (source may be arena-backed)
        const owned_result = if (result) |r| self.allocator.dupe(u8, r) catch null else null;
        const owned_err = if (err_msg) |e| self.allocator.dupe(u8, e) catch null else null;

        var label: []const u8 = "subagent";
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.tasks.get(task_id)) |state| {
                state.status = if (owned_err != null) .failed else .completed;
                state.result = owned_result;
                state.error_msg = owned_err;
                state.completed_at = std.time.milliTimestamp();
                label = state.label;
            }
        }

        // Route result via bus (outside lock)
        if (self.bus) |b| {
            const content = if (owned_result) |r|
                std.fmt.allocPrint(self.allocator, "[Subagent '{s}' completed]\n{s}", .{ label, r }) catch return
            else if (owned_err) |e|
                std.fmt.allocPrint(self.allocator, "[Subagent '{s}' failed]\n{s}", .{ label, e }) catch return
            else
                std.fmt.allocPrint(self.allocator, "[Subagent '{s}' finished]", .{label}) catch return;

            const msg = bus_mod.makeInbound(
                self.allocator,
                "system",
                "subagent",
                "agent",
                content,
                "system:subagent",
            ) catch {
                self.allocator.free(content);
                return;
            };
            self.allocator.free(content);

            b.publishInbound(msg) catch |err| {
                msg.deinit(self.allocator);
                log.err("subagent: failed to publish result to bus: {}", .{err});
            };
        }
    }
};

fn resolveWorkspacePath(
    allocator: Allocator,
    workspace_path: []const u8,
    config_path: []const u8,
    fallback_workspace: []const u8,
) ?[]const u8 {
    if (std.fs.path.isAbsolute(workspace_path)) {
        return allocator.dupe(u8, workspace_path) catch null;
    }
    const normalized_workspace_path = config_mod.normalizeHostPathSeparators(allocator, workspace_path) catch return null;
    defer allocator.free(normalized_workspace_path);
    const home_dir = std.fs.path.dirname(config_path) orelse fallback_workspace;
    return std.fs.path.join(allocator, &.{ home_dir, normalized_workspace_path }) catch null;
}

// ── Thread function ─────────────────────────────────────────────

fn subagentThreadFn(ctx: *ThreadContext) void {
    defer {
        ctx.manager.allocator.free(ctx.task);
        ctx.manager.allocator.free(ctx.label);
        ctx.manager.allocator.free(ctx.origin_channel);
        ctx.manager.allocator.free(ctx.origin_chat_id);
        if (ctx.agent_name) |agent_name| ctx.manager.allocator.free(agent_name);
        ctx.manager.allocator.destroy(ctx);
    }

    // Default prompt differs based on execution mode:
    // - tool-loop mode can use restricted tools
    // - legacy fallback has no tool access
    var system_prompt: []const u8 = if (ctx.manager.task_runner != null)
        "You are a background subagent. Complete the assigned task concisely and accurately. Use available tools when they materially improve correctness."
    else
        "You are a background subagent. Complete the assigned task concisely and accurately. You have no access to interactive tools — focus on reasoning and analysis.";
    var api_key = ctx.manager.api_key;
    var default_provider = ctx.manager.default_provider;
    var default_model = ctx.manager.default_model;
    var temperature: f64 = 0.7;
    var effective_workspace = ctx.manager.workspace_dir;
    var resolved_workspace: ?[]const u8 = null;
    defer if (resolved_workspace) |workspace_dir| ctx.manager.allocator.free(workspace_dir);

    if (ctx.agent_name) |agent_name| {
        const agent_cfg = ctx.manager.findAgent(agent_name) orelse {
            ctx.manager.completeTask(ctx.task_id, null, "UnknownAgent");
            return;
        };

        default_provider = agent_cfg.provider;
        default_model = agent_cfg.model;
        api_key = agent_cfg.api_key orelse ctx.manager.api_key;
        if (agent_cfg.system_prompt) |sp| system_prompt = sp;
        if (agent_cfg.temperature) |t| temperature = t;
        if (agent_cfg.workspace_path) |workspace_path| {
            resolved_workspace = resolveWorkspacePath(
                ctx.manager.allocator,
                workspace_path,
                ctx.manager.config_path,
                ctx.manager.workspace_dir,
            );
            if (resolved_workspace) |workspace_dir| {
                config_mod.Config.scaffoldAgentWorkspace(ctx.manager.allocator, workspace_dir) catch {};
                effective_workspace = workspace_dir;
            }
        }
    }

    if (ctx.manager.task_runner) |runner| {
        const request = TaskRunRequest{
            .task = ctx.task,
            .system_prompt = system_prompt,
            .api_key = api_key,
            .default_provider = default_provider,
            .default_model = default_model,
            .temperature = temperature,
            .workspace_dir = effective_workspace,
            .allowed_paths = ctx.manager.allowed_paths,
            .http_enabled = ctx.manager.http_enabled,
            .http_allowed_domains = ctx.manager.http_allowed_domains,
            .http_max_response_size = ctx.manager.http_max_response_size,
            .http_timeout_secs = ctx.manager.http_timeout_secs,
            .tools_config = ctx.manager.tools_config,
            .memory_config = ctx.manager.memory_config,
            .max_tool_iterations = ctx.manager.config.max_iterations,
            .autonomy = ctx.manager.autonomy,
            .workspace_only = ctx.manager.workspace_only,
            .allowed_commands = ctx.manager.allowed_commands,
            .max_actions_per_hour = ctx.manager.max_actions_per_hour,
            .require_approval_for_medium_risk = ctx.manager.require_approval_for_medium_risk,
            .block_high_risk_commands = ctx.manager.block_high_risk_commands,
            .allow_raw_url_chars = ctx.manager.allow_raw_url_chars,
            .configured_providers = ctx.manager.configured_providers,
            .observer = ctx.manager.observer,
        };

        const result = runner(ctx.manager.allocator, request) catch |err| {
            ctx.manager.completeTask(ctx.task_id, null, @errorName(err));
            return;
        };
        defer ctx.manager.allocator.free(result);
        ctx.manager.completeTask(ctx.task_id, result, null);
        return;
    }

    var cfg_arena = std.heap.ArenaAllocator.init(ctx.manager.allocator);
    defer cfg_arena.deinit();

    // Build a config-like struct that providers.completeWithSystem() accepts
    const cfg = .{
        .api_key = api_key,
        .default_provider = default_provider,
        .default_model = default_model,
        .temperature = temperature,
        .max_tokens = @as(?u64, null),
    };

    const result = providers.completeWithSystem(
        cfg_arena.allocator(),
        &cfg,
        system_prompt,
        ctx.task,
    ) catch |err| {
        ctx.manager.completeTask(ctx.task_id, null, @errorName(err));
        return;
    };

    ctx.manager.completeTask(ctx.task_id, result, null);
}

// ── Tests ───────────────────────────────────────────────────────

fn waitTaskTerminalStatus(manager: *SubagentManager, task_id: u64) !TaskStatus {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        const status = manager.getTaskStatus(task_id) orelse return error.TestUnexpectedResult;
        if (status != .running) return status;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    return error.TestUnexpectedResult;
}

fn testTaskRunnerOk(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    _ = request;
    return allocator.dupe(u8, "runner-ok");
}

fn testTaskRunnerWorkspace(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    return allocator.dupe(u8, request.workspace_dir);
}

fn testTaskRunnerHttpTimeout(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{d}", .{request.http_timeout_secs});
}

fn testTaskRunnerFail(_: Allocator, _: TaskRunRequest) ![]const u8 {
    return error.TestTaskRunnerFailure;
}

test "SubagentManager init and deinit" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();
    try std.testing.expectEqual(@as(u64, 1), mgr.next_id);
    try std.testing.expect(mgr.bus == null);
}

test "SubagentConfig defaults" {
    const sc = SubagentConfig{};
    try std.testing.expectEqual(@as(u32, 15), sc.max_iterations);
    try std.testing.expectEqual(@as(u32, 4), sc.max_concurrent);
}

test "TaskStatus enum values" {
    try std.testing.expect(@intFromEnum(TaskStatus.running) != @intFromEnum(TaskStatus.completed));
    try std.testing.expect(@intFromEnum(TaskStatus.completed) != @intFromEnum(TaskStatus.failed));
}

test "TaskState initial defaults" {
    const state = TaskState{
        .status = .running,
        .label = "test",
        .started_at = 0,
    };
    try std.testing.expect(state.result == null);
    try std.testing.expect(state.error_msg == null);
    try std.testing.expect(state.completed_at == null);
    try std.testing.expect(state.thread == null);
}

test "SubagentManager getRunningCount empty" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();
    try std.testing.expectEqual(@as(u32, 0), mgr.getRunningCount());
}

test "SubagentManager getTaskStatus unknown id" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();
    try std.testing.expect(mgr.getTaskStatus(999) == null);
}

test "SubagentManager getTaskResult unknown id" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();
    try std.testing.expect(mgr.getTaskResult(999) == null);
}

test "SubagentManager completeTask updates state" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    // Manually insert a task state to test completeTask
    const state = try std.testing.allocator.create(TaskState);
    state.* = .{
        .status = .running,
        .label = try std.testing.allocator.dupe(u8, "test-task"),
        .started_at = std.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);

    mgr.completeTask(1, "done!", null);

    try std.testing.expectEqual(TaskStatus.completed, mgr.getTaskStatus(1).?);
    try std.testing.expectEqualStrings("done!", mgr.getTaskResult(1).?);
}

test "SubagentManager completeTask with error" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    const state = try std.testing.allocator.create(TaskState);
    state.* = .{
        .status = .running,
        .label = try std.testing.allocator.dupe(u8, "fail-task"),
        .started_at = std.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);

    mgr.completeTask(1, null, "timeout");

    try std.testing.expectEqual(TaskStatus.failed, mgr.getTaskStatus(1).?);
    try std.testing.expect(mgr.getTaskResult(1) == null);
}

test "SubagentManager completeTask routes via bus" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var bus = bus_mod.Bus.init();
    defer bus.close();

    var mgr = SubagentManager.init(std.testing.allocator, &cfg, &bus, .{});
    defer mgr.deinit();

    const state = try std.testing.allocator.create(TaskState);
    state.* = .{
        .status = .running,
        .label = try std.testing.allocator.dupe(u8, "bus-task"),
        .started_at = std.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);

    mgr.completeTask(1, "result text", null);

    // Check bus received the message — verify depth increased
    try std.testing.expect(bus.inboundDepth() > 0);

    // Drain the bus to avoid memory leak
    bus.close();
    if (bus.consumeInbound()) |msg| {
        msg.deinit(std.testing.allocator);
    }
}

test "SubagentManager spawn stores session key" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    const task_id = try mgr.spawn("quick task", "session-check", "agent", "session:42");
    mgr.mutex.lock();
    defer mgr.mutex.unlock();
    const state = mgr.tasks.get(task_id) orelse return error.TestUnexpectedResult;
    try std.testing.expect(state.session_key != null);
    try std.testing.expectEqualStrings("session:42", state.session_key.?);
}

test "SubagentManager spawnWithAgent rejects unknown agent" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    try std.testing.expectError(
        error.UnknownAgent,
        mgr.spawnWithAgent("quick task", "session-check", "agent", "session:42", "missing-agent"),
    );
}

test "SubagentManager spawnWithAgent accepts configured agent" {
    const agents = [_]config_mod.NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "anthropic/claude-sonnet-4",
    }};
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
        .agents = &agents,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    const task_id = try mgr.spawnWithAgent("quick task", "session-check", "agent", "session:42", "researcher");
    try std.testing.expect(task_id > 0);
}

test "SubagentManager uses named agent workspace_path for task runner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ base, "config.json" });
    defer std.testing.allocator.free(config_path);
    const expected_workspace = try std.fs.path.join(std.testing.allocator, &.{ base, "agents", "researcher" });
    defer std.testing.allocator.free(expected_workspace);

    const agents = [_]config_mod.NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "anthropic/claude-sonnet-4",
        .workspace_path = "agents/researcher",
    }};
    const cfg = config_mod.Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = std.testing.allocator,
        .agents = &agents,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    mgr.task_runner = testTaskRunnerWorkspace;
    defer mgr.deinit();

    const task_id = try mgr.spawnWithAgent("quick task", "workspace-check", "agent", "session:42", "researcher");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.completed, status);
    try std.testing.expectEqualStrings(expected_workspace, mgr.getTaskResult(task_id).?);
}

test "SubagentManager uses task runner callback result" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    mgr.task_runner = testTaskRunnerOk;
    defer mgr.deinit();

    const task_id = try mgr.spawn("quick task", "runner-ok", "agent", "session:42");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.completed, status);
    try std.testing.expectEqualStrings("runner-ok", mgr.getTaskResult(task_id).?);
}

test "SubagentManager propagates http timeout to task runner" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
        .http_request = .{
            .timeout_secs = 17,
        },
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    mgr.task_runner = testTaskRunnerHttpTimeout;
    defer mgr.deinit();

    const task_id = try mgr.spawn("quick task", "runner-timeout", "agent", "session:42");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.completed, status);
    try std.testing.expectEqualStrings("17", mgr.getTaskResult(task_id).?);
}

test "SubagentManager stores runner callback error" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    mgr.task_runner = testTaskRunnerFail;
    defer mgr.deinit();

    const task_id = try mgr.spawn("quick task", "runner-fail", "agent", "session:42");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.failed, status);

    mgr.mutex.lock();
    defer mgr.mutex.unlock();
    const state = mgr.tasks.get(task_id) orelse return error.TestUnexpectedResult;
    try std.testing.expect(state.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, state.error_msg.?, "TestTaskRunnerFailure") != null);
}

test "SubagentManager spawn rollback removes task on out-of-memory" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();
    var cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = alloc,
    };
    var mgr = SubagentManager.init(alloc, &cfg, null, .{});
    defer mgr.deinit();

    try mgr.tasks.ensureTotalCapacity(alloc, 1);
    failing.fail_index = failing.alloc_index + 4;

    try std.testing.expectError(
        error.OutOfMemory,
        mgr.spawn("oom-task", "oom-label", "agent", "session:oom"),
    );
    try std.testing.expectEqual(@as(usize, 0), mgr.tasks.count());
    try std.testing.expectEqual(@as(u32, 0), mgr.getRunningCount());
}
