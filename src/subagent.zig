//! SubagentManager — background task execution via isolated agent instances.
//!
//! Spawns subagents in separate OS threads with restricted tool sets
//! (no message, spawn, delegate — to prevent infinite loops).
//! Task results are routed back to the originating channel/session.

const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const bus_mod = @import("bus.zig");
const config_mod = @import("config.zig");
const config_types = @import("config_types.zig");
const observability = @import("observability.zig");
const provider_names = @import("provider_names.zig");
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
    origin_channel: []const u8,
    origin_chat_id: []const u8,
    origin_account_id: ?[]const u8 = null,
    session_key: ?[]const u8 = null,
    result: ?[]const u8 = null,
    error_msg: ?[]const u8 = null,
    notified: bool = false,
    started_at: i64,
    completed_at: ?i64 = null,
    thread: ?std.Thread = null,
};

pub const CompletionNotice = struct {
    task_id: u64,
    content: []u8,
    origin_channel: []u8,
    origin_chat_id: []u8,
    origin_account_id: ?[]u8 = null,
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
    block_medium_risk_commands: bool,
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
    agent_name: ?[]const u8 = null,
    trace_id: ?[32]u8 = null,
};

// ── SubagentManager ─────────────────────────────────────────────

pub const SubagentManager = struct {
    allocator: Allocator,
    tasks: std.AutoHashMapUnmanaged(u64, *TaskState),
    next_id: u64,
    mutex: std_compat.sync.Mutex,
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
    block_medium_risk_commands: bool,
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
            .block_medium_risk_commands = cfg.autonomy.block_medium_risk_commands,
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
            self.allocator.free(state.origin_channel);
            self.allocator.free(state.origin_chat_id);
            if (state.origin_account_id) |aid| self.allocator.free(aid);
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
        origin_account_id: ?[]const u8,
        origin_session_key: []const u8,
    ) !u64 {
        return self.spawnWithAgent(task, label, origin_channel, origin_chat_id, origin_account_id, origin_session_key, null);
    }

    /// Spawn a background subagent using an optional named agent profile.
    /// When `agent_name` is set, provider/model/prompt are resolved from `agents.list`.
    pub fn spawnWithAgent(
        self: *SubagentManager,
        task: []const u8,
        label: []const u8,
        origin_channel: []const u8,
        origin_chat_id: []const u8,
        origin_account_id: ?[]const u8,
        origin_session_key: []const u8,
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
        const state_origin_channel = try self.allocator.dupe(u8, origin_channel);
        errdefer self.allocator.free(state_origin_channel);
        const state_origin_chat = try self.allocator.dupe(u8, origin_chat_id);
        errdefer self.allocator.free(state_origin_chat);
        const state_origin_account = if (origin_account_id) |account_id| try self.allocator.dupe(u8, account_id) else null;
        errdefer if (state_origin_account) |account_id| self.allocator.free(account_id);
        const state_session = try self.allocator.dupe(u8, origin_session_key);
        errdefer self.allocator.free(state_session);
        state.* = .{
            .status = .running,
            .label = state_label,
            .origin_channel = state_origin_channel,
            .origin_chat_id = state_origin_chat,
            .origin_account_id = state_origin_account,
            .session_key = state_session,
            .started_at = std_compat.time.milliTimestamp(),
        };

        try self.tasks.put(self.allocator, task_id, state);
        errdefer _ = self.tasks.remove(task_id);

        const task_copy = try self.allocator.dupe(u8, task);
        errdefer self.allocator.free(task_copy);
        const label_copy = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(label_copy);
        const agent_name_copy = if (agent_name) |name| try self.allocator.dupe(u8, name) else null;
        errdefer if (agent_name_copy) |name| self.allocator.free(name);

        const trace_id = if (self.observer) |obs| obs.getTraceId() else null;

        // Build thread context
        const ctx = try self.allocator.create(ThreadContext);
        errdefer self.allocator.destroy(ctx);
        ctx.* = .{
            .manager = self,
            .task_id = task_id,
            .task = task_copy,
            .label = label_copy,
            .agent_name = agent_name_copy,
            .trace_id = trace_id,
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

    fn formatTaskCompletionContent(allocator: Allocator, label: []const u8, result: ?[]const u8, err_msg: ?[]const u8) ![]u8 {
        return if (result) |r|
            try std.fmt.allocPrint(allocator, "[Subagent '{s}' completed]\n{s}", .{ label, r })
        else if (err_msg) |e|
            try std.fmt.allocPrint(allocator, "[Subagent '{s}' failed]\n{s}", .{ label, e })
        else
            try std.fmt.allocPrint(allocator, "[Subagent '{s}' finished]", .{label});
    }

    /// Mark a task as completed or failed. Thread-safe.
    fn completeTask(self: *SubagentManager, task_id: u64, result: ?[]const u8, err_msg: ?[]const u8) void {
        // Dupe result/error into manager's allocator (source may be arena-backed)
        const owned_result = if (result) |r| self.allocator.dupe(u8, r) catch null else null;
        const owned_err = if (err_msg) |e| self.allocator.dupe(u8, e) catch null else null;

        var label: []const u8 = "subagent";
        var origin_channel: []const u8 = "system";
        var origin_chat_id: []const u8 = "subagent";
        var origin_account_id: ?[]const u8 = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.tasks.get(task_id)) |state| {
                state.status = if (owned_err != null) .failed else .completed;
                state.result = owned_result;
                state.error_msg = owned_err;
                state.notified = false;
                state.completed_at = std_compat.time.milliTimestamp();
                label = state.label;
                origin_channel = state.origin_channel;
                origin_chat_id = state.origin_chat_id;
                origin_account_id = state.origin_account_id;
            }
        }

        const content = formatTaskCompletionContent(self.allocator, label, owned_result, owned_err) catch return;
        defer self.allocator.free(content);

        // Route result via bus (outside lock)
        if (self.bus) |b| {
            var out = if (origin_account_id) |account_id|
                bus_mod.makeOutboundWithAccount(
                    self.allocator,
                    origin_channel,
                    account_id,
                    origin_chat_id,
                    content,
                ) catch return
            else
                bus_mod.makeOutbound(
                    self.allocator,
                    origin_channel,
                    origin_chat_id,
                    content,
                ) catch return;

            b.publishOutbound(out) catch |err| {
                out.deinit(self.allocator);
                log.err("subagent: failed to publish result to outbound bus: {}", .{err});
            };
        }
    }

    pub fn takeCompletionNoticesForSession(
        self: *SubagentManager,
        allocator: Allocator,
        session_key: ?[]const u8,
    ) ![]CompletionNotice {
        return self.takeCompletionNoticesFiltered(allocator, .{ .session_key = session_key });
    }

    pub fn takeCompletionNoticesForOrigin(
        self: *SubagentManager,
        allocator: Allocator,
        origin_channel: []const u8,
        origin_account_id: ?[]const u8,
    ) ![]CompletionNotice {
        return self.takeCompletionNoticesFiltered(allocator, .{
            .origin_channel = origin_channel,
            .origin_account_id = origin_account_id,
        });
    }

    const CompletionNoticeFilter = struct {
        session_key: ?[]const u8 = null,
        origin_channel: ?[]const u8 = null,
        origin_account_id: ?[]const u8 = null,
    };

    fn taskMatchesNoticeFilter(state: *const TaskState, filter: CompletionNoticeFilter) bool {
        if (filter.session_key) |expected_session| {
            const state_session = state.session_key orelse return false;
            if (!std.mem.eql(u8, state_session, expected_session)) return false;
        }
        if (filter.origin_channel) |expected_channel| {
            if (!std.mem.eql(u8, state.origin_channel, expected_channel)) return false;
        }
        if (filter.origin_account_id) |expected_account| {
            const state_account = state.origin_account_id orelse return false;
            if (!std.mem.eql(u8, state_account, expected_account)) return false;
        }
        return true;
    }

    fn takeCompletionNoticesFiltered(
        self: *SubagentManager,
        allocator: Allocator,
        filter: CompletionNoticeFilter,
    ) ![]CompletionNotice {
        var notices: std.ArrayListUnmanaged(CompletionNotice) = .empty;
        errdefer {
            for (notices.items) |notice| freeNoticeFields(allocator, notice);
            notices.deinit(allocator);
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.tasks.iterator();
        while (it.next()) |entry| {
            const task_id = entry.key_ptr.*;
            const state = entry.value_ptr.*;
            if (state.status == .running or state.notified) continue;
            if (!taskMatchesNoticeFilter(state, filter)) continue;

            const content = formatTaskCompletionContent(allocator, state.label, state.result, state.error_msg) catch continue;
            const origin_channel_dup = allocator.dupe(u8, state.origin_channel) catch {
                allocator.free(content);
                continue;
            };
            const origin_chat_dup = allocator.dupe(u8, state.origin_chat_id) catch {
                allocator.free(content);
                allocator.free(origin_channel_dup);
                continue;
            };
            const origin_account_dup: ?[]u8 = if (state.origin_account_id) |aid|
                allocator.dupe(u8, aid) catch {
                    allocator.free(content);
                    allocator.free(origin_channel_dup);
                    allocator.free(origin_chat_dup);
                    continue;
                }
            else
                null;

            notices.append(allocator, .{
                .task_id = task_id,
                .content = content,
                .origin_channel = origin_channel_dup,
                .origin_chat_id = origin_chat_dup,
                .origin_account_id = origin_account_dup,
            }) catch {
                allocator.free(content);
                allocator.free(origin_channel_dup);
                allocator.free(origin_chat_dup);
                if (origin_account_dup) |aid| allocator.free(aid);
                continue;
            };
            state.notified = true;
        }

        return notices.toOwnedSlice(allocator);
    }

    fn freeNoticeFields(allocator: Allocator, notice: CompletionNotice) void {
        allocator.free(notice.content);
        allocator.free(notice.origin_channel);
        allocator.free(notice.origin_chat_id);
        if (notice.origin_account_id) |aid| allocator.free(aid);
    }

    pub fn freeCompletionNotices(allocator: Allocator, notices: []CompletionNotice) void {
        for (notices) |notice| freeNoticeFields(allocator, notice);
        allocator.free(notices);
    }
};

fn resolveWorkspacePath(
    allocator: Allocator,
    workspace_path: []const u8,
    config_path: []const u8,
    fallback_workspace: []const u8,
) ?[]const u8 {
    if (std_compat.fs.path.isAbsolute(workspace_path)) {
        return allocator.dupe(u8, workspace_path) catch null;
    }
    const normalized_workspace_path = config_mod.normalizeHostPathSeparators(allocator, workspace_path) catch return null;
    defer allocator.free(normalized_workspace_path);
    const home_dir = std_compat.fs.path.dirname(config_path) orelse fallback_workspace;
    return std_compat.fs.path.join(allocator, &.{ home_dir, normalized_workspace_path }) catch null;
}

fn findConfiguredProvider(
    configured_providers: []const config_types.ProviderEntry,
    provider_name: []const u8,
) ?config_types.ProviderEntry {
    for (configured_providers) |entry| {
        if (provider_names.providerNamesMatch(entry.name, provider_name)) return entry;
    }
    return null;
}

fn resolveSubagentProviderApiKey(
    configured_provider: ?config_types.ProviderEntry,
    explicit_api_key: ?[]const u8,
    fallback_api_key: ?[]const u8,
) ?[]const u8 {
    if (explicit_api_key) |api_key| return api_key;
    if (configured_provider) |entry| {
        if (entry.api_key) |api_key| return api_key;
    }
    return fallback_api_key;
}

fn subagentProviderHolder(
    allocator: Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
    configured_provider: ?config_types.ProviderEntry,
) providers.ProviderHolder {
    return providers.holderFromEntry(allocator, provider_name, api_key, configured_provider);
}

// ── Thread function ─────────────────────────────────────────────

fn subagentThreadFn(ctx: *ThreadContext) void {
    defer {
        ctx.manager.allocator.free(ctx.task);
        ctx.manager.allocator.free(ctx.label);
        if (ctx.agent_name) |agent_name| ctx.manager.allocator.free(agent_name);
        ctx.manager.allocator.destroy(ctx);
    }

    if (ctx.manager.observer) |obs| {
        if (ctx.trace_id) |tid| {
            obs.setTraceId(tid);
        }

        const name_to_report = ctx.agent_name orelse "default";
        const subagent_start_event = observability.ObserverEvent{ .subagent_start = .{
            .agent_name = name_to_report,
            .task = ctx.task,
        } };
        obs.recordEvent(&subagent_start_event);
    }

    // Default prompt differs based on execution mode:
    // - tool-loop mode can use restricted tools
    // - legacy fallback has no tool access
    var system_prompt: []const u8 = if (ctx.manager.task_runner != null)
        "You are a background subagent. Complete the assigned task concisely and accurately. Use available tools when they materially improve correctness."
    else
        "You are a background subagent. Complete the assigned task concisely and accurately. You have no access to interactive tools — focus on reasoning and analysis.";
    var default_provider = ctx.manager.default_provider;
    var default_model = ctx.manager.default_model;
    var temperature: f64 = 0.7;
    var explicit_api_key: ?[]const u8 = null;
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
        explicit_api_key = agent_cfg.api_key;
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

    const configured_provider = findConfiguredProvider(ctx.manager.configured_providers, default_provider);
    const api_key = resolveSubagentProviderApiKey(configured_provider, explicit_api_key, ctx.manager.api_key);

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
            .block_medium_risk_commands = ctx.manager.block_medium_risk_commands,
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

    const model = default_model orelse {
        ctx.manager.completeTask(ctx.task_id, null, @errorName(error.NoDefaultModel));
        return;
    };

    var holder = subagentProviderHolder(
        cfg_arena.allocator(),
        default_provider,
        api_key,
        configured_provider,
    );
    defer holder.deinit();

    const result = holder.provider().chatWithSystem(
        cfg_arena.allocator(),
        system_prompt,
        ctx.task,
        model,
        temperature,
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
        std_compat.thread.sleep(10 * std.time.ns_per_ms);
    }
    return error.TestUnexpectedResult;
}

test "subagent provider api key prefers explicit then configured then fallback" {
    const entries = [_]config_types.ProviderEntry{.{
        .name = "groq",
        .api_key = "configured-key",
    }};
    const configured = findConfiguredProvider(&entries, "groq");
    try std.testing.expect(configured != null);

    try std.testing.expectEqualStrings(
        "explicit-key",
        resolveSubagentProviderApiKey(configured, "explicit-key", "fallback-key").?,
    );
    try std.testing.expectEqualStrings(
        "configured-key",
        resolveSubagentProviderApiKey(configured, null, "fallback-key").?,
    );
    try std.testing.expectEqualStrings(
        "fallback-key",
        resolveSubagentProviderApiKey(null, null, "fallback-key").?,
    );
    try std.testing.expect(resolveSubagentProviderApiKey(null, null, null) == null);
}

test "subagent provider holder applies configured provider options" {
    const configured = config_types.ProviderEntry{
        .name = "custom-local",
        .base_url = "http://localhost:4321/v1",
        .native_tools = false,
        .user_agent = "nullclaw-test",
        .api_mode = .responses,
        .chat_template_enable_thinking_param = true,
        .max_streaming_prompt_bytes = 123,
        .extra_body_params = "{\"seed\":1}",
    };

    var holder = subagentProviderHolder(
        std.testing.allocator,
        "custom-local",
        null,
        configured,
    );
    defer holder.deinit();

    switch (holder) {
        .compatible => |*provider| {
            try std.testing.expectEqualStrings("http://localhost:4321/v1", provider.base_url);
            try std.testing.expect(!provider.native_tools);
            try std.testing.expectEqualStrings("nullclaw-test", provider.user_agent.?);
            try std.testing.expectEqual(providers.compatible.CompatibleApiMode.responses, provider.api_mode);
            try std.testing.expect(provider.chat_template_enable_thinking_param);
            try std.testing.expectEqual(@as(?usize, 123), provider.max_streaming_prompt_bytes);
            try std.testing.expectEqualStrings("{\"seed\":1}", provider.extra_body_params.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

fn testTaskRunnerOk(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    _ = request;
    return allocator.dupe(u8, "runner-ok");
}

fn testTaskRunnerWorkspace(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    return allocator.dupe(u8, request.workspace_dir);
}

fn testTaskRunnerWorkspaceAndPrompt(allocator: Allocator, request: TaskRunRequest) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "workspace={s}\nprompt={s}",
        .{ request.workspace_dir, request.system_prompt },
    );
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
        .origin_channel = "agent",
        .origin_chat_id = "session:1",
        .started_at = 0,
    };
    try std.testing.expect(state.result == null);
    try std.testing.expect(state.error_msg == null);
    try std.testing.expect(!state.notified);
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
        .origin_channel = try std.testing.allocator.dupe(u8, "agent"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "session:1"),
        .started_at = std_compat.time.milliTimestamp(),
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
        .origin_channel = try std.testing.allocator.dupe(u8, "agent"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "session:1"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);

    mgr.completeTask(1, null, "timeout");

    try std.testing.expectEqual(TaskStatus.failed, mgr.getTaskStatus(1).?);
    try std.testing.expect(mgr.getTaskResult(1) == null);
}

test "SubagentManager completeTask routes outbound via bus to origin channel" {
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
        .origin_channel = try std.testing.allocator.dupe(u8, "telegram"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "chat-42"),
        .origin_account_id = try std.testing.allocator.dupe(u8, "primary"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);

    mgr.completeTask(1, "result text", null);

    try std.testing.expectEqual(@as(usize, 1), bus.outboundDepth());
    var msg = bus.consumeOutbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("telegram", msg.channel);
    try std.testing.expectEqualStrings("chat-42", msg.chat_id);
    try std.testing.expect(msg.account_id != null);
    try std.testing.expectEqualStrings("primary", msg.account_id.?);
    try std.testing.expect(std.mem.indexOf(u8, msg.content, "bus-task") != null);
}

test "SubagentManager takeCompletionNoticesForSession returns once per task" {
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
        .label = try std.testing.allocator.dupe(u8, "notice-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "cli"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "session:42"),
        .session_key = try std.testing.allocator.dupe(u8, "session:42"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);
    mgr.completeTask(1, "done", null);

    const notices1 = try mgr.takeCompletionNoticesForSession(std.testing.allocator, "session:42");
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, notices1);
    try std.testing.expectEqual(@as(usize, 1), notices1.len);
    try std.testing.expectEqual(@as(u64, 1), notices1[0].task_id);
    try std.testing.expect(std.mem.indexOf(u8, notices1[0].content, "notice-task") != null);

    const notices2 = try mgr.takeCompletionNoticesForSession(std.testing.allocator, "session:42");
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, notices2);
    try std.testing.expectEqual(@as(usize, 0), notices2.len);
}

test "CompletionNotice carries origin channel/chat/account for polling delivery (regression #918)" {
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
        .label = try std.testing.allocator.dupe(u8, "polling-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "telegram"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "987654321"),
        .origin_account_id = try std.testing.allocator.dupe(u8, "main"),
        .session_key = try std.testing.allocator.dupe(u8, "telegram:987654321"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);
    mgr.completeTask(1, "all done", null);

    const notices = try mgr.takeCompletionNoticesForSession(std.testing.allocator, null);
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, notices);
    try std.testing.expectEqual(@as(usize, 1), notices.len);
    try std.testing.expectEqualStrings("telegram", notices[0].origin_channel);
    try std.testing.expectEqualStrings("987654321", notices[0].origin_chat_id);
    try std.testing.expect(notices[0].origin_account_id != null);
    try std.testing.expectEqualStrings("main", notices[0].origin_account_id.?);
    try std.testing.expect(std.mem.indexOf(u8, notices[0].content, "polling-task") != null);
}

test "CompletionNotice origin_account_id stays null when task has none" {
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
        .label = try std.testing.allocator.dupe(u8, "no-account-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "cli"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "session:1"),
        .origin_account_id = null,
        .session_key = try std.testing.allocator.dupe(u8, "session:1"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, state);
    mgr.completeTask(1, "ok", null);

    const notices = try mgr.takeCompletionNoticesForSession(std.testing.allocator, null);
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, notices);
    try std.testing.expectEqual(@as(usize, 1), notices.len);
    try std.testing.expectEqualStrings("cli", notices[0].origin_channel);
    try std.testing.expect(notices[0].origin_account_id == null);
}

test "SubagentManager takeCompletionNoticesForOrigin preserves other accounts (regression #918)" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    const main_state = try std.testing.allocator.create(TaskState);
    main_state.* = .{
        .status = .running,
        .label = try std.testing.allocator.dupe(u8, "main-account-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "telegram"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "chat-main"),
        .origin_account_id = try std.testing.allocator.dupe(u8, "main"),
        .session_key = try std.testing.allocator.dupe(u8, "telegram:main:chat-main"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 1, main_state);

    const secondary_state = try std.testing.allocator.create(TaskState);
    secondary_state.* = .{
        .status = .running,
        .label = try std.testing.allocator.dupe(u8, "secondary-account-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "telegram"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "chat-secondary"),
        .origin_account_id = try std.testing.allocator.dupe(u8, "secondary"),
        .session_key = try std.testing.allocator.dupe(u8, "telegram:secondary:chat-secondary"),
        .started_at = std_compat.time.milliTimestamp(),
    };
    try mgr.tasks.put(std.testing.allocator, 2, secondary_state);

    mgr.completeTask(1, "main done", null);
    mgr.completeTask(2, "secondary done", null);

    const main_notices = try mgr.takeCompletionNoticesForOrigin(std.testing.allocator, "telegram", "main");
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, main_notices);
    try std.testing.expectEqual(@as(usize, 1), main_notices.len);
    try std.testing.expectEqual(@as(u64, 1), main_notices[0].task_id);
    try std.testing.expectEqualStrings("chat-main", main_notices[0].origin_chat_id);

    const secondary_notices = try mgr.takeCompletionNoticesForOrigin(std.testing.allocator, "telegram", "secondary");
    defer SubagentManager.freeCompletionNotices(std.testing.allocator, secondary_notices);
    try std.testing.expectEqual(@as(usize, 1), secondary_notices.len);
    try std.testing.expectEqual(@as(u64, 2), secondary_notices[0].task_id);
    try std.testing.expectEqualStrings("chat-secondary", secondary_notices[0].origin_chat_id);
}

test "SubagentManager spawn stores session key" {
    const cfg = config_mod.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer mgr.deinit();

    const task_id = try mgr.spawn("quick task", "session-check", "agent", "session:42", null, "session:42");
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
        mgr.spawnWithAgent("quick task", "session-check", "agent", "session:42", null, "session:42", "missing-agent"),
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

    const task_id = try mgr.spawnWithAgent("quick task", "session-check", "agent", "session:42", null, "session:42", "researcher");
    try std.testing.expect(task_id > 0);
}

test "SubagentManager uses named agent workspace_path for task runner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const config_path = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "config.json" });
    defer std.testing.allocator.free(config_path);
    const expected_workspace = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "agents", "researcher" });
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

    const task_id = try mgr.spawnWithAgent("quick task", "workspace-check", "agent", "session:42", null, "session:42", "researcher");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.completed, status);
    try std.testing.expectEqualStrings(expected_workspace, mgr.getTaskResult(task_id).?);
}

test "SubagentManager preserves named agent system_prompt when workspace_path is set" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const config_path = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "config.json" });
    defer std.testing.allocator.free(config_path);
    const expected_workspace = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "agents", "researcher" });
    defer std.testing.allocator.free(expected_workspace);
    const expected_prompt = "Focus on implementation and tests.";

    const agents = [_]config_mod.NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "anthropic/claude-sonnet-4",
        .system_prompt = expected_prompt,
        .workspace_path = "agents/researcher",
    }};
    const cfg = config_mod.Config{
        .workspace_dir = base,
        .config_path = config_path,
        .allocator = std.testing.allocator,
        .agents = &agents,
    };
    var mgr = SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    mgr.task_runner = testTaskRunnerWorkspaceAndPrompt;
    defer mgr.deinit();

    const task_id = try mgr.spawnWithAgent("quick task", "workspace-prompt-check", "agent", "session:42", null, "session:42", "researcher");
    const status = try waitTaskTerminalStatus(&mgr, task_id);
    try std.testing.expectEqual(TaskStatus.completed, status);

    const result = mgr.getTaskResult(task_id).?;
    try std.testing.expect(std.mem.indexOf(u8, result, expected_workspace) != null);
    try std.testing.expect(std.mem.indexOf(u8, result, expected_prompt) != null);
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

    const task_id = try mgr.spawn("quick task", "runner-ok", "agent", "session:42", null, "session:42");
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

    const task_id = try mgr.spawn("quick task", "runner-timeout", "agent", "session:42", null, "session:42");
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

    const task_id = try mgr.spawn("quick task", "runner-fail", "agent", "session:42", null, "session:42");
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
        mgr.spawn("oom-task", "oom-label", "agent", "session:oom", null, "session:oom"),
    );
    try std.testing.expectEqual(@as(usize, 0), mgr.tasks.count());
    try std.testing.expectEqual(@as(u32, 0), mgr.getRunningCount());
}
