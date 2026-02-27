const std = @import("std");
const builtin = @import("builtin");
const providers = @import("../providers/root.zig");
const Tool = @import("../tools/root.zig").Tool;
const skills_mod = @import("../skills.zig");
const spawn_tool_mod = @import("../tools/spawn.zig");
const subagent_mod = @import("../subagent.zig");
const memory_mod = @import("../memory/root.zig");
const config_types = @import("../config_types.zig");
const config_module = @import("../config.zig");
const capabilities_mod = @import("../capabilities.zig");
const config_mutator = @import("../config_mutator.zig");
const context_tokens = @import("context_tokens.zig");
const max_tokens_resolver = @import("max_tokens.zig");

const SlashCommand = struct {
    name: []const u8,
    arg: []const u8,
};

pub const BARE_SESSION_RESET_PROMPT =
    "A new session was started via /new or /reset. Execute your Session Startup sequence now - read the required files before responding to the user. Then greet the user in your configured persona, if one is provided. Be yourself - use your defined voice, mannerisms, and mood. Keep it to 1-3 sentences and ask what they want to do. If the runtime model differs from default_model in the system prompt, mention the default model. Do not mention internal steps, files, tools, or reasoning.";

fn parseSlashCommand(message: []const u8) ?SlashCommand {
    const trimmed = std.mem.trim(u8, message, " \t\r\n");
    if (trimmed.len <= 1 or trimmed[0] != '/') return null;

    const body = trimmed[1..];
    var split_idx: usize = 0;
    while (split_idx < body.len) : (split_idx += 1) {
        const ch = body[split_idx];
        if (ch == ':' or ch == ' ' or ch == '\t') break;
    }
    if (split_idx == 0) return null;

    const raw_name = body[0..split_idx];
    const name = if (std.mem.indexOfScalar(u8, raw_name, '@')) |mention_sep|
        raw_name[0..mention_sep]
    else
        raw_name;
    if (name.len == 0) return null;
    var rest = body[split_idx..];
    if (rest.len > 0 and rest[0] == ':') {
        rest = rest[1..];
    }

    return .{
        .name = name,
        .arg = std.mem.trim(u8, rest, " \t"),
    };
}

fn isSlashName(cmd: SlashCommand, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(cmd.name, expected);
}

pub fn bareSessionResetPrompt(message: []const u8) ?[]const u8 {
    const cmd = parseSlashCommand(message) orelse return null;
    if (!(isSlashName(cmd, "new") or isSlashName(cmd, "reset"))) return null;
    if (cmd.arg.len != 0) return null;
    return BARE_SESSION_RESET_PROMPT;
}

fn firstToken(arg: []const u8) []const u8 {
    var it = std.mem.tokenizeAny(u8, arg, " \t");
    return it.next() orelse "";
}

fn parsePositiveUsize(raw: []const u8) ?usize {
    const n = std.fmt.parseInt(usize, raw, 10) catch return null;
    if (n == 0) return null;
    return n;
}

fn isInternalMemoryEntryKeyOrContent(key: []const u8, content: []const u8) bool {
    return memory_mod.isInternalMemoryEntryKeyOrContent(key, content);
}

fn memoryRuntimePtr(self: anytype) ?*memory_mod.MemoryRuntime {
    return if (@hasField(@TypeOf(self.*), "mem_rt")) self.mem_rt else null;
}

fn setModelName(self: anytype, model: []const u8) !void {
    const owned_model = try self.allocator.dupe(u8, model);
    if (self.model_name_owned) self.allocator.free(self.model_name);
    self.model_name = owned_model;
    self.model_name_owned = true;

    if (@hasField(@TypeOf(self.*), "token_limit")) {
        const token_limit_override: ?u64 = if (@hasField(@TypeOf(self.*), "token_limit_override"))
            self.token_limit_override
        else
            null;
        self.token_limit = context_tokens.resolveContextTokens(token_limit_override, self.model_name);
    }

    if (@hasField(@TypeOf(self.*), "max_tokens")) {
        const max_tokens_override: ?u32 = if (@hasField(@TypeOf(self.*), "max_tokens_override"))
            self.max_tokens_override
        else
            null;
        var resolved_max_tokens = max_tokens_resolver.resolveMaxTokens(max_tokens_override, self.model_name);
        if (@hasField(@TypeOf(self.*), "token_limit")) {
            const token_limit_cap: u32 = @intCast(@min(self.token_limit, @as(u64, std.math.maxInt(u32))));
            resolved_max_tokens = @min(resolved_max_tokens, token_limit_cap);
        }
        self.max_tokens = resolved_max_tokens;
    }
}

fn setDefaultProvider(self: anytype, provider_name: []const u8) !void {
    if (!@hasField(@TypeOf(self.*), "default_provider")) return;
    const owned_provider = try self.allocator.dupe(u8, provider_name);
    if (@hasField(@TypeOf(self.*), "default_provider_owned")) {
        if (self.default_provider_owned) self.allocator.free(self.default_provider);
        self.default_provider_owned = true;
    }
    self.default_provider = owned_provider;
}

fn isConfiguredProviderName(self: anytype, provider_name: []const u8) bool {
    if (!@hasField(@TypeOf(self.*), "configured_providers")) return false;
    for (self.configured_providers) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, provider_name)) return true;
    }
    return false;
}

fn hasExplicitProviderPrefix(self: anytype, model: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, model, '/') orelse return false;
    if (slash == 0 or slash + 1 >= model.len) return false;

    const provider_candidate = model[0..slash];
    if (providers.classifyProvider(provider_candidate) != .unknown) return true;

    var lower_buf: [128]u8 = undefined;
    if (provider_candidate.len <= lower_buf.len) {
        _ = std.ascii.lowerString(lower_buf[0..provider_candidate.len], provider_candidate);
        if (providers.classifyProvider(lower_buf[0..provider_candidate.len]) != .unknown) return true;
    }

    return isConfiguredProviderName(self, provider_candidate);
}

fn configPrimaryModelForSelection(self: anytype, model: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, model, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;

    if (hasExplicitProviderPrefix(self, trimmed)) {
        return try self.allocator.dupe(u8, trimmed);
    }

    const provider = if (@hasField(@TypeOf(self.*), "default_provider") and self.default_provider.len > 0)
        self.default_provider
    else
        "openrouter";
    return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ provider, trimmed });
}

fn persistSelectedModelToConfig(self: anytype, model: []const u8) !void {
    if (builtin.is_test) return;

    const primary = try configPrimaryModelForSelection(self, model);
    defer self.allocator.free(primary);

    var result = try config_mutator.mutateDefaultConfig(
        self.allocator,
        .set,
        "agents.defaults.model.primary",
        primary,
        .{ .apply = true },
    );
    defer config_mutator.freeMutationResult(self.allocator, &result);
}

fn invalidateSystemPromptCache(self: anytype) void {
    if (@hasField(@TypeOf(self.*), "has_system_prompt")) {
        self.has_system_prompt = false;
    }
    if (@hasField(@TypeOf(self.*), "system_prompt_has_conversation_context")) {
        self.system_prompt_has_conversation_context = false;
    }
}

test "configPrimaryModelForSelection treats unknown leading segment as model for default provider" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection keeps explicit known provider prefix" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "openrouter/inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection treats known provider prefix case-insensitively" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "OpenRouter/inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("OpenRouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection keeps explicit configured custom provider prefix" {
    const allocator = std.testing.allocator;
    const configured = [_]config_types.ProviderEntry{
        .{ .name = "customgw", .base_url = "https://example.com/v1" },
    };
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &configured,
    };

    const primary = try configPrimaryModelForSelection(&dummy, "customgw/model-a");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("customgw/model-a", primary);
}

test "parseSlashCommand strips bot mention from command name" {
    const parsed = parseSlashCommand("/model@nullclaw_bot openrouter/inception/mercury") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("model", parsed.name);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", parsed.arg);
}

test "parseSlashCommand strips bot mention with colon separator" {
    const parsed = parseSlashCommand("/model@nullclaw_bot: gpt-5.2") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("model", parsed.name);
    try std.testing.expectEqualStrings("gpt-5.2", parsed.arg);
}

test "bareSessionResetPrompt returns prompt for bare /new" {
    const prompt = bareSessionResetPrompt("/new") orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.indexOf(u8, prompt, "Execute your Session Startup sequence now") != null);
}

test "bareSessionResetPrompt returns prompt for bare /reset with mention" {
    const prompt = bareSessionResetPrompt("/reset@nullclaw_bot:") orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.indexOf(u8, prompt, "A new session was started via /new or /reset") != null);
}

test "bareSessionResetPrompt ignores /reset with argument" {
    try std.testing.expect(bareSessionResetPrompt("/reset gpt-4o-mini") == null);
}

test "hotApplyConfigChange updates model primary as provider plus model" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"openrouter/inception/mercury\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("inception/mercury", dummy.model_name);
    try std.testing.expectEqualStrings("inception/mercury", dummy.default_model);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
}

test "hotApplyConfigChange rejects malformed model primary" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
    }{
        .allocator = allocator,
        .model_name = "stable-model",
        .model_name_owned = false,
        .default_provider = "openrouter",
        .default_provider_owned = false,
        .default_model = "stable-model",
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"malformed\"",
    );
    try std.testing.expect(!applied);
    try std.testing.expectEqualStrings("stable-model", dummy.model_name);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
}

test "hotApplyConfigChange model primary refreshes token and max token limits" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"openrouter/gpt-4o\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("gpt-4o", dummy.model_name);
    try std.testing.expectEqualStrings("gpt-4o", dummy.default_model);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
    try std.testing.expectEqual(@as(u64, 128_000), dummy.token_limit);
    try std.testing.expectEqual(@as(u32, 8192), dummy.max_tokens);
}

test "splitPrimaryModelRef parses provider model format" {
    const parsed = splitPrimaryModelRef("openrouter/inception/mercury") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("openrouter", parsed.provider);
    try std.testing.expectEqualStrings("inception/mercury", parsed.model);
}

test "splitPrimaryModelRef rejects malformed values" {
    try std.testing.expect(splitPrimaryModelRef("noslash") == null);
    try std.testing.expect(splitPrimaryModelRef("/model-only") == null);
    try std.testing.expect(splitPrimaryModelRef("provider/") == null);
}

fn setExecNodeId(self: anytype, value: ?[]const u8) !void {
    if (self.exec_node_id_owned and self.exec_node_id != null) {
        self.allocator.free(self.exec_node_id.?);
    }
    self.exec_node_id_owned = false;
    self.exec_node_id = null;
    if (value) |v| {
        self.exec_node_id = try self.allocator.dupe(u8, v);
        self.exec_node_id_owned = true;
    }
}

fn setTtsProvider(self: anytype, value: ?[]const u8) !void {
    if (self.tts_provider_owned and self.tts_provider != null) {
        self.allocator.free(self.tts_provider.?);
    }
    self.tts_provider_owned = false;
    self.tts_provider = null;
    if (value) |v| {
        self.tts_provider = try self.allocator.dupe(u8, v);
        self.tts_provider_owned = true;
    }
}

fn setFocusTarget(self: anytype, value: ?[]const u8) !void {
    if (self.focus_target_owned and self.focus_target != null) {
        self.allocator.free(self.focus_target.?);
    }
    self.focus_target_owned = false;
    self.focus_target = null;
    if (value) |v| {
        self.focus_target = try self.allocator.dupe(u8, v);
        self.focus_target_owned = true;
    }
}

fn setDockTarget(self: anytype, value: ?[]const u8) !void {
    if (self.dock_target_owned and self.dock_target != null) {
        self.allocator.free(self.dock_target.?);
    }
    self.dock_target_owned = false;
    self.dock_target = null;
    if (value) |v| {
        self.dock_target = try self.allocator.dupe(u8, v);
        self.dock_target_owned = true;
    }
}

fn clearPendingExecCommand(self: anytype) void {
    if (self.pending_exec_command_owned and self.pending_exec_command != null) {
        self.allocator.free(self.pending_exec_command.?);
    }
    self.pending_exec_command = null;
    self.pending_exec_command_owned = false;
}

fn setPendingExecCommand(self: anytype, command: []const u8) !void {
    clearPendingExecCommand(self);
    self.pending_exec_command = try self.allocator.dupe(u8, command);
    self.pending_exec_command_owned = true;
    self.pending_exec_id += 1;
    if (self.pending_exec_id == 0) self.pending_exec_id = 1;
}

fn splitFirstToken(arg: []const u8) struct { head: []const u8, tail: []const u8 } {
    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) return .{ .head = "", .tail = "" };

    var i: usize = 0;
    while (i < trimmed.len and trimmed[i] != ' ' and trimmed[i] != '\t') : (i += 1) {}

    if (i >= trimmed.len) return .{ .head = trimmed, .tail = "" };
    return .{
        .head = trimmed[0..i],
        .tail = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
    };
}

fn parseTaskId(raw: []const u8) ?u64 {
    if (raw.len == 0) return null;
    return std.fmt.parseInt(u64, raw, 10) catch null;
}

fn findSpawnTool(self: anytype) ?*spawn_tool_mod.SpawnTool {
    for (self.tools) |t| {
        if (!std.ascii.eqlIgnoreCase(t.name(), "spawn")) continue;
        return @ptrCast(@alignCast(t.ptr));
    }
    return null;
}

fn findSubagentManager(self: anytype) ?*subagent_mod.SubagentManager {
    const spawn_tool = findSpawnTool(self) orelse return null;
    return spawn_tool.manager;
}

pub fn refreshSubagentToolContext(self: anytype) void {
    const spawn_tool = findSpawnTool(self) orelse return;
    spawn_tool.default_channel = "agent";
    spawn_tool.default_chat_id = self.memory_session_id orelse "agent";
}

fn findShellTool(self: anytype) ?Tool {
    for (self.tools) |t| {
        if (std.ascii.eqlIgnoreCase(t.name(), "shell")) return t;
    }
    return null;
}

fn clearSessionState(self: anytype) void {
    self.clearHistory();
    clearPendingExecCommand(self);

    if (self.session_store) |store| {
        store.clearAutoSaved(self.memory_session_id) catch {};
    }
}

fn formatWhoAmI(self: anytype) ![]const u8 {
    const session_id = self.memory_session_id orelse "unknown";
    return try std.fmt.allocPrint(
        self.allocator,
        "Session: {s}\nModel: {s}",
        .{ session_id, self.model_name },
    );
}

fn parseReasoningEffort(raw: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return "";
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return "minimal";
    if (std.ascii.eqlIgnoreCase(raw, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(raw, "high")) return "high";
    if (std.ascii.eqlIgnoreCase(raw, "xhigh")) return "xhigh";
    return null;
}

fn parseVerboseLevel(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    return null;
}

fn parseReasoningMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "stream")) return .stream;
    return null;
}

fn parseUsageMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "tokens")) return .tokens;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    if (std.ascii.eqlIgnoreCase(raw, "cost")) return .cost;
    return null;
}

fn parseExecHost(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "sandbox")) return .sandbox;
    if (std.ascii.eqlIgnoreCase(raw, "gateway")) return .gateway;
    if (std.ascii.eqlIgnoreCase(raw, "node")) return .node;
    return null;
}

fn parseExecSecurity(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "deny")) return .deny;
    if (std.ascii.eqlIgnoreCase(raw, "allowlist")) return .allowlist;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    return null;
}

fn parseExecAsk(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on-miss") or std.ascii.eqlIgnoreCase(raw, "on_miss")) return .on_miss;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    return null;
}

fn parseQueueMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "serial")) return .serial;
    if (std.ascii.eqlIgnoreCase(raw, "latest")) return .latest;
    if (std.ascii.eqlIgnoreCase(raw, "debounce")) return .debounce;
    return null;
}

fn parseQueueDrop(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "summarize")) return .summarize;
    if (std.ascii.eqlIgnoreCase(raw, "oldest")) return .oldest;
    if (std.ascii.eqlIgnoreCase(raw, "newest")) return .newest;
    return null;
}

fn parseTtsMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    if (std.ascii.eqlIgnoreCase(raw, "inbound")) return .inbound;
    if (std.ascii.eqlIgnoreCase(raw, "tagged")) return .tagged;
    return null;
}

fn parseActivationMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "mention")) return .mention;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    return null;
}

fn parseSendMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "inherit")) return .inherit;
    return null;
}

fn parseDurationMs(raw: []const u8) ?u32 {
    if (raw.len == 0) return null;
    if (std.mem.endsWith(u8, raw, "ms")) {
        const base = raw[0 .. raw.len - 2];
        return std.fmt.parseInt(u32, base, 10) catch null;
    }
    if (std.mem.endsWith(u8, raw, "s")) {
        const base = raw[0 .. raw.len - 1];
        const seconds = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, seconds, 1000) catch null;
    }
    if (std.mem.endsWith(u8, raw, "m")) {
        const base = raw[0 .. raw.len - 1];
        const minutes = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, minutes, 60_000) catch null;
    }
    if (std.mem.endsWith(u8, raw, "h")) {
        const base = raw[0 .. raw.len - 1];
        const hours = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, hours, 3_600_000) catch null;
    }
    return std.fmt.parseInt(u32, raw, 10) catch null;
}

fn parseDurationSeconds(raw: []const u8) ?u64 {
    const ms = parseDurationMs(raw) orelse return null;
    return @as(u64, @intCast(ms)) / 1000;
}

fn resetRuntimeCommandState(self: anytype) void {
    self.reasoning_effort = null;
    self.verbose_level = .off;
    self.reasoning_mode = .off;
    self.usage_mode = .off;
    self.exec_host = .gateway;
    self.exec_security = .allowlist;
    self.exec_ask = .on_miss;
    if (self.exec_node_id_owned and self.exec_node_id != null) self.allocator.free(self.exec_node_id.?);
    self.exec_node_id = null;
    self.exec_node_id_owned = false;
    self.queue_mode = .off;
    self.queue_debounce_ms = 0;
    self.queue_cap = 0;
    self.queue_drop = .summarize;
    self.tts_mode = .off;
    if (self.tts_provider_owned and self.tts_provider != null) self.allocator.free(self.tts_provider.?);
    self.tts_provider = null;
    self.tts_provider_owned = false;
    self.tts_limit_chars = 0;
    self.tts_summary = false;
    self.tts_audio = false;
    clearPendingExecCommand(self);
    self.session_ttl_secs = null;
    if (self.focus_target_owned and self.focus_target != null) self.allocator.free(self.focus_target.?);
    self.focus_target = null;
    self.focus_target_owned = false;
    if (self.dock_target_owned and self.dock_target != null) self.allocator.free(self.dock_target.?);
    self.dock_target = null;
    self.dock_target_owned = false;
    self.activation_mode = .mention;
    self.send_mode = .inherit;
}

fn formatStatus(self: anytype) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    const w = out.writer(self.allocator);

    try w.print("Model: {s}\n", .{self.model_name});
    try w.print("History: {d} messages\n", .{self.history.items.len});
    try w.print("Tokens used: {d}\n", .{self.total_tokens});
    try w.print("Tools: {d} available\n", .{self.tools.len});
    try w.print("Thinking: {s}\n", .{self.reasoning_effort orelse "off"});
    try w.print("Verbose: {s}\n", .{self.verbose_level.toSlice()});
    try w.print("Reasoning: {s}\n", .{self.reasoning_mode.toSlice()});
    try w.print("Usage: {s}\n", .{self.usage_mode.toSlice()});
    try w.print(
        "Exec: host={s} security={s} ask={s}",
        .{ self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
    if (self.exec_node_id) |id| try w.print(" node={s}", .{id});
    try w.writeAll("\n");
    try w.print(
        "Queue: mode={s} debounce={d}ms cap={d} drop={s}\n",
        .{ self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
    );
    try w.print("TTS: mode={s} provider={s}\n", .{ self.tts_mode.toSlice(), self.tts_provider orelse "default" });
    try w.print("Activation: {s}\n", .{self.activation_mode.toSlice()});
    try w.print("Send: {s}\n", .{self.send_mode.toSlice()});
    if (self.session_ttl_secs) |ttl| {
        try w.print("Session TTL: {d}s\n", .{ttl});
    } else {
        try w.writeAll("Session TTL: off\n");
    }
    return try out.toOwnedSlice(self.allocator);
}

fn handleThinkCommand(self: anytype, arg: []const u8) ![]const u8 {
    const level = firstToken(arg);
    if (level.len == 0 or std.ascii.eqlIgnoreCase(level, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Thinking: {s}", .{self.reasoning_effort orelse "off"});
    }

    const parsed = parseReasoningEffort(level) orelse
        return try self.allocator.dupe(u8, "Invalid /think value. Use: off|minimal|low|medium|high|xhigh");

    self.reasoning_effort = if (parsed.len == 0) null else parsed;
    return try std.fmt.allocPrint(self.allocator, "Thinking set to: {s}", .{self.reasoning_effort orelse "off"});
}

fn handleVerboseCommand(self: anytype, arg: []const u8) ![]const u8 {
    const level = firstToken(arg);
    if (level.len == 0 or std.ascii.eqlIgnoreCase(level, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Verbose: {s}", .{self.verbose_level.toSlice()});
    }

    const parsed = parseVerboseLevel(@TypeOf(self.verbose_level), level) orelse
        return try self.allocator.dupe(u8, "Invalid /verbose value. Use: on|full|off");
    self.verbose_level = parsed;
    return try std.fmt.allocPrint(self.allocator, "Verbose set to: {s}", .{self.verbose_level.toSlice()});
}

fn handleReasoningCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Reasoning output: {s}", .{self.reasoning_mode.toSlice()});
    }

    const parsed = parseReasoningMode(@TypeOf(self.reasoning_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid /reasoning value. Use: on|off|stream");
    self.reasoning_mode = parsed;
    return try std.fmt.allocPrint(self.allocator, "Reasoning output set to: {s}", .{self.reasoning_mode.toSlice()});
}

fn handleExecCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.print(
            "Exec: host={s} security={s} ask={s}",
            .{ self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
        );
        if (self.exec_node_id) |id| {
            try w.print(" node={s}", .{id});
        }
        return try out.toOwnedSlice(self.allocator);
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse
            return try self.allocator.dupe(u8, "Invalid /exec argument. Use host=<...> security=<...> ask=<...> node=<id>");
        const key = tok[0..eq];
        const value = tok[eq + 1 ..];
        if (value.len == 0) {
            return try self.allocator.dupe(u8, "Invalid /exec argument: empty value");
        }
        if (std.ascii.eqlIgnoreCase(key, "host")) {
            self.exec_host = parseExecHost(@TypeOf(self.exec_host), value) orelse
                return try self.allocator.dupe(u8, "Invalid host. Use: sandbox|gateway|node");
        } else if (std.ascii.eqlIgnoreCase(key, "security")) {
            self.exec_security = parseExecSecurity(@TypeOf(self.exec_security), value) orelse
                return try self.allocator.dupe(u8, "Invalid security. Use: deny|allowlist|full");
        } else if (std.ascii.eqlIgnoreCase(key, "ask")) {
            self.exec_ask = parseExecAsk(@TypeOf(self.exec_ask), value) orelse
                return try self.allocator.dupe(u8, "Invalid ask. Use: off|on-miss|always");
        } else if (std.ascii.eqlIgnoreCase(key, "node")) {
            try setExecNodeId(self, value);
        } else {
            return try std.fmt.allocPrint(self.allocator, "Unknown /exec key: {s}", .{key});
        }
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    const w = out.writer(self.allocator);
    try w.print(
        "Exec set: host={s} security={s} ask={s}",
        .{ self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
    if (self.exec_node_id) |id| {
        try w.print(" node={s}", .{id});
    }
    return try out.toOwnedSlice(self.allocator);
}

fn handleQueueCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Queue: mode={s} debounce={d}ms cap={d} drop={s}",
            .{ self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
        );
    }

    if (std.ascii.eqlIgnoreCase(arg, "reset")) {
        self.queue_mode = .off;
        self.queue_debounce_ms = 0;
        self.queue_cap = 0;
        self.queue_drop = .summarize;
        return try self.allocator.dupe(u8, "Queue settings reset.");
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        if (parseQueueMode(@TypeOf(self.queue_mode), tok)) |mode| {
            self.queue_mode = mode;
            continue;
        }

        const sep = std.mem.indexOfScalar(u8, tok, ':') orelse
            return try self.allocator.dupe(u8, "Invalid /queue argument. Use mode plus debounce:<dur> cap:<n> drop:<summarize|oldest|newest>");
        const key = tok[0..sep];
        const value = tok[sep + 1 ..];

        if (std.ascii.eqlIgnoreCase(key, "debounce")) {
            self.queue_debounce_ms = parseDurationMs(value) orelse
                return try self.allocator.dupe(u8, "Invalid debounce duration");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(key, "cap")) {
            self.queue_cap = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid queue cap");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(key, "drop")) {
            self.queue_drop = parseQueueDrop(@TypeOf(self.queue_drop), value) orelse
                return try self.allocator.dupe(u8, "Invalid drop mode");
            continue;
        }

        return try std.fmt.allocPrint(self.allocator, "Unknown /queue option: {s}", .{key});
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Queue set: mode={s} debounce={d}ms cap={d} drop={s}",
        .{ self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
    );
}

fn handleUsageCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Usage: {s}\nLast turn: prompt={d} completion={d} total={d}\nSession total: {d}",
            .{
                self.usage_mode.toSlice(),
                self.last_turn_usage.prompt_tokens,
                self.last_turn_usage.completion_tokens,
                self.last_turn_usage.total_tokens,
                self.total_tokens,
            },
        );
    }

    self.usage_mode = parseUsageMode(@TypeOf(self.usage_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid /usage value. Use: off|tokens|full|cost");
    return try std.fmt.allocPrint(self.allocator, "Usage mode set to: {s}", .{self.usage_mode.toSlice()});
}

fn handleTtsCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "TTS: mode={s} provider={s} limit={d} summary={s} audio={s}",
            .{
                self.tts_mode.toSlice(),
                self.tts_provider orelse "default",
                self.tts_limit_chars,
                if (self.tts_summary) "on" else "off",
                if (self.tts_audio) "on" else "off",
            },
        );
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        if (parseTtsMode(@TypeOf(self.tts_mode), tok)) |mode| {
            self.tts_mode = mode;
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "status")) continue;

        if (std.mem.startsWith(u8, tok, "provider=")) {
            const value = tok["provider=".len..];
            if (value.len == 0) return try self.allocator.dupe(u8, "Invalid provider value");
            try setTtsProvider(self, value);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "provider")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing provider value");
            try setTtsProvider(self, value);
            continue;
        }

        if (std.mem.startsWith(u8, tok, "limit=")) {
            const value = tok["limit=".len..];
            self.tts_limit_chars = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid TTS limit");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "limit")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing limit value");
            self.tts_limit_chars = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid TTS limit");
            continue;
        }

        if (std.ascii.eqlIgnoreCase(tok, "summary")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing summary value");
            if (std.ascii.eqlIgnoreCase(value, "on")) {
                self.tts_summary = true;
            } else if (std.ascii.eqlIgnoreCase(value, "off")) {
                self.tts_summary = false;
            } else {
                return try self.allocator.dupe(u8, "Invalid summary value. Use on|off");
            }
            continue;
        }

        if (std.ascii.eqlIgnoreCase(tok, "audio")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing audio value");
            if (std.ascii.eqlIgnoreCase(value, "on")) {
                self.tts_audio = true;
            } else if (std.ascii.eqlIgnoreCase(value, "off")) {
                self.tts_audio = false;
            } else {
                return try self.allocator.dupe(u8, "Invalid audio value. Use on|off");
            }
            continue;
        }

        return try std.fmt.allocPrint(self.allocator, "Unknown /tts option: {s}", .{tok});
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "TTS set: mode={s} provider={s} limit={d} summary={s} audio={s}",
        .{
            self.tts_mode.toSlice(),
            self.tts_provider orelse "default",
            self.tts_limit_chars,
            if (self.tts_summary) "on" else "off",
            if (self.tts_audio) "on" else "off",
        },
    );
}

fn handleAllowlistCommand(self: anytype, arg: []const u8) ![]const u8 {
    _ = arg;
    if (self.policy) |pol| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.writeAll("Allowlisted commands:\n");
        for (pol.allowed_commands) |cmd| {
            try w.print("  - {s}\n", .{cmd});
        }
        return try out.toOwnedSlice(self.allocator);
    }
    return try self.allocator.dupe(u8, "No runtime allowlist policy attached.");
}

fn handleContextCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (std.ascii.eqlIgnoreCase(mode, "json")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "{{\"model\":\"{s}\",\"history_messages\":{d},\"token_estimate\":{d},\"tools\":{d}}}",
            .{ self.model_name, self.history.items.len, self.tokenEstimate(), self.tools.len },
        );
    }

    if (std.ascii.eqlIgnoreCase(mode, "detail")) {
        var sys: usize = 0;
        var usr: usize = 0;
        var asst: usize = 0;
        var tool: usize = 0;
        for (self.history.items) |entry| {
            switch (entry.role) {
                .system => sys += 1,
                .user => usr += 1,
                .assistant => asst += 1,
                .tool => tool += 1,
            }
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Context detail:\n  model: {s}\n  messages: {d}\n  token_estimate: {d}\n  tools: {d}\n  by_role: system={d} user={d} assistant={d} tool={d}",
            .{ self.model_name, self.history.items.len, self.tokenEstimate(), self.tools.len, sys, usr, asst, tool },
        );
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Context: messages={d}, token_estimate={d}, tools={d}",
        .{ self.history.items.len, self.tokenEstimate(), self.tools.len },
    );
}

fn handleExportSessionCommand(self: anytype, arg: []const u8) ![]const u8 {
    const raw_path = firstToken(arg);
    const path = if (raw_path.len == 0)
        try std.fmt.allocPrint(self.allocator, "{s}/session-{d}.md", .{ self.workspace_dir, std.time.timestamp() })
    else if (std.fs.path.isAbsolute(raw_path))
        try self.allocator.dupe(u8, raw_path)
    else
        try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.workspace_dir, raw_path });
    defer self.allocator.free(path);

    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.createFileAbsolute(path, .{ .truncate = true, .read = false })
    else
        try std.fs.cwd().createFile(path, .{ .truncate = true, .read = false });
    defer file.close();
    var out_buf: [4096]u8 = undefined;
    var bw = file.writer(&out_buf);
    const w = &bw.interface;
    try w.print("# Session export\n\nModel: `{s}`\n\n", .{self.model_name});
    for (self.history.items) |entry| {
        const role = switch (entry.role) {
            .system => "system",
            .user => "user",
            .assistant => "assistant",
            .tool => "tool",
        };
        try w.print("## {s}\n\n{s}\n\n", .{ role, entry.content });
    }
    try w.flush();

    return try std.fmt.allocPrint(self.allocator, "Session exported to: {s}", .{path});
}

fn handleSessionCommand(self: anytype, arg: []const u8) ![]const u8 {
    var it = std.mem.tokenizeAny(u8, arg, " \t");
    const sub = it.next() orelse return try std.fmt.allocPrint(self.allocator, "Session TTL: {s}", .{if (self.session_ttl_secs) |_| "set" else "off"});
    if (std.ascii.eqlIgnoreCase(sub, "ttl")) {
        const ttl = it.next() orelse {
            if (self.session_ttl_secs) |v| {
                return try std.fmt.allocPrint(self.allocator, "Session TTL: {d}s", .{v});
            }
            return try self.allocator.dupe(u8, "Session TTL: off");
        };
        if (std.ascii.eqlIgnoreCase(ttl, "off")) {
            self.session_ttl_secs = null;
            return try self.allocator.dupe(u8, "Session TTL disabled.");
        }
        self.session_ttl_secs = parseDurationSeconds(ttl) orelse
            return try self.allocator.dupe(u8, "Invalid TTL duration.");
        return try std.fmt.allocPrint(self.allocator, "Session TTL set to {d}s.", .{self.session_ttl_secs.?});
    }
    return try self.allocator.dupe(u8, "Unknown /session command. Use: /session ttl <duration|off>");
}

fn handleFocusCommand(self: anytype, arg: []const u8) ![]const u8 {
    const target = std.mem.trim(u8, arg, " \t");
    if (target.len == 0) {
        return try self.allocator.dupe(u8, "Missing focus target.");
    }
    try setFocusTarget(self, target);
    return try std.fmt.allocPrint(self.allocator, "Focused on: {s}", .{target});
}

fn handleUnfocusCommand(self: anytype) ![]const u8 {
    try setFocusTarget(self, null);
    return try self.allocator.dupe(u8, "Focus cleared.");
}

fn handleDockCommand(self: anytype, channel: []const u8) ![]const u8 {
    try setDockTarget(self, channel);
    return try std.fmt.allocPrint(self.allocator, "Dock target set to: {s}", .{channel});
}

fn handleActivationCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Activation mode: {s}", .{self.activation_mode.toSlice()});
    }
    self.activation_mode = parseActivationMode(@TypeOf(self.activation_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid activation mode. Use: mention|always");
    return try std.fmt.allocPrint(self.allocator, "Activation mode set to: {s}", .{self.activation_mode.toSlice()});
}

fn handleSendCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Send mode: {s}", .{self.send_mode.toSlice()});
    }
    self.send_mode = parseSendMode(@TypeOf(self.send_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid send mode. Use: on|off|inherit");
    return try std.fmt.allocPrint(self.allocator, "Send mode set to: {s}", .{self.send_mode.toSlice()});
}

fn handleElevatedCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Elevated policy: security={s} ask={s}",
            .{ self.exec_security.toSlice(), self.exec_ask.toSlice() },
        );
    }

    if (std.ascii.eqlIgnoreCase(mode, "full")) {
        self.exec_security = .full;
        self.exec_ask = .off;
    } else if (std.ascii.eqlIgnoreCase(mode, "ask")) {
        self.exec_security = .allowlist;
        self.exec_ask = .on_miss;
    } else if (std.ascii.eqlIgnoreCase(mode, "on")) {
        self.exec_security = .allowlist;
        self.exec_ask = .on_miss;
    } else if (std.ascii.eqlIgnoreCase(mode, "off")) {
        self.exec_security = .deny;
        self.exec_ask = .off;
    } else {
        return try self.allocator.dupe(u8, "Invalid /elevated value. Use: on|off|ask|full");
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Elevated policy set: security={s} ask={s}",
        .{ self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
}

fn parseApproveDecision(raw: []const u8) ?enum { allow_once, allow_always, deny } {
    if (std.ascii.eqlIgnoreCase(raw, "allow") or
        std.ascii.eqlIgnoreCase(raw, "once") or
        std.ascii.eqlIgnoreCase(raw, "allow-once") or
        std.ascii.eqlIgnoreCase(raw, "allowonce"))
    {
        return .allow_once;
    }
    if (std.ascii.eqlIgnoreCase(raw, "always") or
        std.ascii.eqlIgnoreCase(raw, "allow-always") or
        std.ascii.eqlIgnoreCase(raw, "allowalways"))
    {
        return .allow_always;
    }
    if (std.ascii.eqlIgnoreCase(raw, "deny") or
        std.ascii.eqlIgnoreCase(raw, "reject") or
        std.ascii.eqlIgnoreCase(raw, "block"))
    {
        return .deny;
    }
    return null;
}

fn runShellCommand(self: anytype, command: []const u8, skip_approval_gate: bool) ![]const u8 {
    if (self.exec_host == .node) {
        return try self.allocator.dupe(u8, "Exec blocked: host=node is not available in this runtime");
    }
    if (self.exec_security == .deny) {
        return try self.allocator.dupe(u8, "Exec blocked by /exec security=deny");
    }
    if (!skip_approval_gate and self.exec_ask == .always) {
        try setPendingExecCommand(self, command);
        return try std.fmt.allocPrint(
            self.allocator,
            "Exec approval required (id={d}). Use /approve {d} allow-once|allow-always|deny",
            .{ self.pending_exec_id, self.pending_exec_id },
        );
    }
    if (self.exec_security == .allowlist) {
        if (self.policy) |pol| {
            if (!pol.isCommandAllowed(command)) {
                return try self.allocator.dupe(u8, "Exec blocked by allowlist policy");
            }
        }
    }

    const shell_tool = findShellTool(self) orelse
        return try self.allocator.dupe(u8, "Shell tool is not enabled.");

    var arena_impl = std.heap.ArenaAllocator.init(self.allocator);
    defer arena_impl.deinit();
    const arena = arena_impl.allocator();

    var args = std.json.ObjectMap.init(arena);
    try args.put("command", .{ .string = command });

    const result = shell_tool.execute(arena, args) catch |err| {
        return try std.fmt.allocPrint(self.allocator, "Bash failed: {s}", .{@errorName(err)});
    };

    const text = if (result.success) result.output else (result.error_msg orelse result.output);
    return try self.allocator.dupe(u8, text);
}

fn handleApproveCommand(self: anytype, arg: []const u8) ![]const u8 {
    const pending_command = self.pending_exec_command orelse
        return try self.allocator.dupe(u8, "No pending approval requests.");

    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Pending approval id={d} for command: {s}\nUse /approve {d} allow-once|allow-always|deny",
            .{ self.pending_exec_id, pending_command, self.pending_exec_id },
        );
    }

    var requested_id: ?u64 = null;
    var decision_token: []const u8 = firstToken(trimmed);

    const first = splitFirstToken(trimmed);
    if (parseTaskId(first.head)) |id| {
        requested_id = id;
        decision_token = firstToken(first.tail);
    }

    const decision = parseApproveDecision(decision_token) orelse
        return try self.allocator.dupe(u8, "Usage: /approve <id?> allow-once|allow-always|deny");

    if (requested_id) |id| {
        if (id != self.pending_exec_id) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Approval id mismatch. Pending id is {d}.",
                .{self.pending_exec_id},
            );
        }
    }

    if (decision == .deny) {
        clearPendingExecCommand(self);
        return try self.allocator.dupe(u8, "Exec request denied.");
    }

    const command_to_run = pending_command;
    defer clearPendingExecCommand(self);

    if (decision == .allow_always) {
        self.exec_ask = .off;
    }

    const output = try runShellCommand(self, command_to_run, true);
    defer self.allocator.free(output);
    return try std.fmt.allocPrint(
        self.allocator,
        "Approved exec (id={d}).\n{s}",
        .{ self.pending_exec_id, output },
    );
}

fn taskStatusLabel(status: subagent_mod.TaskStatus) []const u8 {
    return switch (status) {
        .running => "running",
        .completed => "completed",
        .failed => "failed",
    };
}

fn currentSubagentSessionKey(self: anytype) []const u8 {
    return self.memory_session_id orelse "agent";
}

fn taskBelongsToCurrentSession(self: anytype, state: *const subagent_mod.TaskState) bool {
    const task_session = state.session_key orelse return false;
    return std.mem.eql(u8, task_session, currentSubagentSessionKey(self));
}

fn freeSubagentTaskState(manager: *subagent_mod.SubagentManager, state: *subagent_mod.TaskState) void {
    if (state.thread) |thread| {
        thread.join();
    }
    if (state.result) |r| manager.allocator.free(r);
    if (state.error_msg) |e| manager.allocator.free(e);
    if (state.session_key) |sk| manager.allocator.free(sk);
    manager.allocator.free(state.label);
    manager.allocator.destroy(state);
}

fn formatSubagentList(self: anytype, include_details: bool) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Subagent manager is not enabled.");

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    const w = out.writer(self.allocator);

    manager.mutex.lock();
    defer manager.mutex.unlock();

    var running: u32 = 0;
    var completed: u32 = 0;
    var failed: u32 = 0;
    var visible_count: u32 = 0;

    var it = manager.tasks.iterator();
    while (it.next()) |entry| {
        const task_id = entry.key_ptr.*;
        const state = entry.value_ptr.*;
        if (!taskBelongsToCurrentSession(self, state)) continue;
        visible_count += 1;
        switch (state.status) {
            .running => running += 1,
            .completed => completed += 1,
            .failed => failed += 1,
        }

        try w.print("#{d} {s} [{s}]", .{ task_id, state.label, taskStatusLabel(state.status) });
        if (include_details and state.status == .failed and state.error_msg != null) {
            try w.print(" error={s}", .{state.error_msg.?});
        }
        try w.writeAll("\n");
    }

    if (visible_count == 0) {
        try w.writeAll("No subagents tracked in this session.");
        return try out.toOwnedSlice(self.allocator);
    }

    try w.print("Totals: running={d}, completed={d}, failed={d}", .{ running, completed, failed });
    return try out.toOwnedSlice(self.allocator);
}

fn spawnSubagentTask(self: anytype, task: []const u8, label: []const u8) ![]const u8 {
    const trimmed_task = std.mem.trim(u8, task, " \t");
    if (trimmed_task.len == 0) {
        return try self.allocator.dupe(u8, "Usage: /subagents spawn <task>");
    }

    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Spawn tool is not enabled.");

    const origin_chat = self.memory_session_id orelse "agent";
    const task_id = manager.spawn(trimmed_task, label, "agent", origin_chat) catch |err| {
        return switch (err) {
            error.TooManyConcurrentSubagents => try self.allocator.dupe(u8, "Too many concurrent subagents. Wait for a task to finish."),
            else => try std.fmt.allocPrint(self.allocator, "Failed to spawn subagent: {s}", .{@errorName(err)}),
        };
    };

    return try std.fmt.allocPrint(
        self.allocator,
        "Spawned subagent task #{d} ({s}).",
        .{ task_id, label },
    );
}

fn handleAgentsCommand(self: anytype) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Active agents: 1 (current session). Subagents are not enabled.");

    manager.mutex.lock();
    defer manager.mutex.unlock();
    var tracked: u32 = 0;
    var running: u32 = 0;

    var it = manager.tasks.iterator();
    while (it.next()) |entry| {
        const state = entry.value_ptr.*;
        if (!taskBelongsToCurrentSession(self, state)) continue;
        tracked += 1;
        if (state.status == .running) running += 1;
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Active agents: 1 main + {d} running subagents ({d} tracked tasks).",
        .{ running, tracked },
    );
}

fn handleKillCommand(self: anytype, arg: []const u8) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Subagent manager is not enabled.");

    const target = firstToken(arg);
    if (target.len == 0) {
        return try self.allocator.dupe(u8, "Usage: /kill <id|all>");
    }

    if (std.ascii.eqlIgnoreCase(target, "all")) {
        var ids: std.ArrayListUnmanaged(u64) = .empty;
        defer ids.deinit(self.allocator);

        manager.mutex.lock();
        defer manager.mutex.unlock();

        var running: u32 = 0;
        var it = manager.tasks.iterator();
        while (it.next()) |entry| {
            const task_id = entry.key_ptr.*;
            const state = entry.value_ptr.*;
            if (!taskBelongsToCurrentSession(self, state)) continue;
            if (state.status == .running) {
                running += 1;
            } else {
                try ids.append(self.allocator, task_id);
            }
        }

        var removed: u32 = 0;
        for (ids.items) |task_id| {
            if (manager.tasks.fetchRemove(task_id)) |kv| {
                freeSubagentTaskState(manager, kv.value);
                removed += 1;
            }
        }

        if (running > 0) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Removed {d} completed tasks; {d} running tasks cannot be interrupted in this runtime.",
                .{ removed, running },
            );
        }
        return try std.fmt.allocPrint(self.allocator, "Removed {d} completed tasks.", .{removed});
    }

    const task_id = parseTaskId(target) orelse
        return try self.allocator.dupe(u8, "Usage: /kill <id|all>");

    manager.mutex.lock();
    defer manager.mutex.unlock();

    const state = manager.tasks.get(task_id) orelse
        return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
    if (!taskBelongsToCurrentSession(self, state)) {
        return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
    }
    if (state.status == .running) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Task #{d} is running and cannot be interrupted in this runtime.",
            .{task_id},
        );
    }

    if (manager.tasks.fetchRemove(task_id)) |kv| {
        freeSubagentTaskState(manager, kv.value);
        return try std.fmt.allocPrint(self.allocator, "Task #{d} removed.", .{task_id});
    }
    return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
}

fn handleSubagentsCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const action = parsed.head;

    if (action.len == 0 or std.ascii.eqlIgnoreCase(action, "list") or std.ascii.eqlIgnoreCase(action, "status")) {
        return try formatSubagentList(self, false);
    }
    if (std.ascii.eqlIgnoreCase(action, "help")) {
        return try self.allocator.dupe(u8,
            \\Usage:
            \\  /subagents
            \\  /subagents list
            \\  /subagents spawn <task>
            \\  /subagents info <id>
            \\  /subagents kill <id|all>
        );
    }
    if (std.ascii.eqlIgnoreCase(action, "spawn")) {
        return try spawnSubagentTask(self, parsed.tail, "subagent");
    }
    if (std.ascii.eqlIgnoreCase(action, "info")) {
        const id_text = firstToken(parsed.tail);
        const task_id = parseTaskId(id_text) orelse
            return try self.allocator.dupe(u8, "Usage: /subagents info <id>");

        const manager = findSubagentManager(self) orelse
            return try self.allocator.dupe(u8, "Subagent manager is not enabled.");
        manager.mutex.lock();
        defer manager.mutex.unlock();

        const state = manager.tasks.get(task_id) orelse
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        if (!taskBelongsToCurrentSession(self, state)) {
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        }

        if (state.status == .running) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]",
                .{ task_id, state.label, taskStatusLabel(state.status) },
            );
        }
        if (state.error_msg) |err_msg| {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]\nError: {s}",
                .{ task_id, state.label, taskStatusLabel(state.status), err_msg },
            );
        }
        if (state.result) |result| {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]\nResult:\n{s}",
                .{ task_id, state.label, taskStatusLabel(state.status), result },
            );
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Task #{d}: {s} [{s}]",
            .{ task_id, state.label, taskStatusLabel(state.status) },
        );
    }
    if (std.ascii.eqlIgnoreCase(action, "kill")) {
        return try handleKillCommand(self, parsed.tail);
    }

    return try self.allocator.dupe(u8, "Unknown /subagents action. Use /subagents help.");
}

fn handleSteerCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const id_text = parsed.head;
    const message = parsed.tail;
    const task_id = parseTaskId(id_text) orelse
        return try self.allocator.dupe(u8, "Usage: /steer <id> <message>");
    if (message.len == 0) return try self.allocator.dupe(u8, "Usage: /steer <id> <message>");

    if (findSubagentManager(self)) |manager| {
        manager.mutex.lock();
        defer manager.mutex.unlock();
        const state = manager.tasks.get(task_id) orelse
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        if (!taskBelongsToCurrentSession(self, state)) {
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        }
    }

    const follow_up = try std.fmt.allocPrint(
        self.allocator,
        "Follow up for task #{d}: {s}",
        .{ task_id, message },
    );
    defer self.allocator.free(follow_up);

    const spawned = try spawnSubagentTask(self, follow_up, "steer");
    defer self.allocator.free(spawned);
    return try std.fmt.allocPrint(
        self.allocator,
        "Steer for task #{d} created as a new subagent.\n{s}",
        .{ task_id, spawned },
    );
}

fn handleTellCommand(self: anytype, arg: []const u8) ![]const u8 {
    return try spawnSubagentTask(self, arg, "tell");
}

fn handlePollCommand(self: anytype) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    const w = out.writer(self.allocator);

    var wrote_any = false;
    if (self.pending_exec_command) |cmd| {
        wrote_any = true;
        try w.print("Pending approval id={d}: {s}\n", .{ self.pending_exec_id, cmd });
    }

    if (findSubagentManager(self)) |manager| {
        manager.mutex.lock();
        defer manager.mutex.unlock();
        var running: u32 = 0;
        var completed: u32 = 0;
        var failed: u32 = 0;
        var visible: u32 = 0;

        var it = manager.tasks.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (!taskBelongsToCurrentSession(self, state)) continue;
            visible += 1;
            switch (state.status) {
                .running => running += 1,
                .completed => completed += 1,
                .failed => failed += 1,
            }
        }
        if (visible > 0) {
            wrote_any = true;
            try w.print(
                "Subagent tasks: running={d}, completed={d}, failed={d}\n",
                .{ running, completed, failed },
            );
        }
    }

    if (!wrote_any) {
        return try self.allocator.dupe(u8, "No pending approvals or background tasks.");
    }
    return try out.toOwnedSlice(self.allocator);
}

fn handleStopCommand(self: anytype) ![]const u8 {
    var cleared_pending = false;
    if (self.pending_exec_command != null) {
        clearPendingExecCommand(self);
        cleared_pending = true;
    }

    if (findSubagentManager(self)) |manager| {
        var running: u32 = 0;
        manager.mutex.lock();
        {
            var it = manager.tasks.iterator();
            while (it.next()) |entry| {
                const state = entry.value_ptr.*;
                if (!taskBelongsToCurrentSession(self, state)) continue;
                if (state.status == .running) running += 1;
            }
        }
        manager.mutex.unlock();
        if (running > 0) {
            if (cleared_pending) {
                return try std.fmt.allocPrint(
                    self.allocator,
                    "Cleared pending exec approval. {d} running subagent tasks cannot be interrupted in this runtime.",
                    .{running},
                );
            }
            return try std.fmt.allocPrint(
                self.allocator,
                "{d} running subagent tasks cannot be interrupted in this runtime.",
                .{running},
            );
        }
    }

    if (cleared_pending) {
        return try self.allocator.dupe(u8, "Cleared pending exec approval.");
    }
    return try self.allocator.dupe(u8, "No active background task to stop.");
}

fn parseJsonStringOwned(allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .string) return null;
    return try allocator.dupe(u8, parsed.value.string);
}

fn parseJsonF64(raw: []const u8) ?f64 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .float => |v| v,
        .integer => |v| @floatFromInt(v),
        else => null,
    };
}

fn parseJsonU32(raw: []const u8) ?u32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .integer => |v| blk: {
            if (v < 0 or v > std.math.maxInt(u32)) break :blk null;
            break :blk @intCast(v);
        },
        else => null,
    };
}

fn parseJsonU64(raw: []const u8) ?u64 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .integer => |v| blk: {
            if (v < 0 or v > std.math.maxInt(u64)) break :blk null;
            break :blk @intCast(v);
        },
        else => null,
    };
}

fn splitPrimaryModelRef(primary: []const u8) ?struct { provider: []const u8, model: []const u8 } {
    const slash = std.mem.indexOfScalar(u8, primary, '/') orelse return null;
    if (slash == 0 or slash + 1 >= primary.len) return null;
    return .{
        .provider = primary[0..slash],
        .model = primary[slash + 1 ..],
    };
}

fn hotApplyConfigChange(
    self: anytype,
    action: config_mutator.MutationAction,
    path: []const u8,
    new_value_json: []const u8,
) !bool {
    if (action == .unset) return false;

    if (std.mem.eql(u8, path, "agents.defaults.model.primary")) {
        const primary = try parseJsonStringOwned(self.allocator, new_value_json) orelse return false;
        defer self.allocator.free(primary);
        const parsed = splitPrimaryModelRef(primary) orelse return false;
        try setModelName(self, parsed.model);
        try setDefaultProvider(self, parsed.provider);
        if (@hasField(@TypeOf(self.*), "default_model")) {
            self.default_model = self.model_name;
        }
        return true;
    }

    if (std.mem.eql(u8, path, "default_temperature")) {
        const temp = parseJsonF64(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "temperature")) {
            self.temperature = temp;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.max_tool_iterations")) {
        const v = parseJsonU32(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "max_tool_iterations")) {
            self.max_tool_iterations = v;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.max_history_messages")) {
        const v = parseJsonU32(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "max_history_messages")) {
            self.max_history_messages = v;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.message_timeout_secs")) {
        const v = parseJsonU64(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "message_timeout_secs")) {
            self.message_timeout_secs = v;
            return true;
        }
        return false;
    }

    return false;
}

fn formatConfigMutationResponse(
    allocator: std.mem.Allocator,
    action: config_mutator.MutationAction,
    result: *const config_mutator.MutationResult,
    dry_run: bool,
    hot_applied: bool,
) ![]const u8 {
    const action_name = switch (action) {
        .set => "set",
        .unset => "unset",
    };
    const mode = if (dry_run) "preview" else "applied";
    const restart_text = if (result.requires_restart) "true" else "false";
    const hot_text = if (hot_applied) "true" else "false";
    const backup = result.backup_path orelse "(none)";

    return try std.fmt.allocPrint(
        allocator,
        "Config {s} ({s}):\\n" ++
            "  action: {s}\\n" ++
            "  path: {s}\\n" ++
            "  old: {s}\\n" ++
            "  new: {s}\\n" ++
            "  requires_restart: {s}\\n" ++
            "  hot_applied: {s}\\n" ++
            "  backup: {s}\\n",
        .{
            action_name,
            mode,
            action_name,
            result.path,
            result.old_value_json,
            result.new_value_json,
            restart_text,
            hot_text,
            backup,
        },
    );
}

fn handleCapabilitiesCommand(self: anytype, arg: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, arg, " \t");
    const as_json = std.mem.eql(u8, trimmed, "--json") or std.ascii.eqlIgnoreCase(trimmed, "json");

    var cfg_opt: ?config_module.Config = config_module.Config.load(self.allocator) catch null;
    defer if (cfg_opt) |*cfg| cfg.deinit();
    const cfg_ptr: ?*const config_module.Config = if (cfg_opt) |*cfg| cfg else null;

    const runtime_tools: ?[]const Tool = if (@hasField(@TypeOf(self.*), "tools"))
        self.tools
    else
        null;

    if (as_json) {
        return capabilities_mod.buildManifestJson(self.allocator, cfg_ptr, runtime_tools);
    }
    return capabilities_mod.buildSummaryText(self.allocator, cfg_ptr, runtime_tools);
}

fn handleConfigCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const action = parsed.head;

    if (action.len == 0 or std.ascii.eqlIgnoreCase(action, "show") or std.ascii.eqlIgnoreCase(action, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Runtime config:\n  model={s}\n  workspace={s}\n  exec.host={s}\n  exec.security={s}\n  exec.ask={s}\n  queue.mode={s}\n  tts.mode={s}\n  activation={s}\n  send={s}",
            .{
                self.model_name,
                self.workspace_dir,
                self.exec_host.toSlice(),
                self.exec_security.toSlice(),
                self.exec_ask.toSlice(),
                self.queue_mode.toSlice(),
                self.tts_mode.toSlice(),
                self.activation_mode.toSlice(),
                self.send_mode.toSlice(),
            },
        );
    }

    if (std.ascii.eqlIgnoreCase(action, "get")) {
        const key = std.mem.trim(u8, parsed.tail, " \t");
        if (key.len == 0) return try self.allocator.dupe(u8, "Usage: /config get <path>");
        return config_mutator.getPathValueJson(self.allocator, key) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config get failed: {s}", .{@errorName(err)});
        };
    }

    if (std.ascii.eqlIgnoreCase(action, "validate")) {
        config_mutator.validateCurrentConfig(self.allocator) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config validation failed: {s}", .{@errorName(err)});
        };
        return try self.allocator.dupe(u8, "Config validation: OK");
    }

    if (std.ascii.eqlIgnoreCase(action, "set")) {
        const path_and_value = splitFirstToken(parsed.tail);
        const path = path_and_value.head;
        const value_raw = std.mem.trim(u8, path_and_value.tail, " \t");
        if (path.len == 0 or value_raw.len == 0) {
            return try self.allocator.dupe(u8, "Usage: /config set <path> <value> (dry-run preview)");
        }

        var result = config_mutator.mutateDefaultConfig(self.allocator, .set, path, value_raw, .{ .apply = false }) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config set preview failed: {s}", .{@errorName(err)});
        };
        defer config_mutator.freeMutationResult(self.allocator, &result);

        const response = try formatConfigMutationResponse(self.allocator, .set, &result, true, false);
        return response;
    }

    if (std.ascii.eqlIgnoreCase(action, "unset")) {
        const path = std.mem.trim(u8, parsed.tail, " \t");
        if (path.len == 0) {
            return try self.allocator.dupe(u8, "Usage: /config unset <path> (dry-run preview)");
        }

        var result = config_mutator.mutateDefaultConfig(self.allocator, .unset, path, null, .{ .apply = false }) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config unset preview failed: {s}", .{@errorName(err)});
        };
        defer config_mutator.freeMutationResult(self.allocator, &result);

        const response = try formatConfigMutationResponse(self.allocator, .unset, &result, true, false);
        return response;
    }

    if (std.ascii.eqlIgnoreCase(action, "apply")) {
        const apply_parsed = splitFirstToken(parsed.tail);
        const apply_action = apply_parsed.head;
        const apply_rest = apply_parsed.tail;

        if (std.ascii.eqlIgnoreCase(apply_action, "set")) {
            const path_and_value = splitFirstToken(apply_rest);
            const path = path_and_value.head;
            const value_raw = std.mem.trim(u8, path_and_value.tail, " \t");
            if (path.len == 0 or value_raw.len == 0) {
                return try self.allocator.dupe(u8, "Usage: /config apply set <path> <value>");
            }

            var result = config_mutator.mutateDefaultConfig(self.allocator, .set, path, value_raw, .{ .apply = true }) catch |err| {
                return try std.fmt.allocPrint(self.allocator, "Config apply set failed: {s}", .{@errorName(err)});
            };
            defer config_mutator.freeMutationResult(self.allocator, &result);

            var hot_applied = false;
            if (result.applied and !result.requires_restart) {
                hot_applied = hotApplyConfigChange(self, .set, result.path, result.new_value_json) catch false;
            }
            const response = try formatConfigMutationResponse(self.allocator, .set, &result, false, hot_applied);
            return response;
        }

        if (std.ascii.eqlIgnoreCase(apply_action, "unset")) {
            const path = std.mem.trim(u8, apply_rest, " \t");
            if (path.len == 0) {
                return try self.allocator.dupe(u8, "Usage: /config apply unset <path>");
            }

            var result = config_mutator.mutateDefaultConfig(self.allocator, .unset, path, null, .{ .apply = true }) catch |err| {
                return try std.fmt.allocPrint(self.allocator, "Config apply unset failed: {s}", .{@errorName(err)});
            };
            defer config_mutator.freeMutationResult(self.allocator, &result);

            const response = try formatConfigMutationResponse(self.allocator, .unset, &result, false, false);
            return response;
        }

        return try self.allocator.dupe(u8, "Usage: /config apply <set|unset> ...");
    }

    return try self.allocator.dupe(
        u8,
        "Usage:\n" ++
            "  /config [show]\n" ++
            "  /config get <path>\n" ++
            "  /config set <path> <value>            (dry-run preview)\n" ++
            "  /config unset <path>                  (dry-run preview)\n" ++
            "  /config apply set <path> <value>\n" ++
            "  /config apply unset <path>\n" ++
            "  /config validate",
    );
}

fn handleSkillCommand(self: anytype, arg: []const u8) ![]const u8 {
    const skills = skills_mod.listSkills(self.allocator, self.workspace_dir) catch |err| {
        return try std.fmt.allocPrint(self.allocator, "Failed to load skills: {s}", .{@errorName(err)});
    };
    defer skills_mod.freeSkills(self.allocator, skills);

    const parsed = splitFirstToken(arg);
    const action_or_name = parsed.head;

    if (action_or_name.len == 0 or std.ascii.eqlIgnoreCase(action_or_name, "list")) {
        if (skills.len == 0) {
            return try self.allocator.dupe(u8, "No skills found in workspace.");
        }
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.writeAll("Available skills:\n");
        for (skills) |skill| {
            try w.print("  - {s}", .{skill.name});
            if (skill.description.len > 0) try w.print(": {s}", .{skill.description});
            if (!skill.available) try w.print(" (unavailable: {s})", .{skill.missing_deps});
            try w.writeAll("\n");
        }
        return try out.toOwnedSlice(self.allocator);
    }

    var selected: ?*const skills_mod.Skill = null;
    for (skills) |*skill| {
        if (std.ascii.eqlIgnoreCase(skill.name, action_or_name)) {
            selected = skill;
            break;
        }
    }
    const skill = selected orelse
        return try std.fmt.allocPrint(self.allocator, "Skill not found: {s}", .{action_or_name});

    if (!skill.available) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Skill {s} is unavailable: {s}",
            .{ skill.name, skill.missing_deps },
        );
    }

    const user_input = std.mem.trim(u8, parsed.tail, " \t");
    if (user_input.len == 0) {
        if (skill.instructions.len > 0) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Skill {s}: {s}\nUsage: /skill {s} <task>",
                .{ skill.name, if (skill.description.len > 0) skill.description else "no description", skill.name },
            );
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Skill {s} has no instructions. Usage: /skill {s} <task>",
            .{ skill.name, skill.name },
        );
    }

    const composed = if (skill.instructions.len > 0)
        try std.fmt.allocPrint(
            self.allocator,
            "Apply the skill `{s}`.\n\nSkill instructions:\n{s}\n\nTask:\n{s}",
            .{ skill.name, skill.instructions, user_input },
        )
    else
        try std.fmt.allocPrint(
            self.allocator,
            "Apply the skill `{s}`.\n\nTask:\n{s}",
            .{ skill.name, user_input },
        );
    defer self.allocator.free(composed);

    if (findSubagentManager(self) != null) {
        return try spawnSubagentTask(self, composed, skill.name);
    }
    return try std.fmt.allocPrint(
        self.allocator,
        "Skill prompt prepared for `{s}` (spawn tool is disabled):\n{s}",
        .{ skill.name, composed },
    );
}

fn handleBashCommand(self: anytype, arg: []const u8) ![]const u8 {
    const command = std.mem.trim(u8, arg, " \t");
    if (command.len == 0) {
        return try self.allocator.dupe(u8, "Usage: /bash <command>");
    }
    if (std.ascii.eqlIgnoreCase(command, "poll")) {
        return try self.allocator.dupe(u8, "No background command output is available.");
    }
    if (std.ascii.eqlIgnoreCase(command, "stop")) {
        return try self.allocator.dupe(u8, "No background command is running.");
    }
    return try runShellCommand(self, command, false);
}

pub fn isExecToolName(tool_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(tool_name, "shell");
}

pub fn execBlockMessage(self: anytype, args: std.json.ObjectMap) ?[]const u8 {
    if (self.exec_host == .node) {
        return "Exec blocked: host=node is not available in this runtime";
    }
    if (self.exec_security == .deny) {
        return "Exec blocked by /exec security=deny";
    }
    if (self.exec_ask == .always) {
        if (args.get("command")) |v| {
            if (v == .string) {
                _ = setPendingExecCommand(self, v.string) catch {};
            }
        }
        return "Exec blocked: approval required. Use /approve allow-once|allow-always|deny";
    }

    if (self.exec_security == .allowlist and self.exec_ask == .on_miss) {
        if (args.get("command")) |v| {
            if (v == .string) {
                const command = v.string;
                if (self.policy) |pol| {
                    if (!pol.isCommandAllowed(command)) {
                        return "Exec blocked by allowlist policy";
                    }
                }
            }
        }
    }

    return null;
}

pub fn composeFinalReply(
    self: anytype,
    base_text: []const u8,
    reasoning_content: ?[]const u8,
    usage: providers.TokenUsage,
) ![]const u8 {
    const show_reasoning = self.reasoning_mode != .off and reasoning_content != null and reasoning_content.?.len > 0;
    if (!show_reasoning and self.usage_mode == .off) {
        return try self.allocator.dupe(u8, base_text);
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    const w = out.writer(self.allocator);

    if (show_reasoning) {
        try w.writeAll("Reasoning:\n");
        try w.writeAll(reasoning_content.?);
        try w.writeAll("\n\n");
    }
    try w.writeAll(base_text);

    switch (self.usage_mode) {
        .off => {},
        .tokens => try w.print("\n\n[usage] total_tokens={d}", .{usage.total_tokens}),
        .full => try w.print(
            "\n\n[usage] prompt={d} completion={d} total={d} session_total={d}",
            .{ usage.prompt_tokens, usage.completion_tokens, usage.total_tokens, self.total_tokens },
        ),
        .cost => try w.print(
            "\n\n[usage] prompt={d} completion={d} total={d} (cost estimate unavailable)",
            .{ usage.prompt_tokens, usage.completion_tokens, usage.total_tokens },
        ),
    }

    return try out.toOwnedSlice(self.allocator);
}

fn handleDoctorCommand(self: anytype) ![]const u8 {
    const rt: ?*memory_mod.MemoryRuntime = if (@hasField(@TypeOf(self.*), "mem_rt")) self.mem_rt else null;
    if (rt) |mem_rt| {
        const report = memory_mod.diagnostics.diagnose(mem_rt);
        return memory_mod.diagnostics.formatReport(report, self.allocator);
    }
    return try self.allocator.dupe(u8, "Memory runtime not available. Diagnostics require a configured memory backend.");
}

pub fn handleSlashCommand(self: anytype, message: []const u8) !?[]const u8 {
    const cmd = parseSlashCommand(message) orelse return null;

    if (isSlashName(cmd, "new") or isSlashName(cmd, "reset")) {
        clearSessionState(self);
        if (cmd.arg.len > 0) {
            try setModelName(self, cmd.arg);
            return try std.fmt.allocPrint(self.allocator, "Session cleared. Switched to model: {s}", .{cmd.arg});
        }
        return try self.allocator.dupe(u8, "Session cleared.");
    }

    if (isSlashName(cmd, "restart")) {
        clearSessionState(self);
        resetRuntimeCommandState(self);
        if (cmd.arg.len > 0) {
            try setModelName(self, cmd.arg);
            return try std.fmt.allocPrint(self.allocator, "Session restarted. Switched to model: {s}", .{cmd.arg});
        }
        return try self.allocator.dupe(u8, "Session restarted.");
    }

    if (isSlashName(cmd, "help") or isSlashName(cmd, "commands")) {
        return try self.allocator.dupe(u8,
            \\Available commands:
            \\  /new, /reset [model], /restart [model]
            \\  /help, /commands, /status, /whoami, /id
            \\  /model, /models, /model <name>
            \\  /think, /verbose, /reasoning
            \\  /exec, /queue, /usage, /tts, /voice
            \\  /stop, /compact
            \\  /allowlist, /approve, /context
            \\  /export-session, /export
            \\  /session ttl <duration|off>
            \\  /subagents, /agents, /focus, /unfocus, /kill, /steer, /tell
            \\  /config, /capabilities, /debug
            \\  /dock-telegram, /dock-discord, /dock-slack
            \\  /activation, /send, /elevated, /bash, /poll, /skill
            \\  /doctor — memory subsystem diagnostics
            \\  /memory <stats|status|reindex|count|search|get|list|drain-outbox>
            \\  exit, quit
        );
    }

    if (isSlashName(cmd, "status")) return try formatStatus(self);
    if (isSlashName(cmd, "whoami") or isSlashName(cmd, "id")) return try formatWhoAmI(self);
    if (isSlashName(cmd, "model") or isSlashName(cmd, "models")) {
        if (cmd.arg.len == 0 or
            std.ascii.eqlIgnoreCase(cmd.arg, "list") or
            std.ascii.eqlIgnoreCase(cmd.arg, "status"))
        {
            return try self.formatModelStatus();
        }
        try setModelName(self, cmd.arg);
        if (@hasField(@TypeOf(self.*), "default_model")) {
            self.default_model = self.model_name;
        }
        invalidateSystemPromptCache(self);
        persistSelectedModelToConfig(self, cmd.arg) catch |err| {
            return try std.fmt.allocPrint(
                self.allocator,
                "Switched to model: {s}\nWarning: could not persist model to config.json ({s})",
                .{ cmd.arg, @errorName(err) },
            );
        };
        return try std.fmt.allocPrint(self.allocator, "Switched to model: {s}", .{cmd.arg});
    }

    if (isSlashName(cmd, "think") or isSlashName(cmd, "thinking") or isSlashName(cmd, "t")) return try handleThinkCommand(self, cmd.arg);
    if (isSlashName(cmd, "verbose") or isSlashName(cmd, "v")) return try handleVerboseCommand(self, cmd.arg);
    if (isSlashName(cmd, "reasoning") or isSlashName(cmd, "reason")) return try handleReasoningCommand(self, cmd.arg);
    if (isSlashName(cmd, "exec")) return try handleExecCommand(self, cmd.arg);
    if (isSlashName(cmd, "queue")) return try handleQueueCommand(self, cmd.arg);
    if (isSlashName(cmd, "usage")) return try handleUsageCommand(self, cmd.arg);
    if (isSlashName(cmd, "tts") or isSlashName(cmd, "voice")) return try handleTtsCommand(self, cmd.arg);
    if (isSlashName(cmd, "stop")) return try handleStopCommand(self);
    if (isSlashName(cmd, "compact")) {
        if (self.forceCompressHistory()) {
            return try self.allocator.dupe(u8, "Context compacted.");
        }
        return try self.allocator.dupe(u8, "Nothing to compact.");
    }

    if (isSlashName(cmd, "allowlist")) return try handleAllowlistCommand(self, cmd.arg);
    if (isSlashName(cmd, "approve")) return try handleApproveCommand(self, cmd.arg);
    if (isSlashName(cmd, "context")) return try handleContextCommand(self, cmd.arg);
    if (isSlashName(cmd, "export-session") or isSlashName(cmd, "export")) return try handleExportSessionCommand(self, cmd.arg);
    if (isSlashName(cmd, "session")) return try handleSessionCommand(self, cmd.arg);
    if (isSlashName(cmd, "subagents")) return try handleSubagentsCommand(self, cmd.arg);
    if (isSlashName(cmd, "agents")) return try handleAgentsCommand(self);
    if (isSlashName(cmd, "focus")) return try handleFocusCommand(self, cmd.arg);
    if (isSlashName(cmd, "unfocus")) return try handleUnfocusCommand(self);
    if (isSlashName(cmd, "kill")) return try handleKillCommand(self, cmd.arg);
    if (isSlashName(cmd, "steer")) return try handleSteerCommand(self, cmd.arg);
    if (isSlashName(cmd, "tell")) return try handleTellCommand(self, cmd.arg);

    if (isSlashName(cmd, "config")) return try handleConfigCommand(self, cmd.arg);
    if (isSlashName(cmd, "capabilities")) return try handleCapabilitiesCommand(self, cmd.arg);
    if (isSlashName(cmd, "debug")) {
        if (std.ascii.eqlIgnoreCase(cmd.arg, "show") or cmd.arg.len == 0) return try formatStatus(self);
        if (std.ascii.eqlIgnoreCase(cmd.arg, "reset")) {
            resetRuntimeCommandState(self);
            return try self.allocator.dupe(u8, "Runtime debug state reset.");
        }
        return try self.allocator.dupe(u8, "Supported: /debug show|reset");
    }

    if (isSlashName(cmd, "dock-telegram") or isSlashName(cmd, "dock_telegram")) return try handleDockCommand(self, "telegram");
    if (isSlashName(cmd, "dock-discord") or isSlashName(cmd, "dock_discord")) return try handleDockCommand(self, "discord");
    if (isSlashName(cmd, "dock-slack") or isSlashName(cmd, "dock_slack")) return try handleDockCommand(self, "slack");
    if (isSlashName(cmd, "activation")) return try handleActivationCommand(self, cmd.arg);
    if (isSlashName(cmd, "send")) return try handleSendCommand(self, cmd.arg);
    if (isSlashName(cmd, "elevated") or isSlashName(cmd, "elev")) return try handleElevatedCommand(self, cmd.arg);

    if (isSlashName(cmd, "bash")) return try handleBashCommand(self, cmd.arg);
    if (isSlashName(cmd, "poll")) return try handlePollCommand(self);
    if (isSlashName(cmd, "skill")) return try handleSkillCommand(self, cmd.arg);
    if (isSlashName(cmd, "doctor")) return try handleDoctorCommand(self);
    if (isSlashName(cmd, "memory")) return try handleMemoryCommand(self, cmd.arg);

    return null;
}

fn handleMemoryCommand(self: anytype, arg: []const u8) ![]const u8 {
    const usage =
        "Usage: /memory <stats|status|reindex|count|search|get|list|drain-outbox>\n" ++
        "  /memory search <query> [--limit N]\n" ++
        "  /memory get <key>\n" ++
        "  /memory list [--category C] [--limit N] [--include-internal]";

    const parsed = splitFirstToken(arg);
    const sub = parsed.head;
    const rest = parsed.tail;

    if (sub.len == 0) return try self.allocator.dupe(u8, usage);

    if (std.mem.eql(u8, sub, "doctor") or std.mem.eql(u8, sub, "status")) {
        return try handleDoctorCommand(self);
    }

    const mem_rt = memoryRuntimePtr(self) orelse {
        return try self.allocator.dupe(u8, "Memory runtime not available.");
    };

    if (std.mem.eql(u8, sub, "stats")) {
        const r = mem_rt.resolved;
        const report = mem_rt.diagnose();
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.print("Memory resolved config:\n", .{});
        try w.print("  backend: {s}\n", .{r.primary_backend});
        try w.print("  retrieval: {s}\n", .{r.retrieval_mode});
        try w.print("  vector: {s}\n", .{r.vector_mode});
        try w.print("  embedding: {s}\n", .{r.embedding_provider});
        try w.print("  rollout: {s}\n", .{r.rollout_mode});
        try w.print("  sync: {s}\n", .{r.vector_sync_mode});
        try w.print("  sources: {d}\n", .{r.source_count});
        try w.print("  fallback: {s}\n", .{r.fallback_policy});
        try w.print("  entries: {d}\n", .{report.entry_count});
        if (report.vector_entry_count) |n| {
            try w.print("  vector_entries: {d}\n", .{n});
        } else {
            try w.print("  vector_entries: n/a\n", .{});
        }
        if (report.outbox_pending) |n| {
            try w.print("  outbox_pending: {d}\n", .{n});
        } else {
            try w.print("  outbox_pending: n/a\n", .{});
        }
        return try out.toOwnedSlice(self.allocator);
    }

    if (std.mem.eql(u8, sub, "count")) {
        const count = mem_rt.memory.count() catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory count failed: {s}", .{@errorName(err)});
        };
        return try std.fmt.allocPrint(self.allocator, "{d}", .{count});
    }

    if (std.mem.eql(u8, sub, "reindex")) {
        const count = mem_rt.reindex(self.allocator);
        if (std.mem.eql(u8, mem_rt.resolved.vector_mode, "none")) {
            return try self.allocator.dupe(u8, "Vector plane is disabled; reindex skipped (0 entries).");
        }
        return try std.fmt.allocPrint(self.allocator, "Reindex complete: {d} entries reindexed.", .{count});
    }

    if (std.mem.eql(u8, sub, "drain-outbox") or std.mem.eql(u8, sub, "drain_outbox")) {
        const drained = mem_rt.drainOutbox(self.allocator);
        return try std.fmt.allocPrint(self.allocator, "Outbox drain complete: {d} operation(s) processed.", .{drained});
    }

    if (std.mem.eql(u8, sub, "get")) {
        const key = std.mem.trim(u8, rest, " \t");
        if (key.len == 0) return try self.allocator.dupe(u8, "Usage: /memory get <key>");
        const entry = mem_rt.memory.get(self.allocator, key) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory get failed: {s}", .{@errorName(err)});
        };
        if (entry) |e| {
            defer e.deinit(self.allocator);
            return try std.fmt.allocPrint(
                self.allocator,
                "key: {s}\ncategory: {s}\ntimestamp: {s}\ncontent:\n{s}",
                .{ e.key, e.category.toString(), e.timestamp, e.content },
            );
        }
        return try std.fmt.allocPrint(self.allocator, "Not found: {s}", .{key});
    }

    if (std.mem.eql(u8, sub, "search")) {
        var limit: usize = 6;
        var query_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer query_buf.deinit(self.allocator);

        var it = std.mem.tokenizeAny(u8, rest, " \t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "--limit")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory search <query> [--limit N]");
                limit = parsePositiveUsize(next) orelse return try std.fmt.allocPrint(self.allocator, "Invalid --limit value: {s}", .{next});
                continue;
            }
            if (query_buf.items.len > 0) try query_buf.append(self.allocator, ' ');
            try query_buf.appendSlice(self.allocator, tok);
        }

        const query = std.mem.trim(u8, query_buf.items, " \t");
        if (query.len == 0) return try self.allocator.dupe(u8, "Usage: /memory search <query> [--limit N]");

        const results = mem_rt.search(self.allocator, query, limit, null) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory search failed: {s}", .{@errorName(err)});
        };
        defer memory_mod.retrieval.freeCandidates(self.allocator, results);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.print("Search results: {d}\n", .{results.len});
        for (results, 0..) |c, idx| {
            try w.print("  {d}. {s} [{s}] score={d:.4}", .{ idx + 1, c.key, c.category.toString(), c.final_score });
            if (c.vector_score) |vs| {
                try w.print(" vector_score={d:.4}", .{vs});
            } else {
                try w.print(" vector_score=n/a", .{});
            }
            try w.print(" source={s}\n", .{c.source});
            const preview_len = @min(@as(usize, 140), c.snippet.len);
            const preview = c.snippet[0..preview_len];
            try w.print("     {s}{s}\n", .{ preview, if (c.snippet.len > preview_len) "..." else "" });
        }
        return try out.toOwnedSlice(self.allocator);
    }

    if (std.mem.eql(u8, sub, "list")) {
        var limit: usize = 20;
        var category_opt: ?memory_mod.MemoryCategory = null;
        var include_internal = false;
        var it = std.mem.tokenizeAny(u8, rest, " \t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "--limit")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory list [--category C] [--limit N] [--include-internal]");
                limit = parsePositiveUsize(next) orelse return try std.fmt.allocPrint(self.allocator, "Invalid --limit value: {s}", .{next});
                continue;
            }
            if (std.mem.eql(u8, tok, "--category")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory list [--category C] [--limit N] [--include-internal]");
                category_opt = memory_mod.MemoryCategory.fromString(next);
                continue;
            }
            if (std.mem.eql(u8, tok, "--include-internal")) {
                include_internal = true;
                continue;
            }
            return try std.fmt.allocPrint(self.allocator, "Unknown option for /memory list: {s}", .{tok});
        }

        const entries = mem_rt.memory.list(self.allocator, category_opt, null) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory list failed: {s}", .{@errorName(err)});
        };
        defer memory_mod.freeEntries(self.allocator, entries);

        var filtered_total: usize = 0;
        for (entries) |entry| {
            if (!include_internal and isInternalMemoryEntryKeyOrContent(entry.key, entry.content)) continue;
            filtered_total += 1;
        }

        if (filtered_total == 0) {
            return try self.allocator.dupe(u8, "No memory entries found.");
        }

        const shown = @min(limit, filtered_total);
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const w = out.writer(self.allocator);
        try w.print("Memory entries: showing {d}/{d}\n", .{ shown, filtered_total });
        var written: usize = 0;
        for (entries) |e| {
            if (!include_internal and isInternalMemoryEntryKeyOrContent(e.key, e.content)) continue;
            if (written >= shown) break;
            const preview_len = @min(@as(usize, 120), e.content.len);
            const preview = e.content[0..preview_len];
            try w.print("  {d}. {s} [{s}] {s}\n", .{ written + 1, e.key, e.category.toString(), e.timestamp });
            try w.print("     {s}{s}\n", .{ preview, if (e.content.len > preview_len) "..." else "" });
            written += 1;
        }
        return try out.toOwnedSlice(self.allocator);
    }

    return try self.allocator.dupe(u8, usage);
}
