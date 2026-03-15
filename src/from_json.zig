/// --from-json subcommand: non-interactive config generation from wizard answers.
///
/// Accepts a JSON string with wizard answers, applies them to the config,
/// saves, scaffolds the workspace, and prints {"status":"ok"} on success.
/// Used by nullhub to configure nullclaw without interactive terminal input.
const std = @import("std");
const onboard = @import("onboard.zig");
const channel_catalog = @import("channel_catalog.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;

const WizardAnswers = struct {
    provider: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
    model: ?[]const u8 = null,
    memory: ?[]const u8 = null,
    tunnel: ?[]const u8 = null,
    autonomy: ?[]const u8 = null,
    gateway_port: ?u16 = null,
    /// Override config/workspace directory (used by nullhub for instance isolation).
    /// Falls back to NULLCLAW_HOME env, then ~/.nullclaw/.
    home: ?[]const u8 = null,
};

const AutonomySelectionError = error{InvalidAutonomyLevel};

fn isKnownTunnelProvider(tunnel: []const u8) bool {
    for (onboard.tunnel_options) |option| {
        if (std.mem.eql(u8, option, tunnel)) return true;
    }
    return false;
}

fn applyAutonomySelection(cfg: *Config, autonomy: []const u8) AutonomySelectionError!void {
    if (std.mem.eql(u8, autonomy, "supervised")) {
        cfg.autonomy.level = .supervised;
        cfg.autonomy.require_approval_for_medium_risk = true;
        cfg.autonomy.block_high_risk_commands = true;
        return;
    }
    if (std.mem.eql(u8, autonomy, "autonomous")) {
        cfg.autonomy.level = .full;
        cfg.autonomy.require_approval_for_medium_risk = false;
        cfg.autonomy.block_high_risk_commands = true;
        return;
    }
    if (std.mem.eql(u8, autonomy, "fully_autonomous")) {
        cfg.autonomy.level = .full;
        cfg.autonomy.require_approval_for_medium_risk = false;
        cfg.autonomy.block_high_risk_commands = false;
        return;
    }
    if (std.mem.eql(u8, autonomy, "yolo")) {
        cfg.autonomy.level = .yolo;
        cfg.autonomy.require_approval_for_medium_risk = false;
        cfg.autonomy.block_high_risk_commands = false;
        return;
    }
    return error.InvalidAutonomyLevel;
}

fn applyChannelKey(webhook_selected: *bool, channel_key: []const u8) void {
    const meta = channel_catalog.findByKey(channel_key) orelse return;
    if (!channel_catalog.isBuildEnabled(meta.id)) return;
    switch (meta.id) {
        .webhook => webhook_selected.* = true,
        .cli, .web => {}, // Always enabled by default, no config needed.
        else => {}, // Other channels need manual config; silently skip.
    }
}

fn applyChannelsFromString(cfg: *Config, channels_csv: []const u8) void {
    var webhook_selected = false;

    var it = std.mem.splitScalar(u8, channels_csv, ',');
    while (it.next()) |raw_key| {
        const channel_key = std.mem.trim(u8, raw_key, " ");
        if (channel_key.len == 0) continue;
        applyChannelKey(&webhook_selected, channel_key);
    }

    cfg.channels.webhook = if (webhook_selected) .{ .port = cfg.gateway.port } else null;
}

fn initConfigWithCustomHome(backing_allocator: std.mem.Allocator, home_dir: []const u8) !Config {
    const arena_ptr = try backing_allocator.create(std.heap.ArenaAllocator);
    arena_ptr.* = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer {
        arena_ptr.deinit();
        backing_allocator.destroy(arena_ptr);
    }
    const allocator = arena_ptr.allocator();

    var cfg = Config{
        .workspace_dir = "",
        .config_path = "",
        .allocator = allocator,
        .arena = arena_ptr,
    };

    const config_path = try std.fs.path.join(allocator, &.{ home_dir, "config.json" });
    const workspace_dir = try std.fs.path.join(allocator, &.{ home_dir, "workspace" });
    cfg.config_path = config_path;
    cfg.workspace_dir = workspace_dir;
    cfg.workspace_dir_override = workspace_dir;

    if (std.fs.openFileAbsolute(config_path, .{})) |file| {
        defer file.close();
        const content = try file.readToEndAlloc(allocator, 1024 * 64);
        cfg.parseJson(content) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                std.debug.print("Warning: failed to parse config.json: {s}\n", .{@errorName(err)});
            },
        };
    } else |_| {
        // No existing config at custom path.
    }

    // Enforce home-scoped paths for isolated instances.
    cfg.config_path = config_path;
    cfg.workspace_dir = workspace_dir;
    cfg.workspace_dir_override = workspace_dir;
    cfg.syncFlatFields();

    return cfg;
}

fn loadConfigForFromJson(allocator: std.mem.Allocator, custom_home: ?[]const u8) !Config {
    if (custom_home) |home_dir| {
        return initConfigWithCustomHome(allocator, home_dir);
    }
    return Config.load(allocator) catch try onboard.initFreshConfig(allocator);
}

/// Apply providers from the wizard's providers array (new multi-provider format).
/// Sets default_provider and default_model from the first entry, and creates
/// ProviderEntry array from all entries.
fn applyProvidersFromArray(cfg: *Config, items: []const std.json.Value) !void {
    if (items.len == 0) return;

    var primary_provider_set = false;
    var primary_model_set = false;

    // Create ProviderEntry array from all entries
    var entries_list: std.ArrayListUnmanaged(config_mod.ProviderEntry) = .empty;
    for (items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const name = if (obj.get("provider")) |v|
            (if (v == .string) v.string else continue)
        else
            continue;
        const api_key = if (obj.get("api_key")) |v|
            (if (v == .string and v.string.len > 0) v.string else null)
        else
            null;

        const resolved = onboard.resolveProviderForQuickSetup(name) orelse {
            if (!primary_provider_set) {
                std.debug.print("error: unknown provider '{s}'\n", .{name});
                std.process.exit(1);
            }
            continue;
        };

        if (!primary_provider_set) {
            cfg.default_provider = try cfg.allocator.dupe(u8, resolved.key);
            primary_provider_set = true;

            if (obj.get("model")) |model_v| {
                if (model_v == .string) {
                    const trimmed_model = std.mem.trim(u8, model_v.string, " \t\r\n");
                    if (trimmed_model.len > 0) {
                        cfg.default_model = try cfg.allocator.dupe(u8, trimmed_model);
                        primary_model_set = true;
                    }
                }
            }
        }

        try entries_list.append(cfg.allocator, .{
            .name = try cfg.allocator.dupe(u8, resolved.key),
            .api_key = if (api_key) |k| try cfg.allocator.dupe(u8, k) else null,
        });
    }

    if (entries_list.items.len > 0) {
        cfg.providers = try entries_list.toOwnedSlice(cfg.allocator);
    }

    if (primary_provider_set and !primary_model_set) {
        cfg.default_model = try cfg.allocator.dupe(u8, onboard.defaultModelForProvider(cfg.default_provider));
    }
}

fn channelSupportsAccounts(channel_type: []const u8) bool {
    inline for (std.meta.fields(config_mod.ChannelsConfig)) |field| {
        if (std.mem.eql(u8, channel_type, field.name)) {
            return switch (@typeInfo(field.type)) {
                .pointer => |ptr| ptr.size == .slice,
                else => false,
            };
        }
    }
    return false;
}

fn channelExistsInConfig(channel_type: []const u8) bool {
    inline for (std.meta.fields(config_mod.ChannelsConfig)) |field| {
        if (std.mem.eql(u8, channel_type, field.name)) return true;
    }
    return false;
}

fn firstObjectValue(map: std.json.ObjectMap) ?std.json.Value {
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .object) return entry.value_ptr.*;
    }
    return null;
}

fn selectPreferredAccountValue(map: std.json.ObjectMap, channel_type: []const u8) ?std.json.Value {
    if (map.get("default")) |v| {
        if (v == .object) return v;
    }
    if (map.get("main")) |v| {
        if (v == .object) return v;
    }
    if (map.get(channel_type)) |v| {
        if (v == .object) return v;
    }
    return firstObjectValue(map);
}

fn isLikelyInlineSingleChannelObject(obj: std.json.ObjectMap) bool {
    var has_non_object = false;
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) {
            has_non_object = true;
            break;
        }
    }
    return has_non_object;
}

fn cloneJsonValueWithNormalizedObjects(allocator: std.mem.Allocator, value: std.json.Value) anyerror!std.json.Value {
    return switch (value) {
        .object => |obj| .{ .object = try normalizeWizardAccountObject(allocator, obj) },
        .array => |arr| blk: {
            var cloned = std.json.Array.init(allocator);
            for (arr.items) |item| {
                try cloned.append(try cloneJsonValueWithNormalizedObjects(allocator, item));
            }
            break :blk .{ .array = cloned };
        },
        else => value,
    };
}

fn putValueByDottedKey(
    allocator: std.mem.Allocator,
    root_obj: *std.json.ObjectMap,
    dotted_key: []const u8,
    value: std.json.Value,
) anyerror!void {
    if (std.mem.indexOfScalar(u8, dotted_key, '.') == null) {
        try root_obj.put(dotted_key, value);
        return;
    }

    var segments = std.mem.splitScalar(u8, dotted_key, '.');
    const first = segments.next() orelse return;

    var current_obj: *std.json.ObjectMap = root_obj;
    var segment = first;

    while (segments.next()) |next_segment| {
        if (current_obj.getPtr(segment)) |existing_ptr| {
            if (existing_ptr.* != .object) {
                existing_ptr.* = .{ .object = std.json.ObjectMap.init(allocator) };
            }
        } else {
            try current_obj.put(segment, .{ .object = std.json.ObjectMap.init(allocator) });
        }

        current_obj = &current_obj.getPtr(segment).?.object;
        segment = next_segment;
    }

    try current_obj.put(segment, value);
}

fn normalizeWizardAccountObject(
    allocator: std.mem.Allocator,
    raw_obj: std.json.ObjectMap,
) anyerror!std.json.ObjectMap {
    var normalized = std.json.ObjectMap.init(allocator);

    var it = raw_obj.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const cloned_value = try cloneJsonValueWithNormalizedObjects(allocator, entry.value_ptr.*);
        try putValueByDottedKey(allocator, &normalized, key, cloned_value);
    }

    return normalized;
}

fn addAccountsChannelValue(
    allocator: std.mem.Allocator,
    channels_obj: *std.json.ObjectMap,
    channel_type: []const u8,
    raw_channel_obj: std.json.ObjectMap,
) !void {
    const accounts_source = blk: {
        if (raw_channel_obj.get("accounts")) |v| {
            if (v == .object) break :blk v.object;
        }
        break :blk raw_channel_obj;
    };

    var accounts_obj = std.json.ObjectMap.init(allocator);
    var acc_it = accounts_source.iterator();
    while (acc_it.next()) |acc_entry| {
        const account_name = acc_entry.key_ptr.*;
        if (acc_entry.value_ptr.* != .object) continue;
        const normalized = try normalizeWizardAccountObject(allocator, acc_entry.value_ptr.*.object);
        try accounts_obj.put(account_name, .{ .object = normalized });
    }

    if (accounts_obj.count() == 0) return;

    var wrapper = std.json.ObjectMap.init(allocator);
    try wrapper.put("accounts", .{ .object = accounts_obj });
    try channels_obj.put(channel_type, .{ .object = wrapper });
}

fn addSingleChannelValue(
    allocator: std.mem.Allocator,
    channels_obj: *std.json.ObjectMap,
    channel_type: []const u8,
    raw_channel_obj: std.json.ObjectMap,
) !void {
    const candidate = blk: {
        if (raw_channel_obj.get("accounts")) |v| {
            if (v == .object) {
                if (selectPreferredAccountValue(v.object, channel_type)) |selected| {
                    break :blk selected;
                }
            }
        }

        if (isLikelyInlineSingleChannelObject(raw_channel_obj)) {
            break :blk std.json.Value{ .object = raw_channel_obj };
        }

        if (selectPreferredAccountValue(raw_channel_obj, channel_type)) |selected| {
            break :blk selected;
        }

        break :blk std.json.Value{ .null = {} };
    };

    if (candidate != .object) return;
    const normalized = try normalizeWizardAccountObject(allocator, candidate.object);
    try channels_obj.put(channel_type, .{ .object = normalized });
}

fn applyChannelsFromObject(cfg: *Config, raw_channels: std.json.ObjectMap) !void {
    var channels_obj = std.json.ObjectMap.init(cfg.allocator);

    var ch_it = raw_channels.iterator();
    while (ch_it.next()) |ch_entry| {
        const channel_type = ch_entry.key_ptr.*;
        const channel_value = ch_entry.value_ptr.*;

        if (!channelExistsInConfig(channel_type)) continue;
        if (std.mem.eql(u8, channel_type, "cli")) continue;
        if (channel_value != .object) continue;

        if (channelSupportsAccounts(channel_type)) {
            try addAccountsChannelValue(cfg.allocator, &channels_obj, channel_type, channel_value.object);
        } else {
            try addSingleChannelValue(cfg.allocator, &channels_obj, channel_type, channel_value.object);
        }
    }

    if (channels_obj.getPtr("webhook")) |webhook_ptr| {
        if (webhook_ptr.* == .object and webhook_ptr.object.get("port") == null) {
            try webhook_ptr.object.put("port", .{ .integer = @as(i64, @intCast(cfg.gateway.port)) });
        }
    }

    var root_obj = std.json.ObjectMap.init(cfg.allocator);
    try root_obj.put("channels", .{ .object = channels_obj });
    const root_value: std.json.Value = .{ .object = root_obj };
    const patch_json = try std.json.Stringify.valueAlloc(cfg.allocator, root_value, .{});
    defer cfg.allocator.free(patch_json);

    try cfg.parseJson(patch_json);
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("error: --from-json requires a JSON argument\n", .{});
        std.process.exit(1);
    }

    const json_str = args[0];
    const parsed = std.json.parseFromSlice(
        WizardAnswers,
        allocator,
        json_str,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
    ) catch {
        std.debug.print("error: invalid JSON\n", .{});
        std.process.exit(1);
    };
    defer parsed.deinit();
    const answers = parsed.value;

    // Raw JSON parse for providers array and channels object
    const raw_parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_str,
        .{ .allocate = .alloc_always },
    ) catch null;
    defer if (raw_parsed) |rp| rp.deinit();

    const env_home = std.process.getEnvVarOwned(allocator, "NULLCLAW_HOME") catch null;
    defer if (env_home) |v| allocator.free(v);

    // Resolve home directory: JSON home > NULLCLAW_HOME env > default (~/.nullclaw/)
    const custom_home: ?[]const u8 = answers.home orelse env_home;

    // Load config. For custom home, read/write only that home path.
    var cfg = try loadConfigForFromJson(allocator, custom_home);
    defer cfg.deinit();

    // Check for providers array in raw JSON (new wizard format)
    const has_providers_array = blk: {
        if (raw_parsed) |rp| {
            if (rp.value == .object) {
                if (rp.value.object.get("providers")) |prov_val| {
                    if (prov_val == .array and prov_val.array.items.len > 0) {
                        break :blk true;
                    }
                }
            }
        }
        break :blk false;
    };

    if (has_providers_array) {
        // New multi-provider format from wizard
        const prov_arr = raw_parsed.?.value.object.get("providers").?.array;
        try applyProvidersFromArray(&cfg, prov_arr.items);
    } else {
        // Legacy flat provider/api_key/model fields
        if (answers.provider) |p| {
            const provider_info = onboard.resolveProviderForQuickSetup(p) orelse {
                std.debug.print("error: unknown provider '{s}'\n", .{p});
                std.process.exit(1);
            };
            cfg.default_provider = try cfg.allocator.dupe(u8, provider_info.key);

            if (answers.api_key) |key| {
                const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
                entries[0] = .{
                    .name = try cfg.allocator.dupe(u8, provider_info.key),
                    .api_key = try cfg.allocator.dupe(u8, key),
                };
                cfg.providers = entries;
            }
        } else if (answers.api_key) |key| {
            const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
            entries[0] = .{
                .name = try cfg.allocator.dupe(u8, cfg.default_provider),
                .api_key = try cfg.allocator.dupe(u8, key),
            };
            cfg.providers = entries;
        }

        // Apply model (explicit or derive from provider)
        if (answers.model) |m| {
            cfg.default_model = try cfg.allocator.dupe(u8, m);
        } else if (answers.provider != null) {
            cfg.default_model = try cfg.allocator.dupe(u8, onboard.defaultModelForProvider(cfg.default_provider));
        }
    }

    // Apply memory backend
    if (answers.memory) |m| {
        const backend = onboard.resolveMemoryBackendForQuickSetup(m) catch |err| switch (err) {
            error.UnknownMemoryBackend => {
                std.debug.print("error: unknown memory backend '{s}'\n", .{m});
                std.process.exit(1);
            },
            error.MemoryBackendDisabledInBuild => {
                std.debug.print("error: memory backend '{s}' is disabled in this build\n", .{m});
                std.process.exit(1);
            },
        };
        cfg.memory.backend = backend.name;
        cfg.memory.profile = onboard.memoryProfileForBackend(backend.name);
        cfg.memory.auto_save = backend.auto_save_default;
    }

    // Apply tunnel provider
    if (answers.tunnel) |t| {
        if (!isKnownTunnelProvider(t)) {
            std.debug.print("error: invalid tunnel provider '{s}'\n", .{t});
            std.process.exit(1);
        }
        cfg.tunnel.provider = try cfg.allocator.dupe(u8, t);
    }

    // Apply autonomy level
    if (answers.autonomy) |a| {
        applyAutonomySelection(&cfg, a) catch {
            std.debug.print("error: invalid autonomy level '{s}'\n", .{a});
            std.process.exit(1);
        };
    }

    // Apply gateway port
    if (answers.gateway_port) |port| {
        if (port == 0) {
            std.debug.print("error: gateway_port must be > 0\n", .{});
            std.process.exit(1);
        }
        cfg.gateway.port = port;
    }

    // Apply channels from raw JSON payload.
    // Supports:
    // - legacy CSV string: "channels": "cli,web,webhook"
    // - wizard object map: "channels": {"telegram": {"default": {...}}}
    if (raw_parsed) |rp| {
        if (rp.value == .object) {
            if (rp.value.object.get("channels")) |channels_val| {
                switch (channels_val) {
                    .string => |channels_csv| applyChannelsFromString(&cfg, channels_csv),
                    .object => |channels_obj| {
                        applyChannelsFromObject(&cfg, channels_obj) catch |err| {
                            std.debug.print("error: invalid channels payload ({s})\n", .{@errorName(err)});
                            std.process.exit(1);
                        };
                    },
                    else => {},
                }
            }
        }
    }

    // Ensure a valid default model exists even when omitted in JSON payload.
    if (cfg.default_model == null) {
        cfg.default_model = try cfg.allocator.dupe(u8, onboard.defaultModelForProvider(cfg.default_provider));
    }

    // Sync flat convenience fields
    cfg.syncFlatFields();
    cfg.validate() catch |err| {
        Config.printValidationError(err);
        std.process.exit(1);
    };

    // Ensure parent config directory and workspace directory exist
    if (std.fs.path.dirname(cfg.workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(cfg.workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Scaffold workspace files
    try onboard.scaffoldWorkspaceForConfig(allocator, &cfg, &onboard.ProjectContext{});

    // Save config
    try cfg.save();

    // Output success as JSON to stdout
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    try bw.interface.writeAll("{\"status\":\"ok\"}\n");
    try bw.interface.flush();
}

test "from_json requires JSON argument" {
    // Cannot easily test process.exit in-process; just verify the function signature compiles.
    // The real integration test is: nullclaw --from-json '{"provider":"openrouter"}'
}

test "isKnownTunnelProvider validates wizard options" {
    try std.testing.expect(isKnownTunnelProvider("none"));
    try std.testing.expect(isKnownTunnelProvider("cloudflare"));
    try std.testing.expect(!isKnownTunnelProvider("invalid-tunnel"));
}

test "applyAutonomySelection rejects invalid value" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(error.InvalidAutonomyLevel, applyAutonomySelection(&cfg, "danger-mode"));
}

test "applyChannelsFromString enables webhook from csv" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };

    applyChannelsFromString(&cfg, "cli,webhook,web");
    try std.testing.expect(cfg.channels.webhook != null);
    try std.testing.expectEqual(@as(u16, 3000), cfg.channels.webhook.?.port);
}

test "applyChannelsFromString ignores unknown channels" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };

    // Unknown channels are silently skipped (future-proofing).
    applyChannelsFromString(&cfg, "cli,web,future-channel,telegram");
    try std.testing.expect(cfg.channels.webhook == null);
}

test "applyChannelsFromObject maps wizard telegram account and dotted keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };

    const payload =
        \\{
        \\  "channels": {
        \\    "telegram": {
        \\      "default": {
        \\        "bot_token": "123:ABC",
        \\        "interactive.enabled": true,
        \\        "interactive.ttl_secs": 42
        \\      }
        \\    }
        \\  }
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    try applyChannelsFromObject(&cfg, parsed.value.object.get("channels").?.object);
    try std.testing.expectEqual(@as(usize, 1), cfg.channels.telegram.len);
    try std.testing.expectEqualStrings("default", cfg.channels.telegram[0].account_id);
    try std.testing.expectEqualStrings("123:ABC", cfg.channels.telegram[0].bot_token);
    try std.testing.expect(cfg.channels.telegram[0].interactive.enabled);
    try std.testing.expectEqual(@as(u64, 42), cfg.channels.telegram[0].interactive.ttl_secs);
}

test "applyChannelsFromObject maps single-account webhook channel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    cfg.gateway.port = 4321;

    const payload =
        \\{
        \\  "channels": {
        \\    "webhook": {
        \\      "webhook": {
        \\        "secret": "sec"
        \\      }
        \\    }
        \\  }
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    try applyChannelsFromObject(&cfg, parsed.value.object.get("channels").?.object);
    try std.testing.expect(cfg.channels.webhook != null);
    try std.testing.expectEqual(@as(u16, 4321), cfg.channels.webhook.?.port);
    try std.testing.expectEqualStrings("sec", cfg.channels.webhook.?.secret.?);
}

test "applyProvidersFromArray sets model default from primary provider when omitted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    cfg.default_provider = "openrouter";
    cfg.default_model = "openrouter/some-old-model";

    const payload =
        \\{
        \\  "providers": [
        \\    { "provider": "groq", "api_key": "gsk_test" },
        \\    { "provider": "openrouter", "api_key": "sk-or-test" }
        \\  ]
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    const providers = parsed.value.object.get("providers").?.array.items;
    try applyProvidersFromArray(&cfg, providers);

    try std.testing.expectEqualStrings("groq", cfg.default_provider);
    try std.testing.expect(cfg.default_model != null);
    try std.testing.expectEqualStrings(onboard.defaultModelForProvider("groq"), cfg.default_model.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.providers.len);
}
