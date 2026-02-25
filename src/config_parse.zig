const std = @import("std");
const types = @import("config_types.zig");
const agent_routing = @import("agent_routing.zig");

// Forward-reference to the Config struct defined in config.zig.
// Zig handles circular @import lazily, so this works as long as there is
// no comptime-initialization cycle.
const config_mod = @import("config.zig");
const Config = config_mod.Config;

/// Parse a JSON array of strings into an allocated slice.
pub fn parseStringArray(allocator: std.mem.Allocator, arr: std.json.Array) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    try list.ensureTotalCapacity(allocator, @intCast(arr.items.len));
    for (arr.items) |item| {
        if (item == .string) {
            try list.append(allocator, try allocator.dupe(u8, item.string));
        }
    }
    return try list.toOwnedSlice(allocator);
}

fn splitPrimaryModelRef(primary: []const u8) ?struct { provider: []const u8, model: []const u8 } {
    const slash = std.mem.indexOfScalar(u8, primary, '/') orelse return null;
    if (slash == 0 or slash + 1 >= primary.len) return null;
    return .{
        .provider = primary[0..slash],
        .model = primary[slash + 1 ..],
    };
}

fn parsePeerKind(kind: []const u8) ?agent_routing.ChatType {
    if (std.mem.eql(u8, kind, "direct") or std.mem.eql(u8, kind, "dm")) return .direct;
    if (std.mem.eql(u8, kind, "group")) return .group;
    if (std.mem.eql(u8, kind, "channel")) return .channel;
    return null;
}

fn parseAgentBindingsArray(
    allocator: std.mem.Allocator,
    arr: std.json.Array,
) ![]const agent_routing.AgentBinding {
    var list: std.ArrayListUnmanaged(agent_routing.AgentBinding) = .empty;
    try list.ensureTotalCapacity(allocator, @intCast(arr.items.len));

    for (arr.items) |item| {
        if (item != .object) continue;

        const agent_id_val = item.object.get("agent_id") orelse continue;
        if (agent_id_val != .string) continue;

        var binding = agent_routing.AgentBinding{
            .agent_id = try allocator.dupe(u8, agent_id_val.string),
        };

        if (item.object.get("comment")) |comment_val| {
            if (comment_val == .string) {
                binding.comment = try allocator.dupe(u8, comment_val.string);
            }
        }

        const match_val = item.object.get("match");
        if (match_val) |mv| {
            if (mv == .object) {
                if (mv.object.get("channel")) |v| {
                    if (v == .string) binding.match.channel = try allocator.dupe(u8, v.string);
                }
                if (mv.object.get("account_id")) |v| {
                    if (v == .string) binding.match.account_id = try allocator.dupe(u8, v.string);
                }
                if (mv.object.get("guild_id")) |v| {
                    if (v == .string) binding.match.guild_id = try allocator.dupe(u8, v.string);
                }
                if (mv.object.get("team_id")) |v| {
                    if (v == .string) binding.match.team_id = try allocator.dupe(u8, v.string);
                }
                if (mv.object.get("roles")) |v| {
                    if (v == .array) binding.match.roles = try parseStringArray(allocator, v.array);
                }
                if (mv.object.get("peer")) |peer_val| {
                    if (peer_val == .object) {
                        const kind_val = peer_val.object.get("kind");
                        const id_val = peer_val.object.get("id");
                        if (kind_val != null and id_val != null and kind_val.? == .string and id_val.? == .string) {
                            if (parsePeerKind(kind_val.?.string)) |kind| {
                                binding.match.peer = .{
                                    .kind = kind,
                                    .id = try allocator.dupe(u8, id_val.?.string),
                                };
                            }
                        }
                    }
                }
            }
        }

        try list.append(allocator, binding);
    }

    return list.toOwnedSlice(allocator);
}

const SelectedAccount = struct {
    id: []const u8,
    value: std.json.Value,
};

fn countAccounts(accounts: std.json.ObjectMap) usize {
    var count: usize = 0;
    var it = accounts.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    return count;
}

fn getPreferredAccount(channel_obj: std.json.ObjectMap) ?SelectedAccount {
    const accts_val = channel_obj.get("accounts") orelse return null;
    if (accts_val != .object) return null;
    const accounts = accts_val.object;
    const has_multiple = countAccounts(accounts) > 1;

    if (accounts.get("default")) |default_acc| {
        if (default_acc == .object) {
            if (has_multiple) {
                std.log.warn("Multiple accounts configured; using accounts.default", .{});
            }
            return .{ .id = "default", .value = default_acc };
        }
    }
    if (accounts.get("main")) |main_acc| {
        if (main_acc == .object) {
            if (has_multiple) {
                std.log.warn("Multiple accounts configured; using accounts.main", .{});
            }
            return .{ .id = "main", .value = main_acc };
        }
    }

    var it = accounts.iterator();
    const first = it.next() orelse return null;
    if (first.value_ptr.* != .object) return null;
    if (has_multiple) {
        std.log.warn("Multiple accounts configured; only first account used", .{});
    }
    return .{
        .id = first.key_ptr.*,
        .value = first.value_ptr.*,
    };
}

fn getAllAccountsSorted(allocator: std.mem.Allocator, channel_obj: std.json.ObjectMap) ![]const SelectedAccount {
    const accts_val = channel_obj.get("accounts") orelse return &.{};
    if (accts_val != .object) return &.{};
    const accounts = accts_val.object;

    var list: std.ArrayListUnmanaged(SelectedAccount) = .empty;
    var it = accounts.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .object) {
            try list.append(allocator, .{
                .id = entry.key_ptr.*,
                .value = entry.value_ptr.*,
            });
        }
    }

    if (list.items.len > 1) {
        std.mem.sort(SelectedAccount, list.items, {}, struct {
            fn cmp(_: void, a: SelectedAccount, b: SelectedAccount) bool {
                return std.mem.order(u8, a.id, b.id) == .lt;
            }
        }.cmp);
    }
    return try list.toOwnedSlice(allocator);
}

fn parseTypedValue(comptime T: type, allocator: std.mem.Allocator, value: std.json.Value) ?T {
    return std.json.parseFromValueLeaky(T, allocator, value, .{
        .ignore_unknown_fields = true,
    }) catch null;
}

fn maybeSetAccountId(comptime T: type, allocator: std.mem.Allocator, parsed: *T, account_id: []const u8) !void {
    if (comptime @hasField(T, "account_id")) {
        const current = @field(parsed.*, "account_id");
        if (!std.mem.eql(u8, current, "default")) {
            allocator.free(current);
        }
        @field(parsed.*, "account_id") = try allocator.dupe(u8, account_id);
    }
}

fn parseMultiAccountChannel(comptime T: type, allocator: std.mem.Allocator, channel_value: std.json.Value) ![]const T {
    if (channel_value != .object) return &.{};

    const accounts = try getAllAccountsSorted(allocator, channel_value.object);
    defer if (accounts.len > 0) allocator.free(accounts);
    if (accounts.len == 0) {
        // Accept inline single-account format:
        // "channel": { "token": "...", ... }
        const parsed = parseTypedValue(T, allocator, channel_value) orelse return &.{};
        var list: std.ArrayListUnmanaged(T) = .empty;
        try list.append(allocator, parsed);
        return try list.toOwnedSlice(allocator);
    }

    var list: std.ArrayListUnmanaged(T) = .empty;
    for (accounts) |acc| {
        var parsed = parseTypedValue(T, allocator, acc.value) orelse continue;
        try maybeSetAccountId(T, allocator, &parsed, acc.id);
        try list.append(allocator, parsed);
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn parseSingleAccountChannel(comptime T: type, allocator: std.mem.Allocator, channel_value: std.json.Value) !?T {
    if (channel_value != .object) return null;
    const selected = getPreferredAccount(channel_value.object) orelse return null;

    var parsed = parseTypedValue(T, allocator, selected.value) orelse return null;
    try maybeSetAccountId(T, allocator, &parsed, selected.id);
    return parsed;
}

fn parseInlineChannel(comptime T: type, allocator: std.mem.Allocator, channel_value: std.json.Value) ?T {
    if (channel_value != .object) return null;
    return parseTypedValue(T, allocator, channel_value);
}

fn parseChannels(self: *Config, channels_value: std.json.Value) !void {
    if (channels_value != .object) return;
    const channels_obj = channels_value.object;

    if (channels_obj.get("cli")) |v| {
        if (v == .bool) self.channels.cli = v.bool;
    }

    inline for (std.meta.fields(types.ChannelsConfig)) |field| {
        if (comptime std.mem.eql(u8, field.name, "cli")) continue;
        if (channels_obj.get(field.name)) |channel_value| {
            switch (@typeInfo(field.type)) {
                .pointer => |ptr| {
                    if (ptr.size == .slice) {
                        const Elem = ptr.child;
                        const parsed = try parseMultiAccountChannel(Elem, self.allocator, channel_value);
                        if (parsed.len > 0) {
                            @field(self.channels, field.name) = parsed;
                        }
                    }
                },
                .optional => |opt| {
                    const Child = opt.child;
                    if (comptime @hasField(Child, "account_id")) {
                        if (try parseSingleAccountChannel(Child, self.allocator, channel_value)) |parsed| {
                            @field(self.channels, field.name) = parsed;
                        }
                    } else {
                        if (parseInlineChannel(Child, self.allocator, channel_value)) |parsed| {
                            @field(self.channels, field.name) = parsed;
                        }
                    }
                },
                else => {},
            }
        }
    }
}

/// Parse JSON content into the given Config.
pub fn parseJson(self: *Config, content: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, content, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    // Top-level fields
    if (root.get("default_provider")) |v| {
        if (v == .string) self.legacy_default_provider_detected = true;
    }
    // Legacy key is no longer accepted. Require agents.defaults.model.primary.
    if (root.get("default_model")) |_| {
        self.legacy_default_model_detected = true;
    }
    if (root.get("default_temperature")) |v| {
        if (v == .float) self.default_temperature = v.float;
        if (v == .integer) self.default_temperature = @floatFromInt(v.integer);
    }
    if (root.get("max_tokens")) |v| {
        if (v == .integer) self.max_tokens = @intCast(v.integer);
    }
    if (root.get("reasoning_effort")) |v| {
        if (v == .string) {
            if (std.mem.eql(u8, v.string, "low") or
                std.mem.eql(u8, v.string, "medium") or
                std.mem.eql(u8, v.string, "high") or
                std.mem.eql(u8, v.string, "none"))
            {
                self.reasoning_effort = try self.allocator.dupe(u8, v.string);
            }
        }
    }

    // Model routes
    if (root.get("model_routes")) |v| {
        if (v == .array) {
            var list: std.ArrayListUnmanaged(types.ModelRouteConfig) = .empty;
            try list.ensureTotalCapacity(self.allocator, @intCast(v.array.items.len));
            for (v.array.items) |item| {
                if (item == .object) {
                    const hint = item.object.get("hint") orelse continue;
                    const provider = item.object.get("provider") orelse continue;
                    const model = item.object.get("model") orelse continue;
                    if (hint != .string or provider != .string or model != .string) continue;
                    var route = types.ModelRouteConfig{
                        .hint = try self.allocator.dupe(u8, hint.string),
                        .provider = try self.allocator.dupe(u8, provider.string),
                        .model = try self.allocator.dupe(u8, model.string),
                    };
                    if (item.object.get("api_key")) |ak| {
                        if (ak == .string) route.api_key = try self.allocator.dupe(u8, ak.string);
                    }
                    try list.append(self.allocator, route);
                }
            }
            self.model_routes = try list.toOwnedSlice(self.allocator);
        }
    }

    // Agents section: agents.defaults.model.primary (provider/model) + agents.defaults.heartbeat + agents.list[]
    if (root.get("agents")) |agents_val| {
        if (agents_val == .object) {
            // agents.defaults.model.primary (provider/model) → self.default_provider + self.default_model
            // agents.defaults.heartbeat → self.heartbeat
            if (agents_val.object.get("defaults")) |defaults| {
                if (defaults == .object) {
                    if (defaults.object.get("model")) |mdl| {
                        if (mdl == .object) {
                            if (mdl.object.get("primary")) |v| {
                                if (v == .string) {
                                    if (splitPrimaryModelRef(v.string)) |parsed_ref| {
                                        self.default_provider = try self.allocator.dupe(u8, parsed_ref.provider);
                                        self.default_model = try self.allocator.dupe(u8, parsed_ref.model);
                                    } else {
                                        self.default_provider = "";
                                        self.default_model = null;
                                    }
                                }
                            }
                        }
                    }
                    if (defaults.object.get("heartbeat")) |hb| {
                        if (hb == .object) {
                            // "every" string like "30m", "1h" → interval_minutes; implies enabled=true
                            if (hb.object.get("every")) |v| {
                                if (v == .string) {
                                    self.heartbeat.enabled = true;
                                    const s = v.string;
                                    if (s.len > 1) {
                                        const suffix = s[s.len - 1];
                                        const num_str = s[0 .. s.len - 1];
                                        if (std.fmt.parseInt(u32, num_str, 10)) |num| {
                                            if (suffix == 'h') {
                                                self.heartbeat.interval_minutes = num * 60;
                                            } else {
                                                self.heartbeat.interval_minutes = num;
                                            }
                                        } else |_| {}
                                    }
                                }
                            }
                            // Explicit enabled override
                            if (hb.object.get("enabled")) |v| {
                                if (v == .bool) self.heartbeat.enabled = v.bool;
                            }
                            // Explicit interval_minutes (our internal field)
                            if (hb.object.get("interval_minutes")) |v| {
                                if (v == .integer) self.heartbeat.interval_minutes = @intCast(v.integer);
                            }
                        }
                    }
                }
            }
            // agents.list[] → self.agents
            if (agents_val.object.get("list")) |list_val| {
                if (list_val == .array) {
                    var list: std.ArrayListUnmanaged(types.NamedAgentConfig) = .empty;
                    try list.ensureTotalCapacity(self.allocator, @intCast(list_val.array.items.len));
                    for (list_val.array.items) |item| {
                        if (item == .object) {
                            // "id" or "name" for the agent name
                            const name_val = item.object.get("id") orelse item.object.get("name") orelse continue;
                            const provider = item.object.get("provider") orelse continue;
                            if (name_val != .string or provider != .string) continue;

                            // model can be string or {"primary": "..."}
                            const model_str: ?[]const u8 = blk: {
                                const m = item.object.get("model") orelse break :blk null;
                                if (m == .string) break :blk m.string;
                                if (m == .object) {
                                    if (m.object.get("primary")) |mp| {
                                        if (mp == .string) break :blk mp.string;
                                    }
                                }
                                break :blk null;
                            };
                            if (model_str == null) continue;

                            var agent_cfg = types.NamedAgentConfig{
                                .name = try self.allocator.dupe(u8, name_val.string),
                                .provider = try self.allocator.dupe(u8, provider.string),
                                .model = try self.allocator.dupe(u8, model_str.?),
                            };
                            if (item.object.get("system_prompt")) |sp| {
                                if (sp == .string) agent_cfg.system_prompt = try self.allocator.dupe(u8, sp.string);
                            }
                            if (item.object.get("api_key")) |ak| {
                                if (ak == .string) agent_cfg.api_key = try self.allocator.dupe(u8, ak.string);
                            }
                            if (item.object.get("temperature")) |t| {
                                if (t == .float) agent_cfg.temperature = t.float;
                                if (t == .integer) agent_cfg.temperature = @floatFromInt(t.integer);
                            }
                            if (item.object.get("max_depth")) |md| {
                                if (md == .integer) agent_cfg.max_depth = @intCast(md.integer);
                            }
                            try list.append(self.allocator, agent_cfg);
                        }
                    }
                    self.agents = try list.toOwnedSlice(self.allocator);
                }
            }
        }
    }

    // Agent bindings (OpenClaw-style key, snake_case payload fields).
    const bindings_src = root.get("bindings");
    if (bindings_src) |bindings_val| {
        if (bindings_val == .array) {
            self.agent_bindings = try parseAgentBindingsArray(self.allocator, bindings_val.array);
        }
    }

    // MCP servers (object-of-objects format, compatible with Claude Desktop / Cursor)
    if (root.get("mcp_servers")) |mcp_val| {
        if (mcp_val == .object) {
            var mcp_list: std.ArrayListUnmanaged(types.McpServerConfig) = .empty;
            var mcp_it = mcp_val.object.iterator();
            while (mcp_it.next()) |entry| {
                const server_name = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                if (val != .object) continue;
                const cmd = val.object.get("command") orelse continue;
                if (cmd != .string) continue;

                var mcp_cfg = types.McpServerConfig{
                    .name = try self.allocator.dupe(u8, server_name),
                    .command = try self.allocator.dupe(u8, cmd.string),
                };

                // args: string array
                if (val.object.get("args")) |a| {
                    if (a == .array) mcp_cfg.args = try parseStringArray(self.allocator, a.array);
                }

                // env: object of string→string
                if (val.object.get("env")) |e| {
                    if (e == .object) {
                        var env_list: std.ArrayListUnmanaged(types.McpServerConfig.McpEnvEntry) = .empty;
                        var eit = e.object.iterator();
                        while (eit.next()) |ee| {
                            if (ee.value_ptr.* == .string) {
                                try env_list.append(self.allocator, .{
                                    .key = try self.allocator.dupe(u8, ee.key_ptr.*),
                                    .value = try self.allocator.dupe(u8, ee.value_ptr.string),
                                });
                            }
                        }
                        mcp_cfg.env = try env_list.toOwnedSlice(self.allocator);
                    }
                }

                try mcp_list.append(self.allocator, mcp_cfg);
            }
            self.mcp_servers = try mcp_list.toOwnedSlice(self.allocator);
        }
    }

    // Diagnostics (nested otel object)
    if (root.get("diagnostics")) |diag| {
        if (diag == .object) {
            if (diag.object.get("backend")) |v| {
                if (v == .string) self.diagnostics.backend = try self.allocator.dupe(u8, v.string);
            }
            if (diag.object.get("otel")) |otel| {
                if (otel == .object) {
                    if (otel.object.get("endpoint")) |v| {
                        if (v == .string) self.diagnostics.otel_endpoint = try self.allocator.dupe(u8, v.string);
                    }
                    if (otel.object.get("service_name")) |v| {
                        if (v == .string) self.diagnostics.otel_service_name = try self.allocator.dupe(u8, v.string);
                    }
                }
            }
        }
    }

    // Autonomy
    if (root.get("autonomy")) |aut| {
        if (aut == .object) {
            if (aut.object.get("workspace_only")) |v| {
                if (v == .bool) self.autonomy.workspace_only = v.bool;
            }
            if (aut.object.get("max_actions_per_hour")) |v| {
                if (v == .integer) self.autonomy.max_actions_per_hour = @intCast(v.integer);
            }
            // max_cost_per_day_cents: ignored (removed — never enforced at runtime)
            if (aut.object.get("require_approval_for_medium_risk")) |v| {
                if (v == .bool) self.autonomy.require_approval_for_medium_risk = v.bool;
            }
            if (aut.object.get("block_high_risk_commands")) |v| {
                if (v == .bool) self.autonomy.block_high_risk_commands = v.bool;
            }
            if (aut.object.get("level")) |v| {
                if (v == .string) {
                    if (types.AutonomyLevel.fromString(v.string)) |lvl| {
                        self.autonomy.level = lvl;
                    }
                }
            }
            if (aut.object.get("allowed_commands")) |v| {
                if (v == .array) self.autonomy.allowed_commands = try parseStringArray(self.allocator, v.array);
            }
            // forbidden_paths: ignored (removed — path security handled by path_security.zig)
            if (aut.object.get("allowed_paths")) |v| {
                if (v == .array) self.autonomy.allowed_paths = try parseStringArray(self.allocator, v.array);
            }
        }
    }

    // Runtime
    if (root.get("runtime")) |rt| {
        if (rt == .object) {
            if (rt.object.get("kind")) |v| {
                if (v == .string) self.runtime.kind = try self.allocator.dupe(u8, v.string);
            }
            if (rt.object.get("docker")) |dk| {
                if (dk == .object) {
                    if (dk.object.get("image")) |v| {
                        if (v == .string) self.runtime.docker.image = try self.allocator.dupe(u8, v.string);
                    }
                    if (dk.object.get("network")) |v| {
                        if (v == .string) self.runtime.docker.network = try self.allocator.dupe(u8, v.string);
                    }
                    if (dk.object.get("memory_limit_mb")) |v| {
                        if (v == .integer) self.runtime.docker.memory_limit_mb = @intCast(v.integer);
                    }
                    if (dk.object.get("read_only_rootfs")) |v| {
                        if (v == .bool) self.runtime.docker.read_only_rootfs = v.bool;
                    }
                    if (dk.object.get("mount_workspace")) |v| {
                        if (v == .bool) self.runtime.docker.mount_workspace = v.bool;
                    }
                }
            }
        }
    }

    // Reliability
    if (root.get("reliability")) |rel| {
        if (rel == .object) {
            if (rel.object.get("provider_retries")) |v| {
                if (v == .integer) self.reliability.provider_retries = @intCast(v.integer);
            }
            if (rel.object.get("provider_backoff_ms")) |v| {
                if (v == .integer) self.reliability.provider_backoff_ms = @intCast(v.integer);
            }
            if (rel.object.get("fallback_providers")) |v| {
                if (v == .array) self.reliability.fallback_providers = try parseStringArray(self.allocator, v.array);
            }
            if (rel.object.get("api_keys")) |v| {
                if (v == .array) self.reliability.api_keys = try parseStringArray(self.allocator, v.array);
            }
            if (rel.object.get("model_fallbacks")) |v| {
                if (v == .array) {
                    var fallback_entries: std.ArrayListUnmanaged(types.ModelFallbackEntry) = .empty;
                    errdefer {
                        for (fallback_entries.items) |entry| {
                            for (entry.fallbacks) |fb| self.allocator.free(fb);
                            self.allocator.free(entry.fallbacks);
                            self.allocator.free(entry.model);
                        }
                        fallback_entries.deinit(self.allocator);
                    }

                    for (v.array.items) |entry| {
                        if (entry != .object) continue;
                        const model_val = entry.object.get("model") orelse continue;
                        if (model_val != .string) continue;

                        const model_trimmed = std.mem.trim(u8, model_val.string, " \t\r\n");
                        if (model_trimmed.len == 0) continue;

                        const fallbacks_val = entry.object.get("fallbacks") orelse continue;
                        if (fallbacks_val != .array) continue;

                        const model_copy = try self.allocator.dupe(u8, model_trimmed);
                        const fallback_copy = try parseStringArray(self.allocator, fallbacks_val.array);
                        fallback_entries.append(self.allocator, .{
                            .model = model_copy,
                            .fallbacks = fallback_copy,
                        }) catch |err| {
                            self.allocator.free(model_copy);
                            for (fallback_copy) |fb| self.allocator.free(fb);
                            self.allocator.free(fallback_copy);
                            return err;
                        };
                    }

                    self.reliability.model_fallbacks = try fallback_entries.toOwnedSlice(self.allocator);
                }
            }
            if (rel.object.get("channel_initial_backoff_secs")) |v| {
                if (v == .integer) self.reliability.channel_initial_backoff_secs = @intCast(v.integer);
            }
            if (rel.object.get("channel_max_backoff_secs")) |v| {
                if (v == .integer) self.reliability.channel_max_backoff_secs = @intCast(v.integer);
            }
            if (rel.object.get("scheduler_poll_secs")) |v| {
                if (v == .integer) self.reliability.scheduler_poll_secs = @intCast(v.integer);
            }
            if (rel.object.get("scheduler_retries")) |v| {
                if (v == .integer) self.reliability.scheduler_retries = @intCast(v.integer);
            }
        }
    }

    // Scheduler
    if (root.get("scheduler")) |sch| {
        if (sch == .object) {
            if (sch.object.get("enabled")) |v| {
                if (v == .bool) self.scheduler.enabled = v.bool;
            }
            if (sch.object.get("max_tasks")) |v| {
                if (v == .integer) self.scheduler.max_tasks = @intCast(v.integer);
            }
            if (sch.object.get("max_concurrent")) |v| {
                if (v == .integer) self.scheduler.max_concurrent = @intCast(v.integer);
            }
        }
    }

    // Cron
    if (root.get("cron")) |cr| {
        if (cr == .object) {
            if (cr.object.get("enabled")) |v| {
                if (v == .bool) self.cron.enabled = v.bool;
            }
            if (cr.object.get("interval_minutes")) |v| {
                if (v == .integer) self.cron.interval_minutes = @intCast(v.integer);
            }
            if (cr.object.get("max_run_history")) |v| {
                if (v == .integer) self.cron.max_run_history = @intCast(v.integer);
            }
        }
    }

    // Agent
    if (root.get("agent")) |ag| {
        if (ag == .object) {
            if (ag.object.get("compact_context")) |v| {
                if (v == .bool) self.agent.compact_context = v.bool;
            }
            if (ag.object.get("max_tool_iterations")) |v| {
                if (v == .integer) self.agent.max_tool_iterations = @intCast(v.integer);
            }
            if (ag.object.get("max_history_messages")) |v| {
                if (v == .integer) self.agent.max_history_messages = @intCast(v.integer);
            }
            if (ag.object.get("parallel_tools")) |v| {
                if (v == .bool) self.agent.parallel_tools = v.bool;
            }
            if (ag.object.get("tool_dispatcher")) |v| {
                if (v == .string) self.agent.tool_dispatcher = try self.allocator.dupe(u8, v.string);
            }
            if (ag.object.get("session_idle_timeout_secs")) |v| {
                if (v == .integer) self.agent.session_idle_timeout_secs = @intCast(v.integer);
            }
            if (ag.object.get("compaction_keep_recent")) |v| {
                if (v == .integer) self.agent.compaction_keep_recent = @intCast(v.integer);
            }
            if (ag.object.get("compaction_max_summary_chars")) |v| {
                if (v == .integer) self.agent.compaction_max_summary_chars = @intCast(v.integer);
            }
            if (ag.object.get("compaction_max_source_chars")) |v| {
                if (v == .integer) self.agent.compaction_max_source_chars = @intCast(v.integer);
            }
            if (ag.object.get("token_limit")) |v| {
                if (v == .integer) self.agent.token_limit = @intCast(v.integer);
            }
            if (ag.object.get("message_timeout_secs")) |v| {
                if (v == .integer) self.agent.message_timeout_secs = @intCast(v.integer);
            }
        }
    }

    // Tools (including tools.media.audio)
    if (root.get("tools")) |tl| {
        if (tl == .object) {
            if (tl.object.get("shell_timeout_secs")) |v| {
                if (v == .integer) self.tools.shell_timeout_secs = @intCast(v.integer);
            }
            if (tl.object.get("shell_max_output_bytes")) |v| {
                if (v == .integer) self.tools.shell_max_output_bytes = @intCast(v.integer);
            }
            if (tl.object.get("max_file_size_bytes")) |v| {
                if (v == .integer) self.tools.max_file_size_bytes = @intCast(v.integer);
            }
            if (tl.object.get("web_fetch_max_chars")) |v| {
                if (v == .integer) self.tools.web_fetch_max_chars = @intCast(v.integer);
            }
            // tools.media.audio → self.audio_media
            if (tl.object.get("media")) |media| {
                if (media == .object) {
                    if (media.object.get("audio")) |audio| {
                        if (audio == .object) {
                            if (audio.object.get("enabled")) |v| {
                                if (v == .bool) self.audio_media.enabled = v.bool;
                            }
                            if (audio.object.get("language")) |v| {
                                if (v == .string) self.audio_media.language = try self.allocator.dupe(u8, v.string);
                            }
                            // models[0] → provider, model, base_url, language (override)
                            if (audio.object.get("models")) |models| {
                                if (models == .array and models.array.items.len > 0) {
                                    const m0 = models.array.items[0];
                                    if (m0 == .object) {
                                        if (m0.object.get("provider")) |v| {
                                            if (v == .string) self.audio_media.provider = try self.allocator.dupe(u8, v.string);
                                        }
                                        if (m0.object.get("model")) |v| {
                                            if (v == .string) self.audio_media.model = try self.allocator.dupe(u8, v.string);
                                        }
                                        if (m0.object.get("base_url")) |v| {
                                            if (v == .string) self.audio_media.base_url = try self.allocator.dupe(u8, v.string);
                                        }
                                        if (m0.object.get("language")) |v| {
                                            if (v == .string) {
                                                // Free prior allocation from audio.language if it was set above
                                                if (self.audio_media.language) |prev| self.allocator.free(prev);
                                                self.audio_media.language = try self.allocator.dupe(u8, v.string);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Memory
    if (root.get("memory")) |mem| {
        if (mem == .object) {
            if (mem.object.get("profile")) |v| {
                if (v == .string) self.memory.profile = try self.allocator.dupe(u8, v.string);
            }
            if (mem.object.get("backend")) |v| {
                if (v == .string) self.memory.backend = try self.allocator.dupe(u8, v.string);
            }
            if (mem.object.get("auto_save")) |v| {
                if (v == .bool) self.memory.auto_save = v.bool;
            }
            if (mem.object.get("citations")) |v| {
                if (v == .string) self.memory.citations = try self.allocator.dupe(u8, v.string);
            }

            // search
            if (mem.object.get("search")) |search_val| {
                if (search_val == .object) {
                    const search = search_val.object;
                    if (search.get("enabled")) |v| if (v == .bool) {
                        self.memory.search.enabled = v.bool;
                    };
                    if (search.get("provider")) |v| if (v == .string) {
                        self.memory.search.provider = try self.allocator.dupe(u8, v.string);
                    };
                    if (search.get("model")) |v| if (v == .string) {
                        self.memory.search.model = try self.allocator.dupe(u8, v.string);
                    };
                    if (search.get("dimensions")) |v| if (v == .integer) {
                        self.memory.search.dimensions = @intCast(v.integer);
                    };
                    if (search.get("fallback_provider")) |v| if (v == .string) {
                        self.memory.search.fallback_provider = try self.allocator.dupe(u8, v.string);
                    };

                    // search.store
                    if (search.get("store")) |store_val| {
                        if (store_val == .object) {
                            const store = store_val.object;
                            if (store.get("kind")) |v| if (v == .string) {
                                self.memory.search.store.kind = try self.allocator.dupe(u8, v.string);
                            };
                            if (store.get("sidecar_path")) |v| if (v == .string) {
                                self.memory.search.store.sidecar_path = try self.allocator.dupe(u8, v.string);
                            };
                            if (store.get("qdrant_url")) |v| if (v == .string) {
                                self.memory.search.store.qdrant_url = try self.allocator.dupe(u8, v.string);
                            };
                            if (store.get("qdrant_collection")) |v| if (v == .string) {
                                self.memory.search.store.qdrant_collection = try self.allocator.dupe(u8, v.string);
                            };
                            if (store.get("qdrant_api_key")) |v| if (v == .string) {
                                self.memory.search.store.qdrant_api_key = try self.allocator.dupe(u8, v.string);
                            };
                            if (store.get("pgvector_table")) |v| if (v == .string) {
                                self.memory.search.store.pgvector_table = try self.allocator.dupe(u8, v.string);
                            };
                        }
                    }

                    // search.chunking
                    if (search.get("chunking")) |chunking_val| {
                        if (chunking_val == .object) {
                            const chunking = chunking_val.object;
                            if (chunking.get("max_tokens")) |v| if (v == .integer) {
                                self.memory.search.chunking.max_tokens = @intCast(v.integer);
                            };
                            if (chunking.get("overlap")) |v| if (v == .integer) {
                                self.memory.search.chunking.overlap = @intCast(v.integer);
                            };
                        }
                    }

                    // search.sync
                    if (search.get("sync")) |sync_val| {
                        if (sync_val == .object) {
                            const sync = sync_val.object;
                            if (sync.get("mode")) |v| if (v == .string) {
                                self.memory.search.sync.mode = try self.allocator.dupe(u8, v.string);
                            };
                            if (sync.get("embed_timeout_ms")) |v| if (v == .integer) {
                                self.memory.search.sync.embed_timeout_ms = @intCast(v.integer);
                            };
                            if (sync.get("vector_timeout_ms")) |v| if (v == .integer) {
                                self.memory.search.sync.vector_timeout_ms = @intCast(v.integer);
                            };
                            if (sync.get("embed_max_retries")) |v| if (v == .integer) {
                                self.memory.search.sync.embed_max_retries = @intCast(v.integer);
                            };
                            if (sync.get("vector_max_retries")) |v| if (v == .integer) {
                                self.memory.search.sync.vector_max_retries = @intCast(v.integer);
                            };
                        }
                    }

                    // search.query
                    if (search.get("query")) |query_val| {
                        if (query_val == .object) {
                            const query = query_val.object;
                            if (query.get("max_results")) |v| if (v == .integer) {
                                self.memory.search.query.max_results = @intCast(v.integer);
                            };
                            if (query.get("min_score")) |v| {
                                if (v == .float) self.memory.search.query.min_score = v.float;
                                if (v == .integer) self.memory.search.query.min_score = @floatFromInt(v.integer);
                            }
                            if (query.get("merge_strategy")) |v| if (v == .string) {
                                self.memory.search.query.merge_strategy = try self.allocator.dupe(u8, v.string);
                            };
                            if (query.get("rrf_k")) |v| if (v == .integer) {
                                self.memory.search.query.rrf_k = @intCast(v.integer);
                            };

                            // search.query.hybrid
                            if (query.get("hybrid")) |hybrid_val| {
                                if (hybrid_val == .object) {
                                    const hybrid = hybrid_val.object;
                                    if (hybrid.get("enabled")) |v| if (v == .bool) {
                                        self.memory.search.query.hybrid.enabled = v.bool;
                                    };
                                    if (hybrid.get("vector_weight")) |v| {
                                        if (v == .float) self.memory.search.query.hybrid.vector_weight = v.float;
                                        if (v == .integer) self.memory.search.query.hybrid.vector_weight = @floatFromInt(v.integer);
                                    }
                                    if (hybrid.get("text_weight")) |v| {
                                        if (v == .float) self.memory.search.query.hybrid.text_weight = v.float;
                                        if (v == .integer) self.memory.search.query.hybrid.text_weight = @floatFromInt(v.integer);
                                    }
                                    if (hybrid.get("candidate_multiplier")) |v| if (v == .integer) {
                                        self.memory.search.query.hybrid.candidate_multiplier = @intCast(v.integer);
                                    };

                                    // search.query.hybrid.mmr
                                    if (hybrid.get("mmr")) |mmr_val| {
                                        if (mmr_val == .object) {
                                            const mmr = mmr_val.object;
                                            if (mmr.get("enabled")) |v| if (v == .bool) {
                                                self.memory.search.query.hybrid.mmr.enabled = v.bool;
                                            };
                                            if (mmr.get("lambda")) |v| {
                                                if (v == .float) self.memory.search.query.hybrid.mmr.lambda = v.float;
                                                if (v == .integer) self.memory.search.query.hybrid.mmr.lambda = @floatFromInt(v.integer);
                                            }
                                        }
                                    }

                                    // search.query.hybrid.temporal_decay
                                    if (hybrid.get("temporal_decay")) |td_val| {
                                        if (td_val == .object) {
                                            const td = td_val.object;
                                            if (td.get("enabled")) |v| if (v == .bool) {
                                                self.memory.search.query.hybrid.temporal_decay.enabled = v.bool;
                                            };
                                            if (td.get("half_life_days")) |v| if (v == .integer) {
                                                self.memory.search.query.hybrid.temporal_decay.half_life_days = @intCast(v.integer);
                                            };
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // search.cache
                    if (search.get("cache")) |cache_val| {
                        if (cache_val == .object) {
                            const cache = cache_val.object;
                            if (cache.get("enabled")) |v| if (v == .bool) {
                                self.memory.search.cache.enabled = v.bool;
                            };
                            if (cache.get("max_entries")) |v| if (v == .integer) {
                                self.memory.search.cache.max_entries = @intCast(v.integer);
                            };
                        }
                    }
                }
            }

            // qmd
            if (mem.object.get("qmd")) |qmd_val| {
                if (qmd_val == .object) {
                    const qmd = qmd_val.object;
                    if (qmd.get("enabled")) |v| if (v == .bool) {
                        self.memory.qmd.enabled = v.bool;
                    };
                    if (qmd.get("command")) |v| if (v == .string) {
                        self.memory.qmd.command = try self.allocator.dupe(u8, v.string);
                    };
                    if (qmd.get("search_mode")) |v| if (v == .string) {
                        self.memory.qmd.search_mode = try self.allocator.dupe(u8, v.string);
                    };
                    if (qmd.get("include_default_memory")) |v| if (v == .bool) {
                        self.memory.qmd.include_default_memory = v.bool;
                    };

                    // qmd.mcporter
                    if (qmd.get("mcporter")) |mcp_val| {
                        if (mcp_val == .object) {
                            const mcp = mcp_val.object;
                            if (mcp.get("enabled")) |v| if (v == .bool) {
                                self.memory.qmd.mcporter.enabled = v.bool;
                            };
                            if (mcp.get("server_name")) |v| if (v == .string) {
                                self.memory.qmd.mcporter.server_name = try self.allocator.dupe(u8, v.string);
                            };
                            if (mcp.get("start_daemon")) |v| if (v == .bool) {
                                self.memory.qmd.mcporter.start_daemon = v.bool;
                            };
                        }
                    }

                    // qmd.paths
                    if (qmd.get("paths")) |paths_val| {
                        if (paths_val == .array) {
                            const items = paths_val.array.items;
                            var list = try self.allocator.alloc(types.QmdIndexPath, items.len);
                            var count: usize = 0;
                            for (items) |item| {
                                if (item == .object) {
                                    var entry: types.QmdIndexPath = .{};
                                    if (item.object.get("path")) |v| if (v == .string) {
                                        entry.path = try self.allocator.dupe(u8, v.string);
                                    };
                                    if (item.object.get("name")) |v| if (v == .string) {
                                        entry.name = try self.allocator.dupe(u8, v.string);
                                    };
                                    if (item.object.get("pattern")) |v| if (v == .string) {
                                        entry.pattern = try self.allocator.dupe(u8, v.string);
                                    };
                                    list[count] = entry;
                                    count += 1;
                                }
                            }
                            self.memory.qmd.paths = list[0..count];
                        }
                    }

                    // qmd.sessions
                    if (qmd.get("sessions")) |sess_val| {
                        if (sess_val == .object) {
                            const sess = sess_val.object;
                            if (sess.get("enabled")) |v| if (v == .bool) {
                                self.memory.qmd.sessions.enabled = v.bool;
                            };
                            if (sess.get("export_dir")) |v| if (v == .string) {
                                self.memory.qmd.sessions.export_dir = try self.allocator.dupe(u8, v.string);
                            };
                            if (sess.get("retention_days")) |v| if (v == .integer) {
                                self.memory.qmd.sessions.retention_days = @intCast(v.integer);
                            };
                        }
                    }

                    // qmd.update
                    if (qmd.get("update")) |upd_val| {
                        if (upd_val == .object) {
                            const upd = upd_val.object;
                            if (upd.get("interval_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.interval_ms = @intCast(v.integer);
                            };
                            if (upd.get("debounce_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.debounce_ms = @intCast(v.integer);
                            };
                            if (upd.get("on_boot")) |v| if (v == .bool) {
                                self.memory.qmd.update.on_boot = v.bool;
                            };
                            if (upd.get("wait_for_boot_sync")) |v| if (v == .bool) {
                                self.memory.qmd.update.wait_for_boot_sync = v.bool;
                            };
                            if (upd.get("embed_interval_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.embed_interval_ms = @intCast(v.integer);
                            };
                            if (upd.get("command_timeout_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.command_timeout_ms = @intCast(v.integer);
                            };
                            if (upd.get("update_timeout_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.update_timeout_ms = @intCast(v.integer);
                            };
                            if (upd.get("embed_timeout_ms")) |v| if (v == .integer) {
                                self.memory.qmd.update.embed_timeout_ms = @intCast(v.integer);
                            };
                        }
                    }

                    // qmd.limits
                    if (qmd.get("limits")) |lim_val| {
                        if (lim_val == .object) {
                            const lim = lim_val.object;
                            if (lim.get("max_results")) |v| if (v == .integer) {
                                self.memory.qmd.limits.max_results = @intCast(v.integer);
                            };
                            if (lim.get("max_snippet_chars")) |v| if (v == .integer) {
                                self.memory.qmd.limits.max_snippet_chars = @intCast(v.integer);
                            };
                            if (lim.get("max_injected_chars")) |v| if (v == .integer) {
                                self.memory.qmd.limits.max_injected_chars = @intCast(v.integer);
                            };
                            if (lim.get("timeout_ms")) |v| if (v == .integer) {
                                self.memory.qmd.limits.timeout_ms = @intCast(v.integer);
                            };
                        }
                    }
                }
            }

            // lifecycle
            if (mem.object.get("lifecycle")) |lc_val| {
                if (lc_val == .object) {
                    const lc = lc_val.object;
                    if (lc.get("hygiene_enabled")) |v| if (v == .bool) {
                        self.memory.lifecycle.hygiene_enabled = v.bool;
                    };
                    if (lc.get("archive_after_days")) |v| if (v == .integer) {
                        self.memory.lifecycle.archive_after_days = @intCast(v.integer);
                    };
                    if (lc.get("purge_after_days")) |v| if (v == .integer) {
                        self.memory.lifecycle.purge_after_days = @intCast(v.integer);
                    };
                    if (lc.get("conversation_retention_days")) |v| if (v == .integer) {
                        self.memory.lifecycle.conversation_retention_days = @intCast(v.integer);
                    };
                    if (lc.get("snapshot_enabled")) |v| if (v == .bool) {
                        self.memory.lifecycle.snapshot_enabled = v.bool;
                    };
                    if (lc.get("snapshot_on_hygiene")) |v| if (v == .bool) {
                        self.memory.lifecycle.snapshot_on_hygiene = v.bool;
                    };
                    if (lc.get("auto_hydrate")) |v| if (v == .bool) {
                        self.memory.lifecycle.auto_hydrate = v.bool;
                    };
                }
            }

            // response_cache
            if (mem.object.get("response_cache")) |rc_val| {
                if (rc_val == .object) {
                    const rc = rc_val.object;
                    if (rc.get("enabled")) |v| if (v == .bool) {
                        self.memory.response_cache.enabled = v.bool;
                    };
                    if (rc.get("ttl_minutes")) |v| if (v == .integer) {
                        self.memory.response_cache.ttl_minutes = @intCast(v.integer);
                    };
                    if (rc.get("max_entries")) |v| if (v == .integer) {
                        self.memory.response_cache.max_entries = @intCast(v.integer);
                    };
                }
            }

            // reliability
            if (mem.object.get("reliability")) |rel_val| {
                if (rel_val == .object) {
                    const rel = rel_val.object;
                    if (rel.get("rollout_mode")) |v| if (v == .string) {
                        self.memory.reliability.rollout_mode = try self.allocator.dupe(u8, v.string);
                    };
                    if (rel.get("circuit_breaker_failures")) |v| if (v == .integer) {
                        self.memory.reliability.circuit_breaker_failures = @intCast(v.integer);
                    };
                    if (rel.get("circuit_breaker_cooldown_ms")) |v| if (v == .integer) {
                        self.memory.reliability.circuit_breaker_cooldown_ms = @intCast(v.integer);
                    };
                    if (rel.get("shadow_hybrid_percent")) |v| if (v == .integer) {
                        self.memory.reliability.shadow_hybrid_percent = @intCast(v.integer);
                    };
                    if (rel.get("canary_hybrid_percent")) |v| if (v == .integer) {
                        self.memory.reliability.canary_hybrid_percent = @intCast(v.integer);
                    };
                    if (rel.get("fallback_policy")) |v| if (v == .string) {
                        self.memory.reliability.fallback_policy = try self.allocator.dupe(u8, v.string);
                    };
                }
            }

            // postgres
            if (mem.object.get("postgres")) |pg_val| {
                if (pg_val == .object) {
                    const pg = pg_val.object;
                    if (pg.get("url")) |v| if (v == .string) {
                        self.memory.postgres.url = try self.allocator.dupe(u8, v.string);
                    };
                    if (pg.get("schema")) |v| if (v == .string) {
                        self.memory.postgres.schema = try self.allocator.dupe(u8, v.string);
                    };
                    if (pg.get("table")) |v| if (v == .string) {
                        self.memory.postgres.table = try self.allocator.dupe(u8, v.string);
                    };
                    if (pg.get("connect_timeout_secs")) |v| if (v == .integer) {
                        self.memory.postgres.connect_timeout_secs = @intCast(v.integer);
                    };
                }
            }
            // redis
            if (mem.object.get("redis")) |redis_val| {
                if (redis_val == .object) {
                    const rd = redis_val.object;
                    if (rd.get("host")) |v| if (v == .string) {
                        self.memory.redis.host = try self.allocator.dupe(u8, v.string);
                    };
                    if (rd.get("port")) |v| if (v == .integer) {
                        self.memory.redis.port = @intCast(v.integer);
                    };
                    if (rd.get("password")) |v| if (v == .string) {
                        self.memory.redis.password = try self.allocator.dupe(u8, v.string);
                    };
                    if (rd.get("db_index")) |v| if (v == .integer) {
                        self.memory.redis.db_index = @intCast(v.integer);
                    };
                    if (rd.get("key_prefix")) |v| if (v == .string) {
                        self.memory.redis.key_prefix = try self.allocator.dupe(u8, v.string);
                    };
                    if (rd.get("ttl_seconds")) |v| if (v == .integer) {
                        self.memory.redis.ttl_seconds = @intCast(v.integer);
                    };
                }
            }

            // api
            if (mem.object.get("api")) |api_val| {
                if (api_val == .object) {
                    const api = api_val.object;
                    if (api.get("url")) |v| if (v == .string) {
                        self.memory.api.url = try self.allocator.dupe(u8, v.string);
                    };
                    if (api.get("api_key")) |v| if (v == .string) {
                        self.memory.api.api_key = try self.allocator.dupe(u8, v.string);
                    };
                    if (api.get("timeout_ms")) |v| if (v == .integer) {
                        self.memory.api.timeout_ms = @intCast(v.integer);
                    };
                    if (api.get("namespace")) |v| if (v == .string) {
                        self.memory.api.namespace = try self.allocator.dupe(u8, v.string);
                    };
                }
            }

            // retrieval_stages
            if (mem.object.get("retrieval_stages")) |rs_val| {
                if (rs_val == .object) {
                    const rs = rs_val.object;
                    if (rs.get("query_expansion_enabled")) |v| if (v == .bool) {
                        self.memory.retrieval_stages.query_expansion_enabled = v.bool;
                    };
                    if (rs.get("adaptive_retrieval_enabled")) |v| if (v == .bool) {
                        self.memory.retrieval_stages.adaptive_retrieval_enabled = v.bool;
                    };
                    if (rs.get("adaptive_keyword_max_tokens")) |v| if (v == .integer) {
                        self.memory.retrieval_stages.adaptive_keyword_max_tokens = @intCast(v.integer);
                    };
                    if (rs.get("adaptive_vector_min_tokens")) |v| if (v == .integer) {
                        self.memory.retrieval_stages.adaptive_vector_min_tokens = @intCast(v.integer);
                    };
                    if (rs.get("llm_reranker_enabled")) |v| if (v == .bool) {
                        self.memory.retrieval_stages.llm_reranker_enabled = v.bool;
                    };
                    if (rs.get("llm_reranker_max_candidates")) |v| if (v == .integer) {
                        self.memory.retrieval_stages.llm_reranker_max_candidates = @intCast(v.integer);
                    };
                    if (rs.get("llm_reranker_timeout_ms")) |v| if (v == .integer) {
                        self.memory.retrieval_stages.llm_reranker_timeout_ms = @intCast(v.integer);
                    };
                }
            }

            // summarizer
            if (mem.object.get("summarizer")) |sum_val| {
                if (sum_val == .object) {
                    const sum = sum_val.object;
                    if (sum.get("enabled")) |v| if (v == .bool) {
                        self.memory.summarizer.enabled = v.bool;
                    };
                    if (sum.get("window_size_tokens")) |v| if (v == .integer) {
                        self.memory.summarizer.window_size_tokens = @intCast(v.integer);
                    };
                    if (sum.get("summary_max_tokens")) |v| if (v == .integer) {
                        self.memory.summarizer.summary_max_tokens = @intCast(v.integer);
                    };
                    if (sum.get("auto_extract_semantic")) |v| if (v == .bool) {
                        self.memory.summarizer.auto_extract_semantic = v.bool;
                    };
                }
            }

            // Apply profile defaults after all explicit overrides have been parsed.
            // Only sets fields that are still at their default values.
            self.memory.applyProfileDefaults();
        }
    }

    // Gateway
    if (root.get("gateway")) |gw| {
        if (gw == .object) {
            if (gw.object.get("port")) |v| {
                if (v == .integer) self.gateway.port = @intCast(v.integer);
            }
            if (gw.object.get("host")) |v| {
                if (v == .string) self.gateway.host = try self.allocator.dupe(u8, v.string);
            }
            if (gw.object.get("require_pairing")) |v| {
                if (v == .bool) self.gateway.require_pairing = v.bool;
            }
            if (gw.object.get("allow_public_bind")) |v| {
                if (v == .bool) self.gateway.allow_public_bind = v.bool;
            }
            if (gw.object.get("pair_rate_limit_per_minute")) |v| {
                if (v == .integer) self.gateway.pair_rate_limit_per_minute = @intCast(v.integer);
            }
            if (gw.object.get("webhook_rate_limit_per_minute")) |v| {
                if (v == .integer) self.gateway.webhook_rate_limit_per_minute = @intCast(v.integer);
            }
            if (gw.object.get("idempotency_ttl_secs")) |v| {
                if (v == .integer) self.gateway.idempotency_ttl_secs = @intCast(v.integer);
            }
            if (gw.object.get("paired_tokens")) |v| {
                if (v == .array) self.gateway.paired_tokens = try parseStringArray(self.allocator, v.array);
            }
        }
    }

    // Cost
    if (root.get("cost")) |co| {
        if (co == .object) {
            if (co.object.get("enabled")) |v| {
                if (v == .bool) self.cost.enabled = v.bool;
            }
            if (co.object.get("daily_limit_usd")) |v| {
                if (v == .float) self.cost.daily_limit_usd = v.float;
                if (v == .integer) self.cost.daily_limit_usd = @floatFromInt(v.integer);
            }
            if (co.object.get("monthly_limit_usd")) |v| {
                if (v == .float) self.cost.monthly_limit_usd = v.float;
                if (v == .integer) self.cost.monthly_limit_usd = @floatFromInt(v.integer);
            }
            if (co.object.get("warn_at_percent")) |v| {
                if (v == .integer) self.cost.warn_at_percent = @intCast(v.integer);
            }
            if (co.object.get("allow_override")) |v| {
                if (v == .bool) self.cost.allow_override = v.bool;
            }
        }
    }

    // Identity
    if (root.get("identity")) |id| {
        if (id == .object) {
            if (id.object.get("format")) |v| {
                if (v == .string) self.identity.format = try self.allocator.dupe(u8, v.string);
            }
            if (id.object.get("aieos_path")) |v| {
                if (v == .string) self.identity.aieos_path = try self.allocator.dupe(u8, v.string);
            }
            if (id.object.get("aieos_inline")) |v| {
                if (v == .string) self.identity.aieos_inline = try self.allocator.dupe(u8, v.string);
            }
        }
    }

    // Composio
    if (root.get("composio")) |comp| {
        if (comp == .object) {
            if (comp.object.get("enabled")) |v| {
                if (v == .bool) self.composio.enabled = v.bool;
            }
            if (comp.object.get("api_key")) |v| {
                if (v == .string) self.composio.api_key = try self.allocator.dupe(u8, v.string);
            }
            if (comp.object.get("entity_id")) |v| {
                if (v == .string) self.composio.entity_id = try self.allocator.dupe(u8, v.string);
            }
        }
    }

    // Secrets
    if (root.get("secrets")) |sec| {
        if (sec == .object) {
            if (sec.object.get("encrypt")) |v| {
                if (v == .bool) self.secrets.encrypt = v.bool;
            }
        }
    }

    // Browser
    if (root.get("browser")) |br| {
        if (br == .object) {
            if (br.object.get("enabled")) |v| {
                if (v == .bool) self.browser.enabled = v.bool;
            }
            if (br.object.get("backend")) |v| {
                if (v == .string) self.browser.backend = try self.allocator.dupe(u8, v.string);
            }
            if (br.object.get("native_headless")) |v| {
                if (v == .bool) self.browser.native_headless = v.bool;
            }
            if (br.object.get("native_webdriver_url")) |v| {
                if (v == .string) self.browser.native_webdriver_url = try self.allocator.dupe(u8, v.string);
            }
            if (br.object.get("native_chrome_path")) |v| {
                if (v == .string) self.browser.native_chrome_path = try self.allocator.dupe(u8, v.string);
            }
            if (br.object.get("session_name")) |v| {
                if (v == .string) self.browser.session_name = try self.allocator.dupe(u8, v.string);
            }
            if (br.object.get("allowed_domains")) |v| {
                if (v == .array) self.browser.allowed_domains = try parseStringArray(self.allocator, v.array);
            }
        }
    }

    // HTTP Request
    if (root.get("http_request")) |hr| {
        if (hr == .object) {
            if (hr.object.get("enabled")) |v| {
                if (v == .bool) self.http_request.enabled = v.bool;
            }
            if (hr.object.get("max_response_size")) |v| {
                if (v == .integer) self.http_request.max_response_size = @intCast(v.integer);
            }
            if (hr.object.get("timeout_secs")) |v| {
                if (v == .integer) self.http_request.timeout_secs = @intCast(v.integer);
            }
            if (hr.object.get("allowed_domains")) |v| {
                if (v == .array) self.http_request.allowed_domains = try parseStringArray(self.allocator, v.array);
            }
        }
    }

    // Hardware
    if (root.get("hardware")) |hw| {
        if (hw == .object) {
            if (hw.object.get("enabled")) |v| {
                if (v == .bool) self.hardware.enabled = v.bool;
            }
            if (hw.object.get("serial_port")) |v| {
                if (v == .string) self.hardware.serial_port = try self.allocator.dupe(u8, v.string);
            }
            if (hw.object.get("baud_rate")) |v| {
                if (v == .integer) self.hardware.baud_rate = @intCast(v.integer);
            }
            if (hw.object.get("probe_target")) |v| {
                if (v == .string) self.hardware.probe_target = try self.allocator.dupe(u8, v.string);
            }
            if (hw.object.get("workspace_datasheets")) |v| {
                if (v == .bool) self.hardware.workspace_datasheets = v.bool;
            }
            if (hw.object.get("transport")) |v| {
                if (v == .string) {
                    if (std.mem.eql(u8, v.string, "none")) {
                        self.hardware.transport = .none;
                    } else if (std.mem.eql(u8, v.string, "native")) {
                        self.hardware.transport = .native;
                    } else if (std.mem.eql(u8, v.string, "serial")) {
                        self.hardware.transport = .serial;
                    } else if (std.mem.eql(u8, v.string, "probe")) {
                        self.hardware.transport = .probe;
                    }
                }
            }
        }
    }

    // Peripherals
    if (root.get("peripherals")) |per| {
        if (per == .object) {
            if (per.object.get("enabled")) |v| {
                if (v == .bool) self.peripherals.enabled = v.bool;
            }
            if (per.object.get("datasheet_dir")) |v| {
                if (v == .string) self.peripherals.datasheet_dir = try self.allocator.dupe(u8, v.string);
            }
        }
    }

    // Security
    if (root.get("security")) |sec| {
        if (sec == .object) {
            if (sec.object.get("sandbox")) |sb| {
                if (sb == .object) {
                    if (sb.object.get("enabled")) |v| {
                        if (v == .bool) self.security.sandbox.enabled = v.bool;
                    }
                    if (sb.object.get("backend")) |v| {
                        if (v == .string) {
                            if (std.mem.eql(u8, v.string, "auto")) {
                                self.security.sandbox.backend = .auto;
                            } else if (std.mem.eql(u8, v.string, "landlock")) {
                                self.security.sandbox.backend = .landlock;
                            } else if (std.mem.eql(u8, v.string, "firejail")) {
                                self.security.sandbox.backend = .firejail;
                            } else if (std.mem.eql(u8, v.string, "bubblewrap")) {
                                self.security.sandbox.backend = .bubblewrap;
                            } else if (std.mem.eql(u8, v.string, "docker")) {
                                self.security.sandbox.backend = .docker;
                            } else if (std.mem.eql(u8, v.string, "none")) {
                                self.security.sandbox.backend = .none;
                            }
                        }
                    }
                }
            }
            if (sec.object.get("resources")) |res| {
                if (res == .object) {
                    if (res.object.get("max_memory_mb")) |v| {
                        if (v == .integer) self.security.resources.max_memory_mb = @intCast(v.integer);
                    }
                    if (res.object.get("max_cpu_percent")) |v| {
                        if (v == .integer) self.security.resources.max_cpu_percent = @intCast(v.integer);
                    }
                    if (res.object.get("max_disk_mb")) |v| {
                        if (v == .integer) self.security.resources.max_disk_mb = @intCast(v.integer);
                    }
                    if (res.object.get("max_cpu_time_seconds")) |v| {
                        if (v == .integer) self.security.resources.max_cpu_time_seconds = @intCast(v.integer);
                    }
                    if (res.object.get("max_subprocesses")) |v| {
                        if (v == .integer) self.security.resources.max_subprocesses = @intCast(v.integer);
                    }
                    if (res.object.get("memory_monitoring")) |v| {
                        if (v == .bool) self.security.resources.memory_monitoring = v.bool;
                    }
                }
            }
            if (sec.object.get("audit")) |aud| {
                if (aud == .object) {
                    if (aud.object.get("enabled")) |v| {
                        if (v == .bool) self.security.audit.enabled = v.bool;
                    }
                    if (aud.object.get("log_path")) |v| {
                        if (v == .string) self.security.audit.log_path = try self.allocator.dupe(u8, v.string);
                    }
                    if (aud.object.get("retention_days")) |v| {
                        if (v == .integer) self.security.audit.retention_days = @intCast(v.integer);
                    }
                    if (aud.object.get("max_size_mb")) |v| {
                        if (v == .integer) self.security.audit.max_size_mb = @intCast(v.integer);
                    }
                    if (aud.object.get("sign_events")) |v| {
                        if (v == .bool) self.security.audit.sign_events = v.bool;
                    }
                }
            }
        }
    }

    // Tunnel
    if (root.get("tunnel")) |tun| {
        if (tun == .object) {
            if (tun.object.get("provider")) |v| {
                if (v == .string) self.tunnel.provider = try self.allocator.dupe(u8, v.string);
            }
        }
    }

    // models.providers (object-of-objects: {"models": {"providers": {"openrouter": {"api_key": "..."}, ...}}})
    if (root.get("models")) |models| {
        if (models == .object) {
            if (models.object.get("providers")) |prov| {
                if (prov == .object) {
                    var prov_list: std.ArrayListUnmanaged(types.ProviderEntry) = .empty;
                    var prov_it = prov.object.iterator();
                    while (prov_it.next()) |entry| {
                        const prov_name = entry.key_ptr.*;
                        const val = entry.value_ptr.*;
                        if (val != .object) continue;
                        var pe = types.ProviderEntry{
                            .name = try self.allocator.dupe(u8, prov_name),
                        };
                        if (val.object.get("api_key")) |ak| {
                            if (ak == .string) pe.api_key = try self.allocator.dupe(u8, ak.string);
                        }
                        if (val.object.get("base_url")) |ab| {
                            if (ab == .string) pe.base_url = try self.allocator.dupe(u8, ab.string);
                        }
                        // Accept "api_url" as an alias for "base_url" (fallback if base_url wasn't set)
                        if (pe.base_url == null) {
                            if (val.object.get("api_url")) |au| {
                                if (au == .string) pe.base_url = try self.allocator.dupe(u8, au.string);
                            }
                        }
                        if (val.object.get("native_tools")) |nt| {
                            if (nt == .bool) pe.native_tools = nt.bool;
                        }
                        try prov_list.append(self.allocator, pe);
                    }
                    self.providers = try prov_list.toOwnedSlice(self.allocator);
                }
            }
        }
    }

    // Channels
    if (root.get("channels")) |ch| {
        try parseChannels(self, ch);
    }

    // Session config
    if (root.get("session")) |sess| {
        if (sess == .object) {
            const dm_val = sess.object.get("dm_scope");
            if (dm_val) |v| {
                if (v == .string) {
                    const s = v.string;
                    // Accept both dash and underscore formats
                    if (std.mem.eql(u8, s, "main")) {
                        self.session.dm_scope = .main;
                    } else if (std.mem.eql(u8, s, "per_peer") or std.mem.eql(u8, s, "per-peer")) {
                        self.session.dm_scope = .per_peer;
                    } else if (std.mem.eql(u8, s, "per_channel_peer") or std.mem.eql(u8, s, "per-channel-peer")) {
                        self.session.dm_scope = .per_channel_peer;
                    } else if (std.mem.eql(u8, s, "per_account_channel_peer") or std.mem.eql(u8, s, "per-account-channel-peer")) {
                        self.session.dm_scope = .per_account_channel_peer;
                    }
                }
            }
            const idle_val = sess.object.get("idle_minutes");
            if (idle_val) |v| {
                if (v == .integer) self.session.idle_minutes = @intCast(v.integer);
            }
            const typing_val = sess.object.get("typing_interval_secs");
            if (typing_val) |v| {
                if (v == .integer) self.session.typing_interval_secs = @intCast(v.integer);
            }
            const links_val = sess.object.get("identity_links");
            if (links_val) |links| {
                var link_list: std.ArrayListUnmanaged(types.IdentityLink) = .empty;
                if (links == .array) {
                    // Array format: [{"canonical": "alice", "peers": ["telegram:111"]}]
                    for (links.array.items) |item| {
                        if (item != .object) continue;
                        const canonical = item.object.get("canonical") orelse continue;
                        if (canonical != .string) continue;
                        var link: types.IdentityLink = .{
                            .canonical = try self.allocator.dupe(u8, canonical.string),
                        };
                        if (item.object.get("peers")) |peers| {
                            if (peers == .array) {
                                link.peers = try parseStringArray(self.allocator, peers.array);
                            }
                        }
                        try link_list.append(self.allocator, link);
                    }
                } else if (links == .object) {
                    // Map format: {"alice": ["telegram:111", "discord:222"]}
                    var it = links.object.iterator();
                    while (it.next()) |entry| {
                        if (entry.key_ptr.*.len == 0) continue;
                        if (entry.value_ptr.* != .array) continue;
                        var link: types.IdentityLink = .{
                            .canonical = try self.allocator.dupe(u8, entry.key_ptr.*),
                        };
                        link.peers = try parseStringArray(self.allocator, entry.value_ptr.array);
                        try link_list.append(self.allocator, link);
                    }
                }
                self.session.identity_links = try link_list.toOwnedSlice(self.allocator);
            }
        }
    }
}
