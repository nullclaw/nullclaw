const std = @import("std");
const types = @import("config_types.zig");

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

/// Parse JSON content into the given Config.
pub fn parseJson(self: *Config, content: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, content, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    // Top-level fields
    if (root.get("default_provider")) |v| {
        if (v == .string) self.default_provider = try self.allocator.dupe(u8, v.string);
    }
    // default_model parsed below from agents.defaults.model.primary
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

    // Agents section: agents.defaults.model.primary + agents.defaults.heartbeat + agents.list[]
    if (root.get("agents")) |agents_val| {
        if (agents_val == .object) {
            // agents.defaults.model.primary → self.default_model
            // agents.defaults.heartbeat → self.heartbeat
            if (agents_val.object.get("defaults")) |defaults| {
                if (defaults == .object) {
                    if (defaults.object.get("model")) |mdl| {
                        if (mdl == .object) {
                            if (mdl.object.get("primary")) |v| {
                                if (v == .string) self.default_model = try self.allocator.dupe(u8, v.string);
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
                                            if (v == .string) self.audio_media.language = try self.allocator.dupe(u8, v.string);
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
            if (mem.object.get("backend")) |v| {
                if (v == .string) self.memory.backend = try self.allocator.dupe(u8, v.string);
            }
            if (mem.object.get("auto_save")) |v| {
                if (v == .bool) self.memory.auto_save = v.bool;
            }
            if (mem.object.get("hygiene_enabled")) |v| {
                if (v == .bool) self.memory.hygiene_enabled = v.bool;
            }
            if (mem.object.get("archive_after_days")) |v| {
                if (v == .integer) self.memory.archive_after_days = @intCast(v.integer);
            }
            if (mem.object.get("purge_after_days")) |v| {
                if (v == .integer) self.memory.purge_after_days = @intCast(v.integer);
            }
            if (mem.object.get("conversation_retention_days")) |v| {
                if (v == .integer) self.memory.conversation_retention_days = @intCast(v.integer);
            }
            if (mem.object.get("embedding_provider")) |v| {
                if (v == .string) self.memory.embedding_provider = try self.allocator.dupe(u8, v.string);
            }
            if (mem.object.get("embedding_model")) |v| {
                if (v == .string) self.memory.embedding_model = try self.allocator.dupe(u8, v.string);
            }
            if (mem.object.get("embedding_dimensions")) |v| {
                if (v == .integer) self.memory.embedding_dimensions = @intCast(v.integer);
            }
            if (mem.object.get("vector_weight")) |v| {
                if (v == .float) self.memory.vector_weight = v.float;
            }
            if (mem.object.get("keyword_weight")) |v| {
                if (v == .float) self.memory.keyword_weight = v.float;
            }
            if (mem.object.get("embedding_cache_size")) |v| {
                if (v == .integer) self.memory.embedding_cache_size = @intCast(v.integer);
            }
            if (mem.object.get("chunk_max_tokens")) |v| {
                if (v == .integer) self.memory.chunk_max_tokens = @intCast(v.integer);
            }
            if (mem.object.get("response_cache_enabled")) |v| {
                if (v == .bool) self.memory.response_cache_enabled = v.bool;
            }
            if (mem.object.get("response_cache_ttl_minutes")) |v| {
                if (v == .integer) self.memory.response_cache_ttl_minutes = @intCast(v.integer);
            }
            if (mem.object.get("response_cache_max_entries")) |v| {
                if (v == .integer) self.memory.response_cache_max_entries = @intCast(v.integer);
            }
            if (mem.object.get("snapshot_enabled")) |v| {
                if (v == .bool) self.memory.snapshot_enabled = v.bool;
            }
            if (mem.object.get("snapshot_on_hygiene")) |v| {
                if (v == .bool) self.memory.snapshot_on_hygiene = v.bool;
            }
            if (mem.object.get("auto_hydrate")) |v| {
                if (v == .bool) self.memory.auto_hydrate = v.bool;
            }
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
                        try prov_list.append(self.allocator, pe);
                    }
                    self.providers = try prov_list.toOwnedSlice(self.allocator);
                }
            }
        }
    }

    // Channels (with accounts wrapper: channels.<type>.accounts.<id>.{fields})
    if (root.get("channels")) |ch| {
        if (ch == .object) {
            if (ch.object.get("cli")) |v| {
                if (v == .bool) self.channels.cli = v.bool;
            }

            // Helper: get first account object from accounts wrapper
            const getFirstAccount = struct {
                fn call(obj: std.json.ObjectMap) ?std.json.ObjectMap {
                    const accts = obj.get("accounts") orelse return null;
                    if (accts != .object) return null;
                    var it = accts.object.iterator();
                    const first = it.next() orelse return null;
                    if (first.value_ptr.* != .object) return null;
                    if (it.next() != null) {
                        std.log.warn("Multiple accounts configured; only first account used", .{});
                    }
                    return first.value_ptr.object;
                }
            }.call;

            // Telegram
            if (ch.object.get("telegram")) |tg| {
                if (tg == .object) {
                    if (getFirstAccount(tg.object)) |acc| {
                        if (acc.get("bot_token")) |tok| {
                            if (tok == .string) {
                                self.channels.telegram = .{ .bot_token = try self.allocator.dupe(u8, tok.string) };
                            }
                        }
                        if (self.channels.telegram) |*tg_cfg| {
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) tg_cfg.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("reply_in_private")) |v| {
                                if (v == .bool) tg_cfg.reply_in_private = v.bool;
                            }
                            if (acc.get("proxy")) |v| {
                                if (v == .string) tg_cfg.proxy = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("group_allow_from")) |v| {
                                if (v == .array) tg_cfg.group_allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("group_policy")) |v| {
                                if (v == .string) tg_cfg.group_policy = try self.allocator.dupe(u8, v.string);
                            }
                        }
                    }
                }
            }

            // Discord
            if (ch.object.get("discord")) |disc| {
                if (disc == .object) {
                    if (getFirstAccount(disc.object)) |acc| {
                        if (acc.get("token")) |tok| {
                            if (tok == .string) {
                                self.channels.discord = .{ .token = try self.allocator.dupe(u8, tok.string) };
                            }
                        }
                        if (self.channels.discord) |*dc| {
                            if (acc.get("guild_id")) |v| {
                                if (v == .string) dc.guild_id = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) dc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("allow_bots")) |v| {
                                if (v == .bool) dc.allow_bots = v.bool;
                            }
                            if (acc.get("require_mention")) |v| {
                                if (v == .bool) dc.require_mention = v.bool;
                            }
                            if (acc.get("mention_only")) |v| {
                                if (v == .bool) dc.require_mention = v.bool;
                            }
                            if (acc.get("intents")) |v| {
                                if (v == .integer) dc.intents = @intCast(v.integer);
                            }
                        }
                    }
                }
            }

            // Slack
            if (ch.object.get("slack")) |sl| {
                if (sl == .object) {
                    if (getFirstAccount(sl.object)) |acc| {
                        if (acc.get("bot_token")) |tok| {
                            if (tok == .string) {
                                self.channels.slack = .{ .bot_token = try self.allocator.dupe(u8, tok.string) };
                            }
                        }
                        if (self.channels.slack) |*sc| {
                            if (acc.get("app_token")) |v| {
                                if (v == .string) sc.app_token = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("channel_id")) |v| {
                                if (v == .string) sc.channel_id = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) sc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("dm_policy")) |v| {
                                if (v == .string) sc.dm_policy = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("group_policy")) |v| {
                                if (v == .string) sc.group_policy = try self.allocator.dupe(u8, v.string);
                            }
                        }
                    }
                }
            }

            // IRC
            if (ch.object.get("irc")) |irc| {
                if (irc == .object) {
                    if (getFirstAccount(irc.object)) |acc| irc_blk: {
                        const host = acc.get("host") orelse break :irc_blk;
                        const nick = acc.get("nick") orelse break :irc_blk;
                        if (host != .string or nick != .string) break :irc_blk;
                        self.channels.irc = .{
                            .host = try self.allocator.dupe(u8, host.string),
                            .nick = try self.allocator.dupe(u8, nick.string),
                        };
                        if (self.channels.irc) |*ic| {
                            if (acc.get("port")) |v| {
                                if (v == .integer) ic.port = @intCast(v.integer);
                            }
                            if (acc.get("username")) |v| {
                                if (v == .string) ic.username = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("channels")) |v| {
                                if (v == .array) ic.channels = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) ic.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("server_password")) |v| {
                                if (v == .string) ic.server_password = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("nickserv_password")) |v| {
                                if (v == .string) ic.nickserv_password = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("sasl_password")) |v| {
                                if (v == .string) ic.sasl_password = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("tls")) |v| {
                                if (v == .bool) ic.tls = v.bool;
                            }
                        }
                    }
                }
            }

            // Matrix
            if (ch.object.get("matrix")) |mx| {
                if (mx == .object) {
                    if (getFirstAccount(mx.object)) |acc| mx_blk: {
                        const hs = acc.get("homeserver") orelse break :mx_blk;
                        const at = acc.get("access_token") orelse break :mx_blk;
                        const rid = acc.get("room_id") orelse break :mx_blk;
                        if (hs != .string or at != .string or rid != .string) break :mx_blk;
                        self.channels.matrix = .{
                            .homeserver = try self.allocator.dupe(u8, hs.string),
                            .access_token = try self.allocator.dupe(u8, at.string),
                            .room_id = try self.allocator.dupe(u8, rid.string),
                        };
                        if (self.channels.matrix) |*mc| {
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) mc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                        }
                    }
                }
            }

            // WhatsApp
            if (ch.object.get("whatsapp")) |wa| {
                if (wa == .object) {
                    if (getFirstAccount(wa.object)) |acc| wa_blk: {
                        const at = acc.get("access_token") orelse break :wa_blk;
                        const pni = acc.get("phone_number_id") orelse break :wa_blk;
                        const vt = acc.get("verify_token") orelse break :wa_blk;
                        if (at != .string or pni != .string or vt != .string) break :wa_blk;
                        self.channels.whatsapp = .{
                            .access_token = try self.allocator.dupe(u8, at.string),
                            .phone_number_id = try self.allocator.dupe(u8, pni.string),
                            .verify_token = try self.allocator.dupe(u8, vt.string),
                        };
                        if (self.channels.whatsapp) |*wc| {
                            if (acc.get("app_secret")) |v| {
                                if (v == .string) wc.app_secret = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) wc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("group_allow_from")) |v| {
                                if (v == .array) wc.group_allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("group_policy")) |v| {
                                if (v == .string) wc.group_policy = try self.allocator.dupe(u8, v.string);
                            }
                        }
                    }
                }
            }

            // iMessage (no accounts wrapper — simple struct)
            if (ch.object.get("imessage")) |im| {
                if (im == .object) {
                    self.channels.imessage = .{};
                    if (self.channels.imessage) |*ic| {
                        if (im.object.get("enabled")) |v| {
                            if (v == .bool) ic.enabled = v.bool;
                        }
                        if (im.object.get("allow_from")) |v| {
                            if (v == .array) ic.allow_from = try parseStringArray(self.allocator, v.array);
                        }
                        if (im.object.get("group_allow_from")) |v| {
                            if (v == .array) ic.group_allow_from = try parseStringArray(self.allocator, v.array);
                        }
                        if (im.object.get("group_policy")) |v| {
                            if (v == .string) ic.group_policy = try self.allocator.dupe(u8, v.string);
                        }
                    }
                }
            }

            // Lark
            if (ch.object.get("lark")) |lk| {
                if (lk == .object) {
                    if (getFirstAccount(lk.object)) |acc| lk_blk: {
                        const aid = acc.get("app_id") orelse break :lk_blk;
                        const asec = acc.get("app_secret") orelse break :lk_blk;
                        if (aid != .string or asec != .string) break :lk_blk;
                        self.channels.lark = .{
                            .app_id = try self.allocator.dupe(u8, aid.string),
                            .app_secret = try self.allocator.dupe(u8, asec.string),
                        };
                        if (self.channels.lark) |*lc| {
                            if (acc.get("encrypt_key")) |v| {
                                if (v == .string) lc.encrypt_key = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("verification_token")) |v| {
                                if (v == .string) lc.verification_token = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("use_feishu")) |v| {
                                if (v == .bool) lc.use_feishu = v.bool;
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) lc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("receive_mode")) |v| {
                                if (v == .string) {
                                    if (std.mem.eql(u8, v.string, "webhook")) lc.receive_mode = .webhook;
                                }
                            }
                            if (acc.get("port")) |v| {
                                if (v == .integer) lc.port = @intCast(v.integer);
                            }
                        }
                    }
                }
            }

            // DingTalk
            if (ch.object.get("dingtalk")) |dt| {
                if (dt == .object) {
                    if (getFirstAccount(dt.object)) |acc| dt_blk: {
                        const cid = acc.get("client_id") orelse break :dt_blk;
                        const csec = acc.get("client_secret") orelse break :dt_blk;
                        if (cid != .string or csec != .string) break :dt_blk;
                        self.channels.dingtalk = .{
                            .client_id = try self.allocator.dupe(u8, cid.string),
                            .client_secret = try self.allocator.dupe(u8, csec.string),
                        };
                        if (self.channels.dingtalk) |*dc| {
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) dc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                        }
                    }
                }
            }

            // Signal
            if (ch.object.get("signal")) |sg| {
                if (sg == .object) {
                    if (getFirstAccount(sg.object)) |acc| sg_blk: {
                        const url = acc.get("http_url") orelse break :sg_blk;
                        const acct = acc.get("account") orelse break :sg_blk;
                        if (url != .string or acct != .string) break :sg_blk;
                        self.channels.signal = .{
                            .http_url = try self.allocator.dupe(u8, url.string),
                            .account = try self.allocator.dupe(u8, acct.string),
                        };
                        if (self.channels.signal) |*sc| {
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) sc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("group_allow_from")) |v| {
                                if (v == .array) sc.group_allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("ignore_attachments")) |v| {
                                if (v == .bool) sc.ignore_attachments = v.bool;
                            }
                            if (acc.get("ignore_stories")) |v| {
                                if (v == .bool) sc.ignore_stories = v.bool;
                            }
                        }
                    }
                }
            }

            // Webhook (no accounts wrapper)
            if (ch.object.get("webhook")) |wh| {
                if (wh == .object) {
                    self.channels.webhook = .{};
                    if (self.channels.webhook) |*wc| {
                        if (wh.object.get("port")) |v| {
                            if (v == .integer) wc.port = @intCast(v.integer);
                        }
                        if (wh.object.get("secret")) |v| {
                            if (v == .string) wc.secret = try self.allocator.dupe(u8, v.string);
                        }
                    }
                }
            }

            // Email
            if (ch.object.get("email")) |em| {
                if (em == .object) {
                    if (getFirstAccount(em.object)) |acc| {
                        self.channels.email = .{};
                        if (self.channels.email) |*ec| {
                            if (acc.get("imap_host")) |v| {
                                if (v == .string) ec.imap_host = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("imap_port")) |v| {
                                if (v == .integer) ec.imap_port = @intCast(v.integer);
                            }
                            if (acc.get("imap_folder")) |v| {
                                if (v == .string) ec.imap_folder = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("smtp_host")) |v| {
                                if (v == .string) ec.smtp_host = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("smtp_port")) |v| {
                                if (v == .integer) ec.smtp_port = @intCast(v.integer);
                            }
                            if (acc.get("smtp_tls")) |v| {
                                if (v == .bool) ec.smtp_tls = v.bool;
                            }
                            if (acc.get("username")) |v| {
                                if (v == .string) ec.username = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("password")) |v| {
                                if (v == .string) ec.password = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("from_address")) |v| {
                                if (v == .string) ec.from_address = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("poll_interval_secs")) |v| {
                                if (v == .integer) ec.poll_interval_secs = @intCast(v.integer);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) ec.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("consent_granted")) |v| {
                                if (v == .bool) ec.consent_granted = v.bool;
                            }
                        }
                    }
                }
            }

            // Line
            if (ch.object.get("line")) |ln| {
                if (ln == .object) {
                    if (getFirstAccount(ln.object)) |acc| ln_blk: {
                        const at = acc.get("access_token") orelse break :ln_blk;
                        const cs = acc.get("channel_secret") orelse break :ln_blk;
                        if (at != .string or cs != .string) break :ln_blk;
                        self.channels.line = .{
                            .access_token = try self.allocator.dupe(u8, at.string),
                            .channel_secret = try self.allocator.dupe(u8, cs.string),
                        };
                        if (self.channels.line) |*lc| {
                            if (acc.get("port")) |v| {
                                if (v == .integer) lc.port = @intCast(v.integer);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) lc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                        }
                    }
                }
            }

            // QQ
            if (ch.object.get("qq")) |qq| {
                if (qq == .object) {
                    if (getFirstAccount(qq.object)) |acc| {
                        self.channels.qq = .{};
                        if (self.channels.qq) |*qc| {
                            if (acc.get("app_id")) |v| {
                                if (v == .string) qc.app_id = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("app_secret")) |v| {
                                if (v == .string) qc.app_secret = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("bot_token")) |v| {
                                if (v == .string) qc.bot_token = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("sandbox")) |v| {
                                if (v == .bool) qc.sandbox = v.bool;
                            }
                            if (acc.get("group_policy")) |v| {
                                if (v == .string) {
                                    if (std.mem.eql(u8, v.string, "allowlist")) qc.group_policy = .allowlist;
                                }
                            }
                            if (acc.get("group_allow_from")) |v| {
                                if (v == .array) qc.group_allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) qc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                        }
                    }
                }
            }

            // OneBot
            if (ch.object.get("onebot")) |ob| {
                if (ob == .object) {
                    if (getFirstAccount(ob.object)) |acc| {
                        self.channels.onebot = .{};
                        if (self.channels.onebot) |*oc| {
                            if (acc.get("url")) |v| {
                                if (v == .string) oc.url = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("access_token")) |v| {
                                if (v == .string) oc.access_token = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("group_trigger_prefix")) |v| {
                                if (v == .string) oc.group_trigger_prefix = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) oc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                        }
                    }
                }
            }

            // MaixCam
            if (ch.object.get("maixcam")) |mx| {
                if (mx == .object) {
                    if (getFirstAccount(mx.object)) |acc| {
                        self.channels.maixcam = .{};
                        if (self.channels.maixcam) |*mc| {
                            if (acc.get("port")) |v| {
                                if (v == .integer) mc.port = @intCast(v.integer);
                            }
                            if (acc.get("host")) |v| {
                                if (v == .string) mc.host = try self.allocator.dupe(u8, v.string);
                            }
                            if (acc.get("allow_from")) |v| {
                                if (v == .array) mc.allow_from = try parseStringArray(self.allocator, v.array);
                            }
                            if (acc.get("name")) |v| {
                                if (v == .string) mc.name = try self.allocator.dupe(u8, v.string);
                            }
                        }
                    }
                }
            }
        }
    }
}
