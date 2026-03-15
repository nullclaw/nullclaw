const std = @import("std");
const Config = @import("../config.zig").Config;
const factory = @import("factory.zig");
const ProviderHolder = factory.ProviderHolder;
const Provider = @import("root.zig").Provider;
const reliable = @import("reliable.zig");
const router = @import("router.zig");
const api_key = @import("api_key.zig");

const HolderPlan = struct {
    name: []const u8,
    api_key: ?[]u8,
    base_url: ?[]const u8,
    native_tools: bool,
    user_agent: ?[]const u8,
};

fn trimOptionalKey(raw_key: ?[]const u8) ?[]const u8 {
    const key = raw_key orelse return null;
    const trimmed = std.mem.trim(u8, key, " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn routerProviderIndex(
    default_provider: []const u8,
    plans: []const HolderPlan,
    provider_name: []const u8,
) ?usize {
    if (std.mem.eql(u8, default_provider, provider_name)) return 0;
    for (plans, 0..) |plan, i| {
        if (std.mem.eql(u8, plan.name, provider_name)) return i + 1;
    }
    return null;
}

fn existingPlanKey(
    primary_key: ?[]const u8,
    plans: []const HolderPlan,
    provider_index: usize,
) ?[]const u8 {
    if (provider_index == 0) return primary_key;
    return plans[provider_index - 1].api_key;
}

fn keysMatch(existing_key: ?[]const u8, raw_override: ?[]const u8) bool {
    const override = trimOptionalKey(raw_override) orelse return true;
    if (existing_key) |key| return std.mem.eql(u8, key, override);
    return false;
}

fn appendHolderPlan(
    allocator: std.mem.Allocator,
    plans: *std.ArrayListUnmanaged(HolderPlan),
    cfg: *const Config,
    provider_name: []const u8,
    owned_key: ?[]u8,
) !usize {
    try plans.append(allocator, .{
        .name = provider_name,
        .api_key = owned_key,
        .base_url = cfg.getProviderBaseUrl(provider_name),
        .native_tools = cfg.getProviderNativeTools(provider_name),
        .user_agent = cfg.getProviderUserAgent(provider_name),
    });
    return plans.items.len;
}

/// Runtime provider wiring with optional reliability wrapper.
///
/// Owns:
/// - primary provider holder
/// - optional router-specific provider holders and router wrapper
/// - optional fallback provider holders
/// - optional ReliableProvider wrapper
/// - any resolved API keys allocated during provider resolution
pub const RuntimeProviderBundle = struct {
    allocator: std.mem.Allocator,

    primary_holder: ?*ProviderHolder = null,
    primary_key: ?[]u8 = null,

    router_ptr: ?*router.RouterProvider = null,
    router_provider_names: ?[][]const u8 = null,
    router_providers: ?[]Provider = null,
    router_holders: ?[]ProviderHolder = null,
    router_holders_initialized: usize = 0,
    router_keys: ?[]?[]u8 = null,

    extra_holders: ?[]ProviderHolder = null,
    extra_holders_initialized: usize = 0,
    extra_keys: ?[]?[]u8 = null,

    reliable_ptr: ?*reliable.ReliableProvider = null,
    reliable_entries: ?[]reliable.ProviderEntry = null,
    model_fallbacks: ?[]reliable.ModelFallbackEntry = null,

    pub fn init(allocator: std.mem.Allocator, cfg: *const Config) !RuntimeProviderBundle {
        var bundle = RuntimeProviderBundle{ .allocator = allocator };
        errdefer bundle.deinit();

        bundle.primary_key = api_key.resolveApiKeyFromConfig(
            allocator,
            cfg.default_provider,
            cfg.providers,
        ) catch null;

        const primary_holder = try allocator.create(ProviderHolder);
        bundle.primary_holder = primary_holder;
        primary_holder.* = ProviderHolder.fromConfig(
            allocator,
            cfg.default_provider,
            bundle.primary_key,
            cfg.getProviderBaseUrl(cfg.default_provider),
            cfg.getProviderNativeTools(cfg.default_provider),
            cfg.getProviderUserAgent(cfg.default_provider),
        );

        if (cfg.model_routes.len > 0) {
            var holder_plans: std.ArrayListUnmanaged(HolderPlan) = .empty;
            defer {
                for (holder_plans.items) |plan| {
                    if (plan.api_key) |key| allocator.free(key);
                }
                holder_plans.deinit(allocator);
            }

            var route_entries: std.ArrayListUnmanaged(router.RouterProvider.RouteEntry) = .empty;
            defer route_entries.deinit(allocator);

            for (cfg.providers) |provider_cfg| {
                if (std.mem.eql(u8, provider_cfg.name, cfg.default_provider)) continue;
                if (routerProviderIndex(cfg.default_provider, holder_plans.items, provider_cfg.name) != null) continue;

                const resolved_key = api_key.resolveApiKeyFromConfig(
                    allocator,
                    provider_cfg.name,
                    cfg.providers,
                ) catch null;
                errdefer if (resolved_key) |key| allocator.free(key);

                _ = try appendHolderPlan(
                    allocator,
                    &holder_plans,
                    cfg,
                    provider_cfg.name,
                    resolved_key,
                );
            }

            for (cfg.model_routes) |route_cfg| {
                var provider_index = routerProviderIndex(
                    cfg.default_provider,
                    holder_plans.items,
                    route_cfg.provider,
                );

                if (provider_index) |existing_index| {
                    if (!keysMatch(existingPlanKey(bundle.primary_key, holder_plans.items, existing_index), route_cfg.api_key)) {
                        const override_key = trimOptionalKey(route_cfg.api_key).?;
                        const key_copy = try allocator.dupe(u8, override_key);
                        errdefer allocator.free(key_copy);

                        provider_index = try appendHolderPlan(
                            allocator,
                            &holder_plans,
                            cfg,
                            route_cfg.provider,
                            key_copy,
                        );
                    }
                } else {
                    const resolved_key = if (trimOptionalKey(route_cfg.api_key)) |override_key|
                        try allocator.dupe(u8, override_key)
                    else
                        api_key.resolveApiKeyFromConfig(
                            allocator,
                            route_cfg.provider,
                            cfg.providers,
                        ) catch null;
                    errdefer if (resolved_key) |key| allocator.free(key);

                    provider_index = try appendHolderPlan(
                        allocator,
                        &holder_plans,
                        cfg,
                        route_cfg.provider,
                        resolved_key,
                    );
                }

                try route_entries.append(allocator, .{
                    .hint = route_cfg.hint,
                    .route = .{
                        .provider_name = route_cfg.provider,
                        .model = route_cfg.model,
                    },
                    .provider_index = provider_index,
                });
            }

            bundle.router_keys = try allocator.alloc(?[]u8, holder_plans.items.len);
            for (bundle.router_keys.?) |*key_slot| key_slot.* = null;

            if (holder_plans.items.len > 0) {
                bundle.router_holders = try allocator.alloc(ProviderHolder, holder_plans.items.len);
                for (holder_plans.items, 0..) |*plan, i| {
                    bundle.router_keys.?[i] = plan.api_key;
                    plan.api_key = null;
                    bundle.router_holders.?[i] = ProviderHolder.fromConfig(
                        allocator,
                        plan.name,
                        bundle.router_keys.?[i],
                        plan.base_url,
                        plan.native_tools,
                        plan.user_agent,
                    );
                    bundle.router_holders_initialized = i + 1;
                }
            }

            const router_provider_count = holder_plans.items.len + 1;
            bundle.router_provider_names = try allocator.alloc([]const u8, router_provider_count);
            bundle.router_providers = try allocator.alloc(Provider, router_provider_count);
            bundle.router_provider_names.?[0] = cfg.default_provider;
            bundle.router_providers.?[0] = primary_holder.provider();

            for (holder_plans.items, 0..) |plan, i| {
                bundle.router_provider_names.?[i + 1] = plan.name;
                bundle.router_providers.?[i + 1] = bundle.router_holders.?[i].provider();
            }

            const router_ptr = try allocator.create(router.RouterProvider);
            router_ptr.* = try router.RouterProvider.init(
                allocator,
                bundle.router_provider_names.?,
                bundle.router_providers.?,
                route_entries.items,
                cfg.default_model orelse "",
            );
            bundle.router_ptr = router_ptr;
        }

        const allows_key_rotation = factory.classifyProvider(cfg.default_provider) != .openai_codex_provider;
        var rotating_key_count: usize = 0;
        if (allows_key_rotation) {
            for (cfg.reliability.api_keys) |raw_key| {
                const trimmed = std.mem.trim(u8, raw_key, " \t\r\n");
                if (trimmed.len == 0) continue;
                if (bundle.primary_key) |primary_key| {
                    if (std.mem.eql(u8, primary_key, trimmed)) continue;
                }
                rotating_key_count += 1;
            }
        }

        const extra_count = cfg.reliability.fallback_providers.len + rotating_key_count;
        const need_reliable =
            cfg.reliability.provider_retries > 0 or
            cfg.reliability.model_fallbacks.len > 0 or
            extra_count > 0;

        if (!need_reliable) return bundle;

        if (extra_count > 0) {
            bundle.extra_keys = try allocator.alloc(?[]u8, extra_count);
            for (bundle.extra_keys.?) |*key_slot| key_slot.* = null;
            bundle.extra_holders = try allocator.alloc(ProviderHolder, extra_count);
            bundle.reliable_entries = try allocator.alloc(reliable.ProviderEntry, extra_count);

            var extra_i: usize = 0;

            for (cfg.reliability.fallback_providers) |provider_name| {
                const fb_key = api_key.resolveApiKeyFromConfig(
                    allocator,
                    provider_name,
                    cfg.providers,
                ) catch null;
                bundle.extra_keys.?[extra_i] = fb_key;
                bundle.extra_holders.?[extra_i] = ProviderHolder.fromConfig(
                    allocator,
                    provider_name,
                    fb_key,
                    cfg.getProviderBaseUrl(provider_name),
                    cfg.getProviderNativeTools(provider_name),
                    cfg.getProviderUserAgent(provider_name),
                );
                bundle.extra_holders_initialized = extra_i + 1;
                bundle.reliable_entries.?[extra_i] = .{
                    .name = provider_name,
                    .provider = bundle.extra_holders.?[extra_i].provider(),
                };
                extra_i += 1;
            }

            if (allows_key_rotation) {
                for (cfg.reliability.api_keys) |raw_key| {
                    const trimmed = std.mem.trim(u8, raw_key, " \t\r\n");
                    if (trimmed.len == 0) continue;
                    if (bundle.primary_key) |primary_key| {
                        if (std.mem.eql(u8, primary_key, trimmed)) continue;
                    }

                    const key_copy = try allocator.dupe(u8, trimmed);
                    bundle.extra_keys.?[extra_i] = key_copy;
                    bundle.extra_holders.?[extra_i] = ProviderHolder.fromConfig(
                        allocator,
                        cfg.default_provider,
                        key_copy,
                        cfg.getProviderBaseUrl(cfg.default_provider),
                        cfg.getProviderNativeTools(cfg.default_provider),
                        cfg.getProviderUserAgent(cfg.default_provider),
                    );
                    bundle.extra_holders_initialized = extra_i + 1;
                    bundle.reliable_entries.?[extra_i] = .{
                        .name = cfg.default_provider,
                        .provider = bundle.extra_holders.?[extra_i].provider(),
                    };
                    extra_i += 1;
                }
            }

            std.debug.assert(extra_i == extra_count);
        }

        if (cfg.reliability.model_fallbacks.len > 0) {
            bundle.model_fallbacks = try allocator.alloc(
                reliable.ModelFallbackEntry,
                cfg.reliability.model_fallbacks.len,
            );
            for (cfg.reliability.model_fallbacks, 0..) |entry, i| {
                bundle.model_fallbacks.?[i] = .{
                    .model = entry.model,
                    .fallbacks = entry.fallbacks,
                };
            }
        }

        const reliable_ptr = try allocator.create(reliable.ReliableProvider);
        var reliable_impl = reliable.ReliableProvider.initWithProvider(
            bundle.provider(),
            cfg.reliability.provider_retries,
            cfg.reliability.provider_backoff_ms,
        );

        if (bundle.reliable_entries) |entries| {
            reliable_impl = reliable_impl.withExtras(entries);
        }
        if (bundle.model_fallbacks) |model_fallbacks| {
            reliable_impl = reliable_impl.withModelFallbacks(model_fallbacks);
        }

        reliable_ptr.* = reliable_impl;
        bundle.reliable_ptr = reliable_ptr;

        return bundle;
    }

    pub fn provider(self: *const RuntimeProviderBundle) Provider {
        if (self.reliable_ptr) |rp| return rp.provider();
        if (self.router_ptr) |router_ptr| return router_ptr.provider();
        return self.primary_holder.?.provider();
    }

    pub fn primaryApiKey(self: *const RuntimeProviderBundle) ?[]const u8 {
        return self.primary_key;
    }

    pub fn deinit(self: *RuntimeProviderBundle) void {
        const had_reliable = self.reliable_ptr != null;
        const had_router = self.router_ptr != null;

        if (self.reliable_ptr) |rp| {
            rp.provider().deinit();
            self.allocator.destroy(rp);
            self.reliable_ptr = null;
        } else if (self.router_ptr) |router_ptr| {
            router_ptr.provider().deinit();
            self.allocator.destroy(router_ptr);
            self.router_ptr = null;
        } else if (self.primary_holder) |holder| {
            holder.deinit();
        }

        if (self.model_fallbacks) |fallbacks| {
            self.allocator.free(fallbacks);
            self.model_fallbacks = null;
        }
        if (self.reliable_entries) |entries| {
            self.allocator.free(entries);
            self.reliable_entries = null;
        }

        if (self.router_providers) |providers| {
            self.allocator.free(providers);
            self.router_providers = null;
        }
        if (self.router_provider_names) |names| {
            self.allocator.free(names);
            self.router_provider_names = null;
        }
        if (self.router_holders) |holders| {
            const init_len = @min(self.router_holders_initialized, holders.len);
            for (holders[0..init_len]) |*holder| holder.deinit();
            self.allocator.free(holders);
            self.router_holders = null;
            self.router_holders_initialized = 0;
        }
        if (self.router_keys) |keys| {
            for (keys) |maybe_key| {
                if (maybe_key) |key| self.allocator.free(key);
            }
            self.allocator.free(keys);
            self.router_keys = null;
        }
        if (self.router_ptr) |router_ptr| {
            self.allocator.destroy(router_ptr);
            self.router_ptr = null;
        }

        if (self.extra_holders) |holders| {
            if (!had_reliable) {
                const init_len = @min(self.extra_holders_initialized, holders.len);
                for (holders[0..init_len]) |*holder| holder.deinit();
            }
            self.allocator.free(holders);
            self.extra_holders = null;
            self.extra_holders_initialized = 0;
        }
        if (self.extra_keys) |keys| {
            for (keys) |maybe_key| {
                if (maybe_key) |key| self.allocator.free(key);
            }
            self.allocator.free(keys);
            self.extra_keys = null;
        }

        if (self.primary_holder) |holder| {
            if (!had_reliable or had_router) {
                holder.deinit();
            }
            self.allocator.destroy(holder);
            self.primary_holder = null;
        }
        if (self.primary_key) |key| {
            self.allocator.free(key);
            self.primary_key = null;
        }
    }
};

test "RuntimeProviderBundle init/deinit without reliability wrapper" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 0;
    cfg.reliability.provider_backoff_ms = 50;

    var bundle = try RuntimeProviderBundle.init(std.testing.allocator, &cfg);
    defer bundle.deinit();

    _ = bundle.provider();
}

test "RuntimeProviderBundle init/deinit with fallback providers and model fallbacks" {
    const fb_models = [_][]const u8{
        "openrouter/anthropic/claude-sonnet-4",
    };
    const model_fallbacks = [_]@import("../config.zig").ModelFallbackEntry{
        .{
            .model = "gpt-5.3-codex",
            .fallbacks = &fb_models,
        },
    };

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .default_provider = "openai-codex",
        .default_model = "gpt-5.3-codex",
    };
    cfg.reliability.provider_retries = 1;
    cfg.reliability.provider_backoff_ms = 100;
    cfg.reliability.fallback_providers = &.{"openrouter"};
    cfg.reliability.model_fallbacks = &model_fallbacks;

    var bundle = try RuntimeProviderBundle.init(std.testing.allocator, &cfg);
    defer bundle.deinit();

    _ = bundle.provider();
}

test "RuntimeProviderBundle turns reliability api_keys into fallback providers" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .default_provider = "openrouter",
        .providers = &.{
            .{ .name = "openrouter", .api_key = "primary-key" },
        },
    };
    cfg.reliability.provider_retries = 1;
    cfg.reliability.api_keys = &.{ " primary-key ", "key-b", "", "  key-c  " };

    var bundle = try RuntimeProviderBundle.init(std.testing.allocator, &cfg);
    defer bundle.deinit();

    try std.testing.expect(bundle.reliable_entries != null);
    try std.testing.expectEqual(@as(usize, 2), bundle.reliable_entries.?.len);
    try std.testing.expect(bundle.extra_keys != null);
    try std.testing.expectEqualStrings("key-b", bundle.extra_keys.?[0].?);
    try std.testing.expectEqualStrings("key-c", bundle.extra_keys.?[1].?);
}

test "RuntimeProviderBundle builds router-backed provider when model routes are configured" {
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .default_provider = "openrouter",
        .default_model = "hint:fast",
        .providers = &.{
            .{ .name = "groq", .api_key = "gsk_test" },
        },
        .model_routes = &.{
            .{ .hint = "fast", .provider = "groq", .model = "llama-3.3-70b" },
        },
    };

    var bundle = try RuntimeProviderBundle.init(std.testing.allocator, &cfg);
    defer bundle.deinit();

    try std.testing.expect(bundle.router_ptr != null);
    try std.testing.expectEqualStrings("router", bundle.provider().getName());
    try std.testing.expect(bundle.router_provider_names != null);
    try std.testing.expectEqual(@as(usize, 2), bundle.router_provider_names.?.len);
    try std.testing.expectEqualStrings("openrouter", bundle.router_provider_names.?[0]);
    try std.testing.expectEqualStrings("groq", bundle.router_provider_names.?[1]);
}
