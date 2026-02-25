const std = @import("std");
const Config = @import("../config.zig").Config;
const factory = @import("factory.zig");
const ProviderHolder = factory.ProviderHolder;
const reliable = @import("reliable.zig");
const api_key = @import("api_key.zig");

/// Runtime provider wiring with optional reliability wrapper.
///
/// Owns:
/// - primary provider holder
/// - optional fallback provider holders
/// - optional ReliableProvider wrapper
/// - any resolved API keys allocated during provider resolution
pub const RuntimeProviderBundle = struct {
    allocator: std.mem.Allocator,

    primary_holder: ?*ProviderHolder = null,
    primary_key: ?[]u8 = null,

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
        );

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

    pub fn provider(self: *const RuntimeProviderBundle) @TypeOf(self.primary_holder.?.provider()) {
        if (self.reliable_ptr) |rp| return rp.provider();
        return self.primary_holder.?.provider();
    }

    pub fn primaryApiKey(self: *const RuntimeProviderBundle) ?[]const u8 {
        return self.primary_key;
    }

    pub fn deinit(self: *RuntimeProviderBundle) void {
        const had_reliable = self.reliable_ptr != null;

        if (self.reliable_ptr) |rp| {
            rp.provider().deinit();
            self.allocator.destroy(rp);
            self.reliable_ptr = null;
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
