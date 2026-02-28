const std = @import("std");
const builtin = @import("builtin");

const VendoredFileHash = struct {
    path: []const u8,
    sha256_hex: []const u8,
};

const VENDORED_SQLITE_HASHES = [_]VendoredFileHash{
    .{
        .path = "vendor/sqlite3/sqlite3.c",
        .sha256_hex = "dc58f0b5b74e8416cc29b49163a00d6b8bf08a24dd4127652beaaae307bd1839",
    },
    .{
        .path = "vendor/sqlite3/sqlite3.h",
        .sha256_hex = "05c48cbf0a0d7bda2b6d0145ac4f2d3a5e9e1cb98b5d4fa9d88ef620e1940046",
    },
    .{
        .path = "vendor/sqlite3/sqlite3ext.h",
        .sha256_hex = "ea81fb7bd05882e0e0b92c4d60f677b205f7f1fbf085f218b12f0b5b3f0b9e48",
    },
};

fn hashWithCanonicalLineEndings(bytes: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk_start: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == '\r' and i + 1 < bytes.len and bytes[i + 1] == '\n') {
            if (i > chunk_start) hasher.update(bytes[chunk_start..i]);
            hasher.update("\n");
            i += 1;
            chunk_start = i + 1;
        }
    }
    if (chunk_start < bytes.len) hasher.update(bytes[chunk_start..]);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn verifyVendoredSqliteHashes(b: *std.Build) !void {
    const max_vendor_file_size = 16 * 1024 * 1024;
    for (VENDORED_SQLITE_HASHES) |entry| {
        const file_path = b.pathFromRoot(entry.path);
        defer b.allocator.free(file_path);

        const bytes = std.fs.cwd().readFileAlloc(b.allocator, file_path, max_vendor_file_size) catch |err| {
            std.log.err("failed to read {s}: {s}", .{ file_path, @errorName(err) });
            return err;
        };
        defer b.allocator.free(bytes);

        const digest = hashWithCanonicalLineEndings(bytes);

        const actual_hex_buf = std.fmt.bytesToHex(digest, .lower);
        const actual_hex = actual_hex_buf[0..];

        if (!std.mem.eql(u8, actual_hex, entry.sha256_hex)) {
            std.log.err("vendored sqlite checksum mismatch for {s}", .{entry.path});
            std.log.err("expected: {s}", .{entry.sha256_hex});
            std.log.err("actual:   {s}", .{actual_hex});
            return error.VendoredSqliteChecksumMismatch;
        }
    }
}

const ChannelSelection = struct {
    enable_channel_cli: bool = false,
    enable_channel_telegram: bool = false,
    enable_channel_discord: bool = false,
    enable_channel_slack: bool = false,
    enable_channel_whatsapp: bool = false,
    enable_channel_matrix: bool = false,
    enable_channel_mattermost: bool = false,
    enable_channel_irc: bool = false,
    enable_channel_imessage: bool = false,
    enable_channel_email: bool = false,
    enable_channel_lark: bool = false,
    enable_channel_dingtalk: bool = false,
    enable_channel_line: bool = false,
    enable_channel_onebot: bool = false,
    enable_channel_qq: bool = false,
    enable_channel_maixcam: bool = false,
    enable_channel_signal: bool = false,

    fn enableAll(self: *ChannelSelection) void {
        self.enable_channel_cli = true;
        self.enable_channel_telegram = true;
        self.enable_channel_discord = true;
        self.enable_channel_slack = true;
        self.enable_channel_whatsapp = true;
        self.enable_channel_matrix = true;
        self.enable_channel_mattermost = true;
        self.enable_channel_irc = true;
        self.enable_channel_imessage = true;
        self.enable_channel_email = true;
        self.enable_channel_lark = true;
        self.enable_channel_dingtalk = true;
        self.enable_channel_line = true;
        self.enable_channel_onebot = true;
        self.enable_channel_qq = true;
        self.enable_channel_maixcam = true;
        self.enable_channel_signal = true;
    }
};

fn defaultChannels() ChannelSelection {
    var selection = ChannelSelection{};
    selection.enableAll();
    return selection;
}

fn parseChannelsOption(raw: []const u8) !ChannelSelection {
    var selection = ChannelSelection{};
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        std.log.err("empty -Dchannels list; use e.g. -Dchannels=all or -Dchannels=telegram,slack", .{});
        return error.InvalidChannelsOption;
    }

    var saw_token = false;
    var saw_all = false;
    var saw_none = false;

    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t\r\n");
        if (token.len == 0) continue;
        saw_token = true;

        if (std.mem.eql(u8, token, "all")) {
            saw_all = true;
            selection.enableAll();
        } else if (std.mem.eql(u8, token, "none")) {
            saw_none = true;
            selection = .{};
        } else if (std.mem.eql(u8, token, "cli")) {
            selection.enable_channel_cli = true;
        } else if (std.mem.eql(u8, token, "telegram")) {
            selection.enable_channel_telegram = true;
        } else if (std.mem.eql(u8, token, "discord")) {
            selection.enable_channel_discord = true;
        } else if (std.mem.eql(u8, token, "slack")) {
            selection.enable_channel_slack = true;
        } else if (std.mem.eql(u8, token, "whatsapp")) {
            selection.enable_channel_whatsapp = true;
        } else if (std.mem.eql(u8, token, "matrix")) {
            selection.enable_channel_matrix = true;
        } else if (std.mem.eql(u8, token, "mattermost")) {
            selection.enable_channel_mattermost = true;
        } else if (std.mem.eql(u8, token, "irc")) {
            selection.enable_channel_irc = true;
        } else if (std.mem.eql(u8, token, "imessage")) {
            selection.enable_channel_imessage = true;
        } else if (std.mem.eql(u8, token, "email")) {
            selection.enable_channel_email = true;
        } else if (std.mem.eql(u8, token, "lark")) {
            selection.enable_channel_lark = true;
        } else if (std.mem.eql(u8, token, "dingtalk")) {
            selection.enable_channel_dingtalk = true;
        } else if (std.mem.eql(u8, token, "line")) {
            selection.enable_channel_line = true;
        } else if (std.mem.eql(u8, token, "onebot")) {
            selection.enable_channel_onebot = true;
        } else if (std.mem.eql(u8, token, "qq")) {
            selection.enable_channel_qq = true;
        } else if (std.mem.eql(u8, token, "maixcam")) {
            selection.enable_channel_maixcam = true;
        } else if (std.mem.eql(u8, token, "signal")) {
            selection.enable_channel_signal = true;
        } else {
            std.log.err("unknown channel '{s}' in -Dchannels list", .{token});
            return error.InvalidChannelsOption;
        }
    }

    if (!saw_token) {
        std.log.err("empty -Dchannels list; use e.g. -Dchannels=all or -Dchannels=telegram,slack", .{});
        return error.InvalidChannelsOption;
    }
    if (saw_all and saw_none) {
        std.log.err("ambiguous -Dchannels list: cannot combine 'all' with 'none'", .{});
        return error.InvalidChannelsOption;
    }

    return selection;
}

const EngineSelection = struct {
    // Base backends
    enable_memory_none: bool = false,
    enable_memory_markdown: bool = false,
    enable_memory_memory: bool = false,
    enable_memory_api: bool = false,

    // Optional backends
    enable_sqlite: bool = false,
    enable_memory_sqlite: bool = false,
    enable_memory_lucid: bool = false,
    enable_memory_redis: bool = false,
    enable_memory_lancedb: bool = false,
    enable_postgres: bool = false,

    fn enableBase(self: *EngineSelection) void {
        self.enable_memory_none = true;
        self.enable_memory_markdown = true;
        self.enable_memory_memory = true;
        self.enable_memory_api = true;
    }

    fn enableAllOptional(self: *EngineSelection) void {
        self.enable_memory_sqlite = true;
        self.enable_memory_lucid = true;
        self.enable_memory_redis = true;
        self.enable_memory_lancedb = true;
        self.enable_postgres = true;
    }

    fn finalize(self: *EngineSelection) void {
        // SQLite runtime is needed by sqlite/lucid/lancedb memory backends.
        self.enable_sqlite = self.enable_memory_sqlite or self.enable_memory_lucid or self.enable_memory_lancedb;
    }

    fn hasAnyBackend(self: EngineSelection) bool {
        return self.enable_memory_none or
            self.enable_memory_markdown or
            self.enable_memory_memory or
            self.enable_memory_api or
            self.enable_memory_sqlite or
            self.enable_memory_lucid or
            self.enable_memory_redis or
            self.enable_memory_lancedb or
            self.enable_postgres;
    }
};

fn defaultEngines() EngineSelection {
    var selection = EngineSelection{};
    // Default binary: practical local setup with file/memory/api plus sqlite.
    selection.enableBase();
    selection.enable_memory_sqlite = true;
    selection.finalize();
    return selection;
}

fn parseEnginesOption(raw: []const u8) !EngineSelection {
    var selection = EngineSelection{};
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        std.log.err("empty -Dengines list; use e.g. -Dengines=base or -Dengines=base,sqlite", .{});
        return error.InvalidEnginesOption;
    }

    var saw_token = false;
    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t\r\n");
        if (token.len == 0) continue;
        saw_token = true;

        if (std.mem.eql(u8, token, "base") or std.mem.eql(u8, token, "minimal")) {
            selection.enableBase();
        } else if (std.mem.eql(u8, token, "all")) {
            selection.enableBase();
            selection.enableAllOptional();
        } else if (std.mem.eql(u8, token, "none")) {
            selection.enable_memory_none = true;
        } else if (std.mem.eql(u8, token, "markdown")) {
            selection.enable_memory_markdown = true;
        } else if (std.mem.eql(u8, token, "memory")) {
            selection.enable_memory_memory = true;
        } else if (std.mem.eql(u8, token, "api")) {
            selection.enable_memory_api = true;
        } else if (std.mem.eql(u8, token, "sqlite")) {
            selection.enable_memory_sqlite = true;
        } else if (std.mem.eql(u8, token, "lucid")) {
            selection.enable_memory_lucid = true;
        } else if (std.mem.eql(u8, token, "redis")) {
            selection.enable_memory_redis = true;
        } else if (std.mem.eql(u8, token, "lancedb")) {
            selection.enable_memory_lancedb = true;
        } else if (std.mem.eql(u8, token, "postgres")) {
            selection.enable_postgres = true;
        } else {
            std.log.err("unknown engine '{s}' in -Dengines list", .{token});
            return error.InvalidEnginesOption;
        }
    }

    if (!saw_token) {
        std.log.err("empty -Dengines list; use e.g. -Dengines=base or -Dengines=base,sqlite", .{});
        return error.InvalidEnginesOption;
    }

    selection.finalize();
    if (!selection.hasAnyBackend()) {
        std.log.err("no memory backends selected; choose at least one engine (e.g. base or none)", .{});
        return error.InvalidEnginesOption;
    }

    return selection;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const is_wasi = target.result.os.tag == .wasi;
    const app_version = b.option([]const u8, "version", "Version string embedded in the binary") orelse "2026.2.26";
    const channels_raw = b.option(
        []const u8,
        "channels",
        "Channels list. Tokens: all|none|cli|telegram|discord|slack|whatsapp|matrix|mattermost|irc|imessage|email|lark|dingtalk|line|onebot|qq|maixcam|signal (default: all)",
    );
    const channels = if (channels_raw) |raw| blk: {
        const parsed = parseChannelsOption(raw) catch {
            std.process.exit(1);
        };
        break :blk parsed;
    } else defaultChannels();

    const engines_raw = b.option(
        []const u8,
        "engines",
        "Memory engines list. Tokens: base|minimal|all|none|markdown|memory|api|sqlite|lucid|redis|lancedb|postgres (default: base,sqlite)",
    );
    const engines = if (engines_raw) |raw| blk: {
        const parsed = parseEnginesOption(raw) catch {
            std.process.exit(1);
        };
        break :blk parsed;
    } else defaultEngines();

    const enable_memory_none = engines.enable_memory_none;
    const enable_memory_markdown = engines.enable_memory_markdown;
    const enable_memory_memory = engines.enable_memory_memory;
    const enable_memory_api = engines.enable_memory_api;
    const enable_sqlite = engines.enable_sqlite;
    const enable_memory_sqlite = engines.enable_memory_sqlite;
    const enable_memory_lucid = engines.enable_memory_lucid;
    const enable_memory_redis = engines.enable_memory_redis;
    const enable_memory_lancedb = engines.enable_memory_lancedb;
    const enable_postgres = engines.enable_postgres;
    const enable_channel_cli = channels.enable_channel_cli;
    const enable_channel_telegram = channels.enable_channel_telegram;
    const enable_channel_discord = channels.enable_channel_discord;
    const enable_channel_slack = channels.enable_channel_slack;
    const enable_channel_whatsapp = channels.enable_channel_whatsapp;
    const enable_channel_matrix = channels.enable_channel_matrix;
    const enable_channel_mattermost = channels.enable_channel_mattermost;
    const enable_channel_irc = channels.enable_channel_irc;
    const enable_channel_imessage = channels.enable_channel_imessage;
    const enable_channel_email = channels.enable_channel_email;
    const enable_channel_lark = channels.enable_channel_lark;
    const enable_channel_dingtalk = channels.enable_channel_dingtalk;
    const enable_channel_line = channels.enable_channel_line;
    const enable_channel_onebot = channels.enable_channel_onebot;
    const enable_channel_qq = channels.enable_channel_qq;
    const enable_channel_maixcam = channels.enable_channel_maixcam;
    const enable_channel_signal = channels.enable_channel_signal;

    const effective_enable_memory_sqlite = enable_sqlite and enable_memory_sqlite;
    const effective_enable_memory_lucid = enable_sqlite and enable_memory_lucid;
    const effective_enable_memory_lancedb = enable_sqlite and enable_memory_lancedb;

    if (enable_sqlite) {
        verifyVendoredSqliteHashes(b) catch {
            std.log.err("vendored sqlite integrity check failed", .{});
            std.process.exit(1);
        };
    }

    const sqlite3 = if (enable_sqlite) blk: {
        const sqlite3_dep = b.dependency("sqlite3", .{
            .target = target,
            .optimize = optimize,
        });
        const sqlite3_artifact = sqlite3_dep.artifact("sqlite3");
        sqlite3_artifact.root_module.addCMacro("SQLITE_ENABLE_FTS5", "1");
        break :blk sqlite3_artifact;
    } else null;

    var build_options = b.addOptions();
    build_options.addOption([]const u8, "version", app_version);
    build_options.addOption(bool, "enable_memory_none", enable_memory_none);
    build_options.addOption(bool, "enable_memory_markdown", enable_memory_markdown);
    build_options.addOption(bool, "enable_memory_memory", enable_memory_memory);
    build_options.addOption(bool, "enable_memory_api", enable_memory_api);
    build_options.addOption(bool, "enable_sqlite", enable_sqlite);
    build_options.addOption(bool, "enable_postgres", enable_postgres);
    build_options.addOption(bool, "enable_memory_sqlite", effective_enable_memory_sqlite);
    build_options.addOption(bool, "enable_memory_lucid", effective_enable_memory_lucid);
    build_options.addOption(bool, "enable_memory_redis", enable_memory_redis);
    build_options.addOption(bool, "enable_memory_lancedb", effective_enable_memory_lancedb);
    build_options.addOption(bool, "enable_channel_cli", enable_channel_cli);
    build_options.addOption(bool, "enable_channel_telegram", enable_channel_telegram);
    build_options.addOption(bool, "enable_channel_discord", enable_channel_discord);
    build_options.addOption(bool, "enable_channel_slack", enable_channel_slack);
    build_options.addOption(bool, "enable_channel_whatsapp", enable_channel_whatsapp);
    build_options.addOption(bool, "enable_channel_matrix", enable_channel_matrix);
    build_options.addOption(bool, "enable_channel_mattermost", enable_channel_mattermost);
    build_options.addOption(bool, "enable_channel_irc", enable_channel_irc);
    build_options.addOption(bool, "enable_channel_imessage", enable_channel_imessage);
    build_options.addOption(bool, "enable_channel_email", enable_channel_email);
    build_options.addOption(bool, "enable_channel_lark", enable_channel_lark);
    build_options.addOption(bool, "enable_channel_dingtalk", enable_channel_dingtalk);
    build_options.addOption(bool, "enable_channel_line", enable_channel_line);
    build_options.addOption(bool, "enable_channel_onebot", enable_channel_onebot);
    build_options.addOption(bool, "enable_channel_qq", enable_channel_qq);
    build_options.addOption(bool, "enable_channel_maixcam", enable_channel_maixcam);
    build_options.addOption(bool, "enable_channel_signal", enable_channel_signal);
    const build_options_module = build_options.createModule();

    // ---------- library module (importable by consumers) ----------
    const lib_mod: ?*std.Build.Module = if (is_wasi) null else blk: {
        const module = b.addModule("nullclaw", .{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("build_options", build_options_module);
        if (sqlite3) |lib| {
            module.linkLibrary(lib);
        }
        if (enable_postgres) {
            module.linkSystemLibrary("pq", .{});
        }
        break :blk module;
    };

    // ---------- executable ----------
    const exe_imports: []const std.Build.Module.Import = if (is_wasi)
        &.{}
    else
        &.{.{ .name = "nullclaw", .module = lib_mod.? }};

    const exe = b.addExecutable(.{
        .name = "nullclaw",
        .root_module = b.createModule(.{
            .root_source_file = if (is_wasi) b.path("src/main_wasi.zig") else b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = exe_imports,
        }),
    });
    exe.root_module.addImport("build_options", build_options_module);

    // Link SQLite on the compile step (not the module)
    if (!is_wasi) {
        if (sqlite3) |lib| {
            exe.linkLibrary(lib);
        }
        if (enable_postgres) {
            exe.root_module.linkSystemLibrary("pq", .{});
        }
    }
    exe.dead_strip_dylibs = true;

    if (optimize != .Debug) {
        exe.root_module.strip = true;
        exe.root_module.unwind_tables = .none;
        exe.root_module.omit_frame_pointer = true;
    }

    b.installArtifact(exe);

    // macOS host+target only: strip local symbols post-install.
    // Host `strip` cannot process ELF/PE during cross-builds.
    if (optimize != .Debug and builtin.os.tag == .macos and target.result.os.tag == .macos) {
        const strip_cmd = b.addSystemCommand(&.{"strip"});
        strip_cmd.addArgs(&.{"-x"});
        strip_cmd.addFileArg(exe.getEmittedBin());
        strip_cmd.step.dependOn(b.getInstallStep());
        b.default_step = &strip_cmd.step;
    }

    // ---------- run step ----------
    const run_step = b.step("run", "Run nullclaw");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // ---------- tests ----------
    const test_step = b.step("test", "Run all tests");
    if (!is_wasi) {
        const lib_tests = b.addTest(.{ .root_module = lib_mod.? });
        if (sqlite3) |lib| {
            lib_tests.linkLibrary(lib);
        }
        if (enable_postgres) {
            lib_tests.root_module.linkSystemLibrary("pq", .{});
        }

        const exe_tests = b.addTest(.{ .root_module = exe.root_module });
        test_step.dependOn(&b.addRunArtifact(lib_tests).step);
        test_step.dependOn(&b.addRunArtifact(exe_tests).step);
    }
}
