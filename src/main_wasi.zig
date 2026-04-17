const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const build_options = @import("build_options");
const fs_compat = @import("fs_compat.zig");

const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_SEARCH_MATCHES: usize = 5;

const DEFAULT_WORKSPACE = ".";

const IDENTITY_TEMPLATE =
    \\# IDENTITY.md
    \\Name: NullClaw WASI
    \\Role: Local assistant running in WASM/WASI.
    \\Style: concise, direct, practical.
    \\
;

const USER_TEMPLATE =
    \\# USER.md
    \\Name: User
    \\Preferences:
    \\- Keep responses concise.
    \\- Focus on actionable next steps.
    \\
;

const MEMORY_TEMPLATE =
    \\# MEMORY.md
    \\- **workspace**: Initialized in WASI mode.
    \\- **notes**: Add durable facts with `nullclaw memory add <key> <content>`.
    \\
;

const HEARTBEAT_TEMPLATE =
    \\# HEARTBEAT.md
    \\- Review MEMORY.md and keep it high-signal.
    \\
;

const ParsedWorkspaceArgs = struct {
    workspace: []const u8,
    positionals: []const []const u8,
};

const MemoryMatch = struct {
    line: []const u8,
    score: u32,
};

const Command = enum {
    help,
    version,
    onboard,
    status,
    identity,
    memory,
    agent,
};

fn parse_command(arg: []const u8) ?Command {
    const map = std.StaticStringMap(Command).initComptime(.{
        .{ "help", .help },
        .{ "--help", .help },
        .{ "-h", .help },
        .{ "version", .version },
        .{ "--version", .version },
        .{ "-V", .version },
        .{ "onboard", .onboard },
        .{ "status", .status },
        .{ "identity", .identity },
        .{ "memory", .memory },
        .{ "agent", .agent },
    });
    return map.get(arg);
}

fn print_out(comptime fmt: []const u8, args: anytype) !void {
    var buf: [2048]u8 = undefined;
    var out = std_compat.fs.File.stdout().writer(&buf);
    try out.interface.print(fmt, args);
    try out.interface.flush();
}

fn print_err(comptime fmt: []const u8, args: anytype) !void {
    var buf: [2048]u8 = undefined;
    var out = std_compat.fs.File.stderr().writer(&buf);
    try out.interface.print(fmt, args);
    try out.interface.flush();
}

fn print_usage() !void {
    try print_out(
        \\nullclaw {s} (WASI)
        \\Usage:
        \\  nullclaw version
        \\  nullclaw help
        \\  nullclaw onboard [--workspace PATH]
        \\  nullclaw status [--workspace PATH]
        \\  nullclaw identity <show|set TEXT...> [--workspace PATH]
        \\  nullclaw memory <add|list|search|clear> [...] [--workspace PATH]
        \\  nullclaw agent -m "message" [--workspace PATH]
        \\
        \\OpenClaw-like WASI mode:
        \\  - workspace/IDENTITY.md
        \\  - workspace/USER.md
        \\  - workspace/MEMORY.md
        \\  - workspace/memory/YYYY-MM-DD.md
        \\
    , .{build_options.version});
}

fn parse_workspace_args(allocator: std.mem.Allocator, args: []const []const u8) !ParsedWorkspaceArgs {
    var workspace = try allocator.dupe(u8, DEFAULT_WORKSPACE);
    var positionals: std.ArrayList([]const u8) = .empty;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--workspace")) {
            if (i + 1 >= args.len) return error.MissingWorkspacePath;
            i += 1;
            workspace = try allocator.dupe(u8, args[i]);
            continue;
        }
        try positionals.append(allocator, arg);
    }

    return .{
        .workspace = workspace,
        .positionals = try positionals.toOwnedSlice(allocator),
    };
}

fn join_path(allocator: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    return std_compat.fs.path.join(allocator, &.{ a, b });
}

fn ensure_parent_dir(path: []const u8) !void {
    const maybe_parent = std_compat.fs.path.dirname(path);
    if (maybe_parent) |parent| {
        fs_compat.makePath(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
}

fn file_exists(path: []const u8) bool {
    const file = fs_compat.openPath(path, .{}) catch return false;
    file.close();
    return true;
}

fn read_file_if_present(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    const file = fs_compat.openPath(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, MAX_READ_BYTES);
}

fn write_file_truncate(path: []const u8, content: []const u8) !void {
    try ensure_parent_dir(path);
    const file = try fs_compat.createPath(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
}

fn write_if_missing(path: []const u8, content: []const u8) !bool {
    if (file_exists(path)) return false;
    try ensure_parent_dir(path);
    const file = try fs_compat.createPath(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(content);
    return true;
}

fn append_line(path: []const u8, line: []const u8, allocator: std.mem.Allocator) !void {
    try ensure_parent_dir(path);
    const file = try fs_compat.createPath(path, .{ .truncate = false, .read = true });
    defer file.close();

    const stat = try fs_compat.stat(file);
    const size = stat.size;
    try file.seekTo(size);

    if (size > 0) {
        try file.seekTo(size - 1);
        var last_byte: [1]u8 = undefined;
        const n = try file.read(&last_byte);
        if (n == 1 and last_byte[0] != '\n') {
            try file.seekTo(size);
            try file.writeAll("\n");
        } else {
            try file.seekTo(size);
        }
    }

    const line_with_newline = try std.fmt.allocPrint(allocator, "{s}\n", .{line});
    try file.writeAll(line_with_newline);
}

fn scaffold_workspace(allocator: std.mem.Allocator, workspace: []const u8) !usize {
    fs_compat.makePath(workspace) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const memory_dir = try join_path(allocator, workspace, "memory");
    fs_compat.makePath(memory_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const identity_path = try join_path(allocator, workspace, "IDENTITY.md");
    const user_path = try join_path(allocator, workspace, "USER.md");
    const memory_path = try join_path(allocator, workspace, "MEMORY.md");
    const heartbeat_path = try join_path(allocator, workspace, "HEARTBEAT.md");

    var created: usize = 0;
    if (try write_if_missing(identity_path, IDENTITY_TEMPLATE)) created += 1;
    if (try write_if_missing(user_path, USER_TEMPLATE)) created += 1;
    if (try write_if_missing(memory_path, MEMORY_TEMPLATE)) created += 1;
    if (try write_if_missing(heartbeat_path, HEARTBEAT_TEMPLATE)) created += 1;
    return created;
}

fn memory_line_payload(raw_line: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, raw_line, " \t\r");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '#') return null;

    if (std.mem.startsWith(u8, trimmed, "- ")) {
        const payload = std.mem.trim(u8, trimmed[2..], " \t");
        return if (payload.len == 0) null else payload;
    }
    return trimmed;
}

fn count_memory_entries(text: []const u8) usize {
    var count: usize = 0;
    var line_it = std.mem.splitScalar(u8, text, '\n');
    while (line_it.next()) |raw_line| {
        if (memory_line_payload(raw_line) != null) count += 1;
    }
    return count;
}

fn contains_case_insensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn find_memory_matches(
    allocator: std.mem.Allocator,
    memory_text: []const u8,
    query: []const u8,
    max_matches: usize,
) ![]MemoryMatch {
    var query_tokens: std.ArrayList([]const u8) = .empty;
    var token_it = std.mem.tokenizeAny(u8, query, " \t\r\n");
    while (token_it.next()) |token| {
        if (token.len > 0) try query_tokens.append(allocator, token);
    }
    const tokens = try query_tokens.toOwnedSlice(allocator);
    if (tokens.len == 0) return allocator.alloc(MemoryMatch, 0);

    var matches: std.ArrayList(MemoryMatch) = .empty;
    var line_it = std.mem.splitScalar(u8, memory_text, '\n');
    while (line_it.next()) |raw_line| {
        const payload = memory_line_payload(raw_line) orelse continue;
        var score: u32 = 0;
        for (tokens) |token| {
            if (contains_case_insensitive(payload, token)) score += 1;
        }
        if (score > 0) {
            try matches.append(allocator, .{ .line = payload, .score = score });
        }
    }

    std.mem.sort(MemoryMatch, matches.items, {}, struct {
        fn less_than(_: void, a: MemoryMatch, b: MemoryMatch) bool {
            if (a.score == b.score) return a.line.len < b.line.len;
            return a.score > b.score;
        }
    }.less_than);

    if (matches.items.len > max_matches) {
        matches.shrinkRetainingCapacity(max_matches);
    }
    return matches.toOwnedSlice(allocator);
}

fn to_single_line(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, text.len);
    for (text, 0..) |ch, idx| {
        out[idx] = switch (ch) {
            '\n', '\r', '\t' => ' ',
            else => ch,
        };
    }
    return out;
}

fn daily_log_path(allocator: std.mem.Allocator, workspace: []const u8) ![]u8 {
    const now = std_compat.time.timestamp();
    const epoch_secs: u64 = if (now <= 0) 0 else @intCast(now);
    const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
    const yd = epoch.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const file_name = try std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}.md", .{
        yd.year,
        @intFromEnum(md.month),
        md.day_index + 1,
    });
    const memory_dir = try join_path(allocator, workspace, "memory");
    return join_path(allocator, memory_dir, file_name);
}

fn extract_agent_name(identity_text: ?[]const u8) []const u8 {
    if (identity_text) |text| {
        var line_it = std.mem.splitScalar(u8, text, '\n');
        while (line_it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            if (line.len >= "Name:".len and std.ascii.eqlIgnoreCase(line[0.."Name:".len], "Name:")) {
                const value = std.mem.trim(u8, line["Name:".len..], " \t");
                if (value.len > 0) return value;
            }
        }
    }
    return "NullClaw WASI";
}

fn join_tokens(allocator: std.mem.Allocator, tokens: []const []const u8) ![]u8 {
    if (tokens.len == 0) return allocator.dupe(u8, "");

    var total: usize = 0;
    for (tokens, 0..) |token, idx| {
        total += token.len;
        if (idx > 0) total += 1;
    }

    const out = try allocator.alloc(u8, total);
    var cursor: usize = 0;
    for (tokens, 0..) |token, idx| {
        if (idx > 0) {
            out[cursor] = ' ';
            cursor += 1;
        }
        @memcpy(out[cursor .. cursor + token.len], token);
        cursor += token.len;
    }
    return out;
}

fn run_onboard(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed = try parse_workspace_args(allocator, args);
    if (parsed.positionals.len != 0) {
        try print_err("Usage: nullclaw onboard [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }

    const created = try scaffold_workspace(allocator, parsed.workspace);
    try print_out("Workspace: {s}\n", .{parsed.workspace});
    try print_out("Initialized files: {d}\n", .{created});
}

fn run_status(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed = try parse_workspace_args(allocator, args);
    if (parsed.positionals.len != 0) {
        try print_err("Usage: nullclaw status [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }

    const identity_path = try join_path(allocator, parsed.workspace, "IDENTITY.md");
    const user_path = try join_path(allocator, parsed.workspace, "USER.md");
    const memory_path = try join_path(allocator, parsed.workspace, "MEMORY.md");

    const identity_exists = file_exists(identity_path);
    const user_exists = file_exists(user_path);
    const memory_exists = file_exists(memory_path);

    var memory_count: usize = 0;
    if (memory_exists) {
        if (try read_file_if_present(allocator, memory_path)) |memory_text| {
            memory_count = count_memory_entries(memory_text);
        }
    }

    try print_out("nullclaw WASI status\n", .{});
    try print_out("workspace: {s}\n", .{parsed.workspace});
    try print_out("identity: {s}\n", .{if (identity_exists) "ok" else "missing"});
    try print_out("user: {s}\n", .{if (user_exists) "ok" else "missing"});
    try print_out("memory: {s}\n", .{if (memory_exists) "ok" else "missing"});
    try print_out("memory_entries: {d}\n", .{memory_count});
}

fn run_identity(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed = try parse_workspace_args(allocator, args);
    if (parsed.positionals.len < 1) {
        try print_err("Usage: nullclaw identity <show|set TEXT...> [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }

    _ = try scaffold_workspace(allocator, parsed.workspace);
    const identity_path = try join_path(allocator, parsed.workspace, "IDENTITY.md");

    const subcmd = parsed.positionals[0];
    if (std.mem.eql(u8, subcmd, "show")) {
        const content = try read_file_if_present(allocator, identity_path) orelse "";
        try print_out("{s}\n", .{content});
        return;
    }

    if (std.mem.eql(u8, subcmd, "set")) {
        if (parsed.positionals.len < 2) {
            try print_err("Usage: nullclaw identity set TEXT... [--workspace PATH]\n", .{});
            return error.InvalidUsage;
        }
        const text = try join_tokens(allocator, parsed.positionals[1..]);
        try write_file_truncate(identity_path, text);
        try print_out("Identity updated: {s}\n", .{identity_path});
        return;
    }

    try print_err("Unknown identity command: {s}\n", .{subcmd});
    return error.InvalidUsage;
}

fn run_memory(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed = try parse_workspace_args(allocator, args);
    if (parsed.positionals.len < 1) {
        try print_err("Usage: nullclaw memory <add|list|search|clear> ... [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }

    _ = try scaffold_workspace(allocator, parsed.workspace);
    const memory_path = try join_path(allocator, parsed.workspace, "MEMORY.md");

    const subcmd = parsed.positionals[0];
    if (std.mem.eql(u8, subcmd, "add")) {
        if (parsed.positionals.len < 3) {
            try print_err("Usage: nullclaw memory add <key> <content...> [--workspace PATH]\n", .{});
            return error.InvalidUsage;
        }
        const key = parsed.positionals[1];
        const content = try join_tokens(allocator, parsed.positionals[2..]);
        const line = try std.fmt.allocPrint(allocator, "- **{s}**: {s}", .{ key, content });
        try append_line(memory_path, line, allocator);
        try print_out("Stored memory key: {s}\n", .{key});
        return;
    }

    if (std.mem.eql(u8, subcmd, "list")) {
        const memory_text = try read_file_if_present(allocator, memory_path) orelse "";
        var idx: usize = 1;
        var line_it = std.mem.splitScalar(u8, memory_text, '\n');
        while (line_it.next()) |raw_line| {
            const payload = memory_line_payload(raw_line) orelse continue;
            try print_out("{d}. {s}\n", .{ idx, payload });
            idx += 1;
        }
        if (idx == 1) {
            try print_out("No memory entries.\n", .{});
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "search")) {
        if (parsed.positionals.len < 2) {
            try print_err("Usage: nullclaw memory search <query...> [--workspace PATH]\n", .{});
            return error.InvalidUsage;
        }
        const query = try join_tokens(allocator, parsed.positionals[1..]);
        const memory_text = try read_file_if_present(allocator, memory_path) orelse "";
        const matches = try find_memory_matches(allocator, memory_text, query, MAX_SEARCH_MATCHES);
        if (matches.len == 0) {
            try print_out("No matches for: {s}\n", .{query});
            return;
        }
        try print_out("Matches for: {s}\n", .{query});
        for (matches, 0..) |match, idx| {
            try print_out("{d}. [{d}] {s}\n", .{ idx + 1, match.score, match.line });
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "clear")) {
        try write_file_truncate(memory_path, MEMORY_TEMPLATE);
        try print_out("Memory reset: {s}\n", .{memory_path});
        return;
    }

    try print_err("Unknown memory command: {s}\n", .{subcmd});
    return error.InvalidUsage;
}

fn run_agent(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed = try parse_workspace_args(allocator, args);
    if (parsed.positionals.len < 2) {
        try print_err("Usage: nullclaw agent -m \"message\" [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }
    if (!std.mem.eql(u8, parsed.positionals[0], "-m") and !std.mem.eql(u8, parsed.positionals[0], "--message")) {
        try print_err("Usage: nullclaw agent -m \"message\" [--workspace PATH]\n", .{});
        return error.InvalidUsage;
    }

    _ = try scaffold_workspace(allocator, parsed.workspace);

    const message = try join_tokens(allocator, parsed.positionals[1..]);
    const identity_path = try join_path(allocator, parsed.workspace, "IDENTITY.md");
    const memory_path = try join_path(allocator, parsed.workspace, "MEMORY.md");

    const identity_text = try read_file_if_present(allocator, identity_path);
    const memory_text = try read_file_if_present(allocator, memory_path) orelse "";
    const agent_name = extract_agent_name(identity_text);
    const matches = try find_memory_matches(allocator, memory_text, message, 2);

    const reply = if (matches.len == 0)
        try std.fmt.allocPrint(
            allocator,
            "{s}: noted. I do not have related memory yet, but this turn is saved in the daily log.",
            .{agent_name},
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}: noted. Related memory: {s}. Next practical step: {s}",
            .{ agent_name, matches[0].line, message },
        );

    try print_out("{s}\n", .{reply});

    const daily_path = try daily_log_path(allocator, parsed.workspace);
    const user_one_line = try to_single_line(allocator, message);
    const reply_one_line = try to_single_line(allocator, reply);
    const user_log = try std.fmt.allocPrint(allocator, "- user: {s}", .{user_one_line});
    const assistant_log = try std.fmt.allocPrint(allocator, "- assistant: {s}", .{reply_one_line});
    try append_line(daily_path, user_log, allocator);
    try append_line(daily_path, assistant_log, allocator);
}

pub fn main(init: std.process.Init) !void {
    std_compat.initProcess(init);
    const base_allocator = if (builtin.target.os.tag == .wasi) std.heap.wasm_allocator else std.heap.smp_allocator;
    const args = try std_compat.process.argsAlloc(base_allocator);
    defer std_compat.process.argsFree(base_allocator, args);

    var arena = std.heap.ArenaAllocator.init(base_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    if (args.len < 2) {
        try print_usage();
        return;
    }

    const cmd = parse_command(args[1]) orelse {
        try print_err("Unknown command: {s}\n\n", .{args[1]});
        try print_usage();
        std_compat.process.exit(1);
    };

    const sub_args = args[2..];
    const result = switch (cmd) {
        .help => print_usage(),
        .version => print_out("nullclaw {s}\n", .{build_options.version}),
        .onboard => run_onboard(allocator, sub_args),
        .status => run_status(allocator, sub_args),
        .identity => run_identity(allocator, sub_args),
        .memory => run_memory(allocator, sub_args),
        .agent => run_agent(allocator, sub_args),
    };

    result catch |err| {
        if (err != error.InvalidUsage and err != error.MissingWorkspacePath) {
            print_err("Error: {}\n", .{err}) catch {};
        } else if (err == error.MissingWorkspacePath) {
            print_err("Missing path value after --workspace.\n", .{}) catch {};
        }
        std_compat.process.exit(1);
    };
}
