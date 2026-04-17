const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const fs_compat = @import("../fs_compat.zig");
const http_util = @import("../http_util.zig");
const platform = @import("../platform.zig");
const error_classify = @import("error_classify.zig");
const verbose = @import("../verbose.zig");
const log = std.log.scoped(.provider_sse);

// Keep large request bodies out of argv. On Linux, a single oversized `-d`
// argument can hit execve limits long before the total ARG_MAX budget.
const MAX_INLINE_CURL_BODY_BYTES: usize = 64 * 1024;

var curl_fail_fast_arg_mutex: std_compat.sync.Mutex = .{};
var curl_fail_with_body_supported_cache: ?bool = null;
const stream_stall_detection_args = [_][]const u8{
    "--speed-limit",
    "1",
    "--speed-time",
    "60",
};

fn finalizeStreamResult(
    allocator: std.mem.Allocator,
    accumulated: []const u8,
    stream_usage: ?root.TokenUsage,
) !root.StreamChatResult {
    var content: ?[]const u8 = null;
    var reasoning_content: ?[]const u8 = null;
    if (accumulated.len > 0) {
        const split = try root.splitThinkContent(allocator, accumulated);
        content = split.visible;
        reasoning_content = split.reasoning;
    }

    var usage = stream_usage orelse root.TokenUsage{};
    if (usage.completion_tokens == 0) {
        usage.completion_tokens = @intCast((accumulated.len + 3) / 4);
    }

    return .{
        .content = content,
        .reasoning_content = reasoning_content,
        .usage = usage,
        .model = "",
    };
}

fn parseCurlVersionComponent(component: []const u8) ?u32 {
    var end: usize = 0;
    while (end < component.len and std.ascii.isDigit(component[end])) : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(u32, component[0..end], 10) catch null;
}

fn parseCurlVersionTriplet(version_line: []const u8) ?[3]u32 {
    const prefix = "curl ";
    if (!std.mem.startsWith(u8, version_line, prefix)) return null;

    const version_tail = version_line[prefix.len..];
    const version_end = std.mem.indexOfScalar(u8, version_tail, ' ') orelse version_tail.len;
    const version_token = version_tail[0..version_end];

    var parts = std.mem.splitScalar(u8, version_token, '.');
    const major = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    const minor = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    const patch = parseCurlVersionComponent(parts.next() orelse return null) orelse return null;
    return .{ major, minor, patch };
}

fn curlVersionSupportsFailWithBody(version_line: []const u8) bool {
    const version = parseCurlVersionTriplet(version_line) orelse return false;
    if (version[0] != 7) return version[0] > 7;
    if (version[1] != 76) return version[1] > 76;
    return version[2] >= 0;
}

fn detectCurlFailWithBodySupport(allocator: std.mem.Allocator) bool {
    const result = std_compat.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "curl", "--version" },
        .max_output_bytes = 1024,
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return false,
        else => return false,
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \n\r\t");
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    return curlVersionSupportsFailWithBody(line_it.first());
}

/// Prefer `--fail-with-body` so JSON API errors remain classifiable, but fall
/// back to `-f` on curl releases older than 7.76.0 where the newer flag fails.
pub fn curlFailFastArg(allocator: std.mem.Allocator) []const u8 {
    curl_fail_fast_arg_mutex.lock();
    defer curl_fail_fast_arg_mutex.unlock();

    if (curl_fail_with_body_supported_cache == null) {
        curl_fail_with_body_supported_cache = detectCurlFailWithBodySupport(allocator);
    }

    return if (curl_fail_with_body_supported_cache.?) "--fail-with-body" else "-f";
}

pub fn appendCurlStallDetectionArgs(argv_buf: [][]const u8, argc: *usize) void {
    for (stream_stall_detection_args) |arg| {
        argv_buf[argc.*] = arg;
        argc.* += 1;
    }
}

const CurlBodyArg = struct {
    arg: []const u8,
    temp_path_buf: [std_compat.fs.max_path_bytes]u8 = undefined,
    temp_path_len: usize = 0,
    uses_temp_file: bool = false,

    fn deinit(self: *const CurlBodyArg, allocator: std.mem.Allocator) void {
        if (!self.uses_temp_file) return;
        std_compat.fs.deleteFileAbsolute(self.temp_path_buf[0..self.temp_path_len]) catch {};
        allocator.free(self.arg);
    }
};

fn prepareCurlBodyArg(
    allocator: std.mem.Allocator,
    body: []const u8,
    log_enabled: bool,
) !CurlBodyArg {
    const should_use_temp_file = builtin.os.tag == .windows or body.len > MAX_INLINE_CURL_BODY_BYTES;
    if (!should_use_temp_file) {
        return .{ .arg = body };
    }

    const debug_log = std.log.scoped(.sse);
    var prepared: CurlBodyArg = .{ .arg = body };

    const tmp_dir_path = platform.getTempDir(allocator) catch
        return error.TempDirNotFound;
    defer allocator.free(tmp_dir_path);

    var tmp_dir = std_compat.fs.openDirAbsolute(tmp_dir_path, .{}) catch
        return error.TempDirNotFound;
    defer tmp_dir.close();

    const body_path = std.fmt.bufPrint(
        &prepared.temp_path_buf,
        "{s}{s}sse_body_{d}.tmp",
        .{ tmp_dir_path, std_compat.fs.path.sep_str, std_compat.time.timestamp() },
    ) catch return error.PathTooLong;
    prepared.temp_path_len = body_path.len;
    errdefer std_compat.fs.deleteFileAbsolute(prepared.temp_path_buf[0..prepared.temp_path_len]) catch {};

    var tmp_file = tmp_dir.createFile(
        body_path[tmp_dir_path.len + 1 ..],
        .{ .truncate = true, .exclusive = false },
    ) catch return error.TempFileCreateFailed;

    tmp_file.writeAll(body) catch {
        tmp_file.close();
        return error.TempFileWriteFailed;
    };
    tmp_file.close();

    if (log_enabled) {
        debug_log.info("Using temp file for curl body: {s}, body_len={d}", .{ body_path, body.len });
    }

    const verify_file = std_compat.fs.openFileAbsolute(body_path, .{}) catch return error.TempFileCreateFailed;
    defer verify_file.close();
    const verify_stat = fs_compat.stat(verify_file) catch return error.TempFileCreateFailed;
    if (log_enabled) {
        debug_log.info("Temp body file size: {d} bytes", .{verify_stat.size});
    }

    for (prepared.temp_path_buf[0..prepared.temp_path_len]) |*c| {
        if (c.* == '\\') c.* = '/';
    }

    prepared.arg = try std.fmt.allocPrint(allocator, "@{s}", .{prepared.temp_path_buf[0..prepared.temp_path_len]});
    errdefer allocator.free(prepared.arg);
    prepared.uses_temp_file = true;
    return prepared;
}

/// Result of parsing a single SSE line.
pub const SseLineResult = union(enum) {
    /// Text delta content (owned, caller frees).
    delta: []const u8,
    /// Stream is complete ([DONE] sentinel).
    done: void,
    /// Token usage from a stream chunk.
    usage: root.TokenUsage,
    /// Line should be skipped (empty, comment, or no content).
    skip: void,
};

/// Parse a single SSE line in OpenAI streaming format.
///
/// Handles:
/// - `data: [DONE]` → `.done`
/// - `data: {JSON}` → extracts `choices[0].delta.content` → `.delta`
/// - Empty lines, comments (`:`) → `.skip`
pub fn parseSseLine(allocator: std.mem.Allocator, line: []const u8) !SseLineResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // SSE uses "data:" with an optional single leading space before the value.
    const prefix = "data:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return .skip;

    const data = if (trimmed.len > prefix.len and trimmed[prefix.len] == ' ')
        trimmed[prefix.len + 1 ..]
    else
        trimmed[prefix.len..];

    if (data.len == 0) return .skip;

    if (std.mem.eql(u8, data, "[DONE]")) return .done;

    const content = try extractDeltaContent(allocator, data) orelse {
        // No content delta — check for usage data (sent in the final chunk).
        if (extractStreamUsage(data)) |u| return .{ .usage = u };
        return .skip;
    };
    return .{ .delta = content };
}

/// Extract `usage` object from an OpenAI-compatible streaming chunk.
/// The final chunk typically has `choices:[]` and a top-level `usage` object.
fn extractStreamUsage(json_str: []const u8) ?root.TokenUsage {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, json_str, .{}) catch
        return null;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const usage_val = obj.get("usage") orelse return null;
    if (usage_val != .object) return null;

    var usage = root.TokenUsage{};
    if (usage_val.object.get("prompt_tokens")) |v| {
        if (v == .integer) usage.prompt_tokens = @intCast(v.integer);
    }
    if (usage_val.object.get("completion_tokens")) |v| {
        if (v == .integer) usage.completion_tokens = @intCast(v.integer);
    }
    if (usage_val.object.get("total_tokens")) |v| {
        if (v == .integer) usage.total_tokens = @intCast(v.integer);
    }
    return usage;
}

/// Extract visible streaming text from an SSE JSON payload.
/// Falls back to `delta.reasoning`, `delta.reasoning_content`, or
/// `delta.reasoning_details` when providers stream their thinking trace
/// separately and wraps it in think tags so higher layers can suppress it
/// from user-visible output.
/// Returns owned slice or null if no content found.
pub fn extractDeltaContent(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const choices = obj.get("choices") orelse return null;
    if (choices != .array or choices.array.items.len == 0) return null;

    const first = choices.array.items[0];
    if (first != .object) return null;

    const delta = first.object.get("delta") orelse return null;
    if (delta != .object) return null;

    if (delta.object.get("content")) |content| {
        if (content == .string and content.string.len > 0) {
            return try allocator.dupe(u8, content.string);
        }
    }

    if (delta.object.get("reasoning")) |reasoning| {
        if (reasoning == .string and reasoning.string.len > 0) {
            return try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning.string});
        }
    }

    if (delta.object.get("reasoning_content")) |reasoning_content| {
        if (reasoning_content == .string and reasoning_content.string.len > 0) {
            const wrapped = try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning_content.string});
            return wrapped;
        }
    }

    if (delta.object.get("reasoning_details")) |reasoning_details| {
        if (try root.extractReasoningTextFromDetails(allocator, reasoning_details)) |reasoning_text| {
            defer allocator.free(reasoning_text);
            return try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning_text});
        }
    }

    return null;
}

/// Run curl in SSE streaming mode and parse output line by line.
///
/// Spawns `curl -s --no-buffer` with the strongest supported fail-fast flag:
/// `--fail-with-body` on curl >= 7.76.0, otherwise `-f`.
/// For each SSE delta, calls `callback(ctx, chunk)`.
/// Returns accumulated result after stream completes.
pub fn curlStream(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_header: ?[]const u8,
    extra_headers: []const []const u8,
    timeout_secs: u64,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    // Check verbose mode once at function start
    const log_enabled = verbose.isVerbose();
    const debug_log = std.log.scoped(.sse);

    // Build argv on stack (max 40 args)
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--no-buffer";
    argc += 1;
    argv_buf[argc] = curlFailFastArg(allocator);
    argc += 1;

    var timeout_buf: [32]u8 = undefined;
    if (timeout_secs > 0) {
        const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch unreachable;
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = timeout_str;
        argc += 1;
    }

    // Kill the curl process if transfer rate drops below 1 byte/second for 60 seconds.
    // This catches providers that open the SSE connection but stall mid-stream without
    // hitting the --max-time wall (e.g. glm-5 on infini-ai hanging on large contexts).
    appendCurlStallDetectionArgs(argv_buf[0..], &argc);

    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;

    // Add proxy from environment if set
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);
    http_util.appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    if (auth_header) |auth| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = auth;
        argc += 1;
    }

    for (extra_headers) |hdr| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    // On Windows, command line length is limited to ~32767 chars.
    // Use a temp file there to avoid NameTooLong; keep other platforms in-memory.
    var prepared_body = try prepareCurlBodyArg(allocator, body, log_enabled);
    defer prepared_body.deinit(allocator);

    if (prepared_body.uses_temp_file) {
        argv_buf[argc] = "--data-binary";
        argc += 1;
    } else {
        argv_buf[argc] = "-d";
        argc += 1;
    }
    argv_buf[argc] = prepared_body.arg;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    // Debug: log the curl command
    if (log_enabled) {
        debug_log.info("curl argc={d}, body_len={d}, used_temp_file={}, body_arg={s}", .{ argc, body.len, prepared_body.uses_temp_file, prepared_body.arg });
    }

    var cmd_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer cmd_buf.deinit(allocator);
    for (argv_buf[0..argc], 0..) |arg, i| {
        if (i > 0) cmd_buf.append(allocator, ' ') catch {};
        // Quote arguments that contain spaces or special chars for easy copy-paste
        if (std.mem.indexOfAny(u8, arg, " \t\"'") != null or std.mem.startsWith(u8, arg, "@")) {
            cmd_buf.append(allocator, '"') catch {};
            cmd_buf.appendSlice(allocator, arg) catch {};
            cmd_buf.append(allocator, '"') catch {};
        } else {
            cmd_buf.appendSlice(allocator, arg) catch {};
        }
    }
    if (log_enabled) {
        debug_log.info("curl command: {s}", .{cmd_buf.items});
    }

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    if (log_enabled) {
        debug_log.info("spawning curl process...", .{});
    }
    try child.spawn();
    if (log_enabled) {
        const pid: i64 = if (@import("builtin").os.tag == .windows) @intCast(@intFromPtr(child.id)) else child.id;
        debug_log.info("curl process spawned, pid={d}", .{pid});
    }

    // Read stdout line by line, parse SSE events
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    const stdout_file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var saw_done = false;
    var total_stdout: usize = 0;
    var stream_usage: ?root.TokenUsage = null;

    outer: while (true) {
        const n = stdout_file.read(&read_buf) catch |err| {
            if (log_enabled) {
                debug_log.info("stdout read error: {}", .{err});
            }
            break;
        };
        if (n == 0) {
            if (log_enabled) {
                debug_log.info("stdout read returned 0 bytes (EOF)", .{});
            }
            break;
        }
        total_stdout += n;

        if (log_enabled) {
            debug_log.info("stdout read {d} bytes: {s}", .{ n, read_buf[0..n] });
        }

        // Check if this is JSON (starts with '{')
        if (total_stdout == n and read_buf[0] == '{') {
            if (log_enabled) {
                debug_log.info("Detected JSON response, not SSE", .{});
            }
            // This is a JSON error, not SSE
            const json_response = try allocator.dupe(u8, read_buf[0..n]);
            defer allocator.free(json_response);

            // Try to classify the error
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_response, .{}) catch null;
            if (parsed) |p| {
                defer p.deinit();
                if (error_classify.classifyKnownApiError(p.value.object)) |kind| {
                    _ = child.wait() catch {};
                    return error_classify.kindToError(kind);
                }
            }

            // Return a meaningful error
            _ = child.wait() catch {};
            debug_log.err("Server returned JSON error: {s}", .{json_response});
            return error.ServerError;
        }

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                if (log_enabled) {
                    debug_log.info("parsing SSE line: {s}", .{line_buf.items});
                }
                const result = parseSseLine(allocator, line_buf.items) catch {
                    line_buf.clearRetainingCapacity();
                    continue;
                };
                line_buf.clearRetainingCapacity();
                switch (result) {
                    .delta => |text| {
                        defer allocator.free(text);
                        try accumulated.appendSlice(allocator, text);
                        callback(ctx, root.StreamChunk.textDelta(text));
                    },
                    .usage => |u| stream_usage = u,
                    .done => {
                        if (log_enabled) {
                            debug_log.info("SSE stream done", .{});
                        }
                        saw_done = true;
                        break :outer;
                    },
                    .skip => {},
                }
            } else {
                try line_buf.append(allocator, byte);
            }
        }
    }

    if (log_enabled) {
        debug_log.info("stdout stream ended, saw_done={}, accumulated_len={d}, total_stdout={d}", .{ saw_done, accumulated.items.len, total_stdout });
    }

    // Parse a trailing line when the stream ends without a final '\n'.
    if (!saw_done and line_buf.items.len > 0) {
        const trailing = parseSseLine(allocator, line_buf.items) catch null;
        line_buf.clearRetainingCapacity();
        if (trailing) |result| {
            switch (result) {
                .delta => |text| {
                    defer allocator.free(text);
                    try accumulated.appendSlice(allocator, text);
                    callback(ctx, root.StreamChunk.textDelta(text));
                },
                .usage => |u| stream_usage = u,
                .done => {},
                .skip => {},
            }
        }
    }

    // Drain remaining stdout to prevent deadlock on wait()
    while (true) {
        const n = stdout_file.read(&read_buf) catch break;
        if (n == 0) break;
        if (log_enabled) {
            debug_log.info("drained {d} more stdout bytes", .{n});
        }
    }

    if (log_enabled) {
        debug_log.info("waiting for curl process to exit...", .{});
    }
    const term = child.wait() catch |err| {
        log.err("curlStream child.wait failed: {}", .{err});
        if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
            log.warn("curlStream proceeding despite wait failure after partial stream output", .{});
            callback(ctx, root.StreamChunk.finalChunk());
            return finalizeStreamResult(allocator, accumulated.items, stream_usage);
        }
        return error.CurlWaitError;
    };
    if (log_enabled) {
        debug_log.info("curl process terminated: {}", .{term});
    }
    switch (term) {
        .exited => |code| if (code != 0) {
            if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
                log.warn("curlStream exit code {d} after partial stream output; returning accumulated output", .{code});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, stream_usage);
            }
            return error.CurlFailed;
        },
        else => {
            if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
                log.warn("curlStream abnormal termination after partial stream output; returning accumulated output", .{});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, stream_usage);
            }
            return error.CurlFailed;
        },
    }

    // Signal stream completion only after curl exits successfully.
    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, stream_usage);
}

// ════════════════════════════════════════════════════════════════════════════
// Anthropic SSE Parsing
// ════════════════════════════════════════════════════════════════════════════

/// Result of parsing a single Anthropic SSE line.
pub const AnthropicSseResult = union(enum) {
    /// Remember this event type (caller tracks state).
    event: []const u8,
    /// Text delta content (owned, caller frees).
    delta: []const u8,
    /// Output token count from message_delta usage.
    usage: u32,
    /// Stream is complete (message_stop).
    done: void,
    /// Line should be skipped (empty, comment, or uninteresting event).
    skip: void,
};

/// Parse a single SSE line in Anthropic streaming format.
///
/// Anthropic SSE is stateful: `event:` lines set the context for subsequent `data:` lines.
/// The caller must track `current_event` across calls.
///
/// - `event: X` → `.event` (caller remembers X)
/// - `data: {JSON}` + current_event=="content_block_delta" → extracts `delta.text` → `.delta`
/// - `data: {JSON}` + current_event=="message_delta" → extracts `usage.output_tokens` → `.usage`
/// - `data: {JSON}` + current_event=="message_stop" → `.done`
/// - Everything else → `.skip`
pub fn parseAnthropicSseLine(allocator: std.mem.Allocator, line: []const u8, current_event: []const u8) !AnthropicSseResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // Handle "event: TYPE" lines
    const event_prefix = "event: ";
    if (std.mem.startsWith(u8, trimmed, event_prefix)) {
        return .{ .event = trimmed[event_prefix.len..] };
    }

    // Handle "data: {JSON}" lines
    const data_prefix = "data: ";
    if (!std.mem.startsWith(u8, trimmed, data_prefix)) return .skip;

    const data = trimmed[data_prefix.len..];

    if (std.mem.eql(u8, current_event, "message_stop")) return .done;

    if (std.mem.eql(u8, current_event, "content_block_delta")) {
        const text = try extractAnthropicDelta(allocator, data) orelse return .skip;
        return .{ .delta = text };
    }

    if (std.mem.eql(u8, current_event, "message_delta")) {
        const tokens = try extractAnthropicUsage(data) orelse return .skip;
        return .{ .usage = tokens };
    }

    return .skip;
}

/// Extract `delta.text` from an Anthropic content_block_delta JSON payload.
/// Returns owned slice or null if not a text_delta.
pub fn extractAnthropicDelta(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const delta = obj.get("delta") orelse return null;
    if (delta != .object) return null;

    const dtype = delta.object.get("type") orelse return null;
    if (dtype != .string or !std.mem.eql(u8, dtype.string, "text_delta")) return null;

    const text = delta.object.get("text") orelse return null;
    if (text != .string) return null;
    if (text.string.len == 0) return null;

    return try allocator.dupe(u8, text.string);
}

/// Extract `usage.output_tokens` from an Anthropic message_delta JSON payload.
/// Returns token count or null if not present.
pub fn extractAnthropicUsage(json_str: []const u8) !?u32 {
    // Use a stack buffer for parsing to avoid needing an allocator
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const usage = obj.get("usage") orelse return null;
    if (usage != .object) return null;

    const output_tokens = usage.object.get("output_tokens") orelse return null;
    if (output_tokens != .integer) return null;

    return @intCast(output_tokens.integer);
}

/// Run curl in SSE streaming mode for Anthropic and parse output line by line.
///
/// Similar to `curlStream()` but uses stateful Anthropic SSE parsing.
/// `headers` is a slice of pre-formatted header strings (e.g. "x-api-key: sk-...").
pub fn curlStreamAnthropic(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    // Build argv on stack (max 40 args)
    var argv_buf: [40][]const u8 = undefined;
    var argc: usize = 0;

    argv_buf[argc] = "curl";
    argc += 1;
    argv_buf[argc] = "-s";
    argc += 1;
    argv_buf[argc] = "--no-buffer";
    argc += 1;
    argv_buf[argc] = "-X";
    argc += 1;
    argv_buf[argc] = "POST";
    argc += 1;
    argv_buf[argc] = "-H";
    argc += 1;
    argv_buf[argc] = "Content-Type: application/json";
    argc += 1;

    // Add proxy from environment if set
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    if (proxy) |p| {
        argv_buf[argc] = "--proxy";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);
    http_util.appendCurlResolveArgs(argv_buf[0..], &argc, resolve_entry);

    for (headers) |hdr| {
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = hdr;
        argc += 1;
    }

    const log_enabled = verbose.isVerbose();
    var prepared_body = try prepareCurlBodyArg(allocator, body, log_enabled);
    defer prepared_body.deinit(allocator);

    if (prepared_body.uses_temp_file) {
        argv_buf[argc] = "--data-binary";
    } else {
        argv_buf[argc] = "-d";
    }
    argc += 1;
    argv_buf[argc] = prepared_body.arg;
    argc += 1;
    argv_buf[argc] = url;
    argc += 1;

    var child = std_compat.process.Child.init(argv_buf[0..argc], allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    // Read stdout line by line, parse Anthropic SSE events
    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    var current_event: []const u8 = "";
    var anthropic_usage: root.TokenUsage = .{};
    var saw_done = false;

    const file = child.stdout.?;
    var read_buf: [4096]u8 = undefined;

    outer: while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                const result = parseAnthropicSseLine(allocator, line_buf.items, current_event) catch {
                    line_buf.clearRetainingCapacity();
                    continue;
                };
                switch (result) {
                    .event => |ev| {
                        // Dupe event name — it points into line_buf which we're about to clear
                        if (current_event.len > 0) allocator.free(@constCast(current_event));
                        current_event = allocator.dupe(u8, ev) catch "";
                    },
                    .delta => |text| {
                        defer allocator.free(text);
                        try accumulated.appendSlice(allocator, text);
                        callback(ctx, root.StreamChunk.textDelta(text));
                    },
                    .usage => |tokens| anthropic_usage.completion_tokens = tokens,
                    .done => {
                        saw_done = true;
                        line_buf.clearRetainingCapacity();
                        break :outer;
                    },
                    .skip => {},
                }
                line_buf.clearRetainingCapacity();
            } else {
                try line_buf.append(allocator, byte);
            }
        }
    }

    // Free owned event string
    if (current_event.len > 0) allocator.free(@constCast(current_event));

    // Drain remaining stdout to prevent deadlock on wait()
    while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;
    }

    const term = child.wait() catch |err| {
        log.err("curlStreamAnthropic child.wait failed: {}", .{err});
        if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
            log.warn("curlStreamAnthropic proceeding despite wait failure after partial stream output", .{});
            callback(ctx, root.StreamChunk.finalChunk());
            return finalizeStreamResult(allocator, accumulated.items, anthropic_usage);
        }
        return error.CurlWaitError;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
                log.warn("curlStreamAnthropic exit code {d} after partial stream output; returning accumulated output", .{code});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, anthropic_usage);
            }
            return error.CurlFailed;
        },
        else => {
            if (root.shouldRecoverPartialStream(accumulated.items.len, saw_done)) {
                log.warn("curlStreamAnthropic abnormal termination after partial stream output; returning accumulated output", .{});
                callback(ctx, root.StreamChunk.finalChunk());
                return finalizeStreamResult(allocator, accumulated.items, anthropic_usage);
            }
            return error.CurlFailed;
        },
    }

    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, anthropic_usage);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseSseLine valid delta" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine valid delta without optional space" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data:{\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "prepareCurlBodyArg keeps small bodies inline except on Windows" {
    const allocator = std.testing.allocator;
    const body = [_]u8{'x'} ** 4096;
    var prepared = try prepareCurlBodyArg(allocator, body[0..], false);
    defer prepared.deinit(allocator);

    if (builtin.os.tag == .windows) {
        try std.testing.expect(prepared.uses_temp_file);
        try std.testing.expect(std.mem.startsWith(u8, prepared.arg, "@"));
    } else {
        try std.testing.expect(!prepared.uses_temp_file);
        try std.testing.expectEqualStrings(body[0..], prepared.arg);
    }
}

test "prepareCurlBodyArg spills large bodies to temp file" {
    const allocator = std.testing.allocator;
    const body = [_]u8{'x'} ** (MAX_INLINE_CURL_BODY_BYTES + 1);
    var prepared = try prepareCurlBodyArg(allocator, body[0..], false);
    defer prepared.deinit(allocator);

    try std.testing.expect(prepared.uses_temp_file);
    try std.testing.expect(std.mem.startsWith(u8, prepared.arg, "@"));
}

test "appendCurlStallDetectionArgs appends curl speed flags in order" {
    // Regression: stalled SSE streams must trip curl's speed-limit instead of
    // hanging until --max-time expires with an idle-but-open connection.
    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;
    appendCurlStallDetectionArgs(argv_buf[0..], &argc);

    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("--speed-limit", argv_buf[0]);
    try std.testing.expectEqualStrings("1", argv_buf[1]);
    try std.testing.expectEqualStrings("--speed-time", argv_buf[2]);
    try std.testing.expectEqualStrings("60", argv_buf[3]);
}

test "parseSseLine DONE sentinel" {
    const result = try parseSseLine(std.testing.allocator, "data: [DONE]");
    try std.testing.expect(result == .done);
}

test "parseSseLine DONE sentinel without optional space" {
    const result = try parseSseLine(std.testing.allocator, "data:[DONE]");
    try std.testing.expect(result == .done);
}

test "curlVersionSupportsFailWithBody rejects curl older than 7.76.0" {
    try std.testing.expect(!curlVersionSupportsFailWithBody("curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0"));
}

test "curlVersionSupportsFailWithBody accepts curl 7.76.0 and newer" {
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 7.76.0 (x86_64-pc-linux-gnu) libcurl/7.76.0"));
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 8.17.0 (x86_64-alpine-linux-musl) libcurl/8.17.0"));
}

test "curlVersionSupportsFailWithBody tolerates suffixes in version token" {
    try std.testing.expect(curlVersionSupportsFailWithBody("curl 8.17.0-DEV (x86_64) libcurl/8.17.0"));
}

test "parseSseLine empty line" {
    const result = try parseSseLine(std.testing.allocator, "");
    try std.testing.expect(result == .skip);
}

test "parseSseLine comment" {
    const result = try parseSseLine(std.testing.allocator, ":keep-alive");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty data field" {
    const result = try parseSseLine(std.testing.allocator, "data:");
    try std.testing.expect(result == .skip);
}

test "parseSseLine delta without content" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[{\"delta\":{}}]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty choices" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine invalid JSON" {
    try std.testing.expectError(error.InvalidSseJson, parseSseLine(std.testing.allocator, "data: not-json{{{"));
}

test "extractDeltaContent with content" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"world\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("world", result);
}

test "extractDeltaContent without content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent empty content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent falls back to reasoning_content when content empty" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"\",\"reasoning_content\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

// Regression: OpenRouter's documented chat stream uses delta.reasoning.
test "extractDeltaContent falls back to reasoning when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

test "extractDeltaContent falls back to reasoning_content when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

// Regression: OpenRouter's current normalized streaming shape uses reasoning_details.
test "extractDeltaContent falls back to reasoning_details when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(
        allocator,
        "{\"choices\":[{\"delta\":{\"reasoning_details\":[{\"type\":\"reasoning.summary\",\"summary\":\"plan\"},{\"type\":\"reasoning.text\",\"text\":\"step by step\"}]}}]}",
    )).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>plan\nstep by step</think>", result);
}

test "extractDeltaContent prefers visible content over reasoning_content" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"final answer\",\"reasoning_content\":\"private\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("final answer", result);
}

test "extractDeltaContent empty reasoning_content returns null" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "StreamChunk textDelta token estimate" {
    const chunk = root.StreamChunk.textDelta("12345678");
    try std.testing.expect(chunk.token_count == 2);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqualStrings("12345678", chunk.delta);
}

test "StreamChunk finalChunk" {
    const chunk = root.StreamChunk.finalChunk();
    try std.testing.expect(chunk.is_final);
    try std.testing.expectEqualStrings("", chunk.delta);
    try std.testing.expect(chunk.token_count == 0);
}

// ── Anthropic SSE Tests ─────────────────────────────────────────

test "parseAnthropicSseLine event line returns event" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "event: content_block_delta", "");
    switch (result) {
        .event => |ev| try std.testing.expectEqualStrings("content_block_delta", ev),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with content_block_delta returns delta" {
    const allocator = std.testing.allocator;
    const json = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}";
    const result = try parseAnthropicSseLine(allocator, json, "content_block_delta");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with message_delta returns usage" {
    const json = "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":42}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_delta");
    switch (result) {
        .usage => |tokens| try std.testing.expect(tokens == 42),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with message_stop returns done" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "data: {\"type\":\"message_stop\"}", "message_stop");
    try std.testing.expect(result == .done);
}

test "parseAnthropicSseLine empty line returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine comment returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, ":keep-alive", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine data with unknown event returns skip" {
    const json = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\"}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_start");
    try std.testing.expect(result == .skip);
}

test "extractAnthropicDelta correct JSON returns text" {
    const allocator = std.testing.allocator;
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}";
    const result = (try extractAnthropicDelta(allocator, json)).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("world", result);
}

test "extractAnthropicDelta without text returns null" {
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}";
    const result = try extractAnthropicDelta(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "extractAnthropicUsage correct JSON returns token count" {
    const json = "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":57}}";
    const result = (try extractAnthropicUsage(json)).?;
    try std.testing.expect(result == 57);
}

// ── Stream Usage Extraction Tests ───────────────────────────────

test "extractStreamUsage returns full usage from final chunk" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":263,\"total_tokens\":363}}";
    const usage = extractStreamUsage(json).?;
    try std.testing.expectEqual(@as(u32, 100), usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 263), usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 363), usage.total_tokens);
}

test "extractStreamUsage returns null for chunk without usage" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}";
    try std.testing.expect(extractStreamUsage(json) == null);
}

test "extractStreamUsage returns null for invalid JSON" {
    try std.testing.expect(extractStreamUsage("not-json{{{") == null);
}

test "finalizeStreamResult separates think blocks into reasoning content" {
    const result = try finalizeStreamResult(
        std.testing.allocator,
        "<think>private trace</think>Visible answer",
        .{ .completion_tokens = 4, .total_tokens = 4 },
    );
    defer {
        if (result.content) |content| std.testing.allocator.free(content);
        if (result.reasoning_content) |reasoning| std.testing.allocator.free(reasoning);
    }

    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expectEqualStrings("private trace", result.reasoning_content.?);
}

test "parseSseLine extracts usage from final chunk" {
    const allocator = std.testing.allocator;
    const line = "data: {\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":20,\"total_tokens\":70}}";
    const result = try parseSseLine(allocator, line);
    switch (result) {
        .usage => |u| {
            try std.testing.expectEqual(@as(u32, 50), u.prompt_tokens);
            try std.testing.expectEqual(@as(u32, 20), u.completion_tokens);
            try std.testing.expectEqual(@as(u32, 70), u.total_tokens);
        },
        else => return error.TestUnexpectedResult,
    }
}
