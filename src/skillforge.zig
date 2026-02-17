const std = @import("std");

// SkillForge -- skill auto-discovery, evaluation, and integration engine.
//
// Mirrors ZeroClaw's skillforge module: Scout -> Evaluate -> Integrate pipeline.
// Discovers skills from external sources, scores them, and generates
// compatible manifests for qualified candidates.

// ── Configuration ───────────────────────────────────────────────

pub const SkillForgeConfig = struct {
    enabled: bool = false,
    auto_integrate: bool = true,
    scan_interval_hours: u64 = 24,
    min_score: f64 = 0.7,
    output_dir: []const u8 = "./skills",
};

// ── Scout Types ─────────────────────────────────────────────────

pub const ScoutSource = enum {
    github,
    clawhub,
    huggingface,

    pub fn fromString(s: []const u8) ScoutSource {
        if (eqlLower(s, "github")) return .github;
        if (eqlLower(s, "clawhub")) return .clawhub;
        if (eqlLower(s, "huggingface") or eqlLower(s, "hf")) return .huggingface;
        return .github; // fallback
    }

    pub fn name(self: ScoutSource) []const u8 {
        return switch (self) {
            .github => "github",
            .clawhub => "clawhub",
            .huggingface => "huggingface",
        };
    }
};

pub const ScoutResult = struct {
    result_name: []const u8,
    url: []const u8,
    description: []const u8,
    stars: u64 = 0,
    language: ?[]const u8 = null,
    source: ScoutSource = .github,
    owner: []const u8 = "unknown",
    has_license: bool = false,
};

/// A skill candidate with parsed metadata from scout results.
pub const SkillCandidate = struct {
    result_name: []const u8,
    repo_url: []const u8,
    description: []const u8,
    stars: u64 = 0,
    updated_at: ?[]const u8 = null,
    language: ?[]const u8 = null,
    owner: []const u8 = "unknown",
    has_license: bool = false,
    has_build_zig: bool = false,
    has_root_zig: bool = false,
};

// ── Scout ────────────────────────────────────────────────────────

/// Scout: search GitHub for nullclaw-compatible skill repositories.
/// Uses api.github.com/search/repositories?q=QUERY+topic:nullclaw
pub fn scout(allocator: std.mem.Allocator, query: []const u8) !std.ArrayList(SkillCandidate) {
    var candidates: std.ArrayList(SkillCandidate) = .empty;
    errdefer candidates.deinit(allocator);

    // Build the search URL
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/search/repositories?q={s}+topic:nullclaw&sort=stars&order=desc&per_page=30",
        .{encoded_query},
    );
    defer allocator.free(url);

    // Fetch from GitHub API using std.http.Client
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .extra_headers = &.{
            .{ .name = "User-Agent", .value = "nullclaw/0.1" },
            .{ .name = "Accept", .value = "application/vnd.github.v3+json" },
        },
        .response_writer = &aw.writer,
    }) catch {
        // Network unavailable — return empty list gracefully
        return candidates;
    };

    if (result.status != .ok) {
        return candidates;
    }

    // Parse the response body
    const body = aw.writer.buffer[0..aw.writer.end];
    if (body.len == 0) return candidates;

    // Parse GitHub search results JSON — extract "items" array entries
    try parseGitHubSearchResults(allocator, body, &candidates);

    return candidates;
}

/// Parse GitHub API /search/repositories JSON response into SkillCandidate entries.
/// Uses minimal manual parsing to avoid pulling in std.json for the full response.
fn parseGitHubSearchResults(allocator: std.mem.Allocator, body: []const u8, candidates: *std.ArrayList(SkillCandidate)) !void {
    // Look for each "full_name" occurrence which marks a repo item
    var pos: usize = 0;
    while (pos < body.len) {
        // Find next repo entry by looking for "full_name"
        const full_name_needle = "\"full_name\"";
        const fn_pos = std.mem.indexOfPos(u8, body, pos, full_name_needle) orelse break;

        // Extract fields from this item region
        // Find the enclosing item boundaries (look back for '{' and forward for next item or end)
        const item_start = std.mem.lastIndexOfScalar(u8, body[0..fn_pos], '{') orelse {
            pos = fn_pos + full_name_needle.len;
            continue;
        };

        // Find the end of this item — look for the next "full_name" or end of items array
        const next_item = std.mem.indexOfPos(u8, body, fn_pos + full_name_needle.len, full_name_needle);
        const item_end = if (next_item) |ni|
            std.mem.lastIndexOfScalar(u8, body[0..ni], '{') orelse body.len
        else
            body.len;

        const item = body[item_start..item_end];

        // Extract repo fields
        const repo_name = extractJsonString(item, "name") orelse {
            pos = fn_pos + full_name_needle.len;
            continue;
        };
        const html_url = extractJsonString(item, "html_url") orelse {
            pos = fn_pos + full_name_needle.len;
            continue;
        };
        const description_raw = extractJsonString(item, "description") orelse "";
        const language = extractJsonString(item, "language");
        const owner_login = blk: {
            // Owner is a nested object; find "login" after "owner"
            if (std.mem.indexOf(u8, item, "\"owner\"")) |owner_pos| {
                const after_owner = item[owner_pos..];
                break :blk extractJsonString(after_owner, "login");
            }
            break :blk null;
        };
        const stars = extractJsonNumber(item, "stargazers_count");
        const has_license = std.mem.indexOf(u8, item, "\"license\"") != null and
            std.mem.indexOf(u8, item, "\"license\":null") == null and
            std.mem.indexOf(u8, item, "\"license\": null") == null;

        try candidates.append(allocator, .{
            .result_name = try allocator.dupe(u8, repo_name),
            .repo_url = try allocator.dupe(u8, html_url),
            .description = try allocator.dupe(u8, description_raw),
            .stars = stars,
            .language = if (language) |l| try allocator.dupe(u8, l) else null,
            .owner = if (owner_login) |o| try allocator.dupe(u8, o) else "unknown",
            .has_license = has_license,
        });

        pos = fn_pos + full_name_needle.len;
    }
}

/// Extract a JSON string value for a given key from a JSON fragment.
fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or
        after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1)
    {}

    if (i >= after_key.len or after_key[i] != '"') return null;
    i += 1; // skip opening quote

    const start = i;
    while (i < after_key.len) : (i += 1) {
        if (after_key[i] == '\\' and i + 1 < after_key.len) {
            i += 1;
            continue;
        }
        if (after_key[i] == '"') {
            return after_key[start..i];
        }
    }
    return null;
}

/// Extract a JSON integer value for a given key.
fn extractJsonNumber(json: []const u8, key: []const u8) u64 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return 0;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return 0;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or
        after_key[i] == '\t' or after_key[i] == '\n')) : (i += 1)
    {}

    // Parse number
    const start = i;
    while (i < after_key.len and after_key[i] >= '0' and after_key[i] <= '9') : (i += 1) {}
    if (i == start) return 0;
    return std.fmt.parseInt(u64, after_key[start..i], 10) catch 0;
}

/// Build the GitHub search URL for a query.
pub fn buildGitHubSearchUrl(allocator: std.mem.Allocator, query: []const u8) ![]u8 {
    const encoded = try urlEncode(allocator, query);
    defer allocator.free(encoded);

    return std.fmt.allocPrint(
        allocator,
        "https://api.github.com/search/repositories?q={s}+topic:nullclaw&sort=stars&order=desc&per_page=30",
        .{encoded},
    );
}

// ── Evaluation ──────────────────────────────────────────────────

pub const Recommendation = enum {
    auto,
    manual,
    skip,
};

pub const Scores = struct {
    compatibility: f64,
    quality: f64,
    security: f64,

    /// Weighted total. Weights: compatibility 0.3, quality 0.35, security 0.35.
    pub fn total(self: Scores) f64 {
        return self.compatibility * 0.30 + self.quality * 0.35 + self.security * 0.35;
    }
};

pub const EvalResult = struct {
    candidate: ScoutResult,
    scores: Scores,
    total_score: f64,
    recommendation: Recommendation,
};

/// Known-bad patterns in repo names/descriptions.
const bad_patterns = [_][]const u8{
    "malware", "exploit", "hack", "crack", "keygen", "ransomware", "trojan",
};

/// Check if haystack contains word as a whole word (bounded by non-alphanumeric).
pub fn containsWord(haystack: []const u8, word: []const u8) bool {
    var pos: usize = 0;
    while (pos < haystack.len) {
        if (std.mem.indexOfPos(u8, haystack, pos, word)) |i| {
            const before_ok = i == 0 or !std.ascii.isAlphanumeric(haystack[i - 1]);
            const after = i + word.len;
            const after_ok = after >= haystack.len or !std.ascii.isAlphanumeric(haystack[after]);
            if (before_ok and after_ok) return true;
            pos = i + 1;
        } else {
            break;
        }
    }
    return false;
}

/// Score compatibility dimension.
/// Zig repos get full score; check for build.zig presence in candidates.
fn scoreCompatibility(candidate: ScoutResult) f64 {
    const lang = candidate.language orelse return 0.2;
    if (std.mem.eql(u8, lang, "Zig")) return 1.0;
    if (std.mem.eql(u8, lang, "Rust")) return 1.0;
    if (std.mem.eql(u8, lang, "Python") or std.mem.eql(u8, lang, "TypeScript") or std.mem.eql(u8, lang, "JavaScript")) return 0.6;
    return 0.3;
}

/// Score quality dimension (star-based, log scale).
fn scoreQuality(candidate: ScoutResult) f64 {
    const stars_f: f64 = @floatFromInt(candidate.stars);
    const raw = @log2(stars_f + 1.0) / 10.0;
    return @min(raw, 1.0);
}

/// Score security dimension.
fn scoreSecurity(candidate: ScoutResult) f64 {
    var score: f64 = 0.5;

    // License bonus
    if (candidate.has_license) score += 0.3;

    // Bad pattern penalty (whole-word match)
    const lower_name = candidate.result_name;
    const lower_desc = candidate.description;
    for (bad_patterns) |pat| {
        if (containsWord(lower_name, pat) or containsWord(lower_desc, pat)) {
            score -= 0.5;
            break;
        }
    }

    return std.math.clamp(score, 0.0, 1.0);
}

/// Evaluate a scout result and produce an EvalResult with recommendation.
pub fn evaluate(candidate: ScoutResult, min_score: f64) EvalResult {
    const scores = Scores{
        .compatibility = scoreCompatibility(candidate),
        .quality = scoreQuality(candidate),
        .security = scoreSecurity(candidate),
    };
    const total_score = scores.total();

    const recommendation: Recommendation = if (total_score >= min_score)
        .auto
    else if (total_score >= 0.4)
        .manual
    else
        .skip;

    return .{
        .candidate = candidate,
        .scores = scores,
        .total_score = total_score,
        .recommendation = recommendation,
    };
}

/// Evaluate a SkillCandidate with enhanced compatibility scoring.
pub fn evaluateCandidate(candidate: SkillCandidate, min_score: f64) EvalResult {
    // Enhanced compatibility: check for Zig build files
    var compat: f64 = 0.2;
    if (candidate.language) |lang| {
        if (std.mem.eql(u8, lang, "Zig")) {
            compat = 1.0;
        } else if (std.mem.eql(u8, lang, "Rust")) {
            compat = 1.0;
        } else if (std.mem.eql(u8, lang, "Python") or std.mem.eql(u8, lang, "TypeScript")) {
            compat = 0.6;
        } else {
            compat = 0.3;
        }
    }
    // Bonus for having build.zig or root.zig
    if (candidate.has_build_zig or candidate.has_root_zig) {
        compat = @min(compat + 0.2, 1.0);
    }

    const stars_f: f64 = @floatFromInt(candidate.stars);
    const quality = @min(@log2(stars_f + 1.0) / 10.0, 1.0);

    var security: f64 = 0.5;
    if (candidate.has_license) security += 0.3;
    for (bad_patterns) |pat| {
        if (containsWord(candidate.result_name, pat) or containsWord(candidate.description, pat)) {
            security -= 0.5;
            break;
        }
    }
    security = std.math.clamp(security, 0.0, 1.0);

    const scores = Scores{ .compatibility = compat, .quality = quality, .security = security };
    const total_score = scores.total();

    const recommendation: Recommendation = if (total_score >= min_score)
        .auto
    else if (total_score >= 0.4)
        .manual
    else
        .skip;

    return .{
        .candidate = .{
            .result_name = candidate.result_name,
            .url = candidate.repo_url,
            .description = candidate.description,
            .stars = candidate.stars,
            .language = candidate.language,
            .owner = candidate.owner,
            .has_license = candidate.has_license,
        },
        .scores = scores,
        .total_score = total_score,
        .recommendation = recommendation,
    };
}

// ── Integration ─────────────────────────────────────────────────

/// Integrate a skill: clone repo to skills_dir/NAME/,
/// verify structure (expects skill.json, root.zig, or build.zig).
pub fn integrate(allocator: std.mem.Allocator, candidate: SkillCandidate, skills_dir: []const u8) !IntegrationResult {
    const safe_name = try sanitizePathComponent(candidate.result_name);

    // Ensure skills directory exists
    std.fs.makeDirAbsolute(skills_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return IntegrationResult{
            .skill_name = safe_name,
            .install_path = skills_dir,
            .success = false,
            .error_message = "Failed to create skills directory",
        },
    };

    // Build target path: skills_dir/NAME
    const target_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ skills_dir, safe_name });
    defer allocator.free(target_path);

    // Clone the repository using git
    var child = std.process.Child.init(
        &.{ "git", "clone", "--depth", "1", candidate.repo_url, target_path },
        allocator,
    );
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;

    child.spawn() catch {
        return IntegrationResult{
            .skill_name = safe_name,
            .install_path = skills_dir,
            .success = false,
            .error_message = "Failed to spawn git clone",
        };
    };
    const term = child.wait() catch {
        return IntegrationResult{
            .skill_name = safe_name,
            .install_path = skills_dir,
            .success = false,
            .error_message = "Failed to wait for git clone",
        };
    };

    if (term.Exited != 0) {
        return IntegrationResult{
            .skill_name = safe_name,
            .install_path = skills_dir,
            .success = false,
            .error_message = "git clone exited with non-zero status",
        };
    }

    // Verify the cloned repo has expected structure
    const has_skill_json = hasFile(target_path, "skill.json");
    const has_build_zig = hasFile(target_path, "build.zig");
    const has_root_zig = hasFile(target_path, "root.zig");

    if (!has_skill_json and !has_build_zig and !has_root_zig) {
        // Remove the cloned directory since it lacks expected structure
        std.fs.deleteTreeAbsolute(target_path) catch {};
        return IntegrationResult{
            .skill_name = safe_name,
            .install_path = skills_dir,
            .success = false,
            .error_message = "Cloned repo lacks skill.json, build.zig, or root.zig",
        };
    }

    return IntegrationResult{
        .skill_name = safe_name,
        .install_path = skills_dir,
        .success = true,
    };
}

/// Check if a file exists in a directory.
fn hasFile(dir_path: []const u8, filename: []const u8) bool {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const full = std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir_path, filename }) catch return false;
    std.fs.accessAbsolute(full, .{}) catch return false;
    return true;
}

pub const IntegrationResult = struct {
    skill_name: []const u8,
    install_path: []const u8,
    success: bool,
    error_message: ?[]const u8 = null,
};

// ── Integration Helpers ─────────────────────────────────────────

/// Escape special characters for TOML basic string values.
pub fn escapeToml(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    for (s) |c| {
        switch (c) {
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '"' => try result.appendSlice(allocator, "\\\""),
            '\n' => try result.appendSlice(allocator, "\\n"),
            '\r' => try result.appendSlice(allocator, "\\r"),
            '\t' => try result.appendSlice(allocator, "\\t"),
            0x08 => try result.appendSlice(allocator, "\\b"),
            0x0C => try result.appendSlice(allocator, "\\f"),
            else => try result.append(allocator, c),
        }
    }
    return try result.toOwnedSlice(allocator);
}

/// Sanitize a string for use as a single path component.
/// Rejects empty names, "..", and names containing path separators or NUL.
pub fn sanitizePathComponent(s: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, s, " \t.");
    if (trimmed.len == 0) return error.EmptyName;

    // Check for unsafe patterns
    for (trimmed) |c| {
        if (c == '/' or c == '\\' or c == 0) return error.UnsafePath;
    }
    if (std.mem.eql(u8, trimmed, "..")) return error.UnsafePath;

    return trimmed;
}

// ── ForgeReport ─────────────────────────────────────────────────

pub const ForgeReport = struct {
    discovered: usize = 0,
    evaluated: usize = 0,
    auto_integrated: usize = 0,
    manual_review: usize = 0,
    skipped: usize = 0,
};

/// Run the forge pipeline: scout -> evaluate -> integrate.
pub fn forge(allocator: std.mem.Allocator, cfg: SkillForgeConfig) !ForgeReport {
    if (!cfg.enabled) {
        return .{};
    }

    // Scout phase
    var candidates = try scout(allocator, "nullclaw skill");
    defer candidates.deinit(allocator);

    var report = ForgeReport{};
    report.discovered = candidates.items.len;

    // Evaluate phase
    for (candidates.items) |candidate| {
        report.evaluated += 1;
        const result = evaluateCandidate(candidate, cfg.min_score);
        switch (result.recommendation) {
            .auto => {
                if (cfg.auto_integrate) {
                    const int_result = integrate(allocator, candidate, cfg.output_dir) catch {
                        report.skipped += 1;
                        continue;
                    };
                    if (int_result.success) {
                        report.auto_integrated += 1;
                    } else {
                        report.skipped += 1;
                    }
                } else {
                    report.manual_review += 1;
                }
            },
            .manual => report.manual_review += 1,
            .skip => report.skipped += 1,
        }
    }

    return report;
}

// ── Helpers ─────────────────────────────────────────────────────

fn eqlLower(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

/// Minimal percent-encoding for query strings (space -> +).
pub fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    for (s) |c| {
        switch (c) {
            ' ' => try result.append(allocator, '+'),
            '&' => try result.appendSlice(allocator, "%26"),
            '#' => try result.appendSlice(allocator, "%23"),
            else => try result.append(allocator, c),
        }
    }
    return try result.toOwnedSlice(allocator);
}

/// Deduplicate scout results by URL (keeps first occurrence).
pub fn dedup(allocator: std.mem.Allocator, results: *std.ArrayList(ScoutResult)) !void {
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var i: usize = 0;
    while (i < results.items.len) {
        const url = results.items[i].url;
        if (seen.contains(url)) {
            _ = results.orderedRemove(i);
        } else {
            try seen.put(url, {});
            i += 1;
        }
    }
}

/// Deduplicate skill candidates by repo URL (keeps first occurrence).
pub fn dedupCandidates(allocator: std.mem.Allocator, results: *std.ArrayList(SkillCandidate)) !void {
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var i: usize = 0;
    while (i < results.items.len) {
        const url = results.items[i].repo_url;
        if (seen.contains(url)) {
            _ = results.orderedRemove(i);
        } else {
            try seen.put(url, {});
            i += 1;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

test "ScoutSource.fromString github" {
    try std.testing.expectEqual(ScoutSource.github, ScoutSource.fromString("github"));
    try std.testing.expectEqual(ScoutSource.github, ScoutSource.fromString("GitHub"));
}

test "ScoutSource.fromString clawhub" {
    try std.testing.expectEqual(ScoutSource.clawhub, ScoutSource.fromString("clawhub"));
}

test "ScoutSource.fromString huggingface" {
    try std.testing.expectEqual(ScoutSource.huggingface, ScoutSource.fromString("huggingface"));
    try std.testing.expectEqual(ScoutSource.huggingface, ScoutSource.fromString("hf"));
}

test "ScoutSource.fromString unknown defaults to github" {
    try std.testing.expectEqual(ScoutSource.github, ScoutSource.fromString("unknown"));
}

test "ScoutSource.name" {
    try std.testing.expectEqualStrings("github", ScoutSource.github.name());
    try std.testing.expectEqualStrings("clawhub", ScoutSource.clawhub.name());
    try std.testing.expectEqualStrings("huggingface", ScoutSource.huggingface.name());
}

test "scores total weighted" {
    const s = Scores{ .compatibility = 1.0, .quality = 1.0, .security = 1.0 };
    try std.testing.expect(@abs(s.total() - 1.0) < 0.001);

    const s2 = Scores{ .compatibility = 0.0, .quality = 0.0, .security = 0.0 };
    try std.testing.expect(@abs(s2.total()) < 0.001);
}

test "high quality Rust repo gets auto" {
    const c = ScoutResult{
        .result_name = "test-skill",
        .url = "https://github.com/test/test-skill",
        .description = "A test skill",
        .stars = 500,
        .language = "Rust",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(res.total_score >= 0.7);
    try std.testing.expectEqual(Recommendation.auto, res.recommendation);
}

test "low star no license gets manual or skip" {
    const c = ScoutResult{
        .result_name = "test-skill",
        .url = "https://github.com/test/test-skill",
        .description = "A test skill",
        .stars = 1,
        .language = null,
        .has_license = false,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(res.total_score < 0.7);
    try std.testing.expect(res.recommendation != .auto);
}

test "bad pattern tanks security" {
    const c = ScoutResult{
        .result_name = "malware-skill",
        .url = "https://github.com/test/malware",
        .description = "A bad skill",
        .stars = 1000,
        .language = "Rust",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(res.scores.security <= 0.5);
}

test "hackathon not flagged as bad" {
    const c = ScoutResult{
        .result_name = "hackathon-tools",
        .url = "https://github.com/test/hackathon-tools",
        .description = "Tools for hackathons and lifehacks",
        .stars = 500,
        .language = "Rust",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    // "hack" should NOT match "hackathon" or "lifehacks" (whole-word only)
    try std.testing.expect(res.scores.security >= 0.5);
}

test "exact hack is flagged" {
    const c = ScoutResult{
        .result_name = "hack-tool",
        .url = "https://github.com/test/hack-tool",
        .description = "A hacking tool",
        .stars = 500,
        .language = "Rust",
        .has_license = false,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(res.scores.security < 0.5);
}

test "containsWord basic" {
    try std.testing.expect(containsWord("hello world", "hello"));
    try std.testing.expect(containsWord("hello world", "world"));
    try std.testing.expect(!containsWord("helloworld", "hello"));
}

test "containsWord with hyphens" {
    try std.testing.expect(containsWord("hack-tool", "hack"));
    try std.testing.expect(!containsWord("hackathon", "hack"));
    try std.testing.expect(!containsWord("lifehacks", "hack"));
}

test "containsWord at boundaries" {
    try std.testing.expect(containsWord("hack", "hack"));
    try std.testing.expect(containsWord("hack!", "hack"));
    try std.testing.expect(containsWord("!hack", "hack"));
}

test "escapeToml handles quotes and control chars" {
    const allocator = std.testing.allocator;

    const r1 = try escapeToml(allocator, "say \"hello\"");
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("say \\\"hello\\\"", r1);

    const r2 = try escapeToml(allocator, "back\\slash");
    defer allocator.free(r2);
    try std.testing.expectEqualStrings("back\\\\slash", r2);

    const r3 = try escapeToml(allocator, "line\nbreak");
    defer allocator.free(r3);
    try std.testing.expectEqualStrings("line\\nbreak", r3);

    const r4 = try escapeToml(allocator, "tab\there");
    defer allocator.free(r4);
    try std.testing.expectEqualStrings("tab\\there", r4);

    const r5 = try escapeToml(allocator, "cr\rhere");
    defer allocator.free(r5);
    try std.testing.expectEqualStrings("cr\\rhere", r5);
}

test "sanitizePathComponent rejects traversal" {
    try std.testing.expectError(error.EmptyName, sanitizePathComponent(".."));
    try std.testing.expectError(error.EmptyName, sanitizePathComponent("..."));
    try std.testing.expectError(error.EmptyName, sanitizePathComponent(""));
    try std.testing.expectError(error.EmptyName, sanitizePathComponent("  "));
}

test "sanitizePathComponent rejects separators" {
    try std.testing.expectError(error.UnsafePath, sanitizePathComponent("foo/bar"));
    try std.testing.expectError(error.UnsafePath, sanitizePathComponent("foo\\bar"));
}

test "sanitizePathComponent accepts valid names" {
    const result = try sanitizePathComponent("test-skill");
    try std.testing.expectEqualStrings("test-skill", result);
}

test "sanitizePathComponent trims dots" {
    const result = try sanitizePathComponent(".hidden.");
    try std.testing.expectEqualStrings("hidden", result);
}

test "urlEncode works" {
    const allocator = std.testing.allocator;

    const r1 = try urlEncode(allocator, "hello world");
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("hello+world", r1);

    const r2 = try urlEncode(allocator, "a&b#c");
    defer allocator.free(r2);
    try std.testing.expectEqualStrings("a%26b%23c", r2);
}

test "dedup removes duplicates" {
    const allocator = std.testing.allocator;
    var results: std.ArrayList(ScoutResult) = .empty;
    defer results.deinit(allocator);

    try results.append(allocator, .{ .result_name = "a", .url = "https://github.com/x/a", .description = "" });
    try results.append(allocator, .{ .result_name = "a-dup", .url = "https://github.com/x/a", .description = "" });
    try results.append(allocator, .{ .result_name = "b", .url = "https://github.com/x/b", .description = "" });

    try dedup(allocator, &results);
    try std.testing.expectEqual(@as(usize, 2), results.items.len);
    try std.testing.expectEqualStrings("a", results.items[0].result_name);
    try std.testing.expectEqualStrings("b", results.items[1].result_name);
}

test "default config values" {
    const cfg = SkillForgeConfig{};
    try std.testing.expect(!cfg.enabled);
    try std.testing.expect(cfg.auto_integrate);
    try std.testing.expectEqual(@as(u64, 24), cfg.scan_interval_hours);
    try std.testing.expect(@abs(cfg.min_score - 0.7) < 0.001);
}

test "forge disabled returns empty report" {
    const allocator = std.testing.allocator;
    const cfg = SkillForgeConfig{};
    const report = try forge(allocator, cfg);
    try std.testing.expectEqual(@as(usize, 0), report.discovered);
    try std.testing.expectEqual(@as(usize, 0), report.auto_integrated);
}

test "forge enabled returns empty report (no network)" {
    const allocator = std.testing.allocator;
    const cfg = SkillForgeConfig{ .enabled = true };
    const report = try forge(allocator, cfg);
    try std.testing.expectEqual(@as(usize, 0), report.discovered);
}

test "Zig language gets full compatibility score" {
    const c = ScoutResult{
        .result_name = "zig-skill",
        .url = "https://github.com/test/zig-skill",
        .description = "A Zig skill",
        .stars = 100,
        .language = "Zig",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(@abs(res.scores.compatibility - 1.0) < 0.001);
}

test "Python gets moderate compatibility score" {
    const c = ScoutResult{
        .result_name = "py-skill",
        .url = "https://github.com/test/py-skill",
        .description = "A Python skill",
        .stars = 100,
        .language = "Python",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(@abs(res.scores.compatibility - 0.6) < 0.001);
}

test "unknown language gets low compatibility" {
    const c = ScoutResult{
        .result_name = "cobol-skill",
        .url = "https://github.com/test/cobol-skill",
        .description = "A COBOL skill",
        .stars = 100,
        .language = "COBOL",
        .has_license = true,
    };
    const res = evaluate(c, 0.7);
    try std.testing.expect(@abs(res.scores.compatibility - 0.3) < 0.001);
}

// ── Scout / Integration tests ───────────────────────────────────

test "buildGitHubSearchUrl encodes query" {
    const allocator = std.testing.allocator;
    const url = try buildGitHubSearchUrl(allocator, "nullclaw skill");
    defer allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "nullclaw+skill") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "api.github.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "topic:nullclaw") != null);
}

test "buildGitHubSearchUrl handles special chars" {
    const allocator = std.testing.allocator;
    const url = try buildGitHubSearchUrl(allocator, "foo & bar");
    defer allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "foo+%26+bar") != null);
}

test "scout returns empty list (no network)" {
    const allocator = std.testing.allocator;
    var candidates = try scout(allocator, "test");
    defer candidates.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), candidates.items.len);
}

test "evaluateCandidate with build.zig gets compatibility boost" {
    const candidate = SkillCandidate{
        .result_name = "zig-tool",
        .repo_url = "https://github.com/test/zig-tool",
        .description = "A Zig tool",
        .stars = 100,
        .language = "Zig",
        .has_license = true,
        .has_build_zig = true,
    };
    const res = evaluateCandidate(candidate, 0.7);
    try std.testing.expect(res.scores.compatibility >= 1.0);
}

test "evaluateCandidate without language" {
    const candidate = SkillCandidate{
        .result_name = "unknown-tool",
        .repo_url = "https://github.com/test/unknown",
        .description = "Tool",
        .stars = 10,
    };
    const res = evaluateCandidate(candidate, 0.7);
    try std.testing.expect(res.scores.compatibility < 0.5);
}

test "dedupCandidates removes duplicates" {
    const allocator = std.testing.allocator;
    var candidates: std.ArrayList(SkillCandidate) = .empty;
    defer candidates.deinit(allocator);

    try candidates.append(allocator, .{
        .result_name = "a",
        .repo_url = "https://github.com/x/a",
        .description = "",
    });
    try candidates.append(allocator, .{
        .result_name = "a-dup",
        .repo_url = "https://github.com/x/a",
        .description = "",
    });
    try candidates.append(allocator, .{
        .result_name = "b",
        .repo_url = "https://github.com/x/b",
        .description = "",
    });

    try dedupCandidates(allocator, &candidates);
    try std.testing.expectEqual(@as(usize, 2), candidates.items.len);
    try std.testing.expectEqualStrings("a", candidates.items[0].result_name);
}

test "SkillCandidate defaults" {
    const c = SkillCandidate{
        .result_name = "test",
        .repo_url = "url",
        .description = "desc",
    };
    try std.testing.expect(!c.has_build_zig);
    try std.testing.expect(!c.has_root_zig);
    try std.testing.expect(!c.has_license);
    try std.testing.expectEqual(@as(u64, 0), c.stars);
}

test "IntegrationResult fields" {
    const r = IntegrationResult{
        .skill_name = "test-skill",
        .install_path = "/tmp/skills",
        .success = true,
    };
    try std.testing.expect(r.success);
    try std.testing.expect(r.error_message == null);
}
