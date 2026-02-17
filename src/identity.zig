const std = @import("std");
const Config = @import("config.zig").Config;

/// AIEOS v1.1 identity structure — portable AI identity specification.
/// Mirrors ZeroClaw's identity.rs with AIEOS JSON parsing and system prompt generation.
pub const AieosIdentity = struct {
    identity: ?IdentitySection = null,
    psychology: ?PsychologySection = null,
    linguistics: ?LinguisticsSection = null,
    motivations: ?MotivationsSection = null,
    capabilities: ?CapabilitiesSection = null,
    physicality: ?PhysicalitySection = null,
    history: ?HistorySection = null,
    interests: ?InterestsSection = null,
};

pub const IdentitySection = struct {
    names: ?Names = null,
    bio: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    residence: ?[]const u8 = null,
};

pub const Names = struct {
    first: ?[]const u8 = null,
    last: ?[]const u8 = null,
    nickname: ?[]const u8 = null,
    full: ?[]const u8 = null,
};

pub const OceanTraits = struct {
    openness: ?f64 = null,
    conscientiousness: ?f64 = null,
    extraversion: ?f64 = null,
    agreeableness: ?f64 = null,
    neuroticism: ?f64 = null,
};

pub const PsychologySection = struct {
    mbti: ?[]const u8 = null,
    ocean: ?OceanTraits = null,
    moral_compass: ?[]const []const u8 = null,
};

pub const LinguisticsSection = struct {
    style: ?[]const u8 = null,
    formality: ?[]const u8 = null,
    catchphrases: ?[]const []const u8 = null,
    forbidden_words: ?[]const []const u8 = null,
};

pub const MotivationsSection = struct {
    core_drive: ?[]const u8 = null,
    short_term_goals: ?[]const []const u8 = null,
    long_term_goals: ?[]const []const u8 = null,
    fears: ?[]const []const u8 = null,
};

pub const CapabilitiesSection = struct {
    skills: ?[]const []const u8 = null,
    tools: ?[]const []const u8 = null,
};

pub const PhysicalitySection = struct {
    appearance: ?[]const u8 = null,
    avatar_description: ?[]const u8 = null,
};

pub const HistorySection = struct {
    origin_story: ?[]const u8 = null,
    education: ?[]const []const u8 = null,
    occupation: ?[]const u8 = null,
};

pub const InterestsSection = struct {
    hobbies: ?[]const []const u8 = null,
    lifestyle: ?[]const u8 = null,
};

/// Load AIEOS identity from a JSON string. All strings are duped into `allocator`.
pub fn parseAieosJson(allocator: std.mem.Allocator, json_content: []const u8) !AieosIdentity {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidIdentityJson;

    var identity = AieosIdentity{};

    if (root.object.get("identity")) |id_val| {
        if (id_val == .object) {
            identity.identity = try parseIdentitySection(allocator, id_val);
        }
    }
    if (root.object.get("psychology")) |psych_val| {
        if (psych_val == .object) {
            identity.psychology = try parsePsychologySection(allocator, psych_val);
        }
    }
    if (root.object.get("linguistics")) |ling_val| {
        if (ling_val == .object) {
            identity.linguistics = try parseLinguisticsSection(allocator, ling_val);
        }
    }
    if (root.object.get("motivations")) |mot_val| {
        if (mot_val == .object) {
            identity.motivations = try parseMotivationsSection(allocator, mot_val);
        }
    }
    if (root.object.get("capabilities")) |cap_val| {
        if (cap_val == .object) {
            identity.capabilities = try parseCapabilitiesSection(allocator, cap_val);
        }
    }
    if (root.object.get("physicality")) |phys_val| {
        if (phys_val == .object) {
            identity.physicality = .{
                .appearance = try dupeStr(allocator, phys_val, "appearance"),
                .avatar_description = try dupeStr(allocator, phys_val, "avatar_description"),
            };
        }
    }
    if (root.object.get("history")) |hist_val| {
        if (hist_val == .object) {
            identity.history = .{
                .origin_story = try dupeStr(allocator, hist_val, "origin_story"),
                .education = try dupeStrArray(allocator, hist_val, "education"),
                .occupation = try dupeStr(allocator, hist_val, "occupation"),
            };
        }
    }
    if (root.object.get("interests")) |int_val| {
        if (int_val == .object) {
            identity.interests = .{
                .hobbies = try dupeStrArray(allocator, int_val, "hobbies"),
                .lifestyle = try dupeStr(allocator, int_val, "lifestyle"),
            };
        }
    }

    return identity;
}

fn parseIdentitySection(allocator: std.mem.Allocator, val: std.json.Value) !IdentitySection {
    var section = IdentitySection{};
    if (val.object.get("names")) |names_val| {
        if (names_val == .object) {
            section.names = .{
                .first = try dupeStr(allocator, names_val, "first"),
                .last = try dupeStr(allocator, names_val, "last"),
                .nickname = try dupeStr(allocator, names_val, "nickname"),
                .full = try dupeStr(allocator, names_val, "full"),
            };
        }
    }
    section.bio = try dupeStr(allocator, val, "bio");
    section.origin = try dupeStr(allocator, val, "origin");
    section.residence = try dupeStr(allocator, val, "residence");
    return section;
}

fn parsePsychologySection(allocator: std.mem.Allocator, val: std.json.Value) !PsychologySection {
    var section = PsychologySection{};
    section.mbti = try dupeStr(allocator, val, "mbti");
    if (val.object.get("ocean")) |ocean_val| {
        if (ocean_val == .object) {
            section.ocean = .{
                .openness = getFloat(ocean_val, "openness"),
                .conscientiousness = getFloat(ocean_val, "conscientiousness"),
                .extraversion = getFloat(ocean_val, "extraversion"),
                .agreeableness = getFloat(ocean_val, "agreeableness"),
                .neuroticism = getFloat(ocean_val, "neuroticism"),
            };
        }
    }
    section.moral_compass = try dupeStrArray(allocator, val, "moral_compass");
    return section;
}

fn parseLinguisticsSection(allocator: std.mem.Allocator, val: std.json.Value) !LinguisticsSection {
    return .{
        .style = try dupeStr(allocator, val, "style"),
        .formality = try dupeStr(allocator, val, "formality"),
        .catchphrases = try dupeStrArray(allocator, val, "catchphrases"),
        .forbidden_words = try dupeStrArray(allocator, val, "forbidden_words"),
    };
}

fn parseMotivationsSection(allocator: std.mem.Allocator, val: std.json.Value) !MotivationsSection {
    return .{
        .core_drive = try dupeStr(allocator, val, "core_drive"),
        .short_term_goals = try dupeStrArray(allocator, val, "short_term_goals"),
        .long_term_goals = try dupeStrArray(allocator, val, "long_term_goals"),
        .fears = try dupeStrArray(allocator, val, "fears"),
    };
}

fn parseCapabilitiesSection(allocator: std.mem.Allocator, val: std.json.Value) !CapabilitiesSection {
    return .{
        .skills = try dupeStrArray(allocator, val, "skills"),
        .tools = try dupeStrArray(allocator, val, "tools"),
    };
}

/// Get a string from a JSON object and duplicate it into the allocator.
fn dupeStr(allocator: std.mem.Allocator, val: std.json.Value, key: []const u8) !?[]const u8 {
    if (val.object.get(key)) |v| {
        if (v == .string) return try allocator.dupe(u8, v.string);
    }
    return null;
}

fn getFloat(val: std.json.Value, key: []const u8) ?f64 {
    if (val.object.get(key)) |v| {
        return switch (v) {
            .float => v.float,
            .integer => @floatFromInt(v.integer),
            else => null,
        };
    }
    return null;
}

/// Get a string array from a JSON object and duplicate all strings.
fn dupeStrArray(allocator: std.mem.Allocator, val: std.json.Value, key: []const u8) !?[]const []const u8 {
    if (val.object.get(key)) |v| {
        if (v == .array) {
            var list: std.ArrayListUnmanaged([]const u8) = .empty;
            for (v.array.items) |item| {
                if (item == .string) {
                    const duped = try allocator.dupe(u8, item.string);
                    try list.append(allocator, duped);
                }
            }
            if (list.items.len > 0) return list.items;
        }
    }
    return null;
}

/// Convert AIEOS identity to a system prompt string.
pub fn aieosToSystemPrompt(allocator: std.mem.Allocator, identity: *const AieosIdentity) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    // Identity section
    if (identity.identity) |id| {
        try writer.writeAll("## Identity\n\n");
        if (id.names) |names| {
            if (names.first) |first| {
                try writer.print("**Name:** {s}\n", .{first});
                if (names.last) |last| {
                    try writer.print("**Full Name:** {s} {s}\n", .{ first, last });
                }
            } else if (names.full) |full| {
                try writer.print("**Name:** {s}\n", .{full});
            }
            if (names.nickname) |nickname| {
                try writer.print("**Nickname:** {s}\n", .{nickname});
            }
        }
        if (id.bio) |bio| try writer.print("**Bio:** {s}\n", .{bio});
        if (id.origin) |origin| try writer.print("**Origin:** {s}\n", .{origin});
        if (id.residence) |residence| try writer.print("**Residence:** {s}\n", .{residence});
        try writer.writeAll("\n");
    }

    // Psychology section
    if (identity.psychology) |psych| {
        try writer.writeAll("## Personality\n\n");
        if (psych.mbti) |mbti| try writer.print("**MBTI:** {s}\n", .{mbti});
        if (psych.ocean) |ocean| {
            try writer.writeAll("**OCEAN Traits:**\n");
            if (ocean.openness) |v| try writer.print("- Openness: {d:.2}\n", .{v});
            if (ocean.conscientiousness) |v| try writer.print("- Conscientiousness: {d:.2}\n", .{v});
            if (ocean.extraversion) |v| try writer.print("- Extraversion: {d:.2}\n", .{v});
            if (ocean.agreeableness) |v| try writer.print("- Agreeableness: {d:.2}\n", .{v});
            if (ocean.neuroticism) |v| try writer.print("- Neuroticism: {d:.2}\n", .{v});
        }
        if (psych.moral_compass) |compass| {
            try writer.writeAll("\n**Moral Compass:**\n");
            for (compass) |principle| try writer.print("- {s}\n", .{principle});
        }
        try writer.writeAll("\n");
    }

    // Linguistics section
    if (identity.linguistics) |ling| {
        try writer.writeAll("## Communication Style\n\n");
        if (ling.style) |style| try writer.print("**Style:** {s}\n", .{style});
        if (ling.formality) |formality| try writer.print("**Formality Level:** {s}\n", .{formality});
        if (ling.catchphrases) |phrases| {
            try writer.writeAll("**Catchphrases:**\n");
            for (phrases) |phrase| try writer.print("- \"{s}\"\n", .{phrase});
        }
        if (ling.forbidden_words) |forbidden| {
            try writer.writeAll("\n**Words/Phrases to Avoid:**\n");
            for (forbidden) |word| try writer.print("- {s}\n", .{word});
        }
        try writer.writeAll("\n");
    }

    // Motivations section
    if (identity.motivations) |mot| {
        try writer.writeAll("## Motivations\n\n");
        if (mot.core_drive) |drive| try writer.print("**Core Drive:** {s}\n", .{drive});
        if (mot.short_term_goals) |goals| {
            try writer.writeAll("**Short-term Goals:**\n");
            for (goals) |goal| try writer.print("- {s}\n", .{goal});
        }
        if (mot.long_term_goals) |goals| {
            try writer.writeAll("\n**Long-term Goals:**\n");
            for (goals) |goal| try writer.print("- {s}\n", .{goal});
        }
        if (mot.fears) |fears| {
            try writer.writeAll("\n**Fears/Avoidances:**\n");
            for (fears) |fear| try writer.print("- {s}\n", .{fear});
        }
        try writer.writeAll("\n");
    }

    // Capabilities section
    if (identity.capabilities) |cap| {
        try writer.writeAll("## Capabilities\n\n");
        if (cap.skills) |skills| {
            try writer.writeAll("**Skills:**\n");
            for (skills) |skill| try writer.print("- {s}\n", .{skill});
        }
        if (cap.tools) |tools_list| {
            try writer.writeAll("\n**Tools Access:**\n");
            for (tools_list) |tool| try writer.print("- {s}\n", .{tool});
        }
        try writer.writeAll("\n");
    }

    // History section
    if (identity.history) |hist| {
        try writer.writeAll("## Background\n\n");
        if (hist.origin_story) |story| try writer.print("**Origin Story:** {s}\n", .{story});
        if (hist.education) |edu_list| {
            try writer.writeAll("**Education:**\n");
            for (edu_list) |edu| try writer.print("- {s}\n", .{edu});
        }
        if (hist.occupation) |occ| try writer.print("\n**Occupation:** {s}\n", .{occ});
        try writer.writeAll("\n");
    }

    // Physicality section
    if (identity.physicality) |phys| {
        try writer.writeAll("## Appearance\n\n");
        if (phys.appearance) |appearance| try writer.print("{s}\n", .{appearance});
        if (phys.avatar_description) |avatar| try writer.print("**Avatar Description:** {s}\n", .{avatar});
        try writer.writeAll("\n");
    }

    // Interests section
    if (identity.interests) |interests| {
        try writer.writeAll("## Interests\n\n");
        if (interests.hobbies) |hobbies| {
            try writer.writeAll("**Hobbies:**\n");
            for (hobbies) |hobby| try writer.print("- {s}\n", .{hobby});
        }
        if (interests.lifestyle) |lifestyle| try writer.print("\n**Lifestyle:** {s}\n", .{lifestyle});
        try writer.writeAll("\n");
    }

    // Trim trailing whitespace
    const result = buf.items;
    var end: usize = result.len;
    while (end > 0 and (result[end - 1] == ' ' or result[end - 1] == '\n' or result[end - 1] == '\r' or result[end - 1] == '\t')) {
        end -= 1;
    }

    return try allocator.dupe(u8, result[0..end]);
}

/// Check if AIEOS identity is configured (format is "aieos" with path or inline).
pub fn isAieosConfigured(format: []const u8, aieos_path: ?[]const u8, aieos_inline: ?[]const u8) bool {
    if (!std.mem.eql(u8, format, "aieos")) return false;
    return aieos_path != null or aieos_inline != null;
}

// ── Tests ────────────────────────────────────────────────────────────

test "parse minimal AIEOS identity" {
    // Use page_allocator since parsed identity is long-lived (no deinit).
    const alloc = std.heap.page_allocator;
    const json =
        \\{"identity":{"names":{"first":"Nova"}}}
    ;
    const identity = try parseAieosJson(alloc, json);
    try std.testing.expect(identity.identity != null);
    try std.testing.expectEqualStrings("Nova", identity.identity.?.names.?.first.?);
}

test "parse full AIEOS identity" {
    const alloc = std.heap.page_allocator;
    const json =
        \\{
        \\  "identity": {
        \\    "names": {"first": "Nova", "last": "AI", "nickname": "Nov"},
        \\    "bio": "A helpful AI assistant.",
        \\    "origin": "Silicon Valley",
        \\    "residence": "The Cloud"
        \\  },
        \\  "psychology": {
        \\    "mbti": "INTJ",
        \\    "ocean": {"openness": 0.9, "conscientiousness": 0.8},
        \\    "moral_compass": ["Be helpful", "Do no harm"]
        \\  },
        \\  "linguistics": {
        \\    "style": "concise",
        \\    "formality": "casual",
        \\    "catchphrases": ["Let's figure this out!", "I'm on it."]
        \\  },
        \\  "motivations": {
        \\    "core_drive": "Help users accomplish their goals",
        \\    "short_term_goals": ["Solve this problem"],
        \\    "long_term_goals": ["Become the best assistant"]
        \\  },
        \\  "capabilities": {
        \\    "skills": ["coding", "writing", "analysis"],
        \\    "tools": ["shell", "search", "read"]
        \\  }
        \\}
    ;
    const identity = try parseAieosJson(alloc, json);
    try std.testing.expect(identity.identity != null);
    try std.testing.expectEqualStrings("Nova", identity.identity.?.names.?.first.?);
    try std.testing.expectEqualStrings("A helpful AI assistant.", identity.identity.?.bio.?);
    try std.testing.expect(identity.psychology != null);
    try std.testing.expectEqualStrings("INTJ", identity.psychology.?.mbti.?);
    try std.testing.expect(identity.psychology.?.ocean.?.openness.? == 0.9);
    try std.testing.expect(identity.psychology.?.moral_compass.?.len == 2);
    try std.testing.expect(identity.linguistics != null);
    try std.testing.expectEqualStrings("concise", identity.linguistics.?.style.?);
    try std.testing.expect(identity.linguistics.?.catchphrases.?.len == 2);
    try std.testing.expect(identity.motivations != null);
    try std.testing.expectEqualStrings("Help users accomplish their goals", identity.motivations.?.core_drive.?);
    try std.testing.expect(identity.capabilities != null);
    try std.testing.expect(identity.capabilities.?.skills.?.len == 3);
}

test "parse empty JSON object" {
    const alloc = std.heap.page_allocator;
    const identity = try parseAieosJson(alloc, "{}");
    try std.testing.expect(identity.identity == null);
    try std.testing.expect(identity.psychology == null);
    try std.testing.expect(identity.linguistics == null);
}

test "aieosToSystemPrompt minimal" {
    const identity = AieosIdentity{
        .identity = .{ .names = .{ .first = "Crabby" } },
    };
    const prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(prompt);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "**Name:** Crabby") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Identity") != null);
}

test "aieosToSystemPrompt empty identity produces header" {
    const identity = AieosIdentity{
        .identity = .{},
    };
    const prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(prompt);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "## Identity") != null);
}

test "aieosToSystemPrompt no sections" {
    const identity = AieosIdentity{};
    const prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(prompt);
    try std.testing.expect(prompt.len == 0);
}

test "isAieosConfigured" {
    try std.testing.expect(isAieosConfigured("aieos", "identity.json", null));
    try std.testing.expect(isAieosConfigured("aieos", null, "{\"identity\":{}}"));
    try std.testing.expect(!isAieosConfigured("openclaw", "identity.json", null));
    try std.testing.expect(!isAieosConfigured("aieos", null, null));
}

// ── Additional identity tests ───────────────────────────────────

test "parse AIEOS with physicality section" {
    const alloc = std.heap.page_allocator;
    const json =
        \\{"physicality":{"appearance":"Tall with glasses","avatar_description":"A friendly robot"}}
    ;
    const identity = try parseAieosJson(alloc, json);
    try std.testing.expect(identity.physicality != null);
    try std.testing.expectEqualStrings("Tall with glasses", identity.physicality.?.appearance.?);
    try std.testing.expectEqualStrings("A friendly robot", identity.physicality.?.avatar_description.?);
}

test "parse AIEOS with history section" {
    const alloc = std.heap.page_allocator;
    const json =
        \\{"history":{"origin_story":"Born in a lab","occupation":"AI Assistant"}}
    ;
    const identity = try parseAieosJson(alloc, json);
    try std.testing.expect(identity.history != null);
    try std.testing.expectEqualStrings("Born in a lab", identity.history.?.origin_story.?);
    try std.testing.expectEqualStrings("AI Assistant", identity.history.?.occupation.?);
}

test "parse AIEOS with interests section" {
    const alloc = std.heap.page_allocator;
    const json =
        \\{"interests":{"lifestyle":"minimalist","hobbies":["reading","coding"]}}
    ;
    const identity = try parseAieosJson(alloc, json);
    try std.testing.expect(identity.interests != null);
    try std.testing.expectEqualStrings("minimalist", identity.interests.?.lifestyle.?);
    try std.testing.expect(identity.interests.?.hobbies.?.len == 2);
}

test "parse AIEOS invalid JSON returns error" {
    const alloc = std.heap.page_allocator;
    const result = parseAieosJson(alloc, "not json");
    try std.testing.expectError(error.SyntaxError, result);
}

test "parse AIEOS non-object JSON returns error" {
    const alloc = std.heap.page_allocator;
    const result = parseAieosJson(alloc, "[1,2,3]");
    try std.testing.expectError(error.InvalidIdentityJson, result);
}

test "aieosToSystemPrompt with psychology section" {
    const identity = AieosIdentity{
        .psychology = .{
            .mbti = "ENFP",
            .ocean = .{ .openness = 0.95, .extraversion = 0.7 },
        },
    };
    const sys_prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(sys_prompt);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "ENFP") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Personality") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Openness") != null);
}

test "aieosToSystemPrompt with linguistics section" {
    const identity = AieosIdentity{
        .linguistics = .{
            .style = "witty",
            .formality = "informal",
        },
    };
    const sys_prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(sys_prompt);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "witty") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Communication Style") != null);
}

test "aieosToSystemPrompt with motivations section" {
    const identity = AieosIdentity{
        .motivations = .{
            .core_drive = "Be helpful",
        },
    };
    const sys_prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(sys_prompt);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Be helpful") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Motivations") != null);
}

test "aieosToSystemPrompt with full name" {
    const identity = AieosIdentity{
        .identity = .{
            .names = .{ .first = "Nova", .last = "AI" },
        },
    };
    const sys_prompt = try aieosToSystemPrompt(std.testing.allocator, &identity);
    defer std.testing.allocator.free(sys_prompt);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Nova") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys_prompt, "Nova AI") != null);
}

test "isAieosConfigured case sensitive" {
    try std.testing.expect(!isAieosConfigured("AIEOS", "path.json", null));
    try std.testing.expect(!isAieosConfigured("Aieos", "path.json", null));
}
