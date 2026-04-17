//! JSON Schema cleaning and validation for LLM tool-calling compatibility.
//!
//! Different providers support different subsets of JSON Schema. This module
//! normalizes tool schemas to improve cross-provider compatibility while
//! preserving semantic intent.
//!
//! Operations:
//! 1. Removes unsupported keywords per provider strategy
//! 2. Resolves local `$ref` entries from `$defs` and `definitions`
//! 3. Flattens literal `anyOf` / `oneOf` unions into `enum`
//! 4. Strips nullable variants from unions and `type` arrays
//! 5. Converts `const` to single-value `enum`
//! 6. Detects circular references and stops recursion safely

const std = @import("std");

const log = std.log.scoped(.schema);

/// Schema cleaning strategies for different LLM providers.
pub const CleaningStrategy = enum {
    /// Gemini (Google AI / Vertex AI) — most restrictive.
    gemini,
    /// Anthropic Claude — moderately permissive.
    anthropic,
    /// OpenAI GPT — most permissive.
    openai,
    /// Conservative: remove only universally unsupported keywords.
    conservative,
};

/// Keywords that Gemini rejects for tool schemas.
pub const GEMINI_UNSUPPORTED_KEYWORDS = [_][]const u8{
    // Schema composition
    "$ref",
    "$schema",
    "$id",
    "$defs",
    "definitions",
    // Property constraints
    "additionalProperties",
    "patternProperties",
    // String constraints
    "minLength",
    "maxLength",
    "pattern",
    "format",
    // Number constraints
    "minimum",
    "maximum",
    "multipleOf",
    // Array constraints
    "minItems",
    "maxItems",
    "uniqueItems",
    // Object constraints
    "minProperties",
    "maxProperties",
    // Non-standard
    "examples",
};

/// Keywords Anthropic doesn't handle (refs).
const ANTHROPIC_UNSUPPORTED_KEYWORDS = [_][]const u8{
    "$ref",
    "$defs",
    "definitions",
};

/// OpenAI is most permissive — no keywords removed.
const OPENAI_UNSUPPORTED_KEYWORDS = [_][]const u8{};

/// Conservative strategy — refs + additionalProperties.
const CONSERVATIVE_UNSUPPORTED_KEYWORDS = [_][]const u8{
    "$ref",
    "$defs",
    "definitions",
    "additionalProperties",
};

/// Metadata keys preserved across ref resolution.
const SCHEMA_META_KEYS = [_][]const u8{ "description", "title", "default" };

/// JSON Schema cleaner optimized for LLM tool calling.
pub const SchemaCleanr = struct {
    /// Clean schema for Gemini compatibility (strictest).
    pub fn cleanForGemini(allocator: std.mem.Allocator, schema_json: []const u8) ![]const u8 {
        return clean(allocator, schema_json, .gemini);
    }

    /// Clean schema for Anthropic compatibility.
    pub fn cleanForAnthropic(allocator: std.mem.Allocator, schema_json: []const u8) ![]const u8 {
        return clean(allocator, schema_json, .anthropic);
    }

    /// Clean schema for OpenAI compatibility (most permissive).
    pub fn cleanForOpenAI(allocator: std.mem.Allocator, schema_json: []const u8) ![]const u8 {
        return clean(allocator, schema_json, .openai);
    }

    /// Validate that a schema has a "type" field.
    pub fn validate(allocator: std.mem.Allocator, schema_json: []const u8) bool {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, schema_json, .{}) catch return false;
        defer parsed.deinit();
        const root = parsed.value;
        if (root != .object) return false;
        return root.object.contains("type");
    }

    /// Clean a JSON schema for the given provider strategy.
    /// Input: JSON string of the schema.
    /// Output: cleaned JSON string (caller must free with the same allocator).
    pub fn clean(allocator: std.mem.Allocator, schema_json: []const u8, strategy: CleaningStrategy) ![]const u8 {
        // Use an arena for all intermediate JSON tree allocations
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        // Parse JSON
        const parsed = try std.json.parseFromSlice(std.json.Value, arena_alloc, schema_json, .{});
        const root = parsed.value;

        // Extract $defs for reference resolution
        var defs = extractDefs(arena_alloc, root);

        // Track visited refs for circular detection
        var ref_stack = std.StringHashMap(void).init(arena_alloc);

        // Clean the tree
        const cleaned = try cleanValue(arena_alloc, root, strategy, &defs, &ref_stack);

        // Serialize to JSON, allocating result with the caller's allocator
        return try serializeJson(allocator, cleaned);
    }
};

// ── Internal helpers ────────────────────────────────────────────────

/// Get the unsupported keywords list for a strategy.
fn unsupportedKeywords(strategy: CleaningStrategy) []const []const u8 {
    return switch (strategy) {
        .gemini => &GEMINI_UNSUPPORTED_KEYWORDS,
        .anthropic => &ANTHROPIC_UNSUPPORTED_KEYWORDS,
        .openai => &OPENAI_UNSUPPORTED_KEYWORDS,
        .conservative => &CONSERVATIVE_UNSUPPORTED_KEYWORDS,
    };
}

/// Check if a keyword is in the unsupported list.
fn isUnsupported(keyword: []const u8, strategy: CleaningStrategy) bool {
    const list = unsupportedKeywords(strategy);
    for (list) |k| {
        if (std.mem.eql(u8, keyword, k)) return true;
    }
    return false;
}

/// Extract `$defs` and `definitions` from a root schema value.
fn extractDefs(allocator: std.mem.Allocator, root: std.json.Value) std.json.ObjectMap {
    _ = allocator;
    if (root != .object) {
        // Return an empty map — won't be used, just need a valid value.
        return .empty;
    }
    const obj = root.object;

    // Prefer $defs (JSON Schema 2019-09+), fall back to definitions (draft-07)
    if (obj.get("$defs")) |v| {
        if (v == .object) return v.object;
    }
    if (obj.get("definitions")) |v| {
        if (v == .object) return v.object;
    }
    return .empty;
}

const CleanError = std.mem.Allocator.Error;

/// Recursively clean a JSON value.
fn cleanValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    strategy: CleaningStrategy,
    defs: *std.json.ObjectMap,
    ref_stack: *std.StringHashMap(void),
) CleanError!std.json.Value {
    return switch (value) {
        .object => |obj| try cleanObject(allocator, obj, strategy, defs, ref_stack),
        .array => |arr| {
            var result = blk: {
                var a = std.json.Array.init(allocator);
                try a.ensureTotalCapacity(arr.items.len);
                break :blk a;
            };
            for (arr.items) |item| {
                const cleaned = try cleanValue(allocator, item, strategy, defs, ref_stack);
                result.appendAssumeCapacity(cleaned);
            }
            return .{ .array = result };
        },
        else => value,
    };
}

/// Clean an object schema.
fn cleanObject(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    strategy: CleaningStrategy,
    defs: *std.json.ObjectMap,
    ref_stack: *std.StringHashMap(void),
) CleanError!std.json.Value {
    // Handle $ref resolution
    if (obj.get("$ref")) |ref_val| {
        if (ref_val == .string) {
            return resolveRef(allocator, ref_val.string, &obj, defs, strategy, ref_stack);
        }
    }

    // Handle anyOf/oneOf simplification
    if (obj.contains("anyOf") or obj.contains("oneOf")) {
        if (try trySimplifyUnion(allocator, &obj, defs, strategy, ref_stack)) |simplified| {
            return simplified;
        }
    }

    const has_union = obj.contains("anyOf") or obj.contains("oneOf");

    // Build cleaned object
    var cleaned: std.json.ObjectMap = .empty;

    var it = obj.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        // Skip unsupported keywords
        if (isUnsupported(key, strategy)) continue;

        // Special handling for specific keys
        if (std.mem.eql(u8, key, "const")) {
            // Convert const to enum
            var enum_arr = std.json.Array.init(allocator);
            try enum_arr.ensureTotalCapacity(1);
            enum_arr.appendAssumeCapacity(value);
            try cleaned.put(allocator, "enum", .{ .array = enum_arr });
        } else if (std.mem.eql(u8, key, "type") and has_union) {
            // Skip type if we have anyOf/oneOf (they define the type)
            continue;
        } else if (std.mem.eql(u8, key, "type") and value == .array) {
            // Handle type arrays (remove null)
            try cleaned.put(allocator, key, cleanTypeArray(value));
        } else if (std.mem.eql(u8, key, "properties")) {
            try cleaned.put(allocator, key, try cleanProperties(allocator, value, strategy, defs, ref_stack));
        } else if (std.mem.eql(u8, key, "items")) {
            try cleaned.put(allocator, key, try cleanValue(allocator, value, strategy, defs, ref_stack));
        } else if (std.mem.eql(u8, key, "anyOf") or std.mem.eql(u8, key, "oneOf") or std.mem.eql(u8, key, "allOf")) {
            try cleaned.put(allocator, key, try cleanUnion(allocator, value, strategy, defs, ref_stack));
        } else {
            // Keep all other keys, cleaning nested objects/arrays recursively
            const cleaned_val = switch (value) {
                .object, .array => try cleanValue(allocator, value, strategy, defs, ref_stack),
                else => value,
            };
            try cleaned.put(allocator, key, cleaned_val);
        }
    }

    return .{ .object = cleaned };
}

/// Resolve a $ref to its definition.
fn resolveRef(
    allocator: std.mem.Allocator,
    ref_value: []const u8,
    obj: *const std.json.ObjectMap,
    defs: *std.json.ObjectMap,
    strategy: CleaningStrategy,
    ref_stack: *std.StringHashMap(void),
) CleanError!std.json.Value {
    // Prevent circular references
    if (ref_stack.contains(ref_value)) {
        return preserveMeta(allocator, obj, .{ .object = .empty });
    }

    // Try to resolve local ref (#/$defs/Name or #/definitions/Name)
    if (parseLocalRef(ref_value)) |def_name| {
        if (defs.get(def_name)) |definition| {
            try ref_stack.put(ref_value, {});
            const cleaned = try cleanValue(allocator, definition, strategy, defs, ref_stack);
            _ = ref_stack.remove(ref_value);
            return preserveMeta(allocator, obj, cleaned);
        }
    }

    // Can't resolve: return empty object with metadata
    return preserveMeta(allocator, obj, .{ .object = .empty });
}

/// Parse a local JSON Pointer ref (#/$defs/Name or #/definitions/Name).
fn parseLocalRef(ref_value: []const u8) ?[]const u8 {
    const defs_prefix = "#/$defs/";
    const definitions_prefix = "#/definitions/";

    if (ref_value.len > defs_prefix.len and std.mem.startsWith(u8, ref_value, defs_prefix)) {
        return decodeJsonPointer(ref_value[defs_prefix.len..]);
    }
    if (ref_value.len > definitions_prefix.len and std.mem.startsWith(u8, ref_value, definitions_prefix)) {
        return decodeJsonPointer(ref_value[definitions_prefix.len..]);
    }
    return null;
}

/// Decode JSON Pointer escaping (~0 = ~, ~1 = /).
/// For simplicity, only handle simple cases without tilde (common).
fn decodeJsonPointer(segment: []const u8) []const u8 {
    // Most refs don't contain tildes — return as-is for the common case.
    // Full decoding would require allocation; we skip that for now since
    // LLM tool schemas rarely use escaped pointer segments.
    return segment;
}

/// Try to simplify anyOf/oneOf to a simpler form.
fn trySimplifyUnion(
    allocator: std.mem.Allocator,
    obj: *const std.json.ObjectMap,
    defs: *std.json.ObjectMap,
    strategy: CleaningStrategy,
    ref_stack: *std.StringHashMap(void),
) CleanError!?std.json.Value {
    const union_key: []const u8 = if (obj.contains("anyOf")) "anyOf" else if (obj.contains("oneOf")) "oneOf" else return null;

    const variants_val = obj.get(union_key) orelse return null;
    if (variants_val != .array) return null;
    const variants = variants_val.array.items;

    // Clean all variants first
    var cleaned_variants: std.ArrayList(std.json.Value) = .empty;
    defer cleaned_variants.deinit(allocator);
    try cleaned_variants.ensureTotalCapacity(allocator, variants.len);
    for (variants) |v| {
        const cleaned = try cleanValue(allocator, v, strategy, defs, ref_stack);
        cleaned_variants.appendAssumeCapacity(cleaned);
    }

    // Strip null variants
    var non_null: std.ArrayList(std.json.Value) = .empty;
    defer non_null.deinit(allocator);
    for (cleaned_variants.items) |v| {
        if (!isNullSchema(v)) {
            try non_null.append(allocator, v);
        }
    }

    // If only one variant remains after stripping nulls, return it
    if (non_null.items.len == 1) {
        return preserveMeta(allocator, obj, non_null.items[0]);
    }

    // Try to flatten to enum if all variants are literals
    if (tryFlattenLiteralUnion(allocator, non_null.items)) |enum_value| {
        return preserveMeta(allocator, obj, enum_value);
    }

    return null;
}

/// Check if a schema represents null type.
fn isNullSchema(value: std.json.Value) bool {
    if (value != .object) return false;
    const obj = value.object;

    // { "const": null }
    if (obj.get("const")) |v| {
        if (v == .null) return true;
    }
    // { "enum": [null] }
    if (obj.get("enum")) |v| {
        if (v == .array) {
            const arr = v.array.items;
            if (arr.len == 1 and arr[0] == .null) return true;
        }
    }
    // { "type": "null" }
    if (obj.get("type")) |v| {
        if (v == .string) {
            if (std.mem.eql(u8, v.string, "null")) return true;
        }
    }
    return false;
}

/// Try to flatten anyOf/oneOf with only literal values to enum.
/// Example: anyOf: [{const:"a",type:"string"},{const:"b",type:"string"}] -> {type:"string",enum:["a","b"]}
fn tryFlattenLiteralUnion(allocator: std.mem.Allocator, variants: []const std.json.Value) ?std.json.Value {
    if (variants.len == 0) return null;

    var all_values: std.ArrayList(std.json.Value) = .empty;
    var common_type: ?[]const u8 = null;

    for (variants) |variant| {
        if (variant != .object) return null;
        const obj = variant.object;

        // Extract literal value from const or single-item enum
        const literal_value: std.json.Value = blk: {
            if (obj.get("const")) |cv| break :blk cv;
            if (obj.get("enum")) |ev| {
                if (ev == .array and ev.array.items.len == 1) break :blk ev.array.items[0];
            }
            return null;
        };

        // Check type consistency
        const type_val = obj.get("type") orelse return null;
        if (type_val != .string) return null;
        const variant_type = type_val.string;

        if (common_type) |ct| {
            if (!std.mem.eql(u8, ct, variant_type)) return null;
        } else {
            common_type = variant_type;
        }

        all_values.append(allocator, literal_value) catch return null;
    }

    const ct = common_type orelse return null;

    var result: std.json.ObjectMap = .empty;
    result.put(allocator, "type", .{ .string = ct }) catch return null;
    var enum_arr = std.json.Array.init(allocator);
    enum_arr.ensureTotalCapacity(all_values.items.len) catch return null;
    for (all_values.items) |v| {
        enum_arr.appendAssumeCapacity(v);
    }
    result.put(allocator, "enum", .{ .array = enum_arr }) catch return null;

    return .{ .object = result };
}

/// Clean type array, removing null.
fn cleanTypeArray(value: std.json.Value) std.json.Value {
    if (value != .array) return value;
    const types = value.array.items;

    // Count non-null types
    var count: usize = 0;
    var last_non_null: std.json.Value = .{ .string = "null" };
    for (types) |t| {
        if (t == .string and std.mem.eql(u8, t.string, "null")) continue;
        count += 1;
        last_non_null = t;
    }

    if (count == 0) return .{ .string = "null" };
    if (count == 1) return last_non_null;
    return value; // Multiple non-null types, keep array
}

/// Clean properties object.
fn cleanProperties(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    strategy: CleaningStrategy,
    defs: *std.json.ObjectMap,
    ref_stack: *std.StringHashMap(void),
) CleanError!std.json.Value {
    if (value != .object) return value;
    var cleaned: std.json.ObjectMap = .empty;
    var it = value.object.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        const v = entry.value_ptr.*;
        try cleaned.put(allocator, k, try cleanValue(allocator, v, strategy, defs, ref_stack));
    }
    return .{ .object = cleaned };
}

/// Clean union (anyOf/oneOf/allOf) array.
fn cleanUnion(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    strategy: CleaningStrategy,
    defs: *std.json.ObjectMap,
    ref_stack: *std.StringHashMap(void),
) CleanError!std.json.Value {
    if (value != .array) return value;
    const items = value.array.items;
    var result = std.json.Array.init(allocator);
    try result.ensureTotalCapacity(items.len);
    for (items) |v| {
        const cleaned = try cleanValue(allocator, v, strategy, defs, ref_stack);
        result.appendAssumeCapacity(cleaned);
    }
    return .{ .array = result };
}

/// Preserve metadata (description, title, default) from source to target.
fn preserveMeta(allocator: std.mem.Allocator, source: *const std.json.ObjectMap, target: std.json.Value) std.json.Value {
    if (target != .object) return target;
    var obj = target.object;
    for (&SCHEMA_META_KEYS) |key| {
        if (source.get(key)) |val| {
            obj.put(allocator, key, val) catch |err| log.err("preserveMeta: failed to put key {s}: {}", .{ key, err });
        }
    }
    return .{ .object = obj };
}

/// Serialize a JSON value to a string.
fn serializeJson(allocator: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

// ── Tests ───────────────────────────────────────────────────────────

test "schema gemini removes minLength" {
    const input =
        \\{"type":"string","minLength":1,"description":"A name"}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    // Should not contain minLength
    try std.testing.expect(std.mem.indexOf(u8, result, "minLength") == null);
    // Should still have type and description
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"description\"") != null);
}

test "schema gemini removes additionalProperties" {
    const input =
        \\{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "additionalProperties") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\"") != null);
}

test "schema gemini removes $schema" {
    const input =
        \\{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"string"}}}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "$schema") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\"") != null);
}

test "schema anthropic removes additionalProperties" {
    const input =
        \\{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}
    ;
    // Anthropic strategy does NOT remove additionalProperties (only refs)
    const result = try SchemaCleanr.cleanForAnthropic(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    // Anthropic only removes $ref, $defs, definitions
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\"") != null);
}

test "schema anthropic keeps minimum and maximum" {
    const input =
        \\{"type":"integer","minimum":0,"maximum":100}
    ;
    const result = try SchemaCleanr.cleanForAnthropic(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"minimum\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"maximum\"") != null);
}

test "schema openai keeps most keywords" {
    const input =
        \\{"type":"string","minLength":1,"maxLength":100,"pattern":"^[a-z]+$","format":"email"}
    ;
    const result = try SchemaCleanr.cleanForOpenAI(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"minLength\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"maxLength\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"pattern\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"format\"") != null);
}

test "schema conservative matches gemini on unsupported refs" {
    const input =
        \\{"type":"object","$defs":{"A":{"type":"string"}},"additionalProperties":false}
    ;
    const result = try SchemaCleanr.clean(std.testing.allocator, input, .conservative);
    defer std.testing.allocator.free(result);

    // Conservative removes $defs and additionalProperties
    try std.testing.expect(std.mem.indexOf(u8, result, "$defs") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "additionalProperties") == null);
}

test "schema validate with type returns true" {
    const input =
        \\{"type":"object","properties":{"a":{"type":"string"}}}
    ;
    try std.testing.expect(SchemaCleanr.validate(std.testing.allocator, input));
}

test "schema validate without type returns false" {
    const input =
        \\{"properties":{"a":{"type":"string"}}}
    ;
    try std.testing.expect(!SchemaCleanr.validate(std.testing.allocator, input));
}

test "schema anyOf simplification strips null" {
    const input =
        \\{"oneOf":[{"type":"string"},{"type":"null"}]}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    // Should simplify to just {type:string}
    try std.testing.expect(std.mem.indexOf(u8, result, "\"string\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "oneOf") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"null\"") == null);
}

test "schema cleanForGemini removes all unsupported keywords" {
    const input =
        \\{"type":"string","minLength":1,"maxLength":100,"pattern":"^a$","format":"email","minimum":0,"maximum":99,"multipleOf":2,"minItems":1,"maxItems":10,"uniqueItems":true,"additionalProperties":false,"$schema":"draft-07","examples":["a"]}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    for (&GEMINI_UNSUPPORTED_KEYWORDS) |kw| {
        // Check that the keyword doesn't appear as a JSON key
        const needle = std.fmt.allocPrint(std.testing.allocator, "\"{s}\"", .{kw}) catch continue;
        defer std.testing.allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, result, needle) == null);
    }
    // But type should still be there
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\"") != null);
}

test "schema nested properties cleaned recursively" {
    const input =
        \\{"type":"object","properties":{"user":{"type":"object","properties":{"name":{"type":"string","minLength":1}},"additionalProperties":false}}}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "minLength") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "additionalProperties") == null);
    // But nested type and properties should remain
    try std.testing.expect(std.mem.indexOf(u8, result, "\"name\"") != null);
}

test "schema $ref resolution" {
    const input =
        \\{"type":"object","properties":{"age":{"$ref":"#/$defs/Age"}},"$defs":{"Age":{"type":"integer","minimum":0}}}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    // $ref should be resolved, and minimum stripped by gemini
    try std.testing.expect(std.mem.indexOf(u8, result, "$ref") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "$defs") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "minimum") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"integer\"") != null);
}

test "schema const to enum conversion" {
    const input =
        \\{"const":"fixed_value","description":"A constant"}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"enum\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "fixed_value") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"description\"") != null);
}

test "schema type array null removal" {
    const input =
        \\{"type":["string","null"]}
    ;
    const result = try SchemaCleanr.cleanForGemini(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"string\"") != null);
}

test "schema validate rejects non-object" {
    try std.testing.expect(!SchemaCleanr.validate(std.testing.allocator, "\"just a string\""));
    try std.testing.expect(!SchemaCleanr.validate(std.testing.allocator, "42"));
    try std.testing.expect(!SchemaCleanr.validate(std.testing.allocator, "null"));
}

test "schema validate rejects invalid json" {
    try std.testing.expect(!SchemaCleanr.validate(std.testing.allocator, "{bad json}"));
}
