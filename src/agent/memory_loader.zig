const std = @import("std");
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const MemoryEntry = memory_mod.MemoryEntry;

// ═══════════════════════════════════════════════════════════════════════════
// Memory Loader — inject relevant memory context into user messages
// ═══════════════════════════════════════════════════════════════════════════

/// Default number of memory entries to recall per query.
const DEFAULT_RECALL_LIMIT: usize = 5;

/// Build a memory context preamble by searching stored memories.
///
/// Returns a formatted string like:
/// ```
/// [Memory context]
/// - key1: value1
/// - key2: value2
/// ```
///
/// Returns an empty owned string if no relevant memories are found.
pub fn loadContext(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
) ![]const u8 {
    const entries = mem.recall(allocator, user_message, DEFAULT_RECALL_LIMIT) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.freeEntries(allocator, entries);

    if (entries.len == 0) {
        return try allocator.dupe(u8, "");
    }

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("[Memory context]\n");
    for (entries) |entry| {
        try std.fmt.format(w, "- {s}: {s}\n", .{ entry.key, entry.content });
    }
    try w.writeAll("\n");

    return try buf.toOwnedSlice(allocator);
}

/// Enrich a user message with memory context prepended.
/// If no context is available, returns an owned dupe of the original message.
pub fn enrichMessage(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
) ![]const u8 {
    const context = try loadContext(allocator, mem, user_message);
    if (context.len == 0) {
        allocator.free(context);
        return try allocator.dupe(u8, user_message);
    }

    defer allocator.free(context);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ context, user_message });
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "loadContext returns empty for no-op memory" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const context = try loadContext(allocator, mem, "hello");
    defer allocator.free(context);

    try std.testing.expectEqualStrings("", context);
}

test "enrichMessage with no context returns original" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessage(allocator, mem, "hello");
    defer allocator.free(enriched);

    try std.testing.expectEqualStrings("hello", enriched);
}
