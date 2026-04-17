//! Reciprocal Rank Fusion — merges candidates from multiple ranked lists.
//!
//! Pure function, no I/O, no dependencies beyond retrieval types.
//! Formula: score = sum(1 / (rank_i + k)) across all source lists.

const std = @import("std");
const Allocator = std.mem.Allocator;
const retrieval = @import("engine.zig");
const RetrievalCandidate = retrieval.RetrievalCandidate;

/// Reciprocal Rank Fusion: score = sum(1 / (rank_i + k))
/// Merges candidates from multiple ranked lists by content identity (key).
/// Returns merged candidates sorted by final_score descending, truncated to limit.
/// Caller owns the returned slice; free with `retrieval.freeCandidates`.
pub fn rrfMerge(
    allocator: Allocator,
    sources: []const []const RetrievalCandidate,
    k: u32,
    limit: usize,
) ![]RetrievalCandidate {
    if (sources.len == 0) return allocator.alloc(RetrievalCandidate, 0);

    // Single source → passthrough (copy candidates, set final_score from rank)
    if (sources.len == 1) {
        return singleSourceCopy(allocator, sources[0], k, limit);
    }

    // Build map: key → (accumulated score, first-seen candidate index in `merged`)
    var score_map = std.StringHashMap(ScoreEntry).init(allocator);
    defer score_map.deinit();

    var merged = std.ArrayListUnmanaged(MergeItem).empty;
    defer merged.deinit(allocator);

    for (sources) |source_list| {
        for (source_list, 0..) |candidate, i| {
            const rrf_term = 1.0 / @as(f64, @floatFromInt(i + 1 + k));

            const gop = try score_map.getOrPut(candidate.key);
            if (gop.found_existing) {
                gop.value_ptr.score += rrf_term;
            } else {
                gop.value_ptr.* = .{
                    .score = rrf_term,
                    .index = merged.items.len,
                };
                try merged.append(allocator, .{ .candidate = candidate });
            }
        }
    }

    // Set final scores
    for (merged.items) |*item| {
        if (score_map.get(item.candidate.key)) |entry| {
            item.score = entry.score;
        }
    }

    // Sort by score descending
    std.mem.sortUnstable(MergeItem, merged.items, {}, compareByScoreDesc);

    // Truncate and build output
    const out_len = @min(merged.items.len, limit);
    var result = try allocator.alloc(RetrievalCandidate, out_len);
    var cloned: usize = 0;
    errdefer {
        for (result[0..cloned]) |*c| c.deinit(allocator);
        allocator.free(result);
    }

    for (0..out_len) |i| {
        result[i] = try cloneCandidate(allocator, merged.items[i].candidate, merged.items[i].score);
        cloned += 1;
    }

    return result;
}

const ScoreEntry = struct {
    score: f64,
    index: usize,
};

const MergeItem = struct {
    candidate: RetrievalCandidate,
    score: f64 = 0.0,
};

fn compareByScoreDesc(_: void, a: MergeItem, b: MergeItem) bool {
    return a.score > b.score;
}

fn singleSourceCopy(allocator: Allocator, source: []const RetrievalCandidate, k: u32, limit: usize) ![]RetrievalCandidate {
    const out_len = @min(source.len, limit);
    var result = try allocator.alloc(RetrievalCandidate, out_len);
    var cloned: usize = 0;
    errdefer {
        for (result[0..cloned]) |*c| c.deinit(allocator);
        allocator.free(result);
    }

    for (0..out_len) |i| {
        const rrf_score = 1.0 / @as(f64, @floatFromInt(i + 1 + k));
        result[i] = try cloneCandidate(allocator, source[i], rrf_score);
        cloned += 1;
    }

    return result;
}

fn cloneCandidate(allocator: Allocator, src: RetrievalCandidate, final_score: f64) !RetrievalCandidate {
    const id = try allocator.dupe(u8, src.id);
    errdefer allocator.free(id);
    const key = try allocator.dupe(u8, src.key);
    errdefer allocator.free(key);
    const content = try allocator.dupe(u8, src.content);
    errdefer allocator.free(content);
    const snippet = try allocator.dupe(u8, src.snippet);
    errdefer allocator.free(snippet);
    const source = try allocator.dupe(u8, src.source);
    errdefer allocator.free(source);
    const source_path = try allocator.dupe(u8, src.source_path);
    errdefer allocator.free(source_path);

    return .{
        .id = id,
        .key = key,
        .content = content,
        .snippet = snippet,
        .category = switch (src.category) {
            .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
            else => src.category,
        },
        .keyword_rank = src.keyword_rank,
        .vector_score = src.vector_score,
        .final_score = final_score,
        .source = source,
        .source_path = source_path,
        .start_line = src.start_line,
        .end_line = src.end_line,
        .created_at = src.created_at,
    };
}

// ── Tests ──────────────────────────────────────────────────────────

test "single source passthrough preserves order" {
    const allocator = std.testing.allocator;
    const src = [_]RetrievalCandidate{
        makeTestCandidate("a", "content_a"),
        makeTestCandidate("b", "content_b"),
        makeTestCandidate("c", "content_c"),
    };
    const sources = [_][]const RetrievalCandidate{&src};
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("a", result[0].key);
    try std.testing.expectEqualStrings("b", result[1].key);
    try std.testing.expectEqualStrings("c", result[2].key);
}

test "two sources merge by key, higher combined rank wins" {
    const allocator = std.testing.allocator;
    // Source 1: a (rank 1), b (rank 2)
    const s1 = [_]RetrievalCandidate{
        makeTestCandidate("a", "A"),
        makeTestCandidate("b", "B"),
    };
    // Source 2: b (rank 1), c (rank 2)
    const s2 = [_]RetrievalCandidate{
        makeTestCandidate("b", "B"),
        makeTestCandidate("c", "C"),
    };
    const sources = [_][]const RetrievalCandidate{ &s1, &s2 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    // "b" appears in both sources (rank 1 in s1 at pos 2, rank 1 in s2 at pos 1)
    // so it should have the highest score
    try std.testing.expectEqualStrings("b", result[0].key);
}

test "duplicate keys across sources accumulate score" {
    const allocator = std.testing.allocator;
    const s1 = [_]RetrievalCandidate{makeTestCandidate("x", "X")};
    const s2 = [_]RetrievalCandidate{makeTestCandidate("x", "X")};
    const sources = [_][]const RetrievalCandidate{ &s1, &s2 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("x", result[0].key);
    // Score should be 2 * (1 / (1 + 60)) = 2/61
    const expected: f64 = 2.0 / 61.0;
    try std.testing.expectApproxEqAbs(expected, result[0].final_score, 1e-10);
}

test "empty source list returns empty" {
    const allocator = std.testing.allocator;
    const sources = [_][]const RetrievalCandidate{};
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "all sources empty returns empty" {
    const allocator = std.testing.allocator;
    const empty1 = [_]RetrievalCandidate{};
    const empty2 = [_]RetrievalCandidate{};
    const sources = [_][]const RetrievalCandidate{ &empty1, &empty2 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "limit truncates correctly" {
    const allocator = std.testing.allocator;
    const src = [_]RetrievalCandidate{
        makeTestCandidate("a", "A"),
        makeTestCandidate("b", "B"),
        makeTestCandidate("c", "C"),
    };
    const sources = [_][]const RetrievalCandidate{&src};
    const result = try rrfMerge(allocator, &sources, 60, 2);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
}

test "k=0 vs k=60 changes relative scores" {
    const allocator = std.testing.allocator;
    const src = [_]RetrievalCandidate{
        makeTestCandidate("a", "A"),
        makeTestCandidate("b", "B"),
    };
    const sources = [_][]const RetrievalCandidate{&src};

    const result_k0 = try rrfMerge(allocator, &sources, 0, 10);
    defer retrieval.freeCandidates(allocator, result_k0);

    const result_k60 = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result_k60);

    // With k=0, rank 1 score = 1/1 = 1.0
    // With k=60, rank 1 score = 1/61 ≈ 0.016
    try std.testing.expect(result_k0[0].final_score > result_k60[0].final_score);

    // With k=0, ratio of rank1/rank2 = (1/1)/(1/2) = 2.0
    // With k=60, ratio = (1/61)/(1/62) ≈ 1.016
    // k=60 smooths rank differences
    const ratio_k0 = result_k0[0].final_score / result_k0[1].final_score;
    const ratio_k60 = result_k60[0].final_score / result_k60[1].final_score;
    try std.testing.expect(ratio_k0 > ratio_k60);
}

test "candidates from single source only get single RRF term" {
    const allocator = std.testing.allocator;
    const s1 = [_]RetrievalCandidate{makeTestCandidate("a", "A")};
    const s2 = [_]RetrievalCandidate{makeTestCandidate("b", "B")};
    const sources = [_][]const RetrievalCandidate{ &s1, &s2 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    // Both only appear in one source at rank 1, so both get 1/(1+60) = 1/61
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectApproxEqAbs(result[0].final_score, result[1].final_score, 1e-10);
}

test "large k smooths rank differences" {
    const allocator = std.testing.allocator;
    const src = [_]RetrievalCandidate{
        makeTestCandidate("a", "A"),
        makeTestCandidate("b", "B"),
    };
    const sources = [_][]const RetrievalCandidate{&src};

    // k=1000: rank1 = 1/1001, rank2 = 1/1002
    const result = try rrfMerge(allocator, &sources, 1000, 10);
    defer retrieval.freeCandidates(allocator, result);

    const ratio = result[0].final_score / result[1].final_score;
    // Ratio should be very close to 1.0 with large k
    try std.testing.expect(ratio < 1.01);
}

test "single source with limit 0 returns empty" {
    const allocator = std.testing.allocator;
    const src = [_]RetrievalCandidate{makeTestCandidate("a", "A")};
    const sources = [_][]const RetrievalCandidate{&src};
    const result = try rrfMerge(allocator, &sources, 60, 0);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "three sources merge correctly" {
    const allocator = std.testing.allocator;
    // "a" appears in all 3 sources, "b" in 2, "c" in 1
    const s1 = [_]RetrievalCandidate{ makeTestCandidate("a", "A"), makeTestCandidate("b", "B") };
    const s2 = [_]RetrievalCandidate{ makeTestCandidate("b", "B"), makeTestCandidate("a", "A") };
    const s3 = [_]RetrievalCandidate{ makeTestCandidate("a", "A"), makeTestCandidate("c", "C") };
    const sources = [_][]const RetrievalCandidate{ &s1, &s2, &s3 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    // "a" has 3 RRF terms, should be highest
    try std.testing.expectEqualStrings("a", result[0].key);
    // "b" has 2 RRF terms
    try std.testing.expectEqualStrings("b", result[1].key);
}

test "preserves first-seen candidate content" {
    const allocator = std.testing.allocator;
    const s1 = [_]RetrievalCandidate{makeTestCandidateWithSource("a", "content_from_s1", "primary")};
    const s2 = [_]RetrievalCandidate{makeTestCandidateWithSource("a", "content_from_s2", "qmd")};
    const sources = [_][]const RetrievalCandidate{ &s1, &s2 };
    const result = try rrfMerge(allocator, &sources, 60, 10);
    defer retrieval.freeCandidates(allocator, result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    // Should keep first-seen (from s1)
    try std.testing.expectEqualStrings("content_from_s1", result[0].content);
    try std.testing.expectEqualStrings("primary", result[0].source);
}

// ── Test helpers ───────────────────────────────────────────────────

fn makeTestCandidate(key: []const u8, content: []const u8) RetrievalCandidate {
    return .{
        .id = key,
        .key = key,
        .content = content,
        .snippet = content,
        .category = .core,
        .keyword_rank = null,
        .vector_score = null,
        .final_score = 0.0,
        .source = "test",
        .source_path = "",
        .start_line = 0,
        .end_line = 0,
    };
}

fn makeTestCandidateWithSource(key: []const u8, content: []const u8, source: []const u8) RetrievalCandidate {
    return .{
        .id = key,
        .key = key,
        .content = content,
        .snippet = content,
        .category = .core,
        .keyword_rank = null,
        .vector_score = null,
        .final_score = 0.0,
        .source = source,
        .source_path = "",
        .start_line = 0,
        .end_line = 0,
    };
}
