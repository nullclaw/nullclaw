//! Structured outbound payload types shared across channels.
//!
//! `Payload` intentionally combines the older attachment/choice transport fields
//! with the newer card-oriented fields used by rich renderers such as Lark and
//! DingTalk. Channels can consume only the subset they support.

const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("fs_compat.zig");
const path_security = @import("tools/path_security.zig");

pub const AttachmentKind = enum {
    image,
    document,
    video,
    audio,
    voice,
};

pub const Attachment = struct {
    kind: AttachmentKind,
    target: []const u8,
    caption: ?[]const u8 = null,
};

pub const Choice = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    pub fn initOwned(
        allocator: std.mem.Allocator,
        id: []const u8,
        label: []const u8,
        submit_text: []const u8,
    ) !Choice {
        const id_copy = try allocator.dupe(u8, id);
        errdefer allocator.free(id_copy);
        const label_copy = try allocator.dupe(u8, label);
        errdefer allocator.free(label_copy);

        return .{
            .id = id_copy,
            .label = label_copy,
            .submit_text = try allocator.dupe(u8, submit_text),
        };
    }

    pub fn deinit(self: *const Choice, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

fn initOwnedChoiceAllocationTest(allocator: std.mem.Allocator) !void {
    const choice = try Choice.initOwned(allocator, "approve", "Approve", "approve request");
    defer choice.deinit(allocator);
}

// Regression: a failure while copying a later field must release earlier fields.
test "outbound choice initOwned frees partial allocations on out-of-memory" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initOwnedChoiceAllocationTest,
        .{},
    );
}

pub const CardSection = struct {
    title: []const u8 = "",
    body: []const u8,
};

pub const ActionButton = struct {
    id: []const u8,
    label: []const u8,
};

pub const ActionGroup = struct {
    actions: []const ActionButton,
};

pub const Payload = struct {
    text: []const u8 = "",
    attachments: []const Attachment = &.{},
    choices: []const Choice = &.{},
    card_title: []const u8 = "",
    card_sections: []const CardSection = &.{},
    action_groups: []const ActionGroup = &.{},

    pub fn toPlainText(self: Payload, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        if (self.card_title.len > 0) {
            try buf.appendSlice(allocator, self.card_title);
            try buf.appendSlice(allocator, "\n\n");
        }
        if (self.text.len > 0) {
            try buf.appendSlice(allocator, self.text);
            try buf.append(allocator, '\n');
        }
        for (self.card_sections) |sec| {
            if (sec.title.len > 0) {
                try buf.appendSlice(allocator, sec.title);
                try buf.append(allocator, '\n');
            }
            try buf.appendSlice(allocator, sec.body);
            try buf.append(allocator, '\n');
        }
        for (self.action_groups) |grp| {
            for (grp.actions) |btn| {
                try buf.append(allocator, '[');
                try buf.appendSlice(allocator, btn.label);
                try buf.append(allocator, ']');
                try buf.append(allocator, ' ');
            }
            if (grp.actions.len > 0) try buf.append(allocator, '\n');
        }
        for (self.choices) |choice| {
            try buf.append(allocator, '[');
            try buf.appendSlice(allocator, choice.label);
            try buf.append(allocator, ']');
            try buf.append(allocator, ' ');
        }
        if (self.choices.len > 0) try buf.append(allocator, '\n');

        return buf.toOwnedSlice(allocator);
    }
};

pub fn has_legacy_attachment_markers(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "[IMAGE:") != null or
        std.mem.indexOf(u8, text, "[image:") != null or
        std.mem.indexOf(u8, text, "[FILE:") != null or
        std.mem.indexOf(u8, text, "[file:") != null or
        std.mem.indexOf(u8, text, "[DOCUMENT:") != null or
        std.mem.indexOf(u8, text, "[document:") != null or
        std.mem.indexOf(u8, text, "[PHOTO:") != null or
        std.mem.indexOf(u8, text, "[photo:") != null or
        std.mem.indexOf(u8, text, "[VIDEO:") != null or
        std.mem.indexOf(u8, text, "[video:") != null or
        std.mem.indexOf(u8, text, "[AUDIO:") != null or
        std.mem.indexOf(u8, text, "[audio:") != null or
        std.mem.indexOf(u8, text, "[VOICE:") != null or
        std.mem.indexOf(u8, text, "[voice:") != null;
}

test "outbound has_legacy_attachment_markers detects supported markers" {
    try std.testing.expect(has_legacy_attachment_markers("See [IMAGE:/tmp/photo.png]"));
    try std.testing.expect(has_legacy_attachment_markers("See [file:/tmp/report.pdf]"));
    try std.testing.expect(has_legacy_attachment_markers("See [VOICE:/tmp/note.ogg]"));
}

test "outbound has_legacy_attachment_markers ignores plain text" {
    try std.testing.expect(!has_legacy_attachment_markers("No attachment markers here."));
    try std.testing.expect(!has_legacy_attachment_markers("[IMAGINE:/tmp/photo.png] is not a marker."));
}

/// Restricts which local files an agent's outbound reply may attach. Set for an
/// agent that carries its own autonomy: a local attachment target must resolve
/// (symlinks followed) inside the agent's workspace or one of its allowed_paths.
/// Remote http(s) URLs name no local file and are always allowed.
pub const AttachmentScope = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
};

/// True when `target` may be attached under `scope`. Remote http(s) URLs name
/// no local file and are always allowed. A local target must be an absolute
/// path that resolves (symlinks followed) inside the agent's workspace or one
/// of its allowed_paths.
///
/// Relative targets are refused. The outbound channels
/// (telegram/max/signal `resolveAttachmentPath`) hand a relative target
/// straight to `curl --form file=@<target>`, which resolves it against the
/// *process* cwd — not the workspace this check resolves against. Keeping a
/// relative marker would therefore allow a marker that resolves to a
/// workspace file here while the channel uploads a different, cwd-relative
/// file (e.g. the real config.json).
pub fn attachmentTargetAllowed(
    allocator: std.mem.Allocator,
    scope: AttachmentScope,
    target: []const u8,
) bool {
    const trimmed = std.mem.trim(u8, target, " \t");
    if (trimmed.len == 0) return false;
    if (std.mem.startsWith(u8, trimmed, "http://") or std.mem.startsWith(u8, trimmed, "https://")) return true;
    if (!std_compat.fs.path.isAbsolute(trimmed)) return false;

    const resolved = fs_compat.realpathAllocPath(allocator, trimmed) catch return false;
    defer allocator.free(resolved);
    const ws_resolved = fs_compat.realpathAllocPath(allocator, scope.workspace_dir) catch return false;
    defer allocator.free(ws_resolved);
    return path_security.isResolvedPathAllowed(allocator, resolved, ws_resolved, scope.allowed_paths);
}

const legacy_marker_kinds = [_][]const u8{ "image", "photo", "file", "document", "video", "audio", "voice" };

/// Return the target of a legacy `[KIND:target]` attachment marker, or null when
/// `marker` (the text between the brackets) is not a known marker.
fn legacyMarkerTarget(marker: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, marker, ':') orelse return null;
    const kind = std.mem.trim(u8, marker[0..colon], " ");
    for (legacy_marker_kinds) |known| {
        if (std.ascii.eqlIgnoreCase(kind, known)) {
            const target = std.mem.trim(u8, marker[colon + 1 ..], " ");
            return if (target.len == 0) null else target;
        }
    }
    return null;
}

/// Remove legacy attachment markers whose local target escapes `scope` (an
/// agent's workspace + allowed_paths). Remote URL targets are kept. Returns an
/// owned copy of `text`; each dropped marker is logged. Used to keep an agent
/// with its own autonomy from exfiltrating files outside its workspace through
/// its reply text, independent of tool calls.
pub fn stripEscapingAttachmentMarkers(
    allocator: std.mem.Allocator,
    text: []const u8,
    scope: AttachmentScope,
) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < text.len) {
        const open = std.mem.indexOfPos(u8, text, cursor, "[") orelse {
            try out.appendSlice(allocator, text[cursor..]);
            break;
        };
        try out.appendSlice(allocator, text[cursor..open]);

        const close = std.mem.indexOfPos(u8, text, open, "]") orelse {
            try out.appendSlice(allocator, text[open..]);
            break;
        };

        const marker = text[open + 1 .. close];
        if (legacyMarkerTarget(marker)) |target| {
            if (attachmentTargetAllowed(allocator, scope, target)) {
                try out.appendSlice(allocator, text[open .. close + 1]);
            } else {
                std.log.warn("dropped outbound attachment marker outside the agent workspace: {s}", .{marker});
            }
        } else {
            try out.appendSlice(allocator, text[open .. close + 1]);
        }
        cursor = close + 1;
    }
    return out.toOwnedSlice(allocator);
}

test "attachmentTargetAllowed keeps workspace files and rejects escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp.dir);
    const base = try dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try dir.writeFile(.{ .sub_path = "notes.txt", .data = "hi" });
    const inside = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "notes.txt" });
    defer std.testing.allocator.free(inside);

    const scope = AttachmentScope{ .workspace_dir = base };
    try std.testing.expect(attachmentTargetAllowed(std.testing.allocator, scope, inside));
    // Relative targets are refused because the channel uploader resolves them
    // against the process cwd instead of the workspace.
    try std.testing.expect(!attachmentTargetAllowed(std.testing.allocator, scope, "notes.txt"));
    try std.testing.expect(!attachmentTargetAllowed(std.testing.allocator, scope, "./notes.txt"));
    // Absolute paths outside the workspace, and `..` traversal, are refused.
    try std.testing.expect(!attachmentTargetAllowed(std.testing.allocator, scope, "/etc/passwd"));
    try std.testing.expect(!attachmentTargetAllowed(std.testing.allocator, scope, "../../config.json"));
    try std.testing.expect(!attachmentTargetAllowed(std.testing.allocator, scope, "/nonexistent-nullclaw-probe.txt"));
    // Remote URLs name no local file.
    try std.testing.expect(attachmentTargetAllowed(std.testing.allocator, scope, "https://example.com/x.png"));
}

test "stripEscapingAttachmentMarkers drops escapes and keeps workspace and urls" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp.dir);
    const base = try dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try dir.writeFile(.{ .sub_path = "report.pdf", .data = "hi" });
    const inside = try std_compat.fs.path.join(std.testing.allocator, &.{ base, "report.pdf" });
    defer std.testing.allocator.free(inside);

    const scope = AttachmentScope{ .workspace_dir = base };

    const keep = try std.fmt.allocPrint(std.testing.allocator, "see [DOCUMENT:{s}] and [IMAGE:https://example.com/a.png]", .{inside});
    defer std.testing.allocator.free(keep);
    const kept = try stripEscapingAttachmentMarkers(std.testing.allocator, keep, scope);
    defer std.testing.allocator.free(kept);
    try std.testing.expect(std.mem.indexOf(u8, kept, "report.pdf") != null);
    try std.testing.expect(std.mem.indexOf(u8, kept, "https://example.com/a.png") != null);

    // A marker pointing at an absolute path outside the workspace is dropped,
    // while surrounding text survives.
    const escape = "here you go [DOCUMENT:/etc/passwd] bye";
    const stripped = try stripEscapingAttachmentMarkers(std.testing.allocator, escape, scope);
    defer std.testing.allocator.free(stripped);
    try std.testing.expect(std.mem.indexOf(u8, stripped, "/etc/passwd") == null);
    try std.testing.expect(std.mem.indexOf(u8, stripped, "here you go") != null);
    try std.testing.expect(std.mem.indexOf(u8, stripped, "bye") != null);

    // Non-marker brackets are untouched.
    const plain = try stripEscapingAttachmentMarkers(std.testing.allocator, "hello [world] there", scope);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("hello [world] there", plain);
}

test "Payload toPlainText includes structured card fields and choices" {
    const buttons = [_]ActionButton{
        .{ .id = "approve", .label = "Approve" },
        .{ .id = "deny", .label = "Deny" },
    };
    const groups = [_]ActionGroup{.{ .actions = &buttons }};
    const choices = [_]Choice{
        .{ .id = "later", .label = "Later", .submit_text = "later" },
    };
    const sections = [_]CardSection{.{ .title = "Status", .body = "Waiting review" }};

    const payload = Payload{
        .card_title = "Review",
        .text = "Pick one option.",
        .card_sections = &sections,
        .action_groups = &groups,
        .choices = &choices,
    };

    const text = try payload.toPlainText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "Review") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Waiting review") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "[Approve]") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "[Later]") != null);
}
