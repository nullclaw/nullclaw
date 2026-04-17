//! Structured outbound payload types shared across channels.
//!
//! `Payload` intentionally combines the older attachment/choice transport fields
//! with the newer card-oriented fields used by rich renderers such as Lark and
//! DingTalk. Channels can consume only the subset they support.

const std = @import("std");

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

    pub fn deinit(self: *const Choice, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

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
