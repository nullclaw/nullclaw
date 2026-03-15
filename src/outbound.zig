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

pub const Payload = struct {
    text: []const u8 = "",
    attachments: []const Attachment = &.{},
    choices: []const Choice = &.{},
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
