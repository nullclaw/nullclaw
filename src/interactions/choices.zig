const std = @import("std");

pub const START_TAG = "<nc_choices>";
pub const END_TAG = "</nc_choices>";
pub const MAX_OPTIONS: usize = 6;
pub const MIN_OPTIONS: usize = 2;
pub const MAX_ID_LEN: usize = 24;
pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_SUBMIT_TEXT_LEN: usize = 256;
pub const CALLBACK_PREFIX = "nc1:";

pub const ChoiceCallbackData = struct {
    token: []const u8,
    option_id: []const u8,
};

pub const ChoiceOption = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    pub fn deinit(self: *const ChoiceOption, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

pub const ChoicesDirective = struct {
    version: u8 = 1,
    options: []ChoiceOption,

    pub fn deinit(self: *const ChoicesDirective, allocator: std.mem.Allocator) void {
        for (self.options) |opt| opt.deinit(allocator);
        allocator.free(self.options);
    }
};

pub const ParsedAssistantChoices = struct {
    visible_text: []const u8,
    choices: ?ChoicesDirective = null,

    pub fn deinit(self: *ParsedAssistantChoices, allocator: std.mem.Allocator) void {
        allocator.free(self.visible_text);
        if (self.choices) |*choices| choices.deinit(allocator);
    }
};

const ChoicesBlockSpan = struct {
    open_start: usize,
    content_start: usize,
    close_start: usize,
    close_end: usize,
};

pub fn parseAssistantChoices(allocator: std.mem.Allocator, text: []const u8) !ParsedAssistantChoices {
    const span = findChoicesBlock(text) orelse return .{
        .visible_text = try allocator.dupe(u8, text),
        .choices = null,
    };

    var visible = try stripChoicesBlock(allocator, text, span);
    errdefer allocator.free(visible);

    const json_payload = std.mem.trim(u8, text[span.content_start..span.close_start], " \t\r\n");
    const parsed_choices = try parseChoicesDirective(allocator, json_payload);
    if (parsed_choices == null) {
        if (std.mem.trim(u8, visible, " \t\r\n").len == 0) {
            allocator.free(visible);
            visible = try allocator.dupe(u8, text);
        }
        return .{
            .visible_text = visible,
            .choices = null,
        };
    }

    var choices = parsed_choices.?;
    errdefer choices.deinit(allocator);

    if (std.mem.trim(u8, visible, " \t\r\n").len == 0) {
        allocator.free(visible);
        visible = try synthesizeFallbackText(allocator, choices.options);
    }

    return .{
        .visible_text = visible,
        .choices = choices,
    };
}

fn isValidChoiceCallbackToken(token: []const u8) bool {
    return token.len > 0 and std.mem.indexOfScalar(u8, token, ':') == null;
}

fn choiceCallbackDataLen(token: []const u8, option_id: []const u8) !usize {
    if (!isValidChoiceCallbackToken(token)) return error.InvalidCallbackData;
    if (!isValidChoiceId(option_id)) return error.InvalidCallbackData;
    return CALLBACK_PREFIX.len + token.len + 1 + option_id.len;
}

pub fn formatChoiceCallbackData(
    buf: []u8,
    token: []const u8,
    option_id: []const u8,
    max_len: usize,
) ![]const u8 {
    const needed_len = try choiceCallbackDataLen(token, option_id);
    if (max_len > 0 and needed_len > max_len) return error.CallbackDataTooLong;
    if (needed_len > buf.len) return error.NoSpaceLeft;
    return std.fmt.bufPrint(buf, "{s}{s}:{s}", .{
        CALLBACK_PREFIX,
        token,
        option_id,
    });
}

pub fn buildChoiceCallbackData(
    allocator: std.mem.Allocator,
    token: []const u8,
    option_id: []const u8,
    max_len: usize,
) ![]u8 {
    const needed_len = try choiceCallbackDataLen(token, option_id);
    if (max_len > 0 and needed_len > max_len) return error.CallbackDataTooLong;

    const encoded = try allocator.alloc(u8, needed_len);
    errdefer allocator.free(encoded);
    _ = try std.fmt.bufPrint(encoded, "{s}{s}:{s}", .{
        CALLBACK_PREFIX,
        token,
        option_id,
    });
    return encoded;
}

pub fn parseChoiceCallbackData(data: []const u8) ?ChoiceCallbackData {
    if (!std.mem.startsWith(u8, data, CALLBACK_PREFIX)) return null;
    const rest = data[CALLBACK_PREFIX.len..];
    const sep = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    if (sep == 0 or sep + 1 >= rest.len) return null;
    const token = rest[0..sep];
    const option_id = rest[sep + 1 ..];
    if (!isValidChoiceCallbackToken(token)) return null;
    if (!isValidChoiceId(option_id)) return null;
    return .{
        .token = token,
        .option_id = option_id,
    };
}

fn findChoicesBlock(text: []const u8) ?ChoicesBlockSpan {
    const open_start = std.mem.indexOf(u8, text, START_TAG) orelse return null;
    const content_start = open_start + START_TAG.len;
    const rel_close = std.mem.indexOfPos(u8, text, content_start, END_TAG) orelse return null;
    return .{
        .open_start = open_start,
        .content_start = content_start,
        .close_start = rel_close,
        .close_end = rel_close + END_TAG.len,
    };
}

fn stripChoicesBlock(allocator: std.mem.Allocator, text: []const u8, span: ChoicesBlockSpan) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, text[0..span.open_start]);
    try out.appendSlice(allocator, text[span.close_end..]);
    return try out.toOwnedSlice(allocator);
}

fn synthesizeFallbackText(allocator: std.mem.Allocator, options: []const ChoiceOption) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "Choose: ");
    for (options, 0..) |opt, i| {
        if (i > 0) try out.appendSlice(allocator, " / ");
        try out.appendSlice(allocator, opt.label);
    }
    return try out.toOwnedSlice(allocator);
}

fn parseChoicesDirective(allocator: std.mem.Allocator, json_payload: []const u8) !?ChoicesDirective {
    if (json_payload.len == 0) return null;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_payload, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const v_val = parsed.value.object.get("v") orelse return null;
    const version = switch (v_val) {
        .integer => |i| i,
        else => return null,
    };
    if (version != 1) return null;

    const options_val = parsed.value.object.get("options") orelse return null;
    if (options_val != .array) return null;
    const items = options_val.array.items;
    if (items.len < MIN_OPTIONS or items.len > MAX_OPTIONS) return null;

    var opts: std.ArrayListUnmanaged(ChoiceOption) = .empty;
    var completed = false;
    defer if (!completed) {
        for (opts.items) |opt| opt.deinit(allocator);
        opts.deinit(allocator);
    };

    for (items) |item| {
        if (item != .object) return null;

        const id_val = item.object.get("id") orelse return null;
        const label_val = item.object.get("label") orelse return null;
        if (id_val != .string or label_val != .string) return null;

        const id = id_val.string;
        const label = label_val.string;
        if (!isValidChoiceId(id)) return null;
        if (label.len == 0 or label.len > MAX_LABEL_LEN) return null;

        const submit_text_raw = blk: {
            if (item.object.get("submit_text")) |st| {
                if (st != .string) return null;
                break :blk st.string;
            }
            break :blk label;
        };
        if (submit_text_raw.len == 0 or submit_text_raw.len > MAX_SUBMIT_TEXT_LEN) return null;

        for (opts.items) |existing| {
            if (std.mem.eql(u8, existing.id, id)) return null;
        }

        const id_copy = try allocator.dupe(u8, id);
        errdefer allocator.free(id_copy);
        const label_copy = try allocator.dupe(u8, label);
        errdefer allocator.free(label_copy);
        const submit_copy = try allocator.dupe(u8, submit_text_raw);
        errdefer allocator.free(submit_copy);

        try opts.append(allocator, .{
            .id = id_copy,
            .label = label_copy,
            .submit_text = submit_copy,
        });
    }

    completed = true;
    return .{
        .version = 1,
        .options = try opts.toOwnedSlice(allocator),
    };
}

fn isValidChoiceId(id: []const u8) bool {
    if (id.len == 0 or id.len > MAX_ID_LEN) return false;
    for (id) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '-';
        if (!ok) return false;
    }
    return true;
}

test "choices parse valid directive and strip block" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "You did it?\n<nc_choices>\n{\"v\":1,\"options\":[{\"id\":\"yes\",\"label\":\"Da\",\"submit_text\":\"Da, sdelal\"},{\"id\":\"no\",\"label\":\"Net\"}]}\n</nc_choices>",
    );
    defer parsed.deinit(allocator);

    try std.testing.expect(parsed.choices != null);
    try std.testing.expectEqualStrings("You did it?\n", parsed.visible_text);
    try std.testing.expectEqual(@as(usize, 2), parsed.choices.?.options.len);
    try std.testing.expectEqualStrings("yes", parsed.choices.?.options[0].id);
    try std.testing.expectEqualStrings("Da", parsed.choices.?.options[0].label);
    try std.testing.expectEqualStrings("Da, sdelal", parsed.choices.?.options[0].submit_text);
    try std.testing.expectEqualStrings("Net", parsed.choices.?.options[1].submit_text); // fallback to label
}

test "choices parse invalid json returns no choices and strips block when visible text remains" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "Question\n<nc_choices>{invalid}</nc_choices>",
    );
    defer parsed.deinit(allocator);

    try std.testing.expect(parsed.choices == null);
    try std.testing.expectEqualStrings("Question\n", parsed.visible_text);
}

test "choices parse invalid json keeps original text when stripping would make it empty" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "<nc_choices>{invalid}</nc_choices>",
    );
    defer parsed.deinit(allocator);

    try std.testing.expect(parsed.choices == null);
    try std.testing.expectEqualStrings("<nc_choices>{invalid}</nc_choices>", parsed.visible_text);
}

test "choices parse rejects duplicate ids" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "Pick\n<nc_choices>{\"v\":1,\"options\":[{\"id\":\"a\",\"label\":\"A\"},{\"id\":\"a\",\"label\":\"B\"}]}</nc_choices>",
    );
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.choices == null);
    try std.testing.expectEqualStrings("Pick\n", parsed.visible_text);
}

test "choices parse rejects too many options" {
    const allocator = std.testing.allocator;
    const text =
        "Pick\n" ++
        "<nc_choices>{\"v\":1,\"options\":[" ++
        "{\"id\":\"a\",\"label\":\"A\"}," ++
        "{\"id\":\"b\",\"label\":\"B\"}," ++
        "{\"id\":\"c\",\"label\":\"C\"}," ++
        "{\"id\":\"d\",\"label\":\"D\"}," ++
        "{\"id\":\"e\",\"label\":\"E\"}," ++
        "{\"id\":\"f\",\"label\":\"F\"}," ++
        "{\"id\":\"g\",\"label\":\"G\"}" ++
        "]}</nc_choices>";
    var parsed = try parseAssistantChoices(allocator, text);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.choices == null);
}

test "choices parse synthesizes fallback text when visible text empty" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "<nc_choices>{\"v\":1,\"options\":[{\"id\":\"a\",\"label\":\"A\"},{\"id\":\"b\",\"label\":\"B\"}]}</nc_choices>",
    );
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.choices != null);
    try std.testing.expectEqualStrings("Choose: A / B", parsed.visible_text);
}

test "choices parse rejects invalid id chars" {
    const allocator = std.testing.allocator;
    var parsed = try parseAssistantChoices(
        allocator,
        "Pick\n<nc_choices>{\"v\":1,\"options\":[{\"id\":\"A\",\"label\":\"A\"},{\"id\":\"b\",\"label\":\"B\"}]}</nc_choices>",
    );
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.choices == null);
}

test "choices callback data roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try buildChoiceCallbackData(allocator, "tok1", "yes", 64);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("nc1:tok1:yes", encoded);

    const parsed = parseChoiceCallbackData(encoded) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("tok1", parsed.token);
    try std.testing.expectEqualStrings("yes", parsed.option_id);
}

test "choices format callback data uses caller buffer" {
    var buf: [64]u8 = undefined;
    const encoded = try formatChoiceCallbackData(&buf, "tok1", "yes", 64);
    try std.testing.expectEqualStrings("nc1:tok1:yes", encoded);
}

test "choices callback data rejects long payload" {
    const allocator = std.testing.allocator;
    const long_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    try std.testing.expectError(error.CallbackDataTooLong, buildChoiceCallbackData(allocator, long_token, "yes", 64));
}

test "choices callback data rejects token separator" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;

    try std.testing.expectError(error.InvalidCallbackData, formatChoiceCallbackData(&buf, "tok:1", "yes", 64));
    try std.testing.expectError(error.InvalidCallbackData, buildChoiceCallbackData(allocator, "tok:1", "yes", 64));
}

test "choices parse callback data rejects malformed payload" {
    try std.testing.expect(parseChoiceCallbackData("nc1:tok") == null);
    try std.testing.expect(parseChoiceCallbackData("bad:tok:yes") == null);
    try std.testing.expect(parseChoiceCallbackData("nc1:tok:extra:yes") == null);
    try std.testing.expect(parseChoiceCallbackData("nc1:tok:YES") == null);
}
