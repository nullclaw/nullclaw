const std = @import("std");

pub fn canonicalProviderName(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "grok")) return "xai";
    if (std.mem.eql(u8, name, "together")) return "together-ai";
    if (std.mem.eql(u8, name, "google") or std.mem.eql(u8, name, "google-gemini")) return "gemini";
    if (std.mem.eql(u8, name, "vertex-ai") or std.mem.eql(u8, name, "google-vertex")) return "vertex";
    if (std.mem.eql(u8, name, "claude-code")) return "claude-cli";
    if (std.mem.eql(u8, name, "azure-openai") or std.mem.eql(u8, name, "azure_openai")) return "azure";
    if (std.mem.eql(u8, name, "novita-ai")) return "novita";
    return name;
}

pub fn canonicalProviderNameIgnoreCase(name: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(name, "grok")) return "xai";
    if (std.ascii.eqlIgnoreCase(name, "together")) return "together-ai";
    if (std.ascii.eqlIgnoreCase(name, "google") or std.ascii.eqlIgnoreCase(name, "google-gemini")) return "gemini";
    if (std.ascii.eqlIgnoreCase(name, "vertex-ai") or std.ascii.eqlIgnoreCase(name, "google-vertex")) return "vertex";
    if (std.ascii.eqlIgnoreCase(name, "claude-code")) return "claude-cli";
    if (std.ascii.eqlIgnoreCase(name, "azure-openai") or std.ascii.eqlIgnoreCase(name, "azure_openai")) return "azure";
    if (std.ascii.eqlIgnoreCase(name, "novita-ai")) return "novita";
    return name;
}

pub fn providerNamesMatch(lhs: []const u8, rhs: []const u8) bool {
    return std.mem.eql(u8, canonicalProviderName(lhs), canonicalProviderName(rhs));
}

pub fn providerNamesMatchIgnoreCase(lhs: []const u8, rhs: []const u8) bool {
    return std.ascii.eqlIgnoreCase(canonicalProviderNameIgnoreCase(lhs), canonicalProviderNameIgnoreCase(rhs));
}

test "canonicalProviderName handles supported aliases" {
    try std.testing.expectEqualStrings("xai", canonicalProviderName("grok"));
    try std.testing.expectEqualStrings("together-ai", canonicalProviderName("together"));
    try std.testing.expectEqualStrings("gemini", canonicalProviderName("google"));
    try std.testing.expectEqualStrings("gemini", canonicalProviderName("google-gemini"));
    try std.testing.expectEqualStrings("vertex", canonicalProviderName("vertex-ai"));
    try std.testing.expectEqualStrings("vertex", canonicalProviderName("google-vertex"));
    try std.testing.expectEqualStrings("claude-cli", canonicalProviderName("claude-code"));
    try std.testing.expectEqualStrings("azure", canonicalProviderName("azure-openai"));
    try std.testing.expectEqualStrings("azure", canonicalProviderName("azure_openai"));
    try std.testing.expectEqualStrings("novita", canonicalProviderName("novita-ai"));
}

test "providerNamesMatch handles aliases without broadening custom providers" {
    try std.testing.expect(providerNamesMatch("azure", "azure-openai"));
    try std.testing.expect(providerNamesMatch("gemini", "google"));
    try std.testing.expect(!providerNamesMatch("custom:https://Example.com/v1", "custom:https://example.com/v1"));
}

test "providerNamesMatchIgnoreCase preserves case-insensitive matching" {
    try std.testing.expect(providerNamesMatchIgnoreCase("azure", "AZURE-OPENAI"));
    try std.testing.expect(providerNamesMatchIgnoreCase("CustomGW", "customgw"));
}
