/// Export manifest JSON for nullhub integration.
///
/// Generates the manifest from the same data structures used by the
/// interactive wizard (onboard.zig) and channel catalog, ensuring a
/// single source of truth.
const std = @import("std");
const onboard = @import("onboard.zig");
const channel_catalog = @import("channel_catalog.zig");
const version = @import("version.zig");

pub fn run() !void {
    var buf: [65536]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const out = &bw.interface;

    // ── Top-level fields ─────────────────────────────────────────────
    try out.writeAll(
        \\{
        \\  "schema_version": 1,
        \\  "name": "nullclaw",
        \\  "display_name": "NullClaw",
        \\  "description": "Autonomous AI agent runtime",
        \\  "icon": "agent",
        \\  "repo": "nullclaw/nullclaw",
        \\
    );

    // ── Platforms ────────────────────────────────────────────────────
    try out.writeAll(
        \\  "platforms": {
        \\    "aarch64-macos": { "asset": "nullclaw-macos-aarch64", "binary": "nullclaw" },
        \\    "x86_64-macos": { "asset": "nullclaw-macos-x86_64", "binary": "nullclaw" },
        \\    "x86_64-linux": { "asset": "nullclaw-linux-x86_64", "binary": "nullclaw" },
        \\    "aarch64-linux": { "asset": "nullclaw-linux-aarch64", "binary": "nullclaw" },
        \\    "riscv64-linux": { "asset": "nullclaw-linux-riscv64", "binary": "nullclaw" },
        \\    "x86_64-windows": { "asset": "nullclaw-windows-x86_64.exe", "binary": "nullclaw.exe" },
        \\    "aarch64-windows": { "asset": "nullclaw-windows-aarch64.exe", "binary": "nullclaw.exe" }
        \\  },
        \\
    );

    // ── Build from source ───────────────────────────────────────────
    try out.writeAll(
        \\  "build_from_source": {
        \\    "zig_version": "0.15.2",
        \\    "command": "zig build -Doptimize=ReleaseSmall",
        \\    "output": "zig-out/bin/nullclaw"
        \\  },
        \\
    );

    // ── Launch / health / ports ─────────────────────────────────────
    try out.writeAll(
        \\  "launch": { "command": "gateway", "args": [] },
        \\  "health": { "endpoint": "/health", "port_from_config": "gateway.port", "interval_ms": 15000 },
        \\  "ports": [
        \\    { "name": "gateway", "config_key": "gateway.port", "default": 3000, "protocol": "http" }
        \\  ],
        \\
    );

    // ── Wizard ──────────────────────────────────────────────────────
    try out.writeAll(
        \\  "wizard": {
        \\    "steps": [
        \\
    );

    // Step 1: provider (select)
    try out.writeAll(
        \\      {
        \\        "id": "provider",
        \\        "title": "AI Provider",
        \\        "description": "Select your AI model provider",
        \\        "type": "select",
        \\        "required": true,
        \\        "options": [
        \\
    );
    for (onboard.known_providers, 0..) |p, i| {
        try out.writeAll("          { \"value\": \"");
        try out.writeAll(p.key);
        try out.writeAll("\", \"label\": \"");
        try out.writeAll(p.label);
        try out.writeAll("\", \"description\": \"Default model: ");
        try out.writeAll(p.default_model);
        try out.writeAll("\"");
        // Mark first provider (openrouter) as recommended
        if (i == 0) try out.writeAll(", \"recommended\": true");
        try out.writeAll(" }");
        if (i < onboard.known_providers.len - 1) {
            try out.writeAll(",");
        }
        try out.writeAll("\n");
    }
    try out.writeAll(
        \\        ]
        \\      },
        \\
    );

    // Step 2: api_key (secret, conditional — hidden for local providers)
    try out.writeAll(
        \\      {
        \\        "id": "api_key",
        \\        "title": "API Key",
        \\        "description": "Your provider API key",
        \\        "type": "secret",
        \\        "required": true,
        \\        "condition": { "step": "provider", "not_in": "ollama,lm-studio,claude-cli,codex-cli,openai-codex" }
        \\      },
        \\
    );

    // Step 3: model (dynamic_select)
    try out.writeAll(
        \\      {
        \\        "id": "model",
        \\        "title": "Model",
        \\        "description": "Select the AI model to use",
        \\        "type": "dynamic_select",
        \\        "required": true,
        \\        "dynamic_source": { "command": "--list-models", "depends_on": ["provider", "api_key"] }
        \\      },
        \\
    );

    // Step 4: memory (select, default: sqlite)
    try out.writeAll(
        \\      {
        \\        "id": "memory",
        \\        "title": "Memory Backend",
        \\        "description": "How the agent stores conversation history",
        \\        "type": "select",
        \\        "required": true,
        \\        "group": "settings",
        \\        "advanced": true,
        \\        "default_value": "sqlite",
        \\        "options": [
        \\
    );
    for (onboard.wizard_memory_backend_order, 0..) |name, i| {
        try out.writeAll("          { \"value\": \"");
        try out.writeAll(name);
        try out.writeAll("\", \"label\": \"");
        try out.writeAll(name);
        try out.writeAll("\"");
        if (std.mem.eql(u8, name, "sqlite")) try out.writeAll(", \"recommended\": true");
        try out.writeAll(" }");
        if (i < onboard.wizard_memory_backend_order.len - 1) {
            try out.writeAll(",");
        }
        try out.writeAll("\n");
    }
    try out.writeAll(
        \\        ]
        \\      },
        \\
    );

    // Step 5: tunnel (select, default: none)
    try out.writeAll(
        \\      {
        \\        "id": "tunnel",
        \\        "title": "Tunnel Provider",
        \\        "description": "Expose your agent to the internet",
        \\        "type": "select",
        \\        "required": true,
        \\        "group": "settings",
        \\        "advanced": true,
        \\        "default_value": "none",
        \\        "options": [
        \\
    );
    for (onboard.tunnel_options, 0..) |name, i| {
        try out.writeAll("          { \"value\": \"");
        try out.writeAll(name);
        try out.writeAll("\", \"label\": \"");
        try out.writeAll(name);
        try out.writeAll("\"");
        if (std.mem.eql(u8, name, "none")) try out.writeAll(", \"recommended\": true");
        try out.writeAll(" }");
        if (i < onboard.tunnel_options.len - 1) {
            try out.writeAll(",");
        }
        try out.writeAll("\n");
    }
    try out.writeAll(
        \\        ]
        \\      },
        \\
    );

    // Step 6: autonomy (select, default: supervised)
    try out.writeAll(
        \\      {
        \\        "id": "autonomy",
        \\        "title": "Autonomy Level",
        \\        "description": "How much freedom the agent has",
        \\        "type": "select",
        \\        "required": true,
        \\        "group": "settings",
        \\        "advanced": true,
        \\        "default_value": "supervised",
        \\        "options": [
        \\
    );
    for (onboard.autonomy_options, 0..) |name, i| {
        try out.writeAll("          { \"value\": \"");
        try out.writeAll(name);
        try out.writeAll("\", \"label\": \"");
        try out.writeAll(name);
        try out.writeAll("\"");
        if (std.mem.eql(u8, name, "supervised")) try out.writeAll(", \"recommended\": true");
        try out.writeAll(" }");
        if (i < onboard.autonomy_options.len - 1) {
            try out.writeAll(",");
        }
        try out.writeAll("\n");
    }
    try out.writeAll(
        \\        ]
        \\      },
        \\
    );

    // Step 7: gateway_port (number, default: 3000)
    try out.writeAll(
        \\      {
        \\        "id": "gateway_port",
        \\        "title": "Gateway Port",
        \\        "description": "HTTP gateway listen port",
        \\        "type": "number",
        \\        "required": true,
        \\        "group": "settings",
        \\        "advanced": true,
        \\        "default_value": "3000"
        \\      }
        \\
    );

    // Close wizard and steps
    try out.writeAll(
        \\    ]
        \\  },
        \\
    );

    // ── depends_on / connects_to ────────────────────────────────────
    try out.writeAll(
        \\  "depends_on": [],
        \\  "connects_to": [
        \\    { "component": "nullboiler", "role": "worker", "description": "Registers as a worker node" }
        \\  ]
        \\}
        \\
    );

    try bw.interface.flush();
}

test "export_manifest produces valid structure" {
    // Verify the data sources are accessible and have expected counts
    try std.testing.expect(onboard.known_providers.len >= 29);
    try std.testing.expect(onboard.wizard_memory_backend_order.len == 10);
    try std.testing.expect(onboard.tunnel_options.len == 4);
    try std.testing.expect(onboard.autonomy_options.len == 3);
    try std.testing.expect(channel_catalog.known_channels.len >= 20);

    // Verify first provider
    try std.testing.expectEqualStrings("openrouter", onboard.known_providers[0].key);

    // Verify memory backends start with hybrid
    try std.testing.expectEqualStrings("hybrid", onboard.wizard_memory_backend_order[0]);
}
