//! nullclaw — The smallest AI assistant. Zig-powered.
//!
//! Module hierarchy mirrors ZeroClaw's Rust architecture:
//!   agent, channels, config, cron, daemon, doctor, gateway,
//!   hardware, health, heartbeat, memory, observability,
//!   onboard, providers, security, skills, tools

// Shared utilities
pub const json_util = @import("json_util.zig");
pub const http_util = @import("http_util.zig");
pub const net_security = @import("net_security.zig");
pub const websocket = @import("websocket.zig");

// Phase 1: Core
pub const bus = @import("bus.zig");
pub const config = @import("config.zig");
pub const util = @import("util.zig");
pub const platform = @import("platform.zig");
pub const version = @import("version.zig");
pub const state = @import("state.zig");
pub const status = @import("status.zig");
pub const onboard = @import("onboard.zig");
pub const doctor = @import("doctor.zig");
pub const service = @import("service.zig");
pub const daemon = @import("daemon.zig");
pub const channel_loop = @import("channel_loop.zig");
pub const channel_manager = @import("channel_manager.zig");
pub const channel_catalog = @import("channel_catalog.zig");
pub const migration = @import("migration.zig");

// Phase 2: Agent core
pub const agent = @import("agent.zig");
pub const session = @import("session.zig");
pub const providers = @import("providers/root.zig");
pub const memory = @import("memory/root.zig");

// Phase 3: Networking
pub const gateway = @import("gateway.zig");
pub const channels = @import("channels/root.zig");

// Phase 4: Extensions
pub const security = @import("security/root.zig");
pub const cron = @import("cron.zig");
pub const health = @import("health.zig");
pub const skills = @import("skills.zig");
pub const tools = @import("tools/root.zig");
pub const identity = @import("identity.zig");
pub const cost = @import("cost.zig");
pub const observability = @import("observability.zig");
pub const heartbeat = @import("heartbeat.zig");
pub const runtime = @import("runtime.zig");

// Phase 4b: MCP (Model Context Protocol)
pub const mcp = @import("mcp.zig");
pub const subagent = @import("subagent.zig");

// Phase 4c: Auth
pub const auth = @import("auth.zig");

// Phase 4d: Multimodal
pub const multimodal = @import("multimodal.zig");

// Phase 4e: Agent Routing
pub const agent_routing = @import("agent_routing.zig");

// Phase 5: Hardware & Integrations
pub const hardware = @import("hardware.zig");
pub const integrations = @import("integrations.zig");
pub const peripherals = @import("peripherals.zig");
pub const rag = @import("rag.zig");
pub const skillforge = @import("skillforge.zig");
pub const tunnel = @import("tunnel.zig");
pub const voice = @import("voice.zig");

test {
    // Run tests from all imported modules
    @import("std").testing.refAllDecls(@This());
}
