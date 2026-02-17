//! Agent module — delegates to agent/root.zig.
//!
//! Re-exports all public symbols from the agent submodule.

const agent_root = @import("agent/root.zig");

pub const Agent = agent_root.Agent;
pub const dispatcher = agent_root.dispatcher;
pub const prompt = agent_root.prompt;
pub const memory_loader = agent_root.memory_loader;
pub const run = agent_root.run;
pub const processMessage = agent_root.processMessage;

test {
    _ = agent_root;
}
