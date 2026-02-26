//! Agent module — delegates to agent/root.zig.
//!
//! Re-exports all public symbols from the agent submodule.

const agent_root = @import("agent/root.zig");
const prompt_mod = @import("agent/prompt.zig");

pub const Agent = agent_root.Agent;
pub const run = agent_root.run;
pub const ConversationContext = prompt_mod.ConversationContext;

test {
    _ = agent_root;
}
