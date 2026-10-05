# Subagents

NullClaw can spawn isolated background agents to handle tasks concurrently without blocking the main conversation.

## Overview

Subagents run in separate OS threads with their own tool loop, security policy, and memory backend. They have a restricted tool set — `message`, `spawn`, and `delegate` are excluded to prevent infinite loops.

## Spawning

Subagents are spawned via the `spawn` tool or the `/subagents spawn` command:

```
/subagents spawn --agent researcher "Summarize the latest CVEs for Log4j"
```

The `spawn` tool accepts exactly three parameters: `task` (required), `label`
(optional, defaults to `"subagent"`), and `agent` (optional, a named profile
from `agents.list` used for provider/model override).

### `delegate` is not a subagent

The `delegate` tool does **not** spawn a background subagent. It calls
`completeAgentPrompt` synchronously in the calling thread and returns that
result — no `SubagentManager` task is created, nothing runs concurrently, and no
task ID is issued.

If you want work to run in the background, use `spawn` or `/subagents spawn`.
`delegate` is a single synchronous call that happens to be useful when a prompt
should be completed as one focused unit.

## Limits

Subagent limits are built in and not currently configurable via `config.json`:

| Limit | Default | Notes |
|-------|---------|-------|
| Max tool loop iterations | 15 | Per subagent |
| Max concurrent subagents | 4 | Across the manager |

## Workspace Isolation

Each named agent can have its own `workspace_path`:

```json
{
  "agents": {
    "list": [
      {
        "id": "researcher",
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4",
        "workspace_path": "./workspaces/researcher"
      }
    ]
  }
}
```

Relative paths resolve from the config directory. The workspace is scaffolded on first use, and the agent gets a durable memory namespace `agent:<agent-id>`.

## Result Routing

When a subagent completes, its result is published back to the originating session:

- Success: `[Subagent 'label' completed]\nRESULT`
- Failure: `[Subagent 'label' failed]\nERROR`

## Querying Subagents

Use the `/subagents` commands. There is no tool operation for querying task
state.

```
/subagents                    # list (alias of `list`, and of `status`)
/subagents list               # list tasks
/subagents status             # same as list
/subagents info <id>          # detail for one task
/subagents kill <id|all>      # terminate a task
/subagents help               # usage
```

Notes:

- `spawn` is the only subagent-related *tool*. Its schema is `{task, label, agent}`
  — it cannot query or cancel a task.
- `getTaskStatus`, `getTaskResult`, and `getRunningCount` are **internal Zig
  methods** on `SubagentManager` (`src/subagent.zig`). They are not invokable
  from a prompt, a tool call, or a slash command.
- `kill` is the general task-termination command, shared with the other
  background-job machinery. It is not subagent-specific, and it cannot revive a
  completed task.
