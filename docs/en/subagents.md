# Subagents

NullClaw can spawn isolated background agents to handle tasks concurrently without blocking the main conversation.

## Overview

Subagents run in separate OS threads with their own tool loop, security policy, and memory backend. They have a restricted tool set — `message`, `spawn`, and `delegate` are excluded to prevent infinite loops.

## Spawning

Subagents are spawned via the `spawn` tool or the `/subagents spawn` command:

```
/subagents spawn --agent researcher "Summarize the latest CVEs for Log4j"
```

The `delegate` tool also spawns subagents internally when the agent decides to offload work.

## Configuration

Subagent limits are controlled in `~/.nullclaw/config.json`:

```json
{
  "agents": {
    "defaults": {
      "subagent_max_iterations": 15,
      "subagent_max_concurrent": 4
    }
  }
}
```

| Field | Default | Notes |
|-------|---------|-------|
| `subagent_max_iterations` | 15 | Max tool loop iterations per subagent |
| `subagent_max_concurrent` | 4 | Max concurrent subagents |

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

## Query

Check subagent status via the `spawn` tool or agent commands:

- `getTaskStatus(task_id)` — running, completed, or failed
- `getTaskResult(task_id)` — result text
- `getRunningCount()` — number of active subagents
