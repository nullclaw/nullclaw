# MCP (Model Context Protocol)

NullClaw supports the [Model Context Protocol](https://modelcontextprotocol.io/) to extend agent capabilities with external tools and services.

## Transports

- **stdio**: Launch MCP servers as child processes. Best for local tools and npm packages.
- **http**: Connect to remote MCP servers over HTTPS (or localhost HTTP). Supports custom headers and timeouts.

## Configuration

Add MCP servers to `~/.nullclaw/config.json` under `mcp_servers`:

```json
{
  "mcp_servers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    },
    "remote": {
      "transport": "http",
      "url": "https://mcp.example.com/rpc",
      "timeout_ms": 10000,
      "headers": {
        "Authorization": "Bearer token-here"
      }
    }
  }
}
```

### Config Fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `transport` | string | `stdio` | `stdio` or `http` |
| `command` | string | — | Executable for stdio transport |
| `args` | array | `[]` | Command arguments |
| `env` | array | `[]` | Environment variables: `[{"key": "K", "value": "V"}]` |
| `url` | string | — | HTTP endpoint URL (required for http transport) |
| `timeout_ms` | number | `10000` | Per-request timeout in milliseconds |
| `headers` | array | `[]` | Custom HTTP headers: `[{"key": "K", "value": "V"}]` |

## How It Works

On startup, nullclaw:

1. Connects to each configured MCP server (stdio: spawns process; http: connects to endpoint)
2. Performs the MCP `initialize` handshake
3. Discovers available tools via `tools/list`
4. Wraps each tool with prefix `mcp_<server>_<tool>` (e.g., `mcp_filesystem_read_file`)
5. Exposes them to the agent alongside built-in tools

Tool discovery happens once at startup — there is no hot-reload. Restart nullclaw to pick up new MCP tools.

## Security

- **HTTP URLs**: Must be HTTPS for remote hosts. Plain HTTP is allowed only for localhost and private IPs (127.0.0.1, 10.x, 192.168.x, 172.16-31.x, ::1, fd00::/8, Tailscale 100.64-127.x).
- **Headers**: Validated to prevent injection — no CR/LF allowed in values.
- **Timeouts**: Enforced per-request (default 10s). Adjust `timeout_ms` for slow tools.
- **Failures**: Individual server connection errors are logged and skipped. The agent continues with remaining tools.

## Tool Filtering

Use `agent.tool_filter_groups` to control which MCP tools are included per turn:

```json
{
  "agent": {
    "tool_filter_groups": [
      {
        "mode": "always",
        "tools": ["mcp_filesystem_*"]
      },
      {
        "mode": "dynamic",
        "tools": ["mcp_jira_*"],
        "keywords": ["ticket", "jira", "issue"]
      }
    ]
  }
}
```

- `always`: Tools matching the pattern are always included.
- `dynamic`: Tools are included only when the user message contains a keyword.

## Related

- [Configuration](./configuration.md) — Full config reference
- [Architecture](./architecture.md) — Subsystem overview
- [Security](./security.md) — Security model
