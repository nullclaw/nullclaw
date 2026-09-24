# MCP（模型上下文协议）

NullClaw 支持 [Model Context Protocol](https://modelcontextprotocol.io/)，通过外部工具和服务扩展 agent 能力。

## 传输方式

- **stdio**：以子进程方式启动 MCP 服务器，适合本地工具和 npm 包。
- **http**：通过 HTTPS（或 localhost HTTP）连接远程 MCP 服务器，支持自定义 headers 和超时。

## 配置

在 `~/.nullclaw/config.json` 的 `mcp_servers` 下添加：

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

## 工作原理

启动时，nullclaw 连接每个 MCP 服务器，执行 `initialize` 握手，通过 `tools/list` 发现工具，以 `mcp_<服务器>_<工具>` 前缀暴露给 agent。

工具发现仅在启动时执行一次，重启 nullclaw 以加载新工具。

## 安全

- HTTP URL 必须为 HTTPS（localhost 和私有 IP 除外）
- Header 值禁止换行符
- 单个服务器连接失败不影响其他工具

## 工具过滤

通过 `agent.tool_filter_groups` 控制每轮包含哪些 MCP 工具：

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

- `always`：匹配该模式的工具始终包含。
- `dynamic`：仅当用户消息包含关键词时才包含。

若未配置任何 `tool_filter_groups`，本轮包含全部工具。非 MCP 工具始终包含。`always` 分组在每一轮包含匹配的 MCP 工具。`dynamic` 分组仅当用户消息包含该组关键词之一时包含匹配的 MCP 工具。

## 相关页面

- [配置指南](./configuration.md)
- [架构总览](./architecture.md)
- [安全机制](./security.md)
