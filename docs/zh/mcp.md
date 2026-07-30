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

## 相关页面

- [配置指南](./configuration.md)
- [架构总览](./architecture.md)
- [安全机制](./security.md)
