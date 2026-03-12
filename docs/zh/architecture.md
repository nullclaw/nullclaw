# 架构总览

NullClaw 采用 vtable 可插拔架构。多数能力通过接口实现并在工厂注册，不需要改核心调用链。

## 页面导航

- 这页适合谁：想理解 NullClaw 模块边界、扩展点和实现取舍的开发者与维护者。
- 看完去哪里：准备改代码看 [开发指南](./development.md)；要对照运行时配置看 [配置指南](./configuration.md)；涉及高风险边界看 [安全机制](./security.md)。
- 如果你是从某页来的：从 [README](./README.md) 来，这页提供整体脑图；从 [开发指南](./development.md) 来，这页用于补齐接口与工厂层理解；从 [安全机制](./security.md) 来，可在这里回看 `security`、`runtime`、`gateway` 所在层次。

## 设计核心

- 所有子系统通过统一接口抽象：`ptr: *anyopaque + vtable`。
- 运行时通过工厂选择实现，替换 provider/channel/tool/memory 不需要改业务层。
- 目标是低开销、可移植、可扩展。

## 子系统与扩展点

| 子系统 | 接口 | 内置实现（节选） | 扩展方式 |
|---|---|---|---|
| AI Models | `Provider` | OpenRouter、Anthropic、OpenAI、Ollama、Groq 等 22+ | 添加 provider 实现并注册 |
| Channels | `Channel` | CLI、Telegram、Signal、Discord、Slack、Matrix、WhatsApp、Nostr 等 | 添加 channel 实现并注册 |
| Memory | `Memory` | SQLite（hybrid 检索）、Markdown | 新增 memory backend |
| Tools | `Tool` | shell、file_read、file_write、http_request、browser_open 等 | 新增 tool 实现 |
| Observability | `Observer` | Noop、Log、File、Multi | 对接监控系统 |
| Runtime | `RuntimeAdapter` | Native、Docker、WASM | 新增 runtime adapter |
| Security | `Sandbox` | Landlock、Firejail、Bubblewrap、Docker(auto) | 新增 sandbox backend |
| Tunnel | `Tunnel` | None、Cloudflare、Tailscale、ngrok、Custom | 新增 tunnel provider |
| Peripheral | `Peripheral` | Serial、Arduino、RPi GPIO、STM32/Nucleo | 新增硬件外设驱动 |

## Memory 子系统

| 层 | 实现 |
|---|---|
| Vector 检索 | embedding 以 BLOB 存储在 SQLite，使用 cosine similarity |
| Keyword 检索 | SQLite FTS5 + BM25 |
| Hybrid 合并 | vector + keyword 加权合并 |
| EmbeddingProvider | 通过 vtable 接入 OpenAI/自定义/noop |
| 数据生命周期 | 自动归档 + 清理 |
| 快照迁移 | 全量导出/导入 memory 状态 |

## 架构约束（实战建议）

1. 优先通过新增实现扩展，不直接侵入核心流程。
2. 保持模块职责单一：provider 不跨层依赖 channel 内部。
3. 变更高风险路径（security/runtime/gateway/tools）时，必须补失败路径验证。

## 下一步

- 要开始改实现：继续看 [开发指南](./development.md)，再回到本页对照模块边界。
- 要确认 CLI 与用户侧入口：继续看 [命令参考](./commands.md) 与 [配置指南](./configuration.md)。
- 要审视高风险模块：继续看 [安全机制](./security.md) 和 [Gateway API](./gateway-api.md)。

## 相关页面

- [中文文档入口](./README.md)
- [开发指南](./development.md)
- [配置指南](./configuration.md)
- [安全机制](./security.md)
