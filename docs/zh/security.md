# 安全机制

NullClaw 默认走 secure-by-default：本地绑定、配对鉴权、沙箱隔离、最小权限。

## 页面导航

- 这页适合谁：要评估默认安全边界、审查风险配置，或准备把 NullClaw 接到长期运行环境的人。
- 看完去哪里：要落到具体字段看 [配置指南](./configuration.md)；要对外提供 webhook 看 [Gateway API](./gateway-api.md)；想理解这些边界在系统中的位置看 [架构总览](./architecture.md)。
- 如果你是从某页来的：从 [配置指南](./configuration.md) 来，这页补的是风险判断与默认建议；从 [使用与运维](./usage.md) 来，这页可作为上线前安全检查表；从 [Gateway API](./gateway-api.md) 来，这页帮助确认 pairing、public bind 与 token 管理原则。

## 基线能力

| 项 | 状态 | 说明 |
|---|---|---|
| 网关默认不公网暴露 | 已启用 | 默认绑定 `127.0.0.1`；无 tunnel/显式放开时拒绝公网绑定 |
| 配对鉴权 | 已启用 | 启动时一次性 6 位 pairing code，`POST /pair` 换 token |
| 文件系统范围限制 | 已启用 | 默认 `workspace_only = true`，阻止越界访问 |
| 隧道访问控制 | 已启用 | 公网场景优先通过 Tailscale/Cloudflare/ngrok/custom tunnel |
| 沙箱隔离 | 已启用 | 自动选择 Landlock/Firejail/Bubblewrap/Docker |
| 密钥加密 | 已启用 | 凭据采用 ChaCha20-Poly1305 本地加密存储 |
| 资源限制 | 已启用 | 可配置内存/CPU/子进程等限制 |
| 审计日志 | 已启用 | 可开启并设置保留策略 |

## Channel allowlist 规则

- `allow_from: []`：拒绝所有入站。
- `allow_from: ["*"]`：允许所有来源（高风险，仅显式确认后使用）。
- 其他：按精确匹配允许列表。

## Nostr 特殊规则

- `owner_pubkey` 始终允许（即使 `dm_allowed_pubkeys` 更严格）。
- 私钥使用 `enc2:` 加密格式落盘，仅运行时解密到内存；停止 channel 后清理。

## 推荐安全配置

```json
{
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true,
    "allow_public_bind": false
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": { "backend": "auto" },
    "audit": { "enabled": true, "retention_days": 90 }
  }
}
```

## Shell 环境变量

默认情况下，只有最小的安全环境变量集（`PATH`、`HOME`、`TERM` 等）会传递给 shell 子进程，防止 API 密钥泄露（CWE-200）。

### 路径验证环境变量

### 路径验证环境变量

某些部署场景（如 Kubernetes 中通过 volume mount 注入工具链）需要 `LD_LIBRARY_PATH` 等环境变量来定位共享库，但无条件传递这类变量存在库注入风险。

`tools.path_env_vars` 允许指定值为平台路径列表（Unix 用 `:`，Windows 用 `;`）的环境变量。每个路径组件在传递给子进程前都会经过以下验证：

1. 每个组件必须是绝对路径
2. 每个组件通过 `realpath` 解析（规范化，跟随符号链接）
3. 每个组件必须在工作区或 `allowed_paths` 范围内
4. 系统黑名单路径（`/etc`、`/usr/lib`、`/bin` 等）始终被拒绝

如果任何一个组件验证失败，整个变量会被丢弃。

```json
{
  "autonomy": { "allowed_paths": ["/opt/tools"] },
  "tools": { "path_env_vars": ["LD_LIBRARY_PATH", "PYTHONHOME", "NODE_PATH"] }
}
```

以上述配置为例，当容器环境中 `LD_LIBRARY_PATH=/opt/tools/usr/lib:/opt/tools/lib` 时，shell tool 会验证两个路径组件均在 `/opt/tools`（通过 `allowed_paths`）范围内，然后放行。而攻击者控制的值如 `/tmp/evil:/opt/tools/lib` 会被拒绝，因为 `/tmp/evil` 不在工作区或允许路径内。

## 高风险配置提醒

以下配置会显著扩大权限边界，应仅用于受控环境：

- `autonomy.level = "full"`
- `allowed_commands = ["*"]`
- `allowed_paths = ["*"]`
- `gateway.allow_public_bind = true`

## 下一步

- 要把建议落实到配置：继续看 [配置指南](./configuration.md)，逐项对照 `gateway`、`autonomy`、`security`。
- 要验证对外接入面：继续看 [Gateway API](./gateway-api.md)，检查鉴权与调用方式。
- 要做上线前回归：继续看 [使用与运维](./usage.md)，按诊断与健康检查顺序执行。

## 相关页面

- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [Gateway API](./gateway-api.md)
- [架构总览](./architecture.md)
