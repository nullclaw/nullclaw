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

- 对基于 allowlist 的渠道，空 `allow_from` 会拒绝入站消息。
- 想做私有 bot 时要显式填写允许的用户 ID / OpenID。
- `allow_from: ["*"]`：允许所有来源（高风险，仅显式确认后使用）。
- 其他情况通常是精确匹配 allowlist，或该渠道自己的 fallback / group-policy 语义。

## Pairing 与 Webhook 鉴权边界

- `/pair` 仅支持 POST，并要求 `X-Pairing-Code`。
- 多次错误 pairing 尝试会触发限流，并可能进入临时锁定。
- `/.well-known/agent.json` 与 `/.well-known/agent-card.json` 在启用 A2A 时属于公开发现文档。
- 保持 `gateway.require_pairing = true` 时，`/webhook`、`/a2a` 与 `/media/transcribe` 仍在 bearer 鉴权之后；若关闭 pairing，本地绑定下这些端点就不再要求 bearer token。
- Telegram webhook 要求 `X-Telegram-Bot-Api-Secret-Token` 与 `channels.telegram.accounts.<id>.webhook_secret` 匹配。
- 各 channel 专用入站 webhook 继续使用各自的鉴权或签名规则，不应一概写成 gateway bearer 鉴权。

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
- `autonomy.level = "yolo"`
- `allowed_commands = ["*"]`
- `allowed_paths = ["*"]`
- `block_high_risk_commands = false` — 启用破坏性命令（`rm`、`sudo`、`dd`、`mkfs` 等）
- `block_medium_risk_commands = false` — 启用中风险命令，包括网络/传输类命令（`curl`、`wget`、`nc`、`scp` 等）以及 `git commit`、`npm install`、`touch` 等本地变更
- `gateway.allow_public_bind = true`

## 工作区密钥审计 (Workspace Secret Audit)

`nullclaw workspace audit` 用于扫描工作区、已暂存的 Git diff 或某个 Git 修订区间，检测疑似密钥泄漏。检测完全在本机执行，输出 JSON 形式适配 CI 集成。

### 检测内容

| 检测器 | 来源 |
|---|---|
| 已知 token 前缀指纹 | `AKIA…`、`ghp_`、`gho_`、`ghs_`、`glpat-`、`xoxb-`、`xoxp-`、`sk-`、`sk-proj-` 等 |
| 基于评分的赋值匹配器 | 将 `KEY=value` / `key: value` 拆解为命名分量，与 secret 关键字词典进行打分 |
| 格式检测器 | `-----BEGIN PRIVATE KEY-----` PEM 块；URL 中嵌入的凭据（`scheme://user:pass@host/...`） |
| 高熵字符串扫描 | 长度 ≥ 16 且 Shannon 熵 ≥ 4.0 的 token 形态字符串，排除 UUID、git commit hash 与占位符 |

退出码遵循 `--fail-on <none\|medium\|high\|critical>`（默认 `high`）。配合 `--json` 可用于 CI 流水线。

### 可选的 LLM 二次分类（envelope 形式）

`--llm-triage` 是可选的二次分类阶段，使用 agent 已配置的 LLM provider 对 finding 进行 real_secret / false_positive / uncertain 判定。LLM 收到的是**隐私安全 envelope**，不包含原始密钥值：

| envelope 中包含 | envelope 中**不**包含 |
|---|---|
| `variable_name`、`file_path`、`extension`、`detector` | 密钥原值 |
| `token_type_fingerprint`（本地前缀查表得出） | 密钥的任何子串 |
| `length`、`charset`、`entropy` | 密钥所在行的真实内容 |
| 行上下文掩码（如 `KEY=<SECRET:len=40,charset=base64url,entropy=5.3>`） | 周围非白名单的词 |
| 经白名单过滤的 `nearby_keywords`（约 60 个 security/service 通用词） | 客户名、内部主机名、业务标识 |
| 确定性标志：`is_test_path`、`is_example_file`、`is_in_comment`、`is_in_docstring` | LLM 对这些标志的推断 |

Envelope 模式带版本（`schema_version: "1"`），并附带每条 envelope 的 SHA-256 `envelope_hash` 用于可追溯性。

三种模式：

- `--llm-triage off`（默认）— 不调用 LLM；与基线扫描结果一致
- `--llm-triage dry-run` — 仅打印将要发送的 envelope（输出到 stderr），不发起任何网络请求。建议在启用前用此模式确认实际离开本机的内容
- `--llm-triage external` — 通过已配置 provider vtable 提交 envelope。若存在 `workspace_audit.llm_triage.{provider,model}` 则优先使用它们，否则使用配置中的 primary provider 和 model；也可用 `--llm-provider` / `--llm-model` 覆盖。若 provider 是本地的（如 Ollama），envelope 也不会离开本机

如果希望 audit triage 使用更小或本地的模型，而不改变普通 agent 模型，可以配置：

```json
{
  "workspace_audit": {
    "llm_triage": {
      "provider": "ollama",
      "model": "qwen2.5-coder:7b",
      "max_calls": 20
    }
  }
}
```

这个配置本身不会启用外部 LLM 调用；操作者仍然必须显式传入 `--llm-triage external`。单次运行可用 `--llm-provider`、`--llm-model`、`--llm-max-calls` 覆盖这些配置。未知 provider 名称会被拒绝，除非它有显式的 `models.providers.<name>.base_url`；因此拼写错误不会静默地把 audit envelope 路由到 fallback provider。

每次 `external` 请求都会追加到 `<config-dir>/audit-log.jsonl`。NullClaw 会在 LLM 调用前先写入包含 envelope 的 `sent` 事件，再在响应后写入按 `envelope_hash` 关联的 `verdict` 事件。日志仅追加，便于事后核对实际发出的元数据。

### 运维注意

- 默认 `--llm-triage off` 意味着对现有扫描行为零影响；仅在误报较多时显式启用
- 对隐私敏感场景，启用 `--llm-triage external` 前将 `workspace_audit.llm_triage.provider` 固定为 `ollama` 等本地 provider
- LLM 的判定是参考性的：`false_positive` 会丢弃该 finding，`real_secret` 可能调整 severity。是否上报某候选仍由 Stage 1 的确定性检测器决定

## 下一步

- 要把建议落实到配置：继续看 [配置指南](./configuration.md)，逐项对照 `gateway`、`autonomy`、`security`。
- 要验证对外接入面：继续看 [Gateway API](./gateway-api.md)，检查鉴权与调用方式。
- 要做上线前回归：继续看 [使用与运维](./usage.md)，按诊断与健康检查顺序执行。

## 相关页面

- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [Gateway API](./gateway-api.md)
- [架构总览](./architecture.md)
