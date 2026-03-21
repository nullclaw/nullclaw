# DingTalk 运维就绪

这页聚焦 DingTalk 渠道的专项验证，以及“能发不能收”这类问题的最快排查路径。

## 页面导航

**这页适合谁**

- 正在验证 DingTalk 新部署的运维者
- 排查入站消息缺失或 channel 健康异常的维护者
- 需要判断问题究竟来自配置漂移、过旧二进制还是 DingTalk 侧投递的贡献者

**看完先去哪里**

- 通用服务化和日志流程看 [使用与运维](../usage.md)
- 主配置上下文看 [配置指南](../configuration.md)
- 要放宽 `allow_from` 前先看 [安全机制](../security.md)

## 健康状态应该是什么样

- 当前版本会把 DingTalk 作为 gateway-loop channel 启动，所以日志里应看到
  `dingtalk gateway started`，而不是 `dingtalk started (send-only)`。
- 只有 runtime 已运行且 DingTalk stream websocket 已连通时，channel 健康状态才为真。
- 即使入站坏了，只要 session webhook 目标还新鲜，出站回复仍可能成功；因此
  “能发不能收”通常优先看 stream 链路，而不是 reply 链路。

## 上线前检查清单

1. 先确认你运行的是当前版本。如果日志里还出现
   `dingtalk started (send-only)`，先升级。
2. 检查 `channels.dingtalk.accounts.<id>.client_id` 和 `client_secret`
   是否来自同一个 DingTalk 应用。
3. 检查 `allow_from` 不是空数组。`allow_from: []` 会拒绝所有入站消息。
4. 用 `nullclaw gateway` 启动 runtime，再用 `nullclaw channel status`
   确认 DingTalk 显示为 healthy。
5. 如果怀疑凭据问题，可执行
   `nullclaw --probe-channel-health --channel dingtalk --account <id>`
   验证 token 获取链路。

## 如果入站消息始终收不到

1. 确认 DingTalk 应用已按 stream mode 配置入站投递。当前 runtime 会通过
   DingTalk 的 gateway connection API 打开 websocket；只有出站能力还不够。
2. 确认应用订阅了你期望接收的消息事件。若 DingTalk 根本没发这些回调，
   nullclaw 就没有东西可 ingest。
3. 前台运行并先记录第一条 DingTalk 错误，再考虑重启。最关键的日志通常是
   `dingtalk websocket cycle failed`、
   `dingtalk websocket read failed` 和
   `dingtalk envelope handling failed`。
4. 用一个明确出现在 `allow_from` 里的发送者重新测试。allowlist 未命中看起来像
   “消息被忽略”，而不是传输层失败。

## 回复目标与回退行为

- 新鲜的回复目标会直接使用入站事件携带的 `sessionWebhook` URL。
- 群聊回复目标过期后，nullclaw 可以利用缓存的 conversation id 回退到
  DingTalk AI interaction API。
- 直聊回复目标没有这个群聊回退；session webhook 过期后，需要新的入站事件或
  显式 proactive target。
- 任意 `https://...` webhook 目标会被有意拒绝，出站媒体载荷当前也不支持。

## 建议的验证顺序

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw gateway
```

然后让一个已放行的 DingTalk 发送者发消息，优先记录第一条运行时错误，再做后续操作。
