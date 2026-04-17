# Lark 运维就绪

本指南定义 Lark/飞书通道的专项运维检查项。

## 健康语义

- websocket 模式下，仅当 running 与 connected 同时为真时才算健康。
- webhook 模式下，运行态有效且回调路径可达才算健康。

## 认证与权限

1. 校验租户 token 获取与刷新行为。
2. 业务码非零应视为运行失败。
3. 权限/scope 类错误应立即升级处理。

## `error.LarkApiError` 快速排查

1. 先运行 `nullclaw doctor`，确认渠道配置在结构上是有效的。
2. 启动后运行 `nullclaw channel status`，确认是否处于 running 但未 connected 的状态。
3. 如果持续出现 `warning(lark): lark websocket cycle failed: error.LarkApiError`，优先按下面三类排查：
   - Lark/飞书应用权限或 scope 缺失
   - 区域端点选择错误（`use_feishu`）
   - websocket 回调配置下发失败
4. 如果旧版 Linux 二进制在进入稳定重连日志前就直接崩溃，先升级版本，再继续做权限排查。

## 事件处置步骤

1. 在飞书/Lark 控制台检查应用权限与 scope。
2. 验证回调端点与 websocket 路径可达。
3. 确认发送者白名单（`allow_from`）与群聊 @ 触发逻辑。
4. 仅在完成根因记录后重启通道实例。

## SLO 信号

- auth_fail_total
- reconnect_total
- outbound_send_fail_total
- healthcheck_fail_total
