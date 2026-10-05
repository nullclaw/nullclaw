# 子 Agent（Subagents）

NullClaw 可以派生隔离的后台 agent 来并发处理任务。

## 概述

子 agent 在独立线程中运行，拥有独立的工具循环、安全策略和 memory backend。为防止无限循环，`message`、`spawn`、`delegate` 工具被排除。

## 派生

通过 `spawn` 工具或 `/subagents spawn` 命令：

```
/subagents spawn --agent researcher "总结 Log4j 最新 CVE"
```

`spawn` 工具只接受三个参数：`task`（必填）、`label`（可选，默认 `"subagent"`）、
`agent`（可选，来自 `agents.list` 的命名配置，用于覆盖 provider/model）。

### `delegate` 不是子 agent

`delegate` 工具**不会**派生后台子 agent。它在调用线程内同步调用
`completeAgentPrompt` 并直接返回结果 —— 不会创建 `SubagentManager` 任务，
不并发执行，也不会签发 task ID。

若需要后台执行，请使用 `spawn` 或 `/subagents spawn`。`delegate` 只是把一个
prompt 作为单一聚焦单元同步完成。

## 查询子 agent

使用 `/subagents` 命令。没有任何工具可用于查询任务状态。

```
/subagents                    # 列表（`list` 的别名，也是 `status` 的别名）
/subagents list               # 列出任务
/subagents status             # 同 list
/subagents info <id>          # 单个任务详情
/subagents kill <id|all>      # 终止任务
/subagents help               # 用法
```

注意：

- `spawn` 是唯一与子 agent 相关的**工具**，其 schema 为 `{task, label, agent}`，
  无法查询或取消任务。
- `getTaskStatus`、`getTaskResult`、`getRunningCount` 是 `SubagentManager`
  上的**内部 Zig 方法**（`src/subagent.zig`），无法从 prompt、工具调用或斜杠
  命令中调用。
- `kill` 是通用的任务终止命令，与其他后台任务机制共用，并非子 agent 专用，
  且无法复活已完成的任务。

## 限制

子 agent 的限制为内置值，目前无法通过 `config.json` 配置：

- 每个子 agent 最多 15 次工具循环迭代
- 最多 4 个并发子 agent

## 工作空间隔离

每个命名 agent 可配置独立 `workspace_path`，相对路径从配置目录解析，首次使用时自动创建。

## 结果路由

子 agent 完成后，结果发布回原始会话：
- 成功：`[Subagent 'label' completed]\nRESULT`
- 失败：`[Subagent 'label' failed]\nERROR`

## 相关页面

- [配置指南](./configuration.md)
- [命令参考](./commands.md)
