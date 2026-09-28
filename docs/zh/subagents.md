# 子 Agent（Subagents）

NullClaw 可以派生隔离的后台 agent 来并发处理任务。

## 概述

子 agent 在独立线程中运行，拥有独立的工具循环、安全策略和 memory backend。为防止无限循环，`message`、`spawn`、`delegate` 工具被排除。

## 派生

通过 `spawn` 工具或 `/subagents spawn` 命令：

```
/subagents spawn --agent researcher "总结 Log4j 最新 CVE"
```

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
