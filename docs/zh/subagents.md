# 子 Agent（Subagents）

NullClaw 可以派生隔离的后台 agent 来并发处理任务。

## 概述

子 agent 在独立线程中运行，拥有独立的工具循环、安全策略和 memory backend。为防止无限循环，`message`、`spawn`、`delegate` 工具被排除。

## 派生

通过 `spawn` 工具或 `/subagents spawn` 命令：

```
/subagents spawn --agent researcher "总结 Log4j 最新 CVE"
```

## 配置

```json
{
  "agents": {
    "defaults": {
      "subagent_max_iterations": 15,
      "subagent_max_concurrent": 4
    }
  }
}
```

## 工作空间隔离

每个命名 agent 可配置独立 `workspace_path`，相对路径从配置目录解析，首次使用时自动创建。

## 结果路由

子 agent 完成后，结果发布回原始会话：
- 成功：`[Subagent 'label' completed]\nRESULT`
- 失败：`[Subagent 'label' failed]\nERROR`

## 相关页面

- [配置指南](./configuration.md)
- [命令参考](./commands.md)
