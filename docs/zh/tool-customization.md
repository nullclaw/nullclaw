# 工具定制管理

- 为内置工具添加自定义系统提示词、触发关键词和优先级，以提高工具调用的准确性和响应速度。
- 支持事前无LLM模式: 对工具(如screenshot)支持配置特定触发词(trigger)可以实现直接调用工具的功能，而无需 LLM 参与。
- 支持事后LLM模式: 对工具(如screenshot)支持配置skip_llm_tpl参数可将调用工具的输出直接模板化后返回给用户，而无需 LLM 参与。

## 快速开始

### 1. 查看内置工具列表

```bash
nullclaw tools show --builtin
```

### 2. 查看当前工具定制

```bash
nullclaw tools show
```

### 3. 导出内置工具到 JSON 文件

```bash
nullclaw tools export builtin_tools.json --builtin
```

### 4. 导出工具定制到 JSON 文件

```bash
nullclaw tools export tool_customizations.json
```

### 5. 验证工具定制 JSON 文件

```bash
nullclaw tools validate tool_customizations.json
```

### 6. 导入工具定制（查看预览）

```bash
nullclaw tools import tool_customizations.json
```

**注意**：`import` 命令只显示预览，不会自动应用配置。要应用配置，需要手动编辑配置文件。

## 配置方式

### 方式一：使用外部 JSON 文件

在 `~/.nullclaw/config.json` 中指定外部文件路径：

```json
{
  "tools": {
    "tool_customizations_file": "/path/to/tool_customizations.json"
  }
}
```

外部文件格式：

```json
{
  "screenshot": {
    "system_prompt": "...",
    "triggers": ["截屏", "截图", "screenshot"],
    "priority": 10,
    "enabled": true
  },
  "file_read": {
    "system_prompt": "...",
    "triggers": ["读取文件", "read file"],
    "priority": 5,
    "enabled": true
  }
}
```

### 方式二：直接编辑配置文件

编辑 `~/.nullclaw/config.json`，在 `tools` 部分添加 `tool_customizations`：

```json
{
  "tools": {
    "shell_timeout_secs": 60,
    "shell_max_output_bytes": 1048576,
    "max_file_size_bytes": 10485760,
    "web_fetch_max_chars": 50000,
    "tool_customizations": [
      {
        "name": "screenshot",
        "system_prompt": "Capture and return a screenshot of the current screen. This tool is useful when the user asks to see the screen, take a picture, or capture what's displayed on the monitor.",
        "triggers": [
          "截屏",
          "截图",
          "显示屏幕",
          "screenshot",
          "screen capture",
          "capture screen",
          "take a picture",
          "take a photo",
          "show me the screen",
          "show screen"
        ],
        "priority": 10,
        "enabled": true
      }
    ]
  }
}
```

## 字段说明

### ToolCustomization 结构

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | 是 | 工具名称（如 "screenshot", "file_read", "shell"） |
| `system_prompt` | string | 否 | 自定义系统提示词，覆盖默认工具描述 |
| `triggers` | string[] | 否 | 触发关键词列表，当用户消息包含这些词时会优先调用该工具,为空则没有触发词相关逻辑 |
| `priority` | number | 否 | 优先级（默认 0），数值越高优先级越高 |
| `enabled` | boolean | 否 | 是否启用该工具（默认 true） |
| `skip_llm_tpl` | string | 否 | 跳过 LLM 模板，当配置此字段时，工具执行完成后会将输出通过此模板格式化后直接返回给用户，无需 LLM 处理。模板支持 `{output}` 占位符，例如："Screenshot saved: {output}" |
| `trigger_modifiers` | string[] | 否 | 自定义修饰词列表，会从输入头尾移除后再匹配触发词 |
| `trigger_punctuation` | string | 否 | 自定义标点符号，会从输入中移除后再匹配触发词 |

## 触发关键词匹配规则

触发关键词采用智能匹配算法，支持两种触发模式：

### 1. 精确匹配（直接执行工具）

当用户输入**仅包含**触发词时（去除修饰词和标点后），直接执行工具，不经过 LLM：

**输入清理** - 从头尾两端移除：
- 常见修饰词：`please`, `could you`, `can you`, `would you`, `now`, `go`, `start`, `ok`, `begin`, `do`, `execute`, `run`, `take`, `请`, `帮我`, `开始`
- 全角/半角标点：空格、句号、逗号、感叹号、问号等
- **以上修饰词和标点符号会被移除，仅保留触发词**
- **待清理的修饰词和符号可配置扩展，默认包含以上所有**

**匹配示例**：

| 用户输入 | 清理后 | 触发词 | 结果 |
|----------|--------|--------|------|
| "screenshot" | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| "screenshot." | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| "please screenshot" | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| "screenshot please" | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| "screenshot now" | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| " screenshot ." | "screenshot" | "screenshot" | ✅ 直接执行截图工具 |
| " 截屏 。" | "截屏" | "截屏" | ✅ 直接执行截图工具 |
| "请截屏请" | "截屏" | "截屏" | ✅ 直接执行截图工具 |
| "some screenshot" | "somescreenshot" | "screenshot" | ❌ 不匹配（多余单词） |

### 2. 优先级提示（发送给 LLM）

当用户输入**包含**触发词但不是精确匹配时，在消息前添加优先级提示：

| 用户输入 | 触发词 | 结果 |
|----------|--------|------|
| "请帮我截屏" | "截屏" | 添加优先级提示，发给 LLM |
| "帮我截个图" | "截屏" | 添加优先级提示，发给 LLM |
| "don't screenshot" | "screenshot" | ❌ 不触发（有否定词） |

### 词边界匹配

关键词必须作为**完整单词**出现：

| 消息 | 关键词 | 匹配结果 |
|------|--------|----------|
| "请截屏" | "截屏" | ✅ 完整单词 |
| "noscreenshot" | "screenshot" | ❌ 是其他单词的一部分 |
| "already done" | "read" | ❌ 包含在其他单词中 |

### 否定词检测

如果关键词前有否定词，则不会触发：

| 消息 | 关键词 | 匹配结果 |
|------|--------|----------|
| "不要截屏" | "截屏" | ❌ 有否定词"不要" |
| "don't screenshot" | "screenshot" | ❌ 有否定词"don't" |
| "no screenshot needed" | "screenshot" | ❌ 有否定词"no" |

### 调试触发匹配

启用 verbose 模式查看匹配日志：

```bash
nullclaw agent --verbose
```

日志示例：
```
debug: exact trigger match: tool=screenshot, keyword='screenshot'
debug: executing tool directly due to exact trigger match
```

### 最佳实践

1. **精确匹配触发**：配置简短明确的触发词，如 "screenshot"、"截屏"
2. **避免子字符串冲突**：如用 "screen capture" 而非 "screen"
3. **合理设置优先级**：重要工具设置更高优先级

## CLI 命令

### `nullclaw tools show`

显示当前配置的工具定制。

```bash
nullclaw tools show              # 显示用户配置的工具定制
nullclaw tools show --builtin    # 显示所有内置工具及其描述和参数
```

### `nullclaw tools export`

导出工具定制到 JSON 文件。

```bash
nullclaw tools export output.json           # 导出用户配置的工具定制
nullclaw tools export builtin.json --builtin # 导出所有内置工具信息
```

### `nullclaw tools validate`

验证工具定制 JSON 文件的格式是否正确。

```bash
nullclaw tools validate tool_customizations.json
```

### `nullclaw tools import`

导入工具定制（仅显示预览，不自动应用）。

```bash
nullclaw tools import tool_customizations.json
```

## Agent 会话命令

在 agent 会话中，可以使用以下命令查看工具定制（只读）：

```
/tool-customizations show    # 显示当前工具定制
/tool-customizations list    # 列出所有可用工具
```

**安全提示**：Agent 会话中的命令是只读的，无法修改工具定制。要修改配置，请使用 CLI 命令或直接编辑配置文件。

## 安全考虑

- **分离读写权限**：CLI 命令可以修改配置，Agent 会话只能查看
- **防止提示词注入**：用户无法在对话中意外修改系统提示词
- **需要重启生效**：修改配置后需要重启 agent 才能生效

## 示例配置

### 截图工具（带 skip_llm_tpl）

```json
{
  "name": "screenshot",
  "system_prompt": "Capture and return a screenshot of the current screen. This tool is useful when the user asks to see the screen, take a picture, or capture what's displayed on the monitor.",
  "triggers": [
    "截屏",
    "截图",
    "显示屏幕",
    "screenshot",
    "screen capture",
    "capture screen",
    "show me the screen",
    "show screen"
  ],
  "priority": 10,
  "enabled": true,
  "skip_llm_tpl": "截图已保存: {output}"
}
```

**说明**：当用户输入精确匹配触发词（如 "截图"）时，工具执行完成后会直接返回 "截图已保存: /path/to/screenshot.png"，无需经过 LLM 处理。

### 文件读取工具

```json
{
  "name": "file_read",
  "system_prompt": "Read the contents of a file at the specified path. Use this when the user asks to read, view, or examine a file.",
  "triggers": [
    "读取文件",
    "查看文件",
    "read file",
    "view file",
    "open file"
  ],
  "priority": 5,
  "enabled": true
}
```

### Shell 命令工具

```json
{
  "name": "shell",
  "system_prompt": "Execute a shell command and return the output. Use this when the user asks to run commands, execute scripts, or perform system operations.",
  "triggers": [
    "执行命令",
    "运行命令",
    "run command",
    "execute command",
    "shell"
  ],
  "priority": 8,
  "enabled": true
}
```

## 故障排除

### 问题：`nullclaw tools show` 显示 "No tool customizations configured"

**解决方案**：
1. 检查配置文件路径是否正确
2. 确认 `tool_customizations` 字段存在于 `tools` 对象中
3. 验证 JSON 格式是否正确

### 问题：配置修改后没有生效

**解决方案**：
1. 重启 agent 进程
2. 检查配置文件语法是否正确
3. 运行 `nullclaw tools validate` 验证配置

### 问题：工具没有被触发

**解决方案**：
1. 检查 `enabled` 字段是否为 `true`
2. 确认触发关键词是否正确
3. 检查优先级设置是否合理
4. 查看日志了解工具调用情况

## 相关文件

- `src/config_types.zig` - ToolCustomization 结构定义
- `src/config_parse.zig` - 配置解析逻辑
- `src/tools/root.zig` - 内置工具元数据注册表（`builtin_tool_meta`）
- `src/main.zig` - CLI 命令实现
- `src/agent/commands.zig` - Agent 会话命令实现
- `src/agent/root.zig` - 工具定制加载和应用逻辑
