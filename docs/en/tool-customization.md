# Tool Customization

nullclaw supports adding custom system prompts, trigger keywords, and priorities to tools to improve tool invocation accuracy and response speed.

## Quick Start

### 1. View Built-in Tools

```bash
nullclaw tools show --builtin
```

### 2. View Current Tool Customizations

```bash
nullclaw tools show
```

### 3. Export Built-in Tools to JSON

```bash
nullclaw tools export builtin_tools.json --builtin
```

### 4. Export Tool Customizations to JSON

```bash
nullclaw tools export tool_customizations.json
```

### 5. Validate Tool Customization JSON File

```bash
nullclaw tools validate tool_customizations.json
```

### 6. Import Tool Customizations (Preview Only)

```bash
nullclaw tools import tool_customizations.json
```

**Note**: The `import` command only shows a preview and does not automatically apply the configuration. To apply changes, manually edit the configuration file.

## Configuration Methods

### Method 1: Direct Configuration File Editing

Edit `~/.nullclaw/config.json` and add `tool_customizations` in the `tools` section:

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
          "screenshot",
          "screen capture",
          "capture screen",
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

### Method 2: Using External JSON File

Specify an external file path in `~/.nullclaw/config.json`:

```json
{
  "tools": {
    "tool_customizations_file": "/path/to/tool_customizations.json"
  }
}
```

External file format:

```json
{
  "screenshot": {
    "system_prompt": "...",
    "triggers": ["screenshot", "screen capture"],
    "priority": 10,
    "enabled": true
  },
  "file_read": {
    "system_prompt": "...",
    "triggers": ["read file", "view file"],
    "priority": 5,
    "enabled": true
  }
}
```

## Field Reference

### ToolCustomization Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool name (e.g., "screenshot", "file_read", "shell") |
| `system_prompt` | string | No | Custom system prompt that overrides the default tool description |
| `triggers` | string[] | No | List of trigger keywords; when user messages contain these words, the tool is prioritized |
| `priority` | number | No | Priority (default: 0); higher values mean higher priority |
| `enabled` | boolean | No | Whether the tool is enabled (default: true) |
| `skip_llm_tpl` | string | No | Skip LLM template: when configured, tool output is formatted using this template and returned directly to the user without LLM processing. Supports `{output}` placeholder. Example: "Screenshot saved: {output}" |
| `trigger_modifiers` | string[] | No | Custom modifiers list; removed from input start and end before trigger matching |
| `trigger_punctuation` | string | No | Custom punctuation; removed from input before trigger matching |

## Trigger Keyword Matching Rules

Trigger keywords use an intelligent matching algorithm with two trigger modes:

### 1. Exact Match (Direct Tool Execution)

When user input **contains only** the trigger keyword (after removing modifiers and punctuation), the tool is executed directly without calling LLM:

**Input Cleaning** - removes from start and end:
- Default English modifiers: `please`, `could you`, `can you`, `would you`, `now`, `go`, `start`, `ok`, `begin`, `do`, `execute`, `run`, `take`
- Default Chinese modifiers: `请`, `帮我`, `开始`
- Default punctuation: space, period, comma, exclamation, question mark, etc.
- **Modifiers and punctuation are configurable and can be extended.**

**Match Examples**:

| User Input | Cleaned | Trigger | Result |
|------------|---------|---------|--------|
| "screenshot" | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| "screenshot." | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| "please screenshot" | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| "screenshot please" | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| "screenshot now" | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| " screenshot ." | "screenshot" | "screenshot" | ✅ Execute screenshot tool |
| " 截屏 。" | "截屏" | "截屏" | ✅ Execute screenshot tool |
| "请截屏请" | "截屏" | "截屏" | ✅ Execute screenshot tool |
| "some screenshot" | "somescreenshot" | "screenshot" | ❌ No match (extra word) |

### 2. Priority Hint (Send to LLM)

When user input **contains** the trigger keyword but is not an exact match, a priority hint is prepended:

| User Input | Trigger | Result |
|------------|---------|--------|
| "please screenshot" | "screenshot" | Add priority hint, send to LLM |
| "帮我截个图" | "截屏" | Add priority hint, send to LLM |
| "don't screenshot" | "screenshot" | ❌ No trigger (negation) |

### Word Boundary Matching

Keywords must appear as **whole words**:

| Message | Keyword | Match |
|---------|---------|-------|
| "please screenshot" | "screenshot" | ✅ Whole word |
| "noscreenshot" | "screenshot" | ❌ Part of another word |
| "already done" | "read" | ❌ Contained in other word |

### Negation Detection

If a negation word precedes the keyword, it won't trigger:

| Message | Keyword | Match |
|---------|---------|-------|
| "don't screenshot" | "screenshot" | ❌ Has negation "don't" |
| "no screenshot needed" | "screenshot" | ❌ Has negation "no" |
| "never screenshot" | "screenshot" | ❌ Has negation "never" |

### Debugging Trigger Matches

Enable verbose mode to see matching logs:

```bash
nullclaw agent --verbose
```

Log examples:
```
debug: exact trigger match: tool=screenshot, keyword='screenshot'
debug: executing tool directly due to exact trigger match
```

### Best Practices

1. **Exact match triggers**: Use short, clear trigger keywords like "screenshot"
2. **Avoid substring conflicts**: Use "screen capture" instead of "screen"
3. **Set reasonable priorities**: Higher priority for important tools
4. **Configure modifiers**: Customize trigger_modifiers and trigger_punctuation in config

## CLI Commands

### `nullclaw tools show`

Display current tool customizations.

```bash
nullclaw tools show              # Show user-configured tool customizations
nullclaw tools show --builtin    # Show all built-in tools with descriptions and parameters
```

### `nullclaw tools export`

Export tool customizations to a JSON file.

```bash
nullclaw tools export output.json           # Export user-configured tool customizations
nullclaw tools export builtin.json --builtin # Export all built-in tool information
```

### `nullclaw tools validate`

Validate the format of a tool customization JSON file.

```bash
nullclaw tools validate tool_customizations.json
```

### `nullclaw tools import`

Import tool customizations (preview only, not auto-applied).

```bash
nullclaw tools import tool_customizations.json
```

## Agent Session Commands

In an agent session, use the following commands to view tool customizations (read-only):

```
/tool-customizations show    # Show current tool customizations
/tool-customizations list    # List all available tools
```

**Security Note**: Commands in agent sessions are read-only and cannot modify tool customizations. To modify configuration, use CLI commands or edit the configuration file directly.

## Security Considerations

- **Separated Read/Write Permissions**: CLI commands can modify configuration; agent sessions can only view
- **Prompt Injection Prevention**: Users cannot accidentally modify system prompts during conversations
- **Restart Required**: Configuration changes require an agent restart to take effect

## Example Configurations

### Screenshot Tool (with skipLlmTpl)

```json
{
  "name": "screenshot",
  "system_prompt": "Capture and return a screenshot of the current screen. This tool is useful when the user asks to see the screen, take a picture, or capture what's displayed on the monitor.",
  "triggers": [
    "screenshot",
    "screen capture",
    "capture screen",
    "take a picture",
    "take a photo",
    "show me the screen",
    "show screen"
  ],
  "priority": 10,
  "enabled": true,
  "skip_llm_tpl": "Screenshot saved: {output}"
}
```

**Note**: When user input exactly matches a trigger keyword (e.g., "screenshot"), the tool output will be directly formatted as "Screenshot saved: /path/to/screenshot.png" and returned without LLM processing.

### File Read Tool

```json
{
  "name": "file_read",
  "system_prompt": "Read the contents of a file at the specified path. Use this when the user asks to read, view, or examine a file.",
  "triggers": [
    "read file",
    "view file",
    "open file"
  ],
  "priority": 5,
  "enabled": true
}
```

### Shell Command Tool

```json
{
  "name": "shell",
  "system_prompt": "Execute a shell command and return the output. Use this when the user asks to run commands, execute scripts, or perform system operations.",
  "triggers": [
    "run command",
    "execute command",
    "shell"
  ],
  "priority": 8,
  "enabled": true
}
```

## Troubleshooting

### Issue: `nullclaw tools show` displays "No tool customizations configured"

**Solution**:
1. Check if the configuration file path is correct
2. Confirm that the `tool_customizations` field exists in the `tools` object
3. Verify the JSON format is correct

### Issue: Configuration changes don't take effect

**Solution**:
1. Restart the agent process
2. Check if the configuration file syntax is correct
3. Run `nullclaw tools validate` to validate the configuration

### Issue: Tool is not being triggered

**Solution**:
1. Check if the `enabled` field is `true`
2. Confirm trigger keywords are correct
3. Check if priority settings are reasonable
4. Check logs to understand tool invocation behavior

## Related Files

- `src/config_types.zig` - ToolCustomization structure definition
- `src/config_parse.zig` - Configuration parsing logic
- `src/tools/root.zig` - Built-in tool metadata registry (`builtin_tool_meta`)
- `src/main.zig` - CLI command implementation
- `src/agent/commands.zig` - Agent session command implementation
- `src/agent/root.zig` - Tool customization loading and application logic
