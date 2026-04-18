# Tool Customization Management

Add custom system prompts, trigger keywords, and priorities to built-in tools to improve tool invocation accuracy and response speed.

## Core Features

- **Pre-LLM Mode**: Configure specific trigger words for tools (e.g., screenshot) to enable direct tool invocation without LLM participation
- **Post-LLM Mode**: Configure the `skip_llm_tpl` parameter for tools (e.g., screenshot) to directly return templated tool output to users without LLM processing
- **Trigger-Specific Arguments Mapping**: Configure different parameters for each trigger keyword as shortcuts for more flexible tool invocation

## Quick Start

### 1. View Built-in Tools List

```bash
nullclaw tools show --builtin
```

### 2. View Current Tool Customizations

```bash
nullclaw tools show
```

### 3. Export Built-in Tools to JSON File

```bash
nullclaw tools export builtin_tools.json --builtin
```

### 4. Export Tool Customizations to JSON File

```bash
nullclaw tools export tool_customizations.json
```

### 5. Validate Tool Customization JSON File

```bash
nullclaw tools validate tool_customizations.json
```

### 6. Import Tool Customizations (Preview Only)

```bash
nullclaw tools import-preview tool_customizations.json
```

**Note**: The `import-preview` command only shows a preview and does not automatically apply the configuration. To apply changes, manually edit the configuration file.

## Configuration Methods

### Method 1: Using External JSON File

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

### Method 2: Direct Configuration File Editing

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

## Field Reference

### ToolCustomization Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool name (e.g., "screenshot", "file_read", "shell") |
| `system_prompt` | string | No | Custom system prompt that overrides the default tool description |
| `triggers` | string[] | No | List of trigger keywords; when user messages contain these words, the tool is prioritized. If empty, no trigger logic applies |
| `priority` | number | No | Priority (default: 0); higher values mean higher priority |
| `enabled` | boolean | No | Whether the tool is enabled (default: true) |
| `skip_llm_tpl` | string | No | Skip LLM template: when configured, tool output is formatted using this template and returned directly to the user without LLM processing. Supports `{output}` placeholder. Example: "Screenshot saved: {output}" |
| `trigger_arguments` | object | No | Trigger-specific arguments mapping. Key is the argsKey from trigger suffix (e.g., `"ls"` from `"list directory::ls"`), special key `"default"` is used when no suffix or suffix not found. Format: `{"default": {"command": "ls"}, "ps": {"command": "ps aux"}}`. Supports variable substitution: `{workspace_dir}` (workspace directory), `{timestamp}` (timestamp), `{date}` (date YYYY-MM-DD), `{time}` (time HH-MM-SS), `{home}` (user home directory) |
| `trigger_modifiers` | string[] | No | Custom modifiers list; removed from input start and end before trigger matching |
| `trigger_punctuation` | string | No | Custom punctuation; removed from input before trigger matching |

## Trigger Keyword Matching Rules

Trigger keywords use an intelligent matching algorithm with two trigger modes:

### 1. Exact Match (Direct Tool Execution)

When user input **contains only** the trigger keyword (after removing modifiers and punctuation), the tool is executed directly without calling LLM.

**Note**: Tools configured with `trigger_arguments` allow their triggers to execute directly by default, without additional confirmation. To disable, set `enabled` to `false`.

**Input Cleaning** - removes from both ends:
- Common modifiers: `please`, `could you`, `can you`, `would you`, `now`, `go`, `start`, `ok`, `begin`, `do`, `execute`, `run`, `take`, `请`, `帮我`, `开始`
- Full-width/half-width punctuation: spaces, periods, commas, exclamation marks, question marks, etc.
- **The above modifiers and punctuation are removed, leaving only the trigger keyword**
- **Modifiers and punctuation to be cleaned are configurable and extendable, including all defaults above**

**Match Examples**:

| User Input | Cleaned | Trigger | Result |
|------------|---------|---------|--------|
| "screenshot" | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| "screenshot." | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| "please screenshot" | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| "screenshot please" | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| "screenshot now" | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| " screenshot ." | "screenshot" | "screenshot" | ✅ Execute screenshot tool directly |
| " 截屏 。" | "截屏" | "截屏" | ✅ Execute screenshot tool directly |
| "请截屏请" | "截屏" | "截屏" | ✅ Execute screenshot tool directly |
| "some screenshot" | "somescreenshot" | "screenshot" | ❌ No match (extra word) |

### 2. Priority Hint (Send to LLM)

When user input **contains** the trigger keyword but is not an exact match, a priority hint is prepended:

| User Input | Trigger | Result |
|------------|---------|--------|
| "please help me screenshot" | "screenshot" | Add priority hint, send to LLM |
| "帮我截个图" | "截屏" | Add priority hint, send to LLM |
| "don't screenshot" | "screenshot" | ❌ No trigger (has negation) |

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

1. **Exact match triggers**: Use short, clear trigger keywords like "screenshot", "截屏"
2. **Avoid substring conflicts**: Use "screen capture" instead of "screen"
3. **Set reasonable priorities**: Higher priority for important tools

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

### `nullclaw tools import-preview`

Preview tool customizations (preview only, not auto-applied).

```bash
nullclaw tools import-preview tool_customizations.json
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

### Screenshot Tool (with skip_llm_tpl)

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

## Trigger Keyword Suffix Identifier (Advanced Feature)

Support adding `::argsKey` suffix to trigger keywords, enabling **different trigger keywords for the same tool to correspond to different parameter configurations**.

### Use Case

For example, the shell tool can have multiple trigger keywords, each executing a different command:
- `"list directory"` → execute `ls -la`
- `"show processes"` → execute `ps aux`
- `"check disk"` → execute `df -h`

### Configuration Format

```json
{
  "name": "shell",
  "triggers": [
    "run command",
    "list directory::ls",
    "show processes::ps",
    "check disk::df"
  ],
  "trigger_arguments": {
    "default": {
      "command": "echo 'No command specified'"
    },
    "ls": {
      "command": "ls -la"
    },
    "ps": {
      "command": "ps aux"
    },
    "df": {
      "command": "df -h"
    }
  }
}
```

**Available Parameters**:
- `command` (string, required): Shell command to execute
- `cwd` (string): Working directory (defaults to workspace root)

**Auto-add to allowed_commands**:
- Shell tools configured with `trigger_arguments` will have their commands automatically added to `autonomy.allowed_commands`
- This improves usability by allowing trigger keywords to work without manual `allowed_commands` setup
- Extracts the base command (first word, ignoring parameters and pipe operators)
- Example: `ls -la` extracts `ls`, `ps aux | grep nginx` extracts `ps`

**disable_commands Security Control**:
- `autonomy.disable_commands` can configure a list of commands to prevent auto-adding
- Prevents potentially dangerous commands from being automatically added to `allowed_commands`
- Example configuration:
  ```json
  {
    "autonomy": {
      "disable_commands": ["rm", "sudo", "su", "chmod", "chown"]
    }
  }
  ```
- Even if these commands are configured in `trigger_arguments`, they will not be auto-added to `allowed_commands`

### Matching Rules

| User Input | Trigger Config | Matching Keyword | Args Key Used | Command Executed |
|-----------|---------------|-----------------|--------------|-----------------|
| "list directory" | `"list directory::ls"` | "list directory" | `"ls"` | `ls -la` |
| "show processes" | `"show processes::ps"` | "show processes" | `"ps"` | `ps aux` |
| "check disk" | `"check disk::df"` | "check disk" | `"df"` | `df -h` |
| "run command" | `"run command"` | "run command" | `"default"` | `echo 'No command specified'` |

**Notes**:
- The suffix `::argsKey` does not participate in matching, only used for selecting parameter configuration
- Trigger keywords without suffix use the `"default"` key's parameters
- If the key corresponding to the suffix does not exist, fall back to the `"default"` key

## `trigger_arguments` Examples for Common Tools

Below are `trigger_arguments` examples for common tools:

### screenshot

```json
{
  "name": "screenshot",
  "triggers": ["screenshot", "capture"],
  "trigger_arguments": {
    "default": {
      "filename": "screenshot_{timestamp}.png"
    }
  }
}
```

**Available parameters**:
- `filename` (string): Screenshot filename, saved to workspace directory

### shell - With Suffix Identifier Example

```json
{
  "name": "shell",
  "triggers": [
    "run command",
    "list directory::ls",
    "show processes::ps",
    "check disk::df"
  ],
  "trigger_arguments": {
    "default": {
      "command": "echo 'No command specified'"
    },
    "ls": {
      "command": "ls -la"
    },
    "ps": {
      "command": "ps aux"
    },
    "df": {
      "command": "df -h"
    }
  }
}
```

**Available parameters**:
- `command` (string, required): Shell command to execute
- `cwd` (string): Working directory (defaults to workspace root)

### file_write - With Suffix Identifier Example

```json
{
  "name": "file_write",
  "triggers": [
    "write note::note",
    "write config::config",
    "write log::log"
  ],
  "trigger_arguments": {
    "default": {
      "path": "output.txt",
      "content": ""
    },
    "note": {
      "path": "notes_{date}.md",
      "content": "# Notes for {date}\n\n"
    },
    "config": {
      "path": "config.json",
      "content": "{\n  \"version\": \"1.0.0\"\n}"
    },
    "log": {
      "path": "app_{date}.log",
      "content": "Log started at {time}\n\n"
    }
  }
}
```

**Available parameters**:
- `path` (string, required): File path relative to workspace
- `content` (string, required): File content

### file_read

```json
{
  "name": "file_read",
  "triggers": ["read file", "view file"],
  "trigger_arguments": {
    "default": {
      "path": "README.md"
    }
  }
}
```

**Available parameters**:
- `path` (string, required): File path relative to workspace

### file_write

```json
{
  "name": "file_write",
  "triggers": ["write file", "create file"],
  "trigger_arguments": {
    "default": {
      "path": "notes_{date}.md",
      "content": "# Notes for {date}\n\n"
    }
  }
}
```

**Available parameters**:
- `path` (string, required): File path relative to workspace
- `content` (string, required): File content

### file_edit

```json
{
  "name": "file_edit",
  "triggers": ["edit file", "modify file"],
  "trigger_arguments": {
    "default": {
      "path": "config.txt",
      "old_string": "old_value",
      "new_string": "new_value"
    }
  }
}
```

**Available parameters**:
- `path` (string, required): File path relative to workspace
- `old_string` (string, required): Old text to replace
- `new_string` (string, required): New text

### git

```json
{
  "name": "git",
  "triggers": ["git status", "check git"],
  "trigger_arguments": {
    "default": {
      "command": "status"
    }
  }
}
```

**Available parameters**:
- `command` (string, required): Git command (e.g., status, log, diff)

### browser_open

```json
{
  "name": "browser_open",
  "triggers": ["open url", "browse"],
  "trigger_arguments": {
    "default": {
      "url": "https://example.com"
    }
  }
}
```

**Available parameters**:
- `url` (string, required): URL to open

### web_fetch

```json
{
  "name": "web_fetch",
  "triggers": ["fetch page", "get content"],
  "trigger_arguments": {
    "default": {
      "url": "https://example.com/article"
    }
  }
}
```

**Available parameters**:
- `url` (string, required): Web page URL to fetch

### http_request

```json
{
  "name": "http_request",
  "triggers": ["api request", "http call"],
  "trigger_arguments": {
    "default": {
      "url": "https://api.example.com/data",
      "method": "GET"
    }
  }
}
```

**Available parameters**:
- `url` (string, required): Request URL
- `method` (string): HTTP method (GET, POST, PUT, DELETE, etc., default GET)

### View All Tool Parameters

Use the following command to view all built-in tool parameter definitions:

```bash
nullclaw tools show --builtin
```

## Troubleshooting

### Issue: `nullclaw tools show` displays "No tool customizations configured"

**Solutions**:
1. Check if the configuration file path is correct
2. Confirm that the `tool_customizations` field exists in the `tools` object
3. Verify that the JSON format is correct

### Issue: Configuration changes not taking effect

**Solutions**:
1. Restart the agent process
2. Check if the configuration file syntax is correct
3. Run `nullclaw tools validate` to verify the configuration

### Issue: Tool not being triggered

**Solutions**:
1. Check if the `enabled` field is set to `true`
2. Confirm that the trigger keywords are correct
3. Check if the priority settings are reasonable
4. View logs to understand tool invocation status

## Related Files

- `src/config_types.zig` - ToolCustomization structure definition
- `src/config_parse.zig` - Configuration parsing logic
- `src/tools/root.zig` - Built-in tool metadata registry (`builtin_tool_meta`)
- `src/main.zig` - CLI command implementation
- `src/agent/commands.zig` - Agent session command implementation
- `src/agent/root.zig` - Tool customization loading and application logic
