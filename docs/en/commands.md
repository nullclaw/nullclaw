# Commands

This page groups the NullClaw CLI by task so you can find the right command quickly without scanning the full help output.

`nullclaw help` gives the top-level summary; this page stays aligned with it and expands into the detailed subcommands and notes.

## Page Guide

**Who this page is for**

- Users who already have NullClaw installed and need the right CLI entry point
- Operators checking runtime, service, channel, or diagnostic commands
- Contributors verifying command names, flags, and task groupings

**Read this next**

- Open [Configuration](./configuration.md) if you need to understand what the commands act on
- Open [Usage and Operations](./usage.md) if you want workflows instead of command listings
- Open [Development](./development.md) if you are changing CLI behavior or docs

**If you came from ...**

- [README](./README.md): this page is the fastest way to find a concrete command
- [Installation](./installation.md): after setup, use this page to validate the install and learn daily commands
- `nullclaw help`: use this page when the built-in help is correct but too terse

## Start with these

- Show help: `nullclaw help`
- Show version: `nullclaw version` or `nullclaw --version`
- First-time setup: `nullclaw onboard --interactive`
- Quick validation: `nullclaw agent -m "hello"`
- Long-running mode: `nullclaw gateway`

## Setup and interaction

| Command | Purpose |
|---|---|
| `nullclaw help` | Show top-level help |
| `nullclaw version` / `nullclaw --version` | Show CLI version |
| `nullclaw onboard --interactive` | Run the interactive setup wizard |
| `nullclaw onboard --api-key sk-... --provider openrouter` | Quick provider + API key setup |
| `nullclaw onboard --api-key ... --provider ... --model ... --memory ...` | Set provider, model, and memory backend in one command |
| `nullclaw onboard --channels-only` | Reconfigure channels and allowlists only |
| `nullclaw agent -m "..."` | Run a single prompt |
| `nullclaw agent` | Start interactive chat mode |

### Interactive model routing

- In `nullclaw agent`, `/model` shows the current model plus configured routing/fallback status.
- When auto-routing is configured, `/model` also shows the last auto-route decision and why it was chosen.
- If a routed provider is temporarily rate-limited or out of credits, `/model` shows that route as degraded until its cooldown expires.
- `/model` also lists configured auto routes with their `cost_class` and `quota_class` metadata.
- `/model <provider/model>` pins the current session to that model and disables automatic routing.
- `/model auto` clears the user pin, restores the configured default model, and re-enables `model_routes` for later turns in the same session.
- If no `model_routes` are configured, `/model auto` still clears the pin and returns the session to the configured default model.
- Starting `nullclaw agent` with `--model` or `--provider` also pins the run and bypasses `model_routes`.

## Runtime and operations

| Command | Purpose |
|---|---|
| `nullclaw gateway` | Start the long-running runtime using configured host and port |
| `nullclaw gateway --port 8080` | Override the gateway port from the CLI |
| `nullclaw gateway --host 0.0.0.0 --port 8080` | Override host and port from the CLI |
| `nullclaw service install` | Install the background service |
| `nullclaw service start` | Start the background service |
| `nullclaw service stop` | Stop the background service |
| `nullclaw service restart` | Restart the background service |
| `nullclaw service status` | Show service status |
| `nullclaw service uninstall` | Remove the background service |
| `nullclaw status` | Show overall system status |
| `nullclaw doctor` | Run diagnostics |
| `nullclaw update --check` | Check for updates without installing |
| `nullclaw update --yes` | Install updates without prompting |
| `nullclaw auth login openai-codex` | Authenticate `openai-codex` via OAuth device flow |
| `nullclaw auth login openai-codex --import-codex` | Import auth from `~/.codex/auth.json` |
| `nullclaw auth status openai-codex` | Show authentication state |
| `nullclaw auth logout openai-codex` | Remove stored credentials |

Notes:

- `auth` currently supports only `openai-codex`.
- `gateway --host/--port` overrides only the bind settings; the rest of gateway security still comes from config.

## Channels, scheduling, and extensions

### `channel`

| Command | Purpose |
|---|---|
| `nullclaw channel list` | List known and configured channels |
| `nullclaw channel start` | Start the default available channel |
| `nullclaw channel start telegram` | Start a specific channel |
| `nullclaw channel status` | Show channel health |
| `nullclaw channel add <type>` | Print guidance for adding a channel to config |
| `nullclaw channel remove <name>` | Print guidance for removing a channel from config |

### `cron`

| Command | Purpose |
|---|---|
| `nullclaw cron list` | List scheduled tasks |
| `nullclaw cron add "0 * * * *" "command"` | Add a recurring shell task |
| `nullclaw cron add-agent "0 * * * *" "prompt" --model <model> [--announce] [--channel <name>] [--to <id>]` | Add a recurring agent task |
| `nullclaw cron once 10m "command"` | Add a one-shot delayed shell task |
| `nullclaw cron once-agent 10m "prompt" --model <model>` | Add a one-shot delayed agent task |
| `nullclaw cron run <id>` | Run a task immediately |
| `nullclaw cron pause <id>` / `resume <id>` | Pause or resume a task |
| `nullclaw cron remove <id>` | Delete a task |
| `nullclaw cron runs <id>` | Show recent run history |
| `nullclaw cron update <id> --expression ... --command ... --prompt ... --model ... --enable/--disable` | Update an existing task |

### `skills`

| Command | Purpose |
|---|---|
| `nullclaw skills list` | List installed skills |
| `nullclaw skills install <source>` | Install from a GitHub URL or local path |
| `nullclaw skills remove <name>` | Remove a skill |
| `nullclaw skills info <name>` | Show skill metadata |

## Data, models, and workspace

### `memory`

| Command | Purpose |
|---|---|
| `nullclaw memory stats` | Show resolved memory config and counters |
| `nullclaw memory count` | Show total number of memory entries |
| `nullclaw memory reindex` | Rebuild the vector index |
| `nullclaw memory search "query" --limit 10` | Run retrieval against memory |
| `nullclaw memory get <key>` | Show one memory entry |
| `nullclaw memory list --category task --limit 20` | List memory entries by category |
| `nullclaw memory drain-outbox` | Drain the durable vector outbox queue |
| `nullclaw memory forget <key>` | Delete one memory entry |

### `workspace`, `capabilities`, `models`, `migrate`

| Command | Purpose |
|---|---|
| `nullclaw workspace edit AGENTS.md` | Open a bootstrap markdown file in `$EDITOR` |
| `nullclaw workspace reset-md --dry-run` | Preview workspace markdown reset |
| `nullclaw workspace reset-md --include-bootstrap --clear-memory-md` | Reset bundled markdown files and optionally clear extra files |
| `nullclaw capabilities` | Show a text capability summary |
| `nullclaw capabilities --json` | Show a JSON capability manifest |
| `nullclaw models list` | List providers and default models |
| `nullclaw models info <model>` | Show model details |
| `nullclaw models benchmark` | Run model latency benchmark |
| `nullclaw models refresh` | Refresh the model catalog |
| `nullclaw migrate openclaw --dry-run` | Preview OpenClaw migration |
| `nullclaw migrate openclaw --source /path/to/workspace` | Migrate from a specific source workspace |

Notes:

- `workspace edit` works only with file-based backends such as `markdown` and `hybrid`.
- If bootstrap data is stored in the database backend, the CLI will tell you to use the agent's `memory_store` tool instead.

## Hardware and automation-facing entry points

### `hardware`

| Command | Purpose |
|---|---|
| `nullclaw hardware scan` | Scan connected hardware |
| `nullclaw hardware flash <firmware_file> [--target <board>]` | Flash firmware to a device (currently a placeholder command) |
| `nullclaw hardware monitor` | Monitor hardware devices (currently a placeholder command) |

### Top-level machine-facing flags

These are more useful for automation, probing, or integrations than for normal day-to-day CLI use:

| Command | Purpose |
|---|---|
| `nullclaw --export-manifest` | Export the runtime manifest |
| `nullclaw --list-models` | Print model information |
| `nullclaw --probe-provider-health` | Probe provider health |
| `nullclaw --probe-channel-health` | Probe channel health |
| `nullclaw --from-json` | Run a JSON-driven entry path |

## Recommended troubleshooting order

1. `nullclaw doctor`
2. `nullclaw status`
3. `nullclaw channel status`
4. `nullclaw agent -m "self-check"`
5. If gateway is involved, also run `curl http://127.0.0.1:3000/health`

## Next Steps

- Go to [Usage and Operations](./usage.md) for task-based runtime workflows
- Go to [Configuration](./configuration.md) if a command depends on provider, gateway, or memory settings
- Go to [Development](./development.md) if you plan to change command behavior or update docs alongside code

## Related Pages

- [README](./README.md)
- [Installation](./installation.md)
- [Gateway API](./gateway-api.md)
- [Architecture](./architecture.md)
