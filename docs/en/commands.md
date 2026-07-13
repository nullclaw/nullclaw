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
| `nullclaw agent --workspace /path/to/workspace -m "..."` | Run the agent against a specific workspace for this process |
| `nullclaw agent --skill news-digest -m "..."` | Run a single prompt with a named skill active |
| `nullclaw agent` | Start interactive chat mode |
| `nullclaw acp` | Run the Agent Client Protocol stdio adapter for ACP-compatible editors |
| `nullclaw acp --provider openai --model gpt-5.2` | Pin the ACP adapter to a provider/model for editor-launched sessions |

### Interactive model routing

- In `nullclaw agent`, `/model` shows the current model plus configured routing/fallback status.
- `/config reload` hot reloads supported keys from `config.json` (including agent profiles).
- When auto-routing is configured, `/model` also shows the last auto-route decision and why it was chosen.
- If a routed provider is temporarily rate-limited or out of credits, `/model` shows that route as degraded until its cooldown expires.
- `/model` also lists configured auto routes with their `cost_class` and `quota_class` metadata.
- `/model <provider/model>` pins the current session to that model and disables automatic routing.
- `/model auto` clears the user pin, restores the configured default model, and re-enables `model_routes` for later turns in the same session.
- If no `model_routes` are configured, `/model auto` still clears the pin and returns the session to the configured default model.
- Starting `nullclaw agent` with `--model` or `--provider` also pins the run and bypasses `model_routes`.
- Starting `nullclaw agent` with `--skill <name>` activates that skill before the first message or REPL turn.
- `nullclaw acp` speaks newline-delimited JSON-RPC on stdio. Editors create ACP sessions with an absolute `cwd`; NullClaw forwards that cwd as the workspace for `agent invoke`.

## Runtime and operations

| Command | Purpose |
|---|---|
| `nullclaw gateway` | Start the long-running runtime using configured host and port |
| `nullclaw gateway --port 8080` | Override the gateway port from the CLI |
| `nullclaw gateway --host 0.0.0.0 --port 8080` | Override host and port from the CLI |
| `nullclaw gateway --workspace /path/to/workspace` | Override the workspace directory for this gateway process |
| `nullclaw service install` | Install the background service |
| `nullclaw service start` | Start the background service |
| `nullclaw service stop` | Stop the background service |
| `nullclaw service restart` | Restart the background service |
| `nullclaw service status` | Show service status |
| `nullclaw service uninstall` | Remove the background service |
| `nullclaw status [--json]` | Show overall system status or emit the machine-readable runtime snapshot |
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
- `agent --workspace` and `gateway --workspace` override the resolved workspace for the current process, equivalent to setting `NULLCLAW_WORKSPACE`.

## Channels, scheduling, and extensions

### `channel`

| Command | Purpose |
|---|---|
| `nullclaw channel list [--json]` | List known and configured channels |
| `nullclaw channel start` | Start the default available channel |
| `nullclaw channel start telegram` | Start a specific channel |
| `nullclaw channel status` | Show channel health |
| `nullclaw channel info <type> [--json]` | Show configured accounts for one channel type |
| `nullclaw channel add <type>` | Print guidance for adding a channel to config |
| `nullclaw channel remove <name>` | Print guidance for removing a channel from config |

### `cron`

| Command | Purpose |
|---|---|
| `nullclaw cron list [--json]` | List scheduled tasks |
| `nullclaw cron status [--json]` | Show scheduler-level status and job counters |
| `nullclaw cron add "0 * * * *" "command"` | Add a recurring shell task |
| `nullclaw cron add-agent "0 * * * *" "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | Add a recurring agent task |
| `nullclaw cron once 10m "command"` | Add a one-shot delayed shell task |
| `nullclaw cron once-agent 10m "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | Add a one-shot delayed agent task |
| `nullclaw cron run <id>` | Run a task immediately |
| `nullclaw cron pause <id>` / `resume <id>` | Pause or resume a task |
| `nullclaw cron remove <id>` | Delete a task |
| `nullclaw cron runs <id>` | Show recent run history |
| `nullclaw cron update <id> --expression ... --command ... --prompt ... --model ... --enable/--disable` | Update an existing task |

### `skills`

| Command | Purpose |
|---|---|
| `nullclaw skills list` | List installed skills |
| `nullclaw skills install <source>` | Install from a Git URL, local path, or HTTPS well-known skill endpoint |
| `nullclaw skills install --name <query>` | Search the skill registry and install the best matching skill |
| `nullclaw skills remove <name>` | Remove a skill |
| `nullclaw skills info <name>` | Show skill metadata |

### `history`

| Command | Purpose |
|---|---|
| `nullclaw history list [--limit N] [--offset N] [--json]` | List conversation sessions |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | Show messages for a session |

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
| `nullclaw memory export-jsonl --limit 1000` | Export a governed, PII-redacted JSONL dataset from memory |
| `nullclaw memory hygiene-report --json` | Dry-run exact/normalized duplicate report for memory |
| `nullclaw memory drain-outbox` | Drain the durable vector outbox queue |
| `nullclaw memory forget <key>` | Delete one memory entry |

`memory export-jsonl` emits one JSON object per line with a stable
`schema_version`, `key`, `category`, `timestamp`, `session_id`, and `content`
schema. Bootstrap/autosave internals are excluded unless `--include-internal`
is passed. Content is PII-redacted by default for DS notebooks, model
evaluation, and external review; use `--include-pii` only for trusted local raw
exports.

`memory hygiene-report` is non-destructive. It scans the selected memory slice
and reports exact duplicates plus normalized duplicates where case and
whitespace differ. It does not delete or rewrite entries.

### `workspace`, `capabilities`, `models`, `migrate`

| Command | Purpose |
|---|---|
| `nullclaw workspace edit AGENTS.md` | Open a bootstrap markdown file in `$EDITOR` |
| `nullclaw workspace reset-md --dry-run` | Preview workspace markdown reset |
| `nullclaw workspace reset-md --include-bootstrap --clear-memory-md` | Reset bundled markdown files and optionally clear extra files |
| `nullclaw workspace audit` | Scan workspace files for likely secret leaks (token prefixes, PEM blocks, credentials in URLs, high-entropy strings) |
| `nullclaw workspace audit --staged \| --commit <sha> \| --range a..b` | Audit a staged diff, a historical commit, or a git revision range instead of the workspace tree |
| `nullclaw workspace audit --json [--only-secrets] [--fail-on <level>]` | Machine-readable output for CI integration; non-zero exit when findings meet the threshold |
| `nullclaw workspace audit --llm-triage external` | Re-classify findings via `workspace_audit.llm_triage` or the configured primary LLM provider using privacy-preserving envelopes (no raw secret value leaves the machine) |
| `nullclaw workspace audit --llm-provider ollama --llm-model qwen2.5-coder:7b --llm-max-calls 20` | Override the configured audit triage provider, model, and external-call budget for one run |
| `nullclaw workspace audit --llm-triage dry-run` | Print the envelopes that would be sent without calling the LLM |
| `nullclaw capabilities` | Show a text capability summary |
| `nullclaw capabilities --json` | Show a JSON capability manifest |
| `nullclaw config show [--json]` | Print the full on-disk config |
| `nullclaw config get <path> [--json]` | Read one dotted config value from disk |
| `nullclaw models list` | List providers and default models |
| `nullclaw models info <model>` | Show model details |
| `nullclaw models summary [--json]` | Print the provider/key-safe admin summary used by integrations |
| `nullclaw models benchmark` | Run model latency benchmark |
| `nullclaw models refresh` | Refresh the model catalog |
| `nullclaw migrate openclaw --dry-run` | Preview OpenClaw migration |
| `nullclaw migrate openclaw --source /path/to/workspace` | Migrate from a specific source workspace |

Notes:

- `workspace edit` works only with file-based backends such as `markdown` and `hybrid`.
- If bootstrap data is stored in the database backend, the CLI will tell you to use the agent's `memory_store` tool instead.
- The `--json` read-side commands are intended for automation and for NullHub's managed-instance admin API boundary.

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
| `nullclaw --list-models --provider <name> [--api-key <key>] [--base-url <url>]` | Print model information, including custom OpenAI-compatible endpoints |
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
