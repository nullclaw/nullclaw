# Usage and Operations

This page focuses on day-to-day commands, service mode, and troubleshooting.

## Page Guide

**Who this page is for**

- Users running NullClaw day to day from the CLI or service mode
- Operators checking health, restarts, and post-change validation steps
- Troubleshooters narrowing down common startup, model, channel, or gateway issues

**Read this next**

- Open [Commands](./commands.md) if you need a fuller CLI reference beyond the common paths here
- Open [Security](./security.md) before exposing the gateway or widening allowlists and autonomy
- Open [Gateway API](./gateway-api.md) if your operational flow depends on pairing or webhook calls

**If you came from ...**

- [Installation](./installation.md): this page picks up after the binary is installed and ready for first-run checks
- [Configuration](./configuration.md): come here to validate config changes with runtime commands and troubleshooting steps
- [Commands](./commands.md): return here when you want the operational sequence, not just the raw command list

## First-Run Flow

1. Initialize:

```bash
nullclaw onboard --interactive
```

2. Send a test message:

```bash
nullclaw agent -m "hello nullclaw"
```

3. Start long-running gateway:

```bash
nullclaw gateway
```

## Command Quick Reference

| Command | Purpose |
|---|---|
| `nullclaw onboard --api-key sk-... --provider openrouter` | Quick setup for provider and API key |
| `nullclaw onboard --interactive` | Full interactive setup |
| `nullclaw onboard --channels-only` | Reconfigure channels and allowlists only |
| `nullclaw agent -m "..."` | Single-message mode |
| `nullclaw agent` | Interactive mode |
| `nullclaw gateway` | Start long-running runtime (default `127.0.0.1:3000`) |
| `nullclaw service install` | Install background service |
| `nullclaw service start` | Start background service |
| `nullclaw service status` | Check service status |
| `nullclaw service stop` | Stop background service |
| `nullclaw service uninstall` | Uninstall background service |
| `nullclaw doctor` | Run diagnostics |
| `nullclaw status` | Show global status |
| `nullclaw channel status` | Show channel health |
| `nullclaw channel start telegram` | Start a specific channel |
| `nullclaw migrate openclaw --dry-run` | Dry-run OpenClaw migration |
| `nullclaw migrate openclaw` | Execute OpenClaw migration |
| `nullclaw history list [--limit N] [--offset N] [--json]` | List conversation sessions |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | Show messages for a session |

## Service Mode Recommendations

For long-running deployments:

- Linux uses `systemd --user` when available and falls back to OpenRC on Alpine/OpenRC systems.

```bash
nullclaw service install
nullclaw service start
nullclaw service status
```

After significant config changes, restart service:

```bash
nullclaw service stop
nullclaw service start
```

## Gateway and Pairing

- Default gateway: `127.0.0.1:3000`
- Recommended: keep `gateway.require_pairing = true`
- For public access, prefer tunnel/reverse proxy over direct public bind

Health check:

```bash
curl http://127.0.0.1:3000/health
```

## FAQ

### 1) Startup fails with config error

Steps:

1. Run `nullclaw doctor` for exact error details.
2. Compare with `config.example.json` for key names and nesting.
3. Validate JSON syntax (commas, quotes, braces).

### 2) Model calls fail (401/403)

Common causes:

- API key invalid/expired.
- Provider mismatch (for example, wrong key for selected provider).
- Invalid model route format/string.

Checks:

```bash
nullclaw status
```

Then re-run onboarding:

```bash
nullclaw onboard --interactive
```

### 3) Channel receives no messages

Check:

- `channels.<name>.accounts.*` token/webhook/account settings.
- `allow_from` accidentally set to empty array.
- `nullclaw channel status` health output.

### 4) Gateway starts but is unreachable externally

Common causes:

- Still bound to `127.0.0.1`.
- Tunnel/reverse proxy not configured.
- Firewall port not opened.

### 5) Provider returns 429 / "rate limit exceeded"

Common causes:

- Low-quota coding plans may reject tool-heavy agent turns even when plain chat still works.
- Retry pressure is too aggressive for the current provider plan.
- There is no configured fallback when the primary provider hits quota/rate limits.

Checks:

- For foreground runs, start with `nullclaw agent --verbose`.
- For service mode, inspect `~/.nullclaw/logs/daemon.stdout.log` and `~/.nullclaw/logs/daemon.stderr.log`.
- Run `nullclaw status` to confirm the current provider/model pair.

If the plan is valid but fragile, tune reliability conservatively:

```json
{
  "reliability": {
    "provider_retries": 1,
    "provider_backoff_ms": 3000,
    "fallback_providers": ["openrouter"]
  }
}
```

If you have multiple keys for the same provider, add `reliability.api_keys` so NullClaw can rotate them.

## Post-Change Checklist

After config edits:

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw agent -m "self-check"
```

For gateway scenarios:

```bash
nullclaw gateway
curl http://127.0.0.1:3000/health
```

## Next Steps

- Open [Commands](./commands.md) for less common CLI flows and a broader command catalog
- Review [Security](./security.md) before moving from local-only operation to wider exposure
- Use [Gateway API](./gateway-api.md) when your operational checks include pairing or webhook integrations

## Related Pages

- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Commands](./commands.md)
- [Security](./security.md)
