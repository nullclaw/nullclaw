# Modal + Matrix multi-agent deployment

Deploy nullclaw with multiple agents in a shared Matrix room on [Modal](https://modal.com).

## Architecture

Two agents — planner and builder — run as separate Matrix bot accounts in the same room. Messages from each bot are visible in the room, so you can watch the agents collaborate.

Secrets flow: `.env` (local) → `modal.Secret.from_dotenv()` → container env vars → `inject_secrets()` patches config in-memory → nullclaw starts with real credentials. Secrets never touch config files on disk.

## Prerequisites

- [Zig](https://ziglang.org/) (for cross-compiling)
- Python 3
- [Modal CLI](https://modal.com/docs/guide) (`pip install modal && modal setup`)
- Two Matrix accounts (register at https://app.element.io)

## Quick start

```sh
# 1. Cross-compile + create config/env templates
./install.sh

# 2. Fill in Matrix details + secrets
#    config.matrix.json — homeserver, room_id, user_id, allow_from
#    .env               — API keys and access tokens

# 3. Deploy
./deploy.sh
```

## Matrix setup

1. Register two bot accounts (e.g. on matrix.org via Element)
2. Create a private room, invite both bots + yourself
3. Get access tokens for each bot (Element → Settings → Help & About → Access Token, or use the login API)
4. Fill in `config.matrix.json` with homeserver, room_id, user_id, and allow_from for each account
5. Put the access tokens in `.env` as `MATRIX_PLANNER_TOKEN` and `MATRIX_BUILDER_TOKEN`

## SSH access (optional)

Set `TAILSCALE_AUTHKEY` in `.env` to automatically join your tailnet on deploy. Create a [reusable + ephemeral key](https://login.tailscale.com/admin/settings/keys).

Once deployed, SSH in:

```sh
ssh root@nullclaw-modal   # or whatever TAILSCALE_HOSTNAME you set
```

This gives you a shell in the running container — inspect logs, debug nullclaw, check the workspace, etc.

## Files

| File | Tracked | Purpose |
|------|---------|---------|
| `.env.example` | yes | Secret template |
| `config.matrix.example.json` | yes | Config template (no secrets) |
| `modal_app.py` | yes | Modal app definition |
| `install.sh` | yes | Cross-compile + setup |
| `deploy.sh` | yes | Validate + deploy |
| `.env` | no | Your secrets |
| `config.matrix.json` | no | Your config |
| `nullclaw-linux-musl` | no | Cross-compiled binary |
