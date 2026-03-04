# nullclaw whatsmeow bridge

Minimal HTTP sidecar for `channels.whatsapp_web` in nullclaw.

This process is separate from nullclaw and exposes:

- `GET /health`
- `POST /poll`
- `POST /send`

## Prerequisites

- Go 1.25+
- A WhatsApp account on a phone for QR pairing

## 1) Build

```bash
cd examples/whatsapp-web/whatsmeow-bridge
go mod tidy
go build -o nullclaw-whatsmeow-bridge .
```

## 2) Run (foreground)

```bash
mkdir -p "$HOME/.local/state/nullclaw"
NULLCLAW_ACCOUNT_ID=default \
NULLCLAW_BRIDGE_ADDR=127.0.0.1:3301 \
NULLCLAW_WHATSMEOW_DB="$HOME/.local/state/nullclaw/whatsmeow.db" \
./nullclaw-whatsmeow-bridge
```

Optional (test-only) setting:

- `NULLCLAW_WHATSAPP_WEB_ALLOW_FROM_ME=1`
: allow bridge to emit your own outbound messages in `/poll` for local loopback testing.

## 3) Pair with WhatsApp

On first run, the bridge prints a QR code in the terminal.

On your phone:

1. Open WhatsApp
2. Linked Devices
3. Link a Device
4. Scan the terminal QR

## 4) Verify bridge health

```bash
curl -sS http://127.0.0.1:3301/health
```

Expected JSON shape:

```json
{"ok":true,"connected":true,"logged_in":true}
```

## 5) Configure nullclaw via onboarding

Build nullclaw with the optional channel enabled:

```bash
zig build -Doptimize=ReleaseSmall -Dchannels=all,whatsapp-web
```

Then:

```bash
zig-out/bin/nullclaw onboard
```

In channel setup, choose `WhatsApp Web` and set `bridge_url` to:

```text
http://127.0.0.1:3301
```

Restart nullclaw and tail logs:

```bash
zig-out/bin/nullclaw service restart
journalctl --user -u nullclaw -f
```

You should see session logs with `channel=whatsapp_web`.

## 6) Run bridge with systemd --user (recommended)

Install binary:

```bash
mkdir -p "$HOME/.local/bin" "$HOME/.local/state/nullclaw"
cp ./nullclaw-whatsmeow-bridge "$HOME/.local/bin/"
```

Install service:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp ./nullclaw-whatsmeow.service.example "$HOME/.config/systemd/user/nullclaw-whatsmeow.service"
systemctl --user daemon-reload
systemctl --user enable --now nullclaw-whatsmeow.service
```

Observe logs:

```bash
journalctl --user -u nullclaw-whatsmeow -f
```

## Environment variables

- `NULLCLAW_ACCOUNT_ID`
: account namespace. Must match the channel account (`default` by default).
- `NULLCLAW_BRIDGE_ADDR`
: HTTP bind address (`127.0.0.1:3301` by default).
- `NULLCLAW_WHATSMEOW_DB`
: sqlite path used by whatsmeow store (`/tmp/nullclaw-whatsmeow.db` by default).
- `NULLCLAW_WHATSAPP_WEB_ALLOW_FROM_ME`
: set `1` to include self-sent messages in inbound poll stream.
