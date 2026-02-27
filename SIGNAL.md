# Signal Deployment

Run nullclaw as a Signal chatbot using Docker Compose with a Cloudflare tunnel.

## Architecture

```
Signal app  <-->  signal-cli REST API (:8080)  <-->  nullclaw gateway (:3000)  <-->  Cloudflare tunnel
```

The gateway sends messages via `POST /v2/send` and receives via WebSocket at `/v1/receive/{number}`.

## Setup

### 1. Register or link a Signal account

**Option A — Register a new number** (recommended): Follow the steps in `SIGNAL-REREGISTER.md`.

**Option B — Link to an existing account:**

```bash
docker compose -f docker-compose.yml -f docker-compose.signal.yml up signal-cli
```

Then from another terminal:

```bash
docker exec nullclaw-signal-cli-1 signal-cli link -n nullclaw
```

Scan the QR URI with your Signal app (Settings > Linked Devices > Link New Device). Stop the container once linked.

Device data is stored at `~/.local/share/signal-cli`.

### 2. Create config files

```bash
# Environment secrets
cp .env.signal.example .env.signal
# Edit with your real values:
#   OPENROUTER_API_KEY  - your OpenRouter key
#   SIGNAL_ACCOUNT      - your Signal phone number (+1...)
#   SIGNAL_RECIPIENT    - recipient UUID (preferred) or phone number

# nullclaw config
cp config.signal.example.json config.signal.json
# Replace ${SIGNAL_ACCOUNT} and ${SIGNAL_RECIPIENT} with real phone numbers
# Replace ${OPENROUTER_API_KEY} with your key (or leave it — the env var works too)
# Do NOT change http_url — "http://signal-cli:8080" is the Docker internal address
```

Both `config.signal.json` and `.env.signal` are gitignored.

### 3. Configure Cloudflare tunnel

Point your named tunnel to nullclaw's gateway port. In `~/.cloudflared/config.yml`:

```yaml
tunnel: <your-tunnel-id>
credentials-file: ~/.cloudflared/<your-tunnel-id>.json

ingress:
  - hostname: your-subdomain.example.com
    service: http://localhost:3000
  - service: http_status:404
```

### 4. Build the image

```bash
DOCKER_BUILDKIT=0 docker build -t nullclaw:latest .
```

## Usage

### Start

```bash
# Start signal-cli + nullclaw gateway
docker compose -f docker-compose.yml -f docker-compose.signal.yml --profile gateway up -d

# Start the Cloudflare tunnel (separate process)
cloudflared tunnel run <tunnel-name>
```

### Stop

```bash
docker compose -f docker-compose.yml -f docker-compose.signal.yml --profile gateway down

# Kill cloudflared (if running in foreground, Ctrl+C; otherwise:)
pkill cloudflared
```

### View logs

```bash
# All services
docker compose -f docker-compose.yml -f docker-compose.signal.yml --profile gateway logs -f

# Just the gateway
docker logs -f nullclaw-gateway-1

# Just signal-cli
docker logs -f nullclaw-signal-cli-1
```

### Health checks

```bash
curl http://localhost:3000/health          # nullclaw gateway
curl -i http://localhost:8080/v1/health    # signal-cli daemon (expects HTTP 204)
curl https://your-subdomain.example.com/health  # through tunnel
```

## Uninstall

### Remove containers and volumes

```bash
docker compose -f docker-compose.yml -f docker-compose.signal.yml --profile gateway down -v
```

This removes the containers, network, and the `nullclaw-data` volume (agent memory/state). Signal device data at `~/.local/share/signal-cli` is **not** removed since it's a bind mount.

### Remove the Docker image

```bash
docker rmi nullclaw:latest
docker rmi bbernhard/signal-cli-rest-api:latest
```

### Remove signal-cli device data

```bash
rm -rf ~/.local/share/signal-cli
```

You should also unlink the device from your Signal app: Settings > Linked Devices > select the device > Unlink.

### Remove Cloudflare tunnel

```bash
cloudflared tunnel delete <tunnel-name>
```

And remove the DNS record from your Cloudflare dashboard.

### Remove local config files

```bash
rm .env.signal config.signal.json
```

## File reference

| File | Tracked | Purpose |
|---|---|---|
| `docker-compose.signal.yml` | yes | Compose overlay for signal-cli + gateway |
| `config.signal.example.json` | yes | Config template (copy to `config.signal.json`) |
| `.env.signal.example` | yes | Env template (copy to `.env.signal`) |
| `config.signal.json` | no | Your config with real phone numbers |
| `.env.signal` | no | Your secrets |
| `SIGNAL-REREGISTER.md` | yes | How to register a new Signal number |
| `TEST_GUIDE.md` | yes | Send/receive test commands |
