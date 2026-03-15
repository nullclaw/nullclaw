# Gateway API

Default gateway endpoint: `http://127.0.0.1:3000`

## Page Guide

**Who this page is for**

- Operators wiring external systems into the local gateway
- Integrators testing pairing, bearer-token auth, and webhook delivery
- Reviewers checking what the HTTP surface exposes by default

**Read this next**

- Open [Security](./security.md) before exposing any gateway path beyond loopback or tunnel defaults
- Open [Configuration](./configuration.md) if you need the concrete `gateway` and channel keys behind these examples
- Open [Usage and Operations](./usage.md) for runtime checks, restarts, and troubleshooting around gateway behavior

**If you came from ...**

- [Usage and Operations](./usage.md): this page provides the endpoint-level detail behind the gateway health and webhook checks
- [Security](./security.md): come here when a security review needs the concrete HTTP auth and endpoint surface
- [Configuration](./configuration.md): return here after editing `gateway` settings to validate the API-facing behavior

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | None | Health check |
| `/pair` | POST | `X-Pairing-Code` | Exchange one-time pairing code for bearer token |
| `/webhook` | POST | `Authorization: Bearer <token>` | Send message payload: `{"message":"..."}` |
| `/whatsapp` | GET | Query params | Meta webhook verification |
| `/whatsapp` | POST | Meta signature | WhatsApp inbound webhook |
| `/max` | POST | `X-Max-Bot-Api-Secret` when configured | Max inbound webhook delivery |

## Quick Examples

### 1) Health check

```bash
curl http://127.0.0.1:3000/health
```

### 2) Pair and get token

```bash
curl -X POST \
  -H "X-Pairing-Code: 123456" \
  http://127.0.0.1:3000/pair
```

Expected: bearer token response (exact JSON shape may vary by version).

### 3) Send webhook message

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from webhook"}' \
  http://127.0.0.1:3000/webhook
```

### 4) Max webhook delivery

Single-account example:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"bot_started","chat_id":100,"timestamp":1710000000000,"user":{"user_id":42,"first_name":"Igor"}}' \
  http://127.0.0.1:3000/max
```

Multi-account example:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"message_created","timestamp":1710000000000,"message":{"sender":{"user_id":42,"first_name":"Igor"},"recipient":{"chat_id":100,"chat_type":"dialog"},"body":{"mid":"m1","text":"ping"}}}' \
  "http://127.0.0.1:3000/max?account_id=main"
```

Max webhook notes:

- `nullclaw` routes `/max` to the configured Max account by `account_id` query first, then by `X-Max-Bot-Api-Secret`.
- If `channels.max[].webhook_secret` is configured, the header is required and must match exactly.
- Use HTTPS in the configured Max-side webhook URL.

## Security Guidance

1. Keep `gateway.require_pairing = true`.
2. Keep gateway on loopback (`127.0.0.1`) and expose externally through tunnel/proxy.
3. Treat bearer tokens as secrets; do not commit or log them.
4. Treat Max webhook secrets the same way: randomize them per account and do not reuse one secret across multiple bots.

## Next Steps

- Review [Security](./security.md) before changing public exposure, pairing, or token-handling assumptions
- Check [Configuration](./configuration.md) for the settings that back the examples on this page
- Use [Usage and Operations](./usage.md) for gateway startup, health checks, and post-change validation flow

## Related Pages

- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Security](./security.md)
- [README](./README.md)
