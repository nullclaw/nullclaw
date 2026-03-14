# Adaptive Intelligence

Make your NullClaw agent learn from every interaction — without external API calls.

The adaptive intelligence pipeline is a set of built-in features that score, route, learn, and evolve based on each conversation turn. All processing happens locally using deterministic algorithms; no extra LLM calls are required.

## Pipeline Overview

```
User message
  │
  ├── Skill Router ──────── selects relevant skills by keyword match
  │
  ├── Tiered Context ────── loads L0 (critical) vs L1 (supplementary) memory
  │
  ├── Agent processes ────── tool calls with retry + backoff on transient errors
  │
  ├── Turn Scorer ────────── scores turn quality [-1.0, +1.0]
  │
  ├── Session Digest ─────── extracts insights when session ends
  │
  └── Skill Evolution ────── tracks which skills fire, adjusts over time
```

## Quick Start

Add to your `~/.nullclaw/config.json`:

```json
{
  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
      "skill_routing_enabled": true,
      "skill_routing_max_active": 3,
      "session_digest_enabled": true,
      "session_digest_min_turns": 5,
      "skill_evolution_enabled": true,
      "skill_evolution_max_per_day": 5,
      "skill_evolution_cooldown_minutes": 20
    }
  }
}
```

Then start the gateway:

```bash
nullclaw gateway
```

All features are opt-in via config flags. When disabled (default), they add zero overhead.

## Features

### Turn Scorer (Phase 1)

Scores each agent turn on a scale of [-1.0, +1.0] using weighted signals:

| Signal | Weight | Source |
|--------|--------|--------|
| Tool success/failure | 0.3 | Tool execution result |
| User feedback (thanks, corrections) | 0.4 | Message sentiment |
| Response relevance | 0.2 | Topic continuity |
| Error recovery | 0.1 | Retry success after failure |

Scores are attributed to the model that produced the turn, enabling per-model quality tracking over time.

No config needed — always active. Scores are logged via the observer pipeline.

### Skill Router (Phase 2)

Deterministic keyword-based routing that selects the most relevant skills for each user message. No LLM calls — pure tokenization and weighted scoring.

| Config Key | Default | Description |
|------------|---------|-------------|
| `skill_routing_enabled` | `false` | Enable skill routing |
| `skill_routing_max_active` | `3` | Max skills injected per turn |

How it works:
1. Tokenizes user message and skill names/descriptions
2. Scores each skill: name matches get 3x weight vs description matches
3. Filters stop words (English + Dutch)
4. Top-N skills are injected into the system prompt for that turn

### Tiered Context Loading (Phase 3)

Splits memory into two tiers to keep the context window lean:

- **L0 (Critical):** Always loaded. Identity, active session state, recent corrections.
- **L1 (Supplementary):** Loaded on demand when the skill router or topic signals relevance.

This reduces prompt size by 40-60% for sessions that don't need full memory context.

### Retry & Resilience (Phase 4)

Structured retry with exponential backoff for transient tool failures:

- Classifies errors as transient vs permanent
- Retries transient failures (network timeouts, rate limits) up to 3 times
- Exponential backoff: 1s → 2s → 4s
- Permanent errors (auth failures, invalid input) fail immediately

No config needed — always active for tool execution.

### Session Digest (Phase 5)

Extracts key insights from completed sessions and persists them as `__digest.*` memory keys:

| Config Key | Default | Description |
|------------|---------|-------------|
| `session_digest_enabled` | `false` | Enable digest generation |
| `session_digest_min_turns` | `3` | Minimum turns before generating a digest |
| `session_digest_on_reset` | `true` | Generate on session reset |
| `session_digest_on_eviction` | `true` | Generate on idle session eviction |

Digests are extractive (no LLM summarization) — they identify:
- Topics discussed
- Decisions made
- User preferences expressed
- Unresolved questions

### Skill Evolution (Phase 6)

Tracks which skills are activated over time and detects usage patterns:

| Config Key | Default | Description |
|------------|---------|-------------|
| `skill_evolution_enabled` | `false` | Enable evolution tracking |
| `skill_evolution_max_per_day` | `3` | Max evolution events per day |
| `skill_evolution_cooldown_minutes` | `30` | Cooldown between events for the same skill |

Tracks:
- Activation frequency per skill
- Success correlation (via turn scores)
- Trigger patterns (which keywords lead to which skills)

### Media Delivery (Phase 8)

Send documents, images, and files through any channel:

- Automatic format detection and MIME type handling
- Channel-specific delivery (Telegram documents, WhatsApp media, email attachments)
- Fallback to text representation for channels without media support

## New Channels

### Email (IMAP IDLE + SMTP)

Full email channel with persistent IMAP IDLE for instant message delivery:

```json
{
  "channels": {
    "email": {
      "accounts": {
        "main": {
          "imap_host": "imap.example.com",
          "imap_port": 993,
          "smtp_host": "smtp.example.com",
          "smtp_port": 587,
          "username": "assistant@example.com",
          "password": "YOUR_APP_PASSWORD",
          "from_address": "assistant@example.com",
          "allow_from": ["user@example.com"],
          "polling_interval_secs": 60
        }
      }
    }
  }
}
```

The email channel uses IMAP IDLE for real-time message detection with a heartbeat mechanism that keeps the supervision loop informed during long IDLE waits (preventing false stale-thread restarts).

Build: included by default (`-Dchannels=all` or `-Dchannels=...,email`).

### WhatsApp Web (via Sidecar)

WhatsApp Web integration using a Node.js sidecar process:

```json
{
  "channels": {
    "whatsapp_web": {
      "accounts": {
        "main": {
          "sidecar_url": "http://127.0.0.1:7100",
          "auth_token": "YOUR_TOKEN",
          "allow_from": ["31612345678"]
        }
      }
    }
  }
}
```

Build: opt-in (`-Dchannels=...,whatsapp_web`).

## New Memory Engine

### ClickHouse

For analytics-scale memory storage:

```json
{
  "memory": {
    "backend": "clickhouse",
    "clickhouse_url": "http://localhost:8123",
    "clickhouse_database": "nullclaw"
  }
}
```

Build: opt-in (`-Dengines=...,clickhouse`).

## Verifying It Works

Check the gateway log for these signals:

```
info(turn_scorer): turn scored: 0.72 (model=claude-sonnet-4)
info(skill_router): matched 2 skills for turn: [coding-agent, rag-knowledge]
info(session_digest): digest generated for session abc123 (8 turns, 3 insights)
info(skill_evolution): skill 'coding-agent' evolved: activations=47, success_rate=0.89
```

Or use the status command:

```bash
nullclaw status
```
