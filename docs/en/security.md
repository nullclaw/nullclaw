# Security

NullClaw follows secure-by-default behavior: local bind by default, pairing auth, sandbox isolation, and least privilege.

## Page Guide

**Who this page is for**

- Operators hardening a local or tunneled NullClaw deployment
- Reviewers checking whether config or runtime changes widen trust boundaries
- Contributors touching gateway, tool, sandbox, or exposure-sensitive paths

**Read this next**

- Open [Configuration](./configuration.md) when you need the exact keys behind the controls summarized here
- Open [Gateway API](./gateway-api.md) if your security review includes pairing, bearer tokens, or webhooks
- Open [Usage and Operations](./usage.md) for day-to-day checks after a security-related config change

**If you came from ...**

- [Usage and Operations](./usage.md): this page explains the hardening context behind gateway and service recommendations
- [Configuration](./configuration.md): come here when a config key has security impact and needs policy-level interpretation
- [Architecture](./architecture.md): return here if a subsystem design decision crosses a security-sensitive boundary

## Baseline Controls

| Item | Status | How |
|---|---|---|
| Gateway not publicly exposed by default | Enabled | Defaults to `127.0.0.1`; refuses public bind without tunnel/explicit override |
| Pairing required | Enabled | One-time 6-digit pairing code, exchanged via `POST /pair` |
| Filesystem scope limits | Enabled | `workspace_only = true` by default |
| Tunnel-aware exposure | Enabled | Public access expected via Tailscale/Cloudflare/ngrok/custom tunnel |
| Sandbox isolation | Enabled | Auto-selects Landlock/Firejail/Bubblewrap/Docker |
| Secret encryption | Enabled | Credentials encrypted at rest with ChaCha20-Poly1305 |
| Resource limits | Enabled | Configurable memory/CPU/subprocess limits |
| Audit logging | Enabled | Optional audit trail with retention policy |

## Privacy Redaction Boundary

When PII redaction is enabled, NullClaw replaces detected sensitive values with
deterministic placeholders such as `[EMAIL_1]`, `[PHONE_1]`, or `[CARD_1]`
before provider calls, local session persistence, memory autosave, diagnostics,
and vector embedding sync.

The reusable redactor defaults to one-way operation: it keys values by
HMAC-SHA256 fingerprints and does not retain the original plaintext. The agent
uses an opt-in in-memory reverse map for its per-conversation redactor so it can
rehydrate placeholders for same-principal, single-user display paths. Shared
channel, group, and thread sessions keep placeholders in the outbound response.
Tool arguments keep literal placeholders by default; this prevents provider
output from becoming a provider-to-tool exfiltration channel. The reverse map
lives only in process RAM, is bounded, is reset with the conversation, and is
not written to memory, history, JSONL export, or diagnostics.

The redactor is a lightweight text scanner, not a full DLP/OCR engine. It covers
common text forms for emails, phone numbers, Luhn-valid cards, anchored
passport/ID values, and token/secret patterns. Binary image contents, OCR text,
EXIF metadata, and unsupported locale-specific document formats are outside
this boundary unless another tool extracts them as text first.

## Governed Memory Workflows

Use `nullclaw memory export-jsonl` when memory needs to become a DS artifact.
The command emits JSONL with a stable schema and excludes bootstrap/autosave
internal entries by default. Content is PII-redacted by default. Use
`--include-pii` only when exporting inside a trusted local boundary; the older
`--redact-pii` flag is still accepted as a compatibility no-op.

Use `nullclaw memory hygiene-report` before cleanup work. The command is always
a dry run: it reports exact and normalized duplicate groups without deleting,
rewriting, or reindexing memory entries.

## On-Demand Anonymization Tool

The `anonymize_text` tool exposes the same lightweight redaction primitive to
the agent for one-off text snippets. It accepts a required `text` field and
optional `redact_email`, `redact_phone`, `redact_card`, `redact_id`, and
`redact_tokens` booleans. All categories are enabled by default; explicitly
disabled categories pass through unchanged.

The model-facing `sqlite_query` tool always returns redacted results. Raw
sensitive SQLite output is not exposed through the agent tool schema. It also
rejects common text transform / encoding functions such as `hex(...)` and
`substr(...)`, because those can turn PII into a form the text redactor cannot
recover after query execution.

Each call uses a fresh one-way redactor, so placeholder counters restart from
`[EMAIL_1]` / `[PHONE_1]` inside that call and no plaintext reverse map is kept
after the tool returns. Use it before putting user-supplied text into tickets,
notebooks, logs, exports, or downstream tools that do not need the original
sensitive values. The tool is text-only and bounded to 256 KiB input; it does
not inspect binary image contents, OCR text, or EXIF metadata.

## Channel Allowlists

- Empty `allow_from` denies inbound messages on allowlist-based channels.
- Set explicit user IDs/OpenIDs when you want a private bot.
- `allow_from: ["*"]`: allow all sources (high-risk).
- Otherwise: expect exact-match allowlists or channel-specific fallback/group-policy behavior.

## Pairing and Webhook Auth Boundaries

- `/pair` is POST-only and expects `X-Pairing-Code`.
- Repeated invalid pairing attempts can trigger rate limiting and a temporary lockout.
- `/.well-known/agent.json` and `/.well-known/agent-card.json` are public discovery documents when A2A is enabled.
- Keeping `gateway.require_pairing = true` keeps `/webhook`, `/a2a`, and `/media/transcribe` behind bearer auth; disabling pairing removes that bearer check on local binds.
- Telegram webhook delivery requires `X-Telegram-Bot-Api-Secret-Token` to match `channels.telegram.accounts.<id>.webhook_secret`.
- Channel-specific inbound webhooks keep their own auth or signature rules and should not be documented as if they all use gateway bearer auth.

## Nostr-specific Rules

- `owner_pubkey` is always allowed even if `dm_allowed_pubkeys` is stricter.
- Private keys are stored encrypted (`enc2:`), decrypted in memory only while the channel runs.

## Recommended Security Config

```json
{
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true,
    "allow_public_bind": false
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": { "backend": "auto" },
    "audit": { "enabled": true, "retention_days": 90 }
  }
}
```

## Shell Environment Variables

By default, only a minimal set of safe environment variables (`PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `USER`, `SHELL`, `TMPDIR`) are passed to shell child processes. This prevents leaking API keys and credentials (CWE-200).

### Path-validated Environment Variables

Some deployments inject tools via volume mounts (e.g., a toolbox init container in Kubernetes). These tools may need environment variables like `LD_LIBRARY_PATH` to find shared libraries, but passing `LD_LIBRARY_PATH` unconditionally is a security risk (library injection).

The `tools.path_env_vars` config allows specifying environment variables whose **values are platform path lists** (`:` on Unix, `;` on Windows). Each path component is validated against the sandbox before the variable is passed to child processes:

1. Every component must be an absolute path
2. Every component is resolved via `realpath` (canonicalized, symlinks followed)
3. Every component must be within the workspace or `allowed_paths`
4. The system blocklist (`/etc`, `/usr/lib`, `/bin`, etc.) always rejects

If **any** component fails validation, the entire variable is dropped.

```json
{
  "autonomy": {
    "allowed_paths": ["/opt/tools"]
  },
  "tools": {
    "path_env_vars": ["LD_LIBRARY_PATH", "PYTHONHOME", "NODE_PATH"]
  }
}
```

With the config above and `LD_LIBRARY_PATH=/opt/tools/usr/lib:/opt/tools/lib` set in the container environment, the shell tool will validate both path components against `/opt/tools` (via `allowed_paths`) and pass the variable through. An attacker-controlled value like `/tmp/evil:/opt/tools/lib` would be rejected because `/tmp/evil` is not within the workspace or allowed paths.

## High-risk Settings

These settings significantly widen trust boundaries and should be used only in controlled environments:

- `autonomy.level = "full"`
- `autonomy.level = "yolo"`
- `allowed_commands = ["*"]`
- `allowed_paths = ["*"]`
- `block_high_risk_commands = false` — enables destructive commands (`rm`, `sudo`, `dd`, `mkfs`, etc.)
- `block_medium_risk_commands = false` — enables medium-risk commands, including network/transfer commands (`curl`, `wget`, `nc`, `scp`, etc.) and local mutations such as `git commit`, `npm install`, or `touch`
- `gateway.allow_public_bind = true`

## Workspace Secret Audit

`nullclaw workspace audit` scans the workspace, a staged Git diff, or a Git revision range for likely secret leaks. Detection runs entirely on the local machine and emits findings in a stable JSON shape suitable for CI integration.

### What is detected

| Detector | Source |
|---|---|
| Known token-prefix fingerprints | `AKIA…`, `ghp_`, `gho_`, `ghs_`, `glpat-`, `xoxb-`, `xoxp-`, `sk-`, `sk-proj-` and friends |
| Score-based assignment matcher | Decomposes `KEY=value` / `key: value` into named components scored against a secret-keyword dictionary |
| Format detectors | `-----BEGIN PRIVATE KEY-----` PEM blocks; credentials embedded in URLs (`scheme://user:pass@host/...`) |
| High-entropy walker | Any token-shaped run of ≥ 16 characters with Shannon entropy ≥ 4.0 that is not a UUID, git commit hash, or placeholder string |

Exit codes follow `--fail-on <none\|medium\|high\|critical>` (default `high`). Combine with `--json` for CI pipelines.

### Optional LLM triage

The `--llm-triage` flag adds an opt-in second stage that classifies findings using the agent's configured LLM provider. The classifier receives a **privacy-preserving envelope** that omits the raw secret value:

| In the envelope | NOT in the envelope |
|---|---|
| `variable_name`, `file_path`, `extension`, `detector` | the secret value itself |
| `token_type_fingerprint` (deterministic local lookup) | any substring of the secret |
| `length`, `charset`, `entropy` | line content around the secret |
| Masked line context (e.g. `KEY=<SECRET:len=40,charset=base64url,entropy=5.3>`) | non-canonical surrounding words |
| `nearby_keywords` filtered through a whitelist of ~60 canonical security/service terms | customer names, internal hostnames, business identifiers |
| Deterministic flags: `is_test_path`, `is_example_file`, `is_in_comment`, `is_in_docstring` | the LLM's inference of those flags |

The envelope schema is versioned (`schema_version: "1"`) and each envelope carries a SHA-256 `envelope_hash` for traceability.

Three modes:

- `--llm-triage off` (default) — no LLM activity; behavior identical to a baseline scan.
- `--llm-triage dry-run` — print the envelopes that *would* be sent (to stderr) without making any network call. Use this to confirm what would leave the machine before turning the feature on.
- `--llm-triage external` — submit envelopes through the configured provider vtable. Uses `workspace_audit.llm_triage.{provider,model}` when present, then the configured primary provider/model, unless overridden by `--llm-provider` / `--llm-model`. When the provider is local (e.g. Ollama) the envelopes do not leave the machine at all.

To pin audit triage to a smaller/local model without changing the normal agent model, set:

```json
{
  "workspace_audit": {
    "llm_triage": {
      "provider": "ollama",
      "model": "qwen2.5-coder:7b",
      "max_calls": 20
    }
  }
}
```

This config does not enable external LLM calls by itself; the operator still has to pass `--llm-triage external`. CLI flags `--llm-provider`, `--llm-model`, and `--llm-max-calls` override these config values for a single run. Unknown provider names are rejected unless that provider has an explicit `models.providers.<name>.base_url`, so a typo cannot silently route audit envelopes through a fallback provider.

Every `external` request is appended to `<config-dir>/audit-log.jsonl`. NullClaw writes a `sent` event containing the envelope before the LLM call, then a `verdict` event keyed by `envelope_hash` after the response. The log is append-only and intended for after-the-fact verification of what metadata was sent.

### Operator notes

- Default `--llm-triage off` means no behavior change for existing scans. Enable explicitly when triaging false positives is a problem.
- For privacy-sensitive deployments, pin `workspace_audit.llm_triage.provider` to `ollama` (or another local-only provider) before enabling `--llm-triage external`.
- Verdict values are advisory: a `false_positive` decision drops the finding; a `real_secret` decision may adjust severity. The deterministic Stage 1 detectors remain authoritative on whether a candidate is surfaced at all.

## Next Steps

- Review [Configuration](./configuration.md) before applying any high-risk setting listed on this page
- Use [Gateway API](./gateway-api.md) when you need endpoint-level auth and exposure details
- Run the checks in [Usage and Operations](./usage.md) after changing gateway, channel, or autonomy settings

## Related Pages

- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Gateway API](./gateway-api.md)
- [Architecture](./architecture.md)
