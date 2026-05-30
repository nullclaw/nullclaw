# Security Patch Plan - 2026-05-10

## Scope

This plan covers four security findings:

1. Telegram webhook spoofing and missing webhook authentication.
2. Secret exposure through `curl` process argv.
3. Cron shell jobs bypassing shell tool security controls.
4. Inbound channels allowing all senders when `allow_from` is empty.

Affected areas include:

- `src/gateway.zig`
- `src/http_util.zig`
- `src/providers/**`
- `src/channels/telegram_api.zig`
- `src/channels/discord.zig`
- `src/channels/line.zig`
- `src/cron.zig`
- config examples, documentation, and tests

Keep the patch limited to these security fixes. Do not combine it with unrelated refactors, feature work, or Zig toolchain changes.

## 1. Telegram Webhook Authentication

Risk: forged Telegram webhook updates can drive the agent and tools when the gateway is public or tunneled.

Plan:

- Add config support for a Telegram webhook secret compatible with Telegram's `X-Telegram-Bot-Api-Secret-Token` header.
- Require the secret-token header on `/telegram` webhook POSTs before parsing or dispatching the request body.
- Reject missing or mismatched webhook secrets with an explicit unauthorized response.
- Change `telegramSenderAllowed` so an empty `allow_from` denies by default.
- Require explicit `"*"` as the only allow-all sender configuration.
- Keep webhook failures non-sensitive in logs and responses.

Tests:

- Missing Telegram secret-token header is rejected.
- Incorrect Telegram secret-token header is rejected.
- Correct Telegram secret-token header is accepted.
- Empty Telegram `allow_from` denies.
- Explicit `"*"` allows all senders.
- Forged sender or chat IDs do not bypass webhook secret validation.

## 2. Remove Secrets From Child Process Arguments

Risk: local users, process monitors, or container hosts can read API keys, bearer tokens, bot tokens, proxy credentials, and webhook URLs from process argv.

Plan:

- Audit shared HTTP helpers and all credentialed callers.
- Replace credentialed `curl` execution paths with `std.http.Client`.
- Ensure provider requests do not place `Authorization`, API keys, or bearer tokens in child argv.
- Stop passing Telegram bot tokens in URLs to child processes.
- If any non-secret curl helper remains, make it reject credential-bearing headers and sensitive URLs before spawning.
- Keep outbound URL validation secure-by-default, including HTTPS-only behavior where currently required.

Tests:

- Credential headers are rejected by any remaining child-process HTTP helper.
- OpenAI and Gemini request paths do not use child argv for bearer tokens.
- Telegram API calls do not pass bot tokens through child argv.
- Sensitive values are not included in command construction errors or logs.

If argv exposure cannot be directly unit tested for a specific path, add a short comment near the code explaining the coverage limitation and the integration coverage expected.

## 3. Cron Shell Job Security Enforcement

Risk: anyone who can create or update cron jobs can gain persistent shell execution outside the normal shell tool policy, sandbox, environment scrub, timeout, and output limits.

Plan:

- Route cron shell execution through the same `ShellTool` and `SecurityPolicy` path used by normal shell tool calls.
- Validate shell cron commands when jobs are created or updated.
- Revalidate commands at execution time so previously stored unsafe jobs cannot bypass policy after upgrade.
- Preserve existing agent-job behavior unless it depends on unsafe shell execution.
- If full `ShellTool` integration is too invasive for the first patch, restrict cron REST endpoints to agent jobs only until a separately audited admin shell mode exists.
- Apply the same timeout, output limits, sandbox behavior, and environment scrub used by the shell tool.

Tests:

- Disallowed cron shell command is rejected at creation.
- Disallowed cron shell command is rejected at update.
- Previously stored disallowed cron shell command cannot execute.
- Timeout and output limits apply to cron shell execution.
- Environment secrets are not inherited by cron shell jobs.
- Agent cron jobs continue to execute as expected.

## 4. Deny Empty Inbound Allowlists

Risk: empty `allow_from` values create open-bot behavior that conflicts with the repository's deny-by-default security posture.

Plan:

- Normalize inbound channel semantics:
  - Empty `allow_from` denies all senders.
  - Explicit `"*"` allows all senders.
  - Exact configured sender IDs allow only matching senders.
- Apply this to Telegram gateway handling, Discord, and LINE.
- Update config examples and docs to show explicit sender allowlists.
- Document the behavior change as intentional and security-sensitive.

Tests:

- Discord empty `allow_from` denies.
- Discord explicit `"*"` allows all.
- Discord matching sender allows and non-matching sender denies.
- LINE empty `allow_from` denies.
- LINE explicit `"*"` allows all.
- LINE matching sender allows and non-matching sender denies.
- Telegram gateway empty `allow_from` denies.
- Telegram gateway explicit `"*"` allows all.
- Telegram gateway matching sender allows and non-matching sender denies.

## Config And Documentation

Plan:

- Add a Telegram webhook secret field to the relevant config schema and examples.
- Use neutral placeholders such as `"test-secret"` and `"user_a"` in tests and examples.
- Avoid generating secrets silently during normal config loading.
- Update docs and examples that imply an empty allowlist is safe or permissive.
- Clearly state that allow-all requires explicit `"*"`.

## Validation

Required validation after code changes:

```bash
zig build test --summary all
zig build -Doptimize=ReleaseSmall
```

Security-sensitive changes should also include targeted tests for the modified modules before the full suite is run.

Environment note from 2026-05-10: the current system `zig` was observed as `0.14.1`, while this repository is pinned to `0.16.0`. Full validation must be performed with Zig `0.16.0`.

## Handoff Checklist

Before handing off or opening a PR, include:

1. What changed.
2. What did not change.
3. Threat notes for each fixed class.
4. Validation commands and results.
5. Remaining risks or unknowns.
6. Next recommended action.
