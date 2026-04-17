# Lark Ops Readiness

This guide defines channel-specific operations checks for Lark/Feishu.

## Health Semantics

- Websocket mode is healthy only when both running and connected are true.
- Webhook mode is healthy when runtime is active and callback path is reachable.

## Auth and Permissions

1. Validate tenant token acquisition and refresh behavior.
2. Treat non-zero business code as operational failure.
3. Escalate permission/scope-like errors immediately.

## Fast Triage for `error.LarkApiError`

1. Run `nullclaw doctor` to confirm the channel config is structurally valid.
2. Run `nullclaw channel status` after startup to confirm whether the channel is running but disconnected.
3. Treat repeated `warning(lark): lark websocket cycle failed: error.LarkApiError` as one of:
   - missing Lark/Feishu app permissions or scopes
   - wrong regional endpoint selection (`use_feishu`)
   - websocket callback provisioning failure
4. If an older Linux build crashes before stable reconnect logging, upgrade first and then continue permission triage.

## Incident Steps

1. Check app permissions/scopes in Feishu/Lark console.
2. Verify callback endpoint and websocket path availability.
3. Confirm sender allowlist (`allow_from`) and group mention behavior.
4. Restart channel worker only after root cause capture.

## SLO Signals

- auth_fail_total
- reconnect_total
- outbound_send_fail_total
- healthcheck_fail_total
