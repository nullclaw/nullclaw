# DingTalk Ops Readiness

This page covers DingTalk-specific validation and the fastest path to debug a
runtime that can still send messages but is not receiving inbound events.

## Page Guide

**Who this page is for**

- Operators validating a new DingTalk deployment
- Troubleshooters diagnosing missing inbound messages or unhealthy channel status
- Maintainers checking whether a report is config drift, an outdated binary, or
  a DingTalk-side delivery problem

**Read this next**

- Open [Usage and Operations](../usage.md) for the generic service and log flow
- Open [Configuration](../configuration.md) for the main config file context
- Open [Security](../security.md) before widening `allow_from`

## What Healthy Looks Like

- Current builds start DingTalk as a gateway-loop channel. In startup logs that
  means `dingtalk gateway started`, not `dingtalk started (send-only)`.
- Channel health is true only when the runtime is running and the DingTalk
  stream websocket is connected.
- Outbound replies may still succeed through a fresh session webhook target even
  when inbound delivery is broken, so "I can send but not receive" usually
  points to the stream path, not the reply path.

## Preflight Checklist

1. Confirm you are running a current build. If logs still show
   `dingtalk started (send-only)`, update first.
2. Check `channels.dingtalk.accounts.<id>.client_id` and `client_secret` come
   from the same DingTalk app.
3. Check `allow_from` is not empty. `allow_from: []` denies all inbound
   messages.
4. Start the runtime with `nullclaw gateway` and confirm
   `nullclaw channel status` shows DingTalk as healthy.
5. If credentials are suspect, run
   `nullclaw --probe-channel-health --channel dingtalk --account <id>` to
   validate token acquisition.

## If Inbound Messages Never Arrive

1. Verify the DingTalk app is configured for stream-mode inbound delivery. The
   current runtime opens a websocket via DingTalk's gateway connection API;
   outbound-only setup is not enough.
2. Confirm the app is subscribed to the message events you expect to receive.
   If DingTalk never emits those callbacks, nullclaw has nothing to ingest.
3. Run in the foreground and capture the first DingTalk error before restarting.
   The most relevant log lines are `dingtalk websocket cycle failed`,
   `dingtalk websocket read failed`, and
   `dingtalk envelope handling failed`.
4. Re-test with a sender that is explicitly present in `allow_from`. An
   allowlist miss looks like "message ignored", not transport failure.

## Reply Target and Fallback Behavior

- Fresh reply targets use the `sessionWebhook` URL attached to an inbound event.
- If a group reply target expires, nullclaw can fall back to DingTalk AI
  interaction APIs using the cached conversation id.
- Direct-message reply targets do not have that group fallback; once the session
  webhook expires, you need a fresh inbound event or a proactive target.
- Arbitrary `https://...` webhook targets are rejected intentionally, and media
  payloads are currently unsupported on outbound send.

## Recommended Validation Sequence

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw gateway
```

Then send a DingTalk message from an allowed sender and inspect the first
runtime error before restarting anything.
