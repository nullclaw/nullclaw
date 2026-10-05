# Integration Analysis: nullclaw + nullboiler + nulltickets

## Executive Summary

This document analyzes the integration gaps between three nullclaw ecosystem projects to enable end-to-end multi-agent workflows with Telegram topic routing.

**Target Scenario:**
> User sends message in Telegram General topic → Orchestrator agent decides to delegate coding task → Coder agent executes → Result appears in the Coder topic in Telegram

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   nulltickets   │────▶│   nullboiler     │────▶│    nullclaw     │
│  (Task Tracker) │     │ (DAG Orchestrator)│     │  (AI Runtime)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
   Pipeline FSM             Workflow DAG           Telegram Topics
   Lease-based              Step dispatch          Agent routing
   Role routing             Worker selection       Tool execution
```

### Project Roles

| Component | Responsibility | Key Files |
|-----------|---------------|-----------|
| **nulltickets** | Durable task state, FSM transitions, lease coordination | `src/api.zig`, `src/store.zig`, `src/domain.zig` |
| **nullboiler** | DAG scheduling, worker dispatch, step orchestration | `src/engine.zig`, `src/dispatch.zig`, `src/callbacks.zig` |
| **nullclaw** | AI agent runtime, tool execution, Telegram integration | `src/agent/root.zig`, `src/gateway.zig`, `src/session.zig` |

## Current Capabilities

### ✅ What Already Works

1. **Telegram Topic Delivery** (`nullclaw/src/channels/telegram.zig:146-156`)
   - Supports `chatid#topic:threadid` format for forum topics
   - `MessageTool` can send to any channel/topic combination

2. **Agent Routing per Topic** (`nullclaw/src/agent_bindings_config.zig`)
   - 7-tier binding system: peer → parent_peer → guild_roles → guild → team → account → default
   - `/bind` command for runtime topic-to-agent binding

3. **nullboiler Callback System** (`nullboiler/src/callbacks.zig:21-114`)
   - Webhook callbacks on events: `step.completed`, `step.failed`, `run.completed`, `run.failed`
   - Supports custom headers and HMAC signing

4. **nullboiler Worker Dispatch** (`nullboiler/src/dispatch.zig:89-199`)
   - 5 protocols: webhook, api_chat, openai_chat, mqtt, redis_stream
   - Tag-based worker selection with least-loaded balancing

5. **nullclaw Tool System** (`nullclaw/src/tools/root.zig`)
   - `MessageTool` — send to any channel/topic internally
   - `DelegateTool` — synchronous sub-agent delegation
   - `HttpRequestTool` — arbitrary HTTP calls

6. **Agent Profile System** (`nullclaw/src/config.zig`)
   - Named agents with different providers, models, system prompts
   - Session-scoped agent instances

## Integration Gaps

### Gap 1: External Message Send API (HIGH PRIORITY)

**Problem:** nullclaw's gateway is inbound-only. No endpoint exists for external services (like nullboiler) to trigger outbound messages to specific Telegram topics.

**Current State:**
- Gateway endpoints: `/health`, `/ready`, `/pair`, `/webhook`, `/telegram`, `/whatsapp`, `/a2a`
- No `/api/send` or similar endpoint

**Required:**
- New `POST /api/send` endpoint in `nullclaw/src/gateway.zig`
- Accept JSON: `{channel: "telegram", chat_id: "-100123#topic:456", content: "..."}`
- Hook into `bus.Bus.publishOutbound()` for delivery
- Authentication via existing token/pairing system

**Implementation Notes:**
```zig
// Potential endpoint structure in gateway.zig
POST /api/send
Body: {
  "channel": "telegram",
  "chat_id": "-1001234567890#topic:42",
  "content": "Coder agent completed the task...",
  "reply_to_message_id": null
}
```

### Gap 2: Callback Receiver for nullboiler (HIGH PRIORITY)

**Problem:** nullboiler can fire callbacks when steps complete, but nullclaw has no endpoint to receive them.

**Current State:**
- nullboiler fires callbacks: `fireCallbacks()` in `nullboiler/src/callbacks.zig:21-114`
- Callback format: `{event, run_id, step_id, output, status}`
- nullclaw has no `/api/callback` endpoint

**Required:**
- New `POST /api/callback` endpoint in `nullclaw/src/gateway.zig`
- Parse nullboiler callback format
- Route results to appropriate Telegram topic via outbound bus

**Implementation Notes:**
```zig
// Callback format from nullboiler/src/callbacks.zig
{
  "event": "step.completed",
  "run_id": "run-uuid",
  "step_id": "code",
  "output": "The generated bash script...",
  "status": "ok"
}
```

### Gap 3: Worker Endpoint for nullboiler Dispatch (HIGH PRIORITY)

**Problem:** nullboiler dispatches steps to workers via HTTP POST, but nullclaw has no endpoint that accepts nullboiler's step format.

**Current State:**
- nullboiler dispatches: `dispatchStep()` in `nullboiler/src/dispatch.zig:89-199`
- Dispatch payload: `{prompt, context, step_id, run_id, correlation_id}`
- nullclaw's `/webhook` is designed for Telegram, not generic worker tasks

**Required:**
- New `POST /api/worker` endpoint in `nullclaw/src/gateway.zig`
- Accept nullboiler step dispatch format
- Route to appropriate agent via `agent_routing.resolveRoute()`
- Return response in format: `{status:"ok", response:"..."}`
- Handle via `session_mgr.processMessage()` for agent execution

**Implementation Notes:**
```zig
// Worker dispatch payload from nullboiler
{
  "prompt": "Generate a bash script that...",
  "context": {"previous_output": "..."},
  "step_id": "code",
  "run_id": "run-uuid",
  "correlation_id": "corr-uuid"
}

// Expected response format (nullboiler/src/worker_response.zig:102)
{
  "status": "ok",
  "response": "#!/bin/bash\necho 'Hello World'"
}
```

### Gap 4: Self-Registration with nullboiler (MEDIUM PRIORITY)

**Problem:** nullclaw cannot automatically register itself as a nullboiler worker on startup.

**Current State:**
- nullboiler has `POST /workers` endpoint (`nullboiler/src/api.zig:135`)
- nullclaw has no startup registration logic

**Required:**
- Config additions: `nullboiler.url`, `nullboiler.worker_id`, `nullboiler.tags`, `nullboiler.capacity`
- Startup hook in `nullclaw/src/daemon.zig` or new `nullclaw/src/boiler_client.zig`
- HTTP POST to `{nullboiler_url}/workers` with registration payload

**Implementation Notes:**
```zig
// Registration payload
{
  "id": "nullclaw-coder-1",
  "url": "http://nullclaw:8080/api/worker",
  "protocol": "webhook",
  "tags": ["coder", "bash"],
  "max_concurrent": 3
}
```

### Gap 5: Dedicated Workflow Tool (MEDIUM PRIORITY)

**Problem:** Orchestrator agent must manually construct nullboiler API calls using `http_request` tool, which is error-prone.

**Current State:**
- nullboiler `POST /runs` endpoint exists (`nullboiler/src/api.zig:70`)
- nullclaw `http_request` tool can make arbitrary calls
- No high-level workflow abstraction

**Required:**
- New `create_workflow` tool in `nullclaw/src/tools/workflow.zig`
- Wrap nullboiler `POST /runs` API
- Auto-set callback URL to nullclaw's gateway
- Simplified interface for agent

**Implementation Notes:**
```zig
// Tool interface
{
  "name": "create_workflow",
  "arguments": {
    "workflow_name": "code-review",
    "inputs": {"task": "Create bash script"},
    "telegram_target": "-100123#topic:456"
  }
}
```

### Gap 6: Topic-Aware Callback Routing (MEDIUM PRIORITY)

**Problem:** When nullboiler sends a callback, nullclaw needs to know which Telegram topic to route the result to.

**Current State:**
- Callbacks contain run/step metadata but no Telegram routing info
- Agent bindings config has topic mappings

**Required:**
- Store `telegram_target` (chat_id#topic) in run metadata when creating workflow
- Include in callback payload or correlate via run_id
- Callback receiver looks up target and routes via outbound bus

**Implementation Notes:**
```zig
// Store in run creation
POST /runs
{
  "workflow": {...},
  "inputs": {...},
  "metadata": {
    "telegram_target": "-100123#topic:456",
    "origin_chat_id": "-100123",
    "origin_topic_id": "42"
  }
}
```

### Gap 7: nulltickets Push Notifications (LOW PRIORITY)

**Problem:** nulltickets is pull-based (lease/claim). No push/webhook mechanism for real-time notifications.

**Current State:**
- nulltickets API: claim tasks via `POST /leases/claim`
- No webhook subscription endpoint

**Impact:** Low — nullboiler already bridges via `tracker_client.zig` polling

**Required (if needed):**
- New webhook subscription API in `nulltickets/src/api.zig`
- Fire webhooks on stage transitions

## Implementation Roadmap

### Phase 1: Critical Path (Gaps 1-3)

Without these, nullboiler cannot communicate with nullclaw at all.

1. **Worker Endpoint** (`POST /api/worker`)
   - Accept nullboiler step dispatch
   - Route to agent via session manager
   - Return synchronous response
   - File: `nullclaw/src/gateway.zig`

2. **External Send API** (`POST /api/send`)
   - Accept authenticated requests to send messages
   - Hook into outbound bus
   - Support topic format `chatid#topic:threadid`
   - File: `nullclaw/src/gateway.zig`

3. **Callback Receiver** (`POST /api/callback`)
   - Accept nullboiler callbacks
   - Parse event types
   - Route to appropriate handler
   - File: `nullclaw/src/gateway.zig`

### Phase 2: Feedback Loop (Gaps 2+6)

Close the loop so workflow results reach the right Telegram topic.

4. **Topic-Aware Routing**
   - Store telegram_target in run metadata
   - Callback receiver extracts and routes
   - Integration with agent bindings
   - Files: `nullclaw/src/gateway.zig`, `nullboiler` run creation

### Phase 3: Automation (Gap 4)

5. **Self-Registration**
   - Config schema additions
   - Startup registration logic
   - Health check pings
   - File: `nullclaw/src/daemon.zig`

### Phase 4: Usability (Gap 5)

6. **Workflow Tool**
   - High-level tool for orchestrator agents
   - Auto-configure callbacks
   - Schema validation
   - File: `nullclaw/src/tools/workflow.zig`

### Phase 5: Enhancement (Gap 7)

7. **nulltickets Push** (optional)
   - Webhook subscription API
   - Stage transition events
   - File: `nulltickets/src/api.zig`

## Technical Details

### nullclaw Gateway API Design

```zig
// New endpoints to add in nullclaw/src/gateway.zig

// 1. Worker endpoint for nullboiler dispatch
POST /api/worker
Content-Type: application/json
Authorization: Bearer <token>

Request:
{
  "prompt": "Generate a bash script that...",
  "context": {"previous_output": "..."},
  "step_id": "code",
  "run_id": "run-uuid",
  "correlation_id": "corr-uuid"
}

Response:
{
  "status": "ok",
  "response": "#!/bin/bash\necho 'Hello World'",
  "correlation_id": "corr-uuid"
}

// 2. External message send
POST /api/send
Content-Type: application/json
Authorization: Bearer <token>

Request:
{
  "channel": "telegram",
  "chat_id": "-1001234567890#topic:42",
  "content": "Task completed successfully!",
  "reply_to_message_id": null
}

Response:
{
  "status": "ok",
  "message_id": "12345"
}

// 3. Callback receiver
POST /api/callback
Content-Type: application/json
Authorization: Bearer <token>

Request:
{
  "event": "step.completed",
  "run_id": "run-uuid",
  "step_id": "code",
  "output": "Generated script content...",
  "metadata": {
    "telegram_target": "-100123#topic:42"
  }
}

Response:
{
  "status": "received"
}
```

### nullboiler Integration Points

```zig
// nullboiler/src/callbacks.zig - existing callback firing
// This already works, just needs a target endpoint

pub fn fireCallbacks(
    allocator: std.mem.Allocator,
    callbacks: []const Callback,
    event: Event,
    run_id: []const u8,
    step_id: ?[]const u8,
    output: ?[]const u8,
) !void {
    // Callback POST to nullclaw /api/callback
    // Include telegram_target from run metadata
}
```

### Data Flow Example

```
User in General topic:
  "Write a bash script that backs up my home directory"

1. nullclaw receives via Telegram webhook
2. Agent "orchestrator" processes message
3. Agent calls create_workflow tool
   → POST to nullboiler /runs
   → Metadata includes: telegram_target="general#topic:1"

nullboiler:
4. Creates workflow run
5. Dispatches "code" step to "coder" worker (nullclaw instance)
   → POST to nullclaw /api/worker

nullclaw (coder):
6. Receives step dispatch
7. Agent "coder" generates script
8. Returns response to nullboiler

nullboiler:
9. Step completes
10. Fires callback
    → POST to nullclaw /api/callback
    → Includes output + telegram_target

nullclaw:
11. Callback receiver parses event
12. Routes output to telegram_target
    → POST internally to /api/send
    → Delivers to General topic

User sees:
  [In General topic] "Here's the backup script: ..."
```

## Configuration Example

```json
// nullclaw config.json additions
{
  "nullboiler": {
    "url": "http://nullboiler:8080",
    "worker_id": "nullclaw-main",
    "tags": ["orchestrator", "general"],
    "max_concurrent": 5,
    "auto_register": true
  },
  "gateway": {
    "enable_worker_endpoint": true,
    "enable_callback_endpoint": true,
    "enable_send_api": true
  }
}
```

## Files Modified

| Project | File | Changes |
|---------|------|---------|
| nullclaw | `src/gateway.zig` | Add 3 new endpoints: /api/worker, /api/send, /api/callback |
| nullclaw | `src/config.zig` | Add nullboiler config struct |
| nullclaw | `src/daemon.zig` | Add self-registration startup hook |
| nullclaw | `src/tools/workflow.zig` | New tool for create_workflow |
| nullclaw | `src/tools/root.zig` | Register workflow tool |
| nullboiler | `src/api.zig` | Optionally include telegram_target in run metadata |
| nulltickets | `src/api.zig` | Optional: webhook subscriptions (low priority) |

## References

### nullclaw
- `src/gateway.zig` - HTTP server and routing
- `src/agent/root.zig` - Agent execution
- `src/session.zig` - Session management
- `src/agent_bindings_config.zig` - Topic binding resolution
- `src/tools/message.zig` - Message sending
- `src/channels/telegram.zig` - Telegram topic support

### nullboiler
- `src/engine.zig` - DAG execution loop
- `src/dispatch.zig` - Worker dispatch logic
- `src/callbacks.zig` - Callback firing mechanism
- `src/api.zig` - REST API endpoints
- `src/types.zig` - Step types and data structures

### nulltickets
- `src/api.zig` - REST API
- `src/store.zig` - Database operations
- `src/domain.zig` - FSM transitions

## Version History

| Date | Author | Changes |
|------|--------|---------|
| 2026-03-13 | @vedmalex | Initial gap analysis based on codebase exploration |

---

*This document is a living analysis. As implementations progress, update the status of each gap and add implementation notes.*
