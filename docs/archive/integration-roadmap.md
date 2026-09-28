# Integration Roadmap: nullclaw + nullboiler + nulltickets

> Target: End-to-end multi-agent workflows with Telegram topic routing

## Current Status

✅ **Completed:**
- PR #500: Session provider dangling pointer fix (critical bugfix)
- Full gap analysis documented in `integration-analysis.md`

⏳ **In Progress:**
- PR #459: system_prompt file auto-detect (awaiting CI)

📋 **Planned:**
- 7 integration gaps identified (see below)

---

## Gap Inventory

| # | Gap | Priority | Status | Est. Effort |
|---|-----|----------|--------|-------------|
| 1 | External Message Send API (`POST /api/send`) | 🔴 HIGH | Not started | 1-2 days |
| 2 | Callback Receiver (`POST /api/callback`) | 🔴 HIGH | Not started | 1-2 days |
| 3 | Worker Endpoint (`POST /api/worker`) | 🔴 HIGH | Not started | 2-3 days |
| 4 | Self-Registration with nullboiler | 🟡 MEDIUM | Not started | 1 day |
| 5 | Workflow Tool (`create_workflow`) | 🟡 MEDIUM | Not started | 1-2 days |
| 6 | Topic-Aware Callback Routing | 🟡 MEDIUM | Not started | 1-2 days |
| 7 | nulltickets Push Notifications | 🟢 LOW | Not started | 2-3 days |

---

## Phase 1: Critical Path (Week 1)

**Goal:** Enable nullboiler → nullclaw communication

- [ ] **Gap 3:** Worker Endpoint
  - File: `nullclaw/src/gateway.zig`
  - Accept nullboiler step dispatch format
  - Route to agent via session manager
  - Return synchronous response

- [ ] **Gap 1:** External Message Send API
  - File: `nullclaw/src/gateway.zig`
  - Accept authenticated requests
  - Hook into outbound bus
  - Support topic format `chatid#topic:threadid`

- [ ] **Gap 2:** Callback Receiver
  - File: `nullclaw/src/gateway.zig`
  - Parse nullboiler callback format
  - Route to appropriate handler

---

## Phase 2: Feedback Loop (Week 2)

**Goal:** Results reach correct Telegram topic

- [ ] **Gap 6:** Topic-Aware Routing
  - Store telegram_target in run metadata
  - Callback extracts and routes
  - Integration with agent bindings

- [ ] Integration testing
  - End-to-end workflow test
  - Telegram topic delivery verification

---

## Phase 3: Automation (Week 3)

**Goal:** Seamless deployment

- [ ] **Gap 4:** Self-Registration
  - Config schema: `nullboiler.url`, `worker_id`, `tags`
  - Startup registration logic
  - Health check pings

---

## Phase 4: Usability (Week 4)

**Goal:** Natural orchestrator workflows

- [ ] **Gap 5:** Workflow Tool
  - New tool: `create_workflow`
  - Wrap nullboiler `POST /runs` API
  - Auto-configure callbacks

---

## Phase 5: Enhancement (Future)

- [ ] **Gap 7:** nulltickets Push Notifications
  - Webhook subscription API
  - Stage transition events
  - Low priority — polling works

---

## Technical Notes

### Key Files

**nullclaw:**
- `src/gateway.zig` — Add 3 new endpoints
- `src/config.zig` — Add nullboiler config
- `src/daemon.zig` — Startup registration
- `src/tools/workflow.zig` — New tool

**nullboiler:**
- `src/api.zig` — Include telegram_target in metadata
- `src/callbacks.zig` — Already works (just needs target)

### Testing Strategy

1. Unit tests for each new endpoint
2. Integration test: nullboiler dispatch → nullclaw worker → Telegram delivery
3. End-to-end: User message → orchestrator → workflow → coder → result in topic

### Dependencies

- nullclaw must be running with gateway enabled
- nullboiler must be accessible via HTTP
- Telegram bot must have access to target topics

---

## References

- Full analysis: `./integration-analysis.md`
- nullboiler repo: `https://github.com/nullclaw/nullboiler`
- nulltickets repo: `https://github.com/nullclaw/nulltickets`

---

*Last updated: 2026-03-13*
