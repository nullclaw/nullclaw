#!/usr/bin/env bash
# test-api-e2e.sh — End-to-end smoke test for the REST Admin API (/api/).
#
# Usage:
#   ./scripts/test-api-e2e.sh
#   INFINI_AI_KEY=sk-... ./scripts/test-api-e2e.sh
#
# Prerequisites:
#   - nullclaw binary at zig-out/bin/nullclaw (run `zig build -Doptimize=ReleaseSmall` first)
#   - curl, jq, python3 available on PATH
#
# LLM key resolution (in priority order):
#   1. INFINI_AI_KEY env var
#   2. ~/.nullclaw/config.json models.providers.infini-ai.api_key
#   3. (empty — POST /api/agent invocation checks will fail)
#
# The script:
#   1. Writes a temp config to /tmp/nullclaw-e2e/config.json
#   2. Starts the gateway (which also starts scheduler + session manager via daemon.run)
#   3. Waits for it to be ready
#   4. Runs all API checks
#   5. Kills the gateway and reports pass/fail counts
#
# Exit code: 0 if all checks pass, 1 if any fail.

set -uo pipefail

BINARY="${BINARY:-zig-out/bin/nullclaw}"
E2E_DIR="/tmp/nullclaw-e2e"
PORT=19871
BASE="http://127.0.0.1:${PORT}/api"
TOKEN="e2e-test-token"
AUTH="Authorization: Bearer ${TOKEN}"

# ── LLM key resolution ────────────────────────────────────────────────────────

_resolve_infini_ai_key() {
    python3 - <<'PYEOF' 2>/dev/null || echo ""
import json, os
cfg = os.path.expanduser("~/.nullclaw/config.json")
try:
    with open(cfg) as f:
        d = json.load(f)
    print(d.get("models", {}).get("providers", {}).get("infini-ai", {}).get("api_key", ""))
except Exception:
    print("")
PYEOF
}

INFINI_AI_KEY="${INFINI_AI_KEY:-$(_resolve_infini_ai_key)}"
INFINI_AI_BASE_URL="${INFINI_AI_BASE_URL:-https://cloud.infini-ai.com/maas/coding/v1}"

if [ -z "$INFINI_AI_KEY" ]; then
    echo "WARNING: INFINI_AI_KEY not set and not found in ~/.nullclaw/config.json."
    echo "         POST /api/agent invocation checks will fail (500/503)."
    echo "         Set INFINI_AI_KEY=<key> to enable full e2e coverage."
    echo ""
fi

PASS=0
FAIL=0
FAILURES=()

# ── helpers ─────────────────────────────────────────────────────────────────

check() {
    local label="$1"
    local expected_status="$2"
    local actual_status="$3"
    local body="$4"
    local extra_check="${5:-}"  # optional jq expression that must return 'true'

    local ok=true

    if [ "$actual_status" != "$expected_status" ]; then
        ok=false
    fi

    if [ -n "$extra_check" ] && [ "$ok" = "true" ]; then
        local jq_result
        jq_result=$(echo "$body" | jq -r "$extra_check" 2>/dev/null || echo "false")
        if [ "$jq_result" != "true" ]; then
            ok=false
        fi
    fi

    if [ "$ok" = "true" ]; then
        PASS=$((PASS + 1))
        echo "  PASS  $label"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$label (HTTP $actual_status, expected $expected_status; body: ${body:0:200})")
        echo "  FAIL  $label  [HTTP $actual_status, expected $expected_status]"
        if [ -n "$extra_check" ] && [ "$actual_status" = "$expected_status" ]; then
            echo "        jq '$extra_check' => $(echo "$body" | jq -r "$extra_check" 2>/dev/null || echo '<error>')"
        fi
    fi
}

api() {
    # api <method> <path> [curl-args...]
    # Sets S=status_code  B=body
    local method="$1"; shift
    local path="$1"; shift
    local resp
    resp=$(curl -s -o "$E2E_DIR/resp.json" -w "%{http_code}" \
        -X "$method" \
        -H "$AUTH" \
        "$@" \
        "${BASE}${path}")
    S="$resp"
    B=$(cat "$E2E_DIR/resp.json" 2>/dev/null || echo "")
}

api_agent() {
    # api_agent <method> <path> [curl-args...]
    # Like api() but with a longer timeout for real LLM round-trips.
    local method="$1"; shift
    local path="$1"; shift
    local resp
    resp=$(curl -s --max-time 90 -o "$E2E_DIR/resp.json" -w "%{http_code}" \
        -X "$method" \
        -H "$AUTH" \
        "$@" \
        "${BASE}${path}")
    S="$resp"
    B=$(cat "$E2E_DIR/resp.json" 2>/dev/null || echo "")
}

# ── setup ────────────────────────────────────────────────────────────────────

echo "==> Setting up e2e environment at $E2E_DIR"
rm -rf "$E2E_DIR"
mkdir -p "$E2E_DIR"

# Write config using the OBJECT format for multi-account channels.
# The parser expects: "channel": {"accounts": {"id": {...}}}
# NOT the array format: "channel": [{"account_id": "...", ...}]
# INFINI_AI_KEY and INFINI_AI_BASE_URL are resolved above (env or ~/.nullclaw/config.json).
cat > "$E2E_DIR/config.json" <<EOF
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "infini-ai/glm-5"
      }
    }
  },
  "models": {
    "providers": {
      "infini-ai": {
        "api_key": "${INFINI_AI_KEY}",
        "base_url": "${INFINI_AI_BASE_URL}"
      }
    }
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 19871,
    "admin_api": true,
    "require_pairing": true,
    "paired_tokens": ["e2e-test-token"]
  },
  "channels": {
    "telegram": {
      "accounts": {
        "test_bot": {
          "bot_token": "test_telegram_token_123"
        }
      }
    },
    "discord": {
      "accounts": {
        "test_server": {
          "token": "test_discord_token_456"
        }
      }
    },
    "slack": {
      "accounts": {
        "test_workspace": {
          "bot_token": "xoxb-test-slack-token"
        }
      }
    }
  },
  "mcp_servers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"],
      "env": {
        "OPENROUTER_API_KEY": "e2e-fake-api-key"
      }
    }
  },
  "memory": {
    "backend": "sqlite"
  }
}
EOF

echo "==> Starting gateway"
NULLCLAW_HOME="$E2E_DIR" "$BINARY" gateway > "$E2E_DIR/gateway.log" 2>&1 &
GW_PID=$!
trap 'echo "==> Stopping gateway (pid $GW_PID)"; kill "$GW_PID" 2>/dev/null; wait "$GW_PID" 2>/dev/null' EXIT INT TERM

echo -n "==> Waiting for gateway to be ready"
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "${BASE}/status" 2>/dev/null | grep -q "200"; then
        echo " (ready after ${i}s)"
        break
    fi
    if ! kill -0 "$GW_PID" 2>/dev/null; then
        echo ""
        echo "ERROR: gateway exited early. Log:"
        cat "$E2E_DIR/gateway.log"
        exit 1
    fi
    sleep 1
    echo -n "."
    if [ "$i" = "30" ]; then
        echo ""
        echo "ERROR: gateway did not become ready in 30s. Log:"
        cat "$E2E_DIR/gateway.log"
        exit 1
    fi
done

# Give the scheduler thread a moment to register.
sleep 1

echo ""
echo "==> Running API checks"
echo ""

# ── Auth checks ───────────────────────────────────────────────────────────────

echo "-- Auth"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/status")
check "GET /api/status without token → 401" "401" "$S" ""

S=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-token" "${BASE}/status")
check "GET /api/status with wrong token → 401" "401" "$S" ""

echo ""

# ── Phase 1: Status / Config read / Models ────────────────────────────────────

echo "-- Phase 1: Status / Config read / Models"

api GET /status
check "GET /api/status → 200" "200" "$S" "$B" '.success == true'

# GET /api/config requires ?path= query parameter.
api GET "/config?path=default_temperature"
check "GET /api/config?path=default_temperature → 200" "200" "$S" "$B" '.success == true'

api GET "/config"
check "GET /api/config without path → 400" "400" "$S" "$B" '.success == false'

api GET /models
check "GET /api/models → 200" "200" "$S" "$B" '.success == true'

echo ""

# ── Phase 2: Cron CRUD ────────────────────────────────────────────────────────

echo "-- Phase 2: Cron CRUD"

api GET /cron
check "GET /api/cron → 200" "200" "$S" "$B" '.success == true'

# Create a recurring job.  Field is "expression" (not "schedule").
api POST /cron \
    -H "Content-Type: application/json" \
    -d '{"expression":"0 * * * *","prompt":"ping"}'
check "POST /api/cron create → 200" "200" "$S" "$B" '.success == true'
CRON_ID=$(echo "$B" | jq -r '.data.id // empty')

if [ -n "$CRON_ID" ]; then
    # Note: there is no GET /api/cron/:id endpoint; use GET /api/cron (list) instead.

    api POST "/cron/${CRON_ID}/pause"
    check "POST /api/cron/:id/pause → 200" "200" "$S" "$B" '.success == true'

    api POST "/cron/${CRON_ID}/resume"
    check "POST /api/cron/:id/resume → 200" "200" "$S" "$B" '.success == true'

    # /run triggers the job asynchronously; handler returns 200 via sendSuccess.
    api POST "/cron/${CRON_ID}/run"
    check "POST /api/cron/:id/run → 200" "200" "$S" "$B" '.success == true'

    api PATCH "/cron/${CRON_ID}" \
        -H "Content-Type: application/json" \
        -d '{"prompt":"updated ping"}'
    check "PATCH /api/cron/:id update → 200" "200" "$S" "$B" '.success == true'

    api DELETE "/cron/${CRON_ID}"
    check "DELETE /api/cron/:id → 200" "200" "$S" "$B" '.success == true'
else
    echo "  SKIP  cron sub-tests (cron create did not return an id)"
fi

# Create a one-shot job.  Field is "delay" (not "delay_secs").
api POST /cron/once \
    -H "Content-Type: application/json" \
    -d '{"delay":"1h","prompt":"ping once"}'
check "POST /api/cron/once create → 200" "200" "$S" "$B" '.success == true'
ONCE_ID=$(echo "$B" | jq -r '.data.id // empty')

if [ -n "$ONCE_ID" ]; then
    api DELETE "/cron/${ONCE_ID}"
    check "DELETE /api/cron/once job → 200" "200" "$S" "$B" '.success == true'
fi

# PATCH with unknown id → 404.
api PATCH "/cron/nonexistent-job-id" \
    -H "Content-Type: application/json" \
    -d '{"prompt":"nope"}'
check "PATCH /api/cron/nonexistent → 404" "404" "$S" "$B" '.success == false'

echo ""

# ── Phase 4: Channels ─────────────────────────────────────────────────────────

echo "-- Phase 4: Channels"

api GET /channels
check "GET /api/channels → 200" "200" "$S" "$B" '.success == true'
check "GET /api/channels → has telegram entry" "200" "$S" "$B" \
    '[.data[] | select(.type == "telegram")] | length > 0'
check "GET /api/channels → has discord entry" "200" "$S" "$B" \
    '[.data[] | select(.type == "discord")] | length > 0'
check "GET /api/channels → has slack entry" "200" "$S" "$B" \
    '[.data[] | select(.type == "slack")] | length > 0'

api GET /channels/telegram
check "GET /api/channels/telegram → 200" "200" "$S" "$B" '.success == true'
check "GET /api/channels/telegram → accounts non-empty" "200" "$S" "$B" \
    '.data.accounts | length > 0'

api GET /channels/discord
check "GET /api/channels/discord → 200" "200" "$S" "$B" '.success == true'
check "GET /api/channels/discord → accounts non-empty" "200" "$S" "$B" \
    '.data.accounts | length > 0'

api GET /channels/slack
check "GET /api/channels/slack → 200" "200" "$S" "$B" '.success == true'
check "GET /api/channels/slack → accounts non-empty" "200" "$S" "$B" \
    '.data.accounts | length > 0'

api GET /channels/nonexistent
check "GET /api/channels/nonexistent → 404" "404" "$S" "$B" '.success == false'

echo ""

# ── Phase 4: Skills ───────────────────────────────────────────────────────────

echo "-- Phase 4: Skills"

api GET /skills
check "GET /api/skills → 200" "200" "$S" "$B" '.success == true'

# Path traversal: the router may normalize '..' away (→ 404) or the handler
# catches it (→ 400).  Both are valid rejections.
api DELETE "/skills/.."
if [ "$S" = "400" ] || [ "$S" = "404" ]; then
    PASS=$((PASS + 1))
    echo "  PASS  DELETE /api/skills/.. → $S (path traversal rejected)"
else
    FAIL=$((FAIL + 1))
    FAILURES+=("DELETE /api/skills/.. should reject with 400 or 404, got $S")
    echo "  FAIL  DELETE /api/skills/.. → $S (expected 400 or 404)"
fi

api DELETE "/skills/nonexistent-skill"
check "DELETE /api/skills/nonexistent → 404" "404" "$S" "$B" '.success == false'

# In live mode, install attempts real network I/O (git clone etc.) for the URL.
# A fake/unreachable URL will legitimately fail with 500 INSTALL_FAILED.
# We just verify the endpoint responds (not a crash/hang) and returns JSON.
api POST /skills/install \
    -H "Content-Type: application/json" \
    -d '{"url":"https://example.com/skill"}'
if echo "$B" | jq -e '.success != null' > /dev/null 2>&1; then
    PASS=$((PASS + 1))
    echo "  PASS  POST /api/skills/install → $S (responded with JSON, real install attempt)"
else
    FAIL=$((FAIL + 1))
    FAILURES+=("POST /api/skills/install did not return JSON; HTTP $S body: ${B:0:100}")
    echo "  FAIL  POST /api/skills/install → $S (expected JSON response)"
fi

echo ""

# ── Phase 5: Config mutation ──────────────────────────────────────────────────

echo "-- Phase 5: Config mutation"

api PATCH /config \
    -H "Content-Type: application/json" \
    -d '{"path":"default_temperature","value":0.85}'
check "PATCH /api/config set default_temperature → 200" "200" "$S" "$B" '.success == true'

api PATCH /config \
    -H "Content-Type: application/json" \
    -d '{"path":"scheduler.enabled","value":true}'
check "PATCH /api/config set scheduler.enabled → 200" "200" "$S" "$B" '.success == true'

api DELETE /config \
    -H "Content-Type: application/json" \
    -d '{"path":"scheduler.enabled"}'
check "DELETE /api/config unset scheduler.enabled → 200" "200" "$S" "$B" '.success == true'

api PATCH /config \
    -H "Content-Type: application/json" \
    -d '{"path":"nonexistent.key","value":"foo"}'
check "PATCH /api/config disallowed path → 422" "422" "$S" "$B" '.success == false'

# POST /api/config/validate body is a bare config JSON object (same schema as config.json).
# Use a known-good inline config rather than the (potentially mutated) disk file.
api POST /config/validate \
    -H "Content-Type: application/json" \
    -d '{"agents":{"defaults":{"model":{"primary":"openai/gpt-4o"}}}}'
check "POST /api/config/validate valid config → 200" "200" "$S" "$B" '.success == true'

api POST /config/validate \
    -H "Content-Type: application/json" \
    -d '{"agents":{"defaults":{"model":{"primary":""}}}}'
check "POST /api/config/validate invalid config → 422" "422" "$S" "$B" '.success == false'

api POST /config/reload
check "POST /api/config/reload → 200" "200" "$S" "$B" '.success == true'

echo ""

# ── Phase 6: MCP server management ───────────────────────────────────────────

echo "-- Phase 6: MCP server management"

api GET /mcp
check "GET /api/mcp → 200" "200" "$S" "$B" '.success == true'
check "GET /api/mcp returns array" "200" "$S" "$B" '.data | type == "array"'
check "GET /api/mcp lists context7" "200" "$S" "$B" '.data[0].name == "context7"'
check "GET /api/mcp has transport field" "200" "$S" "$B" '.data[0].transport == "stdio"'
check "GET /api/mcp has command field" "200" "$S" "$B" '.data[0].command == "npx"'
check "GET /api/mcp has args_count" "200" "$S" "$B" '.data[0].args_count == 2'
check "GET /api/mcp shows env key name" "200" "$S" "$B" '(.data[0].env_keys | contains(["OPENROUTER_API_KEY"]))'
check "GET /api/mcp does not expose env value" "200" "$S" "$B" '(.data | tostring | contains("e2e-fake-api-key")) == false'

api GET /mcp/context7
check "GET /api/mcp/:name → 200" "200" "$S" "$B" '.success == true'
check "GET /api/mcp/:name has args array" "200" "$S" "$B" '(.data.args | type) == "array"'
check "GET /api/mcp/:name args includes -y" "200" "$S" "$B" '.data.args | contains(["-y"])'

api GET /mcp/nonexistent
check "GET /api/mcp/nonexistent → 404" "404" "$S" "$B" '.error.code == "MCP_NOT_FOUND"'

echo ""

# ── Phase 7: Agent control ────────────────────────────────────────────────────

echo "-- Phase 7: Agent control"

# POST /api/agent — one-shot invocation (real LLM call; uses api_agent for 90s timeout)
api_agent POST /agent \
    -H "Content-Type: application/json" \
    -d '{"message":"Reply with exactly the word: pong","session":"api:e2e-test"}'
check "POST /api/agent → 200" "200" "$S" "$B" '.success == true'
check "POST /api/agent has response field" "200" "$S" "$B" '(.data.response | type) == "string"'
check "POST /api/agent has session field" "200" "$S" "$B" '.data.session == "api:e2e-test"'
check "POST /api/agent has turn_count field" "200" "$S" "$B" '(.data.turn_count | type) == "number"'

# POST /api/agent — second turn (turn count increments)
api_agent POST /agent \
    -H "Content-Type: application/json" \
    -d '{"message":"Reply with exactly the word: ping","session":"api:e2e-test"}'
check "POST /api/agent second turn → 200" "200" "$S" "$B" '.success == true'
check "POST /api/agent second turn has session field" "200" "$S" "$B" '.data.session == "api:e2e-test"'

# POST /api/agent — missing message → 400 (no LLM call needed)
api POST /agent \
    -H "Content-Type: application/json" \
    -d '{"session":"api:e2e-test"}'
check "POST /api/agent missing message → 400" "400" "$S" "$B" '.error.code == "BAD_REQUEST"'

# POST /api/agent — empty message → 400 (no LLM call needed)
api POST /agent \
    -H "Content-Type: application/json" \
    -d '{"message":"","session":"api:e2e-test"}'
check "POST /api/agent empty message → 400" "400" "$S" "$B" '.error.code == "BAD_REQUEST"'

# POST /api/agent/stream → 501 (SSE not yet supported)
api POST /agent/stream \
    -H "Content-Type: application/json" \
    -d '{"message":"hello"}'
check "POST /api/agent/stream → 501" "501" "$S" "$B" '.error.code == "NOT_IMPLEMENTED"'

# GET /api/agent/sessions — should list the session created above
api GET /agent/sessions
check "GET /api/agent/sessions → 200" "200" "$S" "$B" '.success == true'
check "GET /api/agent/sessions has sessions array" "200" "$S" "$B" '(.data.sessions | type) == "array"'
check "GET /api/agent/sessions has total field" "200" "$S" "$B" '(.data.total | type) == "number"'
check "GET /api/agent/sessions lists e2e session" "200" "$S" "$B" '[.data.sessions[] | select(.session_key == "api:e2e-test")] | length > 0'

# DELETE /api/agent/sessions/:id — terminate the session we just created
# ':' must be percent-encoded as %3A in the URL path segment.
api DELETE /agent/sessions/api%3Ae2e-test
check "DELETE /api/agent/sessions/:id → 200" "200" "$S" "$B" '.success == true'
check "DELETE /api/agent/sessions/:id terminated=true" "200" "$S" "$B" '.data.terminated == true'
check "DELETE /api/agent/sessions/:id returns session_key" "200" "$S" "$B" '.data.session_key == "api:e2e-test"'

# DELETE again — should return 404
api DELETE /agent/sessions/api%3Ae2e-test
check "DELETE /api/agent/sessions/:id non-existent → 404" "404" "$S" "$B" '.error.code == "SESSION_NOT_FOUND"'

echo ""

# ── Phase 3: Memory ───────────────────────────────────────────────────────────

echo "-- Phase 3: Memory"

# GET /api/memory — list all entries (sqlite backend; may be empty or have bootstrap entries)
api GET /memory
check "GET /api/memory → 200" "200" "$S" "$B" '.success == true'
check "GET /api/memory has entries array" "200" "$S" "$B" '(.data.entries | type) == "array"'
check "GET /api/memory has total field" "200" "$S" "$B" '(.data.total | type) == "number"'
check "GET /api/memory has backend field" "200" "$S" "$B" '(.data.backend | type) == "string"'

# GET /api/memory?include_internal=true — include internal keys
api GET '/memory?include_internal=true'
check "GET /api/memory?include_internal=true → 200" "200" "$S" "$B" '.success == true'
check "GET /api/memory?include_internal=true has entries" "200" "$S" "$B" '(.data.entries | type) == "array"'

# GET /api/memory?category=core — filter by category
api GET '/memory?category=core'
check "GET /api/memory?category=core → 200" "200" "$S" "$B" '.success == true'
check "GET /api/memory?category=core all entries are core" "200" "$S" "$B" \
    '[.data.entries[] | select(.category != "core")] | length == 0'

# GET /api/memory?q=hello — keyword search (FTS; sqlite backend)
api GET '/memory?q=hello'
check "GET /api/memory?q=hello → 200" "200" "$S" "$B" '.success == true'
check "GET /api/memory?q=hello has entries" "200" "$S" "$B" '(.data.entries | type) == "array"'

# DELETE /api/memory/:key — delete a key that definitely does not exist
api DELETE '/memory/e2e-nonexistent-key-12345'
check "DELETE /api/memory/nonexistent → 404" "404" "$S" "$B" '.error.code == "NOT_FOUND"'

echo ""

# ── Results ───────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo "========================================"
echo "Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "========================================"

if [ ${#FAILURES[@]} -gt 0 ]; then
    echo ""
    echo "Failures:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    echo ""
    exit 1
fi

exit 0
