#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT_DIR"

mkdir -p examples/edge/cloudflare-worker/dist

zig build-exe examples/edge/cloudflare-worker/agent_core.zig \
  -target wasm32-freestanding \
  -fno-entry \
  -rdynamic \
  -O ReleaseSmall \
  -femit-bin=examples/edge/cloudflare-worker/dist/agent_core.wasm

echo "Built examples/edge/cloudflare-worker/dist/agent_core.wasm"
