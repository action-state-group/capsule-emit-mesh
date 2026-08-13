#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live demo: real mesh-llm node + real goose + two chained capsule streams.
#
# One Goose task run against a real local mesh-llm node, producing:
#   1. ledger-live/capsules.jsonl       -- inference receipts (capsule_sidecar.py,
#                                          the /v1 serve boundary, issue #1233's tuple)
#   2. ledger-live/goose-actions.jsonl  -- action records (goose/server.py,
#                                          the tool-call boundary, capsule-emit-goose)
#
# Prerequisites (see README.md "Live demo" section):
#   - mesh-llm binary (this repo ships a checksummed copy under ../bin/mesh-bundle/,
#     or use your own `mesh-llm` on PATH)
#   - goose CLI installed (brew install block/goose/goose)
#   - a local GGUF model downloaded: mesh-llm download <model-name>
#   - pip install "capsule-emit[mcp]" agent-action-capsule scitt-cose mcp
#
# Anchoring policy (Steven's decision, 2026-08-11): rehearsal runs stay
# offline-verified only. Anchoring posts a real digest to the live, shared
# anchor.agentactioncapsule.org transparency log -- it happens exactly ONCE,
# deliberately, on the actual take used live on the call. This script
# defaults CAPSULE_ANCHOR=false; pass "anchor" as the 4th argument ONLY for
# that one final call-take run, never for a rehearsal.
#
# Usage:
#   ./run_live_demo.sh <mesh-llm-binary> <gguf-blob-path> <model-id> [anchor]
#
# Example (paths from this repo's own rehearsal, see README):
#   ./run_live_demo.sh ../bin/mesh-bundle/mesh-llm \
#     ~/Library/Caches/huggingface/hub/models--bartowski--Hermes-2-Pro-Mistral-7B-GGUF/blobs/<sha256> \
#     bartowski/Hermes-2-Pro-Mistral-7B-GGUF:Q4_K_M
set -euo pipefail

MESH_LLM_BIN="${1:?usage: run_live_demo.sh <mesh-llm-binary> <gguf-blob-path> <model-id> [anchor]}"
GGUF_PATH="${2:?missing gguf-blob-path}"
MODEL_ID="${3:?missing model-id}"
CAPSULE_ANCHOR="false"
if [[ "${4:-}" == "anchor" ]]; then
  CAPSULE_ANCHOR="true"
  echo "!!! ANCHOR MODE: this run's capsules WILL be posted to the live production transparency log. !!!"
  echo "!!! Only use this for the final call-take run, never for a rehearsal.                          !!!"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SERVE_PORT=9337
SIDECAR_PORT=8089
LEDGER_DIR="$ROOT/ledger-live"

cleanup() {
  echo "--- cleanup: stopping mesh-llm serve + sidecar ---"
  [[ -n "${SIDECAR_PID:-}" ]] && kill "$SIDECAR_PID" 2>/dev/null || true
  [[ -n "${SERVE_PID:-}" ]] && kill "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$LEDGER_DIR"
mkdir -p "$LEDGER_DIR"

echo "--- [1/6] building real model-package.json from the actual GGUF ---"
python3 build_real_model_package.py "$GGUF_PATH" "$MODEL_ID"

echo "--- [2/6] starting real mesh-llm serve --local-model-only (port $SERVE_PORT) ---"
"$MESH_LLM_BIN" serve --local-model-only --gguf "$GGUF_PATH" --port "$SERVE_PORT" &
SERVE_PID=$!
for _ in $(seq 1 40); do
  curl -s -m 2 "http://127.0.0.1:$SERVE_PORT/v1/models" | grep -q "$MODEL_ID" && break
  sleep 3
done
curl -s -m 2 "http://127.0.0.1:$SERVE_PORT/v1/models" | grep -q "$MODEL_ID" || {
  echo "mesh-llm did not come up serving $MODEL_ID" >&2
  exit 1
}

echo "--- [3/6] starting capsule_sidecar.py (port $SIDECAR_PORT -> $SERVE_PORT) ---"
python3 capsule_sidecar.py \
  --upstream "http://127.0.0.1:$SERVE_PORT" \
  --listen-port "$SIDECAR_PORT" \
  --ledger-dir "$LEDGER_DIR" \
  --manifest model-package/model-package.live.json \
  --runtime-artifact "$MESH_LLM_BIN" \
  --runtime-label "mesh-llm real local node ($MODEL_ID, --local-model-only)" &
SIDECAR_PID=$!
for _ in $(seq 1 20); do
  curl -s -m 2 "http://127.0.0.1:$SIDECAR_PORT/v1/models" | grep -q "$MODEL_ID" && break
  sleep 1
done

echo "--- [4/6] running the real 'mesh-llm goose' workflow against the sidecar ---"
echo "    (writes ~/.config/goose/custom_providers/mesh.json with base_url -> sidecar;"
echo "     interactive session is not needed for a scripted demo, so it's ended once"
echo "     the provider config is written -- see README 'Why we don't stay attached')"
(printf '' | "$MESH_LLM_BIN" goose --port "$SIDECAR_PORT" --model "$MODEL_ID" > /tmp/mesh-goose-wire.log 2>&1 || true) &
WIRE_PID=$!
for _ in $(seq 1 20); do
  grep -q "Wrote.*mesh.json" /tmp/mesh-goose-wire.log 2>/dev/null && break
  sleep 1
done
kill "$WIRE_PID" 2>/dev/null || true
pkill -f "goose session" 2>/dev/null || true
cat /tmp/mesh-goose-wire.log

echo "--- [5/6] running the real, scripted Goose task (goose run --provider mesh) ---"
GOOSE_PROVIDER=mesh GOOSE_MODEL="$MODEL_ID" \
goose run --no-session --no-profile --max-turns 8 --stats \
  --with-extension "CAPSULE_LEDGER=$LEDGER_DIR/goose-actions.jsonl CAPSULE_OPERATOR=capsule-emit-mesh-poc-demo CAPSULE_DEVELOPER=goose@v1.39.0+mesh-llm CAPSULE_ANCHOR=$CAPSULE_ANCHOR CAPSULE_MODEL_ID=$MODEL_ID python3 $ROOT/goose/server.py" \
  -t "Call the get_node_status tool now with node_id=mesh-node-demo-1. After you receive its result, call the submit_capacity_request tool now with node_id=mesh-node-demo-1, gpu_hours=4, reason=inference_demand_spike. You must call both tools before writing any summary text." \
  | tee "$LEDGER_DIR/goose-session-transcript.txt"

echo "--- [6/6] verifying both capsule streams ---"
echo
echo "== inference receipts (sidecar, /v1 boundary) =="
agent-action-capsule verify --store "$LEDGER_DIR/capsules.jsonl"
echo
echo "== action records (capsule-emit-goose, tool-call boundary) =="
agent-action-capsule verify --store "$LEDGER_DIR/goose-actions.jsonl"

echo
echo "Done. Ledgers:"
echo "  $LEDGER_DIR/capsules.jsonl"
echo "  $LEDGER_DIR/goose-actions.jsonl"
echo "Build permalinks with:"
echo "  capsule-emit permalink --ledger $LEDGER_DIR/capsules.jsonl --bundle --check"
echo "  capsule-emit permalink --ledger $LEDGER_DIR/goose-actions.jsonl --bundle --check"
if [[ "$CAPSULE_ANCHOR" == "true" ]]; then
  echo
  echo "ANCHOR MODE was on: goose-actions.jsonl capsules were anchored inline."
  echo "The sidecar itself never auto-anchors -- anchor capsules.jsonl explicitly, per id:"
  echo "  agent-action-capsule anchor submit <capsule_id>"
else
  echo
  echo "Anchoring: OFF (default -- rehearsal run). Nothing here was posted to"
  echo "anchor.agentactioncapsule.org. Re-run with 'anchor' as the 4th arg ONLY"
  echo "for the final call-take run."
fi
