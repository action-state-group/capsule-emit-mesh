#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real end-to-end: real mesh-llm-host-runtime inference -> capsule_sidecar.py
# (Layer 0) -> local CLL/MMR + signed checkpoint (Layers 1-2, checkpointing.py
# over capsule_emit.checkpoint) -> offline verify.
#
# Unlike run_checkpoint_demo.py (mock_mesh_node.py, synthetic capsules), this
# drives the SAME checkpoint machinery against a REAL, locally-running
# mesh-llm serve process and a REAL downloaded GGUF model -- closing the gap
# flagged in [mesh-llm-deployment-checkpoint-e2e]: the standalone checkpoint
# demo was never driven by an actual mesh-llm deployment run.
#
# No goose / tool-call leg here on purpose -- this item is about the
# inference-receipt (Layer 0) stream feeding the CLL, not the separate
# action-record stream (that's capsule-emit-goose's own boundary).
#
# Anchoring: OFF by default, same posture as run_live_demo.sh -- the sidecar
# config's ts_urls stays empty for this run (local chain only, self-
# checkpointed). verify_real_deployment_checkpoint.py prints the exact staged
# command for live registration; it does not execute it. See that script's
# docstring and this repo's outbox report for why.
#
# Usage:
#   ./run_real_deployment_checkpoint_demo.sh <mesh-llm-binary> <gguf-path> <model-id>
set -euo pipefail

MESH_LLM_BIN="${1:?usage: run_real_deployment_checkpoint_demo.sh <mesh-llm-binary> <gguf-path> <model-id>}"
GGUF_PATH="${2:?missing gguf-path}"
MODEL_ID="${3:?missing model-id}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SERVE_PORT=9341
SIDECAR_PORT=8093
LEDGER_DIR="$ROOT/ledger-real-deployment"

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

echo "--- [2/6] starting real mesh-llm serve (real mesh-llm-host-runtime, port $SERVE_PORT) ---"
"$MESH_LLM_BIN" serve --local-model-only --model "$GGUF_PATH" --port "$SERVE_PORT" &
SERVE_PID=$!
for _ in $(seq 1 60); do
  curl -s -m 2 "http://127.0.0.1:$SERVE_PORT/v1/models" | grep -q "$MODEL_ID" && break
  sleep 3
done
curl -s -m 2 "http://127.0.0.1:$SERVE_PORT/v1/models" | grep -q "$MODEL_ID" || {
  echo "mesh-llm did not come up serving $MODEL_ID" >&2
  exit 1
}
echo "real mesh-llm-host-runtime is up: $("$MESH_LLM_BIN" --version)"

echo "--- [3/6] writing checkpoint config (cadence_entries=2, ts_urls empty -- local chain only) ---"
cat > "$LEDGER_DIR/checkpoint-config.toml" <<EOF
[checkpoint]
log_id = "mesh-real-deployment-demo-1"
cadence_entries = 2
max_lag_entries = 10
# ts_urls left empty deliberately -- see this script's header + outbox report
EOF

echo "--- [4/6] starting capsule_sidecar.py (port $SIDECAR_PORT -> $SERVE_PORT), checkpointing ON ---"
python3 capsule_sidecar.py \
  --upstream "http://127.0.0.1:$SERVE_PORT" \
  --listen-port "$SIDECAR_PORT" \
  --ledger-dir "$LEDGER_DIR" \
  --manifest model-package/model-package.live.json \
  --runtime-artifact "$MESH_LLM_BIN" \
  --runtime-label "mesh-llm-host-runtime real node ($MODEL_ID, local-model-only)" \
  --checkpoint-config "$LEDGER_DIR/checkpoint-config.toml" &
SIDECAR_PID=$!
for _ in $(seq 1 20); do
  curl -s -m 2 "http://127.0.0.1:$SIDECAR_PORT/v1/models" | grep -q "$MODEL_ID" && break
  sleep 1
done

echo "--- [5/6] sending real chat-completion requests through the sidecar (real inference) ---"
PROMPTS=(
  "What is the capital of France? Answer in one word."
  "Name one prime number between 10 and 20."
  "Write a one-line haiku fragment about a Merkle tree."
  "What does MMR stand for in a transparency log? Answer briefly."
)
i=0
for prompt in "${PROMPTS[@]}"; do
  i=$((i + 1))
  body=$(python3 -c "import json,sys; print(json.dumps({'model': sys.argv[1], 'messages': [{'role':'user','content': sys.argv[2]}], 'temperature': 0.2, 'max_tokens': 32, 'seed': $i}))" "$MODEL_ID" "$prompt")
  echo "  [$i/${#PROMPTS[@]}] $prompt"
  curl -s -m 60 -X POST "http://127.0.0.1:$SIDECAR_PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Capsule-Client-Nonce: real-deployment-demo-nonce-$(printf '%04d' "$i")" \
    -d "$body" > "$LEDGER_DIR/response-$i.json" || echo "    (request $i returned non-2xx, capsule still recorded per sidecar honesty posture)"
done

echo "--- [6/6] stopping mesh-llm serve + sidecar, then verifying ---"
kill "$SIDECAR_PID" 2>/dev/null || true
kill "$SERVE_PID" 2>/dev/null || true
wait "$SIDECAR_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
unset SIDECAR_PID SERVE_PID

echo
echo "== capsules ledger =="
wc -l "$LEDGER_DIR/capsules.jsonl"
echo "== checkpoints ledger =="
wc -l "$LEDGER_DIR/checkpoints.jsonl" 2>/dev/null || echo "(no checkpoints.jsonl -- cadence not reached?)"

echo
echo "--- running offline verify + rollback-mutant proof (third-party posture: ledger dir only) ---"
python3 verify_real_deployment_checkpoint.py "$LEDGER_DIR"
