#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Live red-team integrity demo: a real prompt goes to the sidecar in front of
# the ALREADY-RUNNING live M4 mesh-llm node; the node serves it; the sidecar
# seals a real signed, chained AAC capsule for that exchange; the capsule is
# handed back to whoever received the reply. We then verify that capsule
# OFFLINE (no live access to the node/sidecar/rig -- record bytes only).
#
# ONE toggle switches between the two runs this demo exists to show:
#
#   Run A (honest):  ./scripts/redteam_live_demo.sh
#   Run B (liar):    ./scripts/redteam_live_demo.sh --tamper
#                     (or: CAPSULE_DEMO_LIAR=1 ./scripts/redteam_live_demo.sh)
#
# In liar mode, AFTER the capsule is sealed, this script itself acts as a
# malicious relay: it flips ONE field (the served quantization claim) in the
# capsule that gets handed back -- WITHOUT a valid re-signature -- and prints
# exactly what it changed. Offline verify then catches it and prints RED,
# naming the check that failed.
#
# *** What this proves, and what it does NOT prove -- read before presenting ***
# This demonstrates a MALICIOUS-RELAY / IN-TRANSIT TAMPER attack on the
# capsule: something between the seal and the verifier edited a claim without
# re-signing, and capsule_id (a digest over every field) catches it. It does
# NOT demonstrate catching a node that lies CONSISTENTLY about its own
# quant/hardware at seal time (docs/REDTEAM-RUNG2.md, attacks 5/6/7) -- that
# is a documented, uncaught-by-design residual: the config claim is
# self-reported by the same party that seals it, so a consistent self-lie
# reconciles clean. See DEMO-REDTEAM.md's honesty box for the full statement.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- toggle -------------------------------------------------------------
LIAR="${CAPSULE_DEMO_LIAR:-0}"
for arg in "$@"; do
  case "$arg" in
    --tamper|--liar) LIAR=1 ;;
    --honest) LIAR=0 ;;
    *) echo "unknown argument: $arg (expected --tamper or nothing)" >&2; exit 2 ;;
  esac
done

# --- fixed environment (the live M4 node this demo targets) -------------
NODE_BASE="http://127.0.0.1:9338"
SIDECAR_PORT="${SIDECAR_PORT:-8099}"
SIDECAR_BASE="http://127.0.0.1:${SIDECAR_PORT}"
LEDGER_DIR="$ROOT/ledger-redteam-live"
GGUF_PATH="${GGUF_PATH:-/Users/intangible/Llama-3.2-3B.gguf}"
RUNTIME_ARTIFACT="${RUNTIME_ARTIFACT:-/Users/intangible/dev/asg/_worktrees/mesh-llm/mesh-serving-provenance/target/release/mesh-llm}"
MODEL_ID_LABEL="bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M"
PROMPT="In one short sentence, what is the capital of France?"

SIDECAR_PID=""
cleanup() {
  if [[ -n "$SIDECAR_PID" ]] && kill -0 "$SIDECAR_PID" 2>/dev/null; then
    echo "--- cleanup: stopping sidecar (pid $SIDECAR_PID) ---"
    kill "$SIDECAR_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "$LIAR" == "1" ]]; then
  echo "############################################################"
  echo "# RUN B -- LIAR MODE (CAPSULE_DEMO_LIAR=1 / --tamper)"
  echo "# A malicious relay will flip the quant claim on the shared"
  echo "# capsule AFTER sealing, without re-signing. Expect RED."
  echo "############################################################"
else
  echo "############################################################"
  echo "# RUN A -- HONEST MODE"
  echo "# No tamper. Expect GREEN."
  echo "############################################################"
fi

echo "--- [1/7] confirm the live M4 node is up (${NODE_BASE}) ---"
if ! curl -s -m 5 "${NODE_BASE}/v1/models" -o /tmp/redteam-live-models.json; then
  echo "FATAL: live node not reachable at ${NODE_BASE}. Is 'mesh-llm serve' running?" >&2
  exit 1
fi
python3 -c "
import json
data = json.load(open('/tmp/redteam-live-models.json'))
ids = [m['id'] for m in data['data']]
print('live node models:', ids)
"

echo "--- [2/7] rebuild model-package.live.json from the real, currently-served GGUF ---"
if [[ ! -f "$GGUF_PATH" ]]; then
  echo "FATAL: GGUF_PATH=$GGUF_PATH not found. Pass GGUF_PATH=<path> matching the node's --gguf." >&2
  exit 1
fi
python3 build_real_model_package.py "$GGUF_PATH" "$MODEL_ID_LABEL"

echo "--- [3/7] fresh ledger dir + start sidecar in front of the live node ---"
rm -rf "$LEDGER_DIR"
mkdir -p "$LEDGER_DIR"
python3 capsule_sidecar.py \
  --upstream "$NODE_BASE" \
  --listen-port "$SIDECAR_PORT" \
  --ledger-dir "$LEDGER_DIR" \
  --manifest model-package/model-package.live.json \
  --runtime-artifact "$RUNTIME_ARTIFACT" \
  --runtime-label "mesh-llm real M4 node (Llama-3.2-3B Q4_K_M, redteam live demo)" \
  > /tmp/redteam-sidecar.log 2>&1 &
SIDECAR_PID=$!
for _ in $(seq 1 20); do
  curl -s -m 2 "${SIDECAR_BASE}/v1/models" -o /dev/null && break
  sleep 1
done
curl -s -m 2 "${SIDECAR_BASE}/v1/models" -o /dev/null || {
  echo "FATAL: sidecar did not come up. See /tmp/redteam-sidecar.log" >&2
  cat /tmp/redteam-sidecar.log >&2
  exit 1
}

# pick a real served GGUF model id (quantized, not the synthetic test models)
SERVE_MODEL_ID="$(python3 -c "
import json
data = json.load(open('/tmp/redteam-live-models.json'))
candidates = [m['id'] for m in data['data'] if m.get('metadata', {}).get('quant')]
print(candidates[0] if candidates else '')
")"
if [[ -z "$SERVE_MODEL_ID" ]]; then
  echo "FATAL: no quantized local-gguf model advertised by the live node." >&2
  exit 1
fi
echo "serving model for this exchange: $SERVE_MODEL_ID"

echo "--- [4/7] send ONE real prompt through the sidecar to the live node ---"
echo "prompt: ${PROMPT}"
SERVE_MODEL_ID="$SERVE_MODEL_ID" PROMPT="$PROMPT" python3 -c "
import json, os
body = {
    'model': os.environ['SERVE_MODEL_ID'],
    'messages': [{'role': 'user', 'content': os.environ['PROMPT']}],
    'max_tokens': 32,
    'temperature': 0,
}
json.dump(body, open('/tmp/redteam-request-body.json', 'w'))
"
curl -s -m 60 -D /tmp/redteam-reply-headers.txt -X POST "${SIDECAR_BASE}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  --data @/tmp/redteam-request-body.json \
  -o /tmp/redteam-reply-body.json
REPLY_TEXT="$(python3 -c "
import json
body = json.load(open('/tmp/redteam-reply-body.json'))
print(body['choices'][0]['message']['content'])
")"
CAPSULE_ID="$(grep -i '^X-Capsule-Id:' /tmp/redteam-reply-headers.txt | tr -d '\r' | awk '{print $2}')"
echo "reply text : ${REPLY_TEXT}"
echo "capsule_id : ${CAPSULE_ID}"
if [[ -z "$CAPSULE_ID" ]]; then
  echo "FATAL: sidecar reply carried no X-Capsule-Id header." >&2
  exit 1
fi

echo "--- [5/7] fetch the sealed capsule handed back with that reply ---"
python3 - "$LEDGER_DIR/capsules.jsonl" "$CAPSULE_ID" <<'PYEOF' > /tmp/redteam-honest-capsule.json
import json, sys
path, capsule_id = sys.argv[1], sys.argv[2]
for line in open(path):
    rec = json.loads(line)
    if rec["capsule_id"] == capsule_id:
        print(json.dumps(rec, sort_keys=True))
        break
else:
    raise SystemExit(f"capsule {capsule_id} not found in {path}")
PYEOF
python3 -c "
import json
rec = json.load(open('/tmp/redteam-honest-capsule.json'))
poc = rec['model_attestation']['compute_attestation']['x-mesh-poc-v1']
prov = poc['serving_provenance']
print('capsule claims as sealed:')
print('  model         :', rec['model_attestation']['model_id'])
print('  quant claim   :', prov.get('quantization'))
print('  model_canonical_ref:', prov.get('model_canonical_ref'))
print('  hardware      : gpu=%r vram_bytes=%r hostname=%r (null = not populated on this node build, not hidden)' % (
    poc.get('hardware', {}).get('gpu') if 'hardware' in poc else None, None, None))
print('  served_by     :', prov.get('served_by_node_id'))
print('  timestamp     :', rec['timestamp'])
print('  capsule_id    :', rec['capsule_id'])
"

if [[ "$LIAR" == "1" ]]; then
  echo "--- [6/7] LIAR MODE: malicious relay tampers the shared capsule (no re-sign) ---"
  python3 "$ROOT/scripts/_redteam_tamper_capsule.py" "$LEDGER_DIR/capsules.jsonl" "$CAPSULE_ID"
else
  echo "--- [6/7] honest mode: nothing tampered ---"
fi

echo "--- [7/7] stop the sidecar, then verify OFFLINE (record bytes only, no live access) ---"
kill "$SIDECAR_PID" 2>/dev/null || true
wait "$SIDECAR_PID" 2>/dev/null || true
SIDECAR_PID=""

set +e
python3 stranger_verify_bundle.py "$LEDGER_DIR" --issuer-key keys/node-key.pub.pem
VERIFY_STATUS=$?
set -e

echo
if [[ $VERIFY_STATUS -eq 0 ]]; then
  echo "================================================================"
  echo " GREEN -- verified. Sealed record is intact, capsule_id checks out."
  echo "================================================================"
else
  echo "================================================================"
  echo " RED -- verify FAILED. capsule_id no longer matches the record"
  echo " bytes -- the field flipped above broke it. This is exactly the"
  echo " integrity property this demo shows: any edited field, however"
  echo " small, breaks the seal."
  echo "================================================================"
fi

cat <<'EOF'

--- What this proves / what it does NOT prove -----------------------------
PROVES:  a malicious relay (or anyone else) editing a field of an already-
         sealed capsule, without the node's private key, is caught -- the
         capsule_id is a digest over every field, and offline verify
         recomputes it from the bytes alone.
DOES NOT PROVE: that a node cannot lie about its own quant/hardware at seal
         time. If the node itself reports the same (false) quant/hardware
         consistently in the capsule it signs, that signed lie verifies
         CLEAN -- this is a documented, uncaught-by-design residual
         (docs/REDTEAM-RUNG2.md, attacks 5/6/7), not something this script
         (or this rung) claims to catch.
-----------------------------------------------------------------------------
EOF

exit $VERIFY_STATUS
