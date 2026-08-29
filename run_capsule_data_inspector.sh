#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One-command "seal a real capsule and pretty-print EVERY input field" run,
# for a SINGLE real `mesh-llm serve` host + the real `admission-policy`
# plugin. [mesh-capsule-data-inspector-onemac]
#
# Answers, on ONE Mac, with real bytes: "on whose hardware, which model, over
# which bytes." Does five things, in order:
#   1. Checks out and builds the branch-paired real host (`feat/serving-
#      provenance`, stacked on `mesh1331-lifecycle-hooks`) + the real
#      `admission-policy-plugin` (this repo, which already carries
#      `feat/serving-provenance-capture` -- merged to main via #35).
#   2. Starts that real host + plugin, real Metal GPU, on the SAME ports as
#      this repo's own Demo 4 / 2-role runbooks (19337 / console 13131) --
#      reconciled against `_work/two-mac-crossverify-runbook.md` and
#      `_work/mesh-2role-live-adversarial-runbook.md`, both of which use
#      19337 consistently; it was not stale.
#   3. Sends a silent warm-up request, THEN the ONE request you're inspecting
#      (see "why a warm-up" below -- required, not padding).
#   4. Seals a capsule (automatic, inside the plugin's own HTTP handler).
#   5. Checkpoints the plugin's ledger (self-checkpointed, no network by
#      default) and pretty-prints, labeled, every field that fed the capsule
#      via `capsule_field_inspector.py` -- FAILING LOUDLY instead of
#      silently printing nulls if the host isn't reporting real hardware
#      provenance.
#
# Why a warm-up request, when the task asks for "send ONE request": verified
# directly (2026-08-29, this machine) -- the host's `serving_provenance`
# block for an exchange is delivered to the plugin over an async mesh
# channel broadcast, AFTER the plugin has already sealed that SAME
# exchange's capsule (fire-and-forget on the host side; capture is
# correlated by MODEL, not exchange id -- see capsule.rs's ServingProvenance
# doc comment). So the very FIRST request to a model on a freshly-started
# host ALWAYS seals with null hardware fields, real host or not. A silent
# warm-up (discarded) request lets the host publish once before the request
# you actually want inspected -- the ONE labeled, pretty-printed exchange is
# still exactly one real chat completion. Reproduced as a mutant proof: the
# SAME warm-up-then-inspect sequence against a host WITHOUT the
# serving-provenance patch still shows all-null hardware fields, which is
# what `capsule_field_inspector.py`'s fail-loud check is for.
#
# Prerequisites:
#   - a clone of StevenMih/mesh-llm with `fork` (or `origin`) pointing at
#     https://github.com/StevenMih/mesh-llm, so `feat/serving-provenance` is
#     fetchable. Point MESH_LLM_DIR at it.
#   - Rust toolchain (cargo) for both the mesh-llm host and this repo's
#     admission-policy-plugin.
#   - python3 + `pip install -r requirements.txt` (this repo) for the
#     checkpoint step + the pretty-printer.
#   - openssl (ships with macOS) -- see "key format workaround" below.
#
# Usage:
#   ./run_capsule_data_inspector.sh --mesh-llm-dir <path-to-mesh-llm-checkout> \
#       [--model <model-name>] [--port 19337] [--console-port 13131] \
#       [--skip-build] [--python <path-to-python3>]
#
# `--model` defaults to `allowed-test-model`, the PROVEN synthetic name this
# repo's own runbooks use (real hostname/GPU/VRAM/node-id populate for it;
# quantization/model.* stay honestly null -- there's no loaded GGUF behind
# it). Pass a real model name only if it is ALSO registered as a served
# model on the mesh-llm host by that exact name (so `node.served_model_
# descriptors()` can resolve it) -- untested by this script; if the request
# never reaches the plugin at all (no `admission_policy` key in the
# response), that's a routing/naming collision on the mesh-llm side, not a
# bug in this script, and this script will say so rather than hang.
set -euo pipefail

MESH_LLM_DIR=""
MODEL="allowed-test-model"
PORT=19337
CONSOLE_PORT=13131
SKIP_BUILD=0
PYTHON_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mesh-llm-dir) MESH_LLM_DIR="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --console-port) CONSOLE_PORT="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --python) PYTHON_BIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$MESH_LLM_DIR" ]]; then
  echo "FAIL: --mesh-llm-dir is required (a clone of StevenMih/mesh-llm, or a" >&2
  echo "  remote/fork pointing at it, checked out somewhere on disk)." >&2
  exit 1
fi
if [[ "$MODEL" == blocked-* ]]; then
  echo "FAIL: --model '$MODEL' starts with 'blocked-' -- the admission policy" >&2
  echo "  denies it by design (decision.rs::BLOCKED_MODEL_PREFIX); pick a" >&2
  echo "  different name so the exchange is ALLOWED and sealed." >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_BIN="$REPO_DIR/plugins/admission-policy/target/debug/admission-policy-plugin"

echo "== [1/5] branch-pairing: mesh-llm feat/serving-provenance + capsule-emit-mesh (this checkout) =="

# --- mesh-llm side: pin the exact branch that emits serving_provenance ---
cd "$MESH_LLM_DIR"
REMOTE=""
for candidate in fork origin; do
  if git remote get-url "$candidate" 2>/dev/null | grep -qi "StevenMih/mesh-llm"; then
    REMOTE="$candidate"
    break
  fi
done
if [[ -z "$REMOTE" ]]; then
  echo "FAIL: no git remote in $MESH_LLM_DIR points at StevenMih/mesh-llm." >&2
  echo "  Add one: git remote add fork https://github.com/StevenMih/mesh-llm" >&2
  exit 1
fi
git fetch "$REMOTE" feat/serving-provenance
git checkout -B feat/serving-provenance "$REMOTE/feat/serving-provenance"
MESH_LLM_SHA="$(git rev-parse HEAD)"
echo "mesh-llm pinned: $REMOTE/feat/serving-provenance @ $MESH_LLM_SHA"

MESH_LLM_BIN="$MESH_LLM_DIR/target/debug/mesh-llm"
BUILD_MARKER="$MESH_LLM_DIR/target/debug/.mesh-llm-built-from"
if [[ "$SKIP_BUILD" -eq 1 && -x "$MESH_LLM_BIN" ]]; then
  echo "skipping mesh-llm build (--skip-build); using existing binary as-is"
elif [[ -x "$MESH_LLM_BIN" && -f "$BUILD_MARKER" && "$(cat "$BUILD_MARKER")" == "$MESH_LLM_SHA" ]]; then
  echo "mesh-llm binary already built from $MESH_LLM_SHA, skipping rebuild"
else
  echo "building mesh-llm (this can take a while the first time)..."
  cargo build -p mesh-llm --bin mesh-llm
  echo "$MESH_LLM_SHA" > "$BUILD_MARKER"
fi

# --- capsule-emit-mesh side: verify this checkout carries the capture code ---
cd "$REPO_DIR"
if ! grep -q "host_provenance" plugins/admission-policy/src/capsule_emit.rs 2>/dev/null; then
  echo "FAIL: this capsule-emit-mesh checkout does not carry the serving-" >&2
  echo "  provenance capture code (feat/serving-provenance-capture, merged" >&2
  echo "  via #35). Update this checkout to a commit on/after #35." >&2
  exit 1
fi
if [[ "$SKIP_BUILD" -eq 1 && -x "$PLUGIN_BIN" ]]; then
  echo "skipping admission-policy-plugin build (--skip-build)"
else
  echo "building admission-policy-plugin..."
  (cd plugins/admission-policy && cargo build --bin admission-policy-plugin)
fi

# A bare `python3` on this machine can resolve to a stale editable
# capsule-emit install left over from a prior scratch session (this repo's
# own 2-role runbook documents the same landmine: "if `pip show capsule-emit`
# doesn't say 0.5.1, you're pointed at a stale checkout"). Default to a
# dedicated, persistent venv for this script rather than trusting the
# caller's ambient python3.
if [[ -z "$PYTHON_BIN" ]]; then
  INSPECTOR_VENV="$HOME/.cache/capsule-data-inspector/venv"
  if [[ ! -x "$INSPECTOR_VENV/bin/python3" ]]; then
    echo "creating venv at $INSPECTOR_VENV..."
    mkdir -p "$(dirname "$INSPECTOR_VENV")"
    python3 -m venv "$INSPECTOR_VENV"
  fi
  "$INSPECTOR_VENV/bin/pip" install -q --upgrade pip
  "$INSPECTOR_VENV/bin/pip" install -q -r "$REPO_DIR/requirements.txt"
  PYTHON_BIN="$INSPECTOR_VENV/bin/python3"
fi
INSTALLED_VER="$("$PYTHON_BIN" -c "import importlib.metadata as m; print(m.version('capsule-emit'))")"
echo "using python: $PYTHON_BIN (capsule-emit $INSTALLED_VER)"

echo "== [2/5] starting real host (Metal GPU) + admission-policy plugin on :$PORT =="

RUN_DIR="$(mktemp -d /tmp/capsule-inspector-XXXXXX)"  # short path: plugin's unix socket has a ~104-byte sun_path limit
CONFIG="$RUN_DIR/config.toml"
cat > "$CONFIG" <<EOF
version = 1
[[plugin]]
name = "admission-policy"
enabled = true
command = "$PLUGIN_BIN"
args = []
EOF

HOME="$RUN_DIR" ADMISSION_POLICY_BLOCKED_MODELS="blocked-test-model,$MODEL" \
ADMISSION_POLICY_DATA_DIR="$RUN_DIR/capsule-data" \
  "$MESH_LLM_BIN" serve --config "$CONFIG" --port "$PORT" --console "$CONSOLE_PORT" \
    --headless --disable-iroh-relays --log-format json > "$RUN_DIR/run.log" 2>&1 &
HOST_PID=$!
cleanup() {
  # A plain SIGTERM was observed (2026-08-29) to leave the real host process
  # running past this script's own exit -- headless mode does not shut down
  # promptly on TERM alone. Give it a moment, then force it.
  kill "$HOST_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    kill -0 "$HOST_PID" 2>/dev/null || return 0
    sleep 0.3
  done
  kill -9 "$HOST_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "waiting for host to advertise '$MODEL'..."
deadline=$((SECONDS + 30))
until curl -s "http://127.0.0.1:$PORT/v1/models" 2>/dev/null | grep -q "$MODEL"; do
  if [[ $SECONDS -ge $deadline ]]; then
    echo "FAIL: host never advertised '$MODEL' within 30s. Log:" >&2
    tail -50 "$RUN_DIR/run.log" >&2
    exit 1
  fi
  sleep 0.5
done
echo "host up: $RUN_DIR (log: $RUN_DIR/run.log)"

echo "== [3/5] warm-up request (discarded) + the ONE inspected request =="

req_body() {
  local nonce="$1" text="$2"
  printf '{"model":"%s","messages":[{"role":"user","content":"%s"}],"client_nonce":"%s"}' \
    "$MODEL" "$text" "$nonce"
}

curl -s "http://127.0.0.1:$PORT/v1/chat/completions" -H 'content-type: application/json' \
  -d "$(req_body "capsule-data-inspector-warmup" "warm-up -- discarded, not the inspected exchange")" \
  -o "$RUN_DIR/warmup-response.json"
sleep 1.5  # let the host's async terminal-event broadcast land before the real request

NONCE="capsule-data-inspector-$(date +%s 2>/dev/null || echo run)"
curl -s "http://127.0.0.1:$PORT/v1/chat/completions" -H 'content-type: application/json' \
  -d "$(req_body "$NONCE" "one real chat completion for the capsule data inspector")" \
  -o "$RUN_DIR/response.json"

if ! "$PYTHON_BIN" -c "import json,sys; d=json.load(open('$RUN_DIR/response.json')); sys.exit(0 if 'admission_policy' in d else 1)"; then
  echo "FAIL: the response carries no 'admission_policy' key -- the request" >&2
  echo "  was never routed to the plugin at all (model-name routing/registration" >&2
  echo "  problem on the mesh-llm side, not this script). Raw response:" >&2
  cat "$RUN_DIR/response.json" >&2
  exit 1
fi
"$PYTHON_BIN" -c "
import json
d = json.load(open('$RUN_DIR/response.json'))
json.dump(d['admission_policy'], open('$RUN_DIR/admission_policy.json', 'w'))
"
echo "sealed. capsule_id=$("$PYTHON_BIN" -c "import json; print(json.load(open('$RUN_DIR/admission_policy.json'))['capsule_id'])")"

echo "== [4/5] checkpointing the plugin's ledger (self-checkpointed, no network) =="

# Key-format workaround: capsule-producer (Rust, ed25519-dalek's pkcs8
# encoder) writes node-key.pem as an RFC 5958 v2 OneAsymmetricKey with the
# public key embedded. Python's `cryptography` (as used by checkpointing.py)
# only accepts the plain v1/PKCS8 form and raises "ASN.1 parsing error: extra
# data" on the v2 form -- verified directly (2026-08-29), openssl parses the
# original fine, so this is a cryptography-library strictness gap, not a
# malformed key. Re-encoding through `openssl pkey` normalizes to v1/PKCS8
# (drops the optional embedded public key) without touching the key material.
NORM_KEYS="$RUN_DIR/keys-normalized"
mkdir -p "$NORM_KEYS"
openssl pkey -in "$RUN_DIR/capsule-data/keys/node-key.pem" -out "$NORM_KEYS/node-key.pem"
cp "$RUN_DIR/capsule-data/keys/node-key.pub.pem" "$NORM_KEYS/node-key.pub.pem"

CHECKPOINT_LOG="$RUN_DIR/checkpoint-status.txt"
"$PYTHON_BIN" "$REPO_DIR/checkpoint_ledger.py" \
  --ledger-dir "$RUN_DIR/capsule-data/ledger" --keys-dir "$NORM_KEYS" \
  --log-id capsule-data-inspector-onemac > "$CHECKPOINT_LOG" 2>&1 || {
    echo "FAIL: checkpoint_ledger.py failed:" >&2
    cat "$CHECKPOINT_LOG" >&2
    exit 1
  }
cat "$CHECKPOINT_LOG"

echo "== [5/5] pretty-printing every field =="

"$PYTHON_BIN" "$REPO_DIR/capsule_field_inspector.py" "$RUN_DIR/admission_policy.json" \
  --checkpoint-status-file "$CHECKPOINT_LOG"
STATUS=$?

echo ""
echo "run directory (ledger, keys, raw responses, log): $RUN_DIR"
exit "$STATUS"
