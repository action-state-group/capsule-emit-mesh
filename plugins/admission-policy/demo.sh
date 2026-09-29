#!/usr/bin/env bash
# demo.sh -- the 5-minute capsule-emit-mesh demo on two STOCK mesh-llm nodes.
#
#   MESH_LLM_BIN=... MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR=... PLUGIN_PKG=... \
#   GGUF=... ./demo.sh up|ask|status|down
#
#   up      two nodes on this machine: A serves GGUF, B joins A's private mesh.
#           The plugin is installed on each from the package (`mesh-llm plugins
#           install --archive`); once each node has reported its id and key,
#           both restart knowing the other's key, then ONE exchange is sent
#           (B asks A's model).
#           Ends when both sides hold the other's signed record of that exchange,
#           and prints the plugin page URL.
#   ask     one more exchange (B -> A)
#   status  records, received records, confirmed exchanges, per node
#   down    stop both nodes; redact the invite token from the logs
#
# Inputs (environment):
#   MESH_LLM_BIN                        a stock mesh-llm release build
#   MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR  the native runtime bundle built with it
#   PLUGIN_PKG                          capsule-emit-mesh.tar.gz (the plugin package)
#   PYTHON                              python3, for this script's own small JSON
#                                       helpers (the plugin itself needs no Python)
#   GGUF                                the model node A serves
#   DEMO_DIR                            state dir (default: ./demo-run next to this script)
#
# Nothing here joins or publishes to any public mesh: B joins A with an invite
# token kept in a 0600 file (never on a command line), relays are off, and
# `down` removes the token from the logs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="${DEMO_DIR:-$HERE/demo-run}"
PYTHON="${PYTHON:-python3}"
A_CONSOLE=${A_CONSOLE:-3811} A_API=${A_API:-9811}
B_CONSOLE=${B_CONSOLE:-3812} B_API=${B_API:-9812}
PLUGIN=capsule-emit-mesh

need() { [ -n "${!1:-}" ] || { echo "demo: set $1" >&2; exit 2; }; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
up_port() { curl -fs -m 2 -o /dev/null "http://127.0.0.1:$1/api/status"; }
busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
until_ok() {   # until_ok SECONDS WHAT CMD...
  local deadline=$(( $(date +%s) + $1 )) what=$2; shift 2
  until "$@"; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "demo: timed out waiting for $what" >&2; return 1; }
    sleep 1
  done
}

node_env() {   # node_env NAME
  local d="$DEMO_DIR/$1"
  echo HOME="$d/home" TMPDIR="/tmp/demo-$(id -u)-$1/" \
    MESH_LLM_PLUGIN_DIR="$d/plugins" \
    MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR="$MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR" \
    MESH_LLM_NATIVE_RUNTIME_CACHE_DIR="$DEMO_DIR/runtime-cache" \
    ADMISSION_POLICY_DATA_DIR="$d/plugin-data" \
    ADMISSION_POLICY_RECEIVED_LOG_DIR="$d/logs/received" \
    MESH_LLM_CAPSULE_LEDGER_DIR="$d/plugin-data/ledger" \
    MESH_LLM_CAPSULE_RECEIVED_LOG_DIR="$d/logs/received"
  # Each node's plugin checks the records it receives against the other
  # node's key: the JSON map holds no spaces, so it passes through `env`.
  [ -f "$DEMO_DIR/peer-keys.json" ] && echo ADMISSION_POLICY_PEER_KEYS="$(cat "$DEMO_DIR/peer-keys.json")"
  return 0
}

install_plugin() {   # the maintainer step: one command per node
  local d="$DEMO_DIR/$1"
  mkdir -p "$d/home" "$d/logs" "$d/plugin-data" "/tmp/demo-$(id -u)-$1/"
  env $(node_env "$1") "$MESH_LLM_BIN" plugins install --archive "$PLUGIN_PKG" --name "$PLUGIN" > "$d/logs/install.log" 2>&1 \
    || { cat "$d/logs/install.log" >&2; return 1; }
  echo "  node $1: $(env $(node_env "$1") "$MESH_LLM_BIN" plugins list 2>/dev/null | grep "$PLUGIN" | head -n 1)"
}

start_node() {   # start_node NAME CONSOLE API ARGS...
  local name=$1 console=$2 api=$3 d="$DEMO_DIR/$1"; shift 3
  mkdir -p "$d/logs/received"
  ( cd "$d/home"; exec env $(node_env "$name") "$MESH_LLM_BIN" "$@" --disable-iroh-relays \
      --console "$console" --port "$api" --log-format json ) >> "$d/logs/node.log" 2>&1 &
  echo $! > "$d/node.pid"
  until_ok 240 "node $name console :$console" up_port "$console"
}

self_id() { tr -d '[:space:]' < "$DEMO_DIR/$1/plugin-data/self-peer-id" 2>/dev/null || true; }
pub_key() {   # the raw Ed25519 key (hex) in the plugin's public key file
  "$PYTHON" -c 'import base64, sys
b = "".join(l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("-----"))
d = base64.b64decode(b)
print(d[-32:].hex() if len(d) == 44 else "")' "$DEMO_DIR/$1/plugin-data/keys/node-key.pub.pem" 2>/dev/null || true
}
wired() { [ -n "$(self_id a)" ] && [ -n "$(self_id b)" ] && [ -n "$(pub_key a)" ] && [ -n "$(pub_key b)" ]; }

stop_node() {   # stop_node NAME CONSOLE API
  local d="$DEMO_DIR/$1"
  alive "$d/node.pid" && kill -TERM "$(cat "$d/node.pid")" 2>/dev/null || true
  rm -f "$d/node.pid"
  for p in "$2" "$3"; do until_ok 60 "port $p to close" bash -c "! (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null"; done
}

start_both() {   # node A serves, node B joins A's private mesh with a fresh invite
  start_node a $A_CONSOLE $A_API serve --gguf "$GGUF" --ctx-size 2048
  rm -f "$DEMO_DIR/join-token"
  (umask 077; curl -fs "http://127.0.0.1:$A_CONSOLE/api/status" | "$PYTHON" -c '
import json, sys
t = json.load(sys.stdin).get("token") or ""
sys.exit("demo: node A has no invite token") if not t else sys.stdout.write(t)' > "$DEMO_DIR/join-token")
  start_node b $B_CONSOLE $B_API client --join-file "$DEMO_DIR/join-token"
  until_ok 300 "node B to list node A's model" has_model
}

model_on_a() {
  curl -fs "http://127.0.0.1:$B_API/v1/models" | "$PYTHON" -c '
import json, sys
ids = [m["id"] for m in json.load(sys.stdin).get("data") or []]
print(next((i for i in ids if i not in ("mesh", "auto") and not i.startswith("blocked-")), ""))' 2>/dev/null || true
}

lines() { local n; n=$(grep -c . "$1" 2>/dev/null || true); echo "${n:-0}"; }
has_model() { [ -n "$(model_on_a)" ]; }

ask() {
  local model n
  model=$(model_on_a)
  [ -n "$model" ] || { echo "demo: node B lists no model yet" >&2; return 1; }
  n=$(( $(lines "$DEMO_DIR/b/plugin-data/ledger/capsules.jsonl") + 1 ))
  echo "  B asks $model: \"demo exchange $n $(date +%H%M%S): name one colour\""
  # A paying node answers 402 until its wallet is open (`wallet get-balance`
  # opens it; setting a policy does not), and briefly right after the other
  # node sets its price. Retry a 402 for up to 3 minutes.
  local out="$DEMO_DIR/last-answer.json" code i
  for i in $(seq 1 36); do
    code=$(curl -sS -o "$out" -w '%{http_code}' "http://127.0.0.1:$B_API/v1/chat/completions" -H 'content-type: application/json' \
      -d "{\"model\":\"$model\",\"max_tokens\":16,\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"demo exchange $n $(date +%H%M%S): name one colour\"}]}") || code=000
    [ "$code" = 402 ] || break
    echo "  (402: if node B pays for answers, open its wallet: mesh-llm wallet --port $B_CONSOLE get-balance; retrying)"; sleep 5
  done
  [ "$code" = 200 ] || { echo "demo: the ask failed: HTTP $code $(head -c 200 "$out")" >&2; return 1; }
  "$PYTHON" -c 'import json,sys; print("  answer:", (json.load(open(sys.argv[1]))["choices"][0]["message"]["content"] or "").strip()[:80])' "$out"
}

confirmed() {   # confirmed NODE -> "confirmed received own"
  "$PYTHON" - "$DEMO_DIR/$1/plugin-data/ledger" <<'PY'
import json, os, sys
d = sys.argv[1]
def load(n):
    p = os.path.join(d, n)
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []
key = lambda r: ((r.get("effect") or {}).get("request_digest"), (r.get("effect") or {}).get("response_digest"))
own = [r for r in load("capsules.jsonl") if key(r)[0] and key(r)[1]]
ok = {p.get("capsule_id") for p in load("received-provenance.jsonl") if p.get("signature_ok") is True}
used, n = set(), 0
for h in load("received-capsules.jsonl"):
    if h.get("capsule_id") not in ok:
        continue
    i = next((i for i, r in enumerate(own) if i not in used and key(r) == key(h)), None)
    if i is not None:
        used.add(i); n += 1
print(n, len(load("received-capsules.jsonl")), len(own))
PY
}
both_confirmed() {
  local a b; read -r a _ _ <<<"$(confirmed a)"; read -r b _ _ <<<"$(confirmed b)"
  [ "$a" -ge "${1:-1}" ] && [ "$b" -ge "${1:-1}" ]
}

status() {
  local n c r o
  for n in a b; do
    read -r c r o <<<"$(confirmed $n)"
    echo "  node $n: $o exchange records of its own · $r records received from the other node · $c confirmed by the other node"
  done
}

up() {
  for v in MESH_LLM_BIN MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR PLUGIN_PKG GGUF; do need $v; done
  for p in $A_CONSOLE $A_API $B_CONSOLE $B_API; do busy $p && { echo "demo: port $p is in use" >&2; exit 1; }; done
  mkdir -p "$DEMO_DIR/a" "$DEMO_DIR/b" "$DEMO_DIR/runtime-cache"; chmod 700 "$DEMO_DIR"
  rm -f "$DEMO_DIR/peer-keys.json"
  say "1/5  Install the plugin on both nodes (mesh-llm plugins install --archive $(basename "$PLUGIN_PKG"))"
  install_plugin a; install_plugin b

  say "2/5  Start node A (serves $(basename "$GGUF")) and node B (joins A's private mesh)"
  start_both
  echo "  node A console http://127.0.0.1:$A_CONSOLE · node B console http://127.0.0.1:$B_CONSOLE"

  say "3/5  Each node learns the other node's public key (before any traffic)"
  # A node's key and id exist only after its first start, and a running
  # node's environment can't change: record both, then restart both with them.
  until_ok 120 "both plugins to report their peer id and key" wired
  (umask 077; printf '{"%s":"%s","%s":"%s"}' "$(self_id a)" "$(pub_key a)" "$(self_id b)" "$(pub_key b)" > "$DEMO_DIR/peer-keys.json")
  stop_node b $B_CONSOLE $B_API; stop_node a $A_CONSOLE $A_API
  start_both
  echo "  node A $(self_id a | cut -c1-10)… · node B $(self_id b | cut -c1-10)…"

  say "4/5  One exchange: node B asks node A's model"
  ask
  until_ok 90 "each node to hold the other's signed record" both_confirmed 1
  status

  say "5/5  Open the plugin's page"
  echo "  node B: http://127.0.0.1:$B_CONSOLE/plugins/$PLUGIN/evidence"
  echo "  node A: http://127.0.0.1:$A_CONSOLE/plugins/$PLUGIN/evidence"
}

down() {
  stop_node b $B_CONSOLE $B_API; stop_node a $A_CONSOLE $A_API
  rm -f "$DEMO_DIR/join-token"
  "$PYTHON" "$HERE/redact-node-log.py" "$DEMO_DIR" >/dev/null && echo "demo: stopped; invite token redacted from the logs"
}

case "${1:-}" in
  up) up ;;
  ask) ask; sleep 5; status ;;
  status) status ;;
  down) down ;;
  restart)      # restart a stopped run on its own data: no install, no new exchange
    for v in MESH_LLM_BIN MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR GGUF; do need $v; done
    start_both
    echo "demo: restarted on $DEMO_DIR (no new exchange)"; status ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
