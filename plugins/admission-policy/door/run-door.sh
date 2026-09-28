#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Start this node's evidence door: the local service the plugin hands peers'
# pushed records and record requests to. It listens on loopback only, and it
# answers only requests that prove the plugin's token (evidence-door.token in
# the plugin's data directory), proving it back on every reply.
#
# Needs python3 (3.11 or newer). The first run creates door/.venv and
# installs the pinned, hash-checked dependencies from requirements.lock.
#
# Environment (use the same values as the node's):
#   ADMISSION_POLICY_DATA_DIR             the plugin's data directory (give an
#                                         absolute path); unset, the
#                                         plugin's own default:
#                                         $XDG_DATA_HOME/capsule-emit-mesh, else
#                                         ~/.local/share/capsule-emit-mesh
#   ADMISSION_POLICY_EVIDENCE_SERVER_URL  where the plugin looks for the door
#                                         (default http://127.0.0.1:8091); the
#                                         door listens on that URL's port
set -eu

here=$(cd "$(dirname "$0")" && pwd)
if [ -n "${ADMISSION_POLICY_DATA_DIR:-}" ]; then
  data=$ADMISSION_POLICY_DATA_DIR
elif case "${XDG_DATA_HOME:-}" in /*) true ;; *) false ;; esac; then
  # Like the plugin: a relative XDG_DATA_HOME is ignored, as the spec says.
  data=$XDG_DATA_HOME/capsule-emit-mesh
else
  data=$HOME/.local/share/capsule-emit-mesh
fi
echo "run-door: plugin data directory $data" >&2
url=${ADMISSION_POLICY_EVIDENCE_SERVER_URL:-http://127.0.0.1:8091}
case "$url" in
  http://127.0.0.1:*) ;;
  *) echo "run-door: ADMISSION_POLICY_EVIDENCE_SERVER_URL must be http://127.0.0.1:<port>" >&2; exit 1 ;;
esac
port=${url#http://127.0.0.1:}
port=${port%%/*}
case "$port" in
  ''|*[!0-9]*) echo "run-door: no port in $url" >&2; exit 1 ;;
esac

token="$data/evidence-door.token"
if [ ! -f "$token" ]; then
  echo "run-door: $token not found; start the node with the plugin once, then run this again" >&2
  exit 1
fi

venv="$here/.venv"
if [ ! -x "$venv/bin/python" ]; then
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || {
    echo "run-door: python3 3.11 or newer is required" >&2; exit 1; }
  python3 -m venv "$venv"
  "$venv/bin/python" -m pip install --quiet --require-hashes -r "$here/requirements.lock"
fi

mkdir -p "$data/received-log"
exec "$venv/bin/python" "$here/evidence_server.py" \
  --ledger-dir "$data/ledger" \
  --node-key "$data/keys/node-key.pem" \
  --listen-host 127.0.0.1 --listen-port "$port" \
  --token-file "$token" \
  --received-log-dir "$data/received-log"
