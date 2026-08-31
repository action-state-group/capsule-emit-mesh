#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ---------------------------------------------------------------------------
# run_node.sh -- checkpoint-by-default node bring-up.
#
# Starts the checkpoint daemon (checkpoint_daemon.py) alongside a running mesh
# accountability node, so the node's sealed capsule ledger is anchored to the
# neutral witness on a ~5-minute clock WITHOUT any extra flags. This is the
# copy-pasteable "checkpoint-by-default" bring-up: run it in the node's home
# and its history becomes tamper-evident from anywhere, no SSH required.
#
# It does NOT start mesh-llm or the sidecar for you (those are the node
# operator's own serving setup -- see run_live_demo.sh /
# run_real_deployment_checkpoint_demo.sh for full serving bring-ups). It
# attaches the checkpointer to the ledger those write. Run it as a sibling
# process to your node, e.g. from the same supervisor / tmux / login script.
#
# BOTH REQUESTOR AND SHARER (on by default). A first-class node seals BOTH
# halves of the exchanges it takes part in, so it can corroborate as well as be
# corroborated:
#   * SHARER half -- the provider-side capture, in front of your serving node:
#         capsule_sidecar.py --role provider  (the default)
#     or the native Rust admission-policy plugin (Path 1 in the README).
#   * REQUESTOR half -- the requester-side capture, your OWN outbound proxy for
#     requests this node MAKES:
#         capsule_sidecar.py --role requester --upstream <endpoint-you-call>
#     It seals your own half (model requested, gen-params, your nonce, the
#     response you received). The two halves of ONE exchange line up for a third
#     party via serving_provenance.exchange_id (the response-id lineage) -- see
#     the README "Both halves of an exchange" section. Point THIS daemon at each
#     ledger (provider and requester) to checkpoint both by default; a quiet
#     ledger makes no witness traffic.
#
# Defaults, all overridable by env var:
#   NODE_HOME       ~/asg-mesh          (the node's home dir)
#   LEDGER_DIR      $NODE_HOME/data/ledger   (where capsules.jsonl lives)
#   KEYS_DIR        $NODE_HOME/data/ledger/keys OR $LEDGER_DIR/keys (auto)
#   LOG_ID          the machine hostname
#   INTERVAL        300                 (anchor clock, seconds)
#   WITNESS         on                  ("off" to stay self-checkpointed, no network)
#   TS_URL          (unset -> the default neutral witness when WITNESS=on)
#   CHECKPOINT_CONFIG (unset -> mesh defaults; or a checkpoint.example.toml path)
#
# The anchor clock only fires when there is NEW activity, and never on an idle
# interval -- so a quiet node makes no witness traffic. See
# docs/CHECKPOINT-BY-DEFAULT.md for the privacy rationale.
#
# Examples:
#   # Simplest -- on by default, anchoring to the neutral witness every 5 min:
#   ./run_node.sh
#
#   # A different node home + a self-checkpointed (no-network) posture:
#   NODE_HOME=/Users/stevenmih/asg-mesh WITNESS=off ./run_node.sh
#
#   # A tighter clock and an explicit witness URL:
#   INTERVAL=120 TS_URL=https://witness.agentactioncapsule.org ./run_node.sh
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NODE_HOME="${NODE_HOME:-$HOME/asg-mesh}"
LEDGER_DIR="${LEDGER_DIR:-$NODE_HOME/data/ledger}"
LOG_ID="${LOG_ID:-$(hostname -s 2>/dev/null || hostname)}"
INTERVAL="${INTERVAL:-300}"
WITNESS="${WITNESS:-on}"

# keys_dir: the node key sits beside the ledger (keys/node-key.pem) in the
# standard layout; fall back to the ledger dir itself if that's where it is.
if [[ -n "${KEYS_DIR:-}" ]]; then
  :
elif [[ -f "$LEDGER_DIR/keys/node-key.pem" ]]; then
  KEYS_DIR="$LEDGER_DIR/keys"
elif [[ -f "$LEDGER_DIR/node-key.pem" ]]; then
  KEYS_DIR="$LEDGER_DIR"
else
  # Standard node layout default even if the key isn't created yet -- the
  # daemon loads/creates through Ed25519Signer/LocalKeypairSigner.
  KEYS_DIR="$LEDGER_DIR/keys"
fi

if [[ ! -f "$LEDGER_DIR/capsules.jsonl" ]]; then
  echo "run_node.sh: note: $LEDGER_DIR/capsules.jsonl does not exist yet." >&2
  echo "  The daemon will start and wait; it anchors once the node writes capsules." >&2
fi

ARGS=(
  --ledger-dir "$LEDGER_DIR"
  --keys-dir "$KEYS_DIR"
  --log-id "$LOG_ID"
  --interval "$INTERVAL"
)

if [[ -n "${CHECKPOINT_CONFIG:-}" ]]; then
  ARGS+=(--checkpoint-config "$CHECKPOINT_CONFIG")
fi

# Anchoring: on by default (checkpoint-by-default), but overridable. WITNESS=off
# keeps everything local (self-checkpointed, Layer 2, no network).
if [[ "$WITNESS" == "off" ]]; then
  echo "run_node.sh: WITNESS=off -- self-checkpointed only (no witness registration)."
elif [[ -n "${TS_URL:-}" ]]; then
  ARGS+=(--ts-url "$TS_URL")
else
  ARGS+=(--witness)
fi

echo "run_node.sh: checkpoint-by-default is ON"
echo "  ledger-dir : $LEDGER_DIR"
echo "  keys-dir   : $KEYS_DIR"
echo "  log-id     : $LOG_ID"
echo "  interval   : ${INTERVAL}s (anchor clock; only-on-new-activity)"
echo "  witness    : $([[ "$WITNESS" == off ]] && echo 'off (self-checkpointed)' || echo "${TS_URL:-default neutral witness}")"
echo

exec python3 "$ROOT/checkpoint_daemon.py" "${ARGS[@]}"
