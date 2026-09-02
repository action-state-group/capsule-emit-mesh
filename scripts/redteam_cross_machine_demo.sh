#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Path A -- cross-machine integrity demo. M4 (this machine) seals a real
# capsule from a live inference; a maintainer on a DIFFERENT physical
# machine (M3, over Tailscale) verifies it OFFLINE with no access to M4
# at all -- then we show what happens when the copied bundle is tampered
# in transit.
#
# One run does the whole sequence:
#   (1) M4: seal a real capsule from a live inference (reuses
#       redteam_live_demo.sh's sidecar+seal step against the live M4 node).
#   (2) scp just the capsule bundle (capsules.jsonl + its detached .cose
#       statement + the issuer pubkey) to M3.
#   (3) M3: verify OFFLINE -> GREEN.
#   (4) M3: tamper one field on the COPY (no re-sign) -> re-verify -> RED.
#
# Usage:
#   ./scripts/redteam_cross_machine_demo.sh
#
# Override the target machine with M3_HOST / M3_REPO if needed:
#   M3_HOST=user@100.x.x.x M3_REPO=~/capsule-emit-mesh ./scripts/redteam_cross_machine_demo.sh
#
# *** What this proves, and what it does NOT prove -- read before presenting ***
# Same integrity claim as the single-machine demo (scripts/redteam_live_demo.sh
# / DEMO-REDTEAM.md), now shown across a real network hop with no shared
# process or filesystem between sealer and verifier: a capsule edited after
# sealing -- here, by a script standing in for a malicious relay/copy step
# between M4 and M3 -- is caught by the maintainer, offline, with zero access
# to the sealing node. It does NOT show a node being caught lying
# CONSISTENTLY about its own quant/hardware at seal time -- that is a
# documented, uncaught-by-design residual (docs/REDTEAM-RUNG2.md, attacks
# 5/6/7). See DEMO-REDTEAM.md's honesty box for the full statement.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

M3_HOST="${M3_HOST:-stevenmih@100.127.121.98}"
M3_REPO="${M3_REPO:-~/capsule-emit-mesh}"
M3_PYTHON="${M3_PYTHON:-${M3_REPO}/.venv-redteam/bin/python3}"
BUNDLE_LOCAL="$ROOT/redteam-cross-machine-bundle"
BUNDLE_REMOTE_NAME="_redteam-m4-bundle"

echo "############################################################"
echo "# PATH A -- cross-machine: M4 seals, M3 verifies OFFLINE"
echo "# M3 target: ${M3_HOST}"
echo "############################################################"

echo
echo "=== Part 1/2: seal a real capsule on M4 (this machine) ==="
"$ROOT/scripts/redteam_live_demo.sh"
CAPSULE_ID="$(python3 -c "
import json
print(json.loads(open('$ROOT/ledger-redteam-live/capsules.jsonl').read().strip())['capsule_id'])
")"
echo
echo "M4 sealed capsule for cross-machine transfer: ${CAPSULE_ID}"

echo
echo "--- [1/6] build the transfer bundle (capsule + signed statement + issuer pubkey) ---"
rm -rf "$BUNDLE_LOCAL"
mkdir -p "$BUNDLE_LOCAL/signed-statements"
cp "$ROOT/ledger-redteam-live/capsules.jsonl" "$BUNDLE_LOCAL/"
cp "$ROOT/ledger-redteam-live/signed-statements/${CAPSULE_ID}.cose" "$BUNDLE_LOCAL/signed-statements/"
cp "$ROOT/keys/node-key.pub.pem" "$BUNDLE_LOCAL/"
cp "$ROOT/scripts/_redteam_tamper_capsule.py" "$BUNDLE_LOCAL/"
echo "bundle contents:"
find "$BUNDLE_LOCAL" -type f | sed 's/^/  /'

echo
echo "--- [2/6] confirm M3 is reachable over Tailscale ---"
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$M3_HOST" "echo reachable: \$(hostname)"; then
  echo "FATAL: cannot reach $M3_HOST over ssh/Tailscale." >&2
  exit 1
fi

echo
echo "--- [3/6] scp the bundle to M3 (this is the ONLY thing that leaves M4) ---"
ssh "$M3_HOST" "rm -rf ${M3_REPO}/${BUNDLE_REMOTE_NAME} && mkdir -p ${M3_REPO}/${BUNDLE_REMOTE_NAME}"
scp -rq "$BUNDLE_LOCAL"/* "${M3_HOST}:${M3_REPO}/${BUNDLE_REMOTE_NAME}/"

echo
echo "--- [4/6] M3 verifies OFFLINE -- no access to M4, the sidecar, or the node ---"
# Checked by matching the printed "OVERALL:" line rather than trusting ssh's
# process exit code -- some ssh/tty setups don't propagate the remote exit
# status reliably, and the verifier's own top line is the ground truth either
# way (see stranger_verify_bundle.py's three-state PASS/FAIL/UNVERIFIED).
ssh "$M3_HOST" "cd ${M3_REPO} && ${M3_PYTHON} stranger_verify_bundle.py ${BUNDLE_REMOTE_NAME} --issuer-key ${BUNDLE_REMOTE_NAME}/node-key.pub.pem" | tee /tmp/redteam-xmachine-green.txt || true

echo
if grep -q "^OVERALL: PASS$" /tmp/redteam-xmachine-green.txt; then
  echo "================================================================"
  echo " GREEN (on M3) -- verified. M3 trusts this capsule with ZERO"
  echo " access to M4 -- record bytes copied over the wire, that's all."
  echo "================================================================"
else
  echo "UNEXPECTED: M3's first verify (before any tamper) did not PASS. Investigate before continuing." >&2
  exit 1
fi

echo
echo "=== Part 2/2: tamper the copy on M3, re-verify ==="
echo "--- [5/6] M3: a malicious relay/copy step tampers the bundle (no re-sign) ---"
ssh "$M3_HOST" "cd ${M3_REPO} && ${M3_PYTHON} ${BUNDLE_REMOTE_NAME}/_redteam_tamper_capsule.py ${BUNDLE_REMOTE_NAME}/capsules.jsonl ${CAPSULE_ID}"

echo
echo "--- [6/6] M3 re-verifies OFFLINE ---"
ssh "$M3_HOST" "cd ${M3_REPO} && ${M3_PYTHON} stranger_verify_bundle.py ${BUNDLE_REMOTE_NAME} --issuer-key ${BUNDLE_REMOTE_NAME}/node-key.pub.pem" | tee /tmp/redteam-xmachine-red.txt || true

echo
if grep -q "^OVERALL: PASS$" /tmp/redteam-xmachine-red.txt; then
  echo "UNEXPECTED: M3's second verify (after tamper) still PASSED. Investigate -- the demo did not behave as expected." >&2
  exit 1
else
  echo "================================================================"
  echo " RED (on M3) -- verify FAILED after the copy was tampered."
  echo " M3 caught it with no access to M4 -- offline, from bytes alone."
  echo "================================================================"
fi

cat <<'EOF'

--- What this proves / what it does NOT prove -----------------------------
PROVES:  a capsule tampered in transit -- between the sealing node (M4) and
         a maintainer on a genuinely separate machine (M3), with no shared
         process, filesystem, or live access -- is caught. The maintainer
         needs nothing from M4 beyond the copied bytes; capsule_id is a
         digest over every field, recomputed and checked entirely offline.
DOES NOT PROVE: that a node cannot lie about its own quant/hardware at seal
         time. If M4 itself reported the same (false) quant/hardware
         consistently in the capsule it signs, that signed lie would
         verify CLEAN on M3 too -- this is the same documented,
         uncaught-by-design residual as the single-machine demo
         (docs/REDTEAM-RUNG2.md, attacks 5/6/7), not something crossing a
         second machine changes or catches.
-----------------------------------------------------------------------------
EOF

echo "cross-machine demo: PASS (GREEN before tamper, RED after)"
