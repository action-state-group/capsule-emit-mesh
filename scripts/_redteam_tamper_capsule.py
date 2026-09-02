#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Flip ONE field on a sealed capsule's own bytes, without re-signing --
simulates a malicious relay / in-transit tamper (NOT a node lying about
itself at seal time; see the redteam demo docs for that distinction).

Targets model_attestation.compute_attestation.x-mesh-poc-v1
.serving_provenance.model_canonical_ref (the served-quant claim,
Q4_K_M -> Q8_0). capsule_id is left UNCHANGED -- a relay without the
node's signing key can't mint a new legitimate one, and that's exactly
what makes the edit detectable: offline verify recomputes capsule_id
from the current bytes and it no longer matches what the record claims.

Usage: _redteam_tamper_capsule.py <capsules.jsonl> [capsule_id]
If capsule_id is omitted, tampers the first record in the file.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = sys.argv[1]
    capsule_id = sys.argv[2] if len(sys.argv) > 2 else None

    lines = open(path, encoding="utf-8").read().splitlines()
    out = []
    tampered = False
    for line in lines:
        rec = json.loads(line)
        if not tampered and (capsule_id is None or rec["capsule_id"] == capsule_id):
            poc = rec["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
            prov = poc["serving_provenance"]
            before = prov.get("model_canonical_ref")
            after = before.replace("Q4_K_M", "Q8_0") if before and "Q4_K_M" in before else "TAMPERED"
            prov["model_canonical_ref"] = after
            print(
                "tampered field: model_attestation.compute_attestation."
                "x-mesh-poc-v1.serving_provenance.model_canonical_ref"
            )
            print(f"  before (sealed) : {before}")
            print(f"  after (relayed) : {after}")
            print(f"  capsule_id left UNCHANGED at: {rec['capsule_id']}")
            tampered = True
            line = json.dumps(rec, sort_keys=True)
        out.append(line)

    if not tampered:
        print(f"no matching capsule found in {path}", file=sys.stderr)
        return 1

    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
