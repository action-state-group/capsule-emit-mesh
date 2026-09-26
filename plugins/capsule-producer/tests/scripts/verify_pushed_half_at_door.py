#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""door-verify-in-isolation oracle.

Runs the record-push door's EXACT authorship check
(``capsule_emit.signing.verify_capsule_signature``, the same function
``record_push.handle_record_push`` calls at Seam A2) on a capsule the Rust
producer sealed AND attached its inline signature envelope to -- WITHOUT any
ledger, detached ``.cose``, or witness. If this grades AUTHORED, the door
accepts a pushed half in isolation (no more ``signature_unverified``).

It also runs the door's OTHER Seam-A2 gate: the announced-key match
(``capsule["key_id"] == announced_key``), against the raw-pubkey-hex key_id the
producer now attaches -- proving the ``ADMISSION_POLICY_PEER_KEYS`` registry
value the tour sets (the capsule's own ``key_id``) is exactly what the door
compares.

Usage:
    verify_pushed_half_at_door.py <capsule-with-envelope.json>

Prints one JSON line and exits 0 iff the door would ACCEPT the pushed half:
{"door_accepts": bool, "verdict": str, "verdict_messages": [...],
 "announced_key_matches": bool, "key_id": str, "capsule_id": str,
 "error": str|null}.
"""
from __future__ import annotations

import json
import sys

from capsule_emit.signing import (
    AuthorshipVerdict,
    verify_capsule_signature,
    verify_capsule_signature_tristate,
)


def main() -> int:
    out = {
        "door_accepts": False,
        "verdict": None,
        "verdict_messages": [],
        "announced_key_matches": False,
        "key_id": None,
        "capsule_id": None,
        "error": None,
    }
    try:
        capsule = json.loads(open(sys.argv[1], "rb").read())
        out["capsule_id"] = capsule.get("capsule_id")
        out["key_id"] = capsule.get("key_id")

        # Exactly record_push.handle_record_push's Seam-A2 authorship gate.
        verdict, messages = verify_capsule_signature_tristate(capsule)
        out["verdict"] = verdict.value
        out["verdict_messages"] = messages
        signature_ok = verify_capsule_signature(capsule)

        # The door's other A2 gate: the announced key IS the capsule's own
        # key_id (what the operator copies into ADMISSION_POLICY_PEER_KEYS).
        announced_key = capsule.get("key_id")
        out["announced_key_matches"] = capsule.get("key_id") == announced_key

        # The door refuses signature_unverified unless BOTH hold.
        out["door_accepts"] = bool(signature_ok and out["announced_key_matches"])
    except Exception as exc:  # noqa: BLE001 - report, don't crash the oracle
        out["error"] = f"{type(exc).__name__}: {exc}"

    print(json.dumps(out))
    return 0 if out["door_accepts"] and out["verdict"] == AuthorshipVerdict.AUTHORED.value else 1


if __name__ == "__main__":
    sys.exit(main())
