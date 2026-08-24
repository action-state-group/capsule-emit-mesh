#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Milestone 2 cross-language conformance oracle: verify a Rust-written
capsule-producer LEDGER (capsules.jsonl + signed-statements/*.cose) --
signature AND chain -- against the Python reference (scitt_cose +
agent_action_capsule.verify), independent of the Rust code that wrote it.

Usage:
    verify_rust_ledger.py <ledger_dir> <pubkey.pem>

Prints one JSON line:
    {"ok": bool, "count": int, "cose_all_ok": bool, "store_ok": bool,
     "capsule_ids": [...], "findings": [...], "error": str|null}
Exit 0 iff ok.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import scitt_cose
from agent_action_capsule.verify import verify_store


def main() -> int:
    ledger_dir, pubkey_path = sys.argv[1:3]
    out = {
        "ok": False,
        "count": 0,
        "cose_all_ok": False,
        "payload_bytes_all_match": False,
        "store_ok": False,
        "capsule_ids": [],
        "findings": [],
        "error": None,
    }

    try:
        pubkey_pem = Path(pubkey_path).read_bytes()
        capsules_path = Path(ledger_dir) / "capsules.jsonl"
        statements_dir = Path(ledger_dir) / "signed-statements"

        capsules: list[dict] = []
        cose_ok_all = True
        payload_bytes_all_match = True
        for raw_line in capsules_path.read_text().splitlines():
            if not raw_line.strip():
                continue
            capsule = json.loads(raw_line)
            capsules.append(capsule)
            cid = capsule["capsule_id"]
            out["capsule_ids"].append(cid)

            stmt_bytes = (statements_dir / f"{cid}.cose").read_bytes()
            sign1 = scitt_cose.parse_signed_statement(stmt_bytes, public_key_pem=pubkey_pem)
            if sign1["signature_verified"] is not True:
                cose_ok_all = False
                out["findings"].append(f"{cid}: COSE signature did not verify")
                continue

            # Byte-exact: the ledger's jsonl line (minus trailing newline) IS
            # the same serialization of the same JSON value that was signed
            # -- not just semantically equal after re-parsing.
            if sign1["payload"] != raw_line.encode("utf-8"):
                payload_bytes_all_match = False
                out["findings"].append(
                    f"{cid}: COSE payload ({len(sign1['payload'])} bytes) != "
                    f"ledger line ({len(raw_line.encode('utf-8'))} bytes)"
                )

        out["count"] = len(capsules)
        out["cose_all_ok"] = cose_ok_all
        out["payload_bytes_all_match"] = payload_bytes_all_match

        # Chain integrity -- store-level (§6): parent existence,
        # concurrent-supersedes -- across the WHOLE ledger at once.
        results = verify_store(capsules)
        store_ok = all(r.ok for r in results)
        out["store_ok"] = store_ok
        for c, r in zip(capsules, results):
            for f in r.findings:
                out["findings"].append(
                    {"capsule_id": c.get("capsule_id"), "code": f.code, "detail": f.detail, "severity": f.severity}
                )

        out["ok"] = cose_ok_all and payload_bytes_all_match and store_ok
    except Exception as exc:  # noqa: BLE001 - report, don't crash the oracle
        out["error"] = f"{type(exc).__name__}: {exc}"

    print(json.dumps(out))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
