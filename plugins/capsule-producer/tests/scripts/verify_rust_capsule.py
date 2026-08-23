#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Milestone 1 cross-language conformance oracle: verify a Rust-produced
Agent Action Capsule + COSE_Sign1 statement against the Python reference
implementations (agent_action_capsule + scitt_cose), independent of the Rust
code that built them.

Usage:
    verify_rust_capsule.py <capsule.json> <statement.cose> <pubkey.pem>

Prints one JSON line: {"ok": bool, "cose_ok": bool, "capsule_ok": bool,
"capsule_id": str, "findings": [...], "error": str|null}. Exit 0 iff ok.
"""
from __future__ import annotations

import json
import sys

import scitt_cose
from agent_action_capsule.verify import verify as verify_capsule


def main() -> int:
    capsule_path, statement_path, pubkey_path = sys.argv[1:4]

    out = {
        "ok": False,
        "cose_ok": False,
        "capsule_ok": False,
        "capsule_id": None,
        "findings": [],
        "error": None,
    }

    try:
        capsule_bytes = open(capsule_path, "rb").read()
        statement_bytes = open(statement_path, "rb").read()
        pubkey_pem = open(pubkey_path, "rb").read()

        # 1. COSE_Sign1 signature + generic statement fields, verified by the
        #    independent scitt_cose reference (clean-room COSE_Sign1, no
        #    dependency on any COSE library -- and definitely not on `coset`).
        #    parse_signed_statement() never raises; signature_verified gates
        #    whether the decoded fields are authenticated at all.
        sign1 = scitt_cose.parse_signed_statement(statement_bytes, public_key_pem=pubkey_pem)
        if sign1["signature_verified"] is not True:
            out["error"] = f"COSE signature did not verify: {sign1.get('unverified')}"
            print(json.dumps(out))
            return 1
        out["cose_ok"] = True
        out["issuer"] = sign1["issuer"]
        out["subject"] = sign1["subject"]
        out["content_type"] = sign1["content_type"]

        # The statement's payload IS the capsule bytes -- check byte identity,
        # not just "parses to the same JSON", since the COSE signature covers
        # exactly the payload bytes carried in the message.
        if sign1["payload"] != capsule_bytes:
            out["error"] = (
                f"COSE payload ({len(sign1['payload'])} bytes) does not match "
                f"the supplied capsule.json ({len(capsule_bytes)} bytes)"
            )
            print(json.dumps(out))
            return 1

        # 2. Class-1 capsule verification (recomputes capsule_id via JCS,
        #    checks the spec's structural invariants) over the SIGNED payload
        #    bytes, not a copy -- so a producer can't sign one thing and hand
        #    the verifier another.
        capsule = json.loads(sign1["payload"].decode("utf-8"))
        result = verify_capsule(capsule)
        out["capsule_ok"] = result.ok
        out["capsule_id"] = result.capsule_id
        out["findings"] = [
            {"code": f.code, "detail": f.detail, "check": f.check, "severity": f.severity}
            for f in result.findings
        ]

        out["ok"] = out["cose_ok"] and out["capsule_ok"]
    except scitt_cose.CoseError as exc:
        out["error"] = f"CoseError: {exc}"
    except Exception as exc:  # noqa: BLE001 - report, don't crash the oracle
        out["error"] = f"{type(exc).__name__}: {exc}"

    print(json.dumps(out))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
