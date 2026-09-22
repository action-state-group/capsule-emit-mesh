#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-plugin-checkpoint-cadence] cross-language checkpoint invariance
oracle: given a `capsules.jsonl` this crate's `checkpoint.rs` checkpointed,
independently recompute the MMR root over the SAME leaves in Python
(`cll`'s reference MMR, via the `capsule_emit.checkpoint` re-export -- see
that package's module doc) and confirm it matches the Rust-produced
checkpoint's root, then verify the Rust-produced COSE-wire checkpoint
statement with the Python offline verifier -- independent of the Rust code
that built either.

This does NOT re-derive Layer 0 (capsule_id / COSE_Sign1 capsule signature)
byte-identity -- that is `verify_rust_ledger.py`'s job, already covered by
`chain_ledger_conformance.rs`. This script is checkpoint-layer only.

Usage:
    checkpoint_invariance_check.py <ledger_dir> <rust_root_hex> <rust_mmr_size> <checkpoint_cose_hex_path>

`checkpoint_cose_hex_path` is a file containing the Rust-produced COSE_Sign1
checkpoint statement, hex-encoded, one line -- pass "-" to skip the COSE
verification leg (JSON-only / self-attested checkpoint).

Prints one JSON line:
    {"ok": bool, "root_match": bool, "computed_root": str,
     "cose_ok": bool|null, "cose_errors": [...], "error": str|null}
Exit 0 iff ok.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from capsule_emit.checkpoint import MmrLedger, verify_checkpoint_cose_offline


class _Record:
    __slots__ = ("seq", "capsule_id")

    def __init__(self, seq: int, capsule_id: str) -> None:
        self.seq = seq
        self.capsule_id = capsule_id


class _StaticJsonlSource:
    """The minimal `LogSource` shape `MmrLedger` needs (`.scan()` only --
    this script never appends), read fresh from `capsules.jsonl` each call,
    same tolerant-trailing-line discipline `checkpointing.JsonlLogSource`
    and `checkpoint.rs::read_capsule_ids` both hold."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def scan(self, query=None):
        if not self._path.exists():
            return
        lines = [line for line in self._path.read_text().splitlines()]
        last_index = len(lines) - 1
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                capsule = json.loads(line)
            except json.JSONDecodeError:
                if i == last_index:
                    return
                raise
            yield _Record(seq=i + 1, capsule_id=capsule["capsule_id"])


def main() -> int:
    ledger_dir, rust_root_hex, rust_mmr_size_str, cose_hex_path = sys.argv[1:5]
    out = {
        "ok": False,
        "root_match": False,
        "computed_root": None,
        "cose_ok": None,
        "cose_errors": [],
        "error": None,
    }

    try:
        capsules_path = Path(ledger_dir) / "capsules.jsonl"
        mmr = MmrLedger(_StaticJsonlSource(capsules_path))
        mmr.sync()

        rust_mmr_size = int(rust_mmr_size_str)
        computed_root = mmr.root_at(rust_mmr_size).hex()
        out["computed_root"] = computed_root
        out["root_match"] = computed_root == rust_root_hex

        if cose_hex_path == "-":
            out["cose_ok"] = None
        else:
            cose_bytes = bytes.fromhex(Path(cose_hex_path).read_text().strip())
            verified = verify_checkpoint_cose_offline(cose_bytes)
            out["cose_ok"] = bool(verified.ok)
            out["cose_errors"] = list(verified.errors)
            if verified.ok:
                decoded_root_match = verified.decoded.root == rust_root_hex
                decoded_size_match = verified.decoded.mmr_size == rust_mmr_size
                if not (decoded_root_match and decoded_size_match):
                    out["cose_ok"] = False
                    out["cose_errors"].append(
                        f"decoded root/size ({verified.decoded.root}, {verified.decoded.mmr_size}) "
                        f"!= expected ({rust_root_hex}, {rust_mmr_size})"
                    )

        out["ok"] = out["root_match"] and out["cose_ok"] is not False
    except Exception as exc:  # noqa: BLE001 - report, don't crash the oracle
        out["error"] = f"{type(exc).__name__}: {exc}"

    print(json.dumps(out))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
