#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checkpoint a capsule ledger to a COSE_Sign1 `cll-checkpoint`, standalone.

`capsule_sidecar.py --plugin-ledger-dir` does this as a side effect of also
running the full sidecar HTTP proxy (checkpointing.py's `CheckpointState`
loaded at startup + `reconnect()`/`record_appended()` as requests land). A
provider that only needs to checkpoint a ledger it already has -- most
commonly the Rust `admission-policy` plugin's own `capsules.jsonl`, written
by a mesh-llm host with no Python sidecar in the loop at all -- doesn't need
to stand up that proxy. This script is the same `CheckpointState` machinery
(no MMR/COSE logic reimplemented -- see checkpointing.py's own docstring)
run once, standalone, against any on-disk ledger_dir.

Usage:
    python3 checkpoint_ledger.py --ledger-dir <dir> --keys-dir <dir> \
        --log-id <id> [--ts-url URL ...] [--cadence-entries N]

Omit --ts-url to stay self-checkpointed (Layer 2 only, no network -- the
default, matching every other demo in this repo's "anchoring is opt-in,
always" posture). Pass one or more --ts-url to also register with a witness
(default target when a bare `--witness` flag is given:
capsule_emit.checkpoint.DEFAULT_TS_URL, witness.agentactioncapsule.org).

Always emits ONE checkpoint covering everything currently in the ledger
(the `reconnect()` semantics -- mesh architecture doc §4: an offline/never-
checkpointed node's whole backlog is committed in one shot, not one
checkpoint per missed cadence tick), independent of --cadence-entries.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from capsule_emit.checkpoint import DEFAULT_TS_URL, CheckpointConfig
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource


def checkpoint_ledger(
    *,
    ledger_dir: Path,
    keys_dir: Path,
    log_id: str,
    ts_urls: list[str],
    cadence_entries: int = 1,
    max_lag_entries: int = 10,
) -> tuple[CheckpointState, object | None]:
    """Load `<ledger_dir>/capsules.jsonl`, emit one reconnect checkpoint
    covering everything on disk, and return (state, checkpoint_or_None).
    `checkpoint_or_None` is None only when the ledger has nothing new since
    the last checkpoint already recorded in `<ledger_dir>/checkpoints.jsonl`.
    """
    log_source = JsonlLogSource(ledger_dir / "capsules.jsonl")
    signer = Ed25519Signer(keys_dir / "node-key.pem")
    cfg = CheckpointConfig(ts_urls=ts_urls, cadence_entries=cadence_entries, max_lag_entries=max_lag_entries)
    state = CheckpointState.load(ledger_dir=ledger_dir, log_source=log_source, cfg=cfg, signer=signer, log_id=log_id)
    cp = state.reconnect()
    return state, cp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ledger-dir", required=True, help="dir containing capsules.jsonl (this node's or a foreign-owned one, e.g. the Rust plugin's)")
    parser.add_argument("--keys-dir", required=True, help="dir containing node-key.pem (the SAME key that signed the capsules, per the shared-identity convention -- see keys.rs)")
    parser.add_argument("--log-id", required=True, help="stable id for this log (checkpoint.example.toml's log_id)")
    parser.add_argument("--ts-url", action="append", default=[], help="register with this witness URL (repeatable); omit to stay self-checkpointed, no network")
    parser.add_argument("--witness", action="store_true", help="shorthand for --ts-url %s" % DEFAULT_TS_URL)
    parser.add_argument("--cadence-entries", type=int, default=1)
    parser.add_argument("--max-lag-entries", type=int, default=10)
    args = parser.parse_args(argv)

    ts_urls = list(args.ts_url)
    if args.witness and DEFAULT_TS_URL not in ts_urls:
        ts_urls.append(DEFAULT_TS_URL)

    state, cp = checkpoint_ledger(
        ledger_dir=Path(args.ledger_dir),
        keys_dir=Path(args.keys_dir),
        log_id=args.log_id,
        ts_urls=ts_urls,
        cadence_entries=args.cadence_entries,
        max_lag_entries=args.max_lag_entries,
    )
    if cp is None:
        print(f"nothing new to checkpoint: {state.witness_status()}")
    else:
        print(f"checkpoint emitted: mmr_size={cp.mmr_size} root={cp.root}")
        print(state.witness_status())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
