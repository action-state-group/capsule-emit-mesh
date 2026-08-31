#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checkpoint-by-default: a background clock that anchors a mesh node's sealed
capsule ledger to the neutral witness, so the node's history becomes
tamper-evident from anywhere -- no SSH into the box required.

This is the "on by default" scheduler wrapper around checkpointing.py's
`CheckpointState`. It is deliberately NOT the sidecar: `capsule_sidecar.py`
already folds each capsule into the MMR as requests land (`record_appended()`,
the entry-count leg, cheap and on the serving path). What was missing for
checkpoint-by-default is the *time* leg -- a ~5-minute clock that batches the
WITNESS anchor off the serving path -- plus an on-shutdown flush. That is this
file, and it runs against any on-disk `<ledger-dir>/capsules.jsonl` the node
(sidecar or Rust plugin) is writing, needing no code in mesh-llm itself.

WHY A CLOCK, NOT PER-CALL (the privacy rationale, requirement 2)
----------------------------------------------------------------
The local MMR advances on EVERY capsule -- that is free and leaks nothing
(it never leaves the box). Anchoring frequency is the ONLY privacy-sensitive
knob: each witness registration tells the witness "this node had activity in
this window", so anchoring per-call would stream the node's activity
timing/rate straight to a third party. So we batch on a clock:

  * default interval 300s (`--interval` / `cadence_seconds` in the config),
  * only-if-new-activity -- an idle interval anchors NOTHING (no heartbeat,
    no empty-interval traffic that would itself leak "up but silent"),
  * plus one flush on clean shutdown so the final window isn't lost.

`due_for_checkpoint(cfg, entries_since, seconds_since_last=...)` and
`CheckpointState.tick()` enforce exactly this: the age leg only ever fires
when there is at least one unwitnessed entry, and the clock is measured from
the FIRST such entry, not from the last check.

OFFLINE-FIRST (requirement 5)
-----------------------------
The witness being unreachable is not an error here. `CheckpointState`
keeps checkpointing LOCALLY (self-checkpointed, Layer 2) and the next tick
retries the registration; a checkpoint's consistency proof binds prior
history, so a reconnect self-heals the gap in one anchor. The daemon never
crashes the node -- it is a separate process from serving, and every witness
call is best-effort inside `CheckpointState`.

RESTART-SAFE / IDEMPOTENT (requirement 3)
-----------------------------------------
`CheckpointState.load()` resumes from the last stamp in
`<ledger-dir>/checkpoints.jsonl`; the first tick after a restart commits any
backlog in ONE checkpoint chained (with a consistency proof) from that last
size. Running two ticks with no new capsules is a no-op. The checkpoint is
written to the SIBLING `checkpoints.jsonl`, never back into `capsules.jsonl`
(no recursion; see checkpointing.py's module docstring).

Usage (see run_node.sh for the copy-pasteable node bring-up):
    python3 checkpoint_daemon.py \
        --ledger-dir <dir> --keys-dir <dir> --log-id <id> \
        [--interval 300] [--witness | --ts-url URL ...] \
        [--checkpoint-config path.toml] [--once]

Anchoring is OPT-IN, always (this repo's posture): omit --witness/--ts-url to
stay self-checkpointed (Layer 2, no network). Pass --witness to also register
with the default neutral witness (capsule_emit.checkpoint.DEFAULT_TS_URL,
witness.agentactioncapsule.org).
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from capsule_emit.checkpoint import DEFAULT_TS_URL, CheckpointConfig
from checkpointing import (
    CheckpointState,
    Ed25519Signer,
    JsonlLogSource,
    load_checkpoint_config,
)

#: The mesh-node default anchor interval. Upstream CheckpointConfig defaults
#: cadence_seconds to 900 (its own "100 entries or 15 minutes" surface); a
#: mesh accountability node uses a tighter 5-minute clock so a node's history
#: is anchored-fresh, while still batching (never per-call). Config- and
#: flag-overridable.
DEFAULT_INTERVAL_SECONDS = 300


def build_state(
    *,
    ledger_dir: Path,
    keys_dir: Path,
    log_id: str,
    ts_urls: list[str],
    interval_seconds: int,
    checkpoint_config_path: Path | None = None,
) -> CheckpointState:
    """Load a `CheckpointState` over `<ledger-dir>/capsules.jsonl`.

    A `--checkpoint-config` TOML, if given, supplies the base policy
    (cadence_entries / cadence_seconds / max_lag_entries / ts_urls); explicit
    `--interval` and `--ts-url`/`--witness` flags then override it, so the
    file is the deployment default and the flags are the per-invocation knob.
    With no config file, the mesh defaults apply (300s clock, opt-in anchor).
    """
    if checkpoint_config_path is not None:
        loaded = load_checkpoint_config(checkpoint_config_path)
        if loaded is None:
            raise SystemExit(
                f"{checkpoint_config_path} has no [checkpoint] table -- "
                "checkpointing would stay off. Add one, or drop --checkpoint-config."
            )
        cfg, log_id_override = loaded
        if log_id_override:
            log_id = log_id_override
    else:
        cfg = CheckpointConfig(
            ts_urls=[],
            cadence_seconds=DEFAULT_INTERVAL_SECONDS,
        )

    # Flags win over the file: interval and ts_urls are the two knobs a node
    # operator most often overrides per bring-up.
    if interval_seconds is not None:
        cfg.cadence_seconds = interval_seconds
    if ts_urls:
        # Explicit --ts-url/--witness REPLACES the config's list (opt-in, and
        # the operator asked for exactly these).
        cfg.ts_urls = list(ts_urls)

    log_source = JsonlLogSource(ledger_dir / "capsules.jsonl")
    signer = Ed25519Signer(keys_dir / "node-key.pem")
    return CheckpointState.load(
        ledger_dir=ledger_dir,
        log_source=log_source,
        cfg=cfg,
        signer=signer,
        log_id=log_id,
    )


def run_daemon(
    state: CheckpointState,
    *,
    interval_seconds: int,
    stop: threading.Event | None = None,
    max_iterations: int | None = None,
    on_checkpoint=None,
) -> int:
    """The background loop: reconnect-catch-up once at startup, then tick on
    the interval, then flush on shutdown.

    `stop` is set by SIGTERM/SIGINT (or a test); `max_iterations` bounds the
    loop for tests. Returns a count of checkpoints emitted. Never raises out
    of the witness path -- an unreachable witness is handled inside
    `CheckpointState` (offline-first), so the loop keeps running.
    """
    stop = stop or threading.Event()
    emitted = 0

    def _emitted(cp) -> None:
        nonlocal emitted
        if cp is not None:
            emitted += 1
            print(f"[checkpoint-daemon] anchored: {state.witness_status()}", flush=True)
            if on_checkpoint is not None:
                on_checkpoint(cp)

    # Startup catch-up: commit any backlog left by a prior run / offline
    # window in one consistency-proof-chained checkpoint (restart-safe).
    _emitted(state.reconnect())
    print(
        f"[checkpoint-daemon] started: log_id={state.log_id} interval={interval_seconds}s "
        f"witness={'on (' + ','.join(state.cfg.ts_urls) + ')' if state.cfg.ts_urls else 'off (self-checkpointed)'} "
        f"-- {state.witness_status()}",
        flush=True,
    )

    iterations = 0
    while not stop.is_set():
        # Wait out the interval, but wake immediately on shutdown so the
        # final flush is prompt (no up-to-`interval` shutdown stall).
        stop.wait(timeout=interval_seconds)
        if stop.is_set():
            break
        _emitted(state.tick())
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            break

    # On-shutdown flush (requirement 2): anchor the final window's backlog so
    # it isn't lost between the last tick and process exit. Best-effort
    # witness registration as always.
    _emitted(state.checkpoint_on_shutdown())
    print(f"[checkpoint-daemon] stopped: {state.witness_status()}", flush=True)
    return emitted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--ledger-dir", required=True, type=Path, help="dir containing capsules.jsonl (this node's or the Rust plugin's)")
    parser.add_argument("--keys-dir", required=True, type=Path, help="dir containing node-key.pem (the key that signed the capsules)")
    parser.add_argument("--log-id", default=None, help="stable id for this log; falls back to the config's log_id, then to 'mesh-node'")
    parser.add_argument("--interval", type=int, default=None, help=f"witness-anchor clock, seconds (default {DEFAULT_INTERVAL_SECONDS}; the config's cadence_seconds if a --checkpoint-config is given)")
    parser.add_argument("--ts-url", action="append", default=[], help="register with this witness URL (repeatable); omit to stay self-checkpointed, no network")
    parser.add_argument("--witness", action="store_true", help=f"shorthand for --ts-url {DEFAULT_TS_URL}")
    parser.add_argument("--checkpoint-config", type=Path, default=None, help="a TOML file with a [checkpoint] table (checkpoint.example.toml) supplying base cadence/ts_urls policy")
    parser.add_argument("--once", action="store_true", help="run a single reconnect checkpoint and exit (no background loop) -- for cron/systemd-timer style invocation")
    args = parser.parse_args(argv)

    ts_urls = list(args.ts_url)
    if args.witness and DEFAULT_TS_URL not in ts_urls:
        ts_urls.append(DEFAULT_TS_URL)

    interval = args.interval if args.interval is not None else DEFAULT_INTERVAL_SECONDS
    log_id = args.log_id or "mesh-node"

    state = build_state(
        ledger_dir=args.ledger_dir,
        keys_dir=args.keys_dir,
        log_id=log_id,
        ts_urls=ts_urls,
        interval_seconds=interval,
        checkpoint_config_path=args.checkpoint_config,
    )

    if args.once:
        cp = state.reconnect()
        if cp is None:
            print(f"[checkpoint-daemon --once] nothing new to checkpoint: {state.witness_status()}")
        else:
            print(f"[checkpoint-daemon --once] anchored: {state.witness_status()}")
        return 0

    stop = threading.Event()

    def _handle(signum, _frame):
        print(f"[checkpoint-daemon] signal {signum} -- flushing final checkpoint and stopping", flush=True)
        stop.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    run_daemon(state, interval_seconds=interval, stop=stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
