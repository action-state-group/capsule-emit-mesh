<!-- SPDX-License-Identifier: Apache-2.0 -->
# Checkpoint by default

A mesh accountability node seals a signed capsule for every exchange (Layer 0)
and folds each into a local, append-only MMR (Layer 1). **Checkpoint by
default** adds the last mile: a background clock that periodically anchors that
sealed ledger to the neutral witness, so a node's history becomes
**tamper-evident from anywhere — no SSH into the box required**. Anyone holding
a node's `checkpoints.jsonl` (and a witness receipt) can prove the node has not
rewritten, dropped, or back-dated its own log.

This is a node-side background loop only. It changes nothing in mesh-llm and
adds nothing to the serving path.

## What a checkpoint commits to

A checkpoint is a signed commitment to the *entire* capsule ledger up to a size:

- **Local MMR (Layer 1).** Each capsule's leaf is `sha256(0x00 || capsule_id)`,
  folded into a Merkle Mountain Range. The MMR root is a single hash that fixes
  the whole ordered log — remove or reorder any capsule and the root changes.
- **Signed checkpoint (Layer 2).** A `cll-checkpoint` COSE_Sign1 statement over
  that root, the log size, and — for every checkpoint after the first — a
  **consistency proof** binding it to the previous checkpoint. The chain of
  consistency proofs is what makes history-editing detectable: a node cannot
  quietly swap in a different past without breaking the proof.
- **Witness receipt (Layer 3, opt-in).** The checkpoint is POSTed to the neutral
  witness, which independently verifies the COSE envelope and returns a COSE
  **receipt** proving the witness saw this checkpoint at some point in its own
  append-only log. That receipt is what lets a third party trust the node's
  freshness claim without trusting the node.

Checkpoints are written to a **sibling** `checkpoints.jsonl`, never back into
`capsules.jsonl` — the capsule ledger stays exactly what the node (or the Rust
plugin) wrote, byte for byte. See `checkpointing.py`'s module docstring for why
(two single-writer logs; the checkpointer is never a second writer).

## The cadence, and why it's a clock (the privacy rationale)

The cadence is a **~5-minute clock, only-if-new-activity, plus one flush on
shutdown**. It is deliberately *not* per-call and *not* a fixed heartbeat.

Anchoring frequency is **the only privacy-sensitive knob in the whole design.**
The local MMR advances on every capsule — that is free and leaks nothing,
because it never leaves the box. But every *witness registration* tells the
witness "this node had activity in this window." So:

- **Batch on a clock, never per call.** Anchoring per capsule would stream a
  node's activity timing and rate straight to a third party. Batching on a
  ~5-minute clock collapses a whole window into one anchor, so the witness
  learns only "active sometime in this window," not the shape of the traffic.
- **Only-if-new-activity — no empty anchors, no heartbeat.** An idle interval
  anchors *nothing*. A checkpoint is emitted only when there is at least one
  unwitnessed capsule; the age clock is measured from the first such capsule,
  not free-running. A silent node therefore makes **zero** witness traffic — it
  never even leaks "up but idle."
- **Whichever comes first.** If a burst reaches the entry-count cadence
  (`cadence_entries`) before the clock fires, it anchors then; otherwise the
  age clock (`cadence_seconds`, default 300s here) fires. Both are configurable.
- **Flush on clean shutdown**, so the final window between the last tick and
  process exit isn't lost.

The local Layer-1/2 chain still advances continuously and losslessly; only the
Layer-3 witness anchor is throttled. Turning the clock *down* costs privacy (more
timing leaked to the witness); turning it *up* costs freshness (a longer window
where a tamper wouldn't yet be witnessed). 300s is the default balance.

## Offline-first

The witness being unreachable is **not an error**. The node keeps checkpointing
locally (self-checkpointed, Layer 2), the next tick retries the registration,
and because each checkpoint carries a consistency proof over prior history, one
successful anchor after reconnecting **self-heals the whole offline gap** — no
per-missed-tick backlog. The daemon runs off the serving path and never crashes
the node over a witness outage.

## Restart-safety

On start the daemon resumes from the last stamp in `checkpoints.jsonl` and
commits any backlog in one consistency-proof-chained checkpoint. Running it
twice with no new capsules is a no-op. It is safe to restart at any time.

## Node bring-up (the copy-pasteable command)

Run the checkpointer as a sibling process to your node's serving setup (mesh-llm
+ `capsule_sidecar.py`, or the Rust `capsule-producer` plugin). On by default —
no extra flags needed for the common case:

```sh
# Anchors ~/asg-mesh/data/ledger/capsules.jsonl to the neutral witness every
# 5 minutes, only when there's new activity. On by default.
./run_node.sh
```

Common overrides (all env vars):

```sh
# A different node home:
NODE_HOME=/Users/stevenmih/asg-mesh ./run_node.sh

# Local-only (self-checkpointed, no network):
WITNESS=off ./run_node.sh

# A tighter clock:
INTERVAL=120 ./run_node.sh
```

`run_node.sh` is a thin wrapper over `checkpoint_daemon.py`; call that directly
for full control, or from your own supervisor / launchd / systemd unit:

```sh
python3 checkpoint_daemon.py \
    --ledger-dir ~/asg-mesh/data/ledger \
    --keys-dir   ~/asg-mesh/data/ledger/keys \
    --log-id     "$(hostname -s)" \
    --interval 300 \
    --witness              # omit to stay self-checkpointed, no network

# One-shot (cron / systemd-timer style): commit any backlog and exit.
python3 checkpoint_daemon.py --ledger-dir ... --keys-dir ... --once --witness
```

A `--checkpoint-config path.toml` (see `checkpoint.example.toml`) supplies the
base cadence/witness policy; `--interval` and `--ts-url`/`--witness` flags
override it per invocation.

The witness register endpoint is `POST {ts_url}/checkpoints` (COSE-wire only);
the default neutral witness is
`https://witness.agentactioncapsule.org`
(`capsule_emit.checkpoint.DEFAULT_TS_URL`). Registration is **opt-in, always**:
no `--witness`/`--ts-url` means self-checkpointed, no network.

## Where the pieces live

| Piece | File |
| --- | --- |
| MMR / checkpoint / COSE / register adapter | `checkpointing.py` (`CheckpointState`) |
| Time-based `tick()`, on-shutdown flush | `checkpointing.py` (`CheckpointState.tick` / `checkpoint_on_shutdown`) |
| Background clock + on-shutdown daemon | `checkpoint_daemon.py` |
| Copy-pasteable node bring-up | `run_node.sh` |
| Sidecar hooks (per-capsule MMR fold) | `capsule_sidecar.py` (`--checkpoint-config`, `--plugin-checkpoint-config`, `--plugin-ledger-dir`) |
| Config schema | `checkpoint.example.toml` |
| Tests | `tests/test_checkpoint_daemon.py`, `tests/test_checkpointing.py` |
