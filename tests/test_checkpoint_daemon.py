# SPDX-License-Identifier: Apache-2.0
"""Checkpoint-by-default: the time-based (~5-minute) anchor clock, the
only-on-new-activity + on-shutdown cadence, restart-safety, the no-recursion
guarantee, and the offline-first (witness-unreachable) graceful path.

Same posture as test_checkpointing.py: no real network. register_checkpoint is
monkeypatched to a local fake (or a raising fake for the offline path). The
live-anchor leg (real registration against witness.agentactioncapsule.org) is
exercised manually and reported in the PR body, not in CI.
"""
from __future__ import annotations

import json
import threading

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, CheckpointError, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

import checkpoint_daemon
from checkpoint_daemon import DEFAULT_INTERVAL_SECONDS, build_state, run_daemon


def _signer(tmp_path) -> Ed25519Signer:
    return Ed25519Signer(tmp_path / "node-key.pem")


def _fake_capsule(i: int) -> dict:
    return {"capsule_id": f"{i:064x}", "n": i}


class _Clock:
    """A hand-cranked monotonic clock so the age cadence is deterministic."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        assert isinstance(checkpoint_cose, bytes)
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _state(tmp_path, clock, *, cadence_seconds=300, cadence_entries=10_000, ts_urls=("https://fake-ts.example",)):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(
        ts_urls=list(ts_urls), cadence_entries=cadence_entries,
        cadence_seconds=cadence_seconds, max_lag_entries=10_000,
    )
    # One log source: appends and the MMR sync see the same in-memory + on-disk
    # ledger. The age clock measures from when the daemon FIRST NOTICES a
    # pending entry (a sync that folds in new leaves) -- so a test that wants
    # the age leg to fire must: append, notice (tick/record_appended), advance
    # the clock past the interval, then tick again.
    return log, CheckpointState.load(
        ledger_dir=tmp_path, log_source=log,
        cfg=cfg, signer=_signer(tmp_path), log_id="log-a", clock=clock,
    )


# -- the ~5-minute clock: age-based cadence -----------------------------------


def test_tick_anchors_only_after_the_interval_elapses(tmp_path, fake_witness):
    """The age leg fires once `cadence_seconds` has passed since the first
    unwitnessed entry -- not before, and not on every tick."""
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=300)

    log.append(_fake_capsule(0))  # new activity at t=1000
    assert state.tick() is None  # daemon NOTICES the pending entry, clock starts here
    assert len(fake_witness) == 0

    clock.advance(299)
    assert state.tick() is None  # not yet due -- 299s < 300s since first-noticed
    assert len(fake_witness) == 0

    clock.advance(1)  # now exactly 300s since the entry was first noticed
    cp = state.tick()
    assert cp is not None
    assert len(fake_witness) == 1


def test_idle_interval_anchors_nothing_no_heartbeat(tmp_path, fake_witness):
    """only-if-new-activity: an interval with no new capsules must anchor
    NOTHING, no matter how much time passes -- no witness heartbeat that would
    leak 'node up but silent'."""
    clock = _Clock()
    _log, state = _state(tmp_path, clock, cadence_seconds=300)

    for _ in range(20):
        clock.advance(600)  # way past the interval, but the log is empty
        assert state.tick() is None
    assert len(fake_witness) == 0  # zero witness traffic across a totally idle node


def test_clock_measures_from_first_new_activity_after_an_anchor(tmp_path, fake_witness):
    """After an anchor clears the backlog, the clock restarts from the FIRST
    new entry -- not free-running -- so a quiet gap then a new entry still
    waits a full interval before the next anchor."""
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=300)

    log.append(_fake_capsule(0))
    assert state.tick() is None  # first notice
    clock.advance(300)
    assert state.tick() is not None  # anchored the first entry
    assert len(fake_witness) == 1

    # Long idle gap -- no new activity, no anchor.
    clock.advance(10_000)
    assert state.tick() is None
    assert len(fake_witness) == 1

    # New activity now: the clock starts when the daemon notices THIS entry,
    # not from the old anchor.
    log.append(_fake_capsule(1))
    assert state.tick() is None  # notice
    clock.advance(299)
    assert state.tick() is None  # only 299s since THIS entry was noticed
    clock.advance(1)
    assert state.tick() is not None
    assert len(fake_witness) == 2


def test_entry_count_leg_still_fires_before_the_clock(tmp_path, fake_witness):
    """whichever-comes-first: a burst that hits cadence_entries anchors
    immediately, without waiting out the age clock."""
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=10_000, cadence_entries=3)

    for i in range(3):
        log.append(_fake_capsule(i))
    cp = state.tick()  # 3 entries, cadence_entries=3 -> due on count, clock irrelevant
    assert cp is not None
    assert len(fake_witness) == 1


# -- record_appended never fires the time leg (serving path stays cheap) ------


def test_record_appended_does_not_fire_the_age_cadence(tmp_path, fake_witness):
    """The per-append serving-path leg must NOT anchor on age -- only tick()
    (the background clock) does. Otherwise the serving path would leak activity
    timing per-call, defeating the batch-on-a-clock privacy rationale."""
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=1, cadence_entries=10_000)

    log.append(_fake_capsule(0))
    assert state.record_appended() is None  # notices the entry; count leg not met
    clock.advance(10_000)  # ages way past cadence_seconds
    # record_appended NEVER consults the age leg, so even now it must not anchor.
    log.append(_fake_capsule(1))
    assert state.record_appended() is None
    assert len(fake_witness) == 0

    # But the background tick() DOES anchor it on the age leg (way past 1s).
    assert state.tick() is not None
    assert len(fake_witness) == 1


# -- on-shutdown flush --------------------------------------------------------


def test_checkpoint_on_shutdown_flushes_the_final_window(tmp_path, fake_witness):
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=300)

    log.append(_fake_capsule(0))
    log.append(_fake_capsule(1))
    # Not due (only 0s elapsed, count under threshold), but shutdown must still
    # commit the tail.
    assert state.tick() is None
    cp = state.checkpoint_on_shutdown()
    assert cp is not None
    assert len(fake_witness) == 1

    # A second shutdown flush with nothing new is a no-op.
    assert state.checkpoint_on_shutdown() is None
    assert len(fake_witness) == 1


# -- the daemon loop end to end ----------------------------------------------


def test_run_daemon_catches_up_ticks_and_flushes(tmp_path, fake_witness):
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=300)

    # A backlog exists BEFORE the daemon starts (a prior run wrote capsules).
    for i in range(2):
        log.append(_fake_capsule(i))

    stop = threading.Event()
    ticks = {"n": 0}

    # Drive the loop deterministically: our stop.wait override advances the
    # clock by one interval per iteration and stops after two ticks, so the
    # loop body's tick() sees the age cadence as due.
    def _fake_wait(timeout=None):
        ticks["n"] += 1
        clock.advance(300)
        if ticks["n"] == 1:
            log.append(_fake_capsule(2))  # new activity arrives during run
        if ticks["n"] >= 2:
            stop.set()
        return stop.is_set()

    stop.wait = _fake_wait  # type: ignore[assignment]

    emitted = run_daemon(state, interval_seconds=300, stop=stop)

    # startup reconnect (backlog of 2) + at least one tick anchor for entry 2.
    assert emitted >= 2
    # capsules.jsonl untouched by the checkpointer (no recursion) -- 3 lines.
    assert len((tmp_path / "capsules.jsonl").read_text().splitlines()) == 3
    # checkpoints landed in the sibling file.
    assert (tmp_path / "checkpoints.jsonl").exists()


# -- restart-safety / idempotence --------------------------------------------


def test_restart_resumes_from_last_checkpoint_and_chains(tmp_path, fake_witness):
    clock = _Clock()
    log, state = _state(tmp_path, clock, cadence_seconds=300)
    for i in range(3):
        log.append(_fake_capsule(i))
    first = state.reconnect()
    assert first is not None
    assert first.prev_size == 0
    assert len(fake_witness) == 1

    # More capsules land, then a "restart": a brand-new state over the same dir.
    for i in range(3, 5):
        log.append(_fake_capsule(i))

    clock2 = _Clock()
    _log2, state2 = _state(tmp_path, clock2, cadence_seconds=300)
    assert state2.last_checkpoint is not None
    assert state2.last_checkpoint.mmr_size == first.mmr_size  # resumed from disk

    second = state2.reconnect()
    assert second is not None
    assert second.prev_size == first.mmr_size  # chains from the prior checkpoint
    assert second.prev_root == first.root
    assert len(fake_witness) == 2

    # Idempotent: a further reconnect with nothing new is a no-op.
    assert state2.reconnect() is None
    assert len(fake_witness) == 2


# -- no recursion: the checkpoint is NEVER written into capsules.jsonl --------


def test_checkpointer_never_appends_to_capsules_jsonl(tmp_path, fake_witness):
    clock = _Clock()
    capsules_path = tmp_path / "capsules.jsonl"
    lines = [json.dumps(_fake_capsule(i), sort_keys=True) for i in range(4)]
    capsules_path.write_text("\n".join(lines) + "\n")
    before = capsules_path.read_bytes()

    _log, state = _state(tmp_path, clock, cadence_seconds=300)
    log = JsonlLogSource(capsules_path)  # noqa: F841 -- read-only, as the plugin path uses it
    assert state.reconnect() is not None
    clock.advance(300)
    state.tick()

    assert capsules_path.read_bytes() == before  # byte-for-byte unchanged
    assert (tmp_path / "checkpoints.jsonl").exists()  # stamps went to the sibling file


# -- offline-first: witness unreachable never crashes, retries next tick ------


def test_witness_unreachable_keeps_checkpointing_locally_then_recovers(tmp_path, monkeypatch):
    """Requirement 5: an unreachable witness must NOT crash the node. The
    checkpoint still commits locally (self-checkpointed), and a later tick,
    once the witness is back, registers the accrued history."""
    clock = _Clock()

    down = {"is": True}
    registered = []

    def _register(checkpoint_cose, ts_url, *, timeout=30.0):
        if down["is"]:
            raise CheckpointError("connection refused (witness down)")
        registered.append(ts_url)
        return WitnessRecord(
            ts_url=ts_url, entry_hash="h", receipt_b64="eA==",
            leaf_index=len(registered) - 1, tree_size=len(registered),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _register)

    log, state = _state(tmp_path, clock, cadence_seconds=300)
    log.append(_fake_capsule(0))
    assert state.tick() is None  # notice
    clock.advance(300)

    # Witness down: tick must still emit a LOCAL checkpoint, and NOT raise.
    cp = state.tick()
    assert cp is not None
    assert cp.witnesses == []  # self-checkpointed, not witnessed
    assert "NOT independently witnessed" in state.witness_status()
    assert registered == []  # nothing registered while down
    # The stamp is on disk locally regardless of the witness being down.
    assert (tmp_path / "checkpoints.jsonl").exists()

    # Witness recovers; new activity arrives; next tick registers.
    down["is"] = False
    log.append(_fake_capsule(1))
    assert state.tick() is None  # notice
    clock.advance(300)
    cp2 = state.tick()
    assert cp2 is not None
    assert registered == ["https://fake-ts.example"]
    # The recovery checkpoint chains over the locally-committed one (self-heals).
    assert cp2.prev_size == cp.mmr_size


# -- build_state: mesh defaults + config/flag override -------------------------


def test_build_state_defaults_to_300s_and_no_witness(tmp_path):
    state = build_state(
        ledger_dir=tmp_path, keys_dir=tmp_path, log_id="node-x",
        ts_urls=[], interval_seconds=DEFAULT_INTERVAL_SECONDS,
    )
    assert state.cfg.cadence_seconds == 300
    assert state.cfg.ts_urls == []  # anchoring opt-in
    assert state.log_id == "node-x"


def test_build_state_flags_override_config(tmp_path):
    cfg_path = tmp_path / "cp.toml"
    cfg_path.write_text(
        '[checkpoint]\nlog_id = "from-config"\ncadence_seconds = 900\n'
        'ts_urls = ["https://config-witness.example"]\n'
    )
    state = build_state(
        ledger_dir=tmp_path, keys_dir=tmp_path, log_id="ignored",
        ts_urls=["https://flag-witness.example"], interval_seconds=120,
        checkpoint_config_path=cfg_path,
    )
    assert state.log_id == "from-config"  # config log_id used
    assert state.cfg.cadence_seconds == 120  # flag overrides config's 900
    assert state.cfg.ts_urls == ["https://flag-witness.example"]  # flag replaces config's list


def test_build_state_rejects_config_without_checkpoint_table(tmp_path):
    cfg_path = tmp_path / "empty.toml"
    cfg_path.write_text("[other]\nx = 1\n")
    with pytest.raises(SystemExit):
        build_state(
            ledger_dir=tmp_path, keys_dir=tmp_path, log_id="x",
            ts_urls=[], interval_seconds=300, checkpoint_config_path=cfg_path,
        )
