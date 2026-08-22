# SPDX-License-Identifier: Apache-2.0
"""Layer 1-2 checkpointing (checkpointing.py): the LogSource adapter, cadence-
triggered + reconnect checkpointing, and the honest witness-state rendering.

No network calls in this file -- register_checkpoint is monkeypatched to a
local fake. The live-anchor leg (real registration + receipt verification
against anchor.agentactioncapsule.org) is exercised by
`run_checkpoint_demo.py --register-live-anchor`, run manually and reported in
the PR body, not in CI (see README "Checkpointing" honesty note).
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, MmrLedger, WitnessRecord
from checkpointing import (
    CheckpointState,
    Ed25519Signer,
    JsonlLogSource,
    describe_witness_state,
)
from scitt_cose import cll


def _signer(key_id: str = "node-a") -> Ed25519Signer:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return Ed25519Signer(key_id, pem)


def _fake_capsule(i: int) -> dict:
    return {"capsule_id": f"{i:064x}", "n": i}


@pytest.fixture
def fake_witness(monkeypatch):
    """Stand in for a real Transparency Service: same shape as
    register_checkpoint's return value, no network."""
    calls = []

    def _fake_register_checkpoint(cp, ts_url, *, timeout=30.0):
        calls.append((cp.digest(), ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


# -- JsonlLogSource -----------------------------------------------------


def test_jsonl_log_source_append_assigns_gapless_seq(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    records = [log.append(_fake_capsule(i)) for i in range(5)]
    assert [r.seq for r in records] == [1, 2, 3, 4, 5]
    assert [r.capsule_id for r in records] == [f"{i:064x}" for i in range(5)]


def test_jsonl_log_source_scan_matches_append_after_reload(tmp_path):
    ledger_path = tmp_path / "capsules.jsonl"
    log = JsonlLogSource(ledger_path)
    for i in range(4):
        log.append(_fake_capsule(i))

    reloaded = JsonlLogSource(ledger_path)  # a fresh instance, as a new process would create
    scanned = list(reloaded.scan())
    assert [r.seq for r in scanned] == [1, 2, 3, 4]
    assert scanned[2].capsule_id == f"{2:064x}"


def test_jsonl_log_source_fetch_by_capsule_id(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    for i in range(3):
        log.append(_fake_capsule(i))
    found = log.fetch(f"{1:064x}")
    assert found is not None
    assert found.seq == 2
    assert log.fetch("0" * 64 + "ff") is None  # not a real id in this ledger -- absent, not a partial match


def test_jsonl_log_source_scan_on_missing_file_is_empty(tmp_path):
    log = JsonlLogSource(tmp_path / "does-not-exist.jsonl")
    assert list(log.scan()) == []


# -- CheckpointState: cadence + persistence ------------------------------


def test_checkpoint_state_cadence_triggers_after_declared_count(tmp_path, fake_witness):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=3, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=_signer(), log_id="log-a")

    emitted = []
    for i in range(5):
        log.append(_fake_capsule(i))
        cp = state.record_appended()
        if cp is not None:
            emitted.append(cp)

    # cadence_entries=3: due once after the 3rd append, not before, not on every append.
    assert len(emitted) == 1
    assert len(fake_witness) == 1  # exactly one registration call, not zero and not one-per-entry


def test_checkpoint_persists_across_reload(tmp_path, fake_witness):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=2, max_lag_entries=10, ts_urls=["https://fake-ts.example"])
    signer = _signer("node-a")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id="log-a")
    for i in range(2):
        log.append(_fake_capsule(i))
        state.record_appended()
    assert state.last_checkpoint is not None

    # A fresh process: new JsonlLogSource + new CheckpointState reading the same ledger_dir.
    reloaded_log = JsonlLogSource(tmp_path / "capsules.jsonl")
    reloaded = CheckpointState.load(
        ledger_dir=tmp_path, log_source=reloaded_log, cfg=cfg, signer=signer, log_id="log-a"
    )
    assert reloaded.last_checkpoint is not None
    assert reloaded.last_checkpoint.mmr_size == state.last_checkpoint.mmr_size
    assert reloaded.last_checkpoint.root == state.last_checkpoint.root


def test_reconnect_self_heals_backlog_in_one_checkpoint(tmp_path, fake_witness):
    """Mesh architecture doc §4: an offline node keeps appending locally;
    on reconnect it submits ONE checkpoint committing everything accrued
    since the last witnessed one, chained via prev_size/prev_root -- not
    one checkpoint per missed cadence tick."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=100, max_lag_entries=200, ts_urls=["https://fake-ts.example"])
    signer = _signer("node-a")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id="log-a")

    for i in range(3):
        log.append(_fake_capsule(i))
        assert state.record_appended() is None  # cadence=100: nothing due yet

    first_cp = state.reconnect()  # simulate: node reconnects to its witness
    assert first_cp is not None
    assert first_cp.prev_size == 0
    assert len(fake_witness) == 1

    for i in range(3, 6):  # more capsules land while "offline" (no record_appended calls at all)
        log.append(_fake_capsule(i))

    second_cp = state.reconnect()
    assert second_cp is not None
    assert second_cp.prev_size == first_cp.mmr_size  # chains from the last witnessed checkpoint
    assert second_cp.prev_root == first_cp.root
    assert len(fake_witness) == 2  # one checkpoint for the whole 3-entry gap, not three

    # calling reconnect again with nothing new appended must be a no-op.
    assert state.reconnect() is None
    assert len(fake_witness) == 2


# -- honesty rendering: witnessed vs self-checkpointed -------------------


def test_describe_witness_state_never_says_witnessed_without_a_real_witness():
    """Mutant guard: a checkpoint with an EMPTY witnesses list must never be
    described as 'witnessed' -- that would overclaim third-party freshness
    evidence nobody provided (the same discipline as rung-2 D1's
    identity_limitation caveat, applied to logs instead of requesters)."""
    from capsule_emit.checkpoint import CheckpointRecord

    unwitnessed = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=3, root="aa" * 32,
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
    )
    line = describe_witness_state(unwitnessed, current_entries=2)
    assert "witnessed" not in line.split("NOT independently ")[0] or "NOT independently witnessed" in line
    assert "NOT independently witnessed" in line
    assert not line.startswith("witnessed")

    witnessed = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=3, root="aa" * 32,
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
        witnesses=[WitnessRecord(ts_url="https://ts.example", entry_hash="x", receipt_b64="eA==", leaf_index=0, tree_size=1)],
    )
    line2 = describe_witness_state(witnessed, current_entries=2)
    assert line2.startswith("witnessed up to entry")
    assert "NOT independently witnessed" not in line2


def test_describe_witness_state_no_checkpoint_yet_is_unwitnessed():
    line = describe_witness_state(None, current_entries=7)
    assert "unwitnessed" in line
    assert "7 entries" in line


def test_describe_witness_state_surfaces_lag_when_log_outgrew_checkpoint():
    from capsule_emit.checkpoint import CheckpointRecord

    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log-a", mmr_size=1, root="aa" * 32,  # size=1 -> leaf_count=1
        prev_size=0, prev_root="", key_id="node-a",
        timestamp="2026-08-21T00:00:00Z", signature="deadbeef",
    )
    line = describe_witness_state(cp, current_entries=5)
    assert "4 more entries appended since" in line


# -- offline inclusion verification (scitt_cose.cll), fully hermetic ----


def test_offline_inclusion_verify_round_trips_through_cll(tmp_path):
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    for i in range(6):
        log.append(_fake_capsule(i))

    mmr = MmrLedger(log)
    mmr.sync()
    signer = _signer("node-a")
    from capsule_emit.checkpoint import emit_checkpoint

    cp = emit_checkpoint(mmr, signer, log_id="log-a", timestamp="2026-08-21T00:00:00Z")
    # scitt_cose.cll.Checkpoint.from_dict still hard-requires a `peaks_digest` key
    # left over from a shape capsule_emit.checkpoint no longer emits (single-
    # commitment CheckpointRecord, 2026-08-22 Option-C ruling) -- the field is
    # provably unread by any cll.py verification path. See
    # verify_real_deployment_checkpoint.py's cll_checkpoint_from_record() for
    # the full note; flagged in the outbox report as a live cross-repo divergence.
    cll_checkpoint = cll.Checkpoint.from_dict({**cp.to_dict(), "peaks_digest": ""})

    target_seq = 3
    proof = mmr.inclusion_proof(target_seq, size=cp.mmr_size)
    cll_proof = cll.InclusionProof.from_dict(
        {
            "v": proof.v, "kind": proof.kind, "size": proof.size, "leaf_index": proof.leaf_index,
            "witness": list(proof.witness), "peaks_left": list(proof.peaks_left), "peaks_right": list(proof.peaks_right),
        }
    )
    body_digest = bytes.fromhex(f"{target_seq - 1:064x}")
    result = cll.verify_leaf_against_checkpoint(
        body_digest=body_digest, leaf_index=target_seq - 1, checkpoint=cll_checkpoint, proof=cll_proof,
    )
    assert result.ok, result.errors

    # mutant: a tampered body_digest (wrong leaf content) must fail, not silently pass.
    tampered_digest = bytes.fromhex(f"{target_seq:064x}")  # a different, real leaf's digest
    mutant_result = cll.verify_leaf_against_checkpoint(
        body_digest=tampered_digest, leaf_index=target_seq - 1, checkpoint=cll_checkpoint, proof=cll_proof,
    )
    assert not mutant_result.ok
