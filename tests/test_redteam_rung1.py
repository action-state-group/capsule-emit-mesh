# SPDX-License-Identifier: Apache-2.0
"""B5a — adversarial red-team of DEPLOYED rung-1 accountability.

Rung 1 is: a signed, zero-retention, hash-chained capsule ledger + a local MMR
(Layer 1) + periodic signed checkpoints (Layer 2) + independent witnessing
(Layer 3, `register_checkpoint`). This module attacks ONLY what rung 1 alone
buys. It does NOT lean on the config-fingerprint (B2) or binary attestation
(B3) -- those are separate rungs.

For each attack we build a concrete harness against a real (throwaway) ledger +
the checkpoint/witness machinery and record the outcome as one of:

    CAUGHT     -- the machinery rejects it (a verify goes RED)
    LABELED    -- it is not rejected but is named honestly in the record
    RESIDUAL   -- it succeeds and rung 1 alone cannot see it (the product of
                  this exercise; the closing rung is named in the assertion)

The findings table is `docs/REDTEAM-RUNG1.md`. Each test below is the executable
evidence for one row of that table; the docstrings and the table must agree.

No network: `register_checkpoint` is monkeypatched to a local fake witness that
counter-signs whatever COSE-wire checkpoint it is handed (an HONEST witness --
it signs INTEGRITY, it does not and cannot assert COVERAGE, which is the whole
point of attack 4).
"""
from __future__ import annotations

import json

import pytest

import checkpointing
from capsule_emit.checkpoint import (
    CheckpointConfig,
    MmrLedger,
    WitnessRecord,
    verify_checkpoint_consistency,
)
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource


# --------------------------------------------------------------------------
# Shared fixtures: a throwaway ledger + an HONEST fake witness (no network).
# --------------------------------------------------------------------------


def _capsule(i: int, *, status: str = "confirmed") -> dict:
    """A minimal capsule shaped enough for the MMR/checkpoint machinery.

    `capsule_id` is the leaf identity the MMR folds; `status` distinguishes a
    sealed success (`confirmed`) from a sealed failure (`failed`) for the
    selective-log attack.
    """
    return {"capsule_id": f"{i:064x}", "n": i, "status": status}


@pytest.fixture
def fake_witness(monkeypatch):
    """An HONEST independent witness with no network.

    It counter-signs every COSE-wire checkpoint POSTed to it and hands back a
    WitnessRecord, exactly as the real Transparency Service does. Crucially it
    is honest: it attests only that IT SAW this checkpoint (integrity), never
    that the checkpoint COVERS every exchange the node handled. Attack 4 shows
    that an honest witness cannot close the coverage gap.
    """
    calls: list[tuple[bytes, str]] = []

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


def _new_state(tmp_path, *, ts_urls=(), log_id="node-a") -> tuple[CheckpointState, JsonlLogSource]:
    ledger_dir = tmp_path
    caps = ledger_dir / "capsules.jsonl"
    log = JsonlLogSource(caps)
    signer = Ed25519Signer(ledger_dir / "node-key.pem")
    cfg = CheckpointConfig(ts_urls=list(ts_urls))
    state = CheckpointState.load(
        ledger_dir=ledger_dir, log_source=log, cfg=cfg, signer=signer, log_id=log_id
    )
    return state, log


# ==========================================================================
# ATTACK 1 — LEDGER EQUIVOCATION  ->  outcome: CAUGHT
# ==========================================================================
#
# Mechanism: the node tries to show two different histories at the same
# position -- rewrite/rollback the hash-chained log (change an already-sealed
# entry, or fork it) while keeping the same length, then present a divergent
# ledger. The defence under test is the checkpoint's root commitment and the
# consistency proof verified against the witnessed checkpoint.
# ==========================================================================


def test_attack1_equivocation_rewrite_breaks_root(tmp_path, fake_witness):
    """A rewritten entry at the SAME size recomputes to a DIFFERENT root than
    the one the (witnessed) checkpoint signed -> CAUGHT.

    This is the classic fork/rollback shape: same position, same count,
    different content. The MMR root is a commitment over content, so any
    rewrite of an already-checkpointed leaf makes the recomputed root diverge
    from the signed one.
    """
    ledger_dir = tmp_path / "L"
    ledger_dir.mkdir()
    state, log = _new_state(ledger_dir, ts_urls=["https://witness.example"])
    for i in range(4):
        log.append(_capsule(i))
    cp = state.reconnect()
    assert cp is not None and cp.witnesses, "checkpoint should be witnessed by the fake TS"

    # Baseline: the honest log recomputes to exactly the signed root.
    honest_root = state.mmr.root_at(cp.mmr_size).hex()
    assert honest_root == cp.root

    # Equivocate: fork a COPY, rewrite an already-checkpointed leaf, keep size.
    fork_dir = tmp_path / "F"
    fork_dir.mkdir()
    lines = (ledger_dir / "capsules.jsonl").read_text().splitlines()
    forged = json.loads(lines[0])
    forged["capsule_id"] = "e" * 64  # different content, same position
    lines[0] = json.dumps(forged, sort_keys=True)
    (fork_dir / "capsules.jsonl").write_text("\n".join(lines) + "\n")

    forked_mmr = MmrLedger(JsonlLogSource(fork_dir / "capsules.jsonl"))
    forked_mmr.sync()
    forked_root = forked_mmr.root_at(cp.mmr_size).hex()

    # The forged history CANNOT reproduce the witnessed root: equivocation caught.
    assert forked_root != cp.root, "equivocation MUST be caught: forked root must differ"


def test_attack1_equivocation_consistency_proof_goes_red(tmp_path, fake_witness):
    """The consistency proof of the honest checkpoints, re-verified against a
    FORKED MMR, goes RED -> CAUGHT.

    An equivocating node that presents a divergent ledger cannot also produce a
    valid consistency proof from an earlier witnessed checkpoint into that
    divergent ledger: `verify_checkpoint_consistency` recomputes the root at
    the prior size from the presented store and it will not match.
    """
    ledger_dir = tmp_path / "L"
    ledger_dir.mkdir()
    state, log = _new_state(ledger_dir, ts_urls=["https://witness.example"])
    for i in range(3):
        log.append(_capsule(i))
    cp1 = state.reconnect()
    for i in range(3, 6):
        log.append(_capsule(i))
    cp2 = state.reconnect()

    # Honest chain: cp2 provably extends cp1.
    assert verify_checkpoint_consistency(cp1, cp2, state.mmr) is True

    # Fork the log after cp1 was witnessed, then re-check cp1 -> cp2.
    fork_dir = tmp_path / "F"
    fork_dir.mkdir()
    lines = (ledger_dir / "capsules.jsonl").read_text().splitlines()
    forged = json.loads(lines[0])
    forged["capsule_id"] = "d" * 64
    lines[0] = json.dumps(forged, sort_keys=True)
    (fork_dir / "capsules.jsonl").write_text("\n".join(lines) + "\n")
    forked_mmr = MmrLedger(JsonlLogSource(fork_dir / "capsules.jsonl"))
    forked_mmr.sync()

    assert verify_checkpoint_consistency(cp1, cp2, forked_mmr) is False, (
        "equivocation MUST be caught: consistency proof over a forked log must fail"
    )


# ==========================================================================
# ATTACK 2 — NONCE REPLAY  ->  outcome: LABELED (in-lifetime), RESIDUAL (across
#            restart / across nodes)
# ==========================================================================
#
# Mechanism: replay a captured genuine `client_nonce` verbatim on a later,
# unrelated exchange, to make a precomputed/stale record look freshly bound to
# THIS exchange. The defence under test is `_resolve_client_nonce`'s dedup +
# honest labeling.
# ==========================================================================


def test_attack2_nonce_replay_within_lifetime_is_labeled(tmp_path):
    """A replayed client nonce within one node lifetime is not silently
    accepted as fresh -- it is LABELED `client_supplied_replayed`.
    """
    from capsule_sidecar import NodeState, _resolve_client_nonce, CLIENT_NONCE_HEADER

    state = NodeState.__new__(NodeState)
    state.seen_client_nonces = set()

    hdr = {CLIENT_NONCE_HEADER.lower(): "nonce-abc"}
    nonce1, src1 = _resolve_client_nonce(state, hdr)
    assert (nonce1, src1) == ("nonce-abc", "client_supplied")

    # Replay the exact same nonce -> named, not hidden.
    nonce2, src2 = _resolve_client_nonce(state, hdr)
    assert (nonce2, src2) == ("nonce-abc", "client_supplied_replayed"), (
        "replay MUST be labeled, never silently upgraded to client_supplied"
    )


def test_attack2_nonce_replay_across_restart_is_residual(tmp_path):
    """`seen_client_nonces` is in-memory and per-NodeState: a fresh NodeState
    (a process restart) does NOT remember the earlier nonce, so the SAME replay
    reads as `client_supplied` again -> RESIDUAL across restart/node.

    Documented honestly in `_resolve_client_nonce`'s own docstring; closing it
    needs a shared/persistent seen-store, out of scope for the PoC sidecar.
    """
    from capsule_sidecar import NodeState, _resolve_client_nonce, CLIENT_NONCE_HEADER

    hdr = {CLIENT_NONCE_HEADER.lower(): "nonce-xyz"}

    state_before = NodeState.__new__(NodeState)
    state_before.seen_client_nonces = set()
    _, src_first = _resolve_client_nonce(state_before, hdr)
    assert src_first == "client_supplied"

    # Simulate a restart: a brand-new NodeState with an empty seen-set.
    state_after = NodeState.__new__(NodeState)
    state_after.seen_client_nonces = set()
    _, src_after_restart = _resolve_client_nonce(state_after, hdr)
    # The residual: the replay is invisible to a restarted node.
    assert src_after_restart == "client_supplied", (
        "across a restart the replay is NOT caught -- this is the documented residual"
    )


# ==========================================================================
# ATTACK 3 — DROPPED / WITHHELD CHECKPOINT  ->  outcome: LABELED (lag surfaced)
# ==========================================================================
#
# Mechanism: the node skips or withholds a checkpoint -- it keeps appending but
# does not anchor the tail (or hides the newest checkpoint). The question is
# the detection story from the verifier's side.
# ==========================================================================


def test_attack3_dropped_checkpoint_surfaces_as_lag(tmp_path, fake_witness):
    """Withholding the anchor for new entries surfaces as an honest LAG count
    in the witness state -- the newest entries are named as NOT-yet-witnessed,
    never silently folded into the last witnessed size -> LABELED.
    """
    ledger_dir = tmp_path / "L"
    ledger_dir.mkdir()
    state, log = _new_state(ledger_dir, ts_urls=["https://witness.example"])
    for i in range(3):
        log.append(_capsule(i))
    cp = state.reconnect()
    assert cp is not None and cp.witnesses

    # Append more, then DROP the checkpoint (never anchor the tail).
    for i in range(3, 7):
        log.append(_capsule(i))
    state.mmr.sync()  # a verifier syncs the live log but sees no new checkpoint

    status = state.witness_status()
    # The witness state names the un-anchored tail rather than hiding it.
    assert "more entr" in status, f"dropped-checkpoint lag must be named, got: {status!r}"
    assert "witnessed up to entry 3" in status, (
        f"witnessed watermark must stay at the last anchored size, got: {status!r}"
    )


def test_attack3_withheld_newest_checkpoint_leaves_stale_watermark(tmp_path, fake_witness):
    """If the node hides its NEWEST checkpoint and presents only an older one,
    a verifier reading the presented checkpoints sees a witnessed watermark
    BELOW the live log height -- the gap is visible as lag, not concealable as
    "fully witnessed" -> LABELED.

    Note the honest boundary of this row: lag tells a verifier the tail is
    unwitnessed. It does NOT by itself force the node to EVER anchor. A node
    that simply stops checkpointing shows as perpetually-lagging, which is the
    detection signal a requester/monitor keys off (that push is B6a's job, not
    rung 1's).
    """
    ledger_dir = tmp_path / "L"
    ledger_dir.mkdir()
    state, log = _new_state(ledger_dir, ts_urls=["https://witness.example"])
    for i in range(2):
        log.append(_capsule(i))
    cp_old = state.reconnect()
    old_watermark_size = cp_old.mmr_size

    # More activity + a real newer checkpoint, which the node then WITHHOLDS
    # (a verifier is handed only cp_old).
    for i in range(2, 5):
        log.append(_capsule(i))
    cp_new = state.reconnect()
    assert cp_new.mmr_size > old_watermark_size

    # Verifier posture: live log synced, but only cp_old presented.
    from checkpointing import describe_witness_state

    live_leaf_count = state.mmr.leaf_count()
    presented = describe_witness_state(cp_old, live_leaf_count)
    assert "more entr" in presented, (
        f"withheld newer checkpoint must surface as lag against cp_old, got: {presented!r}"
    )


# ==========================================================================
# ATTACK 4 — SELECTIVE-LOG (THE BIG ONE)  ->  outcome: RESIDUAL (uncaught)
# ==========================================================================
#
# Mechanism: an HONEST, fully witnessed log that simply NEVER SEALS FAILURES.
# Every entry it does seal is genuine, chained, checkpointed and witnessed --
# a perfect, witness-consistent chain -- but the set of exchanges it chose to
# seal is a fraudulent subset (all successes, no failures). This is the
# coverage gap: the witness proves INTEGRITY of what was logged, never
# COVERAGE of what happened.
#
# This attack SHOULD SUCCEED against rung 1 alone. That is the point. The
# counter is requester-side correlation (B6a), which is OUT OF SCOPE here.
# ==========================================================================


def test_attack4_selective_log_is_perfectly_witness_consistent(tmp_path, fake_witness):
    """A log that seals only successes and silently drops every failure is
    INDISTINGUISHABLE, to the checkpoint+witness machinery, from an honest,
    complete log -> RESIDUAL (uncaught by rung 1 alone).

    We build TWO ledgers from the SAME sequence of exchanges:
      * honest_full   -- seals every exchange (successes AND failures)
      * selective     -- seals ONLY the successes, drops the failures

    Both are checkpointed and witnessed. We then assert that the selective log
    passes every integrity check the witness/consistency machinery offers --
    nothing rung 1 has can tell it apart from a truthful log. The only thing
    that differs is the SET of exchanges represented, and rung 1 never had a
    view of the true set to compare against.
    """
    # --- the ground-truth stream of exchanges the node actually handled ---
    exchanges = [
        _capsule(0, status="confirmed"),
        _capsule(1, status="failed"),      # <- a failure the node wants to hide
        _capsule(2, status="confirmed"),
        _capsule(3, status="failed"),      # <- another hidden failure
        _capsule(4, status="confirmed"),
    ]

    # --- honest_full: seals EVERYTHING ---
    honest_dir = tmp_path / "honest"
    honest_dir.mkdir()
    honest_state, honest_log = _new_state(honest_dir, ts_urls=["https://witness.example"], log_id="honest")
    for ex in exchanges:
        honest_log.append(ex)
    honest_cp = honest_state.reconnect()

    # --- selective: seals ONLY the successes ---
    selective_dir = tmp_path / "selective"
    selective_dir.mkdir()
    selective_state, selective_log = _new_state(
        selective_dir, ts_urls=["https://witness.example"], log_id="selective"
    )
    for ex in exchanges:
        if ex["status"] == "confirmed":
            selective_log.append(ex)   # failures are simply never recorded
    selective_cp = selective_state.reconnect()

    # 1) The selective log IS witnessed -- the honest fake TS counter-signed it.
    assert selective_cp is not None and selective_cp.witnesses, (
        "selective log is fully witnessed -- that is exactly why the attack works"
    )

    # 2) Its checkpoint root is internally valid: recomputing the root at the
    #    signed size from the selective log reproduces the signed root. The
    #    fraud leaves NO internal inconsistency to detect.
    recomputed = selective_state.mmr.root_at(selective_cp.mmr_size).hex()
    assert recomputed == selective_cp.root, (
        "selective log is internally perfect -- no integrity check can flag it"
    )

    # 3) A verifier holding ONLY the selective ledger + its witnessed checkpoint
    #    sees a clean, consistent, witnessed chain. Every property rung 1
    #    offers is GREEN. The witness proved integrity; it never proved coverage.
    selective_status = selective_state.witness_status()
    assert selective_status.startswith("witnessed up to entry 3"), (
        f"selective log presents a clean 'witnessed' state, got: {selective_status!r}"
    )

    # 4) THE RESIDUAL, stated as an assertion: the honest log and the selective
    #    log commit to DIFFERENT roots (they cover different sets), yet rung 1
    #    gives a verifier NO handle to know the selective root is the fraudulent
    #    one -- there is no rung-1 artifact that encodes "how many exchanges
    #    truly happened". Both are, in isolation, perfectly witness-consistent.
    assert honest_cp.root != selective_cp.root
    # The count difference (5 vs 3) is the fraud, and it is INVISIBLE without an
    # independent record of the true count -- i.e. requester-side correlation.
    from capsule_emit.checkpoint import leaf_count as _leaf_count_at_size

    assert _leaf_count_at_size(honest_cp.mmr_size) == 5
    assert _leaf_count_at_size(selective_cp.mmr_size) == 3
    # Rung 1 alone cannot assert the second is a fraudulent subset of the first.
    # CLOSED BY: B6a (requester-side correlation / requester-held receipts),
    # which supplies the independent count rung 1 structurally lacks.


def test_attack4_witness_cannot_assert_coverage(tmp_path, fake_witness):
    """Direct statement of the coverage limitation: the WitnessRecord returned
    for the selective log carries no field that constrains WHICH or HOW MANY
    exchanges the node handled -- only that this checkpoint was seen. Proof
    that the witness attests integrity, not coverage.
    """
    selective_dir = tmp_path / "selective"
    selective_dir.mkdir()
    state, log = _new_state(selective_dir, ts_urls=["https://witness.example"], log_id="selective")
    for i in range(3):
        log.append(_capsule(i, status="confirmed"))
    cp = state.reconnect()

    witness = cp.witnesses[0]
    fields = witness.to_dict() if hasattr(witness, "to_dict") else vars(witness)
    # The witness record commits to the checkpoint it saw (tree position, entry
    # hash, receipt) -- nothing about the node's TRUE exchange count/set.
    assert "tree_size" in fields or "leaf_index" in fields
    # There is no "coverage" / "total_exchanges_handled" attestation anywhere:
    assert not any("coverage" in str(k).lower() for k in fields), (
        "an honest witness asserts integrity, never coverage -- residual is real"
    )
