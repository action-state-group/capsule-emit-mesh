#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-sequence-per-counterparty] Per-(self, counterparty) monotone seq.

Two layers under test:

  1. `sequence_counter.py` in isolation -- `SequenceCounterStore.next_seq`
     (persistence, independence across pairs) and `verify_pair_continuity`
     (unbroken / gap / regression classification), with no capsule_sidecar
     involvement at all.
  2. `capsule_sidecar.build_capsule` actually embedding `seq`/`prev_seq` into
     `serving_provenance`, keyed the way the task specifies: requester side
     on `served_by_node_id`, provider side on `requesting_party` -- and the
     MUTANT the task names: resetting the counter CACHE file must not look
     like a fresh start to a verifier walking the actual sealed ledger.

MODULE-POLLUTION GUARD: mirrors test_requester_seal_exchange_correlation.py --
sibling test files setattr fakes onto the shared agent_action_capsule/
model_identity modules at collection time, so real modules are reloaded at
EXECUTION time.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import capsule_sidecar as cs
from sequence_counter import (
    UNKNOWN_COUNTERPARTY,
    SequenceCounterStore,
    pair_key,
    verify_pair_continuity,
)

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _real_capsule_sidecar():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


def _state(tmp_path: Path, *, role: str, node_id: str, ledger_dir: Path | None = None) -> "cs.NodeState":
    _real_capsule_sidecar()
    manifest_path = tmp_path / f"manifest-{node_id}.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs.default_state(
        ledger_dir=ledger_dir or (tmp_path / f"ledger-{node_id}"),
        manifest_path=manifest_path,
        keys_dir=tmp_path / f"keys-{node_id}",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=role,
        node_id=node_id,
    )


def _serving_provenance(capsule: dict) -> dict:
    poc = capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    return poc["serving_provenance"]


def _seal(state: "cs.NodeState", *, exchange_id: str = "chatcmpl-fixed") -> dict:
    cs_mod = _real_capsule_sidecar()
    return cs_mod.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="client_supplied",
        request_json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
        exchange_id=exchange_id,
        exchange_id_source="response_id",
    )


# ---------------------------------------------------------------------------
# 1. SequenceCounterStore in isolation
# ---------------------------------------------------------------------------


def test_next_seq_starts_at_one_and_increments_per_pair(tmp_path: Path) -> None:
    store = SequenceCounterStore(tmp_path / "sequence_counters.json")
    seq1, prev1 = store.next_seq("node-a", "node-b")
    assert (seq1, prev1) == (1, None)
    seq2, prev2 = store.next_seq("node-a", "node-b")
    assert (seq2, prev2) == (2, 1)
    # A different counterparty is an independent counter starting at 1.
    seq3, prev3 = store.next_seq("node-a", "node-c")
    assert (seq3, prev3) == (1, None)


def test_missing_counterparty_collapses_to_unknown_bucket_never_invented() -> None:
    assert pair_key("node-a", None) == f"node-a::{UNKNOWN_COUNTERPARTY}"
    assert pair_key("node-a", "") == f"node-a::{UNKNOWN_COUNTERPARTY}"
    assert pair_key("node-a", "node-b") == "node-a::node-b"


def test_counter_state_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "sequence_counters.json"
    store = SequenceCounterStore(path)
    store.next_seq("node-a", "node-b")
    store.next_seq("node-a", "node-b")
    # Fresh store instance from the SAME file -- a restarted process resumes
    # at 3, never repeats 1.
    reopened = SequenceCounterStore(path)
    seq, prev = reopened.next_seq("node-a", "node-b")
    assert (seq, prev) == (3, 2)


def test_corrupt_counter_file_never_crashes_starts_empty_not_invented(tmp_path: Path) -> None:
    path = tmp_path / "sequence_counters.json"
    path.write_text("not json{{{")
    store = SequenceCounterStore(path)
    seq, prev = store.next_seq("node-a", "node-b")
    assert (seq, prev) == (1, None)


def test_verify_pair_continuity_reports_unbroken_for_a_clean_sequence() -> None:
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 2, "prev_seq": 1,
        }}}}},
    ]
    result = verify_pair_continuity(capsules)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity == "unbroken"
    assert pair.gaps_detected == 0
    assert pair.records_checked == 2


def test_verify_pair_continuity_labels_a_dropped_record_as_a_gap_not_broken() -> None:
    """Dropping capsule seq=2 from a bundle (delivered as 1,3) is a labeled
    GAP, not a break -- the underlying stream is still monotone, just
    incomplete as delivered."""
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 3, "prev_seq": 2,
        }}}}},
    ]
    result = verify_pair_continuity(capsules)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity == "unbroken"
    assert pair.gaps_detected == 1


def test_verify_pair_continuity_flags_a_reset_as_broken_not_a_fresh_start() -> None:
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 2, "prev_seq": 1,
        }}}}},
        # Counter cache wiped; sealing resumed as if this were a new pair.
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
    ]
    result = verify_pair_continuity(capsules)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity.startswith("broken"), pair.continuity


def test_verify_pair_continuity_detects_a_dropped_prefix_via_first_record_prev_seq() -> None:
    """ADV-5: dropping records 1..3 leaves the walk seeing only seq=4, whose
    own `prev_seq` still claims a predecessor. That claim must surface as a
    gap, never a clean, untroubled fresh start."""
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 4, "prev_seq": 3,
        }}}}},
    ]
    result = verify_pair_continuity(capsules)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity == "unbroken"
    assert pair.gaps_detected == 3, "records 1..3 were never seen and must count as a gap"


def test_verify_pair_continuity_flags_a_lying_prev_seq_as_broken() -> None:
    """ADV-5: a record whose `prev_seq` does not actually precede its own
    `seq` (a lying `prev_seq`, unrelated to what `next_seq` would ever
    issue) must be flagged broken even though `seq` alone still looks
    monotone."""
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
        # Honest seq (2, monotone) but a fabricated prev_seq.
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 2, "prev_seq": 99,
        }}}}},
    ]
    result = verify_pair_continuity(capsules)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity.startswith("broken"), pair.continuity


def test_verify_pair_continuity_detects_a_dropped_trail_via_checkpoint_cross_check() -> None:
    """ADV-5: dropping the TRAIL (the last record of a pair) is invisible to
    any in-band check -- nothing in the delivered records hints a further
    one ever existed. Only an outside anchor (a checkpoint attesting to the
    true covered count) can catch it."""
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 1, "prev_seq": None,
        }}}}},
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3", "seq": 2, "prev_seq": 1,
        }}}}},
        # seq=3, the pair's true last record, was dropped from delivery.
    ]
    result = verify_pair_continuity(capsules, checkpoint_covered_count=3)
    pair = result[pair_key("m4", "m3")]
    assert pair.continuity.startswith("broken"), pair.continuity

    # The same records with no checkpoint anchor, or one that matches what
    # was actually delivered, are honestly unbroken.
    honest = verify_pair_continuity(capsules, checkpoint_covered_count=2)
    assert honest[pair_key("m4", "m3")].continuity == "unbroken"
    unanchored = verify_pair_continuity(capsules)
    assert unanchored[pair_key("m4", "m3")].continuity == "unbroken"


def test_records_with_no_seq_are_excluded_not_assigned_a_fabricated_one() -> None:
    """A pre-feature record (no `seq` field at all) is simply skipped -- never
    backfilled with an invented sequence number."""
    capsules = [
        {"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {"serving_provenance": {
            "role": "provider", "served_by_node_id": "m4", "requesting_party": "m3",
        }}}}},
    ]
    assert verify_pair_continuity(capsules) == {}


# ---------------------------------------------------------------------------
# 2. capsule_sidecar.build_capsule embeds seq/prev_seq correctly per role
# ---------------------------------------------------------------------------


def test_provider_role_seals_seq_keyed_on_requesting_party(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="m3")
    cap1 = _seal(state)
    cap2 = _seal(state)
    sp1, sp2 = _serving_provenance(cap1), _serving_provenance(cap2)
    assert (sp1["seq"], sp1["prev_seq"]) == (1, None)
    assert (sp2["seq"], sp2["prev_seq"]) == (2, 1)


def test_requester_role_seals_seq_keyed_on_served_by_node_id(tmp_path: Path) -> None:
    """The requester side is keyed on served_by_node_id per the task spec --
    which stays "unknown" until the requester can actually observe who
    served it (a live-mesh gap tracked separately), so repeated requester
    seals with no served_by_node_id land in the SAME "unknown" bucket and
    still sequence monotonically within it -- never a fabricated peer id."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="m4")
    cap1 = _seal(state)
    cap2 = _seal(state)
    sp1, sp2 = _serving_provenance(cap1), _serving_provenance(cap2)
    assert sp1["served_by_node_id"] == "unknown"
    assert (sp1["seq"], sp1["prev_seq"]) == (1, None)
    assert (sp2["seq"], sp2["prev_seq"]) == (2, 1)


def test_different_counterparties_get_independent_counters(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="m3")

    # bilateral_eval absent -> requesting_party defaults to "unknown" for
    # every call in this harness, so simulate a second counterparty by
    # sealing into a second ledger under a different self node id instead --
    # this still proves pairs are independent counters (the pair key is the
    # unit, not the process).
    other_state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="m5")
    cap_m3 = _seal(state)
    cap_m5 = _seal(other_state)
    sp_m3, sp_m5 = _serving_provenance(cap_m3), _serving_provenance(cap_m5)
    assert (sp_m3["seq"], sp_m3["prev_seq"]) == (1, None)
    assert (sp_m5["seq"], sp_m5["prev_seq"]) == (1, None)


# ---------------------------------------------------------------------------
# 3. Acceptance shape + the task's own mutant, over a REAL sealed ledger
# ---------------------------------------------------------------------------


def test_two_exchanges_for_one_pair_seal_seq_1_then_2_into_the_ledger(tmp_path: Path) -> None:
    """Mirrors the acceptance shape (two exchanges for one pair showing
    seq 1,2) without a live two-node mesh: seals two capsules for the SAME
    (self, counterparty) pair straight into one node's real ledger via
    `record_capsule`, then reads the ledger back and confirms
    `verify_pair_continuity` -- reading ONLY the sealed capsules, never the
    counter cache -- reports an unbroken seq 1,2 pair."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="m3")
    for _ in range(2):
        capsule = _seal(state)
        statement = cs_mod.sign_capsule(state, capsule)
        cs_mod.record_capsule(state, capsule, statement)

    ledger_capsules = [json.loads(line) for line in state.ledger_path.read_text().splitlines() if line.strip()]
    assert len(ledger_capsules) == 2
    seqs = [_serving_provenance(c)["seq"] for c in ledger_capsules]
    assert seqs == [1, 2]

    result = verify_pair_continuity(ledger_capsules)
    pair = result[pair_key("m3", UNKNOWN_COUNTERPARTY)]
    assert pair.continuity == "unbroken"
    assert pair.gaps_detected == 0
    assert pair.records_checked == 2


def test_resetting_the_counter_cache_file_is_flagged_broken_not_a_fresh_start(tmp_path: Path) -> None:
    """THE TASK'S OWN MUTANT: reset `sequence_counters.json` mid-stream (a bug,
    or an attacker trying to make a pair look fresh) -- the verifier, which
    reads the LEDGER and never trusts the cache, must catch the resulting
    regression, not treat it as a fresh pair."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="m3")

    def seal_and_record() -> None:
        capsule = _seal(state)
        statement = cs_mod.sign_capsule(state, capsule)
        cs_mod.record_capsule(state, capsule, statement)

    seal_and_record()
    seal_and_record()
    # The ledger itself is untouched; only the write-side cache is wiped.
    state.sequence_counters.path.unlink()
    state.sequence_counters._state.clear()
    seal_and_record()

    ledger_capsules = [json.loads(line) for line in state.ledger_path.read_text().splitlines() if line.strip()]
    seqs = [_serving_provenance(c)["seq"] for c in ledger_capsules]
    assert seqs == [1, 2, 1], "confirms the reset cache really does reissue seq=1"

    result = verify_pair_continuity(ledger_capsules)
    pair = result[pair_key("m3", UNKNOWN_COUNTERPARTY)]
    assert pair.continuity.startswith("broken"), pair.continuity
