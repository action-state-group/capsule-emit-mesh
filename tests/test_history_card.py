# SPDX-License-Identifier: Apache-2.0
"""`history_card()`: checkpoints + receipts + consistency proofs since size
S, folded into properties (continuity/history_depth/unforked/cadence) -- and
its offline verifier.

Builds REAL checkpoint chains through `checkpointing.CheckpointState` (same
COSE-wire consistency-proof path `test_checkpointing.py` exercises), never
hand-rolled fixtures that would let the card's chain walk pass trivially.
"""
from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

import checkpointing
from agent_action_capsule.canonical import FloatInDigestError
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.checkpoint import CheckpointConfig, MmrLedger, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

from history_card import (
    COVERAGE_UNSATISFIABLE,
    FORKS_STATE_ABSENT,
    FORKS_STATE_OK,
    FORKS_STATE_UNREADABLE,
    HISTORY_CHAIN_RELATION,
    MESH_HISTORY_DEFINITION_DIGEST,
    REQUEST_MALFORMED,
    answer_full_history_request,
    build_history_card,
    node_id_from_key_id,
    reconciliation_counts_from_ledger_dir,
    seal_history_card,
    verify_history_card,
    with_peer_reconciliation,
    with_references,
)


def _fake_capsule(i: int) -> dict:
    return {"capsule_id": f"{i:064x}", "n": i}


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
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


def _build_chain(tmp_path, n_checkpoints: int, *, log_id: str = "log-a", entries_per_checkpoint: int = 2):
    """Build a REAL chain of `n_checkpoints` checkpoints (each COSE-wire
    signed, each carrying a real consistency proof against its predecessor
    except the first), and return the parsed `checkpoints.jsonl` lines in
    file order."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=entries_per_checkpoint, max_lag_entries=10_000, ts_urls=["https://fake-ts.example"])
    signer = Ed25519Signer(tmp_path / "node-a.pem")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id=log_id)

    n = 0
    made = 0
    while made < n_checkpoints:
        log.append(_fake_capsule(n))
        n += 1
        if state.record_appended() is not None:
            made += 1

    lines = (tmp_path / "checkpoints.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def test_unbroken_chain_from_genesis(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)

    assert card.properties.continuity == "unbroken"
    assert card.properties.unforked is True
    assert card.properties.history_depth == 4
    assert card.checkpoint_count == 4
    assert card.from_checkpoint.mmr_size == lines[0]["mmr_size"]
    assert card.to_checkpoint.mmr_size == lines[-1]["mmr_size"]
    assert card.properties.cadence["checkpoints"] == 4
    assert card.verify()


def test_unbroken_chain_since_a_later_pinned_size(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 5)
    since = lines[1]["mmr_size"]  # pin at the 2nd checkpoint, ask for what came after

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=since)

    assert card.properties.continuity == "unbroken"
    assert card.properties.history_depth == 3  # checkpoints 3, 4, 5
    assert card.from_checkpoint.mmr_size == since
    assert card.to_checkpoint.mmr_size == lines[-1]["mmr_size"]


def test_since_size_not_a_known_checkpoint_is_refused(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    with pytest.raises(ValueError):
        build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=999_999)


def test_no_checkpoints_since_requested_size_is_honestly_empty(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    since = lines[-1]["mmr_size"]  # pinned at the LATEST checkpoint -- nothing newer

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=since)

    assert card.properties.history_depth == 0
    assert card.properties.unforked is True
    assert card.checkpoint_count == 0


# -- mutant: broken chain must flip continuity, never stay silently green --


def test_tampered_root_breaks_continuity_not_silently_green(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    tampered = copy.deepcopy(lines)
    # Rewrite the 3rd checkpoint's own signed root -- a forged/rolled-back tail
    # presented with an otherwise-intact chain.
    tampered[2]["root"] = "00" * 32

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=tampered, since_size=0)

    assert card.properties.continuity.startswith("broken at ")
    assert card.properties.unforked is False
    # Only the two checkpoints before the tamper are provably chained.
    assert card.properties.history_depth == 2


def test_missing_prev_link_breaks_continuity(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    tampered = copy.deepcopy(lines)
    tampered[2]["prev_size"] = 0  # claims to be a fresh genesis mid-chain

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=tampered, since_size=0)

    assert card.properties.continuity.startswith("broken at ")
    assert card.properties.unforked is False
    assert card.properties.history_depth == 2


# -- mutant: a broken consistency proof (not just a field mismatch) must fail verify --


def test_forged_consistency_proof_fails_verify(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    tampered = copy.deepcopy(lines)
    cose = bytearray(bytes.fromhex(tampered[2]["checkpoint_cose"]))
    cose[-1] ^= 0xFF  # flip a byte deep in the COSE_Sign1 structure/signature
    tampered[2]["checkpoint_cose"] = cose.hex()

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=tampered, since_size=0)

    assert card.properties.continuity.startswith("broken at ")
    assert card.properties.unforked is False


def test_checkpoint_without_cose_is_asserted_not_proven_and_breaks(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    tampered = copy.deepcopy(lines)
    del tampered[2]["checkpoint_cose"]

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=tampered, since_size=0)

    assert "no checkpoint_cose" in card.properties.continuity
    assert card.properties.unforked is False


# -- the verb: answerable only under expected_pin, never on demand --


def test_full_history_refuses_without_expected_pin(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    result = answer_full_history_request(
        node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0, expected_pin=None
    )
    assert result["status"] == REQUEST_MALFORMED


def test_full_history_refuses_a_stale_or_wrong_pin(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    result = answer_full_history_request(
        node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0, expected_pin="00" * 32
    )
    assert result["status"] == COVERAGE_UNSATISFIABLE


def test_full_history_answers_under_a_matching_pin(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    pin = lines[-1]["root"]
    result = answer_full_history_request(
        node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0, expected_pin=pin
    )
    assert result["status"] == "ok"
    assert result["history_card"]["derivation"]["properties"]["continuity"] == "unbroken"


def test_full_history_never_answers_a_query_missing_a_pin_even_with_perfect_history(tmp_path, fake_witness):
    """Caller invariance on the refusal: a perfectly healthy chain still gets
    refused with no pin -- on-demand export is never allowed regardless of
    how good the underlying history is."""
    lines = _build_chain(tmp_path, 10)
    result = answer_full_history_request(
        node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0, expected_pin=""
    )
    assert result["status"] == REQUEST_MALFORMED


# -- the offline verifier: recompute+match from raw checkpoints alone --


def test_verify_history_card_round_trips(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    result = verify_history_card(card.to_value(), lines)
    assert result.ok, result.errors


def test_verify_history_card_rejects_a_published_card_that_overclaims(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)
    value = card.to_value()
    value["derivation"]["properties"]["continuity"] = "unbroken"
    value["derivation"]["properties"]["history_depth"] = 999  # lie about depth

    result = verify_history_card(value, lines)
    assert not result.ok


def test_verify_history_card_catches_a_tampered_ledger_behind_a_stale_published_card(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)
    published = card.to_value()  # honest at publish time

    tampered_lines = copy.deepcopy(lines)
    tampered_lines[2]["root"] = "00" * 32  # ledger rewritten after publish

    result = verify_history_card(published, tampered_lines)
    assert not result.ok


def test_verify_history_card_rejects_a_stolen_history_republished_under_a_stranger_node_id(tmp_path, fake_witness):
    """The exact `[adv-history-card-identity-binding]` mallory reproduction:
    a real, honestly witnessed, structurally-valid checkpoint chain
    republished under a `node_id` that is not its own -- the chain itself
    recomputes and matches fine, so this must be caught by the identity
    check, not the chain-walk."""
    lines = _build_chain(tmp_path, 4)
    honest_node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=honest_node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    honest_result = verify_history_card(card.to_value(), lines)
    assert honest_result.ok, honest_result.errors

    stolen = card.to_value()
    stolen["node_id"] = "mallory-node"

    stolen_result = verify_history_card(stolen, lines)
    assert not stolen_result.ok
    assert any("node_id mismatch" in e for e in stolen_result.errors)


def test_verify_history_card_rejects_a_history_relabeled_to_a_different_log_id(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    honest_node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=honest_node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    relabeled = card.to_value()
    relabeled["log_id"] = "someone-elses-log"

    result = verify_history_card(relabeled, lines)
    assert not result.ok
    assert any("log_id mismatch" in e for e in result.errors)


# -- chain_segment reuse: input identity is the two boundary digests, never per-checkpoint refs --


def test_core_account_is_a_chain_segment_never_per_checkpoint_refs(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)

    acct = card.core_account()
    assert acct.selection.kind == "chain_segment"
    identity = acct.selection.input_identity()
    assert set(identity) == {"start_digest", "end_digest", "relation"}
    assert identity["relation"] == HISTORY_CHAIN_RELATION
    assert identity["start_digest"] == card.from_checkpoint.entry_digest
    assert identity["end_digest"] == card.to_checkpoint.entry_digest
    assert acct.derivation.definition_digest == MESH_HISTORY_DEFINITION_DIGEST


# -- both proof types the card relies on stay O(log n), not O(n) --


@pytest.mark.parametrize("n_entries", [8, 64, 512])
def test_inclusion_and_consistency_proofs_are_logarithmic_not_linear(tmp_path, n_entries):
    import math

    from checkpointing import JsonlLogSource

    log = JsonlLogSource(tmp_path / f"capsules-{n_entries}.jsonl")
    for i in range(n_entries):
        log.append(_fake_capsule(i))
    mmr = MmrLedger(log)
    mmr.sync()

    inclusion = mmr.inclusion_proof(1, size=mmr.size())
    consistency = mmr.consistency_proof(mmr.size() // 2, mmr.size())

    bound = max(4, 4 * math.ceil(math.log2(n_entries + 1)))
    assert len(inclusion.witness) <= bound, "inclusion proof witness path grew faster than O(log n)"
    total_consistency_hashes = len(consistency.old_peaks) + sum(len(w) for w in consistency.witness)
    assert total_consistency_hashes <= bound, "consistency proof size grew faster than O(log n)"


# -- [mesh-peer-root-exchange]: reconciled_with / forks_observed folded in
# from the mesh plugin's own on-disk reconciliation store, cross-language --


def _write_reconciliation_state(ledger_dir, *, reconciled_peers, forks):
    """Write the exact JSON shape the Rust `peer_root_ledger::PersistedState`
    serializes (`observed`/`reconciled_peers`/`forks`), so this test proves
    the Python reader actually understands the Rust writer's format rather
    than a Python-invented one."""
    state = {
        "observed": {},
        "reconciled_peers": list(reconciled_peers),
        "forks": list(forks),
    }
    (ledger_dir / "reconciliation_state.json").write_text(json.dumps(state))


def test_reconciliation_counts_are_zero_with_no_ledger_file(tmp_path):
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (0, 0, FORKS_STATE_ABSENT)


def test_reconciliation_counts_are_zero_on_malformed_json(tmp_path):
    (tmp_path / "reconciliation_state.json").write_text("{not valid json")
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (0, 0, FORKS_STATE_UNREADABLE)


def test_reconciliation_counts_read_the_rust_ledgers_own_json_shape(tmp_path):
    _write_reconciliation_state(
        tmp_path,
        reconciled_peers=["aaaa", "bbbb"],
        forks=[{"peer_id": "aaaa", "log_id": "l", "mmr_size": 4}],
    )
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (2, 1, FORKS_STATE_OK)


def test_three_fork_nodes_gossiping_heads_reconciles_with_two_peers(tmp_path, fake_witness):
    # The acceptance scenario in prose: M4 observes checkpoint heads gossiped
    # by two other fork nodes -> its card shows reconciled_with: 2.
    lines = _build_chain(tmp_path, 2)
    card = build_history_card(node_id="M4", log_id="log-a", checkpoint_lines=lines, since_size=0)
    assert card.reconciled_with == 0  # honestly zero before any ledger is folded in

    _write_reconciliation_state(
        tmp_path,
        reconciled_peers=["m1-peer-id", "m2-peer-id"],
        forks=[],
    )
    reconciled_card = with_peer_reconciliation(card, tmp_path)

    assert reconciled_card.reconciled_with == 2
    assert reconciled_card.forks_observed == 0
    assert reconciled_card.forks_state == FORKS_STATE_OK
    assert reconciled_card.to_value()["peer_reconciliation"] == {
        "reconciled_with": 2,
        "forks_observed": 0,
        "forks_state": FORKS_STATE_OK,
        "note": reconciled_card.to_value()["peer_reconciliation"]["note"],
    }
    # Original card is untouched (no mutation).
    assert card.reconciled_with == 0


def test_with_peer_reconciliation_never_changes_the_chain_walk_verification(tmp_path, fake_witness):
    # Folding in peer-reconciliation counts must not perturb the digest-bound
    # chain-walk properties or verify() -- these live in a separate section
    # precisely so a plugin's observation store can never affect the
    # cryptographically-verified checkpoint history.
    lines = _build_chain(tmp_path, 3)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    assert card.verify()

    _write_reconciliation_state(tmp_path, reconciled_peers=["x", "y", "z"], forks=[{"fake": "fork"}])
    reconciled_card = with_peer_reconciliation(card, tmp_path)

    assert reconciled_card.verify()
    assert reconciled_card.properties == card.properties
    assert reconciled_card.digest() != card.digest(), (
        "the SERIALIZED card digest changes (peer_reconciliation is part of to_value()), "
        "but the underlying chain-walk properties and its own verification must not"
    )


# --------------------------------------------------------------------------- #
# [mesh-history-card-float-cadence]: cadence stats are exact decimal STRINGS  #
# --------------------------------------------------------------------------- #
def test_multi_checkpoint_cadence_seals_and_round_trip_verifies(tmp_path, fake_witness):
    # A >=2-checkpoint selection populates span_seconds/mean_interval_seconds/
    # min_interval_seconds/max_interval_seconds -- these must ride the seal as
    # exact decimal strings, never raw JSON floats, or emit() fails closed
    # with FloatInDigestError (the bug this test guards against).
    lines = _build_chain(tmp_path, 3)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    cadence = card.properties.cadence
    assert cadence["checkpoints"] == 3
    for key in ("span_seconds", "mean_interval_seconds", "min_interval_seconds", "max_interval_seconds"):
        assert isinstance(cadence[key], str), f"{key} must be an exact decimal string, not a JSON float"

    cap = seal_history_card(card, operator="op", developer="dev", signing_node_id="node-a")

    assert cap["action_type"] == "fyi"
    assert isinstance(cap["capsule_id"], str) and len(cap["capsule_id"]) == 64
    assert verify_capsule(cap).ok


# --------------------------------------------------------------------------- #
# [mesh-forks-observed-integrity] adversarial tests                           #
# --------------------------------------------------------------------------- #


def test_missing_forks_key_in_ledger_is_unreadable_never_zero(tmp_path):
    """Deleting just the 'forks' key from reconciliation_state.json (while
    keeping 'reconciled_peers') must produce forks_state='unreadable', not
    forks_observed=0.  This is the [mesh-forks-observed-integrity] attack:
    `jq 'del(.forks)' reconciliation_state.json > tmp && mv tmp reconciliation_state.json`
    then asking for a history card must never publish forks_observed: 0."""
    # File present, parses OK, but 'forks' key deleted (the attack)
    (tmp_path / "reconciliation_state.json").write_text(
        json.dumps({"observed": {}, "reconciled_peers": ["peer-a", "peer-b"]})
    )
    counts = reconciliation_counts_from_ledger_dir(tmp_path)
    assert counts[2] == FORKS_STATE_UNREADABLE
    # Must NOT be 0 (false innocence) -- the count is indeterminate
    # (we can still return 0 as placeholder but forks_state signals it's untrustworthy)
    # The key invariant: to_value() must not publish forks_observed: 0 when unreadable


def test_forks_observed_zero_only_publishable_when_backed_by_evidence(tmp_path, fake_witness):
    """End-to-end: with_peer_reconciliation() on a card backed by an
    unreadable state file must emit forks_observed=None in to_value(),
    never 0.  forks_observed: 0 is only publishable when forks_state='ok'
    or forks_state='absent' (plugin never ran)."""
    lines = _build_chain(tmp_path, 2)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)

    # Write a tampered state file (forks key deleted)
    (tmp_path / "reconciliation_state.json").write_text(
        json.dumps({"observed": {}, "reconciled_peers": ["peer-a"]})
    )
    reconciled = with_peer_reconciliation(card, tmp_path)
    assert reconciled.forks_state == FORKS_STATE_UNREADABLE
    pr = reconciled.to_value()["peer_reconciliation"]
    assert pr["forks_state"] == FORKS_STATE_UNREADABLE
    assert pr["forks_observed"] is None  # never a false zero


def test_absent_ledger_file_publishes_zero_forks_with_absent_state(tmp_path, fake_witness):
    """When no reconciliation_state.json exists (plugin never ran), the card
    legitimately publishes forks_observed=0 with forks_state='absent'.
    This is the honest 'no observations yet' case."""
    lines = _build_chain(tmp_path, 2)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    reconciled = with_peer_reconciliation(card, tmp_path)
    assert reconciled.forks_state == FORKS_STATE_ABSENT
    pr = reconciled.to_value()["peer_reconciliation"]
    assert pr["forks_state"] == FORKS_STATE_ABSENT
    assert pr["forks_observed"] == 0  # honest: plugin never ran


def test_cadence_raw_float_fails_closed_with_float_in_digest_error(tmp_path, fake_witness):
    # Mutant: revert one cadence field to a raw float (the pre-fix shape) --
    # sealing must fail closed with FloatInDigestError, never silently digest
    # a non-reproducible binary64 value.
    lines = _build_chain(tmp_path, 3)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    tampered_cadence = dict(card.properties.cadence)
    tampered_cadence["span_seconds"] = 12.5  # raw float, not the exact-decimal-string form
    tampered_card = replace(card, properties=replace(card.properties, cadence=tampered_cadence))

    with pytest.raises(FloatInDigestError):
        seal_history_card(tampered_card, operator="op", developer="dev", signing_node_id="node-a")


# --------------------------------------------------------------------------- #
# [mesh-history-card-time-provenance] (P1)                                    #
# Temporal properties derived from producer-written cp.timestamp are labelled #
# producer_asserted; real witness receipts flip the label to receipt_bounded.  #
# --------------------------------------------------------------------------- #


def test_temporal_provenance_is_producer_asserted_with_stub_witnesses(tmp_path, monkeypatch):
    """A card built from checkpoints whose only witnesses are stubs (is_stub=True)
    must label its temporal properties as producer_asserted.

    Adversarial-council finding [mesh-history-card-time-provenance]: an actor
    can backdate cp.timestamp at zero cost -- generate a log, checkpoint N times
    with backdated timestamps, sign each.  'Three years of unbroken 60-second
    cadence' is an afternoon's work.  Temporal properties derived purely from
    producer-written timestamps must carry the producer_asserted label so a
    relying party knows they are unverified claims."""
    def _stub_register(checkpoint_cose: bytes, ts_url: str, *, timeout: float = 30.0) -> WitnessRecord:
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash="stub-entry-hash",
            receipt_b64="stub",
            leaf_index=0,
            tree_size=1,
            is_stub=True,
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _stub_register)
    lines = _build_chain(tmp_path, 4)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    assert card.properties.temporal_provenance == "producer_asserted", (
        "a chain with only stub witnesses must be labelled producer_asserted -- "
        "no real TS has bounded these timestamps externally"
    )
    # The card must still round-trip through the verifier correctly.
    result = verify_history_card(card.to_value(), lines)
    assert result.ok, result.errors


def test_temporal_provenance_is_receipt_bounded_with_real_witnesses(tmp_path, fake_witness):
    """A card built from checkpoints with real (non-stub, is_stub=False) witnesses
    labels its temporal properties as receipt_bounded.

    The fake_witness fixture returns WitnessRecord(is_stub=False) -- these count
    as real for labelling purposes because a real TS registration places an
    external upper bound on when that checkpoint could have occurred."""
    lines = _build_chain(tmp_path, 4)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    assert card.properties.temporal_provenance == "receipt_bounded", (
        "a chain with real (non-stub) witness receipts must be labelled receipt_bounded"
    )
    result = verify_history_card(card.to_value(), lines)
    assert result.ok, result.errors


def test_backdated_card_is_still_labelled_producer_asserted_not_silently_accepted(tmp_path, monkeypatch):
    """Demonstrate the specific adversarial scenario: a producer backdates
    cp.timestamp values to forge a multi-year history in minutes.  Without
    real witnesses the card must be labelled producer_asserted, never published
    as if the cadence were externally verified."""
    def _stub_register(checkpoint_cose: bytes, ts_url: str, *, timeout: float = 30.0) -> WitnessRecord:
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash="stub",
            receipt_b64="stub",
            leaf_index=0,
            tree_size=1,
            is_stub=True,
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _stub_register)
    lines = _build_chain(tmp_path, 4)
    # Backdate the timestamps to simulate a forged history spanning years.
    backdated = copy.deepcopy(lines)
    base_year = 2020
    for i, line in enumerate(backdated):
        line["timestamp"] = f"{base_year + i}-01-01T00:00:00Z"

    node_id = node_id_from_key_id(backdated[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=backdated, since_size=0)

    # The chain walk succeeds (backdated timestamps don't break the MMR proofs).
    assert card.properties.continuity == "unbroken"
    # But the temporal provenance is correctly labelled producer_asserted --
    # a relying party reading the card knows the cadence numbers are unverified.
    assert card.properties.temporal_provenance == "producer_asserted"
    # The card must still verify (it's internally consistent).
    result = verify_history_card(card.to_value(), backdated)
    assert result.ok, result.errors


# --------------------------------------------------------------------------- #
# [mesh-history-card-enrichment-verify] (P2)                                  #
# Enriched cards (with_peer_reconciliation / with_references) must verify.    #
# --------------------------------------------------------------------------- #


def test_enriched_card_via_peer_reconciliation_verifies(tmp_path, fake_witness):
    """An enriched card (via with_peer_reconciliation) must pass its own offline
    verification.

    Adversarial-council finding [mesh-history-card-enrichment-verify]: before
    the fix, to_value() always emitted peer_reconciliation at the enriched
    values but build_history_card() always used defaults (zero), so any enriched
    card failed verify_history_card() with 'recomputed card does not match the
    published card'.  This was a straight bug: the verifier was broken for the
    primary enrichment path."""
    lines = _build_chain(tmp_path, 3)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    # Verify the base card first (sanity check).
    base_result = verify_history_card(card.to_value(), lines)
    assert base_result.ok, f"base card must verify before enrichment: {base_result.errors}"

    # Enrich via with_peer_reconciliation.
    state = {"observed": {}, "reconciled_peers": ["peer-x", "peer-y", "peer-z"], "forks": [{"fake": "fork"}]}
    (tmp_path / "reconciliation_state.json").write_text(json.dumps(state))
    enriched = with_peer_reconciliation(card, tmp_path)

    assert enriched.reconciled_with == 3
    assert enriched.forks_observed == 1

    # The enriched card must also verify -- this was the bug.
    result = verify_history_card(enriched.to_value(), lines)
    assert result.ok, (
        f"enriched card (with_peer_reconciliation) must verify offline: {result.errors}"
    )


def test_enriched_card_via_with_references_verifies(tmp_path, fake_witness):
    """An enriched card (via with_references) must pass its own offline
    verification.

    Both enrichment paths must verify: with_peer_reconciliation AND
    with_references (the full regression as stated in
    [mesh-history-card-enrichment-verify])."""
    lines = _build_chain(tmp_path, 3)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    enriched = with_references(
        card,
        references_asked=10,
        references_answered=8,
        adjudications_about_x={"contradicted": 2, "inconclusive": 1},
        ack_refusals_about_x=3,
    )

    result = verify_history_card(enriched.to_value(), lines)
    assert result.ok, (
        f"enriched card (with_references) must verify offline: {result.errors}"
    )


def test_both_enrichment_paths_combined_verify(tmp_path, fake_witness):
    """A card enriched by BOTH with_peer_reconciliation and with_references
    (chained) must also verify."""
    lines = _build_chain(tmp_path, 3)
    node_id = node_id_from_key_id(lines[0]["key_id"])
    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines, since_size=0)

    state = {"observed": {}, "reconciled_peers": ["p1"], "forks": []}
    (tmp_path / "reconciliation_state.json").write_text(json.dumps(state))
    enriched = with_peer_reconciliation(card, tmp_path)
    enriched = with_references(
        enriched,
        references_asked=5,
        references_answered=4,
        adjudications_about_x={},
        ack_refusals_about_x=0,
    )

    result = verify_history_card(enriched.to_value(), lines)
    assert result.ok, (
        f"doubly-enriched card must verify offline: {result.errors}"
    )
