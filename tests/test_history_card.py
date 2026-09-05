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

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, MmrLedger, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

from history_card import (
    COVERAGE_UNSATISFIABLE,
    HISTORY_CHAIN_RELATION,
    MESH_HISTORY_DEFINITION_DIGEST,
    REQUEST_MALFORMED,
    answer_full_history_request,
    build_history_card,
    reconciliation_counts_from_ledger_dir,
    verify_history_card,
    with_peer_reconciliation,
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
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)

    result = verify_history_card(card.to_value(), lines)
    assert result.ok, result.errors


def test_verify_history_card_rejects_a_published_card_that_overclaims(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    value = card.to_value()
    value["derivation"]["properties"]["continuity"] = "unbroken"
    value["derivation"]["properties"]["history_depth"] = 999  # lie about depth

    result = verify_history_card(value, lines)
    assert not result.ok


def test_verify_history_card_catches_a_tampered_ledger_behind_a_stale_published_card(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    published = card.to_value()  # honest at publish time

    tampered_lines = copy.deepcopy(lines)
    tampered_lines[2]["root"] = "00" * 32  # ledger rewritten after publish

    result = verify_history_card(published, tampered_lines)
    assert not result.ok


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
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (0, 0)


def test_reconciliation_counts_are_zero_on_malformed_json(tmp_path):
    (tmp_path / "reconciliation_state.json").write_text("{not valid json")
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (0, 0)


def test_reconciliation_counts_read_the_rust_ledgers_own_json_shape(tmp_path):
    _write_reconciliation_state(
        tmp_path,
        reconciled_peers=["aaaa", "bbbb"],
        forks=[{"peer_id": "aaaa", "log_id": "l", "mmr_size": 4}],
    )
    assert reconciliation_counts_from_ledger_dir(tmp_path) == (2, 1)


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
    assert reconciled_card.to_value()["peer_reconciliation"] == {
        "reconciled_with": 2,
        "forks_observed": 0,
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
