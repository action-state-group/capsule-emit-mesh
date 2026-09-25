# SPDX-License-Identifier: Apache-2.0
"""Tests for [mesh-sharing-policy-v0] the relationship gate --
``evidence_responder.classify_relationship``/``relationship_allowed``/
``classify_leaf_kind``, and ``handle_evidence_request``'s own wiring of the
gate ahead of ``record``/``correlation``/``chain_segment`` requests.

Acceptance / mutants that must flip (design note S1/S3):
  - ``policy=None`` -> the gate never runs at all, reproducing this
    function's exact pre-[mesh-sharing-policy-v0] behavior (every existing
    caller unaffected, byte for byte).
  - ``history_segments: off`` -> refuses EVERYONE, including a real
    counterparty, ``not_authorized``.
  - ``history_segments: counterparties`` (the strictest ON tier) -> answers
    a counterparty, refuses a stranger AND an identified-but-unknown caller.
  - ``history_segments: prospective`` (the documented default) -> answers
    counterparty + identified, refuses only a stranger (no declared id).
  - ``history_segments: peers`` -> answers everyone, including a stranger --
    restores today's pre-gate behavior by explicit opt-in.
  - a ``range`` request is NEVER gated (design note: only
    record/correlation/chain_segment) -- out of ``RELATIONSHIP_GATED_SUBJECT_KINDS``.
"""
from __future__ import annotations

import json

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit import witness
from capsule_emit.evidence_request import Refusal, verify_refusal_offline

import capsule_sidecar as cs
from evidence_responder import (
    RELATIONSHIP_COUNTERPARTY,
    RELATIONSHIP_GATED_SUBJECT_KINDS,
    RELATIONSHIP_IDENTIFIED,
    RELATIONSHIP_STRANGER,
    REASON_NOT_AUTHORIZED,
    classify_leaf_kind,
    classify_relationship,
    handle_evidence_request,
    relationship_allowed,
)
from share_policy import SharePolicy

# ---------------------------------------------------------------------------
# classify_relationship -- pure
# ---------------------------------------------------------------------------


def test_no_declared_id_is_a_stranger():
    assert classify_relationship(None, []) == RELATIONSHIP_STRANGER
    assert classify_relationship("", []) == RELATIONSHIP_STRANGER


def test_declared_id_matching_a_past_exchange_is_a_counterparty():
    entries = [{"model_attestation": {"compute_attestation": {"requesting_party": "node-b"}}}]
    assert classify_relationship("node-b", entries) == RELATIONSHIP_COUNTERPARTY


def test_declared_id_matching_no_past_exchange_is_identified():
    entries = [{"model_attestation": {"compute_attestation": {"requesting_party": "node-b"}}}]
    assert classify_relationship("node-c", entries) == RELATIONSHIP_IDENTIFIED


def test_matches_on_any_of_the_three_counterparty_naming_keys():
    for key in ("requesting_party", "served_by_node_id", "counterparty_ref"):
        entries = [{"model_attestation": {"compute_attestation": {key: "node-b"}}}]
        assert classify_relationship("node-b", entries) == RELATIONSHIP_COUNTERPARTY, key


# ---------------------------------------------------------------------------
# relationship_allowed -- the tier matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier,relationship,expected",
    [
        ("off", RELATIONSHIP_COUNTERPARTY, False),
        ("off", RELATIONSHIP_IDENTIFIED, False),
        ("off", RELATIONSHIP_STRANGER, False),
        ("counterparties", RELATIONSHIP_COUNTERPARTY, True),
        ("counterparties", RELATIONSHIP_IDENTIFIED, False),
        ("counterparties", RELATIONSHIP_STRANGER, False),
        ("prospective", RELATIONSHIP_COUNTERPARTY, True),
        ("prospective", RELATIONSHIP_IDENTIFIED, True),
        ("prospective", RELATIONSHIP_STRANGER, False),
        ("peers", RELATIONSHIP_COUNTERPARTY, True),
        ("peers", RELATIONSHIP_IDENTIFIED, True),
        ("peers", RELATIONSHIP_STRANGER, True),
    ],
)
def test_relationship_allowed_matrix(tier, relationship, expected):
    assert relationship_allowed(relationship, tier) is expected


# ---------------------------------------------------------------------------
# classify_leaf_kind -- pure
# ---------------------------------------------------------------------------


def test_checkpoint_stamp_kind_classifies_as_stamp():
    assert classify_leaf_kind({"kind": "checkpoint_stamp"}) == "stamp"


def test_other_explicit_kind_passes_through():
    assert classify_leaf_kind({"kind": "custom_thing"}) == "custom_thing"


def test_adjudicates_chain_relation_classifies_as_adjudication():
    assert classify_leaf_kind({"chain": {"relation": "adjudicates"}}) == "adjudication"


def test_twin_bracket_id_present_classifies_as_exchange_twin():
    entry = {
        "model_attestation": {
            "compute_attestation": {"x-mesh-poc-v1": {"twin_bracket_id": "br-1"}}
        }
    }
    assert classify_leaf_kind(entry) == "exchange_twin"


def test_no_special_markers_classifies_as_generic_capsule():
    assert classify_leaf_kind({}) == "capsule"


# ---------------------------------------------------------------------------
# handle_evidence_request -- the gate wired end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_witness_state():
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False
    yield
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False


@pytest.fixture
def stub_witness(monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "stub")


@pytest.fixture
def node_state(tmp_path, stub_witness):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    checkpoint_config_path = tmp_path / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
    return cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )


def _seal_served_by(state, *, requesting_party: str) -> dict:
    """A well-formed capsule this node holds, naming ``requesting_party`` as
    its counterparty -- built with ``agent_action_capsule.emit.emit`` (same
    builder ``test_record_push.py``/``test_adjudication_delivery.py`` use
    for a ``compute_attestation``-bearing capsule) and landed in the
    sidecar's REAL ledger store (same append pattern as
    test_evidence_responder.py's own ``_seal_into_sidecar_store``)."""
    effect = EffectRecord(status="confirmed", type="inference_completion", request_digest="c" * 64, response_digest="d" * 64)
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    capsule = emit(
        action_type="decide",
        operator="acme",
        developer="mesh-node@v1",
        compute_attestation={"requesting_party": requesting_party},
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    state.log_source.append(capsule)
    # bundle() needs an in-band checkpoint to answer a `record` subject --
    # see test_evidence_responder.py's own test for why this call is here.
    state.checkpoint.reconnect()
    return capsule


def _record_request(capsule_id: str) -> bytes:
    return json.dumps({"subject": {"kind": "record", "capsule_id": capsule_id}, "coverage": {}}).encode()


def test_policy_none_gate_never_runs_even_for_a_stranger(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    result = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id=None, policy=None
    )
    assert result.subject_kind == "record"  # answered, not refused


def test_history_segments_off_refuses_even_a_real_counterparty(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    policy = SharePolicy(history_segments="off")
    result = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id="node-b", policy=policy
    )
    assert result.reason == REASON_NOT_AUTHORIZED


def test_counterparties_tier_answers_counterparty_refuses_stranger(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    policy = SharePolicy(history_segments="counterparties")

    answered = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id="node-b", policy=policy
    )
    assert answered.subject_kind == "record"

    refused = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id=None, policy=policy
    )
    assert refused.reason == REASON_NOT_AUTHORIZED


def test_prospective_default_tier_answers_identified_but_refuses_stranger(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    policy = SharePolicy(history_segments="prospective")

    # "node-c" never exchanged with this node -- identified, not counterparty.
    answered = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id="node-c", policy=policy
    )
    assert answered.subject_kind == "record"

    refused = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id=None, policy=policy
    )
    assert refused.reason == REASON_NOT_AUTHORIZED


def test_peers_tier_answers_a_bare_stranger(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    policy = SharePolicy(history_segments="peers")
    result = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id=None, policy=policy
    )
    assert result.subject_kind == "record"


def test_gate_refusal_is_signed_and_verifies_offline(node_state):
    capsule = _seal_served_by(node_state, requesting_party="node-b")
    policy = SharePolicy(history_segments="off")
    result = handle_evidence_request(
        node_state, _record_request(capsule["capsule_id"]), requester_id="node-b", policy=policy
    )
    refusal = Refusal(
        request_digest=result.request_digest,
        reason=result.reason,
        issued_at=result.issued_at,
        key_id=result.key_id,
        sig=result.sig,
    )
    assert verify_refusal_offline(refusal)


def test_range_subject_kind_is_never_gated(node_state):
    # Design note S1: the gate applies only to record/correlation/
    # chain_segment -- "range" is deliberately out of scope.
    assert "range" not in RELATIONSHIP_GATED_SUBJECT_KINDS
