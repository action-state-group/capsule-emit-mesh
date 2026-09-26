# SPDX-License-Identifier: Apache-2.0
"""Tests for E14's sidecar wiring — ``evidence_responder.handle_evidence_request``.

These exercise the REAL responder core (``capsule_emit.evidence_request
.answer``) against a real ``capsule_sidecar.NodeState``'s ledger + signing
key — confirming the wiring (paths, key identity), not re-deriving the
responder's own decision logic (that is ``capsule-emit``'s test suite).
Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.
"""
from __future__ import annotations

import json
import tempfile

import pytest
from capsule_emit import seal, witness
from capsule_emit.evidence_request import Artifact, Refusal

import capsule_sidecar as cs
from evidence_responder import handle_evidence_request


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
    # NodeState.__post_init__ loads the manifest for real; write a minimal one.
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    checkpoint_config_path = tmp_path / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )
    return state


def _record_request(capsule_id: str) -> bytes:
    return json.dumps({"subject": {"kind": "record", "capsule_id": capsule_id}, "coverage": {}}).encode()


def _resolve_signer(state):
    from capsule_emit.signing import resolve_signer

    return resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path)


def _seal_into_sidecar_store(state, *, action: str) -> dict:
    """Mint a well-formed capsule via capsule_emit's own ``seal()`` (a
    convenient, already-verified builder), but land it in the sidecar's
    REAL cll.ledger.store.LedgerStore -- ``state.log_source`` -- rather than
    capsule_emit's own flat-file+in-band-checkpoint-stamp convention.
    ``seal()`` still needs a ``ledger=`` to write its own copy to; a scratch
    tempfile it owns exclusively (never read back) satisfies that without
    colliding with the store this test actually asserts against."""
    scratch_ledger = tempfile.mktemp(suffix="-capsule-emit-seal-scratch.jsonl")
    capsule = seal(
        None,
        action=action,
        operator="acme",
        anchor=False,
        ledger=scratch_ledger,
        signing_key_path=state.signing_key_path,
    ).capsule
    state.log_source.append(capsule)
    return capsule


def test_handle_evidence_request_uses_the_sidecar_own_ledger_and_key(node_state):
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(2)]
    # bundle() needs an in-band checkpoint to answer a `record` subject --
    # materialize_flat_view synthesizes one from this sidecar's OWN (real,
    # out-of-band) checkpoint, so it has to actually exist first.
    assert node_state.checkpoint.reconnect() is not None

    result = handle_evidence_request(node_state, _record_request(caps[0]["capsule_id"]))
    assert isinstance(result, Artifact)
    assert result.bundles[0].capsule_id == caps[0]["capsule_id"]


def test_handle_evidence_request_refusal_signed_with_node_key(node_state):
    result = handle_evidence_request(node_state, _record_request("ff" * 32))
    assert isinstance(result, Refusal)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(node_state.signing_key_path.read_bytes(), password=None)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    node_public_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert result.key_id == node_public_hex

    from capsule_emit.evidence_request import verify_refusal_offline

    assert verify_refusal_offline(result)


def test_handle_evidence_request_caller_invariance(node_state):
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(2)]
    assert node_state.checkpoint.reconnect() is not None
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    req_a = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "a"}).encode()
    req_b = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "nonce": "b"}).encode()

    result_a = handle_evidence_request(node_state, req_a, now=now)
    result_b = handle_evidence_request(node_state, req_b, now=now)
    assert json.dumps(result_a.to_dict(), sort_keys=True) == json.dumps(result_b.to_dict(), sort_keys=True)


# [mesh-fabric-vocab-alignment] --------------------------------------------


def test_purpose_and_contract_ref_are_logged_never_change_answer_bytes(node_state, capsys):
    """purpose/contract_ref ride outside RequestMap entirely (see
    log_request_purpose) -- two requests identical except for those two
    fields must resolve to byte-identical answers, and the values are still
    observably logged."""
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(2)]
    assert node_state.checkpoint.reconnect() is not None
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    req_a = json.dumps({"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}}).encode()
    req_b = json.dumps(
        {
            "subject": {"kind": "record", "capsule_id": cid},
            "coverage": {},
            "purpose": "counterparty_check",
            "contract_ref": "contract-123",
        }
    ).encode()

    result_a = handle_evidence_request(node_state, req_a, now=now)
    result_b = handle_evidence_request(node_state, req_b, now=now)
    assert json.dumps(result_a.to_dict(), sort_keys=True) == json.dumps(result_b.to_dict(), sort_keys=True)

    out = capsys.readouterr().out
    assert "purpose='counterparty_check'" in out
    assert "contract_ref='contract-123'" in out


def test_unrecognized_purpose_is_logged_not_refused(node_state, capsys):
    caps = [_seal_into_sidecar_store(node_state, action="act-0")]
    assert node_state.checkpoint.reconnect() is not None
    cid = caps[0]["capsule_id"]

    from capsule_emit.evidence_request import Artifact

    req = json.dumps(
        {"subject": {"kind": "record", "capsule_id": cid}, "coverage": {}, "purpose": "not_a_real_purpose"}
    ).encode()
    result = handle_evidence_request(node_state, req)
    assert isinstance(result, Artifact)
    assert "unrecognized purpose" in capsys.readouterr().out


def test_augment_evidence_answer_dict_artifact_gets_satisfied_status_and_record_inclusion():
    from evidence_responder import augment_evidence_answer_dict

    artifact_dict = {"v": 1, "subject_kind": "record", "bundles": [{"capsule_id": "abc"}]}
    augmented = augment_evidence_answer_dict(artifact_dict)
    assert augmented["status"] == "SATISFIED"
    assert augmented["bundles"][0]["coverage_descriptor"] == ["record_inclusion"]
    # never more than it does -- a single record subject never claims range_completeness
    assert "range_completeness" not in augmented["bundles"][0]["coverage_descriptor"]
    # original dict untouched
    assert "status" not in artifact_dict
    assert "coverage_descriptor" not in artifact_dict["bundles"][0]


def test_augment_evidence_answer_dict_range_final_page_gets_range_completeness():
    from evidence_responder import augment_evidence_answer_dict

    artifact_dict = {
        "v": 1,
        "subject_kind": "range",
        "bundles": [{"capsule_id": "a"}, {"capsule_id": "b"}],
        # no next_page_token -- this page reaches the end of the selection
    }
    augmented = augment_evidence_answer_dict(artifact_dict)
    for b in augmented["bundles"]:
        assert b["coverage_descriptor"] == ["record_inclusion", "range_completeness"]


def test_augment_evidence_answer_dict_range_mid_page_never_claims_completeness():
    from evidence_responder import augment_evidence_answer_dict

    artifact_dict = {
        "v": 1,
        "subject_kind": "range",
        "bundles": [{"capsule_id": "a"}],
        "next_page_token": "50",  # more remains -- this response alone is not complete
    }
    augmented = augment_evidence_answer_dict(artifact_dict)
    assert augmented["bundles"][0]["coverage_descriptor"] == ["record_inclusion"]


def test_augment_evidence_answer_dict_chain_segment_gets_no_coverage_descriptor():
    from evidence_responder import augment_evidence_answer_dict

    artifact_dict = {"v": 1, "subject_kind": "chain_segment", "bundles": [{"from_size": 0, "to_size": 5}]}
    augmented = augment_evidence_answer_dict(artifact_dict)
    assert "coverage_descriptor" not in augmented["bundles"][0]
    assert augmented["status"] == "SATISFIED"


def test_augment_evidence_answer_dict_refusal_status_mapping():
    from evidence_responder import augment_evidence_answer_dict

    assert augment_evidence_answer_dict({"reason": "no_such_subject"})["status"] == "NOT_FOUND"
    assert augment_evidence_answer_dict({"reason": "coverage_unsatisfiable"})["status"] == "NOT_COMMITTED"
    assert augment_evidence_answer_dict({"reason": "policy_decline"})["status"] == "WITHHELD"
    # request_malformed stays a bare refusal reason -- no additive status.
    assert "status" not in augment_evidence_answer_dict({"reason": "request_malformed"})


def test_augment_evidence_answer_dict_pre_alignment_spelling_no_longer_maps():
    """The mutant this test exists to catch: reverting the mapping key to
    the pre-alignment ``no_such_record`` spelling would silently stop
    mapping ``capsule_emit``'s real ``no_such_subject`` refusals to
    ``NOT_FOUND``."""
    from evidence_responder import augment_evidence_answer_dict

    assert "status" not in augment_evidence_answer_dict({"reason": "no_such_record"})


def test_coverage_descriptor_never_claims_capture_coverage_on_a_unilateral_range():
    """The acceptance mutant: a bundle claiming capture_coverage on a
    unilateral (single-ledger) range must be rejected, never shipped."""
    from evidence_responder import _validate_coverage_descriptor

    with pytest.raises(ValueError, match="capture_coverage"):
        _validate_coverage_descriptor("range", ["record_inclusion", "capture_coverage"])
    # the responder's own coverage_descriptor_for never produces this shape
    # in the first place -- this is the defense-in-depth backstop for any
    # caller that tries to assert one anyway.
    with pytest.raises(ValueError):
        _validate_coverage_descriptor("range", ["reconciliation_coverage"])
    with pytest.raises(ValueError):
        _validate_coverage_descriptor("correlation", ["corroboration"])
    # legitimate claims never raise
    _validate_coverage_descriptor("range", ["record_inclusion", "range_completeness"])
