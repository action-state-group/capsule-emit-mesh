# SPDX-License-Identifier: Apache-2.0
"""Tests for ``evidence_responder`` -- the -00 responder over a node's ledger.

These run AAC's protocol core (``agent_action_capsule.evidence_request
.answer``) against a real ``capsule_sidecar.NodeState``'s ledger + signing
key through ``MeshEvidenceStore``: the store adapter, the artifact forms and
the envelope, not the protocol's own decision logic (AAC's conformance
vectors cover that).
Uses ``CAPSULE_WITNESS=stub`` (zero-network) so this runs hermetically.
"""
from __future__ import annotations

import hashlib
import json
import tempfile

import pytest
from agent_action_capsule import evidence_request as er
from capsule_emit import seal, witness
from capsule_emit.bundle import Bundle, verify_bundle

import capsule_sidecar as cs
from evidence_responder import (
    MAX_ANSWER_RECORDS,
    MeshEvidenceStore,
    augment_evidence_answer_dict,
    handle_evidence_request,
    reply_to_wire,
)


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


def _request(subject: dict, coverage: dict | None = None, **members) -> bytes:
    return json.dumps({"subject": subject, "coverage": coverage or {"min_freshness": 0}, **members}).encode()


def _record_request(capsule_id: str, **members) -> bytes:
    return _request({"record": capsule_id}, **members)


def _body(envelope: er.Envelope) -> dict:
    return json.loads(envelope.artifact)


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


def _node_public_hex(node_state) -> str:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )

    private_key = load_pem_private_key(node_state.signing_key_path.read_bytes(), password=None)
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sealed(node_state, n: int) -> list[dict]:
    caps = [_seal_into_sidecar_store(node_state, action=f"act-{i}") for i in range(n)]
    assert node_state.checkpoint.reconnect() is not None
    return caps


def test_record_is_served_in_a_signed_envelope_under_the_node_key(node_state):
    caps = _sealed(node_state, 2)
    request = _record_request(caps[0]["capsule_id"])
    result = handle_evidence_request(node_state, request)
    assert isinstance(result, er.Envelope)
    result.verify_for(request, _node_public_hex(node_state))
    (bundle,) = [Bundle.from_dict(b) for b in _body(result)["bundles"]]
    assert bundle.capsule_id == caps[0]["capsule_id"]
    assert verify_bundle(bundle)[0]
    # proven under the anchor the envelope names, not some earlier checkpoint
    assert hashlib.sha256(bundle.checkpoint_cose).hexdigest() == result.anchor_digest
    assert result.freshness == 2  # min_freshness was a size: the anchor's


def test_anchors_are_the_checkpoints_cose_statements(node_state):
    _sealed(node_state, 1)
    lines = [json.loads(x) for x in (node_state.ledger_dir / "checkpoints.jsonl").read_text().splitlines() if x]
    store = MeshEvidenceStore(node_state.ledger_dir)
    assert [a.digest for a in store.anchors()] == [
        hashlib.sha256(bytes.fromhex(line["checkpoint_cose"])).hexdigest() for line in lines
    ]


def test_expected_pin_serves_under_an_earlier_anchor(node_state):
    first = _sealed(node_state, 1)
    _sealed(node_state, 1)
    store = MeshEvidenceStore(node_state.ledger_dir)
    early = store.anchors()[0].digest
    result = handle_evidence_request(node_state, _request({"record": first[0]["capsule_id"]}, {"expected_pin": early}))
    assert isinstance(result, er.Envelope) and result.anchor_digest == early
    (bundle,) = [Bundle.from_dict(b) for b in _body(result)["bundles"]]
    assert verify_bundle(bundle)[0]


def test_record_after_the_pinned_anchor_is_coverage_unsatisfiable(node_state):
    _sealed(node_state, 1)
    later = _sealed(node_state, 1)
    early = MeshEvidenceStore(node_state.ledger_dir).anchors()[0].digest
    result = handle_evidence_request(node_state, _request({"record": later[0]["capsule_id"]}, {"expected_pin": early}))
    assert isinstance(result, er.Refusal) and result.reason == "coverage_unsatisfiable"


def test_range_full_history_and_correlation(node_state):
    caps = _sealed(node_state, 3)
    ranged = handle_evidence_request(node_state, _request({"range": [1, 2]}))
    assert [b["capsule_id"] for b in _body(ranged)["bundles"]] == [c["capsule_id"] for c in caps[1:]]
    full = handle_evidence_request(node_state, _request({"full_history": None}))
    assert [b["capsule_id"] for b in _body(full)["bundles"]] == [c["capsule_id"] for c in caps]
    beyond = handle_evidence_request(node_state, _request({"range": [0, 3]}))
    assert isinstance(beyond, er.Refusal) and beyond.reason == "coverage_unsatisfiable"


def test_correlation_matches_a_correlator_key_exactly(node_state):
    _sealed(node_state, 2)
    unheld = handle_evidence_request(node_state, _request({"correlation": "no-such-nonce"}))
    assert isinstance(unheld, er.Refusal) and unheld.reason == "no_such_subject"

    from evidence_responder import carries_correlation

    record = {"x": {"y": [{"client_nonce": "n-1"}]}, "z": {"adjudication": {"verdict": "contradicted:node-9"}}}
    assert carries_correlation(record, "n-1")
    assert carries_correlation(record, "node-9")
    assert not carries_correlation(record, "n-")  # never a prefix


def test_checkpoints_subject_serves_the_chain_up_to_the_anchor(node_state):
    _sealed(node_state, 1)
    _sealed(node_state, 1)
    result = handle_evidence_request(node_state, _request({"checkpoints": None}))
    assert isinstance(result, er.Envelope)
    lines = [json.loads(x) for x in (node_state.ledger_dir / "checkpoints.jsonl").read_text().splitlines() if x]
    assert _body(result)["checkpoints"] == lines


def test_unsupported_derivation_and_exchange_subject(node_state):
    caps = _sealed(node_state, 1)
    derived = handle_evidence_request(node_state, _record_request(caps[0]["capsule_id"], derivation="history_card/1"))
    assert isinstance(derived, er.Refusal) and derived.reason == "derivation_unsupported"
    exchange = handle_evidence_request(node_state, _request({"exchange": "ab" * 32}))
    assert isinstance(exchange, er.Refusal) and exchange.reason == "no_such_subject"


def test_pre00_request_is_refused_malformed(node_state):
    caps = _sealed(node_state, 1)
    old = json.dumps({"subject": {"kind": "record", "capsule_id": caps[0]["capsule_id"]}, "coverage": {}}).encode()
    result = handle_evidence_request(node_state, old)
    assert isinstance(result, er.Refusal) and result.reason == "request_malformed"


def test_more_records_than_one_answer_carries_is_policy_declined(node_state, monkeypatch):
    import evidence_responder

    _sealed(node_state, 3)
    monkeypatch.setattr(evidence_responder, "MAX_ANSWER_RECORDS", 2)
    result = handle_evidence_request(node_state, _request({"full_history": None}))
    assert isinstance(result, er.Refusal) and result.reason == "policy_declined"
    assert MAX_ANSWER_RECORDS == 200


def test_served_summary_needs_an_expected_pin_naming_the_latest_anchor(node_state):
    _sealed(node_state, 1)
    _sealed(node_state, 1)
    anchors = MeshEvidenceStore(node_state.ledger_dir).anchors()
    assert len(anchors) == 2
    on_demand = handle_evidence_request(node_state, _request({"full_history": None}, derivation="served_summary/1"))
    assert isinstance(on_demand, er.Refusal) and on_demand.reason == "policy_declined"
    stale = handle_evidence_request(
        node_state, _request({"full_history": None}, {"expected_pin": anchors[0].digest}, derivation="served_summary/1")
    )
    assert isinstance(stale, er.Refusal) and stale.reason == "coverage_unsatisfiable"
    pinned = handle_evidence_request(
        node_state, _request({"full_history": None}, {"expected_pin": anchors[-1].digest}, derivation="served_summary/1")
    )
    assert isinstance(pinned, er.Envelope) and pinned.derivation == "served_summary/1"
    assert _body(pinned)["served_summary"]["schema"] == "mesh-served-summary/1"
    wire = reply_to_wire(pinned)
    assert wire["status"] == "SATISFIED" and "coverage_descriptor" not in wire


def test_handle_evidence_request_refusal_signed_with_node_key(node_state):
    result = handle_evidence_request(node_state, _record_request("ff" * 32))
    assert isinstance(result, er.Refusal) and result.reason == "no_such_subject"
    assert result.key_id == _node_public_hex(node_state)
    assert er.verify_refusal_offline(result)
    assert er.check_refusal(result.to_dict()).conformant


def test_handle_evidence_request_caller_invariance(node_state):
    caps = _sealed(node_state, 2)
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    result_a = handle_evidence_request(node_state, _record_request(cid, nonce="a"), now=now)
    result_b = handle_evidence_request(node_state, _record_request(cid, nonce="b"), now=now)
    assert result_a.artifact == result_b.artifact
    assert result_a.anchor_digest == result_b.anchor_digest
    assert result_a.request_digest != result_b.request_digest


# [mesh-fabric-vocab-alignment] --------------------------------------------


def test_purpose_and_contract_ref_are_logged_never_change_the_artifact(node_state, capsys):
    """purpose/contract_ref are members -00 does not define, so they never
    reach resolution: two requests differing only in them get the same
    artifact, and the values are still observably logged."""
    caps = _sealed(node_state, 2)
    cid = caps[0]["capsule_id"]

    now = "2026-09-02T00:00:00Z"
    result_a = handle_evidence_request(node_state, _record_request(cid), now=now)
    result_b = handle_evidence_request(
        node_state, _record_request(cid, purpose="counterparty_check", contract_ref="contract-123"), now=now
    )
    assert result_a.artifact == result_b.artifact

    out = capsys.readouterr().out
    assert "purpose='counterparty_check'" in out
    assert "contract_ref='contract-123'" in out


def test_unrecognized_purpose_is_logged_not_refused(node_state, capsys):
    caps = _sealed(node_state, 1)
    result = handle_evidence_request(node_state, _record_request(caps[0]["capsule_id"], purpose="not_a_real_purpose"))
    assert isinstance(result, er.Envelope)
    assert "unrecognized purpose" in capsys.readouterr().out


def test_envelope_wire_gets_satisfied_status_and_coverage_descriptor(node_state):
    caps = _sealed(node_state, 2)
    record = reply_to_wire(handle_evidence_request(node_state, _record_request(caps[0]["capsule_id"])))
    assert record["status"] == "SATISFIED"
    assert record["coverage_descriptor"] == ["record_inclusion"]
    full = reply_to_wire(handle_evidence_request(node_state, _request({"full_history": None})))
    assert full["coverage_descriptor"] == ["record_inclusion", "range_completeness"]
    checkpoints = reply_to_wire(handle_evidence_request(node_state, _request({"checkpoints": None})))
    assert "coverage_descriptor" not in checkpoints
    # the additive members are unsigned: a profile reader still reads the envelope
    parsed = er.parse_reply(json.dumps(record).encode())
    assert isinstance(parsed, er.Envelope)
    parsed.verify()


def test_augment_redress_bundles_get_record_inclusion():
    artifact_dict = {"v": 1, "subject_kind": "message_digest", "bundles": [{"capsule_id": "abc"}]}
    augmented = augment_evidence_answer_dict(artifact_dict)
    assert augmented["status"] == "SATISFIED"
    assert augmented["bundles"][0]["coverage_descriptor"] == ["record_inclusion"]
    # original dict untouched
    assert "status" not in artifact_dict
    assert "coverage_descriptor" not in artifact_dict["bundles"][0]


def test_augment_evidence_answer_dict_refusal_status_mapping():
    assert augment_evidence_answer_dict({"reason": "no_such_subject"})["status"] == "NOT_FOUND"
    assert augment_evidence_answer_dict({"reason": "coverage_unsatisfiable"})["status"] == "NOT_COMMITTED"
    assert augment_evidence_answer_dict({"reason": "policy_declined"})["status"] == "WITHHELD"
    # request_malformed stays a bare refusal reason -- no additive status;
    # pre-00 tokens are not registered and map to nothing.
    assert "status" not in augment_evidence_answer_dict({"reason": "request_malformed"})
    assert "status" not in augment_evidence_answer_dict({"reason": "no_such_record"})


def test_coverage_descriptor_never_claims_capture_coverage_on_a_unilateral_range():
    """The acceptance mutant: a claim of capture_coverage on a unilateral
    (single-ledger) range must be rejected, never shipped."""
    from evidence_responder import _validate_coverage_descriptor

    with pytest.raises(ValueError, match="capture_coverage"):
        _validate_coverage_descriptor("range", ["record_inclusion", "capture_coverage"])
    with pytest.raises(ValueError):
        _validate_coverage_descriptor("range", ["reconciliation_coverage"])
    with pytest.raises(ValueError):
        _validate_coverage_descriptor("correlation", ["corroboration"])
    _validate_coverage_descriptor("range", ["record_inclusion", "range_completeness"])


class _Signer:
    def __init__(self, node_state) -> None:
        from evidence_responder import node_signer

        self._signer = node_signer(node_state)
        self.key_id = self._signer.key_id

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._signer.sign(body)


def test_a_checkpoint_without_its_statement_stays_a_link_in_the_chain(node_state):
    """A checkpoint persisted JSON-only (its COSE serialization failed) is no
    anchor, but its successor still proves records against it and a
    checkpoints answer still lists it."""
    _sealed(node_state, 1)
    later = _sealed(node_state, 1)
    path = node_state.ledger_dir / "checkpoints.jsonl"
    lines = [json.loads(x) for x in path.read_text().splitlines() if x]
    del lines[0]["checkpoint_cose"]
    path.write_text("".join(json.dumps(line, sort_keys=True) + "\n" for line in lines))

    store = MeshEvidenceStore(node_state.ledger_dir)
    assert len(store.anchors()) == 1
    result = handle_evidence_request(node_state, _record_request(later[0]["capsule_id"]))
    assert isinstance(result, er.Envelope), result
    (bundle,) = [Bundle.from_dict(b) for b in _body(result)["bundles"]]
    assert bundle.prior_checkpoint is not None and verify_bundle(bundle)[0]
    chain = handle_evidence_request(node_state, _request({"checkpoints": None}))
    assert _body(chain)["checkpoints"] == lines


def test_an_unmounted_segment_refuses_rather_than_shift_positions(node_state):
    caps = _sealed(node_state, 2)
    store = MeshEvidenceStore(node_state.ledger_dir)
    store.archived = [{"kind": "archived_segment", "first_seq": 1, "last_seq": 1}]
    result = er.answer(_record_request(caps[1]["capsule_id"]), store=store, signer=_Signer(node_state))
    assert isinstance(result, er.Refusal) and result.reason == "coverage_unsatisfiable"


def test_records_that_do_not_reproduce_the_anchor_root_are_refused(node_state):
    caps = _sealed(node_state, 2)
    store = MeshEvidenceStore(node_state.ledger_dir)
    store.records = list(reversed(store.records))  # same size, another root
    store.index_of = {r["capsule_id"]: i for i, r in enumerate(store.records)}
    result = er.answer(_record_request(caps[0]["capsule_id"]), store=store, signer=_Signer(node_state))
    assert isinstance(result, er.Refusal) and result.reason == "coverage_unsatisfiable"


def test_a_ledger_line_without_a_capsule_id_is_refused_not_raised(node_state):
    caps = _sealed(node_state, 2)
    store = MeshEvidenceStore(node_state.ledger_dir)
    store.records[1] = {**store.records[1], "capsule_id": "not hex"}
    result = er.answer(_record_request(caps[0]["capsule_id"]), store=store, signer=_Signer(node_state))
    assert isinstance(result, er.Refusal) and result.reason == "coverage_unsatisfiable"


def test_served_summary_is_pinned_to_the_latest_anchor_not_the_last_line(node_state):
    """A checkpoint persisted after the latest anchor without its statement
    must not make that anchor stale for served_summary/1."""
    _sealed(node_state, 1)
    _sealed(node_state, 1)
    path = node_state.ledger_dir / "checkpoints.jsonl"
    lines = [json.loads(x) for x in path.read_text().splitlines() if x]
    del lines[-1]["checkpoint_cose"]
    path.write_text("".join(json.dumps(line, sort_keys=True) + "\n" for line in lines))
    latest = MeshEvidenceStore(node_state.ledger_dir).anchors()[-1].digest
    result = handle_evidence_request(
        node_state, _request({"full_history": None}, {"expected_pin": latest}, derivation="served_summary/1")
    )
    assert isinstance(result, er.Envelope), result
