# SPDX-License-Identifier: Apache-2.0
"""Tests for [mesh-adjudication-delivery-ack] -- ``adjudication_delivery.py``
and its ``POST /evidence/deliver`` door on ``evidence_server.py``.

Acceptance / mutants that must flip (inbox item):
  - corroborated twin -> both providers' chains show it delivered
    (`{"status": "received"}`, folded into the recipient's own ledger).
  - contradicted verdict, cited party is the contradicted owner -> that
    party's chain shows NOTHING (refused, `policy_decline`, never
    `received()`d); the refusal itself is signed and offline-verifiable so
    the requester can hold it (`seal_adjudication_ack_refused`).
  - a delivery whose citations don't include the recipient's own half ->
    `request_malformed`, never `received()`s a verdict about someone else,
    and the recipient's ledger is untouched.

See ``test_twin_adjudicator.py`` for the fixture-half conventions this
file reuses (``compute_attestation.owner.owner_id`` as the E17a/test-fixture
owner convention).
"""
from __future__ import annotations

import json
import sys
import threading
import types
import urllib.error
import urllib.request

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit.evidence_request import verify_refusal_offline
from capsule_emit.ledger import read_ledger

import evidence_server as es
from adjudication_delivery import (
    REASON_POLICY_DECLINE,
    REASON_REQUEST_MALFORMED,
    RELATION_ADJUDICATION_ACK_REFUSED,
    deliver_adjudication,
    handle_delivery,
    seal_adjudication_ack_refused,
)
from checkpointing import JsonlLogSource
from twin_adjudicator import adjudicate, contradicted, seal_adjudication_capsule

REQUEST_DIGEST = "a" * 64


def _response_body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _make_served_half(text: str, *, owner_id: str) -> tuple[dict, dict]:
    """A self-consistent, verifiable served-half capsule + its disclosed
    preimage -- the same shape ``test_twin_adjudicator.py``'s ``_make_half``
    builds, minus the ``AdjudicationHalf`` wrapper (this file needs the raw
    capsule dict to append to a ledger)."""
    from capsule_sidecar import digest_json

    body = _response_body(text)
    digest = digest_json(body)
    effect = EffectRecord(status="confirmed", type="inference_completion", request_digest=REQUEST_DIGEST, response_digest=digest)
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    capsule = emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation={"owner": {"owner_id": owner_id}},
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return capsule, disclosed


def _state(ledger_path, signing_key_path) -> "es.EvidenceServerState":
    return es.EvidenceServerState(ledger_path=ledger_path, signing_key_path=signing_key_path)


def _seed_ledger(ledger_path, capsule: dict) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    JsonlLogSource(ledger_path).append(capsule)


def _keys(tmp_path):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    return keys_dir / NODE_KEY_FILENAME


# ---------------------------------------------------------------------------
# handle_delivery -- pure, no HTTP
# ---------------------------------------------------------------------------


def test_corroborated_delivery_is_received_and_folded_into_ledger(tmp_path):
    from twin_adjudicator import AdjudicationHalf

    cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
    cap_b, disc_b = _make_served_half("hello world", owner_id="owner-b")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
    outcome = adjudicate(half_a, half_b)
    adjudication = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")
    assert adjudication is not None  # corroborated -- a verdict was sealed

    # M3 (owner-b) already holds its own served half; deliver the verdict.
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "m3-ledger" / "capsules.jsonl"
    _seed_ledger(ledger_path, cap_b)
    state = _state(ledger_path, key_path)

    body = json.dumps(adjudication).encode("utf-8")
    result = handle_delivery(state, body)

    assert result == {"status": "received"}
    ledger_ids = [c["capsule_id"] for c in read_ledger(ledger_path)]
    assert cap_b["capsule_id"] in ledger_ids
    assert adjudication["capsule_id"] in ledger_ids


def test_contradicted_verdict_naming_recipient_refuses_policy_decline(tmp_path):
    from twin_adjudicator import AdjudicationHalf

    cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
    cap_b, disc_b = _make_served_half("goodbye world", owner_id="owner-b")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
    outcome = adjudicate(half_a, half_b)
    # This module's own adjudicate() never returns contradicted:<owner>
    # (needs the E17b/E17c referee tiebreak) -- force the shape the way
    # test_twin_adjudicator.py's own test_contradicted_shape_reused_by_seal
    # does, standing in for a referee-backed caller.
    forced = outcome.__class__(**{**outcome.__dict__, "verdict": contradicted("owner-b")})
    adjudication = seal_adjudication_capsule(forced, operator="test-org", developer="referee@v1")

    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "gcp-ledger" / "capsules.jsonl"
    _seed_ledger(ledger_path, cap_b)
    state = _state(ledger_path, key_path)
    before = ledger_path.read_bytes()

    body = json.dumps(adjudication).encode("utf-8")
    result = handle_delivery(state, body)

    assert result["reason"] == REASON_POLICY_DECLINE
    assert "sig" in result and "key_id" in result
    # GCP's chain shows nothing -- the ledger is byte-identical to before.
    assert ledger_path.read_bytes() == before


def test_delivery_not_citing_recipients_own_half_refuses_malformed(tmp_path):
    from twin_adjudicator import AdjudicationHalf

    cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
    cap_b, disc_b = _make_served_half("hello world", owner_id="owner-b")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
    outcome = adjudicate(half_a, half_b)
    adjudication = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

    # A THIRD node, never cited by this adjudication, receives the delivery.
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "stranger-ledger" / "capsules.jsonl"
    cap_c, _disc_c = _make_served_half("unrelated exchange", owner_id="owner-c")
    _seed_ledger(ledger_path, cap_c)
    state = _state(ledger_path, key_path)
    before = ledger_path.read_bytes()

    body = json.dumps(adjudication).encode("utf-8")
    result = handle_delivery(state, body)

    assert result["reason"] == REASON_REQUEST_MALFORMED
    assert ledger_path.read_bytes() == before  # never received() a verdict about someone else


def test_forged_adjudication_capsule_refuses_malformed(tmp_path):
    from twin_adjudicator import AdjudicationHalf

    cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
    cap_b, disc_b = _make_served_half("hello world", owner_id="owner-b")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
    outcome = adjudicate(half_a, half_b)
    adjudication = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")
    forged = dict(adjudication)
    forged["operator"] = "attacker-org"  # content changed, signature stale

    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "m3-ledger" / "capsules.jsonl"
    _seed_ledger(ledger_path, cap_b)
    state = _state(ledger_path, key_path)

    result = handle_delivery(state, json.dumps(forged).encode("utf-8"))
    assert result["reason"] == REASON_REQUEST_MALFORMED


def test_malformed_body_refuses_never_raises(tmp_path):
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    state = _state(ledger_path, key_path)
    result = handle_delivery(state, b"not json")
    assert result["reason"] == REASON_REQUEST_MALFORMED


def test_refusal_verifies_offline(tmp_path):
    from capsule_emit.evidence_request import Refusal

    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    state = _state(ledger_path, key_path)
    result = handle_delivery(state, b"not json")
    refusal = Refusal(**{k: result[k] for k in ("request_digest", "reason", "issued_at", "key_id", "sig")})
    assert verify_refusal_offline(refusal)


# ---------------------------------------------------------------------------
# seal_adjudication_ack_refused -- the requester's own record of a decline
# ---------------------------------------------------------------------------


def test_ack_refused_capsule_cites_the_original_verdict(tmp_path):
    from twin_adjudicator import AdjudicationHalf

    cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
    cap_b, disc_b = _make_served_half("goodbye world", owner_id="owner-b")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
    outcome = adjudicate(half_a, half_b)
    forced = outcome.__class__(**{**outcome.__dict__, "verdict": contradicted("owner-b")})
    adjudication = seal_adjudication_capsule(forced, operator="test-org", developer="referee@v1")

    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "gcp-ledger" / "capsules.jsonl"
    _seed_ledger(ledger_path, cap_b)
    state = _state(ledger_path, key_path)
    refusal = handle_delivery(state, json.dumps(adjudication).encode("utf-8"))
    assert refusal["reason"] == REASON_POLICY_DECLINE

    ack_refused = seal_adjudication_ack_refused(adjudication, refusal, operator="test-org", developer="referee@v1")
    assert ack_refused["chain"]["relation"] == RELATION_ADJUDICATION_ACK_REFUSED
    assert ack_refused["chain"]["parent_capsule_id"] == adjudication["capsule_id"]
    block = ack_refused["model_attestation"]["compute_attestation"]["adjudication_ack_refused"]
    assert block["adjudication_capsule_id"] == adjudication["capsule_id"]
    assert block["refusal"]["reason"] == REASON_POLICY_DECLINE


# ---------------------------------------------------------------------------
# Over HTTP -- POST /evidence/deliver on evidence_server.py
# ---------------------------------------------------------------------------


class _RunningServer:
    def __init__(self, state: "es.EvidenceServerState"):
        self.server = es.run_evidence_server(host="127.0.0.1", port=0, state=state)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)


class TestEvidenceDeliverOverHTTP:
    def test_corroborated_delivery_returns_received_status_200(self, tmp_path):
        from twin_adjudicator import AdjudicationHalf

        cap_a, disc_a = _make_served_half("hello world", owner_id="owner-a")
        cap_b, disc_b = _make_served_half("hello world", owner_id="owner-b")
        half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, disc_a)
        half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, disc_b)
        outcome = adjudicate(half_a, half_b)
        adjudication = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "m3-ledger" / "capsules.jsonl"
        _seed_ledger(ledger_path, cap_b)
        state = _state(ledger_path, key_path)
        server = _RunningServer(state)
        try:
            result = deliver_adjudication(adjudication, server.base_url)
        finally:
            server.close()

        assert result == {"status": "received"}
        assert adjudication["capsule_id"] in [c["capsule_id"] for c in read_ledger(ledger_path)]

    def test_unknown_path_still_404s(self, tmp_path):
        key_path = _keys(tmp_path)
        ledger_path = tmp_path / "ledger" / "capsules.jsonl"
        state = _state(ledger_path, key_path)
        server = _RunningServer(state)
        try:
            req = urllib.request.Request(f"{server.base_url}/nope", method="POST", data=b"{}")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.close()
