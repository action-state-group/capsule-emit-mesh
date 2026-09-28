# SPDX-License-Identifier: Apache-2.0
"""The door's claim checks: a provider that signs, with its own announced
key, a record naming another server (a role lie) or a swapped model is
refused, never held, so the pair can never read confirmed. The honest half is
still received, and a peer that is not the provider can never mark our
exchange."""

from __future__ import annotations

import json
import sys
import types

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit.signing import LocalKeypairSigner, sign_producer_envelope

import evidence_server as es
from peer_keys import ENV_PEER_KEYS
from record_push import (
    REASON_MODEL_MISMATCH,
    REASON_SERVED_BY_MISMATCH,
    REJECTED_PUSHES_FILENAME,
    handle_record_push,
)

REQ = "b" * 64
RESP = "c" * 64
PROVIDER = "c1f5490e053bee3c" + "0" * 48
OTHER = "f" * 64
ASKED = "1" * 64
SWAP = "2" * 64


def _key(tmp_path, name):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    d = tmp_path / name
    load_or_create_signing_key(d)
    return d / NODE_KEY_FILENAME


def _record(role, served_by, *, weights=None, model_id=None):
    ca = {"x-mesh-poc-v1": {"role": role, "serving_provenance": {"served_by_node_id": served_by}}}
    if weights:
        ca["weights_digest"] = {"digest_alg": "SHA-256", "digest": weights, "scope": "file"}
        ca["x-mesh-poc-v1"]["serving_provenance"]["model"] = {"weights_digest": weights}
    capsule = emit(
        action_type="decide",
        operator="op",
        developer="mesh-node@v1",
        compute_attestation=ca,
        effect=EffectRecord(status="confirmed", type="inference_completion", request_digest=REQ, response_digest=RESP),
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed"),
        tool_name="serve_exchange",
    )
    if model_id:
        capsule["model_attestation"]["model_id"] = model_id
    return capsule


def _signed(capsule, key_path):
    c = {k: v for k, v in capsule.items() if k not in ("signature", "key_id", "capsule_id")}
    signer = LocalKeypairSigner(key_path)
    c["key_id"] = signer.key_id
    c["capsule_id"] = compute_capsule_id(json.loads(json.dumps(c)))
    c["signature"], c["key_id"] = sign_producer_envelope(signer, c["capsule_id"])
    return c


def _requester(tmp_path, own_record):
    """The requester's door, holding its own requester record of the exchange."""
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    (ledger / "capsules.jsonl").write_text(json.dumps(own_record) + "\n")
    return es.EvidenceServerState(
        ledger_dir=ledger,
        ledger_path=ledger / "capsules.jsonl",
        signing_key_path=_key(tmp_path, "requester-keys"),
        share_policy=None,
        received_log_dir=None,
    )


def _push(state, capsule, sender, monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({sender: capsule["key_id"]}))
    return handle_record_push(state, json.dumps(capsule).encode(), sender_peer_id=sender)


def _rejected(state):
    path = state.ledger_dir / REJECTED_PUSHES_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


OWN = _record("requested", PROVIDER, model_id=f"local-gguf/sha256-{ASKED}")


def test_honest_served_half_is_received(tmp_path, monkeypatch):
    state = _requester(tmp_path, OWN)
    half = _signed(_record("served", PROVIDER, weights=ASKED, model_id=f"local-gguf/sha256-{ASKED}"), _key(tmp_path, "p"))
    assert _push(state, half, PROVIDER, monkeypatch) == {"status": "received"}


def test_b2_provider_signs_a_role_lie_with_its_own_key_is_refused(tmp_path, monkeypatch):
    state = _requester(tmp_path, OWN)
    lie = _signed(_record("served", OTHER, weights=ASKED, model_id=f"local-gguf/sha256-{ASKED}"), _key(tmp_path, "p"))
    reply = _push(state, lie, PROVIDER, monkeypatch)
    assert reply["reason"] == REASON_SERVED_BY_MISMATCH
    rejected = _rejected(state)
    assert rejected[-1]["reason"] == REASON_SERVED_BY_MISMATCH
    assert rejected[-1]["request_digest"] == REQ
    assert not (state.ledger_dir / "received-capsules.jsonl").exists(), "never held"


def test_d1_provider_resigns_a_model_swap_is_refused(tmp_path, monkeypatch):
    state = _requester(tmp_path, OWN)
    swap = _signed(_record("served", PROVIDER, weights=SWAP, model_id=f"local-gguf/sha256-{SWAP}"), _key(tmp_path, "p"))
    reply = _push(state, swap, PROVIDER, monkeypatch)
    assert reply["reason"] == REASON_MODEL_MISMATCH
    assert _rejected(state)[-1]["request_digest"] == REQ


def test_a_half_whose_own_weights_claims_disagree_is_refused(tmp_path, monkeypatch):
    state = _requester(tmp_path, OWN)
    half = _record("served", PROVIDER, weights=ASKED, model_id=f"local-gguf/sha256-{ASKED}")
    half["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["model"]["weights_digest"] = SWAP
    reply = _push(state, _signed(half, _key(tmp_path, "p")), PROVIDER, monkeypatch)
    assert reply["reason"] == REASON_MODEL_MISMATCH


def test_a_node_we_did_not_route_to_cannot_answer_for_our_exchange(tmp_path, monkeypatch):
    """Another peer, with its own announced key, pushes a served half naming
    itself: our record says the exchange went to PROVIDER."""
    state = _requester(tmp_path, OWN)
    half = _signed(_record("served", OTHER, weights=ASKED), _key(tmp_path, "o"))
    reply = _push(state, half, OTHER, monkeypatch)
    assert reply["reason"] == REASON_SERVED_BY_MISMATCH


def test_without_our_own_record_or_weights_nothing_is_invented(tmp_path, monkeypatch):
    """Stock requesters name no server and no weights on their own record: only
    the half's own consistency and its sender are checked."""
    state = _requester(tmp_path, _record("requested", "unknown", model_id="qwen"))
    half = _signed(_record("served", PROVIDER, weights=SWAP, model_id=f"local-gguf/sha256-{SWAP}"), _key(tmp_path, "p"))
    assert _push(state, half, PROVIDER, monkeypatch) == {"status": "received"}
