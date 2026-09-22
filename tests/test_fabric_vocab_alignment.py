# SPDX-License-Identifier: Apache-2.0
"""[mesh-fabric-vocab-alignment] -- epistemic_type on every record the
plugin/sidecar seals: provider half producer_claim, requester half
observed_event, join card producer_claim, adjudication adjudication,
history-card outputs derived_metric. One additive field, checked at each
seal site's own module boundary; no existing field's value changes (see the
per-module tests this file complements: test_join_card.py,
test_twin_adjudicator.py, test_history_card.py, test_live_referee.py).
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import capsule_sidecar as cs  # noqa: E402
from join_card import (  # noqa: E402
    CARD_SUBJECT_KEY,
    EPISTEMIC_TYPE_PRODUCER_CLAIM as JOIN_CARD_EPISTEMIC_TYPE_PRODUCER_CLAIM,
    ModelRef,
    build_card,
    nostr_pubkey_principal_ref,
    seal_card,
)

# history_card.py's and twin_adjudicator.py's own epistemic_type/status
# assertions live alongside their existing fixture helpers in
# test_history_card.py / test_twin_adjudicator.py respectively -- see
# test_multi_checkpoint_cadence_seals_and_round_trip_verifies and
# test_identical_transcripts_corroborated_offline_no_network in those files.


@pytest.fixture(autouse=True)
def _real_load_manifest(monkeypatch):
    """test_forwarded_copy_and_keys.py permanently replaces
    `model_identity.load_manifest` with `lambda p: {}` on `sys.modules` at
    collection time (its own module docstring explains why -- a stub, never
    reverted) whenever it is the first file to import `model_identity` in
    this process. If that happens before this file's `cs.NodeState` is built,
    `_make_state`'s real `manifest.json` is silently read as `{}` and
    `state.manifest["model_id"]` KeyErrors downstream -- a collection-order
    hazard, not a bug in either file. Force `cs.load_manifest` back to a real
    reader for every test in this file, independent of collection order."""
    monkeypatch.setattr(cs, "load_manifest", lambda p: json.loads(p.read_text()))


def _compute_attestation(capsule: dict) -> dict:
    return capsule["model_attestation"]["compute_attestation"]


def _make_state(**overrides) -> cs.NodeState:
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "manifest.json").write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    return cs.NodeState(
        node_id="mesh-node-demo-1",
        operator="op",
        developer="dev",
        signing_key_pem=b"unused",
        signing_key_path=d / "keys" / "node-key.pem",
        manifest_path=d / "manifest.json",
        runtime_label="rt",
        runtime_digest="0" * 64,
        ledger_dir=d / "ledger",
        **overrides,
    )


def _build(state) -> dict:
    return cs.build_capsule(
        state,
        client_nonce="n",
        client_nonce_source="client_supplied",
        request_json={"model": "m", "temperature": 0.7},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )


def test_provider_role_seals_producer_claim():
    state = _make_state(role=cs.ROLE_PROVIDER)
    capsule = _build(state)
    assert _compute_attestation(capsule)["epistemic_type"] == "producer_claim"


def test_requester_role_seals_observed_event():
    state = _make_state(role=cs.ROLE_REQUESTER)
    capsule = _build(state)
    assert _compute_attestation(capsule)["epistemic_type"] == "observed_event"


def test_join_card_seals_producer_claim_and_optional_principal_ref():
    card = build_card(node_id="n1", hardware_inventory=None, models=[ModelRef(name="m/1")])
    capsule = seal_card(card, operator="op", developer="dev", signing_node_id="n1")
    ca = _compute_attestation(capsule)
    assert ca["epistemic_type"] == JOIN_CARD_EPISTEMIC_TYPE_PRODUCER_CLAIM == "producer_claim"
    # principal_ref absent by default -- this HONEST GAP is asserted, not just implied.
    assert ca[CARD_SUBJECT_KEY]["card"]["principal_ref"] is None


def test_join_card_carries_principal_ref_under_nostr_pubkey_profile_when_wired():
    pubkey_hex = "ab" * 32
    card = build_card(
        node_id="n1",
        hardware_inventory=None,
        models=[ModelRef(name="m/1")],
        principal_ref=nostr_pubkey_principal_ref(pubkey_hex),
    )
    assert card.principal_ref == f"nostr-pubkey:{pubkey_hex}"
    capsule = seal_card(card, operator="op", developer="dev", signing_node_id="n1")
    assert _compute_attestation(capsule)[CARD_SUBJECT_KEY]["card"]["principal_ref"] == f"nostr-pubkey:{pubkey_hex}"


def test_sidecar_seal_join_card_wires_nostr_pubkey_end_to_end(monkeypatch, tmp_path):
    """capsule_sidecar.seal_join_card actually threads NodeState.nostr_pubkey_hex
    through to the sealed card's principal_ref -- not a TODO, end-to-end."""
    monkeypatch.setenv("CAPSULE_WITNESS", "stub")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        nostr_pubkey_hex="cd" * 32,
    )
    monkeypatch.setattr(cs, "capture_mac_hardware_inventory", lambda: None)
    capsule_id = cs.seal_join_card(state)
    lines, _ = cs.read_all_capsules(state.ledger_dir)
    sealed = next(line for line in lines if line["capsule_id"] == capsule_id)
    ca = _compute_attestation(sealed)
    assert ca[CARD_SUBJECT_KEY]["card"]["principal_ref"] == f"nostr-pubkey:{'cd' * 32}"


