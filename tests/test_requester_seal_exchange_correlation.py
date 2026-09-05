#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[b6a-requester-seal] Requester own-half seal + exchange_id correlation.

Proves the two rung-1/2 mechanics this task makes first-class:

  1. REQUESTER OWN-HALF SEAL. capsule_sidecar.py, run with role="requester",
     seals the requestor's OWN half of an exchange (its request, its nonce, the
     response it received) as an independent, self-verifying capsule. The
     record honestly names itself the requester's half: serving_provenance.role
     == "requester", requesting_party == this node, served_by_node_id ==
     "unknown" (a requester's outbound sidecar does not see the serving node id
     at the wire, so it never fabricates one).

  2. EXCHANGE_ID CORRELATION. Both halves of ONE exchange record the SAME
     exchange_id, taken from the response `id` (the host's terminal-event /
     response-id lineage — the same field the Rust admission-policy plugin uses
     for serving_provenance.exchange_id). A third party holding both capsules
     lines them up on serving_provenance.exchange_id; two DIFFERENT exchanges do
     NOT collapse together.

SCOPE GUARD (negative-check mandate): these tests assert the correlator ties
the two halves AND that this is NOT the Move-4 acknowledgment leg — the
requester capsule carries no ack of the provider's capsule_id (no
cross_party.counterparty_ref pointing at the provider's capsule). That upgrade
(full_bilateral) is spec-gated and deliberately NOT built here.

MODULE-POLLUTION GUARD: see test_record_capsule_write_before_verify.py — sibling
test files setattr fakes onto the shared agent_action_capsule/model_identity
modules at collection time, so real modules are reloaded at EXECUTION time.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import capsule_sidecar as cs

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


def _state(tmp_path: Path, *, role: str, node_id: str) -> "cs.NodeState":
    _real_capsule_sidecar()
    manifest_path = tmp_path / f"manifest-{node_id}.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs.default_state(
        ledger_dir=tmp_path / f"ledger-{node_id}",
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


def _seal(state: "cs.NodeState", response_json: dict, *, peer_capsule_id: str | None = None) -> dict:
    """Seal one half over a full response object, deriving exchange_id the same
    way the live handler does."""
    cs_mod = _real_capsule_sidecar()
    exchange_id, source = cs_mod.exchange_id_from_response(response_json)
    return cs_mod.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="client_supplied",
        request_json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "temperature": 0.2},
        request_digest="a" * 64,
        status="confirmed",
        response_digest=cs_mod.digest_json(response_json),
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
        exchange_id=exchange_id,
        exchange_id_source=source,
        peer_capsule_id=peer_capsule_id,
    )


# ---------------------------------------------------------------------------
# 1. exchange_id derivation from the response id (the shared correlator source)
# ---------------------------------------------------------------------------

def test_exchange_id_derived_from_response_id() -> None:
    cs_mod = _real_capsule_sidecar()
    xid, source = cs_mod.exchange_id_from_response({"id": "chatcmpl-abc123", "object": "chat.completion"})
    assert xid == "chatcmpl-abc123"
    assert source == cs_mod.EXCHANGE_ID_SOURCE == "response_id"


def test_exchange_id_unknown_when_response_has_no_id() -> None:
    """Never fabricated: an id-less response (error object / truncated stream)
    yields "unknown"/"unavailable", so a verifier can tell not-correlatable
    apart from a real correlator."""
    cs_mod = _real_capsule_sidecar()
    for resp in ({"error": {"message": "boom"}}, {"id": ""}, {"id": None}):
        xid, source = cs_mod.exchange_id_from_response(resp)
        assert xid == "unknown"
        assert source == "unavailable"


# ---------------------------------------------------------------------------
# 2. Requester own-half seal — the record names itself honestly
# ---------------------------------------------------------------------------

def test_requester_role_seals_own_half(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-node-1")
    response = {"id": "chatcmpl-xyz", "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}
    capsule = _seal(state, response)

    # Self-verifying (real verify()).
    from agent_action_capsule.verify import verify as verify_capsule
    assert verify_capsule(capsule).ok, verify_capsule(capsule).findings

    sp = _serving_provenance(capsule)
    assert sp["role"] == cs_mod.ROLE_REQUESTER
    # The requester IS the requesting party; it does not claim to have served.
    assert sp["requesting_party"] == "req-node-1"
    assert sp["served_by_node_id"] == "unknown"
    # The own-half capsule records the response it received AND the request it
    # made — that is what makes it the requester's half, not a bare receipt.
    assert sp["exchange_id"] == "chatcmpl-xyz"
    assert capsule["model_attestation"]["compute_attestation"]["agent_input_digest"] == "a" * 64


def test_provider_role_is_the_default_and_claims_it_served(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="prov-node-1")
    assert state.role == cs_mod.ROLE_PROVIDER  # default role
    response = {"id": "chatcmpl-xyz", "object": "chat.completion"}
    capsule = _seal(state, response)
    sp = _serving_provenance(capsule)
    assert sp["role"] == cs_mod.ROLE_PROVIDER
    assert sp["served_by_node_id"] == "prov-node-1"


def test_role_is_validated(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    try:
        _state(tmp_path, role="bystander", node_id="x")
    except ValueError as exc:
        assert "role must be one of" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("invalid role was accepted")


# ---------------------------------------------------------------------------
# 3. Correlation: the two halves of ONE exchange are joinable on exchange_id
# ---------------------------------------------------------------------------

def test_two_halves_of_one_exchange_share_exchange_id(tmp_path: Path) -> None:
    """The provider (served-half) and requester (own-half) sidecars observe the
    SAME response object, so both record the SAME exchange_id — a third party
    joins them on serving_provenance.exchange_id."""
    cs_mod = _real_capsule_sidecar()
    response = {"id": "chatcmpl-shared-777", "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}

    provider_state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="prov-1")
    provider_cap = _seal(provider_state, response)
    requester_state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-1")
    requester_cap = _seal(requester_state, response)

    prov_sp = _serving_provenance(provider_cap)
    req_sp = _serving_provenance(requester_cap)

    # JOINABLE: same exchange_id ties the two halves together.
    assert prov_sp["exchange_id"] == req_sp["exchange_id"] == "chatcmpl-shared-777"
    # DISTINGUISHABLE: the halves are different vantage points (roles differ),
    # so a verifier can tell them apart while still joining them.
    assert prov_sp["role"] != req_sp["role"]
    # Independent identities: the two capsules are distinct records (different
    # content addresses), not one record counted twice.
    assert provider_cap["capsule_id"] != requester_cap["capsule_id"]


def test_different_exchanges_do_not_collapse(tmp_path: Path) -> None:
    """Two DIFFERENT exchanges (different response ids) must NOT share an
    exchange_id — the correlator would otherwise be meaningless."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-1")
    cap_a = _seal(state, {"id": "chatcmpl-AAA", "object": "chat.completion"})
    cap_b = _seal(state, {"id": "chatcmpl-BBB", "object": "chat.completion"})
    assert _serving_provenance(cap_a)["exchange_id"] != _serving_provenance(cap_b)["exchange_id"]


# ---------------------------------------------------------------------------
# 4. SCOPE GUARD — this is rung-1/2, NOT the Move-4 ack leg / full_bilateral
# ---------------------------------------------------------------------------

def test_requester_capsule_does_not_carry_move4_ack(tmp_path: Path) -> None:
    """The requester's own-half capsule is an INDEPENDENT half-record sharing a
    correlator. It is NOT the Move-4 acknowledgment leg: it does not sign or
    reference the provider's capsule_id. If any cross_party block is present it
    must not point back at a counterparty capsule as an ack (that is the
    spec-gated full_bilateral upgrade, deliberately out of scope)."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-1")
    # Seal with NO bilateral_eval — the requester own-half seal must stand on
    # its own without any ack machinery.
    capsule = _seal(state, {"id": "chatcmpl-noack", "object": "chat.completion"})
    poc = capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    cross_party = poc.get("cross_party")
    # No ack leg: either no cross_party block at all, or one that carries no
    # counterparty_ref acknowledging a provider capsule_id.
    assert cross_party is None or cross_party.get("counterparty_ref") is None


# ---------------------------------------------------------------------------
# 4b. [mesh-requester-nonce-addendum] serving_provenance.counterparty_ref —
#     the peer's own X-Capsule-Id, read back off the raw-proxy return.
#
# Distinct from the Move-4/bilateral `cross_party.counterparty_ref` the scope
# guard above pins to None: this is an UNVERIFIED, unauthenticated observation
# (the peer's raw response header), not an acknowledgment the requester
# signed. It narrows the "served_by_node_id: unknown" gap without claiming
# node identity — a capsule_id, not a node_id.
# ---------------------------------------------------------------------------


def test_requester_capsule_carries_peer_capsule_id_as_counterparty_ref(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-1")
    capsule = _seal(
        state,
        {"id": "chatcmpl-peer-ref", "object": "chat.completion"},
        peer_capsule_id="capsule-peer-abc",
    )
    sp = _serving_provenance(capsule)
    assert sp["counterparty_ref"] == "capsule-peer-abc"
    assert sp["counterparty_ref_provenance"] == "peer_asserted"


def test_requester_capsule_without_a_peer_capsule_id_leaves_counterparty_ref_absent(tmp_path: Path) -> None:
    """Mutant: no `X-Capsule-Id` header on the upstream response -- both
    fields stay honestly `None`, never invented."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-2")
    capsule = _seal(state, {"id": "chatcmpl-no-peer-ref", "object": "chat.completion"})
    sp = _serving_provenance(capsule)
    assert sp["counterparty_ref"] is None
    assert sp["counterparty_ref_provenance"] is None


def test_requester_capsule_records_an_injected_peer_capsule_id_as_peer_asserted_never_verified(
    tmp_path: Path,
) -> None:
    """Mutant: a substitute/injected `X-Capsule-Id` is still recorded (this
    layer cannot distinguish a genuine peer value from an injected one over
    an unauthenticated header) -- but it is NEVER sealed as anything other
    than `peer_asserted`. Verification is out of scope here by design."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-3")
    capsule = _seal(
        state,
        {"id": "chatcmpl-injected", "object": "chat.completion"},
        peer_capsule_id="injected-not-really-the-peers",
    )
    sp = _serving_provenance(capsule)
    assert sp["counterparty_ref"] == "injected-not-really-the-peers"
    assert sp["counterparty_ref_provenance"] == "peer_asserted"


def test_provider_capsule_never_carries_a_counterparty_ref(tmp_path: Path) -> None:
    """A provider-role capsule served the request itself -- there is no peer
    to hold a capsule reference for, so both fields stay None even if a
    caller mistakenly passed one."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="prov-1")
    capsule = _seal(
        state,
        {"id": "chatcmpl-provider", "object": "chat.completion"},
        peer_capsule_id="capsule-should-be-ignored",
    )
    sp = _serving_provenance(capsule)
    assert sp["counterparty_ref"] is None
    assert sp["counterparty_ref_provenance"] is None


# ---------------------------------------------------------------------------
# 5. [mesh-b1-requestor-capsule-ledger] PROVISIONAL role/observation_point
#    (CPB #70 vocabulary, hard-coded ahead of its promotion)
# ---------------------------------------------------------------------------

def _poc(capsule: dict) -> dict:
    return capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]


def test_requester_capsule_carries_provisional_role_requested_and_client_egress(tmp_path: Path) -> None:
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-node-1")
    capsule = _seal(state, {"id": "chatcmpl-role-req", "object": "chat.completion"})
    poc = _poc(capsule)
    assert poc["role"] == "requested"
    assert poc["observation_point"] == "client_egress"


def test_provider_capsule_carries_provisional_role_served_and_serving_host_ingress(tmp_path: Path) -> None:
    """Mirrors the requester-side field: the provider half gets the CPB #70
    pairing its own vantage requires (serving_host_ingress -> served)."""
    cs_mod = _real_capsule_sidecar()
    state = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="prov-node-1")
    capsule = _seal(state, {"id": "chatcmpl-role-prov", "object": "chat.completion"})
    poc = _poc(capsule)
    assert poc["role"] == "served"
    assert poc["observation_point"] == "serving_host_ingress"


def test_provisional_role_field_has_a_single_labeled_definition() -> None:
    """ACCEPTANCE: 'the provisional role field is a single labeled definition
    (grep shows the PROVISIONAL comment)'. Guards against a future hand-copy
    of the "requested"/"served" literals landing without the CPB #70 label,
    which would silently fork the vocabulary from its one source of truth."""
    source = Path(__file__).resolve().parent.parent / "capsule_sidecar.py"
    text = source.read_text(encoding="utf-8")
    assert text.count("# PROVISIONAL: pending CPB #70 promotion") == 1


def test_two_requesters_same_exchange_each_independently_offline_verifiable(tmp_path: Path) -> None:
    """ACCEPTANCE: 'two requesters, same exchange -> each half independently
    offline-verifiable'. Two DIFFERENT requester nodes (e.g. both dialing the
    same shared/broadcast provider) each seal their own-half capsule for the
    SAME exchange_id. This is NOT a join (that's B2, out of scope): each
    capsule stands alone and verifies on its own bytes, with no reference to
    the other."""
    from agent_action_capsule.verify import verify as verify_capsule

    cs_mod = _real_capsule_sidecar()
    response = {
        "id": "chatcmpl-shared-two-requesters",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    }
    state_a = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-a")
    cap_a = _seal(state_a, response)
    state_b = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-b")
    cap_b = _seal(state_b, response)

    # Each half is independently, offline-verifiable on its own bytes.
    result_a = verify_capsule(cap_a)
    result_b = verify_capsule(cap_b)
    assert result_a.ok, result_a.findings
    assert result_b.ok, result_b.findings

    # Distinct records (different requesting_party, different capsule_id) --
    # not one exchange collapsed into a single shared capsule.
    poc_a, poc_b = _poc(cap_a), _poc(cap_b)
    assert poc_a["role"] == poc_b["role"] == "requested"
    assert poc_a["observation_point"] == poc_b["observation_point"] == "client_egress"
    assert cap_a["capsule_id"] != cap_b["capsule_id"]
    sp_a, sp_b = _serving_provenance(cap_a), _serving_provenance(cap_b)
    assert sp_a["requesting_party"] == "req-a"
    assert sp_b["requesting_party"] == "req-b"
    # Both still carry the SAME shared correlator -- joinable later (B2), not
    # joined here: no reference to the other capsule's id in either record.
    assert sp_a["exchange_id"] == sp_b["exchange_id"] == "chatcmpl-shared-two-requesters"
