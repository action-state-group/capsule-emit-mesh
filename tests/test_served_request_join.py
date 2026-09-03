#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-b2-served-request-join] The served<->request cryptographic join.

Proves `served_request_join.join_served_request` mints a join capsule that:

  1. Cites the PROVIDER's served-half capsule by CPB typed digest reference
     (`type: "capsule"`, `digest_alg: "SHA-256"`, `citation_purpose:
     "responds_to"`) in its top-level `references` array.
  2. Chains onto the REQUESTER's own ledger (`chain.parent_capsule_id ==
     requester capsule_id`, `chain.relation == "confirms"`) — never the
     provider's, per the {{xref}} boundary rule (chain = same-stream,
     references = everything else).
  3. Commits `references` to its own `capsule_id`: tampering the cited
     digest post-seal must flip `verify()` to fail — the join is a real
     signed claim, not a display-only label.
  4. Refuses to mint when: either half fails its own `verify()`; the two
     halves are not the roles they claim (swapped/duplicated args); the two
     halves do not share one `exchange_id`.

Mirrors `tests/test_requester_seal_exchange_correlation.py`'s harness so both
halves are real, `agent_action_capsule.verify()`-clean `capsule_sidecar.
build_capsule()` output, not hand-built fixtures.
"""
from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

import capsule_sidecar as cs
import served_request_join as srj

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _real_modules():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    importlib.reload(srj)
    return cs, srj


def _state(tmp_path: Path, *, role: str, node_id: str) -> "cs.NodeState":
    cs_mod, _ = _real_modules()
    manifest_path = tmp_path / f"manifest-{node_id}.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs_mod.default_state(
        ledger_dir=tmp_path / f"ledger-{node_id}",
        manifest_path=manifest_path,
        keys_dir=tmp_path / f"keys-{node_id}",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=role,
        node_id=node_id,
    )


def _seal(state: "cs.NodeState", response_json: dict) -> dict:
    cs_mod, _ = _real_modules()
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
    )


def _response(exchange_id: str) -> dict:
    return {
        "id": exchange_id,
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    }


def _halves(tmp_path: Path, *, exchange_id: str = "chatcmpl-shared-exchange") -> tuple[dict, dict]:
    """One provider served-half + one requester own-half, same exchange."""
    _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    response = _response(exchange_id)
    provider_capsule = _seal(provider_state, response)
    requester_capsule = _seal(requester_state, response)
    return provider_capsule, requester_capsule


# ---------------------------------------------------------------------------
# 1. the join itself
# ---------------------------------------------------------------------------


def test_join_verifies_offline(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(joined)
    assert result.ok, result.findings


def test_join_references_entry_cites_provider_with_responds_to(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    assert joined["references"] == [
        {
            "type": "capsule",
            "digest_alg": "SHA-256",
            "digest": provider_capsule["capsule_id"],
            "citation_purpose": "responds_to",
        }
    ]


def test_join_chains_onto_requesters_own_half_not_the_providers(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    assert joined["chain"]["parent_capsule_id"] == requester_capsule["capsule_id"]
    assert joined["chain"]["relation"] == "confirms"


def test_join_reference_target_differs_from_chain_parent(tmp_path: Path) -> None:
    """{{xref}} boundary rule: a `references` entry MUST NOT name the same
    target as `chain.parent_capsule_id` -- the join always cites a DIFFERENT
    producer's capsule (provider) than the one it chains onto (requester)."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    assert joined["references"][0]["digest"] != joined["chain"]["parent_capsule_id"]
    assert provider_capsule["capsule_id"] != requester_capsule["capsule_id"]


def test_join_carries_the_shared_exchange_id_self_contained(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path, exchange_id="chatcmpl-xid-carried")
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    compute_attestation = joined["model_attestation"]["compute_attestation"]
    assert compute_attestation["served_request_join"]["exchange_id"] == "chatcmpl-xid-carried"


# ---------------------------------------------------------------------------
# 2. capsule_id commits references -- the join is a real signed claim
# ---------------------------------------------------------------------------


def test_tampered_reference_digest_fails_verify(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    tampered = copy.deepcopy(joined)
    tampered["references"][0]["digest"] = "b" * 64

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(tampered)
    assert not result.ok
    assert any(f.code == "capsule_id_mismatch" for f in result.findings)


def test_stripping_references_fails_verify(tmp_path: Path) -> None:
    """`references` is digest-bearing: dropping it after seal must be caught
    exactly like tampering it (capsule_id was computed WITH it present)."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule)

    tampered = copy.deepcopy(joined)
    del tampered["references"]

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(tampered)
    assert not result.ok
    assert any(f.code == "capsule_id_mismatch" for f in result.findings)


# ---------------------------------------------------------------------------
# 3. refusals -- never silently join what shouldn't be joined
# ---------------------------------------------------------------------------


def test_refuses_when_exchange_ids_differ(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    provider_capsule = _seal(provider_state, _response("chatcmpl-exchange-a"))
    requester_capsule = _seal(requester_state, _response("chatcmpl-exchange-b"))

    with pytest.raises(srj_mod.ExchangeIdMismatchError):
        srj_mod.join_served_request(provider_capsule, requester_capsule)


def test_refuses_when_arguments_are_swapped(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)

    with pytest.raises(srj_mod.RoleMismatchError):
        srj_mod.join_served_request(requester_capsule, provider_capsule)


def test_refuses_when_same_capsule_passed_for_both_halves(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, _requester_capsule = _halves(tmp_path)

    with pytest.raises(srj_mod.RoleMismatchError):
        srj_mod.join_served_request(provider_capsule, provider_capsule)


def test_refuses_an_unverifiable_provider_half(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    forged = copy.deepcopy(provider_capsule)
    forged["capsule_id"] = "c" * 64  # no longer matches its own recomputed digest

    with pytest.raises(srj_mod.UnverifiableHalfError):
        srj_mod.join_served_request(forged, requester_capsule)


def test_refuses_an_unverifiable_requester_half(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    forged = copy.deepcopy(requester_capsule)
    forged["capsule_id"] = "c" * 64

    with pytest.raises(srj_mod.UnverifiableHalfError):
        srj_mod.join_served_request(provider_capsule, forged)


# ---------------------------------------------------------------------------
# 4. multiple requesters sharing one provider exchange -- each join stands alone
# ---------------------------------------------------------------------------


def test_two_requesters_same_provider_each_join_independently_verifiable(tmp_path: Path) -> None:
    """Mirrors [mesh-b1-requestor-capsule-ledger]'s 'two requesters, same
    exchange -> each half independently offline-verifiable' acceptance, one
    level up: two DIFFERENT requester nodes each join against the SAME
    provider capsule. Both joins verify on their own bytes; both cite the
    SAME provider capsule_id; each chains onto its OWN requester half, never
    the other requester's."""
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    response = _response("chatcmpl-shared-two-requesters")
    provider_capsule = _seal(provider_state, response)

    requester_a_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-a")
    requester_b_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-b")
    requester_a_capsule = _seal(requester_a_state, response)
    requester_b_capsule = _seal(requester_b_state, response)

    join_a = srj_mod.join_served_request(provider_capsule, requester_a_capsule)
    join_b = srj_mod.join_served_request(provider_capsule, requester_b_capsule)

    from agent_action_capsule.verify import verify as verify_capsule

    result_a = verify_capsule(join_a)
    result_b = verify_capsule(join_b)
    assert result_a.ok, result_a.findings
    assert result_b.ok, result_b.findings

    assert join_a["references"][0]["digest"] == join_b["references"][0]["digest"] == provider_capsule["capsule_id"]
    assert join_a["chain"]["parent_capsule_id"] == requester_a_capsule["capsule_id"]
    assert join_b["chain"]["parent_capsule_id"] == requester_b_capsule["capsule_id"]
    assert join_a["capsule_id"] != join_b["capsule_id"]


# ---------------------------------------------------------------------------
# 5. build_reference() -- the standalone typed-reference builder
# ---------------------------------------------------------------------------


def test_build_reference_default_citation_purpose() -> None:
    _, srj_mod = _real_modules()
    ref = srj_mod.build_reference("d" * 64)
    assert ref == {
        "type": "capsule",
        "digest_alg": "SHA-256",
        "digest": "d" * 64,
        "citation_purpose": "responds_to",
    }
