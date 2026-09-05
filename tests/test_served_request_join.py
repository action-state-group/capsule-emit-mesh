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
     halves do not share one `exchange_id`; the joiner is not the node the
     requester half itself names as the requesting party.

[adv-served-join-signed] Also proves the cryptographic half that used to be
missing entirely: `sign_served_request_join()` / `verify_served_request_join_
signature()` make the module docstring's long-standing claim ("a stranger
checks the join's signature") literally true, and the join honestly labels
WHO asserts it (`asserted_by_node_id`) as a one-party claim -- see the
"Mallory" section below for the adversarial scenario this closes.

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


def _pubkey_pem(state: "cs.NodeState") -> bytes:
    """The public half of *state*'s node key, written beside it by
    `load_or_create_signing_key()` -- the same discovery convention
    `stranger_verify_bundle.py` uses for a disclosed bundle's issuer key."""
    return (state.signing_key_path.parent / "node-key.pub.pem").read_bytes()


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
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(joined)
    assert result.ok, result.findings


def test_join_references_entry_cites_provider_with_responds_to(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

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
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    assert joined["chain"]["parent_capsule_id"] == requester_capsule["capsule_id"]
    assert joined["chain"]["relation"] == "confirms"


def test_join_reference_target_differs_from_chain_parent(tmp_path: Path) -> None:
    """{{xref}} boundary rule: a `references` entry MUST NOT name the same
    target as `chain.parent_capsule_id` -- the join always cites a DIFFERENT
    producer's capsule (provider) than the one it chains onto (requester)."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    assert joined["references"][0]["digest"] != joined["chain"]["parent_capsule_id"]
    assert provider_capsule["capsule_id"] != requester_capsule["capsule_id"]


def test_join_carries_the_shared_exchange_id_self_contained(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path, exchange_id="chatcmpl-xid-carried")
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    compute_attestation = joined["model_attestation"]["compute_attestation"]
    assert compute_attestation["served_request_join"]["exchange_id"] == "chatcmpl-xid-carried"


def test_join_honestly_labels_who_asserts_it(tmp_path: Path) -> None:
    """[adv-served-join-signed] The join's own sealed content names WHO is
    asserting it, plus the one-party limitation -- never presented as a
    mutual attestation the provider agreed to."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    block = joined["model_attestation"]["compute_attestation"]["served_request_join"]
    assert block["asserted_by_node_id"] == "req-1"
    assert block["assertion_limitation"] == srj_mod.JOIN_ASSERTION_CAVEAT
    assert "one-party" in block["assertion_limitation"]


def test_tampered_asserted_by_node_id_fails_verify(tmp_path: Path) -> None:
    """Relabeling who asserts a join after the fact (without re-signing) is
    exactly as much a tamper as rewriting the cited digest -- both are
    committed into capsule_id."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    tampered = copy.deepcopy(joined)
    tampered["model_attestation"]["compute_attestation"]["served_request_join"]["asserted_by_node_id"] = (
        "mallory-node"
    )

    from agent_action_capsule.verify import verify as verify_capsule

    result = verify_capsule(tampered)
    assert not result.ok
    assert any(f.code == "capsule_id_mismatch" for f in result.findings)


# ---------------------------------------------------------------------------
# 2. capsule_id commits references -- the join is a real signed claim
# ---------------------------------------------------------------------------


def test_tampered_reference_digest_fails_verify(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

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
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

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
        srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")


def test_refuses_when_arguments_are_swapped(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)

    with pytest.raises(srj_mod.RoleMismatchError):
        srj_mod.join_served_request(requester_capsule, provider_capsule, joiner_node_id="req-1")


def test_refuses_when_same_capsule_passed_for_both_halves(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, _requester_capsule = _halves(tmp_path)

    with pytest.raises(srj_mod.RoleMismatchError):
        srj_mod.join_served_request(provider_capsule, provider_capsule, joiner_node_id="req-1")


def test_refuses_an_unverifiable_provider_half(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    forged = copy.deepcopy(provider_capsule)
    forged["capsule_id"] = "c" * 64  # no longer matches its own recomputed digest

    with pytest.raises(srj_mod.UnverifiableHalfError):
        srj_mod.join_served_request(forged, requester_capsule, joiner_node_id="req-1")


def test_refuses_an_unverifiable_requester_half(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)
    forged = copy.deepcopy(requester_capsule)
    forged["capsule_id"] = "c" * 64

    with pytest.raises(srj_mod.UnverifiableHalfError):
        srj_mod.join_served_request(provider_capsule, forged, joiner_node_id="req-1")


def test_refuses_when_joiner_is_not_the_requester(tmp_path: Path) -> None:
    """[adv-served-join-signed] core fix: a node that merely HOLDS a real,
    disclosed requester-half capsule (relay-visible provider capsule +
    requester capsule fetched via an evidence door, say) cannot mint a join
    claiming to have been that requester -- only the node the requester half
    itself names as `requesting_party` may mint the join chained onto it."""
    _, srj_mod = _real_modules()
    provider_capsule, requester_capsule = _halves(tmp_path)

    with pytest.raises(srj_mod.JoinerNotRequesterError):
        srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="mallory-node")


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

    join_a = srj_mod.join_served_request(provider_capsule, requester_a_capsule, joiner_node_id="req-a")
    join_b = srj_mod.join_served_request(provider_capsule, requester_b_capsule, joiner_node_id="req-b")

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


# ---------------------------------------------------------------------------
# 6. sign_served_request_join / verify_served_request_join_signature --
#    the join's actual signature (the module docstring's original claim,
#    now real)
# ---------------------------------------------------------------------------


def test_sign_and_verify_join_signature_roundtrip(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    response = _response("chatcmpl-sign-roundtrip")
    provider_capsule = _seal(provider_state, response)
    requester_capsule = _seal(requester_state, response)

    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")
    signed_statement = srj_mod.sign_served_request_join(
        joined, signing_key_pem=requester_state.signing_key_pem, signing_node_id="req-1"
    )

    valid, reason = srj_mod.verify_served_request_join_signature(
        joined, signed_statement, public_key_pem=_pubkey_pem(requester_state)
    )
    assert valid, reason


def test_sign_served_request_join_rejects_wrong_signing_node_id(tmp_path: Path) -> None:
    """Refuses to let a plaintext `asserted_by_node_id` label and an actual
    signing identity travel under different names."""
    _, srj_mod = _real_modules()
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    with pytest.raises(srj_mod.SignerMismatchError):
        srj_mod.sign_served_request_join(
            joined, signing_key_pem=requester_state.signing_key_pem, signing_node_id="mallory-node"
        )


def test_verify_join_signature_rejects_wrong_public_key(tmp_path: Path) -> None:
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    response = _response("chatcmpl-wrong-pubkey")
    provider_capsule = _seal(provider_state, response)
    requester_capsule = _seal(requester_state, response)

    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")
    signed_statement = srj_mod.sign_served_request_join(
        joined, signing_key_pem=requester_state.signing_key_pem, signing_node_id="req-1"
    )

    # A stranger checking against the PROVIDER's key instead of the actual
    # signer's (requester's) key must not be fooled into a pass.
    valid, reason = srj_mod.verify_served_request_join_signature(
        joined, signed_statement, public_key_pem=_pubkey_pem(provider_state)
    )
    assert not valid, reason


def test_verify_join_signature_rejects_issuer_mismatched_from_asserted_by_node_id(tmp_path: Path) -> None:
    """A signed statement can cryptographically verify (real key, real
    signature, matching payload and subject) and STILL be rejected if its
    own authenticated `issuer` CWT claim disagrees with the plaintext
    `asserted_by_node_id` the capsule itself carries -- the two labels for
    "who asserts this" must never be allowed to drift apart. Reaches the
    underlying COSE primitive directly (bypassing `sign_served_request_
    join()`'s own SignerMismatchError guard) to construct exactly that
    otherwise-impossible-via-the-API state, the same way an attacker
    forging around this module's API would have to."""
    _, srj_mod = _real_modules()
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    mislabeled_statement = scitt_cose_build_signed_statement_direct(
        srj_mod, joined, private_key_pem=requester_state.signing_key_pem, issuer="req-1-alias"
    )

    valid, reason = srj_mod.verify_served_request_join_signature(
        joined, mislabeled_statement, public_key_pem=_pubkey_pem(requester_state)
    )
    assert not valid, reason
    assert "asserted_by_node_id" in reason


def test_verify_join_signature_rejects_bytes_from_a_different_capsule(tmp_path: Path) -> None:
    """A signature real and valid for ONE join must not verify against a
    DIFFERENT join's bytes, even one from the same joiner."""
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")

    response_a = _response("chatcmpl-replay-a")
    provider_capsule_a = _seal(provider_state, response_a)
    requester_capsule_a = _seal(requester_state, response_a)
    joined_a = srj_mod.join_served_request(provider_capsule_a, requester_capsule_a, joiner_node_id="req-1")
    signed_statement_a = srj_mod.sign_served_request_join(
        joined_a, signing_key_pem=requester_state.signing_key_pem, signing_node_id="req-1"
    )

    response_b = _response("chatcmpl-replay-b")
    provider_capsule_b = _seal(provider_state, response_b)
    requester_capsule_b = _seal(requester_state, response_b)
    joined_b = srj_mod.join_served_request(provider_capsule_b, requester_capsule_b, joiner_node_id="req-1")

    valid, reason = srj_mod.verify_served_request_join_signature(
        joined_b, signed_statement_a, public_key_pem=_pubkey_pem(requester_state)
    )
    assert not valid, reason


# ---------------------------------------------------------------------------
# 7. Mallory -- one-party assertion, never mutual
#
# [adv-served-join-signed] The adversarial scenario the fix closes: the
# provider's served-half capsule is relay-visible (Mallory can observe it on
# the wire), and `exchange_id` is a provider-chosen, copyable string. Before
# this fix, `join_served_request()` produced an unsigned dict indistinguish-
# able from one asserted by the real requester -- the module docstring
# CLAIMED a stranger could "check the join's signature" when no signature
# existed at all.
# ---------------------------------------------------------------------------


def test_mallory_forging_the_real_requesters_identity_fails_signature_verification(tmp_path: Path) -> None:
    """Mallory holds the REAL provider capsule and the REAL requester
    capsule (both disclosed/relay-visible) but does NOT hold "req-1"'s
    private node key. She hand-crafts a signed statement claiming issuer
    "req-1" while actually signing with her OWN key -- exactly what a party
    without req-1's key would have to do to make the join's plaintext label
    say "req-1". A stranger who knows req-1's real public key rejects it."""
    _, srj_mod = _real_modules()
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    mallory_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="mallory-node")
    provider_capsule, requester_capsule = _halves(tmp_path)
    joined = srj_mod.join_served_request(provider_capsule, requester_capsule, joiner_node_id="req-1")

    # Mallory cannot go through sign_served_request_join() honestly (it would
    # refuse: her key's node_id is "mallory-node", not "req-1"), so she calls
    # the underlying COSE primitive directly, exactly as an attacker
    # bypassing this module's own API would.
    forged_statement = scitt_cose_build_signed_statement_direct(
        srj_mod, joined, private_key_pem=mallory_state.signing_key_pem, issuer="req-1"
    )

    valid, reason = srj_mod.verify_served_request_join_signature(
        joined, forged_statement, public_key_pem=_pubkey_pem(requester_state)
    )
    assert not valid, reason


def test_mallory_honestly_self_identifying_renders_as_her_own_assertion_only(tmp_path: Path) -> None:
    """Mallory mints her OWN self-attested requester-half capsule for the
    SAME (relay-visible) exchange_id as the real requester and joins it
    against the real provider capsule, honestly as herself. This module
    cannot detect that she was not really served (that is out of scope --
    see the module docstring's "NOT a trust upgrade for either half") -- but
    the resulting join can never be mistaken for the real requester's: it
    verifies, but its own `asserted_by_node_id` names Mallory, not "req-1",
    and its `chain.parent_capsule_id` points at HER OWN requester capsule,
    never the real one."""
    _, srj_mod = _real_modules()
    provider_state = _state(tmp_path, role=cs.ROLE_PROVIDER, node_id="prov-1")
    requester_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="req-1")
    mallory_state = _state(tmp_path, role=cs.ROLE_REQUESTER, node_id="mallory-node")

    shared_exchange_id = "chatcmpl-mallory-observed"
    provider_capsule = _seal(provider_state, _response(shared_exchange_id))
    real_requester_capsule = _seal(requester_state, _response(shared_exchange_id))
    mallory_requester_capsule = _seal(mallory_state, _response(shared_exchange_id))

    mallory_join = srj_mod.join_served_request(
        provider_capsule, mallory_requester_capsule, joiner_node_id="mallory-node"
    )
    signed_statement = srj_mod.sign_served_request_join(
        mallory_join, signing_key_pem=mallory_state.signing_key_pem, signing_node_id="mallory-node"
    )

    valid, reason = srj_mod.verify_served_request_join_signature(
        mallory_join, signed_statement, public_key_pem=_pubkey_pem(mallory_state)
    )
    assert valid, reason

    block = mallory_join["model_attestation"]["compute_attestation"]["served_request_join"]
    assert block["asserted_by_node_id"] == "mallory-node"
    assert block["asserted_by_node_id"] != "req-1"
    assert mallory_join["chain"]["parent_capsule_id"] == mallory_requester_capsule["capsule_id"]
    assert mallory_join["chain"]["parent_capsule_id"] != real_requester_capsule["capsule_id"]

    # And she structurally cannot mint a join naming herself while chained
    # onto the REAL requester's own capsule -- that is the mint-time guard.
    with pytest.raises(srj_mod.JoinerNotRequesterError):
        srj_mod.join_served_request(provider_capsule, real_requester_capsule, joiner_node_id="mallory-node")


def scitt_cose_build_signed_statement_direct(srj_mod, joined_capsule, *, private_key_pem, issuer):
    """Bypass `sign_served_request_join()`'s SignerMismatchError guard to
    build the exact bytes an attacker without the real signing key would
    have to produce -- calling the underlying COSE primitive the same way
    `sign_served_request_join()` does, just without the identity guard."""
    import scitt_cose

    return scitt_cose.build_signed_statement(
        srj_mod._canonical_join_payload(joined_capsule),
        alg=srj_mod.SIG_ALG,
        private_key_pem=private_key_pem,
        issuer=issuer,
        subject=joined_capsule["capsule_id"],
        content_type=srj_mod.JOIN_CONTENT_TYPE,
    )
