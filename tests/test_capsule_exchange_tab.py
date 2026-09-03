# SPDX-License-Identifier: Apache-2.0
"""capsule_exchange_tab.py: Pane C "This exchange" -- the requester/provider
pair drill-down.

Focus: the pair can only ever be graded DOWN by tampering or a missing
half, never up -- a lone half must never render as a match, and a single
disagreeing digest must fail the whole pair even when the other field
agrees. Also covers the local sequence ordinal (and that it is NOT the
cross-signed sequence number) and that the twin/witness-reverify stubs stay
"pending", never silently promoted to a pass.
"""
from __future__ import annotations

import pytest

from capsule_accountability_tab import STATE_ABSENT, STATE_FAILED, STATE_PRESENT_UNVERIFIED, STATE_VERIFIED
from capsule_exchange_tab import (
    PENDING,
    build_exchange_view,
    digest_match_grade,
    exchange_id_for,
    half_by_role,
    identity_chain_for,
    records_for_exchange,
    render_exchange_subtab_html,
    sequence_position,
    twin_adjudication_placeholder,
    witness_receipt_reverify_placeholder,
)


def _capsule(
    *,
    capsule_id,
    role,
    exchange_id="ex-1",
    timestamp="2026-09-03T00:00:00Z",
    request_digest="a" * 64,
    response_digest="b" * 64,
    owner=None,
    served_by_node_id="node-provider",
    requesting_party="node-requester",
) -> dict:
    poc = {
        "role": role,
        "serving_provenance": {
            "model": {"canonical_ref": "meta-llama/Llama-3.2-3B-Instruct", "architecture": "llama"},
            "hardware": {"gpu": "Apple M4 Max", "is_soc": True},
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "exchange_id": exchange_id,
            "served_by_node_id": served_by_node_id,
            "requesting_party": requesting_party,
        },
        "evidence_refs": {"binary_attestation": None, "tee_attestation": None},
    }
    if owner is not None:
        poc["owner"] = owner
    return {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {
            "model_id": "meta-llama/Llama-3.2-3B-Instruct",
            "compute_attestation": {"x-mesh-poc-v1": poc},
        },
        "effect": {"request_digest": request_digest, "response_digest": response_digest, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _pair(exchange_id="ex-1", request_digest="a" * 64, response_digest="b" * 64):
    requester = _capsule(
        capsule_id="r" * 64,
        role="requested",
        exchange_id=exchange_id,
        timestamp="2026-09-03T00:00:00Z",
        request_digest=request_digest,
        response_digest=response_digest,
    )
    provider = _capsule(
        capsule_id="p" * 64,
        role="served",
        exchange_id=exchange_id,
        timestamp="2026-09-03T00:00:01Z",
        request_digest="a" * 64,
        response_digest="b" * 64,
    )
    return requester, provider


# ---------------------------------------------------------------------------
# exchange_id_for / records_for_exchange / half_by_role
# ---------------------------------------------------------------------------


def test_exchange_id_for_reads_serving_provenance():
    requester, _ = _pair(exchange_id="ex-42")
    assert exchange_id_for(requester) == "ex-42"


def test_records_for_exchange_groups_and_sorts_by_timestamp():
    requester, provider = _pair()
    group = records_for_exchange([provider, requester], "ex-1")
    assert [r["capsule_id"] for r in group] == [requester["capsule_id"], provider["capsule_id"]]


def test_records_for_exchange_empty_for_falsy_or_unknown_id():
    requester, provider = _pair()
    assert records_for_exchange([requester, provider], None) == []
    assert records_for_exchange([requester, provider], "unknown") == []


def test_half_by_role_splits_requested_from_served():
    requester, provider = _pair()
    requested, served = half_by_role([requester, provider], "sidecar")
    assert [r["capsule_id"] for r in requested] == [requester["capsule_id"]]
    assert [r["capsule_id"] for r in served] == [provider["capsule_id"]]


# ---------------------------------------------------------------------------
# digest_match_grade -- the pair's shared ground truth
# ---------------------------------------------------------------------------


def test_digest_match_verified_when_both_halves_agree():
    requester, provider = _pair()
    grade = digest_match_grade(requester, provider)
    assert grade["state"] == STATE_VERIFIED
    assert grade["fields"]["request_digest"]["state"] == STATE_VERIFIED
    assert grade["fields"]["response_digest"]["state"] == STATE_VERIFIED


def test_digest_match_absent_when_only_one_half_present():
    requester, _ = _pair()
    grade = digest_match_grade(requester, None)
    assert grade["state"] == STATE_ABSENT
    assert grade["fields"] == {}


def test_digest_match_absent_when_neither_half_present():
    grade = digest_match_grade(None, None)
    assert grade["state"] == STATE_ABSENT


def test_digest_match_mutant_one_disagreeing_field_fails_the_whole_pair():
    """MUTANT: response_digest disagrees between halves while request_digest
    still matches -- the pair must fail, not average to a partial pass."""
    requester, provider = _pair(response_digest="c" * 64)
    # provider still carries the original response_digest, requester was mutated
    grade = digest_match_grade(requester, provider)
    assert grade["state"] == STATE_FAILED
    assert grade["fields"]["response_digest"]["state"] == STATE_FAILED
    assert grade["fields"]["request_digest"]["state"] == STATE_VERIFIED


def test_digest_match_mutant_request_digest_disagrees_too():
    requester, provider = _pair(request_digest="d" * 64)
    grade = digest_match_grade(requester, provider)
    assert grade["state"] == STATE_FAILED


def test_digest_match_present_unverified_when_one_field_missing_but_none_disagree():
    requester, provider = _pair()
    del requester["effect"]["response_digest"]
    grade = digest_match_grade(requester, provider)
    assert grade["state"] == STATE_PRESENT_UNVERIFIED
    assert grade["fields"]["response_digest"]["state"] == STATE_ABSENT


# ---------------------------------------------------------------------------
# sequence_position -- local ordinal, explicitly not the E9 sequence number
# ---------------------------------------------------------------------------


def test_sequence_position_orders_by_timestamp():
    requester, provider = _pair()
    group = records_for_exchange([provider, requester], "ex-1")
    seq_r = sequence_position(group, requester)
    seq_p = sequence_position(group, provider)
    assert seq_r["position"] == 1
    assert seq_p["position"] == 2
    assert seq_r["of"] == seq_p["of"] == 2


def test_sequence_position_caveat_disclaims_the_cross_signed_guarantee():
    requester, provider = _pair()
    group = records_for_exchange([requester, provider], "ex-1")
    seq = sequence_position(group, requester)
    assert "not" in seq["caveat"].lower()
    assert seq["source"] == "local_derivation"


def test_sequence_position_raises_for_a_record_outside_the_group():
    requester, provider = _pair()
    stray = _capsule(capsule_id="s" * 64, role="requested", exchange_id="ex-1")
    group = records_for_exchange([requester, provider], "ex-1")
    with pytest.raises(ValueError):
        sequence_position(group, stray)


# ---------------------------------------------------------------------------
# identity_chain_for
# ---------------------------------------------------------------------------


def test_identity_chain_absent_owner_by_default():
    requester, _ = _pair()
    chain = identity_chain_for(requester)
    assert chain["owner_status"] == "absent"
    assert chain["owner_id"] is None


def test_identity_chain_reads_owner_cert_ref_when_bound():
    owner = {
        "owner_status": "bound",
        "owner_id": "owner-zzz",
        "identity_capsule_id": "cap-who-abc",
        "owner_cert_ref": {"type": "owner_cert", "digest_alg": "SHA-256", "digest": "e" * 64},
        "identity_limitation": "self-asserted owner cert; not independently verified",
    }
    provider = _capsule(capsule_id="p" * 64, role="served", owner=owner)
    chain = identity_chain_for(provider)
    assert chain["owner_status"] == "bound"
    assert chain["owner_cert_ref"] == owner["owner_cert_ref"]


# ---------------------------------------------------------------------------
# twin_adjudication_placeholder / witness_receipt_reverify_placeholder --
# genuine stubs, never a fabricated pass
# ---------------------------------------------------------------------------


def test_twin_adjudication_placeholder_is_pending_not_a_pass():
    placeholder = twin_adjudication_placeholder()
    assert placeholder["state"] == PENDING
    assert placeholder["state"] not in (STATE_VERIFIED, STATE_FAILED)
    assert "mesh-e17a" in placeholder["reason"]


def test_witness_receipt_reverify_placeholder_is_pending_not_a_pass():
    placeholder = witness_receipt_reverify_placeholder()
    assert placeholder["state"] == PENDING
    assert "mesh-e2-witness-checkpoints" in placeholder["reason"]


# ---------------------------------------------------------------------------
# build_exchange_view -- the whole card
# ---------------------------------------------------------------------------


def test_build_exchange_view_from_the_requester_half_finds_the_provider_half():
    requester, provider = _pair()
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    assert view["role"] == "requested"
    assert view["pair"]["requester_half_capsule_id"] == requester["capsule_id"]
    assert view["pair"]["provider_half_capsule_id"] == provider["capsule_id"]
    assert view["pair"]["digest_match"]["state"] == STATE_VERIFIED
    assert view["identity_chain"]["counterpart"] is not None


def test_build_exchange_view_alone_has_no_counterpart_and_absent_digest_match():
    requester, _provider_not_supplied = _pair()
    view = build_exchange_view(requester, all_records=[requester], source_log="sidecar")
    assert view["pair"]["provider_half_capsule_id"] is None
    assert view["pair"]["digest_match"]["state"] == STATE_ABSENT
    assert view["identity_chain"]["counterpart"] is None


def test_build_exchange_view_never_pairs_two_records_sharing_the_same_role():
    """MUTANT: two requester-side records claiming the same exchange_id must
    never be presented as a matched requester/provider pair."""
    requester_a = _capsule(capsule_id="1" * 64, role="requested", exchange_id="ex-9")
    requester_b = _capsule(capsule_id="2" * 64, role="requested", exchange_id="ex-9")
    view = build_exchange_view(requester_a, all_records=[requester_a, requester_b], source_log="sidecar")
    assert view["pair"]["provider_half_capsule_id"] is None
    assert view["pair"]["digest_match"]["state"] == STATE_ABSENT


def test_build_exchange_view_stubs_stay_pending():
    requester, provider = _pair()
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    assert view["twin_adjudication"]["state"] == PENDING
    assert view["witness_receipt_reverify"]["state"] == PENDING


# ---------------------------------------------------------------------------
# render_exchange_subtab_html -- smoke + escaping
# ---------------------------------------------------------------------------


def test_render_exchange_subtab_html_includes_pair_and_sequence():
    requester, provider = _pair()
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    html = render_exchange_subtab_html(view)
    assert "This exchange" in html
    assert "sequence: 1 of 2" in html
    assert "pill-good" in html  # digest match verified renders green


def test_render_exchange_subtab_html_escapes_hostile_owner_id():
    owner = {
        "owner_status": "bound",
        "owner_id": "<script>alert(1)</script>",
        "identity_capsule_id": "cap-who-abc",
        "owner_cert_ref": {"type": "owner_cert", "digest_alg": "SHA-256", "digest": "e" * 64},
        "identity_limitation": None,
    }
    requester = _capsule(capsule_id="r" * 64, role="requested", owner=owner)
    view = build_exchange_view(requester, all_records=[requester], source_log="sidecar")
    html = render_exchange_subtab_html(view)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
