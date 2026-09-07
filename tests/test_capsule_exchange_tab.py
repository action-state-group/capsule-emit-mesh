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

import assurance_map
from capsule_accountability_tab import STATE_ABSENT, STATE_FAILED, STATE_PRESENT_UNVERIFIED, STATE_VERIFIED
from capsule_exchange_tab import (
    EXCHANGE_ROLE_ASKED,
    EXCHANGE_ROLE_SERVED,
    FILTER_ALL,
    FILTER_ASKED,
    FILTER_ISSUES,
    FILTER_SERVED,
    PENDING,
    build_assurance_map,
    build_exchange_list_payload,
    build_exchange_row,
    build_exchange_view,
    digest_match_grade,
    exchange_id_for,
    exchange_key_for,
    filter_exchange_rows,
    group_exchanges,
    half_by_role,
    identity_chain_for,
    records_for_exchange,
    render_exchange_list_html,
    render_exchange_subtab_html,
    sequence_position,
    twin_adjudication_placeholder,
    witness_receipt_reverify_placeholder,
    worst_state,
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
    # twin_adjudicator.py is merged on main now -- the pending reason must
    # say so honestly (this per-exchange view just doesn't call it yet),
    # never the stale "PR #84 not merged" framing.
    assert "twin_adjudicator.py exists on main" in placeholder["reason"]
    assert "not yet merged" not in placeholder["reason"]


def test_witness_receipt_reverify_placeholder_is_pending_not_a_pass():
    placeholder = witness_receipt_reverify_placeholder()
    assert placeholder["state"] == PENDING
    assert "mesh-e2-witness-checkpoints" in placeholder["reason"]
    assert "is merged" in placeholder["reason"]


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


# ---------------------------------------------------------------------------
# worst_state -- the header = the worst line among this exchange's checks
# ([mesh-exchange-card-mismatch-bug]'s principle, reapplied to this module)
# ---------------------------------------------------------------------------


def _synthetic_view(*, digest_match_state=STATE_VERIFIED, verdict_marks=("ok", "warn", "warn"), rung_states=None, witness_pending=True):
    """A hand-built view dict, decoupled from `build_exchange_view`'s real
    fixtures, to unit-test `worst_state`'s fold logic in isolation. The
    default marks mirror what `build_verdict` actually returns today for any
    exchange without cross-party evidence (line 2 warn = no witness receipt
    in this bundle -- excluded from the fold while pending, per doc §3; line
    3 warn = "who asked: self-attested" -- a REAL limitation, always folded)."""
    rung_states = rung_states or {"freshness": {"state": STATE_ABSENT}, "cross_party": {"rung": "unilateral_fallback"}, "runtime_binding": {"state": STATE_ABSENT}}
    return {
        "pair": {"digest_match": {"state": digest_match_state}},
        "verdict": [{"mark": m, "text": ""} for m in verdict_marks],
        "rungs": rung_states,
        "witness_receipt_reverify": {"state": PENDING if witness_pending else STATE_VERIFIED},
    }


def test_worst_state_is_verified_when_everything_checked_is_clean():
    view = _synthetic_view(verdict_marks=("ok", "warn", "ok"))  # line 3 clean too (named counterparty)
    assert worst_state(view) == STATE_VERIFIED


def test_worst_state_real_pair_fixture_reads_present_unverified_not_a_fabricated_pass():
    """The shared `_pair()` fixture carries no cross-party evidence, so
    `cross_party_grade` is honestly `unilateral_fallback` and build_verdict's
    line 3 ("who asked: self-attested") is a REAL limitation -- doc §3 keeps
    that one amber. The header must reflect it, not round up to verified."""
    requester, provider = _pair()
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    assert worst_state(view) == STATE_PRESENT_UNVERIFIED
    assert worst_state(view) != STATE_VERIFIED


def test_worst_state_mutant_a_digest_mismatch_forces_failed_even_if_other_lines_are_green():
    requester, provider = _pair(response_digest="b" * 64)
    provider["effect"]["response_digest"] = "c" * 64  # sealed-digest mismatch, header must go red
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    assert worst_state(view) == STATE_FAILED
    assert worst_state(view) != STATE_VERIFIED


def test_worst_state_a_lone_half_is_unverified_never_a_fabricated_pass():
    requester, _provider = _pair()
    view = build_exchange_view(requester, all_records=[requester], source_log="sidecar")
    assert worst_state(view) != STATE_VERIFIED


def test_worst_state_pending_witness_line_alone_never_forces_a_bad_header():
    """The witness line's honest `warn` (no receipt in this bundle) is a
    view limitation while `witness_receipt_reverify` is pending -- doc §3
    keeps that one grey, so it must not, by itself, push the header down."""
    clean = _synthetic_view(verdict_marks=("ok", "warn", "ok"), witness_pending=True)
    assert worst_state(clean) == STATE_VERIFIED


def test_worst_state_a_real_bad_witness_verdict_still_forces_failed_even_while_pending():
    """The exclusion is for the PLACEHOLDER warn only -- a genuine `bad`
    witness mark (a tampered/forged receipt), should this view ever produce
    one, must never be swallowed by the pending exclusion."""
    tampered = _synthetic_view(verdict_marks=("ok", "bad", "ok"), witness_pending=True)
    assert worst_state(tampered) == STATE_FAILED


# ---------------------------------------------------------------------------
# exchange_key_for -- exchange_id, falling back to request_digest
# ---------------------------------------------------------------------------


def test_exchange_key_for_uses_exchange_id_when_present():
    requester, _ = _pair(exchange_id="ex-42")
    assert exchange_key_for(requester) == "ex-42"


def test_exchange_key_for_falls_back_to_request_digest_when_exchange_id_absent():
    record = _capsule(capsule_id="c" * 64, role="requested", exchange_id="unknown", request_digest="f" * 64)
    assert exchange_key_for(record) == f"digest:{'f' * 64}"


def test_exchange_key_for_none_when_neither_is_present():
    record = _capsule(capsule_id="c" * 64, role="requested", exchange_id="unknown")
    del record["effect"]["request_digest"]
    assert exchange_key_for(record) is None


# ---------------------------------------------------------------------------
# group_exchanges / build_exchange_row -- one row per exchange, role tag,
# mine/theirs as two columns, never a blank cell
# ---------------------------------------------------------------------------


def test_group_exchanges_one_row_per_exchange_id():
    requester, provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([requester, provider])
    assert len(rows) == 1
    assert rows[0]["exchange_key"] == "ex-1"


def test_group_exchanges_role_tag_served_when_this_node_served():
    requester, provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([provider], counterparty_records=[requester])
    assert rows[0]["role_tag"] == EXCHANGE_ROLE_SERVED
    assert rows[0]["mine"]["capsule_id"] == provider["capsule_id"]
    assert rows[0]["theirs"]["capsule_id"] == requester["capsule_id"]


def test_group_exchanges_role_tag_asked_when_this_node_requested():
    requester, provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([requester], counterparty_records=[provider])
    assert rows[0]["role_tag"] == EXCHANGE_ROLE_ASKED


def test_group_exchanges_unilateral_when_only_mine_is_present_never_blank():
    requester, _provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([requester])
    assert rows[0]["unilateral"] is True
    assert rows[0]["theirs"]["text"] == "none (unilateral)"
    assert rows[0]["theirs"]["state"] == STATE_ABSENT


def test_group_exchanges_received_without_a_commitment_never_blank():
    """A received foreign half with no `mine` record for the same exchange
    -- rare, but must render its own honest reason, never a blank cell."""
    _requester, provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([], counterparty_records=[provider])
    assert len(rows) == 1
    assert rows[0]["mine"]["text"] == "none — received without a commitment"
    assert rows[0]["mine"]["state"] == STATE_ABSENT


def test_group_exchanges_default_sort_is_most_recent_first():
    older_r, older_p = _pair(exchange_id="ex-old", request_digest="1" * 64, response_digest="2" * 64)
    older_r["timestamp"] = "2026-09-01T00:00:00Z"
    older_p["timestamp"] = "2026-09-01T00:00:01Z"
    newer_r, newer_p = _pair(exchange_id="ex-new", request_digest="3" * 64, response_digest="4" * 64)
    newer_r["timestamp"] = "2026-09-05T00:00:00Z"
    newer_p["timestamp"] = "2026-09-05T00:00:01Z"

    rows = group_exchanges([older_r, older_p, newer_r, newer_p])

    assert [r["exchange_key"] for r in rows] == ["ex-new", "ex-old"]


def test_group_exchanges_fallback_key_never_mixes_two_different_exchanges():
    a = _capsule(capsule_id="a" * 64, role="requested", exchange_id="unknown", request_digest="1" * 64)
    b = _capsule(capsule_id="b" * 64, role="requested", exchange_id="unknown", request_digest="2" * 64)
    rows = group_exchanges([a, b])
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# filter_exchange_rows -- All / Served / Asked / Issues
# ---------------------------------------------------------------------------


def test_filter_exchange_rows_served_and_asked():
    requester, provider = _pair(exchange_id="ex-1")
    rows = group_exchanges([provider], counterparty_records=[requester])
    assert len(filter_exchange_rows(rows, FILTER_SERVED)) == 1
    assert len(filter_exchange_rows(rows, FILTER_ASKED)) == 0
    assert len(filter_exchange_rows(rows, FILTER_ALL)) == 1


def test_filter_exchange_rows_issues_excludes_a_verified_row():
    clean_row = {"role_tag": EXCHANGE_ROLE_SERVED, "header_state": STATE_VERIFIED}
    assert filter_exchange_rows([clean_row], FILTER_ISSUES) == []


def test_filter_exchange_rows_issues_excludes_an_absent_row_too():
    """A row with nothing to check yet (`STATE_ABSENT`) is not an "issue" --
    only a real warn/failed header is."""
    absent_row = {"role_tag": EXCHANGE_ROLE_ASKED, "header_state": STATE_ABSENT}
    assert filter_exchange_rows([absent_row], FILTER_ISSUES) == []


def test_filter_exchange_rows_issues_includes_a_digest_mismatch_row():
    requester, provider = _pair(exchange_id="ex-1")
    provider["effect"]["response_digest"] = "tampered" + "0" * 56
    rows = group_exchanges([requester, provider])
    assert rows[0]["header_state"] == STATE_FAILED
    assert len(filter_exchange_rows(rows, FILTER_ISSUES)) == 1


def test_filter_exchange_rows_rejects_unknown_filter():
    with pytest.raises(ValueError):
        filter_exchange_rows([], "bogus")


# ---------------------------------------------------------------------------
# build_exchange_list_payload / render_exchange_list_html
# ---------------------------------------------------------------------------


def test_build_exchange_list_payload_shape():
    requester, provider = _pair(exchange_id="ex-1")
    payload = build_exchange_list_payload([requester, provider])
    assert payload["row_count"] == 1
    assert payload["default_sort"] == "timestamp"
    assert set(payload["filters"]) == {FILTER_ALL, FILTER_SERVED, FILTER_ASKED, FILTER_ISSUES}


def test_render_exchange_list_html_includes_role_tag_and_drawer():
    requester, provider = _pair(exchange_id="ex-1")
    payload = build_exchange_list_payload([requester, provider])
    html = render_exchange_list_html(payload)
    assert "ex-1" in html
    assert "This exchange" in html  # the drawer reuses render_exchange_subtab_html verbatim
    assert "filter-chip" in html


def test_render_exchange_list_html_empty_never_crashes():
    payload = build_exchange_list_payload([])
    html = render_exchange_list_html(payload)
    assert "0 exchange(s)" in html


def test_render_exchange_list_html_row_carries_chip_strip_and_data_issue():
    """[mesh-panes-map-chips] item 1: the row no longer renders the bare
    header_state pill (which could leak literal "present-unverified") --
    it carries a chip strip plus a machine-readable data-issue attribute."""
    requester, provider = _pair(exchange_id="ex-1")
    payload = build_exchange_list_payload([requester, provider])
    html = render_exchange_list_html(payload)
    assert "chip-strip" in html
    assert 'data-issue="' in html
    assert "data-state=" not in html


def test_render_exchange_list_html_issues_filter_reads_data_issue():
    payload = build_exchange_list_payload([])
    html = render_exchange_list_html(payload)
    assert 'row.dataset.issue === "true"' in html
    assert "row.dataset.state" not in html


# ---------------------------------------------------------------------------
# build_assurance_map -- the nine-property map ([mesh-panes-map-chips])
# ---------------------------------------------------------------------------


class _FakeFinding:
    def __init__(self, code):
        self.code = code


class _FakeVerifyResult:
    def __init__(self, codes):
        self.findings = [_FakeFinding(c) for c in codes]


def _assert_all_three_recompute_states(*, verify_result, verify_ran, expected_state):
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=verify_result, verify_ran=verify_ran, has_witness_checkpoint=False
    )
    for key in (
        assurance_map.PROPERTY_CONTENT_BINDING,
        assurance_map.PROPERTY_PRODUCER_SIGNATURE,
        assurance_map.PROPERTY_CONTINUITY,
    ):
        assert properties[key]["state"] == expected_state


def test_build_assurance_map_verify_did_not_run_recompute_properties_not_checked():
    _assert_all_three_recompute_states(
        verify_result=None, verify_ran=False, expected_state=assurance_map.STATE_NOT_CHECKED
    )


def test_build_assurance_map_verify_ran_clean_recompute_properties_pass():
    _assert_all_three_recompute_states(
        verify_result=_FakeVerifyResult([]), verify_ran=True, expected_state=assurance_map.STATE_PASS
    )


def test_build_assurance_map_content_binding_fails_on_capsule_id_mismatch():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record,
        verify_result=_FakeVerifyResult(["capsule_id_mismatch"]),
        verify_ran=True,
        has_witness_checkpoint=False,
    )
    assert properties[assurance_map.PROPERTY_CONTENT_BINDING]["state"] == assurance_map.STATE_FAIL
    assert properties[assurance_map.PROPERTY_PRODUCER_SIGNATURE]["state"] == assurance_map.STATE_PASS
    assert properties[assurance_map.PROPERTY_CONTINUITY]["state"] == assurance_map.STATE_PASS


def test_build_assurance_map_producer_signature_fails_on_invalid_signature():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record,
        verify_result=_FakeVerifyResult(["producer_signature_invalid"]),
        verify_ran=True,
        has_witness_checkpoint=False,
    )
    assert properties[assurance_map.PROPERTY_PRODUCER_SIGNATURE]["state"] == assurance_map.STATE_FAIL
    assert properties[assurance_map.PROPERTY_CONTENT_BINDING]["state"] == assurance_map.STATE_PASS


def test_build_assurance_map_continuity_fails_on_broken_chain_parent():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record,
        verify_result=_FakeVerifyResult(["chain_parent_missing"]),
        verify_ran=True,
        has_witness_checkpoint=False,
    )
    assert properties[assurance_map.PROPERTY_CONTINUITY]["state"] == assurance_map.STATE_FAIL
    assert properties[assurance_map.PROPERTY_CONTENT_BINDING]["state"] == assurance_map.STATE_PASS


def test_build_assurance_map_checkpoint_properties_not_present_without_a_checkpoint():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    for key in (
        assurance_map.PROPERTY_LOCAL_INCLUSION,
        assurance_map.PROPERTY_CHECKPOINT_SIGNATURE,
        assurance_map.PROPERTY_EXTERNAL_REGISTRATION,
    ):
        assert properties[key]["state"] == assurance_map.STATE_NOT_PRESENT


def test_build_assurance_map_checkpoint_properties_not_checked_with_a_checkpoint():
    """A checkpoint was supplied to this view, but per-record inclusion/
    re-verify is not wired here yet -- NOT_CHECKED (a view limitation),
    never NOT_PRESENT (which would claim no checkpoint exists at all)."""
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=True
    )
    for key in (
        assurance_map.PROPERTY_LOCAL_INCLUSION,
        assurance_map.PROPERTY_CHECKPOINT_SIGNATURE,
        assurance_map.PROPERTY_EXTERNAL_REGISTRATION,
    ):
        assert properties[key]["state"] == assurance_map.STATE_NOT_CHECKED


def test_build_assurance_map_identity_authority_not_present_with_no_owner_cert():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_IDENTITY_AUTHORITY]["state"] == assurance_map.STATE_NOT_PRESENT


def test_build_assurance_map_identity_authority_pass_when_owner_cert_bound():
    record = _capsule(capsule_id="r" * 64, role="requested", owner={"owner_status": "bound"})
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_IDENTITY_AUTHORITY]["state"] == assurance_map.STATE_PASS


def test_build_assurance_map_identity_authority_fails_when_owner_cert_invalid():
    record = _capsule(capsule_id="r" * 64, role="requested", owner={"owner_status": "invalid"})
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_IDENTITY_AUTHORITY]["state"] == assurance_map.STATE_FAIL


def test_build_assurance_map_capture_coverage_pass_when_both_digests_present():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_CAPTURE_COVERAGE]["state"] == assurance_map.STATE_PASS


def test_build_assurance_map_capture_coverage_not_present_when_a_digest_is_missing():
    record = _capsule(capsule_id="r" * 64, role="requested")
    del record["effect"]["response_digest"]
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_CAPTURE_COVERAGE]["state"] == assurance_map.STATE_NOT_PRESENT


def test_build_assurance_map_outcome_corroboration_always_not_present():
    """Twin/adjudication comparison is genuinely not wired -- this is the
    task's own explicit rule, not NOT_CHECKED."""
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record, verify_result=None, verify_ran=False, has_witness_checkpoint=False
    )
    assert properties[assurance_map.PROPERTY_OUTCOME_CORROBORATION]["state"] == assurance_map.STATE_NOT_PRESENT


def test_build_assurance_map_result_is_always_a_complete_map():
    record = _capsule(capsule_id="r" * 64, role="requested")
    properties = build_assurance_map(
        record,
        verify_result=_FakeVerifyResult(["capsule_id_mismatch", "producer_signature_invalid"]),
        verify_ran=True,
        has_witness_checkpoint=True,
    )
    assurance_map.assert_map_complete(properties)  # raises on any gap -- must not raise


# ---------------------------------------------------------------------------
# grep-gate: rendered HTML must never leak the old vocabulary
# ---------------------------------------------------------------------------


def test_rendered_html_never_leaks_the_old_four_state_vocabulary():
    """[mesh-panes-map-chips]'s whole point: a ladder-shaped vocabulary
    rounding an honest "not checked yet" up to a rendered "present-unverified"
    (or "pending") is the regression this module exists to prevent. Render
    both the list and the card for a small fixture and grep the HTML."""
    requester, provider = _pair(exchange_id="ex-1")
    payload = build_exchange_list_payload([requester, provider])
    list_html = render_exchange_list_html(payload)

    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar", has_witness_checkpoint=True)
    card_html = render_exchange_subtab_html(view)

    for html in (list_html, card_html):
        assert "pending" not in html
        assert "present-unverified" not in html
        assert "trust_level" not in html
        # "continuity-witnessed" is a legitimate compound descriptor (see
        # external_registration's NOT_PRESENT text) -- strip it before
        # checking for a residual BARE "witnessed" (the old vocabulary word).
        assert "witnessed" not in html.replace("continuity-witnessed", "")


def test_rendered_card_never_leaks_build_verdicts_not_yet_proven_line():
    """[mesh-panes-map-chips] step 5: `_pair()` has no `cross_party` block, so
    `label_counterparty` returns "unknown" and `build_verdict`'s line 3 takes
    its warn branch -- the literal "Not yet proven: who asked ..." free-text
    the live Pane C card was leaking. That line must never render verbatim;
    the card renders the assurance map's own `identity_authority` property
    (chip + text) in its place. MUTANT check (QUEUE_PROTOCOL §7): reverting
    the `render_exchange_subtab_html` slice back to `view["verdict"]` (all
    three lines, unsliced) must flip this test to failing -- confirmed by
    hand before landing."""
    requester, provider = _pair(exchange_id="ex-1")
    view = build_exchange_view(requester, all_records=[requester, provider], source_log="sidecar")
    assert view["properties"][assurance_map.PROPERTY_IDENTITY_AUTHORITY] is not None
    html = render_exchange_subtab_html(view)
    assert "Not yet proven" not in html
    assert "who asked" not in html
    assert "identity/authority" in html
