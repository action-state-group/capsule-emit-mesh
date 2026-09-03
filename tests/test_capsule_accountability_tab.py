# SPDX-License-Identifier: Apache-2.0
"""capsule_accountability_tab.py: the dead-simple Accountability-tab re-skin.

Focus of these tests: the honest three(+failed)-state grading of each rung
(freshness / cross-party / runtime-binding / log-integrity), and -- the
required guard -- that tampering with (or simply omitting) the evidence a
rung depends on can only ever LOWER what that rung renders, never raise it.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from agent_manifest._tdx_verify import parse_tdx_quote

from capsule_accountability_tab import (
    STATE_ABSENT,
    STATE_FAILED,
    STATE_PRESENT_UNVERIFIED,
    STATE_VERIFIED,
    build_row,
    build_tab_payload,
    cross_party_grade,
    freshness_grade,
    hardware_inventory_grade,
    log_integrity_grade,
    measurement_class_grade,
    render_accountability_tab_html,
    tee_citation_grade,
)
from capsule_sidecar import IDENTITY_LIMITATION_CAVEAT
from trace_citation import GRADE_PLATFORM_ATTESTED, GRADE_UNATTESTED, trace_record_reference

FIXTURES = Path(__file__).parent / "fixtures" / "tdx-attestation"
QUOTE_A = (FIXTURES / "tdx_quote.bin").read_bytes()
SHARED_MRTD = parse_tdx_quote(QUOTE_A).mrtd.hex()


def _trace_record_bytes(*, measurement=SHARED_MRTD, platform="intel-tdx"):
    record = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "subject": "spiffe://trust.example.org/agent/evidence-demo/prod",
        "runtime": {
            "platform": platform,
            "measurement": f"sha384:{measurement}",
            "evidence": {"format": "tdx-quote-v4", "collateral": "embedded"},
        },
        "model": {"provider": "meta", "model_id": "llama-3.3-70b-instruct"},
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _trace_citation_evidence_ref(*, quote_bytes=QUOTE_A, measurement=SHARED_MRTD):
    record_bytes = _trace_record_bytes(measurement=measurement)
    reference = trace_record_reference(record_bytes, slot="runtime.tee_attestation")
    return {
        "reference": reference,
        "record_raw_b64": base64.b64encode(record_bytes).decode(),
        "quote_b64": base64.b64encode(quote_bytes).decode() if quote_bytes else None,
    }

CROSS_PARTY_ORDER = {"unilateral_fallback": 0, "acknowledged_receipt": 1, "full_bilateral": 2}


def _capsule(
    *,
    capsule_id="c" * 64,
    timestamp="2026-08-30T00:00:00Z",
    model="meta-llama/Llama-3.2-3B-Instruct",
    gpu="Apple M4 Max",
    is_soc=True,
    client_nonce_source="client_supplied",
    cross_party=None,
    binary_attestation=None,
    tee_attestation=None,
    trace_citation=None,
    hardware_inventory=None,
) -> dict:
    poc = {
        "client_nonce_source": client_nonce_source,
        "serving_provenance": {
            "model": {"canonical_ref": model, "architecture": "llama"},
            "hardware": {"gpu": gpu, "is_soc": is_soc},
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
        "evidence_refs": {
            "binary_attestation": binary_attestation,
            "tee_attestation": tee_attestation,
            "trace_citation": trace_citation,
        },
    }
    if cross_party is not None:
        poc["cross_party"] = cross_party
    if hardware_inventory is not None:
        poc["hardware_inventory"] = hardware_inventory
    return {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {"model_id": model, "compute_attestation": {"x-mesh-poc-v1": poc}},
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


# ---------------------------------------------------------------------------
# freshness_grade
# ---------------------------------------------------------------------------


def test_freshness_grade_client_supplied_is_verified():
    assert freshness_grade("client_supplied")["state"] == STATE_VERIFIED


def test_freshness_grade_replay_is_an_explicit_failure_not_amber():
    grade = freshness_grade("client_supplied_replayed")
    assert grade["state"] == STATE_FAILED


@pytest.mark.parametrize("source", ["sidecar_generated_fallback", "local_ingress"])
def test_freshness_grade_node_side_sources_are_present_unverified(source):
    assert freshness_grade(source)["state"] == STATE_PRESENT_UNVERIFIED


def test_freshness_grade_absent_when_no_nonce_source_at_all():
    assert freshness_grade(None)["state"] == STATE_ABSENT


def test_freshness_grade_unknown_value_never_rounds_up_to_verified():
    assert freshness_grade("some_future_unrecognised_value")["state"] != STATE_VERIFIED


# ---------------------------------------------------------------------------
# cross_party_grade
# ---------------------------------------------------------------------------


def test_cross_party_grade_absent_block_is_unilateral_fallback_no_caveat():
    grade = cross_party_grade({})
    assert grade["rung"] == "unilateral_fallback"
    assert grade["identity_limitation"] is None


def test_cross_party_grade_initiator_ref_without_ack_is_acknowledged_receipt():
    poc = {"cross_party": {"initiator_ref": "x" * 64}}
    grade = cross_party_grade(poc)
    assert grade["rung"] == "acknowledged_receipt"
    assert grade["identity_limitation"] is None


def test_cross_party_grade_verified_ack_reaches_full_bilateral_with_caveat():
    poc = {"cross_party": {"initiator_ref": "x" * 64, "ack_verified": True}}
    grade = cross_party_grade(poc)
    assert grade["rung"] == "full_bilateral"
    assert grade["identity_limitation"] == IDENTITY_LIMITATION_CAVEAT


def test_cross_party_grade_ack_verified_without_initiator_ref_stays_unilateral():
    # A record can't claim mutuality it never established the base evidence for.
    poc = {"cross_party": {"initiator_ref": None, "ack_verified": True}}
    grade = cross_party_grade(poc)
    assert grade["rung"] == "unilateral_fallback"
    assert grade["identity_limitation"] is None


# ---------------------------------------------------------------------------
# measurement_class_grade
# ---------------------------------------------------------------------------


def test_measurement_class_grade_absent_when_no_evidence_refs_at_all():
    assert measurement_class_grade({})["state"] == STATE_ABSENT


def test_measurement_class_grade_absent_for_sidecar_shaped_record():
    # The real shape capsule_sidecar.py emits today: present-but-empty refs,
    # no measurement_class key at all -- must render absent, never invented.
    poc = {"evidence_refs": {"statistical_fingerprint": {"type": "statistical_fingerprint", "digest": None}, "tee_attestation": {"type": "tee_attestation", "digest": None}}}
    assert measurement_class_grade(poc)["state"] == STATE_ABSENT


@pytest.mark.parametrize("cls", ["self_measured", "os_measured"])
def test_measurement_class_grade_reads_binary_attestation_class(cls):
    poc = {"evidence_refs": {"binary_attestation": {"measurement_class": cls}}}
    assert measurement_class_grade(poc)["state"] == cls


def test_measurement_class_grade_tee_measured_wins_over_binary():
    poc = {
        "evidence_refs": {
            "binary_attestation": {"measurement_class": "os_measured"},
            "tee_attestation": {"measurement_class": "tee_measured"},
        }
    }
    assert measurement_class_grade(poc)["state"] == "tee_measured"


# ---------------------------------------------------------------------------
# tee_citation_grade -- composition rung, kept SEPARATE from measurement_class_grade
# ---------------------------------------------------------------------------


def test_tee_citation_grade_absent_when_no_citation_offered():
    assert tee_citation_grade({})["state"] == STATE_ABSENT
    assert tee_citation_grade({"evidence_refs": {}})["state"] == STATE_ABSENT


def test_tee_citation_grade_platform_attested_from_a_real_citation():
    poc = {"evidence_refs": {"trace_citation": _trace_citation_evidence_ref()}}
    grade = tee_citation_grade(poc)
    assert grade["state"] == GRADE_PLATFORM_ATTESTED
    assert "genuine Intel silicon" in grade["card_text"]


def test_tee_citation_grade_never_shares_state_space_with_measurement_class_grade():
    # A record whose OWN binary/self-attestation is absent, but which carries a
    # valid TRACE citation, must show the citation on its OWN rung, not be
    # promoted into (or blended with) runtime_binding's tee_measured state.
    poc = {"evidence_refs": {"trace_citation": _trace_citation_evidence_ref()}}
    assert measurement_class_grade(poc)["state"] == STATE_ABSENT
    assert tee_citation_grade(poc)["state"] == GRADE_PLATFORM_ATTESTED


def test_mutant_tee_citation_measurement_mismatch_no_lift():
    poc = {"evidence_refs": {"trace_citation": _trace_citation_evidence_ref(measurement="ff" * 48)}}
    grade = tee_citation_grade(poc)
    assert grade["state"] == GRADE_UNATTESTED


def test_mutant_tee_citation_forged_reference_no_lift():
    ref = _trace_citation_evidence_ref()
    ref["reference"]["digest"] = "0" * 64
    grade = tee_citation_grade({"evidence_refs": {"trace_citation": ref}})
    assert grade["state"] == GRADE_UNATTESTED


def test_mutant_tee_citation_absent_quote_no_lift():
    poc = {"evidence_refs": {"trace_citation": _trace_citation_evidence_ref(quote_bytes=None)}}
    assert tee_citation_grade(poc)["state"] == GRADE_UNATTESTED


# ---------------------------------------------------------------------------
# hardware_inventory_grade -- PATH (a), a different evidence slot from binary_attestation
# ---------------------------------------------------------------------------


def test_hardware_inventory_grade_absent_when_no_block():
    assert hardware_inventory_grade({})["state"] == STATE_ABSENT


def test_hardware_inventory_grade_reads_a_real_capture():
    from mac_hardware_inventory import capture_mac_hardware_inventory

    inventory = capture_mac_hardware_inventory()
    if inventory is None:
        pytest.skip("no macOS hardware available to capture")
    poc = {"hardware_inventory": inventory.to_capsule_block()}
    grade = hardware_inventory_grade(poc)
    assert grade["state"] == "os_measured"
    assert grade["model_identifier"]


def test_mutant_hardware_inventory_wrong_grade_field_never_rounds_up():
    poc = {"hardware_inventory": {"grade": "self_reported", "model_identifier": "Mac16,5"}}
    assert hardware_inventory_grade(poc)["state"] == STATE_ABSENT


# ---------------------------------------------------------------------------
# log_integrity_grade
# ---------------------------------------------------------------------------


def test_log_integrity_grade_true_is_verified():
    grade = log_integrity_grade(True, has_witness_checkpoint=True)
    assert grade["state"] == STATE_VERIFIED
    assert grade["witness_checkpoint_supplied"] is True


def test_log_integrity_grade_false_is_failed_not_amber():
    assert log_integrity_grade(False, has_witness_checkpoint=False)["state"] == STATE_FAILED


def test_log_integrity_grade_none_is_present_unverified():
    assert log_integrity_grade(None, has_witness_checkpoint=False)["state"] == STATE_PRESENT_UNVERIFIED


# ---------------------------------------------------------------------------
# build_row / build_tab_payload / render_accountability_tab_html
# ---------------------------------------------------------------------------


def test_build_row_carries_claimed_model_and_hardware():
    row = build_row(_capsule(), verify_ok=True, has_witness_checkpoint=False)
    assert row["model_claimed"] == "Llama-3.2-3B-Instruct"
    assert row["hardware_claimed"] == "Apple M4 Max, SoC"
    assert row["rungs"]["freshness"]["state"] == STATE_VERIFIED
    assert row["record"]["capsule_id"] == "c" * 64
    assert row["rungs"]["tee_citation"]["state"] == STATE_ABSENT
    assert row["rungs"]["hardware_inventory"]["state"] == STATE_ABSENT


def test_build_row_carries_a_real_tee_citation_and_hardware_inventory():
    from mac_hardware_inventory import capture_mac_hardware_inventory

    inventory = capture_mac_hardware_inventory()
    hw_block = inventory.to_capsule_block() if inventory is not None else None
    row = build_row(
        _capsule(trace_citation=_trace_citation_evidence_ref(), hardware_inventory=hw_block),
        verify_ok=True,
        has_witness_checkpoint=False,
    )
    assert row["rungs"]["tee_citation"]["state"] == GRADE_PLATFORM_ATTESTED
    if hw_block is not None:
        assert row["rungs"]["hardware_inventory"]["state"] == "os_measured"


def test_build_tab_payload_sorts_rows_by_timestamp():
    records = [
        _capsule(capsule_id="b" * 64, timestamp="2026-08-30T02:00:00Z"),
        _capsule(capsule_id="a" * 64, timestamp="2026-08-30T01:00:00Z"),
    ]
    payload = build_tab_payload(records, ledger_dir=None)
    assert [r["capsule_id"] for r in payload["rows"]] == ["a" * 64, "b" * 64]


def test_render_accountability_tab_html_embeds_payload_exactly_once():
    payload = build_tab_payload([_capsule()], ledger_dir=None)
    html = render_accountability_tab_html(payload)
    assert html.count("window.__ACCOUNTABILITY_PAYLOAD__ = ") == 1
    assert "window.__mesh_recomputeCapsuleId" in html  # mesh_verify.js reused, not forked
    assert '"c' + "c" * 63 + '"' in html  # the capsule_id travels in the payload


def test_render_accountability_tab_html_inlines_mesh_verify_js_unmodified():
    # The load-bearing reuse claim: mesh_verify.js's own canonicalization
    # source travels byte-for-byte, never re-implemented or forked.
    from capsule_mesh_viewer import _load_verify_js

    payload = build_tab_payload([_capsule()], ledger_dir=None)
    html = render_accountability_tab_html(payload)
    assert _load_verify_js() in html


def test_render_accountability_tab_html_escapes_script_breakout():
    payload = build_tab_payload([_capsule(model="</script><script>alert(1)</script>")], ledger_dir=None)
    html = render_accountability_tab_html(payload)
    assert "</script><script>alert(1)</script>" not in html


# ---------------------------------------------------------------------------
# Required mutant tests: tampering with (or dropping) evidence must never
# upgrade the rendered rung above what the remaining bytes support.
# ---------------------------------------------------------------------------


def test_mutant_dropping_cross_party_degrades_to_unilateral_never_upgrades():
    poc_with_evidence = {"cross_party": {"initiator_ref": "x" * 64, "ack_verified": True}}
    honest = cross_party_grade(poc_with_evidence)
    assert honest["rung"] == "full_bilateral"

    # Now drop cross_party entirely, as a mutant/tamper would.
    tampered_poc = {k: v for k, v in poc_with_evidence.items() if k != "cross_party"}
    tampered = cross_party_grade(tampered_poc)
    assert tampered["rung"] == "unilateral_fallback"
    assert CROSS_PARTY_ORDER[tampered["rung"]] < CROSS_PARTY_ORDER[honest["rung"]]
    assert tampered["identity_limitation"] is None  # no leftover caveat once the rung drops


def test_mutant_flipping_client_nonce_source_never_stays_verified():
    honest = freshness_grade("client_supplied")
    assert honest["state"] == STATE_VERIFIED

    tampered = freshness_grade("client_supplied_replayed")
    assert tampered["state"] == STATE_FAILED
    assert tampered["state"] != STATE_VERIFIED


def test_mutant_stripping_measurement_class_degrades_to_absent_never_upgrades():
    poc = {"evidence_refs": {"binary_attestation": {"measurement_class": "os_measured"}}}
    honest = measurement_class_grade(poc)
    assert honest["state"] == "os_measured"

    tampered_poc = {"evidence_refs": {"binary_attestation": {k: v for k, v in poc["evidence_refs"]["binary_attestation"].items() if k != "measurement_class"}}}
    tampered = measurement_class_grade(tampered_poc)
    assert tampered["state"] == STATE_ABSENT
    assert tampered["state"] != "os_measured"
    assert tampered["state"] != "tee_measured"


def test_mutant_record_level_cross_party_drop_flows_through_build_row():
    record = _capsule(cross_party={"initiator_ref": "x" * 64, "ack_verified": True})
    honest_row = build_row(record, verify_ok=True, has_witness_checkpoint=False)
    assert honest_row["rungs"]["cross_party"]["rung"] == "full_bilateral"

    poc = record["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    del poc["cross_party"]
    tampered_row = build_row(record, verify_ok=True, has_witness_checkpoint=False)
    assert tampered_row["rungs"]["cross_party"]["rung"] == "unilateral_fallback"
