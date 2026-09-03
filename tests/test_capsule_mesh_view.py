# SPDX-License-Identifier: Apache-2.0
"""capsule_mesh_view.py: the two-log join, role/counterparty display labels,
and the presentation-only (never storage-merge) guarantee.
"""
from __future__ import annotations

import json

import pytest

from capsule_mesh_view import (
    SOURCE_PLUGIN,
    SOURCE_SIDECAR,
    build_machine_view,
    label_advertised_vs_served,
    label_counterparty,
    label_role,
    reconcile_record,
    render_machine_view,
)


def _capsule(
    capsule_id: str,
    timestamp: str,
    *,
    cross_party: dict | None = None,
    observation_point: str | None = None,
    advertisement: dict | None = None,
    serving_provenance: dict | None = None,
    role: str | None = None,
) -> dict:
    poc: dict = {"cross_party": cross_party}
    if advertisement is not None:
        poc["advertisement"] = advertisement
    if serving_provenance is not None:
        poc["serving_provenance"] = serving_provenance
    if role is not None:
        poc["role"] = role
    compute_attestation = {"x-mesh-poc-v1": poc}
    if observation_point is not None:
        compute_attestation["x-mesh-lifecycle-v1"] = {"observation_point": observation_point}
    return {
        "capsule_id": capsule_id,
        "timestamp": timestamp,
        "model_attestation": {"compute_attestation": compute_attestation},
    }


# ---------------------------------------------------------------------------
# label_role
# ---------------------------------------------------------------------------

def test_role_defaults_served_for_both_known_sources_with_no_observation_point():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z")
    assert label_role(rec, SOURCE_PLUGIN) == "served"
    assert label_role(rec, SOURCE_SIDECAR) == "served"


@pytest.mark.parametrize(
    "observation_point",
    ["gateway_ingress", "serving_host_ingress", "backend_dispatch", "client_egress"],
)
def test_role_is_served_for_every_known_observation_point(observation_point):
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", observation_point=observation_point)
    assert label_role(rec, SOURCE_SIDECAR) == "served"
    assert label_role(rec, SOURCE_PLUGIN) == "served"


def test_role_falls_back_to_unknown_for_an_unrecognized_source_log():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z")
    assert label_role(rec, "some-future-log") == "unknown"


def test_role_ignores_a_nonsense_observation_point_value():
    # a record cannot forge a role by carrying garbage in observation_point;
    # it falls back to the per-source default instead.
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", observation_point="not_a_real_point")
    assert label_role(rec, SOURCE_SIDECAR) == "served"


def test_role_via_observation_point_alone_for_an_unrecognized_source_log():
    # Isolates the observation_point branch from the per-source-log default:
    # an unrecognized source_log has no entry in _DEFAULT_ROLE_BY_SOURCE (it
    # falls back to "unknown" on its own -- see
    # test_role_falls_back_to_unknown_for_an_unrecognized_source_log), so the
    # only way this returns "served" is via the observation_point check.
    # Deleting that branch flips this test red -- real mutation coverage for
    # the "fails closed instead of silently mislabeling" claim.
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", observation_point="gateway_ingress")
    assert label_role(rec, "some-future-log") == "served"


def test_role_reads_the_provisional_capsule_field_when_present():
    """[mesh-b1-requestor-capsule-ledger]: capsule_sidecar.py now
    provisionally emits x-mesh-poc-v1.role for real. When a record carries
    it, that field is authoritative -- read directly, not re-derived."""
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", role="requested", observation_point="client_egress")
    assert label_role(rec, SOURCE_SIDECAR) == "requested"


def test_role_field_overrides_the_heuristic_even_when_they_would_disagree():
    """Isolates that the provisional field wins outright, not just when it
    happens to agree with the heuristic -- deleting the early-return branch
    flips this test red."""
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", role="requested", observation_point="serving_host_ingress")
    assert label_role(rec, SOURCE_SIDECAR) == "requested"


# ---------------------------------------------------------------------------
# label_counterparty
# ---------------------------------------------------------------------------

def test_counterparty_unknown_when_no_bilateral_evidence():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", cross_party=None)
    assert label_counterparty(rec) == "unknown"


def test_counterparty_unknown_when_cross_party_present_but_no_initiator_ref():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", cross_party={"initiator_ref": None})
    assert label_counterparty(rec) == "unknown"


def test_counterparty_labels_initiator_ref_when_present():
    rec = _capsule(
        "a" * 64, "2026-08-28T00:00:00Z",
        cross_party={"initiator_ref": "4212f4bc8dbf48b5e81c2a6b8971b3cd53964f80cf15b5781a77e2cb39cd5442"},
    )
    assert label_counterparty(rec) == "initiator:4212f4bc8dbf"


# ---------------------------------------------------------------------------
# label_advertised_vs_served / reconcile_record (verify-after-advertise §12.3)
# ---------------------------------------------------------------------------

_AD_LLAMA_Q4 = {
    "node_id": "mesh-node-demo-1",
    "model_canonical_ref": "meta/Llama-3.2-3B",
    "quantization": "Q4_K_M",
}


def test_view_flags_a_mismatch_loudly_and_names_the_broken_fields():
    served = {
        "served_by_node_id": "mesh-node-demo-1",
        "quantization": "Q8_0",
        "model": {"canonical_ref": "mistralai/Mistral-7B"},
    }
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", advertisement=_AD_LLAMA_Q4, serving_provenance=served)
    label = label_advertised_vs_served(rec)
    assert label.startswith("mismatch(")
    assert "quantization" in label
    assert "model_canonical_ref" in label


def test_view_reports_advertisement_absent_not_a_silent_green():
    served = {"served_by_node_id": "mesh-node-demo-1", "quantization": "Q4_K_M"}
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", serving_provenance=served)
    assert label_advertised_vs_served(rec) == "advertisement_absent"


def test_view_reports_match_for_a_kept_promise():
    served = {
        "served_by_node_id": "mesh-node-demo-1",
        "quantization": "Q4_K_M",
        "model": {"canonical_ref": "meta/Llama-3.2-3B"},
    }
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", advertisement=_AD_LLAMA_Q4, serving_provenance=served)
    assert label_advertised_vs_served(rec) == "match"


def test_reconcile_record_uses_the_records_own_bytes_not_a_co_carried_verdict():
    # Even if a producer co-carried a lying "match" verdict, reconcile_record
    # re-derives from advertisement + serving_provenance and catches the mismatch.
    served = {"served_by_node_id": "mesh-node-demo-1", "quantization": "Q8_0"}
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", advertisement=_AD_LLAMA_Q4, serving_provenance=served)
    rec["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"][
        "advertisement_reconciliation"
    ] = {"overall": "match"}  # a forged, over-claiming co-carried verdict
    assert reconcile_record(rec)["overall"] == "mismatch"


def test_machine_view_row_carries_advertised_vs_served():
    served = {"served_by_node_id": "mesh-node-demo-1", "quantization": "Q8_0"}
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z", advertisement=_AD_LLAMA_Q4, serving_provenance=served)
    rows = build_machine_view([(SOURCE_SIDECAR, [rec], None)])
    assert rows[0]["advertised_vs_served"].startswith("mismatch(")


# ---------------------------------------------------------------------------
# build_machine_view
# ---------------------------------------------------------------------------

def test_merges_and_sorts_by_timestamp_across_both_logs():
    plugin_records = [_capsule("b" * 64, "2026-08-28T02:00:00Z")]
    sidecar_records = [_capsule("a" * 64, "2026-08-28T01:00:00Z")]

    rows = build_machine_view(
        [(SOURCE_PLUGIN, plugin_records, None), (SOURCE_SIDECAR, sidecar_records, None)]
    )

    assert [r["capsule_id"] for r in rows] == ["a" * 64, "b" * 64]
    assert [r["source_log"] for r in rows] == [SOURCE_SIDECAR, SOURCE_PLUGIN]


def test_join_by_capsule_id_seen_in_both_logs_is_marked_witnessed_by_both():
    # A capsule_id recorded by BOTH writers is not a duplicate to discard --
    # it's the strongest accountability signal available (both of this
    # machine's independent writers saw the same content). It collapses to
    # one row (never two rows for one capsule_id) but keeps both sources.
    shared_id = "c" * 64
    plugin_records = [_capsule(shared_id, "2026-08-28T01:00:00Z")]
    sidecar_records = [_capsule(shared_id, "2026-08-28T01:00:00Z")]

    rows = build_machine_view(
        [(SOURCE_PLUGIN, plugin_records, None), (SOURCE_SIDECAR, sidecar_records, None)]
    )

    assert len(rows) == 1
    assert rows[0]["witnessed_by_both"] is True
    assert rows[0]["source_logs"] == [SOURCE_PLUGIN, SOURCE_SIDECAR]
    assert rows[0]["source_log"] == "plugin+sidecar"


def test_witnessed_by_both_verify_ok_is_false_if_either_source_failed_verify():
    shared_id = "c" * 64
    plugin_records = [_capsule(shared_id, "2026-08-28T01:00:00Z")]
    sidecar_records = [_capsule(shared_id, "2026-08-28T01:00:00Z")]

    class OkResult:
        capsule_id = shared_id
        ok = True

    class FailResult:
        capsule_id = shared_id
        ok = False

    rows = build_machine_view(
        [
            (SOURCE_PLUGIN, plugin_records, [OkResult()]),
            (SOURCE_SIDECAR, sidecar_records, [FailResult()]),
        ]
    )

    assert len(rows) == 1
    assert rows[0]["witnessed_by_both"] is True
    assert rows[0]["verify_ok"] is False


def test_single_source_row_is_not_witnessed_by_both():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z")
    rows = build_machine_view([(SOURCE_SIDECAR, [rec], None)])
    assert rows[0]["witnessed_by_both"] is False
    assert rows[0]["source_logs"] == [SOURCE_SIDECAR]


def test_records_without_a_capsule_id_are_skipped_not_crashed_on():
    rows = build_machine_view([(SOURCE_SIDECAR, [{"timestamp": "2026-08-28T00:00:00Z"}], None)])
    assert rows == []


def test_verify_ok_is_none_when_no_verify_results_supplied():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z")
    rows = build_machine_view([(SOURCE_SIDECAR, [rec], None)])
    assert rows[0]["verify_ok"] is None


def test_verify_ok_reads_from_the_supplied_per_source_verify_results():
    rec = _capsule("a" * 64, "2026-08-28T00:00:00Z")

    class FakeResult:
        capsule_id = "a" * 64
        ok = False

    rows = build_machine_view([(SOURCE_SIDECAR, [rec], [FakeResult()])])
    assert rows[0]["verify_ok"] is False


def test_never_writes_to_either_source_log(tmp_path):
    plugin_log = tmp_path / "plugin" / "capsules.jsonl"
    sidecar_log = tmp_path / "sidecar" / "capsules.jsonl"
    plugin_log.parent.mkdir()
    sidecar_log.parent.mkdir()
    plugin_line = json.dumps(_capsule("d" * 64, "2026-08-28T00:00:00Z"))
    sidecar_line = json.dumps(_capsule("e" * 64, "2026-08-28T00:00:01Z"))
    plugin_log.write_text(plugin_line + "\n")
    sidecar_log.write_text(sidecar_line + "\n")

    from capsule_emit.ledger import read_ledger

    build_machine_view(
        [
            (SOURCE_PLUGIN, read_ledger(plugin_log), None),
            (SOURCE_SIDECAR, read_ledger(sidecar_log), None),
        ]
    )

    assert plugin_log.read_text() == plugin_line + "\n"
    assert sidecar_log.read_text() == sidecar_line + "\n"


# ---------------------------------------------------------------------------
# render_machine_view
# ---------------------------------------------------------------------------

def test_render_reports_empty_view_honestly():
    import io

    out = io.StringIO()
    render_machine_view([], out=out)
    assert "no records" in out.getvalue()


def test_render_includes_role_counterparty_and_source_log_columns():
    import io

    rows = build_machine_view(
        [
            (
                SOURCE_SIDECAR,
                [
                    _capsule(
                        "a" * 64, "2026-08-28T00:00:00Z",
                        cross_party={"initiator_ref": "f" * 64},
                    )
                ],
                None,
            )
        ]
    )
    out = io.StringIO()
    render_machine_view(rows, out=out)
    rendered = out.getvalue()
    assert SOURCE_SIDECAR in rendered
    assert "served" in rendered
    assert "initiator:" in rendered
